from __future__ import annotations

import contextlib
import ipaddress
import os
import queue
import re
import threading
import time

from services.db import connect
from services.errors import redact_url_for_display
from services.proxy_context import get_default_proxy_id, normalize_proxy_id
from services.proxy_write_guard import (
    guarded_proxy_rows,
    is_proxy_lifecycle_write_error,
)
from services.runtime_helpers import env_float as _env_float
from services.runtime_helpers import env_int as _env_int
from services.runtime_helpers import now_ts as _now
from services.schema_lifecycle import ensure_column, ensure_index

_CATEGORY_UNSAFE_RE = re.compile(r"[^a-z0-9_\-]+")


def _clean_log_text(value: object, *, max_len: int) -> str:
    text = str(value or "").replace("\r", " ").replace("\n", " ").strip()
    text = "".join(ch if (ch >= " " and ch != "\x7f") else " " for ch in text)
    text = " ".join(text.split())
    if max_len and len(text) > max_len:
        return text[:max_len]
    return text


def _normalize_log_src_ip(value: object) -> str:
    text = _clean_log_text(value, max_len=128)
    if "," in text:
        text = text.split(",", 1)[0].strip()
    try:
        return str(ipaddress.ip_address(text))
    except Exception:
        return "unknown"


def _normalize_log_category(value: object) -> str:
    category = _clean_log_text(value, max_len=128).lower().replace(" ", "_")
    category = _CATEGORY_UNSAFE_RE.sub("", category).strip("_-")
    return category[:128]


def _normalize_log_url(value: object) -> str:
    return redact_url_for_display(_clean_log_text(value, max_len=2000), max_len=2000)


def _normalize_log_ts(value: object) -> int:
    now = _now()
    try:
        ts = int(value)
    except Exception:
        return now
    if ts <= 0 or ts > now + 86400:
        return now
    return ts


_BLOCKED_LOG_STOP = object()


class BlockedLogDb:
    def __init__(self, *, max_rows: int = 5000) -> None:
        try:
            self.max_rows = max(0, min(1_000_000, int(max_rows)))
        except Exception:
            self.max_rows = 5000
        self._conn = None
        self._last_open_attempt = 0
        self._inserts = 0
        self._batch_size = _env_int(
            "WEBFILTER_LOG_BATCH_SIZE",
            128,
            minimum=1,
            maximum=2000,
        )
        self._flush_interval = _env_float(
            "WEBFILTER_LOG_FLUSH_INTERVAL_SECONDS",
            1.0,
            minimum=0.1,
            maximum=10.0,
        )
        self._queue_capacity = _env_int(
            "WEBFILTER_LOG_QUEUE_SIZE",
            10000,
            minimum=100,
            maximum=100000,
        )
        # Keep one internal slot reserved so close() can always wake the writer
        # after atomically stopping new intake, even when the event queue is full.
        self._queue: queue.Queue[tuple[int, str, str, str] | object] = queue.Queue(
            maxsize=self._queue_capacity + 1,
        )
        self._writer_started = False
        self._writer_thread: threading.Thread | None = None
        self._accepting = True
        self._stop_requested = threading.Event()
        self._stop_queued = False
        self._writer_lock = threading.Lock()

    def _proxy_id(self) -> str:
        return normalize_proxy_id(
            os.environ.get("PROXY_INSTANCE_ID")
            or os.environ.get("PROXY_ID")
            or os.environ.get("DEFAULT_PROXY_ID")
            or get_default_proxy_id(),
        )

    def _table(self, conn) -> str:
        return "webfilter_blocked_log"

    def _connect(self):
        now = _now()
        if self._conn is not None:
            return self._conn
        if now == self._last_open_attempt:
            return None
        self._last_open_attempt = now
        conn = None
        try:
            conn = connect()
            try:
                from services.schema_lifecycle import (
                    runtime_schema_ready_for_lazy_store,
                )

                if runtime_schema_ready_for_lazy_store(conn):
                    self._conn = conn
                    return conn
            except Exception:
                pass
            blocked_log_table = self._table(conn)
            conn.execute(
                f"CREATE TABLE IF NOT EXISTS {blocked_log_table}("
                "id BIGINT PRIMARY KEY AUTO_INCREMENT, "
                "proxy_id VARCHAR(64) NOT NULL DEFAULT 'default', "
                "ts BIGINT NOT NULL, "
                "src_ip VARCHAR(64) NOT NULL, "
                "url TEXT NOT NULL, "
                "category VARCHAR(128) NOT NULL, "
                f"KEY idx_{blocked_log_table}_ts_id (ts, id), "
                f"KEY idx_{blocked_log_table}_proxy_ts (proxy_id, ts, id)"
                ")",
            )
            self._ensure_column(
                conn,
                blocked_log_table,
                "proxy_id",
                f"ALTER TABLE {blocked_log_table} ADD COLUMN proxy_id VARCHAR(64) NOT NULL DEFAULT 'default' AFTER id",
            )
            self._ensure_index(
                conn,
                blocked_log_table,
                f"idx_{blocked_log_table}_ts_id",
                f"ALTER TABLE {blocked_log_table} ADD INDEX idx_{blocked_log_table}_ts_id (ts, id)",
            )
            self._ensure_index(
                conn,
                blocked_log_table,
                f"idx_{blocked_log_table}_proxy_ts",
                f"ALTER TABLE {blocked_log_table} ADD INDEX idx_{blocked_log_table}_proxy_ts (proxy_id, ts, id)",
            )
            self._conn = conn
            return conn
        except Exception:
            if conn is not None:
                with contextlib.suppress(Exception):
                    conn.close()
            return None

    @staticmethod
    def _ensure_column(conn, table_name: str, column_name: str, ddl: str) -> None:
        ensure_column(conn, table_name=table_name, column_name=column_name, ddl=ddl)

    @staticmethod
    def _ensure_index(conn, table_name: str, index_name: str, ddl: str) -> None:
        ensure_index(conn, table_name=table_name, index_name=index_name, ddl=ddl)

    def _start_locked(self) -> None:
        if self.max_rows <= 0 or self._writer_started or not self._accepting:
            return
        self._writer_started = True
        self._writer_thread = threading.Thread(
            target=self._run,
            name="webfilter-blocked-log-writer",
            daemon=True,
        )
        self._writer_thread.start()

    def start(self) -> None:
        with self._writer_lock:
            self._start_locked()

    def insert(self, *, ts: int, src_ip: str, url: str, category: str) -> None:
        if self.max_rows <= 0:
            return
        try:
            item = (
                _normalize_log_ts(ts),
                _normalize_log_src_ip(src_ip),
                _normalize_log_url(url),
                _normalize_log_category(category),
            )
            if not item[2] or not item[3]:
                return
            with self._writer_lock:
                if not self._accepting or self._queue.qsize() >= self._queue_capacity:
                    return
                self._start_locked()
                self._queue.put_nowait(item)
        except Exception:
            return

    def close(self, *, timeout: float = 2.0) -> bool:
        """Stop intake and give accepted events one bounded flush opportunity."""
        try:
            join_timeout = max(0.0, float(timeout))
        except Exception:
            join_timeout = 2.0
        conn = None
        with self._writer_lock:
            self._accepting = False
            thread = self._writer_thread
            if thread is None:
                conn = self._conn
                self._conn = None
            elif not self._stop_queued:
                self._stop_requested.set()
                # insert() and close() share this lock, and the queue reserves an
                # internal slot, so every event accepted before this sentinel is
                # ordered ahead of it and no later event can enter the queue.
                self._queue.put_nowait(_BLOCKED_LOG_STOP)
                self._stop_queued = True
        if conn is not None:
            with contextlib.suppress(Exception):
                conn.close()
        if thread is None:
            return True
        if thread is threading.current_thread():
            return False
        thread.join(timeout=join_timeout)
        return not thread.is_alive()

    def _prune_old_rows(self, conn, blocked_log_table: str, proxy_id: str) -> None:
        if self.max_rows <= 0:
            return
        rows = conn.execute(
            f"SELECT ts, id FROM {blocked_log_table} WHERE proxy_id=%s ORDER BY ts DESC, id DESC LIMIT %s",
            (proxy_id, int(self.max_rows)),
        ).fetchall()
        if len(rows) < int(self.max_rows):
            return
        boundary = rows[-1]
        boundary_ts = int(boundary[0] or 0)
        boundary_id = int(boundary[1] or 0)
        chunk_size = _env_int(
            "WEBFILTER_LOG_PRUNE_CHUNK_SIZE",
            500,
            minimum=1,
            maximum=10000,
        )
        max_delete = _env_int(
            "WEBFILTER_LOG_PRUNE_MAX_ROWS",
            5000,
            minimum=1,
            maximum=100000,
        )
        deleted_total = 0
        while deleted_total < max_delete:
            limit = min(chunk_size, max_delete - deleted_total)
            result = conn.execute(
                f"DELETE FROM {blocked_log_table} WHERE proxy_id=%s AND (ts < %s OR (ts = %s AND id < %s)) ORDER BY ts ASC, id ASC LIMIT %s",
                (proxy_id, boundary_ts, boundary_ts, boundary_id, limit),
            )
            conn.commit()
            deleted = max(0, int(getattr(result, "rowcount", 0) or 0))
            deleted_total += deleted
            if deleted < limit:
                break

    def _flush(self, conn, batch: list[tuple[int, str, str, str]]) -> None:
        blocked_log_table = self._table(conn)
        guarded_batch = guarded_proxy_rows(
            conn,
            self._proxy_id(),
            batch,
            lambda proxy_id, row: (proxy_id, row[0], row[1], row[2], row[3]),
        )
        if not guarded_batch.rows:
            return
        conn.executemany(
            f"INSERT INTO {blocked_log_table}(ts, proxy_id, src_ip, url, category) VALUES(%s,%s,%s,%s,%s)",
            [(row[1], row[0], row[2], row[3], row[4]) for row in guarded_batch.rows],
        )
        conn.commit()
        self._inserts += len(guarded_batch.rows)
        if self.max_rows > 0 and self._inserts >= 1000:
            self._inserts = 0
            # The insert commit above is already durable. Pruning remains
            # best-effort so a later prune failure cannot make the writer retry
            # and duplicate the committed batch, including during shutdown.
            with contextlib.suppress(Exception):
                self._prune_old_rows(conn, blocked_log_table, guarded_batch.proxy_id)

    def _flush_batch_if_possible(
        self,
        conn,
        batch: list[tuple[int, str, str, str]],
    ):
        if conn is None:
            conn = self._connect()
        if conn is None:
            return None, False
        try:
            self._flush(conn, batch)
        except Exception as exc:
            with contextlib.suppress(Exception):
                conn.rollback()
            if is_proxy_lifecycle_write_error(exc):
                # A removed/renaming/unregistered proxy must not be allowed to
                # recreate proxy-owned log rows.  The ACL decision has already
                # been returned to Squid; discard this best-effort observability
                # batch rather than retrying a lifecycle-blocked write forever.
                return conn, True
            with contextlib.suppress(Exception):
                conn.close()
            if self._conn is conn:
                self._conn = None
            return None, False
        return conn, True

    def _run(self) -> None:
        conn = None
        batch: list[tuple[int, str, str, str]] = []
        last_flush = time.monotonic()
        stopping = False
        try:
            while not stopping:
                if self._stop_requested.is_set():
                    stopping = True
                    while True:
                        try:
                            item = self._queue.get_nowait()
                        except queue.Empty:
                            break
                        if item is _BLOCKED_LOG_STOP:
                            break
                        batch.append(item)
                else:
                    timeout = max(
                        0.05,
                        self._flush_interval - (time.monotonic() - last_flush),
                    )
                    if len(batch) < self._batch_size:
                        try:
                            item = self._queue.get(timeout=timeout)
                            if item is _BLOCKED_LOG_STOP:
                                stopping = True
                            else:
                                batch.append(item)
                        except queue.Empty:
                            pass
                    else:
                        time.sleep(min(0.05, self._flush_interval))

                if batch and (
                    stopping
                    or len(batch) >= self._batch_size
                    or (time.monotonic() - last_flush) >= self._flush_interval
                ):
                    conn, flushed = self._flush_batch_if_possible(conn, batch)
                    if flushed:
                        batch.clear()
                        last_flush = time.monotonic()
        finally:
            # The writer exclusively owns its cached connection after start().
            # Never close it from a timed-out join while a DB operation may still
            # be using it; the writer closes it as soon as that operation returns.
            cached_conn = self._conn
            self._conn = None
            seen: set[int] = set()
            for candidate in (conn, cached_conn):
                if candidate is None or id(candidate) in seen:
                    continue
                seen.add(id(candidate))
                with contextlib.suppress(Exception):
                    candidate.close()
