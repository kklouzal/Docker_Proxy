#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import queue
import sqlite3
import sys
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING

HERE = Path(Path(__file__).parent).resolve()
APP_ROOT = Path(os.path.join(HERE, "..")).resolve()
if APP_ROOT not in sys.path:
    sys.path.insert(0, APP_ROOT)

import contextlib  # noqa: E402

from services.db import connect  # noqa: E402
from services.domain_normalization import normalize_domain as _norm_domain  # noqa: E402
from services.helper_runtime import (  # noqa: E402
    HelperStats,
    TtlLruCache,
    helper_event,
    split_acl_channel,
    write_acl_response,
)
from services.proxy_context import (  # noqa: E402
    get_default_proxy_id,
    normalize_proxy_id,
)
from services.runtime_helpers import env_float as _env_float  # noqa: E402
from services.runtime_helpers import env_int as _env_int  # noqa: E402
from services.runtime_helpers import now_ts as _now  # noqa: E402

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence


def _parent_domains(domain: str, *, max_levels: int = 6) -> Iterable[str]:
    d = _norm_domain(domain)
    if not d:
        return []
    parts = [p for p in d.split(".") if p]
    if len(parts) < 2:
        return [d]
    # sub.example.co.uk -> try full, then drop left labels
    return [".".join(parts[i:]) for i in range(min(len(parts) - 1, max_levels))]


class _Db:
    def __init__(self) -> None:
        self._conn = None
        self._last_open_attempt = 0
        self._cache_max_entries = _env_int(
            "WEBFILTER_CACHE_ENTRIES",
            200000,
            minimum=1000,
            maximum=1000000,
        )
        self._cache_ttl = _env_float(
            "WEBFILTER_CACHE_TTL_SECONDS",
            3600.0,
            minimum=5.0,
            maximum=86400.0,
        )
        self._cache_negative_ttl = _env_float(
            "WEBFILTER_CACHE_NEGATIVE_TTL_SECONDS",
            1.0,
            minimum=0.1,
            maximum=3600.0,
        )
        self._cache = TtlLruCache(
            max_entries=self._cache_max_entries,
            ttl_seconds=self._cache_ttl,
        )
        self._negative_cache = TtlLruCache(
            max_entries=self._cache_max_entries,
            ttl_seconds=self._cache_negative_ttl,
        )
        self._snapshot_dir = Path(
            (
                os.environ.get("WEBFILTER_SNAPSHOT_DIR")
                or "/var/lib/squid-flask-proxy/webfilter"
            ).strip()
            or "/var/lib/squid-flask-proxy/webfilter",
        )
        self._snapshot_path = self._snapshot_dir / "webcat.sqlite"
        self._snapshot_lock_path = self._snapshot_dir / ".webcat.sqlite.lock"
        self._snapshot_refresh_seconds = _env_float(
            "WEBFILTER_SNAPSHOT_REFRESH_SECONDS",
            30.0,
            minimum=5.0,
            maximum=3600.0,
        )
        self._snapshot_lock_stale_seconds = max(
            60.0,
            self._snapshot_refresh_seconds * 4.0,
        )
        self._snapshot_started = False
        self._snapshot_start_lock = threading.Lock()
        self._snapshot_attempt_ts = 0.0
        self._snapshot_state_lock = threading.Lock()
        self._local_conn: sqlite3.Connection | None = None
        self._local_snapshot_mtime_ns = 0
        self._local_snapshot_built_ts = 0

    def _connect(self):
        now = _now()
        # Reuse only a pre-existing connection so older helper/test paths can
        # discard stale handles explicitly; newly opened connections remain
        # one-shot to avoid pinning broken MySQL sockets.
        if self._conn is not None:
            return self._conn
        # Retry open at most once per second if DB missing during startup.
        if now == self._last_open_attempt:
            return None
        self._last_open_attempt = now
        try:
            return connect()
        except Exception:
            return None

    def _discard_remote_conn(self) -> None:
        conn = self._conn
        self._conn = None
        if conn is not None:
            with contextlib.suppress(Exception):
                conn.close()

    def _cache_get(self, domain: str) -> set[str] | None:
        positive = self._cache.get(domain)
        if positive is not None:
            return set(positive)
        negative = self._negative_cache.get(domain)
        if negative is not None:
            return set()
        return None

    def _cache_put(self, domain: str, values: set[str]) -> set[str]:
        frozen = tuple(sorted(values))
        if values:
            self._cache.put(domain, frozen)
        else:
            self._negative_cache.put(domain, frozen)
        return set(frozen)

    def start(self) -> None:
        with self._snapshot_start_lock:
            if self._snapshot_started:
                return
            self._snapshot_started = True
        try:
            self._load_snapshot_from_disk(force=True)
            # A reconfigured Squid starts fresh helper processes, and those
            # helpers must not pin an older on-disk category snapshot when the
            # Admin UI has already published a newer webcat build timestamp.
            # Always compare the loaded snapshot with MySQL once at helper
            # startup; the steady-state refresh loop still owns periodic updates.
            self._ensure_snapshot(force=True)
        except Exception:
            pass
        thread = threading.Thread(
            target=self._snapshot_loop,
            name="webcat-snapshot-refresh",
            daemon=True,
        )
        thread.start()

    def _snapshot_available(self) -> bool:
        with self._snapshot_state_lock:
            return self._local_conn is not None

    def _acquire_snapshot_lock(self) -> int | None:
        self._snapshot_dir.mkdir(parents=True, exist_ok=True)
        for _ in range(2):
            try:
                fd = os.open(
                    self._snapshot_lock_path,
                    os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                    0o600,
                )
                with contextlib.suppress(Exception):
                    os.write(fd, str(os.getpid()).encode("ascii", errors="ignore"))
                return fd
            except FileExistsError:
                try:
                    stale = (
                        time.time() - self._snapshot_lock_path.stat().st_mtime
                    ) > self._snapshot_lock_stale_seconds
                except Exception:
                    stale = False
                if not stale:
                    return None
                try:
                    self._snapshot_lock_path.unlink(missing_ok=True)
                except Exception:
                    return None
        return None

    def _release_snapshot_lock(self, fd: int | None) -> None:
        if fd is not None:
            with contextlib.suppress(Exception):
                os.close(fd)
        with contextlib.suppress(Exception):
            self._snapshot_lock_path.unlink(missing_ok=True)

    def _refresh_snapshot_lock(self, fd: int | None) -> None:
        if fd is None:
            return
        try:
            # Keep the lock's mtime fresh so long-running snapshot builds are
            # never mistaken for stale locks and re-entered by another helper.
            os.utime(self._snapshot_lock_path, None)
        except Exception:
            pass

    def _swap_local_snapshot(
        self,
        conn: sqlite3.Connection,
        *,
        built_ts: int,
        mtime_ns: int,
    ) -> None:
        old_conn: sqlite3.Connection | None = None
        previous_built_ts = 0
        with self._snapshot_state_lock:
            old_conn = self._local_conn
            previous_built_ts = self._local_snapshot_built_ts
            self._local_conn = conn
            self._local_snapshot_built_ts = int(built_ts or 0)
            self._local_snapshot_mtime_ns = int(mtime_ns or 0)
        if int(built_ts or 0) != int(previous_built_ts or 0):
            self._cache.clear()
            self._negative_cache.clear()
        if old_conn is not None:
            with contextlib.suppress(Exception):
                old_conn.close()

    def _load_snapshot_from_disk(self, *, force: bool = False) -> bool:
        try:
            stat = self._snapshot_path.stat()
        except FileNotFoundError:
            return False
        except Exception:
            return False

        with self._snapshot_state_lock:
            if (
                not force
                and self._local_conn is not None
                and self._local_snapshot_mtime_ns == int(stat.st_mtime_ns)
            ):
                return True

        conn: sqlite3.Connection | None = None
        try:
            conn = sqlite3.connect(
                f"file:{self._snapshot_path.as_posix()}?mode=ro",
                uri=True,
                check_same_thread=False,
                timeout=1.0,
            )
            conn.execute("PRAGMA query_only = ON")
            row = conn.execute("SELECT v FROM meta WHERE k='built_ts'").fetchone()
            built_ts = (
                int(str(row[0]).strip())
                if row and row[0] is not None and str(row[0]).strip()
                else 0
            )
        except Exception:
            if conn is not None:
                with contextlib.suppress(Exception):
                    conn.close()
            return False

        self._swap_local_snapshot(
            conn,
            built_ts=built_ts,
            mtime_ns=int(stat.st_mtime_ns),
        )
        return True

    def _load_remote_built_ts(self) -> int:
        conn = self._connect()
        if conn is None:
            return 0
        try:
            row = conn.execute(
                "SELECT v FROM webcat_meta WHERE k=%s",
                ("built_ts",),
            ).fetchone()
            return (
                int(str(row[0]).strip())
                if row and row[0] is not None and str(row[0]).strip()
                else 0
            )
        except Exception:
            self._discard_remote_conn()
            return 0
        finally:
            with contextlib.suppress(Exception):
                conn.close()

    def _build_snapshot_from_db(self, *, expected_built_ts: int = 0) -> bool:
        lock_fd = self._acquire_snapshot_lock()
        if lock_fd is None:
            return self._load_snapshot_from_disk(force=True)

        tmp_path = self._snapshot_dir / f"webcat.sqlite.tmp-{os.getpid()}"
        local_db: sqlite3.Connection | None = None
        remote_conn = None
        try:
            self._snapshot_dir.mkdir(parents=True, exist_ok=True)
            self._load_snapshot_from_disk(force=True)
            with self._snapshot_state_lock:
                if (
                    self._local_conn is not None
                    and self._local_snapshot_built_ts >= int(expected_built_ts or 0)
                ):
                    return True

            remote_conn = self._connect()
            if remote_conn is None:
                return self._load_snapshot_from_disk(force=True)

            if tmp_path.exists():
                with contextlib.suppress(Exception):
                    tmp_path.unlink()

            local_db = sqlite3.connect(str(tmp_path))
            local_db.execute("PRAGMA journal_mode = OFF")
            local_db.execute("PRAGMA synchronous = OFF")
            local_db.execute("PRAGMA temp_store = MEMORY")
            local_db.execute("PRAGMA locking_mode = EXCLUSIVE")
            local_db.execute(
                "CREATE TABLE domains (domain TEXT PRIMARY KEY, categories TEXT NOT NULL)",
            )
            local_db.execute("CREATE TABLE meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)")

            built_ts = int(expected_built_ts or self._load_remote_built_ts() or _now())
            row_count = 0
            cur = remote_conn.native.cursor()
            try:
                cur.execute(
                    "SELECT domain, categories FROM webcat_domains ORDER BY domain ASC",
                )
                while True:
                    rows = cur.fetchmany(10000)
                    if not rows:
                        break
                    batch = [
                        (_norm_domain(domain), str(categories or ""))
                        for domain, categories in rows
                        if domain
                    ]
                    if not batch:
                        continue
                    local_db.executemany(
                        "INSERT OR REPLACE INTO domains(domain, categories) VALUES(?, ?)",
                        batch,
                    )
                    row_count += len(batch)
                    self._refresh_snapshot_lock(lock_fd)
            finally:
                with contextlib.suppress(Exception):
                    cur.close()

            local_db.execute(
                "INSERT INTO meta(k, v) VALUES('built_ts', ?)",
                (str(built_ts),),
            )
            local_db.execute(
                "INSERT INTO meta(k, v) VALUES('row_count', ?)",
                (str(row_count),),
            )
            local_db.commit()
            local_db.close()
            local_db = None
            Path(tmp_path).replace(self._snapshot_path)
            return self._load_snapshot_from_disk(force=True)
        except Exception:
            self._discard_remote_conn()
            return False
        finally:
            if remote_conn is not None:
                with contextlib.suppress(Exception):
                    remote_conn.close()
            if local_db is not None:
                with contextlib.suppress(Exception):
                    local_db.close()
            try:
                if tmp_path.exists():
                    tmp_path.unlink()
            except Exception:
                pass
            self._release_snapshot_lock(lock_fd)

    def _ensure_snapshot(self, *, force: bool = False) -> bool:
        now = time.monotonic()
        if (
            not force
            and (now - self._snapshot_attempt_ts) < self._snapshot_refresh_seconds
        ):
            return (
                self._load_snapshot_from_disk(force=False) or self._snapshot_available()
            )
        self._snapshot_attempt_ts = now

        remote_built_ts = self._load_remote_built_ts()
        disk_ready = self._load_snapshot_from_disk(force=False)
        with self._snapshot_state_lock:
            local_built_ts = self._local_snapshot_built_ts
            local_ready = self._local_conn is not None
        if remote_built_ts <= 0:
            return disk_ready or local_ready
        if local_ready and remote_built_ts <= local_built_ts:
            return True
        return self._build_snapshot_from_db(expected_built_ts=remote_built_ts)

    def _snapshot_loop(self) -> None:
        while True:
            try:
                self._load_snapshot_from_disk(force=False)
                remote_built_ts = self._load_remote_built_ts()
                with self._snapshot_state_lock:
                    local_built_ts = self._local_snapshot_built_ts
                if remote_built_ts > local_built_ts:
                    self._build_snapshot_from_db(expected_built_ts=remote_built_ts)
            except Exception:
                pass
            time.sleep(self._snapshot_refresh_seconds)

    def _lookup_categories_from_snapshot(self, normalized: str) -> set[str] | None:
        with self._snapshot_state_lock:
            conn = self._local_conn
            if conn is None:
                return None
            for candidate in _parent_domains(normalized):
                row = conn.execute(
                    "SELECT categories FROM domains WHERE domain = ?",
                    (candidate,),
                ).fetchone()
                if row and row[0]:
                    return {c for c in str(row[0]).split("|") if c}
        return set()

    def _lookup_categories_remote(self, normalized: str) -> set[str]:
        conn = self._connect()
        if conn is None:
            return set()
        candidates = list(_parent_domains(normalized))
        if not candidates:
            with contextlib.suppress(Exception):
                conn.close()
            return set()
        placeholders = ",".join(["%s"] * len(candidates))
        params = tuple(candidates + candidates)
        try:
            row = conn.execute(
                f"SELECT categories FROM webcat_domains WHERE domain IN ({placeholders}) ORDER BY FIELD(domain, {placeholders}) LIMIT 1",
                params,
            ).fetchone()
        except Exception:
            self._discard_remote_conn()
            return set()
        finally:
            with contextlib.suppress(Exception):
                conn.close()
        if row and row[0]:
            raw = str(row[0])
            return {c for c in raw.split("|") if c}
        return set()

    def lookup_categories(self, domain: str) -> set[str]:
        normalized = _norm_domain(domain)
        if not normalized:
            return set()

        cached = self._cache_get(normalized)
        if cached is not None:
            return cached

        self.start()
        self._ensure_snapshot(force=False)
        snapshot_hit = self._lookup_categories_from_snapshot(normalized)
        if snapshot_hit is not None:
            return self._cache_put(normalized, snapshot_hit)

        return self._cache_put(normalized, self._lookup_categories_remote(normalized))


class _BlockedLogDb:
    def __init__(self, *, max_rows: int = 5000) -> None:
        self.max_rows = int(max_rows) if max_rows else 5000
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
        self._queue: queue.Queue[tuple[int, str, str, str, str]] = queue.Queue(
            maxsize=_env_int(
                "WEBFILTER_LOG_QUEUE_SIZE",
                10000,
                minimum=100,
                maximum=100000,
            ),
        )
        self._writer_started = False
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
            blocked_log_table = self._table(conn)
            conn.execute(
                f"CREATE TABLE IF NOT EXISTS {blocked_log_table}("
                "id BIGINT PRIMARY KEY AUTO_INCREMENT, "
                "proxy_id VARCHAR(64) NOT NULL DEFAULT 'default', "
                "ts BIGINT NOT NULL, "
                "src_ip VARCHAR(64) NOT NULL, "
                "url TEXT NOT NULL, "
                "category VARCHAR(128) NOT NULL, "
                f"KEY idx_{blocked_log_table}_proxy_ts (proxy_id, ts, id)"
                ")",
            )
            self._conn = conn
            return conn
        except Exception:
            if conn is not None:
                with contextlib.suppress(Exception):
                    conn.close()
            return None

    def start(self) -> None:
        if self.max_rows <= 0:
            return
        with self._writer_lock:
            if self._writer_started:
                return
            self._writer_started = True
            t = threading.Thread(
                target=self._run,
                name="webfilter-blocked-log-writer",
                daemon=True,
            )
            t.start()

    def insert(self, *, ts: int, src_ip: str, url: str, category: str) -> None:
        if self.max_rows <= 0:
            return
        try:
            s_ip = (src_ip or "unknown")[:128]
            s_url = (url or "")[:2000]
            s_cat = (category or "")[:128]
            if not s_url or not s_cat:
                return
            self.start()
            self._queue.put_nowait((int(ts), self._proxy_id(), s_ip, s_url, s_cat))
        except Exception:
            return

    def _flush(self, conn, batch: list[tuple[int, str, str, str, str]]) -> None:
        blocked_log_table = self._table(conn)
        conn.executemany(
            f"INSERT INTO {blocked_log_table}(ts, proxy_id, src_ip, url, category) VALUES(%s,%s,%s,%s,%s)",
            batch,
        )
        conn.commit()
        self._inserts += len(batch)
        if self.max_rows > 0 and self._inserts >= 1000:
            self._inserts = 0
            conn.execute(
                f"DELETE FROM {blocked_log_table} WHERE id NOT IN (SELECT id FROM (SELECT id FROM {blocked_log_table} ORDER BY ts DESC, id DESC LIMIT %s) AS keepers)",
                (int(self.max_rows),),
            )
            conn.commit()

    def _flush_batch_if_possible(
        self,
        conn,
        batch: list[tuple[int, str, str, str, str]],
    ):
        if conn is None:
            conn = self._connect()
        if conn is None:
            return None, False
        try:
            self._flush(conn, batch)
        except Exception:
            with contextlib.suppress(Exception):
                conn.rollback()
            with contextlib.suppress(Exception):
                conn.close()
            return None, False
        return conn, True

    def _run(self) -> None:
        conn = None
        batch: list[tuple[int, str, str, str, str]] = []
        last_flush = time.monotonic()
        while True:
            timeout = max(0.05, self._flush_interval - (time.monotonic() - last_flush))
            if len(batch) < self._batch_size:
                try:
                    item = self._queue.get(timeout=timeout)
                    batch.append(item)
                except queue.Empty:
                    pass
            else:
                time.sleep(min(0.05, self._flush_interval))

            if batch and (
                len(batch) >= self._batch_size
                or (time.monotonic() - last_flush) >= self._flush_interval
            ):
                conn, flushed = self._flush_batch_if_possible(conn, batch)
                if flushed:
                    batch.clear()
                    last_flush = time.monotonic()


def _parse_line(
    line: str,
) -> tuple[str | None, str | None, str | None, str | None, str | None]:
    """Return (channel_id, src_ip, domain, url, category).

    Supported helper input formats:
      - "<domain> <category>"
      - "<channel> <domain> <category>"
      - "<src_ip> <domain> <url> <category>"
      - "<channel> <src_ip> <domain> <url> <category>"
    """
    channel_id, parts = split_acl_channel(line)
    if not parts:
        return None, None, None, None, None

    # New format: src, dst, uri, category
    if len(parts) >= 4:
        return channel_id, parts[0], parts[1], parts[2], parts[3]

    # Old format: dst, category
    if len(parts) >= 2:
        return channel_id, None, parts[0], None, parts[1]

    return channel_id, None, parts[0], None, None


def _write_response(
    channel_id: str | None,
    ok: bool,
    *,
    message: str | None = None,
) -> None:
    write_acl_response(channel_id, ok, message=message)


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Squid external ACL helper for domain category blocking (local categories DB).",
    )
    ap.add_argument(
        "--log-max-rows",
        type=int,
        default=int(os.environ.get("WEBFILTER_LOG_MAX_ROWS", "5000")),
    )
    ap.add_argument(
        "--fail",
        choices=["open", "closed"],
        default=os.environ.get("WEBFILTER_FAIL", "open"),
    )
    args = ap.parse_args(list(argv) if argv is not None else None)

    db = _Db()
    log_db = _BlockedLogDb(max_rows=int(args.log_max_rows))
    log_db.start()
    fail_open = args.fail == "open"
    stats = HelperStats("webcat_acl")
    helper_event(
        "webcat_acl",
        "startup",
        fail_mode=args.fail,
        log_max_rows=int(args.log_max_rows),
    )

    for raw in sys.stdin:
        ch, src_ip, domain, url, category = _parse_line(raw)
        if url:
            url_domain = _norm_domain(url)
            if url_domain:
                domain = url_domain
        if not domain or not category:
            # Fail-open: do not match the ACL (allow). Fail-closed: match (block).
            stats.increment("parse_miss")
            _write_response(ch, not fail_open)
            stats.emit_if_due()
            continue

        cats = db.lookup_categories(domain)
        stats.increment("requests")
        if not cats:
            # Unknown domain: do not match the ACL (allow) unless fail-closed.
            stats.increment("misses")
            _write_response(ch, not fail_open)
            stats.emit_if_due()
            continue

        # External ACL semantics: return OK when the ACL *matches*.
        # For blocking ACLs, we match when the destination is in the named category.
        match = category.lower() in cats
        if match:
            stats.increment("matches")
            # Best-effort: record the event so the admin UI can show a blocked log.
            # This helper is invoked only for requests that reach the deny ACL chain.
            log_db.insert(
                ts=_now(),
                src_ip=(src_ip or ""),
                url=(url or domain or ""),
                category=(category or ""),
            )
        _write_response(ch, match, message=f"category={category}" if match else None)
        stats.emit_if_due()

    stats.emit_if_due(force=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
