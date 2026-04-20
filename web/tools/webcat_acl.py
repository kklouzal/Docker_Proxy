#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import queue
import sys
import threading
import time
from collections import OrderedDict
from typing import Iterable, Optional, Sequence, Set, Tuple


HERE = os.path.abspath(os.path.dirname(__file__))
APP_ROOT = os.path.abspath(os.path.join(HERE, ".."))
if APP_ROOT not in sys.path:
    sys.path.insert(0, APP_ROOT)

from services.db import connect, create_index_if_not_exists


def _now() -> int:
    return int(time.time())


def _env_int(name: str, default: int, *, minimum: int, maximum: int) -> int:
    try:
        value = int((os.environ.get(name) or str(default)).strip() or str(default))
    except Exception:
        value = int(default)
    return max(minimum, min(maximum, value))


def _env_float(name: str, default: float, *, minimum: float, maximum: float) -> float:
    try:
        value = float((os.environ.get(name) or str(default)).strip() or str(default))
    except Exception:
        value = float(default)
    return max(minimum, min(maximum, value))


def _norm_domain(s: str) -> str:
    d = (s or "").strip().lower().rstrip(".")
    if d.startswith("."):
        d = d[1:]
    # Squid passes host:port sometimes
    if ":" in d:
        host, port = d.rsplit(":", 1)
        if port.isdigit():
            d = host
    # Also handle accidental scheme/path
    if "://" in d:
        d = d.split("://", 1)[1]
    d = d.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    return d


def _parent_domains(domain: str, *, max_levels: int = 6) -> Iterable[str]:
    d = _norm_domain(domain)
    if not d:
        return []
    parts = [p for p in d.split(".") if p]
    if len(parts) < 2:
        return [d]
    out = []
    # sub.example.co.uk -> try full, then drop left labels
    for i in range(0, min(len(parts) - 1, max_levels)):
        out.append(".".join(parts[i:]))
    return out


class _Db:
    def __init__(self):
        self._conn = None
        self._last_open_attempt = 0
        self._cache_max_entries = _env_int("WEBFILTER_CACHE_ENTRIES", 200000, minimum=1000, maximum=1000000)
        self._cache_ttl = _env_float("WEBFILTER_CACHE_TTL_SECONDS", 3600.0, minimum=5.0, maximum=86400.0)
        self._cache_negative_ttl = _env_float("WEBFILTER_CACHE_NEGATIVE_TTL_SECONDS", 300.0, minimum=1.0, maximum=3600.0)
        self._cache: OrderedDict[str, tuple[float, tuple[str, ...]]] = OrderedDict()

    def _connect(self):
        now = _now()
        # Retry open at most once per second if DB missing during startup.
        if self._conn is not None:
            return self._conn
        if now == self._last_open_attempt:
            return None
        self._last_open_attempt = now
        try:
            conn = connect()
            self._conn = conn
            return conn
        except Exception:
            return None

    def _cache_get(self, domain: str) -> Optional[Set[str]]:
        entry = self._cache.get(domain)
        if entry is None:
            return None
        expires_at, values = entry
        if time.monotonic() >= expires_at:
            self._cache.pop(domain, None)
            return None
        self._cache.move_to_end(domain)
        return set(values)

    def _cache_put(self, domain: str, values: Set[str]) -> Set[str]:
        ttl = self._cache_ttl if values else self._cache_negative_ttl
        frozen = tuple(sorted(values))
        self._cache[domain] = (time.monotonic() + ttl, frozen)
        self._cache.move_to_end(domain)
        while len(self._cache) > self._cache_max_entries:
            self._cache.popitem(last=False)
        return set(frozen)

    def lookup_categories(self, domain: str) -> Set[str]:
        normalized = _norm_domain(domain)
        if not normalized:
            return set()

        cached = self._cache_get(normalized)
        if cached is not None:
            return cached

        conn = self._connect()
        if conn is None:
            return set()
        candidates = list(_parent_domains(normalized))
        if not candidates:
            return self._cache_put(normalized, set())
        placeholders = ",".join(["?"] * len(candidates))
        params = tuple(candidates + candidates)
        try:
            row = conn.execute(
                f"SELECT categories FROM webcat_domains WHERE domain IN ({placeholders}) ORDER BY FIELD(domain, {placeholders}) LIMIT 1",
                params,
            ).fetchone()
        except Exception:
            return set()
        if row and row[0]:
            raw = str(row[0])
            return self._cache_put(normalized, {c for c in raw.split("|") if c})
        return self._cache_put(normalized, set())


class _BlockedLogDb:
    def __init__(self, *, max_rows: int = 5000):
        self.max_rows = int(max_rows) if max_rows else 5000
        self._conn = None
        self._last_open_attempt = 0
        self._inserts = 0
        self._batch_size = _env_int("WEBFILTER_LOG_BATCH_SIZE", 128, minimum=1, maximum=2000)
        self._flush_interval = _env_float("WEBFILTER_LOG_FLUSH_INTERVAL_SECONDS", 1.0, minimum=0.1, maximum=10.0)
        self._queue: queue.Queue[tuple[int, str, str, str]] = queue.Queue(
            maxsize=_env_int("WEBFILTER_LOG_QUEUE_SIZE", 10000, minimum=100, maximum=100000)
        )
        self._writer_started = False
        self._writer_lock = threading.Lock()

    def _table(self, conn) -> str:
        return "webfilter_blocked_log"

    def _connect(self):
        now = _now()
        if self._conn is not None:
            return self._conn
        if now == self._last_open_attempt:
            return None
        self._last_open_attempt = now
        try:
            conn = connect()
            blocked_log_table = self._table(conn)
            conn.execute(
                f"CREATE TABLE IF NOT EXISTS {blocked_log_table}("
                "id BIGINT PRIMARY KEY AUTO_INCREMENT, "
                "ts BIGINT NOT NULL, "
                "src_ip VARCHAR(64) NOT NULL, "
                "url TEXT NOT NULL, "
                "category VARCHAR(128) NOT NULL"
                ")"
            )
            create_index_if_not_exists(conn, table_name=blocked_log_table, index_name=f"idx_{blocked_log_table}_ts", columns_sql="ts")
            self._conn = conn
            return conn
        except Exception:
            return None

    def start(self) -> None:
        if self.max_rows <= 0:
            return
        with self._writer_lock:
            if self._writer_started:
                return
            self._writer_started = True
            t = threading.Thread(target=self._run, name="webfilter-blocked-log-writer", daemon=True)
            t.start()

    def insert(self, *, ts: int, src_ip: str, url: str, category: str) -> None:
        if self.max_rows <= 0:
            return
        try:
            s_ip = (src_ip or "")[:128]
            s_url = (url or "")[:2000]
            s_cat = (category or "")[:128]
            if not s_ip or not s_url or not s_cat:
                return
            self.start()
            self._queue.put_nowait((int(ts), s_ip, s_url, s_cat))
        except Exception:
            return

    def _flush(self, conn, batch: list[tuple[int, str, str, str]]) -> None:
        blocked_log_table = self._table(conn)
        conn.executemany(
            f"INSERT INTO {blocked_log_table}(ts, src_ip, url, category) VALUES(?,?,?,?)",
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

    def _run(self) -> None:
        conn = None
        batch: list[tuple[int, str, str, str]] = []
        last_flush = time.monotonic()
        while True:
            timeout = max(0.05, self._flush_interval - (time.monotonic() - last_flush))
            try:
                item = self._queue.get(timeout=timeout)
                batch.append(item)
            except queue.Empty:
                pass

            if batch and (len(batch) >= self._batch_size or (time.monotonic() - last_flush) >= self._flush_interval):
                if conn is None:
                    conn = self._connect()
                if conn is not None:
                    try:
                        self._flush(conn, batch)
                    except Exception:
                        try:
                            conn.rollback()
                        except Exception:
                            pass
                        try:
                            conn.close()
                        except Exception:
                            pass
                        conn = None
                batch.clear()
                last_flush = time.monotonic()


def _parse_line(line: str) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str], Optional[str]]:
    """Return (channel_id, src_ip, domain, url, category).

    Supported helper input formats:
      - "<domain> <category>"
      - "<channel> <domain> <category>"
      - "<src_ip> <domain> <url> <category>"
      - "<channel> <src_ip> <domain> <url> <category>"
    """

    t = (line or "").strip()
    if not t:
        return None, None, None, None, None
    parts = t.split()
    if not parts:
        return None, None, None, None, None

    channel_id: Optional[str] = None
    if parts and parts[0].isdigit():
        channel_id = parts[0]
        parts = parts[1:]

    # New format: src, dst, uri, category
    if len(parts) >= 4:
        return channel_id, parts[0], parts[1], parts[2], parts[3]

    # Old format: dst, category
    if len(parts) >= 2:
        return channel_id, None, parts[0], None, parts[1]

    return channel_id, None, parts[0], None, None


def _write_response(channel_id: Optional[str], ok: bool) -> None:
    if channel_id is not None:
        sys.stdout.write(f"{channel_id} {'OK' if ok else 'ERR'}\n")
    else:
        sys.stdout.write(f"{'OK' if ok else 'ERR'}\n")
    sys.stdout.flush()


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Squid external ACL helper for domain category blocking (local categories DB).")
    ap.add_argument("--log-max-rows", type=int, default=int(os.environ.get("WEBFILTER_LOG_MAX_ROWS", "5000")))
    ap.add_argument("--fail", choices=["open", "closed"], default=os.environ.get("WEBFILTER_FAIL", "open"))
    args = ap.parse_args(list(argv) if argv is not None else None)

    db = _Db()
    log_db = _BlockedLogDb(max_rows=int(args.log_max_rows))
    log_db.start()
    fail_open = args.fail == "open"

    for raw in sys.stdin:
        ch, src_ip, domain, url, category = _parse_line(raw)
        if not domain or not category:
            # Fail-open: do not match the ACL (allow). Fail-closed: match (block).
            _write_response(ch, not fail_open)
            continue

        cats = db.lookup_categories(domain)
        if not cats:
            # Unknown domain: do not match the ACL (allow) unless fail-closed.
            _write_response(ch, not fail_open)
            continue

        # External ACL semantics: return OK when the ACL *matches*.
        # For blocking ACLs, we match when the destination is in the named category.
        match = category.lower() in cats
        if match:
            # Best-effort: record the event so the admin UI can show a blocked log.
            # This helper is invoked only for requests that reach the deny ACL chain.
            log_db.insert(ts=_now(), src_ip=(src_ip or ""), url=(url or domain or ""), category=(category or ""))
        _write_response(ch, match)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
