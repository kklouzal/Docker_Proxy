from __future__ import annotations

import os
import re
import sqlite3
import threading
import time
import urllib.request
from urllib.parse import urlparse
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import logging

from services.errors import public_error_message
from services.logutil import log_exception_throttled


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ListStatus:
    key: str
    url: str
    enabled: bool
    last_success: int
    last_attempt: int
    last_error: str
    bytes: int
    rules: int


_DEFAULT_LISTS = {
    "easylist": "https://easylist.to/easylist/easylist.txt",
    "easyprivacy": "https://easylist.to/easylist/easyprivacy.txt",
    "cookiemonster": "https://secure.fanboy.co.nz/fanboy-cookiemonster.txt",
}


_DEFAULT_SETTINGS = {
    # Global on/off switch for ICAP decisions.
    "enabled": "1",
    # Cache URL allow/block decisions for performance.
    "cache_ttl": "3600",
    "cache_max": "200000",
}


def _now() -> int:
    return int(time.time())


class AdblockStore:
    def __init__(
        self,
        db_path: str = "/var/lib/squid-flask-proxy/adblock.db",
        lists_dir: str = "/var/lib/squid-flask-proxy/adblock/lists",
        update_interval_seconds: int = 6 * 60 * 60,
        cicap_access_log_path: str = "/var/log/cicap-access.log",
        blocklog_retention_days: int = 30,
    ):
        self.db_path = db_path
        self.lists_dir = lists_dir
        self.update_interval_seconds = update_interval_seconds
        self.cicap_access_log_path = cicap_access_log_path
        self.blocklog_retention_days = int(blocklog_retention_days)

        self._blocklog_started = False
        self._blocklog_lock = threading.Lock()
        self._last_events_prune_ts = 0

    def _connect(self) -> sqlite3.Connection:
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        conn = sqlite3.connect(self.db_path, timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA busy_timeout=30000;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def init_db(self) -> None:
        os.makedirs(self.lists_dir, exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS adblock_lists (
                    key TEXT PRIMARY KEY,
                    url TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 0,
                    last_success INTEGER NOT NULL DEFAULT 0,
                    last_attempt INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT NOT NULL DEFAULT '',
                    bytes INTEGER NOT NULL DEFAULT 0,
                    rules INTEGER NOT NULL DEFAULT 0
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS adblock_meta (
                    k TEXT PRIMARY KEY,
                    v TEXT NOT NULL
                );
                """
            )

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS adblock_cache_stats (
                    k TEXT PRIMARY KEY,
                    v INTEGER NOT NULL
                );
                """
            )

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS adblock_settings (
                    k TEXT PRIMARY KEY,
                    v TEXT NOT NULL
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS adblock_counts (
                    day INTEGER NOT NULL,
                    list_key TEXT NOT NULL,
                    blocked INTEGER NOT NULL,
                    PRIMARY KEY(day, list_key)
                );
                """
            )

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS adblock_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts INTEGER NOT NULL,
                    src_ip TEXT NOT NULL,
                    method TEXT NOT NULL,
                    url TEXT NOT NULL,
                    http_status INTEGER NOT NULL,
                    http_resp_line TEXT NOT NULL,
                    icap_status INTEGER NOT NULL,
                    raw TEXT NOT NULL,
                    created_ts INTEGER NOT NULL
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_adblock_events_ts ON adblock_events(ts DESC, id DESC);")
            conn.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS idx_adblock_events_uniq
                ON adblock_events(ts, src_ip, url, http_status);
                """
            )

            for key, url in _DEFAULT_LISTS.items():
                conn.execute(
                    """
                    INSERT INTO adblock_lists(key, url, enabled)
                    VALUES(?,?,0)
                    ON CONFLICT(key) DO UPDATE SET url=excluded.url;
                    """,
                    (key, url),
                )

            for k, v in _DEFAULT_SETTINGS.items():
                conn.execute(
                    "INSERT OR IGNORE INTO adblock_settings(k, v) VALUES(?,?)",
                    (k, v),
                )

            conn.execute("INSERT OR IGNORE INTO adblock_meta(k, v) VALUES('settings_version','1')")
            conn.execute("INSERT OR IGNORE INTO adblock_meta(k, v) VALUES('refresh_requested','0')")
            conn.execute("INSERT OR IGNORE INTO adblock_meta(k, v) VALUES('cache_flush_requested','0')")
            conn.execute("INSERT OR IGNORE INTO adblock_meta(k, v) VALUES('cache_last_flush','0')")
            conn.execute("INSERT OR IGNORE INTO adblock_meta(k, v) VALUES('cache_current_size','0')")

            # c-icap access log tail state
            conn.execute("INSERT OR IGNORE INTO adblock_meta(k, v) VALUES('cicap_access_pos','0')")
            conn.execute("INSERT OR IGNORE INTO adblock_meta(k, v) VALUES('cicap_access_inode','0')")

            for k in ("hits", "misses", "evictions"):
                conn.execute(
                    "INSERT OR IGNORE INTO adblock_cache_stats(k,v) VALUES(?,0)",
                    (k,),
                )

    def _get_meta(self, conn: sqlite3.Connection, key: str, default: str = "") -> str:
        row = conn.execute("SELECT v FROM adblock_meta WHERE k=?", (key,)).fetchone()
        return str(row[0]) if row and row[0] is not None else default

    def _set_meta(self, conn: sqlite3.Connection, key: str, value: str) -> None:
        conn.execute(
            "INSERT INTO adblock_meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
            (key, value),
        )

    def start_blocklog_background(self) -> None:
        with self._blocklog_lock:
            if self._blocklog_started:
                return
            self._blocklog_started = True

        self.init_db()

        # Seed only if empty to avoid duplicating historical lines.
        try:
            with self._connect() as conn:
                n = int(conn.execute("SELECT COUNT(*) FROM adblock_events").fetchone()[0] or 0)
                if n == 0:
                    self._seed_from_recent_log(conn)
        except Exception:
            log_exception_throttled(
                logger,
                "adblock_store.blocklog.seed",
                interval_seconds=300.0,
                message="Adblock blocklog seed failed",
            )

        t = threading.Thread(target=self._blocklog_tail_loop, name="adblock-cicap-tailer", daemon=True)
        t.start()

    def _seed_from_recent_log(self, conn: sqlite3.Connection, max_lines: int = 5000) -> None:
        lines = self._read_last_lines(self.cicap_access_log_path, max_lines=max_lines)
        if not lines:
            return
        for ln in lines:
            row = self._parse_cicap_access_line(ln)
            if row:
                self._insert_event(conn, row)
        self._prune_events(conn)

    def _read_last_lines(self, path: str, *, max_lines: int) -> List[str]:
        try:
            with open(path, "rb") as f:
                f.seek(0, os.SEEK_END)
                end = f.tell()
                # Read up to ~1MB from the end and split to lines.
                start = max(0, end - 1_000_000)
                f.seek(start, os.SEEK_SET)
                data = f.read()
            if start > 0:
                nl = data.find(b"\n")
                if nl >= 0:
                    data = data[nl + 1 :]
            text = data.decode("utf-8", errors="replace")
            lines = [ln for ln in text.splitlines() if ln.strip()]
            return lines[-max_lines:]
        except Exception:
            return []

    def _blocklog_tail_loop(self) -> None:
        conn: sqlite3.Connection | None = None
        while True:
            try:
                if conn is None:
                    conn = self._connect()
                self._ingest_new_cicap_lines(conn)
            except sqlite3.Error:
                try:
                    if conn is not None:
                        conn.rollback()
                        conn.close()
                except Exception:
                    log_exception_throttled(
                        logger,
                        "adblock_store.blocklog.conn_reset",
                        interval_seconds=300.0,
                        message="Adblock blocklog tailer failed to reset DB connection",
                    )
                conn = None
            except Exception:
                try:
                    if conn is not None:
                        conn.rollback()
                except Exception:
                    log_exception_throttled(
                        logger,
                        "adblock_store.blocklog.rollback",
                        interval_seconds=300.0,
                        message="Adblock blocklog tailer rollback failed",
                    )
            time.sleep(1.0)

    def _ingest_new_cicap_lines(self, conn: sqlite3.Connection) -> None:
        path = self.cicap_access_log_path
        if not path:
            return

        try:
            st = os.stat(path)
        except Exception:
            return

        inode = int(getattr(st, "st_ino", 0) or 0)
        size = int(getattr(st, "st_size", 0) or 0)

        try:
            last_inode = int(self._get_meta(conn, "cicap_access_inode", "0") or 0)
        except Exception:
            last_inode = 0
        try:
            pos = int(self._get_meta(conn, "cicap_access_pos", "0") or 0)
        except Exception:
            pos = 0

        if inode != 0 and last_inode != 0 and inode != last_inode:
            # Log rotated/recreated.
            pos = 0
        if size < pos:
            # Truncated.
            pos = 0

        # Read incremental bytes from last pos.
        try:
            with open(path, "rb") as f:
                f.seek(pos, os.SEEK_SET)
                data = f.read()
                new_pos = f.tell()
        except Exception:
            return

        if not data:
            # Still update inode if it changed (so we don't keep resetting).
            with conn:
                self._set_meta(conn, "cicap_access_inode", str(inode))
                self._set_meta(conn, "cicap_access_pos", str(pos))
            return

        created_ts = _now()
        event_rows: list[tuple[int, str, str, str, int, str, int, str, int]] = []
        text = data.decode("utf-8", errors="replace")
        for ln in text.splitlines():
            row = self._parse_cicap_access_line(ln)
            if not row:
                continue
            event_rows.append(
                (
                    int(row.get("ts") or 0),
                    str(row.get("src_ip") or "-"),
                    str(row.get("method") or "-"),
                    str(row.get("url") or ""),
                    int(row.get("http_status") or 0),
                    str(row.get("http_resp_line") or ""),
                    int(row.get("icap_status") or 0),
                    str(row.get("raw") or ""),
                    created_ts,
                )
            )

        with conn:
            if event_rows:
                conn.executemany(
                    """
                    INSERT OR IGNORE INTO adblock_events(
                        ts, src_ip, method, url, http_status, http_resp_line, icap_status, raw, created_ts
                    ) VALUES(?,?,?,?,?,?,?,?,?)
                    """,
                    event_rows,
                )

            self._set_meta(conn, "cicap_access_inode", str(inode))
            self._set_meta(conn, "cicap_access_pos", str(new_pos))

            if event_rows:
                if created_ts - int(self._last_events_prune_ts or 0) >= 60:
                    self._prune_events(conn)
                    self._last_events_prune_ts = created_ts

    def _parse_cicap_access_line(self, line: str) -> Optional[Dict[str, Any]]:
        raw = (line or "").strip("\r\n")
        if not raw:
            return None

        # Support both real tabs and literal "\\t" sequences.
        if "\t" in raw:
            parts = raw.split("\t")
        elif "\\t" in raw:
            parts = raw.split("\\t")
        else:
            return None

        parts = [p.strip() for p in parts]
        if len(parts) < 9:
            return None

        ts_s = parts[0]
        http_client_ip = parts[1] if len(parts) > 1 else ""
        remote_ip = parts[2] if len(parts) > 2 else ""
        icap_method = (parts[3] if len(parts) > 3 else "").upper()
        icap_path = parts[4] if len(parts) > 4 else ""
        icap_status_s = parts[5] if len(parts) > 5 else ""

        if icap_method != "REQMOD":
            return None
        if "adblockreq" not in (icap_path or ""):
            return None

        request_line = ""
        http_url = ""
        http_resp_line = ""

        # Expected format (current):
        # ts, http_client_ip, remote_ip, icap_method, icap_path, icap_status, http_req_line, http_url, http_resp_line, ...
        if len(parts) >= 9:
            request_line = parts[6] if len(parts) > 6 else ""
            http_url = parts[7] if len(parts) > 7 else ""
            http_resp_line = parts[8] if len(parts) > 8 else ""

        blocked = "403" in (http_resp_line or "")
        if not blocked:
            return None

        try:
            ts = int(float(ts_s))
        except Exception:
            ts = 0

        src_ip = http_client_ip if http_client_ip and http_client_ip != "-" else remote_ip
        src_ip = src_ip or "-"

        method = "-"
        rl = (request_line or "").strip()
        if rl and rl != "-":
            m = rl.split(" ", 1)[0].strip().upper()
            if re.fullmatch(r"[A-Z]{3,10}", m or ""):
                method = m

        http_status = 403
        try:
            toks = (http_resp_line or "").split()
            if len(toks) >= 2 and toks[1].isdigit():
                http_status = int(toks[1])
        except Exception:
            http_status = 403

        try:
            icap_status = int(icap_status_s) if (icap_status_s or "").strip().isdigit() else 0
        except Exception:
            icap_status = 0

        url = (http_url or "").strip()
        if not url or url == "-":
            return None

        return {
            "ts": ts,
            "src_ip": src_ip,
            "method": method,
            "url": url,
            "http_status": http_status,
            "http_resp_line": (http_resp_line or "").strip(),
            "icap_status": icap_status,
            "raw": raw,
        }

    def _insert_event(self, conn: sqlite3.Connection, row: Dict[str, Any]) -> None:
        conn.execute(
            """
            INSERT OR IGNORE INTO adblock_events(
                ts, src_ip, method, url, http_status, http_resp_line, icap_status, raw, created_ts
            ) VALUES(?,?,?,?,?,?,?,?,?)
            """,
            (
                int(row.get("ts") or 0),
                str(row.get("src_ip") or "-"),
                str(row.get("method") or "-"),
                str(row.get("url") or ""),
                int(row.get("http_status") or 0),
                str(row.get("http_resp_line") or ""),
                int(row.get("icap_status") or 0),
                str(row.get("raw") or ""),
                _now(),
            ),
        )

    def _prune_events(self, conn: sqlite3.Connection) -> None:
        days = max(1, int(self.blocklog_retention_days or 30))
        cutoff = _now() - days * 24 * 3600
        conn.execute("DELETE FROM adblock_events WHERE ts < ?", (int(cutoff),))

    def _checkpoint_and_vacuum(self) -> None:
        try:
            with self._connect() as conn:
                try:
                    conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
                except Exception:
                    log_exception_throttled(
                        logger,
                        "adblock_store.wal_checkpoint",
                        interval_seconds=300.0,
                        message="Adblock DB wal_checkpoint(TRUNCATE) failed",
                    )
                try:
                    conn.execute("VACUUM;")
                except Exception:
                    log_exception_throttled(
                        logger,
                        "adblock_store.vacuum",
                        interval_seconds=300.0,
                        message="Adblock DB VACUUM failed",
                    )
        except Exception:
            log_exception_throttled(
                logger,
                "adblock_store.checkpoint_vacuum",
                interval_seconds=300.0,
                message="Adblock DB checkpoint/vacuum failed",
            )

    def prune_old_entries(self, *, retention_days: int = 30, vacuum: bool = True) -> None:
        """Prune old benign blocklog data to keep the DB bounded."""
        days = max(1, int(retention_days or 30))
        cutoff = _now() - days * 24 * 3600
        cutoff_day = int(cutoff // 86400)
        with self._connect() as conn:
            conn.execute("DELETE FROM adblock_events WHERE ts < ?", (int(cutoff),))
            # Daily rollup rows are small, but keep them aligned with the same retention.
            conn.execute("DELETE FROM adblock_counts WHERE day < ?", (int(cutoff_day),))
        if vacuum:
            self._checkpoint_and_vacuum()

    def list_recent_block_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        self.init_db()
        try:
            limit_i = int(limit)
        except Exception:
            limit_i = 100
        limit_i = max(1, min(500, limit_i))

        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT ts, src_ip, method, url, http_status
                FROM adblock_events
                ORDER BY ts DESC, id DESC
                LIMIT ?
                """,
                (limit_i,),
            ).fetchall()

        out: List[Dict[str, Any]] = []
        for r in rows:
            out.append(
                {
                    "ts": int(r[0] or 0),
                    "src_ip": str(r[1] or "-"),
                    "method": str(r[2] or "-"),
                    "url": str(r[3] or ""),
                    "result": "BLOCKED",
                    "status": str(int(r[4] or 0)),
                }
            )
        return out

    def get_settings(self) -> Dict[str, Any]:
        def as_int(s: str, default: int) -> int:
            try:
                return int((s or "").strip())
            except Exception:
                return default

        with self._connect() as conn:
            rows = conn.execute("SELECT k, v FROM adblock_settings").fetchall()
            m = {str(r[0]): str(r[1]) for r in rows}

        enabled = (m.get("enabled") or _DEFAULT_SETTINGS["enabled"]).strip() == "1"
        cache_ttl = as_int(m.get("cache_ttl") or _DEFAULT_SETTINGS["cache_ttl"], int(_DEFAULT_SETTINGS["cache_ttl"]))
        cache_max = as_int(m.get("cache_max") or _DEFAULT_SETTINGS["cache_max"], int(_DEFAULT_SETTINGS["cache_max"]))

        # Clamp to safe ranges.
        cache_ttl = max(0, min(7 * 24 * 3600, cache_ttl))
        cache_max = max(0, min(1_000_000, cache_max))

        return {
            "enabled": enabled,
            "cache_ttl": cache_ttl,
            "cache_max": cache_max,
        }

    def set_settings(self, *, enabled: bool, cache_ttl: int, cache_max: int) -> None:
        cache_ttl = int(cache_ttl)
        cache_max = int(cache_max)
        cache_ttl = max(0, min(7 * 24 * 3600, cache_ttl))
        cache_max = max(0, min(1_000_000, cache_max))

        with self._connect() as conn:
            conn.execute(
                "INSERT INTO adblock_settings(k,v) VALUES('enabled',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                ("1" if enabled else "0",),
            )
            conn.execute(
                "INSERT INTO adblock_settings(k,v) VALUES('cache_ttl',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                (str(cache_ttl),),
            )
            conn.execute(
                "INSERT INTO adblock_settings(k,v) VALUES('cache_max',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                (str(cache_max),),
            )
            self._bump_version(conn)

    def _bump_version(self, conn: sqlite3.Connection) -> None:
        cur = conn.execute("SELECT v FROM adblock_meta WHERE k='settings_version'").fetchone()
        try:
            v = int(cur[0]) if cur else 1
        except Exception:
            v = 1
        conn.execute(
            "INSERT INTO adblock_meta(k,v) VALUES('settings_version',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
            (str(v + 1),),
        )

    def request_refresh_now(self) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO adblock_meta(k,v) VALUES('refresh_requested',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                (str(_now()),),
            )

    def request_cache_flush(self) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO adblock_meta(k,v) VALUES('cache_flush_requested',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                (str(_now()),),
            )

    def get_settings_version(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT v FROM adblock_meta WHERE k='settings_version'").fetchone()
            try:
                return int(row[0]) if row else 1
            except Exception:
                return 1

    def get_refresh_requested(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT v FROM adblock_meta WHERE k='refresh_requested'").fetchone()
            try:
                return int(row[0]) if row else 0
            except Exception:
                return 0

    def get_cache_flush_requested(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT v FROM adblock_meta WHERE k='cache_flush_requested'").fetchone()
            try:
                return int(row[0]) if row else 0
            except Exception:
                return 0

    def list_statuses(self) -> List[ListStatus]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT key, url, enabled, last_success, last_attempt, last_error, bytes, rules FROM adblock_lists ORDER BY key"
            ).fetchall()
            return [
                ListStatus(
                    key=r["key"],
                    url=r["url"],
                    enabled=bool(r["enabled"]),
                    last_success=int(r["last_success"]),
                    last_attempt=int(r["last_attempt"]),
                    last_error=str(r["last_error"] or ""),
                    bytes=int(r["bytes"]),
                    rules=int(r["rules"]),
                )
                for r in rows
            ]

    def set_enabled(self, enabled_map: Dict[str, bool]) -> None:
        with self._connect() as conn:
            rows = [(1 if enabled else 0, key) for key, enabled in (enabled_map or {}).items()]
            if rows:
                conn.executemany("UPDATE adblock_lists SET enabled=? WHERE key=?", rows)
            self._bump_version(conn)

    def list_path(self, key: str) -> str:
        safe = "".join([c for c in (key or "") if c.isalnum() or c in ("-", "_")])
        return os.path.join(self.lists_dir, f"{safe}.txt")

    def record_block(self, list_key: str) -> None:
        day = int(_now() // 86400)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO adblock_counts(day, list_key, blocked) VALUES(?,?,1)
                ON CONFLICT(day, list_key) DO UPDATE SET blocked = blocked + 1
                """,
                (day, list_key),
            )

    def record_blocks_bulk(self, counts: Dict[str, int]) -> None:
        """Bulk increment blocked counters.

        This is meant for the ICAP hot path: accumulate counts in memory and
        flush periodically to avoid per-request SQLite writes.
        """
        day = int(_now() // 86400)
        rows = []
        for k, v in (counts or {}).items():
            try:
                n = int(v)
            except Exception:
                continue
            if not k or n <= 0:
                continue
            rows.append((day, str(k), n))
        if not rows:
            return

        with self._connect() as conn:
            conn.executemany(
                """
                INSERT INTO adblock_counts(day, list_key, blocked) VALUES(?,?,?)
                ON CONFLICT(day, list_key) DO UPDATE SET blocked = blocked + excluded.blocked
                """,
                rows,
            )

    def stats(self) -> Dict[str, Any]:
        now = _now()
        day = int(now // 86400)
        day_ago = day - 1
        with self._connect() as conn:
            total = conn.execute("SELECT COALESCE(SUM(blocked),0) FROM adblock_counts").fetchone()[0]
            last_24h = conn.execute(
                "SELECT COALESCE(SUM(blocked),0) FROM adblock_counts WHERE day IN (?,?)",
                (day, day_ago),
            ).fetchone()[0]
            by_list = conn.execute(
                "SELECT list_key, COALESCE(SUM(blocked),0) AS blocked FROM adblock_counts GROUP BY list_key ORDER BY list_key"
            ).fetchall()
            by_list_24h = conn.execute(
                "SELECT list_key, COALESCE(SUM(blocked),0) AS blocked FROM adblock_counts WHERE day IN (?,?) GROUP BY list_key ORDER BY list_key",
                (day, day_ago),
            ).fetchall()
        return {
            "total": int(total or 0),
            "last_24h": int(last_24h or 0),
            "by_list": {r[0]: int(r[1] or 0) for r in by_list},
            "by_list_24h": {r[0]: int(r[1] or 0) for r in by_list_24h},
        }

    def should_update(self, status: ListStatus, now_ts: int, force: bool) -> bool:
        if not status.enabled:
            return False
        if force:
            return True
        if status.last_success <= 0:
            return True
        return (now_ts - status.last_success) >= int(self.update_interval_seconds)

    def download_list(self, key: str, url: str, timeout_seconds: int = 25) -> Tuple[bool, str, int, int]:
        """Returns (ok, err, bytes, rules)."""
        path = self.list_path(key)
        tmp = path + ".tmp"
        try:
            u = urlparse(url or "")
            if u.scheme not in ("http", "https"):
                return False, "Only http/https URLs are supported.", 0, 0

            max_bytes = int(os.environ.get("ADBLOCK_MAX_DOWNLOAD_BYTES", str(64 * 1024 * 1024)))
            if max_bytes <= 0:
                max_bytes = 64 * 1024 * 1024

            req = urllib.request.Request(url, headers={"User-Agent": "squid-flask-proxy/icap-adblock"})
            os.makedirs(os.path.dirname(path), exist_ok=True)

            total = 0
            with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
                # Best-effort Content-Length enforcement.
                try:
                    cl = resp.headers.get("Content-Length")
                    if cl is not None and int(cl) > max_bytes:
                        return False, f"Download too large (Content-Length={cl}).", 0, 0
                except Exception:
                    log_exception_throttled(
                        logger,
                        "adblock_store.content_length",
                        interval_seconds=300.0,
                        message="Failed to parse Content-Length for adblock download",
                    )

                with open(tmp, "wb") as f:
                    while True:
                        chunk = resp.read(256 * 1024)
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > max_bytes:
                            raise ValueError(f"Download exceeded limit ({max_bytes} bytes).")
                        f.write(chunk)

            os.replace(tmp, path)

            # Rough rule count: ignore comments/blank.
            rules = 0
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as rf:
                    for line in rf:
                        s = (line or "").strip()
                        if not s or s.startswith("!"):
                            continue
                        rules += 1
            except Exception:
                rules = 0

            return True, "", int(total), int(rules)
        except Exception as e:
            try:
                if os.path.exists(tmp):
                    os.unlink(tmp)
            except OSError:
                pass
            logger.exception("Adblock list download failed (key=%s)", key)
            return False, public_error_message(e, default="Download failed. Check server logs for details.", max_len=400), 0, 0

    def update_one(self, key: str, force: bool = False) -> bool:
        now_ts = _now()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT key, url, enabled, last_success, last_attempt, last_error, bytes, rules FROM adblock_lists WHERE key=?",
                (key,),
            ).fetchone()
            if not row:
                return False
            status = ListStatus(
                key=row["key"],
                url=row["url"],
                enabled=bool(row["enabled"]),
                last_success=int(row["last_success"]),
                last_attempt=int(row["last_attempt"]),
                last_error=str(row["last_error"] or ""),
                bytes=int(row["bytes"]),
                rules=int(row["rules"]),
            )
            if not self.should_update(status, now_ts, force):
                return False
            conn.execute("UPDATE adblock_lists SET last_attempt=? WHERE key=?", (now_ts, key))

        ok, err, b, rules = self.download_list(key, status.url)
        with self._connect() as conn:
            if ok:
                conn.execute(
                    "UPDATE adblock_lists SET last_success=?, last_error='', bytes=?, rules=? WHERE key=?",
                    (now_ts, int(b), int(rules), key),
                )
                return True
            else:
                conn.execute("UPDATE adblock_lists SET last_error=? WHERE key=?", (err[:400], key))
                return False

    def record_cache_stats(self, *, hits: int = 0, misses: int = 0, evictions: int = 0, size: int | None = None) -> None:
        with self._connect() as conn:
            if hits:
                conn.execute(
                    "INSERT INTO adblock_cache_stats(k,v) VALUES('hits',?) ON CONFLICT(k) DO UPDATE SET v = v + excluded.v",
                    (int(hits),),
                )
            if misses:
                conn.execute(
                    "INSERT INTO adblock_cache_stats(k,v) VALUES('misses',?) ON CONFLICT(k) DO UPDATE SET v = v + excluded.v",
                    (int(misses),),
                )
            if evictions:
                conn.execute(
                    "INSERT INTO adblock_cache_stats(k,v) VALUES('evictions',?) ON CONFLICT(k) DO UPDATE SET v = v + excluded.v",
                    (int(evictions),),
                )
            if size is not None:
                conn.execute(
                    "INSERT INTO adblock_meta(k,v) VALUES('cache_current_size',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                    (str(max(0, int(size))),),
                )
                conn.execute(
                    "INSERT INTO adblock_meta(k,v) VALUES('cache_last_flush',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                    (str(_now()),),
                )

    def cache_stats(self) -> Dict[str, int]:
        with self._connect() as conn:
            rows = conn.execute("SELECT k, v FROM adblock_cache_stats").fetchall()
            meta_rows = conn.execute(
                "SELECT k, v FROM adblock_meta WHERE k IN ('cache_current_size','cache_last_flush','cache_flush_requested')"
            ).fetchall()

        stats = {str(r[0]): int(r[1]) for r in rows}
        meta = {str(r[0]): int(r[1]) for r in meta_rows}
        return {
            "hits": int(stats.get("hits") or 0),
            "misses": int(stats.get("misses") or 0),
            "evictions": int(stats.get("evictions") or 0),
            "current_size": int(meta.get("cache_current_size") or 0),
            "last_flush": int(meta.get("cache_last_flush") or 0),
            "last_flush_req": int(meta.get("cache_flush_requested") or 0),
        }

    def get_update_interval_seconds(self) -> int:
        return int(self.update_interval_seconds)


_store: Optional[AdblockStore] = None


def get_adblock_store() -> AdblockStore:
    global _store
    if _store is None:
        def _env_int(name: str, default: int) -> int:
            v = (os.environ.get(name) or "").strip()
            if not v:
                return int(default)
            try:
                return int(v)
            except Exception:
                return int(default)

        _store = AdblockStore(
            db_path=os.environ.get("ADBLOCK_DB", "/var/lib/squid-flask-proxy/adblock.db"),
            lists_dir=os.environ.get("ADBLOCK_LISTS_DIR", "/var/lib/squid-flask-proxy/adblock/lists"),
            update_interval_seconds=_env_int("ADBLOCK_UPDATE_INTERVAL", 6 * 60 * 60),
            cicap_access_log_path=os.environ.get("CICAP_ACCESS_LOG", "/var/log/cicap-access.log"),
            blocklog_retention_days=_env_int("ADBLOCK_BLOCKLOG_RETENTION_DAYS", 30),
        )
    return _store
