from __future__ import annotations

import os
import sqlite3
import time
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


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
    ):
        self.db_path = db_path
        self.lists_dir = lists_dir
        self.update_interval_seconds = update_interval_seconds

    def _connect(self) -> sqlite3.Connection:
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        conn = sqlite3.connect(self.db_path, timeout=3, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
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
            for key, enabled in enabled_map.items():
                conn.execute("UPDATE adblock_lists SET enabled=? WHERE key=?", (1 if enabled else 0, key))
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
            req = urllib.request.Request(url, headers={"User-Agent": "squid-flask-proxy/icap-adblock"})
            with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
                data = resp.read()
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(tmp, "wb") as f:
                f.write(data)
            os.replace(tmp, path)

            # Rough rule count: ignore comments/blank.
            try:
                text = data.decode("utf-8", errors="replace")
                rules = 0
                for line in text.splitlines():
                    s = line.strip()
                    if not s or s.startswith("!"):
                        continue
                    rules += 1
            except Exception:
                rules = 0

            return True, "", int(len(data)), int(rules)
        except Exception as e:
            try:
                if os.path.exists(tmp):
                    os.unlink(tmp)
            except OSError:
                pass
            return False, str(e), 0, 0

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


_store: Optional[AdblockStore] = None


def get_adblock_store() -> AdblockStore:
    global _store
    if _store is None:
        _store = AdblockStore()
    return _store
