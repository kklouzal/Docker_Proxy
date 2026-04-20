from __future__ import annotations

import logging
import os
import re
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from services.db import connect, create_index_if_not_exists
from services.logutil import log_exception_throttled


logger = logging.getLogger(__name__)


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


def _escape_like(value: str) -> str:
    """Escape special LIKE pattern characters for safe SQL queries."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


@dataclass(frozen=True)
class SocksEventRow:
    ts: int
    action: str
    protocol: str
    src_ip: str
    src_port: int
    dst: str
    dst_port: int
    msg: str


def _now() -> int:
    return int(time.time())


# Dante log lines often include an epoch-ish float in parentheses:
#  Dec 12 22:33:24 (1765578804.943147) sockd[32]: ...
_EPOCH_IN_PARENS = re.compile(r"\((?P<epoch>\d{9,12})(?:\.\d+)?\)")

# Dante often prints endpoints as ip.port using a dot separator:
#  172.18.0.2.37614
_IP_PORT_DOT = re.compile(r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\.(?P<port>\d{1,5})")

# Best-effort extraction of endpoint pairs.
_FROM_TO_PATTERNS: List[re.Pattern[str]] = [
    re.compile(
        r"\bfrom\s+(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})[:.](?P<src_port>\d{1,5})\s+to\s+(?P<dst>[A-Za-z0-9._-]+|\d{1,3}(?:\.\d{1,3}){3})[:.](?P<dst_port>\d{1,5})\b",
        re.I,
    ),
    re.compile(
        r"\bfrom\s+(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})\s+to\s+(?P<dst>[A-Za-z0-9._-]+|\d{1,3}(?:\.\d{1,3}){3})[:.](?P<dst_port>\d{1,5})\b",
        re.I,
    ),
]



def _parse_ts(line: str) -> int:
    m = _EPOCH_IN_PARENS.search(line or "")
    if not m:
        return _now()
    try:
        return int(float(m.group("epoch")))
    except Exception:
        return _now()


def _classify(line: str) -> Tuple[str, str]:
    s = (line or "").lower()

    # Dante uses "client pass"/"socks pass" rules; log lines can vary.
    # We keep this intentionally loose and stable.
    if "block(" in s or "blocked" in s or " deny" in s or "denied" in s:
        return "blocked", ""
    if "disconnect" in s:
        return "disconnect", ""
    if "connect" in s:
        return "connect", ""
    if "error" in s or "fail" in s or "warning" in s:
        return "error", ""
    return "info", ""


def _extract_protocol(line: str) -> str:
    s = (line or "").lower()
    # Many logs include protocol hints; if absent, keep unknown.
    if " udp" in s or "udp" in s:
        return "udp"
    if " tcp" in s or "tcp" in s:
        return "tcp"
    return "unknown"


def _extract_endpoints(line: str) -> Tuple[str, int, str, int]:
    s = (line or "")

    # Prefer ip.port tokens since they occur in both accept and connect lines.
    # Use the first as source and the last as destination.
    dot_tokens = _IP_PORT_DOT.findall(s)
    if dot_tokens:
        try:
            src_ip, src_port_s = dot_tokens[0]
            dst_ip, dst_port_s = dot_tokens[-1]
            return src_ip, int(src_port_s), dst_ip.lower(), int(dst_port_s)
        except Exception:
            log_exception_throttled(
                logger,
                "socks_store.extract_endpoints.dot",
                interval_seconds=300.0,
                message="Failed to parse SOCKS endpoints from ip.port tokens",
            )
    for pat in _FROM_TO_PATTERNS:
        m = pat.search(s)
        if not m:
            continue
        src_ip = (m.groupdict().get("src_ip") or "").strip()
        src_port_s = (m.groupdict().get("src_port") or "0").strip()
        dst = (m.groupdict().get("dst") or "").strip()
        dst_port_s = (m.groupdict().get("dst_port") or "0").strip()
        try:
            src_port = int(src_port_s)
        except Exception:
            src_port = 0
        try:
            dst_port = int(dst_port_s)
        except Exception:
            dst_port = 0
        return src_ip, src_port, dst.lower(), dst_port
    return "", 0, "", 0


class SocksStore:
    def __init__(
        self,
        log_path: str = "/var/log/sockd.log",
        seed_max_lines: int = 5000,
        retention_days: int = 30,
    ):
        self.log_path = log_path
        self.seed_max_lines = seed_max_lines
        self.retention_days = retention_days

        self._started = False
        self._start_lock = threading.Lock()

    def _connect(self):
        return connect()

    def _ingest_line_with_conn(self, conn, line: str) -> bool:
        s = (line or "").strip("\r\n")
        if not s:
            return False

        # Avoid counting config/startup warnings as traffic events.
        sl = s.lower()
        if "checkconfig()" in sl:
            return False

        # The Docker health-check sends a 3-byte SOCKS5 version probe every
        # ~15 s from 127.0.0.1 which Dante logs as a block "eof from local
        # client".  These dominate the DB (~50 % of rows) and are not useful.
        if "127.0.0.1" in s and "eof from local client" in sl:
            return False

        # Local and external SOCKS accept lines only show that a client opened a
        # socket to Dante itself (for example, container health checks or the
        # initial client handshake). They do not identify the upstream
        # destination and drown out the useful connect/block/error rows.
        if "pass(" in sl and "/accept" in sl:
            return False

        ts = _parse_ts(s)
        action, _ = _classify(s)
        protocol = _extract_protocol(s)
        src_ip, src_port, dst, dst_port = _extract_endpoints(s)

        conn.execute(
            "INSERT INTO socks_events(ts, action, protocol, src_ip, src_port, dst, dst_port, msg) VALUES(?,?,?,?,?,?,?,?)",
            (ts, action, protocol, src_ip, int(src_port or 0), dst, int(dst_port or 0), s[:600]),
        )
        # Cheap periodic prune.
        if (ts % 97) == 0:
            self._prune(conn)
        return True

    def init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS socks_events (
                    id BIGINT PRIMARY KEY AUTO_INCREMENT,
                    ts BIGINT NOT NULL,
                    action VARCHAR(32) NOT NULL,
                    protocol VARCHAR(32) NOT NULL,
                    src_ip VARCHAR(64) NOT NULL,
                    src_port INT NOT NULL,
                    dst VARCHAR(255) NOT NULL,
                    dst_port INT NOT NULL,
                    msg TEXT NOT NULL
                )
                """
            )
            create_index_if_not_exists(conn, table_name="socks_events", index_name="idx_socks_events_ts", columns_sql="ts")
            create_index_if_not_exists(conn, table_name="socks_events", index_name="idx_socks_events_src", columns_sql="src_ip, ts")
            create_index_if_not_exists(conn, table_name="socks_events", index_name="idx_socks_events_dst", columns_sql="dst, ts")
            self._prune(conn)

    def _prune(self, conn) -> None:
        cutoff = _now() - int(self.retention_days * 24 * 60 * 60)
        conn.execute("DELETE FROM socks_events WHERE ts < ?", (cutoff,))

    def prune_old_entries(self, *, retention_days: int = 30) -> None:
        days = max(1, int(retention_days or 30))
        cutoff = _now() - int(days * 24 * 60 * 60)
        with self._connect() as conn:
            conn.execute("DELETE FROM socks_events WHERE ts < ?", (int(cutoff),))

    def ingest_line(self, line: str) -> None:
        with self._connect() as conn:
            self._ingest_line_with_conn(conn, line)

    def _read_last_lines(self, max_lines: int) -> List[str]:
        path = self.log_path
        if not os.path.exists(path):
            return []
        try:
            with open(path, "rb") as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                read_size = min(size, max_lines * 300)
                if read_size > 0:
                    f.seek(-read_size, os.SEEK_END)
                chunk = f.read().decode("utf-8", errors="replace")
            return chunk.splitlines()[-max_lines:]
        except Exception:
            return []

    def seed_from_recent_log(self) -> None:
        # Only seed when empty to avoid duplicating historical log lines on restarts.
        try:
            with self._connect() as conn:
                n = conn.execute("SELECT COUNT(*) AS n FROM socks_events").fetchone()[0]
                if int(n or 0) > 0:
                    return
        except Exception:
            # If we can't check, fall back to seeding.
            pass

        lines = self._read_last_lines(self.seed_max_lines)
        if not lines:
            return
        with self._connect() as conn:
            for line in lines:
                try:
                    self._ingest_line_with_conn(conn, line)
                except Exception:
                    continue

    def start_background(self) -> None:
        with self._start_lock:
            if self._started:
                return
            self._started = True
            self.init_db()
            t = threading.Thread(target=self._tail_loop, name="socks-tailer", daemon=True)
            t.start()

    def _tail_loop(self) -> None:
        self.seed_from_recent_log()

        commit_batch = _env_int("SOCKS_COMMIT_BATCH", 200, minimum=25, maximum=5000)
        commit_interval = _env_float("SOCKS_COMMIT_INTERVAL_SECONDS", 2.0, minimum=0.25, maximum=10.0)
        poll_interval = _env_float("SOCKS_POLL_INTERVAL_SECONDS", 0.75, minimum=0.1, maximum=5.0)

        path = self.log_path
        last_inode: Optional[int] = None

        while True:
            try:
                if not os.path.exists(path):
                    time.sleep(max(1.0, poll_interval))
                    continue

                st = os.stat(path)
                inode = getattr(st, "st_ino", None)
                if last_inode is None:
                    last_inode = inode

                with self._connect() as conn:
                    pending = 0
                    last_commit = time.time()
                    with open(path, "r", encoding="utf-8", errors="replace") as f:
                        f.seek(0, os.SEEK_END)
                        while True:
                            line = f.readline()
                            if line:
                                try:
                                    if self._ingest_line_with_conn(conn, line):
                                        pending += 1
                                except Exception:
                                    try:
                                        conn.rollback()
                                    except Exception:
                                        log_exception_throttled(
                                            logger,
                                            "socks_store.rollback.ingest",
                                            interval_seconds=300.0,
                                            message="SOCKS tailer rollback failed after ingest error",
                                        )
                                now = time.time()
                                if pending >= commit_batch or (now - last_commit) >= commit_interval:
                                    try:
                                        conn.commit()
                                    except Exception:
                                        try:
                                            conn.rollback()
                                        except Exception:
                                            log_exception_throttled(
                                                logger,
                                                "socks_store.rollback.commit",
                                                interval_seconds=300.0,
                                                message="SOCKS tailer rollback failed after commit error",
                                            )
                                    pending = 0
                                    last_commit = now
                                continue

                            # EOF/idle: commit pending rows so the UI stays fresh.
                            now = time.time()
                            if pending and (now - last_commit) >= commit_interval:
                                try:
                                    conn.commit()
                                except Exception:
                                    try:
                                        conn.rollback()
                                    except Exception:
                                        log_exception_throttled(
                                            logger,
                                            "socks_store.rollback.idle_commit",
                                            interval_seconds=300.0,
                                            message="SOCKS tailer rollback failed after idle commit error",
                                        )
                                pending = 0
                                last_commit = now

                            # Handle copytruncate: inode unchanged but file shrinks.
                            try:
                                if os.path.getsize(path) < f.tell():
                                    f.seek(0, os.SEEK_SET)
                                    continue
                            except Exception:
                                log_exception_throttled(
                                    logger,
                                    "socks_store.copytruncate",
                                    interval_seconds=300.0,
                                    message="SOCKS tailer copytruncate check failed",
                                )

                            # Detect rotation/recreate.
                            try:
                                st2 = os.stat(path)
                                inode2 = getattr(st2, "st_ino", None)
                            except OSError:
                                inode2 = None

                            if inode2 is not None and last_inode is not None and inode2 != last_inode:
                                last_inode = inode2
                                try:
                                    conn.commit()
                                except Exception:
                                    log_exception_throttled(
                                        logger,
                                        "socks_store.commit.rotate",
                                        interval_seconds=300.0,
                                        message="SOCKS tailer final commit failed during rotation",
                                    )
                                break

                            time.sleep(poll_interval)

            except Exception:
                log_exception_throttled(
                    logger,
                    "socks_store.loop",
                    interval_seconds=300.0,
                    message="SOCKS tailer loop failed",
                )
                time.sleep(max(1.0, poll_interval))

    def summary(self, since: int) -> Dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT
                    COUNT(*) AS total,
                    SUM(CASE WHEN action = 'connect' THEN 1 ELSE 0 END) AS connects,
                    SUM(CASE WHEN action = 'disconnect' THEN 1 ELSE 0 END) AS disconnects,
                    SUM(CASE WHEN action = 'blocked' THEN 1 ELSE 0 END) AS blocked,
                    SUM(CASE WHEN action = 'error' THEN 1 ELSE 0 END) AS errors
                FROM socks_events
                WHERE ts >= ?
                """,
                (since,),
            ).fetchone()
            return dict(row or {})

    def top_clients(self, since: int, limit: int = 20, search: str = "") -> List[Dict[str, Any]]:
        like = None
        params: List[Any] = [since]
        where = "WHERE ts >= ? AND src_ip != ''"
        if search:
            like = f"%{_escape_like(search)}%"
            where += " AND src_ip LIKE ? ESCAPE '\\'"
            params.append(like)
        sql = f"""
            SELECT src_ip, COUNT(*) AS events,
                   SUM(CASE WHEN action = 'connect' THEN 1 ELSE 0 END) AS connects,
                   SUM(CASE WHEN action = 'blocked' THEN 1 ELSE 0 END) AS blocked,
                   MAX(ts) AS last_seen
            FROM socks_events
            {where}
            GROUP BY src_ip
            ORDER BY events DESC
            LIMIT ?
            """
        with self._connect() as conn:
            rows = conn.execute(sql, tuple(params + [int(limit)])).fetchall()
            return [dict(r) for r in rows]

    def top_destinations(self, since: int, limit: int = 20, search: str = "") -> List[Dict[str, Any]]:
        like = None
        params: List[Any] = [since]
        where = "WHERE ts >= ? AND dst != ''"
        if search:
            like = f"%{_escape_like(search)}%"
            where += " AND dst LIKE ? ESCAPE '\\'"
            params.append(like)
        sql = f"""
            SELECT dst, dst_port, COUNT(*) AS events,
                   SUM(CASE WHEN action = 'connect' THEN 1 ELSE 0 END) AS connects,
                   SUM(CASE WHEN action = 'blocked' THEN 1 ELSE 0 END) AS blocked,
                   MAX(ts) AS last_seen
            FROM socks_events
            {where}
            GROUP BY dst, dst_port
            ORDER BY events DESC
            LIMIT ?
            """
        with self._connect() as conn:
            rows = conn.execute(sql, tuple(params + [int(limit)])).fetchall()
            return [dict(r) for r in rows]

    def recent(self, limit: int = 200, since: Optional[int] = None, search: str = "") -> List[SocksEventRow]:
        where = []
        params: List[Any] = []
        if since is not None:
            where.append("ts >= ?")
            params.append(int(since))
        if search:
            escaped = _escape_like(search)
            where.append("(src_ip LIKE ? ESCAPE '\\' OR dst LIKE ? ESCAPE '\\')")
            params.extend([f"%{escaped}%", f"%{escaped}%"])
        where_sql = ("WHERE " + " AND ".join(where)) if where else ""
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT ts, action, protocol, src_ip, src_port, dst, dst_port, msg
                FROM socks_events
                {where_sql}
                ORDER BY ts DESC, id DESC
                LIMIT ?
                """,
                tuple(params + [int(limit)]),
            ).fetchall()
            return [
                SocksEventRow(
                    ts=int(r["ts"]),
                    action=str(r["action"]),
                    protocol=str(r["protocol"]),
                    src_ip=str(r["src_ip"]),
                    src_port=int(r["src_port"]),
                    dst=str(r["dst"]),
                    dst_port=int(r["dst_port"]),
                    msg=str(r["msg"]),
                )
                for r in rows
            ]


_store: Optional[SocksStore] = None
_store_lock = threading.Lock()


def get_socks_store() -> SocksStore:
    global _store
    if _store is not None:
        return _store
    with _store_lock:
        if _store is None:
            _store = SocksStore()
        return _store
