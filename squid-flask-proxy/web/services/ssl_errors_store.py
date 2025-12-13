from __future__ import annotations

import os
import re
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


@dataclass(frozen=True)
class SslErrorRow:
    domain: str
    category: str
    reason: str
    count: int
    first_seen: int
    last_seen: int
    sample: str


_TS_PREFIX = re.compile(r"^(?P<date>\d{4}/\d{2}/\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})\|\s*(?P<msg>.*)$")

# Best-effort extraction of a destination domain from cache.log lines.
_DOMAIN_PATTERNS: List[re.Pattern[str]] = [
    re.compile(r"\bCONNECT\s+([A-Za-z0-9.-]+):\d+\b", re.I),
    re.compile(r"\bhttps?://([A-Za-z0-9.-]+)\b", re.I),
    re.compile(r"\bhost=([A-Za-z0-9.-]+)\b", re.I),
    re.compile(r"\bsni=([A-Za-z0-9.-]+)\b", re.I),
    re.compile(r"\bSNI\s*[:=]\s*([A-Za-z0-9.-]+)\b", re.I),
]


def _now() -> int:
    return int(time.time())


def _parse_cache_log_ts(line: str) -> Tuple[int, str]:
    s = (line or "").strip("\r\n")
    m = _TS_PREFIX.match(s)
    if not m:
        return _now(), s
    try:
        # cache.log timestamps are localtime inside the container; treat as local.
        t = time.strptime(f"{m.group('date')} {m.group('time')}", "%Y/%m/%d %H:%M:%S")
        return int(time.mktime(t)), m.group("msg")
    except Exception:
        return _now(), m.group("msg")


def _extract_domain(msg: str) -> str:
    for pat in _DOMAIN_PATTERNS:
        m = pat.search(msg)
        if m:
            return (m.group(1) or "").lower()
    return ""


def _normalize_reason(msg: str) -> str:
    # Keep it stable-ish for grouping.
    s = (msg or "").strip()
    # Drop leading module/pid prefixes like "kid1|" if present.
    s = re.sub(r"^kid\d+\|\s*", "", s, flags=re.I)
    # Remove IPs, ports, hex-ish IDs, and long numbers.
    s = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "<ip>", s)
    s = re.sub(r":\d{2,5}\b", ":<port>", s)
    s = re.sub(r"\b0x[0-9a-fA-F]+\b", "<hex>", s)
    s = re.sub(r"\b\d{4,}\b", "<n>", s)
    # Collapse whitespace.
    s = re.sub(r"\s+", " ", s)
    return s[:300]


def _classify_ssl_error(msg: str) -> Optional[Tuple[str, str]]:
    # Returns (category, reason) or None if not SSL/TLS-related.
    s = (msg or "")
    sl = s.lower()

    # Fast keyword gate.
    if not any(k in sl for k in ("ssl", "tls", "x509", "certificate", "handshake", "bump", "openssl")):
        return None

    # Filter some noisy but not really "error" lines.
    if "accepting ssl bumped" in sl:
        return None

    # Prefer explicit OpenSSL-ish errors.
    if "x509" in sl or "certificate" in sl:
        if "verify" in sl or "unknown ca" in sl or "unable to get local issuer" in sl:
            return "CERT_VERIFY", _normalize_reason(s)
        if "expired" in sl:
            return "CERT_EXPIRED", _normalize_reason(s)
        if "hostname" in sl or "name mismatch" in sl:
            return "CERT_NAME", _normalize_reason(s)
        return "CERT", _normalize_reason(s)

    if "handshake" in sl:
        return "TLS_HANDSHAKE", _normalize_reason(s)

    if "no shared cipher" in sl or "cipher" in sl:
        return "TLS_CIPHER", _normalize_reason(s)

    if "protocol" in sl and ("unsupported" in sl or "wrong version" in sl or "version" in sl):
        return "TLS_PROTOCOL", _normalize_reason(s)

    if "ssl_bump" in sl or "bump" in sl:
        return "SSL_BUMP", _normalize_reason(s)

    # Generic fallback.
    return "TLS_OTHER", _normalize_reason(s)


class SslErrorsStore:
    def __init__(
        self,
        db_path: str = "/var/lib/squid-flask-proxy/ssl_errors.db",
        cache_log_path: str = "/var/log/squid/cache.log",
        seed_max_lines: int = 5000,
    ):
        self.db_path = db_path
        self.cache_log_path = cache_log_path
        self.seed_max_lines = seed_max_lines

        self._started = False
        self._start_lock = threading.Lock()

    def _connect(self) -> sqlite3.Connection:
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        conn = sqlite3.connect(self.db_path, timeout=3, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS ssl_errors (
                    key TEXT PRIMARY KEY,
                    domain TEXT NOT NULL,
                    category TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    count INTEGER NOT NULL DEFAULT 0,
                    first_seen INTEGER NOT NULL,
                    last_seen INTEGER NOT NULL,
                    sample TEXT NOT NULL
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ssl_errors_last_seen ON ssl_errors(last_seen DESC);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ssl_errors_domain ON ssl_errors(domain, last_seen DESC);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ssl_errors_category ON ssl_errors(category, last_seen DESC);")

            # Retention: keep aggregates that have been seen recently.
            cutoff = _now() - (90 * 24 * 60 * 60)
            conn.execute("DELETE FROM ssl_errors WHERE last_seen < ?", (cutoff,))

    def _upsert(self, conn: sqlite3.Connection, domain: str, category: str, reason: str, ts: int, sample: str) -> None:
        key = f"{domain}|{category}|{reason}"
        conn.execute(
            """
            INSERT INTO ssl_errors(key, domain, category, reason, count, first_seen, last_seen, sample)
            VALUES(?,?,?,?,1,?,?,?)
            ON CONFLICT(key) DO UPDATE SET
                count = count + 1,
                first_seen = MIN(first_seen, excluded.first_seen),
                last_seen = MAX(last_seen, excluded.last_seen),
                sample = excluded.sample;
            """,
            (key, domain, category, reason, ts, ts, sample[:400]),
        )

    def ingest_line(self, line: str) -> None:
        ts, msg = _parse_cache_log_ts(line)
        classified = _classify_ssl_error(msg)
        if not classified:
            return
        category, reason = classified
        domain = _extract_domain(msg)
        sample = (msg or "").strip()[:400]

        with self._connect() as conn:
            self._upsert(conn, domain, category, reason, ts, sample)

    def _read_last_lines(self, max_lines: int) -> List[str]:
        path = self.cache_log_path
        if not os.path.exists(path):
            return []
        try:
            with open(path, "rb") as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                read_size = min(size, max_lines * 260)
                if read_size > 0:
                    f.seek(-read_size, os.SEEK_END)
                chunk = f.read().decode("utf-8", errors="replace")
            return chunk.splitlines()[-max_lines:]
        except Exception:
            return []

    def seed_from_recent_log(self) -> None:
        lines = self._read_last_lines(self.seed_max_lines)
        if not lines:
            return
        with self._connect() as conn:
            for line in lines:
                ts, msg = _parse_cache_log_ts(line)
                classified = _classify_ssl_error(msg)
                if not classified:
                    continue
                category, reason = classified
                domain = _extract_domain(msg)
                sample = (msg or "").strip()[:400]
                self._upsert(conn, domain, category, reason, ts, sample)

    def list_recent(self, *, since: Optional[int] = None, search: str = "", limit: int = 200) -> List[SslErrorRow]:
        where = []
        params: List[Any] = []
        if since is not None:
            where.append("last_seen >= ?")
            params.append(int(since))
        if search:
            where.append("domain LIKE ?")
            params.append(f"%{search}%")
        where_sql = ("WHERE " + " AND ".join(where)) if where else ""
        lim = max(10, min(500, int(limit)))
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT domain, category, reason, count, first_seen, last_seen, sample FROM ssl_errors {where_sql} ORDER BY last_seen DESC LIMIT ?",
                tuple(params + [lim]),
            ).fetchall()
        return [
            SslErrorRow(
                domain=str(r[0]),
                category=str(r[1]),
                reason=str(r[2]),
                count=int(r[3]),
                first_seen=int(r[4]),
                last_seen=int(r[5]),
                sample=str(r[6]),
            )
            for r in rows
        ]

    def top_domains(self, *, since: Optional[int] = None, search: str = "", limit: int = 20) -> List[Dict[str, Any]]:
        where = []
        params: List[Any] = []
        if since is not None:
            where.append("last_seen >= ?")
            params.append(int(since))
        if search:
            where.append("domain LIKE ?")
            params.append(f"%{search}%")
        where_sql = ("WHERE " + " AND ".join(where)) if where else ""
        lim = max(5, min(100, int(limit)))
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT domain, COUNT(*) AS buckets, SUM(count) AS total, MAX(last_seen) AS last_seen
                FROM ssl_errors
                {where_sql}
                GROUP BY domain
                ORDER BY total DESC, last_seen DESC
                LIMIT ?
                """,
                tuple(params + [lim]),
            ).fetchall()
        return [
            {
                "domain": str(r[0] or ''),
                "buckets": int(r[1] or 0),
                "total": int(r[2] or 0),
                "last_seen": int(r[3] or 0),
            }
            for r in rows
        ]

    def start_background(self) -> None:
        with self._start_lock:
            if self._started:
                return
            self._started = True

        self.init_db()
        t = threading.Thread(target=self._tail_loop, name="ssl-errors-tailer", daemon=True)
        t.start()

    def _tail_loop(self) -> None:
        self.seed_from_recent_log()

        path = self.cache_log_path
        last_inode: Optional[int] = None

        while True:
            try:
                if not os.path.exists(path):
                    time.sleep(1.0)
                    continue

                st = os.stat(path)
                inode = getattr(st, "st_ino", None)
                if last_inode is None:
                    last_inode = inode

                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    f.seek(0, os.SEEK_END)
                    while True:
                        line = f.readline()
                        if line:
                            self.ingest_line(line)
                            continue

                        try:
                            st2 = os.stat(path)
                            inode2 = getattr(st2, "st_ino", None)
                        except OSError:
                            inode2 = None

                        if inode2 is not None and last_inode is not None and inode2 != last_inode:
                            last_inode = inode2
                            break

                        time.sleep(0.5)
            except Exception:
                time.sleep(1.0)

    def list_errors(self, limit: int = 200) -> List[Dict[str, Any]]:
        lim = max(10, min(1000, int(limit)))
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT domain, category, reason, count, first_seen, last_seen, sample FROM ssl_errors ORDER BY last_seen DESC, count DESC LIMIT ?",
                (lim,),
            ).fetchall()

        out: List[Dict[str, Any]] = []
        for r in rows:
            out.append(
                {
                    "domain": str(r[0] or ""),
                    "category": str(r[1] or ""),
                    "reason": str(r[2] or ""),
                    "count": int(r[3] or 0),
                    "first_seen": int(r[4] or 0),
                    "last_seen": int(r[5] or 0),
                    "sample": str(r[6] or ""),
                }
            )
        return out


_store: Optional[SslErrorsStore] = None


def get_ssl_errors_store() -> SslErrorsStore:
    global _store
    if _store is None:
        _store = SslErrorsStore()
        _store.init_db()
    return _store
