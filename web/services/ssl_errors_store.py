from __future__ import annotations

import hashlib
import logging
import os
import re
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from services.db import DATABASE_ERRORS, connect
from services.logutil import log_exception_throttled
from services.proxy_context import get_proxy_id
from services.runtime_helpers import env_float as _env_float, env_int as _env_int, escape_like as _escape_like, normalize_hostish as _normalize_hostish, now_ts as _now


logger = logging.getLogger(__name__)
@dataclass(frozen=True)
class SslErrorRow:
    domain: str
    category: str
    reason: str
    count: int
    first_seen: int
    last_seen: int
    sample: str


_TS_PREFIX = re.compile(
    r"^(?P<date>\d{4}/\d{2}/\d{2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})"
    r"(?:\|\s*|\s+[^|]+\|\s*)?"
    r"(?P<msg>.*)$"
)
_TLS_ERROR_SIGNATURE = re.compile(r"\b(SQUID_TLS_ERR_[A-Z_]+(?:\+TLS_LIB_ERR=[0-9A-F]+)?(?:\+TLS_IO_ERR=\d+)?)\b", re.I)

# Best-effort extraction of a destination domain from cache.log lines.
_DOMAIN_PATTERNS: List[re.Pattern[str]] = [
    re.compile(r"\bCONNECT\s+([A-Za-z0-9.-]+):\d+\b", re.I),
    re.compile(r"\bhttps?://([A-Za-z0-9.-]+)\b", re.I),
    re.compile(r"\bhost=([A-Za-z0-9.-]+)\b", re.I),
    re.compile(r"\bsni=([A-Za-z0-9.-]+)\b", re.I),
    re.compile(r"\bSNI\s*[:=]\s*([A-Za-z0-9.-]+)\b", re.I),
]
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
            return _normalize_hostish(m.group(1))
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


def _canonical_reason(msg: str) -> str:
    m = _TLS_ERROR_SIGNATURE.search(msg or "")
    if m:
        return m.group(1).upper()
    return _normalize_reason(msg)


def _is_tls_accept_header(msg: str) -> bool:
    sl = (msg or "").lower()
    return "cannot accept a tls connection" in sl or "failure while accepting a tls connection" in sl


def _is_tls_accept_detail(msg: str) -> bool:
    sl = (msg or "").lower()
    return "squid_tls_err_accept" in sl or ("error detail:" in sl and "tls_lib_err=" in sl)


def _extract_followup_context(line: str) -> str:
    s = (line or "").strip()
    if not s:
        return ""
    sl = s.lower()
    if sl.startswith("connection:") or sl.startswith("current master transaction:"):
        return s[:280]
    return ""


def _is_startup_noise(msg: str) -> bool:
    sl = (msg or "").lower()
    return (
        "processing configuration file:" in sl
        or ("helperopenservers: starting" in sl and "ssl_crtd" in sl)
        or "accepting ssl bumped http socket connections" in sl
    )


def _classify_ssl_error(msg: str) -> Optional[Tuple[str, str]]:
    # Returns (category, reason) or None if not SSL/TLS-related.
    s = (msg or "")
    sl = s.lower()

    # Ignore common startup/config noise that mentions ssl/tls but is not an error.
    if _is_startup_noise(s):
        return None

    # Fast keyword gate.
    if not any(k in sl for k in ("ssl", "tls", "x509", "certificate", "handshake", "bump", "openssl")):
        return None

    # Filter some noisy but not really "error" lines.
    if "accepting ssl bumped" in sl:
        return None

    if _is_tls_accept_header(s):
        return "TLS_CLIENT_ACCEPT", "Cannot accept a TLS connection"

    if "squid_tls_err_accept" in sl:
        return "TLS_CLIENT_ACCEPT", _canonical_reason(s)

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
        cache_log_path: str = "/var/log/squid/cache.log",
        seed_max_lines: int = 5000,
    ):
        self.cache_log_path = cache_log_path
        self.seed_max_lines = seed_max_lines

        self._started = False
        self._start_lock = threading.Lock()
        self._pending_error: Optional[Dict[str, Any]] = None
        self._db_initialized = False
        self._db_init_lock = threading.Lock()

    def _connect(self):
        return connect()

    def _row_key(self, proxy_id: str, domain: str, category: str, reason: str) -> str:
        return hashlib.sha1(f"{proxy_id}|{domain}|{category}|{reason}".encode("utf-8", errors="replace")).hexdigest()

    def _update_sample(self, conn, domain: str, category: str, reason: str, ts: int, sample: str) -> None:
        proxy_id = get_proxy_id()
        row_key = self._row_key(proxy_id, domain, category, reason)
        conn.execute(
            "UPDATE ssl_errors SET last_seen = GREATEST(last_seen, %s), sample = %s WHERE row_key = %s",
            (int(ts), sample[:400], row_key),
        )

    def _flush_pending_error(self, conn) -> bool:
        pending = self._pending_error
        if not pending or bool(pending.get("committed")):
            return False
        self._upsert(
            conn,
            str(pending.get("domain") or ""),
            str(pending.get("category") or "TLS_OTHER"),
            str(pending.get("reason") or ""),
            int(pending.get("ts") or _now()),
            str(pending.get("sample") or ""),
        )
        pending["committed"] = True
        return True

    def _ingest_line_with_conn(self, conn, line: str) -> bool:
        raw_line = (line or "").strip("\r\n")
        followup = _extract_followup_context(raw_line)
        if followup:
            pending = self._pending_error
            if not pending:
                return False
            current_sample = str(pending.get("sample") or "")
            if followup.lower() in current_sample.lower():
                return False
            combined = f"{current_sample}\n{followup}".strip()[:400]
            self._update_sample(
                conn,
                str(pending.get("domain") or ""),
                str(pending.get("category") or "TLS_OTHER"),
                str(pending.get("reason") or ""),
                int(pending.get("ts") or _now()),
                combined,
            )
            pending["sample"] = combined
            return True

        ts, msg = _parse_cache_log_ts(raw_line)
        classified = _classify_ssl_error(msg)
        if not classified:
            changed = False
            if (raw_line or "").strip():
                changed = self._flush_pending_error(conn)
                self._pending_error = None
            return changed
        category, reason = classified
        domain = _extract_domain(msg)
        sample = (msg or "").strip()[:400]

        pending = self._pending_error
        if pending and not bool(pending.get("committed")) and _is_tls_accept_detail(msg):
            domain = str(pending.get("domain") or domain)
            combined = f"{str(pending.get('sample') or '').strip()}\n{sample}".strip()[:400]
            self._upsert(conn, domain, category, reason, ts, combined)
            self._pending_error = {
                "ts": int(ts),
                "domain": domain,
                "category": category,
                "reason": reason,
                "sample": combined,
                "committed": True,
            }
            return True

        if _is_tls_accept_header(msg):
            self._flush_pending_error(conn)
            self._pending_error = {
                "ts": int(ts),
                "domain": domain,
                "category": category,
                "reason": reason,
                "sample": sample,
                "committed": False,
            }
            return False

        self._flush_pending_error(conn)
        self._upsert(conn, domain, category, reason, ts, sample)
        self._pending_error = {
            "ts": int(ts),
            "domain": domain,
            "category": category,
            "reason": reason,
            "sample": sample,
            "committed": True,
        }
        return True

    def init_db(self) -> None:
        if self._db_initialized:
            return
        with self._db_init_lock:
            if self._db_initialized:
                return
            with self._connect() as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS ssl_errors (
                        row_key CHAR(40) PRIMARY KEY,
                        proxy_id VARCHAR(64) NOT NULL DEFAULT 'default',
                        domain VARCHAR(255) NOT NULL,
                        category VARCHAR(64) NOT NULL,
                        reason VARCHAR(300) NOT NULL,
                        count BIGINT NOT NULL DEFAULT 0,
                        first_seen BIGINT NOT NULL,
                        last_seen BIGINT NOT NULL,
                        sample TEXT NOT NULL,
                        KEY idx_ssl_errors_proxy_last_seen (proxy_id, last_seen),
                        KEY idx_ssl_errors_proxy_domain (proxy_id, domain, last_seen),
                        KEY idx_ssl_errors_proxy_category (proxy_id, category, last_seen)
                    )
                    """
                )

                self._cleanup_known_false_positives(conn)

                # Retention: keep aggregates that have been seen recently.
                cutoff = _now() - (30 * 24 * 60 * 60)
                conn.execute("DELETE FROM ssl_errors WHERE last_seen < %s", (cutoff,))
            self._db_initialized = True

    def prune_old_entries(self, *, retention_days: int = 30) -> None:
        self.init_db()
        days = max(1, int(retention_days or 30))
        cutoff = _now() - (days * 24 * 60 * 60)
        with self._connect() as conn:
            conn.execute("DELETE FROM ssl_errors WHERE last_seen < %s", (int(cutoff),))

    def _upsert(self, conn, domain: str, category: str, reason: str, ts: int, sample: str) -> None:
        proxy_id = get_proxy_id()
        row_key = self._row_key(proxy_id, domain, category, reason)
        conn.execute(
            """
            INSERT INTO ssl_errors(row_key, proxy_id, domain, category, reason, count, first_seen, last_seen, sample)
            VALUES(%s,%s,%s,%s,%s,1,%s,%s,%s)
            ON DUPLICATE KEY UPDATE
                count = count + 1,
                first_seen = LEAST(first_seen, VALUES(first_seen)),
                last_seen = GREATEST(last_seen, VALUES(last_seen)),
                sample = VALUES(sample);
            """,
            (row_key, proxy_id, domain, category, reason, ts, ts, sample[:400]),
        )

    def _latest_seen_ts(self, conn) -> int:
        proxy_id = get_proxy_id()
        row = conn.execute(
            "SELECT COALESCE(MAX(last_seen), 0) FROM ssl_errors WHERE proxy_id = %s",
            (proxy_id,),
        ).fetchone()
        return int((row[0] if row else 0) or 0)

    def _cleanup_known_false_positives(self, conn) -> None:
        proxy_id = get_proxy_id()
        conn.execute(
            """
            DELETE FROM ssl_errors
            WHERE proxy_id = %s
                            AND (reason LIKE %s OR sample LIKE %s)
            """,
            (proxy_id, "%Processing Configuration File:%", "%Processing Configuration File:%"),
        )

    def ingest_line(self, line: str) -> None:
        self.init_db()
        with self._connect() as conn:
            self._ingest_line_with_conn(conn, line)

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
        self.init_db()
        lines = self._read_last_lines(self.seed_max_lines)
        if not lines:
            return
        with self._connect() as conn:
            latest_seen_ts = self._latest_seen_ts(conn)
            for line in lines:
                ts, _msg = _parse_cache_log_ts(line)
                if latest_seen_ts and ts <= latest_seen_ts:
                    continue
                self._ingest_line_with_conn(conn, line)
            self._flush_pending_error(conn)

    def list_recent(self, *, since: Optional[int] = None, search: str = "", limit: int = 200) -> List[SslErrorRow]:
        self.init_db()
        where = ["proxy_id = %s"]
        params: List[Any] = [get_proxy_id()]
        if since is not None:
            where.append("last_seen >= %s")
            params.append(int(since))
        if search:
            where.append("domain LIKE %s ESCAPE '\\\\'")
            params.append(f"%{_escape_like(search)}%")
        where_sql = ("WHERE " + " AND ".join(where)) if where else ""
        lim = max(10, min(500, int(limit)))
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT domain, category, reason, count, first_seen, last_seen, sample FROM ssl_errors {where_sql} ORDER BY last_seen DESC LIMIT %s",
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
        self.init_db()
        where = ["proxy_id = %s"]
        params: List[Any] = [get_proxy_id()]
        if since is not None:
            where.append("last_seen >= %s")
            params.append(int(since))
        if search:
            where.append("domain LIKE %s ESCAPE '\\\\'")
            params.append(f"%{_escape_like(search)}%")
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
                LIMIT %s
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
            t = threading.Thread(target=self._tail_loop, name="ssl-errors-tailer", daemon=True)
            t.start()

    def _tail_loop(self) -> None:
        commit_batch = _env_int("SSL_ERRORS_COMMIT_BATCH", 200, minimum=25, maximum=5000)
        commit_interval = _env_float("SSL_ERRORS_COMMIT_INTERVAL_SECONDS", 2.0, minimum=0.25, maximum=10.0)
        poll_interval = _env_float("SSL_ERRORS_POLL_INTERVAL_SECONDS", 0.75, minimum=0.1, maximum=5.0)

        path = self.cache_log_path
        last_inode: Optional[int] = None
        seeded_recent_log = False

        while True:
            try:
                self.init_db()
                if not seeded_recent_log:
                    self.seed_from_recent_log()
                    seeded_recent_log = True

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
                                            "ssl_errors_store.rollback.ingest",
                                            interval_seconds=300.0,
                                            message="SSL errors tailer rollback failed after ingest error",
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
                                                "ssl_errors_store.rollback.commit",
                                                interval_seconds=300.0,
                                                message="SSL errors tailer rollback failed after commit error",
                                            )
                                    pending = 0
                                    last_commit = now
                                continue

                            # EOF/idle: commit pending rows so results don't lag.
                            now = time.time()
                            if self._flush_pending_error(conn):
                                pending += 1
                            if pending and (now - last_commit) >= commit_interval:
                                try:
                                    conn.commit()
                                except Exception:
                                    try:
                                        conn.rollback()
                                    except Exception:
                                        log_exception_throttled(
                                            logger,
                                            "ssl_errors_store.rollback.idle_commit",
                                            interval_seconds=300.0,
                                            message="SSL errors tailer rollback failed after idle commit error",
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
                                    "ssl_errors_store.copytruncate",
                                    interval_seconds=300.0,
                                    message="SSL errors tailer copytruncate check failed",
                                )

                            # Detect rotation/recreate.
                            try:
                                st2 = os.stat(path)
                                inode2 = getattr(st2, "st_ino", None)
                            except OSError:
                                inode2 = None

                            if inode2 is not None and last_inode is not None and inode2 != last_inode:
                                last_inode = inode2
                                self._flush_pending_error(conn)
                                try:
                                    conn.commit()
                                except Exception:
                                    log_exception_throttled(
                                        logger,
                                        "ssl_errors_store.commit.rotate",
                                        interval_seconds=300.0,
                                        message="SSL errors tailer final commit failed during rotation",
                                    )
                                break

                            time.sleep(poll_interval)
            except Exception:
                log_exception_throttled(
                    logger,
                    "ssl_errors_store.loop",
                    interval_seconds=300.0,
                    message="SSL errors tailer loop failed",
                )
                time.sleep(max(1.0, poll_interval))

    def list_errors(self, limit: int = 200) -> List[Dict[str, Any]]:
        self.init_db()
        lim = max(10, min(1000, int(limit)))
        proxy_id = get_proxy_id()
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT domain, category, reason, count, first_seen, last_seen, sample FROM ssl_errors WHERE proxy_id=%s ORDER BY last_seen DESC, count DESC LIMIT %s",
                (proxy_id, lim),
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
_store_lock = threading.Lock()


def get_ssl_errors_store() -> SslErrorsStore:
    global _store
    if _store is not None:
        return _store
    with _store_lock:
        if _store is None:
            _store = SslErrorsStore()
            try:
                _store.init_db()
            except DATABASE_ERRORS:
                log_exception_throttled(
                    logger,
                    "ssl_errors_store.init_db",
                    interval_seconds=300.0,
                    message="SSL errors store database initialization failed; proxy runtime will retry lazily.",
                )
        return _store
