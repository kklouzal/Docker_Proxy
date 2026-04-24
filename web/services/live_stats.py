from __future__ import annotations

import hashlib
import logging
import os
import threading
import time
import csv
import io
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from services.db import connect
from services.logutil import log_exception_throttled
from services.proxy_context import get_proxy_id
from services.runtime_helpers import env_float as _env_float, env_int as _env_int, now_ts as _now


logger = logging.getLogger(__name__)


def _escape_like(value: str) -> str:
    """Escape special LIKE pattern characters for safe SQL queries."""
    # Escape %, _, and \\ itself so callers can safely use LIKE-based filtering.
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


@dataclass
class Row:
    key: str
    requests: int
    hit_requests: int
    bytes: int
    hit_bytes: int
    first_seen: int
    last_seen: int
def _pct(numer: int, denom: int) -> float:
    if denom <= 0:
        return 0.0
    return 100.0 * float(numer) / float(denom)


def _is_hit(result_code: str) -> bool:
    # Examples: TCP_HIT/200, TCP_MEM_HIT/200, TCP_IMS_HIT/304, TCP_REFRESH_HIT/200
    # Treat any HIT (except denied) as cache hit.
    if not result_code:
        return False
    if result_code.startswith("TCP_DENIED"):
        return False
    return "HIT" in result_code


def _extract_domain(url: str) -> Optional[str]:
    try:
        raw = (url or "").strip()
        if not raw:
            return None

        parts = urlsplit(raw)
        host = parts.hostname
        if host:
            return host.lower()

        # Handle CONNECT-style URLs without scheme (e.g., "example.com:443").
        # Also tolerate bare hostnames with no scheme or path.
        cand = raw.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        if "@" in cand:
            cand = cand.split("@", 1)[1]
        if cand.startswith("[") and "]" in cand:
            # IPv6 literal like [::1]:443
            host_part = cand[1 : cand.find("]")]
            return host_part.lower() if host_part else None
        if ":" in cand:
            host_part, port = cand.rsplit(":", 1)
            if port.isdigit():
                cand = host_part
        cand = cand.strip().lower()
        return cand or None
    except Exception:
        return None


def _parse_access_log_line(line: str) -> Optional[Tuple[int, str, str, int, Optional[str], str]]:
    # Supported input is the current structured TSV logformat emitted by
    # squid.conf.template.
    s = (line or "").strip("\r\n")
    if not s:
        return None

    # Structured TSV format. In Squid logformat, "\t" is emitted literally, so we
    # support both actual tabs and the two-character sequence "\\t".
    if "\t" in s or "\\t" in s:
        if "\\t" in s and "\t" not in s:
            s = s.replace("\\t", "\t")
        try:
            row = next(csv.reader(io.StringIO(s), delimiter="\t", quotechar='"'))
        except Exception:
            row = []
        if len(row) < 7:
            return None

        try:
            ts = int(float(row[0]))
        except ValueError:
            ts = _now()
        client_ip = row[2]
        method = row[3]
        url = row[4]
        result_code = row[5]
        try:
            size_bytes = int(row[6])
        except ValueError:
            size_bytes = 0
        domain = _extract_domain(url)
        return ts, client_ip, result_code, max(size_bytes, 0), domain, method

    return None


def _derive_not_cached_reason(method: str, result_code: str) -> str:
    # Best-effort reasons based on the current result/status column and method.
    m = (method or "").upper()
    rc = (result_code or "").upper()

    status: Optional[int] = None
    try:
        if "/" in rc:
            status = int(rc.rsplit("/", 1)[1])
    except Exception:
        status = None

    if m and m not in ("GET", "HEAD", "CONNECT"):
        return f"{m} method (not cacheable by default)"

    if m == "CONNECT" or rc.startswith("TCP_TUNNEL") or rc.startswith("TCP_CONNECT"):
        return "HTTPS tunnel (CONNECT) — not cacheable without SSL-bump"

    if status is not None:
        if status in (301, 302, 303, 307, 308):
            return f"Redirect response ({status}) (often not cached without explicit freshness)"
        if status >= 400:
            return f"Error response status {status} (often not cached)"
    if "DENIED" in rc or rc.startswith("TCP_DENIED"):
        return "Denied by ACL"
    if "BYPASS" in rc:
        return "Bypassed (cache deny rule or client no-cache)"
    if "ABORTED" in rc:
        return "Aborted (client/upstream closed connection)"
    if "SWAPFAIL" in rc:
        return "Cache swap failure"
    if "MISS" in rc:
        return "Cache miss (object not in cache)"

    return "Not served from cache"


class LiveStatsStore:
    def __init__(
        self,
        access_log_path: str = "/var/log/squid/access.log",
        seed_max_lines: int = 5000,
    ):
        self.access_log_path = access_log_path
        self.seed_max_lines = seed_max_lines

        self._started = False
        self._start_lock = threading.Lock()

    def _connect(self):
        return connect()

    def _table(self, conn, logical_name: str) -> str:
        mapping = {
            "domains": "live_stats_domains",
            "clients": "live_stats_clients",
            "client_domains": "live_stats_client_domains",
            "client_domain_nocache": "live_stats_client_domain_nocache",
        }
        return mapping[logical_name]

    def _ingest_line_with_conn(self, conn, line: str) -> bool:
        parsed = _parse_access_log_line(line)
        if not parsed:
            return False
        ts, ip, result_code, size_bytes, domain, method = parsed
        if not domain:
            return False

        hit = _is_hit(result_code)
        reason = _derive_not_cached_reason(method, result_code) if not hit else ""

        self._upsert_agg(conn, "domains", "domain", domain, ts, size_bytes, hit)
        self._upsert_agg(conn, "clients", "ip", ip, ts, size_bytes, hit)
        self._upsert_client_domain(conn, ip, domain, ts, size_bytes, hit)
        if not hit:
            self._upsert_client_domain_nocache(conn, ip, domain, ts, reason)
        return True

    def init_db(self) -> None:
        with self._connect() as conn:
            domains_table = self._table(conn, "domains")
            clients_table = self._table(conn, "clients")
            client_domains_table = self._table(conn, "client_domains")
            nocache_table = self._table(conn, "client_domain_nocache")
            conn.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {domains_table} (
                    proxy_id VARCHAR(64) NOT NULL DEFAULT 'default',
                    domain VARCHAR(255) NOT NULL,
                    requests BIGINT NOT NULL DEFAULT 0,
                    hit_requests BIGINT NOT NULL DEFAULT 0,
                    bytes BIGINT NOT NULL DEFAULT 0,
                    hit_bytes BIGINT NOT NULL DEFAULT 0,
                    first_seen BIGINT NOT NULL,
                    last_seen BIGINT NOT NULL,
                    PRIMARY KEY (proxy_id, domain),
                    KEY idx_{domains_table}_proxy_last_seen (proxy_id, last_seen)
                )
                """
            )
            conn.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {clients_table} (
                    proxy_id VARCHAR(64) NOT NULL DEFAULT 'default',
                    ip VARCHAR(64) NOT NULL,
                    requests BIGINT NOT NULL DEFAULT 0,
                    hit_requests BIGINT NOT NULL DEFAULT 0,
                    bytes BIGINT NOT NULL DEFAULT 0,
                    hit_bytes BIGINT NOT NULL DEFAULT 0,
                    first_seen BIGINT NOT NULL,
                    last_seen BIGINT NOT NULL,
                    PRIMARY KEY (proxy_id, ip),
                    KEY idx_{clients_table}_proxy_last_seen (proxy_id, last_seen)
                )
                """
            )
            conn.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {client_domains_table} (
                    proxy_id VARCHAR(64) NOT NULL DEFAULT 'default',
                    ip VARCHAR(64) NOT NULL,
                    domain VARCHAR(255) NOT NULL,
                    requests BIGINT NOT NULL DEFAULT 0,
                    hit_requests BIGINT NOT NULL DEFAULT 0,
                    bytes BIGINT NOT NULL DEFAULT 0,
                    hit_bytes BIGINT NOT NULL DEFAULT 0,
                    first_seen BIGINT NOT NULL,
                    last_seen BIGINT NOT NULL,
                    PRIMARY KEY (proxy_id, ip, domain),
                    KEY idx_{client_domains_table}_proxy_ip (proxy_id, ip)
                )
                """
            )
            conn.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {nocache_table} (
                    row_key CHAR(40) PRIMARY KEY,
                    proxy_id VARCHAR(64) NOT NULL DEFAULT 'default',
                    ip VARCHAR(64) NOT NULL,
                    domain VARCHAR(255) NOT NULL,
                    reason VARCHAR(300) NOT NULL,
                    requests BIGINT NOT NULL DEFAULT 0,
                    first_seen BIGINT NOT NULL,
                    last_seen BIGINT NOT NULL,
                    KEY idx_{nocache_table}_proxy_ip (proxy_id, ip, last_seen),
                    KEY idx_{nocache_table}_proxy_domain (proxy_id, domain, last_seen)
                )
                """
            )

    def prune_old_entries(self, *, retention_days: int = 30) -> None:
        """Prune stale aggregate rows.

        This store keeps only aggregates keyed by (domain/client/etc). Without pruning,
        the table set can grow indefinitely as new domains/clients appear over time.
        """
        days = max(1, int(retention_days or 30))
        cutoff = _now() - (days * 24 * 60 * 60)
        with self._connect() as conn:
            conn.execute(f"DELETE FROM {self._table(conn, 'client_domain_nocache')} WHERE last_seen < %s", (int(cutoff),))
            conn.execute(f"DELETE FROM {self._table(conn, 'client_domains')} WHERE last_seen < %s", (int(cutoff),))
            conn.execute(f"DELETE FROM {self._table(conn, 'domains')} WHERE last_seen < %s", (int(cutoff),))
            conn.execute(f"DELETE FROM {self._table(conn, 'clients')} WHERE last_seen < %s", (int(cutoff),))

    def _upsert_agg(self, conn, table: str, key_col: str, key: str, ts: int, size_bytes: int, is_hit: bool) -> None:
        table_name = self._table(conn, table)
        hit = 1 if is_hit else 0
        hit_bytes = size_bytes if is_hit else 0
        proxy_id = get_proxy_id()
        conn.execute(
            f"""
            INSERT INTO {table_name} (proxy_id, {key_col}, requests, hit_requests, bytes, hit_bytes, first_seen, last_seen)
            VALUES (%s, %s, 1, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                requests = requests + 1,
                hit_requests = hit_requests + VALUES(hit_requests),
                bytes = bytes + VALUES(bytes),
                hit_bytes = hit_bytes + VALUES(hit_bytes),
                first_seen = LEAST(first_seen, VALUES(first_seen)),
                last_seen = GREATEST(last_seen, VALUES(last_seen));
            """ ,
            (proxy_id, key, hit, size_bytes, hit_bytes, ts, ts),
        )

    def _upsert_client_domain(self, conn, ip: str, domain: str, ts: int, size_bytes: int, is_hit: bool) -> None:
        table_name = self._table(conn, "client_domains")
        hit = 1 if is_hit else 0
        hit_bytes = size_bytes if is_hit else 0
        proxy_id = get_proxy_id()
        conn.execute(
            f"""
            INSERT INTO {table_name} (proxy_id, ip, domain, requests, hit_requests, bytes, hit_bytes, first_seen, last_seen)
            VALUES (%s, %s, %s, 1, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                requests = requests + 1,
                hit_requests = hit_requests + VALUES(hit_requests),
                bytes = bytes + VALUES(bytes),
                hit_bytes = hit_bytes + VALUES(hit_bytes),
                first_seen = LEAST(first_seen, VALUES(first_seen)),
                last_seen = GREATEST(last_seen, VALUES(last_seen));
            """,
            (proxy_id, ip, domain, hit, size_bytes, hit_bytes, ts, ts),
        )

    def _upsert_client_domain_nocache(self, conn, ip: str, domain: str, ts: int, reason: str) -> None:
        table_name = self._table(conn, "client_domain_nocache")
        r = (reason or "").strip()
        if not r:
            r = "Not served from cache"
        proxy_id = get_proxy_id()
        row_key = hashlib.sha1(f"{proxy_id}|{ip}|{domain}|{r}".encode("utf-8", errors="replace")).hexdigest()
        conn.execute(
            f"""
            INSERT INTO {table_name} (row_key, proxy_id, ip, domain, reason, requests, first_seen, last_seen)
            VALUES (%s, %s, %s, %s, %s, 1, %s, %s)
            ON DUPLICATE KEY UPDATE
                requests = requests + 1,
                first_seen = LEAST(first_seen, VALUES(first_seen)),
                last_seen = GREATEST(last_seen, VALUES(last_seen));
            """,
            (row_key, proxy_id, ip, domain, r, ts, ts),
        )

    def ingest_line(self, line: str) -> None:
        with self._connect() as conn:
            self._ingest_line_with_conn(conn, line)

    def _read_last_lines(self, max_lines: int) -> List[str]:
        path = self.access_log_path
        if not os.path.exists(path):
            return []
        try:
            with open(path, "rb") as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                read_size = min(size, max_lines * 220)
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
                parsed = _parse_access_log_line(line)
                if not parsed:
                    continue
                ts, ip, result_code, size_bytes, domain, method = parsed
                if not domain:
                    continue
                hit = _is_hit(result_code)
                reason = _derive_not_cached_reason(method, result_code) if not hit else ""
                self._upsert_agg(conn, "domains", "domain", domain, ts, size_bytes, hit)
                self._upsert_agg(conn, "clients", "ip", ip, ts, size_bytes, hit)
                self._upsert_client_domain(conn, ip, domain, ts, size_bytes, hit)
                if not hit:
                    self._upsert_client_domain_nocache(conn, ip, domain, ts, reason)

    def start_background(self) -> None:
        with self._start_lock:
            if self._started:
                return
            self._started = True
            self.init_db()

            t = threading.Thread(target=self._tail_loop, name="live-stats-tailer", daemon=True)
            t.start()

    def _tail_loop(self) -> None:
        # Seed so the page is useful immediately.
        self.seed_from_recent_log()

        commit_batch = _env_int("LIVE_STATS_COMMIT_BATCH", 250, minimum=25, maximum=5000)
        commit_interval = _env_float("LIVE_STATS_COMMIT_INTERVAL_SECONDS", 2.0, minimum=0.25, maximum=10.0)
        poll_interval = _env_float("LIVE_STATS_POLL_INTERVAL_SECONDS", 0.5, minimum=0.1, maximum=5.0)

        # Tail new lines.
        path = self.access_log_path
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
                        # Start at end so we don't reprocess the whole file.
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
                                            "live_stats.rollback.ingest",
                                            interval_seconds=300.0,
                                            message="Live stats tailer rollback failed after ingest error",
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
                                                "live_stats.rollback.commit",
                                                interval_seconds=300.0,
                                                message="Live stats tailer rollback failed after commit error",
                                            )
                                    pending = 0
                                    last_commit = now
                                continue

                            # EOF/idle: commit any pending rows so UI reflects the latest
                            # data even if the log is quiet.
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
                                            "live_stats.rollback.idle_commit",
                                            interval_seconds=300.0,
                                            message="Live stats tailer rollback failed after idle commit error",
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
                                    "live_stats.copytruncate",
                                    interval_seconds=300.0,
                                    message="Live stats tailer copytruncate check failed",
                                )

                            # Handle log rotation by checking inode.
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
                                        "live_stats.commit.rotate",
                                        interval_seconds=300.0,
                                        message="Live stats tailer final commit failed during rotation",
                                    )
                                break

                            time.sleep(poll_interval)
            except Exception:
                log_exception_throttled(
                    logger,
                    "live_stats.loop",
                    interval_seconds=300.0,
                    message="Live stats tailer loop failed",
                )
                time.sleep(max(1.0, poll_interval))

    def _query_rows(self, sql: str, params: Tuple[Any, ...]) -> List[Row]:
        with self._connect() as conn:
            cur = conn.execute(sql, params)
            rows = []
            for r in cur.fetchall():
                rows.append(
                    Row(
                        key=str(r[0]),
                        requests=int(r[1]),
                        hit_requests=int(r[2]),
                        bytes=int(r[3]),
                        hit_bytes=int(r[4]),
                        first_seen=int(r[5]),
                        last_seen=int(r[6]),
                    )
                )
            return rows

    def get_totals(self, *, since: Optional[int] = None) -> Dict[str, int]:
        where = "WHERE proxy_id = %s"
        params: List[Any] = [get_proxy_id()]
        if since is not None:
            where += " AND last_seen >= %s"
            params.append(int(since))
        with self._connect() as conn:
            d = conn.execute(f"SELECT COALESCE(SUM(requests),0), COALESCE(SUM(hit_requests),0) FROM {self._table(conn, 'domains')} {where}", tuple(params)).fetchone()
            c = conn.execute(f"SELECT COALESCE(SUM(requests),0), COALESCE(SUM(hit_requests),0) FROM {self._table(conn, 'clients')} {where}", tuple(params)).fetchone()
        return {
            "domain_requests": int(d[0]) if d else 0,
            "domain_hit_requests": int(d[1]) if d else 0,
            "client_requests": int(c[0]) if c else 0,
            "client_hit_requests": int(c[1]) if c else 0,
        }

    def list_domains(
        self,
        sort: str = "recent",
        order: str = "desc",
        limit: int = 100,
        *,
        since: Optional[int] = None,
        search: str = "",
    ) -> List[Dict[str, Any]]:
        order_sql = "DESC" if order.lower() != "asc" else "ASC"
        where = ["proxy_id = %s"]
        params: List[Any] = [get_proxy_id()]
        if since is not None:
            where.append("last_seen >= %s")
            params.append(int(since))
        if search:
            where.append("domain LIKE %s ESCAPE '\\'")
            params.append(f"%{_escape_like(search)}%")
        where_sql = ("WHERE " + " AND ".join(where)) if where else ""

        with self._connect() as conn:
            domains_table = self._table(conn, "domains")

        if sort == "top":
            sql = f"SELECT domain, requests, hit_requests, bytes, hit_bytes, first_seen, last_seen FROM {domains_table} {where_sql} ORDER BY requests {order_sql}, last_seen DESC LIMIT %s"
        elif sort == "cache":
            sql = f"SELECT domain, requests, hit_requests, bytes, hit_bytes, first_seen, last_seen FROM {domains_table} {where_sql} ORDER BY (CASE WHEN requests>0 THEN (1.0*hit_requests/requests) ELSE 0 END) {order_sql}, requests DESC LIMIT %s"
        else:
            sql = f"SELECT domain, requests, hit_requests, bytes, hit_bytes, first_seen, last_seen FROM {domains_table} {where_sql} ORDER BY last_seen {order_sql}, requests DESC LIMIT %s"

        rows = self._query_rows(sql, tuple(params + [int(limit)]))
        totals = self.get_totals(since=since)
        total = totals["domain_requests"]
        out: List[Dict[str, Any]] = []
        for r in rows:
            out.append(
                {
                    "domain": r.key,
                    "requests": r.requests,
                    "pct": _pct(r.requests, total),
                    "cache_pct": _pct(r.hit_requests, r.requests),
                    "last_seen": r.last_seen,
                }
            )
        return out

    def list_clients(
        self,
        sort: str = "recent",
        order: str = "desc",
        limit: int = 100,
        *,
        since: Optional[int] = None,
        search: str = "",
    ) -> List[Dict[str, Any]]:
        order_sql = "DESC" if order.lower() != "asc" else "ASC"
        where = ["proxy_id = %s"]
        params: List[Any] = [get_proxy_id()]
        if since is not None:
            where.append("last_seen >= %s")
            params.append(int(since))
        if search:
            where.append("ip LIKE %s ESCAPE '\\'")
            params.append(f"%{_escape_like(search)}%")
        where_sql = ("WHERE " + " AND ".join(where)) if where else ""

        with self._connect() as conn:
            clients_table = self._table(conn, "clients")

        if sort == "top":
            sql = f"SELECT ip, requests, hit_requests, bytes, hit_bytes, first_seen, last_seen FROM {clients_table} {where_sql} ORDER BY requests {order_sql}, last_seen DESC LIMIT %s"
        elif sort == "cache":
            sql = f"SELECT ip, requests, hit_requests, bytes, hit_bytes, first_seen, last_seen FROM {clients_table} {where_sql} ORDER BY (CASE WHEN requests>0 THEN (1.0*hit_requests/requests) ELSE 0 END) {order_sql}, requests DESC LIMIT %s"
        else:
            sql = f"SELECT ip, requests, hit_requests, bytes, hit_bytes, first_seen, last_seen FROM {clients_table} {where_sql} ORDER BY last_seen {order_sql}, requests DESC LIMIT %s"

        rows = self._query_rows(sql, tuple(params + [int(limit)]))
        totals = self.get_totals(since=since)
        total = totals["client_requests"]
        out: List[Dict[str, Any]] = []
        for r in rows:
            out.append(
                {
                    "ip": r.key,
                    "requests": r.requests,
                    "pct": _pct(r.requests, total),
                    "cache_pct": _pct(r.hit_requests, r.requests),
                    "last_seen": r.last_seen,
                }
            )
        return out

    def list_client_domains(self, ip: str, sort: str = "top", limit: int = 50) -> List[Dict[str, Any]]:
        if not ip:
            return []
        proxy_id = get_proxy_id()
        with self._connect() as conn:
            client_domains_table = self._table(conn, "client_domains")
        if sort == "recent":
            sql = f"SELECT domain, requests, hit_requests, bytes, hit_bytes, first_seen, last_seen FROM {client_domains_table} WHERE proxy_id=%s AND ip=%s ORDER BY last_seen DESC LIMIT %s"
        elif sort == "cache":
            sql = f"SELECT domain, requests, hit_requests, bytes, hit_bytes, first_seen, last_seen FROM {client_domains_table} WHERE proxy_id=%s AND ip=%s ORDER BY (CASE WHEN requests>0 THEN (1.0*hit_requests/requests) ELSE 0 END) DESC, requests DESC LIMIT %s"
        else:
            sql = f"SELECT domain, requests, hit_requests, bytes, hit_bytes, first_seen, last_seen FROM {client_domains_table} WHERE proxy_id=%s AND ip=%s ORDER BY requests DESC, last_seen DESC LIMIT %s"

        rows = self._query_rows(sql, (proxy_id, ip, int(limit)))
        total = sum(r.requests for r in rows) or 0
        out: List[Dict[str, Any]] = []
        for r in rows:
            out.append(
                {
                    "domain": r.key,
                    "requests": r.requests,
                    "pct": _pct(r.requests, total),
                    "cache_pct": _pct(r.hit_requests, r.requests),
                    "last_seen": r.last_seen,
                }
            )
        return out

    def list_client_not_cached(self, ip: str, limit: int = 50) -> List[Dict[str, Any]]:
        if not ip:
            return []
        lim = max(10, min(500, int(limit)))
        proxy_id = get_proxy_id()
        with self._connect() as conn:
            nocache_table = self._table(conn, "client_domain_nocache")
            client_domains_table = self._table(conn, "client_domains")
        sql = f"""
        SELECT
            cd.domain,
            (cd.requests - cd.hit_requests) AS miss_requests,
            cd.requests AS total_requests,
            cd.hit_requests AS hit_requests,
            cd.last_seen,
            (
                SELECT n.reason
                FROM {nocache_table} n
                WHERE n.proxy_id = cd.proxy_id AND n.ip = cd.ip AND n.domain = cd.domain
                ORDER BY
                    n.requests DESC,
                    (CASE WHEN n.reason IN ('Cache miss (object not in cache)', 'Not served from cache') THEN 1 ELSE 0 END) ASC,
                    n.last_seen DESC
                LIMIT 1
            ) AS reason
        FROM {client_domains_table} cd
        WHERE cd.proxy_id = %s AND cd.ip = %s AND cd.requests > cd.hit_requests
        ORDER BY miss_requests DESC, cd.last_seen DESC
        LIMIT %s
        """
        with self._connect() as conn:
            rows = conn.execute(sql, (proxy_id, ip, lim)).fetchall()

        out: List[Dict[str, Any]] = []
        for r in rows:
            out.append(
                {
                    "domain": str(r[0]),
                    "miss_requests": int(r[1] or 0),
                    "total_requests": int(r[2] or 0),
                    "cache_pct": _pct(int(r[3] or 0), int(r[2] or 0)),
                    "last_seen": int(r[4] or 0),
                    "reason": str(r[5] or "Not served from cache"),
                }
            )
        return out

    def export_rows(self, mode: str, *, since: Optional[int] = None, search: str = "", limit: int = 500) -> List[Dict[str, Any]]:
        mode_s = (mode or "domains").strip().lower()
        lim = max(10, min(1000, int(limit)))
        if mode_s == "clients":
            return self.list_clients(sort="recent", order="desc", limit=lim, since=since, search=search)
        return self.list_domains(sort="recent", order="desc", limit=lim, since=since, search=search)

    def list_domain_not_cached_reasons(self, domain: str, limit: int = 10) -> List[Dict[str, Any]]:
        d = (domain or "").strip().lower().lstrip(".")
        if not d:
            return []

        lim = max(3, min(50, int(limit)))
        proxy_id = get_proxy_id()
        with self._connect() as conn:
            nocache_table = self._table(conn, "client_domain_nocache")
            total_row = conn.execute(
                f"SELECT COALESCE(SUM(requests),0) FROM {nocache_table} WHERE proxy_id=%s AND domain=%s",
                (proxy_id, d),
            ).fetchone()
            total = int(total_row[0] or 0) if total_row else 0

            rows = conn.execute(
                f"""
                SELECT reason, COALESCE(SUM(requests),0) AS req, COALESCE(MAX(last_seen),0) AS last_seen
                FROM {nocache_table}
                WHERE proxy_id=%s AND domain=%s
                GROUP BY reason
                ORDER BY req DESC, last_seen DESC
                LIMIT %s
                """,
                (proxy_id, d, lim),
            ).fetchall()

        out: List[Dict[str, Any]] = []
        for r in rows:
            req = int(r[1] or 0)
            out.append(
                {
                    "reason": str(r[0]),
                    "requests": req,
                    "pct": _pct(req, total),
                    "last_seen": int(r[2] or 0),
                }
            )
        return out

    def list_global_not_cached_reasons(self, limit: int = 50) -> Tuple[int, List[Dict[str, Any]]]:
        lim = max(3, min(200, int(limit)))
        proxy_id = get_proxy_id()
        with self._connect() as conn:
            nocache_table = self._table(conn, "client_domain_nocache")
            total_row = conn.execute(f"SELECT COALESCE(SUM(requests),0) FROM {nocache_table} WHERE proxy_id=%s", (proxy_id,)).fetchone()
            total = int(total_row[0] or 0) if total_row else 0

            rows = conn.execute(
                f"""
                SELECT reason, COALESCE(SUM(requests),0) AS req, COALESCE(MAX(last_seen),0) AS last_seen
                FROM {nocache_table}
                WHERE proxy_id=%s
                GROUP BY reason
                ORDER BY req DESC, last_seen DESC
                LIMIT %s
                """,
                (proxy_id, lim),
            ).fetchall()

        out: List[Dict[str, Any]] = []
        for r in rows:
            req = int(r[1] or 0)
            out.append(
                {
                    "reason": str(r[0]),
                    "requests": req,
                    "pct": _pct(req, total),
                    "last_seen": int(r[2] or 0),
                }
            )
        return total, out


_store: Optional[LiveStatsStore] = None
_store_lock = threading.Lock()


def get_store() -> LiveStatsStore:
    global _store
    if _store is not None:
        return _store
    with _store_lock:
        if _store is None:
            _store = LiveStatsStore()
        return _store
