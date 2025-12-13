from __future__ import annotations

import os
import sqlite3
import threading
import time
import csv
import io
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit


@dataclass
class Row:
    key: str
    requests: int
    hit_requests: int
    bytes: int
    hit_bytes: int
    first_seen: int
    last_seen: int


def _now() -> int:
    return int(time.time())


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
        parts = urlsplit(url)
        host = parts.hostname
        if not host:
            return None
        return host.lower()
    except Exception:
        return None


def _parse_access_log_line(line: str) -> Optional[Tuple[int, str, str, int, Optional[str], str, Dict[str, str]]]:
    # Supports both:
    #  1) Squid default format:
    #     ts elapsed client result_code/status bytes method url ...
    #  2) Our structured TSV logformat (see squid.conf.template).
    # Returns: (ts, client_ip, result_code, bytes, domain, method, extras)
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
        if len(row) >= 7:
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
            extras = {
                "req_cc": row[7] if len(row) > 7 else "",
                "req_pragma": row[8] if len(row) > 8 else "",
                "req_auth": row[9] if len(row) > 9 else "",
                "req_cookie": row[10] if len(row) > 10 else "",
                "rep_cc": row[11] if len(row) > 11 else "",
                "rep_pragma": row[12] if len(row) > 12 else "",
                "rep_expires": row[13] if len(row) > 13 else "",
                "rep_vary": row[14] if len(row) > 14 else "",
                "rep_set_cookie": row[15] if len(row) > 15 else "",
            }
            return ts, client_ip, result_code, max(size_bytes, 0), domain, method, extras

    # Default whitespace format.
    parts = s.split()
    if len(parts) < 7:
        return None

    try:
        ts = int(float(parts[0]))
    except ValueError:
        ts = _now()

    client_ip = parts[2]
    result_code = parts[3]

    try:
        size_bytes = int(parts[4])
    except ValueError:
        size_bytes = 0

    method = parts[5]
    url = parts[6]
    domain = _extract_domain(url)

    return ts, client_ip, result_code, max(size_bytes, 0), domain, method, {}


def _derive_not_cached_reason(domain: str, method: str, result_code: str, extras: Optional[Dict[str, str]] = None) -> str:
    # Best-effort reasons based on Squid access.log result codes and HTTP method.
    # Squid does not log response headers by default, so we cannot reliably detect
    # Cache-Control: private/no-store/etc without changing logformat.
    m = (method or "").upper()
    rc = (result_code or "").upper()

    # Extract HTTP status (best-effort) from e.g. TCP_MISS/200
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

    ex = extras or {}
    req_cc = (ex.get("req_cc") or "").lower()
    req_pragma = (ex.get("req_pragma") or "").lower()
    req_auth = (ex.get("req_auth") or "")
    req_cookie = (ex.get("req_cookie") or "")
    rep_cc = (ex.get("rep_cc") or "").lower()
    rep_pragma = (ex.get("rep_pragma") or "").lower()
    rep_vary = (ex.get("rep_vary") or "").lower()
    rep_set_cookie = (ex.get("rep_set_cookie") or "")

    def cc_has(header: str, token: str) -> bool:
        # token match for Cache-Control directives
        h = (header or "").lower()
        t = token.lower()
        # handle both "token" and "token=" forms
        return (t in h) or (t + "=") in h

    # Client/request-driven reasons.
    if cc_has(req_cc, "no-store"):
        return "Client forbids storage (Cache-Control: no-store)"
    if cc_has(req_cc, "no-cache") or cc_has(req_cc, "max-age=0") or ("no-cache" in req_pragma):
        return "Client requested no-cache (Cache-Control/Pragma)"
    if cc_has(req_cc, "only-if-cached"):
        return "Client requested only-if-cached (offline cache mode)"
    if req_auth and req_auth != "-":
        return "Authorization header present (often not cacheable by default)"
    if req_cookie and req_cookie != "-":
        return "Cookie header present (often reduces cacheability)"

    # Origin/response-driven reasons.
    if cc_has(rep_cc, "no-store") or ("no-store" in rep_pragma):
        return "Origin forbids caching (Cache-Control/Pragma: no-store)"
    if cc_has(rep_cc, "private"):
        return "Origin marks response private (Cache-Control: private)"
    if cc_has(rep_cc, "no-cache"):
        return "Origin requires revalidation (Cache-Control: no-cache)"
    if cc_has(rep_cc, "max-age=0") or cc_has(rep_cc, "s-maxage=0"):
        return "Origin sets max-age=0 (immediate expiry)"
    if rep_set_cookie and rep_set_cookie != "-":
        return "Set-Cookie present (often not cacheable by default)"
    if rep_vary.strip() == "*":
        return "Vary: * (not cacheable)"

    # Status-code heuristics (only if we didn't find a header-driven reason).
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

    # Fall back to a short generic reason.
    return "Not served from cache"


class LiveStatsStore:
    def __init__(
        self,
        db_path: str = "/var/lib/squid-flask-proxy/live_stats.db",
        access_log_path: str = "/var/log/squid/access.log",
        seed_max_lines: int = 5000,
    ):
        self.db_path = db_path
        self.access_log_path = access_log_path
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
                CREATE TABLE IF NOT EXISTS domains (
                    domain TEXT PRIMARY KEY,
                    requests INTEGER NOT NULL DEFAULT 0,
                    hit_requests INTEGER NOT NULL DEFAULT 0,
                    bytes INTEGER NOT NULL DEFAULT 0,
                    hit_bytes INTEGER NOT NULL DEFAULT 0,
                    first_seen INTEGER NOT NULL,
                    last_seen INTEGER NOT NULL
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS clients (
                    ip TEXT PRIMARY KEY,
                    requests INTEGER NOT NULL DEFAULT 0,
                    hit_requests INTEGER NOT NULL DEFAULT 0,
                    bytes INTEGER NOT NULL DEFAULT 0,
                    hit_bytes INTEGER NOT NULL DEFAULT 0,
                    first_seen INTEGER NOT NULL,
                    last_seen INTEGER NOT NULL
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS client_domains (
                    ip TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    requests INTEGER NOT NULL DEFAULT 0,
                    hit_requests INTEGER NOT NULL DEFAULT 0,
                    bytes INTEGER NOT NULL DEFAULT 0,
                    hit_bytes INTEGER NOT NULL DEFAULT 0,
                    first_seen INTEGER NOT NULL,
                    last_seen INTEGER NOT NULL,
                    PRIMARY KEY (ip, domain)
                );
                """
            )

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS client_domain_nocache (
                    ip TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    requests INTEGER NOT NULL DEFAULT 0,
                    first_seen INTEGER NOT NULL,
                    last_seen INTEGER NOT NULL,
                    PRIMARY KEY (ip, domain, reason)
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_domains_last_seen ON domains(last_seen DESC);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_clients_last_seen ON clients(last_seen DESC);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_client_domains_ip ON client_domains(ip);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_client_domain_nocache_ip ON client_domain_nocache(ip, last_seen DESC);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_client_domain_nocache_domain ON client_domain_nocache(domain, last_seen DESC);")

    def _upsert_agg(self, conn: sqlite3.Connection, table: str, key_col: str, key: str, ts: int, size_bytes: int, is_hit: bool) -> None:
        hit = 1 if is_hit else 0
        hit_bytes = size_bytes if is_hit else 0
        conn.execute(
            f"""
            INSERT INTO {table} ({key_col}, requests, hit_requests, bytes, hit_bytes, first_seen, last_seen)
            VALUES (?, 1, ?, ?, ?, ?, ?)
            ON CONFLICT({key_col}) DO UPDATE SET
                requests = requests + 1,
                hit_requests = hit_requests + excluded.hit_requests,
                bytes = bytes + excluded.bytes,
                hit_bytes = hit_bytes + excluded.hit_bytes,
                first_seen = MIN(first_seen, excluded.first_seen),
                last_seen = MAX(last_seen, excluded.last_seen);
            """ ,
            (key, hit, size_bytes, hit_bytes, ts, ts),
        )

    def _upsert_client_domain(self, conn: sqlite3.Connection, ip: str, domain: str, ts: int, size_bytes: int, is_hit: bool) -> None:
        hit = 1 if is_hit else 0
        hit_bytes = size_bytes if is_hit else 0
        conn.execute(
            """
            INSERT INTO client_domains (ip, domain, requests, hit_requests, bytes, hit_bytes, first_seen, last_seen)
            VALUES (?, ?, 1, ?, ?, ?, ?, ?)
            ON CONFLICT(ip, domain) DO UPDATE SET
                requests = requests + 1,
                hit_requests = hit_requests + excluded.hit_requests,
                bytes = bytes + excluded.bytes,
                hit_bytes = hit_bytes + excluded.hit_bytes,
                first_seen = MIN(first_seen, excluded.first_seen),
                last_seen = MAX(last_seen, excluded.last_seen);
            """,
            (ip, domain, hit, size_bytes, hit_bytes, ts, ts),
        )

    def _upsert_client_domain_nocache(self, conn: sqlite3.Connection, ip: str, domain: str, ts: int, reason: str) -> None:
        r = (reason or "").strip()
        if not r:
            r = "Not served from cache"
        conn.execute(
            """
            INSERT INTO client_domain_nocache (ip, domain, reason, requests, first_seen, last_seen)
            VALUES (?, ?, ?, 1, ?, ?)
            ON CONFLICT(ip, domain, reason) DO UPDATE SET
                requests = requests + 1,
                first_seen = MIN(first_seen, excluded.first_seen),
                last_seen = MAX(last_seen, excluded.last_seen);
            """,
            (ip, domain, r, ts, ts),
        )

    def ingest_line(self, line: str) -> None:
        parsed = _parse_access_log_line(line)
        if not parsed:
            return
        ts, ip, result_code, size_bytes, domain, method, extras = parsed
        if not domain:
            return

        hit = _is_hit(result_code)
        reason = _derive_not_cached_reason(domain, method, result_code, extras=extras) if not hit else ""

        with self._connect() as conn:
            self._upsert_agg(conn, "domains", "domain", domain, ts, size_bytes, hit)
            self._upsert_agg(conn, "clients", "ip", ip, ts, size_bytes, hit)
            self._upsert_client_domain(conn, ip, domain, ts, size_bytes, hit)
            if not hit:
                self._upsert_client_domain_nocache(conn, ip, domain, ts, reason)

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
                ts, ip, result_code, size_bytes, domain, method, extras = parsed
                if not domain:
                    continue
                hit = _is_hit(result_code)
                reason = _derive_not_cached_reason(domain, method, result_code, extras=extras) if not hit else ""
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

        # Tail new lines.
        path = self.access_log_path
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
                    # Start at end so we don't reprocess the whole file.
                    f.seek(0, os.SEEK_END)
                    while True:
                        line = f.readline()
                        if line:
                            self.ingest_line(line)
                            continue

                        # Handle log rotation by checking inode.
                        try:
                            st2 = os.stat(path)
                            inode2 = getattr(st2, "st_ino", None)
                        except OSError:
                            inode2 = None

                        if inode2 is not None and last_inode is not None and inode2 != last_inode:
                            last_inode = inode2
                            break

                        time.sleep(0.35)
            except Exception:
                time.sleep(1.0)

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

    def get_totals(self) -> Dict[str, int]:
        with self._connect() as conn:
            d = conn.execute("SELECT COALESCE(SUM(requests),0), COALESCE(SUM(hit_requests),0) FROM domains").fetchone()
            c = conn.execute("SELECT COALESCE(SUM(requests),0), COALESCE(SUM(hit_requests),0) FROM clients").fetchone()
        return {
            "domain_requests": int(d[0]) if d else 0,
            "domain_hit_requests": int(d[1]) if d else 0,
            "client_requests": int(c[0]) if c else 0,
            "client_hit_requests": int(c[1]) if c else 0,
        }

    def list_domains(self, sort: str = "recent", order: str = "desc", limit: int = 100) -> List[Dict[str, Any]]:
        order_sql = "DESC" if order.lower() != "asc" else "ASC"
        if sort == "top":
            sql = f"SELECT domain, requests, hit_requests, bytes, hit_bytes, first_seen, last_seen FROM domains ORDER BY requests {order_sql}, last_seen DESC LIMIT ?"
        elif sort == "cache":
            # cache% sort; protect division by zero
            sql = f"SELECT domain, requests, hit_requests, bytes, hit_bytes, first_seen, last_seen FROM domains ORDER BY (CASE WHEN requests>0 THEN (1.0*hit_requests/requests) ELSE 0 END) {order_sql}, requests DESC LIMIT ?"
        else:
            sql = f"SELECT domain, requests, hit_requests, bytes, hit_bytes, first_seen, last_seen FROM domains ORDER BY last_seen {order_sql}, requests DESC LIMIT ?"

        rows = self._query_rows(sql, (int(limit),))
        totals = self.get_totals()
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

    def list_clients(self, sort: str = "recent", order: str = "desc", limit: int = 100) -> List[Dict[str, Any]]:
        order_sql = "DESC" if order.lower() != "asc" else "ASC"
        if sort == "top":
            sql = f"SELECT ip, requests, hit_requests, bytes, hit_bytes, first_seen, last_seen FROM clients ORDER BY requests {order_sql}, last_seen DESC LIMIT ?"
        elif sort == "cache":
            sql = f"SELECT ip, requests, hit_requests, bytes, hit_bytes, first_seen, last_seen FROM clients ORDER BY (CASE WHEN requests>0 THEN (1.0*hit_requests/requests) ELSE 0 END) {order_sql}, requests DESC LIMIT ?"
        else:
            sql = f"SELECT ip, requests, hit_requests, bytes, hit_bytes, first_seen, last_seen FROM clients ORDER BY last_seen {order_sql}, requests DESC LIMIT ?"

        rows = self._query_rows(sql, (int(limit),))
        totals = self.get_totals()
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
        if sort == "recent":
            sql = "SELECT domain, requests, hit_requests, bytes, hit_bytes, first_seen, last_seen FROM client_domains WHERE ip=? ORDER BY last_seen DESC LIMIT ?"
        elif sort == "cache":
            sql = "SELECT domain, requests, hit_requests, bytes, hit_bytes, first_seen, last_seen FROM client_domains WHERE ip=? ORDER BY (CASE WHEN requests>0 THEN (1.0*hit_requests/requests) ELSE 0 END) DESC, requests DESC LIMIT ?"
        else:
            sql = "SELECT domain, requests, hit_requests, bytes, hit_bytes, first_seen, last_seen FROM client_domains WHERE ip=? ORDER BY requests DESC, last_seen DESC LIMIT ?"

        rows = self._query_rows(sql, (ip, int(limit)))
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
        sql = """
        SELECT
            cd.domain,
            (cd.requests - cd.hit_requests) AS miss_requests,
            cd.requests AS total_requests,
            cd.hit_requests AS hit_requests,
            cd.last_seen,
            (
                SELECT n.reason
                FROM client_domain_nocache n
                WHERE n.ip = cd.ip AND n.domain = cd.domain
                ORDER BY
                    n.requests DESC,
                    (CASE WHEN n.reason IN ('Cache miss (object not in cache)', 'Not served from cache') THEN 1 ELSE 0 END) ASC,
                    n.last_seen DESC
                LIMIT 1
            ) AS reason
        FROM client_domains cd
        WHERE cd.ip = ? AND cd.requests > cd.hit_requests
        ORDER BY miss_requests DESC, cd.last_seen DESC
        LIMIT ?
        """
        with self._connect() as conn:
            rows = conn.execute(sql, (ip, lim)).fetchall()

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

    def list_domain_not_cached_reasons(self, domain: str, limit: int = 10) -> List[Dict[str, Any]]:
        d = (domain or "").strip().lower().lstrip(".")
        if not d:
            return []

        lim = max(3, min(50, int(limit)))
        with self._connect() as conn:
            total_row = conn.execute(
                "SELECT COALESCE(SUM(requests),0) FROM client_domain_nocache WHERE domain=?",
                (d,),
            ).fetchone()
            total = int(total_row[0] or 0) if total_row else 0

            rows = conn.execute(
                """
                SELECT reason, COALESCE(SUM(requests),0) AS req, COALESCE(MAX(last_seen),0) AS last_seen
                FROM client_domain_nocache
                WHERE domain=?
                GROUP BY reason
                ORDER BY req DESC, last_seen DESC
                LIMIT ?
                """,
                (d, lim),
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
        with self._connect() as conn:
            total_row = conn.execute("SELECT COALESCE(SUM(requests),0) FROM client_domain_nocache").fetchone()
            total = int(total_row[0] or 0) if total_row else 0

            rows = conn.execute(
                """
                SELECT reason, COALESCE(SUM(requests),0) AS req, COALESCE(MAX(last_seen),0) AS last_seen
                FROM client_domain_nocache
                GROUP BY reason
                ORDER BY req DESC, last_seen DESC
                LIMIT ?
                """,
                (lim,),
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


def get_store() -> LiveStatsStore:
    global _store
    if _store is None:
        _store = LiveStatsStore()
    return _store
