from __future__ import annotations

import contextlib
import hashlib
import ipaddress
import logging
import os
import pathlib
import re
import socket
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlparse

from services.db import DATABASE_ERRORS, INTEGRITY_ERRORS, connect
from services.errors import public_error_message
from services.logutil import log_database_unavailable, log_exception_throttled
from services.proxy_context import get_proxy_id
from services.runtime_helpers import env_int as _env_int
from services.runtime_helpers import now_ts as _now

logger = logging.getLogger(__name__)


def _is_duplicate_key_error(exc: BaseException) -> bool:
    try:
        if getattr(exc, "args", None):
            return int(exc.args[0]) == 1062
    except Exception:
        return False
    return False


def _is_forbidden_download_ip(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    return (
        ip.is_loopback
        or ip.is_private
        or ip.is_reserved
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
    )


def _is_internal_host(hostname: str) -> bool:
    """Check if hostname resolves to or appears to be an internal/localhost address."""
    h = (hostname or "").strip().lower().rstrip(".")
    if not h:
        return True
    if h in {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}:
        return True
    try:
        return _is_forbidden_download_ip(h)
    except ValueError:
        pass
    if h.endswith((".local", ".internal", ".localhost")):
        return True

    try:
        infos = socket.getaddrinfo(h, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return False
    except OSError:
        return True

    resolved = {info[4][0] for info in infos if info and info[4]}
    return any(_is_forbidden_download_ip(address) for address in resolved)


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl) -> None:
        return None


def _validate_download_url(url: str):
    u = urlparse(url or "")
    if u.scheme not in {"http", "https"}:
        msg = "Only http/https URLs are supported."
        raise ValueError(msg)
    if _is_internal_host(u.hostname or ""):
        msg = "Downloads from internal/localhost addresses are not allowed."
        raise ValueError(msg)
    return u


def _open_download_url(
    url: str,
    *,
    timeout: int,
    max_redirects: int = 5,
    headers: dict[str, str] | None = None,
):
    current = url
    opener = urllib.request.build_opener(_NoRedirectHandler)
    request_headers = {"User-Agent": "squid-flask-proxy/icap-adblock"}
    if headers:
        request_headers.update({str(k): str(v) for k, v in headers.items() if k and v})
    for _ in range(max_redirects + 1):
        _validate_download_url(current)
        req = urllib.request.Request(current, headers=request_headers)
        try:
            return opener.open(req, timeout=timeout)
        except urllib.error.HTTPError as exc:
            if exc.code not in {301, 302, 303, 307, 308}:
                raise
            location = exc.headers.get("Location") if exc.headers is not None else None
            if not location:
                msg = "Download redirect response did not include a Location header."
                raise ValueError(msg) from exc
            current = urljoin(current, location)
            _validate_download_url(current)
    msg = f"Download exceeded redirect limit ({max_redirects})."
    raise ValueError(msg)


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


def _event_key(ts: int, src_ip: str, url: str, http_status: int) -> str:
    raw = f"{int(ts)}|{src_ip}|{url}|{int(http_status)}"
    return hashlib.sha1(raw.encode("utf-8", errors="replace")).hexdigest()


class AdblockStore:
    def __init__(
        self,
        lists_dir: str = "/var/lib/squid-flask-proxy/adblock/lists",
        update_interval_seconds: int = 6 * 60 * 60,
        cicap_access_log_path: str = "/var/log/cicap-access.log",
        blocklog_retention_days: int = 30,
    ) -> None:
        self.lists_dir = lists_dir
        self.update_interval_seconds = update_interval_seconds
        self.cicap_access_log_path = cicap_access_log_path
        self.blocklog_retention_days = int(blocklog_retention_days)

        self._blocklog_started = False
        self._blocklog_lock = threading.Lock()
        self._last_events_prune_ts = 0

    def _connect(self):
        return connect()

    def init_db(self) -> None:
        pathlib.Path(self.lists_dir).mkdir(exist_ok=True, parents=True)
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS adblock_lists (
                    `key` VARCHAR(64) PRIMARY KEY,
                    url TEXT NOT NULL,
                    enabled TINYINT(1) NOT NULL DEFAULT 0,
                    last_success BIGINT NOT NULL DEFAULT 0,
                    last_attempt BIGINT NOT NULL DEFAULT 0,
                    last_error VARCHAR(500) NOT NULL DEFAULT '',
                    bytes BIGINT NOT NULL DEFAULT 0,
                    rules BIGINT NOT NULL DEFAULT 0
                )
                """,
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS adblock_meta (
                    k VARCHAR(64) PRIMARY KEY,
                    v TEXT NOT NULL
                )
                """,
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS adblock_cache_stats (
                    proxy_id VARCHAR(64) NOT NULL DEFAULT 'default',
                    k VARCHAR(64) NOT NULL,
                    v BIGINT NOT NULL
                    , PRIMARY KEY(proxy_id, k)
                )
                """,
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS adblock_settings (
                    k VARCHAR(64) PRIMARY KEY,
                    v TEXT NOT NULL
                )
                """,
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS adblock_counts (
                    proxy_id VARCHAR(64) NOT NULL DEFAULT 'default',
                    day BIGINT NOT NULL,
                    list_key VARCHAR(64) NOT NULL,
                    blocked BIGINT NOT NULL,
                    PRIMARY KEY(proxy_id, day, list_key)
                )
                """,
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS adblock_events (
                    id BIGINT PRIMARY KEY AUTO_INCREMENT,
                    proxy_id VARCHAR(64) NOT NULL DEFAULT 'default',
                    event_key CHAR(40) NOT NULL,
                    ts BIGINT NOT NULL,
                    src_ip VARCHAR(64) NOT NULL,
                    method VARCHAR(16) NOT NULL,
                    url TEXT NOT NULL,
                    http_status INT NOT NULL,
                    http_resp_line VARCHAR(255) NOT NULL,
                    icap_status INT NOT NULL,
                    raw TEXT NOT NULL,
                    created_ts BIGINT NOT NULL,
                    KEY idx_adblock_events_proxy_ts (proxy_id, ts, id),
                    UNIQUE KEY idx_adblock_events_proxy_uniq (proxy_id, event_key)
                )
                """,
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS adblock_proxy_meta (
                    proxy_id VARCHAR(64) NOT NULL DEFAULT 'default',
                    k VARCHAR(64) NOT NULL,
                    v TEXT NOT NULL,
                    PRIMARY KEY(proxy_id, k)
                )
                """,
            )

            for key, url in _DEFAULT_LISTS.items():
                conn.execute(
                    """
                    INSERT INTO adblock_lists(`key`, url, enabled)
                    VALUES(%s,%s,0) AS incoming
                    ON DUPLICATE KEY UPDATE url=incoming.url;
                    """,
                    (key, url),
                )

            for k, v in _DEFAULT_SETTINGS.items():
                conn.execute(
                    "INSERT IGNORE INTO adblock_settings(k, v) VALUES(%s,%s)",
                    (k, v),
                )

            conn.execute(
                "INSERT IGNORE INTO adblock_meta(k, v) VALUES('settings_version','1')",
            )
            conn.execute(
                "INSERT IGNORE INTO adblock_meta(k, v) VALUES('refresh_requested','0')",
            )
            proxy_id = get_proxy_id()
            for k in ("hits", "misses", "evictions"):
                conn.execute(
                    "INSERT IGNORE INTO adblock_cache_stats(proxy_id,k,v) VALUES(%s,%s,0)",
                    (proxy_id, k),
                )
            for key in (
                "cache_flush_requested",
                "cache_last_flush",
                "cache_current_size",
                "cicap_access_pos",
                "cicap_access_inode",
            ):
                conn.execute(
                    "INSERT IGNORE INTO adblock_proxy_meta(proxy_id,k,v) VALUES(%s,%s,'0')",
                    (proxy_id, key),
                )

    def _get_meta(self, conn, key: str, default: str = "") -> str:
        row = conn.execute("SELECT v FROM adblock_meta WHERE k=%s", (key,)).fetchone()
        return str(row[0]) if row and row[0] is not None else default

    def _set_meta(self, conn, key: str, value: str) -> None:
        result = conn.execute(
            "UPDATE adblock_meta SET v=%s WHERE k=%s",
            (value, key),
        )
        if int(getattr(result, "rowcount", 0) or 0) <= 0:
            try:
                conn.execute(
                    "INSERT INTO adblock_meta(k,v) VALUES(%s,%s)",
                    (key, value),
                )
            except INTEGRITY_ERRORS as exc:
                if not _is_duplicate_key_error(exc):
                    raise
                conn.execute(
                    "UPDATE adblock_meta SET v=%s WHERE k=%s",
                    (value, key),
                )

    def _get_proxy_meta(self, conn, key: str, default: str = "") -> str:
        row = conn.execute(
            "SELECT v FROM adblock_proxy_meta WHERE proxy_id=%s AND k=%s",
            (get_proxy_id(), key),
        ).fetchone()
        return str(row[0]) if row and row[0] is not None else default

    def _set_proxy_meta(self, conn, key: str, value: str) -> None:
        proxy_id = get_proxy_id()
        result = conn.execute(
            "UPDATE adblock_proxy_meta SET v=%s WHERE proxy_id=%s AND k=%s",
            (value, proxy_id, key),
        )
        if int(getattr(result, "rowcount", 0) or 0) <= 0:
            try:
                conn.execute(
                    "INSERT INTO adblock_proxy_meta(proxy_id,k,v) VALUES(%s,%s,%s)",
                    (proxy_id, key, value),
                )
            except INTEGRITY_ERRORS as exc:
                if not _is_duplicate_key_error(exc):
                    raise
                conn.execute(
                    "UPDATE adblock_proxy_meta SET v=%s WHERE proxy_id=%s AND k=%s",
                    (value, proxy_id, key),
                )

    def _set_proxy_meta_values(self, conn, values: dict[str, str]) -> None:
        for key in sorted(values):
            self._set_proxy_meta(conn, key, values[key])

    def start_blocklog_background(self) -> None:
        with self._blocklog_lock:
            if self._blocklog_started:
                return
            self.init_db()

            # Seed only if empty to avoid duplicating historical lines.
            try:
                with self._connect() as conn:
                    n = int(
                        conn.execute(
                            "SELECT COUNT(*) FROM adblock_events WHERE proxy_id=%s",
                            (get_proxy_id(),),
                        ).fetchone()[0]
                        or 0,
                    )
                    if n == 0:
                        self._seed_from_recent_log(conn)
            except Exception:
                log_exception_throttled(
                    logger,
                    "adblock_store.blocklog.seed",
                    interval_seconds=300.0,
                    message="Adblock blocklog seed failed",
                )

            t = threading.Thread(
                target=self._blocklog_tail_loop,
                name="adblock-cicap-tailer",
                daemon=True,
            )
            t.start()
            self._blocklog_started = True

    def _seed_from_recent_log(self, conn, max_lines: int = 5000) -> None:
        lines = self._read_last_lines(self.cicap_access_log_path, max_lines=max_lines)
        if not lines:
            return
        for ln in lines:
            row = self._parse_cicap_access_line(ln)
            if row:
                self._insert_event(conn, row)
        self._prune_events(conn)

    def _read_last_lines(self, path: str, *, max_lines: int) -> list[str]:
        try:
            with pathlib.Path(path).open("rb") as f:
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
        while True:
            try:
                path = self.cicap_access_log_path
                if path and pathlib.Path(path).exists():
                    with self._connect() as conn:
                        self._ingest_new_cicap_lines(conn)
            except DATABASE_ERRORS as exc:
                log_database_unavailable(
                    logger,
                    "adblock_store.blocklog.db_unavailable",
                    "Adblock blocklog tailer deferred database work while MySQL is unavailable",
                    exc,
                )
            except Exception:
                log_exception_throttled(
                    logger,
                    "adblock_store.blocklog.loop",
                    interval_seconds=300.0,
                    message="Adblock blocklog tailer loop failed",
                )
            time.sleep(1.0)

    def _ingest_new_cicap_lines(self, conn) -> None:
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
            last_inode = int(self._get_proxy_meta(conn, "cicap_access_inode", "0") or 0)
        except Exception:
            last_inode = 0
        try:
            pos = int(self._get_proxy_meta(conn, "cicap_access_pos", "0") or 0)
        except Exception:
            pos = 0

        if inode != 0 and last_inode not in {0, inode}:
            # Log rotated/recreated.
            pos = 0
        if size < pos:
            # Truncated.
            pos = 0

        # Read incremental bytes from last pos.
        try:
            with pathlib.Path(path).open("rb") as f:
                f.seek(pos, os.SEEK_SET)
                data = f.read()
                new_pos = f.tell()
        except Exception:
            return

        if not data:
            # Still update inode if it changed (so we don't keep resetting).
            try:
                self._set_proxy_meta_values(
                    conn,
                    {
                        "cicap_access_inode": str(inode),
                        "cicap_access_pos": str(pos),
                    },
                )
                conn.commit()
            except Exception:
                with contextlib.suppress(Exception):
                    conn.rollback()
            return

        created_ts = _now()
        event_rows: list[tuple[int, str, str, str, int, str, int, str, int]] = []
        text = data.decode("utf-8", errors="replace")
        proxy_id = get_proxy_id()
        for ln in text.splitlines():
            row = self._parse_cicap_access_line(ln)
            if not row:
                continue
            dedupe_key = _event_key(
                int(row.get("ts") or 0),
                str(row.get("src_ip") or "-"),
                str(row.get("url") or ""),
                int(row.get("http_status") or 0),
            )
            event_rows.append(
                (
                    proxy_id,
                    dedupe_key,
                    int(row.get("ts") or 0),
                    str(row.get("src_ip") or "-"),
                    str(row.get("method") or "-"),
                    str(row.get("url") or ""),
                    int(row.get("http_status") or 0),
                    str(row.get("http_resp_line") or ""),
                    int(row.get("icap_status") or 0),
                    str(row.get("raw") or ""),
                    created_ts,
                ),
            )

        try:
            if event_rows:
                conn.executemany(
                    """
                    INSERT IGNORE INTO adblock_events(
                        proxy_id, event_key, ts, src_ip, method, url, http_status, http_resp_line, icap_status, raw, created_ts
                    ) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """,
                    event_rows,
                )

            self._set_proxy_meta_values(
                conn,
                {
                    "cicap_access_inode": str(inode),
                    "cicap_access_pos": str(new_pos),
                },
            )

            if event_rows:
                if created_ts - int(self._last_events_prune_ts or 0) >= 60:
                    self._prune_events(conn)
                    self._last_events_prune_ts = created_ts
            conn.commit()
        except Exception:
            with contextlib.suppress(Exception):
                conn.rollback()
            raise

    def _parse_cicap_access_line(self, line: str) -> dict[str, Any] | None:
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

        src_ip = (
            http_client_ip if http_client_ip and http_client_ip != "-" else remote_ip
        )
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
            icap_status = (
                int(icap_status_s) if (icap_status_s or "").strip().isdigit() else 0
            )
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

    def _insert_event(self, conn, row: dict[str, Any]) -> None:
        dedupe_key = _event_key(
            int(row.get("ts") or 0),
            str(row.get("src_ip") or "-"),
            str(row.get("url") or ""),
            int(row.get("http_status") or 0),
        )
        conn.execute(
            """
            INSERT IGNORE INTO adblock_events(
                proxy_id, event_key, ts, src_ip, method, url, http_status, http_resp_line, icap_status, raw, created_ts
            ) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            (
                get_proxy_id(),
                dedupe_key,
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

    def _prune_events(self, conn) -> None:
        days = max(1, int(self.blocklog_retention_days or 30))
        cutoff = _now() - days * 24 * 3600
        conn.execute("DELETE FROM adblock_events WHERE ts < %s", (int(cutoff),))

    def prune_old_entries(self, *, retention_days: int = 30) -> None:
        """Prune old benign blocklog data to keep the DB bounded."""
        self.init_db()
        days = max(1, int(retention_days or 30))
        cutoff = _now() - days * 24 * 3600
        cutoff_day = int(cutoff // 86400)
        with self._connect() as conn:
            conn.execute("DELETE FROM adblock_events WHERE ts < %s", (int(cutoff),))
            # Daily rollup rows are small, but keep them aligned with the same retention.
            conn.execute(
                "DELETE FROM adblock_counts WHERE day < %s",
                (int(cutoff_day),),
            )

    def list_recent_block_events(self, limit: int = 100) -> list[dict[str, Any]]:
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
                WHERE proxy_id=%s
                ORDER BY ts DESC, id DESC
                LIMIT %s
                """,
                (get_proxy_id(), limit_i),
            ).fetchall()

        out: list[dict[str, Any]] = [
            {
                "ts": int(r[0] or 0),
                "src_ip": str(r[1] or "-"),
                "method": str(r[2] or "-"),
                "url": str(r[3] or ""),
                "result": "BLOCKED",
                "status": str(int(r[4] or 0)),
            }
            for r in rows
        ]
        return out

    def get_settings(self) -> dict[str, Any]:
        def as_int(s: str, default: int) -> int:
            try:
                return int((s or "").strip())
            except Exception:
                return default

        with self._connect() as conn:
            rows = conn.execute("SELECT k, v FROM adblock_settings").fetchall()
            m = {str(r[0]): str(r[1]) for r in rows}

        enabled = (m.get("enabled") or _DEFAULT_SETTINGS["enabled"]).strip() == "1"
        cache_ttl = as_int(
            m.get("cache_ttl") or _DEFAULT_SETTINGS["cache_ttl"],
            int(_DEFAULT_SETTINGS["cache_ttl"]),
        )
        cache_max = as_int(
            m.get("cache_max") or _DEFAULT_SETTINGS["cache_max"],
            int(_DEFAULT_SETTINGS["cache_max"]),
        )

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
                "INSERT INTO adblock_settings(k,v) VALUES('enabled',%s) AS incoming ON DUPLICATE KEY UPDATE v=incoming.v",
                ("1" if enabled else "0",),
            )
            conn.execute(
                "INSERT INTO adblock_settings(k,v) VALUES('cache_ttl',%s) AS incoming ON DUPLICATE KEY UPDATE v=incoming.v",
                (str(cache_ttl),),
            )
            conn.execute(
                "INSERT INTO adblock_settings(k,v) VALUES('cache_max',%s) AS incoming ON DUPLICATE KEY UPDATE v=incoming.v",
                (str(cache_max),),
            )
            self._bump_version(conn)

    def _bump_version(self, conn) -> None:
        cur = conn.execute(
            "SELECT v FROM adblock_meta WHERE k='settings_version'",
        ).fetchone()
        try:
            v = int(cur[0]) if cur else 1
        except Exception:
            v = 1
        conn.execute(
            "INSERT INTO adblock_meta(k,v) VALUES('settings_version',%s) AS incoming ON DUPLICATE KEY UPDATE v=incoming.v",
            (str(v + 1),),
        )

    def request_refresh_now(self) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO adblock_meta(k,v) VALUES('refresh_requested',%s) AS incoming ON DUPLICATE KEY UPDATE v=incoming.v",
                (str(_now()),),
            )

    def clear_refresh_requested(self) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO adblock_meta(k,v) VALUES('refresh_requested','0') AS incoming ON DUPLICATE KEY UPDATE v=incoming.v",
            )

    def request_cache_flush(self) -> None:
        with self._connect() as conn:
            self._set_proxy_meta(conn, "cache_flush_requested", str(_now()))

    def mark_cache_flushed(self, *, size: int | None = None) -> None:
        with self._connect() as conn:
            self._set_proxy_meta(conn, "cache_flush_requested", "0")
            self._set_proxy_meta(conn, "cache_last_flush", str(_now()))
            if size is not None:
                self._set_proxy_meta(conn, "cache_current_size", str(max(0, int(size))))

    def get_settings_version(self) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT v FROM adblock_meta WHERE k='settings_version'",
            ).fetchone()
            try:
                return int(row[0]) if row else 1
            except Exception:
                return 1

    def get_refresh_requested(self) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT v FROM adblock_meta WHERE k='refresh_requested'",
            ).fetchone()
            try:
                return int(row[0]) if row else 0
            except Exception:
                return 0

    def get_cache_flush_requested(self) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT v FROM adblock_proxy_meta WHERE proxy_id=%s AND k='cache_flush_requested'",
                (get_proxy_id(),),
            ).fetchone()
            try:
                return int(row[0]) if row else 0
            except Exception:
                return 0

    def list_statuses(self) -> list[ListStatus]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT `key`, url, enabled, last_success, last_attempt, last_error, bytes, rules FROM adblock_lists ORDER BY `key`",
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

    def set_enabled(self, enabled_map: dict[str, bool]) -> None:
        with self._connect() as conn:
            rows = [
                (1 if enabled else 0, key)
                for key, enabled in (enabled_map or {}).items()
            ]
            if rows:
                conn.executemany(
                    "UPDATE adblock_lists SET enabled=%s WHERE `key`=%s",
                    rows,
                )
            self._bump_version(conn)

    def list_path(self, key: str) -> str:
        safe = "".join([c for c in (key or "") if c.isalnum() or c in {"-", "_"}])
        return os.path.join(self.lists_dir, f"{safe}.txt")

    def record_block(self, list_key: str) -> None:
        day = int(_now() // 86400)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO adblock_counts(proxy_id, day, list_key, blocked) VALUES(%s,%s,%s,1)
                ON DUPLICATE KEY UPDATE blocked = blocked + 1
                """,
                (get_proxy_id(), day, list_key),
            )

    def record_blocks_bulk(self, counts: dict[str, int]) -> None:
        """Bulk increment blocked counters.

        This is meant for the ICAP hot path: accumulate counts in memory and
        flush periodically to avoid per-request writes.
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
            rows.append((get_proxy_id(), day, str(k), n))
        if not rows:
            return

        with self._connect() as conn:
            conn.executemany(
                """
                INSERT INTO adblock_counts(proxy_id, day, list_key, blocked) VALUES(%s,%s,%s,%s) AS incoming
                ON DUPLICATE KEY UPDATE blocked = blocked + incoming.blocked
                """,
                rows,
            )

    def stats(self) -> dict[str, Any]:
        now = _now()
        day = int(now // 86400)
        day_ago = day - 1
        proxy_id = get_proxy_id()
        with self._connect() as conn:
            total = conn.execute(
                "SELECT COALESCE(SUM(blocked),0) FROM adblock_counts WHERE proxy_id=%s",
                (proxy_id,),
            ).fetchone()[0]
            last_24h = conn.execute(
                "SELECT COALESCE(SUM(blocked),0) FROM adblock_counts WHERE proxy_id=%s AND day IN (%s,%s)",
                (proxy_id, day, day_ago),
            ).fetchone()[0]
            by_list = conn.execute(
                "SELECT list_key, COALESCE(SUM(blocked),0) AS blocked FROM adblock_counts WHERE proxy_id=%s GROUP BY list_key ORDER BY list_key",
                (proxy_id,),
            ).fetchall()
            by_list_24h = conn.execute(
                "SELECT list_key, COALESCE(SUM(blocked),0) AS blocked FROM adblock_counts WHERE proxy_id=%s AND day IN (%s,%s) GROUP BY list_key ORDER BY list_key",
                (proxy_id, day, day_ago),
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

    def download_list(
        self,
        key: str,
        url: str,
        timeout_seconds: int = 25,
    ) -> tuple[bool, str, int, int]:
        """Returns (ok, err, bytes, rules)."""
        path = self.list_path(key)
        tmp = path + ".tmp"
        try:
            try:
                _validate_download_url(url)
            except ValueError as exc:
                return False, str(exc), 0, 0

            max_bytes = int(
                os.environ.get("ADBLOCK_MAX_DOWNLOAD_BYTES", str(64 * 1024 * 1024)),
            )
            if max_bytes <= 0:
                max_bytes = 64 * 1024 * 1024

            list_dir = pathlib.Path(path).parent
            if list_dir:
                pathlib.Path(list_dir).mkdir(exist_ok=True, parents=True)

            total = 0
            with _open_download_url(url, timeout=timeout_seconds) as resp:
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

                with pathlib.Path(tmp).open("wb") as f:
                    while True:
                        chunk = resp.read(256 * 1024)
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > max_bytes:
                            msg = f"Download exceeded limit ({max_bytes} bytes)."
                            raise ValueError(msg)
                        f.write(chunk)

            pathlib.Path(tmp).replace(path)

            # Rough rule count: ignore comments/blank.
            rules = 0
            try:
                with pathlib.Path(path).open(encoding="utf-8", errors="replace") as rf:
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
                if pathlib.Path(tmp).exists():
                    pathlib.Path(tmp).unlink()
            except OSError:
                pass
            logger.exception("Adblock list download failed (key=%s)", key)
            return (
                False,
                public_error_message(
                    e,
                    default="Download failed. Check server logs for details.",
                    max_len=400,
                ),
                0,
                0,
            )

    def update_one(self, key: str, force: bool = False) -> bool:
        now_ts = _now()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT `key`, url, enabled, last_success, last_attempt, last_error, bytes, rules FROM adblock_lists WHERE `key`=%s",
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
            conn.execute(
                "UPDATE adblock_lists SET last_attempt=%s WHERE `key`=%s",
                (now_ts, key),
            )

        ok, err, b, rules = self.download_list(key, status.url)
        with self._connect() as conn:
            if ok:
                conn.execute(
                    "UPDATE adblock_lists SET last_success=%s, last_error='', bytes=%s, rules=%s WHERE `key`=%s",
                    (now_ts, int(b), int(rules), key),
                )
                return True
            conn.execute(
                "UPDATE adblock_lists SET last_error=%s WHERE `key`=%s",
                (err[:400], key),
            )
            return False

    def record_cache_stats(
        self,
        *,
        hits: int = 0,
        misses: int = 0,
        evictions: int = 0,
        size: int | None = None,
    ) -> None:
        proxy_id = get_proxy_id()
        with self._connect() as conn:
            if hits:
                conn.execute(
                    "INSERT INTO adblock_cache_stats(proxy_id,k,v) VALUES(%s, 'hits', %s) AS incoming ON DUPLICATE KEY UPDATE v = v + incoming.v",
                    (proxy_id, int(hits)),
                )
            if misses:
                conn.execute(
                    "INSERT INTO adblock_cache_stats(proxy_id,k,v) VALUES(%s, 'misses', %s) AS incoming ON DUPLICATE KEY UPDATE v = v + incoming.v",
                    (proxy_id, int(misses)),
                )
            if evictions:
                conn.execute(
                    "INSERT INTO adblock_cache_stats(proxy_id,k,v) VALUES(%s, 'evictions', %s) AS incoming ON DUPLICATE KEY UPDATE v = v + incoming.v",
                    (proxy_id, int(evictions)),
                )
            if size is not None:
                self._set_proxy_meta(conn, "cache_current_size", str(max(0, int(size))))

    def cache_stats(self) -> dict[str, int]:
        proxy_id = get_proxy_id()
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT k, v FROM adblock_cache_stats WHERE proxy_id=%s",
                (proxy_id,),
            ).fetchall()
            meta_rows = conn.execute(
                "SELECT k, v FROM adblock_proxy_meta WHERE proxy_id=%s AND k IN ('cache_current_size','cache_last_flush','cache_flush_requested')",
                (proxy_id,),
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


_store: AdblockStore | None = None
_store_lock = threading.Lock()


def get_adblock_store() -> AdblockStore:
    global _store
    if _store is not None:
        return _store
    with _store_lock:
        if _store is None:
            _store = AdblockStore(
                lists_dir=os.environ.get(
                    "ADBLOCK_LISTS_DIR",
                    "/var/lib/squid-flask-proxy/adblock/lists",
                ),
                update_interval_seconds=_env_int(
                    "ADBLOCK_UPDATE_INTERVAL",
                    6 * 60 * 60,
                ),
                cicap_access_log_path=os.environ.get(
                    "CICAP_ACCESS_LOG",
                    "/var/log/cicap-access.log",
                ),
                blocklog_retention_days=_env_int("ADBLOCK_BLOCKLOG_RETENTION_DAYS", 30),
            )
        return _store
