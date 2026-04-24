from __future__ import annotations

import csv
import hashlib
import io
import logging
import os
import threading
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from services.db import connect
from services.logutil import log_exception_throttled
from services.proxy_context import get_proxy_id
from services.runtime_helpers import env_float as _env_float, env_int as _env_int, escape_like as _escape_like, now_ts as _now


logger = logging.getLogger(__name__)


_REQUEST_DIMENSIONS: Dict[str, str] = {
    "client_ip": "client_ip",
    "user_agent": "user_agent",
    "bump_mode": "bump_mode",
    "tls_server_version": "tls_server_version",
    "tls_client_version": "tls_client_version",
    "domain": "domain",
}


def _safe_int(value: object, default: int = 0) -> int:
    try:
        if value is None:
            return int(default)
        text = str(value).strip()
        if not text:
            return int(default)
        return int(float(text))
    except Exception:
        return int(default)


def _safe_text(value: object, *, max_len: int = 0) -> str:
    text = str(value or "").strip()
    if max_len > 0:
        return text[:max_len]
    return text


def _split_tsv(line: str) -> list[str]:
    s = (line or "").strip("\r\n")
    if not s:
        return []
    if "\\t" in s and "\t" not in s:
        s = s.replace("\\t", "\t")
    try:
        row = next(csv.reader(io.StringIO(s), delimiter="\t", quotechar='"'))
    except Exception:
        return []
    return [item.strip() for item in row]


def _normalize_hostish(value: object) -> str:
    host = _safe_text(value, max_len=255).lower().strip().lstrip(".")
    if not host:
        return ""
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if "/" in host:
        host = host.split("/", 1)[0]
    if "?" in host:
        host = host.split("?", 1)[0]
    if "#" in host:
        host = host.split("#", 1)[0]
    return host


def _extract_domain(url: object, *, host: object = "", sni: object = "") -> str:
    for candidate in (sni, host):
        normalized = _normalize_hostish(candidate)
        if normalized:
            return normalized

    raw = _safe_text(url)
    if not raw:
        return ""

    try:
        parts = urlsplit(raw)
        if parts.hostname:
            return _normalize_hostish(parts.hostname)
    except Exception:
        pass

    cand = raw.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in cand:
        cand = cand.split("@", 1)[1]
    if cand.startswith("[") and "]" in cand:
        return _normalize_hostish(cand[1 : cand.find("]")])
    if ":" in cand:
        host_part, port = cand.rsplit(":", 1)
        if port.isdigit():
            cand = host_part
    return _normalize_hostish(cand)


def _parse_status(result_code: str) -> int:
    raw = _safe_text(result_code, max_len=96)
    if "/" not in raw:
        return 0
    tail = raw.rsplit("/", 1)[1].strip()
    return int(tail) if tail.isdigit() else 0


def _event_key(*parts: object) -> str:
    normalized = "|".join(str(part or "") for part in parts)
    return hashlib.sha1(normalized.encode("utf-8", errors="replace")).hexdigest()


def _policy_tags(*, exclusion_rule: str, ssl_exception: str, webfilter_allow: str, cache_bypass: str) -> list[str]:
    tags: list[str] = []
    if exclusion_rule:
        tags.append(f"exclude:{exclusion_rule}")
    if ssl_exception:
        tags.append(f"ssl:{ssl_exception}")
    if webfilter_allow:
        tags.append(f"webfilter:{webfilter_allow}")
    if cache_bypass:
        tags.append(f"cache:{cache_bypass}")
    return tags


def _service_family(adapt_summary: str, adapt_details: str) -> str:
    haystack = f"{adapt_summary} {adapt_details}".lower()
    if any(token in haystack for token in ("avrespmod", "virus_scan", "clamd", "av_resp")):
        return "av"
    if any(token in haystack for token in ("adblockreq", "adblock_req", "adblock")):
        return "adblock"
    return "other"


def _service_label(family: str) -> str:
    if family == "av":
        return "AV / ClamAV"
    if family == "adblock":
        return "Adblock"
    return "Other ICAP"


def _request_target_display(row: Dict[str, Any]) -> str:
    return (
        _safe_text(row.get("domain"), max_len=255)
        or _safe_text(row.get("sni"), max_len=255)
        or _safe_text(row.get("host"), max_len=255)
        or _safe_text(row.get("url"), max_len=255)
        or "-"
    )


def _request_tls_summary(row: Dict[str, Any]) -> str:
    parts: list[str] = []
    bump_mode = _safe_text(row.get("bump_mode"), max_len=64)
    if bump_mode:
        parts.append(f"bump={bump_mode}")
    sni = _safe_text(row.get("sni"), max_len=255)
    if sni:
        parts.append(f"sni={sni}")
    server_version = _safe_text(row.get("tls_server_version"), max_len=64)
    server_cipher = _safe_text(row.get("tls_server_cipher"), max_len=128)
    if server_version:
        cipher_text = f"/{server_cipher}" if server_cipher else ""
        parts.append(f"server={server_version}{cipher_text}")
    client_version = _safe_text(row.get("tls_client_version"), max_len=64)
    client_cipher = _safe_text(row.get("tls_client_cipher"), max_len=128)
    if client_version:
        cipher_text = f"/{client_cipher}" if client_cipher else ""
        parts.append(f"client={client_version}{cipher_text}")
    return " · ".join(parts)


def _normalize_request_row(row: Any) -> Dict[str, Any]:
    data = {
        "ts": int(row[0] or 0),
        "duration_ms": int(row[1] or 0),
        "client_ip": _safe_text(row[2], max_len=64),
        "method": _safe_text(row[3], max_len=16),
        "url": _safe_text(row[4]),
        "domain": _safe_text(row[5], max_len=255),
        "result_code": _safe_text(row[6], max_len=96),
        "http_status": int(row[7] or 0),
        "bytes": int(row[8] or 0),
        "master_xaction": _safe_text(row[9], max_len=128),
        "hierarchy_status": _safe_text(row[10], max_len=255),
        "bump_mode": _safe_text(row[11], max_len=64),
        "sni": _safe_text(row[12], max_len=255),
        "tls_server_version": _safe_text(row[13], max_len=64),
        "tls_server_cipher": _safe_text(row[14], max_len=128),
        "tls_client_version": _safe_text(row[15], max_len=64),
        "tls_client_cipher": _safe_text(row[16], max_len=128),
        "host": _safe_text(row[17], max_len=255),
        "user_agent": _safe_text(row[18], max_len=512),
        "referer": _safe_text(row[19], max_len=512),
        "exclusion_rule": _safe_text(row[20], max_len=64),
        "ssl_exception": _safe_text(row[21], max_len=64),
        "webfilter_allow": _safe_text(row[22], max_len=64),
        "cache_bypass": _safe_text(row[23], max_len=64),
    }
    data["target_display"] = _request_target_display(data)
    data["policy_tags"] = _policy_tags(
        exclusion_rule=data["exclusion_rule"],
        ssl_exception=data["ssl_exception"],
        webfilter_allow=data["webfilter_allow"],
        cache_bypass=data["cache_bypass"],
    )
    data["tls_summary"] = _request_tls_summary(data)
    return data


def _normalize_icap_row(row: Any) -> Dict[str, Any]:
    data = {
        "ts": int(row[0] or 0),
        "master_xaction": _safe_text(row[1], max_len=128),
        "client_ip": _safe_text(row[2], max_len=64),
        "method": _safe_text(row[3], max_len=16),
        "url": _safe_text(row[4]),
        "domain": _safe_text(row[5], max_len=255),
        "icap_time_ms": int(row[6] or 0),
        "adapt_summary": _safe_text(row[7], max_len=1024),
        "adapt_details": _safe_text(row[8]),
        "host": _safe_text(row[9], max_len=255),
        "user_agent": _safe_text(row[10], max_len=512),
        "sni": _safe_text(row[11], max_len=255),
        "exclusion_rule": _safe_text(row[12], max_len=64),
        "ssl_exception": _safe_text(row[13], max_len=64),
        "webfilter_allow": _safe_text(row[14], max_len=64),
        "cache_bypass": _safe_text(row[15], max_len=64),
        "service_family": _safe_text(row[16], max_len=32),
    }
    data["service_label"] = _service_label(data["service_family"])
    data["target_display"] = (
        data["domain"] or data["sni"] or data["host"] or _safe_text(data["url"], max_len=255) or "-"
    )
    data["policy_tags"] = _policy_tags(
        exclusion_rule=data["exclusion_rule"],
        ssl_exception=data["ssl_exception"],
        webfilter_allow=data["webfilter_allow"],
        cache_bypass=data["cache_bypass"],
    )
    return data


class DiagnosticStore:
    def __init__(
        self,
        access_log_path: str = "/var/log/squid/access-observe.log",
        icap_log_path: str = "/var/log/squid/icap.log",
        seed_max_lines: int = 5000,
        retention_days: int = 7,
    ):
        self.access_log_path = access_log_path
        self.icap_log_path = icap_log_path
        self.seed_max_lines = seed_max_lines
        self.retention_days = max(1, int(retention_days or 7))

        self._started = False
        self._start_lock = threading.Lock()

    def _connect(self):
        return connect()

    def init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS diagnostic_requests (
                    id BIGINT PRIMARY KEY AUTO_INCREMENT,
                    proxy_id VARCHAR(64) NOT NULL DEFAULT 'default',
                    event_key CHAR(40) NOT NULL,
                    ts BIGINT NOT NULL,
                    duration_ms INT NOT NULL DEFAULT 0,
                    client_ip VARCHAR(64) NOT NULL,
                    method VARCHAR(16) NOT NULL,
                    url TEXT NOT NULL,
                    domain VARCHAR(255) NOT NULL,
                    result_code VARCHAR(96) NOT NULL,
                    http_status INT NOT NULL DEFAULT 0,
                    bytes BIGINT NOT NULL DEFAULT 0,
                    master_xaction VARCHAR(128) NOT NULL,
                    hierarchy_status VARCHAR(255) NOT NULL,
                    bump_mode VARCHAR(64) NOT NULL,
                    sni VARCHAR(255) NOT NULL,
                    tls_server_version VARCHAR(64) NOT NULL,
                    tls_server_cipher VARCHAR(128) NOT NULL,
                    tls_client_version VARCHAR(64) NOT NULL,
                    tls_client_cipher VARCHAR(128) NOT NULL,
                    host VARCHAR(255) NOT NULL,
                    user_agent VARCHAR(512) NOT NULL,
                    referer VARCHAR(512) NOT NULL,
                    exclusion_rule VARCHAR(64) NOT NULL,
                    ssl_exception VARCHAR(64) NOT NULL,
                    webfilter_allow VARCHAR(64) NOT NULL,
                    cache_bypass VARCHAR(64) NOT NULL,
                    raw TEXT NOT NULL,
                    created_ts BIGINT NOT NULL,
                    UNIQUE KEY idx_diagnostic_requests_proxy_event (proxy_id, event_key),
                    KEY idx_diagnostic_requests_proxy_ts (proxy_id, ts, id),
                    KEY idx_diagnostic_requests_proxy_tx (proxy_id, master_xaction, ts),
                    KEY idx_diagnostic_requests_proxy_domain (proxy_id, domain, ts),
                    KEY idx_diagnostic_requests_proxy_client (proxy_id, client_ip, ts)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS diagnostic_icap_events (
                    id BIGINT PRIMARY KEY AUTO_INCREMENT,
                    proxy_id VARCHAR(64) NOT NULL DEFAULT 'default',
                    event_key CHAR(40) NOT NULL,
                    ts BIGINT NOT NULL,
                    master_xaction VARCHAR(128) NOT NULL,
                    client_ip VARCHAR(64) NOT NULL,
                    method VARCHAR(16) NOT NULL,
                    url TEXT NOT NULL,
                    domain VARCHAR(255) NOT NULL,
                    icap_time_ms INT NOT NULL DEFAULT 0,
                    adapt_summary VARCHAR(1024) NOT NULL,
                    adapt_details TEXT NOT NULL,
                    host VARCHAR(255) NOT NULL,
                    user_agent VARCHAR(512) NOT NULL,
                    sni VARCHAR(255) NOT NULL,
                    exclusion_rule VARCHAR(64) NOT NULL,
                    ssl_exception VARCHAR(64) NOT NULL,
                    webfilter_allow VARCHAR(64) NOT NULL,
                    cache_bypass VARCHAR(64) NOT NULL,
                    service_family VARCHAR(32) NOT NULL,
                    raw TEXT NOT NULL,
                    created_ts BIGINT NOT NULL,
                    UNIQUE KEY idx_diagnostic_icap_proxy_event (proxy_id, event_key),
                    KEY idx_diagnostic_icap_proxy_ts (proxy_id, ts, id),
                    KEY idx_diagnostic_icap_proxy_tx (proxy_id, master_xaction, ts),
                    KEY idx_diagnostic_icap_proxy_domain (proxy_id, domain, ts),
                    KEY idx_diagnostic_icap_proxy_service (proxy_id, service_family, ts)
                )
                """
            )

    def prune_old_entries(self, *, retention_days: int = 0) -> None:
        days = max(1, int(retention_days or self.retention_days))
        cutoff = _now() - (days * 24 * 60 * 60)
        with self._connect() as conn:
            conn.execute("DELETE FROM diagnostic_icap_events WHERE ts < %s", (int(cutoff),))
            conn.execute("DELETE FROM diagnostic_requests WHERE ts < %s", (int(cutoff),))

    def start_background(self) -> None:
        with self._start_lock:
            if self._started:
                return
            self._started = True
            self.init_db()
            self.seed_from_recent_logs()

            request_thread = threading.Thread(
                target=self._tail_file_loop,
                args=(self.access_log_path, self._ingest_request_line_with_conn, "diagnostic-requests-tailer"),
                daemon=True,
            )
            request_thread.start()

            icap_thread = threading.Thread(
                target=self._tail_file_loop,
                args=(self.icap_log_path, self._ingest_icap_line_with_conn, "diagnostic-icap-tailer"),
                daemon=True,
            )
            icap_thread.start()

    def _read_last_lines(self, path: str, *, max_lines: int) -> List[str]:
        if not path or not os.path.exists(path):
            return []
        try:
            with open(path, "rb") as handle:
                handle.seek(0, os.SEEK_END)
                size = handle.tell()
                read_size = min(size, max_lines * 512)
                if read_size > 0:
                    handle.seek(-read_size, os.SEEK_END)
                chunk = handle.read().decode("utf-8", errors="replace")
            return [line for line in chunk.splitlines()[-max_lines:] if line.strip()]
        except Exception:
            return []

    def seed_from_recent_logs(self) -> None:
        request_lines = self._read_last_lines(self.access_log_path, max_lines=self.seed_max_lines)
        icap_lines = self._read_last_lines(self.icap_log_path, max_lines=self.seed_max_lines)
        if not request_lines and not icap_lines:
            return
        with self._connect() as conn:
            for line in request_lines:
                self._ingest_request_line_with_conn(conn, line)
            for line in icap_lines:
                self._ingest_icap_line_with_conn(conn, line)

    def _tail_file_loop(self, path: str, ingest_fn, loop_name: str) -> None:
        commit_batch = _env_int("DIAGNOSTIC_COMMIT_BATCH", 150, minimum=25, maximum=5000)
        commit_interval = _env_float("DIAGNOSTIC_COMMIT_INTERVAL_SECONDS", 2.0, minimum=0.25, maximum=10.0)
        poll_interval = _env_float("DIAGNOSTIC_POLL_INTERVAL_SECONDS", 0.5, minimum=0.1, maximum=5.0)
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
                    with open(path, "r", encoding="utf-8", errors="replace") as handle:
                        handle.seek(0, os.SEEK_END)
                        while True:
                            line = handle.readline()
                            if line:
                                try:
                                    if ingest_fn(conn, line):
                                        pending += 1
                                except Exception:
                                    try:
                                        conn.rollback()
                                    except Exception:
                                        log_exception_throttled(
                                            logger,
                                            f"diagnostic_store.rollback.{loop_name}",
                                            interval_seconds=300.0,
                                            message=f"Diagnostic tailer rollback failed while ingesting {loop_name}",
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
                                                f"diagnostic_store.commit.{loop_name}",
                                                interval_seconds=300.0,
                                                message=f"Diagnostic tailer rollback failed after commit in {loop_name}",
                                            )
                                    pending = 0
                                    last_commit = now
                                continue

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
                                            f"diagnostic_store.idle_commit.{loop_name}",
                                            interval_seconds=300.0,
                                            message=f"Diagnostic tailer rollback failed after idle commit in {loop_name}",
                                        )
                                pending = 0
                                last_commit = now

                            try:
                                if os.path.getsize(path) < handle.tell():
                                    handle.seek(0, os.SEEK_SET)
                                    continue
                            except Exception:
                                log_exception_throttled(
                                    logger,
                                    f"diagnostic_store.copytruncate.{loop_name}",
                                    interval_seconds=300.0,
                                    message=f"Diagnostic tailer copytruncate check failed for {loop_name}",
                                )

                            try:
                                inode_now = getattr(os.stat(path), "st_ino", None)
                            except OSError:
                                inode_now = None
                            if inode_now is not None and last_inode is not None and inode_now != last_inode:
                                last_inode = inode_now
                                try:
                                    conn.commit()
                                except Exception:
                                    log_exception_throttled(
                                        logger,
                                        f"diagnostic_store.rotate.{loop_name}",
                                        interval_seconds=300.0,
                                        message=f"Diagnostic tailer final commit failed during rotation for {loop_name}",
                                    )
                                break

                            time.sleep(poll_interval)
            except Exception:
                log_exception_throttled(
                    logger,
                    f"diagnostic_store.loop.{loop_name}",
                    interval_seconds=300.0,
                    message=f"Diagnostic tailer loop failed for {loop_name}",
                )
                time.sleep(max(1.0, poll_interval))

    def _parse_request_log_line(self, line: str) -> Optional[Dict[str, Any]]:
        row = _split_tsv(line)
        if len(row) < 22:
            return None

        ts = _safe_int(row[0], _now())
        duration_ms = _safe_int(row[1], 0)
        client_ip = _safe_text(row[2], max_len=64)
        method = _safe_text(row[3], max_len=16)
        url = _safe_text(row[4])
        result_code = _safe_text(row[5], max_len=96)
        byte_count = max(0, _safe_int(row[6], 0))
        master_xaction = _safe_text(row[7], max_len=128)
        hierarchy_status = _safe_text(row[8], max_len=255)
        bump_mode = _safe_text(row[9], max_len=64)
        sni = _safe_text(row[10], max_len=255)
        tls_server_version = _safe_text(row[11], max_len=64)
        tls_server_cipher = _safe_text(row[12], max_len=128)
        tls_client_version = _safe_text(row[13], max_len=64)
        tls_client_cipher = _safe_text(row[14], max_len=128)
        host = _safe_text(row[15], max_len=255)
        user_agent = _safe_text(row[16], max_len=512)
        referer = _safe_text(row[17], max_len=512)
        exclusion_rule = _safe_text(row[18], max_len=64)
        ssl_exception = _safe_text(row[19], max_len=64)
        webfilter_allow = _safe_text(row[20], max_len=64)
        cache_bypass = _safe_text(row[21], max_len=64)
        domain = _extract_domain(url, host=host, sni=sni)
        http_status = _parse_status(result_code)

        return {
            "ts": ts,
            "duration_ms": duration_ms,
            "client_ip": client_ip,
            "method": method,
            "url": url,
            "domain": domain,
            "result_code": result_code,
            "http_status": http_status,
            "bytes": byte_count,
            "master_xaction": master_xaction,
            "hierarchy_status": hierarchy_status,
            "bump_mode": bump_mode,
            "sni": sni,
            "tls_server_version": tls_server_version,
            "tls_server_cipher": tls_server_cipher,
            "tls_client_version": tls_client_version,
            "tls_client_cipher": tls_client_cipher,
            "host": host,
            "user_agent": user_agent,
            "referer": referer,
            "exclusion_rule": exclusion_rule,
            "ssl_exception": ssl_exception,
            "webfilter_allow": webfilter_allow,
            "cache_bypass": cache_bypass,
            "raw": (line or "").strip("\r\n")[:4000],
        }

    def _parse_icap_log_line(self, line: str) -> Optional[Dict[str, Any]]:
        row = _split_tsv(line)
        if len(row) < 15:
            return None

        ts = _safe_int(row[0], _now())
        master_xaction = _safe_text(row[1], max_len=128)
        client_ip = _safe_text(row[2], max_len=64)
        method = _safe_text(row[3], max_len=16)
        url = _safe_text(row[4])
        icap_time_ms = _safe_int(row[5], 0)
        adapt_summary = _safe_text(row[6], max_len=1024)
        adapt_details = _safe_text(row[7])
        host = _safe_text(row[8], max_len=255)
        user_agent = _safe_text(row[9], max_len=512)
        sni = _safe_text(row[10], max_len=255)
        exclusion_rule = _safe_text(row[11], max_len=64)
        ssl_exception = _safe_text(row[12], max_len=64)
        webfilter_allow = _safe_text(row[13], max_len=64)
        cache_bypass = _safe_text(row[14], max_len=64)
        domain = _extract_domain(url, host=host, sni=sni)
        family = _service_family(adapt_summary, adapt_details)

        return {
            "ts": ts,
            "master_xaction": master_xaction,
            "client_ip": client_ip,
            "method": method,
            "url": url,
            "domain": domain,
            "icap_time_ms": icap_time_ms,
            "adapt_summary": adapt_summary,
            "adapt_details": adapt_details,
            "host": host,
            "user_agent": user_agent,
            "sni": sni,
            "exclusion_rule": exclusion_rule,
            "ssl_exception": ssl_exception,
            "webfilter_allow": webfilter_allow,
            "cache_bypass": cache_bypass,
            "service_family": family,
            "raw": (line or "").strip("\r\n")[:4000],
        }

    def _ingest_request_line_with_conn(self, conn, line: str) -> bool:
        row = self._parse_request_log_line(line)
        if not row:
            return False
        proxy_id = get_proxy_id()
        event_key = _event_key(
            proxy_id,
            row.get("ts"),
            row.get("master_xaction"),
            row.get("client_ip"),
            row.get("method"),
            row.get("url"),
            row.get("result_code"),
            row.get("bytes"),
        )
        conn.execute(
            """
            INSERT IGNORE INTO diagnostic_requests (
                proxy_id, event_key, ts, duration_ms, client_ip, method, url, domain, result_code, http_status,
                bytes, master_xaction, hierarchy_status, bump_mode, sni, tls_server_version, tls_server_cipher,
                tls_client_version, tls_client_cipher, host, user_agent, referer, exclusion_rule, ssl_exception,
                webfilter_allow, cache_bypass, raw, created_ts
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            (
                proxy_id,
                event_key,
                int(row["ts"]),
                int(row["duration_ms"]),
                str(row["client_ip"]),
                str(row["method"]),
                str(row["url"]),
                str(row["domain"]),
                str(row["result_code"]),
                int(row["http_status"]),
                int(row["bytes"]),
                str(row["master_xaction"]),
                str(row["hierarchy_status"]),
                str(row["bump_mode"]),
                str(row["sni"]),
                str(row["tls_server_version"]),
                str(row["tls_server_cipher"]),
                str(row["tls_client_version"]),
                str(row["tls_client_cipher"]),
                str(row["host"]),
                str(row["user_agent"]),
                str(row["referer"]),
                str(row["exclusion_rule"]),
                str(row["ssl_exception"]),
                str(row["webfilter_allow"]),
                str(row["cache_bypass"]),
                str(row["raw"]),
                int(_now()),
            ),
        )
        return True

    def _ingest_icap_line_with_conn(self, conn, line: str) -> bool:
        row = self._parse_icap_log_line(line)
        if not row:
            return False
        proxy_id = get_proxy_id()
        event_key = _event_key(
            proxy_id,
            row.get("ts"),
            row.get("master_xaction"),
            row.get("url"),
            row.get("adapt_summary"),
            row.get("adapt_details"),
            row.get("service_family"),
        )
        conn.execute(
            """
            INSERT IGNORE INTO diagnostic_icap_events (
                proxy_id, event_key, ts, master_xaction, client_ip, method, url, domain, icap_time_ms,
                adapt_summary, adapt_details, host, user_agent, sni, exclusion_rule, ssl_exception,
                webfilter_allow, cache_bypass, service_family, raw, created_ts
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            (
                proxy_id,
                event_key,
                int(row["ts"]),
                str(row["master_xaction"]),
                str(row["client_ip"]),
                str(row["method"]),
                str(row["url"]),
                str(row["domain"]),
                int(row["icap_time_ms"]),
                str(row["adapt_summary"]),
                str(row["adapt_details"]),
                str(row["host"]),
                str(row["user_agent"]),
                str(row["sni"]),
                str(row["exclusion_rule"]),
                str(row["ssl_exception"]),
                str(row["webfilter_allow"]),
                str(row["cache_bypass"]),
                str(row["service_family"]),
                str(row["raw"]),
                int(_now()),
            ),
        )
        return True

    def list_recent_requests(
        self,
        *,
        since: Optional[int] = None,
        search: str = "",
        client_ip: str = "",
        domain: str = "",
        master_xaction: str = "",
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        where = ["proxy_id = %s"]
        params: List[Any] = [get_proxy_id()]
        if since is not None:
            where.append("ts >= %s")
            params.append(int(since))
        if client_ip:
            where.append("client_ip = %s")
            params.append(client_ip.strip())
        if domain:
            where.append("domain = %s")
            params.append(_normalize_hostish(domain))
        if master_xaction:
            where.append("master_xaction = %s")
            params.append(master_xaction.strip())
        if search:
            like = f"%{_escape_like(search.strip().lower())}%"
            where.append(
                "(" + " OR ".join(
                    [
                        "LOWER(domain) LIKE %s ESCAPE '\\\\'",
                        "LOWER(url) LIKE %s ESCAPE '\\\\'",
                        "LOWER(host) LIKE %s ESCAPE '\\\\'",
                        "LOWER(sni) LIKE %s ESCAPE '\\\\'",
                        "LOWER(master_xaction) LIKE %s ESCAPE '\\\\'",
                        "LOWER(client_ip) LIKE %s ESCAPE '\\\\'",
                        "LOWER(user_agent) LIKE %s ESCAPE '\\\\'",
                    ]
                ) + ")"
            )
            params.extend([like] * 7)
        where_sql = "WHERE " + " AND ".join(where)
        lim = max(1, min(200, int(limit)))

        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT
                    ts, duration_ms, client_ip, method, url, domain, result_code, http_status, bytes,
                    master_xaction, hierarchy_status, bump_mode, sni, tls_server_version, tls_server_cipher,
                    tls_client_version, tls_client_cipher, host, user_agent, referer, exclusion_rule,
                    ssl_exception, webfilter_allow, cache_bypass
                FROM diagnostic_requests
                {where_sql}
                ORDER BY ts DESC, id DESC
                LIMIT %s
                """,
                tuple(params + [lim]),
            ).fetchall()
        return [_normalize_request_row(row) for row in rows]

    def find_request_by_master_xaction(self, master_xaction: str) -> Optional[Dict[str, Any]]:
        tx = (master_xaction or "").strip()
        if not tx:
            return None
        rows = self.list_recent_requests(master_xaction=tx, limit=1)
        return rows[0] if rows else None

    def list_recent_icap(
        self,
        *,
        since: Optional[int] = None,
        search: str = "",
        client_ip: str = "",
        domain: str = "",
        master_xaction: str = "",
        service: str = "",
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        where = ["proxy_id = %s"]
        params: List[Any] = [get_proxy_id()]
        if since is not None:
            where.append("ts >= %s")
            params.append(int(since))
        if client_ip:
            where.append("client_ip = %s")
            params.append(client_ip.strip())
        if domain:
            where.append("domain = %s")
            params.append(_normalize_hostish(domain))
        if master_xaction:
            where.append("master_xaction = %s")
            params.append(master_xaction.strip())
        normalized_service = (service or "").strip().lower()
        if normalized_service:
            where.append("service_family = %s")
            params.append(normalized_service)
        if search:
            like = f"%{_escape_like(search.strip().lower())}%"
            where.append(
                "(" + " OR ".join(
                    [
                        "LOWER(domain) LIKE %s ESCAPE '\\\\'",
                        "LOWER(url) LIKE %s ESCAPE '\\\\'",
                        "LOWER(host) LIKE %s ESCAPE '\\\\'",
                        "LOWER(sni) LIKE %s ESCAPE '\\\\'",
                        "LOWER(master_xaction) LIKE %s ESCAPE '\\\\'",
                        "LOWER(client_ip) LIKE %s ESCAPE '\\\\'",
                        "LOWER(adapt_summary) LIKE %s ESCAPE '\\\\'",
                        "LOWER(adapt_details) LIKE %s ESCAPE '\\\\'",
                    ]
                ) + ")"
            )
            params.extend([like] * 8)
        where_sql = "WHERE " + " AND ".join(where)
        lim = max(1, min(200, int(limit)))

        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT
                    ts, master_xaction, client_ip, method, url, domain, icap_time_ms,
                    adapt_summary, adapt_details, host, user_agent, sni,
                    exclusion_rule, ssl_exception, webfilter_allow, cache_bypass, service_family
                FROM diagnostic_icap_events
                {where_sql}
                ORDER BY ts DESC, id DESC
                LIMIT %s
                """,
                tuple(params + [lim]),
            ).fetchall()
        return [_normalize_icap_row(row) for row in rows]

    def _batch_list_icap_by_master_xactions(
        self,
        master_xactions: List[str],
        *,
        service: str = "",
        limit_per_transaction: int = 5,
    ) -> Dict[str, List[Dict[str, Any]]]:
        txs: List[str] = []
        seen: set[str] = set()
        for raw in master_xactions:
            tx = (raw or "").strip()
            if not tx or tx in seen:
                continue
            seen.add(tx)
            txs.append(tx)
        if not txs:
            return {}

        where = ["proxy_id = %s"]
        params: List[Any] = [get_proxy_id()]
        placeholders = ", ".join(["%s"] * len(txs))
        where.append(f"master_xaction IN ({placeholders})")
        params.extend(txs)
        normalized_service = (service or "").strip().lower()
        if normalized_service:
            where.append("service_family = %s")
            params.append(normalized_service)

        where_sql = "WHERE " + " AND ".join(where)
        max_per_tx = max(1, min(20, int(limit_per_transaction)))

        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT
                    ts, master_xaction, client_ip, method, url, domain, icap_time_ms,
                    adapt_summary, adapt_details, host, user_agent, sni,
                    exclusion_rule, ssl_exception, webfilter_allow, cache_bypass, service_family
                FROM diagnostic_icap_events
                {where_sql}
                ORDER BY ts DESC, id DESC
                """,
                tuple(params),
            ).fetchall()

        grouped: Dict[str, List[Dict[str, Any]]] = {tx: [] for tx in txs}
        for row in rows:
            normalized = _normalize_icap_row(row)
            tx = str(normalized.get("master_xaction") or "").strip()
            if not tx:
                continue
            bucket = grouped.setdefault(tx, [])
            if len(bucket) >= max_per_tx:
                continue
            bucket.append(normalized)
        return grouped

    def list_recent_transactions(
        self,
        *,
        since: Optional[int] = None,
        search: str = "",
        client_ip: str = "",
        domain: str = "",
        master_xaction: str = "",
        service: str = "",
        limit: int = 50,
        icap_limit_per_transaction: int = 5,
    ) -> List[Dict[str, Any]]:
        rows = self.list_recent_requests(
            since=since,
            search=search,
            client_ip=client_ip,
            domain=domain,
            master_xaction=master_xaction,
            limit=limit,
        )
        icap_map = self._batch_list_icap_by_master_xactions(
            [str(row.get("master_xaction") or "") for row in rows],
            service=service,
            limit_per_transaction=icap_limit_per_transaction,
        )

        transactions: List[Dict[str, Any]] = []
        for row in rows:
            related_icap = icap_map.get(str(row.get("master_xaction") or "").strip(), [])
            if (service or "").strip() and not related_icap:
                continue
            enriched = dict(row)
            enriched["related_icap"] = related_icap
            enriched["service_families"] = sorted({str(event.get("service_family") or "") for event in related_icap if event.get("service_family")})
            enriched["icap_event_count"] = len(related_icap)
            transactions.append(enriched)
        return transactions

    def list_request_candidates_for_domain_near_ts(
        self,
        *,
        domain: str,
        around_ts: int,
        window_seconds: int = 300,
        limit: int = 5,
        service: str = "",
        icap_limit_per_transaction: int = 5,
    ) -> List[Dict[str, Any]]:
        normalized_domain = _normalize_hostish(domain)
        if not normalized_domain:
            return []

        center = int(around_ts or _now())
        window_i = max(30, min(24 * 3600, int(window_seconds or 300)))
        lim = max(1, min(20, int(limit)))

        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    ts, duration_ms, client_ip, method, url, domain, result_code, http_status, bytes,
                    master_xaction, hierarchy_status, bump_mode, sni, tls_server_version, tls_server_cipher,
                    tls_client_version, tls_client_cipher, host, user_agent, referer, exclusion_rule,
                    ssl_exception, webfilter_allow, cache_bypass
                FROM diagnostic_requests
                WHERE proxy_id = %s
                  AND domain = %s
                  AND ts BETWEEN %s AND %s
                ORDER BY ABS(ts - %s) ASC, ts DESC, id DESC
                LIMIT %s
                """,
                (
                    get_proxy_id(),
                    normalized_domain,
                    center - window_i,
                    center + window_i,
                    center,
                    lim,
                ),
            ).fetchall()

        normalized_rows = [_normalize_request_row(row) for row in rows]
        icap_map = self._batch_list_icap_by_master_xactions(
            [str(row.get("master_xaction") or "") for row in normalized_rows],
            service=service,
            limit_per_transaction=icap_limit_per_transaction,
        )

        out: List[Dict[str, Any]] = []
        for row in normalized_rows:
            enriched = dict(row)
            enriched["related_icap"] = icap_map.get(str(row.get("master_xaction") or "").strip(), [])
            enriched["time_delta_seconds"] = abs(int(row.get("ts") or 0) - center)
            enriched["correlation_kind"] = "domain_time"
            out.append(enriched)
        return out

    def list_request_candidates_for_policy_event(
        self,
        *,
        around_ts: int,
        url: str = "",
        client_ip: str = "",
        domain: str = "",
        window_seconds: int = 300,
        limit: int = 5,
        service: str = "",
        icap_limit_per_transaction: int = 5,
    ) -> List[Dict[str, Any]]:
        normalized_domain = _normalize_hostish(domain) or _extract_domain(url)
        center = int(around_ts or _now())
        window_i = max(30, min(24 * 3600, int(window_seconds or 300)))
        lim = max(1, min(20, int(limit)))

        where = ["proxy_id = %s", "ts BETWEEN %s AND %s"]
        params: List[Any] = [get_proxy_id(), center - window_i, center + window_i]
        if client_ip:
            where.append("client_ip = %s")
            params.append(client_ip.strip())
        like_parts: List[str] = []
        if normalized_domain:
            like_parts.append("domain = %s")
            params.append(normalized_domain)
        raw_url = (url or "").strip()
        if raw_url:
            like_parts.append("url LIKE %s ESCAPE '\\'")
            params.append(f"%{_escape_like(raw_url)}%")
        elif normalized_domain:
            like_parts.append("url LIKE %s ESCAPE '\\'")
            params.append(f"%{_escape_like(normalized_domain)}%")
        if like_parts:
            where.append("(" + " OR ".join(like_parts) + ")")

        where_sql = "WHERE " + " AND ".join(where)

        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT
                    ts, duration_ms, client_ip, method, url, domain, result_code, http_status, bytes,
                    master_xaction, hierarchy_status, bump_mode, sni, tls_server_version, tls_server_cipher,
                    tls_client_version, tls_client_cipher, host, user_agent, referer, exclusion_rule,
                    ssl_exception, webfilter_allow, cache_bypass
                FROM diagnostic_requests
                {where_sql}
                ORDER BY ABS(ts - %s) ASC, ts DESC, id DESC
                LIMIT %s
                """,
                tuple(params + [center, lim]),
            ).fetchall()

        normalized_rows = [_normalize_request_row(row) for row in rows]
        icap_map = self._batch_list_icap_by_master_xactions(
            [str(row.get("master_xaction") or "") for row in normalized_rows],
            service=service,
            limit_per_transaction=icap_limit_per_transaction,
        )

        out: List[Dict[str, Any]] = []
        for row in normalized_rows:
            enriched = dict(row)
            enriched["related_icap"] = icap_map.get(str(row.get("master_xaction") or "").strip(), [])
            enriched["time_delta_seconds"] = abs(int(row.get("ts") or 0) - center)
            enriched["correlation_kind"] = "domain_time"
            out.append(enriched)
        return out

    def list_icap_candidates_for_domain_near_ts(
        self,
        *,
        domain: str,
        around_ts: int,
        window_seconds: int = 300,
        service: str = "",
        limit: int = 5,
    ) -> List[Dict[str, Any]]:
        normalized_domain = _normalize_hostish(domain)
        if not normalized_domain:
            return []

        center = int(around_ts or _now())
        window_i = max(30, min(24 * 3600, int(window_seconds or 300)))
        lim = max(1, min(20, int(limit)))
        normalized_service = (service or "").strip().lower()

        where = ["proxy_id = %s", "domain = %s", "ts BETWEEN %s AND %s"]
        params: List[Any] = [get_proxy_id(), normalized_domain, center - window_i, center + window_i]
        if normalized_service:
            where.append("service_family = %s")
            params.append(normalized_service)
        where_sql = " AND ".join(where)

        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT
                    ts, master_xaction, client_ip, method, url, domain, icap_time_ms,
                    adapt_summary, adapt_details, host, user_agent, sni,
                    exclusion_rule, ssl_exception, webfilter_allow, cache_bypass, service_family
                FROM diagnostic_icap_events
                WHERE {where_sql}
                ORDER BY ABS(ts - %s) ASC, ts DESC, id DESC
                LIMIT %s
                """,
                tuple(params + [center, lim]),
            ).fetchall()

        out: List[Dict[str, Any]] = []
        for row in rows:
            normalized = _normalize_icap_row(row)
            normalized["time_delta_seconds"] = abs(int(normalized.get("ts") or 0) - center)
            normalized["correlation_kind"] = "domain_time"
            out.append(normalized)
        return out

    def activity_summary(self, *, since: Optional[int] = None) -> Dict[str, int]:
        request_where = ["proxy_id = %s"]
        request_params: List[Any] = [get_proxy_id()]
        icap_where = ["proxy_id = %s"]
        icap_params: List[Any] = [get_proxy_id()]
        if since is not None:
            request_where.append("ts >= %s")
            request_params.append(int(since))
            icap_where.append("ts >= %s")
            icap_params.append(int(since))

        request_where_sql = "WHERE " + " AND ".join(request_where)
        icap_where_sql = "WHERE " + " AND ".join(icap_where)

        with self._connect() as conn:
            req_row = conn.execute(
                f"""
                SELECT COUNT(*), COUNT(DISTINCT client_ip), COUNT(DISTINCT domain), COUNT(DISTINCT master_xaction)
                FROM diagnostic_requests
                {request_where_sql}
                """,
                tuple(request_params),
            ).fetchone()
            icap_row = conn.execute(
                f"""
                SELECT
                    COUNT(*),
                    COALESCE(SUM(CASE WHEN service_family = 'av' THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN service_family = 'adblock' THEN 1 ELSE 0 END), 0)
                FROM diagnostic_icap_events
                {icap_where_sql}
                """,
                tuple(icap_params),
            ).fetchone()

        return {
            "requests": int(req_row[0] or 0) if req_row else 0,
            "clients": int(req_row[1] or 0) if req_row else 0,
            "domains": int(req_row[2] or 0) if req_row else 0,
            "transactions": int(req_row[3] or 0) if req_row else 0,
            "icap_events": int(icap_row[0] or 0) if icap_row else 0,
            "av_icap_events": int(icap_row[1] or 0) if icap_row else 0,
            "adblock_icap_events": int(icap_row[2] or 0) if icap_row else 0,
        }

    def top_request_dimension(self, dimension: str, *, since: Optional[int] = None, limit: int = 10) -> List[Dict[str, Any]]:
        column = _REQUEST_DIMENSIONS.get((dimension or "").strip().lower())
        if not column:
            return []

        lim = max(1, min(50, int(limit)))
        where = ["proxy_id = %s", f"COALESCE(NULLIF(TRIM({column}), ''), '') <> ''"]
        params: List[Any] = [get_proxy_id()]
        if since is not None:
            where.append("ts >= %s")
            params.append(int(since))
        where_sql = "WHERE " + " AND ".join(where)

        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT {column} AS value, COUNT(*) AS total, MAX(ts) AS last_seen
                FROM diagnostic_requests
                {where_sql}
                GROUP BY {column}
                ORDER BY total DESC, last_seen DESC
                LIMIT %s
                """,
                tuple(params + [lim]),
            ).fetchall()

        out: List[Dict[str, Any]] = []
        for row in rows:
            out.append(
                {
                    "value": str(row[0] or ""),
                    "count": int(row[1] or 0),
                    "last_seen": int(row[2] or 0),
                }
            )
        return out

    def top_policy_tags(self, *, since: Optional[int] = None, limit: int = 10) -> List[Dict[str, Any]]:
        lim = max(1, min(50, int(limit)))
        params: List[Any] = [get_proxy_id()]
        since_sql = ""
        if since is not None:
            since_sql = " AND ts >= %s"
            params.append(int(since))

        sql = f"""
        SELECT tag, COUNT(*) AS total, MAX(ts) AS last_seen
        FROM (
            SELECT CONCAT('exclude:', exclusion_rule) AS tag, ts
            FROM diagnostic_requests
            WHERE proxy_id = %s AND COALESCE(NULLIF(TRIM(exclusion_rule), ''), '') <> ''{since_sql}
            UNION ALL
            SELECT CONCAT('ssl:', ssl_exception) AS tag, ts
            FROM diagnostic_requests
            WHERE proxy_id = %s AND COALESCE(NULLIF(TRIM(ssl_exception), ''), '') <> ''{since_sql}
            UNION ALL
            SELECT CONCAT('webfilter:', webfilter_allow) AS tag, ts
            FROM diagnostic_requests
            WHERE proxy_id = %s AND COALESCE(NULLIF(TRIM(webfilter_allow), ''), '') <> ''{since_sql}
            UNION ALL
            SELECT CONCAT('cache:', cache_bypass) AS tag, ts
            FROM diagnostic_requests
            WHERE proxy_id = %s AND COALESCE(NULLIF(TRIM(cache_bypass), ''), '') <> ''{since_sql}
        ) tags
        GROUP BY tag
        ORDER BY total DESC, last_seen DESC
        LIMIT %s
        """

        query_params: List[Any] = []
        for _ in range(4):
            query_params.extend(params)
        query_params.append(lim)

        with self._connect() as conn:
            rows = conn.execute(sql, tuple(query_params)).fetchall()

        return [
            {
                "tag": str(row[0] or ""),
                "count": int(row[1] or 0),
                "last_seen": int(row[2] or 0),
            }
            for row in rows
        ]

    def slowest_requests(self, *, since: Optional[int] = None, limit: int = 10) -> List[Dict[str, Any]]:
        where = ["proxy_id = %s"]
        params: List[Any] = [get_proxy_id()]
        if since is not None:
            where.append("ts >= %s")
            params.append(int(since))
        where_sql = "WHERE " + " AND ".join(where)
        lim = max(1, min(50, int(limit)))

        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT
                    ts, duration_ms, client_ip, method, url, domain, result_code, http_status, bytes,
                    master_xaction, hierarchy_status, bump_mode, sni, tls_server_version, tls_server_cipher,
                    tls_client_version, tls_client_cipher, host, user_agent, referer, exclusion_rule,
                    ssl_exception, webfilter_allow, cache_bypass
                FROM diagnostic_requests
                {where_sql}
                ORDER BY duration_ms DESC, ts DESC, id DESC
                LIMIT %s
                """,
                tuple(params + [lim]),
            ).fetchall()

        return [_normalize_request_row(row) for row in rows]

    def icap_summary(self, *, since: Optional[int] = None, service: str = "") -> Dict[str, int]:
        where = ["proxy_id = %s"]
        params: List[Any] = [get_proxy_id()]
        if since is not None:
            where.append("ts >= %s")
            params.append(int(since))
        normalized_service = (service or "").strip().lower()
        if normalized_service:
            where.append("service_family = %s")
            params.append(normalized_service)
        where_sql = "WHERE " + " AND ".join(where)

        with self._connect() as conn:
            row = conn.execute(
                f"""
                SELECT COUNT(*), COALESCE(AVG(icap_time_ms),0), COALESCE(MAX(icap_time_ms),0)
                FROM diagnostic_icap_events
                {where_sql}
                """,
                tuple(params),
            ).fetchone()
        return {
            "events": int(row[0] or 0) if row else 0,
            "avg_icap_time_ms": int(float(row[1] or 0)) if row else 0,
            "max_icap_time_ms": int(row[2] or 0) if row else 0,
        }

    def slowest_icap_events(self, *, since: Optional[int] = None, service: str = "", limit: int = 10) -> List[Dict[str, Any]]:
        where = ["proxy_id = %s"]
        params: List[Any] = [get_proxy_id()]
        if since is not None:
            where.append("ts >= %s")
            params.append(int(since))
        normalized_service = (service or "").strip().lower()
        if normalized_service:
            where.append("service_family = %s")
            params.append(normalized_service)
        where_sql = "WHERE " + " AND ".join(where)
        lim = max(1, min(50, int(limit)))

        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT
                    ts, master_xaction, client_ip, method, url, domain, icap_time_ms,
                    adapt_summary, adapt_details, host, user_agent, sni,
                    exclusion_rule, ssl_exception, webfilter_allow, cache_bypass, service_family
                FROM diagnostic_icap_events
                {where_sql}
                ORDER BY icap_time_ms DESC, ts DESC, id DESC
                LIMIT %s
                """,
                tuple(params + [lim]),
            ).fetchall()
        return [_normalize_icap_row(row) for row in rows]

    def list_icap_by_master_xaction(self, master_xaction: str, *, limit: int = 20) -> List[Dict[str, Any]]:
        tx = (master_xaction or "").strip()
        if not tx:
            return []
        return self.list_recent_icap(master_xaction=tx, limit=limit)


_store: Optional[DiagnosticStore] = None
_store_lock = threading.Lock()


def get_diagnostic_store() -> DiagnosticStore:
    global _store
    if _store is not None:
        return _store
    with _store_lock:
        if _store is None:
            _store = DiagnosticStore(
                access_log_path=os.environ.get("SQUID_DIAGNOSTIC_ACCESS_LOG", "/var/log/squid/access-observe.log"),
                icap_log_path=os.environ.get("SQUID_DIAGNOSTIC_ICAP_LOG", "/var/log/squid/icap.log"),
                seed_max_lines=_env_int("DIAGNOSTIC_SEED_MAX_LINES", 5000, minimum=500, maximum=20000),
                retention_days=_env_int("DIAGNOSTIC_RETENTION_DAYS", 7, minimum=1, maximum=90),
            )
            _store.init_db()
        return _store
