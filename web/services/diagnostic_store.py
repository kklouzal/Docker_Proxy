from __future__ import annotations

import contextlib
import csv
import hashlib
import io
import ipaddress
import logging
import os
import pathlib
import re
import threading
import time
from typing import Any

from services.bounded_delete import delete_older_than_in_chunks
from services.db import (
    DATABASE_ERRORS,
    connect,
    mysql_advisory_lock,
    mysql_error_code,
    mysql_schema_lock_timeout_seconds,
    run_mysql_operation_with_retry,
)
from services.logutil import log_database_unavailable, log_exception_throttled
from services.observability_backoff import DatabaseWriteBackoff
from services.proxy_context import get_proxy_id
from services.runtime_helpers import env_float as _env_float
from services.runtime_helpers import env_int as _env_int
from services.runtime_helpers import escape_like as _escape_like
from services.runtime_helpers import extract_domain as _extract_domain
from services.runtime_helpers import normalize_hostish as _normalize_hostish
from services.runtime_helpers import now_ts as _now

logger = logging.getLogger(__name__)


_INTERNAL_NETWORK_CACHE: tuple[float, tuple[Any, ...]] = (0.0, ())
_TRUE_ENV_VALUES = {"1", "true", "yes", "on"}
_FALSE_ENV_VALUES = {"0", "false", "no", "off"}


def _env_truthy(value: object | None) -> bool:
    return str(value or "").strip().lower() in _TRUE_ENV_VALUES


def _env_falsey(value: object | None) -> bool:
    return str(value or "").strip().lower() in _FALSE_ENV_VALUES


def _append_bounded_pending_row(
    pending_rows: list[tuple[Any, ...]],
    row: tuple[Any, ...],
    *,
    max_pending_rows: int,
    loop_name: str,
    drop_state: dict[str, Any],
) -> None:
    pending_rows.append(row)
    overflow = len(pending_rows) - max_pending_rows
    if overflow <= 0:
        return
    del pending_rows[:overflow]
    dropped = int(drop_state.get("dropped", 0)) + overflow
    drop_state["dropped"] = dropped
    now = time.time()
    if now - float(drop_state.get("last_log_ts", 0.0)) >= 300.0:
        logger.warning(
            "Diagnostic tailer pending rows exceeded %s in %s; dropped %s oldest rows while database flush is unavailable",
            max_pending_rows,
            loop_name,
            dropped,
        )
        drop_state["last_log_ts"] = now
        drop_state["dropped"] = 0


def _running_in_container() -> bool:
    return (
        pathlib.Path("/.dockerenv").exists()
        or pathlib.Path("/run/.containerenv").exists()
    )


def _diagnostic_filter_internal_traffic_enabled() -> bool:
    override = os.environ.get("DIAGNOSTIC_FILTER_INTERNAL_TRAFFIC")
    if override is not None:
        if _env_falsey(override):
            return False
        if _env_truthy(override):
            return True
    return not _env_truthy(os.environ.get("ENABLE_TEST_MODE"))


def _read_local_link_networks() -> tuple[Any, ...]:
    networks: list[Any] = []
    with contextlib.suppress(Exception):
        networks.extend(
            (ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("::1/128")),
        )
    if not _running_in_container():
        return tuple(networks)
    try:
        lines = (
            pathlib.Path("/proc/net/fib_trie")
            .open(encoding="utf-8", errors="replace")
            .read()
            .splitlines()
        )
    except FileNotFoundError:
        return tuple(networks)
    except Exception:
        log_exception_throttled(
            logger,
            "diagnostic_store.local_networks",
            interval_seconds=300.0,
            message="Failed to inspect local network routes for diagnostic self-traffic filtering",
        )
        return tuple(networks)
    candidate = ""
    for line in lines:
        match = re.search(r"[+|]--\s+([0-9.]+)\b", line)
        if match:
            candidate = match.group(1)
            continue
        if candidate and " host " in line and "LOCAL" in line:
            try:
                network = ipaddress.ip_network(f"{candidate}/32", strict=False)
                if network not in networks:
                    networks.append(network)
            except Exception:
                pass
            candidate = ""
    return tuple(networks)


def _local_link_networks() -> tuple[Any, ...]:
    global _INTERNAL_NETWORK_CACHE
    now = time.time()
    cache_ts, cached = _INTERNAL_NETWORK_CACHE
    if cached and now - cache_ts < 60.0:
        return cached
    networks = _read_local_link_networks()
    _INTERNAL_NETWORK_CACHE = (now, networks)
    return networks


def _is_internal_diagnostic_row(row: dict[str, Any]) -> bool:
    if not _diagnostic_filter_internal_traffic_enabled():
        return False
    client_ip = _safe_text(row.get("client_ip"), max_len=64)
    if not client_ip:
        return False
    try:
        address = ipaddress.ip_address(client_ip)
    except Exception:
        return False
    if address.is_loopback:
        return True
    for network in _local_link_networks():
        try:
            if address.version == network.version and address in network:
                return True
        except Exception:
            continue
    return False


_REQUEST_DIMENSIONS: dict[str, str] = {
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
    if "\\t" in s:
        normalized = []
        in_quotes = False
        i = 0
        while i < len(s):
            ch = s[i]
            if ch == '"':
                normalized.append(ch)
                if in_quotes and i + 1 < len(s) and s[i + 1] == '"':
                    normalized.append(s[i + 1])
                    i += 2
                    continue
                in_quotes = not in_quotes
                i += 1
                continue
            if not in_quotes and ch == "\\" and i + 1 < len(s) and s[i + 1] == "t":
                normalized.append("\t")
                i += 2
                continue
            normalized.append(ch)
            i += 1
        s = "".join(normalized)
    if '"' not in s:
        return [item.strip() for item in s.split("	")]
    try:
        row = next(csv.reader(io.StringIO(s), delimiter="	", quotechar='"'))
    except Exception:
        return []
    return [item.strip() for item in row]


def _parse_status(result_code: str) -> int:
    raw = _safe_text(result_code, max_len=96)
    if "/" not in raw:
        return 0
    tail = raw.rsplit("/", 1)[1].strip()
    return int(tail) if tail.isdigit() else 0


def _event_key(*parts: object) -> str:
    normalized = "|".join(str(part or "") for part in parts)
    return hashlib.sha1(normalized.encode("utf-8", errors="replace")).hexdigest()


def _policy_tags(
    *,
    exclusion_rule: str,
    ssl_exception: str,
    webfilter_allow: str,
    cache_bypass: str,
) -> list[str]:
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


def _policy_text(value: object) -> str:
    text = _safe_text(value, max_len=64)
    return "" if text == "-" else text


def _policy_fields_from_row(row: list[str], start_index: int) -> dict[str, str]:
    def policy_at(offset: int) -> str:
        index = start_index + offset
        return _policy_text(row[index] if len(row) > index else "")

    return {
        "exclusion_rule": policy_at(0),
        "ssl_exception": policy_at(1),
        "webfilter_allow": policy_at(2),
        "cache_bypass": policy_at(3),
    }


def _bounded_raw_line(line: str) -> str:
    return (line or "").strip("\r\n")[:4000]


def _service_family(
    adapt_summary: str,
    adapt_details: str,
    service_name: str = "",
    icap_uri: str = "",
) -> str:
    haystack = f"{service_name} {icap_uri} {adapt_summary} {adapt_details}".lower()
    if any(
        token in haystack
        for token in ("avrespmod", "virus_scan", "clamd", "av_resp", "av_req")
    ):
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


def _request_target_display(row: dict[str, Any]) -> str:
    return (
        _safe_text(row.get("domain"), max_len=255)
        or _safe_text(row.get("sni"), max_len=255)
        or _safe_text(row.get("host"), max_len=255)
        or _safe_text(row.get("url"), max_len=255)
        or "-"
    )


def _request_tls_summary(row: dict[str, Any]) -> str:
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
    return " Â· ".join(parts)


def _normalize_request_row(row: Any) -> dict[str, Any]:
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
        "exclusion_rule": _policy_text(row[20]),
        "ssl_exception": _policy_text(row[21]),
        "webfilter_allow": _policy_text(row[22]),
        "cache_bypass": _policy_text(row[23]),
        "response_content_type": _safe_text(
            row[24] if len(row) > 24 else "", max_len=255
        ),
        "response_server": _safe_text(row[25] if len(row) > 25 else "", max_len=255),
        "response_cf_mitigated": _safe_text(
            row[26] if len(row) > 26 else "", max_len=64
        ),
        "response_alt_svc": _safe_text(row[27] if len(row) > 27 else "", max_len=512),
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


def _normalize_icap_row(row: Any) -> dict[str, Any]:
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
        "exclusion_rule": _policy_text(row[12]),
        "ssl_exception": _policy_text(row[13]),
        "webfilter_allow": _policy_text(row[14]),
        "cache_bypass": _policy_text(row[15]),
        "service_family": _safe_text(row[16], max_len=32),
        "icap_service": _safe_text(row[17] if len(row) > 17 else "", max_len=128),
        "icap_outcome": _safe_text(row[18] if len(row) > 18 else "", max_len=64),
        "icap_status": _safe_int(row[19], 0) if len(row) > 19 else 0,
        "icap_response_time_ms": _safe_int(row[20], 0) if len(row) > 20 else 0,
        "icap_io_time_ms": _safe_int(row[21], 0) if len(row) > 21 else 0,
        "icap_bytes_sent": _safe_int(row[22], 0) if len(row) > 22 else 0,
        "icap_bytes_received": _safe_int(row[23], 0) if len(row) > 23 else 0,
    }
    data["service_label"] = _service_label(data["service_family"])
    data["target_display"] = (
        data["domain"]
        or data["sni"]
        or data["host"]
        or _safe_text(data["url"], max_len=255)
        or "-"
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
    ) -> None:
        self.access_log_path = access_log_path
        self.icap_log_path = icap_log_path
        self.seed_max_lines = seed_max_lines
        self.retention_days = max(1, int(retention_days or 7))

        self._started = False
        self._start_lock = threading.Lock()
        self._db_initialized = False
        self._db_init_lock = threading.Lock()

    def _connect(self):
        return connect()

    def init_db(self) -> None:
        if self._db_initialized:
            return
        with self._db_init_lock:
            if self._db_initialized:
                return

            def _ensure_schema() -> None:
                with self._connect() as conn:
                    with mysql_advisory_lock(
                        conn,
                        "docker_proxy:diagnostic_store:schema",
                        mysql_schema_lock_timeout_seconds(),
                    ):
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
                                response_content_type VARCHAR(255) NOT NULL DEFAULT '',
                                response_server VARCHAR(255) NOT NULL DEFAULT '',
                                response_cf_mitigated VARCHAR(64) NOT NULL DEFAULT '',
                                response_alt_svc VARCHAR(512) NOT NULL DEFAULT '',
                                raw TEXT NOT NULL,
                                created_ts BIGINT NOT NULL,
                                UNIQUE KEY idx_diagnostic_requests_proxy_event (proxy_id, event_key),
                                KEY idx_diagnostic_requests_ts_id (ts, id),
                                KEY idx_diagnostic_requests_proxy_ts (proxy_id, ts, id),
                                KEY idx_diagnostic_requests_proxy_tx (proxy_id, master_xaction, ts),
                                KEY idx_diagnostic_requests_proxy_domain (proxy_id, domain, ts),
                                KEY idx_diagnostic_requests_proxy_client (proxy_id, client_ip, ts),
                                KEY idx_diagnostic_requests_proxy_client_bytes (proxy_id, client_ip, ts, bytes),
                                KEY idx_diagnostic_requests_proxy_bump_domain (proxy_id, bump_mode, domain, ts),
                                KEY idx_diagnostic_requests_proxy_result_ts (proxy_id, result_code, ts)
                            )
                            """,
                        )
                        conn.execute(
                            """
                            CREATE TABLE IF NOT EXISTS diagnostic_policy_tags (
                                proxy_id VARCHAR(64) NOT NULL DEFAULT 'default',
                                request_id BIGINT NOT NULL,
                                tag VARCHAR(512) NOT NULL,
                                ts BIGINT NOT NULL,
                                PRIMARY KEY(proxy_id, request_id, tag),
                                KEY idx_diagnostic_policy_tags_lookup(proxy_id, tag, ts),
                                KEY idx_diagnostic_policy_tags_request(proxy_id, request_id),
                                KEY idx_diagnostic_policy_tags_ts(proxy_id, ts),
                                KEY idx_diagnostic_policy_tags_ts_only(ts, proxy_id, request_id),
                                KEY idx_diagnostic_policy_tags_since(proxy_id, ts, tag)
                            )
                            """,
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
                                KEY idx_diagnostic_icap_ts_id (ts, id),
                                KEY idx_diagnostic_icap_proxy_ts (proxy_id, ts, id),
                                KEY idx_diagnostic_icap_proxy_tx (proxy_id, master_xaction, ts),
                                KEY idx_diagnostic_icap_proxy_domain (proxy_id, domain, ts),
                                KEY idx_diagnostic_icap_proxy_service (proxy_id, service_family, ts),
                                KEY idx_diagnostic_icap_proxy_client_service (proxy_id, client_ip, service_family, ts)
                            )
                            """,
                        )
                        for column_name, ddl in (
                            (
                                "response_content_type",
                                "ALTER TABLE diagnostic_requests ADD COLUMN response_content_type VARCHAR(255) NOT NULL DEFAULT '' AFTER cache_bypass",
                            ),
                            (
                                "response_server",
                                "ALTER TABLE diagnostic_requests ADD COLUMN response_server VARCHAR(255) NOT NULL DEFAULT '' AFTER response_content_type",
                            ),
                            (
                                "response_cf_mitigated",
                                "ALTER TABLE diagnostic_requests ADD COLUMN response_cf_mitigated VARCHAR(64) NOT NULL DEFAULT '' AFTER response_server",
                            ),
                            (
                                "response_alt_svc",
                                "ALTER TABLE diagnostic_requests ADD COLUMN response_alt_svc VARCHAR(512) NOT NULL DEFAULT '' AFTER response_cf_mitigated",
                            ),
                        ):
                            exists = conn.execute(
                                """
                                SELECT 1
                                FROM information_schema.columns
                                WHERE table_schema = DATABASE()
                                  AND table_name = 'diagnostic_requests'
                                  AND column_name = %s
                                LIMIT 1
                                """,
                                (column_name,),
                            ).fetchone()
                            if not exists:
                                try:
                                    conn.execute(ddl)
                                except DATABASE_ERRORS as exc:
                                    if mysql_error_code(exc) != 1060:
                                        raise
                        for table, index_name, ddl in (
                            (
                                "diagnostic_requests",
                                "idx_diagnostic_requests_ts_id",
                                "ALTER TABLE diagnostic_requests ADD INDEX idx_diagnostic_requests_ts_id (ts, id)",
                            ),
                            (
                                "diagnostic_icap_events",
                                "idx_diagnostic_icap_ts_id",
                                "ALTER TABLE diagnostic_icap_events ADD INDEX idx_diagnostic_icap_ts_id (ts, id)",
                            ),
                            (
                                "diagnostic_requests",
                                "idx_diagnostic_requests_proxy_client_bytes",
                                "ALTER TABLE diagnostic_requests ADD INDEX idx_diagnostic_requests_proxy_client_bytes (proxy_id, client_ip, ts, bytes)",
                            ),
                            (
                                "diagnostic_requests",
                                "idx_diagnostic_requests_proxy_bump_domain",
                                "ALTER TABLE diagnostic_requests ADD INDEX idx_diagnostic_requests_proxy_bump_domain (proxy_id, bump_mode, domain, ts)",
                            ),
                            (
                                "diagnostic_requests",
                                "idx_diagnostic_requests_proxy_result_ts",
                                "ALTER TABLE diagnostic_requests ADD INDEX idx_diagnostic_requests_proxy_result_ts (proxy_id, result_code, ts)",
                            ),
                            (
                                "diagnostic_requests",
                                "idx_diagnostic_requests_proxy_cf_ts",
                                "ALTER TABLE diagnostic_requests ADD INDEX idx_diagnostic_requests_proxy_cf_ts (proxy_id, response_cf_mitigated, ts)",
                            ),
                            (
                                "diagnostic_icap_events",
                                "idx_diagnostic_icap_proxy_client_service",
                                "ALTER TABLE diagnostic_icap_events ADD INDEX idx_diagnostic_icap_proxy_client_service (proxy_id, client_ip, service_family, ts)",
                            ),
                            (
                                "diagnostic_policy_tags",
                                "idx_diagnostic_policy_tags_lookup",
                                "ALTER TABLE diagnostic_policy_tags ADD INDEX idx_diagnostic_policy_tags_lookup (proxy_id, tag, ts)",
                            ),
                            (
                                "diagnostic_policy_tags",
                                "idx_diagnostic_policy_tags_request",
                                "ALTER TABLE diagnostic_policy_tags ADD INDEX idx_diagnostic_policy_tags_request (proxy_id, request_id)",
                            ),
                            (
                                "diagnostic_policy_tags",
                                "idx_diagnostic_policy_tags_ts_only",
                                "ALTER TABLE diagnostic_policy_tags ADD INDEX idx_diagnostic_policy_tags_ts_only (ts, proxy_id, request_id)",
                            ),
                            (
                                "diagnostic_policy_tags",
                                "idx_diagnostic_policy_tags_since",
                                "ALTER TABLE diagnostic_policy_tags ADD INDEX idx_diagnostic_policy_tags_since (proxy_id, ts, tag)",
                            ),
                        ):
                            try:
                                exists = conn.execute(
                                    """
                                    SELECT 1
                                    FROM information_schema.statistics
                                    WHERE table_schema = DATABASE()
                                      AND table_name = %s
                                      AND index_name = %s
                                    LIMIT 1
                                    """,
                                    (table, index_name),
                                ).fetchone()
                                if not exists:
                                    conn.execute(ddl)
                            except Exception:
                                logger.warning(
                                    "Failed to ensure diagnostic reporting index %s on %s",
                                    index_name,
                                    table,
                                )

            run_mysql_operation_with_retry(_ensure_schema)
            self._db_initialized = True

    def prune_old_entries(self, *, retention_days: int = 0) -> None:
        self.init_db()
        days = max(1, int(retention_days or self.retention_days))
        cutoff = _now() - (days * 24 * 60 * 60)
        for table, order_by in (
            ("diagnostic_icap_events", ("ts", "id")),
            ("diagnostic_policy_tags", ("ts", "proxy_id", "request_id", "tag")),
            ("diagnostic_requests", ("ts", "id")),
        ):
            delete_older_than_in_chunks(
                self._connect,
                table=table,
                timestamp_column="ts",
                cutoff_ts=int(cutoff),
                order_by_columns=order_by,
                log_key=f"diagnostic_store.prune.{table}",
                log_label=f"Diagnostic store prune for {table}",
            )

    def start_background(self) -> None:
        with self._start_lock:
            if self._started:
                return
            try:
                self.init_db()
                self.seed_from_recent_logs()
            except DATABASE_ERRORS as exc:
                log_database_unavailable(
                    logger,
                    "diagnostic_store.startup.db",
                    "Diagnostic tailer startup DB initialization/seed deferred while MySQL is unavailable",
                    exc,
                )
            except Exception:
                log_exception_throttled(
                    logger,
                    "diagnostic_store.startup",
                    interval_seconds=300.0,
                    message="Diagnostic tailer startup seed failed",
                )

            request_thread = threading.Thread(
                target=self._tail_file_loop,
                args=(
                    self.access_log_path,
                    self._build_request_insert_params,
                    self._flush_request_rows,
                    "diagnostic-requests-tailer",
                ),
                daemon=True,
            )
            request_thread.start()

            icap_thread = threading.Thread(
                target=self._tail_file_loop,
                args=(
                    self.icap_log_path,
                    self._build_icap_insert_params,
                    self._flush_icap_rows,
                    "diagnostic-icap-tailer",
                ),
                daemon=True,
            )
            icap_thread.start()
            self._started = True

    def _read_last_lines(self, path: str, *, max_lines: int) -> list[str]:
        if not path or not pathlib.Path(path).exists():
            return []
        try:
            with pathlib.Path(path).open("rb") as handle:
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
        request_lines = self._read_last_lines(
            self.access_log_path,
            max_lines=self.seed_max_lines,
        )
        icap_lines = self._read_last_lines(
            self.icap_log_path,
            max_lines=self.seed_max_lines,
        )
        if not request_lines and not icap_lines:
            return
        request_rows = [
            row
            for row in (
                self._build_request_insert_params(line) for line in request_lines
            )
            if row is not None
        ]
        icap_rows = [
            row
            for row in (self._build_icap_insert_params(line) for line in icap_lines)
            if row is not None
        ]
        if not request_rows and not icap_rows:
            return
        self.init_db()
        with self._connect() as conn:
            if request_rows:
                self._flush_request_rows(conn, request_rows)
            if icap_rows:
                self._flush_icap_rows(conn, icap_rows)

    def _tail_file_loop(
        self,
        path: str,
        build_row_fn,
        flush_rows_fn,
        loop_name: str,
    ) -> None:
        commit_batch = _env_int(
            "DIAGNOSTIC_COMMIT_BATCH",
            150,
            minimum=25,
            maximum=5000,
        )
        commit_interval = _env_float(
            "DIAGNOSTIC_COMMIT_INTERVAL_SECONDS",
            2.0,
            minimum=0.25,
            maximum=10.0,
        )
        poll_interval = _env_float(
            "DIAGNOSTIC_POLL_INTERVAL_SECONDS",
            0.5,
            minimum=0.1,
            maximum=5.0,
        )
        max_pending_rows = _env_int(
            "DIAGNOSTIC_PENDING_MAX_ROWS",
            5000,
            minimum=commit_batch,
            maximum=100000,
        )
        last_inode: int | None = None
        pending = 0
        pending_rows: list[tuple[Any, ...]] = []
        drop_state: dict[str, Any] = {"dropped": 0, "last_log_ts": 0.0}
        flush_backoff = DatabaseWriteBackoff.from_env(
            "DIAGNOSTIC_DB_WRITE",
            default_base=5.0,
            default_max=120.0,
        )
        last_commit = time.monotonic()
        reopen_from_start = False

        while True:
            try:
                if not pathlib.Path(path).exists():
                    time.sleep(max(1.0, poll_interval))
                    continue

                st = os.stat(path)
                inode = getattr(st, "st_ino", None)
                if last_inode is None:
                    last_inode = inode

                def flush_pending() -> None:
                    nonlocal pending, last_commit
                    if not pending_rows:
                        pending = 0
                        last_commit = time.monotonic()
                        return
                    self.init_db()
                    with self._connect() as conn:
                        flush_rows_fn(conn, pending_rows)
                    flush_backoff.record_success()
                    pending_rows.clear()
                    pending = 0
                    last_commit = time.monotonic()

                def record_deferred_flush(now_mono: float | None = None) -> float:
                    nonlocal last_commit
                    now_mono = time.monotonic() if now_mono is None else now_mono
                    delay = flush_backoff.record_failure(now_mono)
                    last_commit = now_mono
                    return delay

                with pathlib.Path(path).open(
                    encoding="utf-8",
                    errors="replace",
                ) as handle:
                    if reopen_from_start:
                        handle.seek(0, os.SEEK_SET)
                        reopen_from_start = False
                    else:
                        handle.seek(0, os.SEEK_END)
                    while True:
                        line_pos = handle.tell()
                        line = handle.readline()
                        if line:
                            if not line.endswith("\n"):
                                handle.seek(line_pos, os.SEEK_SET)
                                try:
                                    inode_now = getattr(os.stat(path), "st_ino", None)
                                except OSError:
                                    inode_now = None
                                if (
                                    inode_now is not None
                                    and last_inode is not None
                                    and inode_now != last_inode
                                ):
                                    last_inode = inode_now
                                    if flush_backoff.can_attempt():
                                        try:
                                            flush_pending()
                                        except DATABASE_ERRORS as exc:
                                            delay = record_deferred_flush()
                                            log_database_unavailable(
                                                logger,
                                                f"diagnostic_store.rotate.{loop_name}.db",
                                                f"Diagnostic tailer deferred rotation flush for {loop_name} while MySQL is unavailable; retrying in about {delay:.1f}s",
                                                exc,
                                            )
                                        except Exception:
                                            log_exception_throttled(
                                                logger,
                                                f"diagnostic_store.rotate.{loop_name}",
                                                interval_seconds=300.0,
                                                message=f"Diagnostic tailer final commit failed during rotation for {loop_name}",
                                            )
                                    reopen_from_start = True
                                    break
                                time.sleep(poll_interval)
                                continue
                            try:
                                row = build_row_fn(line)
                                if row is not None:
                                    _append_bounded_pending_row(
                                        pending_rows,
                                        row,
                                        max_pending_rows=max_pending_rows,
                                        loop_name=loop_name,
                                        drop_state=drop_state,
                                    )
                                    pending = len(pending_rows)
                            except Exception:
                                log_exception_throttled(
                                    logger,
                                    f"diagnostic_store.ingest.{loop_name}",
                                    interval_seconds=300.0,
                                    message=f"Diagnostic tailer failed to parse a log line in {loop_name}",
                                )
                            now = time.monotonic()
                            if (
                                pending
                                and flush_backoff.can_attempt(now)
                                and (
                                    pending >= commit_batch
                                    or (now - last_commit) >= commit_interval
                                )
                            ):
                                try:
                                    flush_pending()
                                except DATABASE_ERRORS as exc:
                                    delay = record_deferred_flush(now)
                                    log_database_unavailable(
                                        logger,
                                        f"diagnostic_store.commit.{loop_name}.db",
                                        f"Diagnostic tailer deferred batch flush in {loop_name} while MySQL is unavailable; retrying in about {delay:.1f}s",
                                        exc,
                                    )
                                except Exception:
                                    log_exception_throttled(
                                        logger,
                                        f"diagnostic_store.commit.{loop_name}",
                                        interval_seconds=300.0,
                                        message=f"Diagnostic tailer batch commit failed in {loop_name}",
                                    )
                                    last_commit = now
                            continue

                        now = time.monotonic()
                        if (
                            pending
                            and flush_backoff.can_attempt(now)
                            and (now - last_commit) >= commit_interval
                        ):
                            try:
                                flush_pending()
                            except DATABASE_ERRORS as exc:
                                delay = record_deferred_flush(now)
                                log_database_unavailable(
                                    logger,
                                    f"diagnostic_store.idle_commit.{loop_name}.db",
                                    f"Diagnostic tailer deferred idle flush in {loop_name} while MySQL is unavailable; retrying in about {delay:.1f}s",
                                    exc,
                                )
                            except Exception:
                                log_exception_throttled(
                                    logger,
                                    f"diagnostic_store.idle_commit.{loop_name}",
                                    interval_seconds=300.0,
                                    message=f"Diagnostic tailer idle commit failed in {loop_name}",
                                )
                                last_commit = now

                        try:
                            if pathlib.Path(path).stat().st_size < handle.tell():
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
                        if (
                            inode_now is not None
                            and last_inode is not None
                            and inode_now != last_inode
                        ):
                            last_inode = inode_now
                            if flush_backoff.can_attempt(now):
                                try:
                                    flush_pending()
                                except DATABASE_ERRORS as exc:
                                    delay = record_deferred_flush(now)
                                    log_database_unavailable(
                                        logger,
                                        f"diagnostic_store.rotate.{loop_name}.db",
                                        f"Diagnostic tailer deferred rotation flush for {loop_name} while MySQL is unavailable; retrying in about {delay:.1f}s",
                                        exc,
                                    )
                                except Exception:
                                    log_exception_throttled(
                                        logger,
                                        f"diagnostic_store.rotate.{loop_name}",
                                        interval_seconds=300.0,
                                        message=f"Diagnostic tailer final commit failed during rotation for {loop_name}",
                                    )
                            reopen_from_start = True
                            break

                        time.sleep(poll_interval)
            except DATABASE_ERRORS as exc:
                log_database_unavailable(
                    logger,
                    f"diagnostic_store.loop.{loop_name}.db",
                    f"Diagnostic tailer deferred database work for {loop_name} while MySQL is unavailable",
                    exc,
                )
                time.sleep(max(5.0, poll_interval))
            except Exception:
                log_exception_throttled(
                    logger,
                    f"diagnostic_store.loop.{loop_name}",
                    interval_seconds=300.0,
                    message=f"Diagnostic tailer loop failed for {loop_name}",
                )
                time.sleep(max(1.0, poll_interval))

    def _parse_request_log_line(self, line: str) -> dict[str, Any] | None:
        row = _split_tsv(line)
        if len(row) < 18:
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
        policy_fields = _policy_fields_from_row(row, 18)
        response_content_type = _safe_text(
            row[22] if len(row) > 22 else "", max_len=255
        )
        response_server = _safe_text(row[23] if len(row) > 23 else "", max_len=255)
        response_cf_mitigated = _safe_text(row[24] if len(row) > 24 else "", max_len=64)
        response_alt_svc = _safe_text(row[25] if len(row) > 25 else "", max_len=512)
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
            **policy_fields,
            "response_content_type": response_content_type,
            "response_server": response_server,
            "response_cf_mitigated": response_cf_mitigated,
            "response_alt_svc": response_alt_svc,
            "raw": _bounded_raw_line(line),
        }

    def _build_request_insert_params(self, line: str) -> tuple[Any, ...] | None:
        row = self._parse_request_log_line(line)
        if not row or _is_internal_diagnostic_row(row):
            return None
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
        return (
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
            str(row["response_content_type"]),
            str(row["response_server"]),
            str(row["response_cf_mitigated"]),
            str(row["response_alt_svc"]),
            str(row["raw"]),
            int(_now()),
        )

    def _parse_icap_log_line(self, line: str) -> dict[str, Any] | None:
        row = _split_tsv(line)
        if len(row) < 11:
            return None

        # Squid/c-icap builds and previous repository revisions can drift by
        # inserting ICAP status/service tokens around the timing fields. Keep the
        # canonical legacy icapobserve layout first, then parse the extended
        # Squid ICAP tokens when present so operators can attribute failures to
        # adblock REQMOD, upload AV REQMOD, or download AV RESPMOD.
        def _looks_int(value: str) -> bool:
            try:
                int(str(value).strip())
                return True
            except Exception:
                return False

        time_index = 5
        fields_offset = 0
        if len(row) >= 12 and not _looks_int(row[5]) and _looks_int(row[6]):
            time_index = 6
            fields_offset = 1
        elif (
            len(row) >= 12
            and _looks_int(row[5])
            and re.fullmatch(r"[1-5][0-9]{2}", row[6].strip())
        ):
            fields_offset = 1

        ts = _safe_int(row[0], _now())
        master_xaction = _safe_text(row[1], max_len=128)
        client_ip = _safe_text(row[2], max_len=64)
        method = _safe_text(row[3], max_len=16)
        url = _safe_text(row[4])
        icap_time_ms = _safe_int(row[time_index], 0)
        adapt_summary = _safe_text(row[6 + fields_offset], max_len=1024)
        adapt_details = _safe_text(row[7 + fields_offset])
        host = _safe_text(row[8 + fields_offset], max_len=255)
        user_agent = _safe_text(row[9 + fields_offset], max_len=512)
        sni = _safe_text(row[10 + fields_offset], max_len=255)
        policy_fields = _policy_fields_from_row(row, 11 + fields_offset)
        extended_start = 15 + fields_offset
        icap_service = _policy_text(
            row[extended_start] if len(row) > extended_start else ""
        )
        icap_outcome = _policy_text(
            row[extended_start + 1] if len(row) > extended_start + 1 else ""
        )
        icap_status = (
            _safe_int(row[extended_start + 2], 0)
            if len(row) > extended_start + 2
            else 0
        )
        icap_response_time_ms = (
            _safe_int(row[extended_start + 3], 0)
            if len(row) > extended_start + 3
            else 0
        )
        icap_io_time_ms = (
            _safe_int(row[extended_start + 4], 0)
            if len(row) > extended_start + 4
            else 0
        )
        icap_bytes_sent = (
            _safe_int(row[extended_start + 5], 0)
            if len(row) > extended_start + 5
            else 0
        )
        icap_bytes_received = (
            _safe_int(row[extended_start + 6], 0)
            if len(row) > extended_start + 6
            else 0
        )
        icap_metadata_parts = []
        if icap_service:
            icap_metadata_parts.append(f"service={icap_service}")
        if icap_outcome:
            icap_metadata_parts.append(f"outcome={icap_outcome}")
        if icap_status:
            icap_metadata_parts.append(f"status={icap_status}")
        if icap_response_time_ms:
            icap_metadata_parts.append(f"tr_ms={icap_response_time_ms}")
        if icap_io_time_ms:
            icap_metadata_parts.append(f"tio_ms={icap_io_time_ms}")
        if icap_bytes_sent:
            icap_metadata_parts.append(f"bytes_sent={icap_bytes_sent}")
        if icap_bytes_received:
            icap_metadata_parts.append(f"bytes_received={icap_bytes_received}")
        if icap_metadata_parts:
            base_details = "" if adapt_details == "-" else adapt_details
            adapt_details = " ".join(
                part for part in (base_details, ";".join(icap_metadata_parts)) if part
            )

        domain = _extract_domain(url, host=host, sni=sni)
        family = _service_family(adapt_summary, adapt_details, icap_service, url)

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
            **policy_fields,
            "service_family": family,
            "icap_service": icap_service,
            "icap_outcome": icap_outcome,
            "icap_status": icap_status,
            "icap_response_time_ms": icap_response_time_ms,
            "icap_io_time_ms": icap_io_time_ms,
            "icap_bytes_sent": icap_bytes_sent,
            "icap_bytes_received": icap_bytes_received,
            "raw": _bounded_raw_line(line),
        }

    def _build_icap_insert_params(self, line: str) -> tuple[Any, ...] | None:
        row = self._parse_icap_log_line(line)
        if not row or _is_internal_diagnostic_row(row):
            return None
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
        return (
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
        )

    def _flush_request_rows(self, conn, rows: list[tuple[Any, ...]]) -> None:
        if not rows:
            return
        conn.executemany(
            """
            INSERT IGNORE INTO diagnostic_requests (
                proxy_id, event_key, ts, duration_ms, client_ip, method, url, domain, result_code, http_status,
                bytes, master_xaction, hierarchy_status, bump_mode, sni, tls_server_version, tls_server_cipher,
                tls_client_version, tls_client_cipher, host, user_agent, referer, exclusion_rule, ssl_exception,
                webfilter_allow, cache_bypass, response_content_type, response_server, response_cf_mitigated,
                response_alt_svc, raw, created_ts
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            rows,
        )
        self._materialize_request_policy_tags(conn, rows)

    def _materialize_request_policy_tags(
        self, conn, rows: list[tuple[Any, ...]]
    ) -> None:
        tag_rows: list[tuple[Any, ...]] = []
        for row in rows:
            tags = _policy_tags(
                exclusion_rule=_policy_text(row[22]),
                ssl_exception=_policy_text(row[23]),
                webfilter_allow=_policy_text(row[24]),
                cache_bypass=_policy_text(row[25]),
            )
            tag_rows.extend((tag, row[0], row[1]) for tag in tags)
        if not tag_rows:
            return
        conn.executemany(
            """
            INSERT IGNORE INTO diagnostic_policy_tags (proxy_id, request_id, tag, ts)
            SELECT proxy_id, id, %s, ts
            FROM diagnostic_requests
            WHERE proxy_id = %s AND event_key = %s
            LIMIT 1
            """,
            tag_rows,
        )

    def _flush_icap_rows(self, conn, rows: list[tuple[Any, ...]]) -> None:
        if not rows:
            return
        conn.executemany(
            """
            INSERT IGNORE INTO diagnostic_icap_events (
                proxy_id, event_key, ts, master_xaction, client_ip, method, url, domain, icap_time_ms,
                adapt_summary, adapt_details, host, user_agent, sni, exclusion_rule, ssl_exception,
                webfilter_allow, cache_bypass, service_family, raw, created_ts
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            rows,
        )

    def _ingest_request_line_with_conn(self, conn, line: str) -> bool:
        params = self._build_request_insert_params(line)
        if params is None:
            return False
        self._flush_request_rows(conn, [params])
        return True

    def _ingest_icap_line_with_conn(self, conn, line: str) -> bool:
        params = self._build_icap_insert_params(line)
        if params is None:
            return False
        self._flush_icap_rows(conn, [params])
        return True

    def list_recent_requests(
        self,
        *,
        since: int | None = None,
        search: str = "",
        client_ip: str = "",
        domain: str = "",
        master_xaction: str = "",
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        where = ["proxy_id = %s"]
        params: list[Any] = [get_proxy_id()]
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
                "("
                "LOWER(domain) LIKE %s ESCAPE '\\\\' OR LOWER(url) LIKE %s ESCAPE '\\\\' OR LOWER(host) LIKE %s ESCAPE '\\\\' OR LOWER(sni) LIKE %s ESCAPE '\\\\' OR LOWER(master_xaction) LIKE %s ESCAPE '\\\\' OR LOWER(client_ip) LIKE %s ESCAPE '\\\\' OR LOWER(user_agent) LIKE %s ESCAPE '\\\\'"
                ")",
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
                    ssl_exception, webfilter_allow, cache_bypass, response_content_type, response_server,
                    response_cf_mitigated, response_alt_svc
                FROM diagnostic_requests
                {where_sql}
                ORDER BY ts DESC, id DESC
                LIMIT %s
                """,
                (*params, lim),
            ).fetchall()
        return [_normalize_request_row(row) for row in rows]

    def find_request_by_master_xaction(
        self,
        master_xaction: str,
    ) -> dict[str, Any] | None:
        tx = (master_xaction or "").strip()
        if not tx:
            return None
        rows = self.list_recent_requests(master_xaction=tx, limit=1)
        return rows[0] if rows else None

    def list_recent_icap(
        self,
        *,
        since: int | None = None,
        search: str = "",
        client_ip: str = "",
        domain: str = "",
        master_xaction: str = "",
        service: str = "",
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        where = ["proxy_id = %s"]
        params: list[Any] = [get_proxy_id()]
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
                "("
                "LOWER(domain) LIKE %s ESCAPE '\\\\' OR LOWER(url) LIKE %s ESCAPE '\\\\' OR LOWER(host) LIKE %s ESCAPE '\\\\' OR LOWER(sni) LIKE %s ESCAPE '\\\\' OR LOWER(master_xaction) LIKE %s ESCAPE '\\\\' OR LOWER(client_ip) LIKE %s ESCAPE '\\\\' OR LOWER(adapt_summary) LIKE %s ESCAPE '\\\\' OR LOWER(adapt_details) LIKE %s ESCAPE '\\\\'"
                ")",
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
                (*params, lim),
            ).fetchall()
        return [_normalize_icap_row(row) for row in rows]

    def _batch_list_icap_by_master_xactions(
        self,
        master_xactions: list[str],
        *,
        service: str = "",
        limit_per_transaction: int = 5,
    ) -> dict[str, list[dict[str, Any]]]:
        txs: list[str] = []
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
        params: list[Any] = [get_proxy_id()]
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

        grouped: dict[str, list[dict[str, Any]]] = {tx: [] for tx in txs}
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
        since: int | None = None,
        search: str = "",
        client_ip: str = "",
        domain: str = "",
        master_xaction: str = "",
        service: str = "",
        limit: int = 50,
        icap_limit_per_transaction: int = 5,
    ) -> list[dict[str, Any]]:
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

        transactions: list[dict[str, Any]] = []
        for row in rows:
            related_icap = icap_map.get(
                str(row.get("master_xaction") or "").strip(),
                [],
            )
            if (service or "").strip() and not related_icap:
                continue
            enriched = dict(row)
            enriched["related_icap"] = related_icap
            enriched["service_families"] = sorted(
                {
                    str(event.get("service_family") or "")
                    for event in related_icap
                    if event.get("service_family")
                },
            )
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
    ) -> list[dict[str, Any]]:
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
                    ssl_exception, webfilter_allow, cache_bypass, response_content_type, response_server,
                    response_cf_mitigated, response_alt_svc
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

        out: list[dict[str, Any]] = []
        for row in normalized_rows:
            enriched = dict(row)
            enriched["related_icap"] = icap_map.get(
                str(row.get("master_xaction") or "").strip(),
                [],
            )
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
    ) -> list[dict[str, Any]]:
        normalized_domain = _normalize_hostish(domain) or _extract_domain(url)
        center = int(around_ts or _now())
        window_i = max(30, min(24 * 3600, int(window_seconds or 300)))
        lim = max(1, min(20, int(limit)))

        where = ["proxy_id = %s", "ts BETWEEN %s AND %s"]
        params: list[Any] = [get_proxy_id(), center - window_i, center + window_i]
        if client_ip:
            where.append("client_ip = %s")
            params.append(client_ip.strip())
        like_parts: list[str] = []
        if normalized_domain:
            like_parts.append("domain = %s")
            params.append(normalized_domain)
        raw_url = (url or "").strip()
        if raw_url:
            like_parts.append("url LIKE %s ESCAPE '\\\\'")
            params.append(f"%{_escape_like(raw_url)}%")
        elif normalized_domain:
            like_parts.append("url LIKE %s ESCAPE '\\\\'")
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
                    ssl_exception, webfilter_allow, cache_bypass, response_content_type, response_server,
                    response_cf_mitigated, response_alt_svc
                FROM diagnostic_requests
                {where_sql}
                ORDER BY ABS(ts - %s) ASC, ts DESC, id DESC
                LIMIT %s
                """,
                (*params, center, lim),
            ).fetchall()

        normalized_rows = [_normalize_request_row(row) for row in rows]
        icap_map = self._batch_list_icap_by_master_xactions(
            [str(row.get("master_xaction") or "") for row in normalized_rows],
            service=service,
            limit_per_transaction=icap_limit_per_transaction,
        )

        out: list[dict[str, Any]] = []
        for row in normalized_rows:
            enriched = dict(row)
            enriched["related_icap"] = icap_map.get(
                str(row.get("master_xaction") or "").strip(),
                [],
            )
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
    ) -> list[dict[str, Any]]:
        normalized_domain = _normalize_hostish(domain)
        if not normalized_domain:
            return []

        center = int(around_ts or _now())
        window_i = max(30, min(24 * 3600, int(window_seconds or 300)))
        lim = max(1, min(20, int(limit)))
        normalized_service = (service or "").strip().lower()

        where = ["proxy_id = %s", "domain = %s", "ts BETWEEN %s AND %s"]
        params: list[Any] = [
            get_proxy_id(),
            normalized_domain,
            center - window_i,
            center + window_i,
        ]
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
                (*params, center, lim),
            ).fetchall()

        out: list[dict[str, Any]] = []
        for row in rows:
            normalized = _normalize_icap_row(row)
            normalized["time_delta_seconds"] = abs(
                int(normalized.get("ts") or 0) - center,
            )
            normalized["correlation_kind"] = "domain_time"
            out.append(normalized)
        return out

    def activity_summary(self, *, since: int | None = None) -> dict[str, int]:
        request_where = ["proxy_id = %s"]
        request_params: list[Any] = [get_proxy_id()]
        icap_where = ["proxy_id = %s"]
        icap_params: list[Any] = [get_proxy_id()]
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

    def top_request_dimension(
        self,
        dimension: str,
        *,
        since: int | None = None,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        column = _REQUEST_DIMENSIONS.get((dimension or "").strip().lower())
        if not column:
            return []

        lim = max(1, min(50, int(limit)))
        where = ["proxy_id = %s", f"COALESCE(NULLIF(TRIM({column}), ''), '') <> ''"]
        params: list[Any] = [get_proxy_id()]
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
                (*params, lim),
            ).fetchall()

        out: list[dict[str, Any]] = [
            {
                "value": str(row[0] or ""),
                "count": int(row[1] or 0),
                "last_seen": int(row[2] or 0),
            }
            for row in rows
        ]
        return out

    def top_policy_tags(
        self,
        *,
        since: int | None = None,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        self.init_db()
        lim = max(1, min(50, int(limit)))
        params: list[Any] = [get_proxy_id()]
        since_sql = ""
        if since is not None:
            since_sql = " AND ts >= %s"
            params.append(int(since))

        sql = f"""
        SELECT tag, COUNT(*) AS total, MAX(ts) AS last_seen
        FROM diagnostic_policy_tags
        WHERE proxy_id = %s{since_sql}
        GROUP BY tag
        ORDER BY total DESC, last_seen DESC
        LIMIT %s
        """
        query_params = [*params, lim]

        with self._connect() as conn:
            rows = conn.execute(sql, tuple(query_params)).fetchall()
            if not rows:
                has_materialized_tags = conn.execute(
                    "SELECT 1 FROM diagnostic_policy_tags WHERE proxy_id = %s LIMIT 1",
                    (params[0],),
                ).fetchone()
                if not has_materialized_tags:
                    self._backfill_policy_tags(conn, proxy_id=params[0], since=None)
                    rows = conn.execute(sql, tuple(query_params)).fetchall()

        return [
            {
                "tag": str(row[0] or ""),
                "count": int(row[1] or 0),
                "last_seen": int(row[2] or 0),
            }
            for row in rows
        ]

    def _backfill_policy_tags(
        self,
        conn,
        *,
        proxy_id: str,
        since: int | None,
    ) -> None:
        where = ["r.proxy_id = %s"]
        params: list[Any] = [proxy_id]
        if since is not None:
            where.append("r.ts >= %s")
            params.append(int(since))
        where_sql = " AND ".join(where)
        tag_expr = """
        CASE p.kind
            WHEN 'exclude' THEN CASE WHEN COALESCE(NULLIF(NULLIF(TRIM(r.exclusion_rule), ''), '-'), '') <> '' THEN CONCAT('exclude:', TRIM(r.exclusion_rule)) ELSE '' END
            WHEN 'ssl' THEN CASE WHEN COALESCE(NULLIF(NULLIF(TRIM(r.ssl_exception), ''), '-'), '') <> '' THEN CONCAT('ssl:', TRIM(r.ssl_exception)) ELSE '' END
            WHEN 'webfilter' THEN CASE WHEN COALESCE(NULLIF(NULLIF(TRIM(r.webfilter_allow), ''), '-'), '') <> '' THEN CONCAT('webfilter:', TRIM(r.webfilter_allow)) ELSE '' END
            WHEN 'cache' THEN CASE WHEN COALESCE(NULLIF(NULLIF(TRIM(r.cache_bypass), ''), '-'), '') <> '' THEN CONCAT('cache:', TRIM(r.cache_bypass)) ELSE '' END
            ELSE ''
        END
        """
        conn.execute(
            f"""
            INSERT IGNORE INTO diagnostic_policy_tags (proxy_id, request_id, tag, ts)
            SELECT r.proxy_id, r.id, {tag_expr} AS tag, r.ts
            FROM diagnostic_requests r
            CROSS JOIN (
                SELECT 'exclude' AS kind
                UNION ALL SELECT 'ssl'
                UNION ALL SELECT 'webfilter'
                UNION ALL SELECT 'cache'
            ) p
            WHERE {where_sql} AND {tag_expr} <> ''
            """,
            tuple(params),
        )

    def slowest_requests(
        self,
        *,
        since: int | None = None,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        where = [
            "proxy_id = %s",
            "UPPER(COALESCE(method, '')) <> 'CONNECT'",
            "UPPER(COALESCE(result_code, '')) NOT LIKE 'TCP_TUNNEL%%'",
            "UPPER(COALESCE(result_code, '')) NOT LIKE 'TCP_CONNECT%%'",
        ]
        params: list[Any] = [get_proxy_id()]
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
                    ssl_exception, webfilter_allow, cache_bypass, response_content_type, response_server,
                    response_cf_mitigated, response_alt_svc
                FROM diagnostic_requests
                {where_sql}
                ORDER BY duration_ms DESC, ts DESC, id DESC
                LIMIT %s
                """,
                (*params, lim),
            ).fetchall()

        return [_normalize_request_row(row) for row in rows]

    def icap_summary(
        self,
        *,
        since: int | None = None,
        service: str = "",
    ) -> dict[str, int]:
        where = ["proxy_id = %s"]
        params: list[Any] = [get_proxy_id()]
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

    def slowest_icap_events(
        self,
        *,
        since: int | None = None,
        service: str = "",
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        where = ["proxy_id = %s"]
        params: list[Any] = [get_proxy_id()]
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
                (*params, lim),
            ).fetchall()
        return [_normalize_icap_row(row) for row in rows]

    def list_icap_by_master_xaction(
        self,
        master_xaction: str,
        *,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        tx = (master_xaction or "").strip()
        if not tx:
            return []
        return self.list_recent_icap(master_xaction=tx, limit=limit)


_store: DiagnosticStore | None = None
_store_lock = threading.Lock()


def get_diagnostic_store() -> DiagnosticStore:
    global _store
    if _store is not None:
        return _store
    with _store_lock:
        if _store is None:
            _store = DiagnosticStore(
                access_log_path=os.environ.get(
                    "SQUID_DIAGNOSTIC_ACCESS_LOG",
                    "/var/log/squid/access-observe.log",
                ),
                icap_log_path=os.environ.get(
                    "SQUID_DIAGNOSTIC_ICAP_LOG",
                    "/var/log/squid/icap.log",
                ),
                seed_max_lines=_env_int(
                    "DIAGNOSTIC_SEED_MAX_LINES",
                    5000,
                    minimum=500,
                    maximum=20000,
                ),
                retention_days=_env_int(
                    "DIAGNOSTIC_RETENTION_DAYS",
                    7,
                    minimum=1,
                    maximum=90,
                ),
            )
        return _store
