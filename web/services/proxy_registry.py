from __future__ import annotations

import os
import re
import socket
import threading
import time
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from ipaddress import IPv6Address, ip_address
from typing import Any
from urllib.parse import unquote, urlsplit, urlunsplit

from services.db import (
    DATABASE_ERRORS,
    connect,
    mysql_advisory_lock,
    mysql_error_code,
    mysql_schema_lock_timeout_seconds,
    run_mysql_operation_with_retry,
    table_exists,
)
from services.domain_normalization import is_ambiguous_ipv4_like_host
from services.proxy_context import get_default_proxy_id, normalize_proxy_id
from services.proxy_lifecycle import (
    ProxyLifecycleIncompleteError,
    ProxyLifecycleRunResult,
    ensure_lifecycle_schema,
    prepare_proxy_lifecycle,
    proxy_scoped_tables_with_rows,
    remove_proxy_scoped_rows,
    rename_proxy_scoped_rows,
)
from services.proxy_write_guard import (
    clear_proxy_write_guard_cache,
    proxy_lifecycle_lock_name,
)
from services.public_endpoint import _canonical_public_dns_host
from services.public_endpoint import (
    coerce_public_port as _coerce_port,
)
from services.public_endpoint import (
    normalize_public_host as _normalize_public_host,
)
from services.public_endpoint import (
    normalize_public_scheme as _normalize_public_scheme,
)
from services.runtime_helpers import authority_has_empty_explicit_port
from services.url_validation import has_malformed_percent_encoding


def _is_mysql_error_code(exc: BaseException, codes: set[int]) -> bool:
    return mysql_error_code(exc) in codes


def _seed_new_proxy_adblock_runtime_default(conn: Any, proxy_id: str) -> None:
    """Disable adblock for a new proxy when the feature schema is present."""
    # Registry-only/lifecycle tests and partial deployments may initialize
    # proxy_instances without the optional adblock runtime tables. Probe that
    # exact capability rather than broadly suppressing database write errors.
    if not table_exists(conn, "adblock_proxy_meta"):
        return
    conn.execute(
        "INSERT IGNORE INTO adblock_proxy_meta(proxy_id,k,v) VALUES(%s,'enabled','0')",
        (proxy_id,),
    )


@dataclass
class _CommittedLifecycleAttempt:
    committed: bool = False


@contextmanager
def _preserve_committed_lifecycle_success():
    """Suppress connection cleanup DB errors after a proven lifecycle commit.

    Yields:
        Mutable attempt state marked after the lifecycle commit succeeds.

    """
    attempt = _CommittedLifecycleAttempt()
    try:
        yield attempt
    except DATABASE_ERRORS:
        if not attempt.committed:
            raise


def _lifecycle_incomplete_retry_detail(result: ProxyLifecycleRunResult) -> str:
    if any(
        step.truncated and step.detail == "missing_prepared_lifecycle_index"
        for step in result.table_results
    ):
        return "paused to prepare a newly discovered lifecycle index; retry to resume."
    return "paused after bounded chunk limit; retry to resume."


def _has_unsafe_url_text(value: str) -> bool:
    return any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in value)


def _has_unsafe_query_text(value: str) -> bool:
    return any(ord(ch) < 32 or ord(ch) == 127 for ch in value)


_MAX_PERCENT_DECODE_PASSES = 8


def _strict_percent_unquote(value: str) -> str | None:
    if has_malformed_percent_encoding(value):
        return None
    try:
        return unquote(value, errors="strict")
    except UnicodeDecodeError:
        return None


def _bounded_repeated_unquote(value: str) -> str | None:
    decoded = _strict_percent_unquote(value)
    if decoded is None:
        return None
    for _ in range(_MAX_PERCENT_DECODE_PASSES):
        if has_malformed_percent_encoding(decoded):
            return None
        try:
            next_decoded = unquote(decoded, errors="strict")
        except UnicodeDecodeError:
            return None
        if next_decoded == decoded:
            return decoded
        decoded = next_decoded
    if has_malformed_percent_encoding(decoded):
        return None
    try:
        return decoded if unquote(decoded, errors="strict") == decoded else None
    except UnicodeDecodeError:
        return None


def _canonical_management_dns_host(value: str) -> str:
    candidate = _canonical_public_dns_host(value, allow_single_label=True)
    if not candidate or is_ambiguous_ipv4_like_host(candidate):
        return ""
    return candidate


def _safe_decoded_path_segments(path: str) -> list[str] | None:
    raw_segments = path.split("/")
    decoded_segments = []
    repeatedly_decoded_segments = []
    for segment in raw_segments:
        decoded_segment = _strict_percent_unquote(segment)
        if decoded_segment is None:
            return None
        repeatedly_decoded_segment = _bounded_repeated_unquote(segment)
        if repeatedly_decoded_segment is None:
            return None
        decoded_segments.append(decoded_segment)
        repeatedly_decoded_segments.append(repeatedly_decoded_segment)
    if any(
        "/" in segment or "\\" in segment or _has_unsafe_url_text(segment)
        for segment in repeatedly_decoded_segments
    ):
        return None
    segments = [segment for segment in repeatedly_decoded_segments if segment]
    if any(segment in {".", ".."} for segment in segments):
        return None
    return decoded_segments


def _safe_repeatedly_decoded_query(query: str) -> bool:
    decoded_query = _bounded_repeated_unquote(query)
    if decoded_query is None:
        return False
    return "\\" not in decoded_query and not _has_unsafe_query_text(decoded_query)


def normalize_public_pac_path(value: object | None, default: str = "/proxy.pac") -> str:
    fallback = str(default if default is not None else "/proxy.pac").strip()
    if fallback and not fallback.startswith("/"):
        fallback = f"/{fallback}"
    candidate = str(value or "").strip()
    if not candidate:
        return fallback
    if _has_unsafe_url_text(candidate):
        return fallback
    try:
        parsed = urlsplit(candidate)
    except Exception:
        return fallback
    if parsed.username is not None or parsed.password is not None:
        return fallback
    if parsed.fragment:
        return fallback
    if parsed.netloc and not parsed.scheme:
        return fallback
    if parsed.scheme and parsed.scheme.lower() not in {"http", "https"}:
        return fallback
    if parsed.scheme and not parsed.netloc:
        return fallback
    path = parsed.path or fallback
    if path.startswith("//") or "\\" in path:
        return fallback
    if not path.startswith("/"):
        path = f"/{path}"
    if _safe_decoded_path_segments(path) is None:
        return fallback
    query = parsed.query
    if query:
        if not _safe_repeatedly_decoded_query(query):
            return fallback
    return f"{path}?{query}" if query else path


def normalize_management_url(value: object | None) -> str:
    candidate = str(value or "").strip()
    if not candidate:
        return ""
    if _has_unsafe_url_text(candidate):
        return ""
    if "://" not in candidate:
        candidate = f"http://{candidate}"
    try:
        parsed = urlsplit(candidate)
        if authority_has_empty_explicit_port(parsed.netloc):
            return ""
        parsed_port = parsed.port
    except Exception:
        return ""
    if parsed_port == 0:
        return ""
    scheme = str(parsed.scheme or "").lower()
    if scheme not in {"http", "https"}:
        return ""
    host = str(parsed.hostname or "").strip().lower()
    if not host or parsed.username or parsed.password:
        return ""
    if parsed.query or parsed.fragment:
        return ""
    try:
        parsed_ip = ip_address(host)
    except ValueError:
        host = _canonical_management_dns_host(host)
        if not host:
            return ""
    else:
        if getattr(parsed_ip, "scope_id", None):
            return ""
        host = str(parsed_ip)
    if _safe_decoded_path_segments(parsed.path or "") is None:
        return ""

    path = (parsed.path or "").rstrip("/")
    marker = "/api/manage"
    marker_at = path.find(marker)
    if marker_at >= 0:
        marker_end = marker_at + len(marker)
        if marker_end == len(path) or path[marker_end] == "/":
            path = path[:marker_at]
    path = path.rstrip("/")

    netloc = host
    if ":" in host and not host.startswith("["):
        netloc = f"[{host}]"
    if parsed.port is not None:
        netloc = f"{netloc}:{int(parsed.port)}"
    return urlunsplit((scheme, netloc, path, "", ""))


def _dns_safe_proxy_host(value: object | None) -> str:
    raw = str(value or "").strip().lower()
    if not raw or raw == "default":
        return "proxy"
    candidate = re.sub(r"[^a-z0-9-]+", "-", raw).strip("-")
    return candidate or "proxy"


def _parse_public_pac_url(raw_url: object | None) -> tuple[str, str, int, str]:
    candidate = str(raw_url or "").strip()
    if not candidate:
        return "", "http", 80, "/proxy.pac"
    if _has_unsafe_url_text(candidate):
        return "", "http", 80, "/proxy.pac"
    has_absolute_scheme = "://" in candidate
    if "://" not in candidate:
        match = re.match(r"([^/?#]+)(.*)", candidate)
        authority = match.group(1) if match else candidate
        suffix = match.group(2) if match else ""
        if not authority.startswith("[") and authority.count(":") > 1:
            try:
                parsed_ip = ip_address(authority)
            except ValueError:
                parsed_ip = None
            if isinstance(parsed_ip, IPv6Address):
                candidate = f"[{authority}]{suffix}"
        candidate = f"http://{candidate}"
    try:
        parsed = urlsplit(candidate)
    except Exception:
        return "", "http", 80, "/proxy.pac"
    if authority_has_empty_explicit_port(parsed.netloc):
        return "", "http", 80, "/proxy.pac"
    if (
        parsed.netloc
        and not parsed.netloc.startswith("[")
        and "@" not in parsed.netloc
        and parsed.netloc.count(":") > 1
    ):
        try:
            parsed_ip = ip_address(parsed.netloc)
        except ValueError:
            parsed_ip = None
        if isinstance(parsed_ip, IPv6Address):
            parsed = urlsplit(
                urlunsplit(
                    (
                        parsed.scheme,
                        f"[{parsed.netloc}]",
                        parsed.path,
                        parsed.query,
                        "",
                    ),
                ),
            )
    raw_scheme = str(parsed.scheme or "").lower()
    if has_absolute_scheme and raw_scheme not in {"http", "https"}:
        return "", "http", 80, "/proxy.pac"
    if parsed.username is not None or parsed.password is not None:
        return "", "http", 80, "/proxy.pac"
    if parsed.fragment:
        return "", "http", 80, "/proxy.pac"
    host = _normalize_public_host(parsed.hostname, allow_single_label=True)
    if not host:
        return "", "http", 80, "/proxy.pac"
    scheme = _normalize_public_scheme(raw_scheme)
    default_port = 443 if scheme == "https" else 80
    try:
        parsed_port = parsed.port
    except ValueError:
        return "", "http", 80, "/proxy.pac"
    if parsed_port == 0:
        return "", "http", 80, "/proxy.pac"
    path = normalize_public_pac_path(candidate)
    return host, scheme, int(parsed_port or default_port), path


def resolve_local_proxy_public_fields() -> dict[str, object]:
    url_host, url_scheme, url_port, url_path = _parse_public_pac_url(
        os.environ.get("PROXY_PUBLIC_PAC_URL"),
    )
    public_host = (
        _normalize_public_host(
            os.environ.get("PROXY_PUBLIC_HOST"),
            allow_single_label=True,
        )
        or url_host
    )
    public_pac_scheme = _normalize_public_scheme(
        os.environ.get("PROXY_PUBLIC_PAC_SCHEME") or url_scheme or "http",
    )
    default_pac_port = 443 if public_pac_scheme == "https" else 80
    public_pac_port = _coerce_port(
        os.environ.get("PROXY_PUBLIC_PAC_PORT"),
        url_port or default_pac_port,
    )
    public_http_proxy_port = _coerce_port(
        os.environ.get("PROXY_PUBLIC_HTTP_PROXY_PORT"),
        3128,
    )
    return {
        "public_host": public_host,
        "public_pac_scheme": public_pac_scheme,
        "public_pac_port": public_pac_port,
        "public_pac_path": url_path,
        "public_http_proxy_port": public_http_proxy_port,
    }


def resolve_local_proxy_management_url(
    proxy_id: object | None,
    public_host: object | None = None,
) -> str:
    explicit_url = (os.environ.get("PROXY_MANAGEMENT_URL") or "").strip()
    if explicit_url:
        return normalize_management_url(explicit_url)

    scheme = _normalize_public_scheme(
        os.environ.get("PROXY_MANAGEMENT_SCHEME") or "http",
    )
    port = _coerce_port(os.environ.get("PROXY_MANAGEMENT_PORT"), 5000)
    explicit_host = (os.environ.get("PROXY_MANAGEMENT_HOST") or "").strip()
    host = (
        explicit_host
        or str(public_host or "").strip()
        or _dns_safe_proxy_host(proxy_id)
    )
    return normalize_management_url(f"{scheme}://{host}:{port}")


@dataclass(frozen=True)
class ProxyInstance:
    proxy_id: str
    display_name: str
    hostname: str
    management_url: str
    public_host: str
    public_pac_scheme: str
    public_pac_port: int
    public_pac_path: str
    public_http_proxy_port: int
    status: str
    last_heartbeat: int
    last_apply_ts: int
    last_apply_ok: bool
    current_config_sha: str
    detail: str
    created_ts: int
    updated_ts: int


@dataclass(frozen=True)
class ProxyRemovalResult:
    proxy_id: str
    deleted_rows: int
    table_counts: dict[str, int]
    complete: bool = True
    iterations: int = 0
    truncated_tables: tuple[str, ...] = ()
    discovered_tables: tuple[str, ...] = ()


class ProxyRegistry:
    _SELECT_COLUMNS = "proxy_id, display_name, hostname, management_url, public_host, public_pac_scheme, public_pac_port, public_pac_path, public_http_proxy_port, status, last_heartbeat, last_apply_ts, last_apply_ok, current_config_sha, detail, created_ts, updated_ts"

    def __init__(self) -> None:
        self._schema_ready = False
        self._schema_lock = threading.Lock()
        self._columns_cache: dict[str, set[str]] = {}

    def _connect(self):
        return connect()

    def _existing_columns(self, conn, table_name: str) -> set[str]:
        cached = self._columns_cache.get(table_name)
        if cached is not None:
            return set(cached)
        rows = conn.execute(
            """
            SELECT column_name AS column_name
            FROM information_schema.columns
            WHERE table_schema = DATABASE() AND table_name = %s
            """,
            (table_name,),
        ).fetchall()
        columns = {str(row["column_name"] or "") for row in rows}
        self._columns_cache[table_name] = set(columns)
        return columns

    def init_db(self) -> None:
        if self._schema_ready:
            return
        with self._schema_lock:
            if self._schema_ready:
                return

            def _ensure_schema() -> None:
                with self._connect() as conn:
                    from services.schema_lifecycle import (
                        runtime_schema_ready_for_lazy_store,
                    )

                    if runtime_schema_ready_for_lazy_store(conn):
                        self._schema_ready = True
                        return
                    with mysql_advisory_lock(
                        conn,
                        "docker_proxy:proxy_registry:schema",
                        mysql_schema_lock_timeout_seconds(),
                    ):
                        conn.execute(
                            """
                            CREATE TABLE IF NOT EXISTS proxy_instances (
                                proxy_id VARCHAR(64) PRIMARY KEY,
                                display_name VARCHAR(255) NOT NULL,
                                hostname VARCHAR(255) NOT NULL DEFAULT '',
                                management_url VARCHAR(512) NOT NULL DEFAULT '',
                                public_host VARCHAR(255) NOT NULL DEFAULT '',
                                public_pac_scheme VARCHAR(16) NOT NULL DEFAULT 'http',
                                public_pac_port INT NOT NULL DEFAULT 80,
                                public_pac_path VARCHAR(512) NOT NULL DEFAULT '/proxy.pac',
                                public_http_proxy_port INT NOT NULL DEFAULT 3128,
                                status VARCHAR(32) NOT NULL DEFAULT 'unknown',
                                last_heartbeat BIGINT NOT NULL DEFAULT 0,
                                last_apply_ts BIGINT NOT NULL DEFAULT 0,
                                last_apply_ok TINYINT(1) NOT NULL DEFAULT 0,
                                current_config_sha CHAR(64) NOT NULL DEFAULT '',
                                detail TEXT,
                                created_ts BIGINT NOT NULL,
                                updated_ts BIGINT NOT NULL,
                                KEY idx_proxy_instances_status (status, last_heartbeat),
                                KEY idx_proxy_instances_updated (updated_ts)
                            )
                            """,
                        )
                        columns = self._existing_columns(conn, "proxy_instances")
                        required_columns = {
                            "public_host": "ALTER TABLE proxy_instances ADD COLUMN public_host VARCHAR(255) NOT NULL DEFAULT '' AFTER management_url",
                            "public_pac_scheme": "ALTER TABLE proxy_instances ADD COLUMN public_pac_scheme VARCHAR(16) NOT NULL DEFAULT 'http' AFTER public_host",
                            "public_pac_port": "ALTER TABLE proxy_instances ADD COLUMN public_pac_port INT NOT NULL DEFAULT 80 AFTER public_pac_scheme",
                            "public_pac_path": "ALTER TABLE proxy_instances ADD COLUMN public_pac_path VARCHAR(512) NOT NULL DEFAULT '/proxy.pac' AFTER public_pac_port",
                            "public_http_proxy_port": "ALTER TABLE proxy_instances ADD COLUMN public_http_proxy_port INT NOT NULL DEFAULT 3128 AFTER public_pac_path",
                        }
                        for column_name, ddl in required_columns.items():
                            if column_name not in columns:
                                try:
                                    conn.execute(ddl)
                                except DATABASE_ERRORS as exc:
                                    if not _is_mysql_error_code(exc, {1060}):
                                        raise
                        conn.execute(
                            """
                            CREATE TABLE IF NOT EXISTS proxy_id_aliases (
                                alias_proxy_id VARCHAR(64) PRIMARY KEY,
                                proxy_id VARCHAR(64) NOT NULL,
                                created_ts BIGINT NOT NULL,
                                updated_ts BIGINT NOT NULL,
                                KEY idx_proxy_id_aliases_proxy_id (proxy_id)
                            )
                            """,
                        )
                        ensure_lifecycle_schema(conn)
                        self._columns_cache.pop("proxy_instances", None)
                        self._columns_cache["proxy_instances"] = self._existing_columns(
                            conn,
                            "proxy_instances",
                        )

            run_mysql_operation_with_retry(_ensure_schema)
            self._schema_ready = True

    def _row_to_instance(self, row: object | None) -> ProxyInstance | None:
        if not row:
            return None
        return ProxyInstance(
            proxy_id=str(row["proxy_id"]),
            display_name=str(row["display_name"] or row["proxy_id"]),
            hostname=str(row["hostname"] or ""),
            management_url=normalize_management_url(row["management_url"]),
            public_host=_normalize_public_host(
                row["public_host"],
                allow_single_label=True,
            ),
            public_pac_scheme=_normalize_public_scheme(row["public_pac_scheme"]),
            public_pac_port=_coerce_port(row["public_pac_port"], 80),
            public_pac_path=normalize_public_pac_path(
                row.get("public_pac_path") or "/proxy.pac",
            ),
            public_http_proxy_port=_coerce_port(row["public_http_proxy_port"], 3128),
            status=str(row["status"] or "unknown"),
            last_heartbeat=int(row["last_heartbeat"] or 0),
            last_apply_ts=int(row["last_apply_ts"] or 0),
            last_apply_ok=bool(int(row["last_apply_ok"] or 0)),
            current_config_sha=str(row["current_config_sha"] or ""),
            detail=str(row["detail"] or ""),
            created_ts=int(row["created_ts"] or 0),
            updated_ts=int(row["updated_ts"] or 0),
        )

    def ensure_proxy(
        self,
        proxy_id: object | None,
        *,
        display_name: str | None = None,
        hostname: str | None = None,
        management_url: str | None = None,
        public_host: str | None = None,
        public_pac_scheme: str | None = None,
        public_pac_port: int | None = None,
        public_pac_path: str | None = None,
        public_http_proxy_port: int | None = None,
        status: str | None = None,
        detail: str | None = None,
    ) -> ProxyInstance:
        self.init_db()
        proxy_key = normalize_proxy_id(proxy_id)
        now = int(time.time())
        with self._connect() as conn:
            self._ensure_not_tombstoned(conn, proxy_key)
            row = conn.execute(
                f"SELECT {self._SELECT_COLUMNS} FROM proxy_instances WHERE proxy_id=%s LIMIT 1",
                (proxy_key,),
            ).fetchone()
            if row is None:
                conn.execute(
                    """
                    INSERT INTO proxy_instances(
                        proxy_id, display_name, hostname, management_url,
                        public_host, public_pac_scheme, public_pac_port, public_pac_path,
                        public_http_proxy_port, status,
                        last_heartbeat, last_apply_ts, last_apply_ok, current_config_sha,
                        detail, created_ts, updated_ts
                    )
                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """,
                    (
                        proxy_key,
                        (display_name or proxy_key).strip() or proxy_key,
                        (hostname or "").strip(),
                        normalize_management_url(management_url),
                        _normalize_public_host(
                            public_host,
                            allow_single_label=True,
                        ),
                        _normalize_public_scheme(public_pac_scheme),
                        _coerce_port(public_pac_port, 80),
                        normalize_public_pac_path(public_pac_path),
                        _coerce_port(public_http_proxy_port, 3128),
                        (status or "unknown").strip() or "unknown",
                        0,
                        0,
                        0,
                        "",
                        (detail or "").strip(),
                        now,
                        now,
                    ),
                )
                _seed_new_proxy_adblock_runtime_default(conn, proxy_key)
                row = {
                    "proxy_id": proxy_key,
                    "display_name": (display_name or proxy_key).strip() or proxy_key,
                    "hostname": (hostname or "").strip(),
                    "management_url": normalize_management_url(management_url),
                    "public_host": _normalize_public_host(
                        public_host,
                        allow_single_label=True,
                    ),
                    "public_pac_scheme": _normalize_public_scheme(public_pac_scheme),
                    "public_pac_port": _coerce_port(public_pac_port, 80),
                    "public_pac_path": normalize_public_pac_path(public_pac_path),
                    "public_http_proxy_port": _coerce_port(
                        public_http_proxy_port,
                        3128,
                    ),
                    "status": (status or "unknown").strip() or "unknown",
                    "last_heartbeat": 0,
                    "last_apply_ts": 0,
                    "last_apply_ok": 0,
                    "current_config_sha": "",
                    "detail": (detail or "").strip(),
                    "created_ts": now,
                    "updated_ts": now,
                }
            else:
                next_display = (
                    display_name or row["display_name"] or proxy_key
                ).strip() or proxy_key
                next_hostname = (hostname or row["hostname"] or "").strip()
                next_url = normalize_management_url(
                    management_url
                    if management_url is not None
                    else row["management_url"],
                )
                next_public_host = _normalize_public_host(
                    public_host
                    if public_host is not None
                    else row["public_host"] or "",
                    allow_single_label=True,
                )
                next_public_pac_scheme = _normalize_public_scheme(
                    public_pac_scheme
                    if public_pac_scheme is not None
                    else row["public_pac_scheme"],
                )
                next_public_pac_port = _coerce_port(
                    public_pac_port
                    if public_pac_port is not None
                    else row["public_pac_port"],
                    80,
                )
                next_public_pac_path = normalize_public_pac_path(
                    public_pac_path
                    if public_pac_path is not None
                    else row.get("public_pac_path") or "/proxy.pac",
                )
                next_public_http_proxy_port = _coerce_port(
                    public_http_proxy_port
                    if public_http_proxy_port is not None
                    else row["public_http_proxy_port"],
                    3128,
                )
                next_status = row["status"] if status is None else status
                next_status = (next_status or "unknown").strip() or "unknown"
                next_detail = (
                    detail if detail is not None else row["detail"] or ""
                ).strip()
                conn.execute(
                    """
                    UPDATE proxy_instances
                    SET display_name=%s, hostname=%s, management_url=%s,
                        public_host=%s, public_pac_scheme=%s, public_pac_port=%s,
                        public_pac_path=%s, public_http_proxy_port=%s, status=%s, detail=%s, updated_ts=%s
                    WHERE proxy_id=%s
                    """,
                    (
                        next_display,
                        next_hostname,
                        next_url,
                        next_public_host,
                        next_public_pac_scheme,
                        next_public_pac_port,
                        next_public_pac_path,
                        next_public_http_proxy_port,
                        next_status,
                        next_detail,
                        now,
                        proxy_key,
                    ),
                )
                row = {
                    "proxy_id": proxy_key,
                    "display_name": next_display,
                    "hostname": next_hostname,
                    "management_url": next_url,
                    "public_host": next_public_host,
                    "public_pac_scheme": next_public_pac_scheme,
                    "public_pac_port": next_public_pac_port,
                    "public_pac_path": next_public_pac_path,
                    "public_http_proxy_port": next_public_http_proxy_port,
                    "status": next_status,
                    "last_heartbeat": int(row["last_heartbeat"] or 0),
                    "last_apply_ts": int(row["last_apply_ts"] or 0),
                    "last_apply_ok": int(row["last_apply_ok"] or 0),
                    "current_config_sha": str(row["current_config_sha"] or ""),
                    "detail": next_detail,
                    "created_ts": int(row["created_ts"] or 0),
                    "updated_ts": now,
                }
        instance = self._row_to_instance(row)
        assert instance is not None
        return instance

    def ensure_default_proxy(self) -> ProxyInstance:
        default_id = get_default_proxy_id()
        return self.ensure_proxy(
            default_id,
            display_name=os.environ.get("DEFAULT_PROXY_NAME") or default_id,
        )

    def get_proxy(self, proxy_id: object | None) -> ProxyInstance | None:
        self.init_db()
        proxy_key = normalize_proxy_id(proxy_id)
        with self._connect() as conn:
            row = conn.execute(
                f"SELECT {self._SELECT_COLUMNS} FROM proxy_instances WHERE proxy_id=%s LIMIT 1",
                (proxy_key,),
            ).fetchone()
        return self._row_to_instance(row)

    def list_proxies(self) -> list[ProxyInstance]:
        self.init_db()
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT {self._SELECT_COLUMNS} FROM proxy_instances ORDER BY display_name ASC, proxy_id ASC",
            ).fetchall()
        instances = [self._row_to_instance(row) for row in rows]
        return [instance for instance in instances if instance is not None]

    def _lifecycle_lock_name(self, proxy_id: str) -> str:
        return proxy_lifecycle_lock_name(proxy_id)

    def _clear_lifecycle_write_cache(self, *proxy_ids: str) -> None:
        for proxy_id in proxy_ids:
            clear_proxy_write_guard_cache(proxy_id)

    def _ensure_not_tombstoned(
        self,
        conn,
        proxy_key: str,
        *,
        allowed_actions: set[str] | None = None,
    ) -> None:
        ensure_lifecycle_schema(conn)
        row = conn.execute(
            "SELECT action, target_proxy_id FROM proxy_lifecycle_tombstones WHERE proxy_id=%s LIMIT 1",
            (proxy_key,),
        ).fetchone()
        if row is None:
            return
        action = str(row["action"] or "removed")
        if action in (allowed_actions or set()):
            return
        target = str(row["target_proxy_id"] or "")
        if action in {"renamed", "renaming"} and target:
            msg = f"Proxy {proxy_key!r} was renamed to {target!r}."
        else:
            msg = f"Proxy {proxy_key!r} has been removed."
        raise ValueError(msg)

    def rename_proxy(
        self,
        old_proxy_id: object | None,
        new_proxy_id: object | None,
        *,
        display_name: str | None = None,
    ) -> ProxyInstance:
        self.init_db()
        old_key = normalize_proxy_id(old_proxy_id)
        new_key = normalize_proxy_id(new_proxy_id)
        if old_key == new_key:
            instance = self.get_proxy(new_key)
            if instance is None:
                msg = f"Proxy {new_key!r} is not registered."
                raise ValueError(msg)
            return instance

        now = int(time.time())
        lifecycle_result: ProxyLifecycleRunResult | None = None

        def _rename() -> None:
            nonlocal lifecycle_result
            with (
                _preserve_committed_lifecycle_success() as attempt,
                self._connect() as conn,
            ):
                with ExitStack() as stack:
                    for lock_name in sorted(
                        {
                            self._lifecycle_lock_name(old_key),
                            self._lifecycle_lock_name(new_key),
                        },
                    ):
                        stack.enter_context(
                            mysql_advisory_lock(
                                conn,
                                lock_name,
                                mysql_schema_lock_timeout_seconds(),
                            ),
                        )
                    prepare_proxy_lifecycle(conn, action="rename")
                    conn.commit()

                    old_row = conn.execute(
                        f"SELECT {self._SELECT_COLUMNS} FROM proxy_instances WHERE proxy_id=%s LIMIT 1 FOR UPDATE",
                        (old_key,),
                    ).fetchone()
                    new_row = conn.execute(
                        f"SELECT {self._SELECT_COLUMNS} FROM proxy_instances WHERE proxy_id=%s LIMIT 1 FOR UPDATE",
                        (new_key,),
                    ).fetchone()
                    if old_row is None:
                        alias = conn.execute(
                            "SELECT proxy_id FROM proxy_id_aliases WHERE alias_proxy_id=%s LIMIT 1",
                            (old_key,),
                        ).fetchone()
                        tombstone = conn.execute(
                            "SELECT action, target_proxy_id FROM proxy_lifecycle_tombstones WHERE proxy_id=%s LIMIT 1",
                            (old_key,),
                        ).fetchone()
                        tombstone_action = (
                            str(tombstone["action"] or "")
                            if tombstone is not None
                            else ""
                        )
                        tombstone_target = (
                            normalize_proxy_id(tombstone["target_proxy_id"])
                            if tombstone is not None
                            and str(tombstone["target_proxy_id"] or "").strip()
                            else ""
                        )
                        if (
                            new_row is not None
                            and alias is not None
                            and str(alias["proxy_id"] or "") == new_key
                        ) or (
                            new_row is not None
                            and tombstone_action in {"renamed", "renaming"}
                            and tombstone_target == new_key
                        ):
                            leftover_tables = proxy_scoped_tables_with_rows(
                                conn,
                                proxy_id=old_key,
                            )
                            if leftover_tables:
                                msg = (
                                    f"Proxy rename for {old_key!r} is incomplete; "
                                    "leftover scoped rows remain in "
                                    f"{', '.join(leftover_tables[:3])}."
                                )
                                raise ProxyLifecycleIncompleteError(
                                    msg,
                                    ProxyLifecycleRunResult(
                                        action="rename",
                                        proxy_id=old_key,
                                        target_proxy_id=new_key,
                                        complete=False,
                                        discovered_tables=leftover_tables,
                                        truncated_tables=leftover_tables,
                                    ),
                                )
                            conn.execute(
                                "DELETE FROM proxy_id_aliases WHERE alias_proxy_id=%s",
                                (new_key,),
                            )
                            conn.execute(
                                """
                                UPDATE proxy_id_aliases
                                SET proxy_id=%s, updated_ts=%s
                                WHERE proxy_id=%s
                                """,
                                (new_key, int(time.time()), old_key),
                            )
                            conn.execute(
                                """
                                UPDATE proxy_lifecycle_tombstones
                                SET target_proxy_id=%s, detail=%s, updated_ts=%s
                                WHERE action='renamed' AND target_proxy_id=%s
                                """,
                                (
                                    new_key,
                                    f"Proxy renamed to {new_key}.",
                                    int(time.time()),
                                    old_key,
                                ),
                            )
                            conn.execute(
                                """
                                INSERT INTO proxy_id_aliases(alias_proxy_id, proxy_id, created_ts, updated_ts)
                                VALUES(%s,%s,%s,%s)
                                ON DUPLICATE KEY UPDATE proxy_id=VALUES(proxy_id), updated_ts=VALUES(updated_ts)
                                """,
                                (old_key, new_key, now, int(time.time())),
                            )
                            conn.execute(
                                """
                                INSERT INTO proxy_lifecycle_tombstones(proxy_id, action, target_proxy_id, detail, created_ts, updated_ts)
                                VALUES(%s,'renamed',%s,%s,%s,%s)
                                ON DUPLICATE KEY UPDATE action=VALUES(action), target_proxy_id=VALUES(target_proxy_id), detail=VALUES(detail), updated_ts=VALUES(updated_ts)
                                """,
                                (
                                    old_key,
                                    new_key,
                                    f"Proxy renamed to {new_key}.",
                                    now,
                                    int(time.time()),
                                ),
                            )
                            conn.execute(
                                "DELETE FROM proxy_lifecycle_tombstones WHERE proxy_id=%s",
                                (new_key,),
                            )
                            conn.commit()
                            self._clear_lifecycle_write_cache(old_key, new_key)
                            attempt.committed = True
                            return
                        msg = f"Proxy {old_key!r} is not registered."
                        raise ValueError(msg)
                    default_proxy_id = get_default_proxy_id()
                    if default_proxy_id in {old_key, new_key}:
                        msg = f"Default proxy {default_proxy_id!r} cannot be renamed."
                        raise ValueError(msg)
                    lifecycle_state = conn.execute(
                        "SELECT action, target_proxy_id FROM proxy_lifecycle_tombstones WHERE proxy_id=%s LIMIT 1",
                        (old_key,),
                    ).fetchone()
                    if lifecycle_state is not None:
                        action = str(lifecycle_state["action"] or "")
                        raw_target = str(
                            lifecycle_state["target_proxy_id"] or ""
                        ).strip()
                        target_key = (
                            normalize_proxy_id(raw_target) if raw_target else ""
                        )
                        if (
                            action == "renaming"
                            and target_key
                            and target_key != new_key
                        ):
                            msg = (
                                f"Proxy {old_key!r} already has a rename in progress "
                                f"to {target_key!r}; retry with that target to resume."
                            )
                            raise ValueError(msg)
                    self._ensure_not_tombstoned(
                        conn,
                        old_key,
                        allowed_actions={"renaming"},
                    )
                    self._ensure_not_tombstoned(conn, new_key)
                    if new_row is not None:
                        msg = f"Proxy {new_key!r} is already registered."
                        raise ValueError(msg)
                    alias_rows = conn.execute(
                        "SELECT alias_proxy_id, proxy_id FROM proxy_id_aliases WHERE alias_proxy_id IN (%s,%s) FOR UPDATE",
                        (old_key, new_key),
                    ).fetchall()
                    for alias_row in alias_rows:
                        alias_key = str(alias_row["alias_proxy_id"] or "")
                        alias_target = str(alias_row["proxy_id"] or "")
                        if alias_key == old_key and alias_target == new_key:
                            continue
                        msg = (
                            f"Proxy id {alias_key!r} is already registered as an alias; "
                            "choose a different rename target."
                        )
                        raise ValueError(msg)

                    conn.execute(
                        """
                        UPDATE proxy_instances
                        SET status='renaming', detail=%s, updated_ts=%s
                        WHERE proxy_id=%s
                        """,
                        (f"Renaming proxy to {new_key}.", now, old_key),
                    )
                    conn.execute(
                        """
                        INSERT INTO proxy_lifecycle_tombstones(proxy_id, action, target_proxy_id, detail, created_ts, updated_ts)
                        VALUES(%s,'renaming',%s,%s,%s,%s)
                        ON DUPLICATE KEY UPDATE action=VALUES(action), target_proxy_id=VALUES(target_proxy_id), detail=VALUES(detail), updated_ts=VALUES(updated_ts)
                        """,
                        (
                            old_key,
                            new_key,
                            f"Rename in progress to {new_key}.",
                            now,
                            now,
                        ),
                    )
                    self._clear_lifecycle_write_cache(old_key, new_key)

                    lifecycle_result = rename_proxy_scoped_rows(
                        conn,
                        old_proxy_id=old_key,
                        new_proxy_id=new_key,
                        ensure_indexes=False,
                    )
                    if not lifecycle_result.complete:
                        retry_detail = _lifecycle_incomplete_retry_detail(
                            lifecycle_result,
                        )
                        conn.execute(
                            """
                            UPDATE proxy_instances
                            SET status='rename_pending', detail=%s, updated_ts=%s
                            WHERE proxy_id=%s
                            """,
                            (
                                f"Proxy rename {retry_detail}",
                                int(time.time()),
                                old_key,
                            ),
                        )
                        msg = f"Proxy rename for {old_key!r} {retry_detail}"
                        raise ProxyLifecycleIncompleteError(msg, lifecycle_result)

                    conn.execute(
                        """
                        UPDATE proxy_id_aliases
                        SET proxy_id=%s, updated_ts=%s
                        WHERE proxy_id=%s
                        """,
                        (new_key, int(time.time()), old_key),
                    )
                    conn.execute(
                        """
                        UPDATE proxy_lifecycle_tombstones
                        SET target_proxy_id=%s, detail=%s, updated_ts=%s
                        WHERE action='renamed' AND target_proxy_id=%s
                        """,
                        (
                            new_key,
                            f"Proxy renamed to {new_key}.",
                            int(time.time()),
                            old_key,
                        ),
                    )
                    conn.execute(
                        """
                        UPDATE proxy_instances
                        SET proxy_id=%s, display_name=%s, updated_ts=%s, status='unknown', detail=%s
                        WHERE proxy_id=%s
                        """,
                        (
                            new_key,
                            (display_name or old_row["display_name"] or new_key).strip()
                            or new_key,
                            int(time.time()),
                            f"Renamed from {old_key}.",
                            old_key,
                        ),
                    )
                    conn.execute(
                        """
                        INSERT INTO proxy_id_aliases(alias_proxy_id, proxy_id, created_ts, updated_ts)
                        VALUES(%s,%s,%s,%s)
                        ON DUPLICATE KEY UPDATE proxy_id=VALUES(proxy_id), updated_ts=VALUES(updated_ts)
                        """,
                        (old_key, new_key, now, int(time.time())),
                    )
                    conn.execute(
                        """
                        INSERT INTO proxy_lifecycle_tombstones(proxy_id, action, target_proxy_id, detail, created_ts, updated_ts)
                        VALUES(%s,'renamed',%s,%s,%s,%s)
                        ON DUPLICATE KEY UPDATE action=VALUES(action), target_proxy_id=VALUES(target_proxy_id), detail=VALUES(detail), updated_ts=VALUES(updated_ts)
                        """,
                        (
                            old_key,
                            new_key,
                            f"Proxy renamed to {new_key}.",
                            now,
                            int(time.time()),
                        ),
                    )
                    conn.execute(
                        "DELETE FROM proxy_lifecycle_tombstones WHERE proxy_id=%s",
                        (new_key,),
                    )
                    conn.commit()
                    self._clear_lifecycle_write_cache(old_key, new_key)
                    attempt.committed = True

        run_mysql_operation_with_retry(_rename)
        refreshed = self.get_proxy(new_key)
        assert refreshed is not None
        return refreshed

    def remove_proxy(self, proxy_id: object | None) -> ProxyRemovalResult:
        self.init_db()
        proxy_key = normalize_proxy_id(proxy_id)
        table_counts: dict[str, int] = {}
        lifecycle_result: ProxyLifecycleRunResult | None = None

        def _remove() -> None:
            nonlocal lifecycle_result, table_counts
            with (
                _preserve_committed_lifecycle_success() as attempt,
                self._connect() as conn,
            ):
                with mysql_advisory_lock(
                    conn,
                    self._lifecycle_lock_name(proxy_key),
                    mysql_schema_lock_timeout_seconds(),
                ):
                    prepare_proxy_lifecycle(conn, action="remove")
                    conn.commit()

                    rows = conn.execute(
                        "SELECT proxy_id FROM proxy_instances ORDER BY proxy_id FOR UPDATE",
                    ).fetchall()
                    row = next(
                        (
                            candidate
                            for candidate in rows
                            if str(candidate["proxy_id"] or "") == proxy_key
                        ),
                        None,
                    )
                    if row is None:
                        tombstone = conn.execute(
                            "SELECT action FROM proxy_lifecycle_tombstones WHERE proxy_id=%s LIMIT 1",
                            (proxy_key,),
                        ).fetchone()
                        if (
                            tombstone is not None
                            and str(tombstone["action"] or "") == "removed"
                        ):
                            return
                        msg = f"Proxy {proxy_key!r} is not registered."
                        raise ValueError(msg)
                    if proxy_key == get_default_proxy_id():
                        msg = f"Default proxy {proxy_key!r} cannot be removed."
                        raise ValueError(msg)
                    if len(rows) <= 1:
                        msg = "Cannot remove the last registered proxy."
                        raise ValueError(msg)

                    now_ts = int(time.time())
                    conn.execute(
                        """
                        UPDATE proxy_instances
                        SET status='removing', detail=%s, updated_ts=%s
                        WHERE proxy_id=%s
                        """,
                        (
                            "Proxy removal in progress; new writes are rejected.",
                            now_ts,
                            proxy_key,
                        ),
                    )
                    conn.execute(
                        """
                        INSERT INTO proxy_lifecycle_tombstones(proxy_id, action, target_proxy_id, detail, created_ts, updated_ts)
                        VALUES(%s,'removing','',%s,%s,%s)
                        ON DUPLICATE KEY UPDATE action=VALUES(action), detail=VALUES(detail), updated_ts=VALUES(updated_ts)
                        """,
                        (proxy_key, "Proxy removal in progress.", now_ts, now_ts),
                    )
                    self._clear_lifecycle_write_cache(proxy_key)

                    lifecycle_result = remove_proxy_scoped_rows(
                        conn,
                        proxy_id=proxy_key,
                        ensure_indexes=False,
                    )
                    table_counts = dict(lifecycle_result.table_counts)
                    if not lifecycle_result.complete:
                        retry_detail = _lifecycle_incomplete_retry_detail(
                            lifecycle_result,
                        )
                        conn.execute(
                            """
                            UPDATE proxy_instances
                            SET status='remove_pending', detail=%s, updated_ts=%s
                            WHERE proxy_id=%s
                            """,
                            (
                                f"Proxy removal {retry_detail}",
                                int(time.time()),
                                proxy_key,
                            ),
                        )
                        msg = f"Proxy removal for {proxy_key!r} {retry_detail}"
                        raise ProxyLifecycleIncompleteError(msg, lifecycle_result)

                    result = conn.execute(
                        "DELETE FROM proxy_id_aliases WHERE proxy_id=%s",
                        (proxy_key,),
                    )
                    deleted_alias_targets = max(
                        0, int(getattr(result, "rowcount", 0) or 0)
                    )
                    if deleted_alias_targets:
                        table_counts["proxy_id_aliases"] = (
                            table_counts.get("proxy_id_aliases", 0)
                            + deleted_alias_targets
                        )

                    result = conn.execute(
                        "DELETE FROM proxy_id_aliases WHERE alias_proxy_id=%s",
                        (proxy_key,),
                    )
                    deleted_aliases = max(0, int(getattr(result, "rowcount", 0) or 0))
                    if deleted_aliases:
                        table_counts["proxy_id_aliases.alias_proxy_id"] = (
                            table_counts.get("proxy_id_aliases.alias_proxy_id", 0)
                            + deleted_aliases
                        )

                    result = conn.execute(
                        "DELETE FROM proxy_instances WHERE proxy_id=%s",
                        (proxy_key,),
                    )
                    deleted_instance = max(
                        0,
                        int(getattr(result, "rowcount", 0) or 0),
                    )
                    if deleted_instance:
                        table_counts["proxy_instances"] = deleted_instance
                    conn.execute(
                        """
                        UPDATE proxy_lifecycle_tombstones
                        SET action='removed', detail=%s, updated_ts=%s
                        WHERE proxy_id=%s
                        """,
                        (
                            "Proxy removed; scoped rows deleted.",
                            int(time.time()),
                            proxy_key,
                        ),
                    )
                    conn.commit()
                    self._clear_lifecycle_write_cache(proxy_key)
                    attempt.committed = True

        run_mysql_operation_with_retry(_remove)
        result_complete = (
            True if lifecycle_result is None else lifecycle_result.complete
        )
        truncated_tables = (
            () if lifecycle_result is None else lifecycle_result.truncated_tables
        )
        discovered_tables = (
            () if lifecycle_result is None else lifecycle_result.discovered_tables
        )
        iterations = 0 if lifecycle_result is None else lifecycle_result.iterations
        return ProxyRemovalResult(
            proxy_id=proxy_key,
            deleted_rows=sum(table_counts.values()),
            table_counts=dict(sorted(table_counts.items())),
            complete=result_complete,
            iterations=iterations,
            truncated_tables=truncated_tables,
            discovered_tables=discovered_tables,
        )

    def find_reconcile_candidate(
        self,
        proxy_id: object | None,
        *,
        management_url: str = "",
        public_host: str = "",
    ) -> ProxyInstance | None:
        self.init_db()
        proxy_key = normalize_proxy_id(proxy_id)
        checks: list[str] = ["proxy_id <> %s"]
        params: list[object] = [proxy_key]
        match_clauses: list[str] = []
        management_url = normalize_management_url(management_url)
        if management_url:
            match_clauses.append("management_url = %s")
            params.append(management_url)
        public_host = _normalize_public_host(public_host, allow_single_label=True)
        if public_host:
            match_clauses.append("public_host = %s")
            params.append(public_host)
        if not match_clauses:
            return None
        checks.append("(" + " OR ".join(match_clauses) + ")")
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT {self._SELECT_COLUMNS}
                FROM proxy_instances
                WHERE {" AND ".join(checks)}
                ORDER BY last_heartbeat DESC, updated_ts DESC
                LIMIT 2
                """,
                tuple(params),
            ).fetchall()
        if len(rows) != 1:
            return None
        return self._row_to_instance(rows[0])

    def resolve_proxy_id(self, preferred: object | None = None) -> str:
        if preferred:
            proxy_key = normalize_proxy_id(preferred)
            existing = self.get_proxy(proxy_key)
            if existing is not None:
                return existing.proxy_id
            self.init_db()
            with self._connect() as conn:
                tombstone = conn.execute(
                    "SELECT action, target_proxy_id FROM proxy_lifecycle_tombstones WHERE proxy_id=%s LIMIT 1",
                    (proxy_key,),
                ).fetchone()
                if tombstone is not None:
                    action = str(tombstone["action"] or "")
                    target_key = normalize_proxy_id(tombstone["target_proxy_id"])
                    if action == "renamed" and target_key:
                        target = self.get_proxy(target_key)
                        if target is not None:
                            return target.proxy_id
                    if action in {"renaming", "removing", "removed"}:
                        msg = f"Proxy {proxy_key!r} is in lifecycle state {action!r}."
                        raise ValueError(msg)
                alias = conn.execute(
                    "SELECT proxy_id FROM proxy_id_aliases WHERE alias_proxy_id=%s LIMIT 1",
                    (proxy_key,),
                ).fetchone()
            if alias is not None:
                target = self.get_proxy(alias["proxy_id"])
                if target is not None:
                    return target.proxy_id
        proxies = self.list_proxies()
        if proxies:
            return proxies[0].proxy_id
        return self.ensure_default_proxy().proxy_id

    def heartbeat(
        self,
        proxy_id: object | None,
        *,
        status: str = "healthy",
        hostname: str | None = None,
        management_url: str | None = None,
        public_host: str | None = None,
        public_pac_scheme: str | None = None,
        public_pac_port: int | None = None,
        public_pac_path: str | None = None,
        public_http_proxy_port: int | None = None,
        current_config_sha: str | None = None,
        detail: str | None = None,
    ) -> ProxyInstance:
        instance = self.ensure_proxy(
            proxy_id,
            display_name=None,
            hostname=hostname,
            management_url=management_url,
            public_host=public_host,
            public_pac_scheme=public_pac_scheme,
            public_pac_port=public_pac_port,
            public_pac_path=public_pac_path,
            public_http_proxy_port=public_http_proxy_port,
            status=status,
            detail=detail,
        )
        now = int(time.time())
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE proxy_instances
                SET status=%s, hostname=%s, management_url=%s,
                    public_host=%s, public_pac_scheme=%s, public_pac_port=%s,
                    public_pac_path=%s, public_http_proxy_port=%s, last_heartbeat=%s,
                    current_config_sha=%s, detail=%s, updated_ts=%s
                WHERE proxy_id=%s
                """,
                (
                    (status or instance.status).strip() or "unknown",
                    (hostname or instance.hostname).strip(),
                    normalize_management_url(
                        management_url or instance.management_url,
                    ),
                    _normalize_public_host(
                        public_host
                        if public_host is not None
                        else instance.public_host,
                        allow_single_label=True,
                    ),
                    _normalize_public_scheme(
                        public_pac_scheme
                        if public_pac_scheme is not None
                        else instance.public_pac_scheme,
                    ),
                    _coerce_port(
                        public_pac_port
                        if public_pac_port is not None
                        else instance.public_pac_port,
                        80,
                    ),
                    normalize_public_pac_path(
                        public_pac_path
                        if public_pac_path is not None
                        else instance.public_pac_path,
                    ),
                    _coerce_port(
                        public_http_proxy_port
                        if public_http_proxy_port is not None
                        else instance.public_http_proxy_port,
                        3128,
                    ),
                    now,
                    (current_config_sha or instance.current_config_sha).strip(),
                    (detail if detail is not None else instance.detail).strip(),
                    now,
                    instance.proxy_id,
                ),
            )
        refreshed = self.get_proxy(instance.proxy_id)
        assert refreshed is not None
        return refreshed

    def mark_apply_result(
        self,
        proxy_id: object | None,
        *,
        ok: bool,
        detail: str = "",
        current_config_sha: str = "",
    ) -> ProxyInstance:
        instance = self.ensure_proxy(proxy_id)
        now = int(time.time())
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE proxy_instances
                SET last_apply_ts=%s, last_apply_ok=%s, current_config_sha=%s, detail=%s, updated_ts=%s
                WHERE proxy_id=%s
                """,
                (
                    now,
                    1 if ok else 0,
                    current_config_sha.strip(),
                    detail[:4000],
                    now,
                    instance.proxy_id,
                ),
            )
        refreshed = self.get_proxy(instance.proxy_id)
        assert refreshed is not None
        return refreshed

    def register_local_proxy(self) -> ProxyInstance:
        proxy_id = normalize_proxy_id(
            os.environ.get("PROXY_INSTANCE_ID")
            or os.environ.get("PROXY_ID")
            or get_default_proxy_id(),
        )
        display_name = (
            os.environ.get("PROXY_DISPLAY_NAME") or proxy_id
        ).strip() or proxy_id
        hostname = (os.environ.get("PROXY_HOSTNAME") or socket.gethostname()).strip()
        public_fields = resolve_local_proxy_public_fields()
        management_url = resolve_local_proxy_management_url(
            proxy_id,
            public_fields.get("public_host"),
        )
        existing = self.get_proxy(proxy_id)
        if existing is None:
            candidate = self.find_reconcile_candidate(
                proxy_id,
                management_url=management_url,
                public_host=str(public_fields["public_host"] or ""),
            )
            if candidate is not None:
                existing = self.rename_proxy(
                    candidate.proxy_id,
                    proxy_id,
                    display_name=display_name,
                )
        return self.ensure_proxy(
            proxy_id,
            display_name=display_name,
            hostname=hostname,
            management_url=management_url,
            public_host=str(public_fields["public_host"] or ""),
            public_pac_scheme=str(public_fields["public_pac_scheme"] or "http"),
            public_pac_port=int(public_fields["public_pac_port"] or 80),
            public_pac_path=str(public_fields.get("public_pac_path") or "/proxy.pac"),
            public_http_proxy_port=int(public_fields["public_http_proxy_port"] or 3128),
            status="starting" if existing is None else None,
        )


_store: ProxyRegistry | None = None
_store_lock = threading.Lock()


def get_proxy_registry() -> ProxyRegistry:
    global _store
    if _store is not None:
        return _store
    with _store_lock:
        if _store is None:
            _store = ProxyRegistry()
        return _store
