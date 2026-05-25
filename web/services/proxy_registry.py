from __future__ import annotations

import os
import re
import socket
import threading
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

from services.db import (
    DATABASE_ERRORS,
    connect,
    mysql_advisory_lock,
    mysql_schema_lock_timeout_seconds,
    run_mysql_operation_with_retry,
)
from services.proxy_context import get_default_proxy_id, normalize_proxy_id


def _quote_mysql_identifier(value: str) -> str:
    return "`" + str(value).replace("`", "``") + "`"


def _mysql_error_code(exc: BaseException) -> int | None:
    try:
        if getattr(exc, "args", None):
            return int(exc.args[0])
    except Exception:
        return None
    return None


def _is_mysql_error_code(exc: BaseException, codes: set[int]) -> bool:
    return _mysql_error_code(exc) in codes


def _normalize_public_scheme(value: object | None) -> str:
    candidate = str(value or "").strip().lower()
    if candidate in {"http", "https"}:
        return candidate
    return "http"


def _coerce_port(value: object | None, default: int) -> int:
    try:
        parsed = int(str(value or "").strip() or str(default))
    except Exception:
        parsed = int(default)
    if parsed < 1 or parsed > 65535:
        return int(default)
    return parsed


def _coerce_bool(value: object | None, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return bool(default)
    candidate = str(value).strip().lower()
    if not candidate:
        return bool(default)
    if candidate in {"1", "true", "yes", "on"}:
        return True
    if candidate in {"0", "false", "no", "off"}:
        return False
    return bool(default)


def _dns_safe_proxy_host(value: object | None) -> str:
    raw = str(value or "").strip().lower()
    if not raw or raw == "default":
        return "proxy"
    candidate = re.sub(r"[^a-z0-9-]+", "-", raw).strip("-")
    return candidate or "proxy"


def _parse_public_pac_url(raw_url: object | None) -> tuple[str, str, int]:
    candidate = str(raw_url or "").strip()
    if not candidate:
        return "", "http", 80
    if "://" not in candidate:
        candidate = f"http://{candidate}"
    try:
        parsed = urlsplit(candidate)
    except Exception:
        return "", "http", 80
    scheme = _normalize_public_scheme(parsed.scheme)
    host = str(parsed.hostname or "").strip()
    default_port = 443 if scheme == "https" else 80
    try:
        parsed_port = parsed.port
    except ValueError:
        parsed_port = None
    return host, scheme, int(parsed_port or default_port)


def resolve_local_proxy_public_fields() -> dict[str, object]:
    url_host, url_scheme, url_port = _parse_public_pac_url(
        os.environ.get("PROXY_PUBLIC_PAC_URL"),
    )
    public_host = (os.environ.get("PROXY_PUBLIC_HOST") or "").strip() or url_host
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
        "public_http_proxy_port": public_http_proxy_port,
    }


def resolve_local_proxy_management_url(
    proxy_id: object | None,
    public_host: object | None = None,
) -> str:
    explicit_url = (os.environ.get("PROXY_MANAGEMENT_URL") or "").strip()
    if explicit_url:
        return explicit_url.rstrip("/")

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
    return f"{scheme}://{host}:{port}"


@dataclass(frozen=True)
class ProxyInstance:
    proxy_id: str
    display_name: str
    hostname: str
    management_url: str
    public_host: str
    public_pac_scheme: str
    public_pac_port: int
    public_http_proxy_port: int
    status: str
    last_heartbeat: int
    last_apply_ts: int
    last_apply_ok: bool
    current_config_sha: str
    detail: str
    created_ts: int
    updated_ts: int


class ProxyRegistry:
    _SELECT_COLUMNS = "proxy_id, display_name, hostname, management_url, public_host, public_pac_scheme, public_pac_port, public_http_proxy_port, status, last_heartbeat, last_apply_ts, last_apply_ok, current_config_sha, detail, created_ts, updated_ts"

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
                            "public_http_proxy_port": "ALTER TABLE proxy_instances ADD COLUMN public_http_proxy_port INT NOT NULL DEFAULT 3128 AFTER public_pac_port",
                        }
                        for column_name, ddl in required_columns.items():
                            if column_name not in columns:
                                try:
                                    conn.execute(ddl)
                                except DATABASE_ERRORS as exc:
                                    if not _is_mysql_error_code(exc, {1060}):
                                        raise
                        for column_name in ("public_socks_enabled", "public_socks_proxy_port"):
                            if column_name in columns:
                                try:
                                    conn.execute(
                                        f"ALTER TABLE proxy_instances DROP COLUMN {column_name}",
                                    )
                                except DATABASE_ERRORS as exc:
                                    if not _is_mysql_error_code(exc, {1091}):
                                        raise
                        conn.execute("DROP TABLE IF EXISTS socks_events")
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
            management_url=str(row["management_url"] or ""),
            public_host=str(row["public_host"] or ""),
            public_pac_scheme=_normalize_public_scheme(row["public_pac_scheme"]),
            public_pac_port=_coerce_port(row["public_pac_port"], 80),
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
        public_http_proxy_port: int | None = None,
        status: str | None = None,
        detail: str | None = None,
    ) -> ProxyInstance:
        self.init_db()
        proxy_key = normalize_proxy_id(proxy_id)
        now = int(time.time())
        with self._connect() as conn:
            row = conn.execute(
                f"SELECT {self._SELECT_COLUMNS} FROM proxy_instances WHERE proxy_id=%s LIMIT 1",
                (proxy_key,),
            ).fetchone()
            if row is None:
                conn.execute(
                    """
                    INSERT INTO proxy_instances(
                        proxy_id, display_name, hostname, management_url,
                        public_host, public_pac_scheme, public_pac_port,
                        public_http_proxy_port, status,
                        last_heartbeat, last_apply_ts, last_apply_ok, current_config_sha,
                        detail, created_ts, updated_ts
                    )
                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """,
                    (
                        proxy_key,
                        (display_name or proxy_key).strip() or proxy_key,
                        (hostname or "").strip(),
                        (management_url or "").strip(),
                        (public_host or "").strip(),
                        _normalize_public_scheme(public_pac_scheme),
                        _coerce_port(public_pac_port, 80),
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
                row = {
                    "proxy_id": proxy_key,
                    "display_name": (display_name or proxy_key).strip() or proxy_key,
                    "hostname": (hostname or "").strip(),
                    "management_url": (management_url or "").strip(),
                    "public_host": (public_host or "").strip(),
                    "public_pac_scheme": _normalize_public_scheme(public_pac_scheme),
                    "public_pac_port": _coerce_port(public_pac_port, 80),
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
                next_url = (management_url or row["management_url"] or "").strip()
                next_public_host = (
                    public_host if public_host is not None else row["public_host"] or ""
                ).strip()
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
                        public_http_proxy_port=%s, status=%s, detail=%s, updated_ts=%s
                    WHERE proxy_id=%s
                    """,
                    (
                        next_display,
                        next_hostname,
                        next_url,
                        next_public_host,
                        next_public_pac_scheme,
                        next_public_pac_port,
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

    def _proxy_id_tables(self, conn) -> list[str]:
        rows = conn.execute(
            """
            SELECT c.table_name AS table_name
            FROM information_schema.columns c
            JOIN information_schema.tables t
              ON t.table_schema = c.table_schema AND t.table_name = c.table_name
            WHERE c.table_schema = DATABASE()
              AND c.column_name = 'proxy_id'
              AND t.table_type = 'BASE TABLE'
            ORDER BY c.table_name ASC
            """,
        ).fetchall()
        return [str(row["table_name"] or "") for row in rows if row["table_name"]]

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

        def _rename() -> None:
            with self._connect() as conn:
                with mysql_advisory_lock(
                    conn,
                    "docker_proxy:proxy_registry:rename",
                    mysql_schema_lock_timeout_seconds(),
                ):
                    old_row = conn.execute(
                        f"SELECT {self._SELECT_COLUMNS} FROM proxy_instances WHERE proxy_id=%s LIMIT 1",
                        (old_key,),
                    ).fetchone()
                    if old_row is None:
                        msg = f"Proxy {old_key!r} is not registered."
                        raise ValueError(msg)
                    new_row = conn.execute(
                        "SELECT proxy_id FROM proxy_instances WHERE proxy_id=%s LIMIT 1",
                        (new_key,),
                    ).fetchone()
                    if new_row is not None:
                        msg = f"Proxy {new_key!r} is already registered."
                        raise ValueError(msg)

                    tables = self._proxy_id_tables(conn)
                    for table_name in tables:
                        if table_name == "proxy_instances":
                            continue
                        conn.execute(
                            f"UPDATE {_quote_mysql_identifier(table_name)} SET proxy_id=%s WHERE proxy_id=%s",
                            (new_key, old_key),
                        )
                    conn.execute(
                        """
                        UPDATE proxy_instances
                        SET proxy_id=%s, display_name=%s, updated_ts=%s
                        WHERE proxy_id=%s
                        """,
                        (
                            new_key,
                            (display_name or old_row["display_name"] or new_key).strip()
                            or new_key,
                            now,
                            old_key,
                        ),
                    )
                    conn.execute(
                        """
                        INSERT INTO proxy_id_aliases(alias_proxy_id, proxy_id, created_ts, updated_ts)
                        VALUES(%s,%s,%s,%s)
                        ON DUPLICATE KEY UPDATE proxy_id=VALUES(proxy_id), updated_ts=VALUES(updated_ts)
                        """,
                        (old_key, new_key, now, now),
                    )

        run_mysql_operation_with_retry(_rename)
        refreshed = self.get_proxy(new_key)
        assert refreshed is not None
        return refreshed

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
        if management_url.strip():
            match_clauses.append("management_url = %s")
            params.append(management_url.strip())
        if public_host.strip():
            match_clauses.append("public_host = %s")
            params.append(public_host.strip())
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
                    public_http_proxy_port=%s, last_heartbeat=%s,
                    current_config_sha=%s, detail=%s, updated_ts=%s
                WHERE proxy_id=%s
                """,
                (
                    (status or instance.status).strip() or "unknown",
                    (hostname or instance.hostname).strip(),
                    (management_url or instance.management_url).strip(),
                    (
                        public_host if public_host is not None else instance.public_host
                    ).strip(),
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
