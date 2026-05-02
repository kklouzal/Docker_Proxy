from __future__ import annotations

import os
import socket
import threading
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlsplit

from services.db import connect
from services.proxy_context import get_default_proxy_id, normalize_proxy_id


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
    return host, scheme, int(parsed.port or default_port)


def resolve_local_proxy_public_fields() -> dict[str, object]:
    url_host, url_scheme, url_port = _parse_public_pac_url(os.environ.get("PROXY_PUBLIC_PAC_URL"))
    public_host = (os.environ.get("PROXY_PUBLIC_HOST") or "").strip() or url_host
    public_pac_scheme = _normalize_public_scheme(os.environ.get("PROXY_PUBLIC_PAC_SCHEME") or url_scheme or "http")
    default_pac_port = 443 if public_pac_scheme == "https" else 80
    public_pac_port = _coerce_port(os.environ.get("PROXY_PUBLIC_PAC_PORT"), url_port or default_pac_port)
    public_http_proxy_port = _coerce_port(os.environ.get("PROXY_PUBLIC_HTTP_PROXY_PORT"), 3128)
    public_socks_proxy_port = _coerce_port(
        os.environ.get("PROXY_PUBLIC_SOCKS_PROXY_PORT") or os.environ.get("DANTE_PORT"),
        1080,
    )
    public_socks_enabled = _coerce_bool(
        os.environ.get("PROXY_PUBLIC_SOCKS_ENABLED"),
        _coerce_bool(os.environ.get("ENABLE_DANTE"), True),
    )
    return {
        "public_host": public_host,
        "public_pac_scheme": public_pac_scheme,
        "public_pac_port": public_pac_port,
        "public_http_proxy_port": public_http_proxy_port,
        "public_socks_proxy_port": public_socks_proxy_port,
        "public_socks_enabled": public_socks_enabled,
    }


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
    public_socks_proxy_port: int
    public_socks_enabled: bool
    status: str
    last_heartbeat: int
    last_apply_ts: int
    last_apply_ok: bool
    current_config_sha: str
    detail: str
    created_ts: int
    updated_ts: int


class ProxyRegistry:
    def _connect(self):
        return connect()

    def _existing_columns(self, conn, table_name: str) -> set[str]:
        rows = conn.execute(
            """
            SELECT column_name AS column_name
            FROM information_schema.columns
            WHERE table_schema = DATABASE() AND table_name = %s
            """,
            (table_name,),
        ).fetchall()
        return {str(row["column_name"] or "") for row in rows}

    def init_db(self) -> None:
        with self._connect() as conn:
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
                    public_socks_proxy_port INT NOT NULL DEFAULT 1080,
                    public_socks_enabled TINYINT(1) NOT NULL DEFAULT 1,
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
                """
            )
            columns = self._existing_columns(conn, "proxy_instances")
            required_columns = {
                "public_host": "ALTER TABLE proxy_instances ADD COLUMN public_host VARCHAR(255) NOT NULL DEFAULT '' AFTER management_url",
                "public_pac_scheme": "ALTER TABLE proxy_instances ADD COLUMN public_pac_scheme VARCHAR(16) NOT NULL DEFAULT 'http' AFTER public_host",
                "public_pac_port": "ALTER TABLE proxy_instances ADD COLUMN public_pac_port INT NOT NULL DEFAULT 80 AFTER public_pac_scheme",
                "public_http_proxy_port": "ALTER TABLE proxy_instances ADD COLUMN public_http_proxy_port INT NOT NULL DEFAULT 3128 AFTER public_pac_port",
                "public_socks_proxy_port": "ALTER TABLE proxy_instances ADD COLUMN public_socks_proxy_port INT NOT NULL DEFAULT 1080 AFTER public_http_proxy_port",
                "public_socks_enabled": "ALTER TABLE proxy_instances ADD COLUMN public_socks_enabled TINYINT(1) NOT NULL DEFAULT 1 AFTER public_socks_proxy_port",
            }
            for column_name, ddl in required_columns.items():
                if column_name not in columns:
                    conn.execute(ddl)

    def _row_to_instance(self, row: object | None) -> Optional[ProxyInstance]:
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
            public_socks_proxy_port=_coerce_port(row["public_socks_proxy_port"], 1080),
            public_socks_enabled=_coerce_bool(row["public_socks_enabled"], True),
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
        public_socks_proxy_port: int | None = None,
        public_socks_enabled: bool | None = None,
        status: str | None = None,
        detail: str | None = None,
    ) -> ProxyInstance:
        self.init_db()
        proxy_key = normalize_proxy_id(proxy_id)
        now = int(time.time())
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM proxy_instances WHERE proxy_id=%s LIMIT 1",
                (proxy_key,),
            ).fetchone()
            if row is None:
                conn.execute(
                    """
                    INSERT INTO proxy_instances(
                        proxy_id, display_name, hostname, management_url,
                        public_host, public_pac_scheme, public_pac_port,
                        public_http_proxy_port, public_socks_proxy_port, public_socks_enabled,
                        status,
                        last_heartbeat, last_apply_ts, last_apply_ok, current_config_sha,
                        detail, created_ts, updated_ts
                    )
                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
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
                        _coerce_port(public_socks_proxy_port, 1080),
                        1 if _coerce_bool(public_socks_enabled, True) else 0,
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
                row = conn.execute(
                    "SELECT * FROM proxy_instances WHERE proxy_id=%s LIMIT 1",
                    (proxy_key,),
                ).fetchone()
            else:
                next_display = (display_name or row["display_name"] or proxy_key).strip() or proxy_key
                next_hostname = (hostname or row["hostname"] or "").strip()
                next_url = (management_url or row["management_url"] or "").strip()
                next_public_host = (public_host if public_host is not None else row["public_host"] or "").strip()
                next_public_pac_scheme = _normalize_public_scheme(
                    public_pac_scheme if public_pac_scheme is not None else row["public_pac_scheme"]
                )
                next_public_pac_port = _coerce_port(
                    public_pac_port if public_pac_port is not None else row["public_pac_port"],
                    80,
                )
                next_public_http_proxy_port = _coerce_port(
                    public_http_proxy_port if public_http_proxy_port is not None else row["public_http_proxy_port"],
                    3128,
                )
                next_public_socks_proxy_port = _coerce_port(
                    public_socks_proxy_port if public_socks_proxy_port is not None else row["public_socks_proxy_port"],
                    1080,
                )
                next_public_socks_enabled = _coerce_bool(
                    public_socks_enabled if public_socks_enabled is not None else row["public_socks_enabled"],
                    True,
                )
                next_status = (row["status"] if status is None else status)
                next_status = (next_status or "unknown").strip() or "unknown"
                next_detail = (detail if detail is not None else row["detail"] or "").strip()
                conn.execute(
                    """
                    UPDATE proxy_instances
                    SET display_name=%s, hostname=%s, management_url=%s,
                        public_host=%s, public_pac_scheme=%s, public_pac_port=%s,
                        public_http_proxy_port=%s, public_socks_proxy_port=%s, public_socks_enabled=%s,
                        status=%s, detail=%s, updated_ts=%s
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
                        next_public_socks_proxy_port,
                        1 if next_public_socks_enabled else 0,
                        next_status,
                        next_detail,
                        now,
                        proxy_key,
                    ),
                )
                row = conn.execute(
                    "SELECT * FROM proxy_instances WHERE proxy_id=%s LIMIT 1",
                    (proxy_key,),
                ).fetchone()
        instance = self._row_to_instance(row)
        assert instance is not None
        return instance

    def ensure_default_proxy(self) -> ProxyInstance:
        default_id = get_default_proxy_id()
        return self.ensure_proxy(default_id, display_name=os.environ.get("DEFAULT_PROXY_NAME") or default_id)

    def get_proxy(self, proxy_id: object | None) -> Optional[ProxyInstance]:
        self.init_db()
        proxy_key = normalize_proxy_id(proxy_id)
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM proxy_instances WHERE proxy_id=%s LIMIT 1",
                (proxy_key,),
            ).fetchone()
        return self._row_to_instance(row)

    def list_proxies(self) -> list[ProxyInstance]:
        self.init_db()
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM proxy_instances ORDER BY display_name ASC, proxy_id ASC"
            ).fetchall()
        instances = [self._row_to_instance(row) for row in rows]
        return [instance for instance in instances if instance is not None]

    def resolve_proxy_id(self, preferred: object | None = None) -> str:
        if preferred:
            proxy_key = normalize_proxy_id(preferred)
            existing = self.get_proxy(proxy_key)
            if existing is not None:
                return existing.proxy_id
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
        public_socks_proxy_port: int | None = None,
        public_socks_enabled: bool | None = None,
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
            public_socks_proxy_port=public_socks_proxy_port,
            public_socks_enabled=public_socks_enabled,
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
                    public_http_proxy_port=%s, public_socks_proxy_port=%s, public_socks_enabled=%s,
                    last_heartbeat=%s,
                    current_config_sha=%s, detail=%s, updated_ts=%s
                WHERE proxy_id=%s
                """,
                (
                    (status or instance.status).strip() or "unknown",
                    (hostname or instance.hostname).strip(),
                    (management_url or instance.management_url).strip(),
                    (public_host if public_host is not None else instance.public_host).strip(),
                    _normalize_public_scheme(public_pac_scheme if public_pac_scheme is not None else instance.public_pac_scheme),
                    _coerce_port(public_pac_port if public_pac_port is not None else instance.public_pac_port, 80),
                    _coerce_port(
                        public_http_proxy_port if public_http_proxy_port is not None else instance.public_http_proxy_port,
                        3128,
                    ),
                    _coerce_port(
                        public_socks_proxy_port if public_socks_proxy_port is not None else instance.public_socks_proxy_port,
                        1080,
                    ),
                    1
                    if _coerce_bool(
                        public_socks_enabled if public_socks_enabled is not None else instance.public_socks_enabled,
                        True,
                    )
                    else 0,
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
                (now, 1 if ok else 0, current_config_sha.strip(), detail[:4000], now, instance.proxy_id),
            )
        refreshed = self.get_proxy(instance.proxy_id)
        assert refreshed is not None
        return refreshed

    def register_local_proxy(self) -> ProxyInstance:
        proxy_id = normalize_proxy_id(
            os.environ.get("PROXY_INSTANCE_ID")
            or os.environ.get("PROXY_ID")
            or get_default_proxy_id()
        )
        display_name = (os.environ.get("PROXY_DISPLAY_NAME") or proxy_id).strip() or proxy_id
        hostname = (os.environ.get("PROXY_HOSTNAME") or socket.gethostname()).strip()
        management_url = (os.environ.get("PROXY_MANAGEMENT_URL") or "").strip()
        public_fields = resolve_local_proxy_public_fields()
        existing = self.get_proxy(proxy_id)
        return self.ensure_proxy(
            proxy_id,
            display_name=display_name,
            hostname=hostname,
            management_url=management_url,
            public_host=str(public_fields["public_host"] or ""),
            public_pac_scheme=str(public_fields["public_pac_scheme"] or "http"),
            public_pac_port=int(public_fields["public_pac_port"] or 80),
            public_http_proxy_port=int(public_fields["public_http_proxy_port"] or 3128),
            public_socks_proxy_port=int(public_fields["public_socks_proxy_port"] or 1080),
            public_socks_enabled=bool(public_fields["public_socks_enabled"]),
            status="starting" if existing is None else None,
        )


_store: Optional[ProxyRegistry] = None
_store_lock = threading.Lock()


def get_proxy_registry() -> ProxyRegistry:
    global _store
    if _store is not None:
        return _store
    with _store_lock:
        if _store is None:
            _store = ProxyRegistry()
            _store.init_db()
        return _store
