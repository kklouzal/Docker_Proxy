from __future__ import annotations

import os
import socket
import threading
import time
from dataclasses import dataclass
from typing import Optional

from services.db import connect, create_index_if_not_exists
from services.proxy_context import get_default_proxy_id, normalize_proxy_id


@dataclass(frozen=True)
class ProxyInstance:
    proxy_id: str
    display_name: str
    hostname: str
    management_url: str
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

    def init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS proxy_instances (
                    proxy_id VARCHAR(64) PRIMARY KEY,
                    display_name VARCHAR(255) NOT NULL,
                    hostname VARCHAR(255) NOT NULL DEFAULT '',
                    management_url VARCHAR(512) NOT NULL DEFAULT '',
                    status VARCHAR(32) NOT NULL DEFAULT 'unknown',
                    last_heartbeat BIGINT NOT NULL DEFAULT 0,
                    last_apply_ts BIGINT NOT NULL DEFAULT 0,
                    last_apply_ok TINYINT(1) NOT NULL DEFAULT 0,
                    current_config_sha CHAR(64) NOT NULL DEFAULT '',
                    detail TEXT,
                    created_ts BIGINT NOT NULL,
                    updated_ts BIGINT NOT NULL
                )
                """
            )
            create_index_if_not_exists(
                conn,
                table_name="proxy_instances",
                index_name="idx_proxy_instances_status",
                columns_sql="status, last_heartbeat",
            )
            create_index_if_not_exists(
                conn,
                table_name="proxy_instances",
                index_name="idx_proxy_instances_updated",
                columns_sql="updated_ts",
            )

    def _row_to_instance(self, row: object | None) -> Optional[ProxyInstance]:
        if not row:
            return None
        return ProxyInstance(
            proxy_id=str(row["proxy_id"]),
            display_name=str(row["display_name"] or row["proxy_id"]),
            hostname=str(row["hostname"] or ""),
            management_url=str(row["management_url"] or ""),
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
        status: str | None = None,
        detail: str | None = None,
    ) -> ProxyInstance:
        self.init_db()
        proxy_key = normalize_proxy_id(proxy_id)
        now = int(time.time())
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM proxy_instances WHERE proxy_id=? LIMIT 1",
                (proxy_key,),
            ).fetchone()
            if row is None:
                conn.execute(
                    """
                    INSERT INTO proxy_instances(
                        proxy_id, display_name, hostname, management_url, status,
                        last_heartbeat, last_apply_ts, last_apply_ok, current_config_sha,
                        detail, created_ts, updated_ts
                    )
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        proxy_key,
                        (display_name or proxy_key).strip() or proxy_key,
                        (hostname or "").strip(),
                        (management_url or "").strip(),
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
                    "SELECT * FROM proxy_instances WHERE proxy_id=? LIMIT 1",
                    (proxy_key,),
                ).fetchone()
            else:
                next_display = (display_name or row["display_name"] or proxy_key).strip() or proxy_key
                next_hostname = (hostname or row["hostname"] or "").strip()
                next_url = (management_url or row["management_url"] or "").strip()
                next_status = (row["status"] if status is None else status)
                next_status = (next_status or "unknown").strip() or "unknown"
                next_detail = (detail if detail is not None else row["detail"] or "").strip()
                conn.execute(
                    """
                    UPDATE proxy_instances
                    SET display_name=?, hostname=?, management_url=?, status=?, detail=?, updated_ts=?
                    WHERE proxy_id=?
                    """,
                    (next_display, next_hostname, next_url, next_status, next_detail, now, proxy_key),
                )
                row = conn.execute(
                    "SELECT * FROM proxy_instances WHERE proxy_id=? LIMIT 1",
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
                "SELECT * FROM proxy_instances WHERE proxy_id=? LIMIT 1",
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
        current_config_sha: str | None = None,
        detail: str | None = None,
    ) -> ProxyInstance:
        instance = self.ensure_proxy(
            proxy_id,
            display_name=None,
            hostname=hostname,
            management_url=management_url,
            status=status,
            detail=detail,
        )
        now = int(time.time())
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE proxy_instances
                SET status=?, hostname=?, management_url=?, last_heartbeat=?,
                    current_config_sha=?, detail=?, updated_ts=?
                WHERE proxy_id=?
                """,
                (
                    (status or instance.status).strip() or "unknown",
                    (hostname or instance.hostname).strip(),
                    (management_url or instance.management_url).strip(),
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
                SET last_apply_ts=?, last_apply_ok=?, current_config_sha=?, detail=?, updated_ts=?
                WHERE proxy_id=?
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
        existing = self.get_proxy(proxy_id)
        return self.ensure_proxy(
            proxy_id,
            display_name=display_name,
            hostname=hostname,
            management_url=management_url,
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
