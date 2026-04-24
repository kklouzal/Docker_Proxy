from __future__ import annotations

import hashlib
import threading
import time
from dataclasses import dataclass
from typing import Optional

from services.db import connect
from services.proxy_context import normalize_proxy_id


@dataclass(frozen=True)
class ConfigRevision:
    revision_id: int
    proxy_id: str
    config_sha256: str
    config_text: str
    source_kind: str
    created_by: str
    created_ts: int
    is_active: bool


@dataclass(frozen=True)
class ConfigApplication:
    application_id: int
    proxy_id: str
    revision_id: int
    ok: bool
    detail: str
    applied_by: str
    applied_ts: int


@dataclass(frozen=True)
class ConfigRevisionMetadata:
    revision_id: int
    proxy_id: str
    config_sha256: str
    source_kind: str
    created_by: str
    created_ts: int
    is_active: bool


class ConfigRevisionStore:
    def _connect(self):
        return connect()

    def init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS proxy_config_revisions (
                    id BIGINT PRIMARY KEY AUTO_INCREMENT,
                    proxy_id VARCHAR(64) NOT NULL,
                    config_sha256 CHAR(64) NOT NULL,
                    config_text LONGTEXT NOT NULL,
                    source_kind VARCHAR(64) NOT NULL DEFAULT 'manual',
                    created_by VARCHAR(255) NOT NULL DEFAULT '',
                    created_ts BIGINT NOT NULL,
                    is_active TINYINT(1) NOT NULL DEFAULT 1,
                    KEY idx_proxy_config_revisions_proxy_active (proxy_id, is_active, created_ts),
                    KEY idx_proxy_config_revisions_proxy_sha (proxy_id, config_sha256)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS proxy_config_applications (
                    id BIGINT PRIMARY KEY AUTO_INCREMENT,
                    proxy_id VARCHAR(64) NOT NULL,
                    revision_id BIGINT NOT NULL,
                    ok TINYINT(1) NOT NULL,
                    detail TEXT,
                    applied_by VARCHAR(255) NOT NULL DEFAULT '',
                    applied_ts BIGINT NOT NULL,
                    KEY idx_proxy_config_applications_proxy_ts (proxy_id, applied_ts)
                )
                """
            )

    def _row_to_revision(self, row: object | None) -> Optional[ConfigRevision]:
        if not row:
            return None
        return ConfigRevision(
            revision_id=int(row["id"] or 0),
            proxy_id=str(row["proxy_id"]),
            config_sha256=str(row["config_sha256"]),
            config_text=str(row["config_text"] or ""),
            source_kind=str(row["source_kind"] or "manual"),
            created_by=str(row["created_by"] or ""),
            created_ts=int(row["created_ts"] or 0),
            is_active=bool(int(row["is_active"] or 0)),
        )

    def _row_to_application(self, row: object | None) -> Optional[ConfigApplication]:
        if not row:
            return None
        return ConfigApplication(
            application_id=int(row["id"] or 0),
            proxy_id=str(row["proxy_id"]),
            revision_id=int(row["revision_id"] or 0),
            ok=bool(int(row["ok"] or 0)),
            detail=str(row["detail"] or ""),
            applied_by=str(row["applied_by"] or ""),
            applied_ts=int(row["applied_ts"] or 0),
        )

    def _row_to_metadata(self, row: object | None) -> Optional[ConfigRevisionMetadata]:
        if not row:
            return None
        return ConfigRevisionMetadata(
            revision_id=int(row["id"] or 0),
            proxy_id=str(row["proxy_id"]),
            config_sha256=str(row["config_sha256"]),
            source_kind=str(row["source_kind"] or "manual"),
            created_by=str(row["created_by"] or ""),
            created_ts=int(row["created_ts"] or 0),
            is_active=bool(int(row["is_active"] or 0)),
        )

    def get_active_revision(self, proxy_id: object | None) -> Optional[ConfigRevision]:
        self.init_db()
        proxy_key = normalize_proxy_id(proxy_id)
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM proxy_config_revisions
                WHERE proxy_id=%s AND is_active=1
                ORDER BY created_ts DESC, id DESC
                LIMIT 1
                """,
                (proxy_key,),
            ).fetchone()
        return self._row_to_revision(row)

    def get_active_revision_metadata(self, proxy_id: object | None) -> Optional[ConfigRevisionMetadata]:
        self.init_db()
        proxy_key = normalize_proxy_id(proxy_id)
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT id, proxy_id, config_sha256, source_kind, created_by, created_ts, is_active
                FROM proxy_config_revisions
                WHERE proxy_id=%s AND is_active=1
                ORDER BY created_ts DESC, id DESC
                LIMIT 1
                """,
                (proxy_key,),
            ).fetchone()
        return self._row_to_metadata(row)

    def get_active_config_text(self, proxy_id: object | None) -> str:
        revision = self.get_active_revision(proxy_id)
        return revision.config_text if revision is not None else ""

    def create_revision(
        self,
        proxy_id: object | None,
        config_text: str,
        *,
        created_by: str = "",
        source_kind: str = "manual",
        activate: bool = True,
    ) -> ConfigRevision:
        self.init_db()
        proxy_key = normalize_proxy_id(proxy_id)
        text = config_text or ""
        digest = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
        now = int(time.time())

        current = self.get_active_revision(proxy_key)
        if activate and current is not None and current.config_sha256 == digest and current.config_text == text:
            return current

        with self._connect() as conn:
            if activate:
                conn.execute(
                    "UPDATE proxy_config_revisions SET is_active=0 WHERE proxy_id=%s AND is_active=1",
                    (proxy_key,),
                )
            cur = conn.execute(
                """
                INSERT INTO proxy_config_revisions(
                    proxy_id, config_sha256, config_text, source_kind, created_by, created_ts, is_active
                )
                VALUES(%s,%s,%s,%s,%s,%s,%s)
                """,
                (
                    proxy_key,
                    digest,
                    text,
                    (source_kind or "manual").strip() or "manual",
                    (created_by or "").strip(),
                    now,
                    1 if activate else 0,
                ),
            )
            row = conn.execute(
                "SELECT * FROM proxy_config_revisions WHERE id=%s LIMIT 1",
                (int(cur.lastrowid or 0),),
            ).fetchone()
        revision = self._row_to_revision(row)
        assert revision is not None
        return revision

    def ensure_active_revision(
        self,
        proxy_id: object | None,
        config_text: str,
        *,
        created_by: str = "system",
        source_kind: str = "bootstrap",
    ) -> ConfigRevision:
        current = self.get_active_revision(proxy_id)
        if current is not None:
            return current
        return self.create_revision(
            proxy_id,
            config_text,
            created_by=created_by,
            source_kind=source_kind,
            activate=True,
        )

    def record_apply_result(
        self,
        proxy_id: object | None,
        revision_id: int,
        *,
        ok: bool,
        detail: str = "",
        applied_by: str = "proxy",
    ) -> ConfigApplication:
        self.init_db()
        proxy_key = normalize_proxy_id(proxy_id)
        now = int(time.time())
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO proxy_config_applications(proxy_id, revision_id, ok, detail, applied_by, applied_ts)
                VALUES(%s,%s,%s,%s,%s,%s)
                """,
                (proxy_key, int(revision_id), 1 if ok else 0, (detail or "")[:4000], (applied_by or "proxy")[:255], now),
            )
            row = conn.execute(
                "SELECT * FROM proxy_config_applications WHERE id=%s LIMIT 1",
                (int(cur.lastrowid or 0),),
            ).fetchone()
        application = self._row_to_application(row)
        assert application is not None
        return application

    def latest_apply(self, proxy_id: object | None) -> Optional[ConfigApplication]:
        self.init_db()
        proxy_key = normalize_proxy_id(proxy_id)
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM proxy_config_applications
                WHERE proxy_id=%s
                ORDER BY applied_ts DESC, id DESC
                LIMIT 1
                """,
                (proxy_key,),
            ).fetchone()
        return self._row_to_application(row)


_store: Optional[ConfigRevisionStore] = None
_store_lock = threading.Lock()


def get_config_revisions() -> ConfigRevisionStore:
    global _store
    if _store is not None:
        return _store
    with _store_lock:
        if _store is None:
            _store = ConfigRevisionStore()
            _store.init_db()
        return _store
