from __future__ import annotations

import hashlib
import threading
import time
from dataclasses import dataclass

from services.db import OPERATIONAL_ERRORS, connect
from services.proxy_context import normalize_proxy_id
from services.proxy_write_guard import guarded_proxy_write
from services.revision_lifecycle import (
    ensure_generated_column,
    ensure_index,
    mysql_advisory_lock,
    repair_duplicate_active_rows,
)


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
    def __init__(self) -> None:
        self._schema_ready = False
        self._schema_lock = threading.Lock()

    def _connect(self):
        return connect()

    def _is_transient_db_lock(self, exc: BaseException) -> bool:
        if not isinstance(exc, OPERATIONAL_ERRORS):
            return False
        text = str(exc).lower()
        return (
            "deadlock found" in text
            or "lock wait timeout" in text
            or "try restarting transaction" in text
        )

    def _with_db_lock_retry(self, fn, *, attempts: int = 4):
        last_exc: BaseException | None = None
        for i in range(max(1, int(attempts))):
            try:
                return fn()
            except Exception as exc:
                last_exc = exc
                if (
                    not self._is_transient_db_lock(exc)
                    or i >= max(1, int(attempts)) - 1
                ):
                    raise
                time.sleep(min(1.0, 0.1 * (2**i)))
        if last_exc is not None:
            raise last_exc
        return fn()

    def init_db(self) -> None:
        if self._schema_ready:
            return
        with self._schema_lock:
            if self._schema_ready:
                return
        with self._connect() as conn:
            try:
                from services.schema_lifecycle import (
                    runtime_schema_ready_for_lazy_store,
                )

                if runtime_schema_ready_for_lazy_store(conn):
                    self._schema_ready = True
                    return
            except Exception:
                pass
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
                    active_proxy_id VARCHAR(64) GENERATED ALWAYS AS (CASE WHEN is_active=1 THEN proxy_id ELSE NULL END) STORED,
                    UNIQUE KEY uniq_proxy_config_revisions_active_proxy (active_proxy_id),
                    KEY idx_proxy_config_revisions_proxy_active (proxy_id, is_active, created_ts),
                    KEY idx_proxy_config_revisions_proxy_sha (proxy_id, config_sha256)
                )
                """,
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
                """,
            )
            repair_duplicate_active_rows(
                conn,
                table_name="proxy_config_revisions",
                scope_column="proxy_id",
            )
            ensure_generated_column(
                conn,
                table_name="proxy_config_revisions",
                column_name="active_proxy_id",
                ddl=(
                    "ALTER TABLE proxy_config_revisions "
                    "ADD COLUMN active_proxy_id VARCHAR(64) "
                    "GENERATED ALWAYS AS (CASE WHEN is_active=1 THEN proxy_id ELSE NULL END) STORED"
                ),
            )
            ensure_index(
                conn,
                table_name="proxy_config_revisions",
                index_name="uniq_proxy_config_revisions_active_proxy",
                ddl=(
                    "ALTER TABLE proxy_config_revisions "
                    "ADD UNIQUE KEY uniq_proxy_config_revisions_active_proxy (active_proxy_id)"
                ),
            )

        self._schema_ready = True

    def _row_to_revision(self, row: object | None) -> ConfigRevision | None:
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

    def _row_to_application(self, row: object | None) -> ConfigApplication | None:
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

    def _row_to_metadata(self, row: object | None) -> ConfigRevisionMetadata | None:
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

    def get_active_revision(self, proxy_id: object | None) -> ConfigRevision | None:
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

    def get_revision(
        self,
        revision_id: object,
        *,
        proxy_id: object | None = None,
    ) -> ConfigRevision | None:
        self.init_db()
        params: tuple[object, ...]
        if proxy_id is None:
            where = "id=%s"
            params = (int(revision_id or 0),)
        else:
            where = "id=%s AND proxy_id=%s"
            params = (int(revision_id or 0), normalize_proxy_id(proxy_id))
        with self._connect() as conn:
            row = conn.execute(
                f"SELECT * FROM proxy_config_revisions WHERE {where} LIMIT 1",
                params,
            ).fetchone()
        return self._row_to_revision(row)

    def get_active_revision_metadata(
        self,
        proxy_id: object | None,
    ) -> ConfigRevisionMetadata | None:
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
        return self._with_db_lock_retry(
            lambda: self._create_revision_once(
                proxy_id,
                config_text,
                created_by=created_by,
                source_kind=source_kind,
                activate=activate,
            ),
        )

    def _create_revision_once(
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

        with self._connect() as conn:
            with guarded_proxy_write(conn, proxy_key) as guard:
                proxy_key = guard.proxy_id
                lock_scope = proxy_key if activate else f"inactive:{proxy_key}"
                with mysql_advisory_lock(
                    conn,
                    namespace="proxy_config_revisions.active",
                    scope=lock_scope,
                ):
                    current = None
                    if activate:
                        current = self._row_to_revision(
                            conn.execute(
                                """
                                SELECT * FROM proxy_config_revisions
                                WHERE proxy_id=%s AND is_active=1
                                ORDER BY created_ts DESC, id DESC
                                LIMIT 1
                                FOR UPDATE
                                """,
                                (proxy_key,),
                            ).fetchone(),
                        )
                        if (
                            current is not None
                            and current.config_sha256 == digest
                            and current.config_text == text
                        ):
                            return current
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

    def activate_revision(
        self,
        proxy_id: object | None,
        revision_id: object,
    ) -> ConfigRevision:
        return self._with_db_lock_retry(
            lambda: self._activate_revision_once(proxy_id, revision_id),
        )

    def _activate_revision_once(
        self,
        proxy_id: object | None,
        revision_id: object,
    ) -> ConfigRevision:
        self.init_db()
        proxy_key = normalize_proxy_id(proxy_id)
        target_id = int(revision_id or 0)
        with self._connect() as conn:
            with guarded_proxy_write(conn, proxy_key) as guard:
                proxy_key = guard.proxy_id
                with mysql_advisory_lock(
                    conn,
                    namespace="proxy_config_revisions.active",
                    scope=proxy_key,
                ):
                    existing = conn.execute(
                        "SELECT * FROM proxy_config_revisions WHERE id=%s AND proxy_id=%s LIMIT 1 FOR UPDATE",
                        (target_id, proxy_key),
                    ).fetchone()
                    if existing is None:
                        msg = (
                            f"Config revision {target_id} was not found for proxy {proxy_key}."
                        )
                        raise ValueError(msg)
                    conn.execute(
                        "UPDATE proxy_config_revisions SET is_active=0 WHERE proxy_id=%s AND is_active=1 AND id<>%s",
                        (proxy_key, target_id),
                    )
                    conn.execute(
                        "UPDATE proxy_config_revisions SET is_active=1 WHERE proxy_id=%s AND id=%s",
                        (proxy_key, target_id),
                    )
                    row = conn.execute(
                        "SELECT * FROM proxy_config_revisions WHERE id=%s AND proxy_id=%s LIMIT 1",
                        (target_id, proxy_key),
                    ).fetchone()
        revision = self._row_to_revision(row)
        assert revision is not None
        return revision

    def deactivate_revision(
        self,
        proxy_id: object | None,
        revision_id: object,
    ) -> None:
        self._with_db_lock_retry(
            lambda: self._deactivate_revision_once(proxy_id, revision_id),
        )

    def _deactivate_revision_once(
        self,
        proxy_id: object | None,
        revision_id: object,
    ) -> None:
        self.init_db()
        proxy_key = normalize_proxy_id(proxy_id)
        target_id = int(revision_id or 0)
        with self._connect() as conn:
            with guarded_proxy_write(conn, proxy_key) as guard:
                proxy_key = guard.proxy_id
                with mysql_advisory_lock(
                    conn,
                    namespace="proxy_config_revisions.active",
                    scope=proxy_key,
                ):
                    conn.execute(
                        "UPDATE proxy_config_revisions SET is_active=0 WHERE proxy_id=%s AND id=%s",
                        (proxy_key, target_id),
                    )

    def ensure_active_revision(
        self,
        proxy_id: object | None,
        config_text: str,
        *,
        created_by: str = "system",
        source_kind: str = "bootstrap",
    ) -> ConfigRevision:
        return self._with_db_lock_retry(
            lambda: self._ensure_active_revision_once(
                proxy_id,
                config_text,
                created_by=created_by,
                source_kind=source_kind,
            ),
        )

    def _ensure_active_revision_once(
        self,
        proxy_id: object | None,
        config_text: str,
        *,
        created_by: str = "system",
        source_kind: str = "bootstrap",
    ) -> ConfigRevision:
        self.init_db()
        proxy_key = normalize_proxy_id(proxy_id)
        text = config_text or ""
        digest = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
        now = int(time.time())
        with self._connect() as conn:
            with guarded_proxy_write(conn, proxy_key) as guard:
                proxy_key = guard.proxy_id
                with mysql_advisory_lock(
                    conn,
                    namespace="proxy_config_revisions.active",
                    scope=proxy_key,
                ):
                    current = self._row_to_revision(
                        conn.execute(
                            """
                            SELECT * FROM proxy_config_revisions
                            WHERE proxy_id=%s AND is_active=1
                            ORDER BY created_ts DESC, id DESC
                            LIMIT 1
                            FOR UPDATE
                            """,
                            (proxy_key,),
                        ).fetchone(),
                    )
                    if current is not None:
                        return current
                    cur = conn.execute(
                        """
                        INSERT INTO proxy_config_revisions(
                            proxy_id, config_sha256, config_text, source_kind, created_by, created_ts, is_active
                        )
                        VALUES(%s,%s,%s,%s,%s,%s,1)
                        """,
                        (
                            proxy_key,
                            digest,
                            text,
                            (source_kind or "bootstrap").strip() or "bootstrap",
                            (created_by or "system").strip(),
                            now,
                        ),
                    )
                    row = conn.execute(
                        "SELECT * FROM proxy_config_revisions WHERE id=%s LIMIT 1",
                        (int(cur.lastrowid or 0),),
                    ).fetchone()
        revision = self._row_to_revision(row)
        assert revision is not None
        return revision

    def restore_previous_if_current(
        self,
        proxy_id: object | None,
        failed_revision_id: object,
        previous_revision_id: object | None,
    ) -> bool:
        return bool(
            self._with_db_lock_retry(
                lambda: self._restore_previous_if_current_once(
                    proxy_id,
                    failed_revision_id,
                    previous_revision_id,
                ),
            ),
        )

    def _restore_previous_if_current_once(
        self,
        proxy_id: object | None,
        failed_revision_id: object,
        previous_revision_id: object | None,
    ) -> bool:
        self.init_db()
        proxy_key = normalize_proxy_id(proxy_id)
        failed_id = int(failed_revision_id or 0)
        previous_id = int(previous_revision_id or 0) if previous_revision_id else 0
        with self._connect() as conn:
            with guarded_proxy_write(conn, proxy_key) as guard:
                proxy_key = guard.proxy_id
                with mysql_advisory_lock(
                    conn,
                    namespace="proxy_config_revisions.active",
                    scope=proxy_key,
                ):
                    current = conn.execute(
                        """
                        SELECT id FROM proxy_config_revisions
                        WHERE proxy_id=%s AND is_active=1
                        ORDER BY created_ts DESC, id DESC
                        LIMIT 1
                        FOR UPDATE
                        """,
                        (proxy_key,),
                    ).fetchone()
                    if current is None or int(current["id"] or 0) != failed_id:
                        return False
                    if previous_id > 0:
                        previous = conn.execute(
                            "SELECT id FROM proxy_config_revisions WHERE proxy_id=%s AND id=%s LIMIT 1 FOR UPDATE",
                            (proxy_key, previous_id),
                        ).fetchone()
                        if previous is None:
                            return False
                        conn.execute(
                            "UPDATE proxy_config_revisions SET is_active=0 WHERE proxy_id=%s AND is_active=1 AND id<>%s",
                            (proxy_key, previous_id),
                        )
                        conn.execute(
                            "UPDATE proxy_config_revisions SET is_active=1 WHERE proxy_id=%s AND id=%s",
                            (proxy_key, previous_id),
                        )
                    else:
                        conn.execute(
                            "UPDATE proxy_config_revisions SET is_active=0 WHERE proxy_id=%s AND id=%s",
                            (proxy_key, failed_id),
                        )
                    return True

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
        target_revision_id = int(revision_id)
        with self._connect() as conn:
            with guarded_proxy_write(conn, proxy_key) as guard:
                proxy_key = guard.proxy_id
                revision = conn.execute(
                    "SELECT id FROM proxy_config_revisions WHERE proxy_id=%s AND id=%s LIMIT 1 FOR SHARE",
                    (proxy_key, target_revision_id),
                ).fetchone()
                if revision is None:
                    msg = f"Config revision {target_revision_id} was not found for proxy {proxy_key}."
                    raise ValueError(msg)
                cur = conn.execute(
                    """
                    INSERT INTO proxy_config_applications(proxy_id, revision_id, ok, detail, applied_by, applied_ts)
                    VALUES(%s,%s,%s,%s,%s,%s)
                    """,
                    (
                        proxy_key,
                        target_revision_id,
                        1 if ok else 0,
                        (detail or "")[:4000],
                        (applied_by or "proxy")[:255],
                        now,
                    ),
                )
                row = conn.execute(
                    "SELECT * FROM proxy_config_applications WHERE id=%s LIMIT 1",
                    (int(cur.lastrowid or 0),),
                ).fetchone()
        application = self._row_to_application(row)
        assert application is not None
        return application

    def latest_apply(self, proxy_id: object | None) -> ConfigApplication | None:
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


_store: ConfigRevisionStore | None = None
_store_lock = threading.Lock()


def get_config_revisions() -> ConfigRevisionStore:
    global _store
    if _store is not None:
        return _store
    with _store_lock:
        if _store is None:
            _store = ConfigRevisionStore()
        return _store
