from __future__ import annotations

import threading
import time
from dataclasses import dataclass

from services.certificate_core import CertificateBundle
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
class CertificateBundleRevision:
    revision_id: int
    bundle_sha256: str
    cert_sha256: str
    cert_pem: str
    key_pem: str
    chain_pem: str
    source_kind: str
    subject_dn: str
    not_before: str
    not_after: str
    original_filename: str
    original_pfx_blob: bytes | None
    created_by: str
    created_ts: int
    is_active: bool

    @property
    def fullchain_pem(self) -> str:
        return (self.cert_pem or "") + (self.chain_pem or "")

    def to_bundle(self) -> CertificateBundle:
        return CertificateBundle(
            cert_pem=self.cert_pem,
            key_pem=self.key_pem,
            chain_pem=self.chain_pem,
            source_kind=self.source_kind,
            bundle_sha256=self.bundle_sha256,
            cert_sha256=self.cert_sha256,
            subject_dn=self.subject_dn,
            not_before=self.not_before,
            not_after=self.not_after,
            original_pfx_bytes=self.original_pfx_blob,
        )


@dataclass(frozen=True)
class CertificateApplication:
    application_id: int
    proxy_id: str
    revision_id: int
    ok: bool
    detail: str
    applied_by: str
    applied_ts: int
    bundle_sha256: str


@dataclass(frozen=True)
class CertificateBundleMetadata:
    revision_id: int
    bundle_sha256: str
    cert_sha256: str
    source_kind: str
    subject_dn: str
    not_before: str
    not_after: str
    created_by: str
    created_ts: int
    is_active: bool


@dataclass(frozen=True)
class AdminUiHttpsSettings:
    enabled: bool
    certfile: str
    keyfile: str
    san_tokens: str
    updated_by: str
    updated_ts: int


class CertificateBundleStore:
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
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS certificate_bundle_revisions (
                    id BIGINT PRIMARY KEY AUTO_INCREMENT,
                    bundle_sha256 CHAR(64) NOT NULL,
                    cert_sha256 CHAR(64) NOT NULL,
                    cert_pem LONGTEXT NOT NULL,
                    key_pem LONGTEXT NOT NULL,
                    chain_pem LONGTEXT NOT NULL,
                    source_kind VARCHAR(64) NOT NULL DEFAULT 'manual',
                    subject_dn TEXT,
                    not_before VARCHAR(255) NOT NULL DEFAULT '',
                    not_after VARCHAR(255) NOT NULL DEFAULT '',
                    original_filename VARCHAR(255) NOT NULL DEFAULT '',
                    original_pfx_blob LONGBLOB NULL,
                    created_by VARCHAR(255) NOT NULL DEFAULT '',
                    created_ts BIGINT NOT NULL,
                    is_active TINYINT(1) NOT NULL DEFAULT 1,
                    active_global_slot TINYINT GENERATED ALWAYS AS (CASE WHEN is_active=1 THEN 1 ELSE NULL END) STORED,
                    UNIQUE KEY uniq_certificate_bundle_revisions_active (active_global_slot),
                    KEY idx_certificate_bundle_revisions_active (is_active, created_ts),
                    KEY idx_certificate_bundle_revisions_sha (bundle_sha256, created_ts)
                )
                """,
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS proxy_certificate_applications (
                    id BIGINT PRIMARY KEY AUTO_INCREMENT,
                    proxy_id VARCHAR(64) NOT NULL,
                    revision_id BIGINT NOT NULL,
                    ok TINYINT(1) NOT NULL,
                    detail TEXT,
                    applied_by VARCHAR(255) NOT NULL DEFAULT '',
                    applied_ts BIGINT NOT NULL,
                    bundle_sha256 CHAR(64) NOT NULL DEFAULT '',
                    KEY idx_proxy_certificate_applications_proxy_ts (proxy_id, applied_ts),
                    KEY idx_proxy_certificate_applications_proxy_revision_ts (proxy_id, revision_id, applied_ts, id)
                )
                """,
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS admin_ui_https_settings (
                    id TINYINT PRIMARY KEY,
                    enabled TINYINT(1) NOT NULL DEFAULT 0,
                    certfile VARCHAR(1024) NOT NULL DEFAULT '',
                    keyfile VARCHAR(1024) NOT NULL DEFAULT '',
                    san_tokens TEXT,
                    updated_by VARCHAR(255) NOT NULL DEFAULT '',
                    updated_ts BIGINT NOT NULL DEFAULT 0
                )
                """,
            )
            ensure_index(
                conn,
                table_name="proxy_certificate_applications",
                index_name="idx_proxy_certificate_applications_proxy_revision_ts",
                ddl=(
                    "ALTER TABLE proxy_certificate_applications "
                    "ADD INDEX idx_proxy_certificate_applications_proxy_revision_ts "
                    "(proxy_id, revision_id, applied_ts, id)"
                ),
            )
            repair_duplicate_active_rows(
                conn,
                table_name="certificate_bundle_revisions",
            )
            ensure_generated_column(
                conn,
                table_name="certificate_bundle_revisions",
                column_name="active_global_slot",
                ddl=(
                    "ALTER TABLE certificate_bundle_revisions "
                    "ADD COLUMN active_global_slot TINYINT "
                    "GENERATED ALWAYS AS (CASE WHEN is_active=1 THEN 1 ELSE NULL END) STORED"
                ),
            )
            ensure_index(
                conn,
                table_name="certificate_bundle_revisions",
                index_name="uniq_certificate_bundle_revisions_active",
                ddl=(
                    "ALTER TABLE certificate_bundle_revisions "
                    "ADD UNIQUE KEY uniq_certificate_bundle_revisions_active (active_global_slot)"
                ),
            )
            ensure_generated_column(
                conn,
                table_name="admin_ui_https_settings",
                column_name="san_tokens",
                ddl="ALTER TABLE admin_ui_https_settings ADD COLUMN san_tokens TEXT",
            )
            conn.execute(
                """
                INSERT IGNORE INTO admin_ui_https_settings(
                    id, enabled, certfile, keyfile, san_tokens, updated_by, updated_ts
                )
                VALUES(1,0,'','','','',0)
                """,
            )

    def _row_to_revision(self, row: object | None) -> CertificateBundleRevision | None:
        if not row:
            return None
        return CertificateBundleRevision(
            revision_id=int(row["id"] or 0),
            bundle_sha256=str(row["bundle_sha256"] or ""),
            cert_sha256=str(row["cert_sha256"] or ""),
            cert_pem=str(row["cert_pem"] or ""),
            key_pem=str(row["key_pem"] or ""),
            chain_pem=str(row["chain_pem"] or ""),
            source_kind=str(row["source_kind"] or "manual"),
            subject_dn=str(row["subject_dn"] or ""),
            not_before=str(row["not_before"] or ""),
            not_after=str(row["not_after"] or ""),
            original_filename=str(row["original_filename"] or ""),
            original_pfx_blob=row["original_pfx_blob"]
            if row["original_pfx_blob"] is not None
            else None,
            created_by=str(row["created_by"] or ""),
            created_ts=int(row["created_ts"] or 0),
            is_active=bool(int(row["is_active"] or 0)),
        )

    def _row_to_application(self, row: object | None) -> CertificateApplication | None:
        if not row:
            return None
        return CertificateApplication(
            application_id=int(row["id"] or 0),
            proxy_id=str(row["proxy_id"] or "default"),
            revision_id=int(row["revision_id"] or 0),
            ok=bool(int(row["ok"] or 0)),
            detail=str(row["detail"] or ""),
            applied_by=str(row["applied_by"] or ""),
            applied_ts=int(row["applied_ts"] or 0),
            bundle_sha256=str(row["bundle_sha256"] or ""),
        )

    def _row_to_metadata(self, row: object | None) -> CertificateBundleMetadata | None:
        if not row:
            return None
        return CertificateBundleMetadata(
            revision_id=int(row["id"] or 0),
            bundle_sha256=str(row["bundle_sha256"] or ""),
            cert_sha256=str(row["cert_sha256"] or ""),
            source_kind=str(row["source_kind"] or "manual"),
            subject_dn=str(row["subject_dn"] or ""),
            not_before=str(row["not_before"] or ""),
            not_after=str(row["not_after"] or ""),
            created_by=str(row["created_by"] or ""),
            created_ts=int(row["created_ts"] or 0),
            is_active=bool(int(row["is_active"] or 0)),
        )

    def get_active_bundle(self) -> CertificateBundleRevision | None:
        self.init_db()
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM certificate_bundle_revisions
                WHERE is_active=1
                ORDER BY created_ts DESC, id DESC
                LIMIT 1
                """,
            ).fetchone()
        return self._row_to_revision(row)

    def get_revision(self, revision_id: object) -> CertificateBundleRevision | None:
        self.init_db()
        target_id = int(revision_id or 0)
        if target_id <= 0:
            return None
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM certificate_bundle_revisions WHERE id=%s LIMIT 1",
                (target_id,),
            ).fetchone()
        return self._row_to_revision(row)

    def get_active_bundle_metadata(self) -> CertificateBundleMetadata | None:
        self.init_db()
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT id, bundle_sha256, cert_sha256, source_kind, subject_dn, not_before, not_after, created_by, created_ts, is_active
                FROM certificate_bundle_revisions
                WHERE is_active=1
                ORDER BY created_ts DESC, id DESC
                LIMIT 1
                """,
            ).fetchone()
        return self._row_to_metadata(row)

    def create_revision(
        self,
        bundle: CertificateBundle,
        *,
        created_by: str = "",
        original_filename: str = "",
        activate: bool = True,
    ) -> CertificateBundleRevision:
        return self._with_db_lock_retry(
            lambda: self._create_revision_once(
                bundle,
                created_by=created_by,
                original_filename=original_filename,
                activate=activate,
            ),
        )

    def _create_revision_once(
        self,
        bundle: CertificateBundle,
        *,
        created_by: str = "",
        original_filename: str = "",
        activate: bool = True,
    ) -> CertificateBundleRevision:
        self.init_db()
        now = int(time.time())
        with self._connect() as conn:
            lock_scope = "global" if activate else "inactive"
            with mysql_advisory_lock(
                conn,
                namespace="certificate_bundle_revisions.active",
                scope=lock_scope,
            ):
                current = None
                if activate:
                    current = self._row_to_revision(
                        conn.execute(
                            """
                            SELECT * FROM certificate_bundle_revisions
                            WHERE is_active=1
                            ORDER BY created_ts DESC, id DESC
                            LIMIT 1
                            FOR UPDATE
                            """,
                        ).fetchone(),
                    )
                    if (
                        current is not None
                        and current.bundle_sha256 == bundle.bundle_sha256
                        and current.cert_pem == bundle.cert_pem
                        and current.key_pem == bundle.key_pem
                        and current.chain_pem == bundle.chain_pem
                    ):
                        return current
                    conn.execute(
                        "UPDATE certificate_bundle_revisions SET is_active=0 WHERE is_active=1",
                    )
                cur = conn.execute(
                    """
                    INSERT INTO certificate_bundle_revisions(
                        bundle_sha256, cert_sha256, cert_pem, key_pem, chain_pem,
                        source_kind, subject_dn, not_before, not_after,
                        original_filename, original_pfx_blob, created_by, created_ts, is_active
                    )
                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """,
                    (
                        bundle.bundle_sha256,
                        bundle.cert_sha256,
                        bundle.cert_pem,
                        bundle.key_pem,
                        bundle.chain_pem,
                        (bundle.source_kind or "manual").strip() or "manual",
                        (bundle.subject_dn or "")[:4000],
                        (bundle.not_before or "")[:255],
                        (bundle.not_after or "")[:255],
                        (original_filename or "")[:255],
                        bundle.original_pfx_bytes,
                        (created_by or "").strip()[:255],
                        now,
                        1 if activate else 0,
                    ),
                )
                row = conn.execute(
                    "SELECT * FROM certificate_bundle_revisions WHERE id=%s LIMIT 1",
                    (int(cur.lastrowid or 0),),
                ).fetchone()
        revision = self._row_to_revision(row)
        assert revision is not None
        return revision

    def activate_revision(self, revision_id: object) -> CertificateBundleRevision:
        return self._with_db_lock_retry(lambda: self._activate_revision_once(revision_id))

    def _activate_revision_once(self, revision_id: object) -> CertificateBundleRevision:
        self.init_db()
        target_id = int(revision_id or 0)
        with self._connect() as conn:
            with mysql_advisory_lock(
                conn,
                namespace="certificate_bundle_revisions.active",
                scope="global",
            ):
                row = conn.execute(
                    "SELECT * FROM certificate_bundle_revisions WHERE id=%s LIMIT 1 FOR UPDATE",
                    (target_id,),
                ).fetchone()
                if not row:
                    msg = f"Certificate bundle revision {target_id} was not found."
                    raise ValueError(msg)
                conn.execute(
                    "UPDATE certificate_bundle_revisions SET is_active=0 WHERE is_active=1 AND id<>%s",
                    (target_id,),
                )
                conn.execute(
                    "UPDATE certificate_bundle_revisions SET is_active=1 WHERE id=%s",
                    (target_id,),
                )
                row = conn.execute(
                    "SELECT * FROM certificate_bundle_revisions WHERE id=%s LIMIT 1",
                    (target_id,),
                ).fetchone()
        revision = self._row_to_revision(row)
        assert revision is not None
        return revision

    def deactivate_revision(self, revision_id: object) -> None:
        self._with_db_lock_retry(lambda: self._deactivate_revision_once(revision_id))

    def _deactivate_revision_once(self, revision_id: object) -> None:
        self.init_db()
        with self._connect() as conn:
            with mysql_advisory_lock(
                conn,
                namespace="certificate_bundle_revisions.active",
                scope="global",
            ):
                conn.execute(
                    "UPDATE certificate_bundle_revisions SET is_active=0 WHERE id=%s",
                    (int(revision_id or 0),),
                )

    def restore_previous_if_current(
        self,
        failed_revision_id: object,
        previous_revision_id: object | None,
    ) -> bool:
        return bool(
            self._with_db_lock_retry(
                lambda: self._restore_previous_if_current_once(
                    failed_revision_id,
                    previous_revision_id,
                ),
            ),
        )

    def _restore_previous_if_current_once(
        self,
        failed_revision_id: object,
        previous_revision_id: object | None,
    ) -> bool:
        self.init_db()
        failed_id = int(failed_revision_id or 0)
        previous_id = int(previous_revision_id or 0) if previous_revision_id else 0
        with self._connect() as conn:
            with mysql_advisory_lock(
                conn,
                namespace="certificate_bundle_revisions.active",
                scope="global",
            ):
                current = conn.execute(
                    """
                    SELECT id FROM certificate_bundle_revisions
                    WHERE is_active=1
                    ORDER BY created_ts DESC, id DESC
                    LIMIT 1
                    FOR UPDATE
                    """,
                ).fetchone()
                if current is None or int(current["id"] or 0) != failed_id:
                    return False
                if previous_id > 0:
                    previous = conn.execute(
                        "SELECT id FROM certificate_bundle_revisions WHERE id=%s LIMIT 1 FOR UPDATE",
                        (previous_id,),
                    ).fetchone()
                    if previous is None:
                        return False
                    conn.execute(
                        "UPDATE certificate_bundle_revisions SET is_active=0 WHERE is_active=1 AND id<>%s",
                        (previous_id,),
                    )
                    conn.execute(
                        "UPDATE certificate_bundle_revisions SET is_active=1 WHERE id=%s",
                        (previous_id,),
                    )
                else:
                    conn.execute(
                        "UPDATE certificate_bundle_revisions SET is_active=0 WHERE id=%s",
                        (failed_id,),
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
        bundle_sha256: str = "",
    ) -> CertificateApplication:
        self.init_db()
        proxy_key = normalize_proxy_id(proxy_id)
        now = int(time.time())
        target_revision_id = int(revision_id)
        with self._connect() as conn:
            with guarded_proxy_write(conn, proxy_key) as guard:
                proxy_key = guard.proxy_id
                revision = conn.execute(
                    "SELECT id FROM certificate_bundle_revisions WHERE id=%s LIMIT 1 FOR SHARE",
                    (target_revision_id,),
                ).fetchone()
                if revision is None:
                    msg = f"Certificate bundle revision {target_revision_id} was not found."
                    raise ValueError(msg)
                cur = conn.execute(
                    """
                    INSERT INTO proxy_certificate_applications(
                        proxy_id, revision_id, ok, detail, applied_by, applied_ts, bundle_sha256
                    )
                    VALUES(%s,%s,%s,%s,%s,%s,%s)
                    """,
                    (
                        proxy_key,
                        target_revision_id,
                        1 if ok else 0,
                        (detail or "")[:4000],
                        (applied_by or "proxy")[:255],
                        now,
                        (bundle_sha256 or "")[:64],
                    ),
                )
                row = conn.execute(
                    "SELECT * FROM proxy_certificate_applications WHERE id=%s LIMIT 1",
                    (int(cur.lastrowid or 0),),
                ).fetchone()
        application = self._row_to_application(row)
        assert application is not None
        return application

    def latest_apply(
        self,
        proxy_id: object | None,
        *,
        revision_id: object | None = None,
    ) -> CertificateApplication | None:
        self.init_db()
        proxy_key = normalize_proxy_id(proxy_id)
        if revision_id is None:
            sql = """
                SELECT * FROM proxy_certificate_applications
                WHERE proxy_id=%s
                ORDER BY applied_ts DESC, id DESC
                LIMIT 1
                """
            params: tuple[object, ...] = (proxy_key,)
        else:
            sql = """
                SELECT * FROM proxy_certificate_applications
                WHERE proxy_id=%s AND revision_id=%s
                ORDER BY applied_ts DESC, id DESC
                LIMIT 1
                """
            params = (proxy_key, int(revision_id or 0))
        with self._connect() as conn:
            row = conn.execute(sql, params).fetchone()
        return self._row_to_application(row)

    def get_admin_ui_https_settings(self) -> AdminUiHttpsSettings:
        self.init_db()
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT enabled, certfile, keyfile, san_tokens, updated_by, updated_ts
                FROM admin_ui_https_settings
                WHERE id=1
                LIMIT 1
                """,
            ).fetchone()
        if not row:
            return AdminUiHttpsSettings(False, "", "", "", "", 0)
        return AdminUiHttpsSettings(
            enabled=bool(int(row["enabled"] or 0)),
            certfile=str(row["certfile"] or ""),
            keyfile=str(row["keyfile"] or ""),
            san_tokens=str(row["san_tokens"] or ""),
            updated_by=str(row["updated_by"] or ""),
            updated_ts=int(row["updated_ts"] or 0),
        )

    def set_admin_ui_https_settings(
        self,
        *,
        enabled: bool,
        certfile: object | None = None,
        keyfile: object | None = None,
        san_tokens: object | None = None,
        updated_by: object | None = None,
    ) -> AdminUiHttpsSettings:
        self.init_db()
        cert_path = str(certfile or "").strip()[:1024]
        key_path = str(keyfile or "").strip()[:1024]
        san_text = str(san_tokens or "").strip()[:4000]
        updater = str(updated_by or "").strip()[:255]
        now = int(time.time())
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO admin_ui_https_settings(
                    id, enabled, certfile, keyfile, san_tokens, updated_by, updated_ts
                )
                VALUES(1,%s,%s,%s,%s,%s,%s) AS incoming
                ON DUPLICATE KEY UPDATE
                    enabled=incoming.enabled,
                    certfile=incoming.certfile,
                    keyfile=incoming.keyfile,
                    san_tokens=incoming.san_tokens,
                    updated_by=incoming.updated_by,
                    updated_ts=incoming.updated_ts
                """,
                (1 if enabled else 0, cert_path, key_path, san_text, updater, now),
            )
        return self.get_admin_ui_https_settings()


_store: CertificateBundleStore | None = None
_store_lock = threading.Lock()


def get_certificate_bundles() -> CertificateBundleStore:
    global _store
    if _store is not None:
        return _store
    with _store_lock:
        if _store is None:
            _store = CertificateBundleStore()
        return _store
