from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Optional

from services.cert_manager import CertificateBundle
from services.db import connect, create_index_if_not_exists
from services.proxy_context import normalize_proxy_id


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


class CertificateBundleStore:
    def _connect(self):
        return connect()

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
                    is_active TINYINT(1) NOT NULL DEFAULT 1
                )
                """
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
                    bundle_sha256 CHAR(64) NOT NULL DEFAULT ''
                )
                """
            )
            create_index_if_not_exists(
                conn,
                table_name="certificate_bundle_revisions",
                index_name="idx_certificate_bundle_revisions_active",
                columns_sql="is_active, created_ts",
            )
            create_index_if_not_exists(
                conn,
                table_name="certificate_bundle_revisions",
                index_name="idx_certificate_bundle_revisions_sha",
                columns_sql="bundle_sha256, created_ts",
            )
            create_index_if_not_exists(
                conn,
                table_name="proxy_certificate_applications",
                index_name="idx_proxy_certificate_applications_proxy_ts",
                columns_sql="proxy_id, applied_ts",
            )

    def _row_to_revision(self, row: object | None) -> Optional[CertificateBundleRevision]:
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
            original_pfx_blob=row["original_pfx_blob"] if row["original_pfx_blob"] is not None else None,
            created_by=str(row["created_by"] or ""),
            created_ts=int(row["created_ts"] or 0),
            is_active=bool(int(row["is_active"] or 0)),
        )

    def _row_to_application(self, row: object | None) -> Optional[CertificateApplication]:
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

    def get_active_bundle(self) -> Optional[CertificateBundleRevision]:
        self.init_db()
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM certificate_bundle_revisions
                WHERE is_active=1
                ORDER BY created_ts DESC, id DESC
                LIMIT 1
                """
            ).fetchone()
        return self._row_to_revision(row)

    def create_revision(
        self,
        bundle: CertificateBundle,
        *,
        created_by: str = "",
        original_filename: str = "",
        activate: bool = True,
    ) -> CertificateBundleRevision:
        self.init_db()
        current = self.get_active_bundle()
        if (
            activate
            and current is not None
            and current.bundle_sha256 == bundle.bundle_sha256
            and current.cert_pem == bundle.cert_pem
            and current.key_pem == bundle.key_pem
            and current.chain_pem == bundle.chain_pem
        ):
            return current

        now = int(time.time())
        with self._connect() as conn:
            if activate:
                conn.execute("UPDATE certificate_bundle_revisions SET is_active=0 WHERE is_active=1")
            cur = conn.execute(
                """
                INSERT INTO certificate_bundle_revisions(
                    bundle_sha256, cert_sha256, cert_pem, key_pem, chain_pem,
                    source_kind, subject_dn, not_before, not_after,
                    original_filename, original_pfx_blob, created_by, created_ts, is_active
                )
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
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
                "SELECT * FROM certificate_bundle_revisions WHERE id=? LIMIT 1",
                (int(cur.lastrowid or 0),),
            ).fetchone()
        revision = self._row_to_revision(row)
        assert revision is not None
        return revision

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
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO proxy_certificate_applications(
                    proxy_id, revision_id, ok, detail, applied_by, applied_ts, bundle_sha256
                )
                VALUES(?,?,?,?,?,?,?)
                """,
                (
                    proxy_key,
                    int(revision_id),
                    1 if ok else 0,
                    (detail or "")[:4000],
                    (applied_by or "proxy")[:255],
                    now,
                    (bundle_sha256 or "")[:64],
                ),
            )
            row = conn.execute(
                "SELECT * FROM proxy_certificate_applications WHERE id=? LIMIT 1",
                (int(cur.lastrowid or 0),),
            ).fetchone()
        application = self._row_to_application(row)
        assert application is not None
        return application

    def latest_apply(self, proxy_id: object | None) -> Optional[CertificateApplication]:
        self.init_db()
        proxy_key = normalize_proxy_id(proxy_id)
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM proxy_certificate_applications
                WHERE proxy_id=?
                ORDER BY applied_ts DESC, id DESC
                LIMIT 1
                """,
                (proxy_key,),
            ).fetchone()
        return self._row_to_application(row)


_store: Optional[CertificateBundleStore] = None
_store_lock = threading.Lock()


def get_certificate_bundles() -> CertificateBundleStore:
    global _store
    if _store is not None:
        return _store
    with _store_lock:
        if _store is None:
            _store = CertificateBundleStore()
            _store.init_db()
        return _store
