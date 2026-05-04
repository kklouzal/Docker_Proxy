from __future__ import annotations

import sys
from pathlib import Path


def _add_web_to_path() -> None:
    web_dir = Path(__file__).resolve().parents[1]
    if str(web_dir) not in sys.path:
        sys.path.insert(0, str(web_dir))


def test_certificate_bundle_revision_fullchain_and_to_bundle() -> None:
    _add_web_to_path()
    from services.certificate_bundles import CertificateBundleRevision  # type: ignore

    revision = CertificateBundleRevision(
        revision_id=7,
        bundle_sha256="bundle",
        cert_sha256="cert",
        cert_pem="CERT\n",
        key_pem="KEY\n",
        chain_pem="CHAIN\n",
        source_kind="uploaded_pfx",
        subject_dn="CN=Proxy",
        not_before="before",
        not_after="after",
        original_filename="ca.pfx",
        original_pfx_blob=b"pfx",
        created_by="tester",
        created_ts=123,
        is_active=True,
    )

    assert revision.fullchain_pem == "CERT\nCHAIN\n"
    bundle = revision.to_bundle()
    assert bundle.cert_pem == "CERT\n"
    assert bundle.key_pem == "KEY\n"
    assert bundle.chain_pem == "CHAIN\n"
    assert bundle.source_kind == "uploaded_pfx"
    assert bundle.original_pfx_bytes == b"pfx"


def test_certificate_bundle_store_row_converters_handle_nulls_and_types() -> None:
    _add_web_to_path()
    import services.certificate_bundles as certificate_bundles  # type: ignore

    store = certificate_bundles.CertificateBundleStore()
    assert store._row_to_revision(None) is None
    assert store._row_to_application(None) is None
    assert store._row_to_metadata(None) is None

    revision = store._row_to_revision(
        {
            "id": "9",
            "bundle_sha256": None,
            "cert_sha256": "cert",
            "cert_pem": "CERT",
            "key_pem": "KEY",
            "chain_pem": None,
            "source_kind": "manual",
            "subject_dn": None,
            "not_before": "",
            "not_after": "",
            "original_filename": None,
            "original_pfx_blob": None,
            "created_by": None,
            "created_ts": "123",
            "is_active": "1",
        }
    )
    assert revision is not None
    assert revision.revision_id == 9
    assert revision.bundle_sha256 == ""
    assert revision.chain_pem == ""
    assert revision.is_active is True

    application = store._row_to_application(
        {
            "id": "3",
            "proxy_id": "",
            "revision_id": "9",
            "ok": "0",
            "detail": None,
            "applied_by": "admin",
            "applied_ts": "456",
            "bundle_sha256": None,
        }
    )
    assert application is not None
    assert application.proxy_id == "default"
    assert application.ok is False
    assert application.bundle_sha256 == ""

    metadata = store._row_to_metadata(
        {
            "id": "9",
            "bundle_sha256": "bundle",
            "cert_sha256": None,
            "source_kind": None,
            "subject_dn": "subject",
            "not_before": None,
            "not_after": "after",
            "created_by": "tester",
            "created_ts": "789",
            "is_active": "0",
        }
    )
    assert metadata is not None
    assert metadata.source_kind == "manual"
    assert metadata.cert_sha256 == ""
    assert metadata.is_active is False
