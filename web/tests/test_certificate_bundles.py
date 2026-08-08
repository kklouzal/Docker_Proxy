from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


def _add_web_to_path() -> None:
    web_dir = Path(__file__).resolve().parents[1]
    if str(web_dir) not in sys.path:
        sys.path.insert(0, str(web_dir))


_add_web_to_path()
from services import certificate_bundles  # type: ignore  # noqa: E402

CertificateBundleRevision = certificate_bundles.CertificateBundleRevision
CertificateBundleStore = certificate_bundles.CertificateBundleStore


def test_certificate_bundle_revision_fullchain_and_to_bundle() -> None:
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
        },
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
        },
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
        },
    )
    assert metadata is not None
    assert metadata.source_kind == "manual"
    assert metadata.cert_sha256 == ""
    assert metadata.is_active is False


class _ActivationConn:
    def __init__(self, calls: list[str], *, target_exists: bool) -> None:
        self.calls = calls
        self.target_exists = target_exists

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def execute(self, sql, params=None):
        text = str(sql)
        self.calls.append(text)
        if "GET_LOCK" in text:
            return SimpleNamespace(fetchone=lambda: {"acquired": 1})
        if "RELEASE_LOCK" in text:
            return SimpleNamespace(fetchone=lambda: None, rowcount=0)
        if "SELECT * FROM certificate_bundle_revisions WHERE id=%s LIMIT 1" in text:
            row = None
            if self.target_exists:
                row = {
                    "id": 9,
                    "bundle_sha256": "bundle",
                    "cert_sha256": "cert",
                    "cert_pem": "CERT",
                    "key_pem": "KEY",
                    "chain_pem": "",
                    "source_kind": "manual",
                    "subject_dn": "",
                    "not_before": "",
                    "not_after": "",
                    "original_filename": "",
                    "original_pfx_blob": None,
                    "created_by": "operator",
                    "created_ts": 123,
                    "is_active": 1,
                }
            return SimpleNamespace(fetchone=lambda: row)
        return SimpleNamespace(fetchone=lambda: None, rowcount=1)


def test_certificate_bundle_activate_checks_target_before_deactivating_current(
    monkeypatch,
) -> None:
    store = CertificateBundleStore()
    calls: list[str] = []

    monkeypatch.setattr(store, "init_db", lambda: None)
    monkeypatch.setattr(
        store, "_connect", lambda: _ActivationConn(calls, target_exists=False)
    )

    try:
        store.activate_revision(404)
    except ValueError as exc:
        assert "Certificate bundle revision 404 was not found" in str(exc)
    else:  # pragma: no cover - defensive assertion
        msg = "expected missing certificate bundle activation to fail"
        raise AssertionError(msg)

    assert not any("SET is_active=0" in call for call in calls)


def test_certificate_bundle_activate_switches_active_revision(monkeypatch) -> None:
    store = CertificateBundleStore()
    calls: list[str] = []

    monkeypatch.setattr(store, "init_db", lambda: None)
    monkeypatch.setattr(
        store, "_connect", lambda: _ActivationConn(calls, target_exists=True)
    )

    revision = store.activate_revision(9)

    assert revision.revision_id == 9
    assert any("SET is_active=0" in call for call in calls)
    assert any("SET is_active=1" in call for call in calls)


def test_certificate_bundle_latest_apply_can_filter_by_revision(monkeypatch) -> None:
    store = CertificateBundleStore()
    calls: list[tuple[str, tuple[object, ...]]] = []

    class Conn:
        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def execute(self, sql, params=()):
            calls.append((str(sql), tuple(params or ())))
            return SimpleNamespace(fetchone=lambda: None)

    monkeypatch.setattr(store, "init_db", lambda: None)
    monkeypatch.setattr(store, "_connect", Conn)

    assert store.latest_apply("edge-2", revision_id=10) is None

    sql, params = calls[-1]
    assert "WHERE proxy_id=%s AND revision_id=%s" in sql
    assert params == ("edge-2", 10)


def test_certificate_bundle_latest_apply_preserves_unscoped_query(monkeypatch) -> None:
    store = CertificateBundleStore()
    calls: list[tuple[str, tuple[object, ...]]] = []

    class Conn:
        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def execute(self, sql, params=()):
            calls.append((str(sql), tuple(params or ())))
            return SimpleNamespace(fetchone=lambda: None)

    monkeypatch.setattr(store, "init_db", lambda: None)
    monkeypatch.setattr(store, "_connect", Conn)

    assert store.latest_apply("edge-2") is None

    sql, params = calls[-1]
    assert "AND revision_id" not in sql
    assert params == ("edge-2",)


class _AdminUiHttpsSettingsConn:
    def __init__(self, row: dict[str, object]) -> None:
        self.row = row

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def execute(self, _sql, _params=()):
        return SimpleNamespace(fetchone=lambda: self.row)


def test_admin_ui_https_settings_normalize_valid_legacy_scalars(monkeypatch) -> None:
    store = CertificateBundleStore()
    row = {
        "enabled": "0",
        "certfile": "/legacy/admin.crt",
        "keyfile": "/legacy/admin.key",
        "san_tokens": "admin.example.test\n192.0.2.10",
        "updated_by": "legacy-admin",
        "updated_ts": "7",
    }
    monkeypatch.setattr(store, "init_db", lambda: None)
    monkeypatch.setattr(store, "_connect", lambda: _AdminUiHttpsSettingsConn(row))

    settings = store.get_admin_ui_https_settings()

    assert settings.enabled is False
    assert settings.certfile == "/legacy/admin.crt"
    assert settings.keyfile == "/legacy/admin.key"
    assert settings.san_tokens == "admin.example.test\n192.0.2.10"
    assert settings.updated_ts == 7


@pytest.mark.parametrize(
    ("field", "value", "detail"),
    [
        ("enabled", "sometimes", "enabled must be boolean"),
        ("certfile", "/certs/admin.crt\x00ignored", "certfile contains unsupported"),
        ("keyfile", object(), "keyfile must be text"),
        ("san_tokens", "admin.example.test\x07", "san_tokens contains unsupported"),
        ("updated_ts", "yesterday", "updated_ts must be a non-negative integer"),
    ],
)
def test_admin_ui_https_settings_reject_malformed_persisted_rows(
    monkeypatch,
    field,
    value,
    detail,
) -> None:
    store = CertificateBundleStore()
    row = {
        "enabled": 1,
        "certfile": "/certs/admin.crt",
        "keyfile": "/certs/admin.key",
        "san_tokens": "admin.example.test",
        "updated_by": "admin",
        "updated_ts": 7,
    }
    row[field] = value
    monkeypatch.setattr(store, "init_db", lambda: None)
    monkeypatch.setattr(store, "_connect", lambda: _AdminUiHttpsSettingsConn(row))

    with pytest.raises(
        certificate_bundles.InvalidAdminUiHttpsSettingsError,
        match=detail,
    ):
        store.get_admin_ui_https_settings()


@pytest.mark.parametrize(
    ("kwargs", "detail"),
    [
        ({"enabled": "false"}, "enabled must be boolean"),
        (
            {"enabled": True, "certfile": "/certs/admin.crt\n--keyfile"},
            "certfile contains unsupported",
        ),
        (
            {"enabled": True, "san_tokens": "admin.example.test\x00evil.test"},
            "san_tokens contains unsupported",
        ),
    ],
)
def test_admin_ui_https_settings_reject_malformed_writes(
    monkeypatch,
    kwargs,
    detail,
) -> None:
    store = CertificateBundleStore()
    monkeypatch.setattr(store, "init_db", lambda: None)

    with pytest.raises(
        certificate_bundles.InvalidAdminUiHttpsSettingsError,
        match=detail,
    ):
        store.set_admin_ui_https_settings(**kwargs)
