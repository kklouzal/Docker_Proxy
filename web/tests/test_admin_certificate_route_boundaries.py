from __future__ import annotations

from io import BytesIO
from types import SimpleNamespace
from typing import NoReturn
from urllib.parse import parse_qs, urlsplit

from .admin_route_test_utils import (
    FakeCertificateBundles,
    FakeRegistry,
    csrf_token,
    load_admin_app,
    login_client,
)


def _location_params(response) -> dict[str, list[str]]:
    return parse_qs(urlsplit(response.headers["Location"]).query)


def _bundle() -> SimpleNamespace:
    return SimpleNamespace(
        fullchain_pem="-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n",
        bundle_sha256="bundle-sha",
        original_pfx_bytes=b"pfx",
    )


def test_certificate_download_allows_only_active_ca_crt(monkeypatch, tmp_path) -> None:
    bundles = FakeCertificateBundles(bundle=_bundle())
    loaded = load_admin_app(monkeypatch, tmp_path, certificate_bundles=bundles)
    client = loaded.module.app.test_client()
    login_client(client)

    ok = client.get("/certs/download/ca.crt")
    assert ok.status_code == 200
    assert (
        ok.headers["Content-Disposition"] == "attachment; filename=squid-proxy-ca.crt"
    )
    assert "BEGIN CERTIFICATE" in ok.get_data(as_text=True)

    for path in (
        "/certs/download/../ca.key",
        "/certs/download/ca.key",
        "/certs/download/subdir/ca.crt",
    ):
        rejected = client.get(path)
        assert rejected.status_code == 404


def test_certificate_download_404s_when_no_active_bundle(monkeypatch, tmp_path) -> None:
    loaded = load_admin_app(
        monkeypatch, tmp_path, certificate_bundles=FakeCertificateBundles(bundle=None)
    )
    client = loaded.module.app.test_client()
    login_client(client)
    assert client.get("/certs/download/ca.crt").status_code == 404


def test_certificate_upload_rejects_missing_and_unsupported_files(
    monkeypatch, tmp_path
) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/certs")

    missing = client.post(
        "/certs/upload", data={"csrf_token": token}, follow_redirects=False
    )
    assert missing.status_code in {301, 302, 303}
    assert _location_params(missing)["msg"] == ["No PFX file selected."]

    token = csrf_token(client, "/certs")
    unsupported = client.post(
        "/certs/upload",
        data={"csrf_token": token, "pfx": (BytesIO(b"not pfx"), "ca.crt")},
        content_type="multipart/form-data",
        follow_redirects=False,
    )
    assert unsupported.status_code in {301, 302, 303}
    assert "Unsupported file type" in _location_params(unsupported)["msg"][0]


def test_certificate_upload_accepts_pfx_and_p12_extensions_case_insensitively(
    monkeypatch, tmp_path
) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    parsed_bundles: list[bytes] = []

    def _parse_pfx_bundle(pfx_bytes: bytes, *, password: str = ""):
        parsed_bundles.append(pfx_bytes)
        return SimpleNamespace(ok=True, bundle=_bundle(), message="parsed")

    monkeypatch.setattr(loaded.module, "parse_pfx_bundle", _parse_pfx_bundle)
    client = loaded.module.app.test_client()
    login_client(client)

    for filename in ("CA.PFX", "bundle.P12", "mixed.Pfx", "mixed.p12"):
        token = csrf_token(client, "/certs")
        response = client.post(
            "/certs/upload",
            data={
                "csrf_token": token,
                "pfx_password": "secret",
                "pfx": (BytesIO(b"fake pfx"), filename),
            },
            content_type="multipart/form-data",
            follow_redirects=False,
        )
        assert response.status_code in {301, 302, 303}
        assert _location_params(response)["ok"] == ["1"]

    assert len(parsed_bundles) == 4
    assert len(loaded.certificate_bundles.created) == 4


def test_certificates_page_shows_admin_ui_https_status(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("ADMIN_UI_HTTPS_ENABLED", "1")
    monkeypatch.setenv("ADMIN_UI_SSL_CERTFILE", "/certs/ui.crt")
    monkeypatch.setenv("ADMIN_UI_SSL_KEYFILE", "/certs/ui.key")
    bundles = FakeCertificateBundles(bundle=_bundle())
    bundles.admin_ui_https_settings = SimpleNamespace(
        enabled=True,
        certfile="/etc/squid/ssl/certs/ca.crt",
        keyfile="/etc/squid/ssl/certs/ca.key",
        updated_by="admin",
        updated_ts=1,
    )
    loaded = load_admin_app(monkeypatch, tmp_path, certificate_bundles=bundles)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/certs")
    html = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "Admin UI HTTPS" in html
    assert "HTTPS enabled" in html
    assert "restart pending" in html
    assert "/certs/ui.crt" in html
    assert "ADMIN_UI_HTTPS_ENABLED=1" in html


def test_admin_ui_https_preference_uses_active_bundle_paths(
    monkeypatch, tmp_path
) -> None:
    bundles = FakeCertificateBundles(bundle=_bundle())
    loaded = load_admin_app(monkeypatch, tmp_path, certificate_bundles=bundles)
    restart_calls = []
    monkeypatch.setattr(
        loaded.module,
        "_restart_admin_ui_web_process",
        lambda: (restart_calls.append(True) or (True, "restart requested")),
    )
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/certs")

    response = client.post(
        "/certs/admin-ui-https",
        data={
            "csrf_token": token,
            "enabled": "1",
            "cert_source": "active_bundle",
        },
        follow_redirects=False,
    )

    assert response.status_code in {301, 302, 303}
    assert _location_params(response)["ok"] == ["1"]
    assert bundles.admin_ui_https_settings.enabled is True
    assert bundles.admin_ui_https_settings.certfile == "/etc/squid/ssl/certs/ca.crt"
    assert bundles.admin_ui_https_settings.keyfile == "/etc/squid/ssl/certs/ca.key"
    assert bundles.admin_ui_https_settings.updated_by == "admin"
    assert restart_calls == [True]


def test_admin_ui_https_preference_reports_restart_failure(
    monkeypatch, tmp_path
) -> None:
    bundles = FakeCertificateBundles(bundle=_bundle())
    loaded = load_admin_app(monkeypatch, tmp_path, certificate_bundles=bundles)
    monkeypatch.setattr(
        loaded.module,
        "_restart_admin_ui_web_process",
        lambda: (False, "supervisorctl is not available in this runtime."),
    )
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/certs")

    response = client.post(
        "/certs/admin-ui-https",
        data={
            "csrf_token": token,
            "enabled": "1",
            "cert_source": "active_bundle",
        },
        follow_redirects=False,
    )

    assert response.status_code in {301, 302, 303}
    assert _location_params(response)["ok"] == ["0"]
    assert "supervisorctl is not available" in _location_params(response)["msg"][0]
    assert bundles.admin_ui_https_settings.enabled is True


def test_admin_ui_https_preference_requires_bundle_for_default_material(
    monkeypatch, tmp_path
) -> None:
    bundles = FakeCertificateBundles(bundle=None)
    loaded = load_admin_app(monkeypatch, tmp_path, certificate_bundles=bundles)
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/certs")

    response = client.post(
        "/certs/admin-ui-https",
        data={
            "csrf_token": token,
            "enabled": "1",
            "cert_source": "active_bundle",
        },
        follow_redirects=False,
    )

    assert response.status_code in {301, 302, 303}
    assert _location_params(response)["ok"] == ["0"]
    assert "Generate or upload a CA bundle" in _location_params(response)["msg"][0]
    assert bundles.admin_ui_https_settings.enabled is False


def test_admin_ui_https_custom_paths_require_cert_and_key(
    monkeypatch, tmp_path
) -> None:
    bundles = FakeCertificateBundles(bundle=_bundle())
    loaded = load_admin_app(monkeypatch, tmp_path, certificate_bundles=bundles)
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/certs")

    response = client.post(
        "/certs/admin-ui-https",
        data={
            "csrf_token": token,
            "enabled": "1",
            "cert_source": "custom",
            "certfile": "/certs/ui.crt",
        },
        follow_redirects=False,
    )

    assert response.status_code in {301, 302, 303}
    assert _location_params(response)["ok"] == ["0"]
    assert "certificate and key paths are required" in _location_params(response)["msg"][0]


def test_certificate_publish_restores_previous_bundle_when_no_reconcile_queued(
    monkeypatch, tmp_path
) -> None:
    previous = SimpleNamespace(
        revision_id=9,
        fullchain_pem="CERT\n",
        bundle_sha256="previous-sha",
        original_pfx_bytes=None,
    )
    bundles = FakeCertificateBundles(bundle=previous)
    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        certificate_bundles=bundles,
        registry=FakeRegistry(["edge-a", "edge-b"]),
    )

    def fail_reconcile(_proxy_id, **_kwargs):
        return SimpleNamespace(
            operation_id=0,
            status="failed",
            detail="operation ledger unavailable",
        )

    monkeypatch.setattr(loaded.module, "request_proxy_reconcile", fail_reconcile)

    with loaded.module.app.test_request_context("/certs/upload", method="POST"):
        loaded.module.session["user"] = "operator"
        ok, detail = loaded.module._publish_certificate_bundle_remote(_bundle())

    assert ok is False
    assert "no proxy reconciliation operations were queued" in detail
    assert "operation ledger unavailable" in detail
    assert "Previous active certificate bundle was restored" in detail
    assert len(bundles.created) == 1
    assert bundles.bundle is previous


def test_certificate_publish_records_previous_bundle_for_operation_revert(
    monkeypatch, tmp_path
) -> None:
    previous = SimpleNamespace(
        revision_id=9,
        fullchain_pem="CERT\n",
        bundle_sha256="previous-sha",
        original_pfx_bytes=None,
    )
    bundles = FakeCertificateBundles(bundle=previous)
    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        certificate_bundles=bundles,
        registry=FakeRegistry(["edge-a", "edge-b"]),
    )

    with loaded.module.app.test_request_context("/certs/upload", method="POST"):
        loaded.module.session["user"] = "operator"
        ok, detail = loaded.module._publish_certificate_bundle_remote(_bundle())

    assert ok is True
    assert "Queued 2 async operations" in detail
    assert [
        (op.proxy_id, op.target_kind, op.target_ref, op.rollback_kind, op.rollback_ref)
        for op in loaded.operation_ledger.operations
    ] == [
        ("edge-a", "certificate_revision", "1", "certificate_revision", "9"),
        ("edge-b", "certificate_revision", "1", "certificate_revision", "9"),
    ]


def test_certificate_publish_reports_partial_proxy_queue_failure(
    monkeypatch, tmp_path
) -> None:
    previous = SimpleNamespace(
        revision_id=9,
        fullchain_pem="CERT\n",
        bundle_sha256="previous-sha",
        original_pfx_bytes=None,
    )
    bundles = FakeCertificateBundles(bundle=previous)
    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        certificate_bundles=bundles,
        registry=FakeRegistry(["edge-a", "edge-b"]),
    )
    original_reconcile = loaded.module.request_proxy_reconcile

    def flaky_reconcile(proxy_id, **kwargs):
        if proxy_id == "edge-b":
            return SimpleNamespace(
                operation_id=0,
                status="failed",
                detail="edge-b operation ledger unavailable",
            )
        return original_reconcile(proxy_id, **kwargs)

    monkeypatch.setattr(loaded.module, "request_proxy_reconcile", flaky_reconcile)

    with loaded.module.app.test_request_context("/certs/upload", method="POST"):
        loaded.module.session["user"] = "operator"
        ok, detail = loaded.module._publish_certificate_bundle_remote(_bundle())

    assert ok is True
    assert "Queued 1/2 async operations" in detail
    assert "First queue failure: edge-b: edge-b operation ledger unavailable" in detail
    assert bundles.bundle is bundles.created[0]
    queued_operations = [
        (op.proxy_id, op.operation_type) for op in loaded.operation_ledger.operations
    ]
    assert queued_operations == [
        ("edge-a", "certificate_apply"),
    ]


def test_revert_certificate_operation_restores_bundle_and_queues_registered_proxies(
    monkeypatch, tmp_path
) -> None:
    previous = SimpleNamespace(
        revision_id=9,
        fullchain_pem="OLD CERT\n",
        bundle_sha256="previous-sha",
        original_pfx_bytes=None,
    )
    current = SimpleNamespace(
        revision_id=12,
        fullchain_pem="NEW CERT\n",
        bundle_sha256="current-sha",
        original_pfx_bytes=None,
    )
    bundles = FakeCertificateBundles(bundle=current)
    bundles._revisions[previous.revision_id] = previous
    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        certificate_bundles=bundles,
        registry=FakeRegistry(["edge-a", "edge-b"]),
    )
    operation = loaded.operation_ledger.create_operation(
        "edge-a",
        operation_type="certificate_apply",
        target_kind="certificate_revision",
        target_ref=current.revision_id,
        rollback_kind="certificate_revision",
        rollback_ref=previous.revision_id,
    )
    operation.status = "failed"

    monkeypatch.setattr(loaded.module, "get_proxy_id", lambda: "edge-a")
    with loaded.module.app.test_request_context(
        f"/operations/{operation.operation_id}/revert",
        method="POST",
    ):
        loaded.module.session["user"] = "operator"
        response = loaded.module.revert_operation(operation.operation_id)

    assert response.status_code == 302
    assert "reverted=1" in response.location
    assert bundles.bundle is previous
    queued_reverts = loaded.operation_ledger.operations[1:]
    assert [
        (op.proxy_id, op.operation_type, op.target_ref, op.rollback_ref, op.force)
        for op in queued_reverts
    ] == [
        ("edge-a", "certificate_revert", "9", "12", True),
        ("edge-b", "certificate_revert", "9", "12", True),
    ]


def test_revert_certificate_operation_keeps_partial_proxy_queue(
    monkeypatch, tmp_path
) -> None:
    previous = SimpleNamespace(
        revision_id=9,
        fullchain_pem="OLD CERT\n",
        bundle_sha256="previous-sha",
        original_pfx_bytes=None,
    )
    current = SimpleNamespace(
        revision_id=12,
        fullchain_pem="NEW CERT\n",
        bundle_sha256="current-sha",
        original_pfx_bytes=None,
    )
    bundles = FakeCertificateBundles(bundle=current)
    bundles._revisions[previous.revision_id] = previous
    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        certificate_bundles=bundles,
        registry=FakeRegistry(["edge-a", "edge-b"]),
    )
    operation = loaded.operation_ledger.create_operation(
        "edge-a",
        operation_type="certificate_apply",
        target_kind="certificate_revision",
        target_ref=current.revision_id,
        rollback_kind="certificate_revision",
        rollback_ref=previous.revision_id,
    )
    operation.status = "failed"
    original_reconcile = loaded.module.request_proxy_reconcile

    def flaky_reconcile(proxy_id, **kwargs):
        if proxy_id == "edge-b":
            msg = "edge-b operation ledger unavailable"
            raise RuntimeError(msg)
        return original_reconcile(proxy_id, **kwargs)

    monkeypatch.setattr(loaded.module, "get_proxy_id", lambda: "edge-a")
    monkeypatch.setattr(loaded.module, "request_proxy_reconcile", flaky_reconcile)
    with loaded.module.app.test_request_context(
        f"/operations/{operation.operation_id}/revert",
        method="POST",
    ):
        loaded.module.session["user"] = "operator"
        response = loaded.module.revert_operation(operation.operation_id)

    assert response.status_code == 302
    assert "reverted=1" in response.location
    assert bundles.bundle is previous
    queued_reverts = loaded.operation_ledger.operations[1:]
    assert [
        (op.proxy_id, op.operation_type, op.target_ref, op.rollback_ref, op.force)
        for op in queued_reverts
    ] == [("edge-a", "certificate_revert", "9", "12", True)]


def test_operations_page_surfaces_revert_success(monkeypatch, tmp_path) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/operations?reverted=1")

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "Revert queued" in body
    assert "A follow-up operation was queued" in body


def test_operations_page_surfaces_revert_errors(monkeypatch, tmp_path) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    login_client(client)

    expected_messages = {
        "not_revertible": "not revertible for this proxy",
        "rollback_missing": "rollback revision is no longer available",
        "revert_failed": "prior active state was preserved when possible",
        "unsupported_rollback": "unsupported rollback target",
    }

    for error, message in expected_messages.items():
        response = client.get(f"/operations?error={error}")

        assert response.status_code == 200
        body = response.get_data(as_text=True)
        assert "Unable to queue revert" in body
        assert message in body


def test_certificate_upload_rejects_body_over_ten_megabytes(
    monkeypatch, tmp_path
) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/certs")
    too_large = b"x" * (10 * 1024 * 1024 + 1)

    response = client.post(
        "/certs/upload",
        data={"csrf_token": token, "pfx": (BytesIO(too_large), "large.pfx")},
        content_type="multipart/form-data",
        follow_redirects=False,
    )

    assert response.status_code in {301, 302, 303}
    assert _location_params(response)["msg"] == ["Upload too large (max 10MB)."]


def test_certificate_upload_parse_failure_is_sanitized(monkeypatch, tmp_path) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)

    def _parse_pfx_bundle(_pfx_bytes: bytes, *, password: str = "") -> NoReturn:
        msg = "openssl failed with password=secret"
        raise RuntimeError(msg)

    monkeypatch.setattr(loaded.module, "parse_pfx_bundle", _parse_pfx_bundle)
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/certs")

    response = client.post(
        "/certs/upload",
        data={"csrf_token": token, "pfx": (BytesIO(b"fake pfx"), "ca.pfx")},
        content_type="multipart/form-data",
        follow_redirects=False,
    )

    assert response.status_code in {301, 302, 303}
    assert "secret" not in _location_params(response)["msg"][0]


def test_certificate_generation_exception_is_sanitized_and_audited(
    monkeypatch, tmp_path
) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)

    def _fail_generate() -> NoReturn:
        msg = "private key password=secret"
        raise RuntimeError(msg)

    monkeypatch.setattr(loaded.module, "generate_self_signed_ca_bundle", _fail_generate)
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/certs")

    response = client.post(
        "/certs/generate", data={"csrf_token": token}, follow_redirects=False
    )

    assert response.status_code in {301, 302, 303}
    assert "secret" not in _location_params(response)["msg"][0]
    assert loaded.audit_store.records[-1]["kind"] == "ca_ensure"
    assert loaded.audit_store.records[-1]["ok"] is False
