from __future__ import annotations

from datetime import UTC, datetime, timedelta
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from typing import NoReturn
from urllib.parse import parse_qs, urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

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
    cert_pem, key_pem = _valid_tls_material()
    return SimpleNamespace(
        cert_pem=cert_pem,
        key_pem=key_pem,
        fullchain_pem=cert_pem,
        bundle_sha256="bundle-sha",
        original_pfx_bytes=b"pfx",
    )


def _valid_tls_material() -> tuple[str, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Admin UI HTTPS Test CA")]
    )
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM).decode(),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode(),
    )


def _set_admin_ui_https_material(monkeypatch, loaded, tmp_path) -> tuple[str, str]:
    certfile = tmp_path / "admin-ui.crt"
    keyfile = tmp_path / "admin-ui.key"
    monkeypatch.setattr(loaded.module, "ADMIN_UI_SSL_CERTFILE", str(certfile))
    monkeypatch.setattr(loaded.module, "ADMIN_UI_SSL_KEYFILE", str(keyfile))
    monkeypatch.setattr(loaded.module, "ADMIN_UI_CA_DIR", str(tmp_path))
    return str(certfile), str(keyfile)


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


def _cert_page_status_entries(html: str) -> dict[str, str]:
    entries: dict[str, str] = {}
    marker = '<h3 class="page-section-title">Proxy apply status</h3>'
    section = html.split(marker, 1)[1] if marker in html else html
    for item in section.split('<div class="status-item">')[1:]:
        name = item.split("<strong>", 1)[1].split("</strong>", 1)[0].strip()
        badge = (
            item.split('class="badge', 1)[1]
            .split(">", 1)[1]
            .split("</span>", 1)[0]
            .strip()
        )
        entries[name] = badge
    return entries


def test_certs_page_scopes_proxy_apply_status_to_active_revision(
    monkeypatch, tmp_path
) -> None:
    bundle = SimpleNamespace(
        revision_id=10,
        bundle_sha256="active-sha",
        source_kind="manual",
        cert_sha256="cert-sha",
        created_ts=10,
    )
    bundles = FakeCertificateBundles(bundle=bundle)
    bundles.record_apply_result(
        "default",
        9,
        ok=True,
        detail="old applied",
        bundle_sha256="old-sha",
    )
    loaded = load_admin_app(monkeypatch, tmp_path, certificate_bundles=bundles)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/certs")

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert _cert_page_status_entries(html)["Default"] == "Pending evidence"
    assert "old applied" not in html


def test_certs_page_reports_success_failed_and_divergent_proxy_status_by_active_revision(
    monkeypatch, tmp_path
) -> None:
    bundle = SimpleNamespace(
        revision_id=10,
        bundle_sha256="active-sha",
        source_kind="manual",
        cert_sha256="cert-sha",
        created_ts=10,
    )
    bundles = FakeCertificateBundles(bundle=bundle)
    bundles.record_apply_result(
        "default",
        10,
        ok=True,
        detail="default active applied",
        bundle_sha256="active-sha",
    )
    bundles.record_apply_result(
        "edge-2",
        10,
        ok=False,
        detail="edge failed",
        bundle_sha256="active-sha",
    )
    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        certificate_bundles=bundles,
        registry=FakeRegistry(["default", "edge-2"]),
    )
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/certs")

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    statuses = _cert_page_status_entries(html)
    assert statuses["Default"] == "Apply recorded"
    assert statuses["Edge-2"] == "Apply failed"
    assert "but current runtime bundle SHA evidence is unavailable" in html
    assert "edge failed" in html


def test_certs_page_does_not_report_hash_mismatched_active_revision_as_applied(
    monkeypatch, tmp_path
) -> None:
    bundle = SimpleNamespace(
        revision_id=10,
        bundle_sha256="active-sha",
        source_kind="manual",
        cert_sha256="cert-sha",
        created_ts=10,
    )
    bundles = FakeCertificateBundles(bundle=bundle)
    bundles.record_apply_result(
        "default",
        10,
        ok=True,
        detail="claimed active applied",
        bundle_sha256="different-sha",
    )
    loaded = load_admin_app(monkeypatch, tmp_path, certificate_bundles=bundles)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/certs")

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert _cert_page_status_entries(html)["Default"] == "Stale apply evidence"
    assert "Recorded certificate bundle hash does not match the active bundle." in html


def test_certs_page_reports_runtime_verified_per_selected_proxy_without_leakage(
    monkeypatch, tmp_path
) -> None:
    bundle = SimpleNamespace(
        revision_id=10,
        bundle_sha256="active-sha",
        source_kind="manual",
        cert_sha256="cert-sha",
        created_ts=10,
    )
    bundles = FakeCertificateBundles(bundle=bundle)
    bundles.record_apply_result(
        "edge-b",
        10,
        ok=True,
        detail="edge-b applied",
        bundle_sha256="active-sha",
    )

    class CertProxyClient:
        def get_health(self, proxy_id: object, *_, **__) -> dict[str, object]:
            if str(proxy_id) == "edge-a":
                return {
                    "ok": True,
                    "proxy_id": "edge-a",
                    "active_certificate_revision_id": 10,
                    "active_certificate_sha": "active-sha",
                    "current_certificate_sha": "active-sha",
                }
            return {
                "ok": True,
                "proxy_id": "edge-b",
                "active_certificate_revision_id": 10,
                "active_certificate_sha": "active-sha",
                "current_certificate_sha": "other-sha",
            }

    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        certificate_bundles=bundles,
        registry=FakeRegistry(["edge-a", "edge-b"]),
        proxy_client=CertProxyClient(),
    )
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/certs")

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    statuses = _cert_page_status_entries(html)
    assert statuses["Edge-A"] == "Runtime verified"
    assert statuses["Edge-B"] == "Apply recorded"
    assert "desired=active-sha" in html
    assert "running=other-sha" in html


def test_certs_page_prioritizes_pending_applying_failed_and_superseded_operations(
    monkeypatch, tmp_path
) -> None:
    bundle = SimpleNamespace(
        revision_id=10,
        bundle_sha256="active-sha",
        source_kind="manual",
        cert_sha256="cert-sha",
        created_ts=10,
    )
    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        certificate_bundles=FakeCertificateBundles(bundle=bundle),
        registry=FakeRegistry(["pending", "applying", "failed", "superseded"]),
    )
    for proxy_id, status in (
        ("pending", "pending"),
        ("applying", "applying"),
        ("failed", "failed"),
        ("superseded", "superseded"),
    ):
        op = loaded.operation_ledger.create_operation(
            proxy_id,
            operation_type="certificate_apply",
            target_kind="certificate_revision",
            target_ref=10,
        )
        op.status = status

    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/certs")

    assert response.status_code == 200
    statuses = _cert_page_status_entries(response.get_data(as_text=True))
    assert statuses == {
        "Pending": "Apply pending",
        "Applying": "Apply running",
        "Failed": "Apply failed",
        "Superseded": "Apply superseded",
    }


def test_certs_page_without_active_bundle_does_not_leak_stale_apply_status(
    monkeypatch, tmp_path
) -> None:
    bundles = FakeCertificateBundles(bundle=None)
    bundles.record_apply_result(
        "default",
        9,
        ok=True,
        detail="old applied",
        bundle_sha256="old-sha",
    )
    loaded = load_admin_app(monkeypatch, tmp_path, certificate_bundles=bundles)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/certs")

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert _cert_page_status_entries(html)["Default"] == "No active bundle"
    assert "old applied" not in html


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
    runtime_certfile = tmp_path / "runtime-ui.crt"
    runtime_keyfile = tmp_path / "runtime-ui.key"
    runtime_certfile.write_text("CERT\n", encoding="utf-8")
    runtime_keyfile.write_text("KEY\n", encoding="utf-8")
    monkeypatch.setenv("ADMIN_UI_HTTPS_ENABLED", "1")
    monkeypatch.setenv("ADMIN_UI_SSL_CERTFILE", str(runtime_certfile))
    monkeypatch.setenv("ADMIN_UI_SSL_KEYFILE", str(runtime_keyfile))
    monkeypatch.setenv("ADMIN_UI_EFFECTIVE_HTTPS_ENABLED", "1")
    monkeypatch.setenv("ADMIN_UI_EFFECTIVE_SSL_CERTFILE", str(runtime_certfile))
    monkeypatch.setenv("ADMIN_UI_EFFECTIVE_SSL_KEYFILE", str(runtime_keyfile))
    bundles = FakeCertificateBundles(bundle=_bundle())
    bundles.admin_ui_https_settings = SimpleNamespace(
        enabled=True,
        certfile="/etc/squid/ssl/certs/ca.crt",
        keyfile="/etc/squid/ssl/certs/ca.key",
        san_tokens="proxyadmin.example.com\n192.0.2.10",
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
    assert str(runtime_certfile) in html
    assert "ADMIN_UI_HTTPS_ENABLED=1" in html
    assert "proxyadmin.example.com" in html
    assert "192.0.2.10" in html
    assert "Use custom container paths" not in html
    assert 'name="certfile"' not in html
    assert 'name="keyfile"' not in html


def test_certificates_page_reports_https_fallback_when_material_missing(
    monkeypatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("ADMIN_UI_EFFECTIVE_HTTPS_ENABLED", "0")
    monkeypatch.setenv("ADMIN_UI_EFFECTIVE_HTTPS_SOURCE", "db-missing-material")
    bundles = FakeCertificateBundles(bundle=_bundle())
    bundles.admin_ui_https_settings = SimpleNamespace(
        enabled=True,
        certfile="/etc/squid/ssl/certs/ca.crt",
        keyfile="/etc/squid/ssl/certs/ca.key",
        san_tokens="",
        updated_by="admin",
        updated_ts=1,
    )
    loaded = load_admin_app(monkeypatch, tmp_path, certificate_bundles=bundles)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/certs")
    html = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "HTTP only" in html
    assert "missing TLS material" in html
    assert "started HTTP" in html
    assert "leaf missing" in html
    assert "/etc/squid/ssl/certs/admin-ui.crt" in html
    assert "/etc/squid/ssl/certs/admin-ui.key" in html


def test_certificates_page_empty_admin_ui_sans_are_examples_not_defaults(
    monkeypatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("ADMIN_UI_PUBLIC_HOST", "admin-public.example.test")
    bundles = FakeCertificateBundles(bundle=_bundle())
    bundles.admin_ui_https_settings = SimpleNamespace(
        enabled=False,
        certfile="",
        keyfile="",
        san_tokens="",
        updated_by="admin",
        updated_ts=1,
    )
    loaded = load_admin_app(monkeypatch, tmp_path, certificate_bundles=bundles)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/certs")
    html = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "proxyadmin.ad.kklouzal.com" not in html
    assert "192.168.1.10" not in html
    assert 'placeholder="proxyadmin.example.com&#10;192.0.2.10"' in html
    assert "Configured SANs:</strong> <code class=\"mono\">none</code>" in html
    assert "admin-public.example.test" in html
    assert "localhost" in html
    assert "127.0.0.1" in html


def test_certificates_page_converges_stale_ca_paths_to_leaf_paths(
    monkeypatch,
    tmp_path,
) -> None:
    bundles = FakeCertificateBundles(bundle=_bundle())
    bundles.admin_ui_https_settings = SimpleNamespace(
        enabled=True,
        certfile="/etc/squid/ssl/certs/ca.crt",
        keyfile="/etc/squid/ssl/certs/ca.key",
        san_tokens="proxyadmin.example.com",
        updated_by="admin",
        updated_ts=1,
    )
    loaded = load_admin_app(monkeypatch, tmp_path, certificate_bundles=bundles)
    certfile, keyfile = _set_admin_ui_https_material(monkeypatch, loaded, tmp_path)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/certs")

    assert response.status_code == 200
    assert bundles.admin_ui_https_settings.certfile == certfile
    assert bundles.admin_ui_https_settings.keyfile == keyfile
    assert bundles.admin_ui_https_settings.san_tokens == "proxyadmin.example.com"


def test_admin_ui_https_preference_uses_active_bundle_paths(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setenv("ADMIN_UI_PUBLIC_HOST", "admin-public.example.test")
    bundles = FakeCertificateBundles(bundle=_bundle())
    loaded = load_admin_app(monkeypatch, tmp_path, certificate_bundles=bundles)
    certfile, keyfile = _set_admin_ui_https_material(monkeypatch, loaded, tmp_path)
    restart_calls = []
    monkeypatch.setattr(
        loaded.module,
        "_restart_admin_ui_web_process",
        lambda: restart_calls.append(True) or (True, "restart requested"),
    )
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/certs")

    response = client.post(
        "/certs/admin-ui-https",
        data={
            "csrf_token": token,
            "enabled": "1",
        },
        headers={"X-Forwarded-Host": "admin-request.example.test"},
        follow_redirects=False,
    )

    html = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "Opening the HTTPS Admin UI shortly" in html
    assert "https://localhost/certs" in html
    assert "window.location.assign" in html
    assert bundles.admin_ui_https_settings.enabled is True
    assert bundles.admin_ui_https_settings.certfile == certfile
    assert bundles.admin_ui_https_settings.keyfile == keyfile
    assert bundles.admin_ui_https_settings.san_tokens == ""
    assert bundles.admin_ui_https_settings.updated_by == "admin"
    assert restart_calls == [True]
    assert (
        Path(certfile)
        .read_text(encoding="utf-8")
        .startswith(
            "-----BEGIN CERTIFICATE-----",
        )
    )
    assert (
        Path(keyfile)
        .read_text(encoding="utf-8")
        .startswith(
            "-----BEGIN PRIVATE KEY-----",
        )
    )
    leaf = x509.load_pem_x509_certificate(Path(certfile).read_bytes())
    sans = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "localhost" in sans.get_values_for_type(x509.DNSName)
    assert "admin-ui" in sans.get_values_for_type(x509.DNSName)
    assert "admin-public.example.test" in sans.get_values_for_type(x509.DNSName)
    assert "admin-request.example.test" in sans.get_values_for_type(x509.DNSName)
    assert "127.0.0.1" in [
        str(ip) for ip in sans.get_values_for_type(x509.IPAddress)
    ]


def test_admin_ui_https_preference_persists_configured_sans_in_leaf(
    monkeypatch, tmp_path
) -> None:
    bundles = FakeCertificateBundles(bundle=_bundle())
    loaded = load_admin_app(monkeypatch, tmp_path, certificate_bundles=bundles)
    certfile, _keyfile = _set_admin_ui_https_material(monkeypatch, loaded, tmp_path)
    monkeypatch.setattr(
        loaded.module,
        "_restart_admin_ui_web_process",
        lambda: (True, "restart requested"),
    )
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/certs")

    response = client.post(
        "/certs/admin-ui-https",
        data={
            "csrf_token": token,
            "enabled": "1",
            "san_tokens": "proxyadmin.example.com, 192.0.2.10",
        },
        follow_redirects=False,
    )

    assert response.status_code == 200
    assert bundles.admin_ui_https_settings.san_tokens == (
        "proxyadmin.example.com\n192.0.2.10"
    )
    leaf = x509.load_pem_x509_certificate(Path(certfile).read_bytes())
    sans = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "proxyadmin.example.com" in sans.get_values_for_type(x509.DNSName)
    assert "192.0.2.10" in [
        str(ip) for ip in sans.get_values_for_type(x509.IPAddress)
    ]


def test_admin_ui_https_preference_rejects_invalid_configured_san(
    monkeypatch, tmp_path
) -> None:
    bundles = FakeCertificateBundles(bundle=_bundle())
    loaded = load_admin_app(monkeypatch, tmp_path, certificate_bundles=bundles)
    _set_admin_ui_https_material(monkeypatch, loaded, tmp_path)
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/certs")

    response = client.post(
        "/certs/admin-ui-https",
        data={
            "csrf_token": token,
            "enabled": "1",
            "san_tokens": "https://proxyadmin.example.com/certs",
        },
        follow_redirects=False,
    )

    assert response.status_code in {301, 302, 303}
    assert _location_params(response)["ok"] == ["0"]
    assert "DNS names or IP addresses" in _location_params(response)["msg"][0]
    assert bundles.admin_ui_https_settings.enabled is False


def test_regenerate_admin_ui_https_certificate_preserves_ca_and_uses_saved_sans(
    monkeypatch, tmp_path
) -> None:
    bundles = FakeCertificateBundles(bundle=_bundle())
    bundles.admin_ui_https_settings = SimpleNamespace(
        enabled=True,
        certfile="",
        keyfile="",
        san_tokens="proxyadmin.example.com\n192.0.2.10",
        updated_by="admin",
        updated_ts=1,
    )
    loaded = load_admin_app(monkeypatch, tmp_path, certificate_bundles=bundles)
    certfile, keyfile = _set_admin_ui_https_material(monkeypatch, loaded, tmp_path)
    ca_cert = tmp_path / "ca.crt"
    ca_key = tmp_path / "ca.key"
    ca_cert.write_text(bundles.bundle.cert_pem, encoding="utf-8")
    ca_key.write_text(bundles.bundle.key_pem, encoding="utf-8")
    ca_cert_before = ca_cert.read_text(encoding="utf-8")
    ca_key_before = ca_key.read_text(encoding="utf-8")
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/certs")

    response = client.post(
        "/certs/admin-ui-https/regenerate",
        data={"csrf_token": token},
        follow_redirects=False,
    )

    assert response.status_code in {301, 302, 303}
    assert _location_params(response)["ok"] == ["1"]
    assert Path(certfile).is_file()
    assert Path(keyfile).is_file()
    assert ca_cert.read_text(encoding="utf-8") == ca_cert_before
    assert ca_key.read_text(encoding="utf-8") == ca_key_before
    assert bundles.admin_ui_https_settings.certfile == certfile
    assert bundles.admin_ui_https_settings.keyfile == keyfile
    leaf = x509.load_pem_x509_certificate(Path(certfile).read_bytes())
    sans = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "proxyadmin.example.com" in sans.get_values_for_type(x509.DNSName)
    assert "192.0.2.10" in [
        str(ip) for ip in sans.get_values_for_type(x509.IPAddress)
    ]


def test_admin_ui_https_preference_accepts_hidden_fallback_before_checkbox(
    monkeypatch, tmp_path
) -> None:
    bundles = FakeCertificateBundles(bundle=_bundle())
    loaded = load_admin_app(monkeypatch, tmp_path, certificate_bundles=bundles)
    certfile, keyfile = _set_admin_ui_https_material(monkeypatch, loaded, tmp_path)
    restart_calls = []
    monkeypatch.setattr(
        loaded.module,
        "_restart_admin_ui_web_process",
        lambda: restart_calls.append(True) or (True, "restart requested"),
    )
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/certs")

    response = client.post(
        "/certs/admin-ui-https",
        data={
            "csrf_token": token,
            "enabled": ["0", "1"],
        },
        follow_redirects=False,
    )

    assert response.status_code == 200
    assert "Opening the HTTPS Admin UI shortly" in response.get_data(as_text=True)
    assert bundles.admin_ui_https_settings.enabled is True
    assert bundles.admin_ui_https_settings.certfile == certfile
    assert bundles.admin_ui_https_settings.keyfile == keyfile
    assert restart_calls == [True]


def test_admin_ui_https_preference_uses_current_host_for_continue_link(
    monkeypatch, tmp_path
) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)

    with loaded.module.app.test_request_context(
        "/certs",
        base_url="http://admin.example.test:8443",
    ):
        assert (
            loaded.module._admin_ui_https_next_url()
            == "https://admin.example.test:8443/certs?proxy_id=default"
        )


def test_admin_ui_https_preference_continue_link_sanitizes_host(
    monkeypatch, tmp_path
) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)

    with loaded.module.app.test_request_context(
        "/certs",
        environ_overrides={"HTTP_HOST": "user@example.test:8443"},
    ):
        assert loaded.module._admin_ui_https_next_url().startswith("https://localhost/")


def test_admin_ui_https_preference_continue_link_keeps_ipv6_port(
    monkeypatch, tmp_path
) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)

    with loaded.module.app.test_request_context(
        "/certs",
        base_url="http://[2001:db8::10]:8443",
    ):
        assert (
            loaded.module._admin_ui_https_next_url()
            == "https://[2001:db8::10]:8443/certs?proxy_id=default"
        )


def test_admin_ui_https_preference_treats_hidden_fallback_only_as_disabled(
    monkeypatch, tmp_path
) -> None:
    bundles = FakeCertificateBundles(bundle=_bundle())
    bundles.admin_ui_https_settings = SimpleNamespace(
        enabled=True,
        certfile="/etc/squid/ssl/certs/ca.crt",
        keyfile="/etc/squid/ssl/certs/ca.key",
        san_tokens="",
        updated_by="admin",
        updated_ts=1,
    )
    loaded = load_admin_app(monkeypatch, tmp_path, certificate_bundles=bundles)
    restart_calls = []
    monkeypatch.setattr(
        loaded.module,
        "_restart_admin_ui_web_process",
        lambda: restart_calls.append(True) or (True, "restart requested"),
    )
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/certs")

    response = client.post(
        "/certs/admin-ui-https",
        data={
            "csrf_token": token,
            "enabled": "0",
        },
        follow_redirects=False,
    )

    assert response.status_code in {301, 302, 303}
    params = _location_params(response)
    assert params["ok"] == ["1"]
    assert "admin_ui_https_next" not in params
    assert bundles.admin_ui_https_settings.enabled is False
    assert bundles.admin_ui_https_settings.certfile == ""
    assert bundles.admin_ui_https_settings.keyfile == ""
    assert restart_calls == [True]


def test_certificates_page_ignores_https_redirect_query(monkeypatch, tmp_path) -> None:
    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        certificate_bundles=FakeCertificateBundles(bundle=_bundle()),
    )
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get(
        "/certs?ok=1&msg=Saved&admin_ui_https_next=https://evil.example/phish",
    )
    html = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "Opening the HTTPS Admin UI shortly" not in html


def test_admin_ui_https_preference_reports_restart_failure(
    monkeypatch, tmp_path
) -> None:
    bundles = FakeCertificateBundles(bundle=_bundle())
    loaded = load_admin_app(monkeypatch, tmp_path, certificate_bundles=bundles)
    _set_admin_ui_https_material(monkeypatch, loaded, tmp_path)
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
        },
        follow_redirects=False,
    )

    assert response.status_code in {301, 302, 303}
    params = _location_params(response)
    assert params["ok"] == ["0"]
    assert "admin_ui_https_next" not in params
    assert "supervisorctl is not available" in params["msg"][0]
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
        },
        follow_redirects=False,
    )

    assert response.status_code in {301, 302, 303}
    assert _location_params(response)["ok"] == ["0"]
    assert (
        "Generate or upload an SSL inspection CA bundle"
        in _location_params(response)["msg"][0]
    )
    assert bundles.admin_ui_https_settings.enabled is False


def test_admin_ui_https_preference_requires_mounted_active_material(
    monkeypatch, tmp_path
) -> None:
    bundles = FakeCertificateBundles(bundle=_bundle())
    loaded = load_admin_app(monkeypatch, tmp_path, certificate_bundles=bundles)
    monkeypatch.setattr(
        loaded.module,
        "ADMIN_UI_SSL_CERTFILE",
        str(tmp_path / "missing-ca.crt"),
    )
    monkeypatch.setattr(
        loaded.module,
        "ADMIN_UI_SSL_KEYFILE",
        str(tmp_path / "missing-ca.key"),
    )
    monkeypatch.setattr(loaded.module, "ADMIN_UI_CA_DIR", str(tmp_path))
    restart_calls = []
    monkeypatch.setattr(
        loaded.module,
        "_restart_admin_ui_web_process",
        lambda: restart_calls.append(True) or (True, "restart requested"),
    )
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/certs")

    response = client.post(
        "/certs/admin-ui-https",
        data={
            "csrf_token": token,
            "enabled": "1",
        },
        follow_redirects=False,
    )

    assert response.status_code in {301, 302, 303}
    assert _location_params(response)["ok"] == ["0"]
    assert (
        "requires the generated Admin UI server certificate and key"
        in (_location_params(response)["msg"][0])
    )
    assert bundles.admin_ui_https_settings.enabled is False
    assert restart_calls == []


def test_admin_ui_https_preference_rejects_empty_active_material(
    monkeypatch, tmp_path
) -> None:
    bundles = FakeCertificateBundles(bundle=_bundle())
    loaded = load_admin_app(monkeypatch, tmp_path, certificate_bundles=bundles)
    certfile = tmp_path / "empty-ca.crt"
    keyfile = tmp_path / "empty-ca.key"
    certfile.write_bytes(b"")
    keyfile.write_bytes(b"")
    monkeypatch.setattr(loaded.module, "ADMIN_UI_SSL_CERTFILE", str(certfile))
    monkeypatch.setattr(loaded.module, "ADMIN_UI_SSL_KEYFILE", str(keyfile))
    monkeypatch.setattr(loaded.module, "ADMIN_UI_CA_DIR", str(tmp_path))
    restart_calls = []
    monkeypatch.setattr(
        loaded.module,
        "_restart_admin_ui_web_process",
        lambda: restart_calls.append(True) or (True, "restart requested"),
    )
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/certs")

    response = client.post(
        "/certs/admin-ui-https",
        data={"csrf_token": token, "enabled": "1"},
        follow_redirects=False,
    )

    assert response.status_code in {301, 302, 303}
    assert _location_params(response)["ok"] == ["0"]
    assert "valid PEM material" in _location_params(response)["msg"][0]
    assert "certificate file is empty" in _location_params(response)["msg"][0]
    assert bundles.admin_ui_https_settings.enabled is False
    assert restart_calls == []


def test_admin_ui_https_preference_rejects_invalid_active_material(
    monkeypatch, tmp_path
) -> None:
    bundles = FakeCertificateBundles(bundle=_bundle())
    loaded = load_admin_app(monkeypatch, tmp_path, certificate_bundles=bundles)
    certfile = tmp_path / "invalid-ca.crt"
    keyfile = tmp_path / "invalid-ca.key"
    certfile.write_text("not a certificate\n", encoding="utf-8")
    keyfile.write_text("not a private key\n", encoding="utf-8")
    monkeypatch.setattr(loaded.module, "ADMIN_UI_SSL_CERTFILE", str(certfile))
    monkeypatch.setattr(loaded.module, "ADMIN_UI_SSL_KEYFILE", str(keyfile))
    monkeypatch.setattr(loaded.module, "ADMIN_UI_CA_DIR", str(tmp_path))
    restart_calls = []
    monkeypatch.setattr(
        loaded.module,
        "_restart_admin_ui_web_process",
        lambda: restart_calls.append(True) or (True, "restart requested"),
    )
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/certs")

    response = client.post(
        "/certs/admin-ui-https",
        data={"csrf_token": token, "enabled": "1"},
        follow_redirects=False,
    )

    assert response.status_code in {301, 302, 303}
    assert _location_params(response)["ok"] == ["0"]
    assert "valid PEM material" in _location_params(response)["msg"][0]
    assert "not valid PEM material" in _location_params(response)["msg"][0]
    assert bundles.admin_ui_https_settings.enabled is False
    assert restart_calls == []


def test_admin_ui_https_ignores_posted_custom_paths_for_active_bundle(
    monkeypatch, tmp_path
) -> None:
    bundles = FakeCertificateBundles(bundle=_bundle())
    loaded = load_admin_app(monkeypatch, tmp_path, certificate_bundles=bundles)
    certfile, keyfile = _set_admin_ui_https_material(monkeypatch, loaded, tmp_path)
    monkeypatch.setattr(
        loaded.module,
        "_restart_admin_ui_web_process",
        lambda: (True, "restart requested"),
    )
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
            "keyfile": "/certs/ui.key",
        },
        follow_redirects=False,
    )

    assert response.status_code == 200
    assert "Opening the HTTPS Admin UI shortly" in response.get_data(as_text=True)
    assert bundles.admin_ui_https_settings.enabled is True
    assert bundles.admin_ui_https_settings.certfile == certfile
    assert bundles.admin_ui_https_settings.keyfile == keyfile


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


def test_certificate_publish_rejects_zero_registered_proxies_and_restores_previous(
    monkeypatch,
    tmp_path,
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
        registry=FakeRegistry([]),
    )

    with loaded.module.app.test_request_context("/certs/upload", method="POST"):
        loaded.module.session["user"] = "operator"
        ok, detail = loaded.module._publish_certificate_bundle_remote(_bundle())

    assert ok is False
    assert (
        detail
        == "Certificate revision 1 saved, but no registered proxies were available; "
        "certificate bundle was not activated.\n"
        "Previous active certificate bundle was restored."
    )
    assert loaded.operation_ledger.operations == []
    assert len(bundles.created) == 1
    assert bundles._revisions[1] is bundles.created[0]
    assert bundles.bundle is previous


def test_certificate_publish_rejects_zero_registered_proxies_without_previous_active(
    monkeypatch,
    tmp_path,
) -> None:
    bundles = FakeCertificateBundles(bundle=None)
    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        certificate_bundles=bundles,
        registry=FakeRegistry([]),
    )

    with loaded.module.app.test_request_context("/certs/upload", method="POST"):
        loaded.module.session["user"] = "operator"
        ok, detail = loaded.module._publish_certificate_bundle_remote(_bundle())

    assert ok is False
    assert (
        detail
        == "Certificate revision 1 saved, but no registered proxies were available; "
        "certificate bundle was not activated.\n"
        "Unqueued certificate bundle revision was left inactive."
    )
    assert loaded.operation_ledger.operations == []
    assert len(bundles.created) == 1
    assert bundles._revisions[1] is bundles.created[0]
    assert bundles.bundle is None


def test_certificate_generate_audits_zero_registered_proxy_failure(
    monkeypatch,
    tmp_path,
) -> None:
    bundles = FakeCertificateBundles(bundle=None)
    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        certificate_bundles=bundles,
        registry=FakeRegistry([]),
    )
    expected_detail = (
        "Certificate revision 1 saved, but no registered proxies were available; "
        "certificate bundle was not activated.\n"
        "Unqueued certificate bundle revision was left inactive."
    )

    def generate_bundle():
        return _bundle()

    monkeypatch.setattr(
        loaded.module,
        "generate_self_signed_ca_bundle",
        generate_bundle,
    )
    monkeypatch.setattr(loaded.module, "_request_needs_proxy_context", lambda: False)
    client = loaded.module.app.test_client()
    login_client(client)
    with client.session_transaction() as sess:
        token = sess["_csrf_token"]

    response = client.post(
        "/certs/generate",
        data={"csrf_token": token},
        follow_redirects=False,
    )

    assert response.status_code in {301, 302, 303}
    params = _location_params(response)
    assert params["ok"] == ["0"]
    assert params["msg"] == [expected_detail]
    assert bundles.bundle is None
    assert loaded.operation_ledger.operations == []
    assert loaded.audit_store.records[-1]["kind"] == "ca_ensure"
    assert loaded.audit_store.records[-1]["ok"] is False
    assert loaded.audit_store.records[-1]["detail"] == expected_detail


def test_certificate_upload_audits_zero_registered_proxy_failure(
    monkeypatch,
    tmp_path,
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
        registry=FakeRegistry([]),
    )
    expected_detail = (
        "Certificate revision 1 saved, but no registered proxies were available; "
        "certificate bundle was not activated.\n"
        "Previous active certificate bundle was restored."
    )

    def _parse_pfx_bundle(_pfx_bytes: bytes, *, password: str = ""):
        return SimpleNamespace(ok=True, bundle=_bundle(), message="parsed")

    monkeypatch.setattr(loaded.module, "parse_pfx_bundle", _parse_pfx_bundle)
    monkeypatch.setattr(loaded.module, "_request_needs_proxy_context", lambda: False)
    client = loaded.module.app.test_client()
    login_client(client)
    with client.session_transaction() as sess:
        token = sess["_csrf_token"]

    response = client.post(
        "/certs/upload",
        data={
            "csrf_token": token,
            "pfx_password": "secret",
            "pfx": (BytesIO(b"fake pfx"), "bundle.pfx"),
        },
        content_type="multipart/form-data",
        follow_redirects=False,
    )

    assert response.status_code in {301, 302, 303}
    params = _location_params(response)
    assert params["ok"] == ["0"]
    assert params["msg"] == [expected_detail]
    assert bundles.bundle is previous
    assert loaded.operation_ledger.operations == []
    assert loaded.audit_store.records[-1]["kind"] == "ca_upload_pfx"
    assert loaded.audit_store.records[-1]["ok"] is False
    assert loaded.audit_store.records[-1]["detail"] == expected_detail


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
    assert bundles.bundle is bundles.created[0]
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
