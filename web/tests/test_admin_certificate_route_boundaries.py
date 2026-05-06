from __future__ import annotations

from io import BytesIO
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

from .admin_route_test_utils import FakeCertificateBundles, csrf_token, load_admin_app, login_client


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
    assert ok.headers["Content-Disposition"] == "attachment; filename=squid-proxy-ca.crt"
    assert "BEGIN CERTIFICATE" in ok.get_data(as_text=True)

    for path in ("/certs/download/../ca.key", "/certs/download/ca.key", "/certs/download/subdir/ca.crt"):
        rejected = client.get(path)
        assert rejected.status_code == 404


def test_certificate_download_404s_when_no_active_bundle(monkeypatch, tmp_path) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path, certificate_bundles=FakeCertificateBundles(bundle=None))
    client = loaded.module.app.test_client()
    login_client(client)
    assert client.get("/certs/download/ca.crt").status_code == 404


def test_certificate_upload_rejects_missing_and_unsupported_files(monkeypatch, tmp_path) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/certs")

    missing = client.post("/certs/upload", data={"csrf_token": token}, follow_redirects=False)
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


def test_certificate_upload_accepts_pfx_and_p12_extensions_case_insensitively(monkeypatch, tmp_path) -> None:
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
            data={"csrf_token": token, "pfx_password": "secret", "pfx": (BytesIO(b"fake pfx"), filename)},
            content_type="multipart/form-data",
            follow_redirects=False,
        )
        assert response.status_code in {301, 302, 303}
        assert _location_params(response)["ok"] == ["1"]

    assert len(parsed_bundles) == 4
    assert len(loaded.certificate_bundles.created) == 4


def test_certificate_upload_rejects_body_over_ten_megabytes(monkeypatch, tmp_path) -> None:
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

    def _parse_pfx_bundle(_pfx_bytes: bytes, *, password: str = ""):
        raise RuntimeError("openssl failed with password=secret")

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


def test_certificate_generation_exception_is_sanitized_and_audited(monkeypatch, tmp_path) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)

    def _fail_generate():
        raise RuntimeError("private key password=secret")

    monkeypatch.setattr(loaded.module, "generate_self_signed_ca_bundle", _fail_generate)
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/certs")

    response = client.post("/certs/generate", data={"csrf_token": token}, follow_redirects=False)

    assert response.status_code in {301, 302, 303}
    assert "secret" not in _location_params(response)["msg"][0]
    assert loaded.audit_store.records[-1]["kind"] == "ca_ensure"
    assert loaded.audit_store.records[-1]["ok"] is False
