import io
from .flask_test_helpers import import_isolated_app_module, login, redirect_query_params


CERT_PEM = "-----BEGIN CERTIFICATE-----\nMIIFLOCAL\n-----END CERTIFICATE-----\n"
KEY_PEM = "-----BEGIN PRIVATE KEY-----\nMIIELOCAL\n-----END PRIVATE KEY-----\n"


def test_certs_upload_rejects_missing_file(tmp_path):
    app_module = import_isolated_app_module(tmp_path)
    c = app_module.app.test_client()
    csrf = login(c)

    r = c.post(
        "/certs/upload",
        data={"pfx_password": "", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)
    qs = redirect_query_params(r)
    assert qs.get("ok") == ["0"]


def test_certs_upload_rejects_wrong_extension(tmp_path):
    app_module = import_isolated_app_module(tmp_path)
    c = app_module.app.test_client()
    csrf = login(c)

    data = {
        "pfx": (io.BytesIO(b"dummy"), "ca.crt"),
        "pfx_password": "",
        "csrf_token": csrf,
    }
    r = c.post("/certs/upload", data=data, content_type="multipart/form-data", follow_redirects=False)
    assert r.status_code in (301, 302, 303, 307, 308)
    qs = redirect_query_params(r)
    assert qs.get("ok") == ["0"]

def test_certs_upload_rejects_too_large_by_streaming_read(tmp_path):
    app_module = import_isolated_app_module(tmp_path)
    c = app_module.app.test_client()
    csrf = login(c)

    # Exercise the streaming hard-cap (read loop) by uploading >10MB.
    big = b"a" * (10 * 1024 * 1024 + 1)
    r = c.post(
        "/certs/upload",
        data={
            "pfx": (io.BytesIO(big), "ca.pfx"),
            "pfx_password": "",
            "csrf_token": csrf,
        },
        content_type="multipart/form-data",
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)
    qs = redirect_query_params(r)
    assert qs.get("ok") == ["0"]


def test_certs_upload_happy_path_calls_install_and_reload(tmp_path, monkeypatch):
    app_module = import_isolated_app_module(tmp_path)

    calls = {"install": 0, "reload": 0}

    class FakeResult:
        ok = True
        message = "ok"

    def fake_install(_ca_dir: str, _pfx_bytes: bytes, password: str = ""):
        assert password == "secret"
        calls["install"] += 1
        return FakeResult()

    def fake_reload():
        calls["reload"] += 1

    monkeypatch.setattr(app_module, "install_pfx_as_ca", fake_install)
    monkeypatch.setattr(app_module.squid_controller, "reload_squid", fake_reload)

    c = app_module.app.test_client()
    csrf = login(c)

    r = c.post(
        "/certs/upload",
        data={
            "pfx": (io.BytesIO(b"pfx-bytes"), "ca.pfx"),
            "pfx_password": "secret",
            "csrf_token": csrf,
        },
        content_type="multipart/form-data",
        follow_redirects=False,
    )

    assert r.status_code in (301, 302, 303, 307, 308)
    assert calls["install"] == 1
    assert calls["reload"] == 1

    qs = redirect_query_params(r)
    assert qs.get("ok") == ["1"]


def test_certs_generate_local_decodes_reload_tuple_output(tmp_path, monkeypatch):
    from services.cert_manager import build_certificate_bundle  # type: ignore

    app_module = import_isolated_app_module(tmp_path)
    bundle = build_certificate_bundle(CERT_PEM, KEY_PEM, source_kind="self_signed")

    monkeypatch.setattr(app_module, "generate_self_signed_ca_bundle", lambda: bundle)
    monkeypatch.setattr(app_module, "materialize_certificate_bundle", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(app_module.squid_controller, "reload_squid", lambda: (b"reload ok\n", b""))

    c = app_module.app.test_client()
    csrf = login(c)

    r = c.post(
        "/certs/generate",
        data={"csrf_token": csrf},
        follow_redirects=False,
    )

    assert r.status_code in (301, 302, 303, 307, 308)
    qs = redirect_query_params(r)
    assert qs.get("ok") == ["1"]
    assert qs.get("msg") == ["reload ok"]


def test_certs_upload_happy_path_decodes_reload_tuple_output(tmp_path, monkeypatch):
    app_module = import_isolated_app_module(tmp_path)

    class FakeResult:
        ok = True
        message = "ok"
        bundle = None

    monkeypatch.setattr(app_module, "install_pfx_as_ca", lambda *_args, **_kwargs: FakeResult())
    monkeypatch.setattr(app_module.squid_controller, "reload_squid", lambda: (b"reload ok\n", b""))

    c = app_module.app.test_client()
    csrf = login(c)

    r = c.post(
        "/certs/upload",
        data={
            "pfx": (io.BytesIO(b"pfx-bytes"), "ca.pfx"),
            "pfx_password": "secret",
            "csrf_token": csrf,
        },
        content_type="multipart/form-data",
        follow_redirects=False,
    )

    assert r.status_code in (301, 302, 303, 307, 308)
    qs = redirect_query_params(r)
    assert qs.get("ok") == ["1"]
    assert qs.get("msg") == ["reload ok"]
