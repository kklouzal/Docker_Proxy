import io
from .flask_test_helpers import import_isolated_app_module, login, redirect_query_params


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
