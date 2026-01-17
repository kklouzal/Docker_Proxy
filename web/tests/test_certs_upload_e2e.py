import importlib
import io
import os
import sys
import tempfile
from urllib.parse import parse_qs, urlsplit

import pytest


def _import_app_isolated(tmp_path):
    try:
        import flask  # noqa: F401
    except Exception as e:
        pytest.skip(f"Flask not available in this environment: {e}")

    web_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if web_dir not in sys.path:
        sys.path.insert(0, web_dir)

    os.environ["DISABLE_BACKGROUND"] = "1"
    os.environ["AUTH_DB"] = str(tmp_path / "auth.db")
    os.environ["FLASK_SECRET_PATH"] = str(tmp_path / "flask_secret.key")

    if "app" in sys.modules:
        del sys.modules["app"]

    import app as app_module  # type: ignore

    importlib.reload(app_module)
    app_module.app.testing = True
    return app_module


def _get_csrf_token(client) -> str:
    client.get("/login")
    with client.session_transaction() as sess:
        return sess.get("_csrf_token", "") or ""


def _login(client) -> str:
    csrf = _get_csrf_token(client)
    r = client.post(
        "/login",
        data={"username": "admin", "password": "admin", "next": "", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)
    return csrf


def _qs_from_location(resp) -> dict[str, list[str]]:
    loc = resp.headers.get("Location", "") or ""
    return parse_qs(urlsplit(loc).query)


def test_certs_upload_rejects_missing_file(tmp_path):
    app_module = _import_app_isolated(tmp_path)
    c = app_module.app.test_client()
    csrf = _login(c)

    r = c.post(
        "/certs/upload",
        data={"pfx_password": "", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)
    qs = _qs_from_location(r)
    assert qs.get("ok") == ["0"]


def test_certs_upload_rejects_wrong_extension(tmp_path):
    app_module = _import_app_isolated(tmp_path)
    c = app_module.app.test_client()
    csrf = _login(c)

    data = {
        "pfx": (io.BytesIO(b"dummy"), "ca.crt"),
        "pfx_password": "",
        "csrf_token": csrf,
    }
    r = c.post("/certs/upload", data=data, content_type="multipart/form-data", follow_redirects=False)
    assert r.status_code in (301, 302, 303, 307, 308)
    qs = _qs_from_location(r)
    assert qs.get("ok") == ["0"]

def test_certs_upload_rejects_too_large_by_streaming_read(tmp_path):
    app_module = _import_app_isolated(tmp_path)
    c = app_module.app.test_client()
    csrf = _login(c)

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
    qs = _qs_from_location(r)
    assert qs.get("ok") == ["0"]


def test_certs_upload_happy_path_calls_install_and_reload(tmp_path, monkeypatch):
    app_module = _import_app_isolated(tmp_path)

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
    csrf = _login(c)

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

    qs = _qs_from_location(r)
    assert qs.get("ok") == ["1"]
