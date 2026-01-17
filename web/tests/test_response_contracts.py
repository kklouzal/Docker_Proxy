import os
import sys
import tempfile

import pytest


def _import_app_module():
    try:
        import flask  # noqa: F401
    except Exception as e:
        pytest.skip(f"Flask not available in this environment: {e}")

    web_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if web_dir not in sys.path:
        sys.path.insert(0, web_dir)

    os.environ.setdefault("DISABLE_BACKGROUND", "1")
    os.environ.setdefault("AUTH_DB", os.path.join(tempfile.mkdtemp(prefix="sfp_auth_"), "auth.db"))
    os.environ.setdefault(
        "FLASK_SECRET_PATH",
        os.path.join(tempfile.mkdtemp(prefix="sfp_secret_"), "flask_secret.key"),
    )

    import app as app_module  # type: ignore

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


def test_proxy_pac_contract_public_and_mimetype():
    app_module = _import_app_module()
    c = app_module.app.test_client()

    r = c.get("/proxy.pac")
    assert r.status_code == 200
    assert "application/x-ns-proxy-autoconfig" in (r.headers.get("Content-Type", "") or "")
    body = r.data.decode("utf-8", errors="replace")
    assert "FindProxyForURL" in body


def test_api_squid_config_requires_login():
    app_module = _import_app_module()
    c = app_module.app.test_client()

    r = c.get("/api/squid-config", follow_redirects=False)
    assert r.status_code in (301, 302, 303, 307, 308)
    assert (r.headers.get("Location", "") or "").startswith("/login")


def test_api_squid_config_text_plain_when_logged_in(monkeypatch):
    app_module = _import_app_module()

    # Avoid touching real Squid config paths during unit tests.
    monkeypatch.setattr(app_module.squid_controller, "get_current_config", lambda: "test-config\n")

    c = app_module.app.test_client()
    _login(c)

    r = c.get("/api/squid-config")
    assert r.status_code == 200
    assert (r.headers.get("Content-Type", "") or "").startswith("text/plain")
    assert "Content-Security-Policy" not in r.headers
    assert r.data.decode("utf-8", errors="replace") == "test-config\n"


def test_api_timeseries_requires_login():
    app_module = _import_app_module()
    c = app_module.app.test_client()

    r = c.get("/api/timeseries", follow_redirects=False)
    assert r.status_code in (301, 302, 303, 307, 308)
    assert (r.headers.get("Location", "") or "").startswith("/login")


def test_api_timeseries_returns_json_when_logged_in(monkeypatch):
    app_module = _import_app_module()

    class FakeTS:
        def query(self, *, resolution: str, since: int, limit: int):
            return [{"ts": since, "k": "v"}]

    monkeypatch.setattr(app_module, "get_timeseries_store", lambda: FakeTS())

    c = app_module.app.test_client()
    _login(c)

    r = c.get("/api/timeseries?resolution=1s&window=10&limit=1")
    assert r.status_code == 200
    assert r.is_json
    data = r.get_json()
    assert data["resolution"] == "1s"
    assert isinstance(data["since"], int)
    assert data["points"]
    assert "Content-Security-Policy" not in r.headers


def test_certs_download_requires_login():
    app_module = _import_app_module()
    c = app_module.app.test_client()

    r = c.get("/certs/download/ca.crt", follow_redirects=False)
    assert r.status_code in (301, 302, 303, 307, 308)
    assert (r.headers.get("Location", "") or "").startswith("/login")


def test_certs_download_only_allows_ca_crt(monkeypatch, tmp_path):
    app_module = _import_app_module()

    # Replace the global cert manager with a fake so we don't run shell scripts.
    ca_path = tmp_path / "ca.crt"
    ca_path.write_text("dummy", encoding="utf-8")

    class FakeCM:
        ca_cert_path = str(ca_path)

        def ensure_ca(self):
            return str(ca_path)

    monkeypatch.setattr(app_module, "cert_manager", FakeCM())

    c = app_module.app.test_client()
    _login(c)

    # Any other filename should 404 (including traversal attempts).
    for bad in ["nope.crt", "../ca.crt", "..%2Fca.crt", "ca.key"]:
        r_bad = c.get(f"/certs/download/{bad}")
        assert r_bad.status_code == 404

    r = c.get("/certs/download/ca.crt")
    assert r.status_code == 200
    disp = r.headers.get("Content-Disposition", "") or ""
    assert "attachment" in disp
    assert "squid-proxy-ca.crt" in disp


def test_ssl_errors_export_requires_login():
    app_module = _import_app_module()
    c = app_module.app.test_client()

    r = c.get("/ssl-errors/export", follow_redirects=False)
    assert r.status_code in (301, 302, 303, 307, 308)
    assert (r.headers.get("Location", "") or "").startswith("/login")


def test_ssl_errors_export_csv_when_logged_in(monkeypatch):
    app_module = _import_app_module()

    class Row:
        def __init__(self):
            self.domain = "example.com"
            self.category = "tls"
            self.reason = "cert_unknown"
            self.count = 2
            self.last_seen = 123
            self.sample = "https://example.com/"

    class FakeSSL:
        def list_recent(self, *, since: int, search: str, limit: int):
            return [Row()]

    monkeypatch.setattr(app_module, "get_ssl_errors_store", lambda: FakeSSL())

    c = app_module.app.test_client()
    _login(c)
    r = c.get("/ssl-errors/export?window=300")
    assert r.status_code == 200
    assert (r.headers.get("Content-Type", "") or "").startswith("text/csv")
    body = r.data.decode("utf-8", errors="replace")
    assert "domain;category;reason;count;last_seen;sample" in body
    assert "example.com" in body


def test_live_export_requires_login():
    app_module = _import_app_module()
    c = app_module.app.test_client()

    r = c.get("/live/export", follow_redirects=False)
    assert r.status_code in (301, 302, 303, 307, 308)
    assert (r.headers.get("Location", "") or "").startswith("/login")


def test_live_export_csv_when_logged_in(monkeypatch):
    app_module = _import_app_module()

    class FakeLive:
        def export_rows(self, mode: str, *, since: int, search: str, limit: int):
            return [{"k": "v", "n": 1}]

    monkeypatch.setattr(app_module, "get_store", lambda: FakeLive())

    c = app_module.app.test_client()
    _login(c)
    r = c.get("/live/export?mode=domains&window=300")
    assert r.status_code == 200
    assert (r.headers.get("Content-Type", "") or "").startswith("text/csv")
    body = r.data.decode("utf-8", errors="replace")
    assert "k;n" in body
    assert "v;1" in body
