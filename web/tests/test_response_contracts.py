from .flask_test_helpers import import_local_app_module, login


def test_proxy_pac_contract_public_and_mimetype():
    app_module = import_local_app_module()
    c = app_module.app.test_client()

    r = c.get("/proxy.pac")
    assert r.status_code == 200
    assert "application/x-ns-proxy-autoconfig" in (r.headers.get("Content-Type", "") or "")
    body = r.data.decode("utf-8", errors="replace")
    assert "FindProxyForURL" in body


def test_api_squid_config_requires_login():
    app_module = import_local_app_module()
    c = app_module.app.test_client()

    r = c.get("/api/squid-config", follow_redirects=False)
    assert r.status_code in (301, 302, 303, 307, 308)
    assert (r.headers.get("Location", "") or "").startswith("/login")


def test_api_squid_config_text_plain_when_logged_in(monkeypatch):
    app_module = import_local_app_module()

    # Avoid touching real Squid config paths during unit tests.
    monkeypatch.setattr(app_module.squid_controller, "get_current_config", lambda: "test-config\n")

    c = app_module.app.test_client()
    login(c)

    r = c.get("/api/squid-config")
    assert r.status_code == 200
    assert (r.headers.get("Content-Type", "") or "").startswith("text/plain")
    assert "Content-Security-Policy" not in r.headers
    assert r.data.decode("utf-8", errors="replace") == "test-config\n"


def test_api_timeseries_requires_login():
    app_module = import_local_app_module()
    c = app_module.app.test_client()

    r = c.get("/api/timeseries", follow_redirects=False)
    assert r.status_code in (301, 302, 303, 307, 308)
    assert (r.headers.get("Location", "") or "").startswith("/login")


def test_api_timeseries_returns_json_when_logged_in(monkeypatch):
    app_module = import_local_app_module()

    class FakeTS:
        def query(self, *, resolution: str, since: int, limit: int):
            return [{"ts": since, "k": "v"}]

    monkeypatch.setattr(app_module, "get_timeseries_store", lambda: FakeTS())

    c = app_module.app.test_client()
    login(c)

    r = c.get("/api/timeseries?resolution=1s&window=10&limit=1")
    assert r.status_code == 200
    assert r.is_json
    data = r.get_json()
    assert data["resolution"] == "1s"
    assert isinstance(data["since"], int)
    assert data["points"]
    assert "Content-Security-Policy" not in r.headers


def test_certs_download_requires_login():
    app_module = import_local_app_module()
    c = app_module.app.test_client()

    r = c.get("/certs/download/ca.crt", follow_redirects=False)
    assert r.status_code in (301, 302, 303, 307, 308)
    assert (r.headers.get("Location", "") or "").startswith("/login")


def test_certs_download_only_allows_ca_crt(monkeypatch, tmp_path):
    app_module = import_local_app_module()

    from services.certificate_bundles import get_certificate_bundles  # type: ignore
    from services.cert_manager import build_certificate_bundle  # type: ignore

    bundle = build_certificate_bundle(
        "-----BEGIN CERTIFICATE-----\nMIIFREMOTE\n-----END CERTIFICATE-----\n",
        "-----BEGIN PRIVATE KEY-----\nMIIEREMOTE\n-----END PRIVATE KEY-----\n",
        source_kind="test",
    )
    get_certificate_bundles().create_revision(bundle, created_by="tester", activate=True)

    c = app_module.app.test_client()
    login(c)

    # Any other filename should 404 (including traversal attempts).
    for bad in ["nope.crt", "../ca.crt", "..%2Fca.crt", "ca.key"]:
        r_bad = c.get(f"/certs/download/{bad}")
        assert r_bad.status_code == 404

    r = c.get("/certs/download/ca.crt")
    assert r.status_code == 200
    disp = r.headers.get("Content-Disposition", "") or ""
    assert "attachment" in disp
    assert "squid-proxy-ca.crt" in disp
    assert "BEGIN CERTIFICATE" in r.data.decode("utf-8", errors="replace")


def test_ssl_errors_export_requires_login():
    app_module = import_local_app_module()
    c = app_module.app.test_client()

    r = c.get("/ssl-errors/export", follow_redirects=False)
    assert r.status_code in (301, 302, 303, 307, 308)
    assert (r.headers.get("Location", "") or "").startswith("/login")


def test_ssl_errors_export_csv_when_logged_in(monkeypatch):
    app_module = import_local_app_module()

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
    login(c)
    r = c.get("/ssl-errors/export?window=300")
    assert r.status_code == 200
    assert (r.headers.get("Content-Type", "") or "").startswith("text/csv")
    body = r.data.decode("utf-8", errors="replace")
    assert "domain;category;reason;count;last_seen;sample" in body
    assert "example.com" in body


def test_live_export_requires_login():
    app_module = import_local_app_module()
    c = app_module.app.test_client()

    r = c.get("/live/export", follow_redirects=False)
    assert r.status_code in (301, 302, 303, 307, 308)
    assert (r.headers.get("Location", "") or "").startswith("/login")


def test_live_export_csv_when_logged_in(monkeypatch):
    app_module = import_local_app_module()

    class FakeLive:
        def export_rows(self, mode: str, *, since: int, search: str, limit: int):
            return [{"k": "v", "n": 1}]

    monkeypatch.setattr(app_module, "get_store", lambda: FakeLive())

    c = app_module.app.test_client()
    login(c)
    r = c.get("/live/export?mode=domains&window=300")
    assert r.status_code == 200
    assert (r.headers.get("Content-Type", "") or "").startswith("text/csv")
    body = r.data.decode("utf-8", errors="replace")
    assert "k;n" in body
    assert "v;1" in body
