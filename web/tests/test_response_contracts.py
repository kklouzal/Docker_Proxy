from .flask_test_helpers import import_local_app_module, login
from .route_test_support import FakeSquidController


def _configure_app_services(app_module, **overrides):
    app_module.reset_app_runtime_services_for_testing()
    return app_module.configure_app_runtime_services_for_testing(**overrides)


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


def test_api_squid_config_text_plain_when_logged_in():
    app_module = import_local_app_module()
    controller = FakeSquidController({"reload": 0, "clear": 0, "apply": 0})
    controller.current_config = "test-config\n"
    _configure_app_services(app_module, controller=controller)

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

    _configure_app_services(app_module, get_timeseries_store=lambda: FakeTS())

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

    class FakeQueries:
        def ssl_overview(self, *, since: int, search: str, limit: int):
            return {
                "rows": [
                    {
                        "domain": "example.com",
                        "category": "tls",
                        "category_label": "TLS issue",
                        "reason": "cert_unknown",
                        "count": 2,
                        "first_seen": 100,
                        "last_seen": 123,
                    }
                ]
            }

    _configure_app_services(app_module, get_observability_queries=lambda: FakeQueries())

    c = app_module.app.test_client()
    login(c)
    r = c.get("/ssl-errors/export?window=300", follow_redirects=True)
    assert r.status_code == 200
    assert (r.headers.get("Content-Type", "") or "").startswith("text/csv")
    body = r.data.decode("utf-8", errors="replace")
    assert "domain;category;category_label;reason;count;first_seen;last_seen" in body
    assert "example.com" in body


