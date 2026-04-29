from .flask_test_helpers import login, redirect_query_params
from .ui_pages_test_support import app_module  # noqa: F401


def test_index_post_actions_work(app_module):
    c = app_module.app.test_client()
    csrf = login(c)

    r1 = c.post("/reload", headers={"X-CSRF-Token": csrf}, data={}, follow_redirects=False)
    assert r1.status_code in (301, 302, 303, 307, 308)

    r2 = c.post("/cache/clear", headers={"X-CSRF-Token": csrf}, data={}, follow_redirects=False)
    assert r2.status_code in (301, 302, 303, 307, 308)

    calls = getattr(app_module, "_test_calls")
    assert calls["reload"] == 1
    assert calls["clear"] == 1


def test_ssl_errors_exclude_posts_domain_redirects_to_observability(app_module):
    c = app_module.app.test_client()
    csrf = login(c)

    r = c.post(
        "/ssl-errors/exclude",
        headers={"X-CSRF-Token": csrf},
        data={"domain": "Example.COM"},
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)

    store = getattr(app_module, "_test_fake_ex_store")
    assert "example.com" in store.added_domains
    qs = redirect_query_params(r)
    assert qs.get("pane") == ["ssl"]
    assert qs.get("q") == ["example.com"]


def test_legacy_ssl_errors_route_redirects_to_observability_ssl(app_module):
    c = app_module.app.test_client()
    login(c)

    r = c.get("/ssl-errors?window=3600&q=Example.COM", follow_redirects=False)
    assert r.status_code in (301, 302, 303, 307, 308)
    qs = redirect_query_params(r)
    assert qs.get("pane") == ["ssl"]
    assert qs.get("window") == ["3600"]
    assert qs.get("q") == ["example.com"]


def test_legacy_socks_route_redirects_to_transport_pane(app_module):
    c = app_module.app.test_client()
    login(c)

    r = c.get("/socks?window=900&q=198.51.100.7", follow_redirects=False)
    assert r.status_code in (301, 302, 303, 307, 308)
    qs = redirect_query_params(r)
    assert qs.get("pane") == ["transport"]
    assert qs.get("window") == ["900"]
    assert qs.get("q") == ["198.51.100.7"]


def test_clamav_page_shows_observability_handoff(app_module, monkeypatch):
    class FakeDiagnostic:
        def icap_summary(self, *, since: int | None = None, service: str = ""):
            return {"events": 1, "avg_icap_time_ms": 87, "max_icap_time_ms": 87}

    monkeypatch.setattr(app_module, "get_diagnostic_store", lambda: FakeDiagnostic())

    c = app_module.app.test_client()
    login(c)

    r = c.get("/clamav?window=3600")
    assert r.status_code == 200
    body = r.data.decode("utf-8", errors="replace")
    assert "Observability" in body
    assert "Open security pane" in body
    assert "Average ICAP time" in body


def test_index_page_shows_observability_shortcuts(app_module):
    c = app_module.app.test_client()
    login(c)

    r = c.get("/")
    assert r.status_code == 200
    body = r.data.decode("utf-8", errors="replace")
    assert "Observability" in body
    assert "SSL incidents" in body
    assert "Transport" in body
    assert "AV controls" in body


def test_exclusions_bulk_add_redirects_with_feedback(app_module):
    c = app_module.app.test_client()
    csrf = login(c)

    r = c.post(
        "/exclusions",
        headers={"X-CSRF-Token": csrf},
        data={
            "action": "add_domain_bulk",
            "domains_bulk": "example.com\ninternal.example\n",
        },
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)

    store = getattr(app_module, "_test_fake_ex_store")
    assert "example.com" in store.added_domains
    assert "internal.example" in store.added_domains
    qs = redirect_query_params(r)
    assert qs.get("bulk_added") == ["2"]


def test_observability_quick_add_exclusion_returns_to_observability(app_module):
    c = app_module.app.test_client()
    csrf = login(c)

    r = c.post(
        "/exclusions",
        headers={"X-CSRF-Token": csrf},
        data={
            "action": "add_domain",
            "domain": "Example.com",
            "return_to": "/observability?pane=destinations&window=3600",
        },
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)

    store = getattr(app_module, "_test_fake_ex_store")
    assert "example.com" in store.added_domains
    location = r.headers.get("Location", "") or ""
    assert location.startswith("/observability?")
    assert "exclude_added=example.com" in location


def test_clamav_page_separates_policy_and_backend_status(app_module):
    c = app_module.app.test_client()
    login(c)

    r = c.get("/clamav")
    assert r.status_code == 200
    body = r.data.decode("utf-8", errors="replace")
    assert "AV c-icap service" in body
    assert "Clamd backend" in body
    assert "Enable changes the Squid adaptation rule only" in body
