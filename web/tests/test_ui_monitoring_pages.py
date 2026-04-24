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


def test_ssl_errors_exclude_posts_domain(app_module):
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


def test_ssl_errors_page_shows_operator_friendly_summary(app_module, monkeypatch):
    from types import SimpleNamespace

    class FakeSSL:
        def list_recent(self, *, since: int, search: str, limit: int):
            return [
                SimpleNamespace(
                    domain="Example.com",
                    category="CERT_VERIFY",
                    reason="certificate verify failed",
                    count=4,
                    first_seen=1713446400,
                    last_seen=1713448200,
                    sample="CONNECT example.com:443",
                ),
                SimpleNamespace(
                    domain="",
                    category="TLS_OTHER",
                    reason="SQUID_TLS_ERR_ACCEPT",
                    count=2,
                    first_seen=1713446500,
                    last_seen=1713448300,
                    sample="error detail: SQUID_TLS_ERR_ACCEPT",
                ),
            ]

        def top_domains(self, *, since: int, search: str, limit: int):
            return [
                {"domain": "example.com", "total": 4, "buckets": 1, "last_seen": 1713448200},
                {"domain": "", "total": 2, "buckets": 1, "last_seen": 1713448300},
            ]

    monkeypatch.setattr(app_module, "get_ssl_errors_store", lambda: FakeSSL())

    c = app_module.app.test_client()
    login(c)

    r = c.get("/ssl-errors?window=3600")
    assert r.status_code == 200
    body = r.data.decode("utf-8", errors="replace")
    assert "At a glance" in body
    assert "Operator guidance" in body
    assert "Treat exclusions as a last-mile workaround" in body
    assert "Trust / chain failure" in body
    assert "Hostname not captured" in body
    assert "Correlate first; there is no domain to exclude yet." in body
    assert "Top domains worth checking" in body
    assert "example.com" in body


def test_live_page_offers_quick_exclusion_actions(app_module, monkeypatch):
    class FakeLive:
        def get_totals(self, *, since: int):
            return {"domain_requests": 10, "domain_hit_requests": 7, "client_requests": 4, "client_hit_requests": 1}

        def list_domains(self, *, sort: str, order: str, limit: int, since: int, search: str):
            return [{"domain": "example.com", "requests": 10, "pct": 100.0, "cache_pct": 70.0, "last_seen": 1713448200}]

        def list_clients(self, *, sort: str, order: str, limit: int, since: int, search: str):
            return []

        def list_client_domains(self, *, ip: str, sort: str):
            return []

        def list_client_not_cached(self, *, ip: str, limit: int):
            return []

        def list_domain_not_cached_reasons(self, *, domain: str, limit: int):
            return []

        def list_global_not_cached_reasons(self, *, limit: int):
            return 0, []

    monkeypatch.setattr(app_module, "get_store", lambda: FakeLive())

    c = app_module.app.test_client()
    login(c)

    r = c.get("/live?mode=domains&window=3600")
    assert r.status_code == 200
    body = r.data.decode("utf-8", errors="replace")
    assert "At a glance" in body
    assert "Add to exclusions" in body
    assert "SSL errors" in body
    assert 'name="return_to"' in body


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


def test_live_quick_add_exclusion_returns_to_live(app_module):
    c = app_module.app.test_client()
    csrf = login(c)

    r = c.post(
        "/exclusions",
        headers={"X-CSRF-Token": csrf},
        data={
            "action": "add_domain",
            "domain": "Example.com",
            "return_to": "/live?mode=domains&window=3600",
        },
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)

    store = getattr(app_module, "_test_fake_ex_store")
    assert "example.com" in store.added_domains
    location = r.headers.get("Location", "") or ""
    assert location.startswith("/live?")
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
