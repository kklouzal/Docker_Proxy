import pytest

from .flask_test_helpers import import_local_app_module, login, redirect_query_params
from .route_test_support import install_common_ui_test_doubles


@pytest.fixture()
def app_module(monkeypatch):
    app_module = import_local_app_module()
    return install_common_ui_test_doubles(monkeypatch, app_module)


@pytest.mark.parametrize(
    "path, expected",
    [
        ("/", "Status"),
        ("/live", "Live"),
        ("/ssl-errors", "SSL Errors"),
        ("/squid/config", "Squid"),
        ("/exclusions", "Exclusions"),
        ("/certs", "Certificates"),
        ("/adblock", "Ad"),
        ("/webfilter", "Web"),
        ("/clamav", "Clam"),
        ("/sslfilter", "SSL"),
        ("/socks", "SOCKS"),
        ("/pac", "PAC"),
        ("/administration", "Administration"),
    ],
)
def test_ui_pages_render_and_include_csrf_meta(app_module, path: str, expected: str):
    c = app_module.app.test_client()
    login(c)

    r = c.get(path)
    assert r.status_code == 200
    body = r.data.decode("utf-8", errors="replace")
    assert "<meta name=\"csrf-token\"" in body
    assert expected.lower() in body.lower()


def test_logged_in_layout_renders_shell_accessibility_hooks(app_module):
    c = app_module.app.test_client()
    login(c)

    r = c.get("/")
    assert r.status_code == 200
    body = r.data.decode("utf-8", errors="replace")
    assert 'class="skip-link"' in body
    assert 'id="site-header"' in body
    assert 'id="context-strip-slot"' in body
    assert 'id="primary-nav"' in body
    assert 'id="nav-toggle"' in body
    assert 'class="nav-user"' not in body


def test_login_page_uses_updated_auth_shell(app_module):
    c = app_module.app.test_client()

    r = c.get("/login")
    assert r.status_code == 200
    body = r.data.decode("utf-8", errors="replace")
    assert "Secure access" in body
    assert 'class="auth-shell"' in body
    assert "Default credentials for first-run local setups" in body


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


def test_webfilter_test_domain_json(app_module):
    c = app_module.app.test_client()
    csrf = login(c)

    r = c.post("/webfilter/test", headers={"X-CSRF-Token": csrf}, json={"domain": "example.com"})
    assert r.status_code == 200
    assert r.is_json
    data = r.get_json()
    assert data["ok"] is True
    assert data["domain"] == "example.com"


def test_clamav_toggle_calls_apply_config(app_module):
    c = app_module.app.test_client()
    csrf = login(c)

    r = c.post("/clamav/toggle", headers={"X-CSRF-Token": csrf}, data={"action": "enable"}, follow_redirects=False)
    assert r.status_code in (301, 302, 303, 307, 308)

    calls = getattr(app_module, "_test_calls")
    assert calls["apply"] >= 1


def test_clamav_page_separates_policy_and_backend_status(app_module):
    c = app_module.app.test_client()
    login(c)

    r = c.get("/clamav")
    assert r.status_code == 200
    body = r.data.decode("utf-8", errors="replace")
    assert "AV c-icap service" in body
    assert "Clamd backend" in body
    assert "Enable changes the Squid adaptation rule only" in body


def test_pac_builder_create_profile(app_module):
    c = app_module.app.test_client()
    csrf = login(c)

    r = c.post(
        "/pac",
        headers={"X-CSRF-Token": csrf},
        data={
            "action": "create",
            "name": "test",
            "client_cidr": "",
            "socks_enabled": "",
            "socks_host": "",
            "socks_port": "1080",
            "direct_domains": "example.com\n",
            "direct_dst_nets": "",
        },
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)


def test_adblock_save_lists_updates_enabled_map(app_module):
    c = app_module.app.test_client()
    csrf = login(c)

    store = getattr(app_module, "_test_adblock_store")
    assert store.list_statuses(), "expected at least one adblock list status"

    r = c.post(
        "/adblock",
        headers={"X-CSRF-Token": csrf},
        data={"action": "save_lists", "enabled_list1": "on"},
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)
    assert store._enabled_map == {"list1": True}


def test_adblock_save_settings_persists_values(app_module):
    c = app_module.app.test_client()
    csrf = login(c)

    store = getattr(app_module, "_test_adblock_store")
    r = c.post(
        "/adblock",
        headers={"X-CSRF-Token": csrf},
        data={
            "action": "save_settings",
            "adblock_enabled": "on",
            "cache_ttl": "120",
            "cache_max": "999",
        },
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)
    assert store._settings == {"enabled": True, "cache_ttl": 120, "cache_max": 999}


def test_adblock_refresh_sets_flag_and_redirects(app_module):
    c = app_module.app.test_client()
    csrf = login(c)

    store = getattr(app_module, "_test_adblock_store")
    store._statuses[0].enabled = True

    r = c.post(
        "/adblock",
        headers={"X-CSRF-Token": csrf},
        data={"action": "refresh"},
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)
    qs = redirect_query_params(r)
    assert qs.get("refresh_requested") == ["1"]
    assert store._refresh is True


def test_adblock_refresh_without_enabled_lists_redirects_notice(app_module):
    c = app_module.app.test_client()
    csrf = login(c)

    store = getattr(app_module, "_test_adblock_store")
    store._statuses[0].enabled = False
    store._refresh = False

    r = c.post(
        "/adblock",
        headers={"X-CSRF-Token": csrf},
        data={"action": "refresh"},
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)
    qs = redirect_query_params(r)
    assert qs.get("refresh_no_lists") == ["1"]
    assert store._refresh is False


def test_adblock_flush_cache_sets_flag_and_redirects(app_module):
    c = app_module.app.test_client()
    csrf = login(c)

    store = getattr(app_module, "_test_adblock_store")
    store._flush = False
    r = c.post(
        "/adblock",
        headers={"X-CSRF-Token": csrf},
        data={"action": "flush_cache"},
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)
    qs = redirect_query_params(r)
    assert qs.get("cache_flushed") == ["1"]
    assert store._flush is True


def test_webfilter_save_requires_source_url_when_enabling(app_module):
    c = app_module.app.test_client()
    csrf = login(c)

    r = c.post(
        "/webfilter",
        headers={"X-CSRF-Token": csrf},
        data={
            "action": "save",
            "tab": "categories",
            "enabled": "on",
            "source_url": "",
            "categories": ["adult"],
        },
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)
    qs = redirect_query_params(r)
    assert qs.get("tab") == ["categories"]
    assert qs.get("err_source") == ["1"]


def test_webfilter_save_persists_settings_and_applies_include(app_module):
    c = app_module.app.test_client()
    csrf = login(c)

    store = getattr(app_module, "_test_webfilter_store")
    r = c.post(
        "/webfilter",
        headers={"X-CSRF-Token": csrf},
        data={
            "action": "save",
            "tab": "categories",
            "enabled": "on",
            "source_url": "https://example/categories.zip",
            "categories": ["adult", "games"],
        },
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)
    assert store._settings == {
        "enabled": True,
        "source_url": "https://example/categories.zip",
        "blocked_categories": ["adult", "games"],
    }
    assert store._apply_calls >= 1


def test_webfilter_whitelist_add_ok_sets_flash_query(app_module):
    c = app_module.app.test_client()
    csrf = login(c)

    r = c.post(
        "/webfilter",
        headers={"X-CSRF-Token": csrf},
        data={"action": "whitelist_add", "tab": "whitelist", "whitelist_domain": "Example.com"},
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)
    qs = redirect_query_params(r)
    assert qs.get("tab") == ["whitelist"]
    assert qs.get("wl_ok") == ["1"]


def test_webfilter_whitelist_add_error_sets_error_code(app_module):
    c = app_module.app.test_client()
    csrf = login(c)

    store = getattr(app_module, "_test_webfilter_store")
    store.add_whitelist = lambda entry: (False, "bad_domain", "")  # type: ignore[method-assign]

    r = c.post(
        "/webfilter",
        headers={"X-CSRF-Token": csrf},
        data={"action": "whitelist_add", "tab": "whitelist", "whitelist_domain": "not a domain"},
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)
    qs = redirect_query_params(r)
    assert qs.get("tab") == ["whitelist"]
    assert qs.get("wl_err") == ["bad_domain"]


def test_webfilter_whitelist_remove_calls_store(app_module):
    c = app_module.app.test_client()
    csrf = login(c)

    store = getattr(app_module, "_test_webfilter_store")
    store._removed_patterns = []
    r = c.post(
        "/webfilter",
        headers={"X-CSRF-Token": csrf},
        data={"action": "whitelist_remove", "tab": "whitelist", "pattern": "example.com"},
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)
    assert "example.com" in store._removed_patterns


def test_sslfilter_add_ok_and_error(app_module):
    c = app_module.app.test_client()
    csrf = login(c)

    store = getattr(app_module, "_test_sslfilter_store")
    r_ok = c.post(
        "/sslfilter",
        headers={"X-CSRF-Token": csrf},
        data={"action": "add", "cidr": "10.0.0.0/8"},
        follow_redirects=False,
    )
    assert r_ok.status_code in (301, 302, 303, 307, 308)
    qs_ok = redirect_query_params(r_ok)
    assert qs_ok.get("ok") == ["1"]

    store.add_nobump = lambda entry: (False, "bad_cidr", "")  # type: ignore[method-assign]
    r_err = c.post(
        "/sslfilter",
        headers={"X-CSRF-Token": csrf},
        data={"action": "add", "cidr": "bad"},
        follow_redirects=False,
    )
    assert r_err.status_code in (301, 302, 303, 307, 308)
    qs_err = redirect_query_params(r_err)
    assert qs_err.get("err") == ["bad_cidr"]


def test_sslfilter_remove_calls_store(app_module):
    c = app_module.app.test_client()
    csrf = login(c)

    store = getattr(app_module, "_test_sslfilter_store")
    removed = {"cidr": None}

    def fake_remove(cidr: str):
        removed["cidr"] = cidr
        return None

    store.remove_nobump = fake_remove  # type: ignore[method-assign]

    r = c.post(
        "/sslfilter",
        headers={"X-CSRF-Token": csrf},
        data={"action": "remove", "cidr": "10.0.0.0/8"},
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)
    assert removed["cidr"] == "10.0.0.0/8"


def test_exclusions_post_actions_and_apply(app_module, monkeypatch):
    c = app_module.app.test_client()
    csrf = login(c)

    store = getattr(app_module, "_test_fake_ex_store")
    r_add = c.post(
        "/exclusions",
        headers={"X-CSRF-Token": csrf},
        data={"action": "add_domain", "domain": "Example.COM"},
        follow_redirects=False,
    )
    assert r_add.status_code in (301, 302, 303, 307, 308)
    assert "example.com" in store.added_domains

    r_toggle = c.post(
        "/exclusions",
        headers={"X-CSRF-Token": csrf},
        data={"action": "toggle_private", "exclude_private_nets": "on"},
        follow_redirects=False,
    )
    assert r_toggle.status_code in (301, 302, 303, 307, 308)
    assert store._ex.exclude_private_nets is True

    # Apply should regenerate a config from current tunables + exclusions and apply it.
    monkeypatch.setattr(app_module.squid_controller, "get_current_config", lambda: "")
    monkeypatch.setattr(app_module.squid_controller, "get_tunable_options", lambda _cfg=None: {})
    monkeypatch.setattr(app_module.squid_controller, "get_cache_override_options", lambda _cfg=None: {})
    monkeypatch.setattr(app_module.squid_controller, "generate_config_from_template_with_exclusions", lambda options, ex: "CFG")
    monkeypatch.setattr(app_module.squid_controller, "apply_cache_overrides", lambda cfg, overrides: cfg)
    monkeypatch.setattr(app_module.squid_controller, "apply_config_text", lambda cfg: (True, "ok"))

    r_apply = c.post(
        "/exclusions",
        headers={"X-CSRF-Token": csrf},
        data={"action": "apply"},
        follow_redirects=False,
    )
    assert r_apply.status_code in (301, 302, 303, 307, 308)
    assert redirect_query_params(r_apply).get("ok") == ["1"]


def test_clamav_test_endpoints_redirect_with_result(app_module, monkeypatch):
    c = app_module.app.test_client()
    csrf = login(c)

    monkeypatch.setattr(app_module, "_test_eicar", lambda: {"ok": True, "detail": "Eicar FOUND"})
    r1 = c.post("/clamav/test-eicar", headers={"X-CSRF-Token": csrf}, data={}, follow_redirects=False)
    assert r1.status_code in (301, 302, 303, 307, 308)
    qs1 = redirect_query_params(r1)
    assert qs1.get("eicar") == ["ok"]
    assert qs1.get("eicar_detail") == ["Eicar FOUND"]

    monkeypatch.setattr(app_module, "_send_sample_av_icap", lambda: {"ok": False, "detail": "ICAP/1.0 500"})
    r2 = c.post("/clamav/test-icap", headers={"X-CSRF-Token": csrf}, data={}, follow_redirects=False)
    assert r2.status_code in (301, 302, 303, 307, 308)
    qs2 = redirect_query_params(r2)
    assert qs2.get("icap_sample") == ["fail"]
    assert qs2.get("icap_detail") == ["ICAP/1.0 500"]


def test_squid_config_network_tab_mentions_non_standard_ports(app_module):
    c = app_module.app.test_client()
    login(c)

    r = c.get("/squid/config?tab=network")
    assert r.status_code == 200
    body = r.data.decode("utf-8", errors="replace")
    assert "Web destination ports" in body
    assert "Non-standard HTTP and HTTPS destination ports are allowed by default" in body


def test_pac_builder_update_and_delete(app_module):
    c = app_module.app.test_client()
    csrf = login(c)

    store = getattr(app_module, "_test_pac_profiles_store")
    r_upd = c.post(
        "/pac",
        headers={"X-CSRF-Token": csrf},
        data={
            "action": "update",
            "profile_id": "5",
            "name": "updated",
            "client_cidr": "",
            "socks_enabled": "",
            "socks_host": "",
            "socks_port": "1080",
            "direct_domains": "example.com\n",
            "direct_dst_nets": "",
        },
        follow_redirects=False,
    )
    assert r_upd.status_code in (301, 302, 303, 307, 308)
    assert store.upserts and store.upserts[-1]["profile_id"] == 5

    r_del = c.post(
        "/pac",
        headers={"X-CSRF-Token": csrf},
        data={"action": "delete", "profile_id": "5"},
        follow_redirects=False,
    )
    assert r_del.status_code in (301, 302, 303, 307, 308)
    assert 5 in store.deletes


def test_certs_generate_success_and_failure(app_module, monkeypatch):
    c = app_module.app.test_client()
    csrf = login(c)

    class FakeCM:
        def __init__(self):
            self.called = False

        def ca_exists(self):
            return False

        def ensure_ca(self):
            self.called = True

    fake = FakeCM()
    monkeypatch.setattr(app_module, "cert_manager", fake)

    r_ok = c.post("/certs/generate", headers={"X-CSRF-Token": csrf}, data={}, follow_redirects=False)
    assert r_ok.status_code in (301, 302, 303, 307, 308)
    assert fake.called is True
    assert redirect_query_params(r_ok).get("ok") == ["1"]

    def boom():
        raise RuntimeError("nope")

    fake2 = FakeCM()
    fake2.ensure_ca = boom  # type: ignore[method-assign]
    monkeypatch.setattr(app_module, "cert_manager", fake2)
    r_fail = c.post("/certs/generate", headers={"X-CSRF-Token": csrf}, data={}, follow_redirects=False)
    assert r_fail.status_code in (301, 302, 303, 307, 308)
    assert redirect_query_params(r_fail).get("ok") == ["0"]


def test_squid_config_manual_apply_and_validate(app_module, monkeypatch):
    c = app_module.app.test_client()
    csrf = login(c)

    r_apply = c.post(
        "/squid/config",
        headers={"X-CSRF-Token": csrf},
        data={"action": "apply", "tab": "config", "config_text": "http_port 3128\n"},
        follow_redirects=False,
    )
    assert r_apply.status_code in (301, 302, 303, 307, 308)
    assert redirect_query_params(r_apply).get("ok") == ["1"]

    called = {"n": 0}

    def fake_validate(cfg_text: str):
        called["n"] += 1
        return True, "OK"

    monkeypatch.setattr(app_module.squid_controller, "validate_config_text", fake_validate)

    r_val = c.post(
        "/squid/config",
        headers={"X-CSRF-Token": csrf},
        data={"action": "validate", "tab": "config", "config_text": "http_port 3128\n"},
    )
    assert r_val.status_code == 200
    assert called["n"] == 1
