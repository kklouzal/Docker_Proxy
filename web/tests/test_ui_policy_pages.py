from .flask_test_helpers import login, redirect_query_params
from .ui_pages_test_support import app_module  # noqa: F401


def test_webfilter_test_domain_json(app_module):
    c = app_module.app.test_client()
    csrf = login(c)

    r = c.post("/webfilter/test", headers={"X-CSRF-Token": csrf}, json={"domain": "example.com"})
    assert r.status_code == 200
    assert r.is_json
    data = r.get_json()
    assert data["ok"] is True
    assert data["domain"] == "example.com"


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


def test_adblock_page_shows_recent_icap_observability(app_module, monkeypatch):
    class FakeDiagnostic:
        def list_recent_icap(self, *, since: int | None = None, search: str = "", client_ip: str = "", domain: str = "", master_xaction: str = "", service: str = "", limit: int = 50):
            return [
                {
                    "ts": 1713448200,
                    "client_ip": "192.0.2.10",
                    "method": "GET",
                    "target_display": "ads.example.com",
                    "url": "https://ads.example.com/script.js",
                    "icap_time_ms": 22,
                    "service_label": "Adblock",
                    "adapt_summary": "adblockreq / blocked",
                    "policy_tags": ["cache:cookie"],
                    "master_xaction": "tx123",
                }
            ]

        def find_request_by_master_xaction(self, master_xaction: str):
            return {
                "method": "GET",
                "target_display": "ads.example.com",
                "client_ip": "192.0.2.10",
                "result_code": "TCP_DENIED/403",
                "http_status": 403,
            }

        def icap_summary(self, *, since: int | None = None, service: str = ""):
            return {"events": 1, "avg_icap_time_ms": 22, "max_icap_time_ms": 22}

        def slowest_icap_events(self, *, since: int | None = None, service: str = "", limit: int = 10):
            return self.list_recent_icap(limit=limit)

        def list_request_candidates_for_policy_event(self, **_kwargs):
            return []

    monkeypatch.setattr(app_module, "get_diagnostic_store", lambda: FakeDiagnostic())

    c = app_module.app.test_client()
    login(c)
    r = c.get("/adblock?window=3600")
    assert r.status_code == 200
    body = r.data.decode("utf-8", errors="replace")
    assert "Observability handoff" in body
    assert "Open security pane" in body
    assert "Adblock ICAP events" in body


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
    calls = getattr(app_module, "_test_calls")
    assert calls["reload"] >= 1


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
def test_webfilter_unknown_tab_falls_back_to_configuration_ui(app_module):
    c = app_module.app.test_client()
    login(c)

    r = c.get("/webfilter?tab=blockedlog&window=3600")
    assert r.status_code == 200
    body = r.data.decode("utf-8", errors="replace")
    assert "Categories" in body
    assert "Whitelist" in body
    assert "Blocked Log" not in body


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
