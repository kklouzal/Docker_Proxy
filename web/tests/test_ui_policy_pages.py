from types import SimpleNamespace

from .flask_test_helpers import login, redirect_query_params


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

    app_module.configure_app_runtime_services_for_testing(get_diagnostic_store=lambda: FakeDiagnostic())

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


def test_sslfilter_add_honors_return_to(app_module):
    c = app_module.app.test_client()
    csrf = login(c)

    r = c.post(
        "/sslfilter",
        headers={"X-CSRF-Token": csrf},
        data={
            "action": "add",
            "cidr": "10.0.0.0/8",
            "return_to": "/observability?pane=ssl&window=3600&limit=50",
        },
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)
    location = r.headers.get("Location", "") or ""
    assert location.startswith("/observability?")
    qs = redirect_query_params(r)
    assert qs.get("pane") == ["ssl"]
    assert qs.get("window") == ["3600"]
    assert qs.get("cidr_added") == ["10.0.0.0/8"]


def test_sslfilter_page_shows_dynamic_protection_state(app_module):
    c = app_module.app.test_client()
    login(c)

    store = getattr(app_module, "_test_sslfilter_store")
    ex_store = getattr(app_module, "_test_fake_ex_store")
    store._auto_rows = [
        SimpleNamespace(
            cidr="192.0.2.15/32",
            added_ts=1,
            expires_ts=7200,
            last_seen=7000,
            score=46,
            evidence="Observed traffic while protected: 14 recent requests.",
        )
    ]
    ex_store.auto_domains = [
        SimpleNamespace(
            domain="client.wns.windows.com",
            added_ts=1,
            expires_ts=8200,
            last_seen=7100,
            score=74,
            evidence="Renewed: 12 CONNECT→invalid-request pairs.",
        )
    ]
    ex_store._ex.auto_domains = ex_store.auto_domains

    r = c.get("/sslfilter")
    assert r.status_code == 200
    body = r.data.decode("utf-8", errors="replace")
    assert "Temporary domain protections" in body
    assert "State" in body
    assert "Score" in body
    assert "Holding" in body
    assert "Renewed" in body


def test_sslfilter_save_dynamic_settings_runs_pass_and_redirects(app_module):
    c = app_module.app.test_client()
    csrf = login(c)

    class _FakeQueries:
        def reconcile_dynamic_ssl_mitigations(self, *, force: bool = False):
            return {
                "ran": True,
                "changed": True,
                "message": "Dynamic client-experience protection added 1 temporary domain protection.",
                "domain_added": ["client.wns.windows.com"],
                "domain_refreshed": [],
                "domain_cooled": [],
                "domain_removed": [],
                "client_added": [],
                "client_refreshed": [],
                "client_cooled": [],
                "client_removed": [],
            }

    app_module.configure_app_runtime_services_for_testing(get_observability_queries=lambda: _FakeQueries())

    store = getattr(app_module, "_test_sslfilter_store")
    r = c.post(
        "/sslfilter",
        headers={"X-CSRF-Token": csrf},
        data={
            "action": "save_dynamic_settings",
            "dynamic_enabled": "on",
            "auto_domain_enabled": "on",
            "auto_client_enabled": "on",
            "review_window_seconds": "3600",
            "reconcile_interval_seconds": "120",
            "min_pair_events": "6",
            "min_bump_aborts": "8",
            "min_ssl_events": "10",
            "domain_limit": "10",
            "domain_ttl_seconds": "7200",
            "client_pair_events": "24",
            "client_distinct_domains": "4",
            "client_limit": "3",
            "client_ttl_seconds": "1800",
        },
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)
    qs = redirect_query_params(r)
    assert qs.get("dynamic_saved") == ["1"]
    assert qs.get("dynamic_run") == ["1"]
    assert qs.get("dynamic_domains_added") == ["1"]
    assert qs.get("dynamic_domains_cooled") == ["0"]
    assert store.get_dynamic_mitigation_settings().review_window_seconds == 3600


def test_sslfilter_run_dynamic_pass_honors_return_to(app_module):
    c = app_module.app.test_client()
    csrf = login(c)

    class _FakeQueries:
        def reconcile_dynamic_ssl_mitigations(self, *, force: bool = False):
            return {
                "ran": True,
                "changed": False,
                "message": "Dynamic client-experience protection reviewed current evidence; no new temporary mitigations were needed.",
                "domain_added": [],
                "domain_refreshed": [],
                "domain_cooled": ["client.wns.windows.com"],
                "domain_removed": [],
                "client_added": [],
                "client_refreshed": [],
                "client_cooled": [],
                "client_removed": [],
            }

    app_module.configure_app_runtime_services_for_testing(get_observability_queries=lambda: _FakeQueries())

    r = c.post(
        "/sslfilter",
        headers={"X-CSRF-Token": csrf},
        data={
            "action": "run_dynamic_pass",
            "return_to": "/observability?pane=ssl&window=3600&limit=50",
        },
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)
    qs = redirect_query_params(r)
    assert qs.get("pane") == ["ssl"]
    assert qs.get("dynamic_run") == ["1"]
    assert qs.get("dynamic_domains_added") == ["0"]
    assert qs.get("dynamic_domains_cooled") == ["1"]


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

    controller = getattr(app_module, "_test_squid_controller")
    controller.current_config = ""
    controller.tunable_options = {}
    controller.cache_override_options = {}
    controller.generated_config = "CFG"
    controller.apply_result = (True, "ok")

    r_apply = c.post(
        "/exclusions",
        headers={"X-CSRF-Token": csrf},
        data={"action": "apply"},
        follow_redirects=False,
    )
    assert r_apply.status_code in (301, 302, 303, 307, 308)
    assert redirect_query_params(r_apply).get("ok") == ["1"]


def test_exclusions_preset_import_adds_curated_microsoft_domains(app_module):
    from services.exclusions_store import get_domain_exclusion_preset

    c = app_module.app.test_client()
    csrf = login(c)

    r = c.post(
        "/exclusions",
        headers={"X-CSRF-Token": csrf},
        data={"action": "add_domain_preset", "preset_key": "microsoft_update_store"},
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)

    preset = get_domain_exclusion_preset("microsoft_update_store")
    assert preset is not None

    store = getattr(app_module, "_test_fake_ex_store")
    assert "*.prod.do.dsp.mp.microsoft.com" in store.added_domains
    assert "*.windowsupdate.com" in store.added_domains
    assert "storecatalogrevocation.storequality.microsoft.com" in store.added_domains

    qs = redirect_query_params(r)
    assert qs.get("preset_added") == [preset.name]
    assert qs.get("preset_count") == [str(len(preset.domains))]
