from .flask_test_helpers import import_isolated_app_module, login, redirect_query_params


def test_apply_safe_workers_are_clamped(tmp_path, monkeypatch):
    app_module = import_isolated_app_module(tmp_path)

    captured = {"options": None}

    monkeypatch.setattr(app_module.squid_controller, "get_current_config", lambda: "")
    monkeypatch.setattr(
        app_module.squid_controller,
        "get_tunable_options",
        lambda _cfg=None: {"workers": 2, "negative_ttl_seconds": 123},
    )
    monkeypatch.setattr(app_module.squid_controller, "get_cache_override_options", lambda _cfg=None: {})

    def fake_generate(options, exclusions):
        captured["options"] = dict(options)
        return "CFG"

    monkeypatch.setattr(app_module.squid_controller, "generate_config_from_template_with_exclusions", fake_generate)
    monkeypatch.setattr(app_module.squid_controller, "apply_cache_overrides", lambda cfg, overrides: cfg)
    monkeypatch.setattr(app_module.squid_controller, "apply_config_text", lambda cfg: (True, "ok"))

    class FakeEx:
        domains = []
        src_nets = []
        exclude_private_nets = False

    monkeypatch.setattr(app_module, "get_exclusions_store", lambda: type("S", (), {"list_all": lambda self=None: FakeEx()})())

    c = app_module.app.test_client()
    csrf = login(c)

    # too high -> clamped to MAX_WORKERS (default 4)
    r = c.post(
        "/squid/config/apply-safe",
        data={"form_kind": "caching", "workers": "999", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)
    assert captured["options"] is not None
    assert captured["options"]["workers"] == 4

    # too low -> clamped to 1
    captured["options"] = None
    r2 = c.post(
        "/squid/config/apply-safe",
        data={"form_kind": "caching", "workers": "0", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert r2.status_code in (301, 302, 303, 307, 308)
    assert captured["options"]["workers"] == 1


def test_apply_safe_optional_int_blank_does_not_override(tmp_path, monkeypatch):
    app_module = import_isolated_app_module(tmp_path)

    captured = {"options": None}

    monkeypatch.setattr(app_module.squid_controller, "get_current_config", lambda: "")
    monkeypatch.setattr(
        app_module.squid_controller,
        "get_tunable_options",
        lambda _cfg=None: {"negative_ttl_seconds": 123, "workers": 2},
    )
    monkeypatch.setattr(app_module.squid_controller, "get_cache_override_options", lambda _cfg=None: {})

    def fake_generate(options, exclusions):
        captured["options"] = dict(options)
        return "CFG"

    monkeypatch.setattr(app_module.squid_controller, "generate_config_from_template_with_exclusions", fake_generate)
    monkeypatch.setattr(app_module.squid_controller, "apply_cache_overrides", lambda cfg, overrides: cfg)
    monkeypatch.setattr(app_module.squid_controller, "apply_config_text", lambda cfg: (True, "ok"))

    class FakeEx:
        domains = []
        src_nets = []
        exclude_private_nets = False

    monkeypatch.setattr(app_module, "get_exclusions_store", lambda: type("S", (), {"list_all": lambda self=None: FakeEx()})())

    c = app_module.app.test_client()
    csrf = login(c)

    r = c.post(
        "/squid/config/apply-safe",
        data={
            "form_kind": "timeouts",
            "negative_ttl_seconds": "",  # optional int, blank should not override existing
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)
    assert captured["options"] is not None
    assert captured["options"]["negative_ttl_seconds"] == 123


def test_apply_safe_dns_accepts_dns_packet_max_none(tmp_path, monkeypatch):
    app_module = import_isolated_app_module(tmp_path)

    captured = {"options": None}

    monkeypatch.setattr(app_module.squid_controller, "get_current_config", lambda: "")
    monkeypatch.setattr(app_module.squid_controller, "get_tunable_options", lambda _cfg=None: {})
    monkeypatch.setattr(app_module.squid_controller, "get_cache_override_options", lambda _cfg=None: {})

    def fake_generate(options, exclusions):
        captured["options"] = dict(options)
        return "CFG"

    monkeypatch.setattr(app_module.squid_controller, "generate_config_from_template_with_exclusions", fake_generate)
    monkeypatch.setattr(app_module.squid_controller, "apply_cache_overrides", lambda cfg, overrides: cfg)
    monkeypatch.setattr(app_module.squid_controller, "apply_config_text", lambda cfg: (True, "ok"))

    class FakeEx:
        domains = []
        src_nets = []
        exclude_private_nets = False

    monkeypatch.setattr(app_module, "get_exclusions_store", lambda: type("S", (), {"list_all": lambda self=None: FakeEx()})())

    c = app_module.app.test_client()
    csrf = login(c)

    r = c.post(
        "/squid/config/apply-safe",
        data={
            "form_kind": "dns",
            "dns_packet_max": "none",
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)
    assert captured["options"] is not None
    assert captured["options"]["dns_packet_max"] == "none"


def test_apply_safe_ssl_and_performance_fields_flow_into_template_options(tmp_path, monkeypatch):
    app_module = import_isolated_app_module(tmp_path)

    captured = {"options": None}

    monkeypatch.setattr(app_module.squid_controller, "get_current_config", lambda: "")
    monkeypatch.setattr(app_module.squid_controller, "get_tunable_options", lambda _cfg=None: {})
    monkeypatch.setattr(app_module.squid_controller, "get_cache_override_options", lambda _cfg=None: {})

    def fake_generate(options, exclusions):
        captured["options"] = dict(options)
        return "CFG"

    monkeypatch.setattr(app_module.squid_controller, "generate_config_from_template_with_exclusions", fake_generate)
    monkeypatch.setattr(app_module.squid_controller, "apply_cache_overrides", lambda cfg, overrides: cfg)
    monkeypatch.setattr(app_module.squid_controller, "apply_config_text", lambda cfg: (True, "ok"))

    class FakeEx:
        domains = []
        src_nets = []
        exclude_private_nets = False

    monkeypatch.setattr(app_module, "get_exclusions_store", lambda: type("S", (), {"list_all": lambda self=None: FakeEx()})())

    c = app_module.app.test_client()
    csrf = login(c)

    r = c.post(
        "/squid/config/apply-safe",
        data={
            "form_kind": "ssl",
            "dynamic_cert_mem_cache_size_mb": "256",
            "sslcrtd_children": "12",
            "sslcrtd_children_startup": "3",
            "sslcrtd_children_idle": "2",
            "sslcrtd_children_queue_size": "96",
            "sslproxy_session_ttl_seconds": "900",
            "sslproxy_session_cache_size_mb": "16",
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)
    assert captured["options"] is not None
    assert captured["options"]["dynamic_cert_mem_cache_size_mb"] == 256
    assert captured["options"]["sslcrtd_children"] == 12
    assert captured["options"]["sslcrtd_children_startup"] == 3
    assert captured["options"]["sslcrtd_children_idle"] == 2
    assert captured["options"]["sslcrtd_children_queue_size"] == 96
    assert captured["options"]["sslproxy_session_ttl_seconds"] == 900
    assert captured["options"]["sslproxy_session_cache_size_mb"] == 16
    assert captured["options"]["icap_preview_enable_on"] is True

    captured["options"] = None
    r2 = c.post(
        "/squid/config/apply-safe",
        data={
            "form_kind": "performance",
            "memory_pools_limit_mb": "none",
            "shared_memory_locking_on": "on",
            "cpu_affinity_map": "process_numbers=1,2 cores=1,3",
            "max_open_disk_fds": "512",
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )
    assert r2.status_code in (301, 302, 303, 307, 308)
    assert captured["options"] is not None
    assert captured["options"]["memory_pools_limit_mb"] == "none"
    assert captured["options"]["shared_memory_locking_on"] is True
    assert captured["options"]["cpu_affinity_map"] == "process_numbers=1,2 cores=1,3"
    assert captured["options"]["max_open_disk_fds"] == 512


def test_apply_safe_error_redirects(tmp_path, monkeypatch):
    app_module = import_isolated_app_module(tmp_path)

    monkeypatch.setattr(app_module.squid_controller, "get_current_config", lambda: "")
    monkeypatch.setattr(app_module.squid_controller, "get_tunable_options", lambda _cfg=None: {})

    def boom(*_a, **_k):
        raise RuntimeError("boom")

    monkeypatch.setattr(app_module.squid_controller, "generate_config_from_template_with_exclusions", boom)

    class FakeEx:
        domains = []
        src_nets = []
        exclude_private_nets = False

    monkeypatch.setattr(app_module, "get_exclusions_store", lambda: type("S", (), {"list_all": lambda self=None: FakeEx()})())

    c = app_module.app.test_client()
    csrf = login(c)

    r = c.post(
        "/squid/config/apply-safe",
        data={"form_kind": "caching", "workers": "2", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)
    loc = r.headers.get("Location", "") or ""
    assert "error=1" in loc


def test_apply_overrides_maps_form_to_dict(tmp_path, monkeypatch):
    app_module = import_isolated_app_module(tmp_path)

    captured = {"overrides": None}

    monkeypatch.setattr(app_module.squid_controller, "get_current_config", lambda: "")
    monkeypatch.setattr(app_module.squid_controller, "get_tunable_options", lambda _cfg=None: {"workers": 2})

    class FakeEx:
        domains = []
        src_nets = []
        exclude_private_nets = False

    monkeypatch.setattr(app_module, "get_exclusions_store", lambda: type("S", (), {"list_all": lambda self=None: FakeEx()})())

    monkeypatch.setattr(app_module.squid_controller, "generate_config_from_template_with_exclusions", lambda options, exclusions: "CFG")

    def fake_apply_overrides(cfg_text: str, overrides: dict):
        captured["overrides"] = dict(overrides)
        return cfg_text

    monkeypatch.setattr(app_module.squid_controller, "apply_cache_overrides", fake_apply_overrides)
    monkeypatch.setattr(app_module.squid_controller, "apply_config_text", lambda cfg: (True, "ok"))

    c = app_module.app.test_client()
    csrf = login(c)

    r = c.post(
        "/squid/config/apply-overrides",
        data={
            "override_client_no_cache": "on",
            "override_origin_private": "on",
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)
    assert captured["overrides"] is not None
    assert captured["overrides"]["client_no_cache"] is True
    assert captured["overrides"]["origin_private"] is True
    # unchecked boxes must be False
    assert captured["overrides"]["client_no_store"] is False
    assert captured["overrides"]["ignore_auth"] is False

    qs = redirect_query_params(r)
    assert qs.get("ok") == ["1"]
