from .flask_test_helpers import import_isolated_app_module, login, redirect_query_params
from .route_test_support import FakeExclusionsStore, FakeSquidController


def _install_config_test_services(app_module):
    controller = FakeSquidController({"reload": 0, "clear": 0, "apply": 0})
    controller.current_config = ""
    exclusions_store = FakeExclusionsStore()
    app_module.reset_app_runtime_services_for_testing()
    app_module.configure_app_runtime_services_for_testing(
        controller=controller,
        get_exclusions_store=lambda: exclusions_store,
    )
    return controller, exclusions_store


def test_apply_safe_workers_are_clamped(tmp_path):
    app_module = import_isolated_app_module(tmp_path)
    controller, _exclusions_store = _install_config_test_services(app_module)
    controller.tunable_options = {"workers": 2, "negative_ttl_seconds": 123}

    c = app_module.app.test_client()
    csrf = login(c)

    # too high -> clamped to MAX_WORKERS (default 4)
    r = c.post(
        "/squid/config/apply-safe",
        data={"form_kind": "caching", "workers": "999", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)
    assert controller.last_generated_options is not None
    assert controller.last_generated_options["workers"] == 4

    # too low -> clamped to 1
    controller.last_generated_options = None
    r2 = c.post(
        "/squid/config/apply-safe",
        data={"form_kind": "caching", "workers": "0", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert r2.status_code in (301, 302, 303, 307, 308)
    assert controller.last_generated_options is not None
    assert controller.last_generated_options["workers"] == 1


def test_apply_safe_optional_int_blank_does_not_override(tmp_path):
    app_module = import_isolated_app_module(tmp_path)
    controller, _exclusions_store = _install_config_test_services(app_module)
    controller.tunable_options = {"negative_ttl_seconds": 123, "workers": 2}

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
    assert controller.last_generated_options is not None
    assert controller.last_generated_options["negative_ttl_seconds"] == 123


def test_apply_safe_dns_accepts_dns_packet_max_none(tmp_path):
    app_module = import_isolated_app_module(tmp_path)
    controller, _exclusions_store = _install_config_test_services(app_module)

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
    assert controller.last_generated_options is not None
    assert controller.last_generated_options["dns_packet_max"] == "none"


def test_apply_safe_ssl_and_performance_fields_flow_into_template_options(tmp_path):
    app_module = import_isolated_app_module(tmp_path)
    controller, _exclusions_store = _install_config_test_services(app_module)

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
    assert controller.last_generated_options is not None
    assert controller.last_generated_options["dynamic_cert_mem_cache_size_mb"] == 256
    assert controller.last_generated_options["sslcrtd_children"] == 12
    assert controller.last_generated_options["sslcrtd_children_startup"] == 3
    assert controller.last_generated_options["sslcrtd_children_idle"] == 2
    assert controller.last_generated_options["sslcrtd_children_queue_size"] == 96
    assert controller.last_generated_options["sslproxy_session_ttl_seconds"] == 900
    assert controller.last_generated_options["sslproxy_session_cache_size_mb"] == 16
    assert controller.last_generated_options["icap_preview_enable_on"] is True

    controller.last_generated_options = None
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
    assert controller.last_generated_options is not None
    assert controller.last_generated_options["memory_pools_limit_mb"] == "none"
    assert controller.last_generated_options["shared_memory_locking_on"] is True
    assert controller.last_generated_options["cpu_affinity_map"] == "process_numbers=1,2 cores=1,3"
    assert controller.last_generated_options["max_open_disk_fds"] == 512


def test_apply_safe_error_redirects(tmp_path):
    app_module = import_isolated_app_module(tmp_path)
    controller, _exclusions_store = _install_config_test_services(app_module)
    controller.generate_error = RuntimeError("boom")

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


def test_apply_overrides_maps_form_to_dict(tmp_path):
    app_module = import_isolated_app_module(tmp_path)
    controller, _exclusions_store = _install_config_test_services(app_module)
    controller.tunable_options = {"workers": 2}

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
    assert controller.last_overrides is not None
    assert controller.last_overrides["client_no_cache"] is True
    assert controller.last_overrides["origin_private"] is True
    # unchecked boxes must be False
    assert controller.last_overrides["client_no_store"] is False
    assert controller.last_overrides["ignore_auth"] is False

    qs = redirect_query_params(r)
    assert qs.get("ok") == ["1"]
