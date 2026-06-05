from __future__ import annotations

import sys
from pathlib import Path


def _ensure_web_import_path() -> None:
    web_dir = Path(__file__).resolve().parents[1]
    if str(web_dir) not in sys.path:
        sys.path.insert(0, str(web_dir))


_ensure_web_import_path()

from services.squid_config_forms import (  # type: ignore  # noqa: E402
    CACHE_OVERRIDE_FIELDS,
    DEFAULT_HTTP_UPGRADE_REQUEST_PROTOCOLS_RULES,
    DEFAULT_REFRESH_PATTERNS,
    build_template_options,
    build_template_options_from_form,
    get_config_ui_field_map,
    normalize_safe_form_kind,
    parse_cache_override_form,
)


def test_build_template_options_clamps_workers_and_preserves_zero_values() -> None:
    options = build_template_options(
        {
            "workers": 999,
            "minimum_object_size_kb": 0,
            "maximum_object_size_in_memory_kb": 0,
            "collapsed_forwarding": False,
            "range_offset_limit": 0,
            "memory_pools": False,
        },
        max_workers=4,
    )

    assert options["workers"] == 4
    assert options["minimum_object_size_kb"] == 0
    assert options["maximum_object_size_in_memory_kb"] == 0
    assert options["collapsed_forwarding_on"] is False
    assert options["range_cache_on"] is False
    assert options["memory_pools_on"] is False


def test_build_template_options_parses_string_boolean_tunables() -> None:
    options = build_template_options(
        {
            "collapsed_forwarding": "off",
            "range_cache_on": "false",
            "intercept_enabled": "0",
            "https_intercept_enabled": "no",
            "https_intercept_splice_only": "true",
            "memory_pools": "False",
        },
        max_workers=4,
    )

    assert options["collapsed_forwarding_on"] is False
    assert options["range_cache_on"] is False
    assert options["range_offset_limit_value"] == "0"
    assert options["intercept_enabled_on"] is False
    assert options["https_intercept_enabled_on"] is False
    assert options["https_intercept_splice_only_on"] is False
    assert options["memory_pools_on"] is False


def test_build_template_options_defaults_match_perf_baseline() -> None:
    options = build_template_options({}, max_workers=4)

    assert options["cache_dir_type"] == "rock"
    assert options["store_dir_select_algorithm"] == "least-load"
    assert options["cache_mem_mb"] == 256
    assert options["maximum_object_size_mb"] == 128
    assert options["memory_cache_mode"] == "always"
    assert options["shared_transient_entries_limit"] == 16384
    assert options["cache_miss_revalidate_on"] is True
    assert options["reload_into_ims_on"] is False
    assert options["pipeline_prefetch_on"] is False
    assert options["read_ahead_gap_kb"] == 16
    assert options["quick_abort_min_kb"] == 16
    assert options["quick_abort_max_kb"] == 16
    assert options["quick_abort_pct"] == 95
    assert options["explicit_proxy_port"] == 3128
    assert options["intercept_enabled_on"] is False
    assert options["intercept_port"] == 3129
    assert options["https_intercept_enabled_on"] is False
    assert options["https_intercept_port"] == 3130
    assert options["https_intercept_splice_only_on"] is False
    assert options["buffered_logs_on"] is False
    assert options["icap_preview_enable_on"] is True
    assert options["icap_preview_size_kb"] == 128
    assert options["icap_206_enable_on"] is True
    assert options["icap_default_options_ttl_seconds"] == 300
    assert options["icap_client_username_header"] == "X-Client-Username"
    assert options["icap_client_username_encode_on"] is False
    assert options["adaptation_service_iteration_limit"] == 16
    assert options["dns_packet_max"] == 1232
    assert options["dns_timeout_seconds"] == 30
    assert options["positive_dns_ttl_seconds"] == 21600
    assert options["sslcrtd_children"] == 4
    assert options["dynamic_cert_mem_cache_size_mb"] == 128
    assert options["tls_outgoing_options_line"] == "min-version=1.2 options=NO_SSLv3"
    assert options["sslproxy_session_ttl_seconds"] == 600
    assert options["sslproxy_session_cache_size_mb"] == 32
    assert options["sslproxy_cert_sign_hash"] == "sha256"
    assert options["via_on"] is True
    assert options["strip_query_terms_on"] is True
    assert options["request_header_max_size_kb"] == 64
    assert options["reply_header_max_size_kb"] == 64
    assert options["memory_pools_limit_mb"] == 64
    assert options["hopeless_kid_revival_delay_seconds"] == 3600
    assert options["max_open_disk_fds"] == 0
    assert options["store_avg_object_size_kb"] == 13
    assert options["store_objects_per_bucket"] == 20
    assert options["client_db_on"] is True
    assert (
        options["http_upgrade_request_protocols_rules_text"]
        == DEFAULT_HTTP_UPGRADE_REQUEST_PROTOCOLS_RULES
    )
    assert options["refresh_patterns_text"] == DEFAULT_REFRESH_PATTERNS


def test_generated_template_defaults_to_rock_cache_store() -> None:
    from services.squidctl import SquidController  # type: ignore

    controller = SquidController()
    controller.squid_conf_template_path = str(
        Path(__file__).resolve().parents[2] / "squid" / "squid.conf.template"
    )

    config = controller.generate_config_from_template(
        build_template_options({}, max_workers=4)
    )

    assert "cache_dir rock /var/spool/squid 10000 slot-size=32768" in config
    assert "cache_dir ufs" not in config
    assert "store_dir_select_algorithm least-load" in config
    assert "cache_replacement_policy heap GDSF" in config
    assert "maximum_object_size 128 MB" in config
    assert "store_avg_object_size 13 KB" in config
    assert "http_upgrade_request_protocols websocket deny all" in config
    assert "http_upgrade_request_protocols OTHER deny all" in config


def test_default_refresh_patterns_are_standards_safe_and_modern_static_first() -> None:
    lines = [
        line
        for line in DEFAULT_REFRESH_PATTERNS.splitlines()
        if line.startswith("refresh_pattern")
    ]
    query_guard_index = lines.index(r"refresh_pattern -i (/cgi-bin/|\?) 0 0% 0")

    assert lines[0] == "refresh_pattern ^ftp: 1440 20% 10080"
    assert lines[-2] == r"refresh_pattern -i (/cgi-bin/|\?) 0 0% 0"
    assert lines[-1] == "refresh_pattern . 0 20% 4320"
    assert any(
        r"\.(css|js|mjs|map|wasm)(\?.*)?$" in line for line in lines[:query_guard_index]
    )
    assert any("avif|jxl|heic|heif" in line for line in lines[:query_guard_index])
    assert any(
        "appx|appxbundle|msix|msixbundle" in line for line in lines[:query_guard_index]
    )

    dangerous_options = (
        "override-expire",
        "override-lastmod",
        "ignore-no-store",
        "ignore-private",
        "ignore-reload",
        "ignore-auth",
        "reload-into-ims",
        "override-expire",
        "override-lastmod",
    )
    assert not any(option in line for line in lines for option in dangerous_options)


def test_template_refresh_pattern_block_matches_form_default() -> None:
    template = (
        Path(__file__).resolve().parents[2] / "squid" / "squid.conf.template"
    ).read_text(encoding="utf-8")

    assert DEFAULT_REFRESH_PATTERNS in template


def test_config_ui_field_metadata_exposes_dependencies_for_polished_form_logic() -> (
    None
):
    field_map = get_config_ui_field_map()

    assert field_map["cache_dir_ufs_l1"].depends_on == ("cache_dir_type",)
    assert field_map["cache_dir_ufs_l1"].show_when == ("ufs",)
    assert field_map["cache_dir_rock_slot_size_kb"].show_when == ("rock",)
    assert field_map["range_offset_limit_value"].depends_on == ("range_cache_on",)
    assert field_map["pipeline_prefetch_count"].depends_on == ("pipeline_prefetch_on",)
    assert field_map["intercept_port"].depends_on == ("intercept_enabled_on",)
    assert field_map["intercept_port"].show_when == ("checked",)
    assert field_map["https_intercept_port"].depends_on == (
        "https_intercept_enabled_on",
    )
    assert field_map["https_intercept_port"].show_when == ("checked",)
    assert field_map["https_intercept_splice_only_on"].depends_on == (
        "https_intercept_enabled_on",
    )
    assert field_map["https_intercept_splice_only_on"].show_when == ("checked",)
    assert field_map["allow_underscore_on"].depends_on == ("check_hostnames_on",)
    assert field_map["memory_pools_limit_mb"].depends_on == ("memory_pools_on",)
    assert field_map["icap_206_enable_on"].depends_on == ("icap_enable_on",)
    assert field_map["icap_send_client_ip_on"].depends_on == ("icap_enable_on",)
    assert field_map["icap_send_client_username_on"].depends_on == ("icap_enable_on",)
    assert field_map["icap_persistent_connections_on"].depends_on == ("icap_enable_on",)
    assert field_map["icap_preview_enable_on"].depends_on == ("icap_enable_on",)
    assert field_map["icap_client_username_header"].depends_on == (
        "icap_enable_on",
        "icap_send_client_username_on",
    )
    assert field_map["icap_client_username_encode_on"].depends_on == (
        "icap_enable_on",
        "icap_send_client_username_on",
    )
    assert (
        field_map["force_request_body_continuation_rules_text"].placeholder
        == "force_request_body_continuation allow all"
    )
    assert field_map["icap_retry_rules_text"].placeholder == "icap_retry allow all"
    assert (
        field_map["http_upgrade_request_protocols_rules_text"].placeholder
        == DEFAULT_HTTP_UPGRADE_REQUEST_PROTOCOLS_RULES
    )


def test_build_template_options_from_form_updates_only_requested_fields() -> None:
    options = build_template_options_from_form(
        {
            "workers": 2,
            "negative_ttl_seconds": 123,
            "cache_mem_mb": 96,
        },
        {
            "workers": "999",
        },
        form_kind="caching",
        max_workers=4,
    )

    assert options["workers"] == 4
    assert options["negative_ttl_seconds"] == 123
    assert options["cache_mem_mb"] == 96


def test_build_template_options_from_form_supports_intercept_listener_controls() -> (
    None
):
    options = build_template_options_from_form(
        {},
        {
            "explicit_proxy_port": "8080",
            "intercept_enabled_on": "on",
            "intercept_port": "8080",
            "https_intercept_enabled_on": "on",
            "https_intercept_port": "8080",
            "https_intercept_splice_only_on": "on",
        },
        form_kind="network",
        max_workers=4,
    )

    assert options["explicit_proxy_port"] == 8080
    assert options["intercept_enabled_on"] is True
    assert options["intercept_port"] == 8081
    assert options["https_intercept_enabled_on"] is True
    assert options["https_intercept_port"] == 8082
    assert options["https_intercept_splice_only_on"] is True


def test_build_template_options_from_form_resolves_three_way_listener_port_collision() -> (
    None
):
    options = build_template_options_from_form(
        {},
        {
            "explicit_proxy_port": "3130",
            "intercept_enabled_on": "on",
            "intercept_port": "3131",
            "https_intercept_enabled_on": "on",
            "https_intercept_port": "3131",
        },
        form_kind="network",
        max_workers=4,
    )

    assert options["explicit_proxy_port"] == 3130
    assert options["intercept_port"] == 3131
    assert options["https_intercept_port"] == 3132


def test_build_template_options_from_form_blank_optional_values_do_not_override() -> (
    None
):
    options = build_template_options_from_form(
        {
            "negative_ttl_seconds": 123,
            "visible_hostname": "proxy-host",
        },
        {
            "negative_ttl_seconds": "",
            "visible_hostname": "",
        },
        form_kind="caching",
        max_workers=4,
    )

    assert options["negative_ttl_seconds"] == 123
    assert options["visible_hostname"] == "proxy-host"


def test_build_template_options_bounds_numeric_form_and_persisted_values() -> None:
    from services.squidctl import SquidController  # type: ignore

    controller = SquidController()
    controller.squid_conf_template_path = str(
        Path(__file__).resolve().parents[2] / "squid" / "squid.conf.template"
    )

    persisted_options = build_template_options(
        {
            "cache_dir_size_mb": -1,
            "cache_swap_low": -20,
            "cache_swap_high": 120,
            "pipeline_prefetch_count": 999,
            "quick_abort_pct": 999,
            "explicit_proxy_port": 999999,
        },
        max_workers=4,
    )
    form_options = build_template_options_from_form(
        {},
        {
            "cache_dir_size_mb": "-1",
            "cache_swap_low": "-20",
            "cache_swap_high": "120",
            "pipeline_prefetch_on": "on",
            "pipeline_prefetch_count": "999",
            "quick_abort_pct": "999",
            "explicit_proxy_port": "999999",
        },
        form_kind="caching",
        max_workers=4,
    )
    network_form_options = build_template_options_from_form(
        {},
        {"explicit_proxy_port": "999999"},
        form_kind="network",
        max_workers=4,
    )

    assert persisted_options["cache_dir_size_mb"] == 100
    assert persisted_options["cache_swap_low"] == 0
    assert persisted_options["cache_swap_high"] == 100
    assert persisted_options["pipeline_prefetch_on"] is True
    assert persisted_options["pipeline_prefetch_count"] == 16
    assert persisted_options["quick_abort_pct"] == 100
    assert persisted_options["explicit_proxy_port"] == 65535
    assert form_options["cache_dir_size_mb"] == 100
    assert form_options["cache_swap_low"] == 0
    assert form_options["cache_swap_high"] == 100
    assert form_options["pipeline_prefetch_on"] is True
    assert form_options["pipeline_prefetch_count"] == 16
    assert form_options["quick_abort_pct"] == 100
    assert network_form_options["explicit_proxy_port"] == 65535

    config = controller.generate_config_from_template(persisted_options)
    assert "cache_dir rock /var/spool/squid 100 slot-size=32768" in config
    assert "cache_swap_low 0" in config
    assert "cache_swap_high 100" in config
    assert "pipeline_prefetch 16" in config
    assert "quick_abort_pct 100" in config
    assert "http_port 0.0.0.0:65535" in config

    raw_renderer_config = controller.generate_config_from_template(
        {
            "pipeline_prefetch_on": True,
            "pipeline_prefetch_count": 999,
        },
    )
    assert "pipeline_prefetch 16" in raw_renderer_config


def test_build_template_options_from_form_accepts_dns_packet_none() -> None:
    options = build_template_options_from_form(
        {},
        {"dns_packet_max": "none"},
        form_kind="dns",
        max_workers=4,
    )

    assert options["dns_packet_max"] == "none"


def test_build_template_options_from_form_updates_tls_and_disk_fd_tuning_fields() -> (
    None
):
    ssl_options = build_template_options_from_form(
        {},
        {
            "dynamic_cert_mem_cache_size_mb": "256",
            "sslproxy_session_ttl_seconds": "900",
            "sslproxy_session_cache_size_mb": "16",
        },
        form_kind="ssl",
        max_workers=4,
    )
    perf_options = build_template_options_from_form(
        {},
        {"max_open_disk_fds": "512"},
        form_kind="performance",
        max_workers=4,
    )

    assert ssl_options["dynamic_cert_mem_cache_size_mb"] == 256
    assert ssl_options["sslproxy_session_ttl_seconds"] == 900
    assert ssl_options["sslproxy_session_cache_size_mb"] == 16
    assert perf_options["max_open_disk_fds"] == 512


def test_build_template_options_from_form_supports_new_icap_and_guardrail_controls() -> (
    None
):
    icap_options = build_template_options_from_form(
        {},
        {
            "icap_206_enable_on": "on",
            "icap_send_client_username_on": "on",
            "icap_client_username_header": "X-Auth-User",
            "icap_client_username_encode_on": "on",
            "adaptation_service_iteration_limit": "8",
            "force_request_body_continuation_rules_text": "force_request_body_continuation allow all\n",
            "icap_retry_rules_text": "icap_retry allow all\n",
            "icap_retry_limit": "2",
        },
        form_kind="icap",
        max_workers=4,
    )
    perf_options = build_template_options_from_form(
        {},
        {
            "hopeless_kid_revival_delay_seconds": "7200",
            "high_response_time_warning_ms": "2500",
            "high_page_fault_warning": "100",
        },
        form_kind="performance",
        max_workers=4,
    )

    assert icap_options["icap_206_enable_on"] is True
    assert icap_options["icap_send_client_username_on"] is True
    assert icap_options["icap_client_username_header"] == "X-Auth-User"
    assert icap_options["icap_client_username_encode_on"] is True
    assert icap_options["adaptation_service_iteration_limit"] == 8
    assert (
        icap_options["force_request_body_continuation_rules_text"]
        == "force_request_body_continuation allow all"
    )
    assert icap_options["icap_retry_rules_text"] == "icap_retry allow all"
    assert icap_options["icap_retry_limit"] == 2
    assert perf_options["hopeless_kid_revival_delay_seconds"] == 7200
    assert perf_options["high_response_time_warning_ms"] == 2500
    assert perf_options["high_page_fault_warning"] == 100


def test_build_template_options_from_form_supports_new_cache_store_and_memory_pool_controls() -> (
    None
):
    caching_options = build_template_options_from_form(
        {},
        {
            "cache_dir_type": "ufs",
            "cache_dir_ufs_l1": "32",
            "cache_dir_ufs_l2": "512",
            "memory_cache_mode": "disk",
            "shared_transient_entries_limit": "65536",
        },
        form_kind="caching",
        max_workers=4,
    )
    perf_options = build_template_options_from_form(
        {},
        {
            "memory_pools_limit_mb": "none",
            "shared_memory_locking_on": "on",
            "cpu_affinity_map": "process_numbers=1,2 cores=1,3",
        },
        form_kind="performance",
        max_workers=4,
    )

    assert caching_options["cache_dir_type"] == "ufs"
    assert caching_options["cache_dir_ufs_l1"] == 32
    assert caching_options["cache_dir_ufs_l2"] == 512
    assert caching_options["memory_cache_mode"] == "disk"
    assert caching_options["shared_transient_entries_limit"] == 65536
    assert perf_options["memory_pools_limit_mb"] == "none"
    assert perf_options["shared_memory_locking_on"] is True
    assert perf_options["cpu_affinity_map"] == "process_numbers=1,2 cores=1,3"


def test_build_template_options_from_form_supports_multiline_advanced_rules() -> None:
    caching_options = build_template_options_from_form(
        {},
        {
            "cache_policy_rules_text": "cache allow localnet\ncache deny all\n",
            "refresh_patterns_text": "refresh_pattern example.com 60 80% 1440\n",
        },
        form_kind="caching",
        max_workers=4,
    )
    ssl_options = build_template_options_from_form(
        {},
        {
            "sslproxy_cert_error_rules_text": "sslproxy_cert_error allow all\n",
            "sslproxy_cert_sign_rules_text": "sslproxy_cert_sign signTrusted all\n",
        },
        form_kind="ssl",
        max_workers=4,
    )

    assert (
        caching_options["cache_policy_rules_text"]
        == "cache allow localnet\ncache deny all"
    )
    assert (
        caching_options["refresh_patterns_text"]
        == "refresh_pattern example.com 60 80% 1440"
    )
    assert (
        ssl_options["sslproxy_cert_error_rules_text"] == "sslproxy_cert_error allow all"
    )
    assert (
        ssl_options["sslproxy_cert_sign_rules_text"]
        == "sslproxy_cert_sign signTrusted all"
    )


def test_parse_cache_override_form_defaults_unchecked_to_false() -> None:
    overrides = parse_cache_override_form(
        {
            "override_expire": "on",
            "ignore_private": "on",
        },
    )

    assert tuple(overrides) == CACHE_OVERRIDE_FIELDS
    assert overrides["override_expire"] is True
    assert overrides["ignore_private"] is True
    assert overrides["override_lastmod"] is False
    assert overrides["reload_into_ims"] is False
    assert overrides["ignore_reload"] is False
    assert overrides["ignore_no_store"] is False


def test_parse_cache_override_form_accepts_legacy_semantic_names() -> None:
    overrides = parse_cache_override_form(
        {
            "override_client_no_cache": "on",
            "override_origin_private": "on",
            "override_origin_no_store": "on",
        },
    )

    assert overrides["ignore_reload"] is True
    assert overrides["ignore_private"] is True
    assert overrides["ignore_no_store"] is True
    assert overrides["override_expire"] is False
    assert overrides["override_lastmod"] is False
    assert overrides["reload_into_ims"] is False


def test_cache_override_form_contains_exact_current_squid_override_options() -> None:
    expected = (
        "override_expire",
        "override_lastmod",
        "reload_into_ims",
        "ignore_reload",
        "ignore_no_store",
        "ignore_private",
    )

    assert expected == CACHE_OVERRIDE_FIELDS


def test_apply_cache_overrides_applies_all_current_squid_override_flags_and_metadata() -> (
    None
):
    from services.squidctl import SquidController  # type: ignore

    config = (
        "refresh_pattern ^ftp: 1440 20% 10080 ignore-auth\nrefresh_pattern -i (/cgi-bin/|\\?) 0 0% 0 ignore-private\nrefresh_pattern . 0 20% 4320 ignore-no-cache"
        "\n"
    )
    overrides = dict.fromkeys(CACHE_OVERRIDE_FIELDS, True)

    rendered = SquidController().apply_cache_overrides(config, overrides)

    expected_flags = "override-expire override-lastmod reload-into-ims ignore-reload ignore-no-store ignore-private"
    assert f"refresh_pattern ^ftp: 1440 20% 10080 {expected_flags}" in rendered
    assert f"refresh_pattern . 0 20% 4320 {expected_flags}" in rendered
    assert r"refresh_pattern -i (/cgi-bin/|\?) 0 0% 0" in rendered
    assert "ignore-auth" not in rendered
    assert "ignore-no-cache" not in rendered
    assert "ignore-must-revalidate" not in rendered

    for field in CACHE_OVERRIDE_FIELDS:
        assert f"# {field}=1" in rendered


def test_get_cache_override_options_reads_current_and_legacy_metadata() -> None:
    from services.squidctl import SquidController  # type: ignore

    config = "# override_expire=1\n# override_lastmod=1\n# reload_into_ims=0\n# ignore_reload=0\n# ignore_no_store=0\n# ignore_private=0\n# override_client_no_cache=1\n# override_origin_no_store=1\n# override_origin_private=1"

    overrides = SquidController().get_cache_override_options(config)

    assert overrides["override_expire"] is True
    assert overrides["override_lastmod"] is True
    assert overrides["reload_into_ims"] is False
    assert overrides["ignore_reload"] is True
    assert overrides["ignore_no_store"] is True
    assert overrides["ignore_private"] is True


def test_normalize_safe_form_kind_falls_back_to_caching() -> None:
    assert normalize_safe_form_kind("dns") == "dns"
    assert normalize_safe_form_kind("totally-unknown") == "caching"
    assert normalize_safe_form_kind(None) == "caching"


def test_cache_mgr_contact_email_defaults_and_form_metadata() -> None:
    options = build_template_options({}, max_workers=4)
    field_map = get_config_ui_field_map()

    assert options["cache_mgr_email"] == "proxy-admin@example.invalid"
    assert field_map["cache_mgr_email"].label == "Administrator contact email"
    assert field_map["cache_mgr_email"].placeholder == "proxy-admin@example.invalid"


def test_build_template_options_from_form_accepts_cache_mgr_contact_email_and_preserves_blank() -> (
    None
):
    updated = build_template_options_from_form(
        {},
        {"cache_mgr_email": "proxy-team@example.invalid"},
        form_kind="http",
        max_workers=4,
    )
    preserved = build_template_options_from_form(
        {"cache_mgr_email": "helpdesk@example.invalid"},
        {"cache_mgr_email": ""},
        form_kind="http",
        max_workers=4,
    )

    assert updated["cache_mgr_email"] == "proxy-team@example.invalid"
    assert preserved["cache_mgr_email"] == "helpdesk@example.invalid"


def test_generated_config_renders_and_parses_cache_mgr_contact_email() -> None:
    from services.squidctl import SquidController  # type: ignore

    controller = SquidController()
    controller.squid_conf_template_path = str(
        Path(__file__).resolve().parents[2] / "squid" / "squid.conf.template"
    )

    default_config = controller.generate_config_from_template(
        build_template_options({}, max_workers=4)
    )
    custom_config = controller.generate_config_from_template(
        build_template_options(
            {
                "cache_mgr_email": "helpdesk@example.invalid",
                "visible_hostname": "proxy-edge",
            },
            max_workers=4,
        ),
    )

    assert "cache_mgr proxy-admin@example.invalid" in default_config
    assert default_config.count("cache_mgr ") == 1
    assert "cache_mgr helpdesk@example.invalid" in custom_config
    assert custom_config.count("cache_mgr ") == 1
    assert (
        controller.get_tunable_options(custom_config)["cache_mgr_email"]
        == "helpdesk@example.invalid"
    )
    assert "cache_mgr helpdesk@example.invalid" in controller.get_http_lines(
        custom_config
    )
