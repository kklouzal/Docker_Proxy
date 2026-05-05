from __future__ import annotations

import sys
from pathlib import Path


def _ensure_web_import_path() -> None:
    web_dir = Path(__file__).resolve().parents[1]
    if str(web_dir) not in sys.path:
        sys.path.insert(0, str(web_dir))


_ensure_web_import_path()

from services.squid_config_forms import (  # type: ignore  # noqa: E402
    build_template_options,
    build_template_options_from_form,
    get_config_ui_field_map,
    normalize_safe_form_kind,
    parse_cache_override_form,
)


def test_build_template_options_clamps_workers_and_preserves_zero_values():
    options = build_template_options(
        {
            "workers": 999,
            "minimum_object_size_kb": 0,
            "collapsed_forwarding": False,
            "range_offset_limit": 0,
            "memory_pools": False,
        },
        max_workers=4,
    )

    assert options["workers"] == 4
    assert options["minimum_object_size_kb"] == 0
    assert options["collapsed_forwarding_on"] is False
    assert options["range_cache_on"] is False
    assert options["memory_pools_on"] is False


def test_build_template_options_defaults_match_perf_baseline():
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
    assert options["buffered_logs_on"] is False
    assert options["icap_preview_enable_on"] is True
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


def test_generated_template_defaults_to_rock_cache_store() -> None:
    from services.squidctl import SquidController  # type: ignore

    controller = SquidController()
    controller.squid_conf_template_path = str(Path(__file__).resolve().parents[2] / "squid" / "squid.conf.template")

    config = controller.generate_config_from_template(build_template_options({}, max_workers=4))

    assert "cache_dir rock /var/spool/squid 10000 slot-size=32768" in config
    assert "cache_dir ufs" not in config
    assert "store_dir_select_algorithm least-load" in config
    assert "cache_replacement_policy heap GDSF" in config
    assert "maximum_object_size 128 MB" in config
    assert "store_avg_object_size 13 KB" in config


def test_config_ui_field_metadata_exposes_dependencies_for_polished_form_logic():
    field_map = get_config_ui_field_map()

    assert field_map["cache_dir_ufs_l1"].depends_on == ("cache_dir_type",)
    assert field_map["cache_dir_ufs_l1"].show_when == ("ufs",)
    assert field_map["cache_dir_rock_slot_size_kb"].show_when == ("rock",)
    assert field_map["range_offset_limit_value"].depends_on == ("range_cache_on",)
    assert field_map["pipeline_prefetch_count"].depends_on == ("pipeline_prefetch_on",)
    assert field_map["allow_underscore_on"].depends_on == ("check_hostnames_on",)
    assert field_map["memory_pools_limit_mb"].depends_on == ("memory_pools_on",)
    assert field_map["icap_206_enable_on"].depends_on == ("icap_enable_on",)
    assert field_map["icap_send_client_ip_on"].depends_on == ("icap_enable_on",)
    assert field_map["icap_send_client_username_on"].depends_on == ("icap_enable_on",)
    assert field_map["icap_persistent_connections_on"].depends_on == ("icap_enable_on",)
    assert field_map["icap_preview_enable_on"].depends_on == ("icap_enable_on",)
    assert field_map["icap_client_username_header"].depends_on == ("icap_enable_on", "icap_send_client_username_on")
    assert field_map["icap_client_username_encode_on"].depends_on == ("icap_enable_on", "icap_send_client_username_on")
    assert field_map["force_request_body_continuation_rules_text"].placeholder == "force_request_body_continuation allow all"
    assert field_map["icap_retry_rules_text"].placeholder == "icap_retry allow all"


def test_build_template_options_from_form_updates_only_requested_fields():
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


def test_build_template_options_from_form_blank_optional_values_do_not_override():
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


def test_build_template_options_from_form_accepts_dns_packet_none():
    options = build_template_options_from_form(
        {},
        {"dns_packet_max": "none"},
        form_kind="dns",
        max_workers=4,
    )

    assert options["dns_packet_max"] == "none"


def test_build_template_options_from_form_updates_tls_and_disk_fd_tuning_fields():
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


def test_build_template_options_from_form_supports_new_icap_and_guardrail_controls():
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
    assert icap_options["force_request_body_continuation_rules_text"] == "force_request_body_continuation allow all"
    assert icap_options["icap_retry_rules_text"] == "icap_retry allow all"
    assert icap_options["icap_retry_limit"] == 2
    assert perf_options["hopeless_kid_revival_delay_seconds"] == 7200
    assert perf_options["high_response_time_warning_ms"] == 2500
    assert perf_options["high_page_fault_warning"] == 100


def test_build_template_options_from_form_supports_new_cache_store_and_memory_pool_controls():
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


def test_build_template_options_from_form_supports_multiline_advanced_rules():
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

    assert caching_options["cache_policy_rules_text"] == "cache allow localnet\ncache deny all"
    assert caching_options["refresh_patterns_text"] == "refresh_pattern example.com 60 80% 1440"
    assert ssl_options["sslproxy_cert_error_rules_text"] == "sslproxy_cert_error allow all"
    assert ssl_options["sslproxy_cert_sign_rules_text"] == "sslproxy_cert_sign signTrusted all"


def test_parse_cache_override_form_defaults_unchecked_to_false():
    overrides = parse_cache_override_form(
        {
            "override_client_no_cache": "on",
            "override_origin_private": "on",
        }
    )

    assert overrides["client_no_cache"] is True
    assert overrides["origin_private"] is True
    assert overrides["client_no_store"] is False
    assert overrides["origin_no_cache"] is False
    assert overrides["ignore_auth"] is False


def test_normalize_safe_form_kind_falls_back_to_caching():
    assert normalize_safe_form_kind("dns") == "dns"
    assert normalize_safe_form_kind("totally-unknown") == "caching"
    assert normalize_safe_form_kind(None) == "caching"
