from __future__ import annotations

from .flask_test_helpers import ensure_web_import_path


ensure_web_import_path()

from services.squid_config_forms import (  # type: ignore
    build_template_options,
    build_template_options_from_form,
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
    assert options["cache_mem_mb"] == 256
    assert options["maximum_object_size_mb"] == 128
    assert options["memory_cache_mode"] == "always"
    assert options["shared_transient_entries_limit"] == 32768
    assert options["cache_miss_revalidate_on"] is True
    assert options["buffered_logs_on"] is True
    assert options["icap_preview_enable_on"] is True
    assert options["icap_default_options_ttl_seconds"] == 300
    assert options["dns_packet_max"] is None
    assert options["dns_timeout_seconds"] == 15
    assert options["sslcrtd_children"] == 4
    assert options["dynamic_cert_mem_cache_size_mb"] == 128
    assert options["sslproxy_session_ttl_seconds"] == 600
    assert options["sslproxy_session_cache_size_mb"] == 32
    assert options["memory_pools_limit_mb"] == 64
    assert options["max_open_disk_fds"] == 0


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
