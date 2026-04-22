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
