from __future__ import annotations

import json

import pytest
from services.winhttp_registry_builder import (
    WinHttpBuilderError,
    build_advproxy_command,
    build_advproxy_settings_json,
    build_contract_output,
    build_tracing_command,
    decode_basic_winhttp_settings_hex,
    generate_basic_winhttp_binary,
    generate_reg_file_from_hex,
    normalize_bypass_list,
    normalize_reg_binary_export,
)


def test_http_only_generation_matches_known_sample_prefix() -> None:
    result = build_contract_output(
        {
            "proxy_host": "192.168.5.45",
            "proxy_port": "3128",
            "destination_schemes": ["http"],
            "bypass_list": "localhost\n127.0.0.1\n192.168.*\n10.*\n<local>",
        },
    )

    assert result.proxy_string == "http=192.168.5.45:3128"
    assert result.static_registry_available is True
    assert result.normalized_hex.startswith(
        "28000000000000000300000016000000687474703d3139322e3136382e352e34353a33313238",
    )


def test_default_static_output_maps_http_and_https_destinations() -> None:
    result = build_contract_output(
        {
            "proxy_host": "192.168.5.45",
            "proxy_port": 3128,
            "destination_schemes": ["http", "https"],
            "bypass_list": "",
            "include_local_bypass": True,
        },
    )

    assert result.proxy_string == "http=192.168.5.45:3128;https=192.168.5.45:3128"
    assert result.decoded is not None
    assert result.decoded.proxy_string == result.proxy_string
    assert result.decoded.bypass_string == "<local>"
    assert '"AutoDetect": false' in result.advproxy_json


def test_bypass_list_normalizes_lines_semicolons_dedupes_and_local() -> None:
    assert (
        normalize_bypass_list(
            "localhost 127.0.0.1;LOCALHOST\n*.example.local",
            include_local=True,
        )
        == "localhost;127.0.0.1;*.example.local;<local>"
    )


def test_reg_export_normalizer_strips_export_formatting() -> None:
    original = generate_basic_winhttp_binary("http=192.168.5.45:3128", "<local>")
    exported = generate_reg_file_from_hex(original)

    assert normalize_reg_binary_export(exported) == original


def test_reg_export_normalizer_stops_before_following_values() -> None:
    original = generate_basic_winhttp_binary("http=proxy.example:3128", "<local>")
    exported = generate_reg_file_from_hex(original)
    exported += '"OtherValue"=hex:ff,ff,ff,ff\n'

    assert normalize_reg_binary_export(exported) == original


def test_decode_round_trip_rejects_non_ascii_strings() -> None:
    with pytest.raises(WinHttpBuilderError):
        generate_basic_winhttp_binary("http=proxy.example:3128", "cafe\u0301")

    normalized = generate_basic_winhttp_binary("http=proxy.example:3128", "<local>")
    decoded = decode_basic_winhttp_settings_hex(normalized)
    assert decoded.proxy_string == "http=proxy.example:3128"
    assert decoded.bypass_string == "<local>"


def test_advproxy_json_contains_all_documented_keys_and_command_scope() -> None:
    settings = build_advproxy_settings_json(
        proxy_string="http=proxy.example:3128;https=proxy.example:3128",
        bypass_string="<local>",
        autoconfig_url="http://proxy.example/proxy.pac",
        autodetect=True,
    )
    parsed = json.loads(settings)

    assert list(parsed) == ["Proxy", "ProxyBypass", "AutoconfigUrl", "AutoDetect"]
    assert parsed["AutoDetect"] is True
    command = build_advproxy_command(scope="user", settings_json=settings)
    assert command.startswith("netsh winhttp set advproxy setting-scope=user settings=")
    assert '\\"Proxy\\"' in command


def test_pac_or_autodetect_disables_basic_registry_binary() -> None:
    result = build_contract_output(
        {
            "proxy_host": "proxy.example",
            "proxy_port": 3128,
            "destination_schemes": ["http", "https"],
            "autoconfig_url": "http://proxy.example/proxy.pac",
            "autodetect": True,
        },
    )

    assert result.static_registry_available is False
    assert result.normalized_hex == ""
    assert result.reg_file == ""
    assert "AutoconfigUrl" in result.advproxy_json
    assert any(
        "no official byte-for-byte registry serialization contract" in warning
        for warning in result.warnings
    )


def test_advproxy_contract_allows_pac_only_without_static_proxy() -> None:
    result = build_contract_output(
        {
            "proxy_host": "",
            "proxy_port": "",
            "destination_schemes": [],
            "autoconfig_url": "http://proxy.example/proxy.pac",
            "autodetect": True,
            "advproxy_scope": "machine",
        },
    )

    parsed = json.loads(result.advproxy_json)
    assert parsed == {
        "Proxy": "",
        "ProxyBypass": "",
        "AutoconfigUrl": "http://proxy.example/proxy.pac",
        "AutoDetect": True,
    }
    assert result.static_registry_available is False
    assert result.legacy_set_proxy_command == "netsh winhttp reset proxy"


def test_tracing_command_validates_documented_values() -> None:
    assert (
        build_tracing_command(
            state="enabled",
            output="both",
            trace_file_prefix=r"C:\Temp\winhttp",
            level="verbose",
            format_="hex",
            max_trace_file_size="2048",
        )
        == 'netsh winhttp set tracing output=both trace-file-prefix="C:\\Temp\\winhttp" level=verbose format=hex max-trace-file-size=2048 state=enabled'
    )

    with pytest.raises(WinHttpBuilderError):
        build_tracing_command(state="enabled", output="syslog")


@pytest.mark.parametrize(
    ("form_update", "message"),
    [
        ({"proxy_host": 'proxy" & whoami'}, "Proxy host/IP"),
        (
            {
                "use_custom_proxy_map": True,
                "custom_proxy_map": 'http=proxy.example:3128" & whoami',
            },
            "Custom proxy map",
        ),
        ({"bypass_list": '*.example.local|"calc"'}, "Bypass list"),
        ({"autoconfig_url": 'http://proxy.example/proxy.pac" & whoami'}, "Autoconfig URL"),
    ],
)
def test_contract_output_rejects_unsafe_command_characters(
    form_update: dict[str, object],
    message: str,
) -> None:
    form: dict[str, object] = {
        "proxy_host": "proxy.example",
        "proxy_port": 3128,
        "destination_schemes": ["http", "https"],
    }
    form.update(form_update)

    with pytest.raises(WinHttpBuilderError, match=message):
        build_contract_output(form)


def test_contract_output_rejects_control_characters_after_normalization() -> None:
    with pytest.raises(WinHttpBuilderError, match="Custom proxy map"):
        build_contract_output(
            {
                "use_custom_proxy_map": True,
                "custom_proxy_map": "http=proxy.example:3128\x7f",
                "proxy_port": 3128,
                "destination_schemes": ["http"],
            },
        )


def test_command_safety_preserves_common_valid_values() -> None:
    result = build_contract_output(
        {
            "use_custom_proxy_map": True,
            "custom_proxy_map": "http=proxy.example:3128;https=proxy.example:3128",
            "proxy_port": 3128,
            "destination_schemes": ["http"],
            "bypass_list": "*.example.local <local>",
            "autoconfig_url": "http://proxy.example/proxy.pac",
            "trace_file_prefix": r"C:\Temp\winhttp",
            "tracing_state": "enabled",
            "tracing_output": "file",
        },
    )

    assert result.proxy_string == "http=proxy.example:3128;https=proxy.example:3128"
    assert result.bypass_string == "*.example.local;<local>"
    assert "http://proxy.example/proxy.pac" in result.advproxy_json
    assert 'trace-file-prefix="C:\\Temp\\winhttp"' in result.tracing_command


@pytest.mark.parametrize(
    "trace_file_prefix",
    ['C:\\Temp\\win"http', "C:\\Temp\\winhttp&whoami"],
)
def test_tracing_command_rejects_unsafe_trace_file_prefix(
    trace_file_prefix: str,
) -> None:
    with pytest.raises(WinHttpBuilderError, match="Trace file prefix"):
        build_tracing_command(
            state="enabled",
            output="file",
            trace_file_prefix=trace_file_prefix,
        )
