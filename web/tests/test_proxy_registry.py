from __future__ import annotations

import sys
from pathlib import Path


def _add_web_to_path() -> None:
    web_dir = Path(__file__).resolve().parents[1]
    if str(web_dir) not in sys.path:
        sys.path.insert(0, str(web_dir))


def test_parse_public_pac_url_handles_scheme_host_ports_and_invalid_values() -> None:
    _add_web_to_path()
    import services.proxy_registry as proxy_registry  # type: ignore

    assert proxy_registry._parse_public_pac_url("proxy.example") == ("proxy.example", "http", 80)
    assert proxy_registry._parse_public_pac_url("https://proxy.example/proxy.pac") == ("proxy.example", "https", 443)
    assert proxy_registry._parse_public_pac_url("http://proxy.example:8080/proxy.pac") == ("proxy.example", "http", 8080)
    assert proxy_registry._parse_public_pac_url("") == ("", "http", 80)
    assert proxy_registry._parse_public_pac_url("ftp://proxy.example:9000/proxy.pac") == ("proxy.example", "http", 9000)
    assert proxy_registry._parse_public_pac_url("https://proxy.example:not-a-port/proxy.pac") == ("proxy.example", "https", 443)


def test_resolve_local_proxy_public_fields_prefers_explicit_env_over_public_pac_url(monkeypatch) -> None:
    _add_web_to_path()
    import services.proxy_registry as proxy_registry  # type: ignore

    monkeypatch.setenv("PROXY_PUBLIC_PAC_URL", "https://from-url.example:8443/proxy.pac")
    monkeypatch.setenv("PROXY_PUBLIC_HOST", "explicit.example")
    monkeypatch.setenv("PROXY_PUBLIC_PAC_SCHEME", "http")
    monkeypatch.setenv("PROXY_PUBLIC_PAC_PORT", "8080")
    monkeypatch.setenv("PROXY_PUBLIC_HTTP_PROXY_PORT", "3129")

    assert proxy_registry.resolve_local_proxy_public_fields() == {
        "public_host": "explicit.example",
        "public_pac_scheme": "http",
        "public_pac_port": 8080,
        "public_http_proxy_port": 3129,
    }


def test_resolve_local_proxy_public_fields_falls_back_to_public_pac_url_and_port_defaults(monkeypatch) -> None:
    _add_web_to_path()
    import services.proxy_registry as proxy_registry  # type: ignore

    monkeypatch.setenv("PROXY_PUBLIC_PAC_URL", "https://pac.example/proxy.pac")
    monkeypatch.delenv("PROXY_PUBLIC_HOST", raising=False)
    monkeypatch.delenv("PROXY_PUBLIC_PAC_SCHEME", raising=False)
    monkeypatch.setenv("PROXY_PUBLIC_PAC_PORT", "not-a-port")
    monkeypatch.setenv("PROXY_PUBLIC_HTTP_PROXY_PORT", "99999")

    assert proxy_registry.resolve_local_proxy_public_fields() == {
        "public_host": "pac.example",
        "public_pac_scheme": "https",
        "public_pac_port": 443,
        "public_http_proxy_port": 3128,
    }


def test_row_to_instance_normalizes_ports_booleans_and_display_name() -> None:
    _add_web_to_path()
    import services.proxy_registry as proxy_registry  # type: ignore

    row = {
        "proxy_id": "edge-2",
        "display_name": "",
        "hostname": "edge-host",
        "management_url": "http://edge:5000",
        "public_host": "edge.example",
        "public_pac_scheme": "ftp",
        "public_pac_port": 0,
        "public_http_proxy_port": "3129",
        "status": "healthy",
        "last_heartbeat": 123,
        "last_apply_ts": 456,
        "last_apply_ok": "1",
        "current_config_sha": "abc",
        "detail": "ok",
        "created_ts": 100,
        "updated_ts": 200,
    }

    instance = proxy_registry.ProxyRegistry()._row_to_instance(row)
    assert instance is not None
    assert instance.display_name == "edge-2"
    assert instance.public_pac_scheme == "http"
    assert instance.public_pac_port == 80
    assert instance.public_http_proxy_port == 3129
    assert instance.last_apply_ok is True
