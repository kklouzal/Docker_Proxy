from __future__ import annotations

import errno
import json
import stat
import subprocess
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest


def _proxy_record(public_host: str, **overrides: object) -> SimpleNamespace:
    data = {
        "public_host": public_host,
        "public_pac_scheme": "http",
        "public_pac_port": 80,
        "public_pac_path": "/proxy.pac",
        "public_http_proxy_port": 3128,
    }
    data.update(overrides)
    return SimpleNamespace(**data)


class _EmptyRegistry:
    def get_proxy(self, _proxy_id):
        return None


class _EmptyPacProfilesStore:
    def list_profiles(self):
        return []

    def list_proxy_chain_settings(self):
        return SimpleNamespace(backup_proxies=[], direct_enabled=True)


class _EmptySslFilterStore:
    def list_all(self):
        return None


def _evaluate_pac(rendered: str, host: str) -> str:
    script = "\n".join(
        (
            "function dnsDomainIs(host, domain) { return host.endsWith(domain); }",
            "function isPlainHostName(host) { return host.indexOf('.') < 0; }",
            "function dnsResolve(host) { return ''; }",
            "function isInNet(ip, pattern, mask) {",
            "  function toInt(value) {",
            "    return value.split('.').reduce(function(acc, octet) {",
            "      return ((acc << 8) | (parseInt(octet, 10) & 255)) >>> 0;",
            "    }, 0);",
            "  }",
            "  return (toInt(ip) & toInt(mask)) === (toInt(pattern) & toInt(mask));",
            "}",
            rendered,
            f"process.stdout.write(FindProxyForURL('', {json.dumps(host)}));",
        ),
    )
    return subprocess.check_output(["node", "-e", script], text=True)


def _evaluate_pac_with_dns_answer(rendered: str, host: str, dns_answer: str) -> str:
    script = "\n".join(
        (
            "function dnsDomainIs(host, domain) { return host.endsWith(domain); }",
            "function isPlainHostName(host) { return host.indexOf('.') < 0; }",
            f"function dnsResolve(host) {{ return {json.dumps(dns_answer)}; }}",
            "function isInNet(ip, pattern, mask) {",
            "  if (!/^(?:\\d{1,3}\\.){3}\\d{1,3}$/.test(ip || '')) {",
            "    throw new Error('isInNet called with non-IPv4 address: ' + ip);",
            "  }",
            "  function toInt(value) {",
            "    return value.split('.').reduce(function(acc, octet) {",
            "      return ((acc << 8) | (parseInt(octet, 10) & 255)) >>> 0;",
            "    }, 0);",
            "  }",
            "  return (toInt(ip) & toInt(mask)) === (toInt(pattern) & toInt(mask));",
            "}",
            rendered,
            f"process.stdout.write(FindProxyForURL('', {json.dumps(host)}));",
        ),
    )
    return subprocess.check_output(["node", "-e", script], text=True)


def test_pac_url_and_proxy_host_normalization_handles_defaults_ports_and_ipv6() -> None:
    from services import pac_renderer  # type: ignore

    assert pac_renderer.format_proxy_host("proxy.example:3128") == "proxy.example"
    assert pac_renderer.format_proxy_host("93.184.216.34") == "93.184.216.34"
    assert (
        pac_renderer.format_proxy_host("2001:4860:4860::8888")
        == "[2001:4860:4860::8888]"
    )
    assert (
        pac_renderer.format_proxy_host("[2001:4860:4860::8888]:3128")
        == "[2001:4860:4860::8888]"
    )
    assert pac_renderer.format_proxy_host('bad"; alert(1); //') == "127.0.0.1"

    assert (
        pac_renderer._build_pac_url(scheme="http", host="proxy.example", port=80)
        == "http://proxy.example/proxy.pac"
    )
    assert (
        pac_renderer._build_pac_url(scheme="https", host="proxy.example", port=443)
        == "https://proxy.example/proxy.pac"
    )
    assert (
        pac_renderer._build_pac_url(scheme="ftp", host="proxy.example", port=8080)
        == "http://proxy.example:8080/proxy.pac"
    )
    assert (
        pac_renderer._build_pac_url(
            scheme="http", host="2001:4860:4860::8888", port=8080
        )
        == "http://[2001:4860:4860::8888]:8080/proxy.pac"
    )


@pytest.mark.parametrize(
    "host",
    [
        "localhost",
        "api.localhost",
        "localhost.localdomain",
        "printer.local",
        "proxy.internal",
        "gateway.home.arpa",
        "010.000.000.001",
        "999.999.999.999",
        "0x7f000001",
        "127.0.0.1",
        "10.0.0.1",
        "169.254.1.1",
        "224.0.0.1",
        "::1",
        "[::1]:3128",
    ],
)
def test_format_proxy_host_fails_closed_for_request_host_fallback_authorities(
    host: str,
) -> None:
    from services import pac_renderer  # type: ignore

    assert pac_renderer.format_proxy_host(host) == "127.0.0.1"


def test_pac_host_normalization_strips_url_schemes_before_ipv6_detection() -> None:
    from services import pac_renderer  # type: ignore

    assert (
        pac_renderer.format_proxy_host("http://proxy.example:8080/proxy.pac")
        == "proxy.example"
    )
    assert (
        pac_renderer.format_proxy_host("https://[2001:4860:4860::8888]:8443/proxy.pac")
        == "[2001:4860:4860::8888]"
    )
    assert (
        pac_renderer._build_pac_url(
            scheme="http", host="http://proxy.example:8080/proxy.pac", port=80
        )
        == "http://proxy.example/proxy.pac"
    )
    assert (
        pac_renderer.ProxyPacTarget(
            "default",
            "http://proxy.example:8080",
            "http",
            80,
            3128,
        ).proxy_chain
        == "PROXY proxy.example:3128; DIRECT"
    )


def test_proxy_chain_filters_stale_invalid_backup_hosts() -> None:
    from services import pac_renderer  # type: ignore

    target = pac_renderer.ProxyPacTarget(
        "default",
        "primary.example",
        "http",
        80,
        3128,
        backup_proxies=(
            ("backup.example;DIRECT", 3128),
            ("backup.example", 8080),
            ("https://Backup-02.Example:8443", None),
            ("[2001:db8::10]:3130", None),
            ("fe80::1%eth0", 3128),
            ("[fe80::2%eth0]:3131", None),
            ("http://[fe80::3%25eth0]:3132", None),
            ("bad_host.example", 3128),
        ),
    )

    assert (
        target.proxy_chain == "PROXY primary.example:3128; PROXY backup.example:8080; "
        "PROXY backup-02.example:8443; PROXY [2001:db8::10]:3130; DIRECT"
    )
    assert "backup.example;DIRECT" not in target.proxy_chain
    assert "fe80" not in target.proxy_chain
    assert "%eth0" not in target.proxy_chain
    assert "%25eth0" not in target.proxy_chain
    assert "bad_host" not in target.proxy_chain


def test_resolve_proxy_pac_target_honors_public_pac_url_when_registry_is_empty(
    monkeypatch,
) -> None:
    from services import pac_renderer  # type: ignore

    monkeypatch.setattr(pac_renderer, "get_proxy_registry", _EmptyRegistry)
    monkeypatch.setattr(pac_renderer, "get_pac_profiles_store", _EmptyPacProfilesStore)
    monkeypatch.setenv(
        "PROXY_PUBLIC_PAC_URL",
        "https://pac.example:8443/custom/proxy.pac?profile=default",
    )
    monkeypatch.setenv("PROXY_PUBLIC_HTTP_PROXY_PORT", "8080")

    target = pac_renderer.resolve_proxy_pac_target("default")

    assert target.public_host == "pac.example"
    assert target.pac_scheme == "https"
    assert target.pac_port == 8443
    assert target.pac_path == "/custom/proxy.pac?profile=default"
    assert target.http_proxy_port == 8080
    assert target.pac_url == "https://pac.example:8443/custom/proxy.pac?profile=default"
    assert target.proxy_chain == "PROXY pac.example:8080; DIRECT"


@pytest.mark.parametrize(
    ("public_pac_url", "expected_url"),
    [
        (
            "2001:4860:4860::8888/custom/proxy.pac?site=lab",
            "http://[2001:4860:4860::8888]/custom/proxy.pac?site=lab",
        ),
        (
            "https://2001:4860:4860::8888/custom/proxy.pac",
            "https://[2001:4860:4860::8888]/custom/proxy.pac",
        ),
    ],
)
def test_resolve_proxy_pac_target_preserves_unbracketed_ipv6_public_pac_url(
    monkeypatch,
    public_pac_url: str,
    expected_url: str,
) -> None:
    from services import pac_renderer  # type: ignore

    monkeypatch.setattr(pac_renderer, "get_proxy_registry", _EmptyRegistry)
    monkeypatch.setattr(pac_renderer, "get_pac_profiles_store", _EmptyPacProfilesStore)
    monkeypatch.setenv("PROXY_PUBLIC_PAC_URL", public_pac_url)

    target = pac_renderer.resolve_proxy_pac_target("default")

    assert target.public_host == "2001:4860:4860::8888"
    assert target.pac_path.startswith("/custom/proxy.pac")
    assert target.pac_url == expected_url
    assert target.proxy_chain == "PROXY [2001:4860:4860::8888]:3128; DIRECT"


@pytest.mark.parametrize(
    "public_pac_url",
    [
        "ftp://proxy.example:9000/proxy.pac",
        "https:///proxy.pac",
        "https://user:secret@proxy.example/proxy.pac",
        "https://proxy.example/custom/proxy.pac#not-sent",
    ],
)
def test_resolve_proxy_pac_target_ignores_invalid_absolute_public_pac_url(
    monkeypatch,
    public_pac_url: str,
) -> None:
    from services import pac_renderer  # type: ignore

    monkeypatch.setattr(pac_renderer, "get_proxy_registry", _EmptyRegistry)
    monkeypatch.setattr(pac_renderer, "get_pac_profiles_store", _EmptyPacProfilesStore)
    monkeypatch.setenv("PROXY_PUBLIC_PAC_URL", public_pac_url)

    target = pac_renderer.resolve_proxy_pac_target("default")

    assert target.public_host == ""
    assert target.pac_scheme == "http"
    assert target.pac_port == 80
    assert target.pac_path == "/proxy.pac"
    assert target.pac_url == ""


def test_resolve_proxy_pac_target_ignores_invalid_env_public_host(
    monkeypatch,
) -> None:

    from services import pac_renderer  # type: ignore

    monkeypatch.setattr(pac_renderer, "get_proxy_registry", _EmptyRegistry)
    monkeypatch.setattr(pac_renderer, "get_pac_profiles_store", _EmptyPacProfilesStore)
    monkeypatch.setenv("PROXY_PUBLIC_HOST", "bad host.example")
    monkeypatch.delenv("PROXY_PUBLIC_PAC_URL", raising=False)

    target = pac_renderer.resolve_proxy_pac_target("default")

    assert target.public_host == ""
    assert target.pac_url == ""
    assert target.uses_request_host_fallback is True
    assert target.proxy_chain == "PROXY __PAC_PROXY_HOST__:3128; DIRECT"


@pytest.mark.parametrize(
    "public_host",
    [
        "localhost",
        "localhost.localdomain",
        "api.localhost",
        "printer.local",
        "proxy.internal",
        "gateway.home.arpa",
    ],
)
def test_resolve_proxy_pac_target_ignores_reserved_dns_public_host(
    monkeypatch,
    public_host: str,
) -> None:

    from services import pac_renderer  # type: ignore

    monkeypatch.setattr(pac_renderer, "get_proxy_registry", _EmptyRegistry)
    monkeypatch.setattr(pac_renderer, "get_pac_profiles_store", _EmptyPacProfilesStore)
    monkeypatch.setenv("PROXY_PUBLIC_HOST", public_host)
    monkeypatch.delenv("PROXY_PUBLIC_PAC_URL", raising=False)

    target = pac_renderer.resolve_proxy_pac_target("default")

    assert target.public_host == ""
    assert target.pac_url == ""
    assert target.uses_request_host_fallback is True
    assert target.proxy_chain == "PROXY __PAC_PROXY_HOST__:3128; DIRECT"


@pytest.mark.parametrize("public_host", ["2130706433", "017700000001", "127.1"])
def test_resolve_proxy_pac_target_ignores_ambiguous_ipv4_public_host(
    monkeypatch,
    public_host: str,
) -> None:

    from services import pac_renderer  # type: ignore

    monkeypatch.setattr(pac_renderer, "get_proxy_registry", _EmptyRegistry)
    monkeypatch.setattr(pac_renderer, "get_pac_profiles_store", _EmptyPacProfilesStore)
    monkeypatch.setenv("PROXY_PUBLIC_HOST", public_host)
    monkeypatch.delenv("PROXY_PUBLIC_PAC_URL", raising=False)

    target = pac_renderer.resolve_proxy_pac_target("default")

    assert target.public_host == ""
    assert target.pac_url == ""
    assert target.uses_request_host_fallback is True
    assert target.proxy_chain == "PROXY __PAC_PROXY_HOST__:3128; DIRECT"


@pytest.mark.parametrize(
    ("env_name", "value"),
    [
        ("PROXY_PUBLIC_HOST", "[fe80::1%eth0]:3128"),
        ("PROXY_PUBLIC_PAC_URL", "http://[fe80::1%25eth0]/proxy.pac"),
    ],
)
def test_resolve_proxy_pac_target_ignores_scoped_ipv6_public_endpoint(
    monkeypatch,
    env_name: str,
    value: str,
) -> None:

    from services import pac_renderer  # type: ignore

    monkeypatch.setattr(pac_renderer, "get_proxy_registry", _EmptyRegistry)
    monkeypatch.setattr(pac_renderer, "get_pac_profiles_store", _EmptyPacProfilesStore)
    monkeypatch.delenv("PROXY_PUBLIC_HOST", raising=False)
    monkeypatch.delenv("PROXY_PUBLIC_PAC_URL", raising=False)
    monkeypatch.setenv(env_name, value)

    target = pac_renderer.resolve_proxy_pac_target("default")

    assert target.public_host == ""
    assert target.pac_url == ""
    assert target.uses_request_host_fallback is True
    assert target.proxy_chain == "PROXY __PAC_PROXY_HOST__:3128; DIRECT"


@pytest.mark.parametrize(
    ("env_name", "value"),
    [
        ("PROXY_PUBLIC_HOST", "127.0.0.1"),
        ("PROXY_PUBLIC_HOST", "10.0.0.1"),
        ("PROXY_PUBLIC_PAC_URL", "http://[::1]/proxy.pac"),
        ("PROXY_PUBLIC_PAC_URL", "http://169.254.1.1/proxy.pac"),
        ("PROXY_PUBLIC_PAC_URL", "http://224.0.0.1/proxy.pac"),
    ],
)
def test_resolve_proxy_pac_target_ignores_non_public_ip_literal_endpoint(
    monkeypatch,
    env_name: str,
    value: str,
) -> None:

    from services import pac_renderer  # type: ignore

    monkeypatch.setattr(pac_renderer, "get_proxy_registry", _EmptyRegistry)
    monkeypatch.setattr(pac_renderer, "get_pac_profiles_store", _EmptyPacProfilesStore)
    monkeypatch.delenv("PROXY_PUBLIC_HOST", raising=False)
    monkeypatch.delenv("PROXY_PUBLIC_PAC_URL", raising=False)
    monkeypatch.setenv(env_name, value)

    target = pac_renderer.resolve_proxy_pac_target("default")

    assert target.public_host == ""
    assert target.pac_url == ""
    assert target.uses_request_host_fallback is True
    assert target.proxy_chain == "PROXY __PAC_PROXY_HOST__:3128; DIRECT"


def test_resolve_proxy_pac_target_uses_env_endpoint_when_registry_has_no_public_host(
    monkeypatch,
) -> None:

    from services import pac_renderer  # type: ignore

    class _RegistryWithBlankPublicHost:
        def get_proxy(self, _proxy_id):
            return _proxy_record("")

    monkeypatch.setattr(
        pac_renderer, "get_proxy_registry", _RegistryWithBlankPublicHost
    )
    monkeypatch.setattr(pac_renderer, "get_pac_profiles_store", _EmptyPacProfilesStore)
    monkeypatch.setenv("PROXY_PUBLIC_PAC_URL", "https://edge.example/proxy.pac")
    monkeypatch.setenv("PROXY_PUBLIC_HTTP_PROXY_PORT", "8080")

    target = pac_renderer.resolve_proxy_pac_target("default")

    assert target.public_host == "edge.example"
    assert target.pac_scheme == "https"
    assert target.pac_port == 443
    assert target.http_proxy_port == 8080
    assert target.pac_url == "https://edge.example/proxy.pac"


def test_resolve_proxy_pac_target_preserves_registered_compose_public_endpoint(
    monkeypatch,
) -> None:

    from services import pac_renderer  # type: ignore

    class _RegistryWithComposePublicHost:
        def get_proxy(self, _proxy_id):
            return _proxy_record("proxy-edge-2")

    monkeypatch.setattr(
        pac_renderer,
        "get_proxy_registry",
        _RegistryWithComposePublicHost,
    )
    monkeypatch.setattr(pac_renderer, "get_pac_profiles_store", _EmptyPacProfilesStore)
    monkeypatch.setenv("PROXY_PUBLIC_PAC_URL", "https://env.example/proxy.pac")
    monkeypatch.setenv("PROXY_PUBLIC_HTTP_PROXY_PORT", "8080")

    target = pac_renderer.resolve_proxy_pac_target("edge-2")

    assert target.public_host == "proxy-edge-2"
    assert target.pac_url == "http://proxy-edge-2/proxy.pac"
    assert target.proxy_chain_display == "PROXY proxy-edge-2:3128; DIRECT"


def test_build_proxy_pac_state_manifest_preserves_configured_public_pac_path(
    monkeypatch,
) -> None:
    from services import pac_renderer  # type: ignore

    monkeypatch.setattr(pac_renderer, "get_proxy_registry", _EmptyRegistry)
    monkeypatch.setattr(pac_renderer, "get_pac_profiles_store", _EmptyPacProfilesStore)

    monkeypatch.setattr(
        pac_renderer,
        "get_sslfilter_store",
        _EmptySslFilterStore,
    )
    monkeypatch.setenv(
        "PROXY_PUBLIC_PAC_URL",
        "https://pac.example/download/wpad.dat?site=lab",
    )

    state = pac_renderer.build_proxy_pac_state("default")
    manifest = json.loads(
        next(
            item.content
            for item in state.files
            if item.relative_path == "manifest.json"
        )
    )

    assert (
        manifest["public_pac_url"] == "https://pac.example/download/wpad.dat?site=lab"
    )
    assert manifest["public_pac_path"] == "/download/wpad.dat?site=lab"


def test_build_proxy_pac_state_manifest_rejects_encoded_public_pac_separator(
    monkeypatch,
) -> None:
    from services import pac_renderer  # type: ignore

    monkeypatch.setattr(pac_renderer, "get_proxy_registry", _EmptyRegistry)
    monkeypatch.setattr(pac_renderer, "get_pac_profiles_store", _EmptyPacProfilesStore)
    monkeypatch.setattr(
        pac_renderer,
        "get_sslfilter_store",
        _EmptySslFilterStore,
    )
    monkeypatch.setenv(
        "PROXY_PUBLIC_PAC_URL",
        "https://pac.example/download%2fwpad.dat",
    )

    state = pac_renderer.build_proxy_pac_state("default")
    manifest = json.loads(
        next(
            item.content
            for item in state.files
            if item.relative_path == "manifest.json"
        )
    )

    assert manifest["public_pac_url"] == "https://pac.example/proxy.pac"
    assert manifest["public_pac_path"] == "/proxy.pac"


def test_resolve_proxy_pac_target_prefers_registry_public_endpoint_over_env(
    monkeypatch,
) -> None:

    from services import pac_renderer  # type: ignore

    class _RegistryWithPublicHost:
        def get_proxy(self, _proxy_id):
            return _proxy_record(
                "Registry.Example.",
                public_pac_port=8080,
                public_pac_path="/registered/wpad.dat?site=a",
            )

    monkeypatch.setattr(pac_renderer, "get_proxy_registry", _RegistryWithPublicHost)
    monkeypatch.setattr(pac_renderer, "get_pac_profiles_store", _EmptyPacProfilesStore)
    monkeypatch.setenv("PROXY_PUBLIC_PAC_URL", "https://env.example/proxy.pac")
    monkeypatch.setenv("PROXY_PUBLIC_HTTP_PROXY_PORT", "8080")

    target = pac_renderer.resolve_proxy_pac_target("default")

    assert target.public_host == "registry.example"
    assert target.pac_scheme == "http"
    assert target.pac_port == 8080
    assert target.http_proxy_port == 3128
    assert target.pac_path == "/registered/wpad.dat?site=a"
    assert target.pac_url == "http://registry.example:8080/registered/wpad.dat?site=a"


def test_resolve_proxy_pac_target_rejects_registry_public_pac_path_fragment(
    monkeypatch,
) -> None:

    from services import pac_renderer  # type: ignore

    class _RegistryWithFragmentPublicPath:
        def get_proxy(self, _proxy_id):
            return _proxy_record(
                "registry.example",
                public_pac_path="/registered/wpad.dat#not-sent",
            )

    monkeypatch.setattr(
        pac_renderer,
        "get_proxy_registry",
        _RegistryWithFragmentPublicPath,
    )
    monkeypatch.setattr(pac_renderer, "get_pac_profiles_store", _EmptyPacProfilesStore)
    monkeypatch.delenv("PROXY_PUBLIC_PAC_URL", raising=False)

    target = pac_renderer.resolve_proxy_pac_target("default")

    assert target.public_host == "registry.example"
    assert target.pac_path == "/proxy.pac"
    assert target.pac_url == "http://registry.example/proxy.pac"


def test_build_proxy_pac_state_uses_active_proxy_context_when_unspecified(
    monkeypatch,
) -> None:

    from services import pac_renderer  # type: ignore
    from services.proxy_context import reset_proxy_id, set_proxy_id  # type: ignore

    class _Registry:
        def get_proxy(self, proxy_id):
            return _proxy_record(f"{proxy_id}.example")

    monkeypatch.setattr(pac_renderer, "get_proxy_registry", _Registry)
    monkeypatch.setattr(pac_renderer, "get_pac_profiles_store", _EmptyPacProfilesStore)
    monkeypatch.setattr(pac_renderer, "get_sslfilter_store", _EmptySslFilterStore)

    token = set_proxy_id("edge-b")
    try:
        state = pac_renderer.build_proxy_pac_state()
    finally:
        reset_proxy_id(token)

    manifest = json.loads(
        next(
            item.content
            for item in state.files
            if item.relative_path == "manifest.json"
        )
    )

    assert state.proxy_id == "edge-b"
    assert manifest["proxy_id"] == "edge-b"
    assert manifest["public_host"] == "edge-b.example"
    assert manifest["proxy_chain"] == "PROXY edge-b.example:3128; DIRECT"


def test_resolve_proxy_pac_target_scopes_chain_settings_to_requested_proxy(
    monkeypatch,
) -> None:

    from services import pac_renderer  # type: ignore
    from services.proxy_context import (  # type: ignore
        get_proxy_id,
        reset_proxy_id,
        set_proxy_id,
    )

    class _Registry:
        def get_proxy(self, proxy_id):
            return _proxy_record(f"{proxy_id}.example")

    class _ScopedPacProfilesStore:
        def list_proxy_chain_settings(self):
            proxy_id = get_proxy_id()
            if proxy_id == "edge-b":
                return SimpleNamespace(
                    backup_proxies=[
                        SimpleNamespace(
                            proxy_host="backup-b.example",
                            proxy_port=8080,
                        ),
                    ],
                    direct_enabled=False,
                )
            return SimpleNamespace(
                backup_proxies=[
                    SimpleNamespace(
                        proxy_host="backup-a.example",
                        proxy_port=3129,
                    ),
                ],
                direct_enabled=True,
            )

    monkeypatch.setattr(pac_renderer, "get_proxy_registry", _Registry)
    monkeypatch.setattr(
        pac_renderer,
        "get_pac_profiles_store",
        _ScopedPacProfilesStore,
    )

    token = set_proxy_id("edge-a")
    try:
        target = pac_renderer.resolve_proxy_pac_target("edge-b")
    finally:
        reset_proxy_id(token)

    assert target.proxy_id == "edge-b"
    assert target.public_host == "edge-b.example"
    assert (
        target.proxy_chain == "PROXY edge-b.example:3128; PROXY backup-b.example:8080"
    )
    assert "backup-a" not in target.proxy_chain
    assert "DIRECT" not in target.proxy_chain


def test_resolve_proxy_pac_target_filters_stale_invalid_backup_proxy_ports(
    monkeypatch,
) -> None:

    from services import pac_renderer  # type: ignore

    class _Registry:
        def get_proxy(self, _proxy_id):
            return _proxy_record("proxy.example")

    class _StalePacProfilesStore:
        def list_proxy_chain_settings(self):
            return SimpleNamespace(
                backup_proxies=[
                    SimpleNamespace(proxy_host="backup-zero.example", proxy_port=0),
                    SimpleNamespace(proxy_host="backup-empty.example", proxy_port=""),
                    SimpleNamespace(proxy_host="backup-good.example", proxy_port=8080),
                ],
                direct_enabled=True,
            )

    monkeypatch.setattr(pac_renderer, "get_proxy_registry", _Registry)
    monkeypatch.setattr(
        pac_renderer,
        "get_pac_profiles_store",
        _StalePacProfilesStore,
    )

    target = pac_renderer.resolve_proxy_pac_target("default")

    assert target.normalized_backup_proxies == (
        ("backup-empty.example", 3128),
        ("backup-good.example", 8080),
    )
    assert "backup-zero.example" not in target.proxy_chain
    assert "PROXY backup-empty.example:3128" in target.proxy_chain
    assert "PROXY backup-good.example:8080" in target.proxy_chain


def test_rendered_pac_contains_local_direct_rules_and_deduplicates_domains() -> None:
    from services import pac_renderer  # type: ignore
    from services.pac_private_local import LOCAL_DOMAIN_SUFFIXES

    rendered = pac_renderer._render_pac(
        "PROXY proxy.example:3128; DIRECT",
        proxy_host="proxy.example",
        direct_domains=["Example.COM", "*.media.example", "", "example.com"],
        direct_dst_nets=[
            "10.20.0.0/16",
            "10.20.1.7/16",
            "2001:db8::/32",
            "not-a-cidr",
        ],
        include_private=True,
    )

    assert "host === 'localhost'" in rendered
    for suffix in LOCAL_DOMAIN_SUFFIXES:
        assert f'dnsDomainIs(host, "{suffix}")' in rendered
    assert rendered.count('host === "example.com"') == 1
    assert rendered.count('dnsDomainIs(host, ".media.example")') == 1
    assert rendered.count("isInNet(ip, '10.20.0.0', '255.255.0.0')") == 1
    assert "isInNet(ip, '192.168.0.0', '255.255.0.0')" in rendered
    assert "2001:db8" not in rendered
    assert 'return "PROXY proxy.example:3128; DIRECT";' in rendered


def test_rendered_pac_preserves_exact_and_wildcard_direct_domain_semantics() -> None:
    from services import pac_renderer  # type: ignore

    rendered = pac_renderer._render_pac(
        "PROXY proxy.example:3128; DIRECT",
        proxy_host="proxy.example",
        direct_domains=[
            "Example.COM",
            "example.com",
            "*.Example.COM",
            "*.example.com",
        ],
        direct_dst_nets=[],
        include_private=False,
    )

    assert rendered.count("if (host === \"example.com\") return 'DIRECT';") == 1
    assert (
        rendered.count(
            'if (host === "example.com" || dnsDomainIs(host, ".example.com")) return \'DIRECT\';'
        )
        == 1
    )
    assert "if host === \"example.com\" return 'DIRECT';" not in rendered
    assert "if dnsDomainIs(host, \".example.com\") return 'DIRECT';" not in rendered


def test_rendered_pac_is_deterministic_for_equivalent_direct_rule_ordering() -> None:
    from services import pac_renderer  # type: ignore

    first = pac_renderer._render_pac(
        "PROXY proxy.example:3128; DIRECT",
        proxy_host="proxy.example",
        direct_domains=["*.Media.Example", "example.com", "*.media.example"],
        direct_dst_nets=["10.20.1.7/16", "192.0.2.4/24", "10.20.0.0/16"],
        include_private=False,
    )
    second = pac_renderer._render_pac(
        "PROXY proxy.example:3128; DIRECT",
        proxy_host="proxy.example",
        direct_domains=["example.com", "*.media.example"],
        direct_dst_nets=["192.0.2.0/24", "10.20.0.0/16"],
        include_private=False,
    )

    assert first == second


def test_rendered_pac_normalizes_stale_direct_domain_inputs() -> None:
    from services import pac_renderer  # type: ignore

    rendered = pac_renderer._render_pac(
        "PROXY proxy.example:3128; DIRECT",
        proxy_host="proxy.example",
        direct_domains=[
            "https://Bücher.Example:443/path",
            "*.Media.Example",
            ".Legacy.Example",
            "bad domain.example",
            "2001:db8::1",
        ],
        direct_dst_nets=[],
        include_private=False,
    )

    assert 'host === "xn--bcher-kva.example"' in rendered
    assert 'dnsDomainIs(host, ".media.example")' in rendered
    assert 'host === "legacy.example"' in rendered
    assert "bad domain" not in rendered
    assert "2001:db8" not in rendered


def test_rendered_pac_strips_root_dot_before_host_matching() -> None:
    from services import pac_renderer  # type: ignore

    rendered = pac_renderer._render_pac(
        "PROXY proxy.example:3128; DIRECT",
        proxy_host="proxy.example",
        direct_domains=["intranet.example"],
        direct_dst_nets=["192.0.2.0/24"],
        include_private=False,
    )

    host_normalizer = "host = normalizePacHost(host);"
    proxy_host_normalizer = "var normalizedProxyHost = normalizePacHost(proxyHost);"

    assert "function normalizePacHost(value)" in rendered
    assert host_normalizer in rendered
    assert proxy_host_normalizer in rendered
    assert rendered.index(host_normalizer) < rendered.index("host === 'localhost'")
    assert rendered.index(host_normalizer) < rendered.index(
        'host === "intranet.example"'
    )
    assert rendered.index(host_normalizer) < rendered.index("var ip = hostIp();")


def test_rendered_pac_strips_ipv6_url_brackets_before_local_and_proxy_matching() -> (
    None
):
    from services import pac_renderer  # type: ignore

    rendered = pac_renderer._render_pac(
        "PROXY [::1]:3128; DIRECT",
        proxy_host="[::1]",
        direct_domains=[],
        direct_dst_nets=[],
        include_private=False,
    )

    host_normalizer = "host = normalizePacHost(host);"

    assert "function normalizePacHost(value)" in rendered
    assert host_normalizer in rendered
    assert rendered.index(host_normalizer) < rendered.index(
        "isIpv6LoopbackAddress(host)"
    )
    assert rendered.index(host_normalizer) < rendered.index(
        "host === normalizedProxyHost"
    )


def test_rendered_pac_normalizes_host_brackets_ports_and_root_dots() -> None:
    from services import pac_renderer  # type: ignore

    rendered = pac_renderer._render_pac(
        "PROXY proxy.example:3128; DIRECT",
        proxy_host="[2001:db8::10]:3128",
        direct_domains=["example.com", "*.media.example"],
        direct_dst_nets=["10.20.0.0/16"],
        include_private=True,
    )

    assert _evaluate_pac(rendered, "Example.COM.:443") == "DIRECT"
    assert _evaluate_pac(rendered, "video.media.example.:443") == "DIRECT"
    assert _evaluate_pac(rendered, "badexample.com:443") == (
        "PROXY proxy.example:3128; DIRECT"
    )
    assert _evaluate_pac(rendered, "10.20.3.4:443") == "DIRECT"
    assert _evaluate_pac(rendered, "[fe80::1]:443") == "DIRECT"
    assert _evaluate_pac(rendered, "[2001:db8::10]:3128") == "DIRECT"


def test_pac_target_advertises_only_explicit_proxy_listener() -> None:
    from services import pac_renderer  # type: ignore

    target = pac_renderer.ProxyPacTarget(
        proxy_id="default",
        public_host="proxy.example",
        pac_scheme="http",
        pac_port=80,
        http_proxy_port=3128,
    )

    assert target.proxy_chain == "PROXY proxy.example:3128; DIRECT"
    assert "3129" not in target.proxy_chain


def test_pac_target_display_chain_normalizes_url_shaped_public_host() -> None:
    from services import pac_renderer  # type: ignore

    target = pac_renderer.ProxyPacTarget(
        proxy_id="default",
        public_host="http://Proxy.Example:8080/proxy.pac",
        pac_scheme="http",
        pac_port=80,
        http_proxy_port=3128,
    )

    assert target.proxy_chain == "PROXY proxy.example:3128; DIRECT"
    assert target.proxy_chain_display == "PROXY proxy.example:3128; DIRECT"


def test_pac_target_renders_ordered_backup_proxy_chain_and_optional_direct() -> None:
    from services import pac_renderer  # type: ignore

    target = pac_renderer.ProxyPacTarget(
        proxy_id="default",
        public_host="proxy.example",
        pac_scheme="http",
        pac_port=80,
        http_proxy_port=3128,
        backup_proxies=(("backup-a.example", 3128), ("2001:db8::20", 8080)),
        direct_enabled=False,
    )

    assert (
        target.proxy_chain
        == "PROXY proxy.example:3128; PROXY backup-a.example:3128; PROXY [2001:db8::20]:8080"
    )
    assert (
        target.proxy_chain_display
        == "PROXY proxy.example:3128; PROXY backup-a.example:3128; PROXY [2001:db8::20]:8080"
    )
    assert (
        'return "PROXY proxy.example:3128; PROXY backup-a.example:3128; PROXY [2001:db8::20]:8080";'
        in pac_renderer._render_fallback_pac(target, include_private=False)
    )


def test_pac_target_filters_duplicate_proxy_chain_endpoints() -> None:
    from services import pac_renderer  # type: ignore

    target = pac_renderer.ProxyPacTarget(
        proxy_id="default",
        public_host="Proxy.Example.",
        pac_scheme="http",
        pac_port=80,
        http_proxy_port=3128,
        backup_proxies=(
            ("proxy.example", 3128),
            ("backup.example", 8080),
            ("Backup.Example.", 8080),
            ("backup.example", 8443),
            ("2001:db8::20", 8080),
            ("[2001:0db8::20]:8080", None),
        ),
        direct_enabled=True,
    )

    assert (
        target.proxy_chain == "PROXY proxy.example:3128; PROXY backup.example:8080; "
        "PROXY backup.example:8443; PROXY [2001:db8::20]:8080; DIRECT"
    )
    assert target.proxy_chain.count("PROXY proxy.example:3128") == 1
    assert target.proxy_chain.count("PROXY backup.example:8080") == 1
    assert "[2001:0db8::20]:8080" not in target.proxy_chain


def test_pac_target_filters_stale_invalid_backup_proxy_rows() -> None:
    from services import pac_renderer  # type: ignore

    target = pac_renderer.ProxyPacTarget(
        proxy_id="default",
        public_host="proxy.example",
        pac_scheme="http",
        pac_port=80,
        http_proxy_port=3128,
        backup_proxies=(
            ("http://Backup.Example:8080", 3128),
            ("bad host.example", 8080),
            ("backup.example/path", 8080),
            ("[2001:db8::20]:8443", None),
            ("[2001:db8::30]:abc", 8080),
        ),
    )

    assert target.normalized_backup_proxies == (("[2001:db8::20]", 8443),)
    assert (
        target.proxy_chain
        == "PROXY proxy.example:3128; PROXY [2001:db8::20]:8443; DIRECT"
    )
    assert "backup.example" not in target.proxy_chain
    assert "bad host" not in target.proxy_chain
    assert "/path" not in target.proxy_chain
    assert "2001:db8::30" not in target.proxy_chain


def test_pac_state_sha_is_order_stable_and_content_sensitive() -> None:
    from services import pac_renderer  # type: ignore

    files_a = (
        pac_renderer.RenderedPacFile(relative_path="fallback.pac", content="A"),
        pac_renderer.RenderedPacFile(relative_path="manifest.json", content="B"),
    )
    files_b = tuple(reversed(files_a))
    files_c = (
        pac_renderer.RenderedPacFile(relative_path="fallback.pac", content="A"),
        pac_renderer.RenderedPacFile(relative_path="manifest.json", content="changed"),
    )

    assert pac_renderer.calculate_pac_state_sha(
        files_a
    ) == pac_renderer.calculate_pac_state_sha(files_b)
    assert pac_renderer.calculate_pac_state_sha(
        files_a
    ) != pac_renderer.calculate_pac_state_sha(files_c)


def test_select_manifest_file_prefers_matching_cidr_then_catch_all_then_fallback() -> (
    None
):
    from services import pac_renderer  # type: ignore

    manifest = {
        "fallback_file": "fallback.pac",
        "profiles": [
            {"client_cidr": "", "file": "catch-all.pac"},
            {"client_cidr": "10.0.0.0/8", "file": "corp.pac"},
            {"client_cidr": "bad-cidr", "file": "bad.pac"},
        ],
    }

    assert pac_renderer.select_manifest_file(manifest, "10.2.3.4") == "corp.pac"
    assert pac_renderer.select_manifest_file(manifest, "192.0.2.10") == "catch-all.pac"
    assert (
        pac_renderer.select_manifest_file(
            {"fallback_file": "fallback.pac", "profiles": []}, "not-an-ip"
        )
        == "fallback.pac"
    )


def test_select_manifest_file_matches_ipv4_mapped_ipv6_clients_against_ipv4_profiles() -> (
    None
):
    from services import pac_renderer  # type: ignore

    manifest = {
        "fallback_file": "fallback.pac",
        "profiles": [
            {"client_cidr": "", "file": "catch-all.pac"},
            {"client_cidr": "10.0.0.0/8", "file": "corp.pac"},
            {"client_cidr": "10.2.3.0/24", "file": "branch.pac"},
        ],
    }

    assert (
        pac_renderer.select_manifest_file(manifest, "::ffff:10.2.3.44") == "branch.pac"
    )
    assert pac_renderer.select_manifest_file(manifest, "::ffff:10.9.8.7") == "corp.pac"


def test_select_manifest_file_uses_lowest_profile_id_for_equal_prefix_matches() -> None:
    from services import pac_renderer  # type: ignore

    manifest = {
        "fallback_file": "fallback.pac",
        "profiles": [
            {"profile_id": 50, "client_cidr": "10.2.3.0/24", "file": "later.pac"},
            {"profile_id": 20, "client_cidr": "10.2.3.0/24", "file": "earlier.pac"},
            {"profile_id": 10, "client_cidr": "10.0.0.0/8", "file": "corp.pac"},
        ],
    }

    assert pac_renderer.select_manifest_file(manifest, "10.2.3.44") == "earlier.pac"


def test_select_manifest_file_uses_lowest_profile_id_for_catch_all_fallback() -> None:
    from services import pac_renderer  # type: ignore

    manifest = {
        "fallback_file": "fallback.pac",
        "profiles": [
            {"profile_id": 40, "client_cidr": "", "file": "stale-catch-all.pac"},
            {"profile_id": 8, "client_cidr": "", "file": "canonical-catch-all.pac"},
            {"profile_id": 2, "client_cidr": "10.0.0.0/8", "file": "corp.pac"},
        ],
    }

    assert (
        pac_renderer.select_manifest_file(manifest, "192.0.2.55")
        == "canonical-catch-all.pac"
    )
    assert (
        pac_renderer.select_manifest_file(manifest, "not-an-ip")
        == "canonical-catch-all.pac"
    )


def test_select_manifest_file_keeps_manifest_order_when_profile_ids_are_absent() -> (
    None
):
    from services import pac_renderer  # type: ignore

    manifest = {
        "fallback_file": "fallback.pac",
        "profiles": [
            {"client_cidr": "", "file": "first-catch-all.pac"},
            {"client_cidr": "", "file": "second-catch-all.pac"},
            {"client_cidr": "10.2.3.0/24", "file": "first-branch.pac"},
            {"client_cidr": "10.2.3.0/24", "file": "second-branch.pac"},
        ],
    }

    assert (
        pac_renderer.select_manifest_file(manifest, "10.2.3.44") == "first-branch.pac"
    )
    assert (
        pac_renderer.select_manifest_file(manifest, "192.0.2.55")
        == "first-catch-all.pac"
    )


def test_rendered_pac_does_not_treat_ipv6_literals_as_plain_hosts() -> None:
    from services import pac_renderer  # type: ignore

    rendered = pac_renderer._render_fallback_pac(
        pac_renderer.ProxyPacTarget(
            proxy_id="default",
            public_host="proxy.example",
            pac_scheme="http",
            pac_port=80,
            http_proxy_port=3128,
        ),
        include_private=False,
    )

    assert "var isIpv6Literal = host.indexOf(':') >= 0;" in rendered
    assert "if (!isIpv6Literal && isPlainHostName(host)) return 'DIRECT';" in rendered
    assert "if (isPlainHostName(host)) return 'DIRECT';" not in rendered


def test_rendered_pac_always_bypasses_loopback_ipv4_literals() -> None:
    from services import pac_renderer  # type: ignore

    rendered = pac_renderer._render_fallback_pac(
        pac_renderer.ProxyPacTarget(
            proxy_id="default",
            public_host="proxy.example",
            pac_scheme="http",
            pac_port=80,
            http_proxy_port=3128,
        ),
        include_private=False,
    )

    loopback_rule = (
        "if (isIpv4Address(host) && "
        "isInNet(host, '127.0.0.0', '255.0.0.0')) return 'DIRECT';"
    )

    assert "function isIpv4Address(value)" in rendered
    assert loopback_rule in rendered
    assert "var ip = hostIp();" not in rendered


@pytest.mark.parametrize(
    "host",
    [
        "::1",
        "0:0:0:0:0:0:0:1",
        "0000:0000:0000:0000:0000:0000:0000:0001",
        "0:0:0::0:1",
        "[0:0:0:0:0:0:0:1]",
    ],
)
def test_rendered_pac_always_bypasses_equivalent_ipv6_loopback_literals(
    host: str,
) -> None:
    from services import pac_renderer  # type: ignore

    rendered = pac_renderer._render_fallback_pac(
        pac_renderer.ProxyPacTarget(
            proxy_id="default",
            public_host="proxy.example",
            pac_scheme="http",
            pac_port=80,
            http_proxy_port=3128,
            direct_enabled=False,
        ),
        include_private=False,
    )

    assert _evaluate_pac(rendered, host) == "DIRECT"
    assert _evaluate_pac(rendered, "0:0:0:0:0:0:0:2") == ("PROXY proxy.example:3128")


def test_private_local_destination_metadata_tracks_rendered_pac_direct_rules() -> None:
    from services import pac_renderer  # type: ignore
    from services.pac_private_local import (
        PAC_PRIVATE_LOCAL_DESTINATION_CLASSES,
        pac_private_local_destination_values,
    )
    from services.sslfilter_store import get_sslfilter_store  # type: ignore

    rendered_private = pac_renderer._render_pac(
        "PROXY proxy.example:3128",
        proxy_host="proxy.example",
        direct_domains=[],
        direct_dst_nets=[],
        include_private=True,
    )
    rendered_public_only = pac_renderer._render_pac(
        "PROXY proxy.example:3128",
        proxy_host="proxy.example",
        direct_domains=[],
        direct_dst_nets=[],
        include_private=False,
    )

    assert (
        get_sslfilter_store().private_dst_nets == pac_private_local_destination_values()
    )
    for group in PAC_PRIVATE_LOCAL_DESTINATION_CLASSES:
        for value in group.values:
            if value == "plain hostnames":
                assert "isPlainHostName(host)" in rendered_private
            elif value == "localhost":
                assert "host === 'localhost'" in rendered_private
            elif value == "::1/128":
                assert "isIpv6LoopbackAddress(host)" in rendered_private
            elif value == "fc00::/7":
                assert "ipv6FirstHextetValue >= 0xfc00" in rendered_private
                assert "ipv6FirstHextetValue <= 0xfdff" in rendered_private
                assert "ipv6FirstHextetValue >= 0xfc00" not in rendered_public_only
            elif value == "fe80::/10":
                assert "ipv6FirstHextetValue >= 0xfe80" in rendered_private
                assert "ipv6FirstHextetValue <= 0xfebf" in rendered_private
                assert "ipv6FirstHextetValue >= 0xfe80" not in rendered_public_only
            elif value.startswith("."):
                assert f'dnsDomainIs(host, "{value}")' in rendered_private
            else:
                net, prefix = value.split("/", 1)
                if value == "127.0.0.0/8":
                    assert f"isInNet(host, '{net}', '255.0.0.0')" in rendered_private
                    assert f"isInNet(ip, '{net}', '255.0.0.0')" in rendered_private
                elif prefix == "8":
                    assert f"isInNet(ip, '{net}', '255.0.0.0')" in rendered_private
                    assert (
                        f"isInNet(ip, '{net}', '255.0.0.0')" not in rendered_public_only
                    )
                elif prefix == "12":
                    assert f"isInNet(ip, '{net}', '255.240.0.0')" in rendered_private
                    assert (
                        f"isInNet(ip, '{net}', '255.240.0.0')"
                        not in rendered_public_only
                    )
                elif prefix == "16":
                    assert f"isInNet(ip, '{net}', '255.255.0.0')" in rendered_private
                    assert (
                        f"isInNet(ip, '{net}', '255.255.0.0')"
                        not in rendered_public_only
                    )

        for sample in group.sample_hosts:
            assert _evaluate_pac(rendered_private, sample) == "DIRECT"
            if group.requires_private_toggle:
                assert (
                    _evaluate_pac(rendered_public_only, sample)
                    == "PROXY proxy.example:3128"
                )


def test_rendered_pac_bypasses_private_ipv6_literals_only_when_enabled() -> None:
    from services import pac_renderer  # type: ignore

    target = pac_renderer.ProxyPacTarget(
        proxy_id="default",
        public_host="proxy.example",
        pac_scheme="http",
        pac_port=80,
        http_proxy_port=3128,
        direct_enabled=False,
    )
    private_rendered = pac_renderer._render_fallback_pac(target, include_private=True)
    public_only_rendered = pac_renderer._render_fallback_pac(
        target,
        include_private=False,
    )

    assert (
        "var ipv6FirstHextet = isIpv6Literal ? host.split(':', 1)[0] : '';"
        in private_rendered
    )
    assert "ipv6FirstHextetValue >= 0xfc00" in private_rendered
    assert "ipv6FirstHextetValue <= 0xfdff" in private_rendered
    assert "ipv6FirstHextetValue >= 0xfe80" in private_rendered
    assert "ipv6FirstHextetValue <= 0xfebf" in private_rendered
    assert _evaluate_pac(private_rendered, "fc00::1") == "DIRECT"
    assert _evaluate_pac(private_rendered, "fd12:3456::1") == "DIRECT"
    assert _evaluate_pac(private_rendered, "[fe80::1]") == "DIRECT"
    assert _evaluate_pac(private_rendered, "febf::1") == "DIRECT"
    assert (
        _evaluate_pac(private_rendered, "2001:4860:4860::8888")
        == "PROXY proxy.example:3128"
    )
    assert _evaluate_pac(private_rendered, "fec0::1") == "PROXY proxy.example:3128"

    assert _evaluate_pac(public_only_rendered, "fc00::1") == "PROXY proxy.example:3128"
    assert _evaluate_pac(public_only_rendered, "fe80::1") == "PROXY proxy.example:3128"


def test_rendered_pac_keeps_existing_ipv4_private_and_domain_direct_behavior() -> None:
    from services import pac_renderer  # type: ignore

    rendered = pac_renderer._render_pac(
        "PROXY proxy.example:3128; DIRECT",
        proxy_host="proxy.example",
        direct_domains=["example.com", "*.media.example"],
        direct_dst_nets=["10.20.0.0/16"],
        include_private=True,
    )

    assert _evaluate_pac(rendered, "example.com") == "DIRECT"
    assert _evaluate_pac(rendered, "video.media.example") == "DIRECT"
    assert _evaluate_pac(rendered, "10.20.3.4") == "DIRECT"
    assert _evaluate_pac(rendered, "192.168.10.20") == "DIRECT"
    assert _evaluate_pac(rendered, "203.0.113.7") == (
        "PROXY proxy.example:3128; DIRECT"
    )


def test_pac_ipv4_direct_rules_ignore_ipv6_dns_answer_without_throwing() -> None:
    from services import pac_renderer  # type: ignore

    rendered = pac_renderer._render_pac(
        "PROXY proxy.example:3128; DIRECT",
        proxy_host="proxy.example",
        direct_domains=[],
        direct_dst_nets=["10.20.0.0/16"],
        include_private=True,
    )

    assert (
        _evaluate_pac_with_dns_answer(
            rendered,
            "dualstack.example",
            "2001:db8::10",
        )
        == "PROXY proxy.example:3128; DIRECT"
    )
    assert (
        _evaluate_pac_with_dns_answer(
            rendered,
            "intranet.example",
            "10.20.3.4",
        )
        == "DIRECT"
    )


def test_pac_ipv4_direct_rules_ignore_malformed_dns_answer_without_throwing() -> None:
    from services import pac_renderer  # type: ignore

    rendered = pac_renderer._render_pac(
        "PROXY proxy.example:3128; DIRECT",
        proxy_host="proxy.example",
        direct_domains=[],
        direct_dst_nets=["10.20.0.0/16"],
        include_private=False,
    )

    assert (
        _evaluate_pac_with_dns_answer(
            rendered,
            "stale.example",
            "10.20.3.4 garbage",
        )
        == "PROXY proxy.example:3128; DIRECT"
    )


def test_select_manifest_file_prefers_most_specific_overlapping_cidr() -> None:
    from services import pac_renderer  # type: ignore

    manifest = {
        "fallback_file": "fallback.pac",
        "profiles": [
            {"client_cidr": "10.0.0.0/8", "file": "corp.pac"},
            {"client_cidr": "10.2.3.0/24", "file": "branch.pac"},
            {"client_cidr": "10.2.3.64/26", "file": "lab.pac"},
            {"client_cidr": "2001:db8:1::/48", "file": "ipv6-branch.pac"},
        ],
    }

    # Profile diagnostics should mirror this same longest-prefix match behavior.
    assert pac_renderer.select_manifest_file(manifest, "10.2.3.70") == "lab.pac"
    assert pac_renderer.select_manifest_file(manifest, "10.2.3.8") == "branch.pac"
    assert (
        pac_renderer.select_manifest_file(manifest, "2001:db8:1::20")
        == "ipv6-branch.pac"
    )


def test_select_manifest_file_ignores_malformed_profile_file_paths() -> None:
    from services import pac_renderer  # type: ignore

    manifest = {
        "fallback_file": "fallback.pac",
        "profiles": [
            {"client_cidr": "10.0.0.0/8", "file": "corp.pac"},
            {"client_cidr": "10.2.3.0/24", "file": "/absolute.pac"},
            {"client_cidr": "10.2.3.64/26", "file": "lab.pac"},
        ],
    }

    assert pac_renderer.select_manifest_file(manifest, "10.2.3.70") == "lab.pac"
    assert pac_renderer.select_manifest_file(manifest, "10.2.3.8") == "corp.pac"
    assert (
        pac_renderer.select_manifest_file(
            {"fallback_file": "../fallback.pac", "profiles": []}, "192.0.2.10"
        )
        == "fallback.pac"
    )


def test_materialize_proxy_pac_state_fsyncs_parent_directories_after_publish(
    tmp_path,
    monkeypatch,
) -> None:
    from services import pac_renderer  # type: ignore

    target = tmp_path / "pac"
    state = pac_renderer.ProxyPacState(
        proxy_id="live",
        state_sha256="sha",
        files=(
            pac_renderer.RenderedPacFile(relative_path="fallback.pac", content="A"),
            pac_renderer.RenderedPacFile(
                relative_path="profiles/corp.pac", content="B"
            ),
        ),
    )
    parent_fsyncs: list[str] = []
    dir_fsyncs: list[str] = []
    monkeypatch.setattr(
        pac_renderer,
        "_fsync_parent_dir",
        lambda path: parent_fsyncs.append(Path(path).parent.name),
    )
    monkeypatch.setattr(
        pac_renderer,
        "_fsync_dir",
        lambda path: dir_fsyncs.append(Path(path).name),
    )

    pac_renderer.materialize_proxy_pac_state(target, state=state)

    assert parent_fsyncs == ["payload", "profiles", tmp_path.name, tmp_path.name]
    assert dir_fsyncs == ["payload"]
    assert (target / "fallback.pac").read_text(encoding="utf-8") == "A"
    assert (target / "profiles" / "corp.pac").read_text(encoding="utf-8") == "B"


def test_materialize_proxy_pac_state_fsyncs_parent_directories_during_rollback(
    tmp_path,
    monkeypatch,
) -> None:
    from services import pac_renderer  # type: ignore

    target = tmp_path / "pac"
    target.mkdir()
    (target / "fallback.pac").write_text("original\n", encoding="utf-8")
    state = pac_renderer.ProxyPacState(
        proxy_id="live",
        state_sha256="sha",
        files=(
            pac_renderer.RenderedPacFile(relative_path="fallback.pac", content="A"),
        ),
    )
    parent_fsyncs: list[str] = []
    monkeypatch.setattr(
        pac_renderer,
        "_fsync_parent_dir",
        lambda path: parent_fsyncs.append(Path(path).parent.name),
    )
    real_replace = pac_renderer.Path.replace
    publish_failed = False

    def flaky_replace(self: Path, target_path: object) -> Path:
        nonlocal publish_failed
        if Path(target_path) == target and not publish_failed:
            publish_failed = True
            msg = "simulated publish failure"
            raise OSError(msg)
        return real_replace(self, target_path)

    monkeypatch.setattr(pac_renderer.Path, "replace", flaky_replace)

    with pytest.raises(OSError, match="simulated publish failure"):
        pac_renderer.materialize_proxy_pac_state(target, state=state)

    assert parent_fsyncs == ["payload", tmp_path.name, tmp_path.name, tmp_path.name]
    assert (target / "fallback.pac").read_text(encoding="utf-8") == "original\n"


def test_materialize_proxy_pac_state_surfaces_directory_fsync_io_failure_and_rolls_back(
    tmp_path,
    monkeypatch,
) -> None:
    from services import pac_renderer  # type: ignore

    target = tmp_path / "pac"
    target.mkdir()
    (target / "fallback.pac").write_text("original\n", encoding="utf-8")
    state = pac_renderer.ProxyPacState(
        proxy_id="live",
        state_sha256="sha",
        files=(
            pac_renderer.RenderedPacFile(relative_path="fallback.pac", content="A"),
        ),
    )
    real_fsync = pac_renderer.os.fsync
    directory_fsync_count = 0

    def fail_backup_publish_directory_fsync(fd: int) -> None:
        nonlocal directory_fsync_count
        if stat.S_ISDIR(pac_renderer.os.fstat(fd).st_mode):
            directory_fsync_count += 1
            if directory_fsync_count == 3:
                raise OSError(errno.EIO, "directory fsync failed")
        real_fsync(fd)

    monkeypatch.setattr(pac_renderer.os, "fsync", fail_backup_publish_directory_fsync)

    with pytest.raises(OSError, match="directory fsync failed"):
        pac_renderer.materialize_proxy_pac_state(target, state=state)

    assert (target / "fallback.pac").read_text(encoding="utf-8") == "original\n"
    assert not list(tmp_path.glob(".pac-backup-*"))


def test_materialize_proxy_pac_state_serializes_overlapping_same_target(
    tmp_path,
    monkeypatch,
) -> None:
    from services import pac_renderer  # type: ignore

    target = tmp_path / "pac"
    target.mkdir()
    (target / "fallback.pac").write_text("original\n", encoding="utf-8")
    first_state = pac_renderer.ProxyPacState(
        proxy_id="live",
        state_sha256="sha-a",
        files=(
            pac_renderer.RenderedPacFile(relative_path="fallback.pac", content="A"),
        ),
    )
    second_state = pac_renderer.ProxyPacState(
        proxy_id="live",
        state_sha256="sha-b",
        files=(
            pac_renderer.RenderedPacFile(relative_path="fallback.pac", content="B"),
        ),
    )

    first_thread_holder: dict[str, threading.Thread] = {}
    second_thread_holder: dict[str, threading.Thread] = {}
    first_moved_target_to_backup = threading.Event()
    first_can_publish = threading.Event()
    second_waited_for_target_lock = threading.Event()
    second_replaced_while_first_was_paused = threading.Event()
    errors: list[BaseException] = []

    class InstrumentedLock:
        def __init__(self) -> None:
            self._lock = threading.Lock()

        def acquire(self) -> bool:
            if threading.current_thread() is second_thread_holder.get("thread"):
                second_waited_for_target_lock.set()
            return self._lock.acquire()

        def release(self) -> None:
            self._lock.release()

    target_key = pac_renderer._pac_materialization_target_key(target)
    sentinel = object()
    with pac_renderer._PAC_MATERIALIZATION_TARGET_LOCKS_GUARD:
        original_target_lock = pac_renderer._PAC_MATERIALIZATION_TARGET_LOCKS.get(
            target_key,
            sentinel,
        )
        pac_renderer._PAC_MATERIALIZATION_TARGET_LOCKS[target_key] = InstrumentedLock()

    original_replace = pac_renderer.Path.replace

    def interleaving_replace(self: Path, target_path: object) -> Path:
        result = original_replace(self, target_path)
        current_thread = threading.current_thread()
        target_path_obj = Path(target_path)
        if current_thread is first_thread_holder.get(
            "thread"
        ) and target_path_obj.name.startswith(".pac-backup-"):
            first_moved_target_to_backup.set()
            if not first_can_publish.wait(timeout=2):
                msg = "timed out waiting to resume first publish"
                raise AssertionError(msg)
        elif current_thread is second_thread_holder.get("thread"):
            second_replaced_while_first_was_paused.set()
        return result

    monkeypatch.setattr(pac_renderer.Path, "replace", interleaving_replace)

    def publish(state: object) -> None:
        try:
            pac_renderer.materialize_proxy_pac_state(target, state=state)
        except BaseException as exc:  # pragma: no cover - surfaced below
            errors.append(exc)

    try:
        first_thread = threading.Thread(target=publish, args=(first_state,))
        first_thread_holder["thread"] = first_thread
        first_thread.start()
        assert first_moved_target_to_backup.wait(timeout=2)
        assert not target.exists()

        second_thread = threading.Thread(target=publish, args=(second_state,))
        second_thread_holder["thread"] = second_thread
        second_thread.start()
        assert second_waited_for_target_lock.wait(timeout=2)
        assert not second_replaced_while_first_was_paused.is_set()

        first_can_publish.set()
        first_thread.join(timeout=2)
        second_thread.join(timeout=2)

        assert not first_thread.is_alive()
        assert not second_thread.is_alive()
        if errors:
            msg = "publish thread failed"
            raise AssertionError(msg) from errors[0]
        assert (target / "fallback.pac").read_text(encoding="utf-8") == "B"
        assert not list(tmp_path.glob(".pac-backup-*"))
    finally:
        first_can_publish.set()
        with pac_renderer._PAC_MATERIALIZATION_TARGET_LOCKS_GUARD:
            if original_target_lock is sentinel:
                pac_renderer._PAC_MATERIALIZATION_TARGET_LOCKS.pop(target_key, None)
            else:
                pac_renderer._PAC_MATERIALIZATION_TARGET_LOCKS[target_key] = (
                    original_target_lock
                )


def test_materialize_proxy_pac_state_rejects_unsafe_paths_and_preserves_existing_payload(
    tmp_path,
) -> None:
    from services import pac_renderer  # type: ignore

    target = tmp_path / "pac"
    target.mkdir()
    (target / "fallback.pac").write_text("original\n", encoding="utf-8")

    state = pac_renderer.ProxyPacState(
        proxy_id="live",
        state_sha256="sha",
        files=(
            pac_renderer.RenderedPacFile(relative_path="../escape.pac", content="bad"),
        ),
    )

    with pytest.raises(ValueError):
        pac_renderer.materialize_proxy_pac_state(target, state=state)

    assert (target / "fallback.pac").read_text(encoding="utf-8") == "original\n"


def test_materialize_proxy_pac_state_rejects_backslash_traversal_paths(
    tmp_path,
) -> None:
    from services import pac_renderer  # type: ignore

    target = tmp_path / "pac"
    target.mkdir()
    (target / "fallback.pac").write_text("original\n", encoding="utf-8")

    state = pac_renderer.ProxyPacState(
        proxy_id="live",
        state_sha256="sha",
        files=(
            pac_renderer.RenderedPacFile(
                relative_path=r"subdir\..\..\escape.pac",
                content="bad",
            ),
        ),
    )

    with pytest.raises(ValueError):
        pac_renderer.materialize_proxy_pac_state(target, state=state)

    assert (target / "fallback.pac").read_text(encoding="utf-8") == "original\n"
    assert not (tmp_path / "escape.pac").exists()


def test_materialize_proxy_pac_state_rejects_drive_style_first_segment_paths(
    tmp_path,
) -> None:
    from services import pac_renderer  # type: ignore

    target = tmp_path / "pac"
    target.mkdir()
    (target / "fallback.pac").write_text("original\n", encoding="utf-8")

    state = pac_renderer.ProxyPacState(
        proxy_id="live",
        state_sha256="sha",
        files=(
            pac_renderer.RenderedPacFile(
                relative_path="C:/proxy.pac",
                content="bad",
            ),
        ),
    )

    with pytest.raises(ValueError):
        pac_renderer.materialize_proxy_pac_state(target, state=state)

    assert (target / "fallback.pac").read_text(encoding="utf-8") == "original\n"
    assert not (target / "C:" / "proxy.pac").exists()


def test_substitute_request_host_replaces_placeholder_with_normalized_host() -> None:
    from services import pac_renderer  # type: ignore

    content = json.dumps({"proxy": pac_renderer.PAC_HOST_PLACEHOLDER})
    assert "[2001:4860:4860::8888]" in pac_renderer.substitute_request_host(
        content, "[2001:4860:4860::8888]:3128"
    )


def test_substitute_request_host_replaces_invalid_host_with_loopback() -> None:
    from services import pac_renderer  # type: ignore

    content = (
        f'var proxyHost = "{pac_renderer.PAC_HOST_PLACEHOLDER}";\n'
        f'return "PROXY {pac_renderer.PAC_HOST_PLACEHOLDER}:3128; DIRECT";'
    )

    rendered = pac_renderer.substitute_request_host(content, 'bad"; alert(1); //')

    assert 'bad\\"; alert(1);' not in rendered
    assert 'bad"; alert(1);' not in rendered
    assert 'var proxyHost = "127.0.0.1";' in rendered
    assert 'return "PROXY 127.0.0.1:3128; DIRECT";' in rendered


@pytest.mark.parametrize(
    "request_host",
    [
        "localhost",
        "api.localhost",
        "printer.local",
        "proxy.internal:3128",
        "010.000.000.001",
        "999.999.999.999",
        "0x7f000001",
    ],
)
def test_substitute_request_host_replaces_internal_or_ambiguous_fallback_with_loopback(
    request_host: str,
) -> None:
    from services import pac_renderer  # type: ignore

    content = f'return "PROXY {pac_renderer.PAC_HOST_PLACEHOLDER}:3128; DIRECT";'

    rendered = pac_renderer.substitute_request_host(content, request_host)

    assert rendered == 'return "PROXY 127.0.0.1:3128; DIRECT";'
    assert request_host.split(":", 1)[0] not in rendered


def test_substitute_request_host_preserves_valid_public_fallback_hosts() -> None:
    from services import pac_renderer  # type: ignore

    content = f'return "PROXY {pac_renderer.PAC_HOST_PLACEHOLDER}:3128; DIRECT";'

    assert pac_renderer.substitute_request_host(content, "proxy.example:8080") == (
        'return "PROXY proxy.example:3128; DIRECT";'
    )
    assert pac_renderer.substitute_request_host(content, "93.184.216.34") == (
        'return "PROXY 93.184.216.34:3128; DIRECT";'
    )
    assert pac_renderer.substitute_request_host(content, "[2001:4860:4860::8888]") == (
        'return "PROXY [2001:4860:4860::8888]:3128; DIRECT";'
    )


@pytest.mark.parametrize(
    ("request_host", "expected_host"),
    [
        ("192.168.10.20:8080", "192.168.10.20"),
        ("[fd00::20]:8080", "[fd00::20]"),
    ],
)
def test_substitute_request_host_preserves_private_lan_fallback_hosts(
    request_host: str,
    expected_host: str,
) -> None:
    from services import pac_renderer  # type: ignore

    content = f'return "PROXY {pac_renderer.PAC_HOST_PLACEHOLDER}:3128; DIRECT";'

    assert pac_renderer.substitute_request_host(content, request_host) == (
        f'return "PROXY {expected_host}:3128; DIRECT";'
    )


def test_render_proxy_pac_for_request_replaces_invalid_request_host() -> None:
    from services import pac_renderer  # type: ignore

    rendered = pac_renderer.substitute_request_host(
        pac_renderer.build_emergency_pac(),
        'bad"; alert(1); //',
    )

    assert 'var proxyHost = "127.0.0.1";' in rendered
    assert 'return "PROXY 127.0.0.1:3128; DIRECT";' in rendered


class _FakeSslfilterStore:
    def __init__(self, rules) -> None:
        self._rules = rules

    def list_all(self):
        return self._rules


def _sslfilter_rules_with_private_exclusions():
    return SimpleNamespace(exclude_private_nets=True)


def _default_proxy_pac_target(pac_renderer):
    return pac_renderer.ProxyPacTarget(
        proxy_id="default",
        public_host="proxy.example",
        pac_scheme="http",
        pac_port=80,
        http_proxy_port=3128,
    )


def test_fallback_pac_does_not_turn_proxy_side_exclusion_domains_into_direct_rules(
    monkeypatch,
) -> None:
    from services import pac_renderer  # type: ignore

    rules = type(
        "SslFilterRules",
        (),
        {
            "no_bump_domains": ["no-bump.example", "*.fragile.example"],
            "no_cache_domains": [],
            "no_bump_src_nets": ["192.0.2.0/24"],
            "no_cache_src_nets": [],
            "exclude_private_nets": True,
        },
    )()
    monkeypatch.setattr(
        pac_renderer, "get_sslfilter_store", lambda: _FakeSslfilterStore(rules)
    )

    rendered = pac_renderer._render_fallback_pac(
        _default_proxy_pac_target(pac_renderer),
    )

    assert "no-bump.example" not in rendered
    assert "fragile.example" not in rendered
    assert "192.0.2.0" not in rendered
    assert "isInNet(ip, '10.0.0.0', '255.0.0.0')" in rendered
    assert 'return "PROXY proxy.example:3128; DIRECT";' in rendered


def test_profile_pac_keeps_explicit_direct_rules_and_adds_private_when_enabled(
    monkeypatch,
) -> None:
    from services import pac_renderer  # type: ignore
    from services.pac_profiles_store import PacProfile  # type: ignore

    rules = _sslfilter_rules_with_private_exclusions()
    monkeypatch.setattr(
        pac_renderer, "get_sslfilter_store", lambda: _FakeSslfilterStore(rules)
    )

    rendered = pac_renderer._render_profile_pac(
        PacProfile(
            id=1,
            name="Office",
            client_cidr="192.168.50.0/24",
            direct_domains=["intranet.example"],
            direct_dst_nets=["10.20.0.0/16"],
            created_ts=0,
        ),
        _default_proxy_pac_target(pac_renderer),
    )

    assert "intranet.example" in rendered
    assert "isInNet(ip, '10.20.0.0', '255.255.0.0')" in rendered
    assert "isInNet(ip, '192.168.0.0', '255.255.0.0')" in rendered


def test_profile_pac_wildcard_direct_domain_matches_apex_and_subdomains() -> None:
    from services import pac_renderer  # type: ignore
    from services.pac_profiles_store import PacProfile  # type: ignore

    rendered = pac_renderer._render_profile_pac(
        PacProfile(
            id=1,
            name="Wildcard",
            client_cidr="",
            direct_domains=["*.Example.COM"],
            direct_dst_nets=[],
            created_ts=0,
        ),
        _default_proxy_pac_target(pac_renderer),
        include_private=False,
    )

    assert 'host === "example.com" || dnsDomainIs(host, ".example.com")' in rendered
    assert _evaluate_pac(rendered, "example.com") == "DIRECT"
    assert _evaluate_pac(rendered, "www.example.com") == "DIRECT"
    assert _evaluate_pac(rendered, "other.example.net") == (
        "PROXY proxy.example:3128; DIRECT"
    )


def test_build_proxy_pac_state_reads_sslfilter_rules_once(monkeypatch) -> None:
    from services import pac_renderer  # type: ignore
    from services.pac_profiles_store import PacProfile  # type: ignore

    class _CountingSslfilterStore:
        calls = 0

        def list_all(self):
            self.calls += 1
            return _sslfilter_rules_with_private_exclusions()

    class _FakePacProfilesStore:
        def list_profiles(self):
            return [
                PacProfile(
                    id=2,
                    name="Second",
                    client_cidr="",
                    direct_domains=[],
                    direct_dst_nets=[],
                    created_ts=0,
                ),
                PacProfile(
                    id=1,
                    name="First",
                    client_cidr="10.0.0.0/8",
                    direct_domains=[],
                    direct_dst_nets=[],
                    created_ts=0,
                ),
            ]

        def list_proxy_chain_settings(self):
            return type(
                "PacProxyChainSettings",
                (),
                {
                    "backup_proxies": [
                        type(
                            "PacBackupProxy",
                            (),
                            {"proxy_host": "backup.example", "proxy_port": 8080},
                        )()
                    ],
                    "direct_enabled": False,
                },
            )()

    store = _CountingSslfilterStore()
    monkeypatch.setattr(pac_renderer, "get_sslfilter_store", lambda: store)
    monkeypatch.setattr(pac_renderer, "get_pac_profiles_store", _FakePacProfilesStore)
    monkeypatch.setattr(
        pac_renderer,
        "resolve_proxy_pac_target",
        lambda _proxy_id=None: pac_renderer.ProxyPacTarget(
            proxy_id="default",
            public_host="proxy.example",
            pac_scheme="http",
            pac_port=80,
            http_proxy_port=3128,
            backup_proxies=(("backup.example", 8080),),
            direct_enabled=False,
        ),
    )

    state = pac_renderer.build_proxy_pac_state("default")

    assert store.calls == 1
    assert [
        item.relative_path
        for item in state.files
        if item.relative_path.endswith(".pac")
    ] == [
        "fallback.pac",
        "profile-1.pac",
        "profile-2.pac",
    ]
    manifest = json.loads(
        next(
            item.content
            for item in state.files
            if item.relative_path == "manifest.json"
        )
    )
    assert (
        manifest["proxy_chain"] == "PROXY proxy.example:3128; PROXY backup.example:8080"
    )
    assert manifest["direct_enabled"] is False
    assert manifest["public_pac_path"] == "/proxy.pac"


def test_rendered_pac_replaces_invalid_proxy_chain_host() -> None:
    from services import pac_renderer  # type: ignore

    rendered = pac_renderer._render_fallback_pac(
        pac_renderer.ProxyPacTarget(
            proxy_id="default",
            public_host="proxy'host.example",
            pac_scheme="http",
            pac_port=80,
            http_proxy_port=3128,
            backup_proxies=(("backup.example", 8080),),
        ),
        include_private=False,
    )

    assert (
        'return "PROXY 127.0.0.1:3128; PROXY backup.example:8080; DIRECT";' in rendered
    )
    assert "proxy'host.example" not in rendered


def test_pac_profile_match_uses_manifest_specificity_without_database() -> None:
    from services import pac_profiles_store  # type: ignore

    store = pac_profiles_store.PacProfilesStore()
    profiles = [
        pac_profiles_store.PacProfile(1, "Corp", "10.0.0.0/8", [], [], 1),
        pac_profiles_store.PacProfile(2, "Branch", "10.2.0.0/16", [], [], 2),
        pac_profiles_store.PacProfile(3, "Lab", "10.2.3.0/24", [], [], 3),
        pac_profiles_store.PacProfile(4, "Catch-all", "", [], [], 4),
    ]
    store.list_profiles = lambda: profiles  # type: ignore[method-assign]

    assert store.match_profile_for_client_ip("10.2.3.70").name == "Lab"
    assert store.match_profile_for_client_ip("10.2.4.70").name == "Branch"
    assert store.match_profile_for_client_ip("10.99.4.70").name == "Corp"
    assert store.match_profile_for_client_ip("192.0.2.44").name == "Catch-all"
    assert store.match_profile_for_client_ip("not-an-ip").name == "Catch-all"
