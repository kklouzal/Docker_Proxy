from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest


def _add_web_to_path() -> None:
    web_dir = Path(__file__).resolve().parents[1]
    if str(web_dir) not in sys.path:
        sys.path.insert(0, str(web_dir))


def test_pac_url_and_proxy_host_normalization_handles_defaults_ports_and_ipv6() -> None:
    _add_web_to_path()
    from services import pac_renderer  # type: ignore

    assert pac_renderer.format_proxy_host("proxy.example:3128") == "proxy.example"
    assert pac_renderer.format_proxy_host("2001:db8::10") == "[2001:db8::10]"
    assert pac_renderer.format_proxy_host("[2001:db8::10]:3128") == "[2001:db8::10]"

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
        pac_renderer._build_pac_url(scheme="http", host="2001:db8::10", port=8080)
        == "http://[2001:db8::10]:8080/proxy.pac"
    )


def test_pac_host_normalization_strips_url_schemes_before_ipv6_detection() -> None:
    _add_web_to_path()
    from services import pac_renderer  # type: ignore

    assert (
        pac_renderer.format_proxy_host("http://proxy.example:8080/proxy.pac")
        == "proxy.example"
    )
    assert (
        pac_renderer.format_proxy_host("https://[2001:db8::10]:8443/proxy.pac")
        == "[2001:db8::10]"
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


def test_resolve_proxy_pac_target_honors_public_pac_url_when_registry_is_empty(
    monkeypatch,
) -> None:
    _add_web_to_path()
    from services import pac_renderer  # type: ignore

    class _EmptyRegistry:
        def get_proxy(self, _proxy_id):
            return None

    class _EmptyPacProfilesStore:
        def list_proxy_chain_settings(self):
            return type(
                "PacProxyChainSettings",
                (),
                {"backup_proxies": [], "direct_enabled": True},
            )()

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


def test_resolve_proxy_pac_target_uses_env_endpoint_when_registry_has_no_public_host(
    monkeypatch,
) -> None:
    _add_web_to_path()
    from types import SimpleNamespace

    from services import pac_renderer  # type: ignore

    class _RegistryWithBlankPublicHost:
        def get_proxy(self, _proxy_id):
            return SimpleNamespace(
                public_host="",
                public_pac_scheme="http",
                public_pac_port=80,
                public_http_proxy_port=3128,
            )

    class _EmptyPacProfilesStore:
        def list_proxy_chain_settings(self):
            return type(
                "PacProxyChainSettings",
                (),
                {"backup_proxies": [], "direct_enabled": True},
            )()

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


def test_build_proxy_pac_state_manifest_preserves_configured_public_pac_path(
    monkeypatch,
) -> None:
    _add_web_to_path()
    from services import pac_renderer  # type: ignore

    class _EmptyRegistry:
        def get_proxy(self, _proxy_id):
            return None

    class _EmptyPacProfilesStore:
        def list_profiles(self):
            return []

        def list_proxy_chain_settings(self):
            return type(
                "PacProxyChainSettings",
                (),
                {"backup_proxies": [], "direct_enabled": True},
            )()

    monkeypatch.setattr(pac_renderer, "get_proxy_registry", _EmptyRegistry)
    monkeypatch.setattr(pac_renderer, "get_pac_profiles_store", _EmptyPacProfilesStore)

    class _EmptySslFilterStore:
        def list_all(self):
            return None

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


def test_resolve_proxy_pac_target_prefers_registry_public_endpoint_over_env(
    monkeypatch,
) -> None:
    _add_web_to_path()
    from types import SimpleNamespace

    from services import pac_renderer  # type: ignore

    class _RegistryWithPublicHost:
        def get_proxy(self, _proxy_id):
            return SimpleNamespace(
                public_host="registry.example",
                public_pac_scheme="http",
                public_pac_port=8080,
                public_pac_path="/registered/wpad.dat?site=a",
                public_http_proxy_port=3128,
            )

    class _EmptyPacProfilesStore:
        def list_proxy_chain_settings(self):
            return type(
                "PacProxyChainSettings",
                (),
                {"backup_proxies": [], "direct_enabled": True},
            )()

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


def test_resolve_proxy_pac_target_scopes_chain_settings_to_requested_proxy(
    monkeypatch,
) -> None:
    _add_web_to_path()
    from types import SimpleNamespace

    from services import pac_renderer  # type: ignore
    from services.proxy_context import (  # type: ignore
        get_proxy_id,
        reset_proxy_id,
        set_proxy_id,
    )

    class _Registry:
        def get_proxy(self, proxy_id):
            return SimpleNamespace(
                public_host=f"{proxy_id}.example",
                public_pac_scheme="http",
                public_pac_port=80,
                public_pac_path="/proxy.pac",
                public_http_proxy_port=3128,
            )

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
        target.proxy_chain
        == "PROXY edge-b.example:3128; PROXY backup-b.example:8080"
    )
    assert "backup-a" not in target.proxy_chain
    assert "DIRECT" not in target.proxy_chain


def test_rendered_pac_contains_local_direct_rules_and_deduplicates_domains() -> None:
    _add_web_to_path()
    from services import pac_renderer  # type: ignore

    rendered = pac_renderer._render_pac(
        "PROXY proxy.example:3128; DIRECT",
        proxy_host="proxy.example",
        direct_domains=["Example.COM", "*.example.com", "", "example.com"],
        direct_dst_nets=["10.20.0.0/16", "2001:db8::/32", "not-a-cidr"],
        include_private=True,
    )

    assert "host === 'localhost'" in rendered
    assert 'dnsDomainIs(host, ".local")' in rendered
    assert rendered.count('host === "example.com"') == 1
    assert "isInNet(ip, '10.20.0.0', '255.255.0.0')" in rendered
    assert "isInNet(ip, '192.168.0.0', '255.255.0.0')" in rendered
    assert "2001:db8" not in rendered
    assert 'return "PROXY proxy.example:3128; DIRECT";' in rendered


def test_rendered_pac_normalizes_stale_direct_domain_inputs() -> None:
    _add_web_to_path()
    from services import pac_renderer  # type: ignore

    rendered = pac_renderer._render_pac(
        "PROXY proxy.example:3128; DIRECT",
        proxy_host="proxy.example",
        direct_domains=[
            "https://Bücher.Example:443/path",
            "*.Media.Example",
            "bad domain.example",
            "2001:db8::1",
        ],
        direct_dst_nets=[],
        include_private=False,
    )

    assert 'host === "xn--bcher-kva.example"' in rendered
    assert 'dnsDomainIs(host, ".media.example")' in rendered
    assert "bad domain" not in rendered
    assert "2001:db8" not in rendered


def test_pac_target_advertises_only_explicit_proxy_listener() -> None:
    _add_web_to_path()
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
    _add_web_to_path()
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
    _add_web_to_path()
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


def test_pac_target_filters_stale_invalid_backup_proxy_rows() -> None:
    _add_web_to_path()
    from services import pac_renderer  # type: ignore

    target = pac_renderer.ProxyPacTarget(
        proxy_id="default",
        public_host="proxy.example",
        pac_scheme="http",
        pac_port=80,
        http_proxy_port=3128,
        backup_proxies=(
            ("http://Backup.Example:8080/proxy.pac", 3128),
            ("bad host.example", 8080),
            ("backup.example/path", 8080),
            ("[2001:db8::20]:8443", None),
        ),
    )

    assert target.normalized_backup_proxies == (
        ("backup.example", 3128),
        ("[2001:db8::20]", 8443),
    )
    assert (
        target.proxy_chain
        == "PROXY proxy.example:3128; PROXY backup.example:3128; PROXY [2001:db8::20]:8443; DIRECT"
    )
    assert "bad host" not in target.proxy_chain
    assert "/path" not in target.proxy_chain


def test_pac_state_sha_is_order_stable_and_content_sensitive() -> None:
    _add_web_to_path()
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
    _add_web_to_path()
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


def test_select_manifest_file_prefers_most_specific_overlapping_cidr() -> None:
    _add_web_to_path()
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


def test_materialize_proxy_pac_state_rejects_unsafe_paths_and_preserves_existing_payload(
    tmp_path,
) -> None:
    _add_web_to_path()
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
    _add_web_to_path()
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


def test_substitute_request_host_replaces_placeholder_with_normalized_host() -> None:
    _add_web_to_path()
    from services import pac_renderer  # type: ignore

    content = json.dumps({"proxy": pac_renderer.PAC_HOST_PLACEHOLDER})
    assert "[2001:db8::20]" in pac_renderer.substitute_request_host(
        content, "[2001:db8::20]:3128"
    )


def test_substitute_request_host_escapes_javascript_string_content() -> None:
    _add_web_to_path()
    from services import pac_renderer  # type: ignore

    content = (
        f'var proxyHost = "{pac_renderer.PAC_HOST_PLACEHOLDER}";\n'
        f'return "PROXY {pac_renderer.PAC_HOST_PLACEHOLDER}:3128; DIRECT";'
    )

    rendered = pac_renderer.substitute_request_host(content, 'bad"; alert(1); //')

    assert 'bad\\"; alert(1);' in rendered
    assert 'bad"; alert(1);' not in rendered
    assert 'var proxyHost = "bad\\"; alert(1); ";' in rendered
    assert 'return "PROXY bad\\"; alert(1); :3128; DIRECT";' in rendered


def test_render_proxy_pac_for_request_escapes_request_host_in_generated_pac() -> None:
    _add_web_to_path()
    from services import pac_renderer  # type: ignore

    rendered = pac_renderer.substitute_request_host(
        pac_renderer.build_emergency_pac(),
        'bad"; alert(1); //',
    )

    assert 'var proxyHost = "bad\\"; alert(1); ";' in rendered
    assert 'return "PROXY bad\\"; alert(1); :3128; DIRECT";' in rendered


class _FakeSslfilterStore:
    def __init__(self, rules) -> None:
        self._rules = rules

    def list_all(self):
        return self._rules


def test_fallback_pac_does_not_turn_proxy_side_exclusion_domains_into_direct_rules(
    monkeypatch,
) -> None:
    _add_web_to_path()
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
        pac_renderer.ProxyPacTarget(
            proxy_id="default",
            public_host="proxy.example",
            pac_scheme="http",
            pac_port=80,
            http_proxy_port=3128,
        ),
    )

    assert "no-bump.example" not in rendered
    assert "fragile.example" not in rendered
    assert "192.0.2.0" not in rendered
    assert "isInNet(ip, '10.0.0.0', '255.0.0.0')" in rendered
    assert 'return "PROXY proxy.example:3128; DIRECT";' in rendered


def test_profile_pac_keeps_explicit_direct_rules_and_adds_private_when_enabled(
    monkeypatch,
) -> None:
    _add_web_to_path()
    from services import pac_renderer  # type: ignore
    from services.pac_profiles_store import PacProfile  # type: ignore

    rules = type("SslFilterRules", (), {"exclude_private_nets": True})()
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
        pac_renderer.ProxyPacTarget(
            proxy_id="default",
            public_host="proxy.example",
            pac_scheme="http",
            pac_port=80,
            http_proxy_port=3128,
        ),
    )

    assert "intranet.example" in rendered
    assert "isInNet(ip, '10.20.0.0', '255.255.0.0')" in rendered
    assert "isInNet(ip, '192.168.0.0', '255.255.0.0')" in rendered


def test_build_proxy_pac_state_reads_sslfilter_rules_once(monkeypatch) -> None:
    _add_web_to_path()
    from services import pac_renderer  # type: ignore
    from services.pac_profiles_store import PacProfile  # type: ignore

    class _CountingSslfilterStore:
        calls = 0

        def list_all(self):
            self.calls += 1
            return type("SslFilterRules", (), {"exclude_private_nets": True})()

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


def test_rendered_pac_quotes_proxy_chain_as_javascript_literal() -> None:
    _add_web_to_path()
    from services import pac_renderer  # type: ignore

    rendered = pac_renderer._render_fallback_pac(
        pac_renderer.ProxyPacTarget(
            proxy_id="default",
            public_host="proxy'host.example",
            pac_scheme="http",
            pac_port=80,
            http_proxy_port=3128,
            backup_proxies=(("backup'host.example", 8080),),
        ),
        include_private=False,
    )

    assert (
        "return \"PROXY proxy'host.example:3128; PROXY backup'host.example:8080; DIRECT\";"
        in rendered
    )
    assert "return 'PROXY" not in rendered


def test_pac_profile_match_uses_manifest_specificity_without_database() -> None:
    _add_web_to_path()
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
