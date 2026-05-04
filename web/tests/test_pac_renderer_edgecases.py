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
    import services.pac_renderer as pac_renderer  # type: ignore

    assert pac_renderer.format_proxy_host("proxy.example:3128") == "proxy.example"
    assert pac_renderer.format_proxy_host("2001:db8::10") == "[2001:db8::10]"
    assert pac_renderer.format_proxy_host("[2001:db8::10]:3128") == "[2001:db8::10]"

    assert pac_renderer._build_pac_url(scheme="http", host="proxy.example", port=80) == "http://proxy.example/proxy.pac"
    assert pac_renderer._build_pac_url(scheme="https", host="proxy.example", port=443) == "https://proxy.example/proxy.pac"
    assert pac_renderer._build_pac_url(scheme="ftp", host="proxy.example", port=8080) == "http://proxy.example:8080/proxy.pac"
    assert pac_renderer._build_pac_url(scheme="http", host="2001:db8::10", port=8080) == "http://[2001:db8::10]:8080/proxy.pac"


def test_rendered_pac_contains_local_direct_rules_and_deduplicates_domains() -> None:
    _add_web_to_path()
    import services.pac_renderer as pac_renderer  # type: ignore

    rendered = pac_renderer._render_pac(
        "PROXY proxy.example:3128; DIRECT",
        proxy_host="proxy.example",
        direct_domains=["Example.COM", "*.example.com", "", "example.com"],
        direct_dst_nets=["10.20.0.0/16", "2001:db8::/32", "not-a-cidr"],
        include_private=True,
    )

    assert "host === 'localhost'" in rendered
    assert "dnsDomainIs(host, \".local\")" in rendered
    assert rendered.count('host === "example.com"') == 1
    assert "isInNet(ip, '10.20.0.0', '255.255.0.0')" in rendered
    assert "isInNet(ip, '192.168.0.0', '255.255.0.0')" in rendered
    assert "2001:db8" not in rendered
    assert "return 'PROXY proxy.example:3128; DIRECT';" in rendered


def test_pac_state_sha_is_order_stable_and_content_sensitive() -> None:
    _add_web_to_path()
    import services.pac_renderer as pac_renderer  # type: ignore

    files_a = (
        pac_renderer.RenderedPacFile(relative_path="fallback.pac", content="A"),
        pac_renderer.RenderedPacFile(relative_path="manifest.json", content="B"),
    )
    files_b = tuple(reversed(files_a))
    files_c = (
        pac_renderer.RenderedPacFile(relative_path="fallback.pac", content="A"),
        pac_renderer.RenderedPacFile(relative_path="manifest.json", content="changed"),
    )

    assert pac_renderer.calculate_pac_state_sha(files_a) == pac_renderer.calculate_pac_state_sha(files_b)
    assert pac_renderer.calculate_pac_state_sha(files_a) != pac_renderer.calculate_pac_state_sha(files_c)


def test_select_manifest_file_prefers_matching_cidr_then_catch_all_then_fallback() -> None:
    _add_web_to_path()
    import services.pac_renderer as pac_renderer  # type: ignore

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
    assert pac_renderer.select_manifest_file({"fallback_file": "fallback.pac", "profiles": []}, "not-an-ip") == "fallback.pac"


def test_materialize_proxy_pac_state_rejects_unsafe_paths_and_preserves_existing_payload(tmp_path) -> None:
    _add_web_to_path()
    import services.pac_renderer as pac_renderer  # type: ignore

    target = tmp_path / "pac"
    target.mkdir()
    (target / "fallback.pac").write_text("original\n", encoding="utf-8")

    state = pac_renderer.ProxyPacState(
        proxy_id="live",
        state_sha256="sha",
        files=(pac_renderer.RenderedPacFile(relative_path="../escape.pac", content="bad"),),
    )

    with pytest.raises(ValueError):
        pac_renderer.materialize_proxy_pac_state(target, state=state)

    assert (target / "fallback.pac").read_text(encoding="utf-8") == "original\n"


def test_substitute_request_host_replaces_placeholder_with_normalized_host() -> None:
    _add_web_to_path()
    import services.pac_renderer as pac_renderer  # type: ignore

    content = json.dumps({"proxy": pac_renderer.PAC_HOST_PLACEHOLDER})
    assert "[2001:db8::20]" in pac_renderer.substitute_request_host(content, "[2001:db8::20]:3128")
