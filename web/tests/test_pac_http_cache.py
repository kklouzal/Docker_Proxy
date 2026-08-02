from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import pytest


def _add_repo_paths() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    web_root = repo_root / "web"
    for path in (repo_root, web_root):
        path_str = str(path)
        if path_str not in sys.path:
            sys.path.insert(0, path_str)


@pytest.fixture
def pac_http():
    _add_repo_paths()
    from services import pac_http as module  # type: ignore

    return module


def _rendered_state_sha(
    pac_http, manifest: dict[str, object], files: dict[str, str]
) -> str:
    manifest_for_hash = dict(manifest)
    manifest_for_hash["state_sha256"] = ""
    manifest_text = json.dumps(manifest_for_hash, indent=2, sort_keys=True) + "\n"
    rendered_files = [
        pac_http.RenderedPacFile(relative_path=path, content=content)
        for path, content in sorted(files.items())
    ]
    rendered_files.append(
        pac_http.RenderedPacFile(
            relative_path=pac_http.PAC_MANIFEST_FILENAME,
            content=manifest_text,
        ),
    )
    return pac_http.calculate_pac_state_sha(rendered_files)


def _write_verified_pac_state(
    pac_http,
    pac_dir: Path,
    *,
    manifest: dict[str, object],
    files: dict[str, str],
) -> str:
    pac_dir.mkdir(parents=True, exist_ok=True)
    state_sha = _rendered_state_sha(pac_http, manifest, files)
    manifest = dict(manifest)
    manifest["state_sha256"] = state_sha
    for rel_path, content in files.items():
        path = pac_dir / rel_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    (pac_dir / pac_http.PAC_MANIFEST_FILENAME).write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (pac_dir / pac_http.PAC_STATE_SHA_FILENAME).write_text(
        state_sha + "\n",
        encoding="utf-8",
    )
    return state_sha


def test_pac_render_dir_is_cached_until_explicitly_cleared(
    monkeypatch, pac_http
) -> None:
    pac_http.pac_render_dir.cache_clear()
    monkeypatch.setenv("PAC_RENDER_DIR", "/tmp/pac-one")

    first = pac_http.pac_render_dir()
    monkeypatch.setenv("PAC_RENDER_DIR", "/tmp/pac-two")
    second = pac_http.pac_render_dir()

    assert first == "/tmp/pac-one"
    assert second == "/tmp/pac-one"

    pac_http.pac_render_dir.cache_clear()
    assert pac_http.pac_render_dir() == "/tmp/pac-two"


def test_client_ip_ignores_untrusted_forwarded_headers(monkeypatch, pac_http) -> None:
    monkeypatch.delenv("PAC_TRUSTED_PROXY_CIDRS", raising=False)

    assert (
        pac_http.client_ip_from_headers(
            {"X-Forwarded-For": "10.2.3.4", "X-Real-IP": "10.2.3.5"},
            "198.51.100.10",
        )
        == "198.51.100.10"
    )


def test_client_ip_honors_forwarded_headers_from_trusted_proxy(
    monkeypatch, pac_http
) -> None:
    monkeypatch.setenv("PAC_TRUSTED_PROXY_CIDRS", "192.0.2.0/24, 2001:db8::/32")

    assert (
        pac_http.client_ip_from_headers(
            {"X-Forwarded-For": "10.2.3.4, 192.0.2.55"},
            "192.0.2.10",
        )
        == "10.2.3.4"
    )
    assert (
        pac_http.client_ip_from_headers({"X-Real-IP": "2001:db8:1::20"}, "2001:db8::1")
        == "2001:db8:1::20"
    )


def test_trusted_forwarded_headers_accept_ipv4_mapped_proxy_peer(
    monkeypatch, pac_http
) -> None:
    monkeypatch.setenv("PAC_TRUSTED_PROXY_CIDRS", "192.0.2.0/24")

    assert pac_http.forwarded_headers_trusted("::ffff:192.0.2.10") is True
    assert (
        pac_http.client_ip_from_headers(
            {"X-Forwarded-For": "10.2.3.4"},
            "::ffff:192.0.2.10",
        )
        == "10.2.3.4"
    )
    assert (
        pac_http.request_host_from_headers(
            {
                "Host": "internal-proxy.example:5000",
                "X-Forwarded-Host": "public-proxy.example:80",
            },
            "::ffff:192.0.2.10",
        )
        == "public-proxy.example:80"
    )


def test_client_ip_rejects_invalid_forwarded_headers(monkeypatch, pac_http) -> None:
    monkeypatch.setenv("PAC_TRUSTED_PROXY_CIDRS", "192.0.2.0/24")

    assert (
        pac_http.client_ip_from_headers(
            {"X-Forwarded-For": "not-an-ip", "X-Real-IP": "also-bad"},
            "192.0.2.10",
        )
        == "192.0.2.10"
    )


def test_local_pac_cache_ignores_manifest_paths_outside_pac_dir(
    tmp_path, pac_http
) -> None:
    pac_dir = tmp_path / "pac"
    pac_dir.mkdir()
    (tmp_path / "secret.pac").write_text("SECRET", encoding="utf-8")
    (pac_dir / ".state-sha256").write_text("state-one\n", encoding="utf-8")
    (pac_dir / "manifest.json").write_text(
        """{"fallback_file":"fallback.pac","state_sha256":"state-one","profiles":[{"client_cidr":"10.0.0.0/8","file":"../secret.pac"}]}""",
        encoding="utf-8",
    )
    (pac_dir / "fallback.pac").write_text(
        "SAFE __PAC_PROXY_HOST__",
        encoding="utf-8",
    )

    data = pac_http.LocalPacCache(str(pac_dir)).resolve(
        client_ip="10.1.2.3",
        request_host="proxy.example:3128",
    )

    assert data == b"SAFE proxy.example"
    assert b"SECRET" not in (data or b"")


def test_local_pac_cache_ignores_manifest_symlink_outside_pac_dir(
    tmp_path,
    pac_http,
) -> None:
    pac_dir = tmp_path / "pac"
    pac_dir.mkdir()
    (tmp_path / "secret.pac").write_text("SECRET", encoding="utf-8")
    (pac_dir / "linked.pac").symlink_to(tmp_path / "secret.pac")
    (pac_dir / ".state-sha256").write_text("state-one\n", encoding="utf-8")
    (pac_dir / "manifest.json").write_text(
        """{"fallback_file":"linked.pac","state_sha256":"state-one"}""",
        encoding="utf-8",
    )

    data = pac_http.LocalPacCache(str(pac_dir)).resolve(
        client_ip="10.1.2.3",
        request_host="proxy.example:3128",
    )

    assert data is None


def test_request_host_ignores_untrusted_forwarded_host(monkeypatch, pac_http) -> None:
    monkeypatch.setenv("PAC_TRUSTED_PROXY_CIDRS", "198.51.100.0/24")

    assert (
        pac_http.request_host_from_headers(
            {"Host": "internal-proxy.example:5000", "X-Forwarded-Host": "public-proxy"},
            "203.0.113.10",
        )
        == "internal-proxy.example:5000"
    )


def test_request_host_uses_trusted_forwarded_host(monkeypatch, pac_http) -> None:
    monkeypatch.setenv("PAC_TRUSTED_PROXY_CIDRS", "198.51.100.0/24")

    assert (
        pac_http.request_host_from_headers(
            {
                "Host": "internal-proxy.example:5000",
                "X-Forwarded-Host": "public-proxy.example:80, internal-proxy.example:5000",
            },
            "198.51.100.10",
        )
        == "public-proxy.example:80"
    )


def test_request_host_lowercases_dns_authority_and_preserves_port(pac_http) -> None:
    assert (
        pac_http.request_host_from_headers({"Host": "Proxy.Example:3128"})
        == "proxy.example:3128"
    )


def test_request_host_rejects_single_label_dns_authority(pac_http) -> None:
    assert pac_http.request_host_from_headers({"Host": "proxy"}) == "127.0.0.1"
    assert pac_http.request_host_from_headers({"Host": "Proxy:3128"}) == "127.0.0.1"


@pytest.mark.parametrize(
    "host",
    [
        "localhost.localdomain",
        "api.localhost:8080",
        "printer.local",
        "proxy.internal:3128",
        "gateway.home.arpa",
    ],
)
def test_request_host_rejects_reserved_internal_dns_authorities(
    pac_http, host: str
) -> None:
    assert pac_http.request_host_from_headers({"Host": host}) == "127.0.0.1"


def test_request_host_falls_back_to_host_when_trusted_forwarded_host_is_reserved(
    monkeypatch, pac_http
) -> None:
    monkeypatch.setenv("PAC_TRUSTED_PROXY_CIDRS", "198.51.100.0/24")

    assert (
        pac_http.request_host_from_headers(
            {
                "Host": "public-proxy.example:5000",
                "X-Forwarded-Host": "api.localhost:8080",
            },
            "198.51.100.10",
        )
        == "public-proxy.example:5000"
    )
    assert (
        pac_http.request_host_from_headers(
            {
                "Host": "public-proxy.example:5000",
                "X-Forwarded-Host": "proxy.internal, public-proxy.example:5000",
            },
            "198.51.100.10",
        )
        == "public-proxy.example:5000"
    )


def test_request_host_lowercases_trusted_forwarded_dns_authority(
    monkeypatch, pac_http
) -> None:
    monkeypatch.setenv("PAC_TRUSTED_PROXY_CIDRS", "198.51.100.0/24")

    assert (
        pac_http.request_host_from_headers(
            {
                "Host": "internal-proxy.example:5000",
                "X-Forwarded-Host": "Public-Proxy.Example:8080, internal-proxy.example:5000",
            },
            "198.51.100.10",
        )
        == "public-proxy.example:8080"
    )


def test_request_host_preserves_valid_authority_shapes(monkeypatch, pac_http) -> None:
    monkeypatch.setenv("PAC_TRUSTED_PROXY_CIDRS", "198.51.100.0/24")

    assert pac_http.request_host_from_headers({"Host": "192.0.2.10:8080"}) == (
        "192.0.2.10:8080"
    )
    assert pac_http.request_host_from_headers({"Host": "[2001:db8::20]:8443"}) == (
        "[2001:db8::20]:8443"
    )
    assert pac_http.request_host_from_headers({"Host": "2001:db8::20"}) == (
        "2001:db8::20"
    )
    assert (
        pac_http.request_host_from_headers(
            {
                "Host": "internal-proxy.example:5000",
                "X-Forwarded-Host": "public-proxy.example:80",
            },
            "198.51.100.10",
        )
        == "public-proxy.example:80"
    )


@pytest.mark.parametrize(
    "host",
    [
        "127.0.0.1",
        "0.0.0.0:3128",
        "169.254.10.20",
        "224.0.0.1:8080",
        "[::1]:8080",
        "::",
        "[fe80::1]:3128",
        "ff02::1",
        "[::ffff:127.0.0.1]:8080",
    ],
)
def test_request_host_rejects_unsafe_ip_literal_authorities(
    pac_http, host: str
) -> None:
    assert pac_http._normalize_request_authority(host) == ""
    assert pac_http.request_host_from_headers({"Host": host}) == "127.0.0.1"


@pytest.mark.parametrize(
    "forwarded_host",
    [
        "127.0.0.1:3128",
        "0.0.0.0",  # noqa: S104 - verifies wildcard authorities are rejected.
        "169.254.10.20:8080",
        "239.1.2.3",
        "[::1]:8080",
        "[::]:3128",
        "fe80::1",
        "[ff02::1]:8080",
    ],
)
def test_request_host_falls_back_from_unsafe_trusted_forwarded_ip_authority(
    monkeypatch, pac_http, forwarded_host: str
) -> None:
    monkeypatch.setenv("PAC_TRUSTED_PROXY_CIDRS", "198.51.100.0/24")

    assert (
        pac_http.request_host_from_headers(
            {
                "Host": "public-proxy.example:5000",
                "X-Forwarded-Host": forwarded_host,
            },
            "198.51.100.10",
        )
        == "public-proxy.example:5000"
    )


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("192.168.10.20:3128", "192.168.10.20:3128"),
        ("[fd00::20]:8080", "[fd00::20]:8080"),
    ],
)
def test_request_host_preserves_private_lan_ip_authorities(
    pac_http, host: str, expected: str
) -> None:
    assert pac_http.request_host_from_headers({"Host": host}) == expected


def test_request_host_rejects_scoped_ipv6_authority_values(
    monkeypatch, pac_http
) -> None:
    monkeypatch.setenv("PAC_TRUSTED_PROXY_CIDRS", "198.51.100.0/24")

    bad_hosts = [
        "fe80::1%eth0",
        "[fe80::1%eth0]",
        "[fe80::1%eth0]:8080",
    ]

    for bad_host in bad_hosts:
        assert pac_http.request_host_from_headers({"Host": bad_host}) == "127.0.0.1"

    assert (
        pac_http.request_host_from_headers(
            {"Host": "internal-proxy.example:5000", "X-Forwarded-Host": "fe80::1%eth0"},
            "198.51.100.10",
        )
        == "internal-proxy.example:5000"
    )
    assert (
        pac_http.request_host_from_headers(
            {
                "Host": "internal-proxy.example:5000",
                "X-Forwarded-Host": "[fe80::1%eth0]:8080",
            },
            "198.51.100.10",
        )
        == "internal-proxy.example:5000"
    )


def test_request_host_rejects_malformed_host_header_values(pac_http) -> None:
    bad_hosts = [
        "",
        "   ",
        "bad host.example",
        "bad\t.example",
        "bad\x1f.example",
        "bäd.example",
        r"bad\host.example",
        "proxy.example/path",
        "proxy.example?x=1",
        "proxy.example#frag",
        "user@proxy.example",
        "http://proxy.example:8080",
        "//proxy.example:8080",
        "proxy.example:bad",
        "proxy.example:0",
        "proxy.example:65536",
        "2130706433",
        "017700000001",
        "127.1",
        "[2001:db8::20",
        "[2001:db8::20]:bad",
    ]

    for bad_host in bad_hosts:
        assert pac_http.request_host_from_headers({"Host": bad_host}) == "127.0.0.1"


def test_request_host_falls_back_when_trusted_forwarded_host_is_malformed(
    monkeypatch, pac_http
) -> None:
    monkeypatch.setenv("PAC_TRUSTED_PROXY_CIDRS", "198.51.100.0/24")

    assert (
        pac_http.request_host_from_headers(
            {
                "Host": "internal-proxy.example:5000",
                "X-Forwarded-Host": "http://public-proxy.example:80/proxy.pac",
            },
            "198.51.100.10",
        )
        == "internal-proxy.example:5000"
    )
    assert (
        pac_http.request_host_from_headers(
            {"Host": "bad host", "X-Forwarded-Host": "user@public.example"},
            "198.51.100.10",
        )
        == "127.0.0.1"
    )


def test_local_pac_cache_exposes_configured_public_pac_path(tmp_path, pac_http) -> None:
    pac_dir = tmp_path / "pac"
    pac_dir.mkdir()
    (pac_dir / ".state-sha256").write_text("state-one\n", encoding="utf-8")
    (pac_dir / "manifest.json").write_text(
        """{"fallback_file":"fallback.pac","public_pac_path":"/download/wpad.dat?site=lab","state_sha256":"state-one"}""",
        encoding="utf-8",
    )
    (pac_dir / "fallback.pac").write_text("PAC", encoding="utf-8")

    cache = pac_http.LocalPacCache(str(pac_dir))

    assert cache.public_paths() == frozenset(
        {"/proxy.pac", "/wpad.dat", "/download/wpad.dat?site=lab"}
    )
    assert cache.public_request_allowed("/download/wpad.dat", "site=lab") is True
    assert cache.public_request_allowed("/download/wpad.dat") is False


def test_local_pac_cache_matches_percent_encoded_public_pac_path(
    tmp_path, pac_http
) -> None:
    pac_dir = tmp_path / "pac"
    pac_dir.mkdir()
    (pac_dir / ".state-sha256").write_text("state-one\n", encoding="utf-8")
    (pac_dir / "manifest.json").write_text(
        """{"fallback_file":"fallback.pac","public_pac_path":"/download/%77pad.dat?site=lab","state_sha256":"state-one"}""",
        encoding="utf-8",
    )
    (pac_dir / "fallback.pac").write_text("PAC", encoding="utf-8")

    cache = pac_http.LocalPacCache(str(pac_dir))

    assert "/download/wpad.dat?site=lab" in cache.public_paths()
    assert "/download/wpad.dat" not in cache.public_paths()
    assert cache.public_request_allowed("/download/wpad.dat", "site=lab") is True


def test_local_pac_cache_exposes_configured_public_pac_url_target(
    tmp_path,
    pac_http,
) -> None:
    pac_dir = tmp_path / "pac"
    pac_dir.mkdir()
    (pac_dir / ".state-sha256").write_text("state-one\n", encoding="utf-8")
    (pac_dir / "manifest.json").write_text(
        """{"fallback_file":"fallback.pac","public_pac_url":"https://pac.example/download/wpad.dat?site=lab","state_sha256":"state-one"}""",
        encoding="utf-8",
    )
    (pac_dir / "fallback.pac").write_text("PAC", encoding="utf-8")

    cache = pac_http.LocalPacCache(str(pac_dir))

    assert "/download/wpad.dat?site=lab" in cache.public_paths()
    assert "/download/wpad.dat" not in cache.public_paths()
    assert cache.public_request_allowed("/download/wpad.dat", "site=lab") is True


def test_local_pac_cache_rejects_public_pac_path_with_encoded_separator(
    tmp_path, pac_http
) -> None:
    pac_dir = tmp_path / "pac"
    pac_dir.mkdir()
    (pac_dir / ".state-sha256").write_text("state-one\n", encoding="utf-8")
    (pac_dir / "manifest.json").write_text(
        """{"fallback_file":"fallback.pac","public_pac_path":"/download%2fwpad.dat"}""",
        encoding="utf-8",
    )
    (pac_dir / "fallback.pac").write_text("PAC", encoding="utf-8")

    cache = pac_http.LocalPacCache(str(pac_dir))

    assert "/download/wpad.dat" not in cache.public_paths()
    assert cache.public_request_allowed("/download/wpad.dat") is False


def test_local_pac_cache_rejects_credentialed_public_pac_url(
    tmp_path, pac_http
) -> None:
    pac_dir = tmp_path / "pac"
    pac_dir.mkdir()
    (pac_dir / ".state-sha256").write_text("state-one\n", encoding="utf-8")
    (pac_dir / "manifest.json").write_text(
        """{"fallback_file":"fallback.pac","public_pac_url":"https://user:secret@pac.example/download/wpad.dat?site=lab"}""",
        encoding="utf-8",
    )
    (pac_dir / "fallback.pac").write_text("PAC", encoding="utf-8")

    cache = pac_http.LocalPacCache(str(pac_dir))

    assert "/download/wpad.dat" not in cache.public_paths()
    assert cache.public_request_allowed("/download/wpad.dat", "site=lab") is False


@pytest.mark.parametrize(
    "url", ["https:/download/wpad.dat", "https:///download/wpad.dat"]
)
def test_local_pac_cache_rejects_missing_authority_public_pac_url(
    tmp_path,
    pac_http,
    url: str,
) -> None:
    pac_dir = tmp_path / "pac"
    pac_dir.mkdir()
    (pac_dir / ".state-sha256").write_text("state-one\n", encoding="utf-8")
    (pac_dir / "manifest.json").write_text(
        json.dumps({"fallback_file": "fallback.pac", "public_pac_url": url}),
        encoding="utf-8",
    )
    (pac_dir / "fallback.pac").write_text("PAC", encoding="utf-8")

    cache = pac_http.LocalPacCache(str(pac_dir))

    assert "/download/wpad.dat" not in cache.public_paths()
    assert cache.public_request_allowed("/download/wpad.dat") is False


def test_local_pac_cache_requires_configured_public_pac_query(
    tmp_path, pac_http
) -> None:
    pac_dir = tmp_path / "pac"
    pac_dir.mkdir()
    (pac_dir / ".state-sha256").write_text("state-one\n", encoding="utf-8")
    (pac_dir / "manifest.json").write_text(
        """{"fallback_file":"fallback.pac","public_pac_path":"/download/wpad.dat?site=lab","state_sha256":"state-one"}""",
        encoding="utf-8",
    )
    (pac_dir / "fallback.pac").write_text("PAC", encoding="utf-8")

    cache = pac_http.LocalPacCache(str(pac_dir))

    assert cache.public_request_allowed("/download/wpad.dat", "site=lab") is True
    assert cache.public_request_allowed("/download/wpad.dat", b"site=lab") is True
    assert cache.public_request_allowed("/download/wpad.dat", "site=other") is False
    assert cache.public_request_allowed("/download/wpad.dat", "") is False
    assert cache.public_request_allowed("/proxy.pac", "any=query") is True


def test_local_pac_cache_reloads_when_materialized_files_change(
    tmp_path, pac_http
) -> None:
    pac_dir = tmp_path / "pac"
    pac_dir.mkdir()
    (pac_dir / ".state-sha256").write_text("state-one\n", encoding="utf-8")
    (pac_dir / "manifest.json").write_text(
        """{"fallback_file":"fallback.pac","state_sha256":"state-one"}""",
        encoding="utf-8",
    )
    (pac_dir / "fallback.pac").write_text(
        'function FindProxyForURL(){return "PROXY one";}\n',
        encoding="utf-8",
    )

    cache = pac_http.LocalPacCache(str(pac_dir))
    assert cache.resolve(client_ip="192.0.2.10", request_host="proxy.example") == (
        b'function FindProxyForURL(){return "PROXY one";}\n'
    )

    replacement = tmp_path / "replacement"
    replacement.mkdir()
    (replacement / ".state-sha256").write_text("state-two\n", encoding="utf-8")
    (replacement / "manifest.json").write_text(
        """{"fallback_file":"fallback.pac","state_sha256":"state-two"}""",
        encoding="utf-8",
    )
    (replacement / "fallback.pac").write_text(
        'function FindProxyForURL(){return "PROXY two";}\n',
        encoding="utf-8",
    )

    old = tmp_path / "old-pac"
    pac_dir.replace(old)
    replacement.replace(pac_dir)

    assert cache.resolve(client_ip="192.0.2.10", request_host="proxy.example") == (
        b'function FindProxyForURL(){return "PROXY two";}\n'
    )


def test_local_pac_cache_reloads_when_referenced_pac_file_changes(
    tmp_path, pac_http
) -> None:
    pac_dir = tmp_path / "pac"
    pac_dir.mkdir()
    (pac_dir / ".state-sha256").write_text("state-one\n", encoding="utf-8")
    (pac_dir / "manifest.json").write_text(
        """{"fallback_file":"fallback.pac","state_sha256":"state-one"}""",
        encoding="utf-8",
    )
    fallback = pac_dir / "fallback.pac"
    fallback.write_text(
        'function FindProxyForURL(){return "PROXY one";}\n',
        encoding="utf-8",
    )

    cache = pac_http.LocalPacCache(str(pac_dir))
    assert cache.resolve(client_ip="192.0.2.10", request_host="proxy.example") == (
        b'function FindProxyForURL(){return "PROXY one";}\n'
    )

    fallback.write_text(
        'function FindProxyForURL(){return "PROXY two repaired";}\n',
        encoding="utf-8",
    )

    assert cache.resolve(client_ip="192.0.2.10", request_host="proxy.example") == (
        b'function FindProxyForURL(){return "PROXY two repaired";}\n'
    )


def test_local_pac_cache_warm_reload_scans_pac_signatures_once(
    tmp_path,
    pac_http,
) -> None:
    pac_dir = tmp_path / "pac"
    pac_dir.mkdir()
    (pac_dir / ".state-sha256").write_text("state-one\n", encoding="utf-8")
    (pac_dir / "manifest.json").write_text(
        """{"fallback_file":"fallback.pac","state_sha256":"state-one"}""",
        encoding="utf-8",
    )
    fallback = pac_dir / "fallback.pac"
    fallback.write_text(
        'function FindProxyForURL(){return "PROXY one";}\n',
        encoding="utf-8",
    )

    class CountingPacCache(pac_http.LocalPacCache):
        def __init__(self, pac_dir: str) -> None:
            super().__init__(pac_dir)
            self.pac_signature_requests: list[tuple[str, ...]] = []

        def _pac_file_signatures(self, rel_paths: object):
            if isinstance(rel_paths, (list, set, tuple, frozenset)):
                self.pac_signature_requests.append(
                    tuple(sorted(str(item) for item in rel_paths))
                )
            else:
                self.pac_signature_requests.append(())
            return super()._pac_file_signatures(rel_paths)

    cache = CountingPacCache(str(pac_dir))
    first = b'function FindProxyForURL(){return "PROXY one";}\n'
    second = b'function FindProxyForURL(){return "PROXY two";}\n'

    assert cache.resolve(client_ip="192.0.2.10", request_host="proxy.example") == first

    cache.pac_signature_requests.clear()
    assert cache.resolve(client_ip="192.0.2.10", request_host="proxy.example") == first
    assert cache.pac_signature_requests == [("fallback.pac",)]

    fallback.write_text(
        'function FindProxyForURL(){return "PROXY two";}\n',
        encoding="utf-8",
    )
    cache.pac_signature_requests.clear()

    assert cache.resolve(client_ip="192.0.2.10", request_host="proxy.example") == second
    assert cache.pac_signature_requests == [
        ("fallback.pac",),
        ("fallback.pac",),
        ("fallback.pac",),
    ]


def test_local_pac_cache_reloads_when_referenced_pac_file_is_replaced_same_signature(
    tmp_path, pac_http
) -> None:
    pac_dir = tmp_path / "pac"
    pac_dir.mkdir()
    (pac_dir / ".state-sha256").write_text("state-one\n", encoding="utf-8")
    (pac_dir / "manifest.json").write_text(
        """{"fallback_file":"fallback.pac","state_sha256":"state-one"}""",
        encoding="utf-8",
    )
    fallback = pac_dir / "fallback.pac"
    old_content = 'function FindProxyForURL(){return "PROXY one";}\n'
    new_content = 'function FindProxyForURL(){return "DIRECTtwo";}\n'
    assert len(old_content) == len(new_content)
    fallback.write_text(old_content, encoding="utf-8")
    stat = fallback.stat()

    cache = pac_http.LocalPacCache(str(pac_dir))
    assert cache.resolve(client_ip="192.0.2.10", request_host="proxy.example") == (
        old_content.encode("utf-8")
    )

    replacement = pac_dir / ".fallback.pac.tmp"
    replacement.write_text(new_content, encoding="utf-8")
    replacement.replace(fallback)
    os.utime(fallback, ns=(stat.st_atime_ns, stat.st_mtime_ns))

    assert cache.resolve(client_ip="192.0.2.10", request_host="proxy.example") == (
        new_content.encode("utf-8")
    )


def test_local_pac_cache_reloads_when_referenced_pac_file_ctime_changes_only(
    tmp_path,
    pac_http,
) -> None:
    pac_dir = tmp_path / "pac"
    pac_dir.mkdir()
    (pac_dir / ".state-sha256").write_text("state-one\n", encoding="utf-8")
    (pac_dir / "manifest.json").write_text(
        """{"fallback_file":"fallback.pac","state_sha256":"state-one"}""",
        encoding="utf-8",
    )
    fallback = pac_dir / "fallback.pac"
    old_content = 'function FindProxyForURL(){return "PROXY one";}\n'
    new_content = 'function FindProxyForURL(){return "DIRECTtwo";}\n'
    assert len(old_content) == len(new_content)
    fallback.write_text(old_content, encoding="utf-8")
    stat = fallback.stat()

    cache = pac_http.LocalPacCache(str(pac_dir))
    assert cache.resolve(client_ip="192.0.2.10", request_host="proxy.example") == (
        old_content.encode("utf-8")
    )

    time.sleep(0.01)
    fallback.write_text(new_content, encoding="utf-8")
    os.utime(fallback, ns=(stat.st_atime_ns, stat.st_mtime_ns))

    assert fallback.stat().st_ino == stat.st_ino
    assert cache.resolve(client_ip="192.0.2.10", request_host="proxy.example") == (
        new_content.encode("utf-8")
    )


def test_local_pac_cache_rejects_marker_manifest_sha_mismatch(
    tmp_path, pac_http
) -> None:
    pac_dir = tmp_path / "pac"
    pac_dir.mkdir()
    (pac_dir / ".state-sha256").write_text("state-two\n", encoding="utf-8")
    (pac_dir / "manifest.json").write_text(
        """{"fallback_file":"fallback.pac","state_sha256":"state-one"}""",
        encoding="utf-8",
    )
    (pac_dir / "fallback.pac").write_text(
        'function FindProxyForURL(){return "PROXY stale";}\n',
        encoding="utf-8",
    )

    cache = pac_http.LocalPacCache(str(pac_dir))

    assert cache.resolve(client_ip="192.0.2.10", request_host="proxy.example") is None
    assert cache.public_paths() == frozenset({"/proxy.pac", "/wpad.dat"})


def test_local_pac_cache_rejects_tampered_pac_file_with_valid_state_sha(
    tmp_path,
    pac_http,
) -> None:
    _add_repo_paths()
    from services.pac_renderer import RenderedPacFile, calculate_pac_state_sha

    pac_dir = tmp_path / "pac"
    pac_dir.mkdir()
    manifest = {"fallback_file": "fallback.pac", "profiles": [], "state_sha256": ""}
    trusted_fallback = 'function FindProxyForURL(){return "PROXY trusted:3128";}\n'
    manifest_text_for_hash = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    state_sha = calculate_pac_state_sha(
        [
            RenderedPacFile("fallback.pac", trusted_fallback),
            RenderedPacFile("manifest.json", manifest_text_for_hash),
        ],
    )
    manifest["state_sha256"] = state_sha
    (pac_dir / ".state-sha256").write_text(state_sha + "\n", encoding="utf-8")
    (pac_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (pac_dir / "fallback.pac").write_text(trusted_fallback, encoding="utf-8")

    cache = pac_http.LocalPacCache(str(pac_dir))

    assert cache.resolve(client_ip="192.0.2.10", request_host="proxy.example") == (
        trusted_fallback.encode("utf-8")
    )

    (pac_dir / "fallback.pac").write_text(
        'function FindProxyForURL(){return "DIRECT";}\n',
        encoding="utf-8",
    )

    assert cache.resolve(client_ip="192.0.2.10", request_host="proxy.example") is None
    assert cache.public_paths() == frozenset({"/proxy.pac", "/wpad.dat"})


def test_local_pac_cache_rejects_manifest_without_state_marker(
    tmp_path, pac_http
) -> None:
    pac_dir = tmp_path / "pac"
    pac_dir.mkdir()
    (pac_dir / "manifest.json").write_text(
        """{"fallback_file":"fallback.pac","state_sha256":"state-one"}""",
        encoding="utf-8",
    )
    (pac_dir / "fallback.pac").write_text(
        'function FindProxyForURL(){return "PROXY orphaned";}\n',
        encoding="utf-8",
    )

    cache = pac_http.LocalPacCache(str(pac_dir))

    assert cache.resolve(client_ip="192.0.2.10", request_host="proxy.example") is None
    assert cache.public_paths() == frozenset({"/proxy.pac", "/wpad.dat"})


def test_pac_content_disposition_uses_requested_filename(pac_http) -> None:
    assert (
        pac_http.pac_content_disposition("/download/wpad.dat?site=lab")
        == 'inline; filename="wpad.dat"'
    )
    assert (
        pac_http.pac_content_disposition("/download/custom.pac")
        == 'inline; filename="proxy.pac"'
    )


def test_local_pac_cache_selects_profile_from_verified_materialized_snapshot(
    tmp_path,
    pac_http,
) -> None:
    pac_dir = tmp_path / "pac"
    corp_pac = 'function FindProxyForURL(){return "PROXY corp";}\n'
    fallback_pac = 'function FindProxyForURL(){return "PROXY fallback";}\n'
    state_sha = _write_verified_pac_state(
        pac_http,
        pac_dir,
        manifest={
            "fallback_file": "fallback.pac",
            "profiles": [
                {"profile_id": 10, "client_cidr": "10.0.0.0/8", "file": "corp.pac"},
            ],
            "state_sha256": "",
        },
        files={"corp.pac": corp_pac, "fallback.pac": fallback_pac},
    )

    cache = pac_http.LocalPacCache(str(pac_dir))

    corp = cache.resolve_with_metadata(
        client_ip="10.1.2.3",
        request_host="proxy.example",
    )
    fallback = cache.resolve_with_metadata(
        client_ip="192.0.2.10",
        request_host="proxy.example",
    )

    assert corp is not None
    assert corp.source == "materialized"
    assert corp.state_sha256 == state_sha
    assert corp.selected_file == "corp.pac"
    assert corp.content == corp_pac.encode("utf-8")
    assert fallback is not None
    assert fallback.selected_file == "fallback.pac"
    assert fallback.content == fallback_pac.encode("utf-8")


def test_local_pac_cache_serves_fallback_when_profile_file_is_missing(
    tmp_path,
    pac_http,
) -> None:
    pac_dir = tmp_path / "pac"
    _write_verified_pac_state(
        pac_http,
        pac_dir,
        manifest={
            "fallback_file": "fallback.pac",
            "profiles": [
                {"profile_id": 10, "client_cidr": "10.0.0.0/8", "file": "corp.pac"},
            ],
            "state_sha256": "",
        },
        files={
            "fallback.pac": 'function FindProxyForURL(){return "PROXY fallback";}\n'
        },
    )

    cache = pac_http.LocalPacCache(str(pac_dir))

    resolved = cache.resolve_with_metadata(
        client_ip="10.1.2.3",
        request_host="proxy.example",
    )

    assert resolved is not None
    assert resolved.source == "materialized"
    assert resolved.selected_file == "fallback.pac"
    assert resolved.content == b'function FindProxyForURL(){return "PROXY fallback";}\n'

    resolved = pac_http.resolve_pac(
        client_ip="10.1.2.3",
        request_host="proxy.example",
        pac_dir=str(pac_dir),
    )
    assert resolved.source == "materialized"
    assert resolved.selected_file == "fallback.pac"
    assert resolved.content == b'function FindProxyForURL(){return "PROXY fallback";}\n'


def test_local_pac_cache_tracks_missing_profile_file_appearance_and_deletion(
    tmp_path,
    pac_http,
) -> None:
    pac_dir = tmp_path / "pac"
    pac_dir.mkdir()
    (pac_dir / ".state-sha256").write_text("state-one\n", encoding="utf-8")
    (pac_dir / "manifest.json").write_text(
        json.dumps(
            {
                "fallback_file": "fallback.pac",
                "profiles": [
                    {
                        "profile_id": 10,
                        "client_cidr": "10.0.0.0/8",
                        "file": "corp.pac",
                    },
                ],
                "state_sha256": "state-one",
            }
        ),
        encoding="utf-8",
    )
    fallback = pac_dir / "fallback.pac"
    fallback.write_text(
        'function FindProxyForURL(){return "PROXY fallback";}\n',
        encoding="utf-8",
    )

    cache = pac_http.LocalPacCache(str(pac_dir))

    missing = cache.resolve_with_metadata(
        client_ip="10.1.2.3",
        request_host="proxy.example",
    )
    assert missing is not None
    assert missing.selected_file == "fallback.pac"
    assert missing.content == b'function FindProxyForURL(){return "PROXY fallback";}\n'

    (pac_dir / "corp.pac").write_text(
        'function FindProxyForURL(){return "PROXY corp";}\n',
        encoding="utf-8",
    )

    appeared = cache.resolve_with_metadata(
        client_ip="10.1.2.3",
        request_host="proxy.example",
    )
    assert appeared is not None
    assert appeared.selected_file == "corp.pac"
    assert appeared.content == b'function FindProxyForURL(){return "PROXY corp";}\n'

    (pac_dir / "corp.pac").unlink()

    deleted = cache.resolve_with_metadata(
        client_ip="10.1.2.3",
        request_host="proxy.example",
    )
    assert deleted is not None
    assert deleted.selected_file == "fallback.pac"
    assert deleted.content == b'function FindProxyForURL(){return "PROXY fallback";}\n'


def test_local_pac_cache_invalidates_profile_deletion_in_verified_state(
    tmp_path,
    pac_http,
) -> None:
    pac_dir = tmp_path / "pac"
    _write_verified_pac_state(
        pac_http,
        pac_dir,
        manifest={
            "fallback_file": "fallback.pac",
            "profiles": [
                {"profile_id": 10, "client_cidr": "10.0.0.0/8", "file": "corp.pac"},
            ],
            "state_sha256": "",
        },
        files={
            "corp.pac": 'function FindProxyForURL(){return "PROXY corp";}\n',
            "fallback.pac": 'function FindProxyForURL(){return "PROXY fallback";}\n',
        },
    )
    cache = pac_http.LocalPacCache(str(pac_dir))
    assert (
        cache.resolve_with_metadata(
            client_ip="10.1.2.3",
            request_host="proxy.example",
        ).selected_file
        == "corp.pac"
    )  # type: ignore[union-attr]

    replacement = tmp_path / "replacement"
    _write_verified_pac_state(
        pac_http,
        replacement,
        manifest={"fallback_file": "fallback.pac", "profiles": [], "state_sha256": ""},
        files={
            "fallback.pac": 'function FindProxyForURL(){return "PROXY fallback2";}\n'
        },
    )
    old = tmp_path / "old-pac"
    pac_dir.replace(old)
    replacement.replace(pac_dir)

    reloaded = cache.resolve_with_metadata(
        client_ip="10.1.2.3",
        request_host="proxy.example",
    )

    assert reloaded is not None
    assert reloaded.selected_file == "fallback.pac"
    assert (
        reloaded.content == b'function FindProxyForURL(){return "PROXY fallback2";}\n'
    )


def test_local_pac_cache_rejects_partial_generation_that_changes_during_load(
    tmp_path,
    pac_http,
) -> None:
    pac_dir = tmp_path / "pac"
    first_sha = _write_verified_pac_state(
        pac_http,
        pac_dir,
        manifest={"fallback_file": "fallback.pac", "profiles": [], "state_sha256": ""},
        files={"fallback.pac": 'function FindProxyForURL(){return "PROXY one";}\n'},
    )
    second_dir = tmp_path / "second"
    second_sha = _write_verified_pac_state(
        pac_http,
        second_dir,
        manifest={"fallback_file": "fallback.pac", "profiles": [], "state_sha256": ""},
        files={"fallback.pac": 'function FindProxyForURL(){return "PROXY two";}\n'},
    )

    class FlappingPacCache(pac_http.LocalPacCache):
        def __init__(self, pac_dir: str) -> None:
            super().__init__(pac_dir)
            self._swapped = False

        def _pac_file_signatures(self, rel_paths: object):
            signatures = super()._pac_file_signatures(rel_paths)
            if not self._swapped and rel_paths and self._read_state_sha() == first_sha:
                self._swapped = True
                for item in second_dir.iterdir():
                    target = Path(self.pac_dir) / item.name
                    if item.is_file():
                        target.write_text(
                            item.read_text(encoding="utf-8"), encoding="utf-8"
                        )
            return signatures

    cache = FlappingPacCache(str(pac_dir))
    resolved = cache.resolve_with_metadata(
        client_ip="192.0.2.10",
        request_host="proxy.example",
    )

    assert resolved is not None
    assert resolved.state_sha256 == second_sha
    assert resolved.content == b'function FindProxyForURL(){return "PROXY two";}\n'


def test_resolve_pac_reports_emergency_fallback_when_verified_state_is_corrupt(
    tmp_path,
    pac_http,
) -> None:
    pac_dir = tmp_path / "pac"
    pac_dir.mkdir()
    (pac_dir / pac_http.PAC_STATE_SHA_FILENAME).write_text(
        "b" * 64 + "\n", encoding="utf-8"
    )
    (pac_dir / pac_http.PAC_MANIFEST_FILENAME).write_text(
        json.dumps({"fallback_file": "fallback.pac", "state_sha256": "b" * 64}),
        encoding="utf-8",
    )
    (pac_dir / "fallback.pac").write_text(
        'function FindProxyForURL(){return "PROXY tampered";}\n',
        encoding="utf-8",
    )

    resolved = pac_http.resolve_pac(
        client_ip="192.0.2.10",
        request_host="proxy.example",
        pac_dir=str(pac_dir),
    )

    assert resolved.source == "emergency"
    assert resolved.state_sha256 == ""
    assert b"PROXY tampered" not in resolved.content
    assert b"FindProxyForURL" in resolved.content
    assert (
        "state marker" in resolved.diagnostic
        or "materialized files" in resolved.diagnostic
    )
