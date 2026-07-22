from __future__ import annotations

import os
import sys
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


def test_pac_render_dir_is_cached_until_explicitly_cleared(monkeypatch, pac_http) -> None:
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


def test_client_ip_honors_forwarded_headers_from_trusted_proxy(monkeypatch, pac_http) -> None:
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


def test_client_ip_rejects_invalid_forwarded_headers(monkeypatch, pac_http) -> None:
    monkeypatch.setenv("PAC_TRUSTED_PROXY_CIDRS", "192.0.2.0/24")

    assert (
        pac_http.client_ip_from_headers(
            {"X-Forwarded-For": "not-an-ip", "X-Real-IP": "also-bad"},
            "192.0.2.10",
        )
        == "192.0.2.10"
    )


def test_local_pac_cache_ignores_manifest_paths_outside_pac_dir(tmp_path, pac_http) -> None:
    pac_dir = tmp_path / "pac"
    pac_dir.mkdir()
    (tmp_path / "secret.pac").write_text("SECRET", encoding="utf-8")
    (pac_dir / ".state-sha256").write_text("state-one\n", encoding="utf-8")
    (pac_dir / "manifest.json").write_text(
        """{"fallback_file":"fallback.pac","profiles":[{"client_cidr":"10.0.0.0/8","file":"../secret.pac"}]}""",
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
            {"Host": "internal-proxy:5000", "X-Forwarded-Host": "public-proxy"},
            "203.0.113.10",
        )
        == "internal-proxy:5000"
    )


def test_request_host_uses_trusted_forwarded_host(monkeypatch, pac_http) -> None:
    monkeypatch.setenv("PAC_TRUSTED_PROXY_CIDRS", "198.51.100.0/24")

    assert (
        pac_http.request_host_from_headers(
            {
                "Host": "internal-proxy:5000",
                "X-Forwarded-Host": "public-proxy.example:80, internal-proxy:5000",
            },
            "198.51.100.10",
        )
        == "public-proxy.example:80"
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
                "Host": "internal-proxy:5000",
                "X-Forwarded-Host": "public-proxy.example:80",
            },
            "198.51.100.10",
        )
        == "public-proxy.example:80"
    )


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
            {"Host": "internal-proxy:5000", "X-Forwarded-Host": "fe80::1%eth0"},
            "198.51.100.10",
        )
        == "internal-proxy:5000"
    )
    assert (
        pac_http.request_host_from_headers(
            {
                "Host": "internal-proxy:5000",
                "X-Forwarded-Host": "[fe80::1%eth0]:8080",
            },
            "198.51.100.10",
        )
        == "internal-proxy:5000"
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
                "Host": "internal-proxy:5000",
                "X-Forwarded-Host": "http://public-proxy.example:80/proxy.pac",
            },
            "198.51.100.10",
        )
        == "internal-proxy:5000"
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
        """{"fallback_file":"fallback.pac","public_pac_path":"/download/wpad.dat?site=lab"}""",
        encoding="utf-8",
    )
    (pac_dir / "fallback.pac").write_text("PAC", encoding="utf-8")

    assert pac_http.LocalPacCache(str(pac_dir)).public_paths() == frozenset(
        {"/proxy.pac", "/wpad.dat", "/download/wpad.dat"}
    )


def test_local_pac_cache_matches_percent_encoded_public_pac_path(
    tmp_path, pac_http
) -> None:
    pac_dir = tmp_path / "pac"
    pac_dir.mkdir()
    (pac_dir / ".state-sha256").write_text("state-one\n", encoding="utf-8")
    (pac_dir / "manifest.json").write_text(
        """{"fallback_file":"fallback.pac","public_pac_path":"/download/%77pad.dat?site=lab"}""",
        encoding="utf-8",
    )
    (pac_dir / "fallback.pac").write_text("PAC", encoding="utf-8")

    cache = pac_http.LocalPacCache(str(pac_dir))

    assert "/download/wpad.dat" in cache.public_paths()
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


def test_local_pac_cache_requires_configured_public_pac_query(
    tmp_path, pac_http
) -> None:
    pac_dir = tmp_path / "pac"
    pac_dir.mkdir()
    (pac_dir / ".state-sha256").write_text("state-one\n", encoding="utf-8")
    (pac_dir / "manifest.json").write_text(
        """{"fallback_file":"fallback.pac","public_pac_path":"/download/wpad.dat?site=lab"}""",
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


def test_local_pac_cache_rejects_marker_manifest_sha_mismatch(tmp_path, pac_http) -> None:
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


def test_local_pac_cache_rejects_manifest_without_state_marker(tmp_path, pac_http) -> None:
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
