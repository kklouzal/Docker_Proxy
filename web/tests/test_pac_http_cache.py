from __future__ import annotations

import sys
from pathlib import Path


def _add_repo_paths() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    web_root = repo_root / "web"
    for path in (repo_root, web_root):
        path_str = str(path)
        if path_str not in sys.path:
            sys.path.insert(0, path_str)


def test_pac_render_dir_is_cached_until_explicitly_cleared(monkeypatch) -> None:
    _add_repo_paths()
    from services import pac_http  # type: ignore

    pac_http.pac_render_dir.cache_clear()
    monkeypatch.setenv("PAC_RENDER_DIR", "/tmp/pac-one")

    first = pac_http.pac_render_dir()
    monkeypatch.setenv("PAC_RENDER_DIR", "/tmp/pac-two")
    second = pac_http.pac_render_dir()

    assert first == "/tmp/pac-one"
    assert second == "/tmp/pac-one"

    pac_http.pac_render_dir.cache_clear()
    assert pac_http.pac_render_dir() == "/tmp/pac-two"


def test_client_ip_ignores_untrusted_forwarded_headers(monkeypatch) -> None:
    _add_repo_paths()
    from services import pac_http  # type: ignore

    monkeypatch.delenv("PAC_TRUSTED_PROXY_CIDRS", raising=False)

    assert (
        pac_http.client_ip_from_headers(
            {"X-Forwarded-For": "10.2.3.4", "X-Real-IP": "10.2.3.5"},
            "198.51.100.10",
        )
        == "198.51.100.10"
    )


def test_client_ip_honors_forwarded_headers_from_trusted_proxy(monkeypatch) -> None:
    _add_repo_paths()
    from services import pac_http  # type: ignore

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


def test_client_ip_rejects_invalid_forwarded_headers(monkeypatch) -> None:
    _add_repo_paths()
    from services import pac_http  # type: ignore

    monkeypatch.setenv("PAC_TRUSTED_PROXY_CIDRS", "192.0.2.0/24")

    assert (
        pac_http.client_ip_from_headers(
            {"X-Forwarded-For": "not-an-ip", "X-Real-IP": "also-bad"},
            "192.0.2.10",
        )
        == "192.0.2.10"
    )


def test_local_pac_cache_ignores_manifest_paths_outside_pac_dir(tmp_path) -> None:
    _add_repo_paths()
    from services import pac_http  # type: ignore

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
