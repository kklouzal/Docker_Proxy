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
