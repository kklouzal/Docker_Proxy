from __future__ import annotations

import urllib.parse

import pytest

from .live_test_helpers import LIVE_CONFIG, LiveStackClient, admin_client, live_stack_ready


pytestmark = pytest.mark.live


def _path(response_url: str) -> str:
    return urllib.parse.urlsplit(response_url).path


def test_live_admin_security_headers_and_public_health(admin_client: LiveStackClient) -> None:
    response = admin_client.admin_request("/")
    assert response.status == 200
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "SAMEORIGIN"
    assert response.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "Permissions-Policy" in response.headers
    assert "default-src" in response.headers.get("Content-Security-Policy", "")

    health_client = LiveStackClient()
    health_response = health_client.admin_request("/health")
    assert health_response.status == 200
    assert health_response.json() == {"ok": True}
    assert "Content-Security-Policy" not in health_response.headers


def test_live_admin_protected_routes_redirect_to_login_without_session(live_stack_ready: dict[str, dict[str, object]]) -> None:
    _ = live_stack_ready
    client = LiveStackClient()
    for path in ("/", "/api/squid-config", "/api/timeseries", "/certs", "/certs/download/ca.crt", "/observability", "/ssl-errors/export"):
        response = client.admin_request(path, follow_redirects=False)
        assert response.status in (301, 302, 303, 307, 308)
        location = response.headers.get("Location", "") or ""
        assert _path(location) == "/login", f"Expected {path} to redirect to login, got {location!r}."


def test_live_admin_login_rejects_open_redirects_and_allows_local_next(
    live_stack_ready: dict[str, dict[str, object]],
) -> None:
    _ = live_stack_ready
    for next_url in ("https://evil.example/phish", "//evil.example/phish", "squid/config"):
        client = LiveStackClient()
        response = client.login(next_url=next_url)
        assert "evil.example" not in response.url
        assert _path(response.url) == "/"

    local_client = LiveStackClient()
    local_response = local_client.login(next_url="/squid/config")
    assert _path(local_response.url) == "/squid/config"


def test_live_admin_session_cookie_and_csrf_enforcement(live_stack_ready: dict[str, dict[str, object]]) -> None:
    _ = live_stack_ready
    login_client = LiveStackClient()
    login_page = login_client.admin_request("/login")
    token = login_client.refresh_csrf("/login") if not login_client._csrf_token else login_client._csrf_token
    assert login_page.status == 200

    login_response = login_client.admin_request(
        "/login",
        method="POST",
        data=urllib.parse.urlencode(
            {
                "username": LIVE_CONFIG.username,
                "password": LIVE_CONFIG.password,
                "next": "",
                "csrf_token": token,
            }
        ).encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        follow_redirects=False,
    )
    assert login_response.status in (301, 302, 303, 307, 308)
    cookie = login_response.headers.get("Set-Cookie", "")
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie

    missing_csrf = login_client.admin_request(
        "/administration",
        method="POST",
        data=urllib.parse.urlencode({"action": "add_user", "username": "u2", "password": "1234"}).encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert missing_csrf.status == 403

    header_client = LiveStackClient()
    header_client.admin_request("/login")
    header_token = header_client._csrf_token or header_client.refresh_csrf("/login")
    header_response = header_client.admin_request(
        "/login",
        method="POST",
        data=urllib.parse.urlencode(
            {"username": LIVE_CONFIG.username, "password": LIVE_CONFIG.password, "next": ""}
        ).encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded", "X-CSRF-Token": header_token},
        follow_redirects=False,
    )
    assert header_response.status in (301, 302, 303, 307, 308)

    no_session = LiveStackClient()
    rejected_login = no_session.admin_request(
        "/login",
        method="POST",
        data=urllib.parse.urlencode(
            {"username": LIVE_CONFIG.username, "password": LIVE_CONFIG.password, "next": ""}
        ).encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert rejected_login.status == 403