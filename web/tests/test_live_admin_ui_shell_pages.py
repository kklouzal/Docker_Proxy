from __future__ import annotations

import pytest

from .live_test_helpers import LiveStackClient, admin_client, live_stack_ready


pytestmark = pytest.mark.live


@pytest.mark.parametrize(
    "path, expected",
    [
        ("/", "Status"),
        ("/observability", "Observability"),
        ("/squid/config", "Squid"),
        ("/exclusions", "Exclusions"),
        ("/certs", "Certificates"),
        ("/adblock", "Ad"),
        ("/webfilter", "Web"),
        ("/clamav", "Clam"),
        ("/sslfilter", "SSL"),
        ("/pac", "PAC"),
        ("/administration", "Administration"),
    ],
)
def test_live_ui_pages_render_and_include_csrf_meta(admin_client: LiveStackClient, path: str, expected: str) -> None:
    response = admin_client.admin_request(path)
    assert response.status == 200
    assert '<meta name="csrf-token"' in response.text
    assert expected.lower() in response.text.lower()


def test_live_logged_in_layout_renders_shell_accessibility_hooks(admin_client: LiveStackClient) -> None:
    response = admin_client.admin_request("/")
    assert response.status == 200
    body = response.text
    assert 'class="skip-link"' in body
    assert 'id="site-header"' in body
    assert 'id="context-strip-slot"' in body
    assert 'id="primary-nav"' in body
    assert 'id="nav-toggle"' in body
    assert 'class="nav-user"' not in body


def test_live_login_page_uses_updated_auth_shell(live_stack_ready: dict[str, dict[str, object]]) -> None:
    _ = live_stack_ready
    client = LiveStackClient()
    response = client.admin_request("/login")
    assert response.status == 200
    body = response.text
    assert "Secure access" in body
    assert 'class="auth-shell"' in body
    assert "Default credentials for first-run local setups" in body


def test_live_admin_ui_pac_endpoints_are_removed(admin_client: LiveStackClient) -> None:
    for path in ("/proxy.pac", "/wpad.dat"):
        response = admin_client.admin_request(path)
        assert response.status == 404, f"Expected admin UI to reject {path}, got HTTP {response.status}."


def test_live_proxy_serves_pac_and_wpad(live_stack_ready: dict[str, dict[str, object]]) -> None:
    _ = live_stack_ready
    client = LiveStackClient()
    health_response = client.pac_request("/health")
    root_response = client.pac_request("/")
    pac_response = client.pac_request()
    wpad_response = client.wpad_request()
    assert health_response.status == 200
    assert health_response.json().get("service") == "proxy"
    assert root_response.status == 200
    assert pac_response.status == 200
    assert wpad_response.status == 200
    assert "FindProxyForURL" in pac_response.text
    assert pac_response.text == wpad_response.text
    assert root_response.text == wpad_response.text