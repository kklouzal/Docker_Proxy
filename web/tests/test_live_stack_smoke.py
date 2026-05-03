from __future__ import annotations

import pytest

from .live_test_helpers import LiveStackClient, admin_client, live_stack_ready, wait_for_proxy_management_payload


pytestmark = pytest.mark.live


def test_live_admin_health_endpoint(live_stack_ready: dict[str, dict[str, object]]) -> None:
    assert live_stack_ready["admin"]["ok"] is True


def test_live_admin_login_can_load_proxies_page(admin_client: LiveStackClient) -> None:
    response = admin_client.admin_request("/proxies")
    assert response.status == 200
    assert "Selected proxy" in response.text or "Fleet" in response.text


def test_live_proxy_management_health_endpoint(live_stack_ready: dict[str, dict[str, object]]) -> None:
    _ = live_stack_ready
    payload = wait_for_proxy_management_payload()
    assert isinstance(payload.get("ok"), bool)
    assert payload.get("status") in {"healthy", "degraded"}
    assert payload.get("service") != "proxy-management"
    assert "proxy_id" in payload
    assert isinstance(payload.get("services"), dict)


def test_live_proxy_force_sync_and_pac_rendering(live_stack_ready: dict[str, dict[str, object]]) -> None:
    _ = live_stack_ready
    client = LiveStackClient()
    response = client.proxy_management_post_json("/api/manage/sync", {"force": True}, timeout_seconds=90.0)
    payload = response.json()
    assert payload["ok"] is True
    wait_for_proxy_management_payload()
    pac_response = client.pac_request()
    assert pac_response.status == 200
    assert "FindProxyForURL" in pac_response.text
    assert "PROXY " in pac_response.text
    assert "DIRECT" in pac_response.text
    assert "SOCKS" not in pac_response.text.upper()