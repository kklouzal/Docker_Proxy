from __future__ import annotations

import pytest

from .live_test_helpers import LIVE_CONFIG, LiveStackClient, live_stack_ready, wait_for_proxy_management_payload


pytestmark = pytest.mark.live


def test_live_proxy_management_health_requires_auth(live_stack_ready: dict[str, dict[str, object]]) -> None:
    _ = live_stack_ready
    client = LiveStackClient()
    response = client.proxy_management_request("/api/manage/health", auth=False)
    assert response.status == 403


def test_live_proxy_management_auth_accepts_bearer_and_x_proxy_token_and_rejects_bad_token(
    live_stack_ready: dict[str, dict[str, object]],
) -> None:
    _ = live_stack_ready
    if not LIVE_CONFIG.proxy_token:
        pytest.skip("Live proxy-management token is not configured; auth variants are not meaningful.")

    client = LiveStackClient()
    bearer = client.proxy_management_request(
        "/api/manage/health",
        auth=False,
        headers={"Authorization": f"Bearer {LIVE_CONFIG.proxy_token}"},
    )
    x_proxy_token = client.proxy_management_request(
        "/api/manage/health",
        auth=False,
        headers={"X-Proxy-Token": LIVE_CONFIG.proxy_token},
    )
    bad = client.proxy_management_request(
        "/api/manage/health",
        auth=False,
        headers={"Authorization": "Bearer definitely-wrong"},
    )

    assert bearer.status == 200
    assert bearer.json().get("proxy_id") == LIVE_CONFIG.primary_proxy_id
    assert x_proxy_token.status == 200
    assert x_proxy_token.json().get("proxy_id") == LIVE_CONFIG.primary_proxy_id
    assert bad.status == 403


def test_live_proxy_management_health_returns_payload(live_stack_ready: dict[str, dict[str, object]]) -> None:
    _ = live_stack_ready
    payload = wait_for_proxy_management_payload()
    assert isinstance(payload.get("ok"), bool)
    assert payload.get("status") in {"healthy", "degraded"}
    assert "proxy_id" in payload
    assert isinstance(payload.get("services"), dict)
    assert isinstance(payload.get("stats"), dict)


def test_live_proxy_management_sync_endpoint(live_stack_ready: dict[str, dict[str, object]]) -> None:
    _ = live_stack_ready
    client = LiveStackClient()
    response = client.proxy_management_post_json("/api/manage/sync", {"force": True}, timeout_seconds=90.0)
    assert response.status == 200
    payload = response.json()
    assert isinstance(payload, dict)
    assert payload.get("ok") is True


def test_live_proxy_management_cache_clear_endpoint(live_stack_ready: dict[str, dict[str, object]]) -> None:
    _ = live_stack_ready
    client = LiveStackClient()
    response = client.proxy_management_post_json("/api/manage/cache/clear", {}, timeout_seconds=90.0)
    assert response.status == 200
    payload = response.json()
    assert isinstance(payload, dict)
    assert payload.get("ok") is True
    wait_for_proxy_management_payload()


def test_live_proxy_management_clamav_endpoints_reflect_current_backend_behavior(live_stack_ready: dict[str, dict[str, object]]) -> None:
    _ = live_stack_ready
    client = LiveStackClient()

    eicar_response = client.proxy_management_post_json("/api/manage/clamav/test-eicar", {})
    icap_response = client.proxy_management_post_json("/api/manage/clamav/test-icap", {})

    assert eicar_response.status == 503
    assert icap_response.status == 200
    assert eicar_response.json().get("ok") is False
    assert icap_response.json().get("ok") is True
    assert "204 No Content" in str(icap_response.json().get("detail") or "")