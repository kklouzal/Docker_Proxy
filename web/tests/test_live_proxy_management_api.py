from __future__ import annotations

import time

import pytest

from .live_test_helpers import LIVE_CONFIG, LiveStackClient, active_config_text, live_stack_ready, wait_for_proxy_management_payload


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


def test_live_proxy_management_health_reports_supervisor_programs(live_stack_ready: dict[str, dict[str, object]]) -> None:
    _ = live_stack_ready
    expected_programs = ("squid", "cicap_adblock", "cicap_av", "proxy_api", "proxy_agent", "pac_http")
    deadline = time.time() + 120.0
    payload = wait_for_proxy_management_payload()
    while time.time() < deadline:
        services = payload.get("services") or {}
        supervisor = services.get("supervisor") or {}
        programs = supervisor.get("programs") or {}
        if all(program in programs and programs[program].get("ok") is True for program in expected_programs):
            break
        time.sleep(1.0)
        payload = wait_for_proxy_management_payload()

    services = payload.get("services") or {}
    supervisor = services.get("supervisor") or {}
    programs = supervisor.get("programs") or {}

    assert isinstance(supervisor.get("ok"), bool)
    for program in expected_programs:
        assert program in programs
        assert programs[program].get("ok") is True
        assert "RUNNING" in str(programs[program].get("detail") or "")


def test_live_proxy_management_sync_endpoint(live_stack_ready: dict[str, dict[str, object]]) -> None:
    _ = live_stack_ready
    client = LiveStackClient()
    response = client.proxy_management_post_json("/api/manage/sync", {"force": True}, timeout_seconds=90.0)
    assert response.status == 200
    payload = response.json()
    assert isinstance(payload, dict)
    assert payload.get("ok") is True


def test_live_proxy_management_config_validation_endpoint(live_stack_ready: dict[str, dict[str, object]]) -> None:
    _ = live_stack_ready
    client = LiveStackClient()

    valid_response = client.proxy_management_post_json(
        "/api/manage/config/validate",
        {"config_text": active_config_text(LIVE_CONFIG.primary_proxy_id)},
        timeout_seconds=45.0,
    )
    invalid_response = client.proxy_management_post_json(
        "/api/manage/config/validate",
        {"config_text": "not_a_real_squid_directive definitely-invalid\n"},
        timeout_seconds=45.0,
    )

    assert valid_response.status == 200
    assert valid_response.json().get("ok") is True
    assert invalid_response.status == 200
    assert invalid_response.json().get("ok") is False


def test_live_proxy_management_rollback_endpoint_returns_structured_result_and_preserves_health(
    live_stack_ready: dict[str, dict[str, object]],
) -> None:
    _ = live_stack_ready
    client = LiveStackClient()
    response = client.proxy_management_post_json(
        "/api/manage/config/rollback",
        {"reason": "live test rollback contract"},
        timeout_seconds=90.0,
    )
    payload = response.json()

    assert response.status in {200, 409}
    assert isinstance(payload, dict)
    assert payload.get("proxy_id") == LIVE_CONFIG.primary_proxy_id
    assert isinstance(payload.get("ok"), bool)
    assert "detail" in payload
    wait_for_proxy_management_payload()


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