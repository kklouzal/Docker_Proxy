from __future__ import annotations

from typing import Any

import pytest

from .live_test_helpers import (
    LIVE_CONFIG,
    LiveStackClient,
    admin_client,
    management_auth_headers,
    resolve_url,
    wait_for_json_url,
    wait_for_proxy_fixture_response,
    wait_for_proxy_management_payload,
)


pytestmark = pytest.mark.live


def _supervisor_control(client: LiveStackClient, program: str, action: str) -> dict[str, Any]:
    response = client.proxy_management_post_json(
        f"/api/manage/test/supervisor/{program}/{action}",
        {},
        timeout_seconds=90.0,
    )
    payload = response.json()
    assert isinstance(payload, dict)
    assert payload.get("program") == program
    assert payload.get("action") == action
    return payload


def _wait_for_supervisor_program(program: str, *, ok: bool) -> dict[str, Any]:
    def _accept(payload: dict[str, Any], _response: Any) -> bool:
        services = payload.get("services") or {}
        supervisor = services.get("supervisor") or {}
        programs = supervisor.get("programs") or {}
        program_payload = programs.get(program) or {}
        return bool(program_payload.get("ok")) is ok

    return wait_for_json_url(
        resolve_url(LIVE_CONFIG.proxy_management_url, "/api/manage/health"),
        headers=management_auth_headers(),
        description=f"supervisor program {program!r} ok={ok}",
        accept=_accept,
    )


def test_live_public_proxy_listener_rejects_management_routes(admin_client: LiveStackClient) -> None:
    health = admin_client.pac_request("/health")
    management = admin_client.pac_request("/api/manage/health")
    sync = admin_client.pac_request("/api/manage/sync")

    assert health.status == 200
    assert health.json().get("service") == "proxy"
    assert management.status == 404
    assert sync.status == 404


def test_live_disruptive_squid_restart_keeps_pac_serving(admin_client: LiveStackClient) -> None:
    before = admin_client.pac_request()
    assert before.status == 200
    assert "FindProxyForURL" in before.text

    restarted = _supervisor_control(admin_client, "squid", "restart")
    assert restarted.get("ok") is True

    _wait_for_supervisor_program("squid", ok=True)
    after = admin_client.pac_request(timeout_seconds=30.0)
    assert after.status == 200
    assert "FindProxyForURL" in after.text
    wait_for_proxy_management_payload()
