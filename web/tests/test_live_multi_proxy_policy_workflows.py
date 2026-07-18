from __future__ import annotations

import re
import time
from typing import Any

import pytest

from .live_test_helpers import (
    LIVE_CONFIG,
    LiveStackClient,
    management_auth_headers,
    query_params,
    resolve_url,
    unique_domain,
    unique_token,
    wait_for_json_url,
    wait_for_proxy_inventory,
    wait_for_remote_proxy_management_payload,
    with_proxy_id,
)

pytestmark = pytest.mark.live


_PAC_PROFILE_RE = re.compile(
    r'<form [^>]*data-pac-profile-id="(\d+)" [^>]*data-pac-profile-name="([^"]*)"',
)


def _find_pac_profile_id(html: str, profile_name: str) -> int:
    for profile_id, name in _PAC_PROFILE_RE.findall(html):
        if name == profile_name:
            return int(profile_id)
    msg = f"Could not find PAC profile id for {profile_name!r}."
    raise AssertionError(msg)


@pytest.fixture
def multi_proxy_admin(admin_client: LiveStackClient) -> LiveStackClient:
    wait_for_proxy_inventory(
        admin_client,
        [LIVE_CONFIG.primary_proxy_id, LIVE_CONFIG.remote_proxy_id],
        timeout_seconds=120.0,
    )
    return admin_client


def _sync_remote_proxy(client: LiveStackClient, *, force: bool = True) -> dict:
    response = client.remote_proxy_management_post_json(
        "/api/manage/sync", {"force": force}, timeout_seconds=120.0
    )
    assert response.status == 200, response.text
    payload = response.json()
    assert payload.get("ok") is True, payload
    wait_for_remote_proxy_management_payload()
    return payload


def _operation_ledger():
    from services.operation_ledger import get_operation_ledger  # type: ignore

    return get_operation_ledger()


def _build_policy_sha(proxy_id: object) -> str:
    from services.policy_materializer import (  # type: ignore
        build_proxy_policy_state,
    )
    from services.proxy_context import reset_proxy_id, set_proxy_id  # type: ignore

    token = set_proxy_id(proxy_id)
    try:
        return build_proxy_policy_state(proxy_id).policy_sha256
    finally:
        reset_proxy_id(token)


def _wait_for_operation_terminal(
    proxy_id: object,
    operation_id: int,
    *,
    expected_target_ref: str,
    timeout_seconds: float = 120.0,
):
    deadline = time.time() + timeout_seconds
    last = None
    while time.time() < deadline:
        last = _operation_ledger().get_operation(operation_id)
        if last is not None and str(getattr(last, "status", "") or "") in {
            "applied",
            "failed",
            "superseded",
        }:
            assert str(getattr(last, "proxy_id", "") or "") == str(proxy_id)
            assert str(getattr(last, "operation_type", "") or "") == "policy_sync"
            assert str(getattr(last, "target_kind", "") or "") == "policy_state"
            assert str(getattr(last, "target_ref", "") or "") == expected_target_ref
            return last
        time.sleep(LIVE_CONFIG.poll_interval_seconds)
    msg = f"Timed out waiting for policy operation #{operation_id} to reach a terminal state; last={last!r}"
    raise AssertionError(msg)


def _wait_for_remote_policy_health(expected_sha: str) -> dict[str, Any]:
    def _accept(payload: dict[str, Any], _response: Any) -> bool:
        return (
            payload.get("proxy_id") == LIVE_CONFIG.remote_proxy_id
            and payload.get("desired_policy_sha") == expected_sha
            and payload.get("current_policy_sha") == expected_sha
        )

    return wait_for_json_url(
        resolve_url(
            LIVE_CONFIG.remote_proxy_management_url,
            "/api/manage/health?full=1&force=1",
        ),
        headers=management_auth_headers(),
        description="remote selected-proxy policy SHA convergence",
        accept=_accept,
    )


def test_live_remote_pac_profile_updates_only_selected_proxy_pac(
    multi_proxy_admin: LiveStackClient,
) -> None:
    profile_name = unique_token("remote_pac")
    direct_domain = unique_domain("remote-direct")

    create_response = multi_proxy_admin.admin_post_form(
        with_proxy_id("/pac", LIVE_CONFIG.remote_proxy_id),
        {
            "action": "create",
            "name": profile_name,
            "client_cidr": "",
            "direct_domains": direct_domain,
            "direct_dst_nets": "",
        },
        csrf_path=with_proxy_id("/pac", LIVE_CONFIG.remote_proxy_id),
        timeout_seconds=90.0,
    )
    assert create_response.status == 200
    assert query_params(create_response.url).get("proxy_id") == [
        LIVE_CONFIG.remote_proxy_id
    ]
    assert profile_name in create_response.text
    _sync_remote_proxy(multi_proxy_admin)

    remote_pac = multi_proxy_admin.remote_pac_request(
        f"/proxy.pac?probe={profile_name}"
    )
    local_pac = multi_proxy_admin.pac_request(f"/proxy.pac?probe={profile_name}")
    assert remote_pac.status == 200
    assert local_pac.status == 200
    assert direct_domain in remote_pac.text
    assert direct_domain not in local_pac.text

    profiles_page = multi_proxy_admin.admin_request(
        with_proxy_id("/pac", LIVE_CONFIG.remote_proxy_id)
    )
    profile_id = _find_pac_profile_id(profiles_page.text, profile_name)
    delete_response = multi_proxy_admin.admin_post_form(
        with_proxy_id("/pac", LIVE_CONFIG.remote_proxy_id),
        {"action": "delete", "profile_id": str(profile_id)},
        csrf_path=with_proxy_id("/pac", LIVE_CONFIG.remote_proxy_id),
        timeout_seconds=90.0,
    )
    assert delete_response.status == 200
    assert query_params(delete_response.url).get("proxy_id") == [
        LIVE_CONFIG.remote_proxy_id
    ]
    _sync_remote_proxy(multi_proxy_admin)
    assert (
        direct_domain
        not in multi_proxy_admin.remote_pac_request(
            f"/proxy.pac?probe=deleted-{profile_name}"
        ).text
    )


def test_live_remote_sslfilter_policy_mutation_operation_converges_selected_proxy_runtime(
    multi_proxy_admin: LiveStackClient,
) -> None:
    selected_proxy_id = LIVE_CONFIG.remote_proxy_id
    other_proxy_id = LIVE_CONFIG.primary_proxy_id
    domain = unique_domain("remote-policy-converge")
    other_before_sha = _build_policy_sha(other_proxy_id)

    add_response = multi_proxy_admin.admin_post_form(
        with_proxy_id("/sslfilter", selected_proxy_id),
        {"action": "add_domain", "policy": "nobump", "domain": domain},
        csrf_path=with_proxy_id("/sslfilter", selected_proxy_id),
        timeout_seconds=90.0,
    )
    assert add_response.status == 200
    assert query_params(add_response.url).get("proxy_id") == [selected_proxy_id]

    desired_sha = _build_policy_sha(selected_proxy_id)
    latest_operation = next(
        (
            op
            for op in _operation_ledger().list_operations(selected_proxy_id, limit=20)
            if str(getattr(op, "operation_type", "") or "") == "policy_sync"
            and str(getattr(op, "target_ref", "") or "") == desired_sha
        ),
        None,
    )
    assert latest_operation is not None
    assert latest_operation.status in {"pending", "applying"}
    if latest_operation.status == "applying":
        assert latest_operation.started_ts > 0
    assert latest_operation.proxy_id == selected_proxy_id

    sync_payload = _sync_remote_proxy(multi_proxy_admin)
    assert sync_payload.get("executed_operation_types") == ["policy_sync"]
    assert sync_payload.get("policy_sha256") == desired_sha
    assert sync_payload.get("current_policy_sha") == desired_sha

    terminal_operation = _wait_for_operation_terminal(
        selected_proxy_id,
        latest_operation.operation_id,
        expected_target_ref=desired_sha,
    )
    assert terminal_operation.status == "applied"
    health = _wait_for_remote_policy_health(desired_sha)
    assert health.get("desired_policy_sha") == health.get("current_policy_sha")

    other_after_sha = _build_policy_sha(other_proxy_id)
    assert other_after_sha == other_before_sha
    assert all(
        str(getattr(op, "target_ref", "") or "") != desired_sha
        for op in _operation_ledger().list_operations(other_proxy_id, limit=50)
    )

    remove_response = multi_proxy_admin.admin_post_form(
        with_proxy_id("/sslfilter", selected_proxy_id),
        {"action": "remove_domain", "policy": "nobump", "domain": domain},
        csrf_path=with_proxy_id("/sslfilter", selected_proxy_id),
        timeout_seconds=90.0,
    )
    assert remove_response.status == 200
    _sync_remote_proxy(multi_proxy_admin)


def test_live_remote_sslfilter_domain_policy_stays_proxy_side_and_scoped_to_selected_proxy(
    multi_proxy_admin: LiveStackClient,
) -> None:
    domain = unique_domain("remote-sslfilter")

    add_response = multi_proxy_admin.admin_post_form(
        with_proxy_id("/sslfilter", LIVE_CONFIG.remote_proxy_id),
        {"action": "add_domain", "policy": "nobump", "domain": domain},
        csrf_path=with_proxy_id("/sslfilter", LIVE_CONFIG.remote_proxy_id),
        timeout_seconds=90.0,
    )
    assert add_response.status == 200
    assert query_params(add_response.url).get("proxy_id") == [
        LIVE_CONFIG.remote_proxy_id
    ]

    remote_pac = multi_proxy_admin.remote_pac_request()
    local_pac = multi_proxy_admin.pac_request()
    # Remote proxy-side SSL-filter policy should not leak into any client PAC rules.
    assert domain not in remote_pac.text
    assert domain not in local_pac.text

    remove_response = multi_proxy_admin.admin_post_form(
        with_proxy_id("/sslfilter", LIVE_CONFIG.remote_proxy_id),
        {"action": "remove_domain", "policy": "nobump", "domain": domain},
        csrf_path=with_proxy_id("/sslfilter", LIVE_CONFIG.remote_proxy_id),
        timeout_seconds=90.0,
    )
    assert remove_response.status == 200
    assert query_params(remove_response.url).get("proxy_id") == [
        LIVE_CONFIG.remote_proxy_id
    ]
    assert domain not in multi_proxy_admin.remote_pac_request().text


def test_live_remote_sslfilter_rows_stay_scoped_to_selected_proxy(
    multi_proxy_admin: LiveStackClient,
) -> None:
    cidr = "10.88.0.0/16"

    add_response = multi_proxy_admin.admin_post_form(
        with_proxy_id("/sslfilter", LIVE_CONFIG.remote_proxy_id),
        {"action": "add_src", "policy": "nobump", "cidr": cidr},
        csrf_path=with_proxy_id("/sslfilter", LIVE_CONFIG.remote_proxy_id),
        timeout_seconds=90.0,
    )
    assert add_response.status == 200
    assert query_params(add_response.url).get("proxy_id") == [
        LIVE_CONFIG.remote_proxy_id
    ]

    remote_page = multi_proxy_admin.admin_request(
        with_proxy_id("/sslfilter", LIVE_CONFIG.remote_proxy_id)
    )
    local_page = multi_proxy_admin.admin_request(
        with_proxy_id("/sslfilter", LIVE_CONFIG.primary_proxy_id)
    )
    assert cidr in remote_page.text
    assert cidr not in local_page.text

    remove_response = multi_proxy_admin.admin_post_form(
        with_proxy_id("/sslfilter", LIVE_CONFIG.remote_proxy_id),
        {"action": "remove_src", "policy": "nobump", "cidr": cidr},
        csrf_path=with_proxy_id("/sslfilter", LIVE_CONFIG.remote_proxy_id),
        timeout_seconds=90.0,
    )
    assert remove_response.status == 200
    assert (
        cidr
        not in multi_proxy_admin.admin_request(
            with_proxy_id("/sslfilter", LIVE_CONFIG.remote_proxy_id)
        ).text
    )


def test_live_remote_clamav_test_actions_surface_selected_proxy_targets(
    multi_proxy_admin: LiveStackClient,
) -> None:
    eicar_response = multi_proxy_admin.admin_post_form(
        with_proxy_id("/clamav/test-eicar", LIVE_CONFIG.remote_proxy_id),
        {},
        csrf_path=with_proxy_id("/clamav", LIVE_CONFIG.remote_proxy_id),
        timeout_seconds=60.0,
    )
    icap_response = multi_proxy_admin.admin_post_form(
        with_proxy_id("/clamav/test-icap", LIVE_CONFIG.remote_proxy_id),
        {},
        csrf_path=with_proxy_id("/clamav", LIVE_CONFIG.remote_proxy_id),
        timeout_seconds=60.0,
    )

    assert eicar_response.status == 200
    assert icap_response.status == 200
    assert query_params(eicar_response.url).get("proxy_id") == [
        LIVE_CONFIG.remote_proxy_id
    ]
    assert query_params(icap_response.url).get("proxy_id") == [
        LIVE_CONFIG.remote_proxy_id
    ]
    assert "clamav.edge-2.internal:3311" in eicar_response.text
    assert "127.0.0.1:24001" in icap_response.text
    assert "EICAR failed" in eicar_response.text
    assert "ICAP sample failed" in icap_response.text
    assert "Connection refused" in icap_response.text


def test_live_remote_webfilter_save_updates_only_selected_proxy(
    multi_proxy_admin: LiveStackClient,
) -> None:
    source_url = f"https://example.com/{unique_token('remote-webcat')}.tar.gz"
    cleanup_source_url = ""

    try:
        response = multi_proxy_admin.admin_post_form(
            with_proxy_id("/webfilter?tab=categories", LIVE_CONFIG.remote_proxy_id),
            {
                "action": "save",
                "tab": "categories",
                "enabled": "on",
                "source_url": source_url,
                "categories": ["adult", "malware"],
            },
            csrf_path=with_proxy_id(
                "/webfilter?tab=categories", LIVE_CONFIG.remote_proxy_id
            ),
            timeout_seconds=90.0,
        )
        assert response.status == 200
        assert query_params(response.url).get("proxy_id") == [
            LIVE_CONFIG.remote_proxy_id
        ]
        assert query_params(response.url).get("tab") == ["categories"]
        assert query_params(response.url).get("err_source") is None
    finally:
        multi_proxy_admin.admin_post_form(
            with_proxy_id("/webfilter?tab=categories", LIVE_CONFIG.remote_proxy_id),
            {
                "action": "save",
                "tab": "categories",
                "source_url": cleanup_source_url,
            },
            csrf_path=with_proxy_id(
                "/webfilter?tab=categories", LIVE_CONFIG.remote_proxy_id
            ),
            timeout_seconds=90.0,
        )


def test_live_remote_adblock_flush_marks_selected_proxy_only(
    multi_proxy_admin: LiveStackClient,
) -> None:
    response = multi_proxy_admin.admin_post_form(
        with_proxy_id("/adblock", LIVE_CONFIG.remote_proxy_id),
        {"action": "flush_cache"},
        csrf_path=with_proxy_id("/adblock", LIVE_CONFIG.remote_proxy_id),
        timeout_seconds=90.0,
    )
    assert response.status == 200
    assert query_params(response.url).get("proxy_id") == [LIVE_CONFIG.remote_proxy_id]
    assert query_params(response.url).get("cache_flushed") == ["1"]
