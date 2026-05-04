from __future__ import annotations

import re

import pytest

from .live_test_helpers import (
    LIVE_CONFIG,
    LiveStackClient,
    active_config_text,
    admin_client,
    latest_config_apply,
    query_params,
    unique_token,
    wait_for_config_apply,
    wait_for_proxy_inventory,
    with_proxy_id,
)


pytestmark = pytest.mark.live


_CLAMAV_ALLOW_RE = re.compile(r"^(\s*)(#\s*)?(adaptation_access\s+av_resp_set\s+allow\b.*)$", re.I | re.M)


def _config_store():
    from services.config_revisions import get_config_revisions  # type: ignore

    return get_config_revisions()


def _apply_ts(application: object | None) -> int:
    return int(getattr(application, "applied_ts", 0) or 0)


def _append_marker(config_text: str, marker: str) -> str:
    base = (config_text or "").rstrip()
    return f"{base}\n# {marker}\n" if base else f"# {marker}\n"


def _clamav_enabled(config_text: str) -> bool:
    match = _CLAMAV_ALLOW_RE.search(config_text or "")
    if not match:
        return False
    return not bool((match.group(2) or "").strip())


@pytest.fixture
def multi_proxy_admin(admin_client: LiveStackClient) -> LiveStackClient:
    wait_for_proxy_inventory(
        admin_client,
        [LIVE_CONFIG.primary_proxy_id, LIVE_CONFIG.remote_proxy_id],
        timeout_seconds=120.0,
    )
    return admin_client


def test_live_api_squid_config_reads_selected_remote_proxy_revision(multi_proxy_admin: LiveStackClient) -> None:
    revisions = _config_store()
    original_remote = active_config_text(LIVE_CONFIG.remote_proxy_id)
    marker = unique_token("live_remote_config")
    revisions.create_revision(
        LIVE_CONFIG.remote_proxy_id,
        _append_marker(original_remote, marker),
        created_by="live-tests",
        source_kind="live_multi_proxy_scope",
        activate=True,
    )
    try:
        remote_response = multi_proxy_admin.admin_request(with_proxy_id("/api/squid-config", LIVE_CONFIG.remote_proxy_id))
        local_response = multi_proxy_admin.admin_request(with_proxy_id("/api/squid-config", LIVE_CONFIG.primary_proxy_id))
        assert remote_response.status == 200
        assert local_response.status == 200
        assert marker in remote_response.text
        assert marker not in local_response.text
    finally:
        revisions.create_revision(
            LIVE_CONFIG.remote_proxy_id,
            original_remote,
            created_by="live-tests",
            source_kind="live_multi_proxy_restore",
            activate=True,
        )


def test_live_reload_route_targets_selected_remote_proxy(multi_proxy_admin: LiveStackClient) -> None:
    revisions = _config_store()
    original_local = active_config_text(LIVE_CONFIG.primary_proxy_id)
    original_remote = active_config_text(LIVE_CONFIG.remote_proxy_id)
    remote_before = latest_config_apply(LIVE_CONFIG.remote_proxy_id)
    marker = unique_token("live_remote_reload")
    new_revision = revisions.create_revision(
        LIVE_CONFIG.remote_proxy_id,
        _append_marker(original_remote, marker),
        created_by="live-tests",
        source_kind="live_multi_proxy_reload",
        activate=True,
    )
    try:
        response = multi_proxy_admin.admin_post_form(
            with_proxy_id("/reload", LIVE_CONFIG.primary_proxy_id),
            {"proxy_id": LIVE_CONFIG.remote_proxy_id},
            csrf_path="/",
            timeout_seconds=90.0,
        )
        assert response.status == 200
        assert query_params(response.url).get("proxy_id") == [LIVE_CONFIG.remote_proxy_id]

        applied = wait_for_config_apply(
            LIVE_CONFIG.remote_proxy_id,
            revision_id=new_revision.revision_id,
            after_ts=_apply_ts(remote_before) or None,
            timeout_seconds=120.0,
        )
        assert applied is not None
        assert marker in active_config_text(LIVE_CONFIG.remote_proxy_id)
        assert active_config_text(LIVE_CONFIG.primary_proxy_id) == original_local
    finally:
        restore_revision = revisions.create_revision(
            LIVE_CONFIG.remote_proxy_id,
            original_remote,
            created_by="live-tests",
            source_kind="live_multi_proxy_restore",
            activate=True,
        )
        sync_response = multi_proxy_admin.remote_proxy_management_post_json(
            "/api/manage/sync",
            {"force": True},
            timeout_seconds=90.0,
        )
        assert sync_response.status == 200
        assert sync_response.json().get("ok") is True
        wait_for_config_apply(
            LIVE_CONFIG.remote_proxy_id,
            revision_id=restore_revision.revision_id,
            timeout_seconds=120.0,
        )


def test_live_proxies_page_renders_registered_remote_proxy(multi_proxy_admin: LiveStackClient) -> None:
    response = multi_proxy_admin.admin_request("/proxies")
    assert response.status == 200
    assert "Edge 2" in response.text
    assert "Observability (24h)" in response.text


def test_live_clamav_page_uses_selected_remote_proxy_health(multi_proxy_admin: LiveStackClient) -> None:
    remote_response = multi_proxy_admin.admin_request(with_proxy_id("/clamav", LIVE_CONFIG.remote_proxy_id))
    local_response = multi_proxy_admin.admin_request(with_proxy_id("/clamav", LIVE_CONFIG.primary_proxy_id))
    assert remote_response.status == 200
    assert local_response.status == 200
    assert "clamav.edge-2.internal:3311" in remote_response.text
    assert "127.0.0.1:24001" in remote_response.text
    assert "Enable changes the Squid adaptation rule only" in remote_response.text
    assert "clamav.edge-2.internal:3311" not in local_response.text


def test_live_clamav_toggle_publishes_revision_for_selected_remote_proxy(multi_proxy_admin: LiveStackClient) -> None:
    revisions = _config_store()
    original_local = active_config_text(LIVE_CONFIG.primary_proxy_id)
    original_remote = active_config_text(LIVE_CONFIG.remote_proxy_id)
    remote_before = latest_config_apply(LIVE_CONFIG.remote_proxy_id)
    desired_action = "disable" if _clamav_enabled(original_remote) else "enable"
    expected_enabled = desired_action == "enable"

    try:
        response = multi_proxy_admin.admin_post_form(
            with_proxy_id("/clamav/toggle", LIVE_CONFIG.remote_proxy_id),
            {"action": desired_action},
            csrf_path=with_proxy_id("/clamav", LIVE_CONFIG.remote_proxy_id),
            timeout_seconds=90.0,
        )
        assert response.status == 200
        assert query_params(response.url).get("proxy_id") == [LIVE_CONFIG.remote_proxy_id]

        wait_for_config_apply(
            LIVE_CONFIG.remote_proxy_id,
            after_ts=_apply_ts(remote_before) or None,
            timeout_seconds=120.0,
        )
        assert _clamav_enabled(active_config_text(LIVE_CONFIG.remote_proxy_id)) is expected_enabled
        assert active_config_text(LIVE_CONFIG.primary_proxy_id) == original_local
    finally:
        restore_revision = revisions.create_revision(
            LIVE_CONFIG.remote_proxy_id,
            original_remote,
            created_by="live-tests",
            source_kind="live_multi_proxy_restore",
            activate=True,
        )
        sync_response = multi_proxy_admin.remote_proxy_management_post_json(
            "/api/manage/sync",
            {"force": True},
            timeout_seconds=90.0,
        )
        assert sync_response.status == 200
        assert sync_response.json().get("ok") is True
        wait_for_config_apply(
            LIVE_CONFIG.remote_proxy_id,
            revision_id=restore_revision.revision_id,
            timeout_seconds=120.0,
        )
