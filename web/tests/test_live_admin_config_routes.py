from __future__ import annotations

import pytest

from .live_test_helpers import (
    LIVE_CONFIG,
    LiveStackClient,
    active_config_text,
    admin_client,
    latest_config_apply,
    query_params,
    wait_for_config_apply,
    wait_for_proxy_management_payload,
    wait_for_proxy_fixture_response,
)


pytestmark = pytest.mark.live


def _config_store():
    from services.config_revisions import get_config_revisions  # type: ignore

    return get_config_revisions()


def _apply_ts(application: object | None) -> int:
    return int(getattr(application, "applied_ts", 0) or 0)


def _restore_primary_config(client: LiveStackClient, config_text: str) -> None:
    revision = _config_store().create_revision(
        LIVE_CONFIG.primary_proxy_id,
        config_text,
        created_by="live-tests",
        source_kind="live_restore",
        activate=True,
    )
    sync_response = client.proxy_management_post_json("/api/manage/sync", {"force": True}, timeout_seconds=90.0)
    assert sync_response.status == 200
    assert sync_response.json().get("ok") is True
    wait_for_config_apply(LIVE_CONFIG.primary_proxy_id, revision_id=revision.revision_id, timeout_seconds=120.0)
    wait_for_proxy_management_payload()
    wait_for_proxy_fixture_response(client, "/health", timeout_seconds=120.0)


def test_live_api_squid_config_returns_running_config(admin_client: LiveStackClient) -> None:
    response = admin_client.admin_request("/api/squid-config")
    assert response.status == 200
    assert "http_port" in response.text
    assert "ssl_bump" in response.text


def test_live_squid_config_network_tab_mentions_non_standard_ports(admin_client: LiveStackClient) -> None:
    response = admin_client.admin_request("/squid/config?tab=network")
    assert response.status == 200
    assert "Web destination ports" in response.text
    assert "Non-standard HTTP and HTTPS destination ports are allowed by default" in response.text


def test_live_squid_config_manual_validate_and_apply_current_config(admin_client: LiveStackClient) -> None:
    config_response = admin_client.admin_request("/api/squid-config")
    assert config_response.status == 200
    config_text = config_response.text

    validate_response = admin_client.admin_post_form(
        "/squid/config?tab=config",
        {
            "tab": "config",
            "action": "validate",
            "config_text": config_text,
        },
        csrf_path="/squid/config?tab=config",
    )
    assert validate_response.status == 200
    assert "Validation passed" in validate_response.text

    apply_response = admin_client.admin_post_form(
        "/squid/config?tab=config",
        {
            "tab": "config",
            "action": "apply",
            "config_text": config_text,
        },
        csrf_path="/squid/config?tab=config",
        timeout_seconds=120.0,
    )
    assert apply_response.status == 200
    assert query_params(apply_response.url).get("ok") == ["1"]
    assert "Config validated and Squid reloaded." in apply_response.text
    payload = wait_for_proxy_management_payload()
    assert payload.get("status") in {"healthy", "degraded"}


def test_live_observability_and_ssl_exports_return_csv(admin_client: LiveStackClient) -> None:
    observability_export = admin_client.admin_request("/observability/export?pane=destinations&window=3600&limit=25")
    assert observability_export.status == 200
    assert observability_export.headers.get("Content-Type", "").startswith("text/csv")
    assert observability_export.text.splitlines()[0].startswith("domain;")

    ssl_export = admin_client.admin_request("/ssl-errors/export?window=3600&limit=100")
    assert ssl_export.status == 200
    assert ssl_export.headers.get("Content-Type", "").startswith("text/csv")
    assert ssl_export.text.splitlines()[0].startswith("domain;")


def test_live_api_timeseries_returns_json(admin_client: LiveStackClient) -> None:
    response = admin_client.admin_request("/api/timeseries?resolution=1s&window=60&limit=25")
    assert response.status == 200
    payload = response.json()
    assert isinstance(payload, dict)
    assert payload.get("resolution") == "1s"
    assert isinstance(payload.get("points"), list)


def test_live_squid_config_apply_safe_publishes_and_syncs_template_revision(admin_client: LiveStackClient) -> None:
    original_config = active_config_text(LIVE_CONFIG.primary_proxy_id)
    before_apply = latest_config_apply(LIVE_CONFIG.primary_proxy_id)

    try:
        response = admin_client.admin_post_form(
            "/squid/config/apply-safe",
            {
                "form_kind": "caching",
                "negative_ttl_seconds": "123",
            },
            csrf_path="/squid/config?tab=caching",
            timeout_seconds=120.0,
        )
        assert response.status == 200
        assert query_params(response.url).get("ok") == ["1"]

        wait_for_config_apply(
            LIVE_CONFIG.primary_proxy_id,
            after_ts=_apply_ts(before_apply) or None,
            timeout_seconds=120.0,
        )
        assert "negative_ttl 123 seconds" in active_config_text(LIVE_CONFIG.primary_proxy_id)
    finally:
        _restore_primary_config(admin_client, original_config)


def test_live_squid_config_apply_overrides_publishes_override_metadata(admin_client: LiveStackClient) -> None:
    original_config = active_config_text(LIVE_CONFIG.primary_proxy_id)
    before_apply = latest_config_apply(LIVE_CONFIG.primary_proxy_id)

    try:
        response = admin_client.admin_post_form(
            "/squid/config/apply-overrides",
            {
                "override_client_no_cache": "on",
                "override_origin_private": "on",
            },
            csrf_path="/squid/config?tab=caching&subtab=overrides",
            timeout_seconds=120.0,
        )
        assert response.status == 200
        assert query_params(response.url).get("ok") == ["1"]

        wait_for_config_apply(
            LIVE_CONFIG.primary_proxy_id,
            after_ts=_apply_ts(before_apply) or None,
            timeout_seconds=120.0,
        )
        config_text = active_config_text(LIVE_CONFIG.primary_proxy_id)
        assert "# override_client_no_cache=1" in config_text
        assert "# override_origin_private=1" in config_text
        assert "# override_client_no_store=0" in config_text
    finally:
        _restore_primary_config(admin_client, original_config)