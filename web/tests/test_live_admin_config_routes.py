from __future__ import annotations

import pytest

from .live_test_helpers import LiveStackClient, admin_client, query_params, wait_for_proxy_management_payload


pytestmark = pytest.mark.live


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