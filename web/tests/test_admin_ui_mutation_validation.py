from __future__ import annotations

import pytest

from .admin_route_test_utils import (
    FakeController,
    FakeRegistry,
    FakeSslfilterStore,
    load_admin_app,
    login_client,
)


def _login(client) -> None:
    login_client(client)


def _post(client, path: str, data: dict[str, object], *, csrf_path: str | None = None):
    return client.post(path, data=dict(data), follow_redirects=False)


def _loaded(monkeypatch, tmp_path, *, controller=None, **overrides):
    monkeypatch.setenv("DISABLE_CSRF", "1")
    sslfilter_store = overrides.pop("sslfilter_store", None) or FakeSslfilterStore()
    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        controller=controller or FakeController(),
        sslfilter_store=sslfilter_store,
        **overrides,
    )
    loaded.sslfilter_store = sslfilter_store
    client = loaded.module.app.test_client()
    _login(client)
    return loaded, client


def _assert_redirect_success(response) -> None:
    assert response.status_code in {302, 303}
    location = response.headers.get("Location", "")
    assert "error=1" not in location


def test_sslfilter_destination_domain_mutation_syncs_managed_policy(
    monkeypatch, tmp_path
) -> None:
    loaded, client = _loaded(monkeypatch, tmp_path)

    response = _post(
        client,
        "/sslfilter",
        {"action": "add_domain", "policy": "nobump", "domain": "*.discord.com"},
    )
    _assert_redirect_success(response)

    assert loaded.sslfilter_store.no_bump_domains == ["*.discord.com"]
    assert loaded.proxy_client.synced == []
    assert loaded.operation_ledger.operations[-1].proxy_id == "default"
    assert loaded.operation_ledger.operations[-1].operation_type == "manual_sync"
    assert loaded.operation_ledger.operations[-1].status == "pending"

    response = _post(
        client,
        "/sslfilter",
        {"action": "add_domain", "policy": "nocache", "domain": "cache.example"},
    )
    _assert_redirect_success(response)

    assert loaded.sslfilter_store.no_cache_domains == ["cache.example"]
    assert loaded.proxy_client.synced == []
    assert loaded.operation_ledger.operations[-1].proxy_id == "default"
    assert loaded.operation_ledger.operations[-1].operation_type == "manual_sync"
    assert loaded.operation_ledger.operations[-1].status == "pending"


def test_ssl_error_exclusion_quick_action_queues_sslfilter_policy_sync(
    monkeypatch, tmp_path
) -> None:
    loaded, client = _loaded(monkeypatch, tmp_path)

    response = _post(client, "/ssl-errors/exclude", {"domain": "Blocked.Example"})
    _assert_redirect_success(response)

    location = response.headers.get("Location", "")
    assert "pane=ssl" in location
    assert "q=blocked.example" in location
    assert loaded.sslfilter_store.no_bump_domains == ["blocked.example"]
    assert loaded.proxy_client.synced == []
    assert loaded.operation_ledger.operations[-1].proxy_id == "default"
    assert loaded.operation_ledger.operations[-1].operation_type == "manual_sync"
    assert loaded.operation_ledger.operations[-1].status == "pending"


@pytest.mark.parametrize(
    ("path", "data", "expected_source_kind"),
    [
        ("/squid/config/apply-safe", {"form_kind": "caching"}, "template"),
        ("/squid/config/apply-overrides", {"ignore_reload": "on"}, "overrides"),
        ("/clamav/toggle", {"action": "enable"}, "clamav"),
        (
            "/clamav/settings",
            {
                "clamav_fail_mode": "closed",
                "virus_scan_scan_file_types": "TEXT DATA",
                "virus_scan_send_percent_data": "55",
                "virus_scan_start_send_percent_after": "64K",
                "virus_scan_max_object_size": "64M",
                "virus_scan_default_engine": "clamd",
            },
            "clamav-settings",
        ),
    ],
)
def test_program_controlled_admin_config_mutations_validate_before_sync(
    monkeypatch, tmp_path, path, data, expected_source_kind
) -> None:
    loaded, client = _loaded(monkeypatch, tmp_path)

    csrf_path = (
        "/squid/config"
        if path.startswith("/squid/config/")
        else ("/clamav" if path == "/clamav/toggle" else path)
    )
    response = _post(client, path, data, csrf_path=csrf_path)

    _assert_redirect_success(response)
    assert len(loaded.proxy_client.validated) == 1
    assert loaded.config_revisions.created[-1]["source_kind"] == expected_source_kind
    assert loaded.proxy_client.synced == []
    assert loaded.operation_ledger.operations[-1].proxy_id == "default"
    assert loaded.operation_ledger.operations[-1].operation_type == "config_apply"
    assert loaded.operation_ledger.operations[-1].status == "pending"


def test_clamav_settings_route_persists_validated_runtime_controls(
    monkeypatch, tmp_path
) -> None:
    loaded, client = _loaded(monkeypatch, tmp_path)

    response = _post(
        client,
        "/clamav/settings",
        {
            "clamav_fail_mode": "closed",
            "virus_scan_scan_file_types": "TEXT DATA",
            "virus_scan_send_percent_data": "88",
            "virus_scan_start_send_percent_after": "256K",
            "virus_scan_max_object_size": "64M",
            "virus_scan_default_engine": "clamd",
        },
        csrf_path="/clamav",
    )

    _assert_redirect_success(response)
    created = loaded.config_revisions.created[-1]
    config_text = str(created["config_text"])
    assert created["source_kind"] == "clamav-settings"
    assert loaded.proxy_client.validated[-1] == ("default", config_text)
    assert loaded.proxy_client.synced == []
    assert loaded.operation_ledger.operations[-1].proxy_id == "default"
    assert loaded.operation_ledger.operations[-1].operation_type == "config_apply"
    assert loaded.operation_ledger.operations[-1].status == "pending"
    assert "# BEGIN SQUID-UI CLAMAV SETTINGS" in config_text
    assert "# clamav_fail_mode: closed" in config_text
    assert "# file_security_scan_downloads: off" in config_text
    assert "# file_security_scan_uploads: off" in config_text
    assert "# virus_scan_scan_file_types: TEXT DATA" in config_text
    assert "# virus_scan_send_percent_data: 88" in config_text
    assert "# virus_scan_start_send_percent_after: 256K" in config_text
    assert "# virus_scan_allow_204_on: off" in config_text
    assert "# virus_scan_max_object_size: 64M" in config_text
    assert "# virus_scan_default_engine: clamd" in config_text


def test_clamav_settings_preserves_selected_proxy_with_unchecked_policy_boxes(
    monkeypatch, tmp_path
) -> None:
    loaded, client = _loaded(
        monkeypatch,
        tmp_path,
        registry=FakeRegistry(["default", "edge-2"]),
    )

    response = _post(
        client,
        "/clamav/settings?proxy_id=edge-2",
        {
            "clamav_fail_mode": "open",
            "file_security_preset": "balanced",
            "file_security_scan_downloads": "on",
            "file_security_risky_extensions": "exe dll msi",
            "file_security_executable_extensions": "exe dll",
            "file_security_blocked_mime_types": "application/x-msdownload",
            "virus_scan_scan_file_types": "TEXT DATA BINARY",
            "virus_scan_send_percent_data": "88",
            "virus_scan_start_send_percent_after": "256K",
            "virus_scan_max_object_size": "64M",
        },
        csrf_path="/clamav?proxy_id=edge-2",
    )

    _assert_redirect_success(response)
    location = response.headers.get("Location", "")
    assert "proxy_id=edge-2" in location
    created = loaded.config_revisions.created[-1]
    config_text = str(created["config_text"])
    assert loaded.proxy_client.validated[-1] == ("edge-2", config_text)
    assert loaded.operation_ledger.operations[-1].proxy_id == "edge-2"
    assert "# file_security_scan_downloads: on" in config_text
    assert "# file_security_scan_uploads: off" in config_text
    assert "# file_security_block_risky_extensions: off" in config_text
    assert "# file_security_block_executable_content: off" in config_text


def test_clamav_settings_apply_exception_redirects_with_error_banner(
    monkeypatch, tmp_path
) -> None:
    loaded, client = _loaded(monkeypatch, tmp_path)

    def fail_reconcile(*_args, **_kwargs):
        raise RuntimeError("operation ledger unavailable")

    monkeypatch.setattr(loaded.module, "request_proxy_reconcile", fail_reconcile)

    response = _post(
        client,
        "/clamav/settings",
        {
            "clamav_fail_mode": "open",
            "file_security_preset": "balanced",
            "file_security_scan_downloads": "on",
            "virus_scan_scan_file_types": "TEXT DATA BINARY",
            "virus_scan_send_percent_data": "88",
            "virus_scan_start_send_percent_after": "256K",
            "virus_scan_max_object_size": "64M",
        },
        csrf_path="/clamav",
    )

    assert response.status_code in {302, 303}
    location = response.headers.get("Location", "")
    assert "settings_ok=0" in location
    assert "settings_msg=" in location


def test_clamav_toggle_flips_scan_directions_without_dropping_blocking_policy(
    monkeypatch, tmp_path
) -> None:
    loaded, client = _loaded(monkeypatch, tmp_path)

    response = _post(
        client,
        "/clamav/settings",
        {
            "file_security_preset": "strict",
            "clamav_fail_mode": "closed",
        },
        csrf_path="/clamav",
    )
    _assert_redirect_success(response)

    response = _post(
        client, "/clamav/toggle", {"action": "disable"}, csrf_path="/clamav"
    )
    _assert_redirect_success(response)

    config_text = str(loaded.config_revisions.created[-1]["config_text"])
    assert "# file_security_scan_downloads: off" in config_text
    assert "# file_security_scan_uploads: off" in config_text
    assert "# file_security_block_risky_extensions: on" in config_text
    assert "# file_security_block_archives: on" in config_text
    assert "# file_security_block_nested_archives: on" in config_text
    assert "# file_security_block_executable_content: on" in config_text


@pytest.mark.parametrize(
    ("path", "data"),
    [
        (
            "/webfilter",
            {
                "action": "save",
                "enabled": "on",
                "source_url": "https://example.test/categories.txt",
                "categories": ["adult"],
            },
        ),
        ("/webfilter", {"action": "whitelist_add", "whitelist_domain": "discord.com"}),
    ],
)
def test_policy_store_mutations_request_sync_without_config_revision_validation(
    monkeypatch, tmp_path, path, data
) -> None:
    loaded, client = _loaded(monkeypatch, tmp_path)

    response = _post(client, path, data)

    _assert_redirect_success(response)
    assert loaded.proxy_client.synced == []
    assert loaded.operation_ledger.operations[-1].proxy_id == "default"
    assert loaded.operation_ledger.operations[-1].operation_type == "manual_sync"
    assert loaded.operation_ledger.operations[-1].status == "pending"
