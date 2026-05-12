from __future__ import annotations

import pytest

from .admin_route_test_utils import (
    FakeController,
    FakeSslfilterStore,
    load_admin_app,
    login_client,
)


def _login(client) -> None:
    login_client(client)


def _post(client, path: str, data: dict[str, object], *, csrf_path: str | None = None):
    return client.post(path, data=dict(data), follow_redirects=False)


def _loaded(monkeypatch, tmp_path, *, controller=None):
    monkeypatch.setenv("DISABLE_CSRF", "1")
    sslfilter_store = FakeSslfilterStore()
    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        controller=controller or FakeController(),
        sslfilter_store=sslfilter_store,
    )
    loaded.sslfilter_store = sslfilter_store
    client = loaded.module.app.test_client()
    _login(client)
    return loaded, client


def _assert_redirect_success(response) -> None:
    assert response.status_code in {302, 303}
    location = response.headers.get("Location", "")
    assert "error=1" not in location


def test_sslfilter_destination_domain_mutation_syncs_managed_policy(monkeypatch, tmp_path) -> None:
    loaded, client = _loaded(monkeypatch, tmp_path)

    response = _post(client, "/sslfilter", {"action": "add_domain", "policy": "nobump", "domain": "*.discord.com"})
    _assert_redirect_success(response)

    assert loaded.sslfilter_store.no_bump_domains == ["*.discord.com"]
    assert loaded.proxy_client.synced == []
    assert loaded.operation_ledger.operations[-1].proxy_id == "default"
    assert loaded.operation_ledger.operations[-1].operation_type == "manual_sync"
    assert loaded.operation_ledger.operations[-1].status == "pending"

    response = _post(client, "/sslfilter", {"action": "add_domain", "policy": "nocache", "domain": "cache.example"})
    _assert_redirect_success(response)

    assert loaded.sslfilter_store.no_cache_domains == ["cache.example"]
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
def test_program_controlled_admin_config_mutations_validate_before_sync(monkeypatch, tmp_path, path, data, expected_source_kind) -> None:
    loaded, client = _loaded(monkeypatch, tmp_path)

    csrf_path = "/squid/config" if path.startswith("/squid/config/") else ("/clamav" if path == "/clamav/toggle" else path)
    response = _post(client, path, data, csrf_path=csrf_path)

    _assert_redirect_success(response)
    assert len(loaded.proxy_client.validated) == 1
    assert loaded.config_revisions.created[-1]["source_kind"] == expected_source_kind
    assert loaded.proxy_client.synced == []
    assert loaded.operation_ledger.operations[-1].proxy_id == "default"
    assert loaded.operation_ledger.operations[-1].operation_type == "config_apply"
    assert loaded.operation_ledger.operations[-1].status == "pending"


def test_clamav_settings_route_persists_validated_runtime_controls(monkeypatch, tmp_path) -> None:
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
    assert "# virus_scan_scan_file_types: TEXT DATA" in config_text
    assert "# virus_scan_send_percent_data: 88" in config_text
    assert "# virus_scan_start_send_percent_after: 256K" in config_text
    assert "# virus_scan_allow_204_on: off" in config_text
    assert "# virus_scan_max_object_size: 64M" in config_text
    assert "# virus_scan_default_engine: clamd" in config_text


@pytest.mark.parametrize(
    ("path", "data"),
    [
        ("/webfilter", {"action": "save", "enabled": "on", "source_url": "https://example.test/categories.txt", "categories": ["adult"]}),
        ("/webfilter", {"action": "whitelist_add", "whitelist_domain": "discord.com"}),
    ],
)
def test_policy_store_mutations_request_sync_without_config_revision_validation(monkeypatch, tmp_path, path, data) -> None:
    loaded, client = _loaded(monkeypatch, tmp_path)

    response = _post(client, path, data)

    _assert_redirect_success(response)
    assert loaded.proxy_client.synced == []
    assert loaded.operation_ledger.operations[-1].proxy_id == "default"
    assert loaded.operation_ledger.operations[-1].operation_type == "manual_sync"
    assert loaded.operation_ledger.operations[-1].status == "pending"
