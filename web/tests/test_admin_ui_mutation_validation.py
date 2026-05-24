from __future__ import annotations

import pytest

from .admin_route_test_utils import (
    FakeController,
    FakeRegistry,
    FakeSslfilterStore,
    FakeWebfilterStore,
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
        msg = "operation ledger unavailable"
        raise RuntimeError(msg)

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


def test_webfilter_save_rejects_internal_source_without_queueing_sync(
    monkeypatch,
    tmp_path,
) -> None:
    loaded, client = _loaded(monkeypatch, tmp_path)

    response = _post(
        client,
        "/webfilter",
        {
            "action": "save",
            "enabled": "on",
            "source_url": "http://127.0.0.1/private-feed.txt",
            "categories": ["adult"],
        },
    )

    assert response.status_code in {302, 303}
    assert "err_source=1" in response.headers.get("Location", "")
    assert loaded.operation_ledger.operations == []


def test_webfilter_save_persists_shared_source_provider(monkeypatch, tmp_path) -> None:
    webfilter_store = FakeWebfilterStore()
    loaded, client = _loaded(monkeypatch, tmp_path, webfilter_store=webfilter_store)

    response = _post(
        client,
        "/webfilter",
        {
            "action": "save",
            "enabled": "on",
            "source_url": "https://example.test/categories.csv",
            "source_provider": "csv",
            "categories": ["adult"],
        },
    )

    _assert_redirect_success(response)
    assert (
        webfilter_store.last_set_settings["source_url"]
        == "https://example.test/categories.csv"
    )
    assert webfilter_store.last_set_settings["source_provider"] == "csv"
    assert loaded.operation_ledger.operations[-1].operation_type == "manual_sync"


@pytest.mark.parametrize(
    ("path", "data", "expected_location_fragment"),
    [
        (
            "/squid/config",
            {"action": "apply", "config_text": "http_port 3128\n"},
            "error=1",
        ),
        ("/clamav/toggle", {"action": "disable"}, "error=1"),
        ("/sslfilter", {"action": "apply_policy"}, "apply_ok=0"),
        ("/reload", {}, "#status"),
    ],
)
def test_admin_apply_actions_redirect_when_reconcile_queue_raises(
    monkeypatch, tmp_path, path, data, expected_location_fragment
) -> None:
    loaded, client = _loaded(monkeypatch, tmp_path)

    def fail_reconcile(*_args, **_kwargs):
        msg = "operation ledger unavailable"
        raise RuntimeError(msg)

    monkeypatch.setattr(loaded.module, "request_proxy_reconcile", fail_reconcile)

    response = _post(client, path, data)

    assert response.status_code in {302, 303}
    assert expected_location_fragment in response.headers.get("Location", "")


def test_revert_operation_redirects_when_revert_queue_fails(monkeypatch, tmp_path) -> None:
    loaded, client = _loaded(monkeypatch, tmp_path)
    operation = loaded.operation_ledger.create_operation(
        "default",
        operation_type="config_apply",
        rollback_kind="config_revision",
        rollback_ref="1",
    )

    response = _post(client, f"/operations/{operation.operation_id}/revert", {})

    assert response.status_code in {302, 303}
    assert "error=revert_failed" in response.headers.get("Location", "")


@pytest.mark.parametrize(
    ("path", "handler_name", "data"),
    [
        ("/adblock", "_handle_adblock_post", {"action": "save_settings"}),
        ("/webfilter", "_handle_webfilter_post", {"action": "save"}),
        ("/sslfilter", "_handle_sslfilter_post", {"action": "toggle_private"}),
    ],
)
def test_policy_admin_post_handlers_redirect_on_unexpected_store_failures(
    monkeypatch, tmp_path, path, handler_name, data
) -> None:
    loaded, client = _loaded(monkeypatch, tmp_path)

    def fail_handler(*_args, **_kwargs):
        msg = "policy store unavailable"
        raise RuntimeError(msg)

    monkeypatch.setattr(loaded.module, handler_name, fail_handler)

    response = _post(client, path, data)

    assert response.status_code in {302, 303}
    location = response.headers.get("Location", "")
    assert "Operation+failed" in location


def test_pac_refresh_queues_only_without_direct_proxy_sync(monkeypatch, tmp_path):
    class Store:
        def upsert_profile(self, **kwargs):
            return True, "", 1

    store = Store()
    loaded, client = _loaded(monkeypatch, tmp_path, pac_profiles_store=store)
    monkeypatch.setattr(loaded.module, "get_proxy_id", lambda: "edge-pac")

    response = _post(
        client,
        "/pac",
        {"action": "create", "name": "Office", "client_cidr": "10.0.0.0/24"},
    )

    _assert_redirect_success(response)
    assert loaded.proxy_client.synced == []
    assert loaded.operation_ledger.operations[-1].operation_type == "pac_refresh"
    assert loaded.operation_ledger.operations[-1].proxy_id == "edge-pac"


def test_cache_clear_queues_operation_without_direct_proxy_client(monkeypatch, tmp_path):
    loaded, client = _loaded(monkeypatch, tmp_path)
    monkeypatch.setattr(loaded.module, "get_proxy_id", lambda: "edge-cache")

    response = client.post("/cache/clear", follow_redirects=False)

    _assert_redirect_success(response)
    assert loaded.proxy_client.cleared == []
    assert loaded.operation_ledger.operations[-1].operation_type == "cache_clear"
    assert loaded.operation_ledger.operations[-1].proxy_id == "edge-cache"
