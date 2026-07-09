from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlsplit

import pytest

from .admin_route_test_utils import (
    FakeAdblockStore,
    FakePacProfilesStore,
    FakeSslfilterStore,
    FakeWebfilterStore,
    load_admin_app,
)

if TYPE_CHECKING:
    from collections.abc import Callable


def _params(location: str) -> dict[str, list[str]]:
    return parse_qs(urlsplit(location).query)


def test_adblock_settings_clamp_invalid_cache_values_and_request_refresh(
    monkeypatch, tmp_path
) -> None:
    store = FakeAdblockStore()
    loaded = load_admin_app(monkeypatch, tmp_path, adblock_store=store)
    with loaded.module.app.test_request_context(
        "/adblock",
        method="POST",
        data={
            "action": "save_settings",
            "adblock_enabled": "on",
            "cache_ttl": "not-int",
            "cache_max": "-10",
        },
    ):
        response = loaded.module._handle_adblock_post(store)
    assert response.status_code in {301, 302, 303}
    assert store.settings["enabled"] is True
    assert store.settings["cache_ttl"] == 3600
    assert store.settings["cache_max"] == 0
    assert store.refresh_requested == 1
    assert loaded.operation_ledger.operations[-1].operation_type == "adblock_refresh"
    assert loaded.operation_ledger.operations[-1].status == "pending"


def test_adblock_refresh_with_no_enabled_lists_redirects_with_warning(
    monkeypatch, tmp_path
) -> None:
    store = FakeAdblockStore()
    for status in store.statuses:
        status.enabled = False
    loaded = load_admin_app(monkeypatch, tmp_path, adblock_store=store)
    with loaded.module.app.test_request_context(
        "/adblock", method="POST", data={"action": "refresh"}
    ):
        response = loaded.module._handle_adblock_post(store)
    assert _params(response.location)["refresh_no_lists"] == ["1"]
    assert store.refresh_requested == 0


def test_sslfilter_bulk_domains_and_cidrs_report_limited_error_detail(
    monkeypatch, tmp_path
) -> None:
    store = FakeSslfilterStore()
    loaded = load_admin_app(monkeypatch, tmp_path, sslfilter_store=store)
    domain_lines = "one.example\nbad domain/example\ntwo.example\nbad/2\nbad/3\nbad/4"
    with loaded.module.app.test_request_context(
        "/sslfilter",
        method="POST",
        data={
            "action": "add_domain_bulk",
            "policy": "nobump",
            "domains_bulk": domain_lines,
        },
    ):
        response = loaded.module._handle_sslfilter_post(store)
    params = _params(response.location)
    assert params["added"] == ["2"]
    assert params["err"][0].count("Invalid domain") == 3

    cidr_lines = "10.0.0.0/8\nbad\n192.0.2.0/24\nbad-cidr"
    with loaded.module.app.test_request_context(
        "/sslfilter",
        method="POST",
        data={"action": "add_src_bulk", "policy": "nocache", "src_bulk": cidr_lines},
    ):
        cidr_response = loaded.module._handle_sslfilter_post(store)
    cidr_params = _params(cidr_response.location)
    assert cidr_params["added"] == ["2"]
    assert cidr_params["err"][0].count("Invalid CIDR") == 2


def test_webfilter_save_validates_source_url_and_whitelist(
    monkeypatch, tmp_path
) -> None:
    store = FakeWebfilterStore()
    loaded = load_admin_app(monkeypatch, tmp_path, webfilter_store=store)
    with loaded.module.app.test_request_context(
        "/webfilter",
        method="POST",
        data={
            "action": "save",
            "enabled": "on",
            "source_url": "",
            "categories": "adult",
        },
    ):
        missing = loaded.module._handle_webfilter_post(store, "categories")
    assert _params(missing.location)["err_source"] == ["1"]

    with loaded.module.app.test_request_context(
        "/webfilter",
        method="POST",
        data={
            "action": "save",
            "enabled": "on",
            "source_url": "ftp://example.invalid/list.tar.gz",
            "categories": "adult",
        },
    ):
        invalid = loaded.module._handle_webfilter_post(store, "categories")
    assert _params(invalid.location)["err_source"] == ["1"]
    assert not hasattr(store, "last_set_settings")

    with loaded.module.app.test_request_context(
        "/webfilter",
        method="POST",
        data={
            "action": "save",
            "source_url": "http://127.0.0.1/private-feed.tar.gz",
            "categories": "adult",
        },
    ):
        disabled_internal = loaded.module._handle_webfilter_post(store, "categories")
    disabled_params = _params(disabled_internal.location)
    assert "err_source" not in disabled_params
    assert store.last_set_settings["enabled"] is False
    assert (
        store.last_set_settings["source_url"] == "http://127.0.0.1/private-feed.tar.gz"
    )
    assert loaded.operation_ledger.operations == []

    with loaded.module.app.test_request_context(
        "/webfilter",
        method="POST",
        data={"action": "whitelist_add", "whitelist_domain": "bad value"},
    ):
        bad_whitelist = loaded.module._handle_webfilter_post(store, "whitelist")
    assert "wl_err" in _params(bad_whitelist.location)


def test_sslfilter_add_remove_and_unknown_actions(monkeypatch, tmp_path) -> None:
    store = FakeSslfilterStore()
    loaded = load_admin_app(monkeypatch, tmp_path, sslfilter_store=store)
    with loaded.module.app.test_request_context(
        "/sslfilter",
        method="POST",
        data={"action": "add_src", "policy": "nobump", "cidr": "bad"},
    ):
        bad_add = loaded.module._handle_sslfilter_post(store)
    assert "err" in _params(bad_add.location)

    with loaded.module.app.test_request_context(
        "/sslfilter",
        method="POST",
        data={"action": "add_src", "policy": "nobump", "cidr": "10.1.2.0/24"},
    ):
        ok_add = loaded.module._handle_sslfilter_post(store)
    assert _params(ok_add.location)["ok"] == ["1"]
    assert store.no_bump_src_nets == ["10.1.2.0/24"]

    with loaded.module.app.test_request_context(
        "/sslfilter", method="POST", data={"action": "add", "cidr": "172.31.250.0/24"}
    ):
        legacy_add = loaded.module._handle_sslfilter_post(store)
    assert _params(legacy_add.location)["ok"] == ["1"]
    assert "172.31.250.0/24" in store.no_bump_src_nets

    with loaded.module.app.test_request_context(
        "/sslfilter",
        method="POST",
        data={"action": "remove", "cidr": "172.31.250.0/24"},
    ):
        legacy_remove = loaded.module._handle_sslfilter_post(store)
    assert _params(legacy_remove.location)["removed"] == ["1"]
    assert "172.31.250.0/24" not in store.no_bump_src_nets

    with loaded.module.app.test_request_context(
        "/sslfilter", method="POST", data={"action": "unknown"}
    ):
        unknown = loaded.module._handle_sslfilter_post(store)
    assert urlsplit(unknown.location).path == "/sslfilter"


def test_pac_builder_bad_ids_and_xss_like_names_are_handled(
    monkeypatch, tmp_path
) -> None:
    store = FakePacProfilesStore()
    loaded = load_admin_app(monkeypatch, tmp_path, pac_profiles_store=store)
    with loaded.module.app.test_request_context(
        "/pac",
        method="POST",
        data={
            "action": "create",
            "name": "<script>alert(1)</script>",
            "client_cidr": "",
            "direct_domains": "example.com",
        },
    ):
        created = loaded.module._handle_pac_builder_post(store)
    assert _params(created.location)["ok"] == ["1"]
    assert store.profiles[1].name == "<script>alert(1)</script>"

    with loaded.module.app.test_request_context(
        "/pac", method="POST", data={"action": "update", "profile_id": "not-int"}
    ):
        bad_id = loaded.module._handle_pac_builder_post(store)
    params = _params(bad_id.location)
    assert params["error"] == ["1"]
    assert params["msg"]


def test_pac_builder_backup_proxy_chain_actions(monkeypatch, tmp_path) -> None:
    store = FakePacProfilesStore()
    loaded = load_admin_app(monkeypatch, tmp_path, pac_profiles_store=store)

    with loaded.module.app.test_request_context(
        "/pac",
        method="POST",
        data={
            "action": "add_backup_proxy",
            "backup_proxy_host": "backup-a.example",
            "backup_proxy_port": "3128",
        },
    ):
        added_a = loaded.module._handle_pac_builder_post(store)
    assert _params(added_a.location)["ok"] == ["1"]

    with loaded.module.app.test_request_context(
        "/pac",
        method="POST",
        data={
            "action": "add_backup_proxy",
            "backup_proxy_host": "backup-b.example",
            "backup_proxy_port": "8080",
        },
    ):
        added_b = loaded.module._handle_pac_builder_post(store)
    assert _params(added_b.location)["ok"] == ["1"]
    assert [item.proxy_host for item in store.backup_proxies] == [
        "backup-a.example",
        "backup-b.example",
    ]

    with loaded.module.app.test_request_context(
        "/pac",
        method="POST",
        data={
            "action": "move_backup_proxy",
            "backup_proxy_id": str(store.backup_proxies[1].id),
            "direction": "up",
        },
    ):
        moved = loaded.module._handle_pac_builder_post(store)
    assert _params(moved.location)["ok"] == ["1"]
    assert [item.proxy_host for item in store.backup_proxies] == [
        "backup-b.example",
        "backup-a.example",
    ]

    with loaded.module.app.test_request_context(
        "/pac", method="POST", data={"action": "toggle_direct"}
    ):
        toggled = loaded.module._handle_pac_builder_post(store)
    assert _params(toggled.location)["ok"] == ["1"]
    assert store.direct_enabled is False


def test_pac_builder_noop_ids_do_not_queue_runtime_refresh(
    monkeypatch, tmp_path
) -> None:
    store = FakePacProfilesStore()
    loaded = load_admin_app(monkeypatch, tmp_path, pac_profiles_store=store)

    with loaded.module.app.test_request_context(
        "/pac",
        method="POST",
        data={"action": "delete", "profile_id": "999"},
    ):
        missing_profile = loaded.module._handle_pac_builder_post(store)
    params = _params(missing_profile.location)
    assert params["error"] == ["1"]
    assert params["msg"] == ["Profile not found."]
    assert "ok" not in params
    assert loaded.operation_ledger.operations == []

    with loaded.module.app.test_request_context(
        "/pac",
        method="POST",
        data={"action": "remove_backup_proxy", "backup_proxy_id": "999"},
    ):
        missing_backup = loaded.module._handle_pac_builder_post(store)
    params = _params(missing_backup.location)
    assert params["error"] == ["1"]
    assert params["msg"] == ["Backup proxy not found."]
    assert "ok" not in params
    assert loaded.operation_ledger.operations == []

    with loaded.module.app.test_request_context(
        "/pac",
        method="POST",
        data={"action": "remove_backup_proxy", "backup_proxy_id": "not-int"},
    ):
        malformed_backup = loaded.module._handle_pac_builder_post(store)
    params = _params(malformed_backup.location)
    assert params["error"] == ["1"]
    assert params["msg"] == ["Backup proxy not found."]
    assert "ok" not in params
    assert loaded.operation_ledger.operations == []

    with loaded.module.app.test_request_context(
        "/pac",
        method="POST",
        data={
            "action": "move_backup_proxy",
            "backup_proxy_id": "999",
            "direction": "up",
        },
    ):
        missing_move = loaded.module._handle_pac_builder_post(store)
    params = _params(missing_move.location)
    assert params["error"] == ["1"]
    assert params["msg"] == ["Backup proxy not found."]
    assert "ok" not in params
    assert loaded.operation_ledger.operations == []

    with loaded.module.app.test_request_context(
        "/pac",
        method="POST",
        data={
            "action": "move_backup_proxy",
            "backup_proxy_id": "not-int",
            "direction": "up",
        },
    ):
        malformed_move = loaded.module._handle_pac_builder_post(store)
    params = _params(malformed_move.location)
    assert params["error"] == ["1"]
    assert params["msg"] == ["Backup proxy not found."]
    assert "ok" not in params
    assert loaded.operation_ledger.operations == []


def test_pac_builder_reports_reconcile_queue_failure(monkeypatch, tmp_path) -> None:
    store = FakePacProfilesStore()
    loaded = load_admin_app(monkeypatch, tmp_path, pac_profiles_store=store)

    def fail_reconcile(*_args, **_kwargs):
        msg = "operation ledger unavailable"
        raise RuntimeError(msg)

    monkeypatch.setattr(loaded.module, "request_proxy_reconcile", fail_reconcile)

    with loaded.module.app.test_request_context(
        "/pac",
        method="POST",
        data={
            "action": "create",
            "name": "Office LAN",
            "client_cidr": "192.168.10.0/24",
            "direct_domains": "internal.example",
        },
    ):
        response = loaded.module._handle_pac_builder_post(store)

    params = _params(response.location)
    assert params["error"] == ["1"]
    assert "ok" not in params
    assert "proxy materialization was not queued" in params["msg"][0]
    assert loaded.operation_ledger.operations == []
    assert store.profiles[1].name == "Office LAN"


def test_adblock_cache_flush_queues_single_runtime_refresh(
    monkeypatch, tmp_path
) -> None:
    store = FakeAdblockStore()
    loaded = load_admin_app(monkeypatch, tmp_path, adblock_store=store)

    with loaded.module.app.test_request_context(
        "/adblock",
        method="POST",
        data={"action": "flush_cache"},
    ):
        response = loaded.module._handle_adblock_post(store)

    assert _params(response.location)["cache_flushed"] == ["1"]
    assert store.cache_flush_requested == 1
    assert [
        operation.operation_type for operation in loaded.operation_ledger.operations
    ] == ["adblock_refresh"]
    assert loaded.operation_ledger.operations[-1].subject == "Adblock runtime refresh"


def test_adblock_list_save_queues_runtime_refresh(monkeypatch, tmp_path) -> None:
    store = FakeAdblockStore()
    loaded = load_admin_app(monkeypatch, tmp_path, adblock_store=store)

    with loaded.module.app.test_request_context(
        "/adblock",
        method="POST",
        data={"action": "save_lists", "enabled_easylist": "on"},
    ):
        response = loaded.module._handle_adblock_post(store)

    assert response.status_code in {301, 302, 303}
    assert store.refresh_requested == 1
    assert loaded.operation_ledger.operations[-1].operation_type == "adblock_refresh"
    assert loaded.operation_ledger.operations[-1].subject == "Adblock runtime refresh"


def test_adblock_settings_save_queues_forced_runtime_refresh(
    monkeypatch,
    tmp_path,
) -> None:
    store = FakeAdblockStore()
    loaded = load_admin_app(monkeypatch, tmp_path, adblock_store=store)

    with loaded.module.app.test_request_context(
        "/adblock",
        method="POST",
        data={"action": "save_settings", "cache_ttl": "900", "cache_max": "100"},
    ):
        response = loaded.module._handle_adblock_post(store)

    assert response.status_code in {301, 302, 303}
    assert store.settings["enabled"] is False
    assert store.refresh_requested == 1
    operation = loaded.operation_ledger.operations[-1]
    assert operation.operation_type == "adblock_refresh"
    assert operation.subject == "Adblock runtime refresh"
    assert operation.force is True


@pytest.mark.parametrize(
    ("form_data", "assert_mutation"),
    [
        (
            {"action": "save_lists", "enabled_default": "on"},
            lambda store: (
                store.refresh_requested == 1
                and store.statuses[0].enabled is True
                and store.cache_flush_requested == 0
            ),
        ),
        (
            {
                "action": "save_settings",
                "adblock_enabled": "on",
                "cache_ttl": "900",
                "cache_max": "100",
            },
            lambda store: (
                store.refresh_requested == 1
                and store.settings["cache_ttl"] == 900
                and store.settings["cache_max"] == 100
                and store.cache_flush_requested == 0
            ),
        ),
        (
            {"action": "refresh"},
            lambda store: (
                store.refresh_requested == 1 and store.cache_flush_requested == 0
            ),
        ),
        (
            {"action": "flush_cache"},
            lambda store: (
                store.cache_flush_requested == 1 and store.refresh_requested == 0
            ),
        ),
    ],
)
def test_adblock_mutations_report_runtime_refresh_queue_failure(
    monkeypatch,
    tmp_path,
    form_data: dict[str, str],
    assert_mutation: Callable[[FakeAdblockStore], bool],
) -> None:
    store = FakeAdblockStore()
    loaded = load_admin_app(monkeypatch, tmp_path, adblock_store=store)

    def fail_reconcile(*_args, **_kwargs):
        msg = "operation ledger unavailable"
        raise RuntimeError(msg)

    monkeypatch.setattr(loaded.module, "request_proxy_reconcile", fail_reconcile)

    with loaded.module.app.test_request_context(
        "/adblock",
        method="POST",
        data=form_data,
    ):
        response = loaded.module._handle_adblock_post(store)

    params = _params(response.location)
    assert params["error"] == ["1"]
    assert "runtime refresh was not queued" in params["msg"][0]
    assert "refresh_requested" not in params
    assert "cache_flushed" not in params
    assert assert_mutation(store)
    assert loaded.operation_ledger.operations == []
