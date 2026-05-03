from __future__ import annotations

import re
import json

import pytest

from .live_test_helpers import (
    LIVE_CONFIG,
    LiveStackClient,
    admin_client,
    query_params,
    unique_domain,
    unique_token,
    wait_for_proxy_fixture_response,
    wait_for_proxy_management_payload,
)


pytestmark = pytest.mark.live


_PAC_PROFILE_RE = re.compile(
    r'(?s)<input type="hidden" name="action" value="update" />\s*<input type="hidden" name="profile_id" value="(\d+)" />.*?<input name="name" type="text" value="([^"]*)" />'
)


def _find_pac_profile_id(html: str, profile_name: str) -> int:
    for profile_id, name in _PAC_PROFILE_RE.findall(html):
        if name == profile_name:
            return int(profile_id)
    raise AssertionError(f"Could not find PAC profile id for {profile_name!r}.")


def _adblock_store():
    from services.adblock_store import get_adblock_store  # type: ignore

    store = get_adblock_store()
    store.init_db()
    return store


def _adblock_artifacts_store():
    from services.adblock_artifacts import get_adblock_artifacts  # type: ignore

    return get_adblock_artifacts()


def _webfilter_store():
    from services.webfilter_store import get_webfilter_store  # type: ignore

    store = get_webfilter_store()
    store.init_db()
    return store


def _with_proxy_id(proxy_id: object, callback):
    from services.proxy_context import reset_proxy_id, set_proxy_id  # type: ignore

    token = set_proxy_id(proxy_id)
    try:
        return callback()
    finally:
        reset_proxy_id(token)


def _webfilter_settings(proxy_id: object):
    return _with_proxy_id(proxy_id, lambda: _webfilter_store().get_settings())


def _restore_webfilter_settings(proxy_id: object, settings) -> None:
    def _restore() -> None:
        _webfilter_store().set_settings(
            enabled=settings.enabled,
            source_url=settings.source_url,
            blocked_categories=list(settings.blocked_categories),
        )

    _with_proxy_id(proxy_id, _restore)


def test_live_pac_profile_create_update_delete_updates_rendered_pac(admin_client: LiveStackClient) -> None:
    profile_name = unique_token("live_pac")
    direct_domain = unique_domain("direct")
    updated_name = unique_token("live_pac_updated")
    updated_domain = unique_domain("updated-direct")

    create_response = admin_client.admin_post_form(
        "/pac",
        {
            "action": "create",
            "name": profile_name,
            "client_cidr": "",
            "direct_domains": direct_domain,
            "direct_dst_nets": "",
        },
        csrf_path="/pac",
    )
    assert create_response.status == 200
    assert query_params(create_response.url).get("ok") == ["1"]
    assert profile_name in create_response.text

    pac_response = admin_client.pac_request()
    assert pac_response.status == 200
    assert direct_domain in pac_response.text

    profiles_page = admin_client.admin_request("/pac")
    profile_id = _find_pac_profile_id(profiles_page.text, profile_name)

    update_response = admin_client.admin_post_form(
        "/pac",
        {
            "action": "update",
            "profile_id": str(profile_id),
            "name": updated_name,
            "client_cidr": "",
            "direct_domains": updated_domain,
            "direct_dst_nets": "10.77.0.0/16",
        },
        csrf_path="/pac",
    )
    assert update_response.status == 200
    assert query_params(update_response.url).get("ok") == ["1"]
    assert updated_name in update_response.text

    updated_pac = admin_client.pac_request()
    assert updated_domain in updated_pac.text
    assert direct_domain not in updated_pac.text

    delete_response = admin_client.admin_post_form(
        "/pac",
        {
            "action": "delete",
            "profile_id": str(profile_id),
        },
        csrf_path="/pac",
    )
    assert delete_response.status == 200
    assert query_params(delete_response.url).get("ok") == ["1"]
    assert updated_name not in delete_response.text

    fallback_pac = admin_client.pac_request()
    assert updated_domain not in fallback_pac.text


def test_live_exclusions_add_remove_and_apply_reflect_in_proxy_pac(admin_client: LiveStackClient) -> None:
    domain = unique_domain("exclude")
    cidr = "10.55.77.0/24"

    add_domain_response = admin_client.admin_post_form(
        "/exclusions",
        {
            "action": "add_domain",
            "domain": domain,
        },
        csrf_path="/exclusions",
    )
    assert add_domain_response.status == 200
    assert domain in add_domain_response.text

    add_cidr_response = admin_client.admin_post_form(
        "/exclusions",
        {
            "action": "add_src",
            "cidr": cidr,
        },
        csrf_path="/exclusions",
    )
    assert add_cidr_response.status == 200
    assert cidr in add_cidr_response.text

    toggle_private_response = admin_client.admin_post_form(
        "/exclusions",
        {
            "action": "toggle_private",
            "exclude_private_nets": "on",
        },
        csrf_path="/exclusions",
    )
    assert toggle_private_response.status == 200
    assert "Private-network bypass preference updated." in toggle_private_response.text

    exclusions_page = admin_client.admin_request("/exclusions")
    assert domain in exclusions_page.text
    assert cidr in exclusions_page.text
    assert 'name="exclude_private_nets" checked' in exclusions_page.text

    pac_response = admin_client.pac_request()
    assert pac_response.status == 200
    assert domain in pac_response.text

    apply_response = admin_client.admin_post_form(
        "/exclusions",
        {"action": "apply"},
        csrf_path="/exclusions",
    )
    assert apply_response.status == 200
    assert query_params(apply_response.url).get("ok") == ["1"]
    assert "Squid reloaded with updated exclusions." in apply_response.text
    wait_for_proxy_management_payload()

    remove_domain_response = admin_client.admin_post_form(
        "/exclusions",
        {"action": "remove_domain", "domain": domain},
        csrf_path="/exclusions",
    )
    assert remove_domain_response.status == 200
    remove_cidr_response = admin_client.admin_post_form(
        "/exclusions",
        {"action": "remove_src", "cidr": cidr},
        csrf_path="/exclusions",
    )
    assert remove_cidr_response.status == 200
    final_page = admin_client.admin_request("/exclusions")
    assert domain not in final_page.text
    assert cidr not in final_page.text


def test_live_administration_add_change_and_delete_user(admin_client: LiveStackClient) -> None:
    username = unique_token("operator")
    initial_password = "InitialPass123!"
    rotated_password = "RotatedPass123!"

    add_user_response = admin_client.admin_post_form(
        "/administration",
        {
            "action": "add_user",
            "username": username,
            "password": initial_password,
        },
        csrf_path="/administration",
    )
    assert add_user_response.status == 200
    assert "User added." in add_user_response.text
    assert username in add_user_response.text

    delete_current_user_response = admin_client.admin_post_form(
        "/administration",
        {
            "action": "delete_user",
            "username": "admin",
        },
        csrf_path="/administration",
    )
    assert delete_current_user_response.status == 200
    assert "Cannot remove the currently signed-in user." in delete_current_user_response.text

    user_client = LiveStackClient()
    user_client.login(username=username, password=initial_password)
    change_password_response = user_client.admin_post_form(
        "/administration",
        {
            "action": "set_password",
            "username": username,
            "new_password": rotated_password,
        },
        csrf_path="/administration",
    )
    assert change_password_response.status == 200
    assert "Password updated." in change_password_response.text

    user_client.logout()
    relogin_client = LiveStackClient()
    relogin_client.login(username=username, password=rotated_password)

    cleanup_admin = LiveStackClient()
    cleanup_admin.login()
    delete_user_response = cleanup_admin.admin_post_form(
        "/administration",
        {
            "action": "delete_user",
            "username": username,
        },
        csrf_path="/administration",
    )
    assert delete_user_response.status == 200
    assert "User removed." in delete_user_response.text

    deleted_user_client = LiveStackClient()
    failed_login = deleted_user_client.login(username=username, password=rotated_password, expect_success=False)
    assert "Invalid username or password." in failed_login.text


def test_live_sslfilter_and_webfilter_whitelist_workflows(admin_client: LiveStackClient) -> None:
    cidr = "172.31.250.0/24"
    whitelist_domain = unique_domain("allow")

    add_cidr_response = admin_client.admin_post_form(
        "/sslfilter",
        {
            "action": "add",
            "cidr": cidr,
        },
        csrf_path="/sslfilter",
    )
    assert add_cidr_response.status == 200
    assert cidr in add_cidr_response.text

    remove_cidr_response = admin_client.admin_post_form(
        "/sslfilter",
        {
            "action": "remove",
            "cidr": cidr,
        },
        csrf_path="/sslfilter",
    )
    assert remove_cidr_response.status == 200
    assert cidr not in admin_client.admin_request("/sslfilter").text

    add_whitelist_response = admin_client.admin_post_form(
        "/webfilter?tab=whitelist",
        {
            "tab": "whitelist",
            "action": "whitelist_add",
            "whitelist_domain": whitelist_domain,
        },
        csrf_path="/webfilter?tab=whitelist",
    )
    assert add_whitelist_response.status == 200
    assert "Whitelist entry added." in add_whitelist_response.text
    assert whitelist_domain in add_whitelist_response.text

    remove_whitelist_response = admin_client.admin_post_form(
        "/webfilter?tab=whitelist",
        {
            "tab": "whitelist",
            "action": "whitelist_remove",
            "pattern": whitelist_domain,
        },
        csrf_path="/webfilter?tab=whitelist",
    )
    assert remove_whitelist_response.status == 200
    assert whitelist_domain not in admin_client.admin_request("/webfilter?tab=whitelist").text


def test_live_adblock_list_settings_refresh_and_flush_workflows(admin_client: LiveStackClient) -> None:
    store = _adblock_store()
    original_statuses = {status.key: status.enabled for status in store.list_statuses()}
    original_settings = store.get_settings()
    statuses = store.list_statuses()
    assert statuses, "expected live adblock store to seed default lists"
    target_key = statuses[0].key

    try:
        save_lists_response = admin_client.admin_post_form(
            "/adblock",
            {
                "action": "save_lists",
                f"enabled_{target_key}": "on",
            },
            csrf_path="/adblock",
        )
        assert save_lists_response.status == 200
        enabled_map = {status.key: status.enabled for status in store.list_statuses()}
        assert enabled_map[target_key] is True
        assert store.get_refresh_requested() > 0

        save_settings_response = admin_client.admin_post_form(
            "/adblock",
            {
                "action": "save_settings",
                "adblock_enabled": "on",
                "cache_ttl": "120",
                "cache_max": "999",
            },
            csrf_path="/adblock",
        )
        assert save_settings_response.status == 200
        settings = store.get_settings()
        assert settings["enabled"] is True
        assert settings["cache_ttl"] == 120
        assert settings["cache_max"] == 999

        refresh_response = admin_client.admin_post_form(
            "/adblock",
            {"action": "refresh"},
            csrf_path="/adblock",
            timeout_seconds=90.0,
        )
        assert refresh_response.status == 200
        assert query_params(refresh_response.url).get("refresh_requested") == ["1"]

        flush_response = admin_client.admin_post_form(
            "/adblock",
            {"action": "flush_cache"},
            csrf_path="/adblock",
            timeout_seconds=90.0,
        )
        assert flush_response.status == 200
        assert query_params(flush_response.url).get("cache_flushed") == ["1"]
        wait_for_proxy_management_payload()
        wait_for_proxy_fixture_response(admin_client, "/health", timeout_seconds=120.0)

        disable_all_response = admin_client.admin_post_form(
            "/adblock",
            {"action": "save_lists"},
            csrf_path="/adblock",
        )
        assert disable_all_response.status == 200
        refresh_no_lists_response = admin_client.admin_post_form(
            "/adblock",
            {"action": "refresh"},
            csrf_path="/adblock",
        )
        assert refresh_no_lists_response.status == 200
        assert query_params(refresh_no_lists_response.url).get("refresh_no_lists") == ["1"]
    finally:
        store.set_enabled(original_statuses)
        store.set_settings(
            enabled=bool(original_settings.get("enabled")),
            cache_ttl=int(original_settings.get("cache_ttl") or 0),
            cache_max=int(original_settings.get("cache_max") or 0),
        )
        store.clear_refresh_requested()
        _with_proxy_id(LIVE_CONFIG.primary_proxy_id, lambda: store.mark_cache_flushed(size=0))


def test_live_proxy_sync_materializes_adblock_artifact_revision(admin_client: LiveStackClient, tmp_path) -> None:
    artifact_dir = tmp_path / "adblock-artifact"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    (artifact_dir / "domains_allow.txt").write_text("allow-live-artifact.example\n", encoding="utf-8")
    (artifact_dir / "domains_block.txt").write_text("ads-live-artifact.example\n", encoding="utf-8")
    (artifact_dir / "regex_allow.txt").write_text("", encoding="utf-8")
    (artifact_dir / "regex_block.txt").write_text("/tracker-live-artifact[.]example/\n", encoding="utf-8")
    (artifact_dir / "settings.json").write_text(
        json.dumps(
            {
                "enabled": False,
                "cache_ttl": 120,
                "cache_max": 1000,
                "settings_version": 2,
                "enabled_lists": ["live-fixture"],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (artifact_dir / "report.json").write_text(
        json.dumps(
            {
                "enabled_lists": ["live-fixture"],
                "counts": {"domains_block": 1, "domains_allow": 1, "regex_block": 1, "regex_allow": 0},
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    revision = _adblock_artifacts_store().create_revision_from_directory(
        artifact_dir,
        settings_version=2,
        enabled_lists=["live-fixture"],
        created_by="live-tests",
        source_kind="live-fixture",
    )
    store = _adblock_store()
    _with_proxy_id(LIVE_CONFIG.primary_proxy_id, store.request_cache_flush)

    sync_response = admin_client.proxy_management_post_json("/api/manage/sync", {"force": False}, timeout_seconds=90.0)
    assert sync_response.status == 200
    sync_payload = sync_response.json()
    assert sync_payload.get("ok") is True
    assert sync_payload.get("adblock_changed") is True

    latest_apply = _adblock_artifacts_store().latest_apply(LIVE_CONFIG.primary_proxy_id)
    assert latest_apply is not None
    assert latest_apply.revision_id == revision.revision_id
    assert latest_apply.ok is True
    assert latest_apply.artifact_sha256 == revision.artifact_sha256
    assert _with_proxy_id(LIVE_CONFIG.primary_proxy_id, store.get_cache_flush_requested) == 0


def test_live_webfilter_category_validation_and_save_workflows(admin_client: LiveStackClient) -> None:
    original_settings = _webfilter_settings(LIVE_CONFIG.primary_proxy_id)
    source_url = f"https://example.invalid/{unique_token('webcat')}.tar.gz"

    try:
        missing_source_response = admin_client.admin_post_form(
            "/webfilter?tab=categories",
            {
                "action": "save",
                "tab": "categories",
                "enabled": "on",
                "source_url": "",
                "categories": ["adult"],
            },
            csrf_path="/webfilter?tab=categories",
        )
        assert missing_source_response.status == 200
        assert query_params(missing_source_response.url).get("err_source") == ["1"]

        invalid_source_response = admin_client.admin_post_form(
            "/webfilter?tab=categories",
            {
                "action": "save",
                "tab": "categories",
                "enabled": "on",
                "source_url": "ftp://example.invalid/webcat.tar.gz",
                "categories": ["adult"],
            },
            csrf_path="/webfilter?tab=categories",
        )
        assert invalid_source_response.status == 200
        assert query_params(invalid_source_response.url).get("err_source") == ["1"]

        save_response = admin_client.admin_post_form(
            "/webfilter?tab=categories",
            {
                "action": "save",
                "tab": "categories",
                "enabled": "on",
                "source_url": source_url,
                "categories": ["adult", "games"],
            },
            csrf_path="/webfilter?tab=categories",
            timeout_seconds=90.0,
        )
        assert save_response.status == 200
        assert query_params(save_response.url).get("tab") == ["categories"]
        assert query_params(save_response.url).get("err_source") is None
    finally:
        _restore_webfilter_settings(LIVE_CONFIG.primary_proxy_id, original_settings)