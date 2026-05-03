from __future__ import annotations

import re

import pytest

from .live_test_helpers import LiveStackClient, admin_client, query_params, unique_domain, unique_token, wait_for_proxy_management_payload


pytestmark = pytest.mark.live


_PAC_PROFILE_RE = re.compile(
    r'(?s)<input type="hidden" name="action" value="update" />\s*<input type="hidden" name="profile_id" value="(\d+)" />.*?<input name="name" type="text" value="([^"]*)" />'
)


def _find_pac_profile_id(html: str, profile_name: str) -> int:
    for profile_id, name in _PAC_PROFILE_RE.findall(html):
        if name == profile_name:
            return int(profile_id)
    raise AssertionError(f"Could not find PAC profile id for {profile_name!r}.")


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