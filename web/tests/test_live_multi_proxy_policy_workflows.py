from __future__ import annotations

import re

import pytest

from .live_test_helpers import LIVE_CONFIG, LiveStackClient, admin_client, query_params, unique_domain, unique_token, wait_for_proxy_inventory, with_proxy_id


pytestmark = pytest.mark.live


_PAC_PROFILE_RE = re.compile(
    r'(?s)<input type="hidden" name="action" value="update" />\s*<input type="hidden" name="profile_id" value="(\d+)" />.*?<input name="name" type="text" value="([^"]*)" />'
)


def _find_pac_profile_id(html: str, profile_name: str) -> int:
    for profile_id, name in _PAC_PROFILE_RE.findall(html):
        if name == profile_name:
            return int(profile_id)
    raise AssertionError(f"Could not find PAC profile id for {profile_name!r}.")


@pytest.fixture
def multi_proxy_admin(admin_client: LiveStackClient) -> LiveStackClient:
    wait_for_proxy_inventory(
        admin_client,
        [LIVE_CONFIG.primary_proxy_id, LIVE_CONFIG.remote_proxy_id],
        timeout_seconds=120.0,
    )
    return admin_client


def test_live_remote_pac_profile_updates_only_selected_proxy_pac(multi_proxy_admin: LiveStackClient) -> None:
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
    assert query_params(create_response.url).get("proxy_id") == [LIVE_CONFIG.remote_proxy_id]
    assert profile_name in create_response.text

    remote_pac = multi_proxy_admin.remote_pac_request()
    local_pac = multi_proxy_admin.pac_request()
    assert remote_pac.status == 200
    assert local_pac.status == 200
    assert direct_domain in remote_pac.text
    assert direct_domain not in local_pac.text

    profiles_page = multi_proxy_admin.admin_request(with_proxy_id("/pac", LIVE_CONFIG.remote_proxy_id))
    profile_id = _find_pac_profile_id(profiles_page.text, profile_name)
    delete_response = multi_proxy_admin.admin_post_form(
        with_proxy_id("/pac", LIVE_CONFIG.remote_proxy_id),
        {"action": "delete", "profile_id": str(profile_id)},
        csrf_path=with_proxy_id("/pac", LIVE_CONFIG.remote_proxy_id),
        timeout_seconds=90.0,
    )
    assert delete_response.status == 200
    assert query_params(delete_response.url).get("proxy_id") == [LIVE_CONFIG.remote_proxy_id]
    assert direct_domain not in multi_proxy_admin.remote_pac_request().text


def test_live_remote_exclusions_update_only_selected_proxy_pac(multi_proxy_admin: LiveStackClient) -> None:
    domain = unique_domain("remote-exclusion")

    add_response = multi_proxy_admin.admin_post_form(
        with_proxy_id("/exclusions", LIVE_CONFIG.remote_proxy_id),
        {"action": "add_domain", "domain": domain},
        csrf_path=with_proxy_id("/exclusions", LIVE_CONFIG.remote_proxy_id),
        timeout_seconds=90.0,
    )
    assert add_response.status == 200
    assert query_params(add_response.url).get("proxy_id") == [LIVE_CONFIG.remote_proxy_id]

    remote_pac = multi_proxy_admin.remote_pac_request()
    local_pac = multi_proxy_admin.pac_request()
    assert domain in remote_pac.text
    assert domain not in local_pac.text

    remove_response = multi_proxy_admin.admin_post_form(
        with_proxy_id("/exclusions", LIVE_CONFIG.remote_proxy_id),
        {"action": "remove_domain", "domain": domain},
        csrf_path=with_proxy_id("/exclusions", LIVE_CONFIG.remote_proxy_id),
        timeout_seconds=90.0,
    )
    assert remove_response.status == 200
    assert query_params(remove_response.url).get("proxy_id") == [LIVE_CONFIG.remote_proxy_id]
    assert domain not in multi_proxy_admin.remote_pac_request().text


def test_live_remote_sslfilter_rows_stay_scoped_to_selected_proxy(multi_proxy_admin: LiveStackClient) -> None:
    cidr = "10.88.0.0/16"

    add_response = multi_proxy_admin.admin_post_form(
        with_proxy_id("/sslfilter", LIVE_CONFIG.remote_proxy_id),
        {"action": "add", "cidr": cidr},
        csrf_path=with_proxy_id("/sslfilter", LIVE_CONFIG.remote_proxy_id),
        timeout_seconds=90.0,
    )
    assert add_response.status == 200
    assert query_params(add_response.url).get("proxy_id") == [LIVE_CONFIG.remote_proxy_id]

    remote_page = multi_proxy_admin.admin_request(with_proxy_id("/sslfilter", LIVE_CONFIG.remote_proxy_id))
    local_page = multi_proxy_admin.admin_request(with_proxy_id("/sslfilter", LIVE_CONFIG.primary_proxy_id))
    assert cidr in remote_page.text
    assert cidr not in local_page.text

    remove_response = multi_proxy_admin.admin_post_form(
        with_proxy_id("/sslfilter", LIVE_CONFIG.remote_proxy_id),
        {"action": "remove", "cidr": cidr},
        csrf_path=with_proxy_id("/sslfilter", LIVE_CONFIG.remote_proxy_id),
        timeout_seconds=90.0,
    )
    assert remove_response.status == 200
    assert cidr not in multi_proxy_admin.admin_request(with_proxy_id("/sslfilter", LIVE_CONFIG.remote_proxy_id)).text


def test_live_remote_clamav_test_actions_surface_selected_proxy_targets(multi_proxy_admin: LiveStackClient) -> None:
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
    assert query_params(eicar_response.url).get("proxy_id") == [LIVE_CONFIG.remote_proxy_id]
    assert query_params(icap_response.url).get("proxy_id") == [LIVE_CONFIG.remote_proxy_id]
    assert "clamav.edge-2.internal:3311" in eicar_response.text
    assert "127.0.0.1:24001" in icap_response.text
    assert "EICAR failed" in eicar_response.text
    assert "ICAP sample ok" in icap_response.text
    assert "ICAP/1.0 204 No Content" in icap_response.text


def test_live_remote_webfilter_save_updates_only_selected_proxy(multi_proxy_admin: LiveStackClient) -> None:
    source_url = f"https://example.invalid/{unique_token('remote-webcat')}.tar.gz"
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
            csrf_path=with_proxy_id("/webfilter?tab=categories", LIVE_CONFIG.remote_proxy_id),
            timeout_seconds=90.0,
        )
        assert response.status == 200
        assert query_params(response.url).get("proxy_id") == [LIVE_CONFIG.remote_proxy_id]
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
            csrf_path=with_proxy_id("/webfilter?tab=categories", LIVE_CONFIG.remote_proxy_id),
            timeout_seconds=90.0,
        )


def test_live_remote_adblock_flush_marks_selected_proxy_only(multi_proxy_admin: LiveStackClient) -> None:
    response = multi_proxy_admin.admin_post_form(
        with_proxy_id("/adblock", LIVE_CONFIG.remote_proxy_id),
        {"action": "flush_cache"},
        csrf_path=with_proxy_id("/adblock", LIVE_CONFIG.remote_proxy_id),
        timeout_seconds=90.0,
    )
    assert response.status == 200
    assert query_params(response.url).get("proxy_id") == [LIVE_CONFIG.remote_proxy_id]
    assert query_params(response.url).get("cache_flushed") == ["1"]