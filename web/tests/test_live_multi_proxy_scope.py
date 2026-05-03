from __future__ import annotations

import re

import pytest

from .live_test_helpers import LIVE_CONFIG, LiveStackClient, admin_client, query_params, wait_for_proxy_inventory, with_proxy_id


pytestmark = pytest.mark.live


@pytest.fixture
def multi_proxy_admin(admin_client: LiveStackClient) -> LiveStackClient:
    wait_for_proxy_inventory(
        admin_client,
        [LIVE_CONFIG.primary_proxy_id, LIVE_CONFIG.remote_proxy_id],
        timeout_seconds=120.0,
    )
    return admin_client


def test_live_remote_layout_pins_internal_links_and_actions_to_active_proxy(multi_proxy_admin: LiveStackClient) -> None:
    response = multi_proxy_admin.admin_request(with_proxy_id("/webfilter", LIVE_CONFIG.remote_proxy_id))
    assert response.status == 200

    body = response.text
    assert "This tab keeps navigation and form actions pinned to this proxy" in body
    assert f'href="/squid/config?proxy_id={LIVE_CONFIG.remote_proxy_id}"' in body
    assert f'href="/observability?proxy_id={LIVE_CONFIG.remote_proxy_id}' in body
    assert f'href="/proxies?proxy_id={LIVE_CONFIG.remote_proxy_id}"' in body
    assert 'id="proxy-id"' in body
    assert 'Manage proxies' in body
    assert 'class="nav-user"' not in body
    assert re.search(
        rf'action="/webfilter\?(?:tab=categories(?:&amp;|&)proxy_id={re.escape(LIVE_CONFIG.remote_proxy_id)}|proxy_id={re.escape(LIVE_CONFIG.remote_proxy_id)}(?:&amp;|&)tab=categories)"',
        body,
    )
    assert f'data-url="/webfilter/test?proxy_id={LIVE_CONFIG.remote_proxy_id}"' in body


@pytest.mark.parametrize(
    ("path", "expected_text"),
    [
        ("/squid/config", "Selected proxy configuration"),
        ("/adblock", "Shared subscriptions + selected proxy runtime"),
        ("/webfilter", "Shared category feed + selected proxy enforcement"),
        ("/certs", "Shared certificate authority"),
        ("/administration", "Shared control-plane access"),
        ("/proxies", "Registered proxy inventory and targeting"),
    ],
)
def test_live_remote_scope_notices_render_on_key_pages(
    multi_proxy_admin: LiveStackClient,
    path: str,
    expected_text: str,
) -> None:
    response = multi_proxy_admin.admin_request(with_proxy_id(path, LIVE_CONFIG.remote_proxy_id))
    assert response.status == 200
    assert expected_text in response.text


def test_live_remote_post_redirects_preserve_proxy_id(multi_proxy_admin: LiveStackClient) -> None:
    response = multi_proxy_admin.admin_post_form(
        with_proxy_id("/adblock", LIVE_CONFIG.remote_proxy_id),
        {
            "action": "save_settings",
            "adblock_enabled": "on",
            "cache_ttl": "90",
            "cache_max": "4000",
        },
        csrf_path=with_proxy_id("/adblock", LIVE_CONFIG.remote_proxy_id),
    )

    assert response.status == 200
    assert query_params(response.url).get("proxy_id") == [LIVE_CONFIG.remote_proxy_id]


def test_live_remote_pac_page_shows_proxy_pinned_url(multi_proxy_admin: LiveStackClient) -> None:
    response = multi_proxy_admin.admin_request(with_proxy_id("/pac", LIVE_CONFIG.remote_proxy_id))
    assert response.status == 200
    assert LIVE_CONFIG.remote_pac_url in response.text
    assert f"{LIVE_CONFIG.remote_pac_url}?proxy_id={LIVE_CONFIG.remote_proxy_id}" not in response.text


def test_live_proxies_page_marks_active_proxy_in_current_tab(multi_proxy_admin: LiveStackClient) -> None:
    response = multi_proxy_admin.admin_request(with_proxy_id("/proxies", LIVE_CONFIG.remote_proxy_id))
    assert response.status == 200
    assert "Active in this tab" in response.text
    assert LIVE_CONFIG.remote_proxy_id in response.text