from __future__ import annotations

import re

import pytest

from .flask_test_helpers import login, redirect_query_params
from .route_test_support import install_common_ui_test_doubles
from .split_mode_test_helpers import FakeProxyClient, import_remote_app_module


@pytest.fixture()
def remote_app_module(monkeypatch):
    app_module = import_remote_app_module(
        secret_prefix="sfp_secret_ui_scope_",
        mysql_prefix="sfp_mysql_ui_scope_",
    )
    return install_common_ui_test_doubles(monkeypatch, app_module)


def _seed_registry(*proxy_ids: str):
    from services.proxy_registry import get_proxy_registry  # type: ignore

    registry = get_proxy_registry()
    for proxy_id in proxy_ids:
        registry.ensure_proxy(
            proxy_id,
            display_name=proxy_id.replace("-", " ").title(),
            management_url=f"http://{proxy_id}:5000",
            public_host=proxy_id,
            public_pac_scheme="http",
            public_pac_port=80,
            public_http_proxy_port=3128,
            public_socks_proxy_port=1080,
            public_socks_enabled=True,
        )
    return registry


def test_remote_layout_pins_internal_links_and_actions_to_active_proxy(remote_app_module):
    _seed_registry("edge-1")

    client = remote_app_module.app.test_client()
    login(client)

    response = client.get("/webfilter?proxy_id=edge-1")
    assert response.status_code == 200

    body = response.data.decode("utf-8", errors="replace")
    assert "This tab keeps navigation and form actions pinned to this proxy" in body
    assert 'href="/squid/config?proxy_id=edge-1"' in body
    assert 'href="/observability?proxy_id=edge-1' in body
    assert 'href="/proxies?proxy_id=edge-1"' in body
    assert 'id="proxy-id"' in body
    assert 'Manage proxies' in body
    assert 'class="nav-user"' not in body
    assert re.search(r'action="/webfilter\?tab=categories(?:&amp;|&)proxy_id=edge-1"', body)
    assert 'data-url="/webfilter/test?proxy_id=edge-1"' in body


@pytest.mark.parametrize(
    "path, expected_text",
    [
        ("/squid/config?proxy_id=edge-1", "Selected proxy configuration"),
        ("/adblock?proxy_id=edge-1", "Shared subscriptions + selected proxy runtime"),
        ("/webfilter?proxy_id=edge-1", "Shared category feed + selected proxy enforcement"),
        ("/certs?proxy_id=edge-1", "Shared certificate authority"),
        ("/administration?proxy_id=edge-1", "Shared control-plane access"),
        ("/proxies?proxy_id=edge-1", "Registered proxy inventory and targeting"),
    ],
)
def test_remote_scope_notices_render_on_key_pages(remote_app_module, path: str, expected_text: str):
    _seed_registry("edge-1", "edge-2")

    client = remote_app_module.app.test_client()
    login(client)

    response = client.get(path)
    assert response.status_code == 200
    body = response.data.decode("utf-8", errors="replace")
    assert expected_text in body


def test_remote_post_redirects_preserve_proxy_id(remote_app_module):
    _seed_registry("edge-1")

    client = remote_app_module.app.test_client()
    csrf = login(client)

    response = client.post(
        "/adblock?proxy_id=edge-1",
        headers={"X-CSRF-Token": csrf},
        data={
            "action": "save_settings",
            "adblock_enabled": "on",
            "cache_ttl": "90",
            "cache_max": "4000",
        },
        follow_redirects=False,
    )

    assert response.status_code in (301, 302, 303, 307, 308)
    assert redirect_query_params(response).get("proxy_id") == ["edge-1"]


def test_post_form_proxy_id_overrides_action_query_proxy_id(remote_app_module):
    _seed_registry("edge-1", "edge-2")

    fake_client = FakeProxyClient()
    original_client = remote_app_module.get_proxy_client
    remote_app_module.get_proxy_client = lambda: fake_client
    try:
        client = remote_app_module.app.test_client()
        csrf = login(client)

        response = client.post(
            "/reload?proxy_id=edge-1",
            headers={"X-CSRF-Token": csrf},
            data={"proxy_id": "edge-2"},
            follow_redirects=False,
        )
    finally:
        remote_app_module.get_proxy_client = original_client

    assert response.status_code in (301, 302, 303, 307, 308)
    assert fake_client.sync_calls == [("edge-2", True)]
    assert redirect_query_params(response).get("proxy_id") == ["edge-2"]


def test_remote_pac_page_shows_proxy_pinned_url(remote_app_module):
    _seed_registry("edge-1")

    client = remote_app_module.app.test_client()
    login(client)

    response = client.get("/pac?proxy_id=edge-1")
    assert response.status_code == 200
    body = response.data.decode("utf-8", errors="replace")
    assert "http://edge-1/proxy.pac" in body
    assert "http://edge-1/proxy.pac?proxy_id=edge-1" not in body


def test_proxies_page_marks_active_proxy_in_current_tab(remote_app_module):
    _seed_registry("edge-1", "edge-2")

    client = remote_app_module.app.test_client()
    login(client)

    response = client.get("/proxies?proxy_id=edge-1")
    assert response.status_code == 200
    body = response.data.decode("utf-8", errors="replace")
    assert "Active in this tab" in body


