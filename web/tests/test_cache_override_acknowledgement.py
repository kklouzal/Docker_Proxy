from __future__ import annotations

from .admin_route_test_utils import csrf_token, load_admin_app, login_client


def _client(loaded):
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/squid/config?tab=caching&subtab=overrides")
    return client, token


def test_direct_post_rejects_new_cache_risk_without_acknowledgement(
    monkeypatch, tmp_path
) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    client, token = _client(loaded)

    response = client.post(
        "/squid/config/apply-overrides",
        data={"csrf_token": token, "ignore_no_store": "on"},
        follow_redirects=False,
    )

    assert response.status_code in {302, 303}
    assert "error=1" in response.headers["Location"]
    assert "Explicitly+acknowledge" in response.headers["Location"]
    assert loaded.config_revisions.created == []


def test_acknowledged_post_accepts_new_cache_risk(monkeypatch, tmp_path) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    client, token = _client(loaded)

    response = client.post(
        "/squid/config/apply-overrides",
        data={
            "csrf_token": token,
            "ignore_no_store": "on",
            "acknowledge_cache_override_risk": "on",
        },
        follow_redirects=False,
    )

    assert response.status_code in {302, 303}
    assert "ok=1" in response.headers["Location"]
    assert loaded.config_revisions.created[-1]["source_kind"] == "overrides"


def test_risk_reduction_does_not_require_acknowledgement(monkeypatch, tmp_path) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    current = {
        "override_expire": False,
        "override_lastmod": False,
        "reload_into_ims": False,
        "ignore_reload": False,
        "ignore_no_store": True,
        "ignore_private": True,
    }
    monkeypatch.setattr(
        loaded.module.squid_controller,
        "get_cache_override_options",
        lambda _text: current,
    )
    client, token = _client(loaded)

    response = client.post(
        "/squid/config/apply-overrides",
        data={"csrf_token": token, "ignore_private": "on"},
        follow_redirects=False,
    )

    assert response.status_code in {302, 303}
    assert "ok=1" in response.headers["Location"]


def test_page_exposes_server_enforced_acknowledgement(monkeypatch, tmp_path) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    client, _token = _client(loaded)

    response = client.get("/squid/config?tab=caching&subtab=overrides")
    text = response.get_data(as_text=True)

    assert response.status_code == 200
    assert 'name="acknowledge_cache_override_risk"' in text
    assert "acknowledgement is enforced by the server" in text
