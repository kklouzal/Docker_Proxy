from __future__ import annotations

from .flask_test_helpers import import_local_app_module, login, redirect_query_params


def test_live_route_redirects_client_nocache_detail_to_cache_pane(monkeypatch):
    app_module = import_local_app_module()
    monkeypatch.setattr(app_module.time, "time", lambda: 20_000)

    client = app_module.app.test_client()
    login(client)

    response = client.get(
        "/live?mode=clients&ip=192.0.2.55&detail=nocache&window=3600&limit=120",
        follow_redirects=False,
    )
    assert response.status_code in (301, 302, 303, 307, 308)
    qs = redirect_query_params(response)
    assert qs.get("pane") == ["cache"]
    assert qs.get("window") == ["3600"]
    assert qs.get("limit") == ["120"]
    assert qs.get("q") == ["192.0.2.55"]


def test_live_route_redirects_reason_views_to_cache_pane(monkeypatch):
    app_module = import_local_app_module()
    monkeypatch.setattr(app_module.time, "time", lambda: 50_000)

    client = app_module.app.test_client()
    login(client)

    reasons_response = client.get("/live?subtab=reasons&window=7200&limit=150", follow_redirects=False)
    assert reasons_response.status_code in (301, 302, 303, 307, 308)
    reasons_qs = redirect_query_params(reasons_response)
    assert reasons_qs.get("pane") == ["cache"]
    assert reasons_qs.get("window") == ["7200"]
    assert reasons_qs.get("limit") == ["150"]

    domain_response = client.get(
        "/live?mode=domains&domain=example.com&detail=nocache&window=1800",
        follow_redirects=False,
    )
    assert domain_response.status_code in (301, 302, 303, 307, 308)
    domain_qs = redirect_query_params(domain_response)
    assert domain_qs.get("pane") == ["cache"]
    assert domain_qs.get("window") == ["1800"]
    assert domain_qs.get("limit") == ["100"]
    assert domain_qs.get("q") == ["example.com"]
