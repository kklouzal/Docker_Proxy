from __future__ import annotations

import pytest

from .admin_route_test_utils import FakeRegistry, csrf_token, load_admin_app, login_client


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/api/squid-config",
        "/proxies",
        "/observability",
        "/observability/export",
        "/ssl-errors",
        "/ssl-errors/export",
        "/adblock",
        "/webfilter",
        "/sslfilter",
        "/clamav",
        "/squid/config",
        "/exclusions",
        "/pac",
        "/api/timeseries",
        "/certs",
        "/certs/download/ca.crt",
        "/administration",
    ],
)
def test_protected_get_routes_redirect_to_login(monkeypatch, tmp_path, path: str) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    response = client.get(path, follow_redirects=False)
    assert response.status_code in {301, 302, 303, 307, 308}
    assert response.headers["Location"].startswith("/login")


def test_health_is_public_and_json_has_no_csp(monkeypatch, tmp_path) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    response = loaded.module.app.test_client().get("/health")
    assert response.status_code == 200
    assert response.json == {"ok": True}
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert "Content-Security-Policy" not in response.headers


def test_html_security_headers_are_present(monkeypatch, tmp_path) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    login_client(client)
    response = client.get("/")
    assert response.status_code == 200
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "SAMEORIGIN"
    assert "default-src" in response.headers.get("Content-Security-Policy", "")


def test_api_squid_config_plain_text_contract(monkeypatch, tmp_path) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    login_client(client)
    response = client.get("/api/squid-config")
    assert response.status_code == 200
    assert response.headers.get("Content-Type", "").startswith("text/plain")
    assert "http_port" in response.get_data(as_text=True)
    assert "Content-Security-Policy" not in response.headers


def test_api_timeseries_bounds_and_content_type(monkeypatch, tmp_path) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    login_client(client)
    response = client.get("/api/timeseries?resolution=1m&window=1&limit=bad")
    assert response.status_code == 200
    assert response.headers.get("Content-Type", "").startswith("application/json")
    assert response.json["resolution"] == "1m"
    assert isinstance(response.json["points"], list)
    assert "Content-Security-Policy" not in response.headers


def test_proxy_id_query_is_normalized_and_bound_to_session(monkeypatch, tmp_path) -> None:
    registry = FakeRegistry(["default", "bad-value"])
    loaded = load_admin_app(monkeypatch, tmp_path, registry=registry)
    client = loaded.module.app.test_client()
    login_client(client)
    response = client.get("/api/squid-config?proxy_id=../../bad value!!")
    assert response.status_code == 200
    with client.session_transaction() as sess:
        assert sess["active_proxy_id"] == "bad-value"


def test_invalid_proxy_id_falls_back_to_registry_default(monkeypatch, tmp_path) -> None:
    registry = FakeRegistry(["default"])
    loaded = load_admin_app(monkeypatch, tmp_path, registry=registry)
    client = loaded.module.app.test_client()
    login_client(client)
    response = client.get("/api/squid-config?proxy_id=does-not-exist")
    assert response.status_code == 200
    with client.session_transaction() as sess:
        assert sess["active_proxy_id"] == "default"


def test_post_routes_reject_missing_csrf_after_login(monkeypatch, tmp_path) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    login_client(client)
    for path in ("/reload", "/cache/clear", "/webfilter/test", "/ssl-errors/exclude"):
        response = client.post(path, follow_redirects=False)
        assert response.status_code == 403, path


def test_post_routes_accept_header_csrf_for_json(monkeypatch, tmp_path) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/")
    response = client.post("/webfilter/test", json={"domain": "Example.COM"}, headers={"X-CSRF-Token": token})
    assert response.status_code == 200
    assert response.json["ok"] is True
    assert response.json["domain"] == "example.com"
