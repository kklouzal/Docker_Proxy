from __future__ import annotations

import pytest

from .admin_route_test_utils import FakeRegistry, csrf_token, load_admin_app, login_client


class RecordingProxyClient:
    def __init__(self) -> None:
        self.health_calls: list[tuple[str, float | None]] = []

    def get_health(self, proxy_id: object, *_, timeout_seconds: float | None = None, **__) -> dict[str, object]:
        self.health_calls.append((str(proxy_id), timeout_seconds))
        return {
            "ok": True,
            "status": "healthy",
            "proxy_id": str(proxy_id),
            "proxy_status": "Squid check ok.",
            "stats": {},
            "services": {
                "icap": {"ok": True, "detail": "ok"},
                "clamav": {"ok": True, "detail": "ok"},
            },
        }

    def validate_config(self, proxy_id: object, config_text: str) -> dict[str, object]:
        return {"ok": True, "detail": "valid", "proxy_id": str(proxy_id)}

    def sync_proxy(self, proxy_id: object, *, force: bool = False) -> dict[str, object]:
        return {"ok": True, "detail": "sync requested"}

    def clear_proxy_cache(self, proxy_id: object) -> dict[str, object]:
        return {"ok": True, "detail": "cache cleared"}


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


def test_index_uses_cold_cache_safe_proxy_health_timeout(monkeypatch, tmp_path) -> None:
    proxy_client = RecordingProxyClient()
    loaded = load_admin_app(monkeypatch, tmp_path, proxy_client=proxy_client)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/")

    assert response.status_code == 200
    assert proxy_client.health_calls[-1] == ("default", 1.5)


def test_index_reuses_short_lived_proxy_health_cache(monkeypatch, tmp_path) -> None:
    proxy_client = RecordingProxyClient()
    loaded = load_admin_app(monkeypatch, tmp_path, proxy_client=proxy_client)
    client = loaded.module.app.test_client()
    login_client(client)

    assert client.get("/").status_code == 200
    assert client.get("/").status_code == 200

    assert proxy_client.health_calls == [("default", 1.5)]


def test_fleet_checks_only_active_proxy_live_health(monkeypatch, tmp_path) -> None:
    proxy_client = RecordingProxyClient()
    registry = FakeRegistry(["default", "edge-2"])
    loaded = load_admin_app(monkeypatch, tmp_path, proxy_client=proxy_client, registry=registry)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/proxies")

    assert response.status_code == 200
    assert proxy_client.health_calls == [("default", 1.5)]


def test_api_squid_config_plain_text_contract(monkeypatch, tmp_path) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    login_client(client)
    response = client.get("/api/squid-config")
    assert response.status_code == 200
    assert response.headers.get("Content-Type", "").startswith("text/plain")
    assert "http_port" in response.get_data(as_text=True)
    assert "Content-Security-Policy" not in response.headers


def test_network_config_apply_can_publish_intercept_listener(monkeypatch, tmp_path) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    login_client(client)
    response = client.post(
        "/squid/config/apply-safe",
        data={
            "csrf_token": csrf_token(client, "/squid/config?tab=network"),
            "form_kind": "network",
            "explicit_proxy_port": "3128",
            "intercept_enabled_on": "on",
            "intercept_port": "3129",
            "client_persistent_connections_on": "on",
            "server_persistent_connections_on": "on",
            "persistent_connection_after_error_on": "on",
            "client_dst_passthru_on": "on",
            "on_unsupported_protocol_action": "respond",
            "happy_eyeballs_connect_timeout_ms": "250",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    config_text = loaded.config_revisions.get_active_config_text("default")
    assert "http_port 3128" in config_text
    assert "http_port 0.0.0.0:3129 intercept" in config_text
    assert "PROXY" not in config_text


def test_fleet_page_shows_explicit_and_intercept_listeners(monkeypatch, tmp_path) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/proxies")
    text = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "Listeners" in text
    assert "explicit 3128" in text
    assert "intercept 3129" in text


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
    for path in (
        "/reload",
        "/cache/clear",
        "/webfilter/test",
        "/ssl-errors/exclude",
        "/squid/config/apply-all",
        "/squid/config/apply-safe",
        "/squid/config/apply-overrides",
        "/sslfilter",
        "/certs/generate",
        "/certs/upload",
        "/clamav/toggle",
    ):
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


def test_sslfilter_page_exposes_apply_verify_action(monkeypatch, tmp_path) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/sslfilter")
    text = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "Apply &amp; Verify Config" in text
    assert 'name="action" value="apply_policy"' in text


def test_sslfilter_apply_verify_forces_selected_proxy_sync(monkeypatch, tmp_path) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/sslfilter")

    response = client.post(
        "/sslfilter",
        data={"csrf_token": token, "action": "apply_policy"},
        follow_redirects=True,
    )
    text = response.get_data(as_text=True)

    assert response.status_code == 200
    assert loaded.proxy_client.synced[-1] == ("default", True)
    assert "SSL filtering policy applied and verified" in text
    assert any(record["kind"] == "sslfilter_apply_policy" and record["ok"] for record in loaded.audit_store.records)


def test_main_config_page_exposes_rebuild_apply_all_action(monkeypatch, tmp_path) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/squid/config?tab=config")
    text = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "Rebuild, Verify &amp; Apply Saved Settings" in text
    assert 'form="apply-all-config-form"' in text
    assert 'action="/squid/config/apply-all' in text


def test_apply_all_saved_config_rebuilds_validates_and_syncs_selected_proxy(monkeypatch, tmp_path) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/squid/config?tab=config")

    response = client.post(
        "/squid/config/apply-all",
        data={"csrf_token": token},
        follow_redirects=True,
    )
    text = response.get_data(as_text=True)

    assert response.status_code == 200
    assert loaded.proxy_client.validated[-1][0] == "default"
    assert loaded.proxy_client.synced[-1] == ("default", True)
    assert loaded.config_revisions.created[-1]["proxy_id"] == "default"
    assert loaded.config_revisions.created[-1]["source_kind"] == "template-reconcile"
    assert "Saved settings were rebuilt, verified, and applied" in text
    assert any(record["kind"] == "config_apply_all_saved" and record["ok"] for record in loaded.audit_store.records)


def test_sslfilter_apply_verify_targets_selected_proxy(monkeypatch, tmp_path) -> None:
    registry = FakeRegistry(["default", "edge-2"])
    loaded = load_admin_app(monkeypatch, tmp_path, registry=registry)
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/sslfilter?proxy_id=edge-2")

    response = client.post(
        "/sslfilter?proxy_id=edge-2",
        data={"csrf_token": token, "action": "apply_policy"},
        follow_redirects=False,
    )

    assert response.status_code in {301, 302, 303, 307, 308}
    assert "proxy_id=edge-2" in response.headers["Location"]
    assert loaded.proxy_client.synced[-1] == ("edge-2", True)
    assert any(record["kind"] == "sslfilter_apply_policy" and record["ok"] for record in loaded.audit_store.records)


def test_apply_all_saved_config_targets_selected_proxy(monkeypatch, tmp_path) -> None:
    registry = FakeRegistry(["default", "edge-2"])
    loaded = load_admin_app(monkeypatch, tmp_path, registry=registry)
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/squid/config?tab=config&proxy_id=edge-2")

    response = client.post(
        "/squid/config/apply-all?proxy_id=edge-2",
        data={"csrf_token": token},
        follow_redirects=False,
    )

    assert response.status_code in {301, 302, 303, 307, 308}
    assert "proxy_id=edge-2" in response.headers["Location"]
    assert loaded.proxy_client.validated[-1][0] == "edge-2"
    assert loaded.proxy_client.synced[-1] == ("edge-2", True)
    assert loaded.config_revisions.created[-1]["proxy_id"] == "edge-2"
    assert loaded.config_revisions.created[-1]["source_kind"] == "template-reconcile"
    assert any(record["kind"] == "config_apply_all_saved" and record["ok"] for record in loaded.audit_store.records)
