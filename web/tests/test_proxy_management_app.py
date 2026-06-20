from __future__ import annotations

import importlib
import sys
from pathlib import Path
from typing import NoReturn


def _add_repo_paths() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    web_root = repo_root / "web"
    for path in (repo_root, web_root):
        path_text = str(path)
        if path_text not in sys.path:
            sys.path.insert(0, path_text)


def _load_proxy_app(monkeypatch):
    _add_repo_paths()
    monkeypatch.setenv("DISABLE_PROXY_AGENT", "1")
    import proxy.app as proxy_app  # type: ignore

    return importlib.reload(proxy_app)


def _management_get(client, path: str, **kwargs):
    return client.get(path, base_url="http://localhost:5000", **kwargs)


def _management_post(client, path: str, **kwargs):
    return client.post(path, base_url="http://localhost:5000", **kwargs)


def _public_get(client, path: str, **kwargs):
    return client.get(path, base_url="http://localhost", **kwargs)


class _Runtime:
    proxy_id = "edge-a"

    def __init__(self) -> None:
        self.sync_force = None
        self.sync_operation_id = None
        self.validation_text = None
        self.rollback_reason = None

    def collect_health(self, *, force=False):
        return {
            "ok": True,
            "status": "healthy",
            "proxy_id": self.proxy_id,
            "services": {},
            "stats": {},
            "health_scope": "full",
        }

    def collect_navigation_health(self, *, force=False):
        return {
            "ok": True,
            "status": "healthy",
            "proxy_id": self.proxy_id,
            "services": {},
            "stats": {},
            "health_scope": "navigation",
        }

    def sync_from_db(self, *, force=False, operation_id=None):
        self.sync_force = force
        self.sync_operation_id = operation_id
        return {"ok": False, "detail": "sync failed"}

    def validate_config_text(self, config_text: str):
        self.validation_text = config_text
        return {"ok": False, "detail": "parse failed"}

    def rollback_last_known_good_config(self, *, reason: str):
        self.rollback_reason = reason
        return {"ok": False, "detail": "rollback failed"}

    def clear_cache(self):
        return {"ok": False, "detail": "cache clear failed"}

    def test_clamav_eicar(self):
        return {"ok": False, "detail": "clamd unavailable"}

    def test_clamav_icap(self):
        return {"ok": False, "detail": "icap unavailable"}

    def test_control_supervisor_program(self, program_name: str, *, action: str):
        if program_name != "cicap_adblock":
            return {
                "ok": False,
                "proxy_id": self.proxy_id,
                "program": program_name,
                "action": action,
                "detail": "not allowlisted",
            }
        return {
            "ok": True,
            "proxy_id": self.proxy_id,
            "program": program_name,
            "action": action,
            "detail": "done",
        }


class _BrokenHealthRuntime(_Runtime):
    def collect_health(self, *, force=False) -> NoReturn:
        msg = "boom"
        raise RuntimeError(msg)

    def collect_navigation_health(self, *, force=False) -> NoReturn:
        msg = "boom"
        raise RuntimeError(msg)


def test_proxy_management_api_requires_token_for_all_management_endpoints(
    monkeypatch,
) -> None:
    proxy_app = _load_proxy_app(monkeypatch)
    monkeypatch.setenv("PROXY_MANAGEMENT_TOKEN", "secret")
    proxy_app.runtime = _Runtime()
    client = proxy_app.app.test_client()

    assert _management_get(client, "/health").status_code == 200

    endpoints = [
        ("GET", "/api/manage/health", None),
        ("POST", "/api/manage/sync", {}),
        ("POST", "/api/manage/config/validate", {"config_text": "workers 1\n"}),
        ("POST", "/api/manage/config/rollback", {"reason": "test"}),
        ("POST", "/api/manage/cache/clear", {}),
        ("POST", "/api/manage/clamav/test-eicar", {}),
        ("POST", "/api/manage/clamav/test-icap", {}),
        ("GET", "/api/manage/logs?log=access", None),
        ("POST", "/api/manage/test/supervisor/cicap_adblock/restart", {}),
    ]
    for method, path, payload in endpoints:
        response = client.open(
            path, method=method, json=payload, base_url="http://localhost:5000"
        )
        assert response.status_code == 403, path
        assert response.is_json, path
        assert response.get_json()["ok"] is False
        assert "PROXY_MANAGEMENT_TOKEN" in response.get_json()["detail"]


def test_proxy_management_api_accepts_bearer_and_x_proxy_token(monkeypatch) -> None:
    proxy_app = _load_proxy_app(monkeypatch)
    monkeypatch.setenv("PROXY_MANAGEMENT_TOKEN", "secret")
    proxy_app.runtime = _Runtime()
    client = proxy_app.app.test_client()

    bearer = _management_get(
        client, "/api/manage/health", headers={"Authorization": "Bearer secret"}
    )
    x_token = _management_get(
        client, "/api/manage/health", headers={"X-Proxy-Token": "secret"}
    )
    bad = _management_get(
        client, "/api/manage/health", headers={"Authorization": "Bearer wrong"}
    )

    assert bearer.status_code == 200
    assert bearer.get_json()["proxy_id"] == "edge-a"
    assert x_token.status_code == 200
    assert bad.status_code == 403


def test_proxy_management_api_status_codes_and_payload_mapping(monkeypatch) -> None:
    proxy_app = _load_proxy_app(monkeypatch)
    monkeypatch.setenv("PROXY_MANAGEMENT_TOKEN", "secret")
    runtime = _Runtime()
    proxy_app.runtime = runtime
    client = proxy_app.app.test_client()
    headers = {"Authorization": "Bearer secret"}

    sync = _management_post(
        client,
        "/api/manage/sync",
        json={"force": True, "operation_id": 42},
        headers=headers,
    )
    validate = _management_post(
        client,
        "/api/manage/config/validate",
        json={"config_text": "bad\n"},
        headers=headers,
    )
    rollback = _management_post(
        client,
        "/api/manage/config/rollback",
        json={"reason": "bad apply"},
        headers=headers,
    )
    cache = _management_post(
        client, "/api/manage/cache/clear", json={}, headers=headers
    )
    eicar = _management_post(
        client, "/api/manage/clamav/test-eicar", json={}, headers=headers
    )
    icap = _management_post(
        client, "/api/manage/clamav/test-icap", json={}, headers=headers
    )

    assert sync.status_code == 409
    assert sync.get_json()["detail"] == "sync failed"
    assert runtime.sync_force is True
    assert runtime.sync_operation_id == 42
    assert validate.status_code == 200
    assert validate.get_json()["detail"] == "parse failed"
    assert runtime.validation_text == "bad\n"
    assert rollback.status_code == 409
    assert runtime.rollback_reason == "bad apply"
    assert cache.status_code == 500
    assert eicar.status_code == 503
    assert icap.status_code == 503


def test_proxy_management_sync_rejects_invalid_operation_id(monkeypatch) -> None:
    proxy_app = _load_proxy_app(monkeypatch)
    monkeypatch.setenv("PROXY_MANAGEMENT_TOKEN", "secret")
    runtime = _Runtime()
    proxy_app.runtime = runtime
    client = proxy_app.app.test_client()
    headers = {"Authorization": "Bearer secret"}

    response = _management_post(
        client, "/api/manage/sync", json={"operation_id": "not-an-int"}, headers=headers
    )

    assert response.status_code == 400
    assert response.get_json()["ok"] is False
    assert "operation_id" in response.get_json()["detail"]
    assert runtime.sync_operation_id is None


def test_proxy_management_logs_endpoint_reads_allowlisted_log_tail(
    monkeypatch,
    tmp_path,
) -> None:
    proxy_app = _load_proxy_app(monkeypatch)
    monkeypatch.setenv("PROXY_MANAGEMENT_TOKEN", "secret")
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    (log_dir / "access.log").write_text("alpha\nbeta\n", encoding="utf-8")
    monkeypatch.setenv("LOG_DIR", str(log_dir))
    proxy_app.runtime = _Runtime()
    client = proxy_app.app.test_client()
    headers = {"Authorization": "Bearer secret"}

    allowed = _management_get(client, "/api/manage/logs?log=access", headers=headers)
    rejected = _management_get(
        client,
        "/api/manage/logs?log=../../etc/passwd",
        headers=headers,
    )

    assert allowed.status_code == 200
    assert allowed.get_json()["ok"] is True
    assert allowed.get_json()["content"] == "alpha\nbeta\n"
    assert rejected.status_code == 404
    assert rejected.get_json()["status"] == "not_found"


def test_proxy_management_logs_endpoint_reports_unreadable_log_as_server_error(
    monkeypatch,
) -> None:
    proxy_app = _load_proxy_app(monkeypatch)
    monkeypatch.setenv("PROXY_MANAGEMENT_TOKEN", "secret")
    proxy_app.runtime = _Runtime()
    monkeypatch.setattr(
        proxy_app,
        "read_proxy_log",
        lambda _key: {
            "ok": False,
            "status": "unavailable",
            "detail": "Squid access log could not be read: permission denied",
            "key": "access",
            "content": "",
            "logs": [],
        },
    )
    client = proxy_app.app.test_client()

    response = _management_get(
        client,
        "/api/manage/logs?log=access",
        headers={"Authorization": "Bearer secret"},
    )

    assert response.status_code == 500
    assert response.get_json()["status"] == "unavailable"


def test_proxy_management_health_degrades_without_leaking_traceback(
    monkeypatch,
) -> None:
    proxy_app = _load_proxy_app(monkeypatch)
    monkeypatch.setenv("PROXY_MANAGEMENT_TOKEN", "secret")
    proxy_app.runtime = _BrokenHealthRuntime()
    client = proxy_app.app.test_client()

    response = _management_get(
        client, "/api/manage/health", headers={"Authorization": "Bearer secret"}
    )
    payload = response.get_json()

    assert response.status_code == 200
    assert payload["ok"] is False
    assert payload["status"] == "degraded"
    assert payload["proxy_id"] == "edge-a"
    assert "traceback" not in str(payload).lower()


def test_proxy_management_test_supervisor_route_requires_test_mode_and_uses_allowlist(
    monkeypatch,
) -> None:
    proxy_app = _load_proxy_app(monkeypatch)
    monkeypatch.setenv("PROXY_MANAGEMENT_TOKEN", "secret")
    monkeypatch.delenv("ENABLE_TEST_MODE", raising=False)
    proxy_app.runtime = _Runtime()
    client = proxy_app.app.test_client()
    headers = {"Authorization": "Bearer secret"}

    disabled = _management_post(
        client, "/api/manage/test/supervisor/cicap_adblock/restart", headers=headers
    )
    assert disabled.status_code == 404

    monkeypatch.setenv("ENABLE_TEST_MODE", "1")
    allowed = _management_post(
        client, "/api/manage/test/supervisor/cicap_adblock/restart", headers=headers
    )
    rejected = _management_post(
        client, "/api/manage/test/supervisor/proxy_api/stop", headers=headers
    )

    assert allowed.status_code == 200
    assert allowed.get_json()["ok"] is True
    assert allowed.get_json()["action"] == "restart"
    assert rejected.status_code == 409
    assert rejected.get_json()["ok"] is False


def test_proxy_public_listener_serves_health_pac_wpad_and_root(monkeypatch) -> None:
    proxy_app = _load_proxy_app(monkeypatch)
    proxy_app.runtime = _Runtime()
    client = proxy_app.app.test_client()

    health = _public_get(client, "/health")
    pac = _public_get(client, "/proxy.pac")
    wpad = _public_get(client, "/wpad.dat")
    root = _public_get(client, "/")

    assert health.status_code == 200
    assert health.get_json()["service"] == "proxy"
    assert pac.status_code == 200
    assert pac.headers["Content-Type"] == "application/x-ns-proxy-autoconfig"
    assert pac.headers["Content-Disposition"] == 'inline; filename="proxy.pac"'
    assert "FindProxyForURL" in pac.get_data(as_text=True)
    assert wpad.status_code == 200
    assert wpad.headers["Content-Disposition"] == 'inline; filename="wpad.dat"'
    assert root.status_code == 200
    assert root.headers["Content-Disposition"] == 'inline; filename="wpad.dat"'
    assert root.get_data(as_text=True) == wpad.get_data(as_text=True)


def test_proxy_public_listener_rejects_management_and_management_listener_rejects_pac(
    monkeypatch,
) -> None:
    proxy_app = _load_proxy_app(monkeypatch)
    monkeypatch.setenv("PROXY_MANAGEMENT_TOKEN", "secret")
    proxy_app.runtime = _Runtime()
    client = proxy_app.app.test_client()

    health = _public_get(
        client, "/api/manage/health", headers={"Authorization": "Bearer secret"}
    )
    sync = _public_get(
        client, "/api/manage/sync", headers={"Authorization": "Bearer secret"}
    )
    assert health.status_code == 404
    assert health.is_json
    assert "management listener" in health.get_json()["detail"]
    assert sync.status_code == 404
    assert sync.is_json
    assert _management_get(client, "/proxy.pac").status_code == 404
    assert _management_get(client, "/wpad.dat").status_code == 404


def test_management_listener_ignores_spoofed_public_host_port(monkeypatch) -> None:
    proxy_app = _load_proxy_app(monkeypatch)
    monkeypatch.setenv("PROXY_MANAGEMENT_TOKEN", "secret")
    proxy_app.runtime = _Runtime()
    client = proxy_app.app.test_client()

    pac = client.get("/proxy.pac", base_url="http://localhost:5000")
    spoofed_pac = client.get(
        "/proxy.pac",
        base_url="http://localhost:5000",
        headers={"Host": "localhost:80"},
    )
    spoofed_management = client.get(
        "/api/manage/health",
        base_url="http://localhost:5000",
        headers={"Authorization": "Bearer secret", "Host": "localhost:80"},
    )

    assert pac.status_code == 404
    assert spoofed_pac.status_code == 404
    assert spoofed_management.status_code == 200


def test_proxy_management_health_defaults_to_navigation_scope_and_full_is_opt_in(
    monkeypatch,
) -> None:
    proxy_app = _load_proxy_app(monkeypatch)
    monkeypatch.setenv("PROXY_MANAGEMENT_TOKEN", "secret")
    proxy_app.runtime = _Runtime()
    client = proxy_app.app.test_client()
    headers = {"Authorization": "Bearer secret"}

    navigation = _management_get(client, "/api/manage/health", headers=headers)
    full = _management_get(client, "/api/manage/health?full=1", headers=headers)

    assert navigation.status_code == 200
    assert navigation.get_json()["health_scope"] == "navigation"
    assert full.status_code == 200
    assert full.get_json()["health_scope"] == "full"
