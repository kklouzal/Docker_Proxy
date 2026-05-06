from __future__ import annotations

import importlib
import sys
from pathlib import Path


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


class _Runtime:
    proxy_id = "edge-a"

    def __init__(self):
        self.sync_force = None
        self.validation_text = None
        self.rollback_reason = None

    def collect_health(self):
        return {"ok": True, "status": "healthy", "proxy_id": self.proxy_id, "services": {}, "stats": {}}

    def sync_from_db(self, *, force=False):
        self.sync_force = force
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
            return {"ok": False, "proxy_id": self.proxy_id, "program": program_name, "action": action, "detail": "not allowlisted"}
        return {"ok": True, "proxy_id": self.proxy_id, "program": program_name, "action": action, "detail": "done"}


class _BrokenHealthRuntime(_Runtime):
    def collect_health(self):
        raise RuntimeError("boom")


def test_proxy_management_api_requires_token_for_all_management_endpoints(monkeypatch) -> None:
    proxy_app = _load_proxy_app(monkeypatch)
    monkeypatch.setenv("PROXY_MANAGEMENT_TOKEN", "secret")
    proxy_app.runtime = _Runtime()
    client = proxy_app.app.test_client()

    assert client.get("/health").status_code == 200

    endpoints = [
        ("GET", "/api/manage/health", None),
        ("POST", "/api/manage/sync", {}),
        ("POST", "/api/manage/config/validate", {"config_text": "workers 1\n"}),
        ("POST", "/api/manage/config/rollback", {"reason": "test"}),
        ("POST", "/api/manage/cache/clear", {}),
        ("POST", "/api/manage/clamav/test-eicar", {}),
        ("POST", "/api/manage/clamav/test-icap", {}),
        ("POST", "/api/manage/test/supervisor/cicap_adblock/restart", {}),
    ]
    for method, path, payload in endpoints:
        response = client.open(path, method=method, json=payload)
        assert response.status_code == 403, path


def test_proxy_management_api_accepts_bearer_and_x_proxy_token(monkeypatch) -> None:
    proxy_app = _load_proxy_app(monkeypatch)
    monkeypatch.setenv("PROXY_MANAGEMENT_TOKEN", "secret")
    proxy_app.runtime = _Runtime()
    client = proxy_app.app.test_client()

    bearer = client.get("/api/manage/health", headers={"Authorization": "Bearer secret"})
    x_token = client.get("/api/manage/health", headers={"X-Proxy-Token": "secret"})
    bad = client.get("/api/manage/health", headers={"Authorization": "Bearer wrong"})

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

    sync = client.post("/api/manage/sync", json={"force": True}, headers=headers)
    validate = client.post("/api/manage/config/validate", json={"config_text": "bad\n"}, headers=headers)
    rollback = client.post("/api/manage/config/rollback", json={"reason": "bad apply"}, headers=headers)
    cache = client.post("/api/manage/cache/clear", json={}, headers=headers)
    eicar = client.post("/api/manage/clamav/test-eicar", json={}, headers=headers)
    icap = client.post("/api/manage/clamav/test-icap", json={}, headers=headers)

    assert sync.status_code == 409
    assert sync.get_json()["detail"] == "sync failed"
    assert runtime.sync_force is True
    assert validate.status_code == 200
    assert validate.get_json()["detail"] == "parse failed"
    assert runtime.validation_text == "bad\n"
    assert rollback.status_code == 409
    assert runtime.rollback_reason == "bad apply"
    assert cache.status_code == 500
    assert eicar.status_code == 503
    assert icap.status_code == 503


def test_proxy_management_health_degrades_without_leaking_traceback(monkeypatch) -> None:
    proxy_app = _load_proxy_app(monkeypatch)
    monkeypatch.setenv("PROXY_MANAGEMENT_TOKEN", "secret")
    proxy_app.runtime = _BrokenHealthRuntime()
    client = proxy_app.app.test_client()

    response = client.get("/api/manage/health", headers={"Authorization": "Bearer secret"})
    payload = response.get_json()

    assert response.status_code == 200
    assert payload["ok"] is False
    assert payload["status"] == "degraded"
    assert payload["proxy_id"] == "edge-a"
    assert "traceback" not in str(payload).lower()


def test_proxy_management_test_supervisor_route_requires_test_mode_and_uses_allowlist(monkeypatch) -> None:
    proxy_app = _load_proxy_app(monkeypatch)
    monkeypatch.setenv("PROXY_MANAGEMENT_TOKEN", "secret")
    monkeypatch.delenv("ENABLE_TEST_MODE", raising=False)
    proxy_app.runtime = _Runtime()
    client = proxy_app.app.test_client()
    headers = {"Authorization": "Bearer secret"}

    disabled = client.post("/api/manage/test/supervisor/cicap_adblock/restart", headers=headers)
    assert disabled.status_code == 404

    monkeypatch.setenv("ENABLE_TEST_MODE", "1")
    allowed = client.post("/api/manage/test/supervisor/cicap_adblock/restart", headers=headers)
    rejected = client.post("/api/manage/test/supervisor/proxy_api/stop", headers=headers)

    assert allowed.status_code == 200
    assert allowed.get_json()["ok"] is True
    assert allowed.get_json()["action"] == "restart"
    assert rejected.status_code == 409
    assert rejected.get_json()["ok"] is False
