from __future__ import annotations

import io
import json
import sys
import urllib.error
from pathlib import Path
from types import SimpleNamespace

import pytest


def _add_web_to_path() -> None:
    web_dir = Path(__file__).resolve().parents[1]
    if str(web_dir) not in sys.path:
        sys.path.insert(0, str(web_dir))


class _Registry:
    def __init__(self, management_url: str | None):
        self.management_url = management_url

    def get_proxy(self, proxy_id):
        return SimpleNamespace(management_url=self.management_url) if self.management_url is not None else None


class _Response:
    status = 200

    def __init__(self, payload: dict[str, object]):
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def read(self) -> bytes:
        return json.dumps(self._payload).encode("utf-8")


def test_proxy_client_requires_registered_management_url(monkeypatch) -> None:
    _add_web_to_path()
    import services.proxy_client as proxy_client  # type: ignore

    monkeypatch.setattr(proxy_client, "get_proxy_registry", lambda: _Registry(None))

    with pytest.raises(proxy_client.ProxyClientError, match="not registered"):
        proxy_client.ProxyClient().get_health("missing")


def test_proxy_client_sets_bearer_auth_and_json_body(monkeypatch) -> None:
    _add_web_to_path()
    import services.proxy_client as proxy_client  # type: ignore

    captured: dict[str, object] = {}
    monkeypatch.setenv("PROXY_MANAGEMENT_TOKEN", "secret-token")
    monkeypatch.setattr(proxy_client, "get_proxy_registry", lambda: _Registry("http://proxy-mgmt:5000/root/"))

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        captured["method"] = request.get_method()
        captured["auth"] = request.get_header("Authorization")
        captured["content_type"] = request.get_header("Content-type")
        captured["body"] = request.data
        captured["timeout"] = timeout
        return _Response({"ok": True, "changed": False})

    monkeypatch.setattr(proxy_client.urllib.request, "urlopen", fake_urlopen)

    payload = proxy_client.ProxyClient(timeout_seconds=1.25).sync_proxy("live", force=True, timeout_seconds=9.5)

    assert payload == {"ok": True, "changed": False}
    assert captured["url"] == "http://proxy-mgmt:5000/root/api/manage/sync"
    assert captured["method"] == "POST"
    assert captured["auth"] == "Bearer secret-token"
    assert captured["content_type"] == "application/json"
    assert json.loads(captured["body"].decode("utf-8")) == {"force": True}
    assert captured["timeout"] == 9.5


def test_proxy_client_can_request_config_validation_and_rollback(monkeypatch) -> None:
    _add_web_to_path()
    import services.proxy_client as proxy_client  # type: ignore

    captured: list[dict[str, object]] = []
    monkeypatch.setattr(proxy_client, "get_proxy_registry", lambda: _Registry("http://proxy-mgmt:5000"))

    def fake_urlopen(request, timeout):
        captured.append(
            {
                "url": request.full_url,
                "method": request.get_method(),
                "body": json.loads((request.data or b"{}").decode("utf-8")),
                "timeout": timeout,
            }
        )
        return _Response({"ok": True, "detail": "accepted"})

    monkeypatch.setattr(proxy_client.urllib.request, "urlopen", fake_urlopen)

    client = proxy_client.ProxyClient()
    assert client.validate_config("live", "workers 1\n", timeout_seconds=7.0)["ok"] is True
    assert client.rollback_config("live", reason="bad apply", timeout_seconds=8.0)["ok"] is True

    assert captured[0] == {
        "url": "http://proxy-mgmt:5000/api/manage/config/validate",
        "method": "POST",
        "body": {"config_text": "workers 1\n"},
        "timeout": 7.0,
    }
    assert captured[1] == {
        "url": "http://proxy-mgmt:5000/api/manage/config/rollback",
        "method": "POST",
        "body": {"reason": "bad apply"},
        "timeout": 8.0,
    }


def test_proxy_client_http_error_uses_json_detail(monkeypatch) -> None:
    _add_web_to_path()
    import services.proxy_client as proxy_client  # type: ignore

    monkeypatch.setattr(proxy_client, "get_proxy_registry", lambda: _Registry("http://proxy-mgmt:5000"))


    def fake_urlopen(_request, timeout):
        raise urllib.error.HTTPError(
            "http://proxy-mgmt:5000/api/manage/sync",
            409,
            "Conflict",
            {},
            io.BytesIO(b'{"ok": false, "detail": "sync failed clearly"}'),
        )

    monkeypatch.setattr(proxy_client.urllib.request, "urlopen", fake_urlopen)

    with pytest.raises(proxy_client.ProxyClientError, match="sync failed clearly"):
        proxy_client.ProxyClient().sync_proxy("live")


def test_proxy_client_url_error_surfaces_reason(monkeypatch) -> None:
    _add_web_to_path()
    import services.proxy_client as proxy_client  # type: ignore

    monkeypatch.setattr(proxy_client, "get_proxy_registry", lambda: _Registry("http://proxy-mgmt:5000"))
    monkeypatch.setattr(
        proxy_client.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(urllib.error.URLError("network unreachable")),
    )

    with pytest.raises(proxy_client.ProxyClientError, match="network unreachable"):
        proxy_client.ProxyClient().clear_proxy_cache("live")
