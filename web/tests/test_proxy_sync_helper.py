from __future__ import annotations

import importlib
import sys
from pathlib import Path
from types import SimpleNamespace


def _import_proxy_sync_module():
    repo_root = Path(__file__).resolve().parents[2]
    web_root = repo_root / "web"
    for path in (repo_root, web_root):
        path_str = str(path)
        if path_str not in sys.path:
            sys.path.insert(0, path_str)

    import services.proxy_sync as module  # type: ignore

    importlib.reload(module)
    return module


def test_nudge_registered_proxies_counts_only_successful_syncs(monkeypatch):
    module = _import_proxy_sync_module()
    proxies = [
        SimpleNamespace(proxy_id="proxy-a"),
        SimpleNamespace(proxy_id="proxy-b"),
        SimpleNamespace(proxy_id="proxy-c"),
    ]

    class FakeClient:
        def sync_proxy(self, proxy_id: str, *, force: bool = False):
            assert force is True
            if proxy_id == "proxy-a":
                return {"ok": True}
            if proxy_id == "proxy-b":
                return {"ok": False}
            raise module.ProxyClientError("boom")

    monkeypatch.setattr(module, "get_proxy_registry", lambda: SimpleNamespace(list_proxies=lambda: proxies))
    monkeypatch.setattr(module, "get_proxy_client", lambda: FakeClient())

    assert module.nudge_registered_proxies(force=True) == (3, 1)


def test_nudge_registered_proxies_skips_client_lookup_when_registry_empty(monkeypatch):
    module = _import_proxy_sync_module()
    client_requested = {"value": False}

    def _get_proxy_client():
        client_requested["value"] = True
        return object()

    monkeypatch.setattr(module, "get_proxy_registry", lambda: SimpleNamespace(list_proxies=lambda: []))
    monkeypatch.setattr(module, "get_proxy_client", _get_proxy_client)

    assert module.nudge_registered_proxies(force=False) == (0, 0)
    assert client_requested["value"] is False