from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace


def _add_web_to_path() -> None:
    web_dir = Path(__file__).resolve().parents[1]
    if str(web_dir) not in sys.path:
        sys.path.insert(0, str(web_dir))


class _Registry:
    def __init__(self, proxy_ids: list[str]):
        self._proxies = [SimpleNamespace(proxy_id=proxy_id) for proxy_id in proxy_ids]

    def list_proxies(self):
        return list(self._proxies)


def test_nudge_registered_proxies_returns_zero_when_registry_empty(monkeypatch) -> None:
    _add_web_to_path()
    import services.proxy_sync as proxy_sync  # type: ignore

    monkeypatch.setattr(proxy_sync, "get_proxy_registry", lambda: _Registry([]))

    assert proxy_sync.nudge_registered_proxies(force=True) == (0, 0)


def test_nudge_registered_proxies_counts_total_when_client_unavailable(monkeypatch) -> None:
    _add_web_to_path()
    import services.proxy_sync as proxy_sync  # type: ignore

    monkeypatch.setattr(proxy_sync, "get_proxy_registry", lambda: _Registry(["live", "edge-2"]))
    monkeypatch.setattr(proxy_sync, "get_proxy_client", lambda: (_ for _ in ()).throw(RuntimeError("client missing")))

    assert proxy_sync.nudge_registered_proxies(force=False) == (2, 0)


def test_nudge_registered_proxies_counts_only_successful_proxy_syncs(monkeypatch) -> None:
    _add_web_to_path()
    import services.proxy_sync as proxy_sync  # type: ignore

    calls: list[tuple[str, bool]] = []

    class Client:
        def sync_proxy(self, proxy_id: str, *, force: bool = False):
            calls.append((proxy_id, force))
            if proxy_id == "edge-error":
                raise proxy_sync.ProxyClientError("boom")
            return {"ok": proxy_id == "live"}

    monkeypatch.setattr(proxy_sync, "get_proxy_registry", lambda: _Registry(["live", "edge-false", "edge-error"]))
    monkeypatch.setattr(proxy_sync, "get_proxy_client", lambda: Client())

    assert proxy_sync.nudge_registered_proxies(force=True) == (3, 1)
    assert calls == [("live", True), ("edge-false", True), ("edge-error", True)]
