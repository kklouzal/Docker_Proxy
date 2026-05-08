from __future__ import annotations

import gzip
import importlib
import sys
from pathlib import Path

from .admin_route_test_utils import load_admin_app, login_client


class ExplodingRegistry:
    def __getattr__(self, name: str):
        raise AssertionError(f"proxy registry should not be used for this request: {name}")


class CountingRegistry:
    def __init__(self) -> None:
        from .admin_route_test_utils import FakeRegistry

        self._inner = FakeRegistry(["default", "edge-2"])
        self.list_calls = 0
        self.get_calls = 0
        self.resolve_calls = 0

    def list_proxies(self):
        self.list_calls += 1
        return self._inner.list_proxies()

    def ensure_default_proxy(self):
        return self._inner.ensure_default_proxy()

    def get_proxy(self, proxy_id):
        self.get_calls += 1
        return self._inner.get_proxy(proxy_id)

    def resolve_proxy_id(self, preferred=None):
        self.resolve_calls += 1
        return self._inner.resolve_proxy_id(preferred)

    def mark_apply_result(self, *args, **kwargs):
        return self._inner.mark_apply_result(*args, **kwargs)


def _add_repo_paths() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    web_root = repo_root / "web"
    for path in (repo_root, web_root):
        path_text = str(path)
        if path_text not in sys.path:
            sys.path.insert(0, path_text)


def test_login_and_static_requests_do_not_bind_proxy_context(monkeypatch, tmp_path) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path, registry=ExplodingRegistry())
    client = loaded.module.app.test_client()

    login = client.get("/login")
    static = client.get("/static/style.css")

    assert login.status_code == 200
    assert static.status_code == 200
    assert "public" in static.headers.get("Cache-Control", "")
    assert "immutable" in static.headers.get("Cache-Control", "")


def test_rendered_page_reuses_request_proxy_context(monkeypatch, tmp_path) -> None:
    registry = CountingRegistry()
    loaded = load_admin_app(monkeypatch, tmp_path, registry=registry)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/administration")

    assert response.status_code == 200
    assert registry.list_calls == 1
    assert registry.get_calls == 0
    assert registry.resolve_calls == 0


def test_admin_html_responses_are_gzip_compressed_when_requested(monkeypatch, tmp_path) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/squid/config", headers={"Accept-Encoding": "gzip"})

    assert response.status_code == 200
    assert response.headers.get("Content-Encoding") == "gzip"
    assert "Accept-Encoding" in response.headers.get("Vary", "")
    assert b"Squid" in gzip.decompress(response.get_data())


def test_spa_document_fetches_are_not_browser_cached(monkeypatch, tmp_path) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/administration", headers={"X-Requested-With": "spa"})

    assert response.status_code == 200
    assert response.headers.get("Cache-Control") == "no-store, private"


def test_normal_admin_gets_revalidate_instead_of_immutable_cache(monkeypatch, tmp_path) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/administration")

    assert response.status_code == 200
    assert response.headers.get("Cache-Control") == "no-cache"


def test_proxy_pac_responses_have_cache_headers_and_conditional_etag(monkeypatch) -> None:
    _add_repo_paths()
    monkeypatch.setenv("DISABLE_PROXY_AGENT", "1")
    monkeypatch.setenv("PAC_HTTP_PORT", "80")
    sys.modules.pop("proxy.app", None)
    import proxy.app as proxy_app  # type: ignore

    proxy_app = importlib.reload(proxy_app)
    client = proxy_app.app.test_client()

    first = client.get("/proxy.pac", base_url="http://proxy")
    etag = first.headers.get("ETag")
    second = client.get("/proxy.pac", base_url="http://proxy", headers={"If-None-Match": etag or ""})

    assert first.status_code == 200
    assert first.headers.get("Cache-Control") == "public, max-age=30"
    assert etag
    assert second.status_code == 304
