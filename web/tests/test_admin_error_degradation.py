from __future__ import annotations

from .admin_route_test_utils import FakeProxyClient, csrf_token, load_admin_app, login_client


class RaisingObservabilityQueries:
    def summary(self, **_kwargs):
        raise RuntimeError("summary database password=secret")

    def overview_bundle(self, **_kwargs):
        raise RuntimeError("overview failed")

    def top_destinations(self, **_kwargs):
        raise RuntimeError("destinations failed")

    def ssl_overview(self, **_kwargs):
        raise RuntimeError("ssl failed")


class RaisingWebfilterStore:
    def init_db(self) -> None:
        raise RuntimeError("init failed")

    def test_domain(self, _domain: str):
        raise RuntimeError("internal db password=secret")


class InitFailingAdblockStore:
    def init_db(self) -> None:
        raise RuntimeError("init failed")

    def list_statuses(self):
        return []

    def get_settings(self):
        return {"enabled": True, "cache_ttl": 3600, "cache_max": 200000}

    def stats(self):
        return {"total": 0, "last_24h": 0, "by_list": {}, "by_list_24h": {}}

    def cache_stats(self):
        return {"hits": 0, "misses": 0, "evictions": 0, "current_size": 0, "last_flush": 0, "last_flush_req": 0}

    def get_update_interval_seconds(self):
        return 3600


def test_observability_route_and_export_degrade_to_empty_payloads(monkeypatch, tmp_path) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path, observability_queries=RaisingObservabilityQueries())
    client = loaded.module.app.test_client()
    login_client(client)

    page = client.get("/observability?pane=destinations&q=db-password")
    assert page.status_code == 200
    assert "db password" not in page.get_data(as_text=True).lower()

    export = client.get("/observability/export?pane=ssl&limit=10")
    assert export.status_code == 200
    assert export.headers.get("Content-Type", "").startswith("text/csv")
    assert export.get_data(as_text=True).splitlines()[0].startswith("domain;")


def test_webfilter_test_returns_sanitized_error_json(monkeypatch, tmp_path) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path, webfilter_store=RaisingWebfilterStore())
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/")

    response = client.post("/webfilter/test", json={"domain": "example.com"}, headers={"X-CSRF-Token": token})

    assert response.status_code == 200
    assert response.json["ok"] is False
    assert response.json["verdict"] == "error"
    assert "secret" not in response.json["reason"]


def test_clamav_page_and_test_routes_degrade_when_proxy_unavailable(monkeypatch, tmp_path) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    failing_client = FakeProxyClient(loaded.module, fail=True)
    loaded = load_admin_app(monkeypatch, tmp_path, proxy_client=failing_client)
    client = loaded.module.app.test_client()
    login_client(client)

    page = client.get("/clamav")
    assert page.status_code == 200
    assert "proxy unavailable" in page.get_data(as_text=True)

    token = csrf_token(client, "/clamav")
    eicar = client.post("/clamav/test-eicar", data={"csrf_token": token}, follow_redirects=False)
    assert eicar.status_code in {301, 302, 303}
    assert "eicar=fail" in eicar.headers["Location"]

    token = csrf_token(client, "/clamav")
    icap = client.post("/clamav/test-icap", data={"csrf_token": token}, follow_redirects=False)
    assert icap.status_code in {301, 302, 303}
    assert "icap_sample=fail" in icap.headers["Location"]


def test_reload_and_cache_clear_record_failure_without_crashing(monkeypatch, tmp_path) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    failing_client = FakeProxyClient(loaded.module, fail=True)
    loaded = load_admin_app(monkeypatch, tmp_path, proxy_client=failing_client)
    client = loaded.module.app.test_client()
    login_client(client)

    token = csrf_token(client, "/")
    reload_response = client.post("/reload", data={"csrf_token": token}, follow_redirects=False)
    assert reload_response.status_code in {301, 302, 303}

    token = csrf_token(client, "/")
    cache_response = client.post("/cache/clear", data={"csrf_token": token}, follow_redirects=False)
    assert cache_response.status_code in {301, 302, 303}

    failure_records = [record for record in loaded.audit_store.records if record["kind"] in {"proxy_sync", "cache_clear"}]
    assert [record["kind"] for record in failure_records] == ["proxy_sync", "cache_clear"]
    assert all(record["ok"] is False for record in failure_records)


def test_adblock_page_renders_when_init_db_fails(monkeypatch, tmp_path) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path, adblock_store=InitFailingAdblockStore())
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/adblock")

    assert response.status_code == 200
    assert "Ad Blocking" in response.get_data(as_text=True)
