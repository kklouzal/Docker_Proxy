from __future__ import annotations

from types import SimpleNamespace
from typing import NoReturn

from .admin_route_test_utils import (
    FakeAdblockArtifacts,
    FakeAdblockStore,
    FakeProxyClient,
    csrf_token,
    load_admin_app,
    login_client,
)


class RaisingObservabilityQueries:
    def summary(self, **_kwargs) -> NoReturn:
        msg = "summary database password=secret"
        raise RuntimeError(msg)

    def overview_bundle(self, **_kwargs) -> NoReturn:
        msg = "overview failed"
        raise RuntimeError(msg)

    def top_destinations(self, **_kwargs) -> NoReturn:
        msg = "destinations failed"
        raise RuntimeError(msg)

    def ssl_overview(self, **_kwargs) -> NoReturn:
        msg = "ssl failed"
        raise RuntimeError(msg)


class RaisingWebfilterStore:
    def init_db(self) -> None:
        msg = "init failed"
        raise RuntimeError(msg)

    def test_domain(self, _domain: str) -> NoReturn:
        msg = "internal db password=secret"
        raise RuntimeError(msg)


class InitFailingAdblockStore:
    def init_db(self) -> None:
        msg = "init failed"
        raise RuntimeError(msg)

    def list_statuses(self):
        return []

    def get_settings(self):
        return {"enabled": True, "cache_ttl": 3600, "cache_max": 200000}

    def stats(self):
        return {"total": 0, "last_24h": 0, "by_list": {}, "by_list_24h": {}}

    def cache_stats(self):
        return {
            "hits": 0,
            "misses": 0,
            "evictions": 0,
            "current_size": 0,
            "last_flush": 0,
            "last_flush_req": 0,
        }

    def get_update_interval_seconds(self) -> int:
        return 3600


class DestinationExportQueries:
    def summary(self, **_kwargs):
        return {"request_records": 4}

    def top_destinations(self, **kwargs):
        return [
            {
                "domain": "example.com",
                "requests": 2,
                "pct": 50.0,
                "clients": 1,
                "transactions": 2,
                "cache_pct": 0.0,
                "av_icap_events": 0,
                "adblock_icap_events": 0,
                "last_seen": 123,
                "total_requests": kwargs.get("total_requests"),
            },
        ]


def test_observability_route_and_export_degrade_to_empty_payloads(
    monkeypatch, tmp_path
) -> None:
    loaded = load_admin_app(
        monkeypatch, tmp_path, observability_queries=RaisingObservabilityQueries()
    )
    client = loaded.module.app.test_client()
    login_client(client)

    page = client.get("/observability?pane=destinations&q=db-password")
    assert page.status_code == 200
    assert "db password" not in page.get_data(as_text=True).lower()

    remediation = client.get("/observability?pane=remediation&q=db-password")
    assert remediation.status_code == 200
    remediation_body = remediation.get_data(as_text=True).lower()
    assert "observability database query failed" in remediation_body
    assert "db password" not in remediation_body

    export = client.get("/observability/export?pane=ssl&limit=10")
    assert export.status_code == 200
    assert export.headers.get("Content-Type", "").startswith("text/csv")
    assert export.get_data(as_text=True).splitlines()[0].startswith("domain;")


def test_observability_destination_export_initializes_total_requests(
    monkeypatch, tmp_path
) -> None:
    loaded = load_admin_app(
        monkeypatch, tmp_path, observability_queries=DestinationExportQueries()
    )
    client = loaded.module.app.test_client()
    login_client(client)

    export = client.get("/observability/export?pane=destinations&limit=10")

    assert export.status_code == 200
    body = export.get_data(as_text=True)
    assert "example.com" in body
    assert body.splitlines()[0].startswith("domain;")


def test_webfilter_test_returns_sanitized_error_json(monkeypatch, tmp_path) -> None:
    loaded = load_admin_app(
        monkeypatch, tmp_path, webfilter_store=RaisingWebfilterStore()
    )
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/")

    response = client.post(
        "/webfilter/test",
        json={"domain": "example.com"},
        headers={"X-CSRF-Token": token},
    )

    assert response.status_code == 200
    assert response.json["ok"] is False
    assert response.json["verdict"] == "error"
    assert "secret" not in response.json["reason"]


def test_clamav_page_and_test_routes_degrade_when_proxy_unavailable(
    monkeypatch, tmp_path
) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    failing_client = FakeProxyClient(loaded.module, fail=True)
    loaded = load_admin_app(monkeypatch, tmp_path, proxy_client=failing_client)
    client = loaded.module.app.test_client()
    login_client(client)

    page = client.get("/clamav")
    assert page.status_code == 200
    assert "proxy unavailable" in page.get_data(as_text=True)

    token = csrf_token(client, "/clamav")
    eicar = client.post(
        "/clamav/test-eicar", data={"csrf_token": token}, follow_redirects=False
    )
    assert eicar.status_code in {301, 302, 303}
    assert "eicar=fail" in eicar.headers["Location"]

    token = csrf_token(client, "/clamav")
    icap = client.post(
        "/clamav/test-icap", data={"csrf_token": token}, follow_redirects=False
    )
    assert icap.status_code in {301, 302, 303}
    assert "icap_sample=fail" in icap.headers["Location"]


def test_clamav_page_caches_unavailable_proxy_health(monkeypatch, tmp_path) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)

    class CountingFailingProxyClient(FakeProxyClient):
        def __init__(self, admin_app) -> None:
            super().__init__(admin_app, fail=True)
            self.health_calls = 0

        def get_health(self, proxy_id, *args, **kwargs):
            self.health_calls += 1
            return super().get_health(proxy_id, *args, **kwargs)

    failing_client = CountingFailingProxyClient(loaded.module)
    loaded = load_admin_app(monkeypatch, tmp_path, proxy_client=failing_client)
    client = loaded.module.app.test_client()
    login_client(client)

    first = client.get("/clamav")
    second = client.get("/clamav")

    assert first.status_code == 200
    assert second.status_code == 200
    assert failing_client.health_calls == 1
    assert "proxy unavailable" in second.get_data(as_text=True)


def test_reload_and_cache_clear_record_failure_without_crashing(
    monkeypatch, tmp_path
) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    failing_client = FakeProxyClient(loaded.module, fail=True)
    loaded = load_admin_app(monkeypatch, tmp_path, proxy_client=failing_client)
    client = loaded.module.app.test_client()
    login_client(client)

    token = csrf_token(client, "/")
    reload_response = client.post(
        "/reload", data={"csrf_token": token}, follow_redirects=False
    )
    assert reload_response.status_code in {301, 302, 303}

    token = csrf_token(client, "/")
    cache_response = client.post(
        "/cache/clear", data={"csrf_token": token}, follow_redirects=False
    )
    assert cache_response.status_code in {301, 302, 303}

    failure_records = [
        record
        for record in loaded.audit_store.records
        if record["kind"] in {"proxy_sync", "cache_clear"}
    ]
    assert [record["kind"] for record in failure_records] == [
        "proxy_sync",
        "cache_clear",
    ]
    assert failure_records[0]["ok"] is True
    assert "Proxy reconciliation queued" in failure_records[0]["detail"]
    assert failure_records[1]["ok"] is True
    assert "Proxy cache clear queued" in failure_records[1]["detail"]
    assert loaded.proxy_client.cleared == []
    assert loaded.operation_ledger.operations[-1].operation_type == "cache_clear"


def test_adblock_page_renders_when_init_db_fails(monkeypatch, tmp_path) -> None:
    loaded = load_admin_app(
        monkeypatch, tmp_path, adblock_store=InitFailingAdblockStore()
    )
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/adblock")

    assert response.status_code == 200
    assert "Ad Blocking" in response.get_data(as_text=True)


def test_adblock_page_shows_active_compiled_artifact_summary(
    monkeypatch, tmp_path
) -> None:
    summary = SimpleNamespace(
        revision_id=7,
        artifact_sha256="abcdef1234567890",
        settings_version=12,
        source_kind="test",
        created_by="builder",
        created_ts=1_700_000_000,
        enabled_lists=["easylist", "easyprivacy"],
        report={
            "counts": {
                "network_rules_total": 44,
                "network_rules_with_options": 5,
                "cosmetic_rules_total": 6,
            },
            "breakdowns": {
                "lookup_index_counts": {
                    "domain_index": 11,
                    "host_index": 2,
                    "regex_index": 3,
                },
            },
        },
    )
    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        adblock_artifacts=FakeAdblockArtifacts(summary),
    )
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/adblock")
    text = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "Compiled artifact" in text
    assert "rev 7" in text
    assert "abcdef123456" in text
    assert "Domain index rows" in text
    assert "11" in text
    assert "Request index rules" in text
    assert "44" in text
    assert "easylist, easyprivacy" in text


def test_adblock_page_surfaces_stale_or_failed_artifact_build(
    monkeypatch, tmp_path
) -> None:
    store = FakeAdblockStore()
    store.refresh_requested = 1_700_000_100
    summary = SimpleNamespace(
        revision_id=7,
        artifact_sha256="abcdef1234567890",
        settings_version=0,
        source_kind="test",
        created_by="builder",
        created_ts=1_700_000_000,
        enabled_lists=[],
        report={
            "counts": {
                "network_rules_total": 0,
                "network_rules_with_options": 0,
                "cosmetic_rules_total": 0,
            },
            "breakdowns": {
                "lookup_index_counts": {
                    "domain_index": 0,
                    "host_index": 0,
                    "regex_index": 0,
                },
            },
        },
    )
    store.get_artifact_build_status = lambda: {
        "ok": False,
        "detail": "MySQL server has gone away",
        "revision_id": 7,
        "artifact_sha256": "abcdef1234567890",
        "archive_bytes": 68_211_868,
        "ts": 1_700_000_101,
    }
    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        adblock_store=store,
        adblock_artifacts=FakeAdblockArtifacts(summary),
    )
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/adblock")
    text = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "build failed" in text
    assert "Last build failed" in text
    assert "MySQL server has gone away" in text
    assert "Stale lists" in text
    assert "Archive size" in text
