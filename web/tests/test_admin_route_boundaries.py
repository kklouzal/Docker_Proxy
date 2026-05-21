from __future__ import annotations

import pytest

from .admin_route_test_utils import (
    FakeRegistry,
    csrf_token,
    load_admin_app,
    login_client,
)


class RecordingProxyClient:
    def __init__(self) -> None:
        self.health_calls: list[tuple[str, float | None]] = []

    def get_health(
        self, proxy_id: object, *_, timeout_seconds: float | None = None, **__
    ) -> dict[str, object]:
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

    def sync_proxy(
        self,
        proxy_id: object,
        *,
        force: bool = False,
        timeout_seconds: float | None = None,
    ) -> dict[str, object]:
        return {"ok": True, "detail": "sync requested"}

    def clear_proxy_cache(self, proxy_id: object) -> dict[str, object]:
        return {"ok": True, "detail": "cache cleared"}

    def get_clamav_health(
        self, proxy_id: object, *_, timeout_seconds: float | None = None, **__
    ) -> dict[str, object]:
        self.health_calls.append((f"clamav:{proxy_id}", timeout_seconds))
        return {
            "ok": True,
            "status": "healthy",
            "proxy_id": str(proxy_id),
            "services": {
                "clamav": {"ok": True, "detail": "clamav lightweight"},
                "av_icap": {"ok": True, "detail": "ok"},
                "clamd": {"ok": True, "detail": "ok"},
            },
            "health_scope": "clamav",
        }


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
        "/error-pages",
        "/error-pages/preview/ERR_ACCESS_DENIED",
        "/clamav",
        "/squid/config",
        "/pac",
        "/tools/winhttp-registry",
        "/requests",
        "/api/timeseries",
        "/certs",
        "/certs/download/ca.crt",
        "/administration",
    ],
)
def test_protected_get_routes_redirect_to_login(
    monkeypatch, tmp_path, path: str
) -> None:
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
    loaded = load_admin_app(
        monkeypatch, tmp_path, proxy_client=proxy_client, registry=registry
    )
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


def test_network_config_apply_can_publish_intercept_listener(
    monkeypatch, tmp_path
) -> None:
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


def test_fleet_page_shows_explicit_and_intercept_listeners(
    monkeypatch, tmp_path
) -> None:
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


def test_winhttp_registry_builder_renders_and_generates_static_binary(
    monkeypatch, tmp_path
) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.post(
        "/tools/winhttp-registry",
        data={
            "csrf_token": csrf_token(client, "/tools/winhttp-registry"),
            "action": "generate",
            "proxy_host": "192.168.5.45",
            "proxy_port": "3128",
            "destination_schemes": ["http"],
            "bypass_list": "localhost\n<local>",
        },
    )
    text = response.get_data(as_text=True)

    assert response.status_code == 200
    assert (
        "28000000000000000300000016000000687474703d3139322e3136382e352e34353a33313238"
        in text
    )
    assert "netsh winhttp set advproxy" in text


def test_winhttp_registry_builder_normalizes_exported_reg_binary(
    monkeypatch, tmp_path
) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.post(
        "/tools/winhttp-registry",
        data={
            "csrf_token": csrf_token(client, "/tools/winhttp-registry"),
            "action": "normalize_reg",
            "reg_input": '"WinHttpSettings"=hex:28,00,00,00,00,00,00,00,03,00,00,00,00,00,00,00,00,00,00,00',
        },
    )

    assert response.status_code == 200
    assert "2800000000000000030000000000000000000000" in response.get_data(as_text=True)


def test_proxy_id_query_is_normalized_and_bound_to_session(
    monkeypatch, tmp_path
) -> None:
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
        "/adblock",
        "/administration",
        "/cache/clear",
        "/certs/generate",
        "/certs/upload",
        "/clamav/test-eicar",
        "/clamav/test-icap",
        "/clamav/toggle",
        "/pac",
        "/requests",
        "/reload",
        "/squid/config",
        "/squid/config/apply-all",
        "/squid/config/apply-overrides",
        "/squid/config/apply-safe",
        "/ssl-errors/exclude",
        "/sslfilter",
        "/webfilter",
        "/webfilter/test",
    ):
        response = client.post(path, follow_redirects=False)
        assert response.status_code == 403, path


def test_post_routes_accept_header_csrf_for_json(monkeypatch, tmp_path) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/")
    response = client.post(
        "/webfilter/test",
        json={"domain": "Example.COM"},
        headers={"X-CSRF-Token": token},
    )
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
    assert "HTTP/3/QUIC uses UDP/443" in text


def test_pac_page_warns_that_quic_does_not_use_the_http_proxy(
    monkeypatch, tmp_path
) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/pac")
    text = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "HTTP/3/QUIC over UDP/443" in text
    assert "block or reject UDP/443" in text


def test_sslfilter_apply_verify_forces_selected_proxy_sync(
    monkeypatch, tmp_path
) -> None:
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
    assert loaded.proxy_client.synced == []
    assert loaded.operation_ledger.operations[-1].proxy_id == "default"
    assert loaded.operation_ledger.operations[-1].operation_type == "manual_sync"
    assert loaded.operation_ledger.operations[-1].status == "pending"
    assert "Proxy reconciliation queued" in text
    assert any(
        record["kind"] == "sslfilter_apply_policy" and record["ok"]
        for record in loaded.audit_store.records
    )


def test_main_config_page_exposes_rebuild_apply_all_action(
    monkeypatch, tmp_path
) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/squid/config?tab=config")
    text = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "Rebuild, Verify &amp; Apply Saved Settings" in text
    assert 'form="apply-all-config-form"' in text
    assert 'action="/squid/config/apply-all' in text


def test_apply_all_saved_config_rebuilds_validates_and_syncs_selected_proxy(
    monkeypatch, tmp_path
) -> None:
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
    assert loaded.operation_ledger.operations[-1].proxy_id == "default"
    assert loaded.operation_ledger.operations[-1].operation_type == "config_apply"
    assert loaded.operation_ledger.operations[-1].status == "pending"
    assert loaded.config_revisions.created[-1]["proxy_id"] == "default"
    assert loaded.config_revisions.created[-1]["source_kind"] == "template-reconcile"
    assert "Saved settings were rebuilt, verified, and applied" in text
    assert any(
        record["kind"] == "config_apply_all_saved" and record["ok"]
        for record in loaded.audit_store.records
    )


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
    assert loaded.proxy_client.synced == []
    assert loaded.operation_ledger.operations[-1].proxy_id == "edge-2"
    assert loaded.operation_ledger.operations[-1].operation_type == "manual_sync"
    assert loaded.operation_ledger.operations[-1].status == "pending"
    assert any(
        record["kind"] == "sslfilter_apply_policy" and record["ok"]
        for record in loaded.audit_store.records
    )


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
    assert loaded.operation_ledger.operations[-1].proxy_id == "edge-2"
    assert loaded.operation_ledger.operations[-1].operation_type == "config_apply"
    assert loaded.operation_ledger.operations[-1].status == "pending"
    assert loaded.config_revisions.created[-1]["proxy_id"] == "edge-2"
    assert loaded.config_revisions.created[-1]["source_kind"] == "template-reconcile"
    assert any(
        record["kind"] == "config_apply_all_saved" and record["ok"]
        for record in loaded.audit_store.records
    )


def test_observability_clear_logs_is_fleet_wide_mutation(monkeypatch, tmp_path) -> None:
    calls: list[bool] = []

    def clear_logs() -> dict[str, object]:
        calls.append(True)
        return {
            "ok": True,
            "cleared_tables": 2,
            "deleted_rows": 0,
            "tables": [
                {
                    "table": "diagnostic_requests",
                    "status": "cleared",
                    "deleted_rows": 30,
                },
                {"table": "ssl_errors", "status": "cleared", "deleted_rows": 12},
            ],
        }

    loaded = load_admin_app(monkeypatch, tmp_path, clear_observability_logs=clear_logs)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.post(
        "/observability/clear-logs",
        data={"csrf_token": csrf_token(client, "/")},
        follow_redirects=False,
    )

    assert response.status_code in {302, 303}
    assert calls == [True]
    location = response.headers["Location"]
    assert "/observability" in location
    assert "pane=overview" in location
    assert "logs_cleared=1" in location
    assert "clear_tables=2" in location
    assert loaded.audit_store.records[-1]["kind"] == "observability_clear_logs"
    assert loaded.audit_store.records[-1]["ok"] is True
    assert "across the fleet" in loaded.audit_store.records[-1]["detail"]
    assert "2 tables" in loaded.audit_store.records[-1]["detail"]


def test_observability_settings_updates_retention_days(monkeypatch, tmp_path) -> None:
    saved: list[int] = []

    def set_retention(*, retention_days: object) -> dict[str, int]:
        days = int(retention_days)
        saved.append(days)
        return {"retention_days": days, "updated_ts": 123}

    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        get_observability_retention_settings=lambda: {
            "retention_days": 30,
            "updated_ts": 0,
        },
        set_observability_retention_settings=set_retention,
    )
    client = loaded.module.app.test_client()
    login_client(client)

    page = client.get("/observability?pane=settings")
    assert page.status_code == 200
    assert b"MySQL retention" in page.data
    assert b"Save retention" in page.data

    response = client.post(
        "/observability/settings",
        data={"csrf_token": csrf_token(client, "/"), "retention_days": "45"},
        follow_redirects=False,
    )

    assert response.status_code in {302, 303}
    assert saved == [45]
    location = response.headers["Location"]
    assert "/observability" in location
    assert "pane=settings" in location
    assert "settings_saved=1" in location
    assert "retention_days=45" in location
    assert (
        loaded.audit_store.records[-1]["kind"]
        == "observability_retention_settings_save"
    )
    assert loaded.audit_store.records[-1]["ok"] is True
    assert "45 days" in loaded.audit_store.records[-1]["detail"]


def test_observability_settings_runs_manual_database_maintenance(
    monkeypatch, tmp_path
) -> None:
    calls: list[tuple[bool, bool]] = []

    def run_maintenance(*, analyze: bool = False, optimize: bool = False):
        calls.append((analyze, optimize))
        return {
            "ok": True,
            "retention_days": 45,
            "maintenance": {"maintained_tables": 3, "tables": []},
        }

    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        run_observability_maintenance=run_maintenance,
        get_observability_retention_settings=lambda: {
            "retention_days": 45,
            "updated_ts": 0,
        },
    )
    client = loaded.module.app.test_client()
    login_client(client)

    page = client.get("/observability?pane=settings")
    assert page.status_code == 200
    assert b"Run prune, analyze, optimize now" in page.data

    response = client.post(
        "/observability/maintenance",
        data={"csrf_token": csrf_token(client, "/")},
        follow_redirects=False,
    )

    assert response.status_code in {302, 303}
    assert calls == [(True, True)]
    location = response.headers["Location"]
    assert "/observability" in location
    assert "pane=settings" in location
    assert "maintenance_run=1" in location
    assert "retention_days=45" in location
    assert "maintained_tables=3" in location
    assert (
        loaded.audit_store.records[-1]["kind"] == "observability_database_maintenance"
    )
    assert loaded.audit_store.records[-1]["ok"] is True
    assert "45 day retention" in loaded.audit_store.records[-1]["detail"]


def test_clamav_page_uses_dedicated_clamav_health_endpoint(
    monkeypatch, tmp_path
) -> None:
    proxy_client = RecordingProxyClient()
    loaded = load_admin_app(monkeypatch, tmp_path, proxy_client=proxy_client)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/clamav")

    assert response.status_code == 200
    assert proxy_client.health_calls == [("clamav:default", 5.0)]


def test_fleet_observability_summary_is_not_repeated_per_proxy(
    monkeypatch, tmp_path
) -> None:
    class CountingDiagnosticStore:
        def __init__(self) -> None:
            self.activity_calls = 0

        def activity_summary(self, **_kwargs):
            self.activity_calls += 1
            return {"requests": 7, "transactions": 3, "icap_events": 2}

        def icap_summary(self, **_kwargs):
            return {"events": 0, "avg_icap_time_ms": 0, "max_icap_time_ms": 0}

    diagnostic_store = CountingDiagnosticStore()
    registry = FakeRegistry(["default", "edge-2", "edge-3"])
    loaded = load_admin_app(
        monkeypatch, tmp_path, registry=registry, diagnostic_store=diagnostic_store
    )
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/proxies")

    assert response.status_code == 200
    assert diagnostic_store.activity_calls == 1


def test_observability_hostnames_are_not_resolved_by_default(
    monkeypatch, tmp_path
) -> None:
    class RecordingObservabilityQueries:
        def __init__(self) -> None:
            self.top_client_calls = []

        def summary(self, **_kwargs):
            return {"request_records": 0, "cache_hit_pct": 0}

        def top_clients(self, **kwargs):
            self.top_client_calls.append(dict(kwargs))
            return []

    observability_queries = RecordingObservabilityQueries()
    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        observability_queries=observability_queries,
    )
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/observability?pane=clients")
    assert response.status_code == 200
    assert observability_queries.top_client_calls[-1]["resolve_hostnames"] is False

    response = client.get("/observability?pane=clients&resolve_hostnames=1")
    assert response.status_code == 200
    assert observability_queries.top_client_calls[-1]["resolve_hostnames"] is True


def test_observability_metrics_returns_partial_payload_on_collector_failure(
    monkeypatch, tmp_path
) -> None:
    class PartiallyFailingObservabilityQueries:
        def summary(self, **_kwargs):
            msg = "summary unavailable"
            raise RuntimeError(msg)

        def cache_savings(self, **_kwargs):
            return {"estimated_saved_bytes": 42}

        def security_overview(self, **_kwargs):
            return {
                "summary": {
                    "combined_blocks": 7,
                    "potential_findings": 2,
                },
            }

    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        observability_queries=PartiallyFailingObservabilityQueries(),
    )
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/observability/metrics")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "docker_proxy_observability_cache_saved_bytes" in body
    assert 'docker_proxy_observability_cache_saved_bytes{proxy_id="default"} 42' in body
    assert 'docker_proxy_observability_security_blocks{proxy_id="default"} 7' in body
    assert (
        'docker_proxy_observability_scrape_error{proxy_id="default",section="summary"} 1'
        in body
    )
