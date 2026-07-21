from __future__ import annotations

from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import pytest

from .admin_route_test_utils import (
    FakeAdblockArtifacts,
    FakeRegistry,
    FakeSslfilterStore,
    FakeWebfilterStore,
    csrf_token,
    load_admin_app,
    login_client,
)


class RecordingProxyClient:
    def __init__(self) -> None:
        self.health_calls: list[tuple[str, float | None]] = []
        self.health_full_flags: list[bool] = []
        self.log_calls: list[tuple[str, str]] = []

    def get_health(
        self, proxy_id: object, *_, timeout_seconds: float | None = None, **kwargs
    ) -> dict[str, object]:
        self.health_calls.append((str(proxy_id), timeout_seconds))
        self.health_full_flags.append(bool(kwargs.get("full")))
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

    def get_logs(
        self,
        proxy_id: object,
        *,
        log_key: object | None = None,
        timeout_seconds: float | None = None,
        **__,
    ) -> dict[str, object]:
        key = str(log_key or "access")
        self.log_calls.append((str(proxy_id), key))
        logs = [
            {
                "key": "access",
                "label": "Squid access log",
                "available": True,
                "path": "/var/log/squid/access.log",
            },
            {
                "key": "cache",
                "label": "Squid cache log",
                "available": False,
                "path": "/var/log/squid/cache.log",
            },
            {
                "key": "access_observe",
                "label": "Observability access log",
                "available": False,
                "path": "/var/log/squid/access-observe.log",
            },
            {
                "key": "icap",
                "label": "ICAP log",
                "available": False,
                "path": "/var/log/squid/icap.log",
            },
        ]
        if key not in {"access", "cache"}:
            return {
                "ok": False,
                "status": "not_found",
                "detail": "Log file is not allowlisted.",
                "key": key,
                "content": "",
                "logs": logs,
            }
        return {
            "ok": key == "access",
            "status": "ok" if key == "access" else "missing",
            "detail": "Loaded current log file tail."
            if key == "access"
            else "Squid cache log is not available on this proxy.",
            "key": key,
            "label": "Squid access log" if key == "access" else "Squid cache log",
            "content": f"{proxy_id}:{key}:line\n" if key == "access" else "",
            "size_bytes": 19 if key == "access" else 0,
            "truncated": False,
            "max_bytes": 256 * 1024,
            "logs": logs,
        }


class FullHealthOnlyDashboardProxyClient(RecordingProxyClient):
    def get_health(
        self, proxy_id: object, *_, timeout_seconds: float | None = None, **kwargs
    ) -> dict[str, object]:
        self.health_calls.append((str(proxy_id), timeout_seconds))
        full = bool(kwargs.get("full"))
        self.health_full_flags.append(full)
        if not full:
            return {
                "ok": True,
                "status": "healthy",
                "proxy_id": str(proxy_id),
                "proxy_status": "basic navigation health",
                "stats": {},
                "services": {},
            }
        return {
            "ok": True,
            "status": "healthy",
            "proxy_id": str(proxy_id),
            "proxy_status": "full dashboard health",
            "stats": {
                "cpu": {"util_percent": 12.3, "loadavg": {"1m": 1, "5m": 2, "15m": 3}},
                "memory": {
                    "used_bytes": 512 * 1024 * 1024,
                    "total_bytes": 1024 * 1024 * 1024,
                    "used_percent": 50.0,
                },
                "storage": {
                    "cache_path": "/var/spool/squid",
                    "cache_dir_size_human": "17 MiB",
                    "cache_fs_used_human": "4 GiB",
                    "cache_fs_total_human": "8 GiB",
                    "cache_fs_free_human": "4 GiB",
                },
                "squid": {
                    "mgr_available": True,
                    "hit_rate": {"request_hit_ratio": 42.5, "byte_hit_ratio": 21.0},
                    "hit_rate_source": "cachemgr",
                },
            },
            "services": {
                "icap": {"ok": True, "detail": "icap full detail"},
                "clamav": {"ok": True, "detail": "clamav full detail"},
            },
        }


class BadTimestampProxyClient(RecordingProxyClient):
    def get_health(
        self, proxy_id: object, *args, timeout_seconds: float | None = None, **kwargs
    ) -> dict[str, object]:
        payload = super().get_health(
            proxy_id,
            *args,
            timeout_seconds=timeout_seconds,
            **kwargs,
        )
        payload["timestamp"] = "bad-runtime-clock"
        return payload


class RuntimeLogInventoryProxyClient(RecordingProxyClient):
    def get_logs(
        self,
        proxy_id: object,
        *,
        log_key: object | None = None,
        timeout_seconds: float | None = None,
        **__,
    ) -> dict[str, object]:
        key = str(log_key or "access")
        self.log_calls.append((str(proxy_id), key))
        logs = [
            {
                "key": "runtime",
                "label": "Runtime log",
                "available": True,
                "path": "/var/log/proxy/runtime.log",
            },
            {
                "key": "events",
                "label": "Event log",
                "available": True,
                "path": "/var/log/proxy/events.log",
            },
        ]
        if key not in {"runtime", "events"}:
            return {
                "ok": False,
                "status": "not_found",
                "detail": "Log file is not allowlisted.",
                "key": key,
                "content": "",
                "logs": logs,
            }
        return {
            "ok": True,
            "status": "ok",
            "detail": "Loaded current log file tail.",
            "key": key,
            "label": "Runtime log" if key == "runtime" else "Event log",
            "content": f"{proxy_id}:{key}:line\n",
            "size_bytes": 21,
            "truncated": False,
            "max_bytes": 256 * 1024,
            "logs": logs,
        }


class RuntimeDriftSequenceProxyClient(RecordingProxyClient):
    def __init__(self, state_errors: list[str]) -> None:
        super().__init__()
        self.state_errors = list(state_errors)
        self.index = 0

    def get_health(
        self, proxy_id: object, *args, timeout_seconds: float | None = None, **kwargs
    ) -> dict[str, object]:
        payload = super().get_health(
            proxy_id,
            *args,
            timeout_seconds=timeout_seconds,
            **kwargs,
        )
        if not kwargs.get("full"):
            return payload
        error = self.state_errors[min(self.index, len(self.state_errors) - 1)]
        self.index += 1
        payload.update(
            {
                "ok": False,
                "status": "degraded",
                "timestamp": 6200,
                "state_errors": [error],
            },
        )
        return payload


class FailAfterCachedHealthProxyClient(RecordingProxyClient):
    def __init__(self) -> None:
        super().__init__()
        self.admin_app = None
        self.fail_health = False
        self.fail_clamav = False

    def get_health(
        self, proxy_id: object, *_, timeout_seconds: float | None = None, **__
    ) -> dict[str, object]:
        self.health_calls.append((str(proxy_id), timeout_seconds))
        if self.fail_health:
            msg = "management request timed out"
            raise self.admin_app.ProxyClientError(msg)
        return {
            "ok": True,
            "status": "healthy",
            "proxy_id": str(proxy_id),
            "proxy_status": "Squid check ok.",
            "detail": "cached full-health detail",
            "stats": {},
            "services": {
                "icap": {"ok": True, "detail": "ok"},
                "clamav": {"ok": True, "detail": "ok"},
            },
        }

    def get_clamav_health(
        self, proxy_id: object, *_, timeout_seconds: float | None = None, **__
    ) -> dict[str, object]:
        self.health_calls.append((f"clamav:{proxy_id}", timeout_seconds))
        if self.fail_clamav:
            msg = "ClamAV endpoint timed out"
            raise self.admin_app.ProxyClientError(msg)
        return {
            "ok": True,
            "status": "healthy",
            "proxy_id": str(proxy_id),
            "proxy_status": "ClamAV lightweight ok.",
            "detail": "cached clamav detail",
            "services": {
                "clamav": {"ok": True, "detail": "clamav lightweight"},
                "av_icap": {"ok": True, "detail": "ok"},
                "clamd": {"ok": True, "detail": "ok"},
            },
            "health_scope": "clamav",
        }


class RuntimeHealthEchoObservability:
    def summary(self, **_kwargs):
        return {
            "request_records": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "cache_hit_pct": 0.0,
            "clients": 0,
            "destinations": 0,
            "transactions": 0,
            "icap_events": 0,
            "av_icap_events": 0,
            "adblock_icap_events": 0,
        }

    def remediation_overview(self, **kwargs):
        runtime_health = kwargs.get("runtime_health") or {}
        state_errors = runtime_health.get("state_errors") or []
        evidence = "; ".join(str(item) for item in state_errors)
        return {
            "summary": {
                "suggestions": 1,
                "high_confidence": 1,
                "observations": 1,
                "domains": 0,
                "runtime_subjects": 1,
                "latest": int(runtime_health.get("timestamp") or 0),
                "http3_candidates": 0,
            },
            "rows": [
                {
                    "kind": "runtime_state_degraded",
                    "component": "Proxy generated state",
                    "severity": "high",
                    "title": "Proxy generated state does not match runtime",
                    "subject": runtime_health.get("proxy_id") or "default",
                    "subject_type": "proxy",
                    "count": 1,
                    "clients": 0,
                    "last_seen": int(runtime_health.get("timestamp") or 0),
                    "confidence": "high",
                    "evidence": evidence,
                    "recommended_action": "Force a selected-proxy sync.",
                }
            ],
            "top_components": [],
            "top_kinds": [],
            "quic_guidance": [],
        }


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/api/squid-config",
        "/proxies",
        "/observability",
        "/observability/metrics",
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


def test_performance_metrics_are_public_prometheus_text(monkeypatch, tmp_path) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    response = loaded.module.app.test_client().get("/performance?window=3600")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert response.headers.get("Content-Type", "").startswith(
        "text/plain; version=0.0.4"
    )
    assert 'docker_proxy_observability_window_seconds{proxy_id="default"} 3600' in body
    assert "docker_proxy_observability_requests" in body


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
    assert proxy_client.health_full_flags[-1] is True


def test_index_renders_full_proxy_health_stats(monkeypatch, tmp_path) -> None:
    proxy_client = FullHealthOnlyDashboardProxyClient()
    loaded = load_admin_app(monkeypatch, tmp_path, proxy_client=proxy_client)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/")

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert proxy_client.health_calls == [("default", 1.5)]
    assert proxy_client.health_full_flags == [True]
    assert "12.3%" in body
    assert "512 MiB / 1024 MiB" in body
    assert "/var/spool/squid" in body
    assert "4 GiB used / 8 GiB total" in body
    assert "Req 42.5%" in body
    assert "Bytes 21.0%" in body
    assert "icap full detail" in body
    assert "clamav full detail" in body


def test_index_reuses_short_lived_proxy_health_cache(monkeypatch, tmp_path) -> None:
    proxy_client = RecordingProxyClient()
    loaded = load_admin_app(monkeypatch, tmp_path, proxy_client=proxy_client)
    client = loaded.module.app.test_client()
    login_client(client)

    assert client.get("/").status_code == 200
    assert client.get("/").status_code == 200

    assert proxy_client.health_calls == [("default", 1.5)]
    assert proxy_client.health_full_flags == [True]


def test_cached_proxy_health_returns_fresh_cache_before_refresh(
    monkeypatch, tmp_path
) -> None:
    proxy_client = FailAfterCachedHealthProxyClient()
    loaded = load_admin_app(monkeypatch, tmp_path, proxy_client=proxy_client)
    proxy_client.admin_app = loaded.module
    current_time = 100.0
    monkeypatch.setattr(loaded.module.time, "monotonic", lambda: current_time)

    fresh = loaded.module._cached_proxy_health(
        "default",
        timeout_seconds=1.5,
        ttl_seconds=10.0,
    )
    assert fresh["detail"] == "cached full-health detail"

    proxy_client.fail_health = True
    current_time = 105.0
    cached = loaded.module._cached_proxy_health(
        "default",
        timeout_seconds=1.5,
        ttl_seconds=10.0,
    )

    assert cached["detail"] == "cached full-health detail"
    assert cached.get("_stale") is None
    assert "health_cache_detail" not in cached
    assert proxy_client.health_calls == [("default", 1.5)]


def test_cached_proxy_health_serves_recent_stale_payload_after_refresh_failure(
    monkeypatch, tmp_path
) -> None:
    proxy_client = FailAfterCachedHealthProxyClient()
    loaded = load_admin_app(monkeypatch, tmp_path, proxy_client=proxy_client)
    proxy_client.admin_app = loaded.module
    current_time = 100.0
    monkeypatch.setattr(loaded.module.time, "monotonic", lambda: current_time)

    fresh = loaded.module._cached_proxy_health(
        "default",
        timeout_seconds=1.5,
        ttl_seconds=10.0,
    )
    assert fresh["detail"] == "cached full-health detail"

    proxy_client.fail_health = True
    current_time = 111.0
    stale = loaded.module._cached_proxy_health(
        "default",
        timeout_seconds=1.5,
        ttl_seconds=10.0,
    )

    assert stale["_stale"] is True
    assert stale.get("_unavailable_cached") is None
    assert stale["ok"] is False
    assert stale["status"] == "degraded"
    assert stale["previous_ok"] is True
    assert stale["previous_status"] == "healthy"
    assert stale["proxy_status"] == "Squid check ok."
    assert stale["health_cache_detail"] == "management request timed out"
    cache_key = ("default", 1.5, False)
    assert loaded.module._PROXY_HEALTH_CACHE[cache_key][0] == pytest.approx(100.0)
    assert "_unavailable_cached" not in loaded.module._PROXY_HEALTH_CACHE[cache_key][1]


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
    assert proxy_client.health_full_flags == [False]


def test_fleet_query_selects_proxy_for_live_health(monkeypatch, tmp_path) -> None:
    proxy_client = RecordingProxyClient()
    registry = FakeRegistry(["default", "edge-2"])
    loaded = load_admin_app(
        monkeypatch, tmp_path, proxy_client=proxy_client, registry=registry
    )
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/proxies?proxy_id=edge-2")

    assert response.status_code == 200
    assert proxy_client.health_calls == [("edge-2", 1.5)]
    assert proxy_client.health_full_flags == [False]
    with client.session_transaction() as sess:
        assert sess["active_proxy_id"] == "edge-2"


def test_fleet_query_preserves_selected_proxy_in_scoped_links(
    monkeypatch, tmp_path
) -> None:
    registry = FakeRegistry(["default", "edge-2"])
    loaded = load_admin_app(monkeypatch, tmp_path, registry=registry)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/proxies?proxy_id=edge-2")

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert 'href="/?proxy_id=edge-2"' in body
    assert 'href="/operations?proxy_id=edge-2"' in body
    assert 'href="/observability?proxy_id=edge-2"' in body
    assert 'href="/logs?proxy_id=edge-2"' in body


def test_logs_page_renders_status_nav_and_selected_proxy_log(
    monkeypatch, tmp_path
) -> None:
    proxy_client = RecordingProxyClient()
    registry = FakeRegistry(["default", "edge-2"])
    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        proxy_client=proxy_client,
        registry=registry,
    )
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/logs?proxy_id=edge-2&log=access")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert proxy_client.log_calls == [("edge-2", "access")]
    assert "Logs" in body
    assert "edge-2:access:line" in body
    assert "Squid access log" in body
    assert "Squid cache log" in body
    assert "Observability access log" in body
    assert "ICAP log" in body
    assert 'href="/logs?proxy_id=edge-2"' in body


def test_logs_page_preserves_explicit_rejected_log_selection(
    monkeypatch, tmp_path
) -> None:
    proxy_client = RecordingProxyClient()
    registry = FakeRegistry(["default", "edge-2"])
    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        proxy_client=proxy_client,
        registry=registry,
    )
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/logs?proxy_id=edge-2&log=../../etc/passwd")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert proxy_client.log_calls == [("edge-2", "../../etc/passwd")]
    assert "Log file is not allowlisted." in body
    assert "edge-2:access:line" not in body


def test_logs_api_uses_active_proxy_and_rejects_non_allowlisted_log(
    monkeypatch, tmp_path
) -> None:
    proxy_client = RecordingProxyClient()
    registry = FakeRegistry(["default", "edge-2"])
    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        proxy_client=proxy_client,
        registry=registry,
    )
    client = loaded.module.app.test_client()
    login_client(client)

    selected = client.get("/logs?proxy_id=edge-2")
    response = client.get("/api/logs?log=../../etc/passwd")

    assert selected.status_code == 200
    assert response.status_code == 404
    assert response.get_json()["status"] == "not_found"
    assert proxy_client.log_calls[-1] == ("edge-2", "../../etc/passwd")


def test_logs_api_without_explicit_log_falls_back_to_first_advertised_runtime_log(
    monkeypatch, tmp_path
) -> None:
    proxy_client = RuntimeLogInventoryProxyClient()
    loaded = load_admin_app(monkeypatch, tmp_path, proxy_client=proxy_client)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/api/logs")

    assert response.status_code == 200
    assert response.get_json()["key"] == "runtime"
    assert response.get_json()["content"] == "default:runtime:line\n"
    assert proxy_client.log_calls == [("default", "access"), ("default", "runtime")]


def test_logs_api_preserves_explicit_rejected_log_when_default_missing_from_inventory(
    monkeypatch, tmp_path
) -> None:
    proxy_client = RuntimeLogInventoryProxyClient()
    loaded = load_admin_app(monkeypatch, tmp_path, proxy_client=proxy_client)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/api/logs?log=../../etc/passwd")

    assert response.status_code == 404
    assert response.get_json()["status"] == "not_found"
    assert response.get_json()["key"] == "../../etc/passwd"
    assert response.get_json()["content"] == ""
    assert proxy_client.log_calls == [("default", "../../etc/passwd")]


def test_logs_api_treats_missing_allowlisted_log_as_graceful_empty_payload(
    monkeypatch, tmp_path
) -> None:
    proxy_client = RecordingProxyClient()
    loaded = load_admin_app(monkeypatch, tmp_path, proxy_client=proxy_client)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/api/logs?log=cache")

    assert response.status_code == 200
    assert response.get_json()["status"] == "missing"
    assert response.get_json()["content"] == ""


def test_logs_api_reports_unreadable_allowlisted_log_as_server_error(
    monkeypatch, tmp_path
) -> None:
    class UnavailableLogProxyClient(RecordingProxyClient):
        def get_logs(
            self,
            proxy_id: object,
            *,
            log_key: object | None = None,
            timeout_seconds: float | None = None,
            **__,
        ) -> dict[str, object]:
            self.log_calls.append((str(proxy_id), str(log_key or "access")))
            return {
                "ok": False,
                "status": "unavailable",
                "detail": "Squid access log could not be read: permission denied",
                "key": str(log_key or "access"),
                "content": "",
                "logs": [],
            }

    proxy_client = UnavailableLogProxyClient()
    loaded = load_admin_app(monkeypatch, tmp_path, proxy_client=proxy_client)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/api/logs?log=access")

    assert response.status_code == 500
    assert response.get_json()["status"] == "unavailable"


def test_fleet_query_resolves_proxy_alias_for_live_health(
    monkeypatch, tmp_path
) -> None:
    class AliasRegistry(FakeRegistry):
        def resolve_proxy_id(self, preferred: object | None = None) -> str:
            if preferred == "Proxy-P":
                return "Proxy-PR"
            return super().resolve_proxy_id(preferred)

    proxy_client = RecordingProxyClient()
    registry = AliasRegistry(["default", "Proxy-PR"])
    loaded = load_admin_app(
        monkeypatch, tmp_path, proxy_client=proxy_client, registry=registry
    )
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/proxies?proxy_id=Proxy-P")

    assert response.status_code == 200
    assert proxy_client.health_calls == [("Proxy-PR", 1.5)]
    with client.session_transaction() as sess:
        assert sess["active_proxy_id"] == "Proxy-PR"


def test_api_squid_config_plain_text_contract(monkeypatch, tmp_path) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    login_client(client)
    response = client.get("/api/squid-config")
    assert response.status_code == 200
    assert response.headers.get("Content-Type", "").startswith("text/plain")
    assert "http_port" in response.get_data(as_text=True)
    assert "Content-Security-Policy" not in response.headers


def test_api_squid_config_state_reports_pending_desired_revision(
    monkeypatch, tmp_path
) -> None:
    class Revisions:
        def get_active_config_text(self, _proxy_id):
            return "http_port 3128\n"

        def get_active_revision_metadata(self, proxy_id):
            assert proxy_id == "default"
            return SimpleNamespace(
                revision_id=5,
                proxy_id="default",
                config_sha256="desired-sha",
                source_kind="manual",
                created_by="operator",
                created_ts=10,
                is_active=True,
            )

        def latest_apply(self, _proxy_id):
            return None

    class CurrentShaProxyClient(RecordingProxyClient):
        def get_health(self, proxy_id, *_, timeout_seconds=None, **kwargs):
            payload = super().get_health(
                proxy_id, timeout_seconds=timeout_seconds, **kwargs
            )
            payload.update(
                {
                    "active_revision_id": 4,
                    "active_revision_sha": "previous-sha",
                    "current_config_sha": "running-sha",
                }
            )
            return payload

    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        config_revisions=Revisions(),
        proxy_client=CurrentShaProxyClient(),
    )
    loaded.operation_ledger.create_operation(
        "default",
        operation_type="config_apply",
        subject="Squid config",
        summary="Revision 5 saved; applying asynchronously.",
        target_kind="config_revision",
        target_ref=5,
    )
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/api/squid-config/state?proxy_id=default")

    assert response.status_code == 200
    data = response.get_json()
    assert data["proxy_id"] == "default"
    assert data["state"] == "pending"
    assert data["label"] == "Apply pending"
    assert data["active_revision_id"] == 5
    assert data["active_revision_sha"] == "desired-sha"
    assert data["running_config_sha"] == "running-sha"
    assert data["operation_status"] == "pending"


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


def test_safe_config_apply_failure_returns_to_active_form_tab(
    monkeypatch, tmp_path
) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    login_client(client)

    def fail_publish(*_args, **_kwargs):
        msg = "publish failed"
        raise RuntimeError(msg)

    monkeypatch.setattr(loaded.module, "_publish_template_config", fail_publish)

    response = client.post(
        "/squid/config/apply-safe",
        data={
            "csrf_token": csrf_token(client, "/squid/config?tab=network"),
            "form_kind": "network",
            "explicit_proxy_port": "3128",
        },
        follow_redirects=False,
    )

    assert response.status_code in {301, 302, 303}
    assert "tab=network" in response.headers["Location"]
    assert "error=1" in response.headers["Location"]


def test_safe_config_apply_failure_shows_publish_detail(monkeypatch, tmp_path) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    login_client(client)

    monkeypatch.setattr(
        loaded.module,
        "_publish_template_config",
        lambda *_args, **_kwargs: (
            False,
            "Config validation failed; revision was not activated.\nline 42: bad directive",
        ),
    )

    response = client.post(
        "/squid/config/apply-safe",
        data={
            "csrf_token": csrf_token(client, "/squid/config?tab=network"),
            "form_kind": "network",
            "explicit_proxy_port": "3128",
        },
        follow_redirects=True,
    )
    text = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "Config validation/apply failed; previous config kept." in text
    assert "line 42: bad directive" in text


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


def test_layout_links_to_fleet_preserve_active_proxy_context(
    monkeypatch, tmp_path
) -> None:
    registry = FakeRegistry(["default", "edge-2"])
    loaded = load_admin_app(monkeypatch, tmp_path, registry=registry)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/webfilter?proxy_id=edge-2")
    text = response.get_data(as_text=True)

    assert response.status_code == 200
    assert 'href="/proxies?proxy_id=edge-2"' in text
    assert 'href="/logout?proxy_id=edge-2"' not in text


def test_remove_proxy_requires_exact_confirmation(monkeypatch, tmp_path) -> None:
    registry = FakeRegistry(["default", "edge-2"])
    loaded = load_admin_app(monkeypatch, tmp_path, registry=registry)
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/proxies")

    response = client.post(
        "/proxies/remove",
        data={"csrf_token": token, "proxy_id": "default", "confirm_proxy_id": ""},
        follow_redirects=False,
    )

    assert response.status_code in {302, 303}
    assert "error=1" in response.headers["Location"]
    assert [proxy.proxy_id for proxy in registry.list_proxies()] == [
        "default",
        "edge-2",
    ]
    assert not any(
        record["kind"] == "proxy_remove" and record["ok"]
        for record in loaded.audit_store.records
    )

    response = client.post(
        "/proxies/remove",
        data={
            "csrf_token": token,
            "proxy_id": "edge-2",
            "confirm_proxy_id": "edge 2",
        },
        follow_redirects=False,
    )

    assert response.status_code in {302, 303}
    assert "error=1" in response.headers["Location"]
    assert [proxy.proxy_id for proxy in registry.list_proxies()] == [
        "default",
        "edge-2",
    ]

    response = client.post(
        "/proxies/remove",
        data={
            "csrf_token": token,
            "proxy_id": "edge-2",
            "confirm_proxy_id": "edge-2",
        },
        follow_redirects=False,
    )

    assert response.status_code in {302, 303}
    assert "removed=1" in response.headers["Location"]
    assert [proxy.proxy_id for proxy in registry.list_proxies()] == ["default"]
    assert any(
        record["kind"] == "proxy_remove" and record["ok"]
        for record in loaded.audit_store.records
    )


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


def test_existing_proxy_selection_ignores_stale_alias_resolution(
    monkeypatch, tmp_path
) -> None:
    class StaleAliasRegistry(FakeRegistry):
        def resolve_proxy_id(self, preferred: object | None = None) -> str:
            if preferred == "Proxy-PR":
                return "default"
            return super().resolve_proxy_id(preferred)

    registry = StaleAliasRegistry(["default", "Proxy-PR"])
    loaded = load_admin_app(monkeypatch, tmp_path, registry=registry)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/api/squid-config?proxy_id=Proxy-PR")

    assert response.status_code == 200
    with client.session_transaction() as sess:
        assert sess["active_proxy_id"] == "Proxy-PR"


def test_proxy_reconcile_route_renames_active_proxy_and_updates_session(
    monkeypatch, tmp_path
) -> None:
    registry = FakeRegistry(proxy_ids=["Proxy-P", "Proxy-IT"])
    loaded = load_admin_app(monkeypatch, tmp_path, registry=registry)
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/proxies?proxy_id=Proxy-P")

    response = client.post(
        "/proxies/reconcile",
        data={
            "csrf_token": token,
            "old_proxy_id": "Proxy-P",
            "new_proxy_id": "Proxy-PR",
            "display_name": "Proxy-PR",
        },
        follow_redirects=False,
    )

    assert response.status_code in {301, 302, 303}
    assert "proxy_id=Proxy-PR" in response.headers["Location"]
    with client.session_transaction() as sess:
        assert sess["active_proxy_id"] == "Proxy-PR"
    assert registry.get_proxy("Proxy-P") is None
    assert registry.get_proxy("Proxy-PR") is not None


def test_proxy_remove_route_deletes_proxy_and_moves_active_session(
    monkeypatch, tmp_path
) -> None:
    registry = FakeRegistry(proxy_ids=["default", "edge-2"])
    loaded = load_admin_app(monkeypatch, tmp_path, registry=registry)
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/proxies?proxy_id=edge-2")

    response = client.post(
        "/proxies/remove",
        data={
            "csrf_token": token,
            "proxy_id": "edge-2",
            "confirm_proxy_id": "edge-2",
        },
        follow_redirects=False,
    )

    assert response.status_code in {301, 302, 303}
    assert registry.get_proxy("edge-2") is None
    with client.session_transaction() as sess:
        assert sess["active_proxy_id"] == "default"


def test_proxy_remove_route_requires_typed_proxy_id(monkeypatch, tmp_path) -> None:
    registry = FakeRegistry(proxy_ids=["default", "edge-2"])
    loaded = load_admin_app(monkeypatch, tmp_path, registry=registry)
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/proxies")

    response = client.post(
        "/proxies/remove",
        data={
            "csrf_token": token,
            "proxy_id": "edge-2",
            "confirm_proxy_id": "wrong",
        },
        follow_redirects=False,
    )

    assert response.status_code in {301, 302, 303}
    assert "Type+the+proxy+ID" in response.headers["Location"]
    assert registry.get_proxy("edge-2") is not None


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
    assert loaded.operation_ledger.operations[-1].operation_type == "policy_sync"
    assert loaded.operation_ledger.operations[-1].target_kind == "policy_state"
    assert loaded.operation_ledger.operations[-1].status == "pending"
    assert "Policy reconciliation queued" in text
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
    assert "Saved settings were rebuilt, verified, saved as desired state, and queued" in text
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
    assert loaded.operation_ledger.operations[-1].operation_type == "policy_sync"
    assert loaded.operation_ledger.operations[-1].target_kind == "policy_state"
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


def test_clamav_remote_health_returns_fresh_cache_before_refresh(
    monkeypatch, tmp_path
) -> None:
    proxy_client = FailAfterCachedHealthProxyClient()
    loaded = load_admin_app(monkeypatch, tmp_path, proxy_client=proxy_client)
    proxy_client.admin_app = loaded.module
    current_time = 100.0
    monkeypatch.setattr(loaded.module.time, "monotonic", lambda: current_time)

    fresh = loaded.module._clamav_remote_health("default")
    assert fresh["detail"] == "cached clamav detail"

    proxy_client.fail_clamav = True
    current_time = 105.0

    cached = loaded.module._clamav_remote_health("default")

    assert cached["detail"] == "cached clamav detail"
    assert cached.get("_stale") is None
    assert "health_cache_detail" not in cached
    assert proxy_client.health_calls == [("clamav:default", 5.0)]


def test_clamav_remote_health_does_not_reuse_expired_refresh_failure(
    monkeypatch, tmp_path
) -> None:
    proxy_client = FailAfterCachedHealthProxyClient()
    loaded = load_admin_app(monkeypatch, tmp_path, proxy_client=proxy_client)
    proxy_client.admin_app = loaded.module
    current_time = 100.0
    monkeypatch.setattr(loaded.module.time, "monotonic", lambda: current_time)

    fresh = loaded.module._clamav_remote_health("default")
    assert fresh["detail"] == "cached clamav detail"

    proxy_client.fail_clamav = True
    current_time = 111.0
    unavailable = loaded.module._clamav_remote_health("default")

    assert unavailable["_unavailable_cached"] is True
    assert unavailable.get("_stale") is None
    assert unavailable["ok"] is False
    assert unavailable["proxy_status"] == "ClamAV endpoint timed out"
    cache_key = ("default", "clamav", 5.0)
    assert loaded.module._PROXY_HEALTH_CACHE[cache_key][0] == pytest.approx(111.0)
    assert loaded.module._PROXY_HEALTH_CACHE[cache_key][1]["_unavailable_cached"] is True


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


def test_fleet_observability_summary_uses_active_proxy_scope(
    monkeypatch, tmp_path
) -> None:
    class ScopedDiagnosticStore:
        def __init__(self) -> None:
            self.proxy_ids = []

        def activity_summary(self, **_kwargs):
            from services.proxy_context import get_proxy_id

            proxy_id = get_proxy_id()
            self.proxy_ids.append(proxy_id)
            return {
                "requests": 22 if proxy_id == "edge-2" else 7,
                "transactions": 3,
                "icap_events": 2,
            }

        def icap_summary(self, **_kwargs):
            return {"events": 0, "avg_icap_time_ms": 0, "max_icap_time_ms": 0}

    diagnostic_store = ScopedDiagnosticStore()
    registry = FakeRegistry(["default", "edge-2"])
    loaded = load_admin_app(
        monkeypatch, tmp_path, registry=registry, diagnostic_store=diagnostic_store
    )
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/proxies?proxy_id=edge-2")

    assert response.status_code == 200
    assert diagnostic_store.proxy_ids == ["edge-2"]
    assert "Req 22" in response.get_data(as_text=True)


def test_observability_hostnames_are_resolved_by_default(monkeypatch, tmp_path) -> None:
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
    assert observability_queries.top_client_calls[-1]["resolve_hostnames"] is True

    response = client.get("/observability?pane=clients&resolve_hostnames=0")
    assert response.status_code == 200
    assert observability_queries.top_client_calls[-1]["resolve_hostnames"] is False

    response = client.get("/observability?pane=clients&resolve_hostnames=1&limit=60")
    assert response.status_code == 200
    assert observability_queries.top_client_calls[-1]["resolve_hostnames"] is True


def test_observability_accepts_search_alias_for_page_and_export(
    monkeypatch, tmp_path
) -> None:
    class RecordingSearchObservabilityQueries:
        def __init__(self) -> None:
            self.destination_calls = []

        def summary(self, **_kwargs):
            return {"request_records": 0, "cache_hit_pct": 0}

        def top_destinations(self, **kwargs):
            self.destination_calls.append(dict(kwargs))
            return []

    observability_queries = RecordingSearchObservabilityQueries()
    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        observability_queries=observability_queries,
    )
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/observability?pane=destinations&search=Video.Example")
    assert response.status_code == 200
    assert observability_queries.destination_calls[-1]["search"] == "video.example"

    response = client.get(
        "/observability/export?pane=destinations&search=Export.Example"
    )
    assert response.status_code == 200
    assert observability_queries.destination_calls[-1]["search"] == "export.example"

    response = client.get(
        "/observability?pane=destinations&q=canonical.example&search=ignored.example"
    )
    assert response.status_code == 200
    assert observability_queries.destination_calls[-1]["search"] == "canonical.example"


def test_observability_export_reuses_summary_cache_for_same_window(
    monkeypatch, tmp_path
) -> None:
    class CountingObservabilityQueries:
        def __init__(self) -> None:
            self.summary_calls = 0
            self.client_calls = []

        def summary(self, **_kwargs):
            self.summary_calls += 1
            return {"request_records": 14, "cache_hit_pct": 0}

        def top_clients(self, **kwargs):
            self.client_calls.append(dict(kwargs))
            return []

    observability_queries = CountingObservabilityQueries()
    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        observability_queries=observability_queries,
    )
    client = loaded.module.app.test_client()
    login_client(client)

    class RouteClock:
        def __init__(self) -> None:
            self._current_time = iter([1000, 1001])

        def time(self) -> int:
            return next(self._current_time)

        def monotonic(self) -> float:
            return 50.0

    monkeypatch.setattr(loaded.module, "time", RouteClock())

    assert (
        client.get("/observability/export?pane=clients&window=3600").status_code == 200
    )
    assert (
        client.get("/observability/export?pane=clients&window=3600").status_code == 200
    )

    assert observability_queries.summary_calls == 1
    assert [call["total_requests"] for call in observability_queries.client_calls] == [
        14,
        14,
    ]


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


def test_observability_metrics_reuses_short_lived_section_cache(
    monkeypatch, tmp_path
) -> None:
    class CountingObservabilityQueries:
        def __init__(self) -> None:
            self.summary_calls = 0
            self.cache_calls = 0
            self.performance_calls = 0
            self.security_calls = 0

        def summary(self, **_kwargs):
            self.summary_calls += 1
            return {
                "request_records": 9,
                "cache_hits": 6,
                "cache_misses": 3,
                "cache_hit_pct": 66.7,
                "clients": 2,
                "destinations": 4,
                "transactions": 5,
            }

        def cache_savings(self, **_kwargs):
            self.cache_calls += 1
            return {
                "total_bytes": 9999,
                "hit_bytes": 1234,
                "miss_bytes": 8765,
                "estimated_saved_bytes": 1234,
            }

        def performance_overview(self, **kwargs):
            self.performance_calls += 1
            assert kwargs["summary"]["request_records"] == 9
            assert kwargs["summary"]["requests"] == 9
            assert kwargs["summary"]["domains"] == 4
            return {
                "summary": {
                    "requests": kwargs["summary"].get("requests") or 0,
                    "transactions": kwargs["summary"].get("transactions") or 0,
                    "icap_events": 4,
                },
                "av_icap_summary": {
                    "events": 3,
                    "avg_icap_time_ms": 12,
                    "max_icap_time_ms": 30,
                },
                "adblock_icap_summary": {
                    "events": 1,
                    "avg_icap_time_ms": 8,
                    "max_icap_time_ms": 8,
                },
                "slow_requests": [{"duration_ms": 2450}],
                "slow_icap_events": [
                    {"service_family": "av", "icap_time_ms": 55},
                ],
                "top_user_agents": [
                    {"label": 'curl "quoted"', "count": 7},
                    {"label": "agent\rname", "count": 6},
                    {"label": "third", "count": 3},
                    {"label": "fourth", "count": 2},
                    {"label": "fifth", "count": 1},
                    {"label": "sixth", "count": 1},
                ],
                "top_bump_modes": [{"label": "splice", "count": 5}],
                "top_tls_server_versions": [{"label": "TLSv1.3", "count": 4}],
                "top_policy_tags": [{"label": "Finance\\Restricted", "count": 2}],
            }

        def security_overview(self, **_kwargs):
            self.security_calls += 1
            return {
                "summary": {
                    "combined_blocks": 3,
                    "potential_findings": 1,
                },
            }

    observability_queries = CountingObservabilityQueries()
    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        observability_queries=observability_queries,
    )
    client = loaded.module.app.test_client()
    login_client(client)

    class RouteClock:
        def __init__(self) -> None:
            self._current_time = iter([1000, 1001])

        def time(self) -> int:
            return next(self._current_time)

        def monotonic(self) -> float:
            return 50.0

    monkeypatch.setattr(loaded.module, "time", RouteClock())

    first = client.get("/observability/metrics?window=3600")
    second = client.get("/performance?window=3600")

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.headers.get("Content-Type") == second.headers.get("Content-Type")
    assert first.headers.get("Content-Type", "").startswith("text/plain; version=0.0.4")
    assert first.get_data(as_text=True) == second.get_data(as_text=True)
    body = second.get_data(as_text=True)
    assert 'docker_proxy_observability_window_seconds{proxy_id="default"} 3600' in body
    assert 'docker_proxy_observability_requests{proxy_id="default"} 9' in body
    assert 'docker_proxy_observability_clients{proxy_id="default"} 2' in body
    assert 'docker_proxy_observability_destinations{proxy_id="default"} 4' in body
    assert 'docker_proxy_observability_transactions{proxy_id="default"} 5' in body
    assert 'docker_proxy_observability_cache_hits{proxy_id="default"} 6' in body
    assert 'docker_proxy_observability_cache_misses{proxy_id="default"} 3' in body
    assert (
        'docker_proxy_observability_cache_hit_ratio{proxy_id="default"} 0.667' in body
    )
    assert (
        'docker_proxy_observability_cache_total_bytes{proxy_id="default"} 9999' in body
    )
    assert 'docker_proxy_observability_cache_hit_bytes{proxy_id="default"} 1234' in body
    assert (
        'docker_proxy_observability_cache_miss_bytes{proxy_id="default"} 8765' in body
    )
    assert (
        'docker_proxy_observability_icap_events{proxy_id="default",service="av"} 3'
        in body
    )
    assert (
        'docker_proxy_observability_icap_avg_time_ms{proxy_id="default",service="av"} 12'
        in body
    )
    assert (
        'docker_proxy_observability_icap_max_time_ms{proxy_id="default",service="av"} 30'
        in body
    )
    assert (
        'docker_proxy_observability_slowest_http_request_duration_ms{proxy_id="default"} 2450'
        in body
    )
    assert (
        'docker_proxy_observability_slowest_icap_time_ms{proxy_id="default",service="av"} 55'
        in body
    )
    assert (
        'docker_proxy_observability_top_dimension_count{proxy_id="default",dimension="user_agent",rank="1",value="curl \\"quoted\\""} 7'
        in body
    )
    assert (
        'docker_proxy_observability_top_dimension_count{proxy_id="default",dimension="user_agent",rank="2",value="agent\\rname"} 6'
        in body
    )
    assert "agent\rname" not in body
    assert (
        'docker_proxy_observability_top_dimension_count{proxy_id="default",dimension="policy_tag",rank="1",value="Finance\\\\Restricted"} 2'
        in body
    )
    assert 'dimension="user_agent",rank="6"' not in body
    assert observability_queries.summary_calls == 1
    assert observability_queries.cache_calls == 1
    assert observability_queries.performance_calls == 1
    assert observability_queries.security_calls == 1


class SslPaneRowsObservability:
    def summary(self, **_kwargs):
        return {
            "request_records": 1,
            "cache_hits": 0,
            "cache_misses": 1,
            "cache_hit_pct": 0.0,
            "clients": 1,
            "destinations": 1,
            "transactions": 1,
            "icap_events": 0,
            "av_icap_events": 0,
            "adblock_icap_events": 0,
        }

    def _ssl_payload(self):
        return {
            "summary": {
                "bucket_count": 1,
                "total_events": 1,
                "known_domains": 1,
                "unknown_target_buckets": 0,
            },
            "top_categories": [],
            "hints": [],
            "top_domains": [
                {"domain": "broken.example", "total": 1, "buckets": 1, "last_seen": 1}
            ],
            "exclusion_candidates": [
                {
                    "domain": "broken.example",
                    "recommendation": "review",
                    "badge_tone": "warn",
                    "confidence": "medium",
                    "categories": "tls",
                    "sample": "sample",
                    "total": 1,
                    "buckets": 1,
                    "last_seen": 1,
                }
            ],
            "rows": [],
        }

    def overview_bundle(self, **_kwargs):
        return {
            "summary": self.summary(),
            "destinations": [],
            "clients": [],
            "cache_reasons": [],
            "ssl": self._ssl_payload(),
            "security": {
                "summary": {},
                "av_rows": [],
                "adblock_rows": [],
                "webfilter_rows": [],
            },
            "performance": {"summary": {}, "slow_requests": [], "slow_icap_events": []},
        }

    def ssl_overview(self, **_kwargs):
        return self._ssl_payload()


class RemediationRowsObservability:
    def summary(self, **_kwargs):
        return {
            "request_records": 1,
            "cache_hits": 0,
            "cache_misses": 1,
            "cache_hit_pct": 0.0,
            "clients": 1,
            "destinations": 1,
            "transactions": 1,
            "icap_events": 0,
            "av_icap_events": 0,
            "adblock_icap_events": 0,
        }

    def remediation_overview(self, **_kwargs):
        return {
            "summary": {
                "suggestions": 4,
                "high_confidence": 1,
                "observations": 4,
                "domains": 3,
                "runtime_subjects": 1,
                "latest": 1,
                "http3_candidates": 1,
            },
            "rows": [
                {
                    "kind": "runtime_icap_degraded",
                    "component": "ICAP / ClamAV health",
                    "severity": "high",
                    "title": "Runtime health degraded",
                    "subject": "livingroom",
                    "subject_type": "proxy",
                    "count": 1,
                    "clients": 0,
                    "last_seen": 1,
                    "confidence": "high",
                    "evidence": "clamd unreachable",
                    "recommended_action": "Check c-icap and clamd.",
                },
                {
                    "kind": "http3_alt_svc",
                    "component": "HTTP/3 / QUIC routing",
                    "severity": "medium",
                    "title": "Origin advertises HTTP/3 over QUIC",
                    "subject": "video.example",
                    "subject_type": "domain",
                    "count": 1,
                    "clients": 1,
                    "last_seen": 1,
                    "confidence": "medium",
                    "evidence": 'Alt-Svc advertises h3; sample=h3=":443"',
                    "recommended_action": "Block or steer UDP/443.",
                },
                {
                    "kind": "slow_icap",
                    "component": "ICAP av",
                    "severity": "medium",
                    "title": "Slow ICAP adaptation observed",
                    "subject": "scan.example",
                    "subject_type": "domain",
                    "count": 1,
                    "clients": 1,
                    "last_seen": 1,
                    "confidence": "medium",
                    "evidence": "Max ICAP latency 2400 ms",
                    "recommended_action": "Check c-icap/clamd latency or tune scan policy.",
                },
                {
                    "kind": "cloudflare_challenge",
                    "component": "SSL inspection / upstream bot mitigation",
                    "severity": "high",
                    "title": "Cloudflare challenge observed through proxy",
                    "subject": "Challenge.Example/path",
                    "subject_type": "domain",
                    "count": 1,
                    "clients": 1,
                    "last_seen": 1,
                    "confidence": "high",
                    "evidence": "HTTP 403 with Cloudflare mitigation metadata",
                    "recommended_action": "Add a no-bump/splice rule for the domain.",
                },
                {
                    "kind": "cloudflare_challenge",
                    "component": "SSL inspection / upstream bot mitigation",
                    "severity": "high",
                    "title": "Cloudflare challenge observed through proxy",
                    "subject": "bad domain",
                    "subject_type": "domain",
                    "count": 1,
                    "clients": 1,
                    "last_seen": 1,
                    "confidence": "high",
                    "evidence": "HTTP 403 with Cloudflare mitigation metadata",
                    "recommended_action": "Add a no-bump/splice rule for the domain.",
                },
            ],
            "top_components": [],
            "top_kinds": [],
            "quic_guidance": [],
        }


class RegistryListRaises(FakeRegistry):
    def list_proxies(self):
        msg = "registry unavailable"
        raise RuntimeError(msg)


class PartialObservabilityPayload:
    def summary(self, **_kwargs):
        return {}

    def overview_bundle(self, **_kwargs):
        return {
            "summary": {},
            "destinations": [],
            "clients": [],
            "cache_reasons": [],
            "ssl": {},
            "security": {},
            "performance": {},
        }


class UnavailableWebfilterStore:
    def init_db(self):
        msg = "webfilter unavailable"
        raise RuntimeError(msg)

    def get_settings(self):
        msg = "webfilter unavailable"
        raise RuntimeError(msg)

    def safe_browsing_status(self):
        msg = "webfilter unavailable"
        raise RuntimeError(msg)

    def list_available_categories(self):
        msg = "webfilter unavailable"
        raise RuntimeError(msg)

    def list_whitelist(self):
        msg = "webfilter unavailable"
        raise RuntimeError(msg)


class UnavailableAdblockStore:
    def init_db(self):
        msg = "adblock unavailable"
        raise RuntimeError(msg)

    def list_statuses(self):
        msg = "adblock unavailable"
        raise RuntimeError(msg)

    def get_settings(self):
        msg = "adblock unavailable"
        raise RuntimeError(msg)

    def stats(self):
        msg = "adblock unavailable"
        raise RuntimeError(msg)

    def get_update_interval_seconds(self):
        msg = "adblock unavailable"
        raise RuntimeError(msg)

    def get_settings_version(self):
        msg = "adblock unavailable"
        raise RuntimeError(msg)

    def get_refresh_requested(self):
        msg = "adblock unavailable"
        raise RuntimeError(msg)

    def get_artifact_build_status(self):
        msg = "adblock unavailable"
        raise RuntimeError(msg)


def test_observability_ssl_pane_links_to_sslfilter_without_template_error(
    monkeypatch, tmp_path
) -> None:
    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        observability_queries=SslPaneRowsObservability(),
    )
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/observability?pane=ssl")
    text = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "/sslfilter?domain=broken.example" in text


def test_observability_ssl_exclusion_candidates_offer_no_bump_quick_action(
    monkeypatch, tmp_path
) -> None:
    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        observability_queries=SslPaneRowsObservability(),
    )
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/observability?pane=ssl")
    text = response.get_data(as_text=True)

    assert response.status_code == 200
    assert 'action="/ssl-errors/exclude' in text
    assert text.count('action="/ssl-errors/exclude') == 1
    assert 'name="domain" value="broken.example"' in text
    assert ">No-bump domain<" in text


def test_observability_remediation_scopes_row_actions_by_subject_and_kind(
    monkeypatch, tmp_path
) -> None:
    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        observability_queries=RemediationRowsObservability(),
        proxy_client=RecordingProxyClient(),
    )
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/observability?pane=remediation")
    text = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "Domain subjects" in text
    assert "Runtime subjects" in text
    assert ">Inspect destination<" in text
    assert ">Inspect SSL<" in text
    assert ">Inspect SSL Filtering<" in text
    assert "/observability?pane=destinations&amp;q=video.example" in text
    assert "/observability?pane=ssl&amp;q=video.example" in text
    assert "/observability?pane=destinations&amp;q=scan.example" in text
    assert "/observability?pane=ssl&amp;q=scan.example" in text
    assert 'action="/observability/remediation/no-bump-domain' in text
    assert text.count('action="/observability/remediation/no-bump-domain') == 1
    assert 'name="domain" value="challenge.example"' in text
    assert 'name="domain" value="Challenge.Example/path"' not in text
    assert ">No-bump domain<" in text
    assert 'name="domain" value="bad domain"' not in text
    assert 'name="domain" value="video.example"' not in text
    assert 'name="domain" value="scan.example"' not in text
    assert ">Destination</a>" not in text
    assert 'class="btn" href="/sslfilter?domain=video.example' not in text
    assert "/sslfilter?domain=livingroom" not in text
    assert "/observability?pane=destinations&amp;q=livingroom" not in text


def test_observability_remediation_no_bump_domain_adds_sslfilter_rule(
    monkeypatch, tmp_path
) -> None:
    sslfilter_store = FakeSslfilterStore()
    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        observability_queries=RemediationRowsObservability(),
        sslfilter_store=sslfilter_store,
    )
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/observability?pane=remediation")

    response = client.post(
        "/observability/remediation/no-bump-domain",
        data={
            "csrf_token": token,
            "domain": "https://Video.Example/path",
            "window": "900",
            "limit": "20",
            "sort": "count",
            "q": "ssl",
        },
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert "video.example" in sslfilter_store.no_bump_domains
    location = response.headers["Location"]
    assert "pane=remediation" in location
    assert "window=900" in location
    assert "limit=20" in location
    assert "sort=count" in location
    assert "q=ssl" in location
    assert "remediation_ok=1" in location
    assert loaded.operation_ledger.operations[-1].operation_type == "policy_sync"
    assert loaded.operation_ledger.operations[-1].status == "pending"
    assert any(
        record["kind"] == "observability_remediation_no_bump_domain" and record["ok"]
        for record in loaded.audit_store.records
    )


def test_observability_remediation_no_bump_domain_reports_refresh_failure_after_save(
    monkeypatch, tmp_path
) -> None:
    sslfilter_store = FakeSslfilterStore()
    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        observability_queries=RemediationRowsObservability(),
        sslfilter_store=sslfilter_store,
    )

    def fail_reconcile(*_args, **_kwargs):
        return SimpleNamespace(
            operation_id=0,
            status="failed",
            detail="operation ledger unavailable",
        )

    monkeypatch.setattr(loaded.module, "request_proxy_reconcile", fail_reconcile)
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/observability?pane=remediation")

    response = client.post(
        "/observability/remediation/no-bump-domain",
        data={
            "csrf_token": token,
            "domain": "challenge.example",
            "window": "900",
            "limit": "20",
            "sort": "recent",
            "q": "ssl",
        },
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert "challenge.example" in sslfilter_store.no_bump_domains
    assert loaded.operation_ledger.operations == []
    location = response.headers["Location"]
    params = parse_qs(urlparse(location).query)
    assert params["pane"] == ["remediation"]
    assert params["window"] == ["900"]
    assert params["limit"] == ["20"]
    assert params["sort"] == ["recent"]
    assert params["q"] == ["ssl"]
    assert params["remediation_error"] == ["1"]
    assert params["remediation_domain"] == ["challenge.example"]
    assert "saved, but proxy reconciliation was not queued" in params[
        "remediation_msg"
    ][0]
    assert "operation ledger unavailable" in params["remediation_msg"][0]
    assert any(
        record["kind"] == "observability_remediation_no_bump_domain"
        and not record["ok"]
        and "challenge.example" in record["detail"]
        and "not queued" in record["detail"]
        for record in loaded.audit_store.records
    )


def test_observability_remediation_no_bump_domain_rejects_invalid_subject(
    monkeypatch, tmp_path
) -> None:
    sslfilter_store = FakeSslfilterStore()
    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        observability_queries=RemediationRowsObservability(),
        sslfilter_store=sslfilter_store,
    )
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/observability?pane=remediation")

    response = client.post(
        "/observability/remediation/no-bump-domain",
        data={
            "csrf_token": token,
            "domain": "bad domain",
            "window": "900",
            "limit": "20",
            "sort": "recent",
            "q": "video",
        },
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert sslfilter_store.no_bump_domains == []
    location = response.headers["Location"]
    assert "pane=remediation" in location
    assert "window=900" in location
    assert "limit=20" in location
    assert "sort=recent" in location
    assert "q=video" in location
    assert "remediation_error=1" in location
    assert any(
        record["kind"] == "observability_remediation_no_bump_domain"
        and not record["ok"]
        for record in loaded.audit_store.records
    )


def test_observability_remediation_tolerates_bad_runtime_health_timestamp(
    monkeypatch, tmp_path
) -> None:
    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        observability_queries=RemediationRowsObservability(),
        proxy_client=BadTimestampProxyClient(),
    )
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/observability?pane=remediation")
    text = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "Remediation suggestions" in text
    assert "Runtime subjects" in text


def test_observability_remediation_cache_tracks_runtime_health_drift_details(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setenv("PROXY_HEALTH_UI_CACHE_TTL_SECONDS", "0")
    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        observability_queries=RuntimeHealthEchoObservability(),
        proxy_client=RuntimeDriftSequenceProxyClient(
            [
                "PAC drift: desired pac-a does not match runtime.",
                "PAC drift: desired pac-b does not match runtime.",
            ],
        ),
    )
    client = loaded.module.app.test_client()
    login_client(client)

    first_response = client.get("/observability?pane=remediation")
    first_text = first_response.get_data(as_text=True)
    second_response = client.get("/observability?pane=remediation")
    second_text = second_response.get_data(as_text=True)

    assert first_response.status_code == 200
    assert "pac-a" in first_text
    assert second_response.status_code == 200
    assert "pac-b" in second_text
    assert "pac-a" not in second_text


def test_observability_remediation_cache_fingerprint_accepts_scalar_state_error(
    monkeypatch, tmp_path
) -> None:
    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        observability_queries=RuntimeHealthEchoObservability(),
    )

    list_fingerprint = loaded.module._runtime_health_remediation_cache_fingerprint(
        {
            "proxy_id": "livingroom",
            "status": "degraded",
            "state_errors": ["PAC drift: desired state does not match runtime"],
        }
    )
    scalar_fingerprint = loaded.module._runtime_health_remediation_cache_fingerprint(
        {
            "proxy_id": "livingroom",
            "status": "degraded",
            "state_errors": "PAC drift: desired state does not match runtime",
        }
    )
    changed_fingerprint = loaded.module._runtime_health_remediation_cache_fingerprint(
        {
            "proxy_id": "livingroom",
            "status": "degraded",
            "state_errors": "config drift: active revision does not match runtime",
        }
    )

    assert scalar_fingerprint == list_fingerprint
    assert changed_fingerprint != list_fingerprint


def test_unhandled_admin_error_returns_recovery_page_and_clears_proxy_selection(
    monkeypatch, tmp_path
) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path, registry=FakeRegistry(["proxy-p"]))
    loaded.module.app.config.update(PROPAGATE_EXCEPTIONS=False)

    @loaded.module.app.route("/boom")
    def _boom():
        msg = "synthetic route failure"
        raise RuntimeError(msg)

    client = loaded.module.app.test_client()
    login_client(client)
    assert client.get("/?proxy_id=proxy-p").status_code == 200

    response = client.get("/boom")
    text = response.get_data(as_text=True)

    assert response.status_code == 500
    assert "Admin UI recovered from a request error" in text
    assert "/recover" in text
    with client.session_transaction() as sess:
        assert "active_proxy_id" not in sess

    recovered = client.get("/recover", follow_redirects=False)
    assert recovered.status_code in {302, 303}
    assert recovered.headers["Location"].startswith("/?recovered=1")


def test_observability_overview_merges_partial_payload_defaults(
    monkeypatch, tmp_path
) -> None:
    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        observability_queries=PartialObservabilityPayload(),
    )
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/observability?pane=overview")
    text = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "Cache hit rate" in text
    assert "Potential AV findings" in text


def test_policy_requests_page_renders_empty_state_when_store_unavailable(
    monkeypatch, tmp_path
) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    loaded.module.app.config.update(PROPAGATE_EXCEPTIONS=False)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/requests")

    assert response.status_code == 200
    assert "Internal Server Error" not in response.get_data(as_text=True)


def test_adblock_page_renders_empty_state_when_store_unavailable(
    monkeypatch, tmp_path
) -> None:
    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        adblock_store=UnavailableAdblockStore(),
    )
    loaded.module.app.config.update(PROPAGATE_EXCEPTIONS=False)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/adblock")

    assert response.status_code == 200
    assert "Internal Server Error" not in response.get_data(as_text=True)


def test_webfilter_page_renders_empty_state_when_store_unavailable(
    monkeypatch, tmp_path
) -> None:
    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        webfilter_store=UnavailableWebfilterStore(),
    )
    loaded.module.app.config.update(PROPAGATE_EXCEPTIONS=False)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/webfilter")

    assert response.status_code == 200
    assert "Internal Server Error" not in response.get_data(as_text=True)


def test_webfilter_page_normalizes_object_category_rows(monkeypatch, tmp_path) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/webfilter")

    assert response.status_code == 200
    assert 'data-category="adult"' in response.get_data(as_text=True)


def test_webfilter_page_marks_normalized_selected_categories(
    monkeypatch, tmp_path
) -> None:
    store = FakeWebfilterStore()
    store.settings.blocked_categories = [" Adult "]
    loaded = load_admin_app(monkeypatch, tmp_path, webfilter_store=store)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/webfilter")

    assert response.status_code == 200
    text = response.get_data(as_text=True)
    assert 'name="categories" value="adult"' in text
    assert 'data-category="adult"' in text
    assert 'aria-pressed="true"' in text


def test_webfilter_page_renders_editable_shared_source_controls(
    monkeypatch, tmp_path
) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/webfilter")

    assert response.status_code == 200
    text = response.get_data(as_text=True)
    assert 'id="webfilter-source-url"' in text
    assert 'name="source_url"' in text
    assert 'id="webfilter-source-provider"' in text
    assert 'name="source_provider"' in text
    assert 'value="csv"' in text
    assert 'name="action" value="save"' in text
    assert 'name="action" value="safe_browsing_save"' in text
    assert "Save Safe Browsing" in text


def test_recover_route_skips_proxy_registry_when_selection_is_stale(
    monkeypatch, tmp_path
) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path, registry=RegistryListRaises())
    loaded.module.app.config.update(PROPAGATE_EXCEPTIONS=False)
    client = loaded.module.app.test_client()
    login_client(client)

    with client.session_transaction() as sess:
        sess["active_proxy_id"] = "missing-proxy"

    response = client.get("/recover", follow_redirects=False)

    assert response.status_code in {302, 303}
    assert response.headers["Location"].startswith("/?recovered=1")
    with client.session_transaction() as sess:
        assert "active_proxy_id" not in sess


def test_webfilter_page_does_not_render_stored_safe_browsing_key(
    monkeypatch, tmp_path
) -> None:
    store = FakeWebfilterStore()
    store.settings.safe_browsing_api_key = "stored-secret"
    loaded = load_admin_app(monkeypatch, tmp_path, webfilter_store=store)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/webfilter")

    assert response.status_code == 200
    text = response.get_data(as_text=True)
    assert "stored-secret" not in text
    assert 'name="safe_browsing_clear_key"' in text
    assert "Configured - enter a new key to replace" in text


def test_webfilter_save_preserves_stored_safe_browsing_key_when_blank(
    monkeypatch, tmp_path
) -> None:
    store = FakeWebfilterStore()
    store.settings.safe_browsing_api_key = "stored-secret"
    loaded = load_admin_app(monkeypatch, tmp_path, webfilter_store=store)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.post(
        "/webfilter?tab=categories",
        data={
            "csrf_token": csrf_token(client, "/webfilter"),
            "tab": "categories",
            "action": "save",
            "source_url": "https://example.com/categories.csv",
            "source_provider": "csv",
            "safe_browsing_enabled": "on",
            "safe_browsing_api_key": "",
            "safe_browsing_lists": ["se-4b", "mw-4b"],
        },
        follow_redirects=False,
    )

    assert response.status_code in {302, 303}
    assert store.last_set_settings["safe_browsing_api_key"] == "stored-secret"


def test_webfilter_save_clears_stored_safe_browsing_key_when_requested(
    monkeypatch, tmp_path
) -> None:
    store = FakeWebfilterStore()
    store.settings.safe_browsing_api_key = "stored-secret"
    loaded = load_admin_app(monkeypatch, tmp_path, webfilter_store=store)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.post(
        "/webfilter?tab=categories",
        data={
            "csrf_token": csrf_token(client, "/webfilter"),
            "tab": "categories",
            "action": "safe_browsing_save",
            "safe_browsing_api_key": "",
            "safe_browsing_clear_key": "on",
            "safe_browsing_lists": ["se-4b", "mw-4b"],
        },
        follow_redirects=False,
    )

    assert response.status_code in {302, 303}
    assert store.last_set_settings["safe_browsing_enabled"] is False
    assert store.last_set_settings["safe_browsing_api_key"] == ""


def test_webfilter_safe_browsing_save_rejects_without_lists(
    monkeypatch, tmp_path
) -> None:
    store = FakeWebfilterStore()
    loaded = load_admin_app(monkeypatch, tmp_path, webfilter_store=store)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.post(
        "/webfilter?tab=categories",
        data={
            "csrf_token": csrf_token(client, "/webfilter"),
            "tab": "categories",
            "action": "safe_browsing_save",
            "safe_browsing_enabled": "on",
            "safe_browsing_api_key": "test-key",
        },
        follow_redirects=False,
    )

    assert response.status_code in {302, 303}
    assert "err_safe_browsing_lists=1" in response.headers["Location"]
    assert not hasattr(store, "last_set_settings")


def test_webfilter_safe_browsing_save_rejects_invalid_lists(
    monkeypatch, tmp_path
) -> None:
    store = FakeWebfilterStore()
    loaded = load_admin_app(monkeypatch, tmp_path, webfilter_store=store)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.post(
        "/webfilter?tab=categories",
        data={
            "csrf_token": csrf_token(client, "/webfilter"),
            "tab": "categories",
            "action": "safe_browsing_save",
            "safe_browsing_enabled": "on",
            "safe_browsing_api_key": "test-key",
            "safe_browsing_lists": ["invalid-list"],
        },
        follow_redirects=False,
    )

    assert response.status_code in {302, 303}
    assert "err_safe_browsing_lists=1" in response.headers["Location"]
    assert "err_source=1" not in response.headers["Location"]
    assert not hasattr(store, "last_set_settings")


def test_webfilter_safe_browsing_save_rejects_without_api_key(
    monkeypatch, tmp_path
) -> None:
    store = FakeWebfilterStore()
    loaded = load_admin_app(monkeypatch, tmp_path, webfilter_store=store)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.post(
        "/webfilter?tab=categories",
        data={
            "csrf_token": csrf_token(client, "/webfilter"),
            "tab": "categories",
            "action": "safe_browsing_save",
            "safe_browsing_enabled": "on",
            "safe_browsing_api_key": "",
            "safe_browsing_lists": ["se-4b", "mw-4b"],
        },
        follow_redirects=False,
    )

    assert response.status_code in {302, 303}
    assert "err_safe_browsing_key=1" in response.headers["Location"]
    assert not hasattr(store, "last_set_settings")


def test_webfilter_enforcement_save_ignores_incomplete_safe_browsing_form(
    monkeypatch, tmp_path
) -> None:
    store = FakeWebfilterStore()
    loaded = load_admin_app(monkeypatch, tmp_path, webfilter_store=store)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.post(
        "/webfilter?tab=categories",
        data={
            "csrf_token": csrf_token(client, "/webfilter"),
            "tab": "categories",
            "action": "save",
            "source_url": "https://example.com/categories.csv",
            "source_provider": "csv",
            "safe_browsing_enabled": "on",
            "safe_browsing_api_key": "",
            "safe_browsing_lists": ["se-4b", "mw-4b"],
        },
        follow_redirects=False,
    )

    assert response.status_code in {302, 303}
    assert "err_safe_browsing_key=1" not in response.headers["Location"]
    assert store.last_set_settings["safe_browsing_enabled"] is False


def test_webfilter_disabled_save_rejects_unsafe_source_before_store(
    monkeypatch, tmp_path
) -> None:
    store = FakeWebfilterStore()
    loaded = load_admin_app(monkeypatch, tmp_path, webfilter_store=store)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.post(
        "/webfilter?tab=categories",
        data={
            "csrf_token": csrf_token(client, "/webfilter"),
            "tab": "categories",
            "action": "save",
            "enabled": "on",
            "source_url": "http://127.0.0.1/categories.csv",
            "source_provider": "csv",
            "categories": "adult",
        },
        follow_redirects=False,
    )

    assert response.status_code in {302, 303}
    assert "err_source=1" in response.headers["Location"]
    assert not hasattr(store, "last_set_settings")


class PolicyEvidenceProxyClient(RecordingProxyClient):
    def __init__(
        self,
        *,
        current_by_proxy: dict[str, str] | None = None,
        desired_by_proxy: dict[str, str] | None = None,
    ) -> None:
        super().__init__()
        self.current_by_proxy = current_by_proxy or {}
        self.desired_by_proxy = desired_by_proxy or {}

    def get_health(self, proxy_id: object, *args, **kwargs) -> dict[str, object]:
        payload = super().get_health(proxy_id, *args, **kwargs)
        key = str(proxy_id)
        payload.update(
            {
                "desired_policy_sha": self.desired_by_proxy.get(key, "desired-sha"),
                "current_policy_sha": self.current_by_proxy.get(key, "running-sha"),
                "timestamp": 1234,
            }
        )
        return payload


class RuntimeEvidenceProxyClient(RecordingProxyClient):
    def __init__(self, by_proxy: dict[str, dict[str, object]] | None = None) -> None:
        super().__init__()
        self.by_proxy = by_proxy or {}

    def get_health(self, proxy_id: object, *args, **kwargs) -> dict[str, object]:
        payload = super().get_health(proxy_id, *args, **kwargs)
        payload.update(self.by_proxy.get(str(proxy_id), {}))
        return payload


def _artifact_summary(revision_id: int, sha: str) -> SimpleNamespace:
    return SimpleNamespace(
        revision_id=revision_id,
        artifact_sha256=sha,
        report={},
        settings_version=1,
        source_kind="test",
        enabled_lists=["default"],
        created_by="tests",
        created_ts=1234,
        is_active=True,
    )


@pytest.mark.parametrize(
    ("operation_status", "current_sha", "expected_state", "expected_label"),
    [
        ("pending", "old-sha", "pending", "Policy apply pending"),
        ("applying", "old-sha", "applying", "Policy apply running"),
        ("applied", "desired-sha", "reconciled", "Policy running"),
        ("failed", "old-sha", "failed", "Policy apply failed"),
        ("superseded", "old-sha", "superseded", "Policy apply superseded"),
    ],
)
def test_policy_runtime_state_tracks_selected_policy_operation_status(
    monkeypatch,
    tmp_path,
    operation_status: str,
    current_sha: str,
    expected_state: str,
    expected_label: str,
) -> None:
    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        proxy_client=PolicyEvidenceProxyClient(current_by_proxy={"default": current_sha}),
    )
    monkeypatch.setattr(
        loaded.module,
        "_desired_policy_sha_for_proxy",
        lambda _proxy_id: ("desired-sha", ""),
    )
    operation = loaded.operation_ledger.create_operation(
        "default",
        operation_type="policy_sync",
        subject="Policy reconciliation",
        summary="Policy state queued.",
        target_kind="policy_state",
        target_ref="desired-sha",
    )
    operation.status = operation_status

    state = loaded.module._policy_runtime_state("default")

    assert state["state"] == expected_state
    assert state["label"] == expected_label
    assert state["operation_id"] == operation.operation_id
    assert state["operation_status_label"] == (
        "succeeded" if operation_status == "applied" else operation_status.replace("applying", "running")
    )
    assert state["desired_policy_sha"] == "desired-sha"
    assert state["current_policy_sha"] == current_sha


def test_policy_runtime_state_isolated_to_selected_proxy(monkeypatch, tmp_path) -> None:
    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        registry=FakeRegistry(["edge-a", "edge-b"]),
        proxy_client=PolicyEvidenceProxyClient(
            current_by_proxy={"edge-a": "old-a", "edge-b": "old-b"},
            desired_by_proxy={"edge-a": "desired-a", "edge-b": "desired-b"},
        ),
    )
    monkeypatch.setattr(
        loaded.module,
        "_desired_policy_sha_for_proxy",
        lambda proxy_id: (f"desired-{str(proxy_id).split('-')[-1]}", ""),
    )
    edge_a_operation = loaded.operation_ledger.create_operation(
        "edge-a",
        operation_type="policy_sync",
        subject="Policy reconciliation",
        summary="Policy state queued.",
        target_kind="policy_state",
        target_ref="desired-a",
    )
    edge_a_operation.status = "failed"
    edge_b_operation = loaded.operation_ledger.create_operation(
        "edge-b",
        operation_type="policy_sync",
        subject="Policy reconciliation",
        summary="Policy state queued.",
        target_kind="policy_state",
        target_ref="desired-b",
    )
    edge_b_operation.status = "pending"

    client = loaded.module.app.test_client()
    login_client(client)
    response = client.get("/webfilter?proxy_id=edge-b")
    text = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "Policy apply pending" in text
    assert f"#{edge_b_operation.operation_id} pending" in text
    assert f"#{edge_a_operation.operation_id} failed" not in text
    assert "Edge-B" in text


@pytest.mark.parametrize(
    ("operation_status", "current_sha", "expected_state", "expected_label"),
    [
        ("pending", "old-pac", "pending", "PAC materialization pending"),
        ("applying", "old-pac", "applying", "PAC materialization running"),
        ("failed", "old-pac", "failed", "PAC materialization failed"),
        ("superseded", "old-pac", "superseded", "PAC materialization superseded"),
        ("applied", "desired-pac", "reconciled", "PAC materialized"),
        ("applied", "old-pac", "drift", "Saved/runtime PAC mismatch"),
    ],
)
def test_pac_runtime_state_classifies_selected_proxy_materialization(
    monkeypatch,
    tmp_path,
    operation_status: str,
    current_sha: str,
    expected_state: str,
    expected_label: str,
) -> None:
    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        proxy_client=RuntimeEvidenceProxyClient(
            {"default": {"desired_pac_sha": "desired-pac", "current_pac_sha": current_sha}}
        ),
    )
    monkeypatch.setattr(
        loaded.module,
        "_desired_pac_state_sha_for_proxy",
        lambda _proxy_id: ("desired-pac", ""),
    )
    operation = loaded.operation_ledger.create_operation(
        "default",
        operation_type="pac_refresh",
        subject="PAC refresh",
        summary="PAC queued.",
        target_kind="pac_state",
        target_ref="desired-pac",
    )
    operation.status = operation_status

    state = loaded.module._pac_runtime_state("default")

    assert state["state"] == expected_state
    assert state["label"] == expected_label
    assert state["operation_id"] == operation.operation_id
    assert state["desired_pac_sha"] == "desired-pac"
    assert state["current_pac_sha"] == current_sha


def test_pac_runtime_state_no_desired_unavailable_and_stale_operation(
    monkeypatch, tmp_path
) -> None:
    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        proxy_client=RuntimeEvidenceProxyClient(
            {"default": {"status": "offline", "proxy_status": "offline"}}
        ),
    )
    monkeypatch.setattr(
        loaded.module,
        "_desired_pac_state_sha_for_proxy",
        lambda _proxy_id: ("", ""),
    )
    assert loaded.module._pac_runtime_state("default")["state"] == "no_desired_state"

    monkeypatch.setattr(
        loaded.module,
        "_desired_pac_state_sha_for_proxy",
        lambda _proxy_id: ("new-pac", ""),
    )
    stale = loaded.operation_ledger.create_operation(
        "default",
        operation_type="pac_refresh",
        subject="PAC refresh",
        summary="old PAC queued.",
        target_kind="pac_state",
        target_ref="old-pac",
    )
    stale.status = "applied"

    state = loaded.module._pac_runtime_state("default")

    assert state["state"] == "unavailable"
    assert "different PAC fingerprint" in state["detail"]
    assert state["operation_id"] == stale.operation_id


def test_pac_runtime_card_isolates_selected_proxy_partial_convergence(
    monkeypatch, tmp_path
) -> None:
    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        registry=FakeRegistry(["edge-a", "edge-b"]),
        proxy_client=RuntimeEvidenceProxyClient(
            {
                "edge-a": {"desired_pac_sha": "pac-a", "current_pac_sha": "pac-a"},
                "edge-b": {"desired_pac_sha": "pac-b", "current_pac_sha": "old-b"},
            }
        ),
    )
    monkeypatch.setattr(
        loaded.module,
        "_desired_pac_state_sha_for_proxy",
        lambda proxy_id: ("pac-a" if proxy_id == "edge-a" else "pac-b", ""),
    )
    edge_a_operation = loaded.operation_ledger.create_operation(
        "edge-a",
        operation_type="pac_refresh",
        subject="PAC refresh",
        summary="PAC A queued.",
        target_kind="pac_state",
        target_ref="pac-a",
    )
    edge_a_operation.status = "applied"
    edge_b_operation = loaded.operation_ledger.create_operation(
        "edge-b",
        operation_type="pac_refresh",
        subject="PAC refresh",
        summary="PAC B queued.",
        target_kind="pac_state",
        target_ref="pac-b",
    )
    edge_b_operation.status = "pending"

    client = loaded.module.app.test_client()
    login_client(client)
    response = client.get("/pac?proxy_id=edge-b")
    text = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "Selected proxy PAC runtime evidence" in text
    assert "PAC materialization pending" in text
    assert f"#{edge_b_operation.operation_id} pending" in text
    assert f"#{edge_a_operation.operation_id} succeeded" not in text
    assert "Saved PAC profiles/URL are desired state" in text


@pytest.mark.parametrize(
    ("operation_status", "current_sha", "apply_ok", "expected_state", "expected_label"),
    [
        ("pending", "old-artifact", False, "pending", "Adblock apply pending"),
        ("applying", "old-artifact", False, "applying", "Adblock apply running"),
        ("failed", "old-artifact", False, "failed", "Adblock apply failed"),
        ("superseded", "old-artifact", False, "superseded", "Adblock apply superseded"),
        ("applied", "artifact-sha", True, "reconciled", "Adblock artifact applied"),
        ("applied", "old-artifact", False, "drift", "Built/runtime adblock mismatch"),
    ],
)
def test_adblock_runtime_state_classifies_revision_scoped_apply(
    monkeypatch,
    tmp_path,
    operation_status: str,
    current_sha: str,
    apply_ok: bool,
    expected_state: str,
    expected_label: str,
) -> None:
    artifacts = FakeAdblockArtifacts(_artifact_summary(7, "artifact-sha"))
    if apply_ok:
        artifacts.record_apply_result(
            "default",
            7,
            ok=True,
            detail="applied rev 7",
            artifact_sha256="artifact-sha",
        )
    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        adblock_artifacts=artifacts,
        proxy_client=RuntimeEvidenceProxyClient(
            {"default": {"active_adblock_sha": "artifact-sha", "current_adblock_sha": current_sha}}
        ),
    )
    operation = loaded.operation_ledger.create_operation(
        "default",
        operation_type="adblock_refresh",
        subject="Adblock refresh",
        summary="Adblock queued.",
        target_kind="adblock_artifact",
        target_ref="7",
        request_hash="artifact-sha",
    )
    operation.status = operation_status

    state = loaded.module._adblock_runtime_state(
        "default",
        active_artifact=loaded.module._present_adblock_artifact_summary(artifacts.summary),
    )

    assert state["state"] == expected_state
    assert state["label"] == expected_label
    assert state["active_revision_id"] == 7
    assert state["current_adblock_sha"] == current_sha


def test_adblock_runtime_state_no_active_built_unverified_unavailable_and_stale_revision(
    monkeypatch, tmp_path
) -> None:
    loaded_no_artifact = load_admin_app(monkeypatch, tmp_path)
    no_active = loaded_no_artifact.module._adblock_runtime_state(
        "default",
        active_artifact=loaded_no_artifact.module._present_adblock_artifact_summary(None),
    )
    assert no_active["state"] == "no_active_artifact"

    artifacts = FakeAdblockArtifacts(_artifact_summary(2, "new-artifact"))
    artifacts.record_apply_result(
        "default",
        1,
        ok=True,
        detail="stale rev 1 success",
        artifact_sha256="old-artifact",
    )
    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        adblock_artifacts=artifacts,
        proxy_client=RuntimeEvidenceProxyClient({"default": {"current_adblock_sha": ""}}),
    )
    stale = loaded.operation_ledger.create_operation(
        "default",
        operation_type="adblock_refresh",
        subject="Adblock refresh",
        summary="old rev queued.",
        target_kind="adblock_artifact",
        target_ref="1",
        request_hash="old-artifact",
    )
    stale.status = "applied"

    state = loaded.module._adblock_runtime_state(
        "default",
        active_artifact=loaded.module._present_adblock_artifact_summary(artifacts.summary),
    )
    assert state["state"] == "built_unverified"
    assert "different artifact revision/hash" in state["detail"]

    loaded_offline = load_admin_app(
        monkeypatch,
        tmp_path,
        adblock_artifacts=artifacts,
        proxy_client=RuntimeEvidenceProxyClient(
            {"default": {"status": "offline", "proxy_status": "offline"}}
        ),
    )
    unavailable = loaded_offline.module._adblock_runtime_state(
        "default",
        active_artifact=loaded_offline.module._present_adblock_artifact_summary(artifacts.summary),
    )
    assert unavailable["state"] == "unavailable"


def test_adblock_runtime_card_isolates_selected_proxy_partial_convergence(
    monkeypatch, tmp_path
) -> None:
    artifacts = FakeAdblockArtifacts(_artifact_summary(9, "fleet-artifact"))
    artifacts.record_apply_result(
        "edge-a",
        9,
        ok=True,
        detail="edge a applied",
        artifact_sha256="fleet-artifact",
    )
    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        registry=FakeRegistry(["edge-a", "edge-b"]),
        adblock_artifacts=artifacts,
        proxy_client=RuntimeEvidenceProxyClient(
            {
                "edge-a": {"active_adblock_sha": "fleet-artifact", "current_adblock_sha": "fleet-artifact"},
                "edge-b": {"active_adblock_sha": "fleet-artifact", "current_adblock_sha": "old-b"},
            }
        ),
    )
    edge_b_operation = loaded.operation_ledger.create_operation(
        "edge-b",
        operation_type="adblock_refresh",
        subject="Adblock refresh",
        summary="Adblock B queued.",
        target_kind="adblock_artifact",
        target_ref="9",
        request_hash="fleet-artifact",
    )
    edge_b_operation.status = "applying"

    client = loaded.module.app.test_client()
    login_client(client)
    response = client.get("/adblock?proxy_id=edge-b")
    text = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "Selected proxy adblock runtime evidence" in text
    assert "Adblock apply running" in text
    assert f"#{edge_b_operation.operation_id} running" in text
    assert "Shared compiled artifacts are built state" in text
    assert "edge a applied" not in text


def test_sslfilter_policy_change_queues_fingerprinted_policy_operation(
    monkeypatch, tmp_path
) -> None:
    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        proxy_client=PolicyEvidenceProxyClient(),
    )
    monkeypatch.setattr(
        loaded.module,
        "_desired_policy_sha_for_proxy",
        lambda _proxy_id: ("desired-sha", ""),
    )
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.post(
        "/sslfilter",
        data={
            "csrf_token": csrf_token(client, "/sslfilter"),
            "action": "add_domain",
            "policy": "nobump",
            "domain": "example.com",
        },
        follow_redirects=False,
    )

    assert response.status_code in {302, 303}
    assert "policy_queue=1" in response.headers["Location"]
    operation = loaded.operation_ledger.operations[-1]
    assert operation.proxy_id == "default"
    assert operation.operation_type == "policy_sync"
    assert operation.target_kind == "policy_state"
    assert operation.target_ref == "desired-sha"
