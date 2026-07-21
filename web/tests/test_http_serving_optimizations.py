from __future__ import annotations

import gzip
import importlib
import sys
from pathlib import Path

from .admin_route_test_utils import csrf_token, load_admin_app, login_client


class ExplodingRegistry:
    def __getattr__(self, name: str):
        msg = f"proxy registry should not be used for this request: {name}"
        raise AssertionError(msg)


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


class CountingObservabilityQueries:
    def __init__(self) -> None:
        self.summary_calls = 0
        self.performance_calls = 0
        self.reporting_calls = 0

    def summary(self, **_kwargs):
        self.summary_calls += 1
        return {}

    def performance_overview(self, **_kwargs):
        self.performance_calls += 1
        return {"slow_requests": [], "slow_icap_events": []}

    def reporting_overview(self, **_kwargs):
        self.reporting_calls += 1
        return {
            "summary": {},
            "cache_savings": {"estimated_saved_bytes": 0, "byte_hit_pct": 0.0},
            "top_users": [],
            "top_blocked_categories": [],
            "top_malware_attempts": [],
            "top_ssl_bump_failures": [],
            "top_spliced_destinations": [],
            "per_group": [],
            "security": {"summary": {}},
            "audit": {
                "summary": {"events": 0, "failed_events": 0, "last_seen": 0},
                "top_kinds": [],
                "recent": [],
            },
            "time_series": {"tables": [], "latest_ts": 0, "rollup_points": 0},
            "schedules": [],
            "export_contracts": [
                {
                    "name": "JSON",
                    "status": "ready",
                    "endpoint": "/observability/export?pane=reports&format=json",
                }
            ],
            "privacy": {"enabled": True, "mode": "pseudonymized"},
        }

    def save_report_schedule(self, **kwargs):
        return {
            "id": 7,
            "enabled": True,
            "name": kwargs.get("name") or "Daily observability report",
            "cadence": kwargs.get("cadence") or "daily",
            "recipients": kwargs.get("recipients") or "ops@example.com",
            "pane": kwargs.get("pane") or "reports",
            "report_format": kwargs.get("report_format") or "csv",
            "privacy": bool(kwargs.get("privacy")),
            "window_seconds": int(kwargs.get("window_seconds") or 86400),
            "next_run_ts": 123456,
            "last_run_ts": 0,
            "last_status": "configured",
            "updated_ts": 123400,
        }

    def cache_savings(self, **_kwargs):
        return {"estimated_saved_bytes": 0}

    def security_overview(self, **_kwargs):
        return {"summary": {"combined_blocks": 0, "potential_findings": 0}}


def _add_repo_paths() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    web_root = repo_root / "web"
    for path in (repo_root, web_root):
        path_text = str(path)
        if path_text not in sys.path:
            sys.path.insert(0, path_text)


def test_login_and_static_requests_do_not_bind_proxy_context(
    monkeypatch, tmp_path
) -> None:
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


def test_admin_html_responses_are_gzip_compressed_when_requested(
    monkeypatch, tmp_path
) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/squid/config", headers={"Accept-Encoding": "gzip"})

    assert response.status_code == 200
    assert response.headers.get("Content-Encoding") == "gzip"
    assert "Accept-Encoding" in response.headers.get("Vary", "")
    assert b"Squid" in gzip.decompress(response.get_data())


def test_admin_html_responses_respect_gzip_quality_zero(
    monkeypatch, tmp_path
) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/squid/config", headers={"Accept-Encoding": "gzip;q=0"})

    assert response.status_code == 200
    assert response.headers.get("Content-Encoding") is None
    assert b"Squid" in response.get_data()


def test_observability_route_reuses_short_ttl_cache(monkeypatch, tmp_path) -> None:
    queries = CountingObservabilityQueries()
    loaded = load_admin_app(monkeypatch, tmp_path, observability_queries=queries)
    client = loaded.module.app.test_client()
    login_client(client)

    first = client.get("/observability?pane=performance&window=3600")
    second = client.get("/observability?pane=performance&window=3600")

    assert first.status_code == 200
    assert second.status_code == 200
    assert queries.summary_calls == 1
    assert queries.performance_calls == 1


def test_observability_reports_pane_json_export_and_metrics_routes_render(
    monkeypatch, tmp_path
) -> None:
    queries = CountingObservabilityQueries()
    loaded = load_admin_app(monkeypatch, tmp_path, observability_queries=queries)
    client = loaded.module.app.test_client()
    login_client(client)

    page = client.get("/observability?pane=reports&window=3600&privacy=1")
    export = client.get(
        "/observability/export?pane=reports&window=3600&privacy=1&format=json"
    )
    metrics = client.get("/observability/metrics?window=3600")

    assert page.status_code == 200
    assert b"Top users by bandwidth" in page.data
    assert b"Generate report" in page.data
    assert b"Report presets" in page.data
    assert b"Saved presets" in page.data
    assert export.status_code == 200
    assert export.headers.get("Content-Type", "").startswith("application/json")
    assert b'"mode":"pseudonymized"' in export.data
    assert metrics.status_code == 200
    assert b"docker_proxy_observability_requests" in metrics.data


def test_observability_report_schedule_post_records_configuration(
    monkeypatch, tmp_path
) -> None:
    queries = CountingObservabilityQueries()
    loaded = load_admin_app(monkeypatch, tmp_path, observability_queries=queries)
    client = loaded.module.app.test_client()
    login_client(client)

    token = csrf_token(client, "/observability?pane=reports")
    response = client.post(
        "/observability/report-schedules",
        data={
            "csrf_token": token,
            "name": "Daily accountability digest",
            "recipients": "ops@example.com",
            "cadence": "daily",
            "format": "jsonl",
            "privacy": "1",
            "window": "86400",
            "pane": "reports",
        },
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert "schedule_saved=1" in response.headers["Location"]


def test_spa_document_fetches_are_not_browser_cached(monkeypatch, tmp_path) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/administration", headers={"X-Requested-With": "spa"})

    assert response.status_code == 200
    assert response.headers.get("Cache-Control") == "no-store, private"


def test_normal_admin_gets_revalidate_instead_of_immutable_cache(
    monkeypatch, tmp_path
) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/administration")

    assert response.status_code == 200
    assert response.headers.get("Cache-Control") == "no-cache"


def test_proxy_pac_responses_have_cache_headers_and_conditional_etag(
    monkeypatch,
) -> None:
    _add_repo_paths()
    monkeypatch.setenv("DISABLE_PROXY_AGENT", "1")
    monkeypatch.setenv("PAC_HTTP_PORT", "80")
    sys.modules.pop("proxy.app", None)
    import proxy.app as proxy_app  # type: ignore

    proxy_app = importlib.reload(proxy_app)
    client = proxy_app.app.test_client()

    first = client.get("/proxy.pac", base_url="http://proxy")
    etag = first.headers.get("ETag")
    second = client.get(
        "/proxy.pac", base_url="http://proxy", headers={"If-None-Match": etag or ""}
    )

    assert first.status_code == 200
    assert first.headers.get("Cache-Control") == "private, max-age=30"
    assert (
        first.headers.get("Vary")
        == "Host, X-Forwarded-For, X-Forwarded-Host, X-Real-IP"
    )
    assert etag
    assert second.status_code == 304
