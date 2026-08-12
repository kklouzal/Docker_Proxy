from __future__ import annotations

import base64
import gzip
import hashlib
import importlib
import sys

import pytest
from flask import Flask, Response

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
            "next_run_ts": 0,
            "last_run_ts": 0,
            "last_status": "saved preset",
            "delivery_status": "manual_export_only",
            "updated_ts": 123400,
        }

    def cache_savings(self, **_kwargs):
        return {"estimated_saved_bytes": 0}

    def security_overview(self, **_kwargs):
        return {"summary": {"combined_blocks": 0, "potential_findings": 0}}


class ReportsPrivacyLeakQueries(CountingObservabilityQueries):
    def reporting_overview(self, **kwargs):
        self.reporting_calls += 1
        return {
            "summary": {},
            "cache_savings": {"estimated_saved_bytes": 0, "byte_hit_pct": 0.0},
            "top_users": [
                {
                    "client_ip": "192.0.2.80",
                    "client_label": "user-safe",
                    "hostname": "alice-laptop",
                    "requests": 2,
                    "destinations": 1,
                    "bytes": 4096,
                    "cache_hit_bytes": 1024,
                    "last_seen": 4100,
                }
            ],
            "top_blocked_categories": [],
            "top_malware_attempts": [
                {
                    "domain": "malware.example",
                    "client_ip": "192.0.2.80",
                    "client_label": "user-safe",
                    "attempts": 1,
                    "last_seen": 4120,
                    "sample": "blocked malware",
                }
            ],
            "top_ssl_bump_failures": [],
            "top_spliced_destinations": [],
            "per_group": [
                {
                    "group": "192.0.2.0/24",
                    "requests": 2,
                    "clients": 1,
                    "destinations": 1,
                    "bytes": 4096,
                    "cache_hit_bytes": 1024,
                    "last_seen": 4100,
                    "group_source": "client_subnet",
                }
            ],
            "security": {
                "summary": {},
                "av_rows": [{"ts": 4120, "client_ip": "192.0.2.80"}],
                "adblock_rows": [{"ts": 4130, "src_ip": "192.0.2.80"}],
                "webfilter_rows": [
                    {
                        "ts": 4140,
                        "src_ip": "192.0.2.80",
                        "correlated_candidates": [
                            {
                                "client_ip": "192.0.2.80",
                                "url": "https://blocked.example/",
                            }
                        ],
                    }
                ],
            },
            "audit": {
                "summary": {"events": 1, "failed_events": 0, "last_seen": 4150},
                "top_kinds": [],
                "recent": [
                    {
                        "ts": 4150,
                        "kind": "config_apply_manual",
                        "ok": True,
                        "remote_addr": "198.51.100.44",
                        "detail": "admin alice@example.com applied client 192.0.2.80",
                    }
                ],
            },
            "time_series": {"tables": [], "latest_ts": 0, "rollup_points": 0},
            "schedules": [
                {
                    "name": "Daily report",
                    "cadence": "daily",
                    "recipients": "ops@example.com",
                    "pane": "reports",
                    "report_format": "csv",
                    "privacy": True,
                    "window_seconds": 3600,
                    "delivery_status": "manual_export_only",
                }
            ],
            "export_contracts": [],
            "privacy": {"enabled": True, "mode": "pseudonymized"},
        }


class ReportsPrivacyPrefixLeakQueries(CountingObservabilityQueries):
    def reporting_overview(self, **kwargs):
        self.reporting_calls += 1
        assert kwargs["privacy"] is True
        return {
            "summary": {},
            "cache_savings": {"estimated_saved_bytes": 0, "byte_hit_pct": 0.0},
            "top_users": [
                {
                    "client_ip": "192.0.2.90",
                    "client_label": "user-alice@example.com",
                    "hostname": "alice-laptop",
                    "requests": 2,
                    "destinations": 1,
                    "bytes": 4096,
                    "cache_hit_bytes": 1024,
                    "last_seen": 4100,
                },
                {
                    "client_ip": "192.0.2.91",
                    "client_label": "user-0123456789",
                    "hostname": "bob-laptop",
                    "requests": 1,
                    "destinations": 1,
                    "bytes": 2048,
                    "cache_hit_bytes": 0,
                    "last_seen": 4110,
                },
            ],
            "top_blocked_categories": [],
            "top_malware_attempts": [
                {
                    "domain": "malware.example",
                    "client_ip": "192.0.2.90",
                    "client_label": "user-alice@example.com",
                    "attempts": 1,
                    "last_seen": 4120,
                    "sample": "blocked malware",
                }
            ],
            "top_ssl_bump_failures": [],
            "top_spliced_destinations": [],
            "per_group": [
                {
                    "group": "group-domain-admins",
                    "requests": 3,
                    "clients": 2,
                    "destinations": 2,
                    "bytes": 6144,
                    "cache_hit_bytes": 1024,
                    "last_seen": 4100,
                    "group_source": "directory",
                },
                {
                    "group": "group-abcdef1234",
                    "requests": 1,
                    "clients": 1,
                    "destinations": 1,
                    "bytes": 1024,
                    "cache_hit_bytes": 0,
                    "last_seen": 4110,
                    "group_source": "directory",
                },
            ],
            "security": {"summary": {}},
            "audit": {
                "summary": {"events": 1, "failed_events": 0, "last_seen": 4150},
                "top_kinds": [],
                "recent": [
                    {
                        "ts": 4150,
                        "kind": "config_apply_manual",
                        "ok": True,
                        "remote_addr": "user-admin@example.com",
                        "detail": "admin user-alice@example.com applied group-domain-admins",
                    }
                ],
            },
            "time_series": {"tables": [], "latest_ts": 0, "rollup_points": 0},
            "schedules": [],
            "export_contracts": [],
            "privacy": {"enabled": True, "mode": "pseudonymized"},
        }


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


def test_admin_html_responses_respect_gzip_quality_zero(monkeypatch, tmp_path) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/squid/config", headers={"Accept-Encoding": "gzip;q=0"})

    assert response.status_code == 200
    assert response.headers.get("Content-Encoding") is None
    assert b"Squid" in response.get_data()


def test_admin_html_responses_accept_gzip_via_wildcard_encoding(
    monkeypatch, tmp_path
) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/squid/config", headers={"Accept-Encoding": "*"})

    assert response.status_code == 200
    assert response.headers.get("Content-Encoding") == "gzip"
    assert b"Squid" in gzip.decompress(response.get_data())


def test_admin_html_responses_explicit_gzip_zero_overrides_wildcard(
    monkeypatch, tmp_path
) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get(
        "/squid/config", headers={"Accept-Encoding": "br;q=1, *;q=0.5, gzip;q=0"}
    )

    assert response.status_code == 200
    assert response.headers.get("Content-Encoding") is None
    assert b"Squid" in response.get_data()


def test_admin_html_responses_respect_wildcard_quality_zero(
    monkeypatch, tmp_path
) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/squid/config", headers={"Accept-Encoding": "*;q=0"})

    assert response.status_code == 200
    assert response.headers.get("Content-Encoding") is None
    assert b"Squid" in response.get_data()


def test_gzip_negotiation_varies_identity_and_encoded_representations() -> None:
    app = Flask(__name__)

    from web.services.http_optimizations import install_http_optimizations

    install_http_optimizations(app, compress_min_size=1)

    @app.get("/vary.txt")
    def vary_text():
        return Response(
            b"a" * 1000,
            mimetype="text/plain",
            headers={"ETag": '"identity"', "Vary": "Origin"},
        )

    client = app.test_client()

    identity = client.get("/vary.txt")
    encoded = client.get("/vary.txt", headers={"Accept-Encoding": "gzip"})

    assert identity.headers.get("Content-Encoding") is None
    assert identity.headers.get("ETag") == '"identity"'
    assert set(identity.headers.get("Vary", "").split(", ")) == {
        "Origin",
        "Accept-Encoding",
    }
    assert encoded.headers.get("Content-Encoding") == "gzip"
    assert encoded.headers.get("ETag") is None
    assert set(encoded.headers.get("Vary", "").split(", ")) == {
        "Origin",
        "Accept-Encoding",
    }
    assert gzip.decompress(encoded.get_data()) == identity.get_data()


def test_gzip_transformation_drops_stale_representation_integrity_fields() -> None:
    app = Flask(__name__)

    from web.services.http_optimizations import install_http_optimizations

    install_http_optimizations(app, compress_min_size=1)
    body = b"a" * 1000
    sha256 = base64.b64encode(hashlib.sha256(body).digest()).decode("ascii")
    md5 = base64.b64encode(hashlib.md5(body, usedforsecurity=False).digest()).decode(
        "ascii"
    )

    @app.get("/integrity.txt")
    def integrity_text():
        return Response(
            body,
            mimetype="text/plain",
            headers={
                "Content-Digest": f"sha-256=:{sha256}:",
                "Repr-Digest": f"sha-256=:{sha256}:",
                "Digest": f"sha-256={sha256}",
                "Content-MD5": md5,
            },
        )

    client = app.test_client()

    identity = client.get("/integrity.txt")
    encoded = client.get("/integrity.txt", headers={"Accept-Encoding": "gzip"})

    assert identity.headers.get("Content-Digest") == f"sha-256=:{sha256}:"
    assert identity.headers.get("Repr-Digest") == f"sha-256=:{sha256}:"
    assert identity.headers.get("Digest") == f"sha-256={sha256}"
    assert identity.headers.get("Content-MD5") == md5
    assert encoded.headers.get("Content-Encoding") == "gzip"
    assert gzip.decompress(encoded.get_data()) == body
    assert encoded.headers.get("Content-Digest") is None
    assert encoded.headers.get("Repr-Digest") is None
    assert encoded.headers.get("Digest") is None
    assert encoded.headers.get("Content-MD5") is None


def test_gzip_negotiation_rejects_invalid_and_duplicate_refusal_quality() -> None:
    app = Flask(__name__)

    from web.services.http_optimizations import install_http_optimizations

    install_http_optimizations(app, compress_min_size=1)

    @app.get("/quality.txt")
    def quality_text():
        return Response(b"a" * 1000, mimetype="text/plain")

    client = app.test_client()

    valid = client.get(
        "/quality.txt",
        headers={"Accept-Encoding": "gzip;q=0.5"},
    )
    duplicate_positive = client.get(
        "/quality.txt",
        headers={"Accept-Encoding": "gzip;q=0.5, gzip;q=1"},
    )
    invalid = client.get(
        "/quality.txt",
        headers={"Accept-Encoding": "gzip;q=1.5"},
    )
    duplicate_refusal = client.get(
        "/quality.txt",
        headers={"Accept-Encoding": "*;q=0, *;q=1"},
    )

    assert valid.headers.get("Content-Encoding") == "gzip"
    assert duplicate_positive.headers.get("Content-Encoding") == "gzip"
    assert invalid.headers.get("Content-Encoding") is None
    assert duplicate_refusal.headers.get("Content-Encoding") is None


def test_conditional_identity_response_keeps_encoding_vary_metadata() -> None:
    app = Flask(__name__)

    from flask import request

    from web.services.http_optimizations import install_http_optimizations

    install_http_optimizations(app, compress_min_size=1)

    @app.get("/conditional.txt")
    def conditional_text():
        response = Response(b"a" * 1000, mimetype="text/plain")
        response.set_etag("identity")
        return response.make_conditional(request)

    client = app.test_client()

    initial = client.get("/conditional.txt")
    revalidated = client.get(
        "/conditional.txt",
        headers={"If-None-Match": initial.headers["ETag"]},
    )

    assert initial.status_code == 200
    assert initial.headers.get("Vary") == "Accept-Encoding"
    assert revalidated.status_code == 304
    assert revalidated.headers.get("ETag") == initial.headers.get("ETag")
    assert revalidated.headers.get("Vary") == "Accept-Encoding"


def test_partial_content_responses_are_not_gzip_transformed() -> None:
    app = Flask(__name__)

    from web.services.http_optimizations import install_http_optimizations

    install_http_optimizations(app, compress_min_size=1)

    @app.get("/partial.txt")
    def partial_text():
        return Response(
            b"a" * 1000,
            status=206,
            mimetype="text/plain",
            headers={"Content-Range": "bytes 0-999/2000"},
        )

    client = app.test_client()

    response = client.get("/partial.txt", headers={"Accept-Encoding": "gzip"})

    assert response.status_code == 206
    assert response.headers.get("Content-Range") == "bytes 0-999/2000"
    assert response.headers.get("Content-Encoding") is None
    assert response.headers.get("Content-Length") == "1000"
    assert response.get_data() == b"a" * 1000


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
    assert b"Saved manual presets" in page.data
    assert export.status_code == 200
    assert export.headers.get("Content-Type", "").startswith("application/json")
    assert b'"mode":"pseudonymized"' in export.data
    assert metrics.status_code == 200
    assert b"docker_proxy_observability_requests" in metrics.data


@pytest.mark.parametrize("privacy", ["0", "1"])
def test_observability_reports_ui_omits_legacy_recipients_and_offers_manual_export(
    monkeypatch, tmp_path, privacy
) -> None:
    queries = ReportsPrivacyLeakQueries()
    loaded = load_admin_app(monkeypatch, tmp_path, observability_queries=queries)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get(f"/observability?pane=reports&window=3600&privacy={privacy}")

    assert response.status_code == 200
    assert b"Daily report" in response.data
    assert b"ops@example.com" not in response.data
    assert b"Recipients hidden in privacy mode" not in response.data
    assert b"Export now" in response.data
    assert (
        b"/observability/export?pane=reports&amp;window=3600&amp;format=csv&amp;privacy=1"
        in response.data
    )


def test_observability_reports_privacy_export_scrubs_user_identifiers_across_formats(
    monkeypatch, tmp_path
) -> None:
    queries = ReportsPrivacyLeakQueries()
    loaded = load_admin_app(monkeypatch, tmp_path, observability_queries=queries)
    client = loaded.module.app.test_client()
    login_client(client)

    leaked_tokens = (
        b"192.0.2.80",
        b"198.51.100.44",
        b"alice-laptop",
        b"alice@example.com",
        b"ops@example.com",
        b"user-safe",
    )
    for export_format in ("json", "jsonl", "csv"):
        response = client.get(
            f"/observability/export?pane=reports&window=3600&privacy=1&format={export_format}"
        )

        assert response.status_code == 200
        assert b"user-" in response.data
        for token in leaked_tokens:
            assert token not in response.data


def test_observability_reports_privacy_export_scrubs_prefixed_raw_identifiers(
    monkeypatch,
    tmp_path,
) -> None:
    queries = ReportsPrivacyPrefixLeakQueries()
    loaded = load_admin_app(monkeypatch, tmp_path, observability_queries=queries)
    client = loaded.module.app.test_client()
    login_client(client)

    leaked_tokens = (
        b"user-alice@example.com",
        b"user-admin@example.com",
        b"group-domain-admins",
        b"alice-laptop",
    )
    preserved_pseudonyms = (
        b"user-0123456789",
        b"group-abcdef1234",
    )
    for export_format in ("json", "jsonl", "csv"):
        response = client.get(
            f"/observability/export?pane=reports&window=3600&privacy=1&format={export_format}"
        )

        assert response.status_code == 200
        for token in leaked_tokens:
            assert token not in response.data
        for token in preserved_pseudonyms:
            assert token in response.data


class ExplodingReportScheduleQueries(CountingObservabilityQueries):
    def __init__(self, exc: Exception) -> None:
        super().__init__()
        self.exc = exc
        self.save_calls = 0

    def save_report_schedule(self, **_kwargs):
        self.save_calls += 1
        raise self.exc


def test_observability_report_schedule_ignores_legacy_delivery_fields(
    monkeypatch, tmp_path
) -> None:
    queries = CountingObservabilityQueries()
    loaded = load_admin_app(monkeypatch, tmp_path, observability_queries=queries)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.post(
        "/observability/report-schedules",
        data={
            "csrf_token": csrf_token(client, "/observability?pane=reports"),
            "name": "Reusable export",
            "recipients": "not-an-email",
            "cadence": "weekly",
            "format": "json",
            "privacy": "1",
            "window": "3600",
            "pane": "reports",
        },
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert "schedule_saved=1" in response.headers["Location"]


def test_observability_report_schedule_generic_save_error_stays_generic(
    monkeypatch, tmp_path
) -> None:
    raw_error = "database down for sensitive-recipient@example.com"
    queries = ExplodingReportScheduleQueries(RuntimeError(raw_error))
    loaded = load_admin_app(monkeypatch, tmp_path, observability_queries=queries)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.post(
        "/observability/report-schedules",
        data={
            "csrf_token": csrf_token(client, "/observability?pane=reports"),
            "name": "Daily digest",
            "recipients": "ops@example.com",
            "cadence": "daily",
            "format": "json",
            "privacy": "1",
            "window": "3600",
            "pane": "reports",
        },
        follow_redirects=False,
    )

    assert response.status_code == 302
    location = response.headers["Location"]
    assert "schedule_error=1" in location
    assert "schedule_recipient_error" not in location
    assert raw_error not in location
    assert queries.save_calls == 1
    assert loaded.audit_store.records[-1]["detail"] == (
        "Operation failed. Check server logs for details."
    )

    rendered = client.get(location)

    assert rendered.status_code == 200
    assert (
        b"Report preset was not saved. Check Admin UI logs for the database error."
        in rendered.data
    )
    assert raw_error.encode() not in rendered.data
    assert (
        b"recipient is required and the database must be reachable" not in rendered.data
    )


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
    record = loaded.audit_store.records[-1]
    assert record["kind"] == "observability_report_schedule_save"
    assert record["ok"] is True
    assert "saved manual reports observability export preset" in record["detail"]
    assert "recipients" not in record["detail"]
    assert "privacy=on" in record["detail"]
    assert "ops@example.com" not in record["detail"]


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


def test_proxy_pac_emergency_responses_are_private_no_store_and_conditional_etag(
    monkeypatch,
) -> None:
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
    assert first.headers.get("Cache-Control") == "no-store, private"
    assert set(first.headers.get("Vary", "").split(", ")) == {
        "Host",
        "X-Forwarded-For",
        "X-Forwarded-Host",
        "X-Real-IP",
        "Accept-Encoding",
    }
    assert etag
    assert second.status_code == 304
    assert second.headers.get("Vary") == first.headers.get("Vary")
