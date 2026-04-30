from __future__ import annotations

from .flask_test_helpers import import_local_app_module, login


def _install_queries(app_module, fake_queries) -> None:
    app_module.reset_app_runtime_services_for_testing()
    app_module.configure_app_runtime_services_for_testing(
        get_observability_queries=lambda: fake_queries,
    )


class _FakeQueries:
    def __init__(self):
        self.calls: dict[str, object] = {}

    def summary(self, *, since: int):
        self.calls.setdefault("summary", []).append(since)
        return {
            "request_records": 12,
            "cache_hits": 5,
            "cache_misses": 7,
            "cache_hit_pct": 41.7,
            "clients": 3,
            "destinations": 4,
            "transactions": 9,
            "icap_events": 4,
            "av_icap_events": 1,
            "adblock_icap_events": 3,
        }

    def top_destinations(self, *, since: int, search: str = "", limit: int = 50, sort: str = "requests"):
        self.calls["destinations"] = (since, search, limit, sort)
        return [
            {
                "domain": "example.com",
                "requests": 7,
                "hit_requests": 3,
                "clients": 2,
                "transactions": 6,
                "last_seen": 9999,
                "cache_pct": 42.9,
                "av_icap_events": 1,
                "adblock_icap_events": 2,
                "pct": 58.3,
            }
        ]

    def top_clients(self, *, since: int, search: str = "", limit: int = 50, sort: str = "requests", resolve_hostnames: bool = True):
        self.calls["clients"] = (since, search, limit, sort, resolve_hostnames)
        return [
            {
                "ip": "192.0.2.15",
                "requests": 8,
                "hit_requests": 3,
                "destinations": 4,
                "transactions": 7,
                "last_seen": 9990,
                "cache_pct": 37.5,
                "av_icap_events": 1,
                "adblock_icap_events": 0,
                "pct": 66.7,
                "hostname": "workstation.lan",
                "hostname_source": "rdns",
                "hostname_status": "resolved",
            }
        ]

    def top_cache_reasons(self, *, since: int, search: str = "", limit: int = 50, sort: str = "requests"):
        self.calls["cache"] = (since, search, limit, sort)
        return [
            {
                "reason": "POST method (not cacheable by default)",
                "requests": 4,
                "domains": 2,
                "clients": 1,
                "last_seen": 9988,
                "pct": 57.1,
            }
        ]

    def ssl_overview(self, *, since: int, search: str = "", limit: int = 50):
        self.calls["ssl"] = (since, search, limit)
        return {
            "summary": {
                "bucket_count": 2,
                "total_events": 6,
                "known_domains": 1,
                "unknown_target_buckets": 0,
            },
            "rows": [
                {
                    "domain": "example.com",
                    "target_display": "example.com",
                    "has_domain": True,
                    "category": "CERT_VERIFY",
                    "category_label": "Trust / chain failure",
                    "badge_tone": "danger",
                    "operator_note": "Check trust chain.",
                    "reason": "certificate verify failed",
                    "count": 4,
                    "first_seen": 9000,
                    "last_seen": 9999,
                }
            ],
            "top_domains": [{"domain": "example.com", "total": 4, "buckets": 1, "last_seen": 9999}],
            "top_categories": [{"label": "Trust / chain failure", "full_label": "Trust / chain failure", "count": 4}],
            "hints": [{"kind": "info", "title": "Fix trust first", "body": "Prefer trust fixes before exclusions."}],
            "domain_candidates": [
                {
                    "domain": "client.wns.windows.com",
                    "paired_invalid_requests": 12,
                    "bump_aborts": 4,
                    "ssl_events": 7,
                    "clients": 1,
                    "last_seen": 9999,
                    "score": 115,
                    "stage_label": "Stage 2 · domain splice candidate",
                    "stage_tone": "danger",
                    "confidence_label": "High confidence",
                    "summary": "12 CONNECT→invalid-request pairs; 4 bumped aborts; 7 SSL bucket events",
                }
            ],
            "client_candidates": [
                {
                    "client_ip": "192.0.2.15",
                    "cidr": "192.0.2.15/32",
                    "paired_invalid_requests": 18,
                    "distinct_domains": 3,
                    "sample_domains": ["client.wns.windows.com", "mtalk.google.com"],
                    "last_seen": 9998,
                    "stage_label": "Stage 3 · client /32 no-bump",
                    "stage_tone": "danger",
                    "confidence_label": "High confidence",
                    "summary": "18 CONNECT→invalid-request pairs across 3 domains.",
                }
            ],
            "dynamic_policy": {
                "enabled": True,
                "auto_domain_enabled": True,
                "auto_client_enabled": True,
                "review_window_seconds": 14400,
                "reconcile_interval_seconds": 300,
                "last_run_ts": 9998,
                "last_apply_ts": 9997,
                "last_result": "Dynamic client-experience protection added 1 temporary domain protection.",
                "active_domain_count": 1,
                "active_client_count": 1,
                "domains": [
                    {"domain": "client.wns.windows.com", "expires_ts": 12000, "last_seen": 9998, "evidence": "Observed traffic while protected: 22 recent requests.", "score": 62, "score_pct": 62, "state_label": "Holding", "state_tone": "warn"}
                ],
                "clients": [
                    {"cidr": "192.0.2.15/32", "expires_ts": 11000, "last_seen": 9998, "evidence": "Renewed: 18 CONNECT→invalid-request pairs across 3 domains", "score": 87, "score_pct": 87, "state_label": "Renewed", "state_tone": "ok"}
                ],
            },
        }

    def security_overview(self, *, since: int, search: str = "", limit: int = 50):
        self.calls["security"] = (since, search, limit)
        return {
            "summary": {
                "av_events": 3,
                "potential_findings": 1,
                "av_last_seen": 9998,
                "adblock_blocks": 5,
                "adblock_clients": 2,
                "adblock_last_seen": 9997,
                "webfilter_blocks": 4,
                "webfilter_clients": 2,
                "webfilter_categories": 2,
                "webfilter_last_seen": 9996,
                "combined_blocks": 9,
            },
            "av_rows": [
                {
                    "ts": 9998,
                    "client_ip": "192.0.2.5",
                    "target_display": "malware.example",
                    "url": "https://malware.example/dropper",
                    "icap_time_ms": 21,
                    "adapt_summary": "virus_scan RESPMOD Eicar FOUND",
                    "adapt_summary_short": "virus_scan RESPMOD Eicar FOUND",
                    "adapt_details_short": "Eicar test signature",
                    "master_xaction": "tx-av-1",
                    "service_family": "av",
                    "service_label": "AV / ClamAV",
                    "correlation": {"label": "Exact master transaction match", "tone": "ok"},
                    "av_status_label": "Potential finding",
                    "av_status_tone": "danger",
                }
            ],
            "av_top_targets": [{"label": "malware.example", "full_label": "malware.example", "count": 1}],
            "adblock_rows": [
                {"ts": 9997, "src_ip": "192.0.2.10", "method": "GET", "url": "https://ads.example/banner.js", "domain": "ads.example", "http_status": 403, "result": "BLOCKED"}
            ],
            "adblock_top_domains": [{"domain": "ads.example", "blocks": 5, "clients": 2, "last_seen": 9997}],
            "webfilter_rows": [
                {"ts": 9996, "src_ip": "192.0.2.11", "url": "https://adult.example/video", "domain": "adult.example", "category": "adult", "result": "BLOCKED"}
            ],
            "webfilter_top_categories": [{"category": "adult", "blocks": 4, "last_seen": 9996}],
            "webfilter_top_domains": [{"domain": "adult.example", "blocks": 4, "clients": 2, "last_seen": 9996}],
            "notes": ["AV findings are best-effort string matches."],
        }

    def performance_overview(self, *, since: int, limit: int = 10):
        self.calls["performance"] = (since, limit)
        return {
            "summary": {"requests": 12, "transactions": 9, "icap_events": 4},
            "slow_requests": [
                {
                    "ts": 9995,
                    "client_ip": "192.0.2.15",
                    "method": "GET",
                    "target_display": "slow.example",
                    "url": "https://slow.example/image.jpg",
                    "duration_ms": 812,
                    "result_summary": "TCP_MISS/200",
                    "master_xaction": "tx-slow-1",
                    "domain": "slow.example",
                }
            ],
            "slow_icap_events": [
                {
                    "ts": 9994,
                    "service_label": "AV / ClamAV",
                    "service_family": "av",
                    "target_display": "slow-av.example",
                    "url": "https://slow-av.example/file.exe",
                    "icap_time_ms": 301,
                    "adapt_summary": "virus_scan RESPMOD",
                    "adapt_summary_short": "virus_scan RESPMOD",
                    "master_xaction": "tx-icap-1",
                }
            ],
            "top_user_agents": [{"label": "Browser/1.0", "full_label": "Browser/1.0", "count": 4}],
            "top_bump_modes": [{"label": "bump", "full_label": "bump", "count": 4}],
            "top_tls_server_versions": [{"label": "TLSv1.3", "full_label": "TLSv1.3", "count": 4}],
            "top_policy_tags": [{"label": "ssl:corp-exempt", "full_label": "ssl:corp-exempt", "count": 2}],
            "av_icap_summary": {"events": 3},
            "adblock_icap_summary": {"events": 1},
        }

    def transport_overview(self, *, since: int, search: str = "", limit: int = 20):
        self.calls["transport"] = (since, search, limit)
        recent_row = type(
            "RecentSockEvent",
            (),
            {"ts": 9993, "action": "connect", "protocol": "tcp", "src_ip": "192.0.2.25", "src_port": 5555, "dst": "example.net", "dst_port": 443, "msg": "connect ok"},
        )
        return {
            "summary": {"total": 7, "connects": 5, "blocked": 1, "errors": 0, "disconnects": 1},
            "top_clients": [{"src_ip": "192.0.2.25", "events": 5, "connects": 4, "blocked": 1, "last_seen": 9993}],
            "top_destinations": [{"dst": "example.net", "dst_port": 443, "events": 5, "blocked": 1, "last_seen": 9993}],
            "recent": [recent_row],
            "nat_warning": False,
            "nat_warning_text": "",
        }

    def overview_bundle(self, *, since: int, search: str = "", limit: int = 6, resolve_hostnames: bool = False):
        self.calls["overview"] = (since, search, limit, resolve_hostnames)
        return {
            "summary": self.summary(since=since),
            "destinations": self.top_destinations(since=since, search=search, limit=limit, sort="requests"),
            "clients": self.top_clients(since=since, search=search, limit=limit, sort="requests", resolve_hostnames=resolve_hostnames),
            "cache_reasons": self.top_cache_reasons(since=since, search=search, limit=limit, sort="requests"),
            "ssl": self.ssl_overview(since=since, search=search, limit=limit),
            "security": self.security_overview(since=since, search=search, limit=limit),
            "performance": self.performance_overview(since=since, limit=limit),
            "transport": self.transport_overview(since=since, search=search, limit=limit),
        }


def test_observability_page_renders_overview_pane(monkeypatch):
    app_module = import_local_app_module()
    fake_queries = _FakeQueries()
    _install_queries(app_module, fake_queries)
    monkeypatch.setattr(app_module.time, "time", lambda: 12_000)

    client = app_module.app.test_client()
    login(client)

    response = client.get("/observability?pane=overview&window=1800&q=example&resolve_hostnames=1")
    assert response.status_code == 200
    body = response.data.decode("utf-8", errors="replace")
    assert "Largest signals" in body
    assert "Security and enforcement overview" in body
    assert "Transport health" in body
    assert fake_queries.calls["overview"] == (10_200, "example", 10, True)


def test_observability_page_defaults_to_24h_window(monkeypatch):
    app_module = import_local_app_module()
    fake_queries = _FakeQueries()
    _install_queries(app_module, fake_queries)
    monkeypatch.setattr(app_module.time, "time", lambda: 100_000)

    client = app_module.app.test_client()
    login(client)

    response = client.get("/observability")
    assert response.status_code == 200
    assert fake_queries.calls["overview"] == (13_600, "", 10, True)


def test_observability_page_renders_destination_pane(monkeypatch):
    app_module = import_local_app_module()
    fake_queries = _FakeQueries()
    _install_queries(app_module, fake_queries)
    monkeypatch.setattr(app_module.time, "time", lambda: 10_000)

    client = app_module.app.test_client()
    login(client)

    response = client.get("/observability?pane=destinations&window=3600&limit=25&sort=clients&q=example")
    assert response.status_code == 200
    body = response.data.decode("utf-8", errors="replace")
    assert "Requests by destination domain" in body
    assert "example.com" in body
    assert "Trace" in body
    assert fake_queries.calls["destinations"] == (6400, "example", 25, "clients")



def test_observability_page_renders_clients_with_hostnames(monkeypatch):
    app_module = import_local_app_module()
    fake_queries = _FakeQueries()
    _install_queries(app_module, fake_queries)
    monkeypatch.setattr(app_module.time, "time", lambda: 20_000)

    client = app_module.app.test_client()
    login(client)

    response = client.get("/observability?pane=clients&window=7200&resolve_hostnames=1")
    assert response.status_code == 200
    body = response.data.decode("utf-8", errors="replace")
    assert "Requests by client IP" in body
    assert "192.0.2.15" in body
    assert "workstation.lan" in body
    assert fake_queries.calls["clients"] == (12_800, "", 50, "requests", True)



def test_observability_export_returns_csv_for_cache_pane(monkeypatch):
    app_module = import_local_app_module()
    fake_queries = _FakeQueries()
    _install_queries(app_module, fake_queries)
    monkeypatch.setattr(app_module.time, "time", lambda: 30_000)

    client = app_module.app.test_client()
    login(client)

    response = client.get("/observability/export?pane=cache&window=1800&limit=40&sort=recent&q=post")
    assert response.status_code == 200
    body = response.data.decode("utf-8", errors="replace")
    assert "reason;requests;percent_of_misses;domains;clients;last_seen" in body
    assert "POST method (not cacheable by default)" in body
    assert fake_queries.calls["cache"] == (28_200, "post", 40, "recent")


def test_observability_page_renders_security_pane(monkeypatch):
    app_module = import_local_app_module()
    fake_queries = _FakeQueries()
    _install_queries(app_module, fake_queries)
    monkeypatch.setattr(app_module.time, "time", lambda: 40_000)

    client = app_module.app.test_client()
    login(client)

    response = client.get("/observability?pane=security&window=3600&q=malware")
    assert response.status_code == 200
    body = response.data.decode("utf-8", errors="replace")
    assert "Security and enforcement overview" in body
    assert "Potential AV findings" in body
    assert "Ad-blocking blocks" in body
    assert "Content-filtering blocks" in body
    assert "malware.example" in body
    assert fake_queries.calls["security"] == (36_400, "malware", 50)


def test_observability_export_returns_csv_for_transport_pane(monkeypatch):
    app_module = import_local_app_module()
    fake_queries = _FakeQueries()
    _install_queries(app_module, fake_queries)
    monkeypatch.setattr(app_module.time, "time", lambda: 50_000)

    client = app_module.app.test_client()
    login(client)

    response = client.get("/observability/export?pane=transport&window=7200&limit=25&q=example")
    assert response.status_code == 200
    body = response.data.decode("utf-8", errors="replace")
    assert "ts;action;protocol;client_ip;client_port;destination;destination_port;message" in body
    assert "example.net" in body
    assert fake_queries.calls["transport"] == (42_800, "example", 25)


def test_observability_export_returns_empty_overview_csv_when_query_fails(monkeypatch):
    app_module = import_local_app_module()

    class _ExplodingQueries(_FakeQueries):
        def overview_bundle(self, *, since: int, search: str = "", limit: int = 6, resolve_hostnames: bool = False):
            raise RuntimeError("boom")

    _install_queries(app_module, _ExplodingQueries())
    monkeypatch.setattr(app_module.time, "time", lambda: 60_000)

    client = app_module.app.test_client()
    login(client)

    response = client.get("/observability/export?pane=overview")
    assert response.status_code == 200
    body = response.data.decode("utf-8", errors="replace")
    assert "metric;value" in body
    assert "request_records;0" in body
    assert "adblock_icap_events;0" in body


def test_observability_page_renders_ssl_dynamic_candidates(monkeypatch):
    app_module = import_local_app_module()
    fake_queries = _FakeQueries()
    _install_queries(app_module, fake_queries)
    monkeypatch.setattr(app_module.time, "time", lambda: 70_000)

    client = app_module.app.test_client()
    login(client)

    response = client.get("/observability?pane=ssl&window=3600&q=wns")
    assert response.status_code == 200
    body = response.data.decode("utf-8", errors="replace")
    assert "Dynamic protection policy" in body
    assert "Dynamic domain candidates" in body
    assert "Dynamic client escalation candidates" in body
    assert "client.wns.windows.com" in body
    assert "192.0.2.15/32" in body
    assert "Add exclusion" in body
    assert "Add /32 no-bump" in body
    assert "Run protection pass now" in body
    assert "Holding" in body
    assert "Score" in body
    assert fake_queries.calls["ssl"] == (66_400, "wns", 50)
