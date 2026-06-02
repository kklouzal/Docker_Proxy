from __future__ import annotations

import os
import pathlib
import sys

import pytest

from .mysql_test_utils import configure_test_mysql_env


def _add_web_to_path() -> None:
    web_dir = pathlib.Path(os.path.join(pathlib.Path(__file__).parent, "..")).resolve()
    if web_dir not in sys.path:
        sys.path.insert(0, web_dir)


def _request_line(
    *,
    ts: int,
    client_ip: str,
    method: str,
    url: str,
    result_code: str,
    duration_ms: int = 25,
    bytes_sent: int = 0,
    master_xaction: str = "",
    bump_mode: str = "bump",
    response_content_type: str = "",
    response_server: str = "",
    response_cf_mitigated: str = "",
    response_alt_svc: str = "",
) -> str:
    fields = [
        str(ts),
        str(duration_ms),
        client_ip,
        method,
        url,
        result_code,
        str(bytes_sent),
        master_xaction,
        "DIRECT",
        bump_mode,
        "",
        "TLSv1.3",
        "TLS_AES_256_GCM_SHA384",
        "TLSv1.3",
        "TLS_AES_128_GCM_SHA256",
        "",
        "pytest/1.0",
        "-",
        "",
        "",
        "",
        "",
        response_content_type,
        response_server,
        response_cf_mitigated,
        response_alt_svc,
    ]
    return "\t".join(fields)


def _icap_line(
    *,
    ts: int,
    master_xaction: str,
    client_ip: str,
    method: str,
    url: str,
    icap_time_ms: int,
    adapt_summary: str,
    adapt_details: str,
) -> str:
    fields = [
        str(ts),
        master_xaction,
        client_ip,
        method,
        url,
        str(icap_time_ms),
        adapt_summary,
        adapt_details,
        "",
        "pytest/1.0",
        "",
        "",
        "",
        "",
        "",
    ]
    return "\t".join(fields)


def _insert_request(diag_store, line: str) -> None:
    with diag_store._connect() as conn:
        assert diag_store._ingest_request_line_with_conn(conn, line)


def _insert_icap(diag_store, line: str) -> None:
    with diag_store._connect() as conn:
        assert diag_store._ingest_icap_line_with_conn(conn, line)


def test_remediation_suggestion_search_matches_all_visible_fields() -> None:
    _add_web_to_path()
    from services.observability_queries import ObservabilityQueries  # type: ignore

    row = ObservabilityQueries._suggestion_row(
        kind="runtime_icap_degraded",
        component="ICAP / ClamAV health",
        severity="high",
        title="ICAP or ClamAV runtime health is degraded",
        subject="livingroom",
        count=1,
        clients=0,
        last_seen=3030,
        confidence="high",
        recommended_action="Check supervisor state and c-icap listeners.",
        evidence="clamd unreachable",
    )

    assert ObservabilityQueries._suggestion_matches_search(row, "clamd")
    assert ObservabilityQueries._suggestion_matches_search(row, "livingroom")
    assert row["subject_type"] == "domain"
    assert not ObservabilityQueries._suggestion_matches_search(row, "video")


def test_remediation_search_does_not_hide_generated_suggestion_fields(
    monkeypatch,
) -> None:
    _add_web_to_path()
    from services import observability_queries  # type: ignore

    class FakeResult:
        def __init__(self, rows):
            self._rows = rows

        def fetchall(self):
            return self._rows

    class FakeConnection:
        def __init__(self):
            self.executed_sql: list[str] = []

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, sql, _params=()):
            self.executed_sql.append(str(sql))
            if "LOWER(domain) LIKE" in sql:
                return FakeResult([])
            if "response_alt_svc" in sql and "REGEXP '(^|[^a-z0-9])h3[-=]'" in sql:
                return FakeResult(
                    [("stream.example", 2, 1, 4000, 'h3=":443"; ma=86400')],
                )
            return FakeResult([])

    fake_conn = FakeConnection()
    queries = observability_queries.ObservabilityQueries()
    monkeypatch.setattr(queries, "_connect", lambda: fake_conn)
    monkeypatch.setattr(
        queries,
        "ssl_overview",
        lambda **_kwargs: {"exclusion_candidates": []},
    )

    payload = queries.remediation_overview(
        since=3900,
        search="quic",
        limit=10,
        summary={"requests": 0},
    )

    assert [row["kind"] for row in payload["rows"]] == ["http3_alt_svc"]
    assert payload["rows"][0]["component"] == "HTTP/3 / QUIC routing"
    assert all("LOWER(domain) LIKE" not in sql for sql in fake_conn.executed_sql)


def test_remediation_search_does_not_hide_ssl_generated_actions(
    monkeypatch,
) -> None:
    _add_web_to_path()
    from services import observability_queries  # type: ignore

    class FakeResult:
        def fetchall(self):
            return []

    class FakeConnection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, _sql, _params=()):
            return FakeResult()

    queries = observability_queries.ObservabilityQueries()

    def _connect():
        return FakeConnection()

    monkeypatch.setattr(queries, "_connect", _connect)

    ssl_searches: list[str] = []

    def _ssl_overview(**kwargs):
        search = str(kwargs.get("search") or "")
        ssl_searches.append(search)
        if search:
            return {"exclusion_candidates": []}
        return {
            "exclusion_candidates": [
                {
                    "domain": "tls.example",
                    "total": 5,
                    "last_seen": 4100,
                    "reason": "certificate verify failure",
                },
            ],
        }

    monkeypatch.setattr(queries, "ssl_overview", _ssl_overview)

    payload = queries.remediation_overview(
        since=4000,
        search="no-bump",
        limit=10,
        summary={"requests": 0},
    )

    assert ssl_searches == ["no-bump", ""]
    assert [row["kind"] for row in payload["rows"]] == ["ssl_exclusion_candidate"]
    assert payload["rows"][0]["subject"] == "tls.example"
    assert payload["rows"][0]["count"] == 5
    assert payload["rows"][0]["severity"] == "high"
    assert payload["summary"]["observations"] == 5


def test_remediation_summary_separates_domain_and_runtime_subjects(
    monkeypatch,
) -> None:
    _add_web_to_path()
    from services import observability_queries  # type: ignore

    class FakeResult:
        def __init__(self, rows):
            self._rows = rows

        def fetchall(self):
            return self._rows

    class FakeConnection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, sql, _params=()):
            if "response_alt_svc" in str(sql):
                return FakeResult(
                    [("video.example", 2, 1, 4000, 'h3=":443"; ma=86400')],
                )
            return FakeResult([])

    queries = observability_queries.ObservabilityQueries()

    def _connect():
        return FakeConnection()

    monkeypatch.setattr(queries, "_connect", _connect)
    monkeypatch.setattr(
        queries,
        "ssl_overview",
        lambda **_kwargs: {"exclusion_candidates": []},
    )

    payload = queries.remediation_overview(
        since=3900,
        limit=10,
        summary={"requests": 0},
        runtime_health={
            "proxy_id": "livingroom",
            "status": "degraded",
            "timestamp": 4100,
            "stats": {"memory": {"used_percent": 90.0}},
        },
    )

    assert {row["kind"] for row in payload["rows"]} == {
        "http3_alt_svc",
        "memory_pressure",
    }
    assert payload["summary"]["domains"] == 1
    assert payload["summary"]["runtime_subjects"] == 1


def test_remediation_runtime_health_bad_timestamp_degrades_safely(
    monkeypatch,
) -> None:
    _add_web_to_path()
    from services import observability_queries  # type: ignore

    class FakeResult:
        def fetchall(self):
            return []

    class FakeConnection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, _sql, _params=()):
            return FakeResult()

    def _connect():
        return FakeConnection()

    queries = observability_queries.ObservabilityQueries()
    monkeypatch.setattr(queries, "_connect", _connect)
    monkeypatch.setattr(
        queries,
        "ssl_overview",
        lambda **_kwargs: {"exclusion_candidates": []},
    )
    monkeypatch.setattr(observability_queries.time, "time", lambda: 5150)

    payload = queries.remediation_overview(
        since=5000,
        limit=10,
        summary={"request_records": 0},
        runtime_health={
            "proxy_id": "livingroom",
            "status": "degraded",
            "timestamp": "bad-runtime-clock",
            "stats": {"memory": {"used_percent": 90.0}},
        },
    )

    assert [row["kind"] for row in payload["rows"]] == ["memory_pressure"]
    assert payload["rows"][0]["last_seen"] == 5150
    assert payload["summary"]["runtime_subjects"] == 1


def test_remediation_runtime_state_errors_surface_generated_state_drift(
    monkeypatch,
) -> None:
    _add_web_to_path()
    from services import observability_queries  # type: ignore

    class FakeResult:
        def fetchall(self):
            return []

    class FakeConnection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, _sql, _params=()):
            return FakeResult()

    def _connect():
        return FakeConnection()

    queries = observability_queries.ObservabilityQueries()
    monkeypatch.setattr(queries, "_connect", _connect)
    monkeypatch.setattr(
        queries,
        "ssl_overview",
        lambda **_kwargs: {"exclusion_candidates": []},
    )

    payload = queries.remediation_overview(
        since=5000,
        search="pac",
        limit=10,
        summary={"request_records": 0},
        runtime_health={
            "proxy_id": "livingroom",
            "status": "degraded",
            "timestamp": 5200,
            "state_errors": [
                "config drift: active revision does not match runtime",
                "PAC drift: desired state does not match runtime",
                "MySQL lock wait timeout while reading policy state",
            ],
        },
    )

    assert [row["kind"] for row in payload["rows"]] == ["runtime_state_degraded"]
    row = payload["rows"][0]
    assert row["subject"] == "livingroom"
    assert row["subject_type"] == "proxy"
    assert row["count"] == 2
    assert row["component"] == "Proxy generated state"
    assert "PAC drift" in row["evidence"]
    assert "MySQL" not in row["evidence"]
    assert payload["summary"]["runtime_subjects"] == 1


def test_remediation_runtime_state_errors_accept_scalar_payload(
    monkeypatch,
) -> None:
    _add_web_to_path()
    from services import observability_queries  # type: ignore

    class FakeResult:
        def fetchall(self):
            return []

    class FakeConnection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, _sql, _params=()):
            return FakeResult()

    def _connect():
        return FakeConnection()

    queries = observability_queries.ObservabilityQueries()
    monkeypatch.setattr(queries, "_connect", _connect)
    monkeypatch.setattr(
        queries,
        "ssl_overview",
        lambda **_kwargs: {"exclusion_candidates": []},
    )

    payload = queries.remediation_overview(
        since=5000,
        limit=10,
        summary={"request_records": 0},
        runtime_health={
            "proxy_id": "livingroom",
            "status": "degraded",
            "timestamp": 5200,
            "state_errors": "PAC drift: desired state does not match runtime",
        },
    )

    assert [row["kind"] for row in payload["rows"]] == ["runtime_state_degraded"]
    row = payload["rows"][0]
    assert row["count"] == 1
    assert row["evidence"] == "PAC drift: desired state does not match runtime"
    assert payload["summary"]["runtime_subjects"] == 1


def test_remediation_search_keeps_runtime_state_drift_visible(monkeypatch) -> None:
    _add_web_to_path()
    from services import observability_queries  # type: ignore

    class FakeResult:
        def __init__(self, rows):
            self._rows = rows

        def fetchall(self):
            return self._rows

    class FakeConnection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, sql, _params=()):
            if "result_code LIKE 'TCP_MISS_ABORTED/%%'" in str(sql):
                return FakeResult(
                    [("video.example", 3, 1, 5300, "video/iso.segment")],
                )
            return FakeResult([])

    queries = observability_queries.ObservabilityQueries()

    def _connect():
        return FakeConnection()

    monkeypatch.setattr(queries, "_connect", _connect)
    monkeypatch.setattr(
        queries,
        "ssl_overview",
        lambda **_kwargs: {"exclusion_candidates": []},
    )

    payload = queries.remediation_overview(
        since=5000,
        search="video",
        limit=10,
        summary={"request_records": 0},
        runtime_health={
            "proxy_id": "livingroom",
            "status": "degraded",
            "timestamp": 5301,
            "state_errors": [
                "PAC: desired desired-pac- does not match current current-pac-.",
            ],
        },
    )

    assert {row["kind"] for row in payload["rows"]} == {
        "aborted_media_segments",
        "runtime_state_degraded",
    }
    assert payload["summary"]["domains"] == 1
    assert payload["summary"]["runtime_subjects"] == 1


def test_observability_queries_roll_up_destinations_clients_and_cache_reasons(
    tmp_path, monkeypatch
) -> None:
    _add_web_to_path()
    configure_test_mysql_env(tmp_path / "observability-queries")

    from services import observability_queries  # type: ignore
    from services.diagnostic_store import DiagnosticStore  # type: ignore

    diag_store = DiagnosticStore()
    diag_store.init_db()
    queries = observability_queries.ObservabilityQueries()

    _insert_request(
        diag_store,
        _request_line(
            ts=2000,
            client_ip="192.0.2.10",
            method="GET",
            url="https://alpha.example/hit",
            result_code="TCP_HIT/200",
            bytes_sent=100,
            master_xaction="tx-alpha-1",
        ),
    )
    _insert_request(
        diag_store,
        _request_line(
            ts=2005,
            client_ip="192.0.2.10",
            method="POST",
            url="https://alpha.example/api",
            result_code="TCP_MISS/200",
            bytes_sent=110,
            master_xaction="tx-alpha-2",
        ),
    )
    _insert_request(
        diag_store,
        _request_line(
            ts=2010,
            client_ip="192.0.2.10",
            method="POST",
            url="https://alpha.example/api/next",
            result_code="TCP_MISS/200",
            bytes_sent=120,
            master_xaction="tx-alpha-3",
        ),
    )
    _insert_request(
        diag_store,
        _request_line(
            ts=2020,
            client_ip="192.0.2.11",
            method="GET",
            url="https://beta.example/home",
            result_code="TCP_BYPASS/200",
            bytes_sent=130,
            master_xaction="tx-beta-1",
        ),
    )
    _insert_request(
        diag_store,
        _request_line(
            ts=900,
            client_ip="192.0.2.55",
            method="GET",
            url="https://stale.example/old",
            result_code="TCP_MISS/200",
            bytes_sent=50,
            master_xaction="tx-stale",
        ),
    )

    _insert_icap(
        diag_store,
        _icap_line(
            ts=2006,
            master_xaction="tx-alpha-2",
            client_ip="192.0.2.10",
            method="POST",
            url="https://alpha.example/api",
            icap_time_ms=25,
            adapt_summary="virus_scan RESPMOD",
            adapt_details="clean",
        ),
    )
    _insert_icap(
        diag_store,
        _icap_line(
            ts=2021,
            master_xaction="tx-beta-1",
            client_ip="192.0.2.11",
            method="GET",
            url="https://beta.example/home",
            icap_time_ms=11,
            adapt_summary="adblockreq REQMOD",
            adapt_details="blocked banner",
        ),
    )

    class FakeClientCache:
        def resolve_many(self, ips):
            return {
                "192.0.2.10": {
                    "hostname": "workstation.lan",
                    "hostname_source": "rdns",
                    "hostname_status": "resolved",
                },
                "192.0.2.11": {
                    "hostname": "tablet.lan",
                    "hostname_source": "rdns",
                    "hostname_status": "resolved",
                },
            }

    monkeypatch.setattr(
        observability_queries, "get_client_identity_cache", FakeClientCache
    )

    summary = queries.summary(since=1800)
    assert summary == {
        "request_records": 4,
        "cache_hits": 1,
        "cache_misses": 3,
        "cache_hit_pct": 25.0,
        "clients": 2,
        "destinations": 2,
        "transactions": 4,
        "icap_events": 2,
        "av_icap_events": 1,
        "adblock_icap_events": 1,
    }

    destinations = queries.top_destinations(since=1800, limit=10, sort="requests")
    assert destinations[0]["domain"] == "alpha.example"
    assert destinations[0]["requests"] == 3
    assert destinations[0]["clients"] == 1
    assert destinations[0]["transactions"] == 3
    assert destinations[0]["cache_pct"] == pytest.approx(33.3)
    assert destinations[0]["av_icap_events"] == 1
    assert destinations[0]["adblock_icap_events"] == 0

    clients = queries.top_clients(
        since=1800, limit=10, sort="requests", resolve_hostnames=True
    )
    assert clients[0]["ip"] == "192.0.2.10"
    assert clients[0]["hostname"] == "workstation.lan"
    assert clients[0]["requests"] == 3
    assert clients[0]["destinations"] == 1
    assert clients[0]["transactions"] == 3
    assert clients[0]["av_icap_events"] == 1

    reasons = queries.top_cache_reasons(since=1800, limit=10, sort="requests")
    assert reasons[0] == {
        "reason": "POST method (not cacheable by default)",
        "requests": 2,
        "domains": 1,
        "clients": 1,
        "last_seen": 2010,
        "pct": 66.7,
    }
    assert reasons[1]["reason"] == "Bypassed (cache deny rule or client no-cache)"
    assert reasons[1]["requests"] == 1


def test_observability_queries_surface_ssl_security_and_performance(
    tmp_path, monkeypatch
) -> None:
    _add_web_to_path()
    configure_test_mysql_env(tmp_path / "observability-hub")

    from services import observability_queries  # type: ignore
    from services.adblock_store import AdblockStore  # type: ignore
    from services.diagnostic_store import DiagnosticStore  # type: ignore
    from services.ssl_errors_store import SslErrorsStore  # type: ignore
    from services.webfilter_store import WebFilterStore  # type: ignore

    diag_store = DiagnosticStore()
    diag_store.init_db()
    ssl_store = SslErrorsStore()
    ssl_store.init_db()
    adblock_store = AdblockStore(lists_dir=str(tmp_path / "adblock-lists"))
    adblock_store.init_db()
    webfilter_store = WebFilterStore()
    webfilter_store.init_db()
    queries = observability_queries.ObservabilityQueries()

    _insert_request(
        diag_store,
        _request_line(
            ts=3000,
            client_ip="192.0.2.40",
            method="GET",
            url="https://tls.example/app",
            result_code="TCP_MISS/200",
            bytes_sent=200,
            master_xaction="tx-find-1",
        ),
    )
    _insert_request(
        diag_store,
        _request_line(
            ts=3010,
            client_ip="192.0.2.41",
            method="GET",
            url="https://ads.example/banner.js",
            result_code="TCP_BYPASS/200",
            bytes_sent=120,
            master_xaction="tx-block-1",
        ),
    )
    _insert_request(
        diag_store,
        _request_line(
            ts=3025,
            client_ip="192.0.2.42",
            method="CONNECT",
            url="id.evidence.com:443",
            result_code="TCP_TUNNEL/200",
            duration_ms=2589651,
            master_xaction="tx-tunnel-1",
        ),
    )
    _insert_icap(
        diag_store,
        _icap_line(
            ts=3002,
            master_xaction="tx-find-1",
            client_ip="192.0.2.40",
            method="GET",
            url="https://malware.example/dropper.exe",
            icap_time_ms=44,
            adapt_summary="virus_scan RESPMOD Eicar FOUND",
            adapt_details="Malware blocked by scanner",
        ),
    )

    with ssl_store._connect() as conn:
        row_key = ssl_store._row_key(
            "default", "tls.example", "CERT_VERIFY", "certificate verify failed"
        )
        conn.execute(
            """
            INSERT INTO ssl_errors(row_key, proxy_id, domain, category, reason, count, first_seen, last_seen, sample)
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            (
                row_key,
                "default",
                "tls.example",
                "CERT_VERIFY",
                "certificate verify failed",
                5,
                2900,
                3005,
                "CONNECT tls.example:443",
            ),
        )

    with adblock_store._connect() as conn:
        conn.execute(
            """
            INSERT INTO adblock_events(proxy_id, event_key, ts, src_ip, method, url, http_status, http_resp_line, icap_status, raw, created_ts)
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            (
                "default",
                "a" * 40,
                3015,
                "192.0.2.41",
                "GET",
                "https://ads.example/banner.js",
                403,
                "HTTP/1.1 403 Forbidden",
                204,
                "blocked",
                3015,
            ),
        )

    with webfilter_store._connect() as conn:
        conn.execute(
            "INSERT INTO webfilter_blocked_log(proxy_id, ts, src_ip, url, category) VALUES(%s,%s,%s,%s,%s)",
            ("default", 3020, "192.0.2.42", "id.evidence.com:443", "adult"),
        )

    monkeypatch.setattr(
        observability_queries, "get_diagnostic_store", lambda: diag_store
    )
    monkeypatch.setattr(
        observability_queries, "get_ssl_errors_store", lambda: ssl_store
    )
    monkeypatch.setattr(
        observability_queries, "get_adblock_store", lambda: adblock_store
    )
    monkeypatch.setattr(
        observability_queries, "get_webfilter_store", lambda: webfilter_store
    )

    ssl_payload = queries.ssl_overview(since=2800, limit=10)
    assert ssl_payload["summary"]["bucket_count"] == 1
    assert ssl_payload["summary"]["total_events"] == 5
    assert ssl_payload["top_domains"][0]["domain"] == "tls.example"

    security_payload = queries.security_overview(since=2800, limit=10)
    assert security_payload["summary"]["potential_findings"] == 1
    assert security_payload["summary"]["adblock_blocks"] == 1
    assert security_payload["summary"]["webfilter_blocks"] == 1
    assert security_payload["av_rows"][0]["av_status_label"] == "Potential finding"
    assert (
        security_payload["av_rows"][0]["correlated_request"]["client_ip"]
        == "192.0.2.40"
    )
    assert (
        security_payload["adblock_rows"][0]["correlated_candidates"][0]["client_ip"]
        == "192.0.2.41"
    )
    assert (
        security_payload["webfilter_rows"][0]["correlated_candidates"][0]["client_ip"]
        == "192.0.2.42"
    )
    assert security_payload["adblock_top_domains"][0]["domain"] == "ads.example"
    assert security_payload["webfilter_top_categories"][0]["category"] == "adult"

    performance_payload = queries.performance_overview(since=2800, limit=10)
    assert performance_payload["slow_requests"][0]["target_display"] == "ads.example"
    assert (
        performance_payload["slow_icap_events"][0]["target_display"]
        == "malware.example"
    )
    assert performance_payload["top_user_agents"][0]["label"] == "pytest/1.0"

    overview = queries.overview_bundle(since=2800, limit=5, resolve_hostnames=False)
    assert overview["summary"]["request_records"] == 3
    assert overview["ssl"]["summary"]["total_events"] == 5
    assert overview["security"]["summary"]["combined_blocks"] == 2


def test_observability_overview_bundle_reuses_precomputed_summary(
    tmp_path, monkeypatch
) -> None:
    _add_web_to_path()
    configure_test_mysql_env(tmp_path / "observability-queries-summary-reuse")

    from services import observability_queries  # type: ignore

    queries = observability_queries.ObservabilityQueries()
    summary_calls = {"count": 0}

    def _summary(**_kwargs):
        summary_calls["count"] += 1
        return {
            "request_records": 7,
            "cache_hits": 3,
            "cache_misses": 4,
            "cache_hit_pct": 42.9,
            "clients": 2,
            "destinations": 2,
            "transactions": 7,
            "icap_events": 1,
            "av_icap_events": 1,
            "adblock_icap_events": 0,
        }

    monkeypatch.setattr(queries, "summary", _summary)
    monkeypatch.setattr(queries, "top_destinations", lambda **_kwargs: [])
    monkeypatch.setattr(queries, "top_clients", lambda **_kwargs: [])
    monkeypatch.setattr(queries, "top_cache_reasons", lambda **_kwargs: [])
    monkeypatch.setattr(
        queries,
        "ssl_overview",
        lambda **_kwargs: {
            "summary": {},
            "rows": [],
            "top_domains": [],
            "exclusion_candidates": [],
            "top_categories": [],
            "hints": [],
        },
    )
    monkeypatch.setattr(
        queries,
        "security_overview",
        lambda **_kwargs: {
            "summary": {},
            "av_rows": [],
            "av_top_targets": [],
            "adblock_rows": [],
            "adblock_top_domains": [],
            "webfilter_rows": [],
            "webfilter_top_categories": [],
            "webfilter_top_domains": [],
            "notes": [],
        },
    )
    monkeypatch.setattr(
        queries,
        "performance_overview",
        lambda **_kwargs: {
            "summary": {},
            "slow_requests": [],
            "slow_icap_events": [],
            "top_user_agents": [],
            "top_bump_modes": [],
            "top_tls_server_versions": [],
            "top_policy_tags": [],
            "av_icap_summary": {},
            "adblock_icap_summary": {},
        },
    )

    payload = queries.overview_bundle(
        since=2800, limit=5, resolve_hostnames=False, summary=_summary()
    )

    assert summary_calls["count"] == 1
    assert payload["summary"]["request_records"] == 7


def test_observability_performance_overview_reuses_precomputed_summary(
    tmp_path, monkeypatch
) -> None:
    _add_web_to_path()
    configure_test_mysql_env(
        tmp_path / "observability-queries-performance-summary-reuse"
    )

    from services import observability_queries  # type: ignore

    class CountingDiagnosticStore:
        def __init__(self) -> None:
            self.activity_summary_calls = 0

        def activity_summary(self, *, since):
            self.activity_summary_calls += 1
            return {
                "request_records": 1,
                "cache_hits": 1,
                "cache_misses": 0,
                "cache_hit_pct": 100.0,
                "clients": 1,
                "destinations": 1,
                "transactions": 1,
                "icap_events": 0,
                "av_icap_events": 0,
                "adblock_icap_events": 0,
            }

        def slowest_requests(self, **_kwargs):
            return []

        def slowest_icap_events(self, **_kwargs):
            return []

        def top_request_dimension(self, _dimension, **_kwargs):
            return []

        def top_policy_tags(self, **_kwargs):
            return []

        def icap_summary(self, **_kwargs):
            return {"events": 0, "avg_icap_time_ms": 0, "max_icap_time_ms": 0}

        def list_recent_icap(self, **_kwargs):
            return []

    fake_store = CountingDiagnosticStore()
    monkeypatch.setattr(
        observability_queries, "get_diagnostic_store", lambda: fake_store
    )

    queries = observability_queries.ObservabilityQueries()
    payload = queries.performance_overview(
        since=2800,
        limit=5,
        summary={
            "requests": 1,
            "cache_hits": 1,
            "cache_misses": 0,
            "cache_hit_pct": 100.0,
            "clients": 1,
            "destinations": 1,
            "transactions": 1,
            "icap_events": 0,
            "av_icap_events": 0,
            "adblock_icap_events": 0,
        },
    )

    assert fake_store.activity_summary_calls == 0
    assert payload["summary"]["requests"] == 1


def test_observability_reporting_overview_correlates_bandwidth_security_ssl_and_privacy(
    tmp_path, monkeypatch
) -> None:
    _add_web_to_path()
    configure_test_mysql_env(tmp_path / "observability-reporting-overview")

    from services import observability_queries  # type: ignore
    from services.adblock_store import AdblockStore  # type: ignore
    from services.audit_store import AuditStore  # type: ignore
    from services.diagnostic_store import DiagnosticStore  # type: ignore
    from services.ssl_errors_store import SslErrorsStore  # type: ignore
    from services.webfilter_store import WebFilterStore  # type: ignore

    diag_store = DiagnosticStore()
    diag_store.init_db()
    ssl_store = SslErrorsStore()
    ssl_store.init_db()
    adblock_store = AdblockStore(lists_dir=str(tmp_path / "adblock-lists-reporting"))
    adblock_store.init_db()
    webfilter_store = WebFilterStore()
    webfilter_store.init_db()
    audit_store = AuditStore()
    audit_store.init_db()

    _insert_request(
        diag_store,
        _request_line(
            ts=4100,
            client_ip="192.0.2.80",
            method="GET",
            url="https://files.example/iso",
            result_code="TCP_HIT/200",
            bytes_sent=4096,
            master_xaction="tx-report-1",
        ),
    )
    _insert_request(
        diag_store,
        _request_line(
            ts=4110,
            client_ip="192.0.2.80",
            method="CONNECT",
            url="updates.example:443",
            result_code="TCP_TUNNEL/200",
            bytes_sent=2048,
            master_xaction="tx-report-2",
            bump_mode="splice",
        ),
    )
    _insert_icap(
        diag_store,
        _icap_line(
            ts=4120,
            master_xaction="tx-malware-1",
            client_ip="192.0.2.80",
            method="GET",
            url="https://phishing.example/payload",
            icap_time_ms=15,
            adapt_summary="virus_scan RESPMOD Malware FOUND",
            adapt_details="phishing payload blocked",
        ),
    )

    with webfilter_store._connect() as conn:
        conn.execute(
            "INSERT INTO webfilter_blocked_log(proxy_id, ts, src_ip, url, category) VALUES(%s,%s,%s,%s,%s)",
            ("default", 4130, "192.0.2.80", "https://games.example/play", "games"),
        )
    with ssl_store._connect() as conn:
        row_key = ssl_store._row_key(
            "default", "updates.example", "HANDSHAKE", "bump handshake failed"
        )
        conn.execute(
            """
            INSERT INTO ssl_errors(row_key, proxy_id, domain, category, reason, count, first_seen, last_seen, sample)
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            (
                row_key,
                "default",
                "updates.example",
                "HANDSHAKE",
                "bump handshake failed",
                3,
                4105,
                4115,
                "CONNECT updates.example:443",
            ),
        )
    audit_store.record(
        kind="config_apply_manual",
        ok=True,
        remote_addr="127.0.0.1",
        detail="applied reporting test config",
    )

    monkeypatch.setattr(
        observability_queries, "get_diagnostic_store", lambda: diag_store
    )
    monkeypatch.setattr(
        observability_queries, "get_ssl_errors_store", lambda: ssl_store
    )
    monkeypatch.setattr(
        observability_queries, "get_adblock_store", lambda: adblock_store
    )
    monkeypatch.setattr(
        observability_queries, "get_webfilter_store", lambda: webfilter_store
    )

    queries = observability_queries.ObservabilityQueries()
    queries.save_report_schedule(
        name="Daily accountability digest",
        cadence="daily",
        recipients="ops@example.com",
        pane="reports",
        report_format="jsonl",
        privacy=True,
        window_seconds=86400,
    )
    payload = queries.reporting_overview(
        since=4000,
        search="example",
        limit=10,
        resolve_hostnames=False,
        privacy=True,
    )

    assert payload["cache_savings"]["estimated_saved_bytes"] == 4096
    assert payload["top_users"][0]["client_label"].startswith("user-")
    assert payload["top_users"][0]["client_label"] != "192.0.2.80"
    assert payload["top_users"][0]["client_ip"] == ""
    assert payload["top_blocked_categories"][0]["category"] == "games"
    assert payload["top_malware_attempts"][0]["domain"] == "phishing.example"
    assert payload["top_malware_attempts"][0]["client_label"].startswith("user-")
    assert payload["top_malware_attempts"][0]["client_ip"] == ""
    assert payload["top_ssl_bump_failures"][0]["domain"] == "updates.example"
    assert payload["top_spliced_destinations"][0]["domain"] == "updates.example"
    assert payload["per_group"][0]["group"].startswith("group-")
    assert payload["audit"]["summary"]["events"] >= 1
    assert payload["schedules"][0]["name"] == "Daily accountability digest"
    assert any(
        row["name"] == "Prometheus" and row["status"] == "ready"
        for row in payload["export_contracts"]
    )
    assert any(
        row["name"] == "SIEM/syslog" and row["status"] == "ready"
        for row in payload["export_contracts"]
    )
    assert any(
        row["name"] == "Scheduled email" and row["status"] == "configured"
        for row in payload["export_contracts"]
    )


def test_remediation_overview_surfaces_quic_cloudflare_and_icap_signals(
    tmp_path,
) -> None:
    _add_web_to_path()
    configure_test_mysql_env(tmp_path / "observability-remediation")

    from services import observability_queries  # type: ignore
    from services.diagnostic_store import DiagnosticStore  # type: ignore

    diag_store = DiagnosticStore()
    diag_store.init_db()
    queries = observability_queries.ObservabilityQueries()

    _insert_request(
        diag_store,
        _request_line(
            ts=3000,
            client_ip="192.0.2.10",
            method="GET",
            url="https://video.example/watch",
            result_code="TCP_MISS/403",
            master_xaction="tx-cf",
            response_server="cloudflare",
            response_cf_mitigated="challenge",
            response_alt_svc='h3=":443"; ma=86400',
        ),
    )
    for offset in range(3):
        _insert_request(
            diag_store,
            _request_line(
                ts=3010 + offset,
                client_ip="192.0.2.10",
                method="GET",
                url=f"https://cdn.example/video/seg-000{offset}.m4s",
                result_code="TCP_MISS_ABORTED/200",
                master_xaction=f"tx-media-{offset}",
                response_content_type="video/iso.segment",
            ),
        )
    _insert_icap(
        diag_store,
        _icap_line(
            ts=3020,
            master_xaction="tx-icap",
            client_ip="192.0.2.10",
            method="GET",
            url="https://scan.example/file.bin",
            icap_time_ms=1500,
            adapt_summary="virus_scan RESPMOD timeout",
            adapt_details="clamd timeout bypassed",
        ),
    )

    runtime_health = {
        "proxy_id": "livingroom",
        "status": "degraded",
        "timestamp": 3030,
        "services": {"clamd": {"ok": False, "detail": "clamd unreachable"}},
        "stats": {
            "memory": {
                "used_percent": 91.5,
                "available_bytes": 128 * 1024 * 1024,
            },
        },
        "state_errors": ["MySQL lock wait timeout while reading policy state"],
    }

    payload = queries.remediation_overview(
        since=2990,
        limit=20,
        runtime_health=runtime_health,
    )
    kinds = {row["kind"]: row for row in payload["rows"]}

    assert kinds["cloudflare_challenge"]["count"] == 1
    assert kinds["http3_alt_svc"]["subject"] == "video.example"
    assert kinds["aborted_media_segments"]["count"] == 3
    assert kinds["slow_icap"]["component"] == "ICAP av"
    assert kinds["icap_degraded"]["confidence"] == "high"
    assert kinds["runtime_icap_degraded"]["subject"] == "livingroom"
    assert kinds["runtime_icap_degraded"]["subject_type"] == "proxy"
    assert kinds["memory_pressure"]["subject_type"] == "proxy"
    assert kinds["mysql_degraded"]["subject_type"] == "proxy"
    assert kinds["http3_alt_svc"]["subject_type"] == "domain"
    assert kinds["memory_pressure"]["component"] == "Proxy runtime resources"
    assert kinds["mysql_degraded"]["component"] == "MySQL / observability ingestion"
    assert payload["summary"]["observations"] >= 10
    assert payload["summary"]["domains"] == 3
    assert payload["summary"]["runtime_subjects"] == 1
    assert payload["summary"]["http3_candidates"] == 1

    video_payload = queries.remediation_overview(
        since=2990,
        search="video",
        limit=20,
        runtime_health=runtime_health,
    )
    assert {row["kind"] for row in video_payload["rows"]} == {
        "aborted_media_segments",
        "cloudflare_challenge",
        "http3_alt_svc",
    }

    h3_payload = queries.remediation_overview(
        since=2990,
        search="h3",
        limit=20,
        runtime_health=runtime_health,
    )
    assert {row["kind"] for row in h3_payload["rows"]} == {"http3_alt_svc"}

    cloudflare_payload = queries.remediation_overview(
        since=2990,
        search="cloudflare",
        limit=20,
        runtime_health=runtime_health,
    )
    assert {row["kind"] for row in cloudflare_payload["rows"]} == {
        "cloudflare_challenge",
    }

    media_payload = queries.remediation_overview(
        since=2990,
        search="iso.segment",
        limit=20,
        runtime_health=runtime_health,
    )
    assert {row["kind"] for row in media_payload["rows"]} == {
        "aborted_media_segments",
    }

    icap_payload = queries.remediation_overview(
        since=2990,
        search="scan",
        limit=20,
        runtime_health=runtime_health,
    )
    assert {row["kind"] for row in icap_payload["rows"]} == {
        "icap_degraded",
        "slow_icap",
    }
