from __future__ import annotations

import os
import sys

from .mysql_test_utils import configure_test_mysql_env


def _add_web_to_path() -> None:
    web_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if web_dir not in sys.path:
        sys.path.insert(0, web_dir)


def _request_line(
    *,
    ts: int,
    client_ip: str,
    method: str,
    url: str,
    result_code: str,
    bytes_sent: int = 0,
    master_xaction: str = "",
) -> str:
    fields = [
        str(ts),
        "25",
        client_ip,
        method,
        url,
        result_code,
        str(bytes_sent),
        master_xaction,
        "DIRECT",
        "bump",
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


def test_observability_queries_roll_up_destinations_clients_and_cache_reasons(tmp_path, monkeypatch):
    _add_web_to_path()
    configure_test_mysql_env(tmp_path / "observability-queries")

    from services.diagnostic_store import DiagnosticStore  # type: ignore
    import services.observability_queries as observability_queries  # type: ignore

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

    monkeypatch.setattr(observability_queries, "get_client_identity_cache", lambda: FakeClientCache())

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
    assert destinations[0]["cache_pct"] == 33.3
    assert destinations[0]["av_icap_events"] == 1
    assert destinations[0]["adblock_icap_events"] == 0

    clients = queries.top_clients(since=1800, limit=10, sort="requests", resolve_hostnames=True)
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


def test_observability_queries_surface_ssl_security_and_performance(tmp_path, monkeypatch):
    _add_web_to_path()
    configure_test_mysql_env(tmp_path / "observability-hub")

    from services.adblock_store import AdblockStore  # type: ignore
    from services.diagnostic_store import DiagnosticStore  # type: ignore
    from services.ssl_errors_store import SslErrorsStore  # type: ignore
    from services.webfilter_store import WebFilterStore  # type: ignore
    import services.observability_queries as observability_queries  # type: ignore

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
        row_key = ssl_store._row_key("default", "tls.example", "CERT_VERIFY", "certificate verify failed")
        conn.execute(
            """
            INSERT INTO ssl_errors(row_key, proxy_id, domain, category, reason, count, first_seen, last_seen, sample)
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            (row_key, "default", "tls.example", "CERT_VERIFY", "certificate verify failed", 5, 2900, 3005, "CONNECT tls.example:443"),
        )

    with adblock_store._connect() as conn:
        conn.execute(
            """
            INSERT INTO adblock_events(proxy_id, event_key, ts, src_ip, method, url, http_status, http_resp_line, icap_status, raw, created_ts)
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            ("default", "a" * 40, 3015, "192.0.2.41", "GET", "https://ads.example/banner.js", 403, "HTTP/1.1 403 Forbidden", 204, "blocked", 3015),
        )

    with webfilter_store._connect() as conn:
        conn.execute(
            "INSERT INTO webfilter_blocked_log(proxy_id, ts, src_ip, url, category) VALUES(%s,%s,%s,%s,%s)",
            ("default", 3020, "192.0.2.42", "https://adult.example/video", "adult"),
        )

    monkeypatch.setattr(observability_queries, "get_diagnostic_store", lambda: diag_store)
    monkeypatch.setattr(observability_queries, "get_ssl_errors_store", lambda: ssl_store)
    monkeypatch.setattr(observability_queries, "get_adblock_store", lambda: adblock_store)
    monkeypatch.setattr(observability_queries, "get_webfilter_store", lambda: webfilter_store)

    ssl_payload = queries.ssl_overview(since=2800, limit=10)
    assert ssl_payload["summary"]["bucket_count"] == 1
    assert ssl_payload["summary"]["total_events"] == 5
    assert ssl_payload["top_domains"][0]["domain"] == "tls.example"

    security_payload = queries.security_overview(since=2800, limit=10)
    assert security_payload["summary"]["potential_findings"] == 1
    assert security_payload["summary"]["adblock_blocks"] == 1
    assert security_payload["summary"]["webfilter_blocks"] == 1
    assert security_payload["av_rows"][0]["av_status_label"] == "Potential finding"
    assert security_payload["adblock_top_domains"][0]["domain"] == "ads.example"
    assert security_payload["webfilter_top_categories"][0]["category"] == "adult"

    performance_payload = queries.performance_overview(since=2800, limit=10)
    assert performance_payload["slow_requests"][0]["target_display"] == "ads.example"
    assert performance_payload["slow_icap_events"][0]["target_display"] == "malware.example"
    assert performance_payload["top_user_agents"][0]["label"] == "pytest/1.0"

    overview = queries.overview_bundle(since=2800, limit=5, resolve_hostnames=False)
    assert overview["summary"]["request_records"] == 2
    assert overview["ssl"]["summary"]["total_events"] == 5
    assert overview["security"]["summary"]["combined_blocks"] == 2
