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


def test_observability_queries_surface_ssl_security_performance_and_transport(tmp_path, monkeypatch):
    _add_web_to_path()
    configure_test_mysql_env(tmp_path / "observability-hub")

    from services.adblock_store import AdblockStore  # type: ignore
    from services.diagnostic_store import DiagnosticStore  # type: ignore
    from services.socks_store import SocksStore  # type: ignore
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
    socks_store = SocksStore()
    socks_store.init_db()
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

    with socks_store._connect() as conn:
        conn.execute(
            "INSERT INTO socks_events(proxy_id, ts, action, protocol, src_ip, src_port, dst, dst_port, msg) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            ("default", 3025, "connect", "tcp", "192.0.2.43", 5151, "example.net", 443, "connect ok"),
        )

    monkeypatch.setattr(observability_queries, "get_diagnostic_store", lambda: diag_store)
    monkeypatch.setattr(observability_queries, "get_ssl_errors_store", lambda: ssl_store)
    monkeypatch.setattr(observability_queries, "get_adblock_store", lambda: adblock_store)
    monkeypatch.setattr(observability_queries, "get_webfilter_store", lambda: webfilter_store)
    monkeypatch.setattr(observability_queries, "get_socks_store", lambda: socks_store)

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

    transport_payload = queries.transport_overview(since=2800, limit=10)
    assert transport_payload["summary"]["total"] == 1
    assert transport_payload["top_clients"][0]["src_ip"] == "192.0.2.43"
    assert transport_payload["recent"][0].dst == "example.net"

    overview = queries.overview_bundle(since=2800, limit=5, resolve_hostnames=False)
    assert overview["summary"]["request_records"] == 2
    assert overview["ssl"]["summary"]["total_events"] == 5
    assert overview["security"]["summary"]["combined_blocks"] == 2


def test_ssl_overview_surfaces_dynamic_domain_and_client_candidates(tmp_path, monkeypatch):
    _add_web_to_path()
    configure_test_mysql_env(tmp_path / "observability-ssl-candidates")

    from services.diagnostic_store import DiagnosticStore  # type: ignore
    from services.ssl_errors_store import SslErrorsStore  # type: ignore
    import services.observability_queries as observability_queries  # type: ignore

    diag_store = DiagnosticStore()
    diag_store.init_db()
    ssl_store = SslErrorsStore()
    ssl_store.init_db()
    queries = observability_queries.ObservabilityQueries()

    for offset in range(6):
        ts = 4000 + (offset * 10)
        _insert_request(
            diag_store,
            _request_line(
                ts=ts,
                client_ip="192.0.2.90",
                method="CONNECT",
                url="client.wns.windows.com:443",
                result_code="NONE_NONE/200",
                bytes_sent=0,
                master_xaction=f"tx-wns-{offset}",
            ),
        )
        _insert_request(
            diag_store,
            _request_line(
                ts=ts + 1,
                client_ip="192.0.2.90",
                method="-",
                url="error:invalid-request",
                result_code="NONE_NONE/400",
                bytes_sent=0,
                master_xaction=f"tx-wns-bad-{offset}",
            ),
        )
    for offset in range(6):
        ts = 4100 + (offset * 10)
        _insert_request(
            diag_store,
            _request_line(
                ts=ts,
                client_ip="192.0.2.90",
                method="CONNECT",
                url="mtalk.google.com:5228",
                result_code="NONE_NONE/200",
                bytes_sent=0,
                master_xaction=f"tx-mtalk-{offset}",
            ),
        )
        _insert_request(
            diag_store,
            _request_line(
                ts=ts + 1,
                client_ip="192.0.2.90",
                method="-",
                url="error:invalid-request",
                result_code="NONE_NONE/400",
                bytes_sent=0,
                master_xaction=f"tx-mtalk-bad-{offset}",
            ),
        )

    _insert_request(
        diag_store,
        _request_line(
            ts=4200,
            client_ip="192.0.2.90",
            method="GET",
            url="https://client.wns.windows.com/abort",
            result_code="NONE_NONE_ABORTED/200",
            bytes_sent=0,
            master_xaction="tx-wns-abort",
        ),
    )

    with ssl_store._connect() as conn:
        row_key = ssl_store._row_key("default", "client.wns.windows.com", "TLS_CLIENT_ACCEPT", "SQUID_TLS_ERR_ACCEPT+TLS_LIB_ERR=A000119+TLS_IO_ERR=1")
        conn.execute(
            """
            INSERT INTO ssl_errors(row_key, proxy_id, domain, category, reason, count, first_seen, last_seen, sample)
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            (
                row_key,
                "default",
                "client.wns.windows.com",
                "TLS_CLIENT_ACCEPT",
                "SQUID_TLS_ERR_ACCEPT+TLS_LIB_ERR=A000119+TLS_IO_ERR=1",
                7,
                3999,
                4201,
                "CONNECT client.wns.windows.com:443",
            ),
        )

    class _EmptyExclusions:
        def list_all(self):
            return type("Exclusions", (), {"domains": []})()

    class _EmptySslFilter:
        def list_nobump(self, limit: int = 5000):
            return []

    monkeypatch.setattr(observability_queries, "get_ssl_errors_store", lambda: ssl_store)
    monkeypatch.setattr(observability_queries, "get_exclusions_store", lambda: _EmptyExclusions())
    monkeypatch.setattr(observability_queries, "get_sslfilter_store", lambda: _EmptySslFilter())

    ssl_payload = queries.ssl_overview(since=3900, limit=20)
    domains = {row["domain"] for row in ssl_payload["domain_candidates"]}
    clients = {row["cidr"] for row in ssl_payload["client_candidates"]}

    assert "client.wns.windows.com" in domains
    assert "mtalk.google.com" in domains
    assert "192.0.2.90/32" in clients
    assert any("Dynamic mitigation candidates available" == hint["title"] for hint in ssl_payload["hints"])


def test_reconcile_dynamic_ssl_mitigations_adds_temporary_domain_and_client_protections(tmp_path):
    _add_web_to_path()
    configure_test_mysql_env(tmp_path / "observability-ssl-reconcile")

    from services.diagnostic_store import DiagnosticStore  # type: ignore
    from services.exclusions_store import get_exclusions_store  # type: ignore
    from services.sslfilter_store import get_sslfilter_store  # type: ignore
    import services.observability_queries as observability_queries  # type: ignore

    diag_store = DiagnosticStore()
    diag_store.init_db()
    ex_store = get_exclusions_store()
    sslfilter_store = get_sslfilter_store()
    queries = observability_queries.ObservabilityQueries()

    for offset in range(12):
        ts = 5000 + (offset * 5)
        _insert_request(
            diag_store,
            _request_line(
                ts=ts,
                client_ip="192.0.2.90",
                method="CONNECT",
                url="client.wns.windows.com:443",
                result_code="NONE_NONE/200",
                bytes_sent=0,
                master_xaction=f"tx-wns-{offset}",
            ),
        )
        _insert_request(
            diag_store,
            _request_line(
                ts=ts + 1,
                client_ip="192.0.2.90",
                method="-",
                url="error:invalid-request",
                result_code="NONE_NONE/400",
                bytes_sent=0,
                master_xaction=f"tx-wns-bad-{offset}",
            ),
        )
    for offset in range(12):
        ts = 5100 + (offset * 5)
        _insert_request(
            diag_store,
            _request_line(
                ts=ts,
                client_ip="192.0.2.90",
                method="CONNECT",
                url="mtalk.google.com:5228",
                result_code="NONE_NONE/200",
                bytes_sent=0,
                master_xaction=f"tx-mtalk-{offset}",
            ),
        )
        _insert_request(
            diag_store,
            _request_line(
                ts=ts + 1,
                client_ip="192.0.2.90",
                method="-",
                url="error:invalid-request",
                result_code="NONE_NONE/400",
                bytes_sent=0,
                master_xaction=f"tx-mtalk-bad-{offset}",
            ),
        )

    sslfilter_store.set_dynamic_mitigation_settings(
        enabled=True,
        auto_domain_enabled=True,
        auto_client_enabled=True,
        review_window_seconds=3600,
        reconcile_interval_seconds=60,
        min_pair_events=6,
        min_bump_aborts=8,
        min_ssl_events=10,
        domain_limit=10,
        domain_ttl_seconds=3600,
        client_pair_events=20,
        client_distinct_domains=2,
        client_limit=5,
        client_ttl_seconds=1800,
    )

    result = queries.reconcile_dynamic_ssl_mitigations(force=True, now_ts=5300)

    active_domains = {row.domain for row in ex_store.list_auto_domains(limit=20, now_ts=5300)}
    active_clients = {row.cidr for row in sslfilter_store.list_auto_nobump(limit=20, now_ts=5300)}
    materialized = sslfilter_store.render_materialized_state(now_ts=5300)

    assert result["ran"] is True
    assert result["changed"] is True
    assert "client.wns.windows.com" in active_domains
    assert "mtalk.google.com" in active_domains
    assert "192.0.2.90/32" in active_clients
    assert "192.0.2.90/32" in materialized.list_text
    assert "ssl_bump splice sslfilter_nobump" in materialized.include_text


def test_reconcile_dynamic_ssl_mitigations_keeps_active_protections_warm_without_fresh_failures(tmp_path):
    _add_web_to_path()
    configure_test_mysql_env(tmp_path / "observability-ssl-warm-hold")

    from services.diagnostic_store import DiagnosticStore  # type: ignore
    from services.exclusions_store import get_exclusions_store  # type: ignore
    from services.sslfilter_store import get_sslfilter_store  # type: ignore
    import services.observability_queries as observability_queries  # type: ignore

    diag_store = DiagnosticStore()
    diag_store.init_db()
    ex_store = get_exclusions_store()
    sslfilter_store = get_sslfilter_store()
    queries = observability_queries.ObservabilityQueries()

    ex_store.save_auto_domain_state(
        "client.wns.windows.com",
        added_ts=5000,
        expires_ts=8600,
        evidence="Renewed: initial failure burst",
        last_seen=5000,
        score=82,
    )
    sslfilter_store.save_auto_nobump_state(
        "192.0.2.90/32",
        added_ts=5000,
        expires_ts=7600,
        evidence="Renewed: client kept failing across protected domains",
        last_seen=5000,
        score=88,
    )

    _insert_request(
        diag_store,
        _request_line(
            ts=5550,
            client_ip="192.0.2.90",
            method="GET",
            url="https://client.wns.windows.com/channel",
            result_code="TCP_MISS/200",
            bytes_sent=25,
            master_xaction="tx-warm-1",
        ),
    )
    _insert_request(
        diag_store,
        _request_line(
            ts=5560,
            client_ip="192.0.2.90",
            method="GET",
            url="https://mtalk.google.com/channel",
            result_code="TCP_MISS/200",
            bytes_sent=25,
            master_xaction="tx-warm-2",
        ),
    )

    sslfilter_store.set_dynamic_mitigation_settings(
        enabled=True,
        auto_domain_enabled=True,
        auto_client_enabled=True,
        review_window_seconds=3600,
        reconcile_interval_seconds=60,
        min_pair_events=6,
        min_bump_aborts=8,
        min_ssl_events=10,
        domain_limit=10,
        domain_ttl_seconds=3600,
        client_pair_events=20,
        client_distinct_domains=2,
        client_limit=5,
        client_ttl_seconds=1800,
    )

    result = queries.reconcile_dynamic_ssl_mitigations(force=True, now_ts=5600)

    held_domain = ex_store.list_auto_domains(limit=20, now_ts=5600)[0]
    held_client = sslfilter_store.list_auto_nobump(limit=20, now_ts=5600)[0]

    assert result["changed"] is True
    assert result["domain_cooled"] == ["client.wns.windows.com"]
    assert result["client_cooled"] == ["192.0.2.90/32"]
    assert held_domain.evidence.startswith("Observed traffic while protected:")
    assert held_client.evidence.startswith("Observed traffic while protected:")
    assert held_domain.score >= 35
    assert held_client.score >= 45
    assert held_domain.expires_ts > 5600
    assert held_client.expires_ts > 5600


def test_reconcile_dynamic_ssl_mitigations_retires_dormant_protections(tmp_path):
    _add_web_to_path()
    configure_test_mysql_env(tmp_path / "observability-ssl-retire")

    from services.diagnostic_store import DiagnosticStore  # type: ignore
    from services.exclusions_store import get_exclusions_store  # type: ignore
    from services.sslfilter_store import get_sslfilter_store  # type: ignore
    import services.observability_queries as observability_queries  # type: ignore

    diag_store = DiagnosticStore()
    diag_store.init_db()
    ex_store = get_exclusions_store()
    sslfilter_store = get_sslfilter_store()
    queries = observability_queries.ObservabilityQueries()

    ex_store.save_auto_domain_state(
        "client.wns.windows.com",
        added_ts=5000,
        expires_ts=9000,
        evidence="Cooling down: initial placeholder",
        last_seen=5000,
        score=12,
    )
    sslfilter_store.save_auto_nobump_state(
        "192.0.2.90/32",
        added_ts=5000,
        expires_ts=9000,
        evidence="Cooling down: initial placeholder",
        last_seen=5000,
        score=12,
    )

    sslfilter_store.set_dynamic_mitigation_settings(
        enabled=True,
        auto_domain_enabled=True,
        auto_client_enabled=True,
        review_window_seconds=3600,
        reconcile_interval_seconds=60,
        min_pair_events=6,
        min_bump_aborts=8,
        min_ssl_events=10,
        domain_limit=10,
        domain_ttl_seconds=3600,
        client_pair_events=20,
        client_distinct_domains=2,
        client_limit=5,
        client_ttl_seconds=1800,
    )

    result = queries.reconcile_dynamic_ssl_mitigations(force=True, now_ts=5600)

    assert result["domain_removed"] == ["client.wns.windows.com"]
    assert result["client_removed"] == ["192.0.2.90/32"]
    assert ex_store.list_auto_domains(limit=20, now_ts=5600) == []
    assert sslfilter_store.list_auto_nobump(limit=20, now_ts=5600) == []
