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


def _insert_request(diag_store, line: str) -> None:
    with diag_store._connect() as conn:
        assert diag_store._ingest_request_line_with_conn(conn, line)


def test_stats_windowed_totals_and_lists_use_diagnostic_requests_not_cumulative_tables(tmp_path):
    _add_web_to_path()
    configure_test_mysql_env(tmp_path / "stats-window")

    from services.diagnostic_store import DiagnosticStore  # type: ignore
    from services.live_stats import LiveStatsStore  # type: ignore

    diag_store = DiagnosticStore()
    diag_store.init_db()
    live_store = LiveStatsStore()
    live_store.init_db()

    with live_store._connect() as conn:
        conn.execute(
            """
            INSERT INTO live_stats_domains (proxy_id, domain, requests, hit_requests, bytes, hit_bytes, first_seen, last_seen)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            ("default", "legacy.example", 5000, 4900, 123456, 120000, 10, 2100),
        )
        conn.execute(
            """
            INSERT INTO live_stats_clients (proxy_id, ip, requests, hit_requests, bytes, hit_bytes, first_seen, last_seen)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            ("default", "192.0.2.10", 5000, 4900, 123456, 120000, 10, 2100),
        )

    _insert_request(
        diag_store,
        _request_line(
            ts=1900,
            client_ip="192.0.2.10",
            method="GET",
            url="https://legacy.example/app",
            result_code="TCP_HIT/200",
            bytes_sent=100,
            master_xaction="tx-legacy-window",
        ),
    )
    _insert_request(
        diag_store,
        _request_line(
            ts=1950,
            client_ip="192.0.2.20",
            method="GET",
            url="https://fresh.example/home",
            result_code="TCP_MISS/200",
            bytes_sent=200,
            master_xaction="tx-fresh-window",
        ),
    )
    _insert_request(
        diag_store,
        _request_line(
            ts=900,
            client_ip="192.0.2.30",
            method="GET",
            url="https://stale.example/archive",
            result_code="TCP_MISS/200",
            bytes_sent=50,
            master_xaction="tx-stale-outside-window",
        ),
    )

    totals = live_store.get_totals(since=1800)
    assert totals == {
        "domain_requests": 2,
        "domain_hit_requests": 1,
        "client_requests": 2,
        "client_hit_requests": 1,
    }

    domains = live_store.list_domains(sort="top", order="desc", limit=10, since=1800, search="")
    assert [(row["domain"], row["requests"]) for row in domains] == [
        ("fresh.example", 1),
        ("legacy.example", 1),
    ]

    clients = live_store.list_clients(sort="top", order="desc", limit=10, since=1800, search="")
    assert [(row["ip"], row["requests"]) for row in clients] == [
        ("192.0.2.20", 1),
        ("192.0.2.10", 1),
    ]


def test_stats_windowed_client_details_and_reasons_use_diagnostic_requests(tmp_path):
    _add_web_to_path()
    configure_test_mysql_env(tmp_path / "stats-reasons")

    from services.diagnostic_store import DiagnosticStore  # type: ignore
    from services.live_stats import LiveStatsStore  # type: ignore

    diag_store = DiagnosticStore()
    diag_store.init_db()
    live_store = LiveStatsStore()
    live_store.init_db()

    with live_store._connect() as conn:
        conn.execute(
            """
            INSERT INTO live_stats_client_domains (proxy_id, ip, domain, requests, hit_requests, bytes, hit_bytes, first_seen, last_seen)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            ("default", "192.0.2.44", "legacy.example", 7000, 6500, 777777, 700000, 10, 2100),
        )
        conn.execute(
            """
            INSERT INTO live_stats_client_domain_nocache (row_key, proxy_id, ip, domain, reason, requests, first_seen, last_seen)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            ("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", "default", "192.0.2.44", "legacy.example", "Denied by ACL", 7000, 10, 2100),
        )

    _insert_request(
        diag_store,
        _request_line(
            ts=2000,
            client_ip="192.0.2.44",
            method="POST",
            url="https://alpha.example/api",
            result_code="TCP_MISS/200",
            bytes_sent=100,
            master_xaction="tx-alpha-1",
        ),
    )
    _insert_request(
        diag_store,
        _request_line(
            ts=2005,
            client_ip="192.0.2.44",
            method="POST",
            url="https://alpha.example/api/next",
            result_code="TCP_MISS/200",
            bytes_sent=110,
            master_xaction="tx-alpha-2",
        ),
    )
    _insert_request(
        diag_store,
        _request_line(
            ts=2010,
            client_ip="192.0.2.44",
            method="GET",
            url="https://alpha.example/cached",
            result_code="TCP_HIT/200",
            bytes_sent=90,
            master_xaction="tx-alpha-3",
        ),
    )
    _insert_request(
        diag_store,
        _request_line(
            ts=2020,
            client_ip="192.0.2.44",
            method="GET",
            url="https://beta.example/resource",
            result_code="TCP_BYPASS/200",
            bytes_sent=140,
            master_xaction="tx-beta-1",
        ),
    )
    _insert_request(
        diag_store,
        _request_line(
            ts=900,
            client_ip="192.0.2.44",
            method="GET",
            url="https://legacy.example/old",
            result_code="TCP_MISS/200",
            bytes_sent=50,
            master_xaction="tx-legacy-outside-window",
        ),
    )

    client_domains = live_store.list_client_domains(ip="192.0.2.44", sort="top", limit=10, since=1800)
    assert [(row["domain"], row["requests"]) for row in client_domains] == [
        ("alpha.example", 3),
        ("beta.example", 1),
    ]
    assert [round(row["pct"], 1) for row in client_domains] == [75.0, 25.0]

    not_cached = live_store.list_client_not_cached(ip="192.0.2.44", limit=10, since=1800)
    assert not_cached[0]["domain"] == "alpha.example"
    assert not_cached[0]["miss_requests"] == 2
    assert not_cached[0]["total_requests"] == 3
    assert not_cached[0]["reason"] == "POST method (not cacheable by default)"
    assert not_cached[1]["domain"] == "beta.example"
    assert not_cached[1]["reason"] == "Bypassed (cache deny rule or client no-cache)"

    alpha_reasons = live_store.list_domain_not_cached_reasons(domain="alpha.example", limit=10, since=1800)
    assert alpha_reasons == [
        {
            "reason": "POST method (not cacheable by default)",
            "requests": 2,
            "pct": 100.0,
            "last_seen": 2005,
        }
    ]

    global_total, global_reasons = live_store.list_global_not_cached_reasons(limit=10, since=1800)
    assert global_total == 3
    assert [(row["reason"], row["requests"]) for row in global_reasons] == [
        ("POST method (not cacheable by default)", 2),
        ("Bypassed (cache deny rule or client no-cache)", 1),
    ]