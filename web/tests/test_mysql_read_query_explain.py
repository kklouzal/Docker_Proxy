from __future__ import annotations

import concurrent.futures
import hashlib
import importlib
import json
from typing import TYPE_CHECKING, Any
from unittest import SkipTest

import pytest

from .mysql_test_utils import configure_test_mysql_env

if TYPE_CHECKING:
    from pathlib import Path


def _fresh_diagnostic_store(tmp_path: Path):
    configure_test_mysql_env(
        ("read-query-explain", tmp_path), secret_path=tmp_path / "flask_secret.key"
    )
    module = importlib.import_module("services.diagnostic_store")
    return importlib.reload(module)


def _event_key(*parts: object) -> str:
    return hashlib.sha256("|".join(str(part) for part in parts).encode()).hexdigest()[
        :40
    ]


def _request_row(
    proxy_id: str, seq: int, *, ts: int, domain: str, client_ip: str
) -> tuple[Any, ...]:
    tx = f"tx-{proxy_id}-{seq}"
    url = f"https://{domain}/objects/{seq}?client={client_ip}"
    return (
        proxy_id,
        _event_key("request", proxy_id, seq, ts, domain, client_ip),
        ts,
        10 + (seq % 200),
        client_ip,
        "GET",
        url,
        domain,
        "TCP_MISS/200" if seq % 3 else "TCP_HIT/200",
        200,
        1024 + seq,
        tx,
        "HIER_DIRECT",
        "splice" if seq % 5 else "bump",
        domain,
        "TLSv1.3",
        "TLS_AES_128_GCM_SHA256",
        "TLSv1.3",
        "TLS_AES_128_GCM_SHA256",
        domain,
        "pytest-agent",
        "",
        "",
        "",
        "",
        "",
        "",
        f"raw {seq}",
        ts + 1,
    )


def _icap_row(
    proxy_id: str, seq: int, *, ts: int, domain: str, client_ip: str, service: str
) -> tuple[Any, ...]:
    tx = f"tx-{proxy_id}-{seq}"
    return (
        proxy_id,
        _event_key("icap", proxy_id, seq, ts, domain, service),
        ts,
        tx,
        client_ip,
        "GET",
        f"https://{domain}/objects/{seq}",
        domain,
        5 + (seq % 60),
        "ICAP/200 clean" if service == "av" else "ICAP/204 adapted",
        f"service={service}",
        domain,
        "pytest-agent",
        domain,
        "",
        "",
        "",
        "",
        service,
        f"icap raw {seq}",
        ts + 1,
    )


def _seed_observability_rows(conn, *, center: int = 1_800_000_000) -> None:
    request_rows: list[tuple[Any, ...]] = []
    icap_rows: list[tuple[Any, ...]] = []
    seq = 0
    for proxy_id in ("edge-a", "edge-b", "deleted-old"):
        for offset in range(-1800, 1801):
            domain = "hot.example.test" if offset % 11 else "skewed.example.test"
            client_ip = "10.0.0.10" if offset % 7 else "10.0.0.99"
            request_rows.append(
                _request_row(
                    proxy_id,
                    seq,
                    ts=center + offset,
                    domain=domain,
                    client_ip=client_ip,
                ),
            )
            if offset % 4 == 0:
                icap_rows.append(
                    _icap_row(
                        proxy_id,
                        seq,
                        ts=center + offset,
                        domain=domain,
                        client_ip=client_ip,
                        service="av" if offset % 8 else "adblock",
                    ),
                )
            seq += 1
    # NULL-equivalent/blank searchable fields should not disturb scoped reads.
    request_rows.append(
        _request_row(
            "edge-a",
            seq,
            ts=center,
            domain="",
            client_ip="10.0.0.10",
        ),
    )
    conn.executemany(
        """
        INSERT INTO diagnostic_requests(
            proxy_id, event_key, ts, duration_ms, client_ip, method, url, domain,
            result_code, http_status, bytes, master_xaction, hierarchy_status, bump_mode,
            sni, tls_server_version, tls_server_cipher, tls_client_version, tls_client_cipher,
            host, user_agent, referer, exclusion_rule, ssl_exception, webfilter_allow,
            cache_bypass, file_security_policy, raw, created_ts
        ) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """,
        request_rows,
    )
    conn.executemany(
        """
        INSERT INTO diagnostic_icap_events(
            proxy_id, event_key, ts, master_xaction, client_ip, method, url, domain,
            icap_time_ms, adapt_summary, adapt_details, host, user_agent, sni,
            exclusion_rule, ssl_exception, webfilter_allow, cache_bypass, service_family,
            raw, created_ts
        ) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """,
        icap_rows,
    )
    conn.execute("ANALYZE TABLE diagnostic_requests")
    conn.execute("ANALYZE TABLE diagnostic_icap_events")


def _explain_json(conn, sql: str, params: tuple[Any, ...]) -> dict[str, Any]:
    row = conn.execute(f"EXPLAIN FORMAT=JSON {sql}", params).fetchone()
    raw = row[0] if row is not None else "{}"
    return json.loads(raw)


def _walk_json(value: Any):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk_json(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_json(child)


def _assert_no_temp_sort(plan: dict[str, Any]) -> None:
    assert not any(node.get("using_filesort") is True for node in _walk_json(plan)), (
        json.dumps(plan, sort_keys=True)
    )
    assert not any(
        node.get("using_temporary_table") is True for node in _walk_json(plan)
    ), json.dumps(plan, sort_keys=True)


def _assert_indexed_access(
    plan: dict[str, Any], *, table: str, expected_key: str
) -> None:
    table_nodes = [
        node["table"]
        for node in _walk_json(plan)
        if isinstance(node.get("table"), dict)
    ]
    matches = [node for node in table_nodes if node.get("table_name") == table]
    assert matches, json.dumps(plan, sort_keys=True)
    keys = {str(node.get("key") or "") for node in matches}
    assert expected_key in keys, json.dumps(plan, sort_keys=True)
    assert any(
        str(node.get("access_type") or "").lower() in {"range", "ref"}
        for node in matches
    ), json.dumps(plan, sort_keys=True)


@pytest.mark.integration
@pytest.mark.mysql
def test_mysql_observability_correlation_readers_use_index_ranges(
    tmp_path: Path,
) -> None:
    try:
        diagnostic_module = _fresh_diagnostic_store(tmp_path)
    except SkipTest as exc:
        pytest.skip(str(exc))

    from services.db import connect  # type: ignore
    from services.proxy_context import reset_proxy_id, set_proxy_id  # type: ignore

    store = diagnostic_module.DiagnosticStore()
    store.init_db()
    center = 1_800_000_000
    txs = [f"tx-edge-a-{seq}" for seq in (10, 20, 30, 40, 50)]
    with connect() as conn:
        _seed_observability_rows(conn, center=center)
        batch_plan = _explain_json(
            conn,
            """
            SELECT ts, master_xaction
            FROM (
                SELECT ts, master_xaction, ROW_NUMBER() OVER (
                    PARTITION BY master_xaction ORDER BY ts DESC, id DESC
                ) AS tx_rank
                FROM diagnostic_requests
                WHERE proxy_id = %s AND master_xaction IN (%s, %s, %s, %s, %s)
            ) ranked
            WHERE tx_rank = 1
            """,
            ("edge-a", *txs),
        )
    _assert_indexed_access(
        batch_plan,
        table="diagnostic_requests",
        expected_key="idx_diagnostic_requests_proxy_tx_ts_id",
    )

    def read_for_proxy(proxy_id: str) -> tuple[str, int, int]:
        token = set_proxy_id(proxy_id)
        try:
            policy_candidates = store.list_request_candidates_for_policy_event(
                around_ts=center,
                url="https://hot.example.test/objects/",
                client_ip="10.0.0.10",
                domain="hot.example.test",
                window_seconds=600,
                limit=5,
            )
            assert all(row["client_ip"] == "10.0.0.10" for row in policy_candidates)
            assert all(row["domain"] == "hot.example.test" for row in policy_candidates)
            # _seed_observability_rows numbers rows across proxies in order.
            first_seq = {"edge-a": 0, "edge-b": 3601, "deleted-old": 7202}[proxy_id]
            found = store.batch_find_requests_by_master_xactions(
                [f"tx-{proxy_id}-{first_seq + offset}" for offset in (10, 20, 30)]
            )
            return proxy_id, len(policy_candidates), len(found)
        finally:
            reset_proxy_id(token)

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        results = list(
            executor.map(read_for_proxy, ["edge-a", "edge-b", "deleted-old"] * 3)
        )
    assert all(
        request_count > 0 and found_count == 3
        for _proxy_id, request_count, found_count in results
    )
