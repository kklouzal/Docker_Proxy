import ipaddress
from contextlib import nullcontext
from types import SimpleNamespace
from typing import ClassVar

import pytest
from services.diagnostic_store import (
    DiagnosticStore,
    _nearest_rows,
    _normalize_icap_row,
    _normalize_request_row,
)
from services.runtime_helpers import split_squid_tsv as _split_tsv

from .mysql_test_utils import configure_test_mysql_env, register_test_proxies


class _LifecycleThread:
    created: ClassVar[list[_LifecycleThread]] = []

    def __init__(self, *, target, name=None, args=(), daemon=None):
        self.target = target
        self.name = name
        self.args = args
        self.daemon = daemon
        self.alive = False
        self.created.append(self)

    def start(self) -> None:
        self.alive = True

    def join(self, _timeout: float) -> None:
        self.alive = False

    def is_alive(self) -> bool:
        return self.alive


def test_background_clean_stop_allows_same_store_to_restart(monkeypatch) -> None:
    _LifecycleThread.created.clear()
    store = DiagnosticStore()
    monkeypatch.setattr(store, "init_db", lambda: None)
    monkeypatch.setattr(store, "seed_from_recent_logs", lambda: None)
    monkeypatch.setattr("services.diagnostic_store.threading.Thread", _LifecycleThread)

    store.start_background()
    first_workers = list(store._threads)
    assert store.stop_background(timeout=0.0) is True
    assert store._started is False
    assert store._threads == []

    store.start_background()

    assert store._started is True
    assert len(store._threads) == 2
    assert all(worker not in first_workers for worker in store._threads)


def test_background_stop_timeout_preserves_live_worker_ownership(monkeypatch) -> None:
    class StuckThread(_LifecycleThread):
        def join(self, _timeout: float) -> None:
            pass

    _LifecycleThread.created.clear()
    store = DiagnosticStore()
    worker = StuckThread(target=lambda: None)
    worker.start()
    store._threads = [worker]
    store._started = True
    monkeypatch.setattr(store, "init_db", lambda: None)
    monkeypatch.setattr(store, "seed_from_recent_logs", lambda: None)

    assert store.stop_background(timeout=0.0) is False
    store.start_background()

    assert store._started is True
    assert store._threads == [worker]


def _candidate_request_row(
    *,
    ts: int,
    master_xaction: str,
    row_id: int,
    url_path: str = "request",
) -> tuple[object, ...]:
    return (
        ts,
        10 + row_id,
        "192.0.2.10",
        "GET",
        f"https://example.test/{url_path}",
        "example.test",
        "TCP_MISS/200",
        200,
        100 + row_id,
        master_xaction,
        "DIRECT",
        "bump",
        "example.test",
        "TLSv1.3",
        "TLS_AES_256_GCM_SHA384",
        "TLSv1.3",
        "TLS_AES_128_GCM_SHA256",
        "example.test",
        "pytest/1.0",
        "-",
        "",
        "",
        "",
        "",
        "file_security_risky_extension",
        "text/html",
        "origin",
        "",
        "",
        row_id,
    )


def test_nearest_rows_has_deterministic_equal_timestamp_tie_ordering() -> None:
    rows = [
        (1000, "older-center", 1),
        (1000, "newer-center", 9),
        (999, "before", 4),
        (1001, "after-older", 3),
        (1001, "after-newer", 5),
        (998, "far-before", 8),
        (1002, "far-after", 7),
    ]

    nearest = _nearest_rows(rows, center=1000, limit=7, id_index=2)

    assert nearest == [
        (1000, "newer-center"),
        (1000, "older-center"),
        (1001, "after-older"),
        (1001, "after-newer"),
        (999, "before"),
        (1002, "far-after"),
        (998, "far-before"),
    ]


def test_policy_candidate_query_ignores_blank_client_ip_for_domain_time_match(
    monkeypatch,
) -> None:
    captured_sql: list[str] = []
    captured_params: list[tuple[object, ...]] = []

    class FakeCursor:
        def __init__(self, rows):
            self._rows = rows

        def fetchall(self):
            return self._rows

    class RequestConnection:
        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def execute(self, sql, params):
            sql_text = str(sql)
            captured_sql.append(sql_text)
            captured_params.append(tuple(params))
            if "client_ip = %s" in sql_text:
                # A whitespace-only policy src_ip used to bind as an empty client_ip,
                # which made the otherwise valid domain/time correlation impossible.
                return FakeCursor([])
            if "ORDER BY ts DESC" in sql_text:
                return FakeCursor(
                    [
                        _candidate_request_row(
                            ts=1000,
                            master_xaction="tx-domain-match",
                            row_id=40,
                        )
                    ]
                )
            if "ORDER BY ts ASC" in sql_text:
                return FakeCursor([])
            raise AssertionError(sql_text)

    store = DiagnosticStore()
    monkeypatch.setattr(store, "init_db", lambda: None)
    monkeypatch.setattr(store, "_connect", RequestConnection)
    monkeypatch.setattr(
        store,
        "_batch_list_icap_by_master_xactions",
        lambda *_args, **_kwargs: {},
    )

    candidates = store.list_request_candidates_for_policy_event(
        around_ts=1000,
        url="https://example.test/policy",
        client_ip="   ",
        domain="example.test",
        window_seconds=30,
        limit=3,
    )

    assert "client_ip = %s" not in captured_sql[0]
    assert "domain = %s" in captured_sql[0]
    assert "url LIKE %s" in captured_sql[0]
    assert all("" not in params for params in captured_params)
    assert [row["master_xaction"] for row in candidates] == ["tx-domain-match"]
    assert candidates[0]["correlation_kind"] == "domain_time"


def test_policy_candidate_queries_order_ties_by_id(monkeypatch) -> None:
    request_sql: list[str] = []

    class FakeCursor:
        def __init__(self, rows):
            self._rows = rows

        def fetchall(self):
            return self._rows

    class RequestConnection:
        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def execute(self, sql, _params):
            sql_text = str(sql)
            request_sql.append(sql_text)
            if "ORDER BY ts DESC" in sql_text:
                return FakeCursor(
                    [
                        _candidate_request_row(
                            ts=1000,
                            master_xaction="tx-policy-old",
                            row_id=20,
                        ),
                        _candidate_request_row(
                            ts=1000,
                            master_xaction="tx-policy-new",
                            row_id=21,
                        ),
                    ]
                )
            if "ORDER BY ts ASC" in sql_text:
                return FakeCursor(
                    [
                        _candidate_request_row(
                            ts=1001,
                            master_xaction="tx-policy-after",
                            row_id=22,
                        )
                    ]
                )
            raise AssertionError(sql_text)

    request_store = DiagnosticStore()
    monkeypatch.setattr(request_store, "init_db", lambda: None)
    monkeypatch.setattr(request_store, "_connect", RequestConnection)
    monkeypatch.setattr(
        request_store,
        "_batch_list_icap_by_master_xactions",
        lambda *_args, **_kwargs: {},
    )

    policy_candidates = request_store.list_request_candidates_for_policy_event(
        around_ts=1000,
        url="https://example.test/policy",
        client_ip="192.0.2.10",
        domain="example.test",
        window_seconds=30,
        limit=3,
    )

    assert "ORDER BY ts DESC, id DESC" in request_sql[0]
    assert "ORDER BY ts ASC, id ASC" in request_sql[1]
    assert [row["master_xaction"] for row in policy_candidates] == [
        "tx-policy-new",
        "tx-policy-old",
        "tx-policy-after",
    ]
    assert [row["correlation_kind"] for row in policy_candidates] == ["domain_time"] * 3


def test_read_last_lines_drops_partial_leading_seed_line(tmp_path) -> None:
    store = DiagnosticStore()
    log = tmp_path / "access-observe.log"
    long_first_record = "1710000001	" + ("x" * 1700) + "	TCP_HIT/200"
    complete_second_record = "1710000002	request-second	TCP_MISS/200"
    complete_third_record = "1710000003	request-third	TCP_HIT/200"
    log.write_text(
        f"{long_first_record}\n{complete_second_record}\n{complete_third_record}\n",
        encoding="utf-8",
    )

    lines = store._read_last_lines(str(log), max_lines=3)

    assert lines == [complete_second_record, complete_third_record]


def test_read_last_lines_drops_partial_trailing_seed_line(tmp_path) -> None:
    store = DiagnosticStore()
    log = tmp_path / "access-observe.log"
    complete_record = "1710000004	request-complete	TCP_MISS/200"
    partially_written_record = "1710000005	request-partial	TCP_HIT/200"
    log.write_text(
        complete_record + "\n" + partially_written_record,
        encoding="utf-8",
    )

    lines = store._read_last_lines(str(log), max_lines=10)

    assert lines == [complete_record]


def test_read_last_lines_keeps_seed_line_when_tail_starts_on_line_boundary(
    tmp_path,
) -> None:
    store = DiagnosticStore()
    log = tmp_path / "access-observe.log"
    base_tailed_record = "1710000006\trequest-boundary\tTCP_HIT/200\n"
    padding_len = 512 - len(base_tailed_record.encode("utf-8"))
    tailed_record = base_tailed_record.replace(
        "boundary",
        "boundary" + ("a" * padding_len),
    )
    assert len(tailed_record.encode("utf-8")) == 512
    filler_record = "1710000000\tfiller\tTCP_MISS/200\n"
    log.write_text(filler_record + tailed_record, encoding="utf-8")

    lines = store._read_last_lines(str(log), max_lines=1)

    assert lines == [tailed_record.rstrip("\n")]


def test_parse_request_log_line_extracts_tls_and_policy_fields() -> None:
    store = DiagnosticStore()
    line = (
        "1777000000\t125\t192.0.2.10\tCONNECT\texample.com:443\tTCP_TUNNEL/200\t1234"
        "\ttx123\tDIRECT\tbump\texample.com\tTLSv1.3\tTLS_AES_256_GCM_SHA384"
        "\tTLSv1.3\tTLS_AES_128_GCM_SHA256\texample.com\tMozilla/5.0\t-"
        "\tdomain\tsteam\twhitelist\tcookie"
    )

    row = store._parse_request_log_line(line)

    assert row is not None
    assert row["master_xaction"] == "tx123"
    assert row["domain"] == "example.com"
    assert row["http_status"] == 200
    assert row["ssl_exception"] == "steam"
    assert row["cache_bypass"] == "cookie"


def test_parse_request_log_line_ignores_dash_placeholders_for_domain() -> None:
    store = DiagnosticStore()
    line = (
        "1777357408\t79\t127.0.0.1\tHEAD\thttp://example.com/\tTCP_MISS/200\t482"
        "\t54\tHIER_DIRECT\t-\t-\t-\t-\t-\t-\texample.com\tcurl/8.19.0\t-"
        "\t-\t-\t-\t-"
    )

    row = store._parse_request_log_line(line)

    assert row is not None
    assert row["domain"] == "example.com"


def test_parse_request_log_line_normalizes_dash_policy_placeholders() -> None:
    store = DiagnosticStore()
    line = (
        "1777357408\t79\t192.0.2.10\tGET\thttp://example.com/\tTCP_MISS/200\t482"
        "\t54\tHIER_DIRECT\t-\t-\t-\t-\t-\t-\texample.com\tcurl/8.19.0\t-"
        "\t-\t-\t-\t-"
    )

    row = store._parse_request_log_line(line)

    assert row is not None
    assert row["exclusion_rule"] == ""
    assert row["ssl_exception"] == ""
    assert row["webfilter_allow"] == ""
    assert row["cache_bypass"] == ""


def test_parse_request_log_line_accepts_legacy_base_columns() -> None:
    store = DiagnosticStore()
    line = (
        "1777357408\t79\t192.0.2.10\tGET\thttp://example.com/\tTCP_MISS/200\t482"
        "\t54\tHIER_DIRECT\t-\t-\t-\t-\t-\t-\texample.com\tcurl/8.19.0\t-"
    )

    row = store._parse_request_log_line(line)

    assert row is not None
    assert row["domain"] == "example.com"
    assert row["exclusion_rule"] == ""
    assert row["ssl_exception"] == ""
    assert row["webfilter_allow"] == ""
    assert row["cache_bypass"] == ""
    assert row["response_content_type"] == ""
    assert row["response_server"] == ""
    assert row["response_cf_mitigated"] == ""
    assert row["response_alt_svc"] == ""


def test_parse_request_log_line_ignores_rows_shorter_than_legacy_base() -> None:
    store = DiagnosticStore()
    line = (
        "1777357408\t79\t192.0.2.10\tGET\thttp://example.com/\tTCP_MISS/200\t482"
        "\t54\tHIER_DIRECT\t-\t-\t-\t-\t-\t-\texample.com\tcurl/8.19.0"
    )

    assert store._parse_request_log_line(line) is None


def test_parse_icap_log_line_classifies_av_service_family() -> None:
    store = DiagnosticStore()
    line = (
        "1777000001\ttx123\t192.0.2.10\tGET\thttps://example.com/file.exe\t87"
        "\tavrespmod / virus_scan allow\tclamd clean\texample.com\tMozilla/5.0\texample.com"
        "\t\tsslfilter_nobump\t\t"
    )

    row = store._parse_icap_log_line(line)

    assert row is not None
    assert row["master_xaction"] == "tx123"
    assert row["domain"] == "example.com"
    assert row["icap_time_ms"] == 87
    assert row["service_family"] == "av"
    assert row["ssl_exception"] == "sslfilter_nobump"


def test_parse_icap_log_line_ignores_dash_placeholders_for_domain() -> None:
    store = DiagnosticStore()
    line = (
        "1777357408\t54\t127.0.0.1\tHEAD\thttp://example.com/\t15"
        "\t-\t-\texample.com\tcurl/8.19.0\t-\t-\t-\t-\t-"
    )

    row = store._parse_icap_log_line(line)

    assert row is not None
    assert row["domain"] == "example.com"


def test_parse_icap_log_line_normalizes_dash_policy_placeholders() -> None:
    store = DiagnosticStore()
    line = (
        "1777357408\t54\t192.0.2.10\tHEAD\thttp://example.com/\t15"
        "\t-\t-\texample.com\tcurl/8.19.0\t-\t-\t-\t-\t-"
    )

    row = store._parse_icap_log_line(line)

    assert row is not None
    assert row["exclusion_rule"] == ""
    assert row["ssl_exception"] == ""
    assert row["webfilter_allow"] == ""
    assert row["cache_bypass"] == ""


def test_parse_icap_log_line_accepts_legacy_base_columns() -> None:
    store = DiagnosticStore()
    line = (
        "1777000001\ttx123\t192.0.2.10\tGET\thttps://example.com/file.exe\t87"
        "\tavrespmod / virus_scan allow\tclamd clean\texample.com\tMozilla/5.0\texample.com"
    )

    row = store._parse_icap_log_line(line)

    assert row is not None
    assert row["domain"] == "example.com"
    assert row["service_family"] == "av"
    assert row["exclusion_rule"] == ""
    assert row["ssl_exception"] == ""
    assert row["webfilter_allow"] == ""
    assert row["cache_bypass"] == ""


def test_parse_icap_log_line_accepts_extra_status_after_timing() -> None:
    store = DiagnosticStore()
    line = (
        "1777000001\ttx123\t192.0.2.10\tGET\thttps://example.com/file.exe\t87"
        "\t200\tavrespmod / virus_scan allow\tclamd clean\texample.com\tMozilla/5.0\texample.com"
        "\t-\tsslfilter_nobump\t-\t-"
    )

    row = store._parse_icap_log_line(line)

    assert row is not None
    assert row["icap_time_ms"] == 87
    assert row["service_family"] == "av"
    assert row["domain"] == "example.com"
    assert row["ssl_exception"] == "sslfilter_nobump"


def test_parse_icap_log_line_accepts_extra_token_before_timing() -> None:
    store = DiagnosticStore()
    line = (
        "1777000001\ttx123\t192.0.2.10\tGET\thttps://example.com/file.exe"
        "\tavscan\t87\tavrespmod / virus_scan allow\tclamd clean\texample.com\tMozilla/5.0\texample.com"
    )

    row = store._parse_icap_log_line(line)

    assert row is not None
    assert row["icap_time_ms"] == 87
    assert row["service_family"] == "av"


def test_parse_icap_log_line_captures_extended_service_outcome_fields() -> None:
    store = DiagnosticStore()
    line = (
        "1777000002\ttx-resp\t192.0.2.10\tGET\thttp://example.com/file.bin\t11"
        "\t-\t-\texample.com\tcurl/8.19.0\t-\t-\t-\t-\t-"
        "\tav_resp\tICAP_ERR_GONE\t500\t12\t10\t512\t0"
    )

    row = store._parse_icap_log_line(line)

    assert row is not None
    assert row["service_family"] == "av"
    assert row["icap_service"] == "av_resp"
    assert row["icap_outcome"] == "ICAP_ERR_GONE"
    assert row["icap_status"] == 500
    assert row["icap_response_time_ms"] == 12
    assert row["icap_io_time_ms"] == 10
    assert row["icap_bytes_sent"] == 512
    assert row["icap_bytes_received"] == 0


def test_normalized_icap_row_exposes_extended_service_fields() -> None:
    row = _normalize_icap_row(
        [
            1777000002,
            "tx-resp",
            "192.0.2.10",
            "GET",
            "http://example.com/file.bin",
            "example.com",
            11,
            "-",
            "-",
            "example.com",
            "curl/8.19.0",
            "-",
            "-",
            "-",
            "-",
            "-",
            "av",
            "av_resp",
            "ICAP_ERR_GONE",
            500,
            12,
            10,
            512,
            0,
        ]
    )

    assert row["icap_service"] == "av_resp"
    assert row["icap_outcome"] == "ICAP_ERR_GONE"
    assert row["icap_status"] == 500


def test_normalized_icap_row_defaults_extended_fields_for_legacy_rows() -> None:
    row = _normalize_icap_row(
        [
            1777000002,
            "tx-legacy",
            "192.0.2.10",
            "GET",
            "http://example.com/file.bin",
            "example.com",
            11,
            "-",
            "-",
            "example.com",
            "curl/8.19.0",
            "-",
            "-",
            "-",
            "-",
            "-",
            "av",
        ]
    )

    assert row["icap_service"] == ""
    assert row["icap_outcome"] == ""
    assert row["icap_status"] == 0
    assert row["icap_response_time_ms"] == 0
    assert row["icap_io_time_ms"] == 0
    assert row["icap_bytes_sent"] == 0
    assert row["icap_bytes_received"] == 0
    assert row["av_threat"] == ""


def test_extended_icap_metadata_survives_flush_listing_and_enrichment(
    monkeypatch,
) -> None:
    store = DiagnosticStore()
    line = (
        "1777000002\ttx-resp\t192.0.2.10\tGET\thttp://example.com/file.bin\t11"
        "\t-\t-\texample.com\tcurl/8.19.0\t-\t-\t-\t-\t-"
        "\tav_resp\tICAP_ERR_GONE\t500\t12\t10\t512\t64"
        "\tType=0;%20Resolution=2;%20Threat=Eicar-Signature;"
    )
    inserted_sql: list[str] = []

    class FakeCursor:
        def __init__(self, rows):
            self._rows = rows

        def fetchall(self):
            return self._rows

    class FakeConnection:
        persisted: tuple[object, ...] | None = None

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def executemany(self, sql, rows):
            materialized = tuple(tuple(row) for row in rows)
            assert len(materialized) == 1
            self.persisted = materialized[0]
            inserted_sql.append(str(sql))

        def execute(self, sql, _params):
            assert self.persisted is not None
            sql_text = str(sql)
            selected = tuple(self.persisted[2:27])
            if "FORCE INDEX" in sql_text:
                if "ORDER BY ts ASC" in sql_text:
                    return FakeCursor([])
                return FakeCursor([(*selected, 1)])
            return FakeCursor([selected])

    connection = FakeConnection()
    monkeypatch.setattr(store, "_connect", lambda: connection)
    monkeypatch.setattr(store, "init_db", lambda: None)

    params = store._build_icap_insert_params(line)
    assert params is not None
    store._flush_icap_rows(connection, [params])
    assert connection.persisted is not None
    assert "icap_service, icap_outcome, icap_status" in inserted_sql[0]
    assert inserted_sql[0].count("%s") == 29
    assert len(connection.persisted) == 29

    recent = store.list_recent_icap(search="ICAP_ERR_GONE", limit=1)
    assert recent[0]["icap_service"] == "av_resp"
    assert recent[0]["icap_outcome"] == "ICAP_ERR_GONE"
    assert recent[0]["icap_status"] == 500
    assert recent[0]["icap_response_time_ms"] == 12
    assert recent[0]["icap_io_time_ms"] == 10
    assert recent[0]["icap_bytes_sent"] == 512
    assert recent[0]["icap_bytes_received"] == 64
    assert recent[0]["av_threat"] == "Eicar-Signature"
    assert store.list_recent_icap(search="eicar", limit=1)[0]["av_threat"] == (
        "Eicar-Signature"
    )

    slowest = store.slowest_icap_events(limit=1)
    assert slowest[0]["icap_outcome"] == "ICAP_ERR_GONE"
    assert slowest[0]["icap_io_time_ms"] == 10


def test_icap_schema_creates_and_additively_migrates_extended_columns(
    monkeypatch,
) -> None:
    statements: list[str] = []

    class FakeCursor:
        def __init__(self, row=None):
            self._row = row

        def fetchone(self):
            return self._row

    class FakeConnection:
        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def execute(self, sql, params=()):
            sql_text = str(sql)
            statements.append(sql_text)
            if "information_schema.columns" in sql_text:
                if "diagnostic_requests" in sql_text:
                    return FakeCursor((1,))
                assert params[0].startswith("icap_") or params[0] == "av_threat"
                return FakeCursor(None)
            if "information_schema.statistics" in sql_text:
                return FakeCursor((1,))
            return FakeCursor()

    connection = FakeConnection()
    monkeypatch.setattr(
        "services.diagnostic_store.run_mysql_operation_with_retry",
        lambda operation: operation(),
    )
    monkeypatch.setattr(
        "services.diagnostic_store.mysql_advisory_lock",
        lambda *_args, **_kwargs: nullcontext(),
    )
    monkeypatch.setattr(
        "services.schema_lifecycle.runtime_schema_ready_for_lazy_store",
        lambda _conn: False,
    )
    store = DiagnosticStore()
    monkeypatch.setattr(store, "_connect", lambda: connection)

    store.init_db()

    create_icap = next(
        sql
        for sql in statements
        if "CREATE TABLE IF NOT EXISTS diagnostic_icap_events" in sql
    )
    for column in (
        "icap_service",
        "icap_outcome",
        "icap_status",
        "icap_response_time_ms",
        "icap_io_time_ms",
        "icap_bytes_sent",
        "icap_bytes_received",
        "av_threat",
    ):
        assert column in create_icap
        assert any(
            f"ALTER TABLE diagnostic_icap_events ADD COLUMN {column}" in sql
            for sql in statements
        )


def test_parse_icap_log_line_ignores_rows_shorter_than_legacy_base() -> None:
    store = DiagnosticStore()
    line = (
        "1777000001\ttx123\t192.0.2.10\tGET\thttps://example.com/file.exe\t87"
        "\tavrespmod / virus_scan allow\tclamd clean\texample.com\tMozilla/5.0"
    )

    assert store._parse_icap_log_line(line) is None


def test_log_parsers_share_policy_field_and_raw_line_normalization() -> None:
    store = DiagnosticStore()
    request_line = (
        "1777000000\t125\t192.0.2.10\tCONNECT\texample.com:443\tTCP_TUNNEL/200\t1234"
        "\ttx123\tDIRECT\tbump\texample.com\tTLSv1.3\tTLS_AES_256_GCM_SHA384"
        "\tTLSv1.3\tTLS_AES_128_GCM_SHA256\texample.com\tMozilla/5.0\t-"
        "\texclude-rule\tssl-rule\twebfilter-rule\tcache-rule\r\n"
    )
    icap_line = (
        "1777000001\ttx123\t192.0.2.10\tGET\thttps://example.com/file.exe\t87"
        "\tavrespmod / virus_scan allow\tclamd clean\texample.com\tMozilla/5.0\texample.com"
        "\texclude-rule\tssl-rule\twebfilter-rule\tcache-rule\r\n"
    )

    request_row = store._parse_request_log_line(request_line)
    icap_row = store._parse_icap_log_line(icap_line)

    assert request_row is not None
    assert icap_row is not None
    for row in (request_row, icap_row):
        assert row["exclusion_rule"] == "exclude-rule"
        assert row["ssl_exception"] == "ssl-rule"
        assert row["webfilter_allow"] == "webfilter-rule"
        assert row["cache_bypass"] == "cache-rule"
        assert not row["raw"].endswith(("\r", "\n"))


def test_split_tsv_accepts_literal_escaped_tabs() -> None:
    assert _split_tsv("alpha\\tbeta\\tgam\\tma") == ["alpha", "beta", "gam", "ma"]


def test_normalized_stored_rows_do_not_emit_dash_policy_tags() -> None:
    request_row = _normalize_request_row(
        [
            1777000000,
            125,
            "192.0.2.10",
            "GET",
            "http://example.com/",
            "example.com",
            "TCP_MISS/200",
            200,
            482,
            "tx123",
            "HIER_DIRECT",
            "",
            "",
            "",
            "",
            "",
            "",
            "example.com",
            "curl/8.19.0",
            "-",
            "-",
            "-",
            "-",
            "-",
        ]
    )
    icap_row = _normalize_icap_row(
        [
            1777000001,
            "tx123",
            "192.0.2.10",
            "GET",
            "http://example.com/",
            "example.com",
            15,
            "-",
            "-",
            "example.com",
            "curl/8.19.0",
            "-",
            "-",
            "-",
            "-",
            "-",
            "other",
        ]
    )

    assert request_row["policy_tags"] == []
    assert icap_row["policy_tags"] == []


def test_normalized_request_row_preserves_response_metadata() -> None:
    row = _normalize_request_row(
        [
            1777000000,
            125,
            "192.0.2.10",
            "GET",
            "http://example.com/",
            "example.com",
            "TCP_MISS/403",
            403,
            482,
            "tx123",
            "HIER_DIRECT",
            "",
            "",
            "",
            "",
            "",
            "",
            "example.com",
            "curl/8.19.0",
            "-",
            "",
            "",
            "",
            "",
            "file_security_risky_extension",
            "text/html",
            "cloudflare",
            "challenge",
            'h3=":443"; ma=86400',
        ]
    )

    assert row["response_content_type"] == "text/html"
    assert row["response_server"] == "cloudflare"
    assert row["response_cf_mitigated"] == "challenge"
    assert row["response_alt_svc"].startswith("h3=")


def test_batch_request_lookup_returns_newest_row_per_transaction(monkeypatch) -> None:
    captured: dict[str, object] = {}
    request_row = (
        1777000000,
        125,
        "192.0.2.10",
        "GET",
        "http://example.com/",
        "example.com",
        "TCP_MISS/403",
        403,
        482,
        "tx123",
        "HIER_DIRECT",
        "",
        "",
        "",
        "",
        "",
        "",
        "example.com",
        "curl/8.19.0",
        "-",
        "",
        "",
        "",
        "",
        "file_security_risky_extension",
        "text/html",
        "cloudflare",
        "challenge",
        'h3=":443"; ma=86400',
    )

    class FakeCursor:
        def fetchall(self):
            return [request_row]

    class FakeConnection:
        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def execute(self, sql, params):
            captured["sql"] = sql
            captured["params"] = params
            return FakeCursor()

    def fake_connect():
        return FakeConnection()

    store = DiagnosticStore()
    monkeypatch.setattr(store, "_connect", fake_connect)

    assert store.batch_find_requests_by_master_xactions(["", "  "]) == {}
    assert "sql" not in captured

    found = store.batch_find_requests_by_master_xactions(["tx123", " tx123 ", ""])

    # One query for every transaction; duplicates and blanks are not sent.
    sql = " ".join(str(captured["sql"]).split())
    assert "master_xaction IN (%s)" in sql
    assert "PARTITION BY master_xaction ORDER BY ts DESC, id DESC" in sql
    assert "WHERE tx_rank = 1" in sql
    assert captured["params"][1:] == ("tx123",)
    row = found["tx123"]
    assert row["response_content_type"] == "text/html"
    assert row["response_server"] == "cloudflare"
    assert row["response_cf_mitigated"] == "challenge"
    assert row["response_alt_svc"].startswith("h3=")


def test_top_policy_tags_queries_materialized_policy_tag_table(monkeypatch) -> None:
    captured: dict[str, object] = {}

    class FakeCursor:
        def fetchall(self):
            return [("ssl:rule", 2, 1777000001)]

    class FakeConnection:
        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def execute(self, sql, params):
            captured["sql"] = sql
            captured["params"] = params
            return FakeCursor()

    def fake_connect():
        return FakeConnection()

    store = DiagnosticStore()
    monkeypatch.setattr(store, "_connect", fake_connect)
    monkeypatch.setattr(store, "init_db", lambda: None)

    assert store.top_policy_tags(limit=3) == [
        {"tag": "ssl:rule", "count": 2, "last_seen": 1777000001}
    ]

    sql = str(captured["sql"])
    assert "FROM diagnostic_policy_tags" in sql
    assert "UNION ALL" not in sql
    assert "diagnostic_requests" not in sql
    assert captured["params"][-1] == 3


def test_request_flush_materializes_policy_tags_for_top_query(tmp_path) -> None:
    configure_test_mysql_env(tmp_path)
    register_test_proxies()
    store = DiagnosticStore()
    store.init_db()
    line = (
        "1777000000	125	192.0.2.10	CONNECT	example.com:443	TCP_TUNNEL/200	1234"
        "	tx-policy	DIRECT	bump	example.com	TLSv1.3	TLS_AES_256_GCM_SHA384"
        "	TLSv1.3	TLS_AES_128_GCM_SHA256	example.com	Mozilla/5.0	-"
        "	exclude-rule	ssl-rule	-	cache-rule"
    )
    row = store._build_request_insert_params(line)
    assert row is not None

    with store._connect() as conn:
        store._flush_request_rows(conn, [row])
        stored_tags = [
            str(item[0])
            for item in conn.execute(
                "SELECT tag FROM diagnostic_policy_tags ORDER BY tag"
            ).fetchall()
        ]

    assert stored_tags == ["cache:cache-rule", "exclude:exclude-rule", "ssl:ssl-rule"]
    top = store.top_policy_tags(limit=5)
    assert {item["tag"]: item["count"] for item in top} == {
        "cache:cache-rule": 1,
        "exclude:exclude-rule": 1,
        "ssl:ssl-rule": 1,
    }


def _diagnostic_request_line(
    client_ip: str, *, url: str = "http://example.com/", method: str = "GET"
) -> str:
    return (
        f"1777357408\t79\t{client_ip}\t{method}\t{url}\tTCP_MISS/200\t482"
        "\t54\tHIER_DIRECT\t-\t-\t-\t-\t-\t-\texample.com\tcurl/8.19.0\t-"
        "\t-\t-\t-\t-"
    )


def test_build_request_insert_params_filters_loopback_and_exact_self_addresses(
    monkeypatch,
) -> None:
    monkeypatch.delenv("ENABLE_TEST_MODE", raising=False)
    monkeypatch.setenv("DIAGNOSTIC_FILTER_INTERNAL_TRAFFIC", "1")
    monkeypatch.setattr(
        "services.diagnostic_store._local_link_networks",
        lambda: (ipaddress.ip_network("172.19.0.1/32"),),
    )
    store = DiagnosticStore()
    self_probe = (
        "1778373091\t0\t127.0.0.1\t-\terror:transaction-end-before-headers\tNONE_NONE/0\t0"
        "\t-\tHIER_NONE\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-"
    )
    assert store._build_request_insert_params(self_probe) is None
    assert (
        store._build_request_insert_params(_diagnostic_request_line("172.19.0.1"))
        is None
    )
    assert (
        store._build_request_insert_params(_diagnostic_request_line("172.19.0.3"))
        is not None
    )
    assert (
        store._build_request_insert_params(_diagnostic_request_line("192.0.2.10"))
        is not None
    )


def test_build_request_insert_params_keeps_live_test_container_traffic_by_default(
    monkeypatch,
) -> None:
    monkeypatch.setenv("ENABLE_TEST_MODE", "1")
    monkeypatch.delenv("DIAGNOSTIC_FILTER_INTERNAL_TRAFFIC", raising=False)
    monkeypatch.setattr(
        "services.diagnostic_store._local_link_networks",
        lambda: (ipaddress.ip_network("172.19.0.1/32"),),
    )
    store = DiagnosticStore()
    assert (
        store._build_request_insert_params(_diagnostic_request_line("172.19.0.1"))
        is not None
    )
    monkeypatch.setenv("DIAGNOSTIC_FILTER_INTERNAL_TRAFFIC", "1")
    assert (
        store._build_request_insert_params(_diagnostic_request_line("172.19.0.1"))
        is None
    )
    assert (
        store._build_request_insert_params(_diagnostic_request_line("172.19.0.3"))
        is not None
    )


def test_build_icap_insert_params_filters_internal_sources(monkeypatch) -> None:
    monkeypatch.delenv("ENABLE_TEST_MODE", raising=False)
    monkeypatch.setenv("DIAGNOSTIC_FILTER_INTERNAL_TRAFFIC", "1")
    monkeypatch.setattr(
        "services.diagnostic_store._local_link_networks",
        lambda: (ipaddress.ip_network("172.19.0.1/32"),),
    )
    store = DiagnosticStore()
    self_line = (
        "1777000001\ttx123\t172.19.0.1\tGET\thttps://example.com/file.exe\t87"
        "\tavrespmod / virus_scan allow\tclamd clean\texample.com\tMozilla/5.0\texample.com"
        "\t\tsslfilter_nobump\t\t"
    )
    same_subnet_client_line = (
        "1777000001\ttx123\t172.19.0.3\tGET\thttps://example.com/file.exe\t87"
        "\tavrespmod / virus_scan allow\tclamd clean\texample.com\tMozilla/5.0\texample.com"
        "\t\tsslfilter_nobump\t\t"
    )
    assert store._build_icap_insert_params(self_line) is None
    assert store._build_icap_insert_params(same_subnet_client_line) is not None


def test_local_link_network_cache_uses_monotonic_expiry(monkeypatch) -> None:
    from services import diagnostic_store

    monotonic_times = iter((10.0, 69.0, 70.0))
    reads = iter((("first",), ("refreshed",)))

    def fail_if_wall_clock_is_read() -> float:
        message = "cache expiry must not consult the wall clock"
        raise AssertionError(message)

    monkeypatch.setattr(
        diagnostic_store,
        "time",
        SimpleNamespace(
            time=fail_if_wall_clock_is_read,
            monotonic=lambda: next(monotonic_times),
        ),
    )
    monkeypatch.setattr(
        diagnostic_store, "_read_local_link_networks", lambda: next(reads)
    )
    monkeypatch.setattr(diagnostic_store, "_INTERNAL_NETWORK_CACHE", (0.0, ()))

    assert diagnostic_store._local_link_networks() == ("first",)
    assert diagnostic_store._local_link_networks() == ("first",)
    assert diagnostic_store._local_link_networks() == ("refreshed",)


def test_append_bounded_pending_row_drops_oldest_rows(monkeypatch, caplog) -> None:
    from services import diagnostic_store

    pending = [("old-1",), ("old-2",)]
    drop_state = {"dropped": 0, "last_log_mono": None}
    monotonic_times = iter((10.0, 309.0, 310.0))

    def fail_if_wall_clock_is_read() -> float:
        message = "warning throttle must not consult the wall clock"
        raise AssertionError(message)

    monkeypatch.setattr(
        diagnostic_store,
        "time",
        SimpleNamespace(
            time=fail_if_wall_clock_is_read,
            monotonic=lambda: next(monotonic_times),
        ),
    )

    diagnostic_store._append_bounded_pending_row(
        pending,
        ("new",),
        max_pending_rows=2,
        loop_name="test",
        drop_state=drop_state,
    )

    assert pending == [("old-2",), ("new",)]
    assert drop_state["dropped"] == 0
    assert int(drop_state["last_log_mono"]) == 10

    for row in (("newer",), ("newest",)):
        diagnostic_store._append_bounded_pending_row(
            pending,
            row,
            max_pending_rows=2,
            loop_name="test",
            drop_state=drop_state,
        )

    assert int(drop_state["last_log_mono"]) == 310
    assert drop_state["dropped"] == 0
    assert caplog.messages == [
        "Diagnostic tailer pending rows exceeded 2 in test; dropped 1 oldest rows while database flush is unavailable",
        "Diagnostic tailer pending rows exceeded 2 in test; dropped 2 oldest rows while database flush is unavailable",
    ]


def test_request_parser_captures_remediation_response_metadata() -> None:
    from services.diagnostic_store import DiagnosticStore  # type: ignore

    fields = [
        "1710000010",
        "42",
        "10.0.0.8",
        "GET",
        "https://example.com/",
        "TCP_MISS/403",
        "512",
        "tx-meta",
        "DIRECT",
        "bump",
        "example.com",
        "TLSv1.3",
        "TLS_AES_256_GCM_SHA384",
        "TLSv1.3",
        "TLS_AES_128_GCM_SHA256",
        "example.com",
        "pytest/1.0",
        "-",
        "",
        "",
        "",
        "",
        "file_security_risky_extension",
        "text/html",
        "cloudflare",
        "challenge",
        'h3=":443"; ma=86400',
    ]
    line = "\t".join(fields)

    parsed = DiagnosticStore()._parse_request_log_line(line)

    assert parsed is not None
    assert parsed["file_security_policy"] == "file_security_risky_extension"
    assert parsed["response_content_type"] == "text/html"
    assert parsed["response_server"] == "cloudflare"
    assert parsed["response_cf_mitigated"] == "challenge"
    assert parsed["response_alt_svc"].startswith("h3=")


def test_file_security_note_materializes_structured_policy_tag() -> None:
    from services.diagnostic_store import DiagnosticStore  # type: ignore

    fields = [
        "1710000010",
        "1",
        "10.0.0.8",
        "GET",
        "https://downloads.example/OAWrapper.exe",
        "TCP_DENIED/403",
        "512",
        "tx-file-policy",
        "HIER_NONE",
        "bump",
        "downloads.example",
        "",
        "",
        "",
        "",
        "downloads.example",
        "NvBackend/43.4.0.0",
        "-",
        "",
        "",
        "",
        "",
        "file_security_risky_extension",
        "text/html",
        "squid/7.1",
        "",
        "",
    ]

    parsed = DiagnosticStore()._parse_request_log_line("\t".join(fields))

    assert parsed is not None
    assert parsed["file_security_policy"] == "file_security_risky_extension"
    from services.diagnostic_store import _policy_tags

    assert _policy_tags(
        exclusion_rule="",
        ssl_exception="",
        webfilter_allow="",
        cache_bypass="",
        file_security_policy=parsed["file_security_policy"],
    ) == ["file_security:file_security_risky_extension"]


def test_split_tsv_normalizes_escaped_delimiters_when_quoted_field_contains_real_tab():
    line = '1710000000\\t10\\t192.0.2.10\\tGET\\thttp://example.test/\\t"agent\twith real tab"\\tTCP_MISS/200'

    assert _split_tsv(line) == [
        "1710000000",
        "10",
        "192.0.2.10",
        "GET",
        "http://example.test/",
        "agent\twith real tab",
        "TCP_MISS/200",
    ]


# A diagnostic logformat row as Squid 7.8 writes it in production: absent
# values are "-" and header fields are URL-escaped.
_SQUID_DIAGNOSTIC_FIELDS = (
    "1777000000.123",
    "42",
    "192.0.2.10",
    "GET",
    "https://example.com/a%20b",
    "TCP_MISS/200",
    "512",
    "-",
    "HIER_DIRECT/203.0.113.5",
    "-",
    "-",
    "-",
    "-",
    "-",
    "-",
    "example.com",
    "Mozilla/5.0%20(X11;%20Linux)%20100%25%20%22quoted%22",
    "-",
    "-",
    "-",
    "-",
    "-",
    "-",
    "text/html;%20charset=utf-8",
    "nginx",
    "-",
    "h3=%22:443%22;%20ma=86400",
)
_SQUID_DIAGNOSTIC_LINE = "\t".join(_SQUID_DIAGNOSTIC_FIELDS)


def test_request_parse_maps_squid_absent_marker_and_decodes_headers() -> None:
    row = DiagnosticStore()._parse_request_log_line(_SQUID_DIAGNOSTIC_LINE)

    assert row is not None
    for field in (
        "master_xaction",
        "bump_mode",
        "sni",
        "tls_server_version",
        "tls_server_cipher",
        "tls_client_version",
        "tls_client_cipher",
        "referer",
        "response_cf_mitigated",
    ):
        assert row[field] == "", field
    assert row["user_agent"] == 'Mozilla/5.0 (X11; Linux) 100% "quoted"'
    assert row["response_content_type"] == "text/html; charset=utf-8"
    assert row["response_alt_svc"] == 'h3=":443"; ma=86400'
    # The request URL keeps its own percent-encoding.
    assert row["url"] == "https://example.com/a%20b"


def test_icap_parse_maps_squid_absent_marker_and_decodes_headers() -> None:
    line = (
        "1777000002\t-\t192.0.2.10\tGET\thttp://example.com/file.bin\t11"
        "\t-\t-\texample.com\tcurl/8.19.0%20(x)\t-\t-\t-\t-\t-"
        "\tav_resp\tICAP_ECHO\t204\t12\t10\t512\t64"
    )
    row = DiagnosticStore()._parse_icap_log_line(line)

    assert row is not None
    assert row["master_xaction"] == ""
    assert row["adapt_summary"] == ""
    assert row["user_agent"] == "curl/8.19.0 (x)"
    assert row["adapt_details"].startswith("service=av_resp;")
    assert row["av_threat"] == ""


@pytest.mark.parametrize(
    ("infection_field", "expected"),
    [
        # Squid URL-escapes the logged header value; '-' marks it absent.
        (
            "Type=0;%20Resolution=2;%20Threat=Win.Test.EICAR_HDB-1;",
            "Win.Test.EICAR_HDB-1",
        ),
        ("Type=0; Resolution=2; Threat=Eicar-Signature;", "Eicar-Signature"),
        ("Type=0;%20Resolution=2;", "Unknown"),
        ("-", ""),
    ],
)
def test_icap_parse_reads_x_infection_found_threat(
    infection_field: str, expected: str
) -> None:
    line = (
        "1777000002\ttx-1\t192.0.2.10\tGET\thttps://secure.eicar.org/eicar.com.txt\t16"
        "\t-\t-\tsecure.eicar.org\tcurl/8.19.0\t-\t-\t-\t-\t-"
        f"\tav_resp\tICAP_MOD\t200\t16\t14\t719\t336\t{infection_field}"
    )
    row = DiagnosticStore()._parse_icap_log_line(line)

    assert row is not None
    assert row["service_family"] == "av"
    assert row["icap_bytes_received"] == 336
    assert row["av_threat"] == expected


def test_icap_parse_keeps_lines_without_the_infection_field() -> None:
    """Lines written before the field was added (22 fields) still parse."""
    line = (
        "1777000002\ttx-1\t192.0.2.10\tGET\thttps://example.com/\t16"
        "\t-\t-\texample.com\tcurl/8.19.0\t-\t-\t-\t-\t-"
        "\tav_resp\tICAP_MOD\t200\t16\t14\t719\t336"
    )
    row = DiagnosticStore()._parse_icap_log_line(line)

    assert row is not None
    assert row["icap_bytes_received"] == 336
    assert row["av_threat"] == ""


def test_absent_transaction_rows_do_not_correlate_with_each_other(
    monkeypatch,
) -> None:
    store = DiagnosticStore()
    monkeypatch.setattr(
        store,
        "_connect",
        lambda: (_ for _ in ()).throw(AssertionError("queried blank tx ids")),
    )
    row = store._parse_request_log_line(_SQUID_DIAGNOSTIC_LINE)

    assert store._batch_list_icap_by_master_xactions([row["master_xaction"]]) == {}
    assert store.batch_find_requests_by_master_xactions([row["master_xaction"]]) == {}


def test_event_keys_stay_stable_across_absent_marker_normalization() -> None:
    from services.diagnostic_store import _event_key  # type: ignore

    # Rows stored before "-" was normalized hashed the raw marker; a replayed
    # line must keep deduplicating against them.
    assert _event_key(1777000000, "", "192.0.2.10", 0) == _event_key(
        1777000000, "-", "192.0.2.10", 0
    )
    import hashlib

    legacy = hashlib.sha1(
        b"1777000000|-|192.0.2.10|", usedforsecurity=False
    ).hexdigest()
    assert _event_key(1777000000, "", "192.0.2.10", 0) == legacy


def test_tls_summary_uses_a_real_middle_dot_separator() -> None:
    row = _normalize_request_row(
        (0, 0, "", "", "", "", "", 0, 0, "", "", "bump", "example.com", "TLSv1.3")
        + ("",) * 15
    )

    assert row["tls_summary"] == "bump=bump · sni=example.com · server=TLSv1.3"
