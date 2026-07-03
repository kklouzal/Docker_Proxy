import ipaddress

from services.diagnostic_store import (
    DiagnosticStore,
    _normalize_icap_row,
    _normalize_request_row,
    _split_tsv,
)


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


def test_list_recent_requests_selects_response_metadata(monkeypatch) -> None:
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

    rows = store.list_recent_requests(limit=1)

    sql = str(captured["sql"])
    assert "response_content_type" in sql
    assert "response_server" in sql
    assert "response_cf_mitigated" in sql
    assert "response_alt_svc" in sql
    assert rows[0]["response_content_type"] == "text/html"
    assert rows[0]["response_server"] == "cloudflare"
    assert rows[0]["response_cf_mitigated"] == "challenge"
    assert rows[0]["response_alt_svc"].startswith("h3=")


def test_top_policy_tags_sql_filters_dash_placeholders(monkeypatch) -> None:
    captured: dict[str, object] = {}

    class FakeCursor:
        def fetchall(self):
            return []

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

    assert store.top_policy_tags(limit=3) == []

    sql = str(captured["sql"])
    assert "NULLIF(NULLIF(TRIM(exclusion_rule), ''), '-')" in sql
    assert "NULLIF(NULLIF(TRIM(ssl_exception), ''), '-')" in sql
    assert "NULLIF(NULLIF(TRIM(webfilter_allow), ''), '-')" in sql
    assert "NULLIF(NULLIF(TRIM(cache_bypass), ''), '-')" in sql
    assert captured["params"][-1] == 3


def test_list_recent_transactions_attaches_related_icap_and_filters_service() -> None:
    store = DiagnosticStore()

    def fake_requests(**_kwargs):
        return [
            {
                "ts": 1777000000,
                "client_ip": "192.0.2.10",
                "method": "GET",
                "target_display": "example.com",
                "url": "https://example.com/file.exe",
                "result_code": "TCP_MISS/200",
                "http_status": 200,
                "bytes": 1024,
                "master_xaction": "tx123",
                "hierarchy_status": "DIRECT",
                "bump_mode": "bump",
                "sni": "example.com",
                "tls_server_version": "TLSv1.3",
                "tls_server_cipher": "TLS_AES_256_GCM_SHA384",
                "tls_client_version": "TLSv1.3",
                "tls_client_cipher": "TLS_AES_128_GCM_SHA256",
                "host": "example.com",
                "user_agent": "Mozilla/5.0",
                "referer": "-",
                "policy_tags": ["cache:cookie"],
                "tls_summary": "bump=bump Â· sni=example.com",
            },
            {
                "ts": 1777000001,
                "client_ip": "192.0.2.11",
                "method": "GET",
                "target_display": "example.net",
                "url": "https://example.net/",
                "result_code": "TCP_MISS/200",
                "http_status": 200,
                "bytes": 2048,
                "master_xaction": "tx999",
                "hierarchy_status": "DIRECT",
                "bump_mode": "bump",
                "sni": "example.net",
                "tls_server_version": "TLSv1.3",
                "tls_server_cipher": "TLS_AES_256_GCM_SHA384",
                "tls_client_version": "TLSv1.3",
                "tls_client_cipher": "TLS_AES_128_GCM_SHA256",
                "host": "example.net",
                "user_agent": "Mozilla/5.0",
                "referer": "-",
                "policy_tags": [],
                "tls_summary": "bump=bump Â· sni=example.net",
            },
        ]

    def fake_icap(_txs, *, service: str = "", limit_per_transaction: int = 5):
        if service == "av":
            return {
                "tx123": [
                    {
                        "service_family": "av",
                        "service_label": "AV / ClamAV",
                        "icap_time_ms": 42,
                        "adapt_summary": "avrespmod / virus_scan allow",
                    },
                ],
            }
        return {
            "tx123": [
                {
                    "service_family": "av",
                    "service_label": "AV / ClamAV",
                    "icap_time_ms": 42,
                    "adapt_summary": "avrespmod / virus_scan allow",
                },
            ],
            "tx999": [],
        }

    store.list_recent_requests = fake_requests  # type: ignore[method-assign]
    store._batch_list_icap_by_master_xactions = fake_icap  # type: ignore[method-assign]

    all_rows = store.list_recent_transactions(limit=10)
    assert len(all_rows) == 2
    assert all_rows[0]["icap_event_count"] == 1
    assert all_rows[0]["service_families"] == ["av"]

    av_rows = store.list_recent_transactions(limit=10, service="av")
    assert len(av_rows) == 1
    assert av_rows[0]["master_xaction"] == "tx123"


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


def test_append_bounded_pending_row_drops_oldest_rows(monkeypatch) -> None:
    from services import diagnostic_store

    pending = [("old-1",), ("old-2",)]
    drop_state = {"dropped": 0, "last_log_ts": 0.0}
    monkeypatch.setattr(diagnostic_store.time, "time", lambda: 301.0)

    diagnostic_store._append_bounded_pending_row(
        pending,
        ("new",),
        max_pending_rows=2,
        loop_name="test",
        drop_state=drop_state,
    )

    assert pending == [("old-2",), ("new",)]
    assert drop_state["dropped"] == 0
    assert drop_state["last_log_ts"] > 300.0


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
        "text/html",
        "cloudflare",
        "challenge",
        'h3=":443"; ma=86400',
    ]
    line = "\t".join(fields)

    parsed = DiagnosticStore()._parse_request_log_line(line)

    assert parsed is not None
    assert parsed["response_content_type"] == "text/html"
    assert parsed["response_server"] == "cloudflare"
    assert parsed["response_cf_mitigated"] == "challenge"
    assert parsed["response_alt_svc"].startswith("h3=")


def test_split_tsv_normalizes_escaped_delimiters_when_quoted_field_contains_real_tab():
    from services.diagnostic_store import _split_tsv

    line = '1710000000\\t10\\t192.0.2.10\\tGET\\thttp://example.test/\\t"agent\twith real tab"\\tTCP_MISS/200'

    assert _split_tsv(line) == [
        '1710000000',
        '10',
        '192.0.2.10',
        'GET',
        'http://example.test/',
        'agent\twith real tab',
        'TCP_MISS/200',
    ]
