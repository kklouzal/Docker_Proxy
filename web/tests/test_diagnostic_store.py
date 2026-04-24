from services.diagnostic_store import DiagnosticStore


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
                "tls_summary": "bump=bump · sni=example.com",
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
                "tls_summary": "bump=bump · sni=example.net",
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
                    }
                ]
            }
        return {
            "tx123": [
                {
                    "service_family": "av",
                    "service_label": "AV / ClamAV",
                    "icap_time_ms": 42,
                    "adapt_summary": "avrespmod / virus_scan allow",
                }
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
