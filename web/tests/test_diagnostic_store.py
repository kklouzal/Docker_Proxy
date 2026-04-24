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
