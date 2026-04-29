from services.runtime_helpers import decode_bytes, extract_domain, normalize_hostish, not_cached_reason


def test_decode_bytes_handles_bytes_strings_and_none() -> None:
    assert decode_bytes(b"decoded\n") == "decoded"
    assert decode_bytes("  already text  ") == "already text"
    assert decode_bytes(None) == ""


def test_normalize_hostish_handles_placeholders_and_ports() -> None:
    assert normalize_hostish("-") == ""
    assert normalize_hostish("Example.COM:443") == "example.com"
    assert normalize_hostish("[2001:db8::1]:8443") == "2001:db8::1"


def test_extract_domain_prefers_sni_host_then_url() -> None:
    assert extract_domain("https://fallback.example/path", sni="api.example") == "api.example"
    assert extract_domain("https://fallback.example/path", host="cdn.example:443") == "cdn.example"
    assert extract_domain("https://fallback.example/path") == "fallback.example"


def test_not_cached_reason_matches_expected_labels() -> None:
    assert not_cached_reason("POST", "TCP_MISS/200") == "POST method (not cacheable by default)"
    assert not_cached_reason("CONNECT", "TCP_TUNNEL/200") == "HTTPS tunnel (CONNECT) — not cacheable without SSL-bump"
    assert not_cached_reason("GET", "TCP_BYPASS/200") == "Bypassed (cache deny rule or client no-cache)"
    assert not_cached_reason("GET", "TCP_MISS/302") == "Redirect response (302) (often not cached without explicit freshness)"
