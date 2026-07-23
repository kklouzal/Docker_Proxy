import pytest
from services.runtime_helpers import (
    decode_bytes,
    env_float,
    env_int,
    extract_domain,
    normalize_hostish,
    not_cached_reason,
)


def test_decode_bytes_handles_bytes_strings_and_none() -> None:
    assert decode_bytes(b"decoded\n") == "decoded"
    assert decode_bytes("  already text  ") == "already text"
    assert decode_bytes(None) == ""


def test_env_int_uses_default_for_missing_blank_and_invalid_values(monkeypatch) -> None:
    monkeypatch.delenv("HELPER_INT", raising=False)
    assert env_int("HELPER_INT", 7) == 7

    monkeypatch.setenv("HELPER_INT", "  ")
    assert env_int("HELPER_INT", 7) == 7

    monkeypatch.setenv("HELPER_INT", "invalid")
    assert env_int("HELPER_INT", 7) == 7


def test_env_int_clamps_to_optional_bounds(monkeypatch) -> None:
    monkeypatch.setenv("HELPER_INT", "0")
    assert env_int("HELPER_INT", 7, minimum=2, maximum=10) == 2

    monkeypatch.setenv("HELPER_INT", "42")
    assert env_int("HELPER_INT", 7, minimum=2, maximum=10) == 10


def test_env_float_uses_default_for_missing_blank_invalid_and_non_finite_values(
    monkeypatch,
) -> None:
    monkeypatch.delenv("HELPER_FLOAT", raising=False)
    assert env_float("HELPER_FLOAT", 7.5) == pytest.approx(7.5)

    for value in ("  ", "invalid", "nan", "NaN", "inf", "+Inf", "-Infinity"):
        monkeypatch.setenv("HELPER_FLOAT", value)
        assert env_float(
            "HELPER_FLOAT", 7.5, minimum=1.0, maximum=10.0
        ) == pytest.approx(7.5)


def test_env_float_clamps_finite_values_to_optional_bounds(monkeypatch) -> None:
    monkeypatch.setenv("HELPER_FLOAT", "0.5")
    assert env_float(
        "HELPER_FLOAT", 7.5, minimum=2.0, maximum=10.0
    ) == pytest.approx(2.0)

    monkeypatch.setenv("HELPER_FLOAT", "42.5")
    assert env_float(
        "HELPER_FLOAT", 7.5, minimum=2.0, maximum=10.0
    ) == pytest.approx(10.0)


def test_normalize_hostish_handles_placeholders_and_ports() -> None:
    assert normalize_hostish("-") == ""
    assert normalize_hostish("Example.COM:443") == "example.com"
    assert normalize_hostish("example.com:65535") == "example.com"
    assert normalize_hostish("[2001:db8::1]:8443") == "2001:db8::1"


def test_normalize_hostish_rejects_malformed_authority_ports() -> None:
    for value in (
        "example.com:notaport",
        "example.com:",
        "example.com:65536",
        "[2001:db8::1]:notaport",
        "[2001:db8::1]:65536",
        "https://example.com:notaport/path",
        "https://example.com:/path",
        "https://example.com:65536/path",
        "https://[2001:db8::1]:notaport/path",
        "https://[2001:db8::1]:65536/path",
    ):
        assert normalize_hostish(value) == ""
        assert extract_domain(value) == ""


def test_normalize_hostish_uses_url_parsing_for_scheme_bearing_values() -> None:
    assert normalize_hostish("http://example.com/path") == "example.com"
    assert (
        normalize_hostish("https://user:pass@Example.COM:443/path?x=1#frag")
        == "example.com"
    )
    assert normalize_hostish("https://[2001:db8::1]:8443/path") == "2001:db8::1"


def test_normalize_hostish_rejects_percent_encoded_authority_delimiters() -> None:
    for value in (
        "https://safe.example%2f.evil.example/path",
        "https://safe.example%40evil.example/path",
        "safe.example%2fevil.example",
        "safe.example%5c.evil.example",
    ):
        assert normalize_hostish(value) == ""
        assert extract_domain(value) == ""


def test_extract_domain_prefers_sni_host_then_url() -> None:
    assert (
        extract_domain("https://fallback.example/path", sni="api.example")
        == "api.example"
    )
    assert (
        extract_domain("https://fallback.example/path", host="cdn.example:443")
        == "cdn.example"
    )
    assert extract_domain("https://fallback.example/path") == "fallback.example"


def test_not_cached_reason_matches_expected_labels() -> None:
    assert (
        not_cached_reason("POST", "TCP_MISS/200")
        == "POST method (not cacheable by default)"
    )
    assert (
        not_cached_reason("CONNECT", "TCP_TUNNEL/200")
        == "HTTPS tunnel (CONNECT) — not cacheable without SSL-bump"
    )
    assert (
        not_cached_reason("GET", "TCP_BYPASS/200")
        == "Bypassed (cache deny rule or client no-cache)"
    )
    assert (
        not_cached_reason("GET", "TCP_MISS/302")
        == "Redirect response (302) (often not cached without explicit freshness)"
    )
