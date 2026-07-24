from __future__ import annotations

import sys
from pathlib import Path


def _add_web_to_path() -> None:
    web_dir = Path(__file__).resolve().parents[1]
    if str(web_dir) not in sys.path:
        sys.path.insert(0, str(web_dir))


_add_web_to_path()

from services.domain_normalization import (  # type: ignore  # noqa: E402
    looks_like_domain,
    normalize_domain,
)


def test_normalize_domain_rejects_consecutive_empty_labels() -> None:
    assert normalize_domain("bad..example") == ""
    assert normalize_domain("https://bad..example/path") == ""
    assert looks_like_domain("bad..example") is False


def test_normalize_domain_preserves_intentional_leading_and_trailing_dot_cleanup() -> None:
    assert normalize_domain(".Example.COM.") == "example.com"


def test_normalize_domain_rejects_malformed_named_ports() -> None:
    assert normalize_domain("example.com:http") == ""
    assert normalize_domain("example.com:abc") == ""
    assert normalize_domain("user@example.com:abc") == ""
    assert normalize_domain("http://example.com:http/path") == ""


def test_normalize_domain_rejects_raw_userinfo_or_email_like_hosts() -> None:
    for value in (
        "user@example.com",
        "operator:secret@example.com",
        "example.com@evil.test",
    ):
        assert normalize_domain(value) == ""
        assert looks_like_domain(value) is False


def test_normalize_domain_preserves_explicit_url_userinfo_hostname() -> None:
    assert normalize_domain("https://user:pass@Example.COM:443/path") == "example.com"


def test_normalize_domain_preserves_legacy_bare_userinfo_authority_tokens() -> None:
    assert normalize_domain("user@Example.COM:443") == "example.com"
    assert normalize_domain("user@[2001:db8::1]:443") == "2001:db8::1"


def test_normalize_domain_rejects_ambiguous_raw_userinfo_without_port() -> None:
    for value in (
        "user@example.com",
        "operator:secret@example.com:443",
        "example.com@evil.test:443",
        "user@example.com:notaport",
    ):
        assert normalize_domain(value) == ""
        assert looks_like_domain(value) is False


def test_normalize_domain_rejects_malformed_dns_labels_and_wildcards() -> None:
    for value in (
        "bad domain.example",
        "_bad.example",
        "-bad.example",
        "bad-.example",
        "bad.-example",
        "*.example.com",
        "bad/example",
        "bad?example.com",
    ):
        assert normalize_domain(value) == ""
        assert looks_like_domain(value) is False


def test_normalize_domain_rejects_ambiguous_ipv4_host_forms() -> None:
    for value in (
        "12345",
        "127.1",
        "0177.0.0.1",
        "0x7f000001",
        "http://127.1:8080/path",
    ):
        assert normalize_domain(value) == ""
        assert looks_like_domain(value) is False


def test_normalize_domain_preserves_supported_host_forms() -> None:
    assert normalize_domain("https://Bücher.Example:443/path") == (
        "xn--bcher-kva.example"
    )
    assert normalize_domain("example.com:443") == "example.com"
    assert normalize_domain("localhost") == "localhost"
    assert normalize_domain("traffic-fixture") == "traffic-fixture"
    assert normalize_domain("[2001:db8::1]:443") == "2001:db8::1"


def test_normalize_domain_preserves_canonical_ipv4_literals() -> None:
    assert normalize_domain("192.168.1.10") == "192.168.1.10"
    assert normalize_domain("http://192.168.1.10:8080/path") == "192.168.1.10"
    assert normalize_domain("255.255.255.255") == "255.255.255.255"


def test_normalize_domain_preserves_valid_ipv6_literals_only() -> None:
    assert normalize_domain("2001:db8::1") == "2001:db8::1"
    assert normalize_domain("[2001:db8::1]:443") == "2001:db8::1"
    assert normalize_domain("example.com:abc:def") == ""
    assert normalize_domain("[2001:db8::1]:abc") == ""
