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


def test_normalize_domain_preserves_supported_host_forms() -> None:
    assert normalize_domain("https://Bücher.Example:443/path") == (
        "xn--bcher-kva.example"
    )
    assert normalize_domain("example.com:443") == "example.com"
    assert normalize_domain("localhost") == "localhost"
    assert normalize_domain("traffic-fixture") == "traffic-fixture"
    assert normalize_domain("[2001:db8::1]:443") == "2001:db8::1"


def test_normalize_domain_preserves_valid_ipv6_literals_only() -> None:
    assert normalize_domain("2001:db8::1") == "2001:db8::1"
    assert normalize_domain("[2001:db8::1]:443") == "2001:db8::1"
    assert normalize_domain("example.com:abc:def") == ""
    assert normalize_domain("[2001:db8::1]:abc") == ""
