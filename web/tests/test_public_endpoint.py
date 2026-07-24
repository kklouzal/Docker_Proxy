from __future__ import annotations

import sys
from pathlib import Path

import pytest


def _add_web_to_path() -> None:
    web_dir = Path(__file__).resolve().parents[1]
    if str(web_dir) not in sys.path:
        sys.path.insert(0, str(web_dir))


@pytest.mark.parametrize(
    "value",
    [
        "localhost",
        "LOCALHOST.",
        "localhost.localdomain",
        "api.localhost",
        "printer.local",
        "proxy.internal",
        "ip6-localhost",
        "ip6-loopback",
        "gateway.home.arpa",
        "http://localhost:8080/proxy.pac",
        "https://proxy.internal/wpad.dat",
    ],
)
def test_normalize_public_host_rejects_internal_reserved_dns_names(value: str) -> None:
    _add_web_to_path()
    from services.public_endpoint import normalize_public_host  # type: ignore

    assert normalize_public_host(value) == ""
    assert normalize_public_host(value, default="fallback.example") == "fallback.example"


@pytest.mark.parametrize(
    "value",
    [
        "proxy",
        "Proxy.",
        "http://proxy:8080/proxy.pac",
    ],
)
def test_normalize_public_host_rejects_single_label_dns_names(value: str) -> None:
    _add_web_to_path()
    from services.public_endpoint import normalize_public_host  # type: ignore

    assert normalize_public_host(value) == ""
    assert normalize_public_host(value, default="fallback.example") == "fallback.example"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("proxy", "proxy"),
        ("Proxy-Edge-2.", "proxy-edge-2"),
        ("http://proxy:8080/proxy.pac", "proxy"),
    ],
)
def test_normalize_public_host_allows_explicit_single_label_dns_names(
    value: str,
    expected: str,
) -> None:
    _add_web_to_path()
    from services.public_endpoint import normalize_public_host  # type: ignore

    assert normalize_public_host(value, allow_single_label=True) == expected


@pytest.mark.parametrize(
    "value",
    [
        "127.0.0.1",
        "10.0.0.1",
        "::1",
        "[::1]:8080",
        "169.254.1.1",
        "0.0.0.0",  # noqa: S104 - verifies wildcard public endpoint is rejected.
        "224.0.0.1",
        "http://10.0.0.1/proxy.pac",
    ],
)
def test_normalize_public_host_rejects_non_public_ip_literals(value: str) -> None:
    _add_web_to_path()
    from services.public_endpoint import normalize_public_host  # type: ignore

    assert normalize_public_host(value) == ""
    assert normalize_public_host(value, default="fallback.example") == "fallback.example"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("Proxy-Edge.Example.COM.", "proxy-edge.example.com"),
        ("https://Proxy-Edge.Example.COM:8443/proxy.pac", "proxy-edge.example.com"),
        ("93.184.216.34", "93.184.216.34"),
        ("[2001:4860:4860::8888]:8080", "2001:4860:4860::8888"),
    ],
)
def test_normalize_public_host_accepts_public_endpoint_hosts(
    value: str,
    expected: str,
) -> None:
    _add_web_to_path()
    from services.public_endpoint import normalize_public_host  # type: ignore

    assert normalize_public_host(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "proxy.example]",
        "proxy.example[",
        "93.184.216.34]",
        "2001:4860:4860::8888]",
    ],
)
def test_normalize_public_host_rejects_stray_authority_brackets(value: str) -> None:
    _add_web_to_path()
    from services.public_endpoint import normalize_public_host  # type: ignore

    assert normalize_public_host(value) == ""
    assert normalize_public_host(value, default="fallback.example") == "fallback.example"


@pytest.mark.parametrize(
    "value",
    [
        "proxy.example:",
        "https://proxy.example:",
        "http://proxy.example:/proxy.pac",
        "[2001:4860:4860::8888]:",
        "https://[2001:4860:4860::8888]:/proxy.pac",
    ],
)
def test_normalize_public_host_rejects_empty_explicit_authority_ports(value: str) -> None:
    _add_web_to_path()
    from services.public_endpoint import normalize_public_host  # type: ignore

    assert normalize_public_host(value) == ""
    assert normalize_public_host(value, default="fallback.example") == "fallback.example"


@pytest.mark.parametrize(
    "value",
    [
        "proxy.example:0",
        "https://proxy.example:0/proxy.pac",
        "[2001:4860:4860::8888]:0",
        "https://[2001:4860:4860::8888]:0/proxy.pac",
    ],
)
def test_normalize_public_host_rejects_zero_explicit_authority_ports(value: str) -> None:
    _add_web_to_path()
    from services.public_endpoint import normalize_public_host  # type: ignore

    assert normalize_public_host(value) == ""
    assert normalize_public_host(value, default="fallback.example") == "fallback.example"
