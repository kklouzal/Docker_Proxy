from __future__ import annotations

import pytest
from services.forwarding_canary_config import (
    DEFAULT_FORWARDING_CANARY_PATH,
    forwarding_canary_listener_host,
    forwarding_canary_path,
    forwarding_canary_port,
    normalize_forwarding_canary_path,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, DEFAULT_FORWARDING_CANARY_PATH),
        ("/custom-canary", "/custom-canary"),
        ("custom-canary", DEFAULT_FORWARDING_CANARY_PATH),
        ("/custom?query=1", DEFAULT_FORWARDING_CANARY_PATH),
        ("/custom#fragment", DEFAULT_FORWARDING_CANARY_PATH),
        (r"/custom\\path", DEFAULT_FORWARDING_CANARY_PATH),
        ("/custom//path", DEFAULT_FORWARDING_CANARY_PATH),
        ("/custom path", DEFAULT_FORWARDING_CANARY_PATH),
        ("/custom\x00path", DEFAULT_FORWARDING_CANARY_PATH),
        ("/custom\x7fpath", DEFAULT_FORWARDING_CANARY_PATH),
        ("/custom\x80path", DEFAULT_FORWARDING_CANARY_PATH),
    ],
    ids=[
        "default",
        "valid-custom",
        "relative",
        "query",
        "fragment",
        "backslash",
        "double-slash",
        "whitespace",
        "c0-control",
        "del-control",
        "c1-control",
    ],
)
def test_forwarding_canary_path_contract(value: object, expected: str) -> None:
    assert normalize_forwarding_canary_path(value) == expected


def test_forwarding_canary_environment_contract_is_shared(monkeypatch) -> None:
    monkeypatch.setenv("FORWARDING_CANARY_HOST", "127.0.0.2")
    monkeypatch.setenv("FORWARDING_CANARY_PORT", "18081")
    monkeypatch.setenv("FORWARDING_CANARY_PATH", "/custom-canary")

    from services import health_checks, proxy_health
    from services.squid_core import SquidController

    from proxy import forwarding_canary

    assert (
        forwarding_canary_listener_host()
        == forwarding_canary._canary_host()
        == "127.0.0.2"
    )
    assert forwarding_canary_port() == forwarding_canary._canary_port() == 18081
    assert (
        forwarding_canary_path() == forwarding_canary._canary_path() == "/custom-canary"
    )
    assert health_checks._forwarding_canary_path() == "/custom-canary"
    assert (
        proxy_health._forwarding_canary_target_url()
        == "http://127.0.0.2:18081/custom-canary"
    )
    assert SquidController._forwarding_canary_path(None) == "/custom-canary"
    assert SquidController._forwarding_canary_port(None) == 18081


@pytest.mark.parametrize(
    "host",
    ["0.0.0.0", "::1", "127.0.0.1.evil.test"],  # noqa: S104 - unsafe inputs must fail safe.
)
@pytest.mark.parametrize("port", ["0", "65536", "not-a-port"])
def test_forwarding_canary_listener_and_client_fail_safe(
    monkeypatch, host: str, port: str
) -> None:
    monkeypatch.setenv("FORWARDING_CANARY_HOST", host)
    monkeypatch.setenv("FORWARDING_CANARY_PORT", port)

    from services.forwarding_canary_config import forwarding_canary_target_url

    assert forwarding_canary_listener_host() == "127.0.0.1"
    assert forwarding_canary_port() == 18080
    assert forwarding_canary_target_url() == (
        "http://127.0.0.1:18080/__docker_proxy_forwarding_canary"
    )
