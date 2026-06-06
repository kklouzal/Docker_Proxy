from __future__ import annotations

import socket
import sys
from pathlib import Path

import pytest


def _import_webfilter_store_module():
    web_dir = Path(__file__).resolve().parents[1]
    if str(web_dir) not in sys.path:
        sys.path.insert(0, str(web_dir))
    from services import webfilter_store  # type: ignore

    return webfilter_store


def test_webfilter_core_uses_shared_idna_normalization() -> None:
    m = _import_webfilter_store_module()

    assert m._norm_domain("http://Bücher.Example:8080/path") == "xn--bcher-kva.example"
    assert m._looks_like_host("http://Bücher.Example:8080/path") is True


def test_sslfilter_domain_policy_uses_shared_idna_normalization() -> None:
    web_dir = Path(__file__).resolve().parents[1]
    if str(web_dir) not in sys.path:
        sys.path.insert(0, str(web_dir))
    from services import sslfilter_store  # type: ignore

    assert sslfilter_store._normalize_domain_rule(
        "https://Bücher.Example:443/path"
    ) == (True, "", "xn--bcher-kva.example")
    assert sslfilter_store._normalize_domain_rule("*.Bücher.Example") == (
        True,
        "",
        "*.xn--bcher-kva.example",
    )
    assert (
        sslfilter_store._normalize_domain_for_squid("*.Bücher.Example")
        == ".xn--bcher-kva.example"
    )
    ok, detail, canonical = sslfilter_store._normalize_domain_rule("bad/example")
    assert ok is False
    assert canonical == ""
    assert "invalid domain characters" in detail.lower()


def test_webfilter_run_build_passes_provider_to_builder() -> None:
    m = _import_webfilter_store_module()
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv

        class Result:
            returncode = 0
            stdout = b""
            stderr = b""

        return Result()

    old_run = m.run
    try:
        m.run = fake_run
        ok, err = m.WebFilterStore()._run_build(
            "https://example.test/feed.csv", source_provider="csv"
        )
    finally:
        m.run = old_run

    assert ok is True
    assert err == ""
    assert "--provider" in captured["argv"]
    assert captured["argv"][captured["argv"].index("--provider") + 1] == "csv"


def test_webfilter_run_build_defaults_invalid_provider_to_auto() -> None:
    m = _import_webfilter_store_module()
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv

        class Result:
            returncode = 0
            stdout = b""
            stderr = b""

        return Result()

    old_run = m.run
    try:
        m.run = fake_run
        ok, _err = m.WebFilterStore()._run_build(
            "https://example.test/feed.csv", source_provider="bad-provider"
        )
    finally:
        m.run = old_run

    assert ok is True
    assert captured["argv"][captured["argv"].index("--provider") + 1] == "auto"


def test_webfilter_loop_uses_error_backoff_for_database_outages(monkeypatch) -> None:
    m = _import_webfilter_store_module()
    store = m.WebFilterStore()
    sleeps: list[float] = []

    class StopLoopError(Exception):
        pass

    def fail_init_db():
        raise m.DATABASE_ERRORS[0](2003, "database unavailable")

    def stop_after_sleep(seconds: float):
        sleeps.append(seconds)
        raise StopLoopError

    monkeypatch.setenv("WEBFILTER_ENABLED_POLL_SECONDS", "120")
    monkeypatch.setenv("WEBFILTER_ERROR_BACKOFF_SECONDS", "7")
    monkeypatch.setattr(store, "init_db", fail_init_db)
    monkeypatch.setattr(m, "log_database_unavailable", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(m.time, "sleep", stop_after_sleep)

    with pytest.raises(StopLoopError):
        store._loop()

    assert sleeps == [7.0]


@pytest.mark.parametrize(
    "source_url",
    [
        "file:///etc/passwd",
        "http://127.0.0.1/feed.csv",
        "http://localhost/feed.csv",
        "http://proxy.internal/feed.csv",
        "http://exa mple.com/feed.csv",
        "https://example.test/feed file.csv",
        "http://[::1",
    ],
)
def test_webfilter_source_url_validation_rejects_unsafe_targets(
    source_url, monkeypatch
) -> None:
    m = _import_webfilter_store_module()
    download_safety = m.validate_source_url.__globals__["download_safety"]

    with pytest.raises(ValueError):
        m.validate_source_url(source_url)

    def fake_getaddrinfo(*_args, **_kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]

    monkeypatch.setattr(download_safety.socket, "getaddrinfo", fake_getaddrinfo)

    assert (
        m.validate_source_url(" https://example.test/feed.csv ")
        == "https://example.test/feed.csv"
    )


def test_webfilter_source_url_validation_rejects_unverifiable_dns(monkeypatch) -> None:
    m = _import_webfilter_store_module()
    download_safety = m.validate_source_url.__globals__["download_safety"]

    def fake_getaddrinfo(*_args, **_kwargs):
        msg = "dns unavailable"
        raise socket.gaierror(msg)

    monkeypatch.setattr(download_safety.socket, "getaddrinfo", fake_getaddrinfo)

    with pytest.raises(ValueError):
        m.validate_source_url("https://unresolved.example.test/feed.csv")
