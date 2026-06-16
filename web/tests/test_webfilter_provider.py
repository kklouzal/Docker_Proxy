from __future__ import annotations

import socket
import sys
from pathlib import Path

import pytest


def _ensure_web_import_path() -> None:
    web_dir = Path(__file__).resolve().parents[1]
    if str(web_dir) not in sys.path:
        sys.path.insert(0, str(web_dir))


def _import_webfilter_store_module():
    _ensure_web_import_path()
    from services import webfilter_store  # type: ignore

    return webfilter_store


def test_webfilter_core_uses_shared_idna_normalization() -> None:
    m = _import_webfilter_store_module()

    assert m._norm_domain("http://Bücher.Example:8080/path") == "xn--bcher-kva.example"
    assert m._looks_like_host("http://Bücher.Example:8080/path") is True


def test_webfilter_whitelist_remove_normalizes_like_add(monkeypatch) -> None:
    m = _import_webfilter_store_module()
    store = m.WebFilterStore()
    deletes: list[tuple[object, ...]] = []

    class FakeConn:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, _sql, params=()):
            deletes.append(tuple(params or ()))

    monkeypatch.setattr(store, "init_db", lambda: None)
    monkeypatch.setattr(store, "_connect", FakeConn)

    store.remove_whitelist(".Bücher.Example")

    assert deletes == [("default", "*.xn--bcher-kva.example")]


def test_sslfilter_domain_policy_uses_shared_idna_normalization() -> None:
    _ensure_web_import_path()
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


def test_webfilter_loop_preserves_refresh_request_after_failed_build(
    monkeypatch,
) -> None:
    m = _import_webfilter_store_module()
    store = m.WebFilterStore()
    values = {
        "refresh_requested": "1",
        "next_run_ts": "900",
        "last_error": "",
    }
    sleeps: list[float] = []

    class StopLoopError(Exception):
        pass

    class FakeConn:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    def stop_after_sleep(seconds: float):
        sleeps.append(seconds)
        raise StopLoopError

    monkeypatch.setenv("WEBFILTER_ENABLED_POLL_SECONDS", "120")
    monkeypatch.setenv("WEBFILTER_ERROR_BACKOFF_SECONDS", "9")
    monkeypatch.setattr(m, "_now", lambda: 1000)
    monkeypatch.setattr(store, "init_db", lambda: None)
    monkeypatch.setattr(store, "_connect", FakeConn)
    monkeypatch.setattr(
        store,
        "_get_global_setting_conn",
        lambda _conn, key, default="": {
            "source_url": "https://example.test/categories.tar.gz",
            "source_provider": "auto",
            "next_run_ts": values["next_run_ts"],
        }.get(key, default),
    )
    monkeypatch.setattr(
        store,
        "_refresh_requested_conn",
        lambda _conn: values["refresh_requested"] == "1",
    )
    monkeypatch.setattr(
        store,
        "_category_build_needed_conn",
        lambda _conn: True,
    )
    monkeypatch.setattr(
        store,
        "_run_build",
        lambda _source_url, *, source_provider="auto": (False, "download failed"),
    )

    def record_attempt(_conn, *, ok: bool, err: str) -> None:
        assert ok is False
        values["last_error"] = err

    def clear_refresh(_conn) -> None:
        values["refresh_requested"] = "0"

    def set_next_run(_conn, *, ts: int) -> None:
        values["next_run_ts"] = str(ts)

    monkeypatch.setattr(store, "_record_attempt_conn", record_attempt)
    monkeypatch.setattr(store, "_clear_refresh_requested_conn", clear_refresh)
    monkeypatch.setattr(store, "_set_next_run_conn", set_next_run)
    monkeypatch.setattr(m.time, "sleep", stop_after_sleep)

    with pytest.raises(StopLoopError):
        store._loop()

    assert sleeps == [9.0]
    assert values["refresh_requested"] == "1"
    assert values["next_run_ts"] == "900"
    assert values["last_error"] == "download failed"


@pytest.mark.parametrize(
    "source_url",
    [
        "file:///etc/passwd",
        "http://127.0.0.1/feed.csv",
        "http://localhost/feed.csv",
        "http://proxy.internal/feed.csv",
        "https://feed-user:feed-pass@example.test/feed.csv",
        r"https://example.test\@127.0.0.1/feed.csv",
        r"https://example.test\path/feed.csv",
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


def test_webfilter_source_url_validation_reports_embedded_credentials(
    monkeypatch,
) -> None:
    m = _import_webfilter_store_module()
    download_safety = m.validate_source_url.__globals__["download_safety"]

    monkeypatch.setattr(
        download_safety.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("credential-bearing URLs should not reach DNS")
        ),
    )

    with pytest.raises(ValueError, match="embedded credentials"):
        m.validate_source_url("https://feed-user:feed-pass@example.test/feed.csv")


@pytest.mark.parametrize(
    "source_url",
    [
        r"https://example.test\@127.0.0.1/feed.csv",
        r"https://example.test\path/feed.csv",
    ],
)
def test_webfilter_source_url_validation_reports_malformed_urls(
    source_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    m = _import_webfilter_store_module()
    download_safety = m.validate_source_url.__globals__["download_safety"]

    monkeypatch.setattr(
        download_safety.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("malformed URLs should not reach DNS")
        ),
    )

    with pytest.raises(ValueError, match="valid absolute HTTP/HTTPS"):
        m.validate_source_url(source_url)


@pytest.mark.parametrize(
    "source_url",
    [
        "http://127.0.0.1/feed.csv",
        "https://feed-user:feed-pass@example.test/feed.csv",
        r"https://example.test\path/feed.csv",
    ],
)
def test_webfilter_store_rejects_disabled_unsafe_source_before_persistence(
    source_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    m = _import_webfilter_store_module()
    store = m.WebFilterStore()
    download_safety = m.validate_source_url.__globals__["download_safety"]

    monkeypatch.setattr(store, "init_db", lambda: None)
    monkeypatch.setattr(
        store,
        "_connect",
        lambda: (_ for _ in ()).throw(
            AssertionError("unsafe source should not reach persistence")
        ),
    )
    monkeypatch.setattr(
        download_safety.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("unsafe source should not reach DNS")
        ),
    )

    with pytest.raises(ValueError):
        store.set_settings(
            enabled=True,
            source_url=source_url,
            blocked_categories=["adult"],
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
