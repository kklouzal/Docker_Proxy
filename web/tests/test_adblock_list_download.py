"""Subscription downloads only replace a cached list with a complete, usable list."""

from __future__ import annotations

import contextlib
import http.client
import socket
import threading
from pathlib import Path

import pytest

from .mysql_test_utils import ensure_web_import_path

ensure_web_import_path()

import services.adblock_store as store_module  # ruff: ignore[module-import-not-at-top-of-file]

_GOOD_LIST = "[Adblock Plus 2.0]\n! Title: cached\n||ads.example^\n"


def _serve_once(raw_response: bytes) -> int:
    """Answer one HTTP request with ``raw_response`` and close; return the port."""
    listener = socket.create_server(("127.0.0.1", 0))
    port = int(listener.getsockname()[1])

    def serve() -> None:
        with listener:
            conn, _addr = listener.accept()
            with conn:
                conn.recv(65536)
                conn.sendall(raw_response)

    threading.Thread(target=serve, daemon=True).start()
    return port


def _download(
    tmp_path: Path, monkeypatch, raw_response: bytes
) -> tuple[bool, str, Path]:
    port = _serve_once(raw_response)

    @contextlib.contextmanager
    def open_download_url(_url: str, *, timeout: int):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
        try:
            conn.request("GET", "/list.txt")
            yield conn.getresponse()
        finally:
            conn.close()

    monkeypatch.setattr(store_module, "_validate_download_url", lambda _url: None)
    monkeypatch.setattr(store_module, "_open_download_url", open_download_url)
    store = store_module.AdblockStore(lists_dir=str(tmp_path / "lists"))
    path = Path(store.list_path("easylist"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_GOOD_LIST, encoding="utf-8")
    ok, err, _bytes, _rules = store.download_list(
        "easylist", "https://lists.example/list.txt"
    )
    assert not Path(f"{path}.tmp").exists()
    return ok, err, path


def _response(body: bytes, *, content_length: int | None = None, ctype="text/plain"):
    length = len(body) if content_length is None else content_length
    return (
        b"HTTP/1.1 200 OK\r\n"
        + f"Content-Type: {ctype}\r\nContent-Length: {length}\r\n".encode()
        + b"Connection: close\r\n\r\n"
        + body
    )


def test_truncated_download_keeps_the_cached_list(tmp_path, monkeypatch) -> None:
    body = b"[Adblock Plus 2.0]\n||new.example^\n"
    ok, err, path = _download(
        tmp_path, monkeypatch, _response(body, content_length=len(body) + 500)
    )

    assert ok is False
    assert "truncated" in err
    assert path.read_text(encoding="utf-8") == _GOOD_LIST


@pytest.mark.parametrize(
    ("body", "reason"),
    [
        (b"", "empty"),
        (b"\n  \n", "empty"),
        (b"<!doctype html>\n<html><body>Service unavailable</body></html>\n", "HTML"),
        (b"[Adblock Plus 2.0]\n! Title: empty\n! Expires: 1 day\n", "no rules"),
    ],
)
def test_unusable_download_keeps_the_cached_list(
    tmp_path, monkeypatch, body: bytes, reason: str
) -> None:
    ok, err, path = _download(tmp_path, monkeypatch, _response(body))

    assert ok is False
    assert reason in err
    assert path.read_text(encoding="utf-8") == _GOOD_LIST


def test_complete_download_replaces_the_cached_list(tmp_path, monkeypatch) -> None:
    body = b"[Adblock Plus 2.0]\n! Title: new\n||new.example^\n##.banner\n"
    ok, err, path = _download(tmp_path, monkeypatch, _response(body))

    assert (ok, err) == (True, "")
    assert path.read_bytes() == body


def test_chunked_download_without_content_length_is_accepted(
    tmp_path, monkeypatch
) -> None:
    body = b"||new.example^\n"
    raw = (
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
        + f"{len(body):x}\r\n".encode()
        + body
        + b"\r\n0\r\n\r\n"
    )
    ok, err, path = _download(tmp_path, monkeypatch, raw)

    assert (ok, err) == (True, "")
    assert path.read_bytes() == body


def test_next_download_time_follows_the_failure_backoff() -> None:
    store = store_module.AdblockStore(
        lists_dir="/nonexistent",
        update_interval_seconds=43200,
        download_retry_seconds=900,
    )

    def status(last_success: int, last_attempt: int) -> store_module.ListStatus:
        return store_module.ListStatus(
            key="easylist",
            url="https://lists.example/list.txt",
            enabled=True,
            last_success=last_success,
            last_attempt=last_attempt,
            last_error="" if last_attempt <= last_success else "failed",
            bytes=1,
            rules=1,
        )

    now = 100_000
    # Never downloaded: due now.
    assert store.next_download_ts(status(0, 0), now) == now
    # Last download succeeded: due one update interval later.
    assert store.next_download_ts(status(90_000, 90_000), now) == 90_000 + 43200
    # Last attempt failed: retried after the backoff, not at the interval.
    assert store.next_download_ts(status(50_000, 99_800), now) == 99_800 + 900
    assert store.next_download_ts(status(0, 99_800), now) == 99_800 + 900
    # A failed refresh of a recent good copy waits for the interval as well.
    assert store.next_download_ts(status(99_000, 99_800), now) == 99_000 + 43200
    # Overdue is reported as now.
    assert store.next_download_ts(status(1, 1), now) == now
