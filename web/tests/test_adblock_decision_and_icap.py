from __future__ import annotations

import socket
import sys
import threading
from pathlib import Path

import pytest

from .test_adblock_lookup import _add_web_to_path, _build_lookup_db


@pytest.mark.parametrize(
    ("method", "url", "headers", "expected"),
    [
        (
            "GET",
            "https://api.example.com/data",
            {"Sec-Fetch-Dest": "empty", "Sec-Fetch-Mode": "cors"},
            "xmlhttprequest",
        ),
        (
            "GET",
            "https://api.example.com/data",
            {"X-Requested-With": "XMLHttpRequest"},
            "xmlhttprequest",
        ),
        (
            "GET",
            "https://static.example/frame.html",
            {"Sec-Fetch-Dest": "iframe"},
            "subdocument",
        ),
        (
            "GET",
            "https://static.example/app-worker",
            {"Sec-Fetch-Dest": "worker"},
            "script",
        ),
        (
            "GET",
            "https://static.example/styles",
            {"Sec-Fetch-Dest": "style"},
            "stylesheet",
        ),
        (
            "GET",
            "https://static.example/font",
            {"Sec-Fetch-Dest": "font"},
            "font",
        ),
        (
            "GET",
            "https://static.example/movie",
            {"Sec-Fetch-Dest": "video"},
            "media",
        ),
        (
            "POST",
            "https://metrics.example/ping",
            {"Ping-To": "https://target.example/"},
            "ping",
        ),
        (
            "POST",
            "https://api.example.com/data",
            {"Accept": "application/json"},
            "xmlhttprequest",
        ),
        (
            "GET",
            "https://fonts.example/font",
            {"Accept": "font/woff2"},
            "font",
        ),
    ],
)
def test_infer_resource_type_uses_browser_fetch_metadata(
    method: str,
    url: str,
    headers: dict[str, str],
    expected: str,
) -> None:
    _add_web_to_path()
    from services.adblock_decision import infer_resource_type

    assert infer_resource_type(method, url, headers) == expected


def test_sqlite_decision_engine_applies_full_abp_semantics(tmp_path: Path) -> None:
    db_path = _build_lookup_db(
        tmp_path,
        [
            "||ads.example^",
            "@@||ads.example/allowed.js$script",
            "||cdn.example.com/assets/ad.js^$script",
            "||cdn.example.com/assets/ad.css^$~stylesheet",
            "wss://loader.*.com/ws^$websocket,third-party",
            "/tracker[.]example/$third-party",
            "plain-ad-token$domain=source.example",
            "||api.example.com/path$method=POST,denyallow=allowed.example",
            "||api.example.com/ads^$xmlhttprequest",
            "||static.example/frame^$subdocument",
            "@@||important.example/ads^",
            "||important.example/ads^$important",
            "CaseSensitive$match-case",
            "||static.example/CasePath^$match-case",
            "modifier-token$redirect=noopjs",
            "@@||tiktok.com^$generichide",
            "||analytics.tiktok.com^",
            "||fetchsite.example^$third-party",
            "||scoped-fetchsite.example^$third-party,domain=source.example",
            "||excluded-scope.example^$third-party,domain=~excluded.example",
            "||ads.example.co.uk^$third-party",
            "||adserver.local^$third-party",
            "https://192.168.1.20/banner.js$third-party",
            "||[2001:db8::20]^$third-party,domain=~[2001:db8::20]",
        ],
    )

    _add_web_to_path()
    from services.adblock_decision import AdblockDecisionEngine

    engine = AdblockDecisionEngine(db_path, cache_ttl_seconds=0, cache_max=0)

    assert engine.decide("https://sub.ads.example/banner.js").blocked is True
    assert engine.decide("https://user:pass@sub.ads.example/banner.js").blocked is True
    exception = engine.decide(
        "https://ads.example/allowed.js",
        headers={"accept": "application/javascript"},
    )
    assert exception.blocked is False
    assert exception.reason == "exception"

    assert (
        engine.decide(
            "https://cdn.example.com/assets/ad.js?slot=1",
            headers={"accept": "application/javascript"},
        ).blocked
        is True
    )
    assert (
        engine.decide(
            "https://cdn.example.com/assets/ad.css",
            headers={"accept": "text/css"},
        ).blocked
        is False
    )
    assert (
        engine.decide(
            "wss://loader.foo.com/ws",
            headers={"upgrade": "websocket", "referer": "https://source.example/"},
        ).blocked
        is True
    )
    assert (
        engine.decide(
            "https://static.example/plain-ad-token.js",
            headers={"referer": "https://source.example/page"},
        ).blocked
        is True
    )
    assert (
        engine.decide(
            "https://static.example/plain-ad-token.js",
            headers={"referer": "https://other.example/page"},
        ).blocked
        is False
    )
    assert (
        engine.decide(
            "https://api.example.com/path",
            method="POST",
        ).blocked
        is True
    )
    assert (
        engine.decide(
            "https://api.example.com/ads/data",
            headers={
                "accept": "application/json",
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
            },
        ).blocked
        is True
    )
    assert (
        engine.decide(
            "https://api.example.com/ads/data",
            headers={"accept": "application/json"},
        ).blocked
        is False
    )
    assert (
        engine.decide(
            "https://static.example/frame/ad.html",
            headers={"sec-fetch-dest": "iframe"},
        ).blocked
        is True
    )
    important = engine.decide("https://important.example/ads/banner.js")
    assert important.blocked is True
    assert important.reason == "important-rule-match"
    assert (
        engine.decide(
            "https://allowed.example/path",
            method="POST",
        ).blocked
        is False
    )
    assert engine.decide("https://static.example/CaseSensitive.js").blocked is True
    assert engine.decide("https://static.example/casesensitive.js").blocked is False
    assert engine.decide("https://static.example/CasePath/banner.js").blocked is True
    assert engine.decide("https://static.example/casepath/banner.js").blocked is False
    assert engine.decide("https://static.example/modifier-token.js").blocked is False
    analytics_tiktok = engine.decide("https://analytics.tiktok.com/i18n/pixel/events.js")
    assert analytics_tiktok.blocked is True
    assert analytics_tiktok.raw == "||analytics.tiktok.com^"
    assert (
        engine.decide(
            "https://fetchsite.example/ads.js",
            headers={"Sec-Fetch-Site": "cross-site"},
        ).blocked
        is True
    )
    assert (
        engine.decide(
            "https://fetchsite.example/ads.js",
            headers={"Sec-Fetch-Site": "same-site"},
        ).blocked
        is False
    )
    assert (
        engine.decide(
            "https://scoped-fetchsite.example/ads.js",
            headers={"Sec-Fetch-Site": "cross-site"},
        ).blocked
        is False
    )
    assert (
        engine.decide(
            "https://scoped-fetchsite.example/ads.js",
            headers={"Referer": "https://source.example/page"},
        ).blocked
        is True
    )
    assert (
        engine.decide(
            "https://excluded-scope.example/ads.js",
            headers={"Sec-Fetch-Site": "cross-site"},
        ).blocked
        is False
    )
    assert (
        engine.decide(
            "https://excluded-scope.example/ads.js",
            headers={"Referer": "https://other.example/page"},
        ).blocked
        is True
    )
    assert (
        engine.decide(
            "https://excluded-scope.example/ads.js",
            headers={"Referer": "https://excluded.example/page"},
        ).blocked
        is False
    )
    assert (
        engine.decide(
            "https://ads.example.co.uk/banner.js",
            headers={"referer": "https://shop.other.co.uk/"},
        ).blocked
        is True
    )
    assert (
        engine.decide(
            "https://ads.example.co.uk/banner.js",
            headers={"referer": "https://shop.example.co.uk/"},
        ).blocked
        is False
    )
    assert (
        engine.decide(
            "https://adserver.local/banner.js",
            headers={"referer": "https://intranet.local/"},
        ).blocked
        is True
    )
    assert (
        engine.decide(
            "https://adserver.local/banner.js",
            headers={"referer": "https://adserver.local/"},
        ).blocked
        is False
    )
    assert (
        engine.decide(
            "https://192.168.1.20/banner.js",
            headers={"referer": "https://192.168.1.10/"},
        ).blocked
        is True
    )
    assert (
        engine.decide(
            "https://192.168.1.20/banner.js",
            headers={"referer": "https://192.168.1.20/"},
        ).blocked
        is False
    )
    assert (
        engine.decide(
            "https://[2001:db8::20]/banner.js",
            headers={"referer": "https://[2001:db8::10]/"},
        ).blocked
        is True
    )
    assert (
        engine.decide(
            "https://[2001:db8::20]/banner.js",
            headers={"referer": "https://[2001:db8:0:0:0:0:0:20]/"},
        ).blocked
        is False
    )


def _send_icap(port: int, payload: bytes) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=2.0) as sock:
        sock.settimeout(2.0)
        sock.sendall(payload)
        chunks: list[bytes] = []
        while True:
            try:
                chunk = sock.recv(65536)
            except TimeoutError:
                break
            if not chunk:
                break
            chunks.append(chunk)
            if b"\r\n\r\n" in b"".join(chunks):
                break
        return b"".join(chunks)


def _recv_icap_headers(sock: socket.socket) -> bytes:
    chunks: list[bytes] = []
    while b"\r\n\r\n" not in b"".join(chunks):
        chunk = sock.recv(65536)
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def _recv_icap_response_count(sock: socket.socket, count: int) -> bytes:
    chunks: list[bytes] = []
    while b"".join(chunks).count(b"ICAP/1.0 ") < count:
        chunk = sock.recv(65536)
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


class _ChunkedSocket:
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks

    def settimeout(self, _timeout: float) -> None:
        return

    def recv(self, n: int) -> bytes:
        if not self._chunks:
            return b""
        chunk = self._chunks.pop(0)
        if len(chunk) <= n:
            return chunk
        self._chunks.insert(0, chunk[n:])
        return chunk[:n]


def test_adblock_icap_parse_http_request_normalizes_connect_authority() -> None:
    _add_web_to_path()
    from tools.adblock_icap_server import _parse_http_request

    method, url, headers = _parse_http_request(
        b"CONNECT ads.example:443 HTTP/1.1\r\n"
        b"Host: ads.example:443\r\n"
        b"User-Agent: probe\r\n\r\n",
    )

    assert method == "CONNECT"
    assert url == "https://ads.example:443/"
    assert headers["host"] == "ads.example:443"


def test_adblock_icap_extracts_request_headers_without_buffering_body() -> None:
    _add_web_to_path()
    from tools.adblock_icap_server import (
        _encapsulated_http_request,
        _parse_http_request,
    )

    http = (
        b"POST http://ads.example/collect HTTP/1.1\r\n"
        b"Host: ads.example\r\n"
        b"Content-Length: 7\r\n\r\n"
    )
    body = b"7\r\npayload\r\n0\r\n\r\n"
    icap = (
        b"REQMOD icap://127.0.0.1/adblockreq ICAP/1.0\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Encapsulated: req-hdr=0, req-body="
        + str(len(http)).encode("ascii")
        + b"\r\n\r\n"
        + http
        + body
    )

    method, url, headers = _parse_http_request(_encapsulated_http_request(icap))

    assert method == "POST"
    assert url == "http://ads.example/collect"
    assert headers["host"] == "ads.example"
    assert headers["content-length"] == "7"


def test_adblock_icap_reads_preview_zero_chunk_before_responding() -> None:
    _add_web_to_path()
    from tools.adblock_icap_server import _read_icap_message

    http = (
        b"POST http://ads.example/collect HTTP/1.1\r\n"
        b"Host: ads.example\r\n"
        b"Content-Length: 7\r\n\r\n"
    )
    headers = (
        b"REQMOD icap://127.0.0.1/adblockreq ICAP/1.0\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Preview: 0\r\n"
        b"Encapsulated: req-hdr=0, req-body="
        + str(len(http)).encode("ascii")
        + b"\r\n\r\n"
    )
    sock = _ChunkedSocket([headers[:32], headers[32:] + http[:10], http[10:], b"0\r\n\r\n"])

    message, pending, force_close = _read_icap_message(
        sock,
        max_bytes=65536,
        max_body_drain_bytes=65536,
        timeout_seconds=5.0,
    )

    assert message.endswith(b"0\r\n\r\n")
    assert pending == b""
    assert force_close is False


def test_adblock_icap_server_blocks_connect_authority_requests(tmp_path: Path) -> None:
    db_path = _build_lookup_db(tmp_path, ["||ads.example^"])
    log_path = tmp_path / "cicap-access.log"

    _add_web_to_path()
    from services.adblock_decision import AdblockDecisionEngine
    from tools.adblock_icap_server import _AdblockIcapServer

    server = _AdblockIcapServer(
        ("127.0.0.1", 0),
        engine=AdblockDecisionEngine(db_path, cache_ttl_seconds=0, cache_max=0),
        access_log_path=str(log_path),
        max_request_bytes=65536,
    )
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        http = (
            b"CONNECT ads.example:443 HTTP/1.1\r\n"
            b"Host: ads.example:443\r\n"
            b"User-Agent: proxy-probe\r\n\r\n"
        )
        req = (
            b"REQMOD icap://127.0.0.1/adblockreq ICAP/1.0\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Encapsulated: req-hdr=0, null-body="
            + str(len(http)).encode("ascii")
            + b"\r\n\r\n"
            + http
        )
        response = _send_icap(port, req)
        assert response.startswith(b"ICAP/1.0 200")
        icap_header = response.split(b"\r\n\r\n", 1)[0]
        assert b"Connection: close" not in icap_header
        assert b"HTTP/1.1 403 Forbidden" in response
        log_text = log_path.read_text(encoding="utf-8")
        assert "CONNECT https://ads.example:443/ HTTP/1.1" in log_text
    finally:
        server.shutdown()
        server.server_close()


def test_adblock_icap_server_blocks_post_requests_with_preview_zero(
    tmp_path: Path,
) -> None:
    db_path = _build_lookup_db(tmp_path, ["||ads.example^$method=post"])
    log_path = tmp_path / "cicap-access.log"
    recorded_blocks: list[str] = []

    _add_web_to_path()
    from services.adblock_decision import AdblockDecisionEngine
    from tools.adblock_icap_server import _AdblockIcapServer

    server = _AdblockIcapServer(
        ("127.0.0.1", 0),
        engine=AdblockDecisionEngine(db_path, cache_ttl_seconds=0, cache_max=0),
        access_log_path=str(log_path),
        max_request_bytes=65536,
        block_recorder=recorded_blocks.append,
    )
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        http = (
            b"POST http://ads.example/collect HTTP/1.1\r\n"
            b"Host: ads.example\r\n"
            b"Content-Length: 7\r\n\r\n"
        )
        req = (
            b"REQMOD icap://127.0.0.1/adblockreq ICAP/1.0\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Preview: 0\r\n"
            b"Encapsulated: req-hdr=0, req-body="
            + str(len(http)).encode("ascii")
            + b"\r\n\r\n"
            + http
            + b"0\r\n\r\n"
        )
        response = _send_icap(port, req)
        assert response.startswith(b"ICAP/1.0 200")
        icap_header = response.split(b"\r\n\r\n", 1)[0]
        assert b"Connection: close" not in icap_header
        assert b"HTTP/1.1 403 Forbidden" in response
        log_text = log_path.read_text(encoding="utf-8")
        assert "POST http://ads.example/collect HTTP/1.1" in log_text
        assert recorded_blocks == ["sample"]
    finally:
        server.shutdown()
        server.server_close()


def test_adblock_icap_server_uses_sqlite_decisions_and_logs_blocks(
    tmp_path: Path,
) -> None:
    db_path = _build_lookup_db(tmp_path, ["||ads.example^"])
    log_path = tmp_path / "cicap-access.log"
    recorded_blocks: list[str] = []

    _add_web_to_path()
    from services.adblock_decision import AdblockDecisionEngine
    from tools.adblock_icap_server import _AdblockIcapServer

    engine = AdblockDecisionEngine(db_path, cache_ttl_seconds=0, cache_max=0)
    assert engine.decide("http://ads.example/banner.js").list_key == "sample"
    server = _AdblockIcapServer(
        ("127.0.0.1", 0),
        engine=engine,
        access_log_path=str(log_path),
        max_request_bytes=65536,
        block_recorder=recorded_blocks.append,
    )
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        options = _send_icap(
            port,
            (
                b"OPTIONS icap://127.0.0.1/adblockreq ICAP/1.0\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Encapsulated: null-body=0\r\n\r\n"
            ),
        )
        assert options.startswith(b"ICAP/1.0 200")
        assert b"Methods: REQMOD" in options
        assert b"Preview: 0" in options
        assert b"Connection: close" not in options

        http = (
            b"GET http://ads.example/banner.js HTTP/1.1\r\n"
            b"Host: ads.example\r\n"
            b"Accept: application/javascript\r\n\r\n"
        )
        req = (
            b"REQMOD icap://127.0.0.1/adblockreq ICAP/1.0\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Encapsulated: req-hdr=0, null-body="
            + str(len(http)).encode("ascii")
            + b"\r\n\r\n"
            + http
        )
        response = _send_icap(port, req)
        assert response.startswith(b"ICAP/1.0 200")
        assert b"HTTP/1.1 403 Forbidden" in response
        log_text = log_path.read_text(encoding="utf-8")
        assert "ads.example/banner.js" in log_text
        assert "\tsample\t" in log_text
        assert recorded_blocks == ["sample"]
    finally:
        server.shutdown()
        server.server_close()


def test_adblock_icap_server_handles_persistent_transactions(tmp_path: Path) -> None:
    db_path = _build_lookup_db(tmp_path, ["||ads.example^"])
    log_path = tmp_path / "cicap-access.log"

    _add_web_to_path()
    from services.adblock_decision import AdblockDecisionEngine
    from tools.adblock_icap_server import _AdblockIcapServer

    server = _AdblockIcapServer(
        ("127.0.0.1", 0),
        engine=AdblockDecisionEngine(db_path, cache_ttl_seconds=0, cache_max=0),
        access_log_path=str(log_path),
        max_request_bytes=65536,
    )
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2.0) as sock:
            sock.settimeout(2.0)
            sock.sendall(
                b"OPTIONS icap://127.0.0.1/adblockreq ICAP/1.0\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Encapsulated: null-body=0\r\n\r\n",
            )
            options = _recv_icap_headers(sock)
            assert options.startswith(b"ICAP/1.0 200")
            assert b"Connection: close" not in options

            http = (
                b"GET http://allowed.example/page.html HTTP/1.1\r\n"
                b"Host: allowed.example\r\n\r\n"
            )
            sock.sendall(
                b"REQMOD icap://127.0.0.1/adblockreq ICAP/1.0\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Encapsulated: req-hdr=0, null-body="
                + str(len(http)).encode("ascii")
                + b"\r\n\r\n"
                + http,
            )
            allowed = _recv_icap_headers(sock)
            assert allowed.startswith(b"ICAP/1.0 204")
            assert b"Connection: close" not in allowed

            sock.sendall(
                b"OPTIONS icap://127.0.0.1/adblockreq ICAP/1.0\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Connection: close\r\n"
                b"Encapsulated: null-body=0\r\n\r\n",
            )
            closing = _recv_icap_headers(sock)
            assert closing.startswith(b"ICAP/1.0 200")
            assert b"Connection: close" in closing
    finally:
        server.shutdown()
        server.server_close()


def test_adblock_icap_server_honors_connection_close_token_lists(
    tmp_path: Path,
) -> None:
    db_path = _build_lookup_db(tmp_path, [])
    log_path = tmp_path / "cicap-access.log"

    _add_web_to_path()
    from services.adblock_decision import AdblockDecisionEngine
    from tools.adblock_icap_server import _AdblockIcapServer

    server = _AdblockIcapServer(
        ("127.0.0.1", 0),
        engine=AdblockDecisionEngine(db_path, cache_ttl_seconds=0, cache_max=0),
        access_log_path=str(log_path),
        max_request_bytes=65536,
    )
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        response = _send_icap(
            port,
            (
                b"OPTIONS icap://127.0.0.1/adblockreq ICAP/1.0\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Connection: keep-alive, close\r\n"
                b"Encapsulated: null-body=0\r\n\r\n"
            ),
        )
        assert response.startswith(b"ICAP/1.0 200")
        assert b"Connection: close" in response
    finally:
        server.shutdown()
        server.server_close()


def test_adblock_icap_server_caps_keepalive_transactions(tmp_path: Path) -> None:
    db_path = _build_lookup_db(tmp_path, [])
    log_path = tmp_path / "cicap-access.log"

    _add_web_to_path()
    from services.adblock_decision import AdblockDecisionEngine
    from tools.adblock_icap_server import _AdblockIcapServer

    server = _AdblockIcapServer(
        ("127.0.0.1", 0),
        engine=AdblockDecisionEngine(db_path, cache_ttl_seconds=0, cache_max=0),
        access_log_path=str(log_path),
        max_request_bytes=65536,
        max_keepalive_requests=2,
    )
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2.0) as sock:
            sock.settimeout(2.0)
            for expected_close in (False, True):
                sock.sendall(
                    b"OPTIONS icap://127.0.0.1/adblockreq ICAP/1.0\r\n"
                    b"Host: 127.0.0.1\r\n"
                    b"Encapsulated: null-body=0\r\n\r\n",
                )
                response = _recv_icap_headers(sock)
                assert response.startswith(b"ICAP/1.0 200")
                assert (b"Connection: close" in response) is expected_close
    finally:
        server.shutdown()
        server.server_close()


def test_adblock_icap_server_handles_coalesced_persistent_transactions(
    tmp_path: Path,
) -> None:
    db_path = _build_lookup_db(tmp_path, [])
    log_path = tmp_path / "cicap-access.log"

    _add_web_to_path()
    from services.adblock_decision import AdblockDecisionEngine
    from tools.adblock_icap_server import _AdblockIcapServer

    server = _AdblockIcapServer(
        ("127.0.0.1", 0),
        engine=AdblockDecisionEngine(db_path, cache_ttl_seconds=0, cache_max=0),
        access_log_path=str(log_path),
        max_request_bytes=65536,
    )
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        req = (
            b"OPTIONS icap://127.0.0.1/adblockreq ICAP/1.0\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Encapsulated: null-body=0\r\n\r\n"
        )
        with socket.create_connection(("127.0.0.1", port), timeout=2.0) as sock:
            sock.settimeout(2.0)
            sock.sendall(req + req)
            responses = _recv_icap_response_count(sock, 2)

        assert responses.count(b"ICAP/1.0 200") == 2
        assert b"Connection: close" not in responses
    finally:
        server.shutdown()
        server.server_close()


def test_adblock_icap_server_drains_and_closes_after_unpreviewed_request_body(
    tmp_path: Path,
) -> None:
    db_path = _build_lookup_db(tmp_path, [])
    log_path = tmp_path / "cicap-access.log"

    _add_web_to_path()
    from services.adblock_decision import AdblockDecisionEngine
    from tools.adblock_icap_server import _AdblockIcapServer

    server = _AdblockIcapServer(
        ("127.0.0.1", 0),
        engine=AdblockDecisionEngine(db_path, cache_ttl_seconds=0, cache_max=0),
        access_log_path=str(log_path),
        max_request_bytes=65536,
    )
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        http = (
            b"POST http://allowed.example/collect HTTP/1.1\r\n"
            b"Host: allowed.example\r\n"
            b"Content-Length: 7\r\n\r\n"
        )
        req = (
            b"REQMOD icap://127.0.0.1/adblockreq ICAP/1.0\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Encapsulated: req-hdr=0, req-body="
            + str(len(http)).encode("ascii")
            + b"\r\n\r\n"
            + http
            + b"7\r\npayload\r\n0\r\n\r\n"
        )
        response = _send_icap(port, req)

        assert response.startswith(b"ICAP/1.0 204")
        assert b"Connection: close" in response
    finally:
        server.shutdown()
        server.server_close()


def test_proxy_payload_includes_sqlite_adblock_runtime() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    dockerfile = (repo_root / "docker/Dockerfile.proxy").read_text(encoding="utf-8")
    entrypoint = (repo_root / "docker/entrypoint.sh").read_text(encoding="utf-8")

    assert "web/services/adblock_decision.py" in dockerfile
    assert "web/services/adblock_lookup.py" in dockerfile
    assert "web/tools/adblock_icap_server.py" in dockerfile
    assert "python3 /app/tools/adblock_icap_server.py" in entrypoint
    assert "request_lookup.sqlite" in entrypoint
    assert "srv_url_check.so" not in entrypoint


if str(Path(__file__).resolve().parents[1]) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
