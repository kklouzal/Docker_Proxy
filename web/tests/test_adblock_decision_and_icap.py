from __future__ import annotations

import socket
import struct
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

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
            "||firstparty-only.example^$~third-party",
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
            "https://sub.cdn.example.com/assets/ad.js?slot=1",
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
    analytics_tiktok = engine.decide(
        "https://analytics.tiktok.com/i18n/pixel/events.js"
    )
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
    assert engine.decide("https://firstparty-only.example/banner.js").blocked is False
    assert (
        engine.decide(
            "https://firstparty-only.example/banner.js",
            headers={"referer": "https://firstparty-only.example/page"},
        ).blocked
        is True
    )
    assert (
        engine.decide(
            "https://firstparty-only.example/banner.js",
            headers={"referer": "https://other.example/page"},
        ).blocked
        is False
    )


@pytest.mark.parametrize(
    "url",
    [
        "http://[::1",
        "http://user:pass@[::1",
        "http://example.com]",
        "https://ads.example:bad/banner.js",
        "https://ads.example:99999/banner.js",
    ],
)
def test_adblock_decision_malformed_request_urls_do_not_raise(
    tmp_path: Path,
    url: str,
) -> None:
    db_path = _build_lookup_db(tmp_path, ["||ads.example^", "malformed-token"])

    _add_web_to_path()
    from services.adblock_decision import AdblockDecisionEngine

    engine = AdblockDecisionEngine(db_path, cache_ttl_seconds=60, cache_max=10)

    decision = engine.decide(url)

    assert decision.blocked is False
    assert decision.reason == "no-match"
    assert decision.rule_id == ""


def test_adblock_decision_percent_encoded_authority_delimiters_do_not_match_suffixes(
    tmp_path: Path,
) -> None:
    db_path = _build_lookup_db(tmp_path, ["||ads.example^"])

    _add_web_to_path()
    from services.adblock_decision import AdblockDecisionEngine

    engine = AdblockDecisionEngine(db_path, cache_ttl_seconds=0, cache_max=0)

    decision = engine.decide("https://safe.example%2f.ads.example/banner.js")

    assert decision.blocked is False
    assert decision.reason == "no-match"
    assert engine.decide("https://user:pass@sub.ads.example/banner.js").blocked is True


@pytest.mark.parametrize(
    ("headers", "source_url"),
    [
        ({"Referer": "http://source.example]"}, ""),
        ({"Origin": "http://source.example]"}, ""),
        ({}, "http://source.example]"),
    ],
)
def test_adblock_decision_malformed_source_urls_do_not_match_scoped_rules(
    tmp_path: Path,
    headers: dict[str, str],
    source_url: str,
) -> None:
    db_path = _build_lookup_db(
        tmp_path,
        [
            "||scoped.example^$domain=source.example",
            "||thirdparty.example^$third-party",
        ],
    )

    _add_web_to_path()
    from services.adblock_decision import AdblockDecisionEngine

    engine = AdblockDecisionEngine(db_path, cache_ttl_seconds=0, cache_max=0)

    scoped = engine.decide(
        "https://scoped.example/ad.js",
        headers=headers,
        source_url=source_url,
    )
    third_party = engine.decide(
        "https://thirdparty.example/ad.js",
        headers=headers,
        source_url=source_url,
    )

    assert scoped.blocked is False
    assert scoped.reason == "no-match"
    assert third_party.blocked is False
    assert third_party.reason == "no-match"


def test_adblock_decision_valid_ipv6_literal_matching_still_works(
    tmp_path: Path,
) -> None:
    db_path = _build_lookup_db(
        tmp_path,
        ["||[2001:db8::20]^$third-party,domain=~[2001:db8::20]"],
    )

    _add_web_to_path()
    from services.adblock_decision import AdblockDecisionEngine

    engine = AdblockDecisionEngine(db_path, cache_ttl_seconds=0, cache_max=0)

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


@pytest.mark.parametrize(
    "target",
    [
        "ads.example",
        "",
        ":443",
        "ads.example:0",
        "ads.example:bad",
        "ads.example:99999",
        "user:pass@ads.example:443",
        "ads.example:443/path",
        "ads.example:443?slot=1",
        "ads.example:443#frag",
        "ads.example:443\x7f",
        "ads.example%2f.evil:443",
        "ads.example%3a443",
        "ads.example\\@safe.example:443",
        "ads.example:443 safe.example:443",
        "[2001:db8::20]",
        "[2001:db8::20]:0",
        "[2001:db8::20]:bad",
        "2001:db8::20:443",
    ],
)
def test_adblock_icap_parse_http_request_rejects_malformed_connect_authority(
    target: str,
) -> None:
    _add_web_to_path()
    from tools.adblock_icap_server import _parse_http_request

    method, url, headers = _parse_http_request(
        (
            f"CONNECT {target} HTTP/1.1\r\n"
            "Host: fallback.example:443\r\n"
            "User-Agent: probe\r\n\r\n"
        ).encode("ascii"),
    )

    assert method == "CONNECT"
    assert url == ""
    assert headers["host"] == "fallback.example:443"


def test_adblock_icap_parse_http_request_allows_bracketed_ipv6_connect_authority() -> None:
    _add_web_to_path()
    from tools.adblock_icap_server import _parse_http_request

    method, url, headers = _parse_http_request(
        b"CONNECT [2001:db8::20]:443 HTTP/1.1\r\n"
        b"Host: [2001:db8::20]:443\r\n"
        b"User-Agent: probe\r\n\r\n",
    )
    parsed = urlsplit(url)

    assert method == "CONNECT"
    assert url == "https://[2001:db8::20]:443/"
    assert parsed.netloc == "[2001:db8::20]:443"
    assert parsed.hostname == "2001:db8::20"
    assert parsed.port == 443
    assert parsed.username is None
    assert headers["host"] == "[2001:db8::20]:443"


def test_adblock_icap_parse_http_request_preserves_scheme_relative_authority() -> None:
    _add_web_to_path()
    from tools.adblock_icap_server import _parse_http_request

    method, url, headers = _parse_http_request(
        b"GET //ads.example/banner.js?slot=1 HTTP/1.1\r\n"
        b"Host: safe.example\r\n"
        b"X-Forwarded-Proto: https\r\n"
        b"User-Agent: probe\r\n\r\n",
    )

    assert method == "GET"
    assert url == "https://ads.example/banner.js?slot=1"
    assert headers["host"] == "safe.example"


@pytest.mark.parametrize(
    ("http", "expected"),
    [
        (
            (
                b"GET /banner.js HTTP/1.1\r\n"
                b"Host: ads.example\r\n"
                b"User-Agent: probe\r\n\r\n"
            ),
            "http://ads.example/banner.js",
        ),
        (
            (
                b"GET /banner.js HTTP/1.1\r\n"
                b"Host: ads.example:8080\r\n"
                b"X-Forwarded-Proto: https\r\n\r\n"
            ),
            "https://ads.example:8080/banner.js",
        ),
        (
            (
                b"GET /banner.js HTTP/1.1\r\n"
                b"Host: [2001:db8::20]:443\r\n\r\n"
            ),
            "http://[2001:db8::20]:443/banner.js",
        ),
        (
            (
                b"GET http://ads.example/banner.js HTTP/1.1\r\n"
                b"Host: safe.example\r\n"
                b"X-Forwarded-Proto: https\r\n\r\n"
            ),
            "http://ads.example/banner.js",
        ),
    ],
)
def test_adblock_icap_parse_http_request_accepts_unambiguous_non_connect_targets(
    http: bytes,
    expected: str,
) -> None:
    _add_web_to_path()
    from tools.adblock_icap_server import _parse_http_request

    method, url, _headers = _parse_http_request(http)

    assert method == "GET"
    assert url == expected
    parsed = urlsplit(url)
    assert parsed.geturl() == url
    assert parsed.netloc
    assert parsed.hostname
    assert parsed.username is None
    assert parsed.password is None


@pytest.mark.parametrize(
    "http",
    [
        b"GET /banner.js HTTP/1.1\r\nHost: \r\n\r\n",
        b"GET /banner.js HTTP/1.1\r\nHost: :80\r\n\r\n",
        b"GET /banner.js HTTP/1.1\r\nHost: ads.example:bad\r\n\r\n",
        b"GET /banner.js HTTP/1.1\r\nHost: ads.example:99999\r\n\r\n",
        b"GET /banner.js HTTP/1.1\r\nHost: safe.example@ads.example\r\n\r\n",
        b"GET /banner.js HTTP/1.1\r\nHost: ads.example/path\r\n\r\n",
        b"GET /banner.js HTTP/1.1\r\nHost: ads.example?slot=1\r\n\r\n",
        b"GET /banner.js HTTP/1.1\r\nHost: ads.example#frag\r\n\r\n",
        b"GET /banner.js HTTP/1.1\r\nHost: ads.example%2f.safe\r\n\r\n",
        b"GET /banner.js HTTP/1.1\r\nHost: ads.example\\@safe.example\r\n\r\n",
        b"GET /banner.js HTTP/1.1\r\nHost: [2001:db8::20\r\n\r\n",
        b"GET /banner.js HTTP/1.1 extra\r\nHost: ads.example\r\n\r\n",
        b"GET /banner.js#frag HTTP/1.1\r\nHost: ads.example\r\n\r\n",
        b"GET //safe.example@ads.example/banner.js HTTP/1.1\r\nHost: safe.example\r\n\r\n",
        b"GET //ads.example:bad/banner.js HTTP/1.1\r\nHost: safe.example\r\n\r\n",
        b"GET //ads.example/banner.js#frag HTTP/1.1\r\nHost: safe.example\r\n\r\n",
        b"GET //ads.example%2f.safe/banner.js HTTP/1.1\r\nHost: safe.example\r\n\r\n",
        b"GET //ads.example\\@safe.example/banner.js HTTP/1.1\r\nHost: safe.example\r\n\r\n",
        b"GET http://safe.example@ads.example/banner.js HTTP/1.1\r\nHost: safe.example\r\n\r\n",
        b"GET http://ads.example:bad/banner.js HTTP/1.1\r\nHost: safe.example\r\n\r\n",
        b"GET http://ads.example/banner.js#frag HTTP/1.1\r\nHost: safe.example\r\n\r\n",
    ],
)
def test_adblock_icap_parse_http_request_rejects_ambiguous_non_connect_targets(
    http: bytes,
) -> None:
    _add_web_to_path()
    from tools.adblock_icap_server import _parse_http_request

    _method, url, _headers = _parse_http_request(http)

    assert url == ""


def test_adblock_icap_rejects_duplicate_encapsulated_offsets() -> None:
    _add_web_to_path()
    from tools.adblock_icap_server import _encapsulated_http_request

    blocked = (
        b"GET http://ads.example/banner.js HTTP/1.1\r\n"
        b"Host: ads.example\r\n\r\n"
    )
    later_allowed = (
        b"GET http://allowed.example/page HTTP/1.1\r\n"
        b"Host: allowed.example\r\n\r\n"
    )
    icap = (
        b"REQMOD icap://127.0.0.1/adblockreq ICAP/1.0\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Encapsulated: req-hdr=0, null-body="
        + str(len(blocked)).encode("ascii")
        + b", req-hdr="
        + str(len(blocked)).encode("ascii")
        + b", null-body="
        + str(len(blocked) + len(later_allowed)).encode("ascii")
        + b"\r\n\r\n"
        + blocked
        + later_allowed
    )

    assert _encapsulated_http_request(icap) == b""


def test_adblock_icap_rejects_out_of_order_encapsulated_offsets() -> None:
    _add_web_to_path()
    from tools.adblock_icap_server import _encapsulated_http_request

    http = b"GET http://ads.example/banner.js HTTP/1.1\r\nHost: ads.example\r\n\r\n"
    icap = (
        b"REQMOD icap://127.0.0.1/adblockreq ICAP/1.0\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Encapsulated: req-hdr=10, null-body=0\r\n\r\n" + http
    )

    assert _encapsulated_http_request(icap) == b""


def test_adblock_icap_rejects_req_hdr_without_body_boundary() -> None:
    _add_web_to_path()
    from tools.adblock_icap_server import _read_icap_message

    http = (
        b"GET http://ads.example/banner.js HTTP/1.1\r\n"
        b"Host: ads.example\r\n\r\n"
    )
    next_req = (
        b"OPTIONS icap://127.0.0.1/adblockreq ICAP/1.0\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Encapsulated: null-body=0\r\n\r\n"
    )
    request = (
        b"REQMOD icap://127.0.0.1/adblockreq ICAP/1.0\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Encapsulated: req-hdr=0\r\n\r\n"
        + http
        + next_req
    )

    message, pending, force_close = _read_icap_message(
        _ChunkedSocket([request]),
        max_bytes=65536,
        max_body_drain_bytes=65536,
        timeout_seconds=5.0,
    )

    assert message == request
    assert pending == b""
    assert force_close is True


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
    sock = _ChunkedSocket(
        [headers[:32], headers[32:] + http[:10], http[10:], b"0\r\n\r\n"]
    )

    message, pending, force_close = _read_icap_message(
        sock,
        max_bytes=65536,
        max_body_drain_bytes=65536,
        timeout_seconds=5.0,
    )

    assert message.endswith(b"0\r\n\r\n")
    assert pending == b""
    assert force_close is False


def test_adblock_icap_reads_preview_zero_ieof_chunk_before_responding() -> None:
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
    sock = _ChunkedSocket([headers + http + b"0; ieof\r\n\r\n"])

    message, pending, force_close = _read_icap_message(
        sock,
        max_bytes=65536,
        max_body_drain_bytes=65536,
        timeout_seconds=5.0,
    )

    assert message.endswith(b"0; ieof\r\n\r\n")
    assert pending == b""
    assert force_close is False


def test_adblock_icap_preserves_pipelined_request_after_valid_preview_zero() -> None:
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
    next_req = (
        b"OPTIONS icap://127.0.0.1/adblockreq ICAP/1.0\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Encapsulated: null-body=0\r\n\r\n"
    )
    sock = _ChunkedSocket([headers + http + b"0\r\n\r\n" + next_req])

    message, pending, force_close = _read_icap_message(
        sock,
        max_bytes=65536,
        max_body_drain_bytes=65536,
        timeout_seconds=5.0,
    )

    assert message.endswith(b"0\r\n\r\n")
    assert pending == next_req
    assert force_close is False


@pytest.mark.parametrize("chunk_line", [b"\r\n", b"+0\r\n", b"-0\r\n"])
def test_adblock_icap_rejects_empty_or_signed_preview_chunk_size(
    chunk_line: bytes,
) -> None:
    _add_web_to_path()
    from tools.adblock_icap_server import _read_icap_message

    http = (
        b"POST http://allowed.example/collect HTTP/1.1\r\n"
        b"Host: allowed.example\r\n"
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
    next_req = (
        b"OPTIONS icap://127.0.0.1/adblockreq ICAP/1.0\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Encapsulated: null-body=0\r\n\r\n"
    )
    malformed_preview_end = chunk_line + b"\r\n"
    sock = _ChunkedSocket([headers + http + malformed_preview_end + next_req])

    message, pending, force_close = _read_icap_message(
        sock,
        max_bytes=65536,
        max_body_drain_bytes=65536,
        timeout_seconds=5.0,
    )

    assert message.endswith(malformed_preview_end + next_req)
    assert pending == b""
    assert force_close is True


def test_adblock_icap_rejects_malformed_zero_preview_before_pipeline() -> None:
    _add_web_to_path()
    from tools.adblock_icap_server import _read_icap_message

    http = (
        b"POST http://allowed.example/collect HTTP/1.1\r\n"
        b"Host: allowed.example\r\n"
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
    next_req = (
        b"OPTIONS icap://127.0.0.1/adblockreq ICAP/1.0\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Encapsulated: null-body=0\r\n\r\n"
    )
    sock = _ChunkedSocket([headers + http + b"0\r\n" + next_req])

    message, pending, force_close = _read_icap_message(
        sock,
        max_bytes=65536,
        max_body_drain_bytes=65536,
        timeout_seconds=5.0,
    )

    assert message.endswith(b"0\r\n" + next_req)
    assert pending == b""
    assert force_close is True


def test_adblock_icap_server_closes_after_empty_preview_chunk_size(
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
        malformed_req = (
            b"REQMOD icap://127.0.0.1/adblockreq ICAP/1.0\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Preview: 0\r\n"
            b"Encapsulated: req-hdr=0, req-body="
            + str(len(http)).encode("ascii")
            + b"\r\n\r\n"
            + http
            + b"\r\n\r\n"
        )
        next_req = (
            b"OPTIONS icap://127.0.0.1/adblockreq ICAP/1.0\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Encapsulated: null-body=0\r\n\r\n"
        )
        with socket.create_connection(("127.0.0.1", port), timeout=2.0) as sock:
            sock.settimeout(2.0)
            sock.sendall(malformed_req + next_req)
            responses = _recv_icap_response_count(sock, 2)

        assert responses.count(b"ICAP/1.0 ") == 1
        assert responses.startswith(b"ICAP/1.0 204")
        assert b"Connection: close" in responses
    finally:
        server.shutdown()
        server.server_close()


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


def test_adblock_icap_server_blocks_scheme_relative_request_targets(
    tmp_path: Path,
) -> None:
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
            b"GET //ads.example/banner.js HTTP/1.1\r\n"
            b"Host: safe.example\r\n"
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
        assert b"HTTP/1.1 403 Forbidden" in response
        log_text = log_path.read_text(encoding="utf-8")
        assert "GET http://ads.example/banner.js HTTP/1.1" in log_text
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


def test_adblock_icap_server_ignores_reset_peer_during_response(
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
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
            b"GET http://allowed.example/page.html HTTP/1.1\r\n"
            b"Host: allowed.example\r\n\r\n"
        )
        req = (
            b"REQMOD icap://127.0.0.1/adblockreq ICAP/1.0\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Encapsulated: req-hdr=0, null-body="
            + str(len(http)).encode("ascii")
            + b"\r\n\r\n"
            + http
        )
        with socket.create_connection(("127.0.0.1", port), timeout=2.0) as sock:
            sock.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_LINGER,
                struct.pack("ii", 1, 0),
            )
            sock.sendall(req)
        time.sleep(0.2)

        captured = capfd.readouterr()
        assert "ConnectionResetError" not in captured.err
        assert "Exception occurred during processing of request" not in captured.err
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
