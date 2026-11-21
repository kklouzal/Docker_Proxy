from __future__ import annotations

import gc
import os
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest

from .clock_patching import patch_module_clock
from .test_adblock_lookup import _build_lookup_db


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
    # No Referer/Origin: the unknown context is in no excluded domain, so a
    # filter that only excludes domains applies (ABP/uBO semantics).
    assert (
        engine.decide(
            "https://excluded-scope.example/ads.js",
            headers={"Sec-Fetch-Site": "cross-site"},
        ).blocked
        is True
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


def test_decision_engine_follows_filter_type_and_scope_defaults(tmp_path: Path) -> None:
    db_path = _build_lookup_db(
        tmp_path,
        [
            "||tracker.example^",
            "||cdn.example/ads/",
            "-ad-banner.",
            "-sponsor-$~script",
            "||popunder.example^$document",
            "||ads.",
            "||142.91.159.",
            "||widget.example^$script,domain=shop.*",
            "||cmp.example^",
            "@@||cmp.example^$domain=~brand.*",
        ],
    )

    from services.adblock_decision import AdblockDecisionEngine

    engine = AdblockDecisionEngine(db_path, cache_ttl_seconds=0, cache_max=0)

    def decide(url: str, resource_type: str, source: str = "") -> bool:
        return engine.decide(
            url, resource_type=resource_type, source_url=source
        ).blocked

    # Filters without type options skip the main document, except a pure
    # hostname filter (uBO strict blocking); $document opts in explicitly.
    assert decide("https://tracker.example/", "document") is True
    assert decide("https://cdn.example/ads/page.html", "document") is False
    assert decide("https://cdn.example/ads/a.js", "script") is True
    assert decide("https://news.example/2026/x-ad-banner.html", "document") is False
    assert decide("https://news.example/js/x-ad-banner.min.js", "script") is True
    assert decide("https://news.example/x-sponsor-y.html", "document") is False
    assert decide("https://news.example/x-sponsor-y.png", "image") is True
    assert decide("https://popunder.example/landing", "document") is True
    # A trailing dot leaves the host label open; it is not ||ads^.
    assert decide("https://ads.tracker2.example/x.js", "script") is True
    assert decide("https://adsense.example/x.js", "script") is False
    assert decide("http://142.91.159.12/x.js", "script") is True
    assert decide("http://142.91.15.12/x.js", "script") is False
    # Entity domains: label sequence + any public suffix, subdomains included.
    assert decide("https://widget.example/w.js", "script", "https://shop.de/") is True
    assert (
        decide("https://widget.example/w.js", "script", "https://www.shop.co.uk/")
        is True
    )
    assert (
        decide("https://widget.example/w.js", "script", "https://shop.evil.com/")
        is False
    )
    assert decide("https://cmp.example/c.js", "script", "https://brand.fr/") is True
    assert decide("https://cmp.example/c.js", "script", "https://other.fr/") is False


def test_resource_type_inference_without_fetch_metadata() -> None:
    from services.adblock_decision import infer_resource_type

    navigation_accept = (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,*/*;q=0.8"
    )
    assert (
        infer_resource_type("GET", "https://x.example/", {"Accept": navigation_accept})
        == "document"
    )
    assert (
        infer_resource_type(
            "GET", "https://x.example/p", {"Accept": "image/avif,image/webp,*/*"}
        )
        == "image"
    )
    assert (
        infer_resource_type("GET", "https://x.example/p", {"Sec-Fetch-Dest": "frame"})
        == "subdocument"
    )
    assert (
        infer_resource_type(
            "GET", "https://x.example/sw", {"Sec-Fetch-Dest": "serviceworker"}
        )
        == "script"
    )


def test_adblock_decision_enforces_method_contract_without_cache_leakage(
    tmp_path: Path,
) -> None:
    db_path = _build_lookup_db(
        tmp_path,
        [
            "||negated-method.example^$method=~get",
            "||positive-method.example^$method=post|put",
            "||connect-method.example^$method=connect",
            "||empty-method.example^$method=",
            "||unsupported-method.example^$method=trace",
        ],
    )

    from services.adblock_decision import AdblockDecisionEngine

    engine = AdblockDecisionEngine(db_path, cache_ttl_seconds=60, cache_max=10)

    negated_url = "https://negated-method.example/collect"
    [hydrated_rule] = engine.lookup.candidate_rules(negated_url)
    assert hydrated_rule.rule["value_options"]["method"] == ["~GET"]
    assert engine.decide(negated_url, method="GET").blocked is False
    post_decision = engine.decide(negated_url, method=" post ")
    assert post_decision.blocked is True
    assert post_decision.raw == "||negated-method.example^$method=~get"
    assert engine.decide(negated_url, method="GET").blocked is False

    positive_url = "https://positive-method.example/collect"
    assert engine.decide(positive_url, method="put").blocked is True
    assert engine.decide(positive_url, method="GET").blocked is False

    assert (
        engine.decide(
            "https://connect-method.example/",
            method="CONNECT",
        ).blocked
        is False
    )

    assert (
        engine.decide("https://empty-method.example/collect", method="POST").blocked
        is False
    )
    assert (
        engine.decide(
            "https://unsupported-method.example/collect",
            method="TRACE",
        ).blocked
        is False
    )


def test_adblock_decision_cache_ttl_uses_elapsed_not_wall_time(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = _build_lookup_db(tmp_path, ["||cached.example^"])

    from services import adblock_decision

    clocks = {"wall": 1_000.0, "elapsed": 100.0}
    patch_module_clock(monkeypatch, adblock_decision, time=lambda: clocks["wall"])
    patch_module_clock(
        monkeypatch, adblock_decision, monotonic=lambda: clocks["elapsed"]
    )
    engine = adblock_decision.AdblockDecisionEngine(
        db_path,
        cache_ttl_seconds=60,
        cache_max=10,
    )
    candidate_calls = 0
    original_candidate_rules = engine.lookup.candidate_rules

    def counting_candidate_rules(
        *args: object, **kwargs: object
    ) -> list[dict[str, object]]:
        nonlocal candidate_calls
        candidate_calls += 1
        return original_candidate_rules(*args, **kwargs)

    monkeypatch.setattr(engine.lookup, "candidate_rules", counting_candidate_rules)
    url = "https://cached.example/banner.js"

    assert engine.decide(url).blocked is True
    assert candidate_calls == 1

    clocks.update(wall=100_000.0, elapsed=159.0)
    assert engine.decide(url).blocked is True
    assert candidate_calls == 1

    clocks.update(wall=10.0, elapsed=161.0)
    assert engine.decide(url).blocked is True
    assert candidate_calls == 2


def test_adblock_decision_treats_escaped_abp_metacharacters_as_literals(
    tmp_path: Path,
) -> None:
    db_path = _build_lookup_db(
        tmp_path,
        [
            r"escaped\*token",
            r"escaped\^token",
            r"escaped\|",
        ],
    )

    from services.adblock_decision import AdblockDecisionEngine

    engine = AdblockDecisionEngine(db_path, cache_ttl_seconds=0, cache_max=0)

    assert engine.decide("https://static.example/escaped*token.js").blocked is True
    assert engine.decide("https://static.example/escapedXYZtoken.js").blocked is False
    assert engine.decide("https://static.example/escaped^token.js").blocked is True
    assert engine.decide("https://static.example/escaped/token.js").blocked is False
    assert engine.decide("https://static.example/escaped|").blocked is True
    assert engine.decide("https://static.example/escaped").blocked is False


def test_adblock_decision_preserves_absolute_and_host_authority_boundaries(
    tmp_path: Path,
) -> None:
    db_path = _build_lookup_db(
        tmp_path,
        [
            "|https://absolute.example/ads.js|",
            "||host.example/ads.js|",
            "||port.example:8443/ads.js|",
            "||bare.example|",
        ],
    )

    from services.adblock_decision import AdblockDecisionEngine, _RuleMatcher

    engine = AdblockDecisionEngine(db_path, cache_ttl_seconds=0, cache_max=0)

    assert engine.decide("https://absolute.example/ads.js").blocked is True
    assert engine.decide("https://absolute.example:8443/ads.js").blocked is False
    assert engine.decide("https://user@absolute.example/ads.js").blocked is False

    assert engine.decide("https://host.example/ads.js").blocked is True
    assert engine.decide("https://sub.host.example/ads.js").blocked is True
    assert engine.decide("https://host.example:8443/ads.js").blocked is False

    assert engine.decide("https://port.example:8443/ads.js").blocked is True
    assert engine.decide("https://port.example/ads.js").blocked is False
    assert engine.decide("https://port.example:9443/ads.js").blocked is False

    assert engine.decide("https://bare.example").blocked is True
    assert engine.decide("https://bare.example/").blocked is False

    [compiled_host_rule] = [
        rule
        for rule in engine.lookup.candidate_rules("https://host.example/ads.js")
        if rule.rule["raw"] == "||host.example/ads.js|"
    ]
    fallback_host_rule = dict(compiled_host_rule.rule)
    fallback_host_rule.pop("compiled_regex")
    assert (
        _RuleMatcher(fallback_host_rule).matches(
            engine._request_context(
                "https://host.example:8443/ads.js",
                method="GET",
                resource_type="other",
                source_host="",
                third_party=None,
            ),
        )
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
        r"https://safe.example\@ads.example/banner.js",
        r"https://safe.example\.ads.example/banner.js",
        r"https://ads.example\path/banner.js",
        "https://ads.example\n.evil/banner.js",
    ],
)
def test_adblock_decision_malformed_request_urls_do_not_raise(
    tmp_path: Path,
    url: str,
) -> None:
    db_path = _build_lookup_db(tmp_path, ["||ads.example^", "malformed-token"])

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


def _drive(reader: Any, sock: _ChunkedSocket) -> Any:
    """Run a sans-IO ICAP reader generator over a blocking (fake) socket."""
    try:
        wanted = next(reader)
        while True:
            try:
                chunk: bytes | None = sock.recv(wanted)
            except TimeoutError, OSError:
                chunk = None
            wanted = reader.send(chunk)
    except StopIteration as done:
        return done.value


def _read_icap_message(
    sock: _ChunkedSocket,
    *,
    max_bytes: int,
    max_body_drain_bytes: int,
    timeout_seconds: float,
    pending: bytes = b"",
) -> tuple[bytes, bytes, bool]:
    from tools import adblock_icap_server

    del timeout_seconds  # the server's event loop owns read deadlines
    return _drive(
        adblock_icap_server._read_icap_message(
            max_bytes=max_bytes,
            max_body_drain_bytes=max_body_drain_bytes,
            pending=pending,
        ),
        sock,
    )


def _drain_chunked_body(
    sock: _ChunkedSocket,
    body: bytes,
    *,
    max_drain_bytes: int,
) -> bool:
    from tools import adblock_icap_server

    return _drive(
        adblock_icap_server._drain_chunked_body(body, max_drain_bytes=max_drain_bytes),
        sock,
    )


def test_adblock_icap_parse_http_request_normalizes_connect_authority() -> None:
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


def test_adblock_icap_parse_http_request_allows_bracketed_ipv6_connect_authority() -> (
    None
):
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
            (b"GET /banner.js HTTP/1.1\r\nHost: [2001:db8::20]:443\r\n\r\n"),
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
    from tools.adblock_icap_server import _parse_http_request

    _method, url, _headers = _parse_http_request(http)

    assert url == ""


def test_adblock_icap_rejects_duplicate_encapsulated_offsets() -> None:
    from tools.adblock_icap_server import _encapsulated_http_request

    blocked = b"GET http://ads.example/banner.js HTTP/1.1\r\nHost: ads.example\r\n\r\n"
    later_allowed = (
        b"GET http://allowed.example/page HTTP/1.1\r\nHost: allowed.example\r\n\r\n"
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
    from tools.adblock_icap_server import _encapsulated_http_request

    http = b"GET http://ads.example/banner.js HTTP/1.1\r\nHost: ads.example\r\n\r\n"
    icap = (
        b"REQMOD icap://127.0.0.1/adblockreq ICAP/1.0\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Encapsulated: req-hdr=10, null-body=0\r\n\r\n" + http
    )

    assert _encapsulated_http_request(icap) == b""


def test_adblock_icap_rejects_req_hdr_without_body_boundary() -> None:
    http = b"GET http://ads.example/banner.js HTTP/1.1\r\nHost: ads.example\r\n\r\n"
    next_req = (
        b"OPTIONS icap://127.0.0.1/adblockreq ICAP/1.0\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Encapsulated: null-body=0\r\n\r\n"
    )
    request = (
        b"REQMOD icap://127.0.0.1/adblockreq ICAP/1.0\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Encapsulated: req-hdr=0\r\n\r\n" + http + next_req
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


def test_adblock_icap_rejects_duplicate_encapsulated_header_fields() -> None:
    http = b"GET http://ads.example/banner.js HTTP/1.1\r\nHost: ads.example\r\n\r\n"
    next_req = (
        b"OPTIONS icap://127.0.0.1/adblockreq ICAP/1.0\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Encapsulated: null-body=0\r\n\r\n"
    )
    request = (
        b"REQMOD icap://127.0.0.1/adblockreq ICAP/1.0\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Encapsulated: req-hdr=0, null-body="
        + str(len(http)).encode("ascii")
        + b"\r\n"
        b"Encapsulated: req-hdr=0, req-body=" + str(len(http)).encode("ascii") + b"\r\n"
        b"Preview: 0\r\n\r\n" + http + b"0\r\n\r\n" + next_req
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


@pytest.mark.parametrize(
    "malformed_header",
    [
        b"Malformed-Header-Line",
        b": empty-name",
        b"Bad Header: value",
        b"Bad\x01Name: value",
        b" Continuation-Like: value",
        b"\tContinuation-Like: value",
    ],
)
def test_adblock_icap_rejects_malformed_general_header_before_pipeline(
    malformed_header: bytes,
) -> None:
    http = b"GET http://allowed.example/page HTTP/1.1\r\nHost: allowed.example\r\n\r\n"
    next_req = (
        b"OPTIONS icap://127.0.0.1/adblockreq ICAP/1.0\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Encapsulated: null-body=0\r\n\r\n"
    )
    request = (
        b"REQMOD icap://127.0.0.1/adblockreq ICAP/1.0\r\n"
        b"Host: 127.0.0.1\r\n" + malformed_header + b"\r\n"
        b"Encapsulated: req-hdr=0, null-body="
        + str(len(http)).encode("ascii")
        + b"\r\n\r\n"
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


def test_adblock_icap_allows_duplicate_equal_preview_zero_before_pipeline() -> None:
    http = (
        b"POST http://ads.example/collect HTTP/1.1\r\n"
        b"Host: ads.example\r\n"
        b"Content-Length: 7\r\n\r\n"
    )
    headers = (
        b"REQMOD icap://127.0.0.1/adblockreq ICAP/1.0\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Preview: 0\r\n"
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


@pytest.mark.parametrize(
    "preview_headers",
    [
        [b"Preview: -1\r\n"],
        [b"Preview: +0\r\n"],
        [b"Preview: \r\n"],
        [b"Preview: 999999999999999999999999\r\n"],
        [b"Preview: 0\r\n", b"Preview: 1\r\n"],
    ],
)
def test_adblock_icap_rejects_malformed_or_conflicting_preview_before_pipeline(
    preview_headers: list[bytes],
) -> None:
    http = (
        b"POST http://allowed.example/collect HTTP/1.1\r\n"
        b"Host: allowed.example\r\n"
        b"Content-Length: 7\r\n\r\n"
    )
    headers = (
        b"REQMOD icap://127.0.0.1/adblockreq ICAP/1.0\r\n"
        b"Host: 127.0.0.1\r\n"
        + b"".join(preview_headers)
        + b"Encapsulated: req-hdr=0, req-body="
        + str(len(http)).encode("ascii")
        + b"\r\n\r\n"
    )
    next_req = (
        b"OPTIONS icap://127.0.0.1/adblockreq ICAP/1.0\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Encapsulated: null-body=0\r\n\r\n"
    )
    request = headers + http + b"0\r\n\r\n" + next_req

    message, pending, force_close = _read_icap_message(
        _ChunkedSocket([request]),
        max_bytes=65536,
        max_body_drain_bytes=65536,
        timeout_seconds=5.0,
    )

    assert message == request
    assert pending == b""
    assert force_close is True


@pytest.mark.parametrize("chunk_line", [b"\r\n", b"+0\r\n", b"-0\r\n"])
def test_adblock_icap_rejects_empty_or_signed_preview_chunk_size(
    chunk_line: bytes,
) -> None:
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


def test_adblock_icap_server_bind_failure_preserves_original_error() -> None:
    class _TrackedEngine:
        def __init__(self) -> None:
            self.close_calls = 0

        def close(self) -> None:
            self.close_calls += 1

    from tools.adblock_icap_server import _AdblockIcapServer

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    engine = _TrackedEngine()
    try:
        with pytest.raises(OSError) as excinfo:
            _AdblockIcapServer(
                ("127.0.0.1", int(listener.getsockname()[1])),
                engine=engine,  # type: ignore[arg-type]
                access_log_path="/dev/null",
                max_request_bytes=65536,
            )

        assert not isinstance(excinfo.value, AttributeError)
        assert engine.close_calls == 1
    finally:
        listener.close()


def test_adblock_icap_server_shares_one_sqlite_connection_and_closes_it(
    tmp_path: Path,
) -> None:
    if not Path("/proc/self/fd").is_dir():
        pytest.skip("SQLite descriptor lifecycle proof requires procfs")

    db_path = _build_lookup_db(tmp_path, ["||ads.example^"])
    log_path = tmp_path / "cicap-access.log"
    db_stat = db_path.stat()

    def open_db_descriptors() -> list[int]:
        descriptors: list[int] = []
        for entry in Path("/proc/self/fd").iterdir():
            try:
                descriptor_stat = os.stat(entry)
            except OSError:
                continue
            if (
                descriptor_stat.st_dev == db_stat.st_dev
                and descriptor_stat.st_ino == db_stat.st_ino
            ):
                descriptors.append(int(entry.name))
        return descriptors

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
    gc_was_enabled = gc.isenabled()
    gc.disable()
    try:
        for index in range(3):
            http = (
                f"GET http://ads.example/banner{index}.js HTTP/1.1\r\n"
                "Host: ads.example\r\n\r\n"
            ).encode("ascii")
            request = (
                b"REQMOD icap://127.0.0.1/adblockreq ICAP/1.0\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Connection: close\r\n"
                b"Encapsulated: req-hdr=0, null-body="
                + str(len(http)).encode("ascii")
                + b"\r\n\r\n"
                + http
            )
            assert _send_icap(port, request).startswith(b"ICAP/1.0 200")
            # Every ICAP connection is served from the same SQLite connection.
            assert len(open_db_descriptors()) == 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)
        if gc_was_enabled:
            gc.enable()
        gc.collect()
    assert open_db_descriptors() == []


def test_adblock_icap_server_allows_connect_authority_requests(tmp_path: Path) -> None:
    db_path = _build_lookup_db(tmp_path, ["||ads.example^"])
    log_path = tmp_path / "cicap-access.log"

    from services.adblock_decision import AdblockDecisionEngine
    from services.helper_runtime import HelperStats
    from tools.adblock_icap_server import _AdblockIcapServer

    stats = HelperStats("test", emit_interval_seconds=3600)
    server = _AdblockIcapServer(
        ("127.0.0.1", 0),
        engine=AdblockDecisionEngine(db_path, cache_ttl_seconds=0, cache_max=0),
        access_log_path=str(log_path),
        max_request_bytes=65536,
        stats=stats,
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
        assert response.startswith(b"ICAP/1.0 204")
        icap_header = response.split(b"\r\n\r\n", 1)[0]
        assert b"Connection: close" not in icap_header
        assert b"HTTP/1.1 403 Forbidden" not in response
        assert not log_path.exists()
        assert stats.counters == {"unsupported_http_method": 1, "allowed": 1}
    finally:
        server.shutdown()
        server.server_close()


def test_adblock_icap_server_fail_opens_unsupported_http_method(
    tmp_path: Path,
) -> None:
    db_path = _build_lookup_db(tmp_path, ["||ads.example^"])
    log_path = tmp_path / "cicap-access.log"

    from services.adblock_decision import AdblockDecisionEngine
    from services.helper_runtime import HelperStats
    from tools.adblock_icap_server import _AdblockIcapServer

    stats = HelperStats("test", emit_interval_seconds=3600)
    server = _AdblockIcapServer(
        ("127.0.0.1", 0),
        engine=AdblockDecisionEngine(db_path, cache_ttl_seconds=0, cache_max=0),
        access_log_path=str(log_path),
        max_request_bytes=65536,
        stats=stats,
    )
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        http = b"TRACE http://ads.example/ HTTP/1.1\r\nHost: ads.example\r\n\r\n"
        req = (
            b"REQMOD icap://127.0.0.1/adblockreq ICAP/1.0\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Encapsulated: req-hdr=0, null-body="
            + str(len(http)).encode("ascii")
            + b"\r\n\r\n"
            + http
        )

        response = _send_icap(port, req)

        assert response.startswith(b"ICAP/1.0 204")
        assert b"HTTP/1.1 403 Forbidden" not in response
        assert not log_path.exists()
        assert stats.counters == {"unsupported_http_method": 1, "allowed": 1}
    finally:
        server.shutdown()
        server.server_close()


def test_adblock_icap_server_blocks_scheme_relative_request_targets(
    tmp_path: Path,
) -> None:
    db_path = _build_lookup_db(tmp_path, ["||ads.example^"])
    log_path = tmp_path / "cicap-access.log"

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
    finally:
        server.shutdown()
        server.server_close()


def test_adblock_icap_server_uses_sqlite_decisions_and_logs_blocks(
    tmp_path: Path,
) -> None:
    db_path = _build_lookup_db(tmp_path, ["||ads.example^"])
    log_path = tmp_path / "cicap-access.log"

    from services.adblock_decision import AdblockDecisionEngine
    from tools.adblock_icap_server import _AdblockIcapServer

    engine = AdblockDecisionEngine(db_path, cache_ttl_seconds=0, cache_max=0)
    assert engine.decide("http://ads.example/banner.js").list_key == "sample"
    server = _AdblockIcapServer(
        ("127.0.0.1", 0),
        engine=engine,
        access_log_path=str(log_path),
        max_request_bytes=65536,
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
            b"X-Client-IP: 192.0.2.7\r\n"
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
        assert "\tblock\trule-match\n" in log_text
        # The blocked browser is the X-Client-IP Squid sends, not the local
        # ICAP peer; the tailer stores it as the event's source address.
        from services.adblock_store import AdblockStore

        row = AdblockStore()._parse_cicap_access_line(log_text.splitlines()[-1])
        assert row is not None
        assert row["src_ip"] == "192.0.2.7"
    finally:
        server.shutdown()
        server.server_close()


def test_adblock_icap_http_client_ip_requires_one_valid_address() -> None:
    from tools.adblock_icap_server import _http_client_ip

    head = b"REQMOD icap://127.0.0.1/adblockreq ICAP/1.0\r\nHost: 127.0.0.1\r\n"
    assert _http_client_ip(head + b"X-Client-IP: 2001:db8::1") == "2001:db8::1"
    assert _http_client_ip(head + b"x-client-ip:  192.0.2.9 ") == "192.0.2.9"
    assert _http_client_ip(head) == ""
    assert _http_client_ip(head + b"X-Client-IP: not-an-ip") == ""
    assert (
        _http_client_ip(head + b"X-Client-IP: 192.0.2.1\r\nX-Client-IP: 192.0.2.2")
        == ""
    )


def test_adblock_icap_server_handles_persistent_transactions(tmp_path: Path) -> None:
    db_path = _build_lookup_db(tmp_path, ["||ads.example^"])
    log_path = tmp_path / "cicap-access.log"

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


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        ([b"Connection: keep-alive\r\n"], False),
        ([b"Connection: keep-alive, Close\t\r\n"], True),
        ([b"Connection: keep-alive\r\n", b"Connection: keep-alive\r\n"], False),
        ([b"Connection: close\r\n", b"Connection: close\r\n"], True),
        ([b"Connection: close\r\n", b"Connection: keep-alive\r\n"], True),
        ([b"Connection: keep-alive\r\n", b"Connection: upgrade\r\n"], True),
    ],
)
def test_adblock_icap_connection_close_requested_handles_duplicate_lists(
    headers: list[bytes],
    expected: bool,
) -> None:
    from tools.adblock_icap_server import _connection_close_requested

    header_blob = (
        b"OPTIONS icap://127.0.0.1/adblockreq ICAP/1.0\r\n"
        + b"".join(headers)
        + b"Encapsulated: null-body=0"
    )

    assert _connection_close_requested(header_blob) is expected


def test_adblock_icap_server_closes_on_duplicate_conflicting_connection(
    tmp_path: Path,
) -> None:
    db_path = _build_lookup_db(tmp_path, [])
    log_path = tmp_path / "cicap-access.log"

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
            b"Connection: close\r\n"
            b"Connection: keep-alive\r\n"
            b"Encapsulated: null-body=0\r\n\r\n"
        )
        next_req = (
            b"OPTIONS icap://127.0.0.1/adblockreq ICAP/1.0\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Encapsulated: null-body=0\r\n\r\n"
        )
        with socket.create_connection(("127.0.0.1", port), timeout=2.0) as sock:
            sock.settimeout(2.0)
            sock.sendall(req + next_req)
            responses = _recv_icap_response_count(sock, 2)

        assert responses.count(b"ICAP/1.0 ") == 1
        assert responses.startswith(b"ICAP/1.0 200")
        assert b"Connection: close" in responses
    finally:
        server.shutdown()
        server.server_close()


def test_adblock_icap_server_caps_keepalive_transactions(tmp_path: Path) -> None:
    db_path = _build_lookup_db(tmp_path, [])
    log_path = tmp_path / "cicap-access.log"

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


@pytest.mark.parametrize(
    ("case", "body"),
    [
        ("empty-size", b"\r\npayload\r\n0\r\n\r\n"),
        ("non-hex-size", b"G\r\npayload\r\n0\r\n\r\n"),
        ("signed-size", b"+7\r\npayload\r\n0\r\n\r\n"),
        ("prefixed-size", b"0x7\r\npayload\r\n0\r\n\r\n"),
        ("short-payload", b"8\r\npayload\r\n0\r\n\r\n"),
        ("missing-payload-crlf", b"7\r\npayload0\r\n\r\n"),
        ("eof-before-zero", b"7\r\npayload\r\n"),
        ("malformed-trailer", b"0\r\nBad Trailer\r\n\r\n"),
        ("duplicate-ieof", b"0;ieof;ieof\r\n\r\n"),
        ("illegal-ieof", b"1;ieof\r\nx\r\n0\r\n\r\n"),
        ("max-size-overflow", b"2001\r\n" + (b"x" * 8192) + b"\r\n0\r\n\r\n"),
    ],
)
def test_adblock_icap_unpreviewed_body_drain_rejects_malformed_framing(
    case: str,
    body: bytes,
) -> None:
    del case
    assert (
        _drain_chunked_body(
            _ChunkedSocket([]),
            body,
            max_drain_bytes=8192,
        )
        is False
    )


def test_adblock_icap_unpreviewed_body_drain_accepts_valid_framing() -> None:
    assert (
        _drain_chunked_body(
            _ChunkedSocket([]),
            b"7; ext=value\r\npayload\r\n0; ieof\r\nX-Trailer: ok\r\n\r\n",
            max_drain_bytes=8192,
        )
        is True
    )


@pytest.mark.parametrize(
    "body",
    [
        b"G\r\npayload\r\n0\r\n\r\n",
        b"8\r\npayload\r\n0\r\n\r\n",
        b"0\r\nBad Trailer\r\n\r\n",
        b"0;ieof;ieof\r\n\r\n",
        b"1;ieof\r\nx\r\n0\r\n\r\n",
        b"0\r\n\r\nJUNK",
    ],
)
def test_adblock_icap_server_allows_and_closes_after_malformed_unpreviewed_body(
    tmp_path: Path,
    body: bytes,
) -> None:
    db_path = _build_lookup_db(tmp_path, [])
    log_path = tmp_path / "cicap-access.log"

    from services.adblock_decision import AdblockDecisionEngine
    from tools.adblock_icap_server import _AdblockIcapServer

    server = _AdblockIcapServer(
        ("127.0.0.1", 0),
        engine=AdblockDecisionEngine(db_path, cache_ttl_seconds=0, cache_max=0),
        access_log_path=str(log_path),
        max_request_bytes=65536,
        request_timeout_seconds=0.2,
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
            b"Encapsulated: req-hdr=0, req-body="
            + str(len(http)).encode("ascii")
            + b"\r\n\r\n"
            + http
            + body
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


def test_adblock_icap_server_drains_and_closes_after_unpreviewed_request_body(
    tmp_path: Path,
) -> None:
    db_path = _build_lookup_db(tmp_path, [])
    log_path = tmp_path / "cicap-access.log"

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


def test_adblock_icap_parse_args_falls_back_for_malformed_numeric_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tools.adblock_icap_server import _parse_args

    malformed_env = {
        "CICAP_PORT": "not-a-port",
        "ADBLOCK_CACHE_TTL": "not-a-ttl",
        "ADBLOCK_CACHE_MAX": "not-a-cache-max",
        "ADBLOCK_RULE_CACHE_MAX": "not-a-rule-cache-max",
        "ADBLOCK_ICAP_MAX_REQUEST_BYTES": "not-max-request-bytes",
        "ADBLOCK_ICAP_MAX_BODY_DRAIN_BYTES": "not-max-body-drain-bytes",
        "ADBLOCK_ICAP_REQUEST_TIMEOUT": "not-a-timeout",
        "ADBLOCK_ICAP_MAX_KEEPALIVE_REQUESTS": "not-keepalive-requests",
    }
    for name, value in malformed_env.items():
        monkeypatch.setenv(name, value)

    args = _parse_args([])

    assert args.port == 14000
    # Malformed cache overrides fall back to the artifact settings / defaults.
    assert args.cache_ttl is None
    assert args.cache_max is None
    assert args.rule_cache_max == 50000
    assert args.max_request_bytes == 262144
    assert args.max_body_drain_bytes == 8388608
    assert args.request_timeout == pytest.approx(5.0)
    assert args.max_keepalive_requests == 1000


def test_adblock_icap_parse_args_preserves_cli_numeric_rejection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tools.adblock_icap_server import _parse_args

    monkeypatch.setenv("ADBLOCK_CACHE_TTL", "1800")
    monkeypatch.setenv("ADBLOCK_ICAP_REQUEST_TIMEOUT", "2.5")

    with pytest.raises(SystemExit) as exc_info:
        _parse_args(["--cache-ttl", "bad-cli-int"])
    assert exc_info.value.code == 2

    with pytest.raises(SystemExit) as exc_info:
        _parse_args(["--request-timeout", "bad-cli-float"])
    assert exc_info.value.code == 2


def test_adblock_icap_parse_args_reads_valid_numeric_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tools.adblock_icap_server import _parse_args

    monkeypatch.setenv("ADBLOCK_CACHE_TTL", "1800")
    monkeypatch.setenv("ADBLOCK_ICAP_REQUEST_TIMEOUT", "2.5")

    args = _parse_args([])

    assert args.cache_ttl == 1800
    assert args.request_timeout == pytest.approx(2.5)


@pytest.mark.parametrize("value", ["nan", "inf", "-inf"])
def test_adblock_icap_parse_args_rejects_non_finite_timeout_env(
    monkeypatch: pytest.MonkeyPatch,
    value: str,
) -> None:
    from tools.adblock_icap_server import _parse_args

    monkeypatch.setenv("ADBLOCK_ICAP_REQUEST_TIMEOUT", value)

    assert _parse_args([]).request_timeout == pytest.approx(5.0)


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


def test_domain_option_matches_bracketed_ipv6_source_literally() -> None:
    from services.adblock_decision import (
        _any_domain_matches,
        _compiled_domain_test,
        _host_suffix_set,
    )

    def domain_matches(host: str, domain: str) -> bool:
        test = _compiled_domain_test(domain)
        return test is not None and _any_domain_matches(
            host, _host_suffix_set(host), (test,)
        )

    # fnmatch would read "[2001:db8::1]" as a one-character class.
    assert domain_matches("[2001:db8::1]", "[2001:db8::1]") is True
    assert domain_matches("1", "[2001:db8::1]") is False
    assert domain_matches("ads.example", "*.example") is True


def test_ubo_option_aliases_apply_and_unknown_options_discard_rules(
    tmp_path: Path,
) -> None:
    db_path = _build_lookup_db(
        tmp_path,
        [
            "||alias-xhr.example^$xhr",
            "||alias-3p.example^$3p",
            "||alias-1p.example^$1p",
            "||alias-from.example^$from=source.example",
            "||unknown-option.example^$webrtc",
            "@@||unknown-allow.example^$specifichide",
            "||unknown-allow.example^",
        ],
    )

    from services.adblock_decision import AdblockDecisionEngine

    engine = AdblockDecisionEngine(db_path, cache_ttl_seconds=0, cache_max=0)
    xhr = {"sec-fetch-mode": "cors", "sec-fetch-dest": "empty"}
    image = {"accept": "image/webp"}

    assert engine.decide("https://alias-xhr.example/a", headers=xhr).blocked is True
    assert engine.decide("https://alias-xhr.example/a", headers=image).blocked is False

    cross = {"referer": "https://other.example/"}
    same = {"referer": "https://www.alias-3p.example/"}
    assert engine.decide("https://alias-3p.example/a", headers=cross).blocked is True
    assert engine.decide("https://alias-3p.example/a", headers=same).blocked is False
    same_1p = {"referer": "https://www.alias-1p.example/"}
    assert engine.decide("https://alias-1p.example/a", headers=same_1p).blocked
    assert engine.decide("https://alias-1p.example/a", headers=cross).blocked is False

    scoped = {"referer": "https://source.example/"}
    assert engine.decide("https://alias-from.example/a", headers=scoped).blocked
    assert engine.decide("https://alias-from.example/a", headers=cross).blocked is False

    # Unsupported options must not turn into unrestricted block or allow rules.
    assert engine.decide("https://unknown-option.example/a").blocked is False
    assert engine.decide("https://unknown-allow.example/a").blocked is True


_PRECEDENCE_RULES = (
    "||tier.example^",
    "@@||tier.example/allow/",
    "||tier.example/allow/important/$important",
    "@@||tier.example/allow/important/override/$important",
)


@pytest.mark.parametrize(
    "lists",
    [
        pytest.param([("sample", list(_PRECEDENCE_RULES))], id="one-list"),
        pytest.param(
            [(f"list{index}", [rule]) for index, rule in enumerate(_PRECEDENCE_RULES)],
            id="one-list-per-tier",
        ),
        pytest.param(
            [(f"list{index}", [rule]) for index, rule in enumerate(_PRECEDENCE_RULES)][
                ::-1
            ],
            id="reversed-list-order",
        ),
    ],
)
def test_rule_precedence_follows_adguard_priorities(
    tmp_path: Path, lists: list[tuple[str, list[str]]]
) -> None:
    # AdGuard KB "Rule priorities": @@ adds 10^5, $important 10^6, so
    # @@$important > $important block > @@ > block, whatever list holds them.
    from tools import adblock_compile as ac  # type: ignore

    db_path = tmp_path / "request_lookup.sqlite"
    ac._write_request_lookup_index(str(db_path), lists, ac._Aggregate())

    from services.adblock_decision import AdblockDecisionEngine

    engine = AdblockDecisionEngine(db_path, cache_ttl_seconds=0, cache_max=0)
    expected = {
        "https://tier.example/x.js": (True, "rule-match", 0),
        "https://tier.example/allow/x.js": (False, "exception", 1),
        "https://tier.example/allow/important/x.js": (
            True,
            "important-rule-match",
            2,
        ),
        "https://tier.example/allow/important/override/x.js": (
            False,
            "important-exception",
            3,
        ),
    }
    list_of = {rule: key for key, rules in lists for rule in rules}
    for url, (blocked, reason, tier) in expected.items():
        decision = engine.decide(url, headers={"Sec-Fetch-Dest": "script"})
        assert (decision.blocked, decision.reason) == (blocked, reason), url
        assert decision.raw == _PRECEDENCE_RULES[tier]
        assert decision.list_key == list_of[_PRECEDENCE_RULES[tier]]


def test_important_exception_also_beats_plain_blocks(tmp_path: Path) -> None:
    db_path = _build_lookup_db(
        tmp_path,
        ["||vip.example^", "@@||vip.example/ok^$important"],
    )

    from services.adblock_decision import AdblockDecisionEngine

    engine = AdblockDecisionEngine(db_path, cache_ttl_seconds=0, cache_max=0)

    allowed = engine.decide("https://vip.example/ok")
    assert (allowed.blocked, allowed.reason) == (False, "important-exception")
    assert engine.decide("https://vip.example/other").blocked is True


_NAVIGATION = {
    "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
}


def test_top_level_navigation_is_its_own_context(tmp_path: Path) -> None:
    db_path = _build_lookup_db(
        tmp_path,
        [
            "||nav3p.example^$third-party",
            "||nav1p.example^$~third-party",
            "||navhost.example^",
            "||navdoc.example^$document",
            "||navdoc3p.example^$document,third-party",
            "||navscoped.example^$document,domain=navscoped.example",
            "||navelsewhere.example^$document,domain=opener.example",
        ],
    )

    from services.adblock_decision import AdblockDecisionEngine

    engine = AdblockDecisionEngine(db_path, cache_ttl_seconds=0, cache_max=0)
    opener = {"Referer": "https://opener.example/page", "Sec-Fetch-Site": "cross-site"}

    def blocked(url: str, headers: dict[str, str]) -> bool:
        return engine.decide(url, headers=headers).blocked

    navigation = {**_NAVIGATION, **opener}
    # A link from another site is first-party to the page it opens.
    assert blocked("https://nav3p.example/", navigation) is False
    assert blocked("https://nav1p.example/", navigation) is True
    assert blocked("https://navdoc3p.example/", navigation) is False
    # Hostname-only and explicit $document filters still block pages.
    assert blocked("https://navhost.example/", navigation) is True
    assert blocked("https://navdoc.example/", navigation) is True
    # $domain= is evaluated against the page itself, not the opener.
    assert blocked("https://navscoped.example/", navigation) is True
    assert blocked("https://navelsewhere.example/", navigation) is False
    # Accept-based inference (no fetch metadata) is a navigation too.
    inferred = {"Accept": _NAVIGATION["Accept"], "Referer": opener["Referer"]}
    assert blocked("https://nav3p.example/", inferred) is False
    assert blocked("https://nav1p.example/", inferred) is True
    # Frames keep the embedding page as their context.
    frame = {"Sec-Fetch-Dest": "iframe", "Sec-Fetch-Mode": "navigate", **opener}
    assert blocked("https://nav3p.example/", frame) is True
    assert blocked("https://nav1p.example/", frame) is False
    script = {"Sec-Fetch-Dest": "script", **opener}
    assert blocked("https://nav3p.example/a.js", script) is True


def test_sec_fetch_site_decides_party_over_referer_heuristic(
    tmp_path: Path,
) -> None:
    db_path = _build_lookup_db(
        tmp_path,
        [
            "||sfs3p.example^$third-party",
            "||sfs1p.example^$~third-party",
            "||user.github.io^$third-party",
            "||sfsscoped.example^$domain=source.example",
        ],
    )

    from services.adblock_decision import AdblockDecisionEngine

    engine = AdblockDecisionEngine(db_path, cache_ttl_seconds=0, cache_max=0)

    def blocked(url: str, referer: str, fetch_site: str | None) -> bool:
        headers = {"Sec-Fetch-Dest": "script", "Referer": referer}
        if fetch_site is not None:
            headers["Sec-Fetch-Site"] = fetch_site
        return engine.decide(url, headers=headers).blocked

    same = "https://www.sfs3p.example/"
    other = "https://other.example/"
    # Without Sec-Fetch-Site the registrable-domain heuristic decides.
    assert blocked("https://sfs3p.example/a.js", same, None) is False
    assert blocked("https://sfs3p.example/a.js", other, None) is True
    # The browser's verdict wins over the heuristic both ways.
    assert blocked("https://sfs3p.example/a.js", same, "cross-site") is True
    assert blocked("https://sfs3p.example/a.js", other, "same-site") is False
    assert blocked("https://sfs3p.example/a.js", other, "same-origin") is False
    assert blocked("https://sfs1p.example/a.js", other, "same-site") is True
    assert blocked("https://sfs1p.example/a.js", other, "cross-site") is False
    # The browser knows the PSL private section the heuristic lacks.
    sibling = "https://other.github.io/"
    assert blocked("https://user.github.io/a.js", sibling, None) is False
    assert blocked("https://user.github.io/a.js", sibling, "cross-site") is True
    # `none` (user-initiated) is first-party with no initiator.
    assert blocked("https://sfs3p.example/a.js", other, "none") is False
    assert blocked("https://sfs1p.example/a.js", other, "none") is True
    source = "https://source.example/page"
    assert blocked("https://sfsscoped.example/a.js", source, "none") is False
    # $domain= still matches the Referer/Origin initiator host.
    assert blocked("https://sfsscoped.example/a.js", source, "cross-site") is True
    assert blocked("https://sfsscoped.example/a.js", other, "cross-site") is False
    # An unknown value is treated as absent.
    assert blocked("https://sfs3p.example/a.js", same, "bogus") is False


def test_decision_cache_keys_on_every_party_input(tmp_path: Path) -> None:
    db_path = _build_lookup_db(
        tmp_path,
        [
            "||party.example^$third-party",
            "||scoped.example^$domain=source.example",
            "||page.example^$third-party,document",
        ],
    )

    from services.adblock_decision import AdblockDecisionEngine

    engine = AdblockDecisionEngine(db_path, cache_ttl_seconds=60, cache_max=100)
    referer = "https://www.party.example/"

    def blocked(url: str, **headers: str) -> bool:
        return engine.decide(
            url,
            headers={"Sec-Fetch-Dest": "script", "Referer": referer, **headers},
        ).blocked

    assert blocked("https://party.example/a.js") is False
    assert blocked("https://party.example/a.js", **{"Sec-Fetch-Site": "cross-site"})
    assert blocked("https://party.example/a.js") is False
    referer = "https://source.example/"
    url = "https://scoped.example/a.js"
    assert blocked(url, **{"Sec-Fetch-Site": "same-origin"}) is True
    assert blocked(url, **{"Sec-Fetch-Site": "none"}) is False
    assert blocked(url, **{"Sec-Fetch-Site": "same-origin"}) is True
    cached = len(engine._cache)
    # Navigations depend on the URL alone, so openers share one entry.
    for opener in ("https://a.example/", "https://b.example/x", ""):
        headers = dict(_NAVIGATION)
        if opener:
            headers.update({"Referer": opener, "Sec-Fetch-Site": "cross-site"})
        assert engine.decide("https://page.example/", headers=headers).blocked is False
    assert len(engine._cache) == cached + 1


def test_icap_decision_cache_uses_artifact_admin_settings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import json

    from tools.adblock_icap_server import _decision_cache_settings, _parse_args

    db_path = tmp_path / "request_lookup.sqlite"
    monkeypatch.delenv("ADBLOCK_CACHE_TTL", raising=False)
    monkeypatch.delenv("ADBLOCK_CACHE_MAX", raising=False)

    # No published settings: built-in defaults.
    assert _decision_cache_settings(_parse_args(["--db", str(db_path)])) == (
        3600,
        50000,
    )

    (tmp_path / "settings.json").write_text(
        json.dumps({"cache_ttl": 120, "cache_max": 4096}),
        encoding="utf-8",
    )
    # The Admin UI values published with the artifact take effect.
    assert _decision_cache_settings(_parse_args(["--db", str(db_path)])) == (
        120,
        4096,
    )

    # An explicit operator override still wins.
    monkeypatch.setenv("ADBLOCK_CACHE_TTL", "30")
    assert _decision_cache_settings(_parse_args(["--db", str(db_path)])) == (
        30,
        4096,
    )

    (tmp_path / "settings.json").write_text(
        json.dumps({"cache_ttl": -5, "cache_max": True}),
        encoding="utf-8",
    )
    monkeypatch.delenv("ADBLOCK_CACHE_TTL")
    assert _decision_cache_settings(_parse_args(["--db", str(db_path)])) == (
        3600,
        50000,
    )


def test_decision_cache_keys_on_source_host_not_referer_path(tmp_path: Path) -> None:
    db_path = _build_lookup_db(tmp_path, ["||ads.example^$domain=source.example"])

    from services.adblock_decision import AdblockDecisionEngine

    engine = AdblockDecisionEngine(db_path, cache_ttl_seconds=60, cache_max=10)
    for page in ("a", "b?x=1", "c#frag"):
        decision = engine.decide(
            "https://ads.example/x.js",
            headers={"referer": f"https://source.example/{page}"},
        )
        assert decision.blocked is True
    assert len(engine._cache) == 1
    assert (
        engine.decide(
            "https://ads.example/x.js",
            headers={"referer": "https://other.example/a"},
        ).blocked
        is False
    )
    assert len(engine._cache) == 2


def test_icap_server_refuses_unsupported_lookup_schema_before_listening(
    tmp_path: Path, monkeypatch
) -> None:
    import sqlite3

    from services.adblock_lookup import AdblockLookupSchemaError
    from tools import adblock_icap_server

    db_path = _build_lookup_db(tmp_path, ["||ads.example^"])
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("UPDATE metadata SET value='3' WHERE key='schema_version'")
        conn.commit()
    finally:
        conn.close()
    monkeypatch.setattr(
        adblock_icap_server,
        "_AdblockIcapServer",
        lambda *_args, **_kwargs: pytest.fail("served an unsupported lookup"),
    )

    with pytest.raises(AdblockLookupSchemaError, match="schema version 3"):
        adblock_icap_server.main(["--db", str(db_path), "--port", "0"])


def test_rule_matcher_unmatchable_domain_include_still_restricts_scope() -> None:
    from services.adblock_decision import AdblockDecisionEngine, _RuleMatcher

    context = AdblockDecisionEngine._request_context(
        "https://ads.example/x.js",
        method="GET",
        resource_type="script",
        source_host="news.example",
        third_party=None,
    )
    assert context is not None
    base = {"rule_id": "r1", "action": "block", "pattern_kind": "option_only"}

    assert _RuleMatcher(base).matches(context) is True
    # "." normalizes to nothing: the include can never match, so the rule is
    # scoped to no source domain rather than to every source domain.
    assert _RuleMatcher({**base, "domain_includes": ["."]}).matches(context) is False
    assert (
        _RuleMatcher({**base, "domain_includes": [".", "news.example"]}).matches(
            context
        )
        is True
    )
    assert _RuleMatcher({**base, "domain_excludes": ["."]}).matches(context) is True
    assert (
        _RuleMatcher({**base, "domain_include_patterns": ["news.*"]}).matches(context)
        is True
    )
    # Discarded and non-blocking options never match.
    for extra in (
        {"misc_options": ["unknown"]},
        {"value_options": ["not", "a", "dict"]},
        {"value_options": {"csp": "x"}},
        {"behavior_options": ["badfilter"]},
        {"value_options": {"method": []}},
        {"value_options": {"method": ["trace"]}},
    ):
        assert _RuleMatcher({**base, **extra}).matches(context) is False


@pytest.mark.parametrize(
    "char",
    ["\x00", "\x1f", " ", "\t", "\x7f", "\\", "\x85", "\xa0", "\u2028", "\u3000"],
)
def test_adblock_url_split_rejects_whitespace_controls_and_backslash(
    char: str,
) -> None:
    from services.adblock_hosts import safe_adblock_urlsplit

    assert safe_adblock_urlsplit(f"https://ads.example/a{char}b") is None
    assert safe_adblock_urlsplit("https://ads.example/a\u00e9b") is not None


def test_adblock_block_log_follows_truncation_removal_and_replacement(
    tmp_path: Path,
) -> None:
    from tools.adblock_icap_server import _AppendLog

    path = tmp_path / "logs" / "cicap-access.log"
    log = _AppendLog(str(path))
    try:
        log.append(b"one\n")
        log.append(b"two\n")
        assert path.read_bytes() == b"one\ntwo\n"

        # copytruncate rotation keeps the file: appends continue at its end.
        path.write_bytes(b"")
        log.append(b"three\n")
        assert path.read_bytes() == b"three\n"

        # A replaced file is reopened instead of writing to the old inode.
        rotated = tmp_path / "logs" / "cicap-access.log.1"
        path.rename(rotated)
        path.write_bytes(b"")
        log.append(b"four\n")
        assert path.read_bytes() == b"four\n"
        assert rotated.read_bytes() == b"three\n"

        # A removed log (and directory) is recreated.
        path.unlink()
        rotated.unlink()
        path.parent.rmdir()
        log.append(b"five\n")
        assert path.read_bytes() == b"five\n"
    finally:
        log.close()


def _reqmod(url: str) -> bytes:
    host = urlsplit(url).hostname or ""
    http = f"GET {url} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode("ascii")
    return (
        b"REQMOD icap://127.0.0.1/adblockreq ICAP/1.0\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Encapsulated: req-hdr=0, null-body="
        + str(len(http)).encode("ascii")
        + b"\r\n\r\n"
        + http
    )


def _recv_icap_head(sock: socket.socket) -> bytes:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(65536)
        if not chunk:
            break
        data += chunk
    return data


def test_adblock_icap_server_serves_connection_bursts_and_stalled_peers(
    tmp_path: Path,
) -> None:
    db_path = _build_lookup_db(tmp_path, ["||ads.example^"])

    from services.adblock_decision import AdblockDecisionEngine
    from tools.adblock_icap_server import _AdblockIcapServer

    server = _AdblockIcapServer(
        ("127.0.0.1", 0),
        engine=AdblockDecisionEngine(db_path),
        access_log_path=str(tmp_path / "cicap-access.log"),
        max_request_bytes=65536,
        request_timeout_seconds=1.0,
    )
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    sockets: list[socket.socket] = []
    try:
        # A peer that stops mid-message must not hold up anyone else.
        stalled = socket.create_connection(("127.0.0.1", port), timeout=5.0)
        sockets.append(stalled)
        stalled_request = _reqmod("http://ads.example/stalled.js")
        stalled.sendall(stalled_request[:40])

        # A page-load burst: many connections opened and used at once (more
        # than socketserver's default listen backlog of 5).
        started = time.monotonic()
        burst = [
            socket.create_connection(("127.0.0.1", port), timeout=5.0)
            for _ in range(64)
        ]
        sockets.extend(burst)
        for index, sock in enumerate(burst):
            sock.sendall(_reqmod(f"http://cdn{index}.example/app.js"))
        for sock in burst:
            assert _recv_icap_head(sock).startswith(b"ICAP/1.0 204")
        assert time.monotonic() - started < 0.9

        # Persistent connections keep working after the burst.
        burst[0].sendall(_reqmod("http://ads.example/banner.js"))
        assert _recv_icap_head(burst[0]).startswith(b"ICAP/1.0 200")

        stalled.sendall(stalled_request[40:])
        assert _recv_icap_head(stalled).startswith(b"ICAP/1.0 200")

        # Idle persistent connections are Squid's to close: one idle well past
        # the request timeout is still served (no reuse race).
        time.sleep(1.5)
        idle = burst[1]
        idle.sendall(_reqmod("http://ads.example/after-idle.js"))
        assert _recv_icap_head(idle).startswith(b"ICAP/1.0 200")

        # A started message that stalls is still bounded by the timeout.
        slow = socket.create_connection(("127.0.0.1", port), timeout=5.0)
        sockets.append(slow)
        slow.sendall(_reqmod("http://ads.example/slow.js")[:30])
        started = time.monotonic()
        while slow.recv(65536):
            pass
        assert time.monotonic() - started < 3.0
    finally:
        for sock in sockets:
            sock.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _start_helper_processes(
    tmp_path: Path, db_path: Path, processes: int
) -> tuple[subprocess.Popen[str], int, Path]:
    port = _free_port()
    log_path = tmp_path / "cicap-access.log"
    script = Path(__file__).resolve().parents[1] / "tools" / "adblock_icap_server.py"
    helper = subprocess.Popen(
        [
            sys.executable,
            str(script),
            "--port",
            str(port),
            "--db",
            str(db_path),
            "--access-log",
            str(log_path),
            "--processes",
            str(processes),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    assert helper.stdout is not None
    for _ in range(processes):
        assert "listening on" in helper.stdout.readline()
    return helper, port, log_path


def _process_exits(pid: int, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            status = Path(f"/proc/{pid}/status").read_text(encoding="utf-8")
        except OSError:
            return True
        if "zombie" in status:
            return True
        time.sleep(0.05)
    return False


def _worker_pids(parent_pid: int) -> list[int]:
    children = Path(f"/proc/{parent_pid}/task/{parent_pid}/children")
    return [int(pid) for pid in children.read_text(encoding="utf-8").split()]


@pytest.mark.skipif(
    not Path("/proc/self/task").is_dir(), reason="worker supervision proof needs procfs"
)
def test_adblock_icap_worker_processes_share_the_port_and_live_with_the_helper(
    tmp_path: Path,
) -> None:
    db_path = _build_lookup_db(tmp_path, ["||ads.example^"])
    helper, port, log_path = _start_helper_processes(tmp_path, db_path, 3)
    try:
        workers = _worker_pids(helper.pid)
        assert len(workers) == 2

        # Connections spread over the workers; every one answers, and every
        # blocked request leaves exactly one whole line in the shared log.
        sockets = [
            socket.create_connection(("127.0.0.1", port), timeout=5.0)
            for _ in range(48)
        ]
        try:
            for index, sock in enumerate(sockets):
                sock.sendall(_reqmod(f"http://ads.example/{index}.js"))
            for sock in sockets:
                assert _recv_icap_head(sock).startswith(b"ICAP/1.0 200")
        finally:
            for sock in sockets:
                sock.close()
        lines = log_path.read_text(encoding="utf-8").splitlines()
        assert sorted(line.split("\t")[7] for line in lines) == sorted(
            f"http://ads.example/{index}.js" for index in range(48)
        )

        # A dead worker takes the helper down so supervisor restarts the set.
        os.kill(workers[0], signal.SIGKILL)
        assert helper.wait(timeout=5.0) == 1
        # Its remaining worker follows its parent out.
        assert _process_exits(workers[1])
    finally:
        if helper.poll() is None:
            helper.kill()
            helper.wait(timeout=5.0)


@pytest.mark.skipif(
    not Path("/proc/self/task").is_dir(), reason="worker supervision proof needs procfs"
)
def test_adblock_icap_workers_exit_when_the_helper_is_killed(tmp_path: Path) -> None:
    db_path = _build_lookup_db(tmp_path, ["||ads.example^"])
    helper, _port, _log_path = _start_helper_processes(tmp_path, db_path, 2)
    try:
        [worker] = _worker_pids(helper.pid)
        os.kill(helper.pid, signal.SIGKILL)
        helper.wait(timeout=5.0)
        assert _process_exits(worker)
    finally:
        if helper.poll() is None:
            helper.kill()
            helper.wait(timeout=5.0)
