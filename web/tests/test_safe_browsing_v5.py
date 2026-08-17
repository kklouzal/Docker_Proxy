import base64
import hashlib
import threading
from typing import NoReturn

import pytest
from services import safe_browsing_v5
from services.safe_browsing_v5 import (
    SafeBrowsingLocalChecker,
    SafeBrowsingSettings,
    SafeBrowsingStore,
    SafeBrowsingVerdict,
    _checksum_for_prefixes,
    _decode_b64,
    _decode_search_full_hash,
    canonicalize_url,
    decode_rice_delta_32,
    expression_hashes,
    url_expressions,
)


def _ignore_cache_response(_prefix, _response, _cache_duration, local_lists=None):
    return None


def test_safe_browsing_url_expressions_include_host_suffix_path_prefixes() -> None:
    expressions = url_expressions("HTTPS://Sub.Example.COM/a/b/c?x=1#frag")
    assert "sub.example.com/a/b/c?x=1" in expressions
    assert "example.com/" in expressions
    assert all("#" not in expr for expr in expressions)


def test_safe_browsing_doc_url_expression_examples() -> None:
    assert url_expressions("http://a.b.com/1/2.html?param=1") == [
        "a.b.com/1/2.html?param=1",
        "a.b.com/1/2.html",
        "a.b.com/",
        "a.b.com/1/",
        "b.com/1/2.html?param=1",
        "b.com/1/2.html",
        "b.com/",
        "b.com/1/",
    ]
    assert url_expressions("http://a.b.c.d.e.f.com/1.html") == [
        "a.b.c.d.e.f.com/1.html",
        "a.b.c.d.e.f.com/",
        "c.d.e.f.com/1.html",
        "c.d.e.f.com/",
        "d.e.f.com/1.html",
        "d.e.f.com/",
        "e.f.com/1.html",
        "e.f.com/",
        "f.com/1.html",
        "f.com/",
    ]
    assert url_expressions("http://1.2.3.4/1/") == ["1.2.3.4/1/", "1.2.3.4/"]
    assert url_expressions("http://example.co.uk/1") == [
        "example.co.uk/1",
        "example.co.uk/",
    ]


def test_safe_browsing_canonicalization_normalizes_controls_path_ip_and_idn() -> None:
    assert (
        canonicalize_url("http://0300.0250.0001.0001/a//b/../c#frag")
        == "http://192.168.1.1/a/c"
    )
    assert canonicalize_url("http://☃.example/%2525") == "http://xn--n3h.example/%25"


def test_safe_browsing_canonicalization_preserves_encoded_fragment_marker_in_path() -> (
    None
):
    assert canonicalize_url("http://host.com/ab%23cd") == "http://host.com/ab%23cd"
    assert url_expressions("http://host.com/ab%23cd") == [
        "host.com/ab%23cd",
        "host.com/",
    ]


def test_safe_browsing_ipv6_literals_stay_bracketed_for_expression_generation() -> None:
    assert canonicalize_url("http://[2001:db8::1]/a") == "http://[2001:db8::1]/a"
    assert canonicalize_url("http://[2001:db8::1]:443/a") == "http://[2001:db8::1]/a"
    assert url_expressions("http://[2001:db8::1]/a") == [
        "2001:db8::1/a",
        "2001:db8::1/",
    ]


@pytest.mark.parametrize(
    "url",
    [
        "http://[::1",
        "http://user:pass@[::1",
        "http://example.com]",
    ],
)
def test_safe_browsing_malformed_bracket_urls_are_empty(url: str) -> None:
    assert canonicalize_url(url) == ""
    assert url_expressions(url) == []


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com:bad/path",
        "http://example.com:/path",
        "http://example.com:99999/path",
        "http://user:pass@example.com:/path",
        "http://[2001:db8::1]:/a",
        "http://[2001:db8::1]:bad/a",
        r"http://example.com\evil.test/path",
        r"http://example.com\@evil.test/path",
    ],
)
def test_safe_browsing_malformed_authority_urls_are_empty(url: str) -> None:
    assert canonicalize_url(url) == ""
    assert url_expressions(url) == []


def test_safe_browsing_percent_encoded_authority_delimiters_are_empty() -> None:
    for url in (
        "http://good.example%40evil.example/path",
        "http://good.example%5Cevil.example/path",
        "http://good.example%2Fevil.example/path",
        "http://good.example%3A80/path",
        "http://good.example%5B.evil/path",
    ):
        assert canonicalize_url(url) == ""
        assert url_expressions(url) == []


def test_safe_browsing_hashes_are_sha256_expression_hashes() -> None:
    expressions = url_expressions("example.com/")
    hashes = expression_hashes("example.com/")
    assert hashlib.sha256(expressions[0].encode("utf-8")).digest() in hashes
    assert all(len(item) == 32 for item in hashes)


def test_safe_browsing_rice_decoder_handles_single_value() -> None:
    assert decode_rice_delta_32({"firstValue": 0x01020304, "entriesCount": 0}) == [
        0x01020304
    ]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("firstValue", True),
        ("firstValue", 1.0),
        ("firstValue", "1"),
        ("firstValue", -1),
        ("firstValue", 1 << 32),
        ("entriesCount", False),
        ("entriesCount", -1),
        ("entriesCount", 1 << 31),
        ("riceParameter", "3"),
        ("riceParameter", 2),
        ("riceParameter", 31),
    ],
)
def test_safe_browsing_rice_decoder_rejects_invalid_numeric_fields(
    field, value
) -> None:
    payload = {
        "firstValue": 1,
        "entriesCount": 1,
        "riceParameter": 3,
        "encodedData": "AA==",
    }
    payload[field] = value
    with pytest.raises(ValueError, match="compressed Rice parameters are invalid"):
        decode_rice_delta_32(payload)


def test_safe_browsing_rice_decoder_rejects_truncated_payload() -> None:
    with pytest.raises(ValueError, match="compressed Rice data is truncated"):
        decode_rice_delta_32(
            {
                "firstValue": 7,
                "entriesCount": 1,
                "riceParameter": 3,
                "encodedData": "",
            }
        )


@pytest.mark.parametrize(
    ("encoded_data", "expected"),
    [
        pytest.param("AA==", b"\x00", id="standard-padded"),
        pytest.param("AA", b"\x00", id="standard-unpadded"),
        pytest.param("+w==", b"\xfb", id="standard-padded-alphabet"),
        pytest.param("+w", b"\xfb", id="standard-unpadded-alphabet"),
        pytest.param("-w==", b"\xfb", id="url-safe-padded-alphabet"),
        pytest.param("-w", b"\xfb", id="url-safe-unpadded-alphabet"),
    ],
)
def test_safe_browsing_byte_decoder_accepts_protojson_base64_variants(
    encoded_data,
    expected,
) -> None:
    assert _decode_b64(encoded_data, field="encodedData") == expected


@pytest.mark.parametrize(
    "encoded_data",
    ["@@", "A", "AA=", "AA=AA", "A-A+", "A_A/", 1],
)
def test_safe_browsing_rice_decoder_rejects_malformed_base64(encoded_data) -> None:
    with pytest.raises(ValueError, match=r"compressed Rice encodedData.*base64"):
        decode_rice_delta_32(
            {
                "firstValue": 7,
                "entriesCount": 1,
                "riceParameter": 3,
                "encodedData": encoded_data,
            }
        )


def test_safe_browsing_checker_does_not_call_remote_without_local_prefix(
    monkeypatch,
) -> None:
    checker = SafeBrowsingLocalChecker(api_key="test")
    monkeypatch.setattr(checker, "_local_lists_for_prefix", lambda prefix: ())

    def fail_remote(*args, **kwargs) -> NoReturn:
        msg = "remote hashes.search should not run without a local prefix hit"
        raise AssertionError(msg)

    monkeypatch.setattr(checker._store, "search_hashes", fail_remote)
    verdict = checker.check_url("http://clean.example/")
    assert verdict.verdict == "safe"
    assert verdict.reason == "no local hash-prefix match"
    assert checker._verdict_cache == {}


def test_safe_browsing_checker_confirms_full_hash_after_local_prefix(
    monkeypatch,
) -> None:
    checker = SafeBrowsingLocalChecker(api_key="test")
    hashes = expression_hashes("http://bad.example/")
    target = hashes[0]
    monkeypatch.setattr(
        checker,
        "_local_lists_for_prefix",
        lambda prefix: ("mw-4b",) if prefix == target[:4] else (),
    )
    monkeypatch.setattr(
        checker, "_cache_lookup", lambda prefix, full_hashes, local_lists=None: None
    )
    monkeypatch.setattr(checker, "_cache_search_response", _ignore_cache_response)
    monkeypatch.setattr(
        checker._store,
        "search_hashes",
        lambda api_key, prefixes: (
            [
                {
                    "fullHash": base64.urlsafe_b64encode(target)
                    .decode("ascii")
                    .rstrip("="),
                    "fullHashDetails": [{"threatType": "MALWARE"}],
                }
            ],
            300,
        ),
    )
    verdict = checker.check_url("http://bad.example/")
    assert verdict == SafeBrowsingVerdict(
        "unsafe", "MALWARE", "mw-4b", False, "confirmed by hashes.search"
    )


def test_safe_browsing_checker_fails_open_when_full_hash_search_raises(
    monkeypatch,
) -> None:
    checker = SafeBrowsingLocalChecker(api_key="test")
    target = expression_hashes("http://suspicious.example/")[0]
    remote_calls = []

    monkeypatch.setattr(
        checker,
        "_local_lists_for_prefix",
        lambda prefix: ("mw-4b",) if prefix == target[:4] else (),
    )
    monkeypatch.setattr(
        checker, "_cache_lookup", lambda prefix, full_hashes, local_lists=None: None
    )

    def search_hashes(api_key, prefixes):
        remote_calls.append((api_key, tuple(prefixes)))
        msg = "simulated hashes.search timeout with secret test key"
        raise TimeoutError(msg)

    def cache_search_response(*args, **kwargs) -> NoReturn:
        msg = "failed hashes.search responses must not be cached as unsafe"
        raise AssertionError(msg)

    monkeypatch.setattr(checker._store, "search_hashes", search_hashes)
    monkeypatch.setattr(checker, "_cache_search_response", cache_search_response)

    verdict = checker.check_url("http://suspicious.example/")

    assert verdict == SafeBrowsingVerdict(
        "safe",
        reason="full-hash confirmation unavailable",
    )
    assert "secret" not in verdict.reason
    assert remote_calls == [("test", (target[:4],))]
    assert checker._verdict_cache == {}


def test_safe_browsing_checker_does_not_cache_api_key_unavailable_verdict(
    monkeypatch,
) -> None:
    checker = SafeBrowsingLocalChecker(api_key="")
    target = expression_hashes("http://needs-confirmation.example/")[0]

    monkeypatch.setattr(
        checker,
        "_local_lists_for_prefix",
        lambda prefix: ("mw-4b",) if prefix == target[:4] else (),
    )
    monkeypatch.setattr(
        checker, "_cache_lookup", lambda prefix, full_hashes, local_lists=None: None
    )
    monkeypatch.setattr(checker, "_api_key_from_settings", lambda: "")

    verdict = checker.check_url("http://needs-confirmation.example/")

    assert verdict == SafeBrowsingVerdict(
        "safe",
        reason="api key unavailable for full-hash confirmation",
    )
    assert checker._verdict_cache == {}


def test_safe_browsing_checker_reports_matching_list_for_threat(monkeypatch) -> None:
    checker = SafeBrowsingLocalChecker(
        api_key="test",
        selected_lists=("se-4b", "mw-4b"),
    )
    target = expression_hashes("http://bad.example/")[0]
    monkeypatch.setattr(
        checker,
        "_local_lists_for_prefix",
        lambda prefix: ("se-4b", "mw-4b") if prefix == target[:4] else (),
    )
    monkeypatch.setattr(
        checker, "_cache_lookup", lambda prefix, full_hashes, local_lists=None: None
    )
    monkeypatch.setattr(
        checker,
        "_cache_search_response",
        _ignore_cache_response,
    )
    monkeypatch.setattr(
        checker._store,
        "search_hashes",
        lambda api_key, prefixes: (
            [
                {
                    "fullHash": base64.urlsafe_b64encode(target)
                    .decode("ascii")
                    .rstrip("="),
                    "fullHashDetails": [{"threatType": "MALWARE"}],
                }
            ],
            300,
        ),
    )

    verdict = checker.check_url("http://bad.example/")

    assert verdict == SafeBrowsingVerdict(
        "unsafe", "MALWARE", "mw-4b", False, "confirmed by hashes.search"
    )


def test_safe_browsing_opener_disables_ambient_proxies() -> None:
    proxy_handlers = [
        handler
        for handler in safe_browsing_v5._SAFE_BROWSING_OPENER.handlers
        if isinstance(handler, safe_browsing_v5.urllib.request.ProxyHandler)
    ]

    assert proxy_handlers == []


def test_safe_browsing_redirects_fail_closed_before_forwarding_api_key() -> None:
    request = safe_browsing_v5.urllib.request.Request(
        "https://safebrowsing.googleapis.com/v5/hashes:search?key=***"
    )

    with pytest.raises(RuntimeError, match="redirects are not allowed"):
        safe_browsing_v5._RejectSafeBrowsingRedirects().redirect_request(
            request,
            None,
            302,
            "Found",
            {},
            "https://attacker.example/collect",
        )


def test_safe_browsing_request_json_reports_response_size_limit(monkeypatch) -> None:

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, size):
            assert size == 1025
            return b"x" * 1025

    def fake_urlopen(request, timeout):
        assert timeout == 30
        assert "hashLists:batchGet" in request.full_url
        return FakeResponse()

    monkeypatch.setenv("SAFE_BROWSING_MAX_RESPONSE_BYTES", "1024")
    monkeypatch.setattr(safe_browsing_v5, "_open_safe_browsing_request", fake_urlopen)

    try:
        SafeBrowsingStore()._request_json("/hashLists:batchGet", "key", [])
    except ValueError as exc:
        assert "SAFE_BROWSING_MAX_RESPONSE_BYTES (1024 bytes)" in str(exc)
    else:
        msg = "oversized Safe Browsing responses should fail with a clear error"
        raise AssertionError(msg)


def _search_hash_item(
    full_hash: bytes,
    details: object | None = None,
) -> dict[str, object]:
    return {
        "fullHash": base64.urlsafe_b64encode(full_hash).decode("ascii").rstrip("="),
        "fullHashDetails": details
        if details is not None
        else [{"threatType": "MALWARE"}],
    }


@pytest.mark.parametrize("urlsafe", [False, True], ids=["standard", "url-safe"])
@pytest.mark.parametrize("padded", [True, False], ids=["padded", "unpadded"])
def test_safe_browsing_search_full_hash_decoder_accepts_protojson_base64_variants(
    urlsafe,
    padded,
) -> None:
    full_hash = bytes.fromhex("fbfffefd") * 8
    encoder = base64.urlsafe_b64encode if urlsafe else base64.b64encode
    encoded = encoder(full_hash).decode("ascii")
    if not padded:
        encoded = encoded.rstrip("=")

    assert _decode_search_full_hash(encoded) == full_hash


@pytest.mark.parametrize(
    ("value", "error"),
    [
        pytest.param(
            "+_/+/fv//v37//79+//+/fv//v37//79+//+/fv//v0=",
            "must use one base64 alphabet",
            id="mixed-alphabets",
        ),
        pytest.param("A" * 41, "correctly padded base64", id="impossible-length"),
        pytest.param("A" * 43 + "==", "correctly padded base64", id="bad-padding"),
        pytest.param("@" * 44, "must be base64-encoded", id="invalid-characters"),
        pytest.param(" A" * 22, "must be base64-encoded", id="whitespace"),
        pytest.param("", "must be base64-encoded", id="empty"),
        pytest.param(None, "must be base64-encoded", id="null"),
        pytest.param(1, "must be base64-encoded", id="non-string"),
        pytest.param(
            base64.b64encode(b"x" * 31).decode("ascii"),
            "must be exactly 32 bytes",
            id="wrong-decoded-length",
        ),
    ],
)
def test_safe_browsing_search_full_hash_decoder_rejects_malformed_values(
    value,
    error,
) -> None:
    with pytest.raises(ValueError, match=error):
        _decode_search_full_hash(value)


@pytest.mark.parametrize(
    "response",
    [
        pytest.param([], id="non-object-response"),
        pytest.param({"fullHashes": None}, id="null-full-hashes"),
        pytest.param({"fullHashes": {}}, id="non-array-full-hashes"),
        pytest.param({"fullHashes": [None]}, id="null-entry"),
        pytest.param({"fullHashes": ["hash"]}, id="non-object-entry"),
        pytest.param(
            {"fullHashes": [{"fullHashDetails": []}]},
            id="missing-full-hash",
        ),
        pytest.param(
            {"fullHashes": [_search_hash_item(b"a" * 31)]},
            id="wrong-hash-length",
        ),
        pytest.param(
            {
                "fullHashes": [
                    {"fullHash": "!!!!", "fullHashDetails": []},
                ],
            },
            id="invalid-base64",
        ),
        pytest.param(
            {"fullHashes": [_search_hash_item(b"wxyz" + b"b" * 28)]},
            id="unrequested-prefix",
        ),
        pytest.param(
            {
                "fullHashes": [
                    _search_hash_item(b"abcd" + b"a" * 28, {}),
                ],
            },
            id="non-array-details",
        ),
        pytest.param(
            {
                "fullHashes": [
                    _search_hash_item(b"abcd" + b"a" * 28, [None]),
                ],
            },
            id="non-object-detail",
        ),
        pytest.param(
            {
                "fullHashes": [
                    _search_hash_item(b"abcd" + b"a" * 28, [{}]),
                ],
            },
            id="missing-threat-type",
        ),
        pytest.param(
            {
                "fullHashes": [
                    _search_hash_item(
                        b"abcd" + b"a" * 28,
                        [{"threatType": "MALWARE", "attributes": "CANARY"}],
                    ),
                ],
            },
            id="non-array-attributes",
        ),
        pytest.param(
            {"fullHashes": [], "cacheDuration": {"seconds": 300}},
            id="invalid-cache-duration",
        ),
    ],
)
def test_safe_browsing_search_hashes_rejects_malformed_response(
    monkeypatch,
    response,
) -> None:
    store = SafeBrowsingStore()
    monkeypatch.setattr(store, "_request_json", lambda *_args, **_kwargs: response)

    with pytest.raises(ValueError, match="hash search"):
        store.search_hashes("key", [b"abcd"])


def test_safe_browsing_search_hashes_accepts_valid_multi_prefix_multi_threat(
    monkeypatch,
) -> None:
    first = b"abcd" + b"a" * 28
    second = bytes.fromhex("fbfffefd") + b"b" * 28
    response = {
        "fullHashes": [
            _search_hash_item(
                first,
                [
                    {"threatType": "MALWARE"},
                    {"threatType": "SOCIAL_ENGINEERING"},
                ],
            ),
            {
                "fullHash": base64.b64encode(second).decode("ascii"),
                "fullHashDetails": [
                    {"threatType": "FUTURE_THREAT_TYPE", "attributes": []},
                ],
            },
        ],
        "cacheDuration": "3.5s",
    }
    calls = []
    store = SafeBrowsingStore()

    def request_json(path, api_key, params, timeout):
        calls.append((path, api_key, params, timeout))
        return response

    monkeypatch.setattr(store, "_request_json", request_json)

    full_hashes, duration = store.search_hashes("key", [first[:4], second[:4]])

    assert full_hashes == [
        _search_hash_item(
            first,
            [
                {"threatType": "MALWARE"},
                {"threatType": "SOCIAL_ENGINEERING"},
            ],
        ),
        _search_hash_item(second, [{"threatType": "FUTURE_THREAT_TYPE"}]),
    ]
    assert duration == 3
    assert calls == [
        (
            "/hashes:search",
            "key",
            [("hashPrefixes", "YWJjZA"), ("hashPrefixes", "-__-_Q")],
            8,
        ),
    ]


def test_safe_browsing_search_hashes_normalizes_known_fields_and_base64(
    monkeypatch,
) -> None:
    target = bytes.fromhex("fbfffefd") + b"a" * 28
    response = {
        "fullHashes": [
            {
                "fullHash": base64.b64encode(target).decode("ascii"),
                "ignoredEntryField": "untrusted",
                "fullHashDetails": [
                    {
                        "threatType": "FUTURE_THREAT_TYPE",
                        "attributes": ["FUTURE_ATTRIBUTE"],
                        "ignoredDetailField": {"untrusted": True},
                    },
                ],
            },
        ],
    }
    store = SafeBrowsingStore()
    monkeypatch.setattr(store, "_request_json", lambda *_args, **_kwargs: response)

    full_hashes, _duration = store.search_hashes("key", [target[:4]])

    assert full_hashes == [
        {
            "fullHash": base64.urlsafe_b64encode(target).decode("ascii").rstrip("="),
            "fullHashDetails": [
                {
                    "threatType": "FUTURE_THREAT_TYPE",
                    "attributes": ["FUTURE_ATTRIBUTE"],
                },
            ],
        },
    ]


def test_safe_browsing_search_hashes_coalesces_duplicate_full_hash_details(
    monkeypatch,
) -> None:
    target = b"abcd" + b"a" * 28
    response = {
        "fullHashes": [
            _search_hash_item(target, [{"threatType": "MALWARE"}]),
            _search_hash_item(
                target,
                [
                    {"threatType": "MALWARE"},
                    {"threatType": "SOCIAL_ENGINEERING"},
                ],
            ),
        ],
        "cacheDuration": "300s",
    }
    store = SafeBrowsingStore()
    monkeypatch.setattr(store, "_request_json", lambda *_args, **_kwargs: response)

    full_hashes, duration = store.search_hashes("key", [target[:4]])

    assert full_hashes == [
        _search_hash_item(
            target,
            [
                {"threatType": "MALWARE"},
                {"threatType": "SOCIAL_ENGINEERING"},
            ],
        ),
    ]
    assert duration == 300


def test_safe_browsing_checker_fails_open_for_malformed_hash_search_response(
    monkeypatch,
) -> None:
    from services import safe_browsing_v5

    checker = SafeBrowsingLocalChecker(api_key="test", selected_lists=("mw-4b",))
    target = b"abcd" + b"a" * 28
    monkeypatch.setattr(safe_browsing_v5, "expression_hashes", lambda _url: [target])
    monkeypatch.setattr(
        checker, "_synchronize_local_cache_versions", lambda _lists: None
    )
    monkeypatch.setattr(checker, "_local_lists_for_prefix", lambda _prefix: ("mw-4b",))
    monkeypatch.setattr(
        checker, "_cache_lookup", lambda _prefix, _hashes, _lists=None: None
    )
    monkeypatch.setattr(
        checker._store,
        "_request_json",
        lambda *_args, **_kwargs: {
            "fullHashes": [None],
            "cacheDuration": "300s",
        },
    )

    def fail_cache(*_args, **_kwargs) -> NoReturn:
        msg = "malformed provider data must not reach the cache writer"
        raise AssertionError(msg)

    monkeypatch.setattr(checker, "_cache_search_response", fail_cache)

    assert checker.check_url(
        "http://malformed-response.example/"
    ) == SafeBrowsingVerdict(
        "safe",
        reason="full-hash confirmation unavailable",
    )
    assert checker._verdict_cache == {}


def test_safe_browsing_checker_rejects_full_hash_for_unrequested_prefix(
    monkeypatch,
) -> None:
    from services import safe_browsing_v5

    checker = SafeBrowsingLocalChecker(api_key="test", selected_lists=("mw-4b",))
    requested = b"abcd" + b"a" * 28
    other_expression = b"wxyz" + b"b" * 28
    monkeypatch.setattr(
        safe_browsing_v5,
        "expression_hashes",
        lambda _url: [requested, other_expression],
    )
    monkeypatch.setattr(
        checker, "_synchronize_local_cache_versions", lambda _lists: None
    )
    monkeypatch.setattr(
        checker,
        "_local_lists_for_prefix",
        lambda prefix: ("mw-4b",) if prefix == requested[:4] else (),
    )
    monkeypatch.setattr(
        checker, "_cache_lookup", lambda _prefix, _hashes, _lists=None: None
    )
    monkeypatch.setattr(
        checker._store,
        "_request_json",
        lambda *_args, **_kwargs: {
            "fullHashes": [_search_hash_item(other_expression)],
            "cacheDuration": "300s",
        },
    )

    cache_calls = []
    monkeypatch.setattr(
        checker,
        "_cache_search_response",
        lambda *args, **kwargs: cache_calls.append((args, kwargs)),
    )

    assert checker.check_url("http://cross-prefix.example/") == SafeBrowsingVerdict(
        "safe",
        reason="full-hash confirmation unavailable",
    )
    assert cache_calls == []
    assert checker._verdict_cache == {}


def test_safe_browsing_cache_skips_wrong_prefix_and_duplicate_full_hash() -> None:
    requested = b"abcd" + b"a" * 28
    wrong_prefix = b"wxyz" + b"b" * 28
    executed = []

    class FakeConn:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, sql, params=None):
            executed.append((sql, params))

    checker = SafeBrowsingLocalChecker(api_key="test")
    checker._connect = FakeConn
    checker._cache_search_response(
        requested[:4],
        [
            _search_hash_item(requested),
            _search_hash_item(requested),
            _search_hash_item(wrong_prefix),
        ],
        300,
        local_lists=("mw-4b",),
    )

    inserts = [
        params for sql, params in executed if "safe_browsing_full_hash_cache" in sql
    ]
    assert len(inserts) == 1
    assert inserts[0][0:4] == (requested[:4], requested, "MALWARE", "mw-4b")


def test_safe_browsing_checker_ignores_unknown_threat_attribute(monkeypatch) -> None:
    checker = SafeBrowsingLocalChecker(api_key="test")
    target = expression_hashes("http://future-attribute.example/")[0]
    monkeypatch.setattr(
        checker,
        "_local_lists_for_prefix",
        lambda prefix: ("mw-4b",) if prefix == target[:4] else (),
    )
    monkeypatch.setattr(
        checker, "_cache_lookup", lambda _prefix, _hashes, local_lists=None: None
    )
    monkeypatch.setattr(checker, "_cache_search_response", _ignore_cache_response)
    monkeypatch.setattr(
        checker._store,
        "search_hashes",
        lambda _api_key, _prefixes: (
            [
                _search_hash_item(
                    target,
                    [{"threatType": "MALWARE", "attributes": ["FUTURE_ATTRIBUTE"]}],
                ),
            ],
            300,
        ),
    )

    assert checker.check_url("http://future-attribute.example/") == SafeBrowsingVerdict(
        "safe",
        reason="full hash not returned",
    )


def _stateful_local_list_checker(url: str, *, prefix_present: bool):
    target = expression_hashes(url)[0]
    state = {
        "version": b"v1",
        "prefixes": {target[:4]} if prefix_present else set(),
        "version_queries": 0,
        "prefix_queries": 0,
        "full_hash_queries": 0,
        "fail_version_query": False,
    }

    class Result:
        def __init__(self, rows=()):
            self.rows = list(rows)

        def fetchall(self):
            return self.rows

    class DatabaseUnavailableError(RuntimeError):
        pass

    class Conn:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, sql, params=None):
            normalized = " ".join(str(sql).split())
            if "FROM safe_browsing_hash_lists" in normalized:
                state["version_queries"] += 1
                if state["fail_version_query"]:
                    raise DatabaseUnavailableError
                return Result([("mw-4b", state["version"])])
            if "FROM safe_browsing_hash_prefixes" in normalized:
                state["prefix_queries"] += 1
                prefix = params[0]
                return Result([("mw-4b",)] if prefix in state["prefixes"] else [])
            if "FROM safe_browsing_full_hash_cache" in normalized:
                state["full_hash_queries"] += 1
                return Result([(target, "MALWARE", "mw-4b", 9999999999)])
            raise AssertionError(normalized)

    checker = SafeBrowsingLocalChecker(
        api_key="test",
        selected_lists=("mw-4b",),
    )
    checker._connect = Conn
    return checker, target, state


@pytest.mark.parametrize("clear_verdict", [False, True], ids=["verdict", "prefix"])
def test_safe_browsing_list_version_change_invalidates_unsafe_local_caches(
    clear_verdict,
) -> None:
    url = "http://removed-threat.example/"
    checker, _target, state = _stateful_local_list_checker(
        url,
        prefix_present=True,
    )

    assert checker.check_url(url).verdict == "unsafe"
    state["version"] = b"v2"
    state["prefixes"] = set()
    if clear_verdict:
        checker._verdict_cache.clear()

    verdict = checker.check_url(url)

    assert verdict == SafeBrowsingVerdict("safe", reason="no local hash-prefix match")
    assert state["prefix_queries"] == 2


def test_safe_browsing_concurrent_old_version_cannot_repopulate_verdict_cache(
    monkeypatch,
) -> None:
    url = "http://concurrent-removed-threat.example/"
    checker, _target, state = _stateful_local_list_checker(
        url,
        prefix_present=True,
    )
    cache_write_ready = threading.Event()
    release_cache_write = threading.Event()
    results = []
    errors = []
    original_cache_verdict = checker._cache_verdict

    def delayed_cache_verdict(key, verdict, *args):
        if threading.current_thread() is stale_thread:
            cache_write_ready.set()
            if not release_cache_write.wait(timeout=5):
                msg = "timed out waiting to release stale cache write"
                raise AssertionError(msg)
        return original_cache_verdict(key, verdict, *args)

    monkeypatch.setattr(checker, "_cache_verdict", delayed_cache_verdict)

    def stale_lookup() -> None:
        try:
            results.append(checker.check_url(url))
        except Exception as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    stale_thread = threading.Thread(target=stale_lookup)
    stale_thread.start()
    assert cache_write_ready.wait(timeout=5)

    state["version"] = b"v2"
    state["prefixes"] = set()
    assert checker.check_url(url) == SafeBrowsingVerdict(
        "safe",
        reason="no local hash-prefix match",
    )

    release_cache_write.set()
    stale_thread.join(timeout=5)
    assert not stale_thread.is_alive()
    assert errors == []
    assert results
    assert results[0].verdict == "unsafe"

    assert checker.check_url(url) == SafeBrowsingVerdict(
        "safe",
        reason="no local hash-prefix match",
    )


def test_safe_browsing_list_version_change_invalidates_prefix_misses() -> None:
    url = "http://new-threat.example/"
    checker, target, state = _stateful_local_list_checker(
        url,
        prefix_present=False,
    )

    assert checker.check_url(url).verdict == "safe"
    state["version"] = b"v2"
    state["prefixes"] = {target[:4]}

    verdict = checker.check_url(url)

    assert verdict.verdict == "unsafe"
    assert state["prefix_queries"] > len(expression_hashes(url))


def test_safe_browsing_unchanged_list_version_retains_local_caches() -> None:
    url = "http://cached-threat.example/"
    checker, _target, state = _stateful_local_list_checker(
        url,
        prefix_present=True,
    )

    assert checker.check_url(url).verdict == "unsafe"
    assert checker.check_url(url).verdict == "unsafe"

    assert state["version_queries"] == 2
    assert state["prefix_queries"] == 1
    assert state["full_hash_queries"] == 1


def test_safe_browsing_list_version_error_does_not_reuse_unsafe_local_cache() -> None:
    url = "http://unavailable-list-state.example/"
    checker, _target, state = _stateful_local_list_checker(
        url,
        prefix_present=True,
    )

    assert checker.check_url(url).verdict == "unsafe"
    state["fail_version_query"] = True
    state["prefixes"] = set()

    verdict = checker.check_url(url)

    assert verdict == SafeBrowsingVerdict("safe", reason="no local hash-prefix match")


def test_safe_browsing_prefix_miss_cache_uses_short_ttl(monkeypatch) -> None:
    from services import safe_browsing_v5

    now = [100.0]
    rows_by_call = [[], [("mw-4b",)]]
    calls = []

    class Result:
        def __init__(self, rows):
            self.rows = rows

        def fetchall(self):
            return self.rows

        def fetchone(self):
            return self.rows[0] if self.rows else None

    class FakeConn:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, sql, params=None):
            calls.append((sql, params))
            return Result(rows_by_call[min(len(calls) - 1, len(rows_by_call) - 1)])

    checker = SafeBrowsingLocalChecker(
        api_key="test",
        prefix_hit_ttl_seconds=3600,
        prefix_miss_ttl_seconds=10,
        selected_lists=("mw-4b",),
    )
    monkeypatch.setattr(safe_browsing_v5.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(checker, "_connect", FakeConn)

    assert checker._local_lists_for_prefix(b"abcd") == ()
    now[0] = 105.0
    assert checker._local_lists_for_prefix(b"abcd") == ()
    assert len(calls) == 1
    now[0] = 111.0
    assert checker._local_lists_for_prefix(b"abcd") == ("mw-4b",)
    now[0] = 120.0
    assert checker._local_lists_for_prefix(b"abcd") == ("mw-4b",)
    assert len(calls) == 2


def test_safe_browsing_prefix_lookup_filters_to_selected_lists(monkeypatch) -> None:
    from services import safe_browsing_v5

    calls = []

    class Result:
        def __init__(self, rows):
            self.rows = rows

        def fetchall(self):
            return self.rows

    class FakeConn:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, sql, params=None):
            calls.append((sql, params))
            assert "list_name IN" in sql
            assert params == (b"abcd", "mw-4b")
            return Result([])

    checker = SafeBrowsingLocalChecker(api_key="test", selected_lists=("mw-4b",))
    monkeypatch.setattr(safe_browsing_v5.time, "monotonic", lambda: 100.0)
    monkeypatch.setattr(checker, "_connect", FakeConn)

    assert checker._local_lists_for_prefix(b"abcd") == ()
    assert len(calls) == 1


def test_safe_browsing_checker_ignores_unselected_threat_response(monkeypatch) -> None:
    checker = SafeBrowsingLocalChecker(api_key="test", selected_lists=("mw-4b",))
    target = expression_hashes("http://social.example/")[0]
    monkeypatch.setattr(
        checker,
        "_local_lists_for_prefix",
        lambda prefix: ("mw-4b",) if prefix == target[:4] else (),
    )
    monkeypatch.setattr(
        checker, "_cache_lookup", lambda prefix, full_hashes, local_lists=None: None
    )
    monkeypatch.setattr(
        checker,
        "_cache_search_response",
        _ignore_cache_response,
    )
    monkeypatch.setattr(
        checker._store,
        "search_hashes",
        lambda api_key, prefixes: (
            [
                {
                    "fullHash": base64.urlsafe_b64encode(target)
                    .decode("ascii")
                    .rstrip("="),
                    "fullHashDetails": [{"threatType": "SOCIAL_ENGINEERING"}],
                }
            ],
            300,
        ),
    )

    verdict = checker.check_url("http://social.example/")

    assert verdict == SafeBrowsingVerdict("safe", reason="full hash not returned")


def test_safe_browsing_checker_continues_after_negative_prefix_cache(
    monkeypatch,
) -> None:
    from services import safe_browsing_v5

    checker = SafeBrowsingLocalChecker(api_key="test")
    first = b"a" * 32
    second = b"b" * 32
    monkeypatch.setattr(
        safe_browsing_v5,
        "expression_hashes",
        lambda url: [first, second],
    )
    monkeypatch.setattr(
        checker,
        "_local_lists_for_prefix",
        lambda prefix: ("mw-4b",) if prefix in {first[:4], second[:4]} else (),
    )

    def cache_lookup(prefix, full_hashes, local_lists=None):
        if prefix == first[:4]:
            return SafeBrowsingVerdict(
                "safe",
                cache_hit=True,
                reason="cached negative full-hash response",
            )
        return None

    monkeypatch.setattr(checker, "_cache_lookup", cache_lookup)
    monkeypatch.setattr(
        checker,
        "_cache_search_response",
        _ignore_cache_response,
    )
    monkeypatch.setattr(
        checker._store,
        "search_hashes",
        lambda api_key, prefixes: (
            [
                {
                    "fullHash": base64.urlsafe_b64encode(second)
                    .decode("ascii")
                    .rstrip("="),
                    "fullHashDetails": [{"threatType": "MALWARE"}],
                }
            ],
            300,
        ),
    )

    verdict = checker.check_url("http://bad.example/")

    assert verdict == SafeBrowsingVerdict(
        "unsafe", "MALWARE", "mw-4b", False, "confirmed by hashes.search"
    )


def test_safe_browsing_verdict_cache_scopes_to_selected_lists(monkeypatch) -> None:
    checker = SafeBrowsingLocalChecker(api_key="test")
    target = expression_hashes("http://social.example/")[0]
    remote_calls = []

    def selected_lists():
        if remote_calls:
            return ("se-4b",)
        return ("mw-4b",)

    monkeypatch.setattr(checker, "_selected_lists_for_lookup", selected_lists)
    monkeypatch.setattr(
        checker,
        "_local_lists_for_prefix",
        lambda prefix: selected_lists() if prefix == target[:4] else (),
    )
    monkeypatch.setattr(
        checker, "_cache_lookup", lambda prefix, full_hashes, local_lists=None: None
    )
    monkeypatch.setattr(
        checker,
        "_cache_search_response",
        _ignore_cache_response,
    )

    def search_hashes(api_key, prefixes):
        remote_calls.append(tuple(prefixes))
        return (
            [
                {
                    "fullHash": base64.urlsafe_b64encode(target)
                    .decode("ascii")
                    .rstrip("="),
                    "fullHashDetails": [{"threatType": "SOCIAL_ENGINEERING"}],
                }
            ],
            300,
        )

    monkeypatch.setattr(checker._store, "search_hashes", search_hashes)

    assert checker.check_url("http://social.example/") == SafeBrowsingVerdict(
        "safe",
        reason="full hash not returned",
    )
    assert checker.check_url("http://social.example/") == SafeBrowsingVerdict(
        "unsafe", "SOCIAL_ENGINEERING", "se-4b", False, "confirmed by hashes.search"
    )
    assert remote_calls == [(target[:4],), (target[:4],)]


def test_safe_browsing_unselected_cached_threat_does_not_skip_selected_lookup(
    monkeypatch,
) -> None:
    checker = SafeBrowsingLocalChecker(api_key="test")
    target = expression_hashes("http://multi-threat.example/")[0]
    remote_calls = []

    monkeypatch.setattr(checker, "_selected_lists_for_lookup", lambda: ("se-4b",))
    monkeypatch.setattr(
        checker,
        "_local_lists_for_prefix",
        lambda prefix: ("se-4b",) if prefix == target[:4] else (),
    )
    monkeypatch.setattr(
        checker,
        "_cache_lookup",
        lambda _prefix, _full_hashes, local_lists=None: SafeBrowsingVerdict(
            "unsafe",
            "MALWARE",
            "mw-4b",
            True,
            "cached full-hash match",
        ),
    )
    monkeypatch.setattr(
        checker,
        "_cache_search_response",
        _ignore_cache_response,
    )

    def search_hashes(api_key, prefixes):
        remote_calls.append(tuple(prefixes))
        return (
            [
                {
                    "fullHash": base64.urlsafe_b64encode(target)
                    .decode("ascii")
                    .rstrip("="),
                    "fullHashDetails": [
                        {"threatType": "MALWARE"},
                        {"threatType": "SOCIAL_ENGINEERING"},
                    ],
                }
            ],
            300,
        )

    monkeypatch.setattr(checker._store, "search_hashes", search_hashes)

    assert checker.check_url("http://multi-threat.example/") == SafeBrowsingVerdict(
        "unsafe", "SOCIAL_ENGINEERING", "se-4b", False, "confirmed by hashes.search"
    )
    assert remote_calls == [(target[:4],)]


def test_safe_browsing_cached_threat_must_match_local_prefix_list(
    monkeypatch,
) -> None:
    from services import safe_browsing_v5

    checker = SafeBrowsingLocalChecker(
        api_key="test",
        selected_lists=("se-4b", "mw-4b"),
    )
    target = expression_hashes("http://multi-list.example/")[0]
    prefix = target[:4]
    remote_calls = []

    class Result:
        def __init__(self, rows=()) -> None:
            self.rows = list(rows)

        def fetchall(self):
            return self.rows

    class FakeConn:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, sql, params=None):
            if sql.startswith("DELETE FROM"):
                return Result()
            if "safe_browsing_full_hash_cache" in sql:
                assert "list_name IN" in sql
                assert params == (prefix, 100, "se-4b")
                return Result([])
            raise AssertionError(sql)

    monkeypatch.setattr(safe_browsing_v5, "_now", lambda: 100)
    monkeypatch.setattr(
        checker,
        "_local_lists_for_prefix",
        lambda matched_prefix: ("se-4b",) if matched_prefix == prefix else (),
    )
    monkeypatch.setattr(checker, "_connect", FakeConn)
    monkeypatch.setattr(
        checker,
        "_cache_search_response",
        _ignore_cache_response,
    )

    def search_hashes(api_key, prefixes):
        remote_calls.append(tuple(prefixes))
        return (
            [
                {
                    "fullHash": base64.urlsafe_b64encode(target)
                    .decode("ascii")
                    .rstrip("="),
                    "fullHashDetails": [
                        {"threatType": "MALWARE"},
                        {"threatType": "SOCIAL_ENGINEERING"},
                    ],
                }
            ],
            300,
        )

    monkeypatch.setattr(checker._store, "search_hashes", search_hashes)

    assert checker.check_url("http://multi-list.example/") == SafeBrowsingVerdict(
        "unsafe", "SOCIAL_ENGINEERING", "se-4b", False, "confirmed by hashes.search"
    )
    assert remote_calls == [(prefix,)]


def test_safe_browsing_cache_does_not_write_prefix_negative_after_positive_response() -> (
    None
):
    target = b"a" * 32
    prefix = target[:4]
    executed = []

    class FakeConn:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, sql, params=None):
            executed.append((sql, params))

    checker = SafeBrowsingLocalChecker(api_key="test")
    checker._connect = FakeConn
    checker._cache_search_response(
        prefix,
        [
            {
                "fullHash": base64.urlsafe_b64encode(target)
                .decode("ascii")
                .rstrip("="),
                "fullHashDetails": [{"threatType": "MALWARE"}],
            }
        ],
        300,
        local_lists=("se-4b", "mw-4b"),
    )

    full_hash_insert = next(
        params for sql, params in executed if "safe_browsing_full_hash_cache" in sql
    )
    assert full_hash_insert == (
        prefix,
        target,
        "MALWARE",
        "mw-4b",
        full_hash_insert[-1],
    )
    assert any("safe_browsing_full_hash_cache" in sql for sql, _params in executed)
    assert not any("safe_browsing_negative_cache" in sql for sql, _params in executed)


def test_safe_browsing_legacy_negative_cache_does_not_skip_selected_lookup(
    monkeypatch,
) -> None:
    checker = SafeBrowsingLocalChecker(api_key="test", selected_lists=("se-4b",))
    target = expression_hashes("http://social.example/")[0]
    remote_calls = []

    class Result:
        def __init__(self, rows=(), row=None) -> None:
            self.rows = list(rows)
            self.row = row

        def fetchall(self):
            return self.rows

        def fetchone(self):
            return self.row

    class FakeConn:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, sql, params=None):
            if sql.startswith("DELETE FROM"):
                return Result()
            if "safe_browsing_full_hash_cache WHERE prefix" in sql:
                return Result([])
            if "safe_browsing_negative_cache WHERE prefix" in sql:
                return Result(row=(999999,))
            raise AssertionError(sql)

    monkeypatch.setattr(
        checker,
        "_local_lists_for_prefix",
        lambda prefix: ("se-4b",) if prefix == target[:4] else (),
    )
    monkeypatch.setattr(checker, "_connect", FakeConn)
    monkeypatch.setattr(
        checker,
        "_cache_search_response",
        _ignore_cache_response,
    )

    def search_hashes(api_key, prefixes):
        remote_calls.append(tuple(prefixes))
        return (
            [
                {
                    "fullHash": base64.urlsafe_b64encode(target)
                    .decode("ascii")
                    .rstrip("="),
                    "fullHashDetails": [{"threatType": "SOCIAL_ENGINEERING"}],
                }
            ],
            300,
        )

    monkeypatch.setattr(checker._store, "search_hashes", search_hashes)

    assert checker.check_url("http://social.example/") == SafeBrowsingVerdict(
        "unsafe", "SOCIAL_ENGINEERING", "se-4b", False, "confirmed by hashes.search"
    )
    assert remote_calls == [(target[:4],)]


@pytest.mark.parametrize("env_value", ["", "not-an-int"])
def test_safe_browsing_acl_ignores_invalid_log_max_rows_env_for_argparse_help(
    monkeypatch, capsys, env_value
) -> None:
    from tools import safe_browsing_acl

    monkeypatch.setenv("WEBFILTER_LOG_MAX_ROWS", env_value)

    try:
        safe_browsing_acl.main(["--help"])
    except SystemExit as exc:
        assert exc.code == 0
    else:  # pragma: no cover - argparse --help should exit
        raise AssertionError

    assert "--log-max-rows" in capsys.readouterr().out


def test_safe_browsing_helper_logs_threat_category(monkeypatch) -> None:
    from tools import safe_browsing_acl

    assert safe_browsing_acl._parse_line(
        "7 192.0.2.10 bad.example -\n",
    ) == (
        "7",
        "192.0.2.10",
        "bad.example",
    )

    inserted = []
    lifecycle = []

    class FakeLogDb:
        def __init__(self, max_rows) -> None:
            self.max_rows = max_rows

        def start(self) -> None:
            lifecycle.append("start")

        def insert(self, **kwargs) -> None:
            inserted.append(kwargs)

        def close(self) -> bool:
            lifecycle.append("close")
            return True

    checker_selected_lists = []

    class FakeChecker:
        def __init__(self, *, selected_lists=None):
            checker_selected_lists.append(selected_lists)

        def check_url(self, url):
            return SafeBrowsingVerdict(
                "unsafe", "SOCIAL_ENGINEERING", "se-4b", False, "confirmed"
            )

    outputs = []
    monkeypatch.setattr(safe_browsing_acl, "BlockedLogDb", FakeLogDb)
    monkeypatch.setattr(safe_browsing_acl, "SafeBrowsingLocalChecker", FakeChecker)
    monkeypatch.setattr(
        safe_browsing_acl.sys, "stdin", ["192.0.2.10 203.0.113.5 http://bad.example/\n"]
    )
    monkeypatch.setattr(safe_browsing_acl.sys.stdout, "write", outputs.append)
    monkeypatch.setattr(safe_browsing_acl.sys.stdout, "flush", lambda: None)

    assert safe_browsing_acl.main(["--list", "se-4b", "--list", "uwsa-4b"]) == 0
    assert checker_selected_lists == [["se-4b", "uwsa-4b"]]
    assert lifecycle == ["start", "close"]
    assert outputs == ["OK message=category=google-safe-browsing/social-engineering\n"]
    assert inserted[0]["src_ip"] == "192.0.2.10"
    assert inserted[0]["url"] == "http://bad.example/"
    assert inserted[0]["category"] == "google-safe-browsing/social-engineering"


def test_safe_browsing_status_counts_prefixes_and_cache(monkeypatch) -> None:
    class Result:
        def __init__(self, value) -> None:
            self.value = value

        def fetchone(self):
            if isinstance(self.value, dict):
                return self.value
            return (self.value,)

    class FakeConn:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, sql, params=None):
            if "GET_LOCK" in sql:
                return Result({"acquired": 1})
            if "RELEASE_LOCK" in sql:
                return Result({"released": 1})
            if sql.startswith("CREATE TABLE"):
                return Result(0)
            if "information_schema.statistics" in sql:
                return Result(1)
            if "information_schema.columns" in sql:
                return Result(1)
            if "safe_browsing_hash_lists" in sql:
                assert params == ("mw-4b", "se-4b")
                return Result(2)
            if "safe_browsing_hash_prefixes" in sql:
                assert params == ("mw-4b", "se-4b")
                return Result(42)
            if "safe_browsing_full_hash_cache" in sql:
                assert "list_name IN (%s,%s)" in sql
                assert params == (1000, "mw-4b", "se-4b")
                return Result(3)
            if "safe_browsing_negative_cache" in sql:
                assert params == (1000,)
                return Result(5)
            raise AssertionError(sql)

    store = SafeBrowsingStore()
    monkeypatch.setattr(store, "_connect", FakeConn)
    monkeypatch.setattr("services.safe_browsing_v5._now", lambda: 1000)
    settings = SafeBrowsingSettings(
        enabled=True,
        api_key="key",
        lists=("mw-4b", "se-4b"),
        last_success=10,
        last_attempt=9,
        last_error="",
        next_run_ts=20,
    )

    status = store.status(settings)

    assert status.enabled is True
    assert status.configured is True
    assert status.list_count == 2
    assert status.prefix_count == 42
    assert status.positive_cache_entries == 3
    assert status.negative_cache_entries == 5
    assert status.cache_entries == 8


def test_safe_browsing_status_filters_positive_cache_to_selected_lists(
    monkeypatch,
) -> None:
    rows = [
        {"list_name": "mw-4b", "expires_ts": 1000},
        {"list_name": "se-4b", "expires_ts": 1000},
        {"list_name": "uwsa-4b", "expires_ts": 1000},
        {"list_name": "mw-4b", "expires_ts": 999},
        {"list_name": "uws-4b", "expires_ts": 1000},
    ]

    class Result:
        def __init__(self, value) -> None:
            self.value = value

        def fetchone(self):
            if isinstance(self.value, dict):
                return self.value
            return (self.value,)

    class FakeConn:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, sql, params=None):
            if "GET_LOCK" in sql:
                return Result({"acquired": 1})
            if "RELEASE_LOCK" in sql:
                return Result({"released": 1})
            if sql.startswith("CREATE TABLE"):
                return Result(0)
            if "information_schema.statistics" in sql:
                return Result(1)
            if "information_schema.columns" in sql:
                return Result(1)
            if "safe_browsing_hash_lists" in sql:
                assert params == ("mw-4b", "se-4b")
                return Result(2)
            if "safe_browsing_hash_prefixes" in sql:
                assert params == ("mw-4b", "se-4b")
                return Result(42)
            if "safe_browsing_full_hash_cache" in sql:
                assert "list_name IN (%s,%s)" in sql
                assert params == (1000, "mw-4b", "se-4b")
                selected = set(params[1:])
                count = sum(
                    1
                    for row in rows
                    if row["expires_ts"] >= params[0] and row["list_name"] in selected
                )
                return Result(count)
            if "safe_browsing_negative_cache" in sql:
                assert params == (1000,)
                return Result(5)
            raise AssertionError(sql)

    store = SafeBrowsingStore()
    monkeypatch.setattr(store, "_connect", FakeConn)
    monkeypatch.setattr("services.safe_browsing_v5._now", lambda: 1000)
    settings = SafeBrowsingSettings(
        enabled=True,
        api_key="key",
        lists=("mw-4b", "se-4b"),
        last_success=10,
        last_attempt=9,
        last_error="",
        next_run_ts=20,
    )

    status = store.status(settings)

    assert status.positive_cache_entries == 2
    assert status.negative_cache_entries == 5
    assert status.cache_entries == 7


def _urlsafe_test_b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _rice_removals(indices: list[int], *, rice_parameter: int = 3) -> dict[str, object]:
    assert indices == sorted(indices)
    assert indices
    bits: list[int] = []
    for index in range(1, len(indices)):
        delta = indices[index] - indices[index - 1]
        quotient, remainder = divmod(delta, 1 << rice_parameter)
        bits.extend([1] * quotient)
        bits.append(0)
        bits.extend((remainder >> offset) & 1 for offset in range(rice_parameter))
    encoded = bytearray((len(bits) + 7) // 8)
    for index, bit in enumerate(bits):
        encoded[index // 8] |= bit << (index % 8)
    return {
        "firstValue": indices[0],
        "entriesCount": len(indices) - 1,
        "riceParameter": rice_parameter,
        "encodedData": base64.urlsafe_b64encode(encoded).decode("ascii"),
    }


class _HashListResult:
    def __init__(self, rows=(), *, rowcount: int = 0) -> None:
        self.rows = list(rows)
        self.rowcount = rowcount

    def fetchall(self):
        return self.rows

    def fetchone(self):
        return self.rows[0] if self.rows else None


class _TransactionalHashListConn:
    def __init__(self, prefixes: list[bytes], version: bytes = b"v1") -> None:
        self.persisted_prefixes = set(prefixes)
        self.persisted_version = version
        self.prefixes = set(prefixes)
        self.version = version
        self.commit_count = 0
        self.rollback_count = 0
        self.fail_version_write = False

    def __enter__(self):
        self.prefixes = set(self.persisted_prefixes)
        self.version = self.persisted_version
        return self

    def __exit__(self, exc_type, *_args):
        if exc_type is None:
            self.commit()
        else:
            self.rollback()
        return False

    def commit(self) -> None:
        self.persisted_prefixes = set(self.prefixes)
        self.persisted_version = self.version
        self.commit_count += 1

    def rollback(self) -> None:
        self.prefixes = set(self.persisted_prefixes)
        self.version = self.persisted_version
        self.rollback_count += 1

    def execute(self, sql, params=None):
        if sql.startswith("SELECT version"):
            rows = [(self.version,)] if self.version is not None else []
            return _HashListResult(rows)
        if sql.startswith("SELECT prefix"):
            return _HashListResult((prefix,) for prefix in sorted(self.prefixes))
        if sql.startswith("DELETE FROM safe_browsing_hash_prefixes"):
            before = len(self.prefixes)
            if "prefix IN" in sql:
                self.prefixes.difference_update(params[1:])
            elif "generation <>" in sql:
                generation = params[1]
                self.prefixes = {
                    prefix
                    for prefix in self.prefixes
                    if getattr(self, "generations", {}).get(prefix) == generation
                }
            else:
                self.prefixes.clear()
            return _HashListResult(rowcount=before - len(self.prefixes))
        if sql.startswith("DELETE FROM safe_browsing_hash_lists"):
            self.version = None
            return _HashListResult(rowcount=1)
        if sql.startswith("INSERT INTO safe_browsing_hash_lists"):
            if self.fail_version_write:
                msg = "simulated version write failure"
                raise RuntimeError(msg)
            self.version = params[1]
            return _HashListResult(rowcount=1)
        raise AssertionError(sql)

    def executemany(self, sql, params):
        assert sql.startswith("INSERT INTO safe_browsing_hash_prefixes")
        if not hasattr(self, "generations"):
            self.generations = {}
        for _name, prefix, generation in params:
            self.prefixes.add(prefix)
            self.generations[prefix] = generation
        return _HashListResult()


def _run_hash_list_update(monkeypatch, item, prefixes):
    store = SafeBrowsingStore()
    conn = _TransactionalHashListConn(prefixes)
    monkeypatch.setattr(store, "init_db", lambda: None)
    monkeypatch.setattr(store, "init_schema", lambda _conn: None)
    monkeypatch.setattr(store, "_connect", lambda: conn)
    monkeypatch.setattr(
        store,
        "_request_json",
        lambda *_args, **_kwargs: {"hashLists": [item]},
    )
    settings = SafeBrowsingSettings(
        enabled=True,
        api_key="test",
        lists=("mw-4b",),
        last_success=0,
        last_attempt=0,
        last_error="",
        next_run_ts=0,
    )
    result = store.update_lists(settings)
    return result, conn


@pytest.mark.parametrize(
    "compressed_removals",
    [
        pytest.param(_rice_removals([3]), id="past-end"),
    ],
)
def test_safe_browsing_invalid_removal_without_checksum_requires_full_refresh(
    monkeypatch,
    compressed_removals,
) -> None:
    prefixes = [(value).to_bytes(4, "big") for value in (1, 2, 3)]
    (ok, error, wait), conn = _run_hash_list_update(
        monkeypatch,
        {
            "name": "mw-4b",
            "version": _urlsafe_test_b64(b"v2"),
            "partialUpdate": True,
            "compressedRemovals": compressed_removals,
        },
        prefixes,
    )

    assert ok is False
    assert "full refresh required" in error
    assert wait == 1800
    assert conn.persisted_prefixes == set()
    assert conn.persisted_version is None
    assert conn.rollback_count == 1


def test_safe_browsing_duplicate_removal_requires_full_refresh(monkeypatch) -> None:
    prefixes = [(value).to_bytes(4, "big") for value in (1, 2, 3)]
    (ok, error, _wait), conn = _run_hash_list_update(
        monkeypatch,
        {
            "name": "mw-4b",
            "version": _urlsafe_test_b64(b"v2"),
            "partialUpdate": True,
            "compressedRemovals": _rice_removals([1, 1]),
        },
        prefixes,
    )

    assert ok is False
    assert "full refresh required" in error
    assert conn.persisted_prefixes == set()
    assert conn.persisted_version is None


def test_safe_browsing_valid_removals_use_original_sorted_indices(monkeypatch) -> None:
    prefixes = [(value).to_bytes(4, "big") for value in (1, 2, 3, 4)]
    expected = {prefixes[1], prefixes[3]}
    checksum = base64.urlsafe_b64encode(
        _checksum_for_prefixes(sorted(expected))
    ).decode("ascii")
    (ok, error, _wait), conn = _run_hash_list_update(
        monkeypatch,
        {
            "name": "mw-4b",
            "version": _urlsafe_test_b64(b"v2"),
            "partialUpdate": True,
            "compressedRemovals": _rice_removals([0, 2]),
            "sha256Checksum": checksum,
        },
        prefixes,
    )

    assert ok is True
    assert error == ""
    assert conn.persisted_prefixes == expected
    assert conn.persisted_version == b"v2"


def test_safe_browsing_noop_update_may_omit_checksum(monkeypatch) -> None:
    prefixes = [(value).to_bytes(4, "big") for value in (1, 2)]
    (ok, error, _wait), conn = _run_hash_list_update(
        monkeypatch,
        {
            "name": "mw-4b",
            "version": _urlsafe_test_b64(b"v2"),
            "partialUpdate": True,
        },
        prefixes,
    )

    assert ok is True
    assert error == ""
    assert conn.persisted_prefixes == set(prefixes)
    assert conn.persisted_version == b"v2"


def test_safe_browsing_partial_write_failure_rolls_back_list_and_version(
    monkeypatch,
) -> None:
    prefixes = [(value).to_bytes(4, "big") for value in (1, 2, 3)]
    checksum = base64.urlsafe_b64encode(
        _checksum_for_prefixes([prefixes[0], prefixes[2]])
    ).decode("ascii")
    store = SafeBrowsingStore()
    conn = _TransactionalHashListConn(prefixes)
    conn.fail_version_write = True
    monkeypatch.setattr(store, "init_schema", lambda _conn: None)

    with pytest.raises(RuntimeError, match="simulated version write failure"):
        with conn:
            store._apply_hash_list(
                conn,
                {
                    "name": "mw-4b",
                    "version": _urlsafe_test_b64(b"v2"),
                    "partialUpdate": True,
                    "compressedRemovals": _rice_removals([1]),
                    "sha256Checksum": checksum,
                },
            )

    assert conn.persisted_prefixes == set(prefixes)
    assert conn.persisted_version == b"v1"
    assert conn.rollback_count == 1


@pytest.mark.parametrize(
    "compressed_removals",
    [
        pytest.param({"firstValue": -1, "entriesCount": 0}, id="negative"),
        pytest.param(
            {
                "firstValue": 1,
                "entriesCount": 1,
                "riceParameter": 3,
                "encodedData": "",
            },
            id="truncated",
        ),
        pytest.param([1], id="wrong-type"),
    ],
)
def test_safe_browsing_malformed_removal_does_not_mutate(
    monkeypatch,
    compressed_removals,
) -> None:
    prefixes = [(value).to_bytes(4, "big") for value in (1, 2, 3)]
    (ok, error, _wait), conn = _run_hash_list_update(
        monkeypatch,
        {
            "name": "mw-4b",
            "version": _urlsafe_test_b64(b"v2"),
            "partialUpdate": True,
            "compressedRemovals": compressed_removals,
        },
        prefixes,
    )

    assert ok is False
    assert error
    assert conn.persisted_prefixes == set(prefixes)
    assert conn.persisted_version == b"v1"
    assert conn.rollback_count == 1


@pytest.mark.parametrize(
    ("field", "value"),
    [
        pytest.param("sha256Checksum", "@@", id="checksum-malformed-base64"),
        pytest.param("sha256Checksum", "AA", id="checksum-wrong-length"),
        pytest.param("version", "A", id="version"),
    ],
)
def test_safe_browsing_malformed_hash_list_byte_field_does_not_mutate(
    monkeypatch,
    field,
    value,
) -> None:
    prefixes = [(number).to_bytes(4, "big") for number in (1, 2, 3)]
    item = {
        "name": "mw-4b",
        "version": _urlsafe_test_b64(b"v2"),
        "partialUpdate": True,
        "compressedRemovals": _rice_removals([1]),
        "sha256Checksum": _urlsafe_test_b64(
            _checksum_for_prefixes([prefixes[0], prefixes[2]])
        ),
    }
    item[field] = value

    (ok, error, _wait), conn = _run_hash_list_update(monkeypatch, item, prefixes)

    assert ok is False
    assert field in error
    assert conn.persisted_prefixes == set(prefixes)
    assert conn.persisted_version == b"v1"
    assert conn.rollback_count == 1


def test_safe_browsing_apply_hash_list_rejects_checksum_mismatch() -> None:
    class Result:
        def __init__(self, rows=()) -> None:
            self.rows = list(rows)

        def fetchall(self):
            return self.rows

        def fetchone(self):
            return self.rows[0] if self.rows else None

    class FakeConn:
        def __init__(self) -> None:
            self.sql = []

        def execute(self, sql, params=None):
            self.sql.append((sql, params))
            if sql.startswith("SELECT prefix"):
                return Result([])
            return Result([])

        def executemany(self, sql, params):
            self.sql.append((sql, tuple(params)))
            return Result([])

    store = SafeBrowsingStore()
    conn = FakeConn()
    bad_checksum = base64.urlsafe_b64encode(b"x" * 32).decode("ascii").rstrip("=")
    try:
        store._apply_hash_list(
            conn,
            {
                "name": "mw-4b",
                "version": "AA",
                "partialUpdate": False,
                "additionsFourBytes": {"firstValue": 1, "entriesCount": 0},
                "sha256Checksum": bad_checksum,
            },
        )
    except ValueError as exc:
        assert "checksum mismatch" in str(exc)
    else:
        msg = "checksum mismatch should fail"
        raise AssertionError(msg)
    assert any(
        "DELETE FROM safe_browsing_hash_lists" in sql for sql, _params in conn.sql
    )


def test_safe_browsing_apply_hash_list_accepts_matching_checksum() -> None:
    class Result:
        def __init__(self, rows=()) -> None:
            self.rows = list(rows)

        def fetchall(self):
            return self.rows

        def fetchone(self):
            return self.rows[0] if self.rows else None

    class FakeConn:
        def __init__(self) -> None:
            self.inserted = []

        def execute(self, sql, params=None):
            if sql.startswith("SELECT prefix"):
                return Result([])
            return Result([])

        def executemany(self, sql, params):
            self.inserted.extend(params)
            return Result([])

    store = SafeBrowsingStore()
    prefix = (1).to_bytes(4, "big")
    checksum = (
        base64.urlsafe_b64encode(_checksum_for_prefixes([prefix]))
        .decode("ascii")
        .rstrip("=")
    )
    conn = FakeConn()
    store._apply_hash_list(
        conn,
        {
            "name": "mw-4b",
            "version": "AA",
            "partialUpdate": False,
            "additionsFourBytes": {"firstValue": 1, "entriesCount": 0},
            "sha256Checksum": checksum,
        },
    )
    assert len(conn.inserted) == 1
    assert conn.inserted[0][:2] == ("mw-4b", prefix)
    assert isinstance(conn.inserted[0][2], int)


@pytest.mark.parametrize(
    "additions",
    [
        pytest.param(
            {"firstValue": 1, "entriesCount": 1, "riceParameter": 3, "encodedData": ""},
            id="truncated",
        ),
        pytest.param({"firstValue": True, "entriesCount": 0}, id="boolean"),
        pytest.param({"firstValue": 1 << 32, "entriesCount": 0}, id="overflow"),
    ],
)
def test_safe_browsing_apply_rejects_invalid_additions_before_mutation(
    additions,
) -> None:
    class Result:
        def __init__(self, rows=()) -> None:
            self.rows = list(rows)

        def fetchall(self):
            return self.rows

        def fetchone(self):
            return self.rows[0] if self.rows else None

    class FakeConn:
        def __init__(self) -> None:
            self.executed = []
            self.inserted = []

        def execute(self, sql, params=None):
            self.executed.append((sql, params))
            if sql.startswith("SELECT prefix"):
                return Result([])
            return Result([])

        def executemany(self, sql, params):
            self.inserted.extend(params)
            return Result([])

    conn = FakeConn()
    with pytest.raises(ValueError, match="compressed Rice"):
        SafeBrowsingStore()._apply_hash_list(
            conn,
            {
                "name": "mw-4b",
                "version": "AA",
                "partialUpdate": False,
                "additionsFourBytes": additions,
            },
        )

    assert conn.inserted == []
    assert not any(
        "INSERT INTO safe_browsing_hash_lists" in sql for sql, _params in conn.executed
    )
    assert not any(
        sql.startswith("DELETE FROM safe_browsing_hash_prefixes")
        for sql, _params in conn.executed
    )


def test_safe_browsing_ignores_canary_full_hash_detail(monkeypatch) -> None:
    checker = SafeBrowsingLocalChecker(api_key="test")
    target = expression_hashes("http://bad.example/")[0]
    monkeypatch.setattr(
        checker,
        "_local_lists_for_prefix",
        lambda prefix: ("mw-4b",) if prefix == target[:4] else (),
    )
    monkeypatch.setattr(
        checker, "_cache_lookup", lambda prefix, full_hashes, local_lists=None: None
    )
    monkeypatch.setattr(checker, "_cache_search_response", _ignore_cache_response)
    monkeypatch.setattr(
        checker._store,
        "search_hashes",
        lambda api_key, prefixes: (
            [
                {
                    "fullHash": base64.urlsafe_b64encode(target)
                    .decode("ascii")
                    .rstrip("="),
                    "fullHashDetails": [
                        {"threatType": "MALWARE", "attributes": ["CANARY"]}
                    ],
                }
            ],
            300,
        ),
    )
    assert checker.check_url("http://bad.example/").verdict == "safe"


def _batch_update_settings(
    lists: tuple[str, ...] = ("mw-4b",),
) -> SafeBrowsingSettings:
    return SafeBrowsingSettings(
        enabled=True,
        api_key="key",
        lists=lists,
        last_success=0,
        last_attempt=0,
        last_error="",
        next_run_ts=0,
    )


class _BatchUpdateConn:
    def __init__(self, versions: dict[str, bytes] | None = None) -> None:
        self.versions = versions or {}
        self.persisted_applied: list[str] = []
        self.applied: list[str] = []

    def __enter__(self):
        self.applied = list(self.persisted_applied)
        return self

    def __exit__(self, exc_type, *_args):
        if exc_type is None:
            self.persisted_applied = list(self.applied)
        else:
            self.applied = list(self.persisted_applied)
        return False

    def execute(self, sql, params=None):
        assert sql.startswith("SELECT version")
        version = self.versions.get(params[0])
        return _HashListResult([(version,)] if version else [])


def _run_batch_response(monkeypatch, response, *, lists=("mw-4b",), versions=None):
    store = SafeBrowsingStore()
    conn = _BatchUpdateConn(versions)
    request_calls = []
    monkeypatch.setattr(store, "init_db", lambda: None)
    monkeypatch.setattr(store, "_connect", lambda: conn)

    def fake_request_json(path, api_key, params, timeout):
        request_calls.append((path, api_key, params, timeout))
        return response

    def fake_apply(active_conn, item):
        active_conn.applied.append(item["name"])

    monkeypatch.setattr(store, "_request_json", fake_request_json)
    monkeypatch.setattr(store, "_apply_hash_list", fake_apply)
    result = store.update_lists(_batch_update_settings(lists))
    return result, conn, request_calls


@pytest.mark.parametrize(
    ("response", "error_fragment"),
    [
        pytest.param([], "object", id="non-object-response"),
        pytest.param({}, "hashLists", id="missing-array"),
        pytest.param({"hashLists": {}}, "hashLists", id="non-array"),
        pytest.param({"hashLists": [None]}, "object", id="null-entry"),
        pytest.param({"hashLists": ["mw-4b"]}, "object", id="string-entry"),
        pytest.param({"hashLists": [{}]}, "name", id="missing-name"),
        pytest.param(
            {"hashLists": [{"name": 42}]},
            "name",
            id="non-string-name",
        ),
    ],
)
def test_safe_browsing_update_lists_rejects_malformed_batch_without_mutation(
    monkeypatch,
    response,
    error_fragment,
) -> None:
    (ok, error, wait), conn, _calls = _run_batch_response(monkeypatch, response)

    assert ok is False
    assert error_fragment in error
    assert wait == 1800
    assert conn.persisted_applied == []


@pytest.mark.parametrize(
    ("response_names", "error_fragment"),
    [
        pytest.param(["mw-4b"], "requested", id="missing"),
        pytest.param(
            ["mw-4b", "mw-4b", "se-4b"],
            "duplicate",
            id="duplicate",
        ),
        pytest.param(
            ["mw-4b", "uws-4b"],
            "unexpected",
            id="unexpected",
        ),
        pytest.param(
            ["se-4b", "mw-4b"],
            "order",
            id="out-of-order",
        ),
    ],
)
def test_safe_browsing_update_lists_rejects_invalid_batch_names_atomically(
    monkeypatch,
    response_names,
    error_fragment,
) -> None:
    response = {"hashLists": [{"name": name} for name in response_names]}
    (ok, error, wait), conn, _calls = _run_batch_response(
        monkeypatch,
        response,
        lists=("mw-4b", "se-4b"),
    )

    assert ok is False
    assert error_fragment in error
    assert wait == 1800
    assert conn.persisted_applied == []


def test_safe_browsing_update_lists_applies_valid_batch_and_pairs_versions(
    monkeypatch,
) -> None:
    response = {
        "hashLists": [
            {"name": "se-4b", "minimumWaitDuration": "7200s"},
            {"name": "mw-4b", "minimumWaitDuration": "1800s"},
            {"name": "uws-4b", "minimumWaitDuration": "3600s"},
        ],
    }
    (ok, error, wait), conn, calls = _run_batch_response(
        monkeypatch,
        response,
        lists=("se-4b", "mw-4b", "uws-4b"),
        versions={"se-4b": b"se-v1", "uws-4b": b"uws-v3"},
    )

    assert (ok, error, wait) == (True, "", 7200)
    assert conn.persisted_applied == ["se-4b", "mw-4b", "uws-4b"]
    assert calls == [
        (
            "/hashLists:batchGet",
            "key",
            [
                ("names", "se-4b"),
                ("names", "mw-4b"),
                ("names", "uws-4b"),
                ("version", _urlsafe_test_b64(b"se-v1")),
                ("version", _urlsafe_test_b64(b"uws-v3")),
            ],
            120,
        ),
    ]


def test_safe_browsing_update_lists_uses_immediate_wait_only_when_all_lists_allow_it(
    monkeypatch,
) -> None:
    response = {
        "hashLists": [
            {"name": "se-4b", "minimumWaitDuration": "0s"},
            {"name": "mw-4b"},
            {"name": "uws-4b", "minimumWaitDuration": "3600s"},
        ],
    }
    (ok, error, wait), conn, _calls = _run_batch_response(
        monkeypatch,
        response,
        lists=("se-4b", "mw-4b", "uws-4b"),
    )

    assert (ok, error, wait) == (True, "", 3600)
    assert conn.persisted_applied == ["se-4b", "mw-4b", "uws-4b"]


def test_safe_browsing_update_lists_preserves_immediate_multi_list_refresh(
    monkeypatch,
) -> None:
    response = {
        "hashLists": [
            {"name": "se-4b", "minimumWaitDuration": "0s"},
            {"name": "mw-4b"},
        ],
    }
    result, _conn, _calls = _run_batch_response(
        monkeypatch,
        response,
        lists=("se-4b", "mw-4b"),
    )

    assert result == (True, "", 0)


def test_safe_browsing_update_lists_rejects_duplicate_requested_names(
    monkeypatch,
) -> None:
    (ok, error, wait), conn, calls = _run_batch_response(
        monkeypatch,
        {"hashLists": []},
        lists=("mw-4b", "mw-4b"),
    )

    assert ok is False
    assert "duplicate" in error
    assert wait == 1800
    assert conn.persisted_applied == []
    assert calls == []


def test_safe_browsing_update_lists_releases_db_before_network_fetch(
    monkeypatch,
) -> None:
    closed_before_request: list[bool] = []
    events: list[str] = []

    class FakeResult:
        def __init__(self, row=None):
            self._row = row

        def fetchone(self):
            return self._row

    class FakeConn:
        def __enter__(self):
            events.append("enter")
            return self

        def __exit__(self, *_args):
            events.append("exit")
            return False

        def execute(self, *_args, **_kwargs):
            return FakeResult(("v1",))

    store = SafeBrowsingStore()
    monkeypatch.setattr(store, "init_db", lambda: None)
    monkeypatch.setattr(store, "_connect", FakeConn)
    monkeypatch.setattr(
        store, "_apply_hash_list", lambda _conn, _item: events.append("apply")
    )

    def fake_request_json(*_args, **_kwargs):
        closed_before_request.append(events == ["enter", "exit"])
        return {"hashLists": [{"name": "mw-4b", "minimumWaitDuration": "3600s"}]}

    monkeypatch.setattr(store, "_request_json", fake_request_json)

    ok, err, wait = store.update_lists(
        SafeBrowsingSettings(
            enabled=True,
            api_key="key",
            lists=("mw-4b",),
            last_success=0,
            last_attempt=0,
            last_error="",
            next_run_ts=0,
        ),
    )

    assert ok is True
    assert err == ""
    assert wait == 3600
    assert closed_before_request == [True]
    assert events == ["enter", "exit", "enter", "apply", "exit"]


def test_safe_browsing_updater_retries_failed_status_write_without_refetching(
    monkeypatch,
) -> None:
    state = {
        "last_success": 900,
        "last_attempt": 0,
        "last_error": "",
        "next_run_ts": 0,
    }
    provider_calls: list[int] = []
    status_calls: list[tuple[bool, str, int]] = []
    failed_final_write = False

    class StatusDatabaseUnavailableError(RuntimeError):
        pass

    class StopLoopError(Exception):
        pass

    def get_settings() -> SafeBrowsingSettings:
        return SafeBrowsingSettings(
            enabled=True,
            api_key="key",
            lists=("mw-4b",),
            **state,
        )

    def set_status(ok: bool, error: str, next_run_ts: int) -> None:
        nonlocal failed_final_write
        status_calls.append((ok, error, next_run_ts))
        if error == "malformed provider response" and not failed_final_write:
            failed_final_write = True
            raise StatusDatabaseUnavailableError
        state["last_attempt"] = 1000
        if ok:
            state["last_success"] = 1000
            state["last_error"] = ""
        else:
            state["last_error"] = error
        state["next_run_ts"] = next_run_ts

    store = SafeBrowsingStore()

    def update_lists(_settings):
        provider_calls.append(1)
        return False, "malformed provider response", 1800

    sleeps = 0

    def stop_after_retry(_seconds: float) -> None:
        nonlocal sleeps
        sleeps += 1
        if sleeps == 2:
            raise StopLoopError

    monkeypatch.setattr(store, "update_lists", update_lists)
    monkeypatch.setattr(safe_browsing_v5, "_now", lambda: 1000)
    monkeypatch.setattr(store._stop_event, "wait", stop_after_retry)

    with pytest.raises(StopLoopError):
        store._loop(get_settings, set_status)

    assert provider_calls == [1]
    assert status_calls == [
        (False, "", 2800),
        (False, "malformed provider response", 2800),
        (False, "malformed provider response", 2800),
    ]
    assert state == {
        "last_success": 900,
        "last_attempt": 1000,
        "last_error": "malformed provider response",
        "next_run_ts": 2800,
    }


def test_safe_browsing_updater_reports_success_only_after_update(
    monkeypatch,
) -> None:
    store = SafeBrowsingStore()
    status_calls: list[tuple[bool, str, int]] = []
    monkeypatch.setattr(store, "update_lists", lambda _settings: (True, "", 7200))
    monkeypatch.setattr(safe_browsing_v5, "_now", lambda: 1000)

    store._run_updater_once(
        _batch_update_settings, lambda *args: status_calls.append(args)
    )

    assert status_calls == [
        (False, "", 2800),
        (True, "", 8200),
    ]


def test_safe_browsing_updater_reports_unexpected_provider_failure(
    monkeypatch,
) -> None:
    store = SafeBrowsingStore()
    settings = _batch_update_settings()
    status_calls: list[tuple[bool, str, int]] = []

    class UnexpectedProviderError(ValueError):
        pass

    class StopLoopError(Exception):
        pass

    def fail_provider(_settings):
        raise UnexpectedProviderError

    monkeypatch.setattr(store, "update_lists", fail_provider)
    monkeypatch.setattr(safe_browsing_v5, "_now", lambda: 1000)
    monkeypatch.setattr(
        store._stop_event,
        "wait",
        lambda _seconds: (_ for _ in ()).throw(StopLoopError),
    )

    with pytest.raises(StopLoopError):
        store._loop(lambda: settings, lambda *args: status_calls.append(args))

    assert status_calls == [
        (False, "", 2800),
        (False, "Google Safe Browsing list update failed.", 2800),
    ]


def test_safe_browsing_update_lists_redacts_api_key_from_url_errors(
    monkeypatch,
) -> None:
    class FakeResult:
        def fetchone(self):
            return None

    class FakeConn:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, *_args, **_kwargs):
            return FakeResult()

    store = SafeBrowsingStore()
    monkeypatch.setattr(store, "init_db", lambda: None)
    monkeypatch.setattr(store, "_connect", FakeConn)

    class UrlError(ValueError):
        def __str__(self) -> str:
            return (
                "urlopen failed: "
                "https://safebrowsing.googleapis.com/v5/hashes:search?key=AIzaSECRET"
                "&hashPrefixes=abcd"
            )

    def fake_request_json(*_args, **_kwargs):
        raise UrlError

    monkeypatch.setattr(store, "_request_json", fake_request_json)

    ok, err, wait = store.update_lists(
        SafeBrowsingSettings(
            enabled=True,
            api_key="AIzaSECRET",
            lists=(),
            last_success=0,
            last_attempt=0,
            last_error="",
            next_run_ts=0,
        ),
    )

    assert ok is False
    assert wait == 1800
    assert "AIzaSECRET" not in err
    assert "safebrowsing.googleapis.com/v5/hashes:search" in err
    assert "?key=[redacted]" in err
    assert "&hashPrefixes=abcd" in err


def test_safe_browsing_enforces_android_unwanted_software(monkeypatch) -> None:
    checker = SafeBrowsingLocalChecker(api_key="test", selected_lists=("uwsa-4b",))
    target = expression_hashes("http://bad-android.example/")[0]
    monkeypatch.setattr(
        checker,
        "_local_lists_for_prefix",
        lambda prefix: ("uwsa-4b",) if prefix == target[:4] else (),
    )
    monkeypatch.setattr(
        checker, "_cache_lookup", lambda prefix, full_hashes, local_lists=None: None
    )
    monkeypatch.setattr(
        checker,
        "_cache_search_response",
        _ignore_cache_response,
    )
    monkeypatch.setattr(
        checker._store,
        "search_hashes",
        lambda api_key, prefixes: (
            [
                {
                    "fullHash": base64.urlsafe_b64encode(target)
                    .decode("ascii")
                    .rstrip("="),
                    "fullHashDetails": [{"threatType": "UNWANTED_SOFTWARE_ANDROID"}],
                }
            ],
            300,
        ),
    )

    verdict = checker.check_url("http://bad-android.example/")

    assert verdict == SafeBrowsingVerdict(
        "unsafe",
        "UNWANTED_SOFTWARE_ANDROID",
        "uwsa-4b",
        False,
        "confirmed by hashes.search",
    )


def test_safe_browsing_provider_cache_duration_is_preserved_without_floor_or_cap(
    monkeypatch,
) -> None:
    checker = SafeBrowsingLocalChecker(api_key="test")
    executed = []

    class Conn:
        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def execute(self, sql, params=()):
            executed.append((" ".join(str(sql).split()), tuple(params)))

    monkeypatch.setattr(checker, "_connect", Conn)
    monkeypatch.setattr(safe_browsing_v5, "_now", lambda: 100)
    full_hash = b"abcd" + (b"x" * 28)
    response = [
        {
            "fullHash": base64.urlsafe_b64encode(full_hash).decode().rstrip("="),
            "fullHashDetails": [{"threatType": "MALWARE"}],
        }
    ]

    checker._cache_search_response(b"abcd", response, 0, ("mw-4b",))
    checker._cache_search_response(b"abcd", response, 172800, ("mw-4b",))

    inserts = [params for sql, params in executed if sql.startswith("INSERT INTO")]
    assert [params[-1] for params in inserts] == [100, 172900]


def test_safe_browsing_remote_verdict_cache_does_not_outlive_provider_ttl(
    monkeypatch,
) -> None:
    checker = SafeBrowsingLocalChecker(api_key="test", selected_lists=("mw-4b",))
    target = expression_hashes("http://short-lived.example/")[0]
    now = [100.0]
    remote_calls = []
    monkeypatch.setattr(safe_browsing_v5.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(checker, "_synchronize_local_cache_versions", lambda _lists: 0)
    monkeypatch.setattr(
        checker,
        "_local_lists_for_prefix",
        lambda prefix: ("mw-4b",) if prefix == target[:4] else (),
    )
    monkeypatch.setattr(checker, "_cache_lookup", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(checker, "_cache_search_response", _ignore_cache_response)

    def search_hashes(_api_key, prefixes):
        remote_calls.append(tuple(prefixes))
        return (
            [
                {
                    "fullHash": base64.urlsafe_b64encode(target).decode().rstrip("="),
                    "fullHashDetails": [{"threatType": "MALWARE"}],
                }
            ],
            1,
        )

    monkeypatch.setattr(checker._store, "search_hashes", search_hashes)

    assert checker.check_url("http://short-lived.example/").verdict == "unsafe"
    now[0] = 100.5
    assert checker.check_url("http://short-lived.example/").verdict == "unsafe"
    now[0] = 101.1
    assert checker.check_url("http://short-lived.example/").verdict == "unsafe"
    assert len(remote_calls) == 2


def test_safe_browsing_cache_lookup_treats_exact_expiry_as_expired(monkeypatch) -> None:
    checker = SafeBrowsingLocalChecker(api_key="test", selected_lists=("mw-4b",))
    queries = []

    class Result:
        def fetchall(self):
            return []

    class Conn:
        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def execute(self, sql, params=()):
            queries.append((" ".join(str(sql).split()), tuple(params)))
            return Result()

    monkeypatch.setattr(checker, "_connect", Conn)
    monkeypatch.setattr(safe_browsing_v5, "_now", lambda: 100)

    assert checker._cache_lookup(b"abcd", set(), ("mw-4b",)) is None
    assert "expires_ts > %s" in queries[0][0]
    assert queries[0][1][1] == 100


def test_safe_browsing_cache_lookup_does_not_delete_expired_rows(monkeypatch) -> None:
    checker = SafeBrowsingLocalChecker(api_key="test", selected_lists=("mw-4b",))
    prefix = b"abcd"
    full_hash = prefix + (b"x" * 28)
    queries: list[str] = []

    class Result:
        def fetchall(self):
            return [(full_hash, "MALWARE", "mw-4b")]

    class Conn:
        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def execute(self, sql, params=()):
            queries.append(" ".join(str(sql).split()))
            return Result()

    monkeypatch.setattr(checker, "_connect", Conn)

    verdict = checker._cache_lookup(prefix, {full_hash}, ("mw-4b",))

    assert verdict == SafeBrowsingVerdict(
        "unsafe",
        "MALWARE",
        "mw-4b",
        True,
        "cached full-hash match",
    )
    assert queries
    assert all(not query.upper().startswith("DELETE ") for query in queries)


def test_safe_browsing_hash_list_replacement_marks_generation_before_prune(
    monkeypatch,
) -> None:
    from services import safe_browsing_v5

    class Result:
        def __init__(self, rows=(), rowcount=0) -> None:
            self._rows = list(rows)
            self.rowcount = rowcount

        def fetchall(self):
            return self._rows

        def fetchone(self):
            return self._rows[0] if self._rows else None

    class FakeConn:
        def __init__(self) -> None:
            self.executed = []
            self.executemany_calls = []

        def execute(self, sql, params=None):
            normalized = " ".join(str(sql).split())
            self.executed.append((normalized, tuple(params or ())))
            if (
                "FROM safe_browsing_hash_prefixes WHERE list_name=%s ORDER BY prefix"
                in normalized
            ):
                return Result(rows=[(b"zzzz",)])
            if normalized.startswith("DELETE FROM safe_browsing_hash_prefixes"):
                return Result(rowcount=1)
            return Result()

        def executemany(self, sql, params):
            normalized = " ".join(str(sql).split())
            rows = list(params or [])
            self.executemany_calls.append((normalized, rows))
            return Result(rowcount=len(rows))

    monkeypatch.setattr(safe_browsing_v5.time, "time_ns", lambda: 123456789)
    conn = FakeConn()
    item = {
        "name": "mw-4b",
        "additionsFourBytes": {"firstValue": 0x01020304, "entriesCount": 0},
        "version": "AQID",
    }

    SafeBrowsingStore()._apply_hash_list(conn, item)

    insert_sql, rows = conn.executemany_calls[-1]
    assert "generation" in insert_sql
    assert rows == [("mw-4b", b"\x01\x02\x03\x04", 123456789)]
    delete_sql, delete_params = next(
        (sql, params)
        for sql, params in conn.executed
        if sql.startswith("DELETE FROM safe_browsing_hash_prefixes")
        and "generation <>" in sql
    )
    assert "ORDER BY prefix ASC LIMIT" in delete_sql
    assert delete_params == ("mw-4b", 123456789, 5000)
