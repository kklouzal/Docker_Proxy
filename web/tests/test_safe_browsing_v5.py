import base64
import hashlib
from typing import NoReturn

import pytest
from services.safe_browsing_v5 import (
    SafeBrowsingLocalChecker,
    SafeBrowsingSettings,
    SafeBrowsingStore,
    SafeBrowsingVerdict,
    _checksum_for_prefixes,
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


def test_safe_browsing_canonicalization_preserves_encoded_fragment_marker_in_path() -> None:
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


def test_safe_browsing_hashes_are_sha256_expression_hashes() -> None:
    expressions = url_expressions("example.com/")
    hashes = expression_hashes("example.com/")
    assert hashlib.sha256(expressions[0].encode("utf-8")).digest() in hashes
    assert all(len(item) == 32 for item in hashes)


def test_safe_browsing_rice_decoder_handles_single_value() -> None:
    assert decode_rice_delta_32({"firstValue": 0x01020304, "entriesCount": 0}) == [
        0x01020304
    ]


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


def test_safe_browsing_request_json_reports_response_size_limit(monkeypatch) -> None:
    from services import safe_browsing_v5

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
    monkeypatch.setattr(safe_browsing_v5.urllib.request, "urlopen", fake_urlopen)

    try:
        SafeBrowsingStore()._request_json("/hashLists:batchGet", "key", [])
    except ValueError as exc:
        assert "SAFE_BROWSING_MAX_RESPONSE_BYTES (1024 bytes)" in str(exc)
    else:
        msg = "oversized Safe Browsing responses should fail with a clear error"
        raise AssertionError(msg)


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

    class FakeLogDb:
        def __init__(self, max_rows) -> None:
            self.max_rows = max_rows

        def start(self) -> None:
            pass

        def insert(self, **kwargs) -> None:
            inserted.append(kwargs)

    checker_selected_lists = []

    class FakeChecker:
        def __init__(self, *, selected_lists=None):
            checker_selected_lists.append(selected_lists)

        def check_url(self, url):
            return SafeBrowsingVerdict(
                "unsafe", "SOCIAL_ENGINEERING", "se-4b", False, "confirmed"
            )

    outputs = []
    monkeypatch.setattr(safe_browsing_acl, "_BlockedLogDb", FakeLogDb)
    monkeypatch.setattr(safe_browsing_acl, "SafeBrowsingLocalChecker", FakeChecker)
    monkeypatch.setattr(
        safe_browsing_acl.sys, "stdin", ["192.0.2.10 203.0.113.5 http://bad.example/\n"]
    )
    monkeypatch.setattr(safe_browsing_acl.sys.stdout, "write", outputs.append)
    monkeypatch.setattr(safe_browsing_acl.sys.stdout, "flush", lambda: None)

    assert safe_browsing_acl.main(["--list", "se-4b", "--list", "uwsa-4b"]) == 0
    assert checker_selected_lists == [["se-4b", "uwsa-4b"]]
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
                return Result(3)
            if "safe_browsing_negative_cache" in sql:
                return Result(5)
            raise AssertionError(sql)

    store = SafeBrowsingStore()
    monkeypatch.setattr(store, "_connect", FakeConn)
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
    assert all(not query.upper().startswith('DELETE ') for query in queries)


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
            if "FROM safe_browsing_hash_prefixes WHERE list_name=%s ORDER BY prefix" in normalized:
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
