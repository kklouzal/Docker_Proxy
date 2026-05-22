import base64
import hashlib
from typing import NoReturn

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
    monkeypatch.setattr(checker, "_cache_lookup", lambda prefix, full_hashes: None)
    monkeypatch.setattr(
        checker, "_cache_search_response", lambda prefix, response, cache_duration: None
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

    def cache_lookup(prefix, full_hashes):
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
        lambda prefix, response, cache_duration: None,
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


def test_safe_browsing_helper_logs_threat_category(monkeypatch) -> None:
    from tools import safe_browsing_acl

    inserted = []

    class FakeLogDb:
        def __init__(self, max_rows) -> None:
            self.max_rows = max_rows

        def start(self) -> None:
            pass

        def insert(self, **kwargs) -> None:
            inserted.append(kwargs)

    class FakeChecker:
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

    assert safe_browsing_acl.main([]) == 0
    assert outputs == ["OK\n"]
    assert inserted[0]["src_ip"] == "192.0.2.10"
    assert inserted[0]["url"] == "http://bad.example/"
    assert inserted[0]["category"] == "google-safe-browsing/social-engineering"


def test_safe_browsing_status_counts_prefixes_and_cache(monkeypatch) -> None:
    class Result:
        def __init__(self, value) -> None:
            self.value = value

        def fetchone(self):
            return (self.value,)

    class FakeConn:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, sql, params=None):
            if sql.startswith("CREATE TABLE"):
                return Result(0)
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
    assert conn.inserted == [("mw-4b", prefix)]


def test_safe_browsing_ignores_canary_full_hash_detail(monkeypatch) -> None:
    checker = SafeBrowsingLocalChecker(api_key="test")
    target = expression_hashes("http://bad.example/")[0]
    monkeypatch.setattr(
        checker,
        "_local_lists_for_prefix",
        lambda prefix: ("mw-4b",) if prefix == target[:4] else (),
    )
    monkeypatch.setattr(checker, "_cache_lookup", lambda prefix, full_hashes: None)
    monkeypatch.setattr(
        checker, "_cache_search_response", lambda prefix, response, cache_duration: None
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
                    "fullHashDetails": [
                        {"threatType": "MALWARE", "attributes": ["CANARY"]}
                    ],
                }
            ],
            300,
        ),
    )
    assert checker.check_url("http://bad.example/").verdict == "safe"


def test_safe_browsing_update_lists_releases_db_before_network_fetch(monkeypatch) -> None:
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
    monkeypatch.setattr(store, "_apply_hash_list", lambda _conn, _item: events.append("apply"))

    def fake_request_json(*_args, **_kwargs):
        closed_before_request.append(events == ["enter", "exit"])
        return {"hashLists": [{"name": "mw-4b", "minimumWaitDuration": "3600s"}]}

    monkeypatch.setattr(store, "_request_json", fake_request_json)

    ok, err, wait = store.update_lists(
        SafeBrowsingSettings(enabled=True, api_key="key", lists=("mw-4b",), last_success=0, last_attempt=0, last_error="", next_run_ts=0),
    )

    assert ok is True
    assert err == ""
    assert wait == 3600
    assert closed_before_request == [True]
    assert events == ["enter", "exit", "enter", "apply", "exit"]
