import base64
import hashlib

from services.safe_browsing_v5 import (
    SafeBrowsingLocalChecker,
    SafeBrowsingVerdict,
    canonicalize_url,
    decode_rice_delta_32,
    expression_hashes,
    url_expressions,
)


def test_safe_browsing_url_expressions_include_host_suffix_path_prefixes():
    expressions = url_expressions("HTTPS://Sub.Example.COM/a/b/c?x=1#frag")
    assert "sub.example.com/a/b/c?x=1" in expressions
    assert "example.com/" in expressions
    assert all("#" not in expr for expr in expressions)


def test_safe_browsing_hashes_are_sha256_expression_hashes():
    expressions = url_expressions("example.com/")
    hashes = expression_hashes("example.com/")
    assert hashlib.sha256(expressions[0].encode("utf-8")).digest() in hashes
    assert all(len(item) == 32 for item in hashes)


def test_safe_browsing_rice_decoder_handles_single_value():
    assert decode_rice_delta_32({"firstValue": 0x01020304, "entriesCount": 0}) == [0x01020304]


def test_safe_browsing_checker_does_not_call_remote_without_local_prefix(monkeypatch):
    checker = SafeBrowsingLocalChecker(api_key="test")
    monkeypatch.setattr(checker, "_local_lists_for_prefix", lambda prefix: ())

    def fail_remote(*args, **kwargs):
        raise AssertionError("remote hashes.search should not run without a local prefix hit")

    monkeypatch.setattr(checker._store, "search_hashes", fail_remote)
    verdict = checker.check_url("http://clean.example/")
    assert verdict.verdict == "safe"
    assert verdict.reason == "no local hash-prefix match"


def test_safe_browsing_checker_confirms_full_hash_after_local_prefix(monkeypatch):
    checker = SafeBrowsingLocalChecker(api_key="test")
    hashes = expression_hashes("http://bad.example/")
    target = hashes[0]
    monkeypatch.setattr(checker, "_local_lists_for_prefix", lambda prefix: ("mw-4b",) if prefix == target[:4] else ())
    monkeypatch.setattr(checker, "_cache_lookup", lambda prefix, full_hashes: None)
    monkeypatch.setattr(checker, "_cache_search_response", lambda prefix, response, cache_duration: None)
    monkeypatch.setattr(
        checker._store,
        "search_hashes",
        lambda api_key, prefixes: ([{"fullHash": base64.urlsafe_b64encode(target).decode("ascii").rstrip("="), "fullHashDetails": [{"threatType": "MALWARE"}]}], 300),
    )
    verdict = checker.check_url("http://bad.example/")
    assert verdict == SafeBrowsingVerdict("unsafe", "MALWARE", "mw-4b", False, "confirmed by hashes.search")


def test_safe_browsing_helper_logs_threat_category(monkeypatch):
    from tools import safe_browsing_acl

    inserted = []

    class FakeLogDb:
        def __init__(self, max_rows):
            self.max_rows = max_rows

        def start(self):
            pass

        def insert(self, **kwargs):
            inserted.append(kwargs)

    class FakeChecker:
        def check_url(self, url):
            return SafeBrowsingVerdict("unsafe", "SOCIAL_ENGINEERING", "se-4b", False, "confirmed")

    outputs = []
    monkeypatch.setattr(safe_browsing_acl, "_BlockedLogDb", FakeLogDb)
    monkeypatch.setattr(safe_browsing_acl, "SafeBrowsingLocalChecker", lambda: FakeChecker())
    monkeypatch.setattr(safe_browsing_acl.sys, "stdin", ["192.0.2.10 203.0.113.5 http://bad.example/\n"])
    monkeypatch.setattr(safe_browsing_acl.sys.stdout, "write", lambda value: outputs.append(value))
    monkeypatch.setattr(safe_browsing_acl.sys.stdout, "flush", lambda: None)

    assert safe_browsing_acl.main([]) == 0
    assert outputs == ["OK\n"]
    assert inserted[0]["category"] == "google-safe-browsing/social-engineering"
