import os
import sys
import unittest


def _import_candidate():
    # Ensure we import from web/icap_server.py
    web_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if web_dir not in sys.path:
        sys.path.insert(0, web_dir)

    try:
        from adblockparser import AdblockRules  # noqa: F401
    except Exception as e:
        raise unittest.SkipTest(f"adblockparser not available: {e}")

    from icap_server import (  # type: ignore
        _CandidateMatcher,
        _RuleEntry,
        _MAX_TOKENS_PER_RULE,
        _extract_rule_keys,
    )
    return AdblockRules, _CandidateMatcher, _RuleEntry, _extract_rule_keys, _MAX_TOKENS_PER_RULE


class TestCandidateMatcher(unittest.TestCase):
    def test_exception_overrides_across_lists(self):
        AdblockRules, CandidateMatcher, RuleEntry, extract_rule_keys, max_tokens = _import_candidate()

        # Block in list A, exception in list B should allow.
        list_a = AdblockRules(["||ads.example.com^"])
        list_b = AdblockRules(["@@||ads.example.com^"])

        entries = []
        for key, ruleset in [("A", list_a), ("B", list_b)]:
            for rule in ruleset.rules:
                host_cand, token_cand = extract_rule_keys(rule)
                host_keys = tuple(sorted(host_cand)[:2])
                token_keys = tuple(sorted(token_cand)[:max_tokens])
                tp_opt = rule.options.get("third-party") if hasattr(rule, "options") else None
                entries.append(
                    RuleEntry(
                        order=len(entries),
                        list_key=key,
                        rule=rule,
                        is_exception=bool(getattr(rule, "is_exception", False)),
                        host_keys=host_keys,
                        token_keys=token_keys,
                        third_party_opt=(None if tp_opt is None else bool(tp_opt)),
                    )
                )

        m = CandidateMatcher(entries)
        url = "https://ads.example.com/banner.js"
        self.assertIsNone(m.match(url, document_host="example.com", third_party=True))

    def test_block_returns_list_key(self):
        AdblockRules, CandidateMatcher, RuleEntry, extract_rule_keys, max_tokens = _import_candidate()

        list_a = AdblockRules(["||ads.example.com^"])
        entries = []
        for rule in list_a.rules:
            host_cand, token_cand = extract_rule_keys(rule)
            host_keys = tuple(sorted(host_cand)[:2])
            token_keys = tuple(sorted(token_cand)[:max_tokens])
            entries.append(
                RuleEntry(
                    order=len(entries),
                    list_key="A",
                    rule=rule,
                    is_exception=bool(getattr(rule, "is_exception", False)),
                    host_keys=host_keys,
                    token_keys=token_keys,
                    third_party_opt=None,
                )
            )

        m = CandidateMatcher(entries)
        url = "https://ads.example.com/banner.js"
        self.assertEqual(m.match(url, document_host="example.com", third_party=True), "A")

    def test_third_party_option_prunes(self):
        AdblockRules, CandidateMatcher, RuleEntry, extract_rule_keys, max_tokens = _import_candidate()

        list_a = AdblockRules(["||tracker.example^$third-party"])
        entries = []
        for rule in list_a.rules:
            host_cand, token_cand = extract_rule_keys(rule)
            host_keys = tuple(sorted(host_cand)[:2])
            token_keys = tuple(sorted(token_cand)[:max_tokens])
            tp_opt = rule.options.get("third-party") if hasattr(rule, "options") else None
            entries.append(
                RuleEntry(
                    order=len(entries),
                    list_key="A",
                    rule=rule,
                    is_exception=False,
                    host_keys=host_keys,
                    token_keys=token_keys,
                    third_party_opt=(None if tp_opt is None else bool(tp_opt)),
                )
            )

        m = CandidateMatcher(entries)
        url = "https://tracker.example/pixel"
        # Should not match for first-party when third_party=False.
        self.assertIsNone(m.match(url, document_host="tracker.example", third_party=False))
        # Should match for third-party.
        self.assertEqual(m.match(url, document_host="example.com", third_party=True), "A")


if __name__ == "__main__":
    unittest.main()
