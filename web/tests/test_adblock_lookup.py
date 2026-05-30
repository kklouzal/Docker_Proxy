from __future__ import annotations

import json
import sqlite3
import sys
from contextlib import ExitStack
from pathlib import Path
from typing import Any


def _add_web_to_path() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    web_root = repo_root / "web"
    for path in (str(repo_root), str(web_root)):
        if path not in sys.path:
            sys.path.insert(0, path)


def _build_lookup_db(tmp_path: Path, lines: list[str]) -> Path:
    _add_web_to_path()
    from tools import adblock_compile as ac  # type: ignore

    out = tmp_path / "compiled"
    out.mkdir()

    class Writers:
        pass

    paths = {
        "network_jsonl": out / "network_rules.jsonl",
        "cosmetic_jsonl": out / "cosmetic_rules.jsonl",
        "network_no_options_jsonl": out / "network_no_options.jsonl",
        "network_with_options_jsonl": out / "network_with_options.jsonl",
        "network_option_domain_jsonl": out / "network_option_domain.jsonl",
        "network_option_third_party_jsonl": out / "network_option_third_party.jsonl",
        "network_option_type_jsonl": out / "network_option_type.jsonl",
        "network_option_misc_jsonl": out / "network_option_misc.jsonl",
        "network_kind_domain_only_jsonl": out / "network_kind_domain_only.jsonl",
        "network_kind_host_anchored_jsonl": out / "network_kind_host_anchored.jsonl",
        "network_kind_left_anchored_jsonl": out / "network_kind_left_anchored.jsonl",
        "network_kind_substring_jsonl": out / "network_kind_substring.jsonl",
        "network_kind_wildcard_jsonl": out / "network_kind_wildcard.jsonl",
        "network_kind_regex_jsonl": out / "network_kind_regex.jsonl",
        "network_block_jsonl": out / "network_block.jsonl",
        "network_exception_jsonl": out / "network_exception.jsonl",
        "request_index_domain_jsonl": out / "request_index_domain.jsonl",
        "request_index_host_jsonl": out / "request_index_host.jsonl",
        "request_index_regex_jsonl": out / "request_index_regex.jsonl",
        "request_index_generic_jsonl": out / "request_index_generic.jsonl",
        "cosmetic_elemhide_jsonl": out / "cosmetic_elemhide.jsonl",
        "cosmetic_elemhide_exception_jsonl": out / "cosmetic_elemhide_exception.jsonl",
        "cosmetic_extended_css_jsonl": out / "cosmetic_extended_css.jsonl",
        "cosmetic_extended_css_exception_jsonl": out
        / "cosmetic_extended_css_exception.jsonl",
        "cosmetic_html_filter_jsonl": out / "cosmetic_html_filter.jsonl",
        "cosmetic_html_filter_exception_jsonl": out
        / "cosmetic_html_filter_exception.jsonl",
        "cosmetic_scriptlet_jsonl": out / "cosmetic_scriptlet.jsonl",
        "cosmetic_scriptlet_exception_jsonl": out
        / "cosmetic_scriptlet_exception.jsonl",
        "cosmetic_scoped_jsonl": out / "cosmetic_scoped.jsonl",
        "cosmetic_global_jsonl": out / "cosmetic_global.jsonl",
        "cosmetic_exception_jsonl": out / "cosmetic_exception.jsonl",
        "cosmetic_non_exception_jsonl": out / "cosmetic_non_exception.jsonl",
    }
    agg = ac._Aggregate(
        network_rules_total=0,
        network_rules_by_kind={},
        network_rules_with_options=0,
        network_rules_with_domain_opt=0,
        cosmetic_rules_total=0,
        cosmetic_rules_by_marker={},
        option_key_counts={},
        option_group_counts={},
    )
    with ExitStack() as stack:
        writers = Writers()
        for name, path in paths.items():
            setattr(
                writers,
                name,
                stack.enter_context(path.open("w", encoding="utf-8", newline="\n")),
            )
        writers.network_type_pos_jsonl = {
            item: stack.enter_context(
                (out / f"network_type_{item}.jsonl").open(
                    "w",
                    encoding="utf-8",
                    newline="\n",
                ),
            )
            for item in ac._KNOWN_TYPES
        }
        writers.network_type_neg_jsonl = {
            item: stack.enter_context(
                (out / f"network_type_not_{item}.jsonl").open(
                    "w",
                    encoding="utf-8",
                    newline="\n",
                ),
            )
            for item in ac._KNOWN_TYPES
        }
        ac._compile_and_extract_all(
            lines=lines,
            list_key="sample",
            agg=agg,
            writers=writers,
        )

    db_path = out / "request_lookup.sqlite"
    ac._write_request_lookup_index(str(db_path), str(out / "network_rules.jsonl"))
    return db_path


def _raws(rules: list[dict[str, Any]]) -> set[str]:
    return {str(rule["raw"]) for rule in rules}


def test_adblock_lookup_index_returns_indexed_url_candidates(tmp_path: Path) -> None:
    db_path = _build_lookup_db(
        tmp_path,
        [
            "||ads.example^",
            "@@||allow.example^",
            "||cdn.example.com/assets/ad.js^$script",
            "||*.example.net/ad^",
            "wss://loader.*.com/ws^$websocket,third-party",
            "/tracker[.]example/$third-party",
            "plain-ad-token$~stylesheet",
        ],
    )

    _add_web_to_path()
    from services.adblock_lookup import AdblockLookupIndex

    lookup = AdblockLookupIndex(db_path)

    assert "||ads.example^" in _raws(
        lookup.candidate_rules("https://sub.ads.example/banner.js")
    )
    assert "||ads.example^" in _raws(
        lookup.candidate_rules("https://user:pass@sub.ads.example/banner.js")
    )
    script_candidates = _raws(
        lookup.candidate_rules(
            "https://cdn.example.com/assets/ad.js?slot=1",
            resource_type="script",
        )
    )
    assert "||cdn.example.com/assets/ad.js^$script" in script_candidates
    wildcard_host_candidates = _raws(
        lookup.candidate_rules("https://sub.example.net/ad.js")
    )
    assert "||*.example.net/ad^" in wildcard_host_candidates

    negated_script_candidates = _raws(
        lookup.candidate_rules(
            "https://static.example/plain-ad-token.js",
            resource_type="script",
        )
    )
    assert "plain-ad-token$~stylesheet" in negated_script_candidates
    negated_stylesheet_candidates = _raws(
        lookup.candidate_rules(
            "https://static.example/plain-ad-token.css",
            resource_type="stylesheet",
        )
    )
    assert "plain-ad-token$~stylesheet" not in negated_stylesheet_candidates

    websocket_candidates = _raws(
        lookup.candidate_rules(
            "wss://loader.foo.com/ws",
            resource_type="websocket",
        )
    )
    assert "wss://loader.*.com/ws^$websocket,third-party" in websocket_candidates

    generic_candidates = _raws(
        lookup.candidate_rules("https://static.example/plain-ad-token.js")
    )
    assert "plain-ad-token$~stylesheet" in generic_candidates
    assert "/tracker[.]example/$third-party" not in generic_candidates

    regex_candidates = _raws(
        lookup.candidate_rules("https://cdn.example/tracker.example/pixel")
    )
    assert "/tracker[.]example/$third-party" in regex_candidates


def test_lookup_hydrates_payload_from_jsonl_for_legacy_sqlite_schema(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "request_lookup.sqlite"
    conn = sqlite3.connect(str(db_path))
    try:
        conn.executescript(
            """
            CREATE TABLE rules(
                rule_id TEXT PRIMARY KEY,
                list_key TEXT NOT NULL,
                action TEXT NOT NULL,
                exception INTEGER NOT NULL,
                pattern_kind TEXT NOT NULL,
                raw TEXT NOT NULL,
                pattern TEXT NOT NULL,
                options_json TEXT NOT NULL,
                resource_types_json TEXT NOT NULL,
                excluded_resource_types_json TEXT NOT NULL,
                third_party TEXT NOT NULL,
                behavior_options_json TEXT NOT NULL,
                value_options_json TEXT NOT NULL
            ) WITHOUT ROWID;
            CREATE TABLE domain_index(
                host TEXT NOT NULL,
                action TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                PRIMARY KEY(host, action, rule_id)
            ) WITHOUT ROWID;
            CREATE TABLE host_index(host TEXT, action TEXT, rule_id TEXT);
            CREATE TABLE host_pattern_index(host_pattern TEXT, action TEXT, rule_id TEXT);
            CREATE TABLE regex_index(action TEXT, rule_id TEXT, regex TEXT);
            CREATE TABLE generic_index(literal_key TEXT, pattern_kind TEXT, action TEXT, rule_id TEXT);
            """
        )
        assert not conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='resource_type_index'"
        ).fetchone()
        conn.execute(
            "INSERT INTO rules VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "r1",
                "sample",
                "block",
                0,
                "domain_only",
                "||ads.example^",
                "||ads.example^",
                "{}",
                "[]",
                "[]",
                "any",
                "[]",
                "{}",
            ),
        )
        conn.execute(
            "INSERT INTO domain_index VALUES(?,?,?)", ("ads.example", "block", "r1")
        )
        conn.commit()
    finally:
        conn.close()
    (tmp_path / "network_rules.jsonl").write_text(
        json.dumps(
            {
                "id": "r1",
                "list_key": "sample",
                "action": "block",
                "exception": False,
                "raw": "||ads.example^",
                "pattern": "||ads.example^",
                "pattern_kind": "domain_only",
                "host": "ads.example",
            },
        )
        + "\n",
        encoding="utf-8",
    )

    _add_web_to_path()
    from services.adblock_lookup import AdblockLookupIndex

    lookup = AdblockLookupIndex(db_path)

    rules = lookup.candidate_rules(
        "https://sub.ads.example/banner.js",
        resource_type="script",
    )

    assert rules[0]["host"] == "ads.example"
    assert rules[0]["raw"] == "||ads.example^"
