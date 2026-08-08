from __future__ import annotations

import json
import sqlite3
import sys
import threading
from contextlib import ExitStack
from pathlib import Path
from typing import Any

import pytest


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


def test_adblock_lookup_close_waits_for_in_flight_candidate_query(
    tmp_path: Path,
) -> None:
    db_path = _build_lookup_db(tmp_path, ["||ads.example^"])

    _add_web_to_path()
    from services.adblock_lookup import AdblockLookupIndex

    index = AdblockLookupIndex(db_path)
    query_entered = threading.Event()
    release_query = threading.Event()
    close_started = threading.Event()
    close_done = threading.Event()
    original_candidate_rule_ids = index._candidate_rule_ids
    result: list[dict[str, Any]] = []

    def blocked_candidate_rule_ids(
        conn: sqlite3.Connection,
        url: str,
        *,
        resource_type: str = "",
    ) -> set[str]:
        query_entered.set()
        assert release_query.wait(timeout=2.0)
        return original_candidate_rule_ids(
            conn,
            url,
            resource_type=resource_type,
        )

    def query() -> None:
        result.extend(index.candidate_rules("https://ads.example/banner.js"))

    def close() -> None:
        close_started.set()
        index.close()
        close_done.set()

    index._candidate_rule_ids = blocked_candidate_rule_ids  # type: ignore[method-assign]
    query_thread = threading.Thread(target=query)
    close_thread = threading.Thread(target=close)
    query_thread.start()
    assert query_entered.wait(timeout=2.0)
    close_thread.start()
    assert close_started.wait(timeout=2.0)
    assert close_done.wait(timeout=0.1) is False

    release_query.set()
    query_thread.join(timeout=2.0)
    close_thread.join(timeout=2.0)

    assert query_thread.is_alive() is False
    assert close_thread.is_alive() is False
    assert _raws(result) == {"||ads.example^"}
    index.close()
    with pytest.raises(RuntimeError, match="lookup index is closed"):
        index.candidate_rules("https://ads.example/banner.js")


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


def test_lookup_returns_domain_anchored_wildcard_host_subdomain_candidates(
    tmp_path: Path,
) -> None:
    db_path = _build_lookup_db(
        tmp_path,
        ["||google.*/pagead/lvz?$script"],
    )

    _add_web_to_path()
    from services.adblock_lookup import AdblockLookupIndex

    lookup = AdblockLookupIndex(db_path)

    candidates = _raws(
        lookup.candidate_rules(
            "https://www.google.com/pagead/lvz?slot=1",
            resource_type="script",
        ),
    )

    assert "||google.*/pagead/lvz?$script" in candidates


def test_token_prefilters_preserve_host_pattern_and_regex_candidate_superset(
    tmp_path: Path,
) -> None:
    db_path = _build_lookup_db(
        tmp_path,
        [
            "||ad*server.example^",
            "/tracker*/",
            "/tracker.*/",
            "/tracker[.]example/",
        ],
    )

    _add_web_to_path()
    from services.adblock_lookup import AdblockLookupIndex

    urls = [
        "https://adXYZserver.example/banner.js",
        "https://static.example/tracke",
        "https://static.example/trackerxyz",
        "https://static.example/tracker.example/pixel",
    ]
    indexed_lookup = AdblockLookupIndex(db_path)
    indexed_candidates = {
        url: _raws(indexed_lookup.candidate_rules(url)) for url in urls
    }

    conn = sqlite3.connect(str(db_path))
    try:
        conn.executescript(
            """
            DELETE FROM host_pattern_token_index;
            DELETE FROM regex_token_index;
            """,
        )
        conn.commit()
    finally:
        conn.close()

    missing_rows_lookup = AdblockLookupIndex(db_path)
    missing_rows_candidates = {
        url: _raws(missing_rows_lookup.candidate_rules(url)) for url in urls
    }

    conn = sqlite3.connect(str(db_path))
    try:
        conn.executescript(
            """
            DROP TABLE host_pattern_token_index;
            DROP TABLE regex_token_index;
            """,
        )
        conn.commit()
    finally:
        conn.close()

    unfiltered_lookup = AdblockLookupIndex(db_path)
    unfiltered_candidates = {
        url: _raws(unfiltered_lookup.candidate_rules(url)) for url in urls
    }

    assert indexed_candidates == missing_rows_candidates == unfiltered_candidates
    assert "||ad*server.example^" in indexed_candidates[urls[0]]
    assert "/tracker*/" in indexed_candidates[urls[1]]
    assert "/tracker.*/" in indexed_candidates[urls[2]]
    assert "/tracker[.]example/" in indexed_candidates[urls[3]]


def test_adblock_lookup_rejects_malformed_authority_candidates(
    tmp_path: Path,
) -> None:
    db_path = _build_lookup_db(
        tmp_path,
        ["||ads.example^", "||safe.example^", "||[2001:db8::20]^"],
    )

    _add_web_to_path()
    from services.adblock_lookup import AdblockLookupIndex

    lookup = AdblockLookupIndex(db_path)

    assert _raws(lookup.candidate_rules("http://[::1")) == set()
    assert _raws(lookup.candidate_rules("https://ads.example:bad/banner.js")) == set()
    assert _raws(lookup.candidate_rules("https://ads.example:99999/banner.js")) == set()
    assert _raws(
        lookup.candidate_rules(r"https://safe.example\@ads.example/banner.js")
    ) == set()
    assert _raws(
        lookup.candidate_rules(r"https://safe.example\.ads.example/banner.js")
    ) == set()
    assert _raws(lookup.candidate_rules(r"https://ads.example\path/banner.js")) == set()
    assert _raws(lookup.candidate_rules("https://ads.example\n.evil/banner.js")) == set()
    assert _raws(
        lookup.candidate_rules("https://safe.example%2f.ads.example/banner.js")
    ) == set()
    assert "||ads.example^" in _raws(
        lookup.candidate_rules("https://user:pass@sub.ads.example/banner.js")
    )
    assert "||[2001:db8::20]^" in _raws(
        lookup.candidate_rules("https://[2001:db8::20]/banner.js")
    )


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
        for rule_id, pattern_kind, raw in (
            ("r2", "host_anchored", "||cdn.example/assets^"),
            ("r3", "host_anchored_pattern", "||google.*/pagead^"),
        ):
            conn.execute(
                "INSERT INTO rules VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    rule_id,
                    "sample",
                    "block",
                    0,
                    pattern_kind,
                    raw,
                    raw,
                    "{}",
                    "[]",
                    "[]",
                    "any",
                    "[]",
                    "{}",
                ),
            )
        conn.execute(
            "INSERT INTO host_index VALUES(?,?,?)",
            ("cdn.example", "block", "r2"),
        )
        conn.execute(
            "INSERT INTO host_pattern_index VALUES(?,?,?)",
            ("google.*", "block", "r3"),
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
        + "\n"
        + json.dumps(
            {
                "id": "r2",
                "list_key": "sample",
                "action": "block",
                "exception": False,
                "raw": "||cdn.example/assets^",
                "pattern": "||cdn.example/assets^",
                "pattern_kind": "host_anchored",
                "host": "cdn.example",
            },
        )
        + "\n"
        + json.dumps(
            {
                "id": "r3",
                "list_key": "sample",
                "action": "block",
                "exception": False,
                "raw": "||google.*/pagead^",
                "pattern": "||google.*/pagead^",
                "pattern_kind": "host_anchored_pattern",
                "host_pattern": "google.*",
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
    assert "||cdn.example/assets^" in _raws(
        lookup.candidate_rules("https://sub.cdn.example/assets/banner.js"),
    )
    assert "||google.*/pagead^" in _raws(
        lookup.candidate_rules("https://www.google.com/pagead/banner.js"),
    )


def test_lookup_uses_jsonl_payload_when_embedded_payload_is_incomplete(
    tmp_path: Path,
) -> None:
    db_path = _build_lookup_db(tmp_path, ["||ads.example^$script"])
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("UPDATE rules SET payload_json='{}'")
        conn.commit()
    finally:
        conn.close()

    _add_web_to_path()
    from services.adblock_lookup import AdblockLookupIndex

    lookup = AdblockLookupIndex(db_path)
    [rule] = lookup.candidate_rules(
        "https://ads.example/banner.js",
        resource_type="script",
    )

    assert rule["host"] == "ads.example"
    assert rule["raw"] == "||ads.example^$script"


def test_lookup_ignores_malformed_resource_type_prefilter_schema(
    tmp_path: Path,
) -> None:
    db_path = _build_lookup_db(tmp_path, ["resource-token$script"])
    conn = sqlite3.connect(str(db_path))
    try:
        conn.executescript(
            """
            DROP TABLE resource_type_index;
            CREATE TABLE resource_type_index(rule_id TEXT);
            """,
        )
        conn.commit()
    finally:
        conn.close()

    _add_web_to_path()
    from services.adblock_lookup import AdblockLookupIndex

    lookup = AdblockLookupIndex(db_path)

    assert "resource-token$script" in _raws(
        lookup.candidate_rules(
            "https://static.example/resource-token.png",
            resource_type="image",
        ),
    )


def test_adblock_lookup_chunks_large_sqlite_in_queries(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = _build_lookup_db(
        tmp_path,
        [f"sharedtoken/path{index}" for index in range(8)],
    )

    _add_web_to_path()
    import services.adblock_lookup as lookup_module

    monkeypatch.setattr(lookup_module, "_SQLITE_IN_CHUNK_SIZE", 3)
    lookup = lookup_module.AdblockLookupIndex(db_path)

    rules = lookup.candidate_rules("https://static.example/sharedtoken/path3")

    assert "sharedtoken/path3" in _raws(rules)
    assert len(rules) == 8
