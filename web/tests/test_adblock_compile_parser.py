from __future__ import annotations

import json
import re
import sqlite3
import sys
from pathlib import Path
from typing import Any

from .subprocess_test_utils import run_test_process


def _compile_sample(tmp_path: Path, lines: list[str]) -> Path:
    """Compile ``lines`` as list "sample"; return the lookup database path."""
    from tools import adblock_compile as ac  # type: ignore

    out = tmp_path / "compiled"
    out.mkdir()
    db_path = out / "request_lookup.sqlite"
    ac._write_request_lookup_index(str(db_path), [("sample", lines)], ac._Aggregate())
    return db_path


def _parsed_rules(lines: list[str]) -> list[dict[str, Any]]:
    """Return the normalized network records the compiler parses from ``lines``."""
    from tools import adblock_compile as ac  # type: ignore

    records: list[dict[str, Any]] = []
    ac._compile_and_extract_all(
        lines=lines,
        list_key="sample",
        agg=ac._Aggregate(),
        add_network_rule=records.append,
    )
    return records


_INDEXED_RULES_SQL = {
    "domain_index": (
        "SELECT r.raw FROM rules r JOIN (SELECT DISTINCT rule_id FROM "
        "domain_index) i ON i.rule_id = r.rule_id ORDER BY r.raw"
    ),
    "generic_index": (
        "SELECT r.raw FROM rules r JOIN (SELECT DISTINCT rule_id FROM "
        "generic_index) i ON i.rule_id = r.rule_id ORDER BY r.raw"
    ),
}


def _indexed_raws(db_path: Path, table: str) -> list[str]:
    """Return the raw text of the rules that ``table`` indexes."""
    conn = sqlite3.connect(str(db_path))
    try:
        return [row[0] for row in conn.execute(_INDEXED_RULES_SQL[table])]
    finally:
        conn.close()


_HOST_KINDS = {
    "absolute_url",
    "absolute_url_pattern",
    "host_anchored",
    "host_anchored_pattern",
}


def _of_kind(records: list[dict[str, Any]], *kinds: str) -> list[dict[str, Any]]:
    return [rule for rule in records if rule["pattern_kind"] in kinds]


def _generic(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        rule
        for rule in records
        if rule["pattern_kind"] not in {*_HOST_KINDS, "domain_only", "regex", "empty"}
    ]


def _domain_index_hosts(db_path: Path) -> set[str]:
    conn = sqlite3.connect(str(db_path))
    try:
        return {row[0] for row in conn.execute("SELECT host FROM domain_index")}
    finally:
        conn.close()


def test_main_compiles_explicit_enabled_lists_without_database_state(
    tmp_path: Path,
) -> None:
    from tools import adblock_compile as ac  # type: ignore

    lists = tmp_path / "lists"
    out = tmp_path / "compiled"
    lists.mkdir()
    (lists / "easylist.txt").write_text("||ads.example^\n", encoding="utf-8")
    (lists / "disabled.txt").write_text("||disabled.example^\n", encoding="utf-8")

    rc = ac.main(
        [
            "--lists-dir",
            str(lists),
            "--out-dir",
            str(out),
            "--enabled-list",
            "easylist",
        ],
    )

    assert rc == 0
    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert report["enabled_lists"] == ["easylist"]
    assert report["files"] == {"request_lookup_sqlite": "request_lookup.sqlite"}
    # Only the runtime lookup is written: no diagnostic buckets.
    assert sorted(path.name for path in out.iterdir()) == [
        "report.json",
        "request_lookup.sqlite",
    ]
    assert _domain_index_hosts(out / "request_lookup.sqlite") == {"ads.example"}


def test_main_fails_when_explicit_list_is_missing(tmp_path: Path) -> None:
    from tools import adblock_compile as ac  # type: ignore

    lists = tmp_path / "lists"
    out = tmp_path / "compiled"
    lists.mkdir()

    rc = ac.main(
        ["--lists-dir", str(lists), "--out-dir", str(out), "--enabled-list", "gone"],
    )

    assert rc == 1
    assert not (out / "report.json").exists()
    assert not (out / "request_lookup.sqlite").exists()


def test_main_fails_when_enabled_list_catalog_is_unreadable(
    tmp_path: Path, monkeypatch
) -> None:
    from services import adblock_store  # type: ignore
    from tools import adblock_compile as ac  # type: ignore

    class UnreadableStore:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def init_db(self) -> None:
            return None

        def list_statuses(self) -> list[object]:
            msg = "statuses read failed"
            raise RuntimeError(msg)

    monkeypatch.setattr(adblock_store, "AdblockStore", UnreadableStore)
    out = tmp_path / "compiled"

    rc = ac.main(["--lists-dir", str(tmp_path / "lists"), "--out-dir", str(out)])

    assert rc == 1
    assert not (out / "request_lookup.sqlite").exists()


def test_script_entrypoint_compiles_explicit_enabled_lists_without_pythonpath(
    tmp_path: Path,
) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    script = repo_root / "web" / "tools" / "adblock_compile.py"
    lists = tmp_path / "lists"
    out = tmp_path / "compiled"
    lists.mkdir()
    (lists / "easylist.txt").write_text("||script-entry.example^\n", encoding="utf-8")

    result = run_test_process(
        [
            sys.executable,
            str(script),
            "--lists-dir",
            str(lists),
            "--out-dir",
            str(out),
            "--enabled-list",
            "easylist",
        ],
        check=False,
        capture_output=True,
        env={},
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert _domain_index_hosts(out / "request_lookup.sqlite") == {
        "script-entry.example"
    }


def test_abp_regex_options_split_after_closing_delimiter() -> None:
    from tools import adblock_compile as ac  # type: ignore

    rule = (
        r"/^https?:\/\/s3\.*\.amazonaws\.com\/[a-f0-9]{45,}"
        r"\/[a-f,0-9]{8,10}$/$script,third-party,xmlhttprequest,"
        r"domain=~amazon.com"
    )

    pattern, options = ac._split_options(rule)

    assert pattern.endswith("$/")
    assert options == "script,third-party,xmlhttprequest,domain=~amazon.com"
    tokens, parsed = ac._parse_options(options)
    assert tokens[0] == "script"
    assert "/$script" not in parsed
    assert ")/$script" not in parsed
    assert parsed["domain"] == ["~amazon.com"]


def test_abp_options_split_ignores_escaped_literal_dollars() -> None:
    from tools import adblock_compile as ac  # type: ignore

    assert ac._split_options(r"plain\$literal") == (r"plain\$literal", "")
    assert ac._split_options(r"||shop.example/path\$price^$script") == (
        r"||shop.example/path\$price^",
        "script",
    )
    assert ac._split_options(r"||shop.example/path\\$script") == (
        r"||shop.example/path\\",
        "script",
    )


def test_abp_regex_compilation_honors_escaped_pattern_metacharacters() -> None:
    from services.adblock_patterns import abp_suffix_to_regex, abp_to_regex

    wildcard_regex = abp_to_regex(r"ad\*token")
    assert re.search(wildcard_regex, "https://static.example/ad*token.js")
    assert not re.search(wildcard_regex, "https://static.example/adXYZtoken.js")

    separator_regex = abp_to_regex(r"ad\^token")
    assert re.search(separator_regex, "https://static.example/ad^token.js")
    assert not re.search(separator_regex, "https://static.example/ad/token.js")

    right_anchor_regex = abp_to_regex(r"ad\|")
    assert re.search(right_anchor_regex, "https://static.example/ad|")
    assert not re.search(right_anchor_regex, "https://static.example/ad")

    assert re.search(abp_to_regex("ad*token"), "https://static.example/adXYZtoken.js")
    assert re.search(abp_to_regex("ad^token"), "https://static.example/ad/token.js")
    assert re.search(abp_to_regex("ad|"), "https://static.example/ad")
    assert re.match(abp_suffix_to_regex("|"), "")
    assert not re.match(abp_suffix_to_regex("|"), "/")


def test_network_rules_emit_normalized_request_indexes() -> None:
    records = _parsed_rules(
        [
            (
                r"/^https?:\/\/s3\.*\.amazonaws\.com\/[a-f0-9]{45,}"
                r"\/[a-f,0-9]{8,10}$/$script,third-party,xmlhttprequest,"
                r"domain=~amazon.com"
            ),
            "@@||youtube.com/get_video_info?$xmlhttprequest,domain=music.youtube.com|tv.youtube.com",
            "||example.com/ad/path|$script,~third-party",
            "||port.example:8443/ad/path|",
            "|https://left.example/ad^$image",
            "wss://loader.*.com/ws^$websocket,third-party",
            "ads.js|",
            r"price\$literal",
            r"||shop.example/path\$price^$script",
            "plain-ad-token$~stylesheet",
            "||ads.example^$third-party",
        ],
    )

    regex_rules = _of_kind(records, "regex")
    assert len(regex_rules) == 1
    regex_rule = regex_rules[0]
    assert regex_rule["pattern_kind"] == "regex"
    assert regex_rule["resource_types"] == ["script", "xmlhttprequest"]
    assert regex_rule["third_party"] == "only"
    assert regex_rule["domain_excludes"] == ["amazon.com"]
    assert "/$script" not in regex_rule["options"]

    host_rules = _of_kind(records, "host_anchored")
    by_host = {rule["host"]: rule for rule in host_rules}
    assert by_host["example.com"]["suffix"] == "/ad/path|"
    assert by_host["example.com"]["compiled_regex"].endswith(r"/ad/path$")
    assert by_host["example.com"]["resource_types"] == ["script"]
    assert by_host["example.com"]["third_party"] == "exclude"
    assert by_host["port.example"]["suffix"] == ":8443/ad/path|"
    assert ":8443/ad/path$" in by_host["port.example"]["compiled_regex"]
    assert by_host["youtube.com"]["action"] == "allow"
    assert by_host["youtube.com"]["domain_includes"] == [
        "music.youtube.com",
        "tv.youtube.com",
    ]
    assert by_host["shop.example"]["suffix"] == r"/path\$price^"
    assert by_host["shop.example"]["resource_types"] == ["script"]
    by_raw = {rule["raw"]: rule for rule in records}
    left = by_raw["|https://left.example/ad^$image"]
    assert left["pattern_kind"] == "absolute_url"
    assert re.search(left["compiled_regex"], "https://left.example/ad?x")
    assert not re.search(left["compiled_regex"], "http://x/?https://left.example/ad")
    absolute_pattern = by_raw["wss://loader.*.com/ws^$websocket,third-party"]
    assert absolute_pattern["pattern_kind"] == "absolute_url_pattern"
    assert re.search(absolute_pattern["compiled_regex"], "wss://loader.cdn.com/ws")
    assert absolute_pattern["resource_types"] == ["websocket"]
    assert absolute_pattern["third_party"] == "only"

    domain_rules = _of_kind(records, "domain_only")
    assert any(
        rule["host"] == "ads.example" and rule["third_party"] == "only"
        for rule in domain_rules
    )

    generic_rules = _generic(records)
    assert {rule["pattern_kind"] for rule in generic_rules} == {
        "right_anchored",
        "substring",
    }
    assert any(rule["pattern"] == r"price\$literal" for rule in generic_rules)
    assert any(
        rule["excluded_resource_types"] == ["stylesheet"] for rule in generic_rules
    )


def test_request_lookup_sqlite_indexes_fast_candidate_shapes(tmp_path: Path) -> None:
    from tools import adblock_compile as ac  # type: ignore

    lines = [
        "||ads.example^",
        "@@||allow.example^",
        "||example.com/ad/path|$script,~third-party",
        "wss://loader.*.com/ws^$websocket,third-party",
        "/tracker[.]example/$third-party",
        "plain-ad-token$~stylesheet",
        "$popup,third-party,domain=example.com",
        "badfilter-target",
        "badfilter-target$badfilter",
    ]
    db_path = tmp_path / "request_lookup.sqlite"
    _per_list, counts = ac._write_request_lookup_index(
        str(db_path), [("sample", lines)], ac._Aggregate()
    )

    conn = sqlite3.connect(str(db_path))
    try:
        assert counts["rules"] == 7
        assert conn.execute(
            "SELECT payload_json FROM rules WHERE raw=?",
            ("||ads.example^",),
        ).fetchone()[0]
        assert conn.execute(
            "SELECT COUNT(*) FROM rules WHERE raw='badfilter-target'"
        ).fetchone() == (0,)
        assert sorted(conn.execute("SELECT host FROM domain_index")) == [
            ("ads.example",),
            ("allow.example",),
        ]
        assert conn.execute("SELECT host FROM host_index").fetchall() == [
            ("example.com",),
        ]
        # Every other rule is keyed by a whole-token literal ("loader" sits
        # between "/" and "."; "plain" and "token" touch the unanchored
        # pattern edges, so "ad" keys that rule); the regex and the
        # option-only rule have no key and are candidates for every request.
        keys = dict(
            conn.execute(
                "SELECT r.raw, g.literal_key FROM generic_index g "
                "JOIN rules r ON r.rule_id = g.rule_id"
            )
        )
        assert keys == {
            "wss://loader.*.com/ws^$websocket,third-party": "loader",
            "/tracker[.]example/$third-party": "",
            "plain-ad-token$~stylesheet": "ad",
            "$popup,third-party,domain=example.com": "",
        }
        assert conn.execute(
            "SELECT COUNT(*) FROM resource_type_index WHERE resource_type='websocket'"
        ).fetchone() == (1,)
        assert {
            row[0]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        } == {
            "metadata",
            "rules",
            "domain_index",
            "host_index",
            "generic_index",
            "resource_type_index",
        }
        assert counts == {
            "rules": 7,
            "domain_index": 2,
            "host_index": 1,
            "generic_index": 4,
            "resource_type_index": 4,
        }
    finally:
        conn.close()


def test_generic_keys_are_whole_url_tokens() -> None:
    from services.adblock_patterns import (
        pattern_token_key,
        pattern_tokens,
        url_tokens,
    )

    # Edge tokens of an unanchored pattern, and tokens touching "*", can run
    # into neighbouring URL characters, so they never key a rule.
    assert pattern_tokens("-ad-banner.") == ["ad", "banner"]
    assert pattern_tokens("adserver.") == []
    assert pattern_tokens("/ads*banner/") == []
    assert pattern_tokens("||ads.") == ["ads"]
    assert pattern_tokens("|https://x.o2.pl^") == ["https", "x", "o2", "pl"]
    assert pattern_tokens("ad.js|") == ["js"]
    assert pattern_tokens(r"ad\*token/") == []
    assert pattern_tokens("&ad_type=") == ["ad", "type"]
    assert pattern_tokens("||bücher.*/ads/") == []
    assert {"x", "ad", "banner", "js"} <= url_tokens(
        "https://cdn.example/X-AD-Banner.js"
    )
    # The rarest qualifying token keys the rule; ties prefer the longer one.
    assert pattern_token_key("-ad-banner.", {"banner": 9, "ad": 2}) == "ad"
    assert pattern_token_key("-ad-banner.", {}) == "banner"
    assert pattern_token_key("adserver.", {}) == ""


def test_request_indexes_skip_rules_disabled_by_badfilter(tmp_path: Path) -> None:
    lines = [
        "badfilter-target",
        "badfilter-target$badfilter",
        "@@||allow.example^",
        "@@||allow.example^$badfilter",
        "||kept.example^",
    ]
    out = _compile_sample(tmp_path, lines)

    assert _indexed_raws(out, "generic_index") == []
    assert _indexed_raws(out, "domain_index") == ["||kept.example^"]

    # Disabled rules are still parsed (and counted); only the lookup omits them.
    assert {rule["raw"] for rule in _parsed_rules(lines)} == {
        "badfilter-target",
        "badfilter-target$badfilter",
        "@@||allow.example^",
        "@@||allow.example^$badfilter",
        "||kept.example^",
    }


def test_parser_preserves_option_only_and_csp_rules() -> None:
    records = _parsed_rules(
        [
            "$popup,third-party,domain=example.com|~excluded.example",
            "$csp=script-src 'self' data: 'unsafe-inline' 'unsafe-hashes' 'unsafe-eval',domain=thumbs.pro",
        ],
    )

    generic_rules = _generic(records)
    by_option = {rule["options_raw"].split("=", 1)[0]: rule for rule in generic_rules}

    popup_rule = by_option["popup,third-party,domain"]
    assert popup_rule["pattern_kind"] == "option_only"
    assert popup_rule["resource_types"] == ["popup"]
    assert popup_rule["third_party"] == "only"
    assert popup_rule["domain_includes"] == ["example.com"]
    assert popup_rule["domain_excludes"] == ["excluded.example"]

    csp_rule = by_option["csp"]
    assert csp_rule["pattern_kind"] == "option_only"
    assert csp_rule["options"]["csp"].endswith("'unsafe-eval'")
    assert csp_rule["domain_includes"] == ["thumbs.pro"]
    assert csp_rule["misc_options"] == {}


def test_parser_indexes_wildcard_hosts_as_host_patterns() -> None:
    records = _parsed_rules(
        [
            "||google.*/pagead/lvz?$script",
            "||betvictor.com*&utm_campaign=$popup",
            "@@||sourcepointcmp.bloomberg.*/mms/get_site_data?$domain=bloomberg.co.jp|bloomberg.com",
            "||[::]^$third-party,domain=~[::1]|~localhost",
            "||[2001:db8::20]^$third-party,domain=~[2001:db8::10]",
            "||api.example.com/path$method=post,denyallow=foo.example|bar.example",
            "||cdn.example.com/assets/ad.js^$script",
            "||query.example.com/api?kind=ad^$xmlhttprequest",
            "@@||consent.truste.com/notice$domain=$domain=fortune.com|hsl.fi",
        ],
    )

    host_rules = _of_kind(records, *_HOST_KINDS)
    by_raw = {rule["raw"]: rule for rule in host_rules}

    wildcard = by_raw["||google.*/pagead/lvz?$script"]
    assert wildcard["pattern_kind"] == "host_anchored_pattern"
    assert wildcard["resource_types"] == ["script"]
    assert r"\|\|" not in wildcard["compiled_regex"]
    assert "google\\..*" in wildcard["compiled_regex"]
    assert re.search(wildcard["compiled_regex"], "https://www.google.de/pagead/lvz?")

    host_with_wildcard_suffix = by_raw["||betvictor.com*&utm_campaign=$popup"]
    assert host_with_wildcard_suffix["pattern_kind"] == "host_anchored"
    assert host_with_wildcard_suffix["host"] == "betvictor.com"
    assert host_with_wildcard_suffix["suffix"] == "*&utm_campaign="
    assert host_with_wildcard_suffix["resource_types"] == ["popup"]

    exception = by_raw[
        "@@||sourcepointcmp.bloomberg.*/mms/get_site_data?$domain=bloomberg.co.jp|bloomberg.com"
    ]
    assert exception["action"] == "allow"
    assert exception["pattern_kind"] == "host_anchored_pattern"
    assert exception["domain_includes"] == ["bloomberg.co.jp", "bloomberg.com"]

    domain_rules = _of_kind(records, "domain_only")
    domain_by_raw = {rule["raw"]: rule for rule in domain_rules}

    unspecified_ipv6 = domain_by_raw["||[::]^$third-party,domain=~[::1]|~localhost"]
    assert unspecified_ipv6["pattern_kind"] == "domain_only"
    assert unspecified_ipv6["host"] == "[::]"
    assert unspecified_ipv6["domain_exclude_patterns"] == []
    assert unspecified_ipv6["domain_excludes"] == ["[::1]", "localhost"]

    literal_ipv6 = domain_by_raw["||[2001:db8::20]^$third-party,domain=~[2001:db8::10]"]
    assert literal_ipv6["pattern_kind"] == "domain_only"
    assert literal_ipv6["host"] == "[2001:db8::20]"
    assert literal_ipv6["domain_exclude_patterns"] == []
    assert literal_ipv6["domain_excludes"] == ["[2001:db8::10]"]

    method = by_raw[
        "||api.example.com/path$method=post,denyallow=foo.example|bar.example"
    ]
    assert method["pattern_kind"] == "host_anchored"
    assert method["options"]["method"] == ["POST"]
    assert method["options"]["denyallow"] == ["foo.example", "bar.example"]

    trailing_path_separator = by_raw["||cdn.example.com/assets/ad.js^$script"]
    assert trailing_path_separator["suffix"] == "/assets/ad.js^"
    assert re.search(
        trailing_path_separator["compiled_regex"],
        "https://cdn.example.com/assets/ad.js",
    )

    trailing_query_separator = by_raw["||query.example.com/api?kind=ad^$xmlhttprequest"]
    assert trailing_query_separator["suffix"] == "/api?kind=ad^"
    assert re.search(
        trailing_query_separator["compiled_regex"],
        "https://query.example.com/api?kind=ad&x=1",
    )

    duplicated_domain = by_raw[
        "@@||consent.truste.com/notice$domain=$domain=fortune.com|hsl.fi"
    ]
    assert duplicated_domain["action"] == "allow"
    assert duplicated_domain["domain_includes"] == ["fortune.com", "hsl.fi"]


def test_cosmetic_rules_are_counted_by_marker_not_indexed(tmp_path: Path) -> None:
    from tools import adblock_compile as ac  # type: ignore

    agg = ac._Aggregate()
    lines = [
        "madewell.com##+js(cookie-remover, dns_cookie)",
        "example.com#@#+js(set, foo, noopFunc)",
        'history.com#?#[data-sentry-component="Box"]:has-text(Privacy)',
        "example.com#@?#.notice:has-text(Privacy)",
        "podleze-piekielko.pl#$#abort-on-property-read cookieman",
        "example.com#@$#abort-on-property-read cookieman",
        "plain.example##.ad-unit",
    ]
    per_list, counts = ac._write_request_lookup_index(
        str(tmp_path / "request_lookup.sqlite"), [("sample", lines)], agg
    )

    assert agg.cosmetic_rules_total == 7
    assert agg.cosmetic_rules_by_marker == {
        "##": 2,
        "#@#": 1,
        "#?#": 1,
        "#@?#": 1,
        "#$#": 1,
        "#@$#": 1,
    }
    assert per_list["sample"]["cosmetic"] == 7
    assert counts["rules"] == 0


def test_identical_inputs_compile_to_identical_artifact_digest(tmp_path: Path) -> None:
    """Rebuilding unchanged lists must reuse the active revision, not add one.

    report.json is part of the artifact digest; it previously embedded the
    random temporary build directory, so every rebuild produced a new
    multi-MB revision.
    """
    from services import adblock_artifacts  # type: ignore
    from tools import adblock_compile as ac  # type: ignore

    lists = tmp_path / "lists"
    lists.mkdir()
    (lists / "easylist.txt").write_text(
        "||ads.example^\n||track.example^$third-party\nexample.com##.ad\n/banner[0-9]+/\n",
        encoding="utf-8",
    )
    digests = []
    archives = []
    for name in ("build-a", "build-b"):
        out = tmp_path / name
        out.mkdir()
        assert (
            ac.main(
                [
                    "--lists-dir",
                    str(lists),
                    "--out-dir",
                    str(out),
                    "--enabled-list",
                    "easylist",
                ],
            )
            == 0
        )
        report = json.loads((out / "report.json").read_text(encoding="utf-8"))
        assert report["files"]["request_lookup_sqlite"] == "request_lookup.sqlite"
        assert str(tmp_path) not in (out / "report.json").read_text(encoding="utf-8")
        file_map = adblock_artifacts._load_directory_files(out)
        digests.append(adblock_artifacts._calculate_artifact_sha(file_map))
        archives.append(adblock_artifacts._build_deterministic_archive(file_map))

    assert digests[0] == digests[1]
    assert archives[0] == archives[1]
