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


def _compile_sample(tmp_path: Path, lines: list[str]) -> Path:
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

    return out


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_main_compiles_explicit_enabled_lists_without_database_state(
    tmp_path: Path,
) -> None:
    _add_web_to_path()
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
    assert "ads.example" in (out / "request_index_domain.jsonl").read_text(
        encoding="utf-8"
    )
    assert "disabled.example" not in (out / "request_index_domain.jsonl").read_text(
        encoding="utf-8"
    )


def test_abp_regex_options_split_after_closing_delimiter() -> None:
    _add_web_to_path()
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
    _add_web_to_path()
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


def test_network_rules_emit_normalized_request_indexes(tmp_path: Path) -> None:
    out = _compile_sample(
        tmp_path,
        [
            (
                r"/^https?:\/\/s3\.*\.amazonaws\.com\/[a-f0-9]{45,}"
                r"\/[a-f,0-9]{8,10}$/$script,third-party,xmlhttprequest,"
                r"domain=~amazon.com"
            ),
            "@@||youtube.com/get_video_info?$xmlhttprequest,domain=music.youtube.com|tv.youtube.com",
            "||example.com/ad/path|$script,~third-party",
            "|https://left.example/ad^$image",
            "wss://loader.*.com/ws^$websocket,third-party",
            "ads.js|",
            r"price\$literal",
            r"||shop.example/path\$price^$script",
            "plain-ad-token$~stylesheet",
            "||ads.example^$third-party",
        ],
    )

    regex_rules = _read_jsonl(out / "request_index_regex.jsonl")
    assert len(regex_rules) == 1
    regex_rule = regex_rules[0]
    assert regex_rule["pattern_kind"] == "regex"
    assert regex_rule["resource_types"] == ["script", "xmlhttprequest"]
    assert regex_rule["third_party"] == "only"
    assert regex_rule["domain_excludes"] == ["amazon.com"]
    assert "/$script" not in regex_rule["options"]

    host_rules = _read_jsonl(out / "request_index_host.jsonl")
    by_host = {rule["host"]: rule for rule in host_rules}
    assert by_host["example.com"]["suffix"] == "/ad/path|"
    assert by_host["example.com"]["suffix_right_anchored"] is True
    assert by_host["example.com"]["path_pattern"] == "/ad/path"
    assert by_host["example.com"]["query_pattern"] == ""
    assert by_host["example.com"]["resource_types"] == ["script"]
    assert by_host["example.com"]["third_party"] == "exclude"
    assert by_host["left.example"]["pattern_kind"] == "absolute_url"
    assert by_host["left.example"]["url_scheme_pattern"] == "https"
    assert by_host["left.example"]["url_left_anchored"] is True
    assert by_host["left.example"]["path_pattern"] == "/ad"
    assert by_host["left.example"]["suffix_separator_suffix"] is True
    assert by_host["youtube.com"]["action"] == "allow"
    assert by_host["youtube.com"]["domain_includes"] == [
        "music.youtube.com",
        "tv.youtube.com",
    ]
    assert by_host["shop.example"]["suffix"] == r"/path\$price^"
    assert by_host["shop.example"]["resource_types"] == ["script"]
    absolute_patterns = [
        rule for rule in host_rules if rule["pattern_kind"] == "absolute_url_pattern"
    ]
    assert absolute_patterns[0]["host_pattern"] == "loader.*.com"
    assert absolute_patterns[0]["path_pattern"] == "/ws"
    assert absolute_patterns[0]["resource_types"] == ["websocket"]
    assert absolute_patterns[0]["third_party"] == "only"

    domain_rules = _read_jsonl(out / "request_index_domain.jsonl")
    assert any(
        rule["host"] == "ads.example" and rule["third_party"] == "only"
        for rule in domain_rules
    )

    generic_rules = _read_jsonl(out / "request_index_generic.jsonl")
    assert {rule["pattern_kind"] for rule in generic_rules} == {
        "right_anchored",
        "substring",
    }
    assert any(rule["pattern"] == r"price\$literal" for rule in generic_rules)
    assert any(
        rule["excluded_resource_types"] == ["stylesheet"] for rule in generic_rules
    )
    assert any(rule.get("right_anchored") is True for rule in generic_rules)


def test_request_lookup_sqlite_indexes_fast_candidate_shapes(tmp_path: Path) -> None:
    out = _compile_sample(
        tmp_path,
        [
            "||ads.example^",
            "@@||allow.example^",
            "||example.com/ad/path|$script,~third-party",
            "wss://loader.*.com/ws^$websocket,third-party",
            "/tracker[.]example/$third-party",
            "plain-ad-token$~stylesheet",
            "$popup,third-party,domain=example.com",
            "badfilter-target",
            "badfilter-target$badfilter",
        ],
    )

    _add_web_to_path()
    from tools import adblock_compile as ac  # type: ignore

    db_path = out / "request_lookup.sqlite"
    counts = ac._write_request_lookup_index(
        str(db_path),
        str(out / "network_rules.jsonl"),
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
        assert conn.execute(
            "SELECT action FROM domain_index WHERE host=?",
            ("ads.example",),
        ).fetchone() == ("block",)
        assert conn.execute(
            "SELECT action FROM domain_index WHERE host=?",
            ("allow.example",),
        ).fetchone() == ("allow",)
        assert conn.execute(
            "SELECT path_pattern FROM host_index WHERE host=?",
            ("example.com",),
        ).fetchone() == ("/ad/path",)
        assert conn.execute(
            "SELECT host_pattern FROM host_pattern_index"
        ).fetchone() == ("loader.*.com",)
        assert conn.execute(
            "SELECT literal_key FROM host_pattern_token_index"
        ).fetchone() == ("loader",)
        assert conn.execute("SELECT COUNT(*) FROM regex_index").fetchone() == (1,)
        assert conn.execute("SELECT literal_key FROM regex_token_index").fetchone() == (
            "tracker",
        )
        assert conn.execute(
            "SELECT literal_key FROM generic_index WHERE pattern_kind='substring'"
        ).fetchone() == ("plain-ad-token",)
        assert conn.execute(
            "SELECT COUNT(*) FROM option_index WHERE option_key='popup'"
        ).fetchone() == (1,)
        assert conn.execute(
            "SELECT COUNT(*) FROM resource_type_index WHERE resource_type='websocket'"
        ).fetchone() == (1,)
        assert conn.execute(
            "SELECT COUNT(*) FROM domain_scope_index WHERE domain='example.com'"
        ).fetchone() == (1,)
    finally:
        conn.close()


def test_parser_preserves_option_only_and_csp_rules(tmp_path: Path) -> None:
    out = _compile_sample(
        tmp_path,
        [
            "$popup,third-party,domain=example.com|~excluded.example",
            "$csp=script-src 'self' data: 'unsafe-inline' 'unsafe-hashes' 'unsafe-eval',domain=thumbs.pro",
        ],
    )

    generic_rules = _read_jsonl(out / "request_index_generic.jsonl")
    by_option = {rule["options_raw"].split("=", 1)[0]: rule for rule in generic_rules}

    popup_rule = by_option["popup,third-party,domain"]
    assert popup_rule["pattern_kind"] == "option_only"
    assert popup_rule["applies_without_url_pattern"] is True
    assert popup_rule["resource_types"] == ["popup"]
    assert popup_rule["third_party"] == "only"
    assert popup_rule["domain_includes"] == ["example.com"]
    assert popup_rule["domain_excludes"] == ["excluded.example"]

    csp_rule = by_option["csp"]
    assert csp_rule["pattern_kind"] == "option_only"
    assert csp_rule["options"]["csp"].endswith("'unsafe-eval'")
    assert csp_rule["domain_includes"] == ["thumbs.pro"]
    assert csp_rule["misc_options"] == {}
    assert _read_jsonl(out / "network_option_misc.jsonl") == []


def test_parser_indexes_wildcard_hosts_as_host_patterns(tmp_path: Path) -> None:
    out = _compile_sample(
        tmp_path,
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

    host_rules = _read_jsonl(out / "request_index_host.jsonl")
    by_raw = {rule["raw"]: rule for rule in host_rules}

    wildcard = by_raw["||google.*/pagead/lvz?$script"]
    assert wildcard["pattern_kind"] == "host_anchored_pattern"
    assert wildcard["host_pattern"] == "google.*"
    assert wildcard["path_pattern"] == "/pagead/lvz"
    assert wildcard["query_pattern"] == "?"
    assert wildcard["resource_types"] == ["script"]
    assert r"\|\|" not in wildcard["compiled_regex"]
    assert "google\\..*" in wildcard["compiled_regex"]

    host_with_wildcard_suffix = by_raw["||betvictor.com*&utm_campaign=$popup"]
    assert host_with_wildcard_suffix["pattern_kind"] == "host_anchored"
    assert host_with_wildcard_suffix["host"] == "betvictor.com"
    assert host_with_wildcard_suffix["suffix"] == "*&utm_campaign="
    assert host_with_wildcard_suffix["resource_types"] == ["popup"]

    exception = by_raw[
        "@@||sourcepointcmp.bloomberg.*/mms/get_site_data?$domain=bloomberg.co.jp|bloomberg.com"
    ]
    assert exception["action"] == "allow"
    assert exception["host_pattern"] == "sourcepointcmp.bloomberg.*"
    assert exception["domain_includes"] == ["bloomberg.co.jp", "bloomberg.com"]

    domain_rules = _read_jsonl(out / "request_index_domain.jsonl")
    domain_by_raw = {rule["raw"]: rule for rule in domain_rules}

    unspecified_ipv6 = domain_by_raw["||[::]^$third-party,domain=~[::1]|~localhost"]
    assert unspecified_ipv6["pattern_kind"] == "domain_only"
    assert unspecified_ipv6["host"] == "[::]"
    assert unspecified_ipv6["domain_exclude_patterns"] == []
    assert unspecified_ipv6["domain_excludes"] == ["[::1]", "localhost"]

    literal_ipv6 = domain_by_raw[
        "||[2001:db8::20]^$third-party,domain=~[2001:db8::10]"
    ]
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
    assert trailing_path_separator["path_pattern"] == "/assets/ad.js"
    assert trailing_path_separator["query_pattern"] == ""
    assert trailing_path_separator["suffix_separator_suffix"] is True

    trailing_query_separator = by_raw["||query.example.com/api?kind=ad^$xmlhttprequest"]
    assert trailing_query_separator["path_pattern"] == "/api"
    assert trailing_query_separator["query_pattern"] == "?kind=ad"
    assert trailing_query_separator["suffix_separator_suffix"] is True

    duplicated_domain = by_raw[
        "@@||consent.truste.com/notice$domain=$domain=fortune.com|hsl.fi"
    ]
    assert duplicated_domain["action"] == "allow"
    assert duplicated_domain["domain_includes"] == ["fortune.com", "hsl.fi"]


def test_cosmetic_parser_splits_scriptlets_and_html_filters(tmp_path: Path) -> None:
    out = _compile_sample(
        tmp_path,
        [
            "madewell.com##+js(cookie-remover, dns_cookie)",
            "example.com#@#+js(set, foo, noopFunc)",
            'history.com#?#[data-sentry-component="Box"]:has-text(Privacy)',
            "example.com#@?#.notice:has-text(Privacy)",
            "podleze-piekielko.pl#$#abort-on-property-read cookieman",
            "example.com#@$#abort-on-property-read cookieman",
            "plain.example##.ad-unit",
        ],
    )

    scriptlets = _read_jsonl(out / "cosmetic_scriptlet.jsonl")
    assert scriptlets[0]["kind"] == "scriptlet"
    assert scriptlets[0]["marker"] == "##"
    assert scriptlets[0]["selector"].startswith("+js(")

    scriptlet_exceptions = _read_jsonl(out / "cosmetic_scriptlet_exception.jsonl")
    assert scriptlet_exceptions[0]["kind"] == "scriptlet_exception"
    assert scriptlet_exceptions[0]["exception"] is True

    extended_css = _read_jsonl(out / "cosmetic_extended_css.jsonl")
    assert extended_css[0]["kind"] == "extended_css"
    extended_css_exceptions = _read_jsonl(out / "cosmetic_extended_css_exception.jsonl")
    assert extended_css_exceptions[0]["kind"] == "extended_css_exception"
    assert extended_css_exceptions[0]["exception"] is True

    html_filters = _read_jsonl(out / "cosmetic_html_filter.jsonl")
    assert html_filters[0]["kind"] == "html_filter"
    html_filter_exceptions = _read_jsonl(out / "cosmetic_html_filter_exception.jsonl")
    assert html_filter_exceptions[0]["kind"] == "html_filter_exception"
    assert html_filter_exceptions[0]["exception"] is True

    elemhide = _read_jsonl(out / "cosmetic_elemhide.jsonl")
    assert elemhide[0]["kind"] == "elemhide"
