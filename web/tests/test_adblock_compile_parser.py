from __future__ import annotations

import json
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
        "cosmetic_scriptlet_jsonl": out / "cosmetic_scriptlet.jsonl",
        "cosmetic_scriptlet_exception_jsonl": out
        / "cosmetic_scriptlet_exception.jsonl",
        "cosmetic_scoped_jsonl": out / "cosmetic_scoped.jsonl",
        "cosmetic_global_jsonl": out / "cosmetic_global.jsonl",
        "cosmetic_exception_jsonl": out / "cosmetic_exception.jsonl",
        "cosmetic_non_exception_jsonl": out / "cosmetic_non_exception.jsonl",
    }

    agg = ac._Aggregate(
        domains_block=set(),
        domains_allow=set(),
        regex_block=set(),
        regex_allow=set(),
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
            "ads.js|",
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
    assert by_host["youtube.com"]["action"] == "allow"
    assert by_host["youtube.com"]["domain_includes"] == [
        "music.youtube.com",
        "tv.youtube.com",
    ]

    domain_rules = _read_jsonl(out / "request_index_domain.jsonl")
    assert any(
        rule["host"] == "ads.example" and rule["third_party"] == "only"
        for rule in domain_rules
    )

    generic_rules = _read_jsonl(out / "request_index_generic.jsonl")
    assert {rule["pattern_kind"] for rule in generic_rules} == {
        "left_anchored",
        "right_anchored",
        "substring",
    }
    assert any(
        rule["excluded_resource_types"] == ["stylesheet"] for rule in generic_rules
    )
    assert any(rule.get("right_anchored") is True for rule in generic_rules)
