#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import sqlite3
import sys
from contextlib import ExitStack, suppress
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

HERE = pathlib.Path(__file__).resolve().parent
APP_ROOT = pathlib.Path(os.path.join(HERE, "..")).resolve()
APP_ROOT_STR = str(APP_ROOT)
if APP_ROOT_STR not in sys.path:
    sys.path.insert(0, APP_ROOT_STR)

from services.adblock_hosts import (  # noqa: E402
    looks_like_adblock_host as _looks_like_host,
)
from services.adblock_hosts import (  # noqa: E402
    normalize_adblock_host as _normalize_host,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

# ABP / EasyList parsing notes (minimal subset):
# - Comments start with '!'
# - Header line often: [Adblock Plus 2.0]
# - Cosmetic rules contain selector separators like '##', '#@#', '#?#', '#$#'
# - Exception rules start with '@@'
# - Options are appended after '$' (network rules); request indexes preserve
#   full parsed rules for SQLite-backed request-time lookup.


_COSMETIC_MARKERS = ("#@?#", "#@$#", "#@%#", "#@#", "#?#", "#$#", "#%#", "##")


@dataclass
class _RuleWriters:
    network_jsonl: Any
    cosmetic_jsonl: Any

    # Network buckets
    network_no_options_jsonl: Any
    network_with_options_jsonl: Any
    network_option_domain_jsonl: Any
    network_option_third_party_jsonl: Any
    network_option_type_jsonl: Any
    network_option_misc_jsonl: Any

    network_kind_domain_only_jsonl: Any
    network_kind_host_anchored_jsonl: Any
    network_kind_left_anchored_jsonl: Any
    network_kind_substring_jsonl: Any
    network_kind_wildcard_jsonl: Any
    network_kind_regex_jsonl: Any

    # Network split by exception flag
    network_block_jsonl: Any
    network_exception_jsonl: Any

    # Request-time index families. These are still line-oriented artifacts so
    # downstream runtimes can load only the index families they need.
    request_index_domain_jsonl: Any
    request_index_host_jsonl: Any
    request_index_regex_jsonl: Any
    request_index_generic_jsonl: Any

    # Network split by resource-type options (e.g., $script / $~script)
    network_type_pos_jsonl: dict[str, Any]
    network_type_neg_jsonl: dict[str, Any]

    # Cosmetic sub-buckets
    cosmetic_elemhide_jsonl: Any
    cosmetic_elemhide_exception_jsonl: Any
    cosmetic_extended_css_jsonl: Any
    cosmetic_extended_css_exception_jsonl: Any
    cosmetic_html_filter_jsonl: Any
    cosmetic_html_filter_exception_jsonl: Any
    cosmetic_scriptlet_jsonl: Any
    cosmetic_scriptlet_exception_jsonl: Any

    # Cosmetic splits
    cosmetic_scoped_jsonl: Any
    cosmetic_global_jsonl: Any
    cosmetic_exception_jsonl: Any
    cosmetic_non_exception_jsonl: Any


@dataclass
class _Aggregate:
    network_rules_total: int
    network_rules_by_kind: dict[str, int]
    network_rules_with_options: int
    network_rules_with_domain_opt: int
    cosmetic_rules_total: int
    cosmetic_rules_by_marker: dict[str, int]
    option_key_counts: dict[str, int]
    option_group_counts: dict[str, int]


_KNOWN_TYPES: set[str] = {
    "script",
    "image",
    "stylesheet",
    "xmlhttprequest",
    "subdocument",
    "document",
    "font",
    "media",
    "object",
    "ping",
    "popup",
    "websocket",
    "other",
}

_VALUE_OPTIONS: set[str] = {
    "csp",
    "denyallow",
    "domain",
    "header",
    "method",
    "permissions",
    "redirect",
    "redirect-rule",
    "removeparam",
    "rewrite",
}

_BEHAVIOR_OPTIONS: set[str] = {
    "badfilter",
    "elemhide",
    "genericblock",
    "generichide",
    "important",
    "match-case",
}

_ALL_KNOWN_OPTIONS = (
    _KNOWN_TYPES
    | _VALUE_OPTIONS
    | _BEHAVIOR_OPTIONS
    | {"third-party", "~third-party"}
    | {f"~{item}" for item in _KNOWN_TYPES}
    | {f"~{item}" for item in _BEHAVIOR_OPTIONS}
)


_DOMAIN_ONLY_RE = re.compile(r"^\|\|(?P<host>[a-z0-9.-]+)\^?$", re.IGNORECASE)
_ABP_SEPARATOR_REGEX = r"(?:[^A-Za-z0-9_.%-]|$)"
LOOKUP_STRATEGY = (
    "domain suffix candidates -> domain_index; exact and host-suffix "
    "candidates -> host_index; host-pattern/regex token prefilters before "
    "payload verification; generic literal-key prefilter before payload "
    "verification"
)


def _is_comment_or_header(s: str) -> bool:
    t = (s or "").strip()
    if not t:
        return True
    if t.startswith("!"):
        return True
    return bool(t.startswith("[") and t.endswith("]"))


def _is_cosmetic(s: str) -> bool:
    # Very conservative detection.
    return any(m in s for m in _COSMETIC_MARKERS)


def _split_options(rule: str) -> tuple[str, str]:
    # Split the ABP options suffix. Regex rules are /.../$options, and the
    # regex body can legitimately contain '$' anchors, escaped slashes, and
    # character classes. For non-regex rules, only an unescaped '$' starts the
    # options suffix; '\$' is a literal URL-pattern dollar.
    s = (rule or "").strip()
    if len(s) >= 2 and s.startswith("/"):
        regex_end = _find_regex_delimiter(s)
        if regex_end is not None:
            pattern = s[: regex_end + 1]
            tail = s[regex_end + 1 :]
            if not tail:
                return pattern, ""
            if tail.startswith("$"):
                return pattern, tail[1:].strip()
            return s, ""
    delimiter = _find_options_delimiter(s)
    if delimiter is None:
        return s, ""
    pat = s[:delimiter]
    opts = s[delimiter + 1 :]
    return pat.strip(), opts.strip()


def _find_options_delimiter(rule: str) -> int | None:
    for index, ch in enumerate(rule or ""):
        if ch != "$":
            continue
        backslashes = 0
        cursor = index - 1
        while cursor >= 0 and rule[cursor] == "\\":
            backslashes += 1
            cursor -= 1
        if backslashes % 2 == 0:
            return index
    return None


def _find_regex_delimiter(rule: str) -> int | None:
    escaped = False
    in_class = False
    for i, ch in enumerate(rule[1:], start=1):
        if escaped:
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if ch == "[":
            in_class = True
            continue
        if ch == "]" and in_class:
            in_class = False
            continue
        if ch == "/" and not in_class:
            tail = rule[i + 1 :]
            if not tail or tail.startswith("$"):
                return i
    return None


def _subscription_list_path(lists_dir: pathlib.Path, key: str) -> str:
    safe = "".join([c for c in (key or "") if c.isalnum() or c in {"-", "_"}])
    return os.path.join(str(lists_dir), f"{safe}.txt")


def _parse_options(opts: str) -> tuple[list[str], dict[str, Any]]:
    raw = (opts or "").strip()
    if not raw:
        return [], {}

    tokens = _split_option_tokens(raw)
    parsed: dict[str, Any] = {}
    for t in tokens:
        if "=" in t:
            k, v = t.split("=", 1)
            k = k.strip().lower()
            v = v.strip()
            if k == "domain":
                # ABP domain=example.com|~foo.com
                parts = [
                    _normalize_domain_option_value(p) for p in v.split("|") if p.strip()
                ]
                parsed[k] = parts
            elif k in {"denyallow", "method"}:
                parsed[k] = [
                    _normalize_domain_option_value(p)
                    if k == "denyallow"
                    else p.strip().upper()
                    for p in v.split("|")
                    if p.strip()
                ]
            else:
                parsed[k] = v
        else:
            # flags can be negated: ~third-party, ~script
            parsed[t.strip().lower()] = True
    return tokens, parsed


def _split_option_tokens(raw: str) -> list[str]:
    tokens: list[str] = []
    for part in (raw or "").split(","):
        item = part.strip()
        if not item:
            continue
        key = item.split("=", 1)[0].strip().lower()
        if tokens and key not in _ALL_KNOWN_OPTIONS:
            # Some valued ABP options, especially CSP/header-style options, can
            # contain commas. Preserve the whole value instead of inventing a
            # bogus option key from the continuation.
            tokens[-1] = f"{tokens[-1]},{item}"
            continue
        tokens.append(item)
    return tokens


def _normalize_domain_option_value(value: str) -> str:
    raw = (value or "").strip().lower().rstrip(".")
    if not raw:
        return ""
    if raw.startswith("$") and "=" in raw:
        key, remainder = raw[1:].split("=", 1)
        if key.strip().lower() in {"domain", "denyallow"}:
            raw = remainder.strip().lower().rstrip(".")
            if not raw:
                return ""
    negated = raw.startswith("~")
    body = raw[1:].strip().rstrip(".") if negated else raw
    if not body:
        return ""
    if body in {"local", "localhost"} or "*" in body or body.startswith("["):
        normalized = body
    else:
        normalized = _normalize_host(body)
    return f"~{normalized}" if negated else normalized


def _option_semantics(
    tokens: list[str],
    opt_parsed: dict[str, Any],
) -> dict[str, Any]:
    resource_types = sorted(
        {key for key in opt_parsed if (key or "").lower() in _KNOWN_TYPES},
    )
    excluded_resource_types = sorted(
        {
            key[1:]
            for key in opt_parsed
            if (key or "").startswith("~") and key[1:] in _KNOWN_TYPES
        },
    )
    if "third-party" in opt_parsed:
        third_party = "only"
    elif "~third-party" in opt_parsed:
        third_party = "exclude"
    else:
        third_party = "any"

    domain_values = opt_parsed.get("domain") or []
    domain_includes: list[str] = []
    domain_excludes: list[str] = []
    domain_include_patterns: list[str] = []
    domain_exclude_patterns: list[str] = []
    if isinstance(domain_values, list):
        for item in domain_values:
            raw_value = str(item or "").strip().lower().rstrip(".")
            if not raw_value:
                continue
            excluded = raw_value.startswith("~")
            domain = raw_value[1:].strip().rstrip(".") if excluded else raw_value
            domain = _normalize_host(domain)
            if not domain:
                continue
            is_pattern = "*" in domain
            if excluded:
                if is_pattern:
                    domain_exclude_patterns.append(domain)
                else:
                    domain_excludes.append(domain)
            elif is_pattern:
                domain_include_patterns.append(domain)
            else:
                domain_includes.append(domain)

    standard_keys = {"domain", "third-party", "~third-party"}
    standard_keys.update(_KNOWN_TYPES)
    standard_keys.update({f"~{item}" for item in _KNOWN_TYPES})
    standard_keys.update(_VALUE_OPTIONS)
    standard_keys.update(_BEHAVIOR_OPTIONS)
    standard_keys.update({f"~{item}" for item in _BEHAVIOR_OPTIONS})
    misc_options = {
        key: value for key, value in opt_parsed.items() if key not in standard_keys
    }
    behavior_options = sorted(
        key
        for key in opt_parsed
        if key in _BEHAVIOR_OPTIONS
        or (key.startswith("~") and key[1:] in _BEHAVIOR_OPTIONS)
    )
    value_options = {
        key: value for key, value in opt_parsed.items() if key in _VALUE_OPTIONS
    }
    return {
        "option_tokens": tokens,
        "resource_types": resource_types,
        "excluded_resource_types": excluded_resource_types,
        "third_party": third_party,
        "domain_includes": sorted(set(domain_includes)),
        "domain_excludes": sorted(set(domain_excludes)),
        "domain_include_patterns": sorted(set(domain_include_patterns)),
        "domain_exclude_patterns": sorted(set(domain_exclude_patterns)),
        "behavior_options": behavior_options,
        "value_options": value_options,
        "misc_options": misc_options,
    }


def _rule_id(list_key: str, raw_line: str, *, exception: bool) -> str:
    # Stable id for cross-bucket joins without parsing all JSONL files.
    h = hashlib.sha1()
    h.update((list_key or "").encode("utf-8", errors="ignore"))
    h.update(b"\n")
    h.update(b"1" if exception else b"0")
    h.update(b"\n")
    h.update((raw_line or "").strip().encode("utf-8", errors="ignore"))
    return h.hexdigest()


def _option_groups(opt_parsed: dict[str, Any]) -> set[str]:
    if not opt_parsed:
        return set()

    groups: set[str] = set()
    if "domain" in opt_parsed:
        groups.add("domain")

    if "third-party" in opt_parsed or "~third-party" in opt_parsed:
        groups.add("third_party")

    type_hit = False
    for k in opt_parsed:
        kk = (k or "").lower().lstrip("~")
        if kk in _KNOWN_TYPES:
            type_hit = True
            break
    if type_hit:
        groups.add("type")

    misc = False
    for k in opt_parsed:
        kl = (k or "").lower()
        if kl in _ALL_KNOWN_OPTIONS:
            continue
        misc = True
        break
    if misc:
        groups.add("misc")
    return groups


def _abp_to_regex(pattern: str) -> str:
    p = pattern or ""
    left_anchored = p.startswith("|") and not p.startswith("||")
    right_anchored = p.endswith("|") and not p.endswith(r"\|")
    if left_anchored:
        p = p[1:]
    if right_anchored:
        p = p[:-1]

    parts: list[str] = []
    for ch in p:
        if ch == "*":
            parts.append(".*")
        elif ch == "^":
            parts.append(_ABP_SEPARATOR_REGEX)
        else:
            parts.append(re.escape(ch))
    body = "".join(parts)
    if left_anchored:
        body = "^" + body
    if right_anchored:
        body += "$"
    return body


def _host_pattern_to_regex(host_pattern: str) -> str:
    host = (host_pattern or "").strip().lower().rstrip(".")
    if not host:
        return ""
    return _abp_to_regex(host)


def _host_anchored_pattern_to_regex(host_pattern: str, suffix: str) -> str:
    host_regex = _host_pattern_to_regex(host_pattern)
    suffix_regex = _abp_to_regex(suffix)
    if not host_regex:
        return suffix_regex
    return (
        r"^[a-z][a-z0-9+.-]*://(?:[^/?#@]*@)?(?:[^/?#]*\.)?" + host_regex + suffix_regex
    )


def _suffix_fields(suffix: str) -> dict[str, Any]:
    suffix_right_anchored = suffix.endswith("|")
    suffix_body = suffix[:-1] if suffix_right_anchored else suffix
    return {
        "suffix": suffix,
        "suffix_body": suffix_body,
        "suffix_right_anchored": suffix_right_anchored,
        "suffix_regex": _abp_to_regex(suffix),
        **_split_suffix_parts(suffix_body),
    }


def _split_suffix_parts(suffix_body: str) -> dict[str, Any]:
    suffix = suffix_body or ""
    separator_prefix = suffix.startswith("^")
    if separator_prefix:
        suffix = suffix[1:]
    separator_suffix = suffix.endswith("^")
    if separator_suffix:
        suffix = suffix[:-1]

    fragment_pattern = ""
    if "#" in suffix:
        suffix, fragment_pattern = suffix.split("#", 1)
        fragment_pattern = "#" + fragment_pattern

    path_pattern = ""
    query_pattern = ""
    if suffix.startswith("?"):
        query_pattern = suffix
    elif "?" in suffix:
        path_pattern, query = suffix.split("?", 1)
        query_pattern = "?" + query
    else:
        path_pattern = suffix

    return {
        "suffix_separator_prefix": separator_prefix,
        "suffix_separator_suffix": separator_suffix,
        "path_pattern": path_pattern,
        "query_pattern": query_pattern,
        "fragment_pattern": fragment_pattern,
    }


def _classify_absolute_url_pattern(pattern: str) -> tuple[str, dict[str, Any]] | None:
    p = (pattern or "").strip()
    left_anchored = p.startswith("|") and not p.startswith("||")
    candidate = p[1:] if left_anchored else p
    if "://" not in candidate:
        return None

    scheme, rest = candidate.split("://", 1)
    scheme = scheme.strip().lower()
    if not scheme or any(ch.isspace() for ch in scheme):
        return None

    host = rest
    suffix = ""
    for i, ch in enumerate(rest):
        if ch in {"/", "^", "?", "#", "|"}:
            host = rest[:i]
            suffix = rest[i:]
            break
    if not host:
        return None

    normalized_host = _normalize_host(host)
    fields = {
        "absolute_url": True,
        "url_left_anchored": left_anchored,
        "url_scheme_pattern": scheme,
        "compiled_regex": _abp_to_regex(p),
        **_suffix_fields(suffix),
    }
    if _looks_like_host(normalized_host):
        return "absolute_url", {
            "host": normalized_host,
            "anchor": "absolute_url",
            **fields,
        }

    normalized_pattern = _normalize_host(host)
    return "absolute_url_pattern", {
        "host": normalized_host,
        "host_pattern": normalized_pattern,
        "host_pattern_regex": _host_pattern_to_regex(normalized_pattern),
        "anchor": "absolute_url_pattern",
        **fields,
    }


def _classify_network_pattern(pattern: str) -> tuple[str, dict[str, Any]]:
    # Returns (pattern_kind, extra_fields)
    p = (pattern or "").strip()
    if not p:
        return "option_only", {"applies_without_url_pattern": True}
    if len(p) >= 3 and p.startswith("/") and p.endswith("/"):
        return "regex", {"regex": p[1:-1], "compiled_regex": p[1:-1]}
    if p.startswith("||"):
        # host-anchored. May include path.
        rest = p[2:]
        host = rest
        suffix = ""
        # Split host from first delimiter.
        for i, ch in enumerate(rest):
            if ch in {"/", "^", "?", "#", "|"}:
                host = rest[:i]
                suffix = rest[i:]
                break
        raw_host = host
        if "*" in raw_host:
            star_index = raw_host.find("*")
            prefix = raw_host[:star_index]
            normalized_prefix = _normalize_host(prefix)
            if (
                prefix
                and not prefix.endswith(".")
                and _looks_like_host(normalized_prefix)
            ):
                host = normalized_prefix
                suffix = raw_host[star_index:] + suffix
        host = _normalize_host(host)
        suffix_fields = _suffix_fields(suffix)
        if _looks_like_host(host):
            if suffix in {"", "^"}:
                return "domain_only", {"host": host, "anchor": "domain"}
            return "host_anchored", {
                "host": host,
                "anchor": "domain",
                **suffix_fields,
            }
        normalized_pattern = _normalize_host(raw_host)
        return "host_anchored_pattern", {
            "host": host,
            "host_pattern": normalized_pattern,
            "host_pattern_regex": _host_pattern_to_regex(normalized_pattern),
            "anchor": "domain_pattern",
            "compiled_regex": _host_anchored_pattern_to_regex(
                normalized_pattern,
                suffix,
            ),
            **suffix_fields,
        }
    absolute_url = _classify_absolute_url_pattern(p)
    if absolute_url is not None:
        return absolute_url
    if p.startswith("|"):
        return "left_anchored", {"compiled_regex": _abp_to_regex(p)}
    if p.startswith("@@"):
        # Should have been stripped earlier; keep classification stable.
        return "exception_prefixed", {}
    if p.endswith("|") and not p.endswith(r"\|"):
        return "right_anchored", {
            "compiled_regex": _abp_to_regex(p),
            "right_anchored": True,
        }
    # Generic substring/wildcard network rule.
    if any(ch in p for ch in ("*", "^")):
        return "wildcard", {"compiled_regex": _abp_to_regex(p)}
    return "substring", {"substring": p}


def _parse_cosmetic(rule: str) -> dict[str, Any] | None:
    s = (rule or "").strip()
    if not s:
        return None
    for marker in _COSMETIC_MARKERS:
        if marker not in s:
            continue
        left, right = s.split(marker, 1)
        left = left.strip()
        right = right.strip()

        # Domain prefix can be empty or comma-separated.
        domains: list[str] = []
        if left:
            domains = [
                d.strip().lower().lstrip(".") for d in left.split(",") if d.strip()
            ]

        kind = "cosmetic"
        if marker == "##":
            kind = "scriptlet" if right.startswith("+js(") else "elemhide"
        elif marker == "#@#":
            kind = (
                "scriptlet_exception"
                if right.startswith("+js(")
                else "elemhide_exception"
            )
        elif marker == "#?#":
            kind = "extended_css"
        elif marker == "#@?#":
            kind = "extended_css_exception"
        elif marker == "#$#":
            kind = "html_filter"
        elif marker == "#@$#":
            kind = "html_filter_exception"
        elif marker == "#%#":
            kind = "scriptlet"
        elif marker == "#@%#":
            kind = "scriptlet_exception"

        return {
            "kind": kind,
            "marker": marker,
            "domains": domains,
            "selector": right,
        }
    return None


def _extract_domain_only(pattern: str) -> str | None:
    # Accept only the simplest, safest class: ||host^ (or ||host)
    # Reject anything with wildcards/path/query.
    s = (pattern or "").strip()
    m = _DOMAIN_ONLY_RE.match(s)
    if not m:
        return None
    host = (m.group("host") or "").strip().lower().rstrip(".")
    if not host:
        return None
    if ".." in host or host.startswith("-") or host.endswith("-"):
        return None
    if "." not in host:
        return None
    # Require at least one alpha in the TLD-ish part to avoid numeric junk.
    last = host.rsplit(".", 1)[-1]
    if not any(c.isalpha() for c in last):
        return None
    return host


def _compile_and_extract_all(
    *,
    lines: Iterable[str],
    list_key: str,
    agg: _Aggregate,
    writers: _RuleWriters,
) -> dict[str, int]:
    # Single pass over a list file that:
    #  - extracts every parsed rule into JSONL buckets
    #  - feeds the SQLite request lookup used by the runtime ICAP helper
    # We build counts manually to avoid re-reading.
    cosmetic = comments = empty = network_other = 0
    total = 0
    network_total = 0
    network_with_opts = 0

    for raw in lines:
        total += 1
        s = (raw or "").strip()
        if not s:
            empty += 1
            continue
        if s.startswith("!") or (s.startswith("[") and s.endswith("]")):
            comments += 1
            continue

        # Cosmetic rules (keep the old counter behavior).
        if _is_cosmetic(s):
            cosmetic += 1
            parsed = _parse_cosmetic(s)
            if parsed is not None:
                is_cosmetic_exception = parsed.get("kind") in {
                    "elemhide_exception",
                    "extended_css_exception",
                    "html_filter_exception",
                    "scriptlet_exception",
                }
                parsed["exception"] = bool(is_cosmetic_exception)
                parsed["id"] = _rule_id(
                    list_key,
                    s,
                    exception=bool(is_cosmetic_exception),
                )
                parsed["list_key"] = list_key
                parsed["raw"] = s
                writers.cosmetic_jsonl.write(
                    json.dumps(parsed, ensure_ascii=False) + "\n",
                )

                # Cosmetic sub-buckets
                k = parsed.get("kind") or "cosmetic"
                if k == "elemhide":
                    writers.cosmetic_elemhide_jsonl.write(
                        json.dumps(parsed, ensure_ascii=False) + "\n",
                    )
                elif k == "elemhide_exception":
                    writers.cosmetic_elemhide_exception_jsonl.write(
                        json.dumps(parsed, ensure_ascii=False) + "\n",
                    )
                elif k == "extended_css":
                    writers.cosmetic_extended_css_jsonl.write(
                        json.dumps(parsed, ensure_ascii=False) + "\n",
                    )
                elif k == "extended_css_exception":
                    writers.cosmetic_extended_css_exception_jsonl.write(
                        json.dumps(parsed, ensure_ascii=False) + "\n",
                    )
                elif k == "html_filter":
                    writers.cosmetic_html_filter_jsonl.write(
                        json.dumps(parsed, ensure_ascii=False) + "\n",
                    )
                elif k == "html_filter_exception":
                    writers.cosmetic_html_filter_exception_jsonl.write(
                        json.dumps(parsed, ensure_ascii=False) + "\n",
                    )
                elif k == "scriptlet":
                    writers.cosmetic_scriptlet_jsonl.write(
                        json.dumps(parsed, ensure_ascii=False) + "\n",
                    )
                elif k == "scriptlet_exception":
                    writers.cosmetic_scriptlet_exception_jsonl.write(
                        json.dumps(parsed, ensure_ascii=False) + "\n",
                    )

                # Cosmetic scope and exception splits
                domains = parsed.get("domains") or []
                if domains:
                    writers.cosmetic_scoped_jsonl.write(
                        json.dumps(parsed, ensure_ascii=False) + "\n",
                    )
                else:
                    writers.cosmetic_global_jsonl.write(
                        json.dumps(parsed, ensure_ascii=False) + "\n",
                    )

                if is_cosmetic_exception:
                    writers.cosmetic_exception_jsonl.write(
                        json.dumps(parsed, ensure_ascii=False) + "\n",
                    )
                else:
                    writers.cosmetic_non_exception_jsonl.write(
                        json.dumps(parsed, ensure_ascii=False) + "\n",
                    )

                agg.cosmetic_rules_total += 1
                agg.cosmetic_rules_by_marker[parsed.get("marker") or "?"] = (
                    agg.cosmetic_rules_by_marker.get(
                        parsed.get("marker") or "?",
                        0,
                    )
                    + 1
                )
            continue

        # Network rules.
        is_exception = False
        if s.startswith("@@"):
            is_exception = True
            s = s[2:].strip()

        pattern, opts = _split_options(s)
        opt_tokens, opt_parsed = _parse_options(opts)
        if opts:
            network_with_opts += 1

        pattern_kind, extra = _classify_network_pattern(pattern)
        network_total += 1

        # Update aggregate stats.
        agg.network_rules_total += 1
        agg.network_rules_by_kind[pattern_kind] = (
            agg.network_rules_by_kind.get(pattern_kind, 0) + 1
        )
        if opts:
            agg.network_rules_with_options += 1
        if "domain" in opt_parsed:
            agg.network_rules_with_domain_opt += 1

        for k in opt_parsed:
            agg.option_key_counts[k] = agg.option_key_counts.get(k, 0) + 1

        for g in _option_groups(opt_parsed):
            agg.option_group_counts[g] = agg.option_group_counts.get(g, 0) + 1

        if pattern_kind not in {
            "absolute_url",
            "absolute_url_pattern",
            "domain_only",
            "host_anchored",
            "host_anchored_pattern",
            "left_anchored",
            "option_only",
            "regex",
            "right_anchored",
            "substring",
            "wildcard",
        }:
            network_other += 1

        # Persist full normalized rule for future use.
        rec: dict[str, Any] = {
            "kind": "network",
            "id": _rule_id(list_key, raw, exception=is_exception),
            "list_key": list_key,
            "action": "allow" if is_exception else "block",
            "exception": bool(is_exception),
            "raw": (raw or "").strip(),
            "pattern": pattern,
            "pattern_kind": pattern_kind,
            "options_raw": opts,
            "options": opt_parsed,
        }
        rec.update(_option_semantics(opt_tokens, opt_parsed))
        if extra:
            rec.update(extra)
        writers.network_jsonl.write(json.dumps(rec, ensure_ascii=False) + "\n")

        # Network exception split
        if is_exception:
            writers.network_exception_jsonl.write(
                json.dumps(rec, ensure_ascii=False) + "\n",
            )
        else:
            writers.network_block_jsonl.write(
                json.dumps(rec, ensure_ascii=False) + "\n",
            )

        # Options buckets
        if opts:
            writers.network_with_options_jsonl.write(
                json.dumps(rec, ensure_ascii=False) + "\n",
            )
        else:
            writers.network_no_options_jsonl.write(
                json.dumps(rec, ensure_ascii=False) + "\n",
            )

        groups = _option_groups(opt_parsed)
        if "domain" in groups:
            writers.network_option_domain_jsonl.write(
                json.dumps(rec, ensure_ascii=False) + "\n",
            )
        if "third_party" in groups:
            writers.network_option_third_party_jsonl.write(
                json.dumps(rec, ensure_ascii=False) + "\n",
            )
        if "type" in groups:
            writers.network_option_type_jsonl.write(
                json.dumps(rec, ensure_ascii=False) + "\n",
            )
        if "misc" in groups:
            writers.network_option_misc_jsonl.write(
                json.dumps(rec, ensure_ascii=False) + "\n",
            )

        # Pattern-kind buckets
        if pattern_kind == "domain_only":
            writers.network_kind_domain_only_jsonl.write(
                json.dumps(rec, ensure_ascii=False) + "\n",
            )
        elif pattern_kind in {
            "absolute_url",
            "absolute_url_pattern",
            "host_anchored",
            "host_anchored_pattern",
        }:
            writers.network_kind_host_anchored_jsonl.write(
                json.dumps(rec, ensure_ascii=False) + "\n",
            )
        elif pattern_kind == "left_anchored":
            writers.network_kind_left_anchored_jsonl.write(
                json.dumps(rec, ensure_ascii=False) + "\n",
            )
        elif pattern_kind == "regex":
            writers.network_kind_regex_jsonl.write(
                json.dumps(rec, ensure_ascii=False) + "\n",
            )
        elif pattern_kind == "wildcard":
            writers.network_kind_wildcard_jsonl.write(
                json.dumps(rec, ensure_ascii=False) + "\n",
            )
        else:
            writers.network_kind_substring_jsonl.write(
                json.dumps(rec, ensure_ascii=False) + "\n",
            )

        if pattern_kind == "domain_only":
            writers.request_index_domain_jsonl.write(
                json.dumps(rec, ensure_ascii=False) + "\n",
            )
        elif pattern_kind in {
            "absolute_url",
            "absolute_url_pattern",
            "host_anchored",
            "host_anchored_pattern",
        }:
            writers.request_index_host_jsonl.write(
                json.dumps(rec, ensure_ascii=False) + "\n",
            )
        elif pattern_kind == "regex":
            writers.request_index_regex_jsonl.write(
                json.dumps(rec, ensure_ascii=False) + "\n",
            )
        elif pattern_kind != "empty":
            writers.request_index_generic_jsonl.write(
                json.dumps(rec, ensure_ascii=False) + "\n",
            )

        # Resource-type buckets
        if opt_parsed:
            for t in _KNOWN_TYPES:
                if t in opt_parsed and t in writers.network_type_pos_jsonl:
                    writers.network_type_pos_jsonl[t].write(
                        json.dumps(rec, ensure_ascii=False) + "\n",
                    )
                neg = f"~{t}"
                if neg in opt_parsed and t in writers.network_type_neg_jsonl:
                    writers.network_type_neg_jsonl[t].write(
                        json.dumps(rec, ensure_ascii=False) + "\n",
                    )

    return {
        "total": total,
        "empty": empty,
        "comments": comments,
        "cosmetic": cosmetic,
        "network_other": network_other,
        "network_rules_total": network_total,
        "network_rules_with_options": network_with_opts,
    }


def _json_compact(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _literal_lookup_key(pattern: str) -> str:
    tokens = [
        token.strip(".")
        for token in re.findall(r"[A-Za-z0-9][A-Za-z0-9_.-]{2,}", pattern or "")
        if token.strip(".")
    ]
    if not tokens:
        return ""
    return max((token.lower() for token in tokens), key=lambda item: (len(item), item))


def _regex_lookup_key(pattern: str) -> str:
    if any(marker in (pattern or "") for marker in ("|", "?")) or "{0" in (
        pattern or ""
    ):
        return ""
    return _literal_lookup_key(pattern)


def _sqlite_scalar_values(value: Any) -> list[str]:
    if value is True:
        return ["1"]
    if value is False or value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if str(item or "").strip()]
    if isinstance(value, dict):
        return [_json_compact(value)]
    text = str(value or "").strip()
    return [text] if text else []


def _badfilter_disable_key(rec: dict[str, Any]) -> tuple[str, str, str]:
    options = dict(rec.get("options") or {})
    options.pop("badfilter", None)
    return (
        str(rec.get("action") or ""),
        str(rec.get("pattern") or ""),
        _json_compact(options),
    )


def _create_lookup_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        PRAGMA journal_mode=OFF;
        PRAGMA synchronous=OFF;
        PRAGMA temp_store=MEMORY;

        CREATE TABLE metadata(
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        ) WITHOUT ROWID;

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
            value_options_json TEXT NOT NULL,
            payload_json TEXT NOT NULL
        ) WITHOUT ROWID;

        CREATE TABLE domain_index(
            host TEXT NOT NULL,
            action TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            PRIMARY KEY(host, action, rule_id)
        ) WITHOUT ROWID;

        CREATE TABLE host_index(
            host TEXT NOT NULL,
            action TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            pattern_kind TEXT NOT NULL,
            url_scheme_pattern TEXT NOT NULL,
            path_pattern TEXT NOT NULL,
            query_pattern TEXT NOT NULL,
            suffix_separator_prefix INTEGER NOT NULL,
            suffix_separator_suffix INTEGER NOT NULL,
            PRIMARY KEY(host, action, rule_id)
        ) WITHOUT ROWID;

        CREATE TABLE host_pattern_index(
            host_pattern TEXT NOT NULL,
            action TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            pattern_kind TEXT NOT NULL,
            url_scheme_pattern TEXT NOT NULL,
            path_pattern TEXT NOT NULL,
            query_pattern TEXT NOT NULL,
            PRIMARY KEY(host_pattern, action, rule_id)
        ) WITHOUT ROWID;

        CREATE TABLE host_pattern_token_index(
            literal_key TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            PRIMARY KEY(literal_key, rule_id)
        ) WITHOUT ROWID;

        CREATE TABLE regex_index(
            action TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            regex TEXT NOT NULL,
            PRIMARY KEY(action, rule_id)
        ) WITHOUT ROWID;

        CREATE TABLE regex_token_index(
            literal_key TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            PRIMARY KEY(literal_key, rule_id)
        ) WITHOUT ROWID;

        CREATE TABLE generic_index(
            literal_key TEXT NOT NULL,
            pattern_kind TEXT NOT NULL,
            action TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            PRIMARY KEY(literal_key, pattern_kind, action, rule_id)
        ) WITHOUT ROWID;

        CREATE TABLE option_index(
            option_key TEXT NOT NULL,
            option_value TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            PRIMARY KEY(option_key, option_value, rule_id)
        ) WITHOUT ROWID;

        CREATE TABLE resource_type_index(
            resource_type TEXT NOT NULL,
            negated INTEGER NOT NULL,
            rule_id TEXT NOT NULL,
            PRIMARY KEY(resource_type, negated, rule_id)
        ) WITHOUT ROWID;

        CREATE TABLE domain_scope_index(
            domain TEXT NOT NULL,
            excluded INTEGER NOT NULL,
            pattern INTEGER NOT NULL,
            rule_id TEXT NOT NULL,
            PRIMARY KEY(domain, excluded, pattern, rule_id)
        ) WITHOUT ROWID;
        """
    )


def _create_lookup_indexes(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE INDEX idx_rules_kind_action ON rules(pattern_kind, action);
        CREATE INDEX idx_domain_action ON domain_index(action, host);
        CREATE INDEX idx_host_action ON host_index(action, host);
        CREATE INDEX idx_host_pattern_action ON host_pattern_index(action, host_pattern);
        CREATE INDEX idx_host_pattern_token_rule ON host_pattern_token_index(rule_id);
        CREATE INDEX idx_regex_action ON regex_index(action);
        CREATE INDEX idx_regex_token_rule ON regex_token_index(rule_id);
        CREATE INDEX idx_generic_kind_key ON generic_index(pattern_kind, literal_key);
        CREATE INDEX idx_option_key ON option_index(option_key, option_value);
        CREATE INDEX idx_resource_type ON resource_type_index(resource_type, negated);
        CREATE INDEX idx_domain_scope ON domain_scope_index(domain, excluded, pattern);
        """
    )


def _write_request_lookup_index(
    sqlite_path: str,
    network_jsonl_path: str,
) -> dict[str, int]:
    path = pathlib.Path(sqlite_path)
    path.parent.mkdir(exist_ok=True, parents=True)
    with suppress(FileNotFoundError):
        path.unlink()
    conn = sqlite3.connect(str(path))
    counts: dict[str, int] = {
        "rules": 0,
        "domain_index": 0,
        "host_index": 0,
        "host_pattern_index": 0,
        "host_pattern_token_index": 0,
        "regex_index": 0,
        "regex_token_index": 0,
        "generic_index": 0,
        "option_index": 0,
        "resource_type_index": 0,
        "domain_scope_index": 0,
    }
    try:
        _create_lookup_schema(conn)
        conn.execute(
            "INSERT INTO metadata(key, value) VALUES(?, ?)",
            ("schema_version", "4"),
        )
        conn.execute(
            "INSERT INTO metadata(key, value) VALUES(?, ?)",
            ("lookup_strategy", LOOKUP_STRATEGY),
        )
        with pathlib.Path(network_jsonl_path).open(
            encoding="utf-8",
            errors="replace",
        ) as handle:
            records = [json.loads(line) for line in handle if line.strip()]
        disabled_by_badfilter = {
            _badfilter_disable_key(rec)
            for rec in records
            if "badfilter" in set(rec.get("behavior_options") or [])
        }
        skipped_badfilter = 0
        with conn:
            for rec in records:
                if (
                    "badfilter" in set(rec.get("behavior_options") or [])
                    or _badfilter_disable_key(rec) in disabled_by_badfilter
                ):
                    skipped_badfilter += 1
                    continue
                rule_id = str(rec.get("id") or "")
                if not rule_id:
                    continue
                action = str(rec.get("action") or "")
                pattern_kind = str(rec.get("pattern_kind") or "")
                inserted = conn.execute(
                    """
                        INSERT OR IGNORE INTO rules(
                            rule_id, list_key, action, exception, pattern_kind, raw,
                            pattern, options_json, resource_types_json,
                            excluded_resource_types_json, third_party,
                            behavior_options_json, value_options_json, payload_json
                        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                    (
                        rule_id,
                        str(rec.get("list_key") or ""),
                        action,
                        1 if rec.get("exception") else 0,
                        pattern_kind,
                        str(rec.get("raw") or ""),
                        str(rec.get("pattern") or ""),
                        _json_compact(rec.get("options") or {}),
                        _json_compact(rec.get("resource_types") or []),
                        _json_compact(rec.get("excluded_resource_types") or []),
                        str(rec.get("third_party") or "any"),
                        _json_compact(rec.get("behavior_options") or []),
                        _json_compact(rec.get("value_options") or {}),
                        _json_compact(rec),
                    ),
                )
                if not inserted.rowcount:
                    continue
                counts["rules"] += 1

                if pattern_kind == "domain_only" and rec.get("host"):
                    conn.execute(
                        "INSERT OR IGNORE INTO domain_index(host, action, rule_id) VALUES(?, ?, ?)",
                        (str(rec.get("host") or ""), action, rule_id),
                    )
                    counts["domain_index"] += 1
                elif pattern_kind in {
                    "absolute_url",
                    "host_anchored",
                } and rec.get("host"):
                    conn.execute(
                        """
                            INSERT OR IGNORE INTO host_index(
                                host, action, rule_id, pattern_kind,
                                url_scheme_pattern, path_pattern, query_pattern,
                                suffix_separator_prefix, suffix_separator_suffix
                            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                        (
                            str(rec.get("host") or ""),
                            action,
                            rule_id,
                            pattern_kind,
                            str(rec.get("url_scheme_pattern") or ""),
                            str(rec.get("path_pattern") or ""),
                            str(rec.get("query_pattern") or ""),
                            1 if rec.get("suffix_separator_prefix") else 0,
                            1 if rec.get("suffix_separator_suffix") else 0,
                        ),
                    )
                    counts["host_index"] += 1
                elif pattern_kind in {
                    "absolute_url_pattern",
                    "host_anchored_pattern",
                } and rec.get("host_pattern"):
                    host_pattern = str(rec.get("host_pattern") or "")
                    conn.execute(
                        """
                            INSERT OR IGNORE INTO host_pattern_index(
                                host_pattern, action, rule_id, pattern_kind,
                                url_scheme_pattern, path_pattern, query_pattern
                            ) VALUES(?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            host_pattern,
                            action,
                            rule_id,
                            pattern_kind,
                            str(rec.get("url_scheme_pattern") or ""),
                            str(rec.get("path_pattern") or ""),
                            str(rec.get("query_pattern") or ""),
                        ),
                    )
                    counts["host_pattern_index"] += 1
                    conn.execute(
                        "INSERT OR IGNORE INTO host_pattern_token_index(literal_key, rule_id) VALUES(?, ?)",
                        (_literal_lookup_key(host_pattern), rule_id),
                    )
                    counts["host_pattern_token_index"] += 1
                elif pattern_kind == "regex":
                    regex = str(rec.get("regex") or "")
                    conn.execute(
                        "INSERT OR IGNORE INTO regex_index(action, rule_id, regex) VALUES(?, ?, ?)",
                        (action, rule_id, regex),
                    )
                    counts["regex_index"] += 1
                    conn.execute(
                        "INSERT OR IGNORE INTO regex_token_index(literal_key, rule_id) VALUES(?, ?)",
                        (_regex_lookup_key(regex), rule_id),
                    )
                    counts["regex_token_index"] += 1
                elif pattern_kind != "empty":
                    conn.execute(
                        """
                            INSERT OR IGNORE INTO generic_index(
                                literal_key, pattern_kind, action, rule_id
                            ) VALUES(?, ?, ?, ?)
                            """,
                        (
                            _literal_lookup_key(str(rec.get("pattern") or "")),
                            pattern_kind,
                            action,
                            rule_id,
                        ),
                    )
                    counts["generic_index"] += 1

                options = rec.get("options") or {}
                if isinstance(options, dict):
                    for key, value in options.items():
                        for item in _sqlite_scalar_values(value):
                            conn.execute(
                                "INSERT OR IGNORE INTO option_index(option_key, option_value, rule_id) VALUES(?, ?, ?)",
                                (str(key), item, rule_id),
                            )
                            counts["option_index"] += 1

                for resource_type in rec.get("resource_types") or []:
                    conn.execute(
                        "INSERT OR IGNORE INTO resource_type_index(resource_type, negated, rule_id) VALUES(?, 0, ?)",
                        (str(resource_type), rule_id),
                    )
                    counts["resource_type_index"] += 1
                for resource_type in rec.get("excluded_resource_types") or []:
                    conn.execute(
                        "INSERT OR IGNORE INTO resource_type_index(resource_type, negated, rule_id) VALUES(?, 1, ?)",
                        (str(resource_type), rule_id),
                    )
                    counts["resource_type_index"] += 1

                for domain in rec.get("domain_includes") or []:
                    conn.execute(
                        "INSERT OR IGNORE INTO domain_scope_index(domain, excluded, pattern, rule_id) VALUES(?, 0, 0, ?)",
                        (str(domain), rule_id),
                    )
                    counts["domain_scope_index"] += 1
                for domain in rec.get("domain_excludes") or []:
                    conn.execute(
                        "INSERT OR IGNORE INTO domain_scope_index(domain, excluded, pattern, rule_id) VALUES(?, 1, 0, ?)",
                        (str(domain), rule_id),
                    )
                    counts["domain_scope_index"] += 1
                for domain in rec.get("domain_include_patterns") or []:
                    conn.execute(
                        "INSERT OR IGNORE INTO domain_scope_index(domain, excluded, pattern, rule_id) VALUES(?, 0, 1, ?)",
                        (str(domain), rule_id),
                    )
                    counts["domain_scope_index"] += 1
                for domain in rec.get("domain_exclude_patterns") or []:
                    conn.execute(
                        "INSERT OR IGNORE INTO domain_scope_index(domain, excluded, pattern, rule_id) VALUES(?, 1, 1, ?)",
                        (str(domain), rule_id),
                    )
                    counts["domain_scope_index"] += 1

        _create_lookup_indexes(conn)
        count_queries = {
            "rules": "SELECT COUNT(*) FROM rules",
            "domain_index": "SELECT COUNT(*) FROM domain_index",
            "host_index": "SELECT COUNT(*) FROM host_index",
            "host_pattern_index": "SELECT COUNT(*) FROM host_pattern_index",
            "host_pattern_token_index": "SELECT COUNT(*) FROM host_pattern_token_index",
            "regex_index": "SELECT COUNT(*) FROM regex_index",
            "regex_token_index": "SELECT COUNT(*) FROM regex_token_index",
            "generic_index": "SELECT COUNT(*) FROM generic_index",
            "option_index": "SELECT COUNT(*) FROM option_index",
            "resource_type_index": "SELECT COUNT(*) FROM resource_type_index",
            "domain_scope_index": "SELECT COUNT(*) FROM domain_scope_index",
        }
        for table_name, query in count_queries.items():
            row = conn.execute(query).fetchone()
            counts[table_name] = int(row[0] or 0) if row else 0
        for key, value in sorted(counts.items()):
            conn.execute(
                "INSERT OR REPLACE INTO metadata(key, value) VALUES(?, ?)",
                (f"count_{key}", str(int(value))),
            )
        conn.execute(
            "INSERT OR REPLACE INTO metadata(key, value) VALUES(?, ?)",
            ("count_skipped_badfilter", str(int(skipped_badfilter))),
        )
        conn.execute("PRAGMA optimize")
        conn.commit()
    finally:
        conn.close()
    return counts


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Compile EasyList-style adblock lists into request lookup artifacts",
    )
    ap.add_argument(
        "--lists-dir",
        default="/var/lib/squid-flask-proxy/adblock/lists",
        help="Directory containing downloaded filter list files",
    )
    ap.add_argument(
        "--out-dir",
        default="/var/lib/squid-flask-proxy/adblock/compiled",
        help="Output directory for compiled buckets",
    )
    ap.add_argument(
        "--enabled-list",
        action="append",
        dest="enabled_lists",
        default=[],
        help=(
            "Subscription list key to compile. Repeat for multiple lists. "
            "When omitted, enabled lists are read from the configured database."
        ),
    )
    ns = ap.parse_args(argv)

    # Import AdblockStore from the app codebase.
    # This script lives in /app/tools; add /app to sys.path.
    if APP_ROOT_STR not in sys.path:
        sys.path.insert(0, APP_ROOT_STR)

    explicit_enabled_lists = [
        str(item).strip() for item in (ns.enabled_lists or []) if str(item).strip()
    ]
    enabled_paths: list[tuple[str, str]] = []
    if explicit_enabled_lists:
        seen: set[str] = set()
        for key in explicit_enabled_lists:
            if key in seen:
                continue
            seen.add(key)
            enabled_paths.append((key, _subscription_list_path(ns.lists_dir, key)))
    else:
        try:
            from services.adblock_store import AdblockStore  # type: ignore
        except Exception:
            return 2

        store = AdblockStore(lists_dir=str(ns.lists_dir))
        with suppress(Exception):
            store.init_db()

        try:
            for st in store.list_statuses():
                if not st.enabled:
                    continue
                enabled_paths.append((st.key, store.list_path(st.key)))
        except Exception:
            pass

    out_dir = str(ns.out_dir)
    pathlib.Path(out_dir).mkdir(exist_ok=True, parents=True)

    # Writers for full-rule extraction (JSONL keeps memory low).
    network_jsonl_path = os.path.join(out_dir, "network_rules.jsonl")
    cosmetic_jsonl_path = os.path.join(out_dir, "cosmetic_rules.jsonl")

    network_no_options_jsonl_path = os.path.join(out_dir, "network_no_options.jsonl")
    network_with_options_jsonl_path = os.path.join(
        out_dir,
        "network_with_options.jsonl",
    )
    network_option_domain_jsonl_path = os.path.join(
        out_dir,
        "network_option_domain.jsonl",
    )
    network_option_third_party_jsonl_path = os.path.join(
        out_dir,
        "network_option_third_party.jsonl",
    )
    network_option_type_jsonl_path = os.path.join(out_dir, "network_option_type.jsonl")
    network_option_misc_jsonl_path = os.path.join(out_dir, "network_option_misc.jsonl")

    network_kind_domain_only_jsonl_path = os.path.join(
        out_dir,
        "network_kind_domain_only.jsonl",
    )
    network_kind_host_anchored_jsonl_path = os.path.join(
        out_dir,
        "network_kind_host_anchored.jsonl",
    )
    network_kind_left_anchored_jsonl_path = os.path.join(
        out_dir,
        "network_kind_left_anchored.jsonl",
    )
    network_kind_substring_jsonl_path = os.path.join(
        out_dir,
        "network_kind_substring.jsonl",
    )
    network_kind_wildcard_jsonl_path = os.path.join(
        out_dir,
        "network_kind_wildcard.jsonl",
    )
    network_kind_regex_jsonl_path = os.path.join(out_dir, "network_kind_regex.jsonl")

    network_block_jsonl_path = os.path.join(out_dir, "network_block.jsonl")
    network_exception_jsonl_path = os.path.join(out_dir, "network_exception.jsonl")

    request_index_domain_jsonl_path = os.path.join(
        out_dir,
        "request_index_domain.jsonl",
    )
    request_index_host_jsonl_path = os.path.join(out_dir, "request_index_host.jsonl")
    request_index_regex_jsonl_path = os.path.join(out_dir, "request_index_regex.jsonl")
    request_index_generic_jsonl_path = os.path.join(
        out_dir,
        "request_index_generic.jsonl",
    )
    request_lookup_sqlite_path = os.path.join(out_dir, "request_lookup.sqlite")

    # Per-resource-type option buckets
    network_type_pos_paths: dict[str, str] = {
        t: os.path.join(out_dir, f"network_type_{t}.jsonl")
        for t in sorted(_KNOWN_TYPES)
    }
    network_type_neg_paths: dict[str, str] = {
        t: os.path.join(out_dir, f"network_type_not_{t}.jsonl")
        for t in sorted(_KNOWN_TYPES)
    }

    cosmetic_elemhide_jsonl_path = os.path.join(out_dir, "cosmetic_elemhide.jsonl")
    cosmetic_elemhide_exception_jsonl_path = os.path.join(
        out_dir,
        "cosmetic_elemhide_exception.jsonl",
    )
    cosmetic_extended_css_jsonl_path = os.path.join(
        out_dir,
        "cosmetic_extended_css.jsonl",
    )
    cosmetic_extended_css_exception_jsonl_path = os.path.join(
        out_dir,
        "cosmetic_extended_css_exception.jsonl",
    )
    cosmetic_html_filter_jsonl_path = os.path.join(
        out_dir, "cosmetic_html_filter.jsonl"
    )
    cosmetic_html_filter_exception_jsonl_path = os.path.join(
        out_dir,
        "cosmetic_html_filter_exception.jsonl",
    )
    cosmetic_scriptlet_jsonl_path = os.path.join(out_dir, "cosmetic_scriptlet.jsonl")
    cosmetic_scriptlet_exception_jsonl_path = os.path.join(
        out_dir,
        "cosmetic_scriptlet_exception.jsonl",
    )

    cosmetic_scoped_jsonl_path = os.path.join(out_dir, "cosmetic_scoped.jsonl")
    cosmetic_global_jsonl_path = os.path.join(out_dir, "cosmetic_global.jsonl")
    cosmetic_exception_jsonl_path = os.path.join(out_dir, "cosmetic_exception.jsonl")
    cosmetic_non_exception_jsonl_path = os.path.join(
        out_dir,
        "cosmetic_non_exception.jsonl",
    )

    agg = _Aggregate(
        network_rules_total=0,
        network_rules_by_kind={},
        network_rules_with_options=0,
        network_rules_with_domain_opt=0,
        cosmetic_rules_total=0,
        cosmetic_rules_by_marker={},
        option_key_counts={},
        option_group_counts={},
    )

    per_list_counts: dict[str, dict[str, int]] = {}

    with ExitStack() as stack:
        net_f = stack.enter_context(
            pathlib.Path(network_jsonl_path).open("w", encoding="utf-8", newline="\n"),
        )
        cos_f = stack.enter_context(
            pathlib.Path(cosmetic_jsonl_path).open("w", encoding="utf-8", newline="\n"),
        )
        net_no_opts_f = stack.enter_context(
            pathlib.Path(network_no_options_jsonl_path).open(
                "w",
                encoding="utf-8",
                newline="\n",
            ),
        )
        net_with_opts_f = stack.enter_context(
            pathlib.Path(network_with_options_jsonl_path).open(
                "w",
                encoding="utf-8",
                newline="\n",
            ),
        )
        net_opt_domain_f = stack.enter_context(
            pathlib.Path(network_option_domain_jsonl_path).open(
                "w",
                encoding="utf-8",
                newline="\n",
            ),
        )
        net_opt_third_party_f = stack.enter_context(
            pathlib.Path(network_option_third_party_jsonl_path).open(
                "w",
                encoding="utf-8",
                newline="\n",
            ),
        )
        net_opt_type_f = stack.enter_context(
            pathlib.Path(network_option_type_jsonl_path).open(
                "w",
                encoding="utf-8",
                newline="\n",
            ),
        )
        net_opt_misc_f = stack.enter_context(
            pathlib.Path(network_option_misc_jsonl_path).open(
                "w",
                encoding="utf-8",
                newline="\n",
            ),
        )

        net_kind_domain_only_f = stack.enter_context(
            pathlib.Path(network_kind_domain_only_jsonl_path).open(
                "w",
                encoding="utf-8",
                newline="\n",
            ),
        )
        net_kind_host_anchored_f = stack.enter_context(
            pathlib.Path(network_kind_host_anchored_jsonl_path).open(
                "w",
                encoding="utf-8",
                newline="\n",
            ),
        )
        net_kind_left_anchored_f = stack.enter_context(
            pathlib.Path(network_kind_left_anchored_jsonl_path).open(
                "w",
                encoding="utf-8",
                newline="\n",
            ),
        )
        net_kind_substring_f = stack.enter_context(
            pathlib.Path(network_kind_substring_jsonl_path).open(
                "w",
                encoding="utf-8",
                newline="\n",
            ),
        )
        net_kind_wildcard_f = stack.enter_context(
            pathlib.Path(network_kind_wildcard_jsonl_path).open(
                "w",
                encoding="utf-8",
                newline="\n",
            ),
        )
        net_kind_regex_f = stack.enter_context(
            pathlib.Path(network_kind_regex_jsonl_path).open(
                "w",
                encoding="utf-8",
                newline="\n",
            ),
        )

        net_block_f = stack.enter_context(
            pathlib.Path(network_block_jsonl_path).open(
                "w",
                encoding="utf-8",
                newline="\n",
            ),
        )
        net_exception_f = stack.enter_context(
            pathlib.Path(network_exception_jsonl_path).open(
                "w",
                encoding="utf-8",
                newline="\n",
            ),
        )

        request_index_domain_f = stack.enter_context(
            pathlib.Path(request_index_domain_jsonl_path).open(
                "w",
                encoding="utf-8",
                newline="\n",
            ),
        )
        request_index_host_f = stack.enter_context(
            pathlib.Path(request_index_host_jsonl_path).open(
                "w",
                encoding="utf-8",
                newline="\n",
            ),
        )
        request_index_regex_f = stack.enter_context(
            pathlib.Path(request_index_regex_jsonl_path).open(
                "w",
                encoding="utf-8",
                newline="\n",
            ),
        )
        request_index_generic_f = stack.enter_context(
            pathlib.Path(request_index_generic_jsonl_path).open(
                "w",
                encoding="utf-8",
                newline="\n",
            ),
        )

        net_type_pos_fs: dict[str, Any] = {
            t: stack.enter_context(
                pathlib.Path(p).open("w", encoding="utf-8", newline="\n"),
            )
            for t, p in network_type_pos_paths.items()
        }
        net_type_neg_fs: dict[str, Any] = {
            t: stack.enter_context(
                pathlib.Path(p).open("w", encoding="utf-8", newline="\n"),
            )
            for t, p in network_type_neg_paths.items()
        }

        cos_elemhide_f = stack.enter_context(
            pathlib.Path(cosmetic_elemhide_jsonl_path).open(
                "w",
                encoding="utf-8",
                newline="\n",
            ),
        )
        cos_elemhide_exception_f = stack.enter_context(
            pathlib.Path(cosmetic_elemhide_exception_jsonl_path).open(
                "w",
                encoding="utf-8",
                newline="\n",
            ),
        )
        cos_extended_css_f = stack.enter_context(
            pathlib.Path(cosmetic_extended_css_jsonl_path).open(
                "w",
                encoding="utf-8",
                newline="\n",
            ),
        )
        cos_extended_css_exception_f = stack.enter_context(
            pathlib.Path(cosmetic_extended_css_exception_jsonl_path).open(
                "w",
                encoding="utf-8",
                newline="\n",
            ),
        )
        cos_html_filter_f = stack.enter_context(
            pathlib.Path(cosmetic_html_filter_jsonl_path).open(
                "w",
                encoding="utf-8",
                newline="\n",
            ),
        )
        cos_html_filter_exception_f = stack.enter_context(
            pathlib.Path(cosmetic_html_filter_exception_jsonl_path).open(
                "w",
                encoding="utf-8",
                newline="\n",
            ),
        )
        cos_scriptlet_f = stack.enter_context(
            pathlib.Path(cosmetic_scriptlet_jsonl_path).open(
                "w",
                encoding="utf-8",
                newline="\n",
            ),
        )
        cos_scriptlet_exception_f = stack.enter_context(
            pathlib.Path(cosmetic_scriptlet_exception_jsonl_path).open(
                "w",
                encoding="utf-8",
                newline="\n",
            ),
        )

        cos_scoped_f = stack.enter_context(
            pathlib.Path(cosmetic_scoped_jsonl_path).open(
                "w",
                encoding="utf-8",
                newline="\n",
            ),
        )
        cos_global_f = stack.enter_context(
            pathlib.Path(cosmetic_global_jsonl_path).open(
                "w",
                encoding="utf-8",
                newline="\n",
            ),
        )
        cos_exception_f = stack.enter_context(
            pathlib.Path(cosmetic_exception_jsonl_path).open(
                "w",
                encoding="utf-8",
                newline="\n",
            ),
        )
        cos_non_exception_f = stack.enter_context(
            pathlib.Path(cosmetic_non_exception_jsonl_path).open(
                "w",
                encoding="utf-8",
                newline="\n",
            ),
        )

        writers = _RuleWriters(
            network_jsonl=net_f,
            cosmetic_jsonl=cos_f,
            network_no_options_jsonl=net_no_opts_f,
            network_with_options_jsonl=net_with_opts_f,
            network_option_domain_jsonl=net_opt_domain_f,
            network_option_third_party_jsonl=net_opt_third_party_f,
            network_option_type_jsonl=net_opt_type_f,
            network_option_misc_jsonl=net_opt_misc_f,
            network_kind_domain_only_jsonl=net_kind_domain_only_f,
            network_kind_host_anchored_jsonl=net_kind_host_anchored_f,
            network_kind_left_anchored_jsonl=net_kind_left_anchored_f,
            network_kind_substring_jsonl=net_kind_substring_f,
            network_kind_wildcard_jsonl=net_kind_wildcard_f,
            network_kind_regex_jsonl=net_kind_regex_f,
            network_block_jsonl=net_block_f,
            network_exception_jsonl=net_exception_f,
            request_index_domain_jsonl=request_index_domain_f,
            request_index_host_jsonl=request_index_host_f,
            request_index_regex_jsonl=request_index_regex_f,
            request_index_generic_jsonl=request_index_generic_f,
            network_type_pos_jsonl=net_type_pos_fs,
            network_type_neg_jsonl=net_type_neg_fs,
            cosmetic_elemhide_jsonl=cos_elemhide_f,
            cosmetic_elemhide_exception_jsonl=cos_elemhide_exception_f,
            cosmetic_extended_css_jsonl=cos_extended_css_f,
            cosmetic_extended_css_exception_jsonl=cos_extended_css_exception_f,
            cosmetic_html_filter_jsonl=cos_html_filter_f,
            cosmetic_html_filter_exception_jsonl=cos_html_filter_exception_f,
            cosmetic_scriptlet_jsonl=cos_scriptlet_f,
            cosmetic_scriptlet_exception_jsonl=cos_scriptlet_exception_f,
            cosmetic_scoped_jsonl=cos_scoped_f,
            cosmetic_global_jsonl=cos_global_f,
            cosmetic_exception_jsonl=cos_exception_f,
            cosmetic_non_exception_jsonl=cos_non_exception_f,
        )

        for key, path in enabled_paths:
            try:
                with pathlib.Path(path).open(encoding="utf-8", errors="replace") as f:
                    lines = f.read().splitlines()
            except FileNotFoundError:
                continue
            except Exception:
                continue

            per_list_counts[key] = _compile_and_extract_all(
                lines=lines,
                list_key=key,
                agg=agg,
                writers=writers,
            )

    lookup_index_counts = _write_request_lookup_index(
        request_lookup_sqlite_path,
        network_jsonl_path,
    )

    merged_counts = {
        "network_rules_total": int(agg.network_rules_total),
        "network_rules_with_options": int(agg.network_rules_with_options),
        "network_rules_with_domain_opt": int(agg.network_rules_with_domain_opt),
        "cosmetic_rules_total": int(agg.cosmetic_rules_total),
    }

    report = {
        "enabled_lists": [k for k, _ in enabled_paths if k in per_list_counts],
        "counts": merged_counts,
        "breakdowns": {
            "network_by_pattern_kind": dict(
                sorted(
                    agg.network_rules_by_kind.items(),
                    key=lambda kv: (-kv[1], kv[0]),
                ),
            ),
            "cosmetic_by_marker": dict(
                sorted(
                    agg.cosmetic_rules_by_marker.items(),
                    key=lambda kv: (-kv[1], kv[0]),
                ),
            ),
            "option_key_counts": dict(
                sorted(agg.option_key_counts.items(), key=lambda kv: (-kv[1], kv[0])),
            ),
            "option_group_counts": dict(
                sorted(agg.option_group_counts.items(), key=lambda kv: (-kv[1], kv[0])),
            ),
            "lookup_index_counts": lookup_index_counts,
        },
        "per_list": per_list_counts,
        "files": {
            "network_rules_jsonl": network_jsonl_path,
            "cosmetic_rules_jsonl": cosmetic_jsonl_path,
            "network_no_options_jsonl": os.path.join(
                out_dir,
                "network_no_options.jsonl",
            ),
            "network_with_options_jsonl": os.path.join(
                out_dir,
                "network_with_options.jsonl",
            ),
            "network_option_domain_jsonl": os.path.join(
                out_dir,
                "network_option_domain.jsonl",
            ),
            "network_option_third_party_jsonl": os.path.join(
                out_dir,
                "network_option_third_party.jsonl",
            ),
            "network_option_type_jsonl": os.path.join(
                out_dir,
                "network_option_type.jsonl",
            ),
            "network_option_misc_jsonl": os.path.join(
                out_dir,
                "network_option_misc.jsonl",
            ),
            "network_kind_domain_only_jsonl": os.path.join(
                out_dir,
                "network_kind_domain_only.jsonl",
            ),
            "network_kind_host_anchored_jsonl": os.path.join(
                out_dir,
                "network_kind_host_anchored.jsonl",
            ),
            "network_kind_left_anchored_jsonl": os.path.join(
                out_dir,
                "network_kind_left_anchored.jsonl",
            ),
            "network_kind_substring_jsonl": os.path.join(
                out_dir,
                "network_kind_substring.jsonl",
            ),
            "network_kind_wildcard_jsonl": os.path.join(
                out_dir,
                "network_kind_wildcard.jsonl",
            ),
            "network_kind_regex_jsonl": os.path.join(
                out_dir,
                "network_kind_regex.jsonl",
            ),
            "network_block_jsonl": os.path.join(out_dir, "network_block.jsonl"),
            "network_exception_jsonl": os.path.join(out_dir, "network_exception.jsonl"),
            "request_index_domain_jsonl": os.path.join(
                out_dir,
                "request_index_domain.jsonl",
            ),
            "request_index_host_jsonl": os.path.join(
                out_dir,
                "request_index_host.jsonl",
            ),
            "request_index_regex_jsonl": os.path.join(
                out_dir,
                "request_index_regex.jsonl",
            ),
            "request_index_generic_jsonl": os.path.join(
                out_dir,
                "request_index_generic.jsonl",
            ),
            "request_lookup_sqlite": request_lookup_sqlite_path,
            "cosmetic_elemhide_jsonl": os.path.join(out_dir, "cosmetic_elemhide.jsonl"),
            "cosmetic_elemhide_exception_jsonl": os.path.join(
                out_dir,
                "cosmetic_elemhide_exception.jsonl",
            ),
            "cosmetic_extended_css_jsonl": os.path.join(
                out_dir,
                "cosmetic_extended_css.jsonl",
            ),
            "cosmetic_extended_css_exception_jsonl": os.path.join(
                out_dir,
                "cosmetic_extended_css_exception.jsonl",
            ),
            "cosmetic_html_filter_jsonl": os.path.join(
                out_dir,
                "cosmetic_html_filter.jsonl",
            ),
            "cosmetic_html_filter_exception_jsonl": os.path.join(
                out_dir,
                "cosmetic_html_filter_exception.jsonl",
            ),
            "cosmetic_scriptlet_jsonl": os.path.join(
                out_dir,
                "cosmetic_scriptlet.jsonl",
            ),
            "cosmetic_scriptlet_exception_jsonl": os.path.join(
                out_dir,
                "cosmetic_scriptlet_exception.jsonl",
            ),
            "cosmetic_scoped_jsonl": os.path.join(out_dir, "cosmetic_scoped.jsonl"),
            "cosmetic_global_jsonl": os.path.join(out_dir, "cosmetic_global.jsonl"),
            "cosmetic_exception_jsonl": os.path.join(
                out_dir,
                "cosmetic_exception.jsonl",
            ),
            "cosmetic_non_exception_jsonl": os.path.join(
                out_dir,
                "cosmetic_non_exception.jsonl",
            ),
            "network_type": {
                "pos": {
                    t: os.path.join(out_dir, f"network_type_{t}.jsonl")
                    for t in sorted(_KNOWN_TYPES)
                },
                "neg": {
                    t: os.path.join(out_dir, f"network_type_not_{t}.jsonl")
                    for t in sorted(_KNOWN_TYPES)
                },
            },
        },
        "notes": {
            "full_extraction": "All parsed network rules and cosmetic rules are emitted to JSONL buckets for inspection and future expansion.",
            "request_indexes": "request_index_*.jsonl contains normalized request-time ABP fields for domain, host/path, regex, and generic buckets.",
            "request_lookup_sqlite": "request_lookup.sqlite is the fast lookup substrate: indexed domain suffix, exact host, host-pattern, regex, generic literal-key, option, resource-type, and domain-scope tables joined to full rule payloads by rule_id.",
        },
    }
    with pathlib.Path(os.path.join(out_dir, "report.json")).open(
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(report, f, indent=2, sort_keys=True)
        f.write("\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
