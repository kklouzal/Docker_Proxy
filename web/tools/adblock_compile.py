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
from contextlib import suppress
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

HERE = pathlib.Path(__file__).resolve().parent
APP_ROOT = pathlib.Path(os.path.join(HERE, "..")).resolve()
APP_ROOT_STR = str(APP_ROOT)
if APP_ROOT_STR not in sys.path:
    sys.path.insert(0, APP_ROOT_STR)

from services.adblock_hosts import (  # ruff: ignore[module-import-not-at-top-of-file]
    looks_like_adblock_host as _looks_like_host,
)
from services.adblock_hosts import (  # ruff: ignore[module-import-not-at-top-of-file]
    normalize_adblock_host as _normalize_host,
)
from services.adblock_lookup import (  # ruff: ignore[module-import-not-at-top-of-file]
    LOOKUP_SCHEMA_VERSION,
)
from services.adblock_patterns import (  # ruff: ignore[module-import-not-at-top-of-file]
    abp_host_anchored_to_regex as _abp_host_anchored_to_regex,
)
from services.adblock_patterns import (  # ruff: ignore[module-import-not-at-top-of-file]
    abp_suffix_to_regex as _abp_suffix_to_regex,
)
from services.adblock_patterns import abp_to_regex as _abp_to_regex  # ruff: ignore[module-import-not-at-top-of-file]

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

# ABP / EasyList parsing notes (minimal subset):
# - Comments start with '!'
# - Header line often: [Adblock Plus 2.0]
# - Cosmetic rules contain selector separators like '##', '#@#', '#?#', '#$#'
# - Exception rules start with '@@'
# - Options are appended after '$' (network rules). Network rules are parsed
#   straight into the SQLite request lookup; cosmetic rules are only counted
#   (the ICAP helper filters requests, it does not rewrite pages).


_COSMETIC_MARKERS = ("#@?#", "#@$#", "#@%#", "#@#", "#?#", "#$#", "#%#", "##")


@dataclass
class _Aggregate:
    network_rules_total: int = 0
    network_rules_by_kind: dict[str, int] = field(default_factory=dict)
    network_rules_with_options: int = 0
    network_rules_with_domain_opt: int = 0
    cosmetic_rules_total: int = 0
    cosmetic_rules_by_marker: dict[str, int] = field(default_factory=dict)
    option_key_counts: dict[str, int] = field(default_factory=dict)
    option_group_counts: dict[str, int] = field(default_factory=dict)


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

# uBlock Origin option aliases, mapped to the canonical ABP option they mean.
# Negating an alias negates its canonical option (``~1p`` -> ``third-party``).
_OPTION_ALIASES: dict[str, str] = {
    "1p": "~third-party",
    "3p": "third-party",
    "beacon": "ping",
    "css": "stylesheet",
    "doc": "document",
    "ehide": "elemhide",
    "first-party": "~third-party",
    "frame": "subdocument",
    "from": "domain",
    "ghide": "generichide",
    "xhr": "xmlhttprequest",
}

_ALL_KNOWN_OPTIONS = (
    _KNOWN_TYPES
    | _VALUE_OPTIONS
    | _BEHAVIOR_OPTIONS
    | {"third-party", "~third-party"}
    | {f"~{item}" for item in _KNOWN_TYPES}
    | {f"~{item}" for item in _BEHAVIOR_OPTIONS}
    | set(_OPTION_ALIASES)
    | {f"~{item}" for item in _OPTION_ALIASES}
)


def _canonical_option_key(key: str) -> str:
    negated = key.startswith("~")
    base = key[1:] if negated else key
    canonical = _OPTION_ALIASES.get(base)
    if canonical is None:
        return key
    if not negated:
        return canonical
    return canonical[1:] if canonical.startswith("~") else f"~{canonical}"


LOOKUP_INDEX_COUNT_TABLES = (
    "rules",
    "domain_index",
    "host_index",
    "host_pattern_index",
    "host_pattern_token_index",
    "regex_index",
    "regex_token_index",
    "generic_index",
    "option_index",
    "resource_type_index",
    "domain_scope_index",
)
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
            k = _canonical_option_key(k.strip().lower())
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
            parsed[_canonical_option_key(t.strip().lower())] = True
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
    # Stable id: identical list lines keep their id across rebuilds.
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


def _host_pattern_to_regex(host_pattern: str) -> str:
    host = (host_pattern or "").strip().lower().rstrip(".")
    if not host:
        return ""
    return _abp_to_regex(host)


def _suffix_fields(suffix: str) -> dict[str, Any]:
    suffix_right_anchored = suffix.endswith("|")
    suffix_body = suffix[:-1] if suffix_right_anchored else suffix
    return {
        "suffix": suffix,
        "suffix_body": suffix_body,
        "suffix_right_anchored": suffix_right_anchored,
        "suffix_regex": _abp_suffix_to_regex(suffix),
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
        if raw_host.startswith("["):
            bracket_end = raw_host.find("]")
            if bracket_end >= 0 and raw_host[bracket_end + 1 :].startswith(":"):
                host = raw_host[: bracket_end + 1]
                suffix = raw_host[bracket_end + 1 :] + suffix
        elif raw_host.count(":") == 1:
            host, port_suffix = raw_host.split(":", 1)
            suffix = ":" + port_suffix + suffix
        host_pattern = host
        if "*" in host_pattern:
            star_index = host_pattern.find("*")
            prefix = host_pattern[:star_index]
            normalized_prefix = _normalize_host(prefix)
            if (
                prefix
                and not prefix.endswith(".")
                and _looks_like_host(normalized_prefix)
            ):
                host = normalized_prefix
                suffix = host_pattern[star_index:] + suffix
        host = _normalize_host(host)
        suffix_fields = _suffix_fields(suffix)
        if _looks_like_host(host):
            if suffix in {"", "^"}:
                return "domain_only", {"host": host, "anchor": "domain"}
            return "host_anchored", {
                "host": host,
                "anchor": "domain",
                "compiled_regex": _abp_host_anchored_to_regex(host, suffix),
                **suffix_fields,
            }
        normalized_pattern = _normalize_host(host_pattern)
        return "host_anchored_pattern", {
            "host": host,
            "host_pattern": normalized_pattern,
            "host_pattern_regex": _host_pattern_to_regex(normalized_pattern),
            "anchor": "domain_pattern",
            "compiled_regex": _abp_host_anchored_to_regex(
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


def _cosmetic_marker(rule: str) -> str:
    return next(marker for marker in _COSMETIC_MARKERS if marker in rule)


def _split_network_rule(s: str) -> tuple[bool, str, str]:
    """Return (exception, pattern, options) for a stripped network rule line."""
    is_exception = s.startswith("@@")
    if is_exception:
        s = s[2:].strip()
    pattern, opts = _split_options(s)
    return is_exception, pattern, opts


def _badfilter_disabled_keys(
    sources: list[tuple[str, list[str]]],
) -> set[tuple[str, str, str]]:
    """Rules named by a ``$badfilter`` rule in any enabled list."""
    disabled: set[tuple[str, str, str]] = set()
    for _list_key, lines in sources:
        for raw in lines:
            s = (raw or "").strip()
            if "badfilter" not in s or _is_comment_or_header(s) or _is_cosmetic(s):
                continue
            is_exception, pattern, opts = _split_network_rule(s)
            _, opt_parsed = _parse_options(opts)
            if "badfilter" in opt_parsed:
                disabled.add(
                    _badfilter_disable_key(
                        {
                            "action": "allow" if is_exception else "block",
                            "pattern": pattern,
                            "options": opt_parsed,
                        },
                    ),
                )
    return disabled


def _compile_and_extract_all(
    *,
    lines: Iterable[str],
    list_key: str,
    agg: _Aggregate,
    add_network_rule: Callable[[dict[str, Any]], None],
) -> dict[str, int]:
    """Parse one list, passing each normalized network rule to ``add_network_rule``."""
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
        if _is_comment_or_header(s):
            comments += 1
            continue

        if _is_cosmetic(s):
            cosmetic += 1
            marker = _cosmetic_marker(s)
            agg.cosmetic_rules_total += 1
            agg.cosmetic_rules_by_marker[marker] = (
                agg.cosmetic_rules_by_marker.get(marker, 0) + 1
            )
            continue

        is_exception, pattern, opts = _split_network_rule(s)
        opt_tokens, opt_parsed = _parse_options(opts)
        if opts:
            network_with_opts += 1

        pattern_kind, extra = _classify_network_pattern(pattern)
        network_total += 1

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
        add_network_rule(rec)

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
        CREATE INDEX idx_resource_type_rule ON resource_type_index(rule_id);
        CREATE INDEX idx_domain_scope ON domain_scope_index(domain, excluded, pattern);
        """
    )


# Matcher fields of a rule that have no rules-table column (adblock_decision
# reads them from the candidate rule). Empty values are omitted: every reader
# treats a missing field as empty. "id" lets older readers, which ignore a
# payload naming another rule, keep using these artifacts.
_RULE_PAYLOAD_FIELDS = (
    "id",
    "host",
    "compiled_regex",
    "suffix",
    "regex",
    "misc_options",
    "domain_includes",
    "domain_excludes",
    "domain_include_patterns",
    "domain_exclude_patterns",
)


def _rule_match_payload(rec: dict[str, Any]) -> dict[str, Any]:
    return {key: rec[key] for key in _RULE_PAYLOAD_FIELDS if rec.get(key)}


def _insert_lookup_rule(
    conn: sqlite3.Connection,
    rec: dict[str, Any],
    counts: dict[str, int],
) -> None:
    rule_id = str(rec.get("id") or "")
    if not rule_id:
        return
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
            _json_compact(_rule_match_payload(rec)),
        ),
    )
    if not inserted.rowcount:
        return
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


def _write_request_lookup_index(
    sqlite_path: str,
    sources: list[tuple[str, list[str]]],
    agg: _Aggregate,
) -> tuple[dict[str, dict[str, int]], dict[str, int]]:
    """Compile ``(list_key, lines)`` sources straight into the lookup database.

    Rules stream into SQLite in source order (deterministic file bytes);
    ``$badfilter`` targets are collected from every source first. Returns the
    per-list parse counts and the lookup table counts.
    """
    path = pathlib.Path(sqlite_path)
    path.parent.mkdir(exist_ok=True, parents=True)
    with suppress(FileNotFoundError):
        path.unlink()
    conn = sqlite3.connect(str(path))
    counts: dict[str, int] = dict.fromkeys(LOOKUP_INDEX_COUNT_TABLES, 0)
    per_list_counts: dict[str, dict[str, int]] = {}
    try:
        _create_lookup_schema(conn)
        conn.execute(
            "INSERT INTO metadata(key, value) VALUES(?, ?)",
            ("schema_version", LOOKUP_SCHEMA_VERSION),
        )
        conn.execute(
            "INSERT INTO metadata(key, value) VALUES(?, ?)",
            ("lookup_strategy", LOOKUP_STRATEGY),
        )
        disabled_by_badfilter = _badfilter_disabled_keys(sources)
        skipped_badfilter = 0

        def add_network_rule(rec: dict[str, Any]) -> None:
            nonlocal skipped_badfilter
            if (
                "badfilter" in set(rec.get("behavior_options") or [])
                or _badfilter_disable_key(rec) in disabled_by_badfilter
            ):
                skipped_badfilter += 1
                return
            _insert_lookup_rule(conn, rec, counts)

        with conn:
            for list_key, lines in sources:
                per_list_counts[list_key] = _compile_and_extract_all(
                    lines=lines,
                    list_key=list_key,
                    agg=agg,
                    add_network_rule=add_network_rule,
                )

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
        # Rules arrive in source order but are keyed by a hash, which leaves
        # half-full B-tree pages; rebuilding packs them (deterministically,
        # -9% file size). A file temp store keeps the rebuild out of memory.
        conn.execute("PRAGMA temp_store=FILE")
        conn.execute("VACUUM")
    finally:
        conn.close()
    return per_list_counts, counts


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
        try:
            store.init_db()
            enabled_paths.extend(
                (st.key, store.list_path(st.key))
                for st in store.list_statuses()
                if st.enabled
            )
        except Exception as exc:
            # Compiling without the enabled-list catalog would replace the
            # compiled rules with an empty artifact.
            sys.stderr.write(f"adblock_compile: cannot read enabled lists: {exc}\n")
            return 1

    out_dir = str(ns.out_dir)
    pathlib.Path(out_dir).mkdir(exist_ok=True, parents=True)

    sources: list[tuple[str, list[str]]] = []
    for key, path in enabled_paths:
        try:
            with pathlib.Path(path).open(encoding="utf-8", errors="replace") as f:
                sources.append((key, f.read().splitlines()))
        except FileNotFoundError:
            # A database-enabled list that was never downloaded has no rules
            # yet; it is omitted from report.enabled_lists. Lists named
            # explicitly were selected because they have local content.
            if not explicit_enabled_lists:
                continue
            sys.stderr.write(f"adblock_compile: list {key!r} not found: {path}\n")
            return 1
        except OSError as exc:
            sys.stderr.write(f"adblock_compile: cannot read list {key!r}: {exc}\n")
            return 1

    agg = _Aggregate()
    per_list_counts, lookup_index_counts = _write_request_lookup_index(
        os.path.join(out_dir, "request_lookup.sqlite"),
        sources,
        agg,
    )

    merged_counts = {
        "network_rules_total": int(agg.network_rules_total),
        "network_rules_with_options": int(agg.network_rules_with_options),
        "network_rules_with_domain_opt": int(agg.network_rules_with_domain_opt),
        "cosmetic_rules_total": int(agg.cosmetic_rules_total),
    }

    # report.json is part of the published artifact and its SHA-256: it names
    # artifact-relative files only, so identical inputs produce an identical
    # artifact and revision reuse works.
    report = {
        "lookup_schema_version": LOOKUP_SCHEMA_VERSION,
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
        "files": {"request_lookup_sqlite": "request_lookup.sqlite"},
        "notes": {
            "request_lookup_sqlite": "request_lookup.sqlite is the fast lookup substrate: indexed domain suffix, exact host, host-pattern, regex, generic literal-key, option, resource-type, and domain-scope tables joined to the rules table by rule_id.",
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
