#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from contextlib import ExitStack
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple


# ABP / EasyList parsing notes (minimal subset):
# - Comments start with '!'
# - Header line often: [Adblock Plus 2.0]
# - Cosmetic rules contain selector separators like '##', '#@#', '#?#', '#$#'
# - Exception rules start with '@@'
# - Options are appended after '$' (network rules); for first-pass we only trust no-option domain rules.


_COSMETIC_MARKERS = ("##", "#@#", "#?#", "#$#", "#%#")


@dataclass(frozen=True)
class CompileOutput:
    domains_block: Set[str]
    domains_allow: Set[str]
    regex_block: List[str]
    network_other: int
    cosmetic: int
    comments: int
    empty: int
    total: int


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

    # Network split by resource-type options (e.g., $script / $~script)
    network_type_pos_jsonl: Dict[str, Any]
    network_type_neg_jsonl: Dict[str, Any]

    # Cosmetic sub-buckets
    cosmetic_elemhide_jsonl: Any
    cosmetic_elemhide_exception_jsonl: Any
    cosmetic_extended_css_jsonl: Any
    cosmetic_scriptlet_jsonl: Any
    cosmetic_scriptlet_exception_jsonl: Any

    # Cosmetic splits
    cosmetic_scoped_jsonl: Any
    cosmetic_global_jsonl: Any
    cosmetic_exception_jsonl: Any
    cosmetic_non_exception_jsonl: Any


@dataclass
class _Aggregate:
    domains_block: Set[str]
    domains_allow: Set[str]
    regex_block: Set[str]
    regex_allow: Set[str]

    # Additional buckets for future use.
    network_rules_total: int
    network_rules_by_kind: Dict[str, int]
    network_rules_with_options: int
    network_rules_with_domain_opt: int
    cosmetic_rules_total: int
    cosmetic_rules_by_marker: Dict[str, int]
    option_key_counts: Dict[str, int]
    option_group_counts: Dict[str, int]


_HOST_RE = re.compile(r"^(?=.{1,255}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$", re.IGNORECASE)

_KNOWN_TYPES: Set[str] = {
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
    "websocket",
    "other",
}


_DOMAIN_ONLY_RE = re.compile(r"^\|\|(?P<host>[a-z0-9.-]+)\^?$", re.IGNORECASE)


def _is_comment_or_header(s: str) -> bool:
    t = (s or "").strip()
    if not t:
        return True
    if t.startswith("!"):
        return True
    if t.startswith("[") and t.endswith("]"):
        return True
    return False


def _is_cosmetic(s: str) -> bool:
    # Very conservative detection.
    for m in _COSMETIC_MARKERS:
        if m in s:
            return True
    return False


def _split_options(rule: str) -> Tuple[str, str]:
    # Split at first '$' (options suffix). ABP regex rules are like /.../ and may contain '$' inside.
    s = (rule or "").strip()
    if len(s) >= 3 and s.startswith("/") and s.endswith("/"):
        return s, ""
    if "$" not in s:
        return s, ""
    pat, opts = s.split("$", 1)
    return pat.strip(), opts.strip()


def _normalize_regex_for_cicap_table(pattern: str) -> str:
    """Normalize a regex so it can be used as a c-icap lookup-table key.

    The lookup table file parser treats ':' as a separator, so patterns like
    'https?:' must not contain a literal ':' character.

    c-icap is linked against PCRE2 in this image, so we can safely use '\x3A'.
    """

    p = (pattern or "").strip()
    if not p:
        return p
    # The lookup-table parser treats ':' as a separator and does not support
    # escaping it. Replace scheme/port ':' with a single-character wildcard.
    #
    # We do a targeted replacement for the common '://', then fall back to any
    # remaining ':' characters.
    p = p.replace(r":\/\/", r".\/\/")
    p = p.replace("://", ".//")
    return p.replace(":", ".")


def _parse_options(opts: str) -> Tuple[List[str], Dict[str, Any]]:
    raw = (opts or "").strip()
    if not raw:
        return [], {}

    tokens = [t.strip() for t in raw.split(",") if t.strip()]
    parsed: Dict[str, Any] = {}
    for t in tokens:
        if "=" in t:
            k, v = t.split("=", 1)
            k = k.strip().lower()
            v = v.strip()
            if k == "domain":
                # ABP domain=example.com|~foo.com
                parts = [p.strip() for p in v.split("|") if p.strip()]
                parsed[k] = parts
            else:
                parsed[k] = v
        else:
            # flags can be negated: ~third-party, ~script
            parsed[t.strip().lower()] = True
    return tokens, parsed


def _rule_id(list_key: str, raw_line: str, *, exception: bool) -> str:
    # Stable id for cross-bucket joins without parsing all JSONL files.
    h = hashlib.sha1()
    h.update((list_key or "").encode("utf-8", errors="ignore"))
    h.update(b"\n")
    h.update(b"1" if exception else b"0")
    h.update(b"\n")
    h.update((raw_line or "").strip().encode("utf-8", errors="ignore"))
    return h.hexdigest()


def _option_groups(opt_parsed: Dict[str, Any]) -> Set[str]:
    if not opt_parsed:
        return set()

    groups: Set[str] = set()
    if "domain" in opt_parsed:
        groups.add("domain")

    if "third-party" in opt_parsed or "~third-party" in opt_parsed:
        groups.add("third_party")

    type_hit = False
    for k in opt_parsed.keys():
        kk = (k or "").lower().lstrip("~")
        if kk in _KNOWN_TYPES:
            type_hit = True
            break
    if type_hit:
        groups.add("type")

    misc = False
    for k in opt_parsed.keys():
        kl = (k or "").lower()
        if kl == "domain" or kl in ("third-party", "~third-party"):
            continue
        if kl.lstrip("~") in _KNOWN_TYPES:
            continue
        misc = True
        break
    if misc:
        groups.add("misc")
    return groups


def _looks_like_host(s: str) -> bool:
    h = (s or "").strip().lower().rstrip(".")
    if not h or "." not in h:
        return False
    if ".." in h:
        return False
    return _HOST_RE.match(h) is not None


def _classify_network_pattern(pattern: str) -> Tuple[str, Dict[str, Any]]:
    # Returns (pattern_kind, extra_fields)
    p = (pattern or "").strip()
    if not p:
        return "empty", {}
    if len(p) >= 3 and p.startswith("/") and p.endswith("/"):
        return "regex", {"regex": p[1:-1]}
    if p.startswith("||"):
        # host-anchored. May include path.
        rest = p[2:]
        host = rest
        suffix = ""
        # Split host from first delimiter.
        for i, ch in enumerate(rest):
            if ch in ("/", "^", "?", "#"):
                host = rest[:i]
                suffix = rest[i:]
                break
        host = host.strip()
        if _looks_like_host(host):
            if suffix in ("", "^"):
                return "domain_only", {"host": host.lower().rstrip(".")}
            return "host_anchored", {"host": host.lower().rstrip("."), "suffix": suffix}
        return "host_anchored_other", {"host": host}
    if p.startswith("|"):
        return "left_anchored", {}
    if p.startswith("@@"):
        # Should have been stripped earlier; keep classification stable.
        return "exception_prefixed", {}
    # Generic substring/wildcard network rule.
    if any(ch in p for ch in ("*", "^")):
        return "wildcard", {}
    return "substring", {}


def _parse_cosmetic(rule: str) -> Optional[Dict[str, Any]]:
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
        domains: List[str] = []
        if left:
            domains = [d.strip().lower().lstrip(".") for d in left.split(",") if d.strip()]

        kind = "cosmetic"
        if marker == "##":
            kind = "elemhide"
        elif marker == "#@#":
            kind = "elemhide_exception"
        elif marker == "#?#":
            kind = "extended_css"
        elif marker == "#$#":
            kind = "scriptlet"
        elif marker == "#%#":
            kind = "scriptlet_exception"

        return {
            "kind": kind,
            "marker": marker,
            "domains": domains,
            "selector": right,
        }
    return None


def _extract_domain_only(pattern: str) -> Optional[str]:
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


def compile_lines(lines: Iterable[str]) -> CompileOutput:
    domains_block: Set[str] = set()
    domains_allow: Set[str] = set()
    regex_block: List[str] = []

    cosmetic = comments = empty = network_other = 0
    total = 0

    for raw in lines:
        total += 1
        s = (raw or "").strip()
        if not s:
            empty += 1
            continue

        if s.startswith("!") or (s.startswith("[") and s.endswith("]")):
            comments += 1
            continue

        if _is_cosmetic(s):
            cosmetic += 1
            continue

        is_exception = False
        if s.startswith("@@"):
            is_exception = True
            s = s[2:].strip()

        pattern, opts = _split_options(s)
        if opts:
            # For the first-pass domain buckets, ignore option-bearing rules.
            network_other += 1
            continue

        # Explicit regex rule.
        if len(pattern) >= 3 and pattern.startswith("/") and pattern.endswith("/"):
            if not is_exception:
                inner = _normalize_regex_for_cicap_table(pattern[1:-1])
                if inner:
                    regex_block.append(f"/{inner}/")
            else:
                # Exception regexes exist but are risky without full ABP semantics.
                network_other += 1
            continue

        dom = _extract_domain_only(pattern)
        if dom:
            if is_exception:
                domains_allow.add(dom)
            else:
                domains_block.add(dom)
            continue

        network_other += 1

    # Ensure exception overrides are represented (keep both; runtime will check allow first).
    return CompileOutput(
        domains_block=domains_block,
        domains_allow=domains_allow,
        regex_block=regex_block,
        network_other=network_other,
        cosmetic=cosmetic,
        comments=comments,
        empty=empty,
        total=total,
    )


def _compile_and_extract_all(
    *,
    lines: Iterable[str],
    list_key: str,
    agg: _Aggregate,
    writers: _RuleWriters,
) -> Dict[str, int]:
    # Single pass over a list file that:
    #  - preserves current “safe” buckets for c-icap
    #  - extracts every rule into JSONL buckets for future expansion
    # We build counts manually to avoid re-reading.
    domains_block: Set[str] = set()
    domains_allow: Set[str] = set()
    regex_block: Set[str] = set()
    regex_allow: Set[str] = set()

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
                is_cosmetic_exception = (parsed.get("kind") in ("elemhide_exception", "scriptlet_exception"))
                parsed["exception"] = bool(is_cosmetic_exception)
                parsed["id"] = _rule_id(list_key, s, exception=bool(is_cosmetic_exception))
                parsed["list_key"] = list_key
                parsed["raw"] = s
                writers.cosmetic_jsonl.write(json.dumps(parsed, ensure_ascii=False) + "\n")

                # Cosmetic sub-buckets
                k = parsed.get("kind") or "cosmetic"
                if k == "elemhide":
                    writers.cosmetic_elemhide_jsonl.write(json.dumps(parsed, ensure_ascii=False) + "\n")
                elif k == "elemhide_exception":
                    writers.cosmetic_elemhide_exception_jsonl.write(json.dumps(parsed, ensure_ascii=False) + "\n")
                elif k == "extended_css":
                    writers.cosmetic_extended_css_jsonl.write(json.dumps(parsed, ensure_ascii=False) + "\n")
                elif k == "scriptlet":
                    writers.cosmetic_scriptlet_jsonl.write(json.dumps(parsed, ensure_ascii=False) + "\n")
                elif k == "scriptlet_exception":
                    writers.cosmetic_scriptlet_exception_jsonl.write(json.dumps(parsed, ensure_ascii=False) + "\n")

                # Cosmetic scope and exception splits
                domains = parsed.get("domains") or []
                if domains:
                    writers.cosmetic_scoped_jsonl.write(json.dumps(parsed, ensure_ascii=False) + "\n")
                else:
                    writers.cosmetic_global_jsonl.write(json.dumps(parsed, ensure_ascii=False) + "\n")

                if is_cosmetic_exception:
                    writers.cosmetic_exception_jsonl.write(json.dumps(parsed, ensure_ascii=False) + "\n")
                else:
                    writers.cosmetic_non_exception_jsonl.write(json.dumps(parsed, ensure_ascii=False) + "\n")

                agg.cosmetic_rules_total += 1
                agg.cosmetic_rules_by_marker[parsed.get("marker") or "?"] = agg.cosmetic_rules_by_marker.get(
                    parsed.get("marker") or "?", 0
                ) + 1
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
        agg.network_rules_by_kind[pattern_kind] = agg.network_rules_by_kind.get(pattern_kind, 0) + 1
        if opts:
            agg.network_rules_with_options += 1
        if "domain" in opt_parsed:
            agg.network_rules_with_domain_opt += 1

        for k in opt_parsed.keys():
            agg.option_key_counts[k] = agg.option_key_counts.get(k, 0) + 1

        for g in _option_groups(opt_parsed):
            agg.option_group_counts[g] = agg.option_group_counts.get(g, 0) + 1

        # Preserve current safe c-icap buckets.
        if not opts:
            if pattern_kind == "regex":
                regex = (extra.get("regex") or "").strip()
                if regex:
                    regex = _normalize_regex_for_cicap_table(regex)
                    regex = f"/{regex}/"
                    if is_exception:
                        regex_allow.add(regex)
                    else:
                        regex_block.add(regex)
            elif pattern_kind == "domain_only":
                host = (extra.get("host") or "").strip().lower().rstrip(".")
                if host:
                    if is_exception:
                        domains_allow.add(host)
                    else:
                        domains_block.add(host)
            else:
                network_other += 1
        else:
            network_other += 1

        # Persist full normalized rule for future use.
        rec: Dict[str, Any] = {
            "kind": "network",
            "id": _rule_id(list_key, raw, exception=is_exception),
            "list_key": list_key,
            "exception": bool(is_exception),
            "raw": (raw or "").strip(),
            "pattern": pattern,
            "pattern_kind": pattern_kind,
            "options_raw": opts,
            "options": opt_parsed,
        }
        if extra:
            rec.update(extra)
        writers.network_jsonl.write(json.dumps(rec, ensure_ascii=False) + "\n")

        # Network exception split
        if is_exception:
            writers.network_exception_jsonl.write(json.dumps(rec, ensure_ascii=False) + "\n")
        else:
            writers.network_block_jsonl.write(json.dumps(rec, ensure_ascii=False) + "\n")

        # Options buckets
        if opts:
            writers.network_with_options_jsonl.write(json.dumps(rec, ensure_ascii=False) + "\n")
        else:
            writers.network_no_options_jsonl.write(json.dumps(rec, ensure_ascii=False) + "\n")

        groups = _option_groups(opt_parsed)
        if "domain" in groups:
            writers.network_option_domain_jsonl.write(json.dumps(rec, ensure_ascii=False) + "\n")
        if "third_party" in groups:
            writers.network_option_third_party_jsonl.write(json.dumps(rec, ensure_ascii=False) + "\n")
        if "type" in groups:
            writers.network_option_type_jsonl.write(json.dumps(rec, ensure_ascii=False) + "\n")
        if "misc" in groups:
            writers.network_option_misc_jsonl.write(json.dumps(rec, ensure_ascii=False) + "\n")

        # Pattern-kind buckets
        if pattern_kind == "domain_only":
            writers.network_kind_domain_only_jsonl.write(json.dumps(rec, ensure_ascii=False) + "\n")
        elif pattern_kind in ("host_anchored", "host_anchored_other"):
            writers.network_kind_host_anchored_jsonl.write(json.dumps(rec, ensure_ascii=False) + "\n")
        elif pattern_kind == "left_anchored":
            writers.network_kind_left_anchored_jsonl.write(json.dumps(rec, ensure_ascii=False) + "\n")
        elif pattern_kind == "regex":
            writers.network_kind_regex_jsonl.write(json.dumps(rec, ensure_ascii=False) + "\n")
        elif pattern_kind == "wildcard":
            writers.network_kind_wildcard_jsonl.write(json.dumps(rec, ensure_ascii=False) + "\n")
        else:
            writers.network_kind_substring_jsonl.write(json.dumps(rec, ensure_ascii=False) + "\n")

        # Resource-type buckets
        if opt_parsed:
            for t in _KNOWN_TYPES:
                if t in opt_parsed and t in writers.network_type_pos_jsonl:
                    writers.network_type_pos_jsonl[t].write(json.dumps(rec, ensure_ascii=False) + "\n")
                neg = f"~{t}"
                if neg in opt_parsed and t in writers.network_type_neg_jsonl:
                    writers.network_type_neg_jsonl[t].write(json.dumps(rec, ensure_ascii=False) + "\n")

    # Merge into aggregate.
    agg.domains_allow.update(domains_allow)
    agg.domains_block.update(domains_block)
    agg.regex_block.update(regex_block)
    agg.regex_allow.update(regex_allow)

    return {
        "total": total,
        "empty": empty,
        "comments": comments,
        "cosmetic": cosmetic,
        "network_other": network_other,
        "domains_block": len(domains_block),
        "domains_allow": len(domains_allow),
        "regex_block": len(regex_block),
        "regex_allow": len(regex_allow),
        "network_rules_total": network_total,
        "network_rules_with_options": network_with_opts,
    }


def _write_sorted_lines(path: str, items: Iterable[str]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        for s in sorted(set(items)):
            f.write(s)
            f.write("\n")


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Compile EasyList-style adblock lists into c-icap friendly buckets")
    ap.add_argument(
        "--db",
        default="/var/lib/squid-flask-proxy/adblock.db",
        help="Path to adblock SQLite DB (used to discover enabled lists)",
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
    ns = ap.parse_args(argv)

    # Import AdblockStore from the app codebase.
    # This script lives in /app/tools; add /app to sys.path.
    here = os.path.abspath(os.path.dirname(__file__))
    app_root = os.path.abspath(os.path.join(here, ".."))
    if app_root not in sys.path:
        sys.path.insert(0, app_root)

    try:
        from services.adblock_store import AdblockStore  # type: ignore
    except Exception as e:
        print(f"[adblock_compile] failed to import AdblockStore: {e}", file=sys.stderr)
        return 2

    store = AdblockStore(db_path=str(ns.db), lists_dir=str(ns.lists_dir))
    try:
        store.init_db()
    except Exception:
        pass

    enabled_paths: List[Tuple[str, str]] = []
    try:
        for st in store.list_statuses():
            if not st.enabled:
                continue
            enabled_paths.append((st.key, store.list_path(st.key)))
    except Exception as e:
        print(f"[adblock_compile] failed to read list statuses: {e}", file=sys.stderr)

    out_dir = str(ns.out_dir)
    os.makedirs(out_dir, exist_ok=True)

    # Writers for full-rule extraction (JSONL keeps memory low).
    network_jsonl_path = os.path.join(out_dir, "network_rules.jsonl")
    cosmetic_jsonl_path = os.path.join(out_dir, "cosmetic_rules.jsonl")

    network_no_options_jsonl_path = os.path.join(out_dir, "network_no_options.jsonl")
    network_with_options_jsonl_path = os.path.join(out_dir, "network_with_options.jsonl")
    network_option_domain_jsonl_path = os.path.join(out_dir, "network_option_domain.jsonl")
    network_option_third_party_jsonl_path = os.path.join(out_dir, "network_option_third_party.jsonl")
    network_option_type_jsonl_path = os.path.join(out_dir, "network_option_type.jsonl")
    network_option_misc_jsonl_path = os.path.join(out_dir, "network_option_misc.jsonl")

    network_kind_domain_only_jsonl_path = os.path.join(out_dir, "network_kind_domain_only.jsonl")
    network_kind_host_anchored_jsonl_path = os.path.join(out_dir, "network_kind_host_anchored.jsonl")
    network_kind_left_anchored_jsonl_path = os.path.join(out_dir, "network_kind_left_anchored.jsonl")
    network_kind_substring_jsonl_path = os.path.join(out_dir, "network_kind_substring.jsonl")
    network_kind_wildcard_jsonl_path = os.path.join(out_dir, "network_kind_wildcard.jsonl")
    network_kind_regex_jsonl_path = os.path.join(out_dir, "network_kind_regex.jsonl")

    network_block_jsonl_path = os.path.join(out_dir, "network_block.jsonl")
    network_exception_jsonl_path = os.path.join(out_dir, "network_exception.jsonl")

    # Per-resource-type option buckets
    network_type_pos_paths: Dict[str, str] = {t: os.path.join(out_dir, f"network_type_{t}.jsonl") for t in sorted(_KNOWN_TYPES)}
    network_type_neg_paths: Dict[str, str] = {t: os.path.join(out_dir, f"network_type_not_{t}.jsonl") for t in sorted(_KNOWN_TYPES)}

    cosmetic_elemhide_jsonl_path = os.path.join(out_dir, "cosmetic_elemhide.jsonl")
    cosmetic_elemhide_exception_jsonl_path = os.path.join(out_dir, "cosmetic_elemhide_exception.jsonl")
    cosmetic_extended_css_jsonl_path = os.path.join(out_dir, "cosmetic_extended_css.jsonl")
    cosmetic_scriptlet_jsonl_path = os.path.join(out_dir, "cosmetic_scriptlet.jsonl")
    cosmetic_scriptlet_exception_jsonl_path = os.path.join(out_dir, "cosmetic_scriptlet_exception.jsonl")

    cosmetic_scoped_jsonl_path = os.path.join(out_dir, "cosmetic_scoped.jsonl")
    cosmetic_global_jsonl_path = os.path.join(out_dir, "cosmetic_global.jsonl")
    cosmetic_exception_jsonl_path = os.path.join(out_dir, "cosmetic_exception.jsonl")
    cosmetic_non_exception_jsonl_path = os.path.join(out_dir, "cosmetic_non_exception.jsonl")

    agg = _Aggregate(
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

    per_list_counts: Dict[str, Dict[str, int]] = {}

    with ExitStack() as stack:
        net_f = stack.enter_context(open(network_jsonl_path, "w", encoding="utf-8", newline="\n"))
        cos_f = stack.enter_context(open(cosmetic_jsonl_path, "w", encoding="utf-8", newline="\n"))
        net_no_opts_f = stack.enter_context(open(network_no_options_jsonl_path, "w", encoding="utf-8", newline="\n"))
        net_with_opts_f = stack.enter_context(open(network_with_options_jsonl_path, "w", encoding="utf-8", newline="\n"))
        net_opt_domain_f = stack.enter_context(open(network_option_domain_jsonl_path, "w", encoding="utf-8", newline="\n"))
        net_opt_third_party_f = stack.enter_context(open(network_option_third_party_jsonl_path, "w", encoding="utf-8", newline="\n"))
        net_opt_type_f = stack.enter_context(open(network_option_type_jsonl_path, "w", encoding="utf-8", newline="\n"))
        net_opt_misc_f = stack.enter_context(open(network_option_misc_jsonl_path, "w", encoding="utf-8", newline="\n"))

        net_kind_domain_only_f = stack.enter_context(open(network_kind_domain_only_jsonl_path, "w", encoding="utf-8", newline="\n"))
        net_kind_host_anchored_f = stack.enter_context(open(network_kind_host_anchored_jsonl_path, "w", encoding="utf-8", newline="\n"))
        net_kind_left_anchored_f = stack.enter_context(open(network_kind_left_anchored_jsonl_path, "w", encoding="utf-8", newline="\n"))
        net_kind_substring_f = stack.enter_context(open(network_kind_substring_jsonl_path, "w", encoding="utf-8", newline="\n"))
        net_kind_wildcard_f = stack.enter_context(open(network_kind_wildcard_jsonl_path, "w", encoding="utf-8", newline="\n"))
        net_kind_regex_f = stack.enter_context(open(network_kind_regex_jsonl_path, "w", encoding="utf-8", newline="\n"))

        net_block_f = stack.enter_context(open(network_block_jsonl_path, "w", encoding="utf-8", newline="\n"))
        net_exception_f = stack.enter_context(open(network_exception_jsonl_path, "w", encoding="utf-8", newline="\n"))

        net_type_pos_fs: Dict[str, Any] = {t: stack.enter_context(open(p, "w", encoding="utf-8", newline="\n")) for t, p in network_type_pos_paths.items()}
        net_type_neg_fs: Dict[str, Any] = {t: stack.enter_context(open(p, "w", encoding="utf-8", newline="\n")) for t, p in network_type_neg_paths.items()}

        cos_elemhide_f = stack.enter_context(open(cosmetic_elemhide_jsonl_path, "w", encoding="utf-8", newline="\n"))
        cos_elemhide_exception_f = stack.enter_context(open(cosmetic_elemhide_exception_jsonl_path, "w", encoding="utf-8", newline="\n"))
        cos_extended_css_f = stack.enter_context(open(cosmetic_extended_css_jsonl_path, "w", encoding="utf-8", newline="\n"))
        cos_scriptlet_f = stack.enter_context(open(cosmetic_scriptlet_jsonl_path, "w", encoding="utf-8", newline="\n"))
        cos_scriptlet_exception_f = stack.enter_context(open(cosmetic_scriptlet_exception_jsonl_path, "w", encoding="utf-8", newline="\n"))

        cos_scoped_f = stack.enter_context(open(cosmetic_scoped_jsonl_path, "w", encoding="utf-8", newline="\n"))
        cos_global_f = stack.enter_context(open(cosmetic_global_jsonl_path, "w", encoding="utf-8", newline="\n"))
        cos_exception_f = stack.enter_context(open(cosmetic_exception_jsonl_path, "w", encoding="utf-8", newline="\n"))
        cos_non_exception_f = stack.enter_context(open(cosmetic_non_exception_jsonl_path, "w", encoding="utf-8", newline="\n"))

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
            network_type_pos_jsonl=net_type_pos_fs,
            network_type_neg_jsonl=net_type_neg_fs,
            cosmetic_elemhide_jsonl=cos_elemhide_f,
            cosmetic_elemhide_exception_jsonl=cos_elemhide_exception_f,
            cosmetic_extended_css_jsonl=cos_extended_css_f,
            cosmetic_scriptlet_jsonl=cos_scriptlet_f,
            cosmetic_scriptlet_exception_jsonl=cos_scriptlet_exception_f,

            cosmetic_scoped_jsonl=cos_scoped_f,
            cosmetic_global_jsonl=cos_global_f,
            cosmetic_exception_jsonl=cos_exception_f,
            cosmetic_non_exception_jsonl=cos_non_exception_f,
        )

        for key, path in enabled_paths:
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    lines = f.read().splitlines()
            except FileNotFoundError:
                continue
            except Exception as e:
                print(f"[adblock_compile] failed reading {key} at {path}: {e}", file=sys.stderr)
                continue

            per_list_counts[key] = _compile_and_extract_all(lines=lines, list_key=key, agg=agg, writers=writers)

    # Preserve current c-icap buckets.
    _write_sorted_lines(os.path.join(out_dir, "domains_allow.txt"), agg.domains_allow)
    _write_sorted_lines(os.path.join(out_dir, "domains_block.txt"), agg.domains_block)
    _write_sorted_lines(os.path.join(out_dir, "regex_block.txt"), agg.regex_block)
    _write_sorted_lines(os.path.join(out_dir, "regex_allow.txt"), agg.regex_allow)

    merged_counts = {
        "domains_allow": len(agg.domains_allow),
        "domains_block": len(agg.domains_block),
        "regex_block": len(agg.regex_block),
        "regex_allow": len(agg.regex_allow),
        "network_rules_total": int(agg.network_rules_total),
        "network_rules_with_options": int(agg.network_rules_with_options),
        "network_rules_with_domain_opt": int(agg.network_rules_with_domain_opt),
        "cosmetic_rules_total": int(agg.cosmetic_rules_total),
    }

    report = {
        "enabled_lists": [k for k, _ in enabled_paths],
        "counts": merged_counts,
        "breakdowns": {
            "network_by_pattern_kind": dict(sorted(agg.network_rules_by_kind.items(), key=lambda kv: (-kv[1], kv[0]))),
            "cosmetic_by_marker": dict(sorted(agg.cosmetic_rules_by_marker.items(), key=lambda kv: (-kv[1], kv[0]))),
            "option_key_counts": dict(sorted(agg.option_key_counts.items(), key=lambda kv: (-kv[1], kv[0]))),
            "option_group_counts": dict(sorted(agg.option_group_counts.items(), key=lambda kv: (-kv[1], kv[0]))),
        },
        "per_list": per_list_counts,
        "files": {
            "domains_allow": os.path.join(out_dir, "domains_allow.txt"),
            "domains_block": os.path.join(out_dir, "domains_block.txt"),
            "regex_block": os.path.join(out_dir, "regex_block.txt"),
            "regex_allow": os.path.join(out_dir, "regex_allow.txt"),
            "network_rules_jsonl": network_jsonl_path,
            "cosmetic_rules_jsonl": cosmetic_jsonl_path,
            "network_no_options_jsonl": os.path.join(out_dir, "network_no_options.jsonl"),
            "network_with_options_jsonl": os.path.join(out_dir, "network_with_options.jsonl"),
            "network_option_domain_jsonl": os.path.join(out_dir, "network_option_domain.jsonl"),
            "network_option_third_party_jsonl": os.path.join(out_dir, "network_option_third_party.jsonl"),
            "network_option_type_jsonl": os.path.join(out_dir, "network_option_type.jsonl"),
            "network_option_misc_jsonl": os.path.join(out_dir, "network_option_misc.jsonl"),
            "network_kind_domain_only_jsonl": os.path.join(out_dir, "network_kind_domain_only.jsonl"),
            "network_kind_host_anchored_jsonl": os.path.join(out_dir, "network_kind_host_anchored.jsonl"),
            "network_kind_left_anchored_jsonl": os.path.join(out_dir, "network_kind_left_anchored.jsonl"),
            "network_kind_substring_jsonl": os.path.join(out_dir, "network_kind_substring.jsonl"),
            "network_kind_wildcard_jsonl": os.path.join(out_dir, "network_kind_wildcard.jsonl"),
            "network_kind_regex_jsonl": os.path.join(out_dir, "network_kind_regex.jsonl"),

            "network_block_jsonl": os.path.join(out_dir, "network_block.jsonl"),
            "network_exception_jsonl": os.path.join(out_dir, "network_exception.jsonl"),
            "cosmetic_elemhide_jsonl": os.path.join(out_dir, "cosmetic_elemhide.jsonl"),
            "cosmetic_elemhide_exception_jsonl": os.path.join(out_dir, "cosmetic_elemhide_exception.jsonl"),
            "cosmetic_extended_css_jsonl": os.path.join(out_dir, "cosmetic_extended_css.jsonl"),
            "cosmetic_scriptlet_jsonl": os.path.join(out_dir, "cosmetic_scriptlet.jsonl"),
            "cosmetic_scriptlet_exception_jsonl": os.path.join(out_dir, "cosmetic_scriptlet_exception.jsonl"),

            "cosmetic_scoped_jsonl": os.path.join(out_dir, "cosmetic_scoped.jsonl"),
            "cosmetic_global_jsonl": os.path.join(out_dir, "cosmetic_global.jsonl"),
            "cosmetic_exception_jsonl": os.path.join(out_dir, "cosmetic_exception.jsonl"),
            "cosmetic_non_exception_jsonl": os.path.join(out_dir, "cosmetic_non_exception.jsonl"),

            "network_type": {
                "pos": {t: os.path.join(out_dir, f"network_type_{t}.jsonl") for t in sorted(_KNOWN_TYPES)},
                "neg": {t: os.path.join(out_dir, f"network_type_not_{t}.jsonl") for t in sorted(_KNOWN_TYPES)},
            },
        },
        "notes": {
            "domain_buckets_policy": "Only option-less domain-only rules (||host^) and their @@ exceptions are promoted to domains_*.txt for c-icap.",
            "full_extraction": "All parsed network rules and cosmetic rules are emitted to JSONL buckets for future REQMOD/RESPMOD expansion.",
        },
    }
    with open(os.path.join(out_dir, "report.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, sort_keys=True)
        f.write("\n")

    print(
        f"[adblock_compile] compiled: allow={len(agg.domains_allow)} block={len(agg.domains_block)} regex_block={len(agg.regex_block)} regex_allow={len(agg.regex_allow)} network_total={agg.network_rules_total} cosmetic_total={agg.cosmetic_rules_total}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
