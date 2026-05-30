from __future__ import annotations

import fnmatch
import ipaddress
import re
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from functools import lru_cache
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from services.adblock_lookup import AdblockLookupIndex

if TYPE_CHECKING:
    from pathlib import Path

_ABP_SEPARATOR_RE = r"(?:[^A-Za-z0-9_.%-]|$)"
_RESOURCE_EXTENSIONS = {
    "font": {".eot", ".otf", ".ttf", ".woff", ".woff2"},
    "image": {
        ".apng",
        ".avif",
        ".bmp",
        ".gif",
        ".ico",
        ".jpeg",
        ".jpg",
        ".png",
        ".svg",
        ".webp",
    },
    "media": {".aac", ".avi", ".m4a", ".m4v", ".mov", ".mp3", ".mp4", ".ogg", ".webm"},
    "script": {".js", ".mjs"},
    "stylesheet": {".css"},
}
_NON_BLOCKING_MODIFIER_OPTIONS = {
    "csp",
    "header",
    "permissions",
    "redirect",
    "redirect-rule",
    "removeparam",
    "rewrite",
}
_COMMON_SECOND_LEVEL_PUBLIC_SUFFIXES = {"ac", "co", "com", "edu", "gov", "net", "org"}


@dataclass(frozen=True)
class AdblockDecision:
    blocked: bool
    rule_id: str = ""
    raw: str = ""
    action: str = "allow"
    reason: str = "no-match"
    list_key: str = ""


def _normalize_host(host: str) -> str:
    value = (host or "").strip().lower().rstrip(".")
    if not value:
        return ""
    if value.startswith("[") and "]" in value:
        return value.split("]", 1)[0] + "]"
    if ":" in value:
        value = value.split(":", 1)[0]
    try:
        return value.encode("idna").decode("ascii").lower().rstrip(".")
    except Exception:
        return value


def _host_matches(host: str, rule_host: str) -> bool:
    host = _normalize_host(host)
    rule_host = _normalize_host(rule_host)
    return bool(
        host and rule_host and (host == rule_host or host.endswith("." + rule_host))
    )


def _domain_matches(host: str, domain: str) -> bool:
    domain = (domain or "").strip().lower().rstrip(".")
    if not domain:
        return False
    if "*" in domain or domain.startswith("["):
        return fnmatch.fnmatchcase(_normalize_host(host), domain)
    return _host_matches(host, domain)


def _site_key(host: str) -> str:
    normalized = _normalize_host(host)
    if not normalized:
        return ""
    try:
        return ipaddress.ip_address(normalized.strip("[]")).compressed.lower()
    except ValueError:
        pass

    labels = [label for label in normalized.split(".") if label]
    if len(labels) < 2:
        return normalized
    if all(label.isdigit() for label in labels):
        return normalized
    try:  # pragma: no cover - optional dependency path
        from publicsuffix2 import get_sld  # type: ignore

        site = get_sld(normalized)
        if site:
            return site.lower().rstrip(".")
    except Exception:
        pass
    if (
        len(labels) >= 3
        and len(labels[-1]) == 2
        and labels[-2] in _COMMON_SECOND_LEVEL_PUBLIC_SUFFIXES
    ):
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _is_third_party(request_host: str, source_host: str) -> bool | None:
    request_site = _site_key(request_host)
    source_site = _site_key(source_host)
    if not request_site or not source_site:
        return None
    return request_site != source_site


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
            parts.append(_ABP_SEPARATOR_RE)
        else:
            parts.append(re.escape(ch))
    body = "".join(parts)
    if left_anchored:
        body = "^" + body
    if right_anchored:
        body += "$"
    return body


@lru_cache(maxsize=50000)
def _compile_regex(pattern: str, *, ignore_case: bool) -> re.Pattern[str] | None:
    try:
        flags = re.IGNORECASE if ignore_case else 0
        return re.compile(pattern, flags)
    except re.error:
        return None


def _unescape_abp_literal(pattern: str) -> str:
    return re.sub(r"\\(.)", r"\1", pattern or "")


def _request_suffix(parsed: Any) -> str:
    suffix = parsed.path or "/"
    if parsed.query:
        suffix += "?" + parsed.query
    if parsed.fragment:
        suffix += "#" + parsed.fragment
    return suffix


def infer_resource_type(
    method: str, url: str, headers: dict[str, str] | None = None
) -> str:
    headers = headers or {}
    normalized_method = (method or "").strip().upper()
    lower_headers = {str(k).lower(): str(v) for k, v in headers.items()}
    if lower_headers.get("upgrade", "").lower() == "websocket":
        return "websocket"

    fetch_dest = lower_headers.get("sec-fetch-dest", "").strip().lower()
    fetch_mode = lower_headers.get("sec-fetch-mode", "").strip().lower()
    fetch_dest_types = {
        "document": "document",
        "font": "font",
        "image": "image",
        "object": "object",
        "script": "script",
        "style": "stylesheet",
        "worker": "script",
    }
    if fetch_dest in fetch_dest_types:
        return fetch_dest_types[fetch_dest]
    if fetch_dest == "iframe":
        return "subdocument"
    if fetch_mode in {"cors", "same-origin"} and fetch_dest in {"", "empty"}:
        return "xmlhttprequest"
    if lower_headers.get("x-requested-with", "").lower() == "xmlhttprequest":
        return "xmlhttprequest"

    path = urlsplit(url or "").path.lower()
    for resource_type, extensions in _RESOURCE_EXTENSIONS.items():
        if any(path.endswith(ext) for ext in extensions):
            return resource_type

    accept = lower_headers.get("accept", "").lower()
    if "text/css" in accept:
        return "stylesheet"
    if "javascript" in accept or "ecmascript" in accept:
        return "script"
    if accept.startswith("image/") or "image/" in accept:
        return "image"
    if "text/html" in accept and normalized_method in {"GET", "HEAD"}:
        return "document"
    return "other"


def source_url_from_headers(headers: dict[str, str] | None) -> str:
    headers = headers or {}
    for key in ("referer", "referrer", "origin"):
        value = str(headers.get(key) or headers.get(key.title()) or "").strip()
        if value:
            return value
    return ""


class AdblockDecisionEngine:
    def __init__(
        self,
        db_path: str | Path,
        *,
        cache_ttl_seconds: int = 3600,
        cache_max: int = 200000,
        rule_cache_max: int = 50000,
    ) -> None:
        self.lookup = AdblockLookupIndex(db_path, rule_cache_max=rule_cache_max)
        self.cache_ttl_seconds = max(0, int(cache_ttl_seconds or 0))
        self.cache_max = max(0, int(cache_max or 0))
        self._cache: OrderedDict[
            tuple[str, str, str, str], tuple[float, AdblockDecision]
        ] = OrderedDict()
        self._cache_lock = threading.Lock()

    def decide(
        self,
        url: str,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        resource_type: str = "",
        source_url: str = "",
    ) -> AdblockDecision:
        headers = headers or {}
        effective_resource_type = (
            resource_type.strip().lower()
            if resource_type
            else infer_resource_type(method, url, headers)
        )
        effective_source_url = source_url or source_url_from_headers(headers)
        cache_key = (
            (method or "").strip().upper(),
            url or "",
            effective_resource_type,
            effective_source_url,
        )
        cached = self._get_cached(cache_key)
        if cached is not None:
            return cached

        candidates = self.lookup.candidate_rules(
            url,
            resource_type=effective_resource_type,
        )
        matches = [
            rule
            for rule in candidates
            if self._rule_matches(
                rule,
                url,
                method=method,
                resource_type=effective_resource_type,
                source_url=effective_source_url,
            )
        ]
        important_block = next(
            (
                rule
                for rule in matches
                if rule.get("action") == "block"
                and "important" in set(rule.get("behavior_options") or [])
            ),
            None,
        )
        if important_block is not None:
            decision = AdblockDecision(
                blocked=True,
                rule_id=str(
                    important_block.get("rule_id") or important_block.get("id") or "",
                ),
                raw=str(important_block.get("raw") or ""),
                action="block",
                reason="important-rule-match",
                list_key=str(important_block.get("list_key") or ""),
            )
        else:
            allow = next(
                (rule for rule in matches if rule.get("action") == "allow"),
                None,
            )
            if allow is not None:
                decision = AdblockDecision(
                    blocked=False,
                    rule_id=str(allow.get("rule_id") or allow.get("id") or ""),
                    raw=str(allow.get("raw") or ""),
                    action="allow",
                    reason="exception",
                    list_key=str(allow.get("list_key") or ""),
                )
            else:
                block = next(
                    (rule for rule in matches if rule.get("action") == "block"),
                    None,
                )
                decision = (
                    AdblockDecision(
                        blocked=True,
                        rule_id=str(block.get("rule_id") or block.get("id") or ""),
                        raw=str(block.get("raw") or ""),
                        action="block",
                        reason="rule-match",
                        list_key=str(block.get("list_key") or ""),
                    )
                    if block is not None
                    else AdblockDecision(blocked=False)
                )
        self._put_cached(cache_key, decision)
        return decision

    def _get_cached(
        self,
        key: tuple[str, str, str, str],
    ) -> AdblockDecision | None:
        if not self.cache_ttl_seconds or not self.cache_max:
            return None
        with self._cache_lock:
            hit = self._cache.get(key)
            if hit is None:
                return None
            expires_at, decision = hit
            if expires_at < time.time():
                self._cache.pop(key, None)
                return None
            self._cache.move_to_end(key)
            return decision

    def _put_cached(
        self,
        key: tuple[str, str, str, str],
        decision: AdblockDecision,
    ) -> None:
        if not self.cache_ttl_seconds or not self.cache_max:
            return
        with self._cache_lock:
            self._cache[key] = (time.time() + self.cache_ttl_seconds, decision)
            self._cache.move_to_end(key)
            while len(self._cache) > self.cache_max:
                self._cache.popitem(last=False)

    def _rule_matches(
        self,
        rule: dict[str, Any],
        url: str,
        *,
        method: str,
        resource_type: str,
        source_url: str,
    ) -> bool:
        parsed = urlsplit(url or "")
        request_host = _normalize_host(parsed.hostname or parsed.netloc or "")
        source_host = _normalize_host(urlsplit(source_url or "").hostname or "")
        if not self._options_match(
            rule,
            method=method,
            resource_type=resource_type,
            request_host=request_host,
            source_host=source_host,
        ):
            return False

        kind = str(rule.get("pattern_kind") or "")
        pattern = str(rule.get("pattern") or "")
        case_sensitive = "match-case" in set(rule.get("behavior_options") or [])
        if kind == "option_only":
            return True
        if kind == "domain_only":
            return _host_matches(request_host, str(rule.get("host") or ""))
        if kind in {"host_anchored", "absolute_url"}:
            if not _host_matches(request_host, str(rule.get("host") or "")):
                return False
            if kind == "absolute_url":
                scheme_pattern = str(rule.get("url_scheme_pattern") or "").lower()
                if scheme_pattern and not fnmatch.fnmatchcase(
                    parsed.scheme.lower(),
                    scheme_pattern,
                ):
                    return False
            return self._suffix_matches(
                rule,
                _request_suffix(parsed),
                case_sensitive=case_sensitive,
            )
        if kind in {"host_anchored_pattern", "absolute_url_pattern"}:
            compiled_regex = str(rule.get("compiled_regex") or "")
            compiled = _compile_regex(compiled_regex, ignore_case=not case_sensitive)
            return bool(compiled and compiled.search(url))
        if kind in {"left_anchored", "right_anchored", "wildcard"}:
            compiled_regex = str(rule.get("compiled_regex") or _abp_to_regex(pattern))
            compiled = _compile_regex(compiled_regex, ignore_case=not case_sensitive)
            return bool(compiled and compiled.search(url))
        if kind == "regex":
            compiled = _compile_regex(
                str(rule.get("regex") or pattern),
                ignore_case=not case_sensitive,
            )
            return bool(compiled and compiled.search(url))
        if kind == "substring":
            needle = _unescape_abp_literal(pattern)
            haystack = url or ""
            if not case_sensitive:
                needle = needle.lower()
                haystack = haystack.lower()
            return needle in haystack
        return False

    def _suffix_matches(
        self,
        rule: dict[str, Any],
        suffix: str,
        *,
        case_sensitive: bool = False,
    ) -> bool:
        raw_suffix = str(rule.get("suffix") or "")
        if not raw_suffix:
            return True
        suffix_regex = str(rule.get("suffix_regex") or "")
        if suffix_regex:
            compiled = _compile_regex(suffix_regex, ignore_case=not case_sensitive)
            return bool(compiled and compiled.match(suffix))
        expected = _unescape_abp_literal(
            str(rule.get("path_pattern") or "") + str(rule.get("query_pattern") or "")
        )
        haystack = suffix or ""
        if not case_sensitive:
            expected = expected.lower()
            haystack = haystack.lower()
        return bool(expected and haystack.startswith(expected))

    def _options_match(
        self,
        rule: dict[str, Any],
        *,
        method: str,
        resource_type: str,
        request_host: str,
        source_host: str,
    ) -> bool:
        method_values = (rule.get("value_options") or {}).get("method") or []
        if method_values and (method or "").strip().upper() not in {
            str(item).upper() for item in method_values
        }:
            return False

        resource_types = {str(item) for item in rule.get("resource_types") or []}
        excluded_resource_types = {
            str(item) for item in rule.get("excluded_resource_types") or []
        }
        if resource_types and resource_type not in resource_types:
            return False
        if excluded_resource_types and resource_type in excluded_resource_types:
            return False

        third_party = str(rule.get("third_party") or "any")
        third_party_state = _is_third_party(request_host, source_host)
        if third_party == "only" and third_party_state is not True:
            return False
        if third_party == "exclude" and third_party_state is True:
            return False

        if not self._domain_scope_matches(rule, source_host):
            return False

        denyallow = (rule.get("value_options") or {}).get("denyallow") or []
        if denyallow and any(
            _domain_matches(request_host, str(item)) for item in denyallow
        ):
            return False

        behavior_options = set(rule.get("behavior_options") or [])
        value_options = set((rule.get("value_options") or {}).keys())
        if "badfilter" in behavior_options:
            return False
        return not bool(value_options & _NON_BLOCKING_MODIFIER_OPTIONS)

    def _domain_scope_matches(self, rule: dict[str, Any], source_host: str) -> bool:
        includes = [str(item) for item in rule.get("domain_includes") or []]
        include_patterns = [
            str(item) for item in rule.get("domain_include_patterns") or []
        ]
        excludes = [str(item) for item in rule.get("domain_excludes") or []]
        exclude_patterns = [
            str(item) for item in rule.get("domain_exclude_patterns") or []
        ]
        if any(_domain_matches(source_host, item) for item in excludes):
            return False
        if any(
            fnmatch.fnmatchcase(_normalize_host(source_host), item)
            for item in exclude_patterns
        ):
            return False
        if includes or include_patterns:
            return any(_domain_matches(source_host, item) for item in includes) or any(
                fnmatch.fnmatchcase(_normalize_host(source_host), item)
                for item in include_patterns
            )
        return True
