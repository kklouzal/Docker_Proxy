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

from services.adblock_hosts import adblock_host_suffix_candidates
from services.adblock_hosts import normalize_adblock_host as _normalize_host
from services.adblock_hosts import safe_adblock_urlsplit as _safe_urlsplit
from services.adblock_lookup import AdblockLookupIndex
from services.adblock_patterns import (
    abp_host_anchored_to_regex as _abp_host_anchored_to_regex,
)
from services.adblock_patterns import abp_to_regex as _abp_to_regex
from services.domain_normalization import registrable_domain_start

if TYPE_CHECKING:
    from pathlib import Path

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
    "elemhide",
    "genericblock",
    "generichide",
    "header",
    "jsinject",
    "permissions",
    "redirect",
    "redirect-rule",
    "removeparam",
    "rewrite",
    "specifichide",
}
# uBO's method= option is limited to the DNR request-method set.
SUPPORTED_REQUEST_METHODS = frozenset(
    {
        "DELETE",
        "GET",
        "HEAD",
        "OPTIONS",
        "PATCH",
        "POST",
        "PUT",
    },
)


@dataclass(frozen=True)
class AdblockDecision:
    blocked: bool
    rule_id: str = ""
    raw: str = ""
    action: str = "allow"
    reason: str = "no-match"
    list_key: str = ""


@dataclass(frozen=True)
class _RequestContext:
    """Per-request facts shared by every candidate rule evaluation."""

    url: str
    method: str
    resource_type: str
    request_host: str
    request_suffixes: frozenset[str]
    source_host: str
    source_suffixes: frozenset[str]
    third_party: bool | None


@lru_cache(maxsize=16384)
def _normalized_rule_host(value: str) -> str:
    return _normalize_host(value)


def _host_suffix_set(normalized_host: str) -> frozenset[str]:
    return frozenset(adblock_host_suffix_candidates(normalized_host))


def _domain_matches(host: str, suffixes: frozenset[str], domain: str) -> bool:
    domain = (domain or "").strip().lower().rstrip(".")
    if not domain:
        return False
    if "*" in domain:
        return fnmatch.fnmatchcase(host, domain)
    # Bracketed IPv6 literals are exact hosts, never fnmatch character classes.
    normalized = _normalized_rule_host(domain)
    return bool(normalized) and normalized in suffixes


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
    return ".".join(labels[registrable_domain_start(labels) :])


def _is_third_party(request_host: str, source_host: str) -> bool | None:
    request_site = _site_key(request_host)
    source_site = _site_key(source_host)
    if not request_site or not source_site:
        return None
    return request_site != source_site


def _normalize_method(method: Any) -> str:
    return str(method or "").strip().upper()


def _header_value(headers: dict[str, str], key: str) -> str:
    key_lower = key.lower()
    for candidate, value in headers.items():
        if str(candidate).lower() == key_lower:
            return str(value).strip()
    return ""


@lru_cache(maxsize=50000)
def _compile_regex(pattern: str, *, ignore_case: bool) -> re.Pattern[str] | None:
    try:
        flags = re.IGNORECASE if ignore_case else 0
        return re.compile(pattern, flags)
    except re.error:
        return None


def _unescape_abp_literal(pattern: str) -> str:
    return re.sub(r"\\(.)", r"\1", pattern or "")


def infer_resource_type(
    method: str, url: str, headers: dict[str, str] | None = None
) -> str:
    headers = headers or {}
    normalized_method = _normalize_method(method)
    lower_headers = {str(k).lower(): str(v) for k, v in headers.items()}
    if lower_headers.get("upgrade", "").lower() == "websocket":
        return "websocket"

    fetch_dest = lower_headers.get("sec-fetch-dest", "").strip().lower()
    fetch_mode = lower_headers.get("sec-fetch-mode", "").strip().lower()
    fetch_dest_types = {
        "audio": "media",
        "document": "document",
        "embed": "object",
        "font": "font",
        "image": "image",
        "object": "object",
        "track": "media",
        "script": "script",
        "style": "stylesheet",
        "video": "media",
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
    if lower_headers.get("ping-to") or lower_headers.get("ping-from"):
        return "ping"

    parsed = _safe_urlsplit(url)
    path = (parsed.path if parsed is not None else "").lower()
    for resource_type, extensions in _RESOURCE_EXTENSIONS.items():
        if any(path.endswith(ext) for ext in extensions):
            return resource_type

    accept = lower_headers.get("accept", "").lower()
    content_type = lower_headers.get("content-type", "").lower()
    if "text/ping" in content_type or (
        "ping" in content_type and normalized_method == "POST"
    ):
        return "ping"
    if "text/css" in accept:
        return "stylesheet"
    if "javascript" in accept or "ecmascript" in accept:
        return "script"
    if accept.startswith("image/") or "image/" in accept:
        return "image"
    if accept.startswith(("audio/", "video/")):
        return "media"
    if "font/" in accept:
        return "font"
    if normalized_method not in {"GET", "HEAD"} and (
        "json" in accept or "xml" in accept
    ):
        return "xmlhttprequest"
    if "text/html" in accept and normalized_method in {"GET", "HEAD"}:
        return "document"
    return "other"


def source_url_from_headers(headers: dict[str, str] | None) -> str:
    headers = headers or {}
    for key in ("referer", "referrer", "origin"):
        value = _header_value(headers, key)
        if value:
            return value
    return ""


def third_party_hint_from_headers(headers: dict[str, str] | None) -> bool | None:
    headers = headers or {}
    fetch_site = _header_value(headers, "sec-fetch-site").lower()
    if fetch_site == "cross-site":
        return True
    if fetch_site in {"same-origin", "same-site", "none"}:
        return False
    return None


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
            tuple[str, str, str, str, str], tuple[float, AdblockDecision]
        ] = OrderedDict()
        self._cache_lock = threading.Lock()

    def close_thread_connection(self) -> None:
        self.lookup.close_thread_connection()

    def close(self) -> None:
        self.lookup.close()
        with self._cache_lock:
            self._cache.clear()

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
        effective_third_party_hint = third_party_hint_from_headers(headers)
        cache_key = (
            _normalize_method(method),
            url or "",
            effective_resource_type,
            effective_source_url,
            str(effective_third_party_hint),
        )
        cached = self._get_cached(cache_key)
        if cached is not None:
            return cached

        context = self._request_context(
            url,
            method=method,
            resource_type=effective_resource_type,
            source_url=effective_source_url,
            third_party_hint=effective_third_party_hint,
        )
        if context is None:
            decision = AdblockDecision(blocked=False)
            self._put_cached(cache_key, decision)
            return decision

        candidates = self.lookup.candidate_rules(
            url,
            resource_type=effective_resource_type,
        )
        matches = [rule for rule in candidates if self._rule_matches(rule, context)]
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
        key: tuple[str, str, str, str, str],
    ) -> AdblockDecision | None:
        if not self.cache_ttl_seconds or not self.cache_max:
            return None
        with self._cache_lock:
            hit = self._cache.get(key)
            if hit is None:
                return None
            expires_at, decision = hit
            if expires_at < time.monotonic():
                self._cache.pop(key, None)
                return None
            self._cache.move_to_end(key)
            return decision

    def _put_cached(
        self,
        key: tuple[str, str, str, str, str],
        decision: AdblockDecision,
    ) -> None:
        if not self.cache_ttl_seconds or not self.cache_max:
            return
        with self._cache_lock:
            self._cache[key] = (time.monotonic() + self.cache_ttl_seconds, decision)
            self._cache.move_to_end(key)
            while len(self._cache) > self.cache_max:
                self._cache.popitem(last=False)

    @staticmethod
    def _request_context(
        url: str,
        *,
        method: str,
        resource_type: str,
        source_url: str,
        third_party_hint: bool | None,
    ) -> _RequestContext | None:
        parsed = _safe_urlsplit(url)
        if parsed is None:
            return None
        request_host = _normalize_host(parsed.hostname or "")
        source_parsed = _safe_urlsplit(source_url)
        source_host = _normalize_host(
            source_parsed.hostname if source_parsed is not None else "",
        )
        third_party = _is_third_party(request_host, source_host)
        if third_party is None and third_party_hint is not None:
            third_party = bool(third_party_hint)
        return _RequestContext(
            url=url,
            method=_normalize_method(method),
            resource_type=resource_type,
            request_host=request_host,
            request_suffixes=_host_suffix_set(request_host),
            source_host=source_host,
            source_suffixes=_host_suffix_set(source_host),
            third_party=third_party,
        )

    def _rule_matches(self, rule: dict[str, Any], context: _RequestContext) -> bool:
        if not self._options_match(rule, context):
            return False

        url = context.url
        kind = str(rule.get("pattern_kind") or "")
        pattern = str(rule.get("pattern") or "")
        case_sensitive = "match-case" in set(rule.get("behavior_options") or [])
        if kind == "option_only":
            return True
        if kind == "domain_only":
            return _domain_matches(
                context.request_host,
                context.request_suffixes,
                str(rule.get("host") or ""),
            )
        if kind == "absolute_url":
            compiled_regex = str(rule.get("compiled_regex") or _abp_to_regex(pattern))
            compiled = _compile_regex(compiled_regex, ignore_case=not case_sensitive)
            return bool(compiled and compiled.search(url))
        if kind == "host_anchored":
            if not _domain_matches(
                context.request_host,
                context.request_suffixes,
                str(rule.get("host") or ""),
            ):
                return False
            compiled_regex = str(
                rule.get("compiled_regex")
                or _abp_host_anchored_to_regex(
                    str(rule.get("host") or ""),
                    str(rule.get("suffix") or ""),
                )
            )
            compiled = _compile_regex(compiled_regex, ignore_case=not case_sensitive)
            return bool(compiled and compiled.search(url))
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

    def _options_match(self, rule: dict[str, Any], context: _RequestContext) -> bool:
        value_options = rule.get("value_options") or {}
        if not isinstance(value_options, dict):
            return False
        if "method" in value_options:
            method_values = value_options["method"]
            # An explicitly present but malformed method= must not become an
            # unrestricted rule merely because it has no usable values.
            if not isinstance(method_values, list) or not method_values:
                return False
            included_methods: set[str] = set()
            excluded_methods: set[str] = set()
            for item in method_values:
                option_value = str(item or "").strip().upper()
                excluded = option_value.startswith("~")
                option_method = option_value[1:] if excluded else option_value
                if option_method not in SUPPORTED_REQUEST_METHODS:
                    return False
                target = excluded_methods if excluded else included_methods
                target.add(option_method)

            request_method = context.method
            if request_method not in SUPPORTED_REQUEST_METHODS:
                return False
            if included_methods and request_method not in included_methods:
                return False
            if request_method in excluded_methods:
                return False

        resource_types = {str(item) for item in rule.get("resource_types") or []}
        excluded_resource_types = {
            str(item) for item in rule.get("excluded_resource_types") or []
        }
        if resource_types and context.resource_type not in resource_types:
            return False
        if excluded_resource_types and context.resource_type in excluded_resource_types:
            return False

        third_party = str(rule.get("third_party") or "any")
        if third_party == "only" and context.third_party is not True:
            return False
        if third_party == "exclude" and context.third_party is not False:
            return False

        if not self._domain_scope_matches(rule, context):
            return False

        denyallow = (rule.get("value_options") or {}).get("denyallow") or []
        if denyallow and any(
            _domain_matches(context.request_host, context.request_suffixes, str(item))
            for item in denyallow
        ):
            return False

        behavior_options = set(rule.get("behavior_options") or [])
        value_options = set((rule.get("value_options") or {}).keys())
        if "badfilter" in behavior_options:
            return False
        return not bool(
            (behavior_options | value_options) & _NON_BLOCKING_MODIFIER_OPTIONS
        )

    def _domain_scope_matches(
        self,
        rule: dict[str, Any],
        context: _RequestContext,
    ) -> bool:
        includes = rule.get("domain_includes") or []
        include_patterns = [
            _normalized_rule_host(str(item))
            for item in rule.get("domain_include_patterns") or []
        ]
        excludes = rule.get("domain_excludes") or []
        exclude_patterns = [
            _normalized_rule_host(str(item))
            for item in rule.get("domain_exclude_patterns") or []
        ]
        if not (includes or include_patterns or excludes or exclude_patterns):
            return True
        source_host = context.source_host
        if not source_host:
            return False
        suffixes = context.source_suffixes
        if any(_domain_matches(source_host, suffixes, str(item)) for item in excludes):
            return False
        if any(fnmatch.fnmatchcase(source_host, item) for item in exclude_patterns):
            return False
        if includes or include_patterns:
            return any(
                _domain_matches(source_host, suffixes, str(item)) for item in includes
            ) or any(
                fnmatch.fnmatchcase(source_host, item) for item in include_patterns
            )
        return True
