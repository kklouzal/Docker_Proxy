from __future__ import annotations

import fnmatch
import ipaddress
import json
import re
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from services.adblock_hosts import adblock_host_suffix_candidates
from services.adblock_hosts import normalize_adblock_host as _normalize_host
from services.adblock_hosts import safe_adblock_urlsplit as _safe_urlsplit
from services.adblock_lookup import AdblockLookupIndex
from services.adblock_patterns import (
    abp_host_anchored_to_regex as _abp_host_anchored_to_regex,
)
from services.adblock_patterns import abp_to_regex as _abp_to_regex
from services.domain_normalization import registrable_domain_start

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


# Bounds enforced by AdblockStore.set_shared_settings for the Admin UI values.
_MAX_ARTIFACT_CACHE_TTL_SECONDS = 7 * 24 * 3600
_MAX_ARTIFACT_CACHE_ENTRIES = 1_000_000


def artifact_decision_cache_settings(
    db_path: str | Path,
) -> tuple[int | None, int | None]:
    """Return the Admin UI cache TTL/size published beside the lookup DB.

    The artifact's ``settings.json`` carries the shared ``cache_ttl`` and
    ``cache_max`` values; a missing file or value yields ``None`` so callers
    keep their configured defaults.
    """
    settings_path = Path(db_path).parent / "settings.json"
    try:
        payload = json.loads(settings_path.read_text(encoding="utf-8"))
    except OSError, ValueError:
        return None, None
    if not isinstance(payload, dict):
        return None, None

    def bounded(key: str, maximum: int) -> int | None:
        value = payload.get(key)
        if isinstance(value, bool) or not isinstance(value, int):
            return None
        return value if 0 <= value <= maximum else None

    return (
        bounded("cache_ttl", _MAX_ARTIFACT_CACHE_TTL_SECONDS),
        bounded("cache_max", _MAX_ARTIFACT_CACHE_ENTRIES),
    )


@dataclass(frozen=True)
class AdblockDecision:
    blocked: bool
    rule_id: str = ""
    raw: str = ""
    action: str = "allow"
    reason: str = "no-match"
    list_key: str = ""


# Shared by every unmatched request (and so by most decision cache entries).
_NO_MATCH = AdblockDecision(blocked=False)


@dataclass(frozen=True)
class _RequestContext:
    """Per-request facts shared by every candidate rule evaluation."""

    url: str
    url_lower: str
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


@lru_cache(maxsize=8192)
def _host_suffix_set(normalized_host: str) -> frozenset[str]:
    """Return the domain-option keys ``normalized_host`` matches.

    These are the host and its parent domains plus, for a DNS name, the uBO
    entity forms (``google.*`` for ``www.google.co.uk``: a registrable-domain
    label sequence followed by its public suffix). Entity keys end in ``.*``,
    which no host name does, so one membership test serves both.
    """
    suffixes = adblock_host_suffix_candidates(normalized_host)
    labels = normalized_host.split(".")
    if len(labels) < 2 or normalized_host.startswith("[") or "%" in normalized_host:
        return frozenset(suffixes)
    try:
        ipaddress.ip_address(normalized_host)
    except ValueError:
        pass
    else:
        return frozenset(suffixes)
    registrable = registrable_domain_start(labels)
    entities = (
        ".".join(labels[index : registrable + 1]) + ".*"
        for index in range(registrable + 1)
    )
    return frozenset((*suffixes, *entities))


@lru_cache(maxsize=8192)
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


def _source_host(source_url: str) -> str:
    parsed = _safe_urlsplit(source_url)
    return _normalize_host(parsed.hostname if parsed is not None else "")


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
        "audioworklet": "script",
        "document": "document",
        "embed": "object",
        "fencedframe": "subdocument",
        "font": "font",
        "frame": "subdocument",
        "iframe": "subdocument",
        "image": "image",
        "object": "object",
        "paintworklet": "script",
        "script": "script",
        "serviceworker": "script",
        "sharedworker": "script",
        "style": "stylesheet",
        "track": "media",
        "video": "media",
        "worker": "script",
    }
    if fetch_dest in fetch_dest_types:
        return fetch_dest_types[fetch_dest]
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
    # A navigation's Accept also lists image types, so test it first.
    if "text/html" in accept and normalized_method in {"GET", "HEAD"}:
        return "document"
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


def _decision_for_matches(matches: list[_RuleMatcher]) -> AdblockDecision:
    # uBO precedence: important exception > important block > exception > block.
    for action, important, reason in (
        ("allow", True, "important-exception"),
        ("block", True, "important-rule-match"),
        ("allow", False, "exception"),
        ("block", False, "rule-match"),
    ):
        for matcher in matches:
            if matcher.action == action and (not important or matcher.important):
                rule = matcher.rule
                return AdblockDecision(
                    blocked=action == "block",
                    rule_id=str(rule.get("rule_id") or rule.get("id") or ""),
                    raw=str(rule.get("raw") or ""),
                    action=action,
                    reason=reason,
                    list_key=str(rule.get("list_key") or ""),
                )
    return _NO_MATCH


def _compiled_domain_test(domain: Any) -> tuple[bool, str] | None:
    """Compile one domain option value for ``_any_domain_matches``.

    An entity (``example.*``) or a plain value matches through the host's
    ``_host_suffix_set`` keys: the host, a parent domain, or an entity whose
    ``*`` stands for the public suffix. Any other value containing ``*`` is an
    fnmatch pattern over the whole host. Returns (is_pattern, value), or None
    when the value can never match.
    """
    text = str(domain).strip().lower().rstrip(".")
    if not text:
        return None
    if text.endswith(".*") and "*" not in text[:-2]:
        return False, text
    if "*" in text:
        return True, text
    normalized = _normalized_rule_host(text)
    return (False, normalized) if normalized else None


def _compiled_domain_tests(domains: Any) -> tuple[tuple[bool, str], ...]:
    tests = (_compiled_domain_test(item) for item in domains or [])
    return tuple(test for test in tests if test is not None)


def _any_domain_matches(
    host: str,
    suffixes: frozenset[str],
    tests: tuple[tuple[bool, str], ...],
) -> bool:
    for is_pattern, value in tests:
        if is_pattern:
            if fnmatch.fnmatchcase(host, value):
                return True
        elif value in suffixes:
            return True
    return False


class _RuleMatcher:
    """A candidate rule with its request-independent matching work done once.

    ``matches`` is exactly the ABP/uBO evaluation of the decoded rule dict:
    option checks (method, resource type, party, domain scope, denyallow,
    discarded/non-blocking options) and then the URL pattern. Matchers are
    built when a rule enters the lookup's bounded rule cache.
    """

    __slots__ = (
        "action",
        "applies_to_document",
        "case_sensitive",
        "denyallow",
        "domain_excludes",
        "domain_includes",
        "domain_scoped",
        "excluded_methods",
        "excluded_resource_types",
        "has_domain_includes",
        "host_test",
        "important",
        "included_methods",
        "kind",
        "needle",
        "regex",
        "resource_types",
        "rule",
        "third_party",
        "unusable",
    )

    def __init__(self, rule: dict[str, Any]) -> None:
        self.rule = rule
        self.action = rule.get("action")
        behavior_options = set(rule.get("behavior_options") or [])
        self.important = "important" in behavior_options
        self.case_sensitive = "match-case" in behavior_options
        self.unusable = False
        self.included_methods: frozenset[str] | None = None
        self.excluded_methods: frozenset[str] = frozenset()
        self.resource_types = frozenset(
            str(item) for item in rule.get("resource_types") or []
        )
        self.excluded_resource_types = frozenset(
            str(item) for item in rule.get("excluded_resource_types") or []
        )
        self.third_party = str(rule.get("third_party") or "any")
        self.kind = str(rule.get("pattern_kind") or "")
        # A filter without type options covers every request type except the
        # main document (ABP's default content type; uBO and adblock-rust
        # agree), with uBO's strict-blocking exception: a pure hostname
        # filter (||example.com^) also matches the page itself. Negated types
        # (~script) leave the remaining default types, so not the document.
        self.applies_to_document = (
            "document" in self.resource_types
            if self.resource_types
            else self.kind == "domain_only" and not self.excluded_resource_types
        )
        includes = [
            *(rule.get("domain_includes") or []),
            *(rule.get("domain_include_patterns") or []),
        ]
        excludes = [
            *(rule.get("domain_excludes") or []),
            *(rule.get("domain_exclude_patterns") or []),
        ]
        self.domain_includes = _compiled_domain_tests(includes)
        self.domain_excludes = _compiled_domain_tests(excludes)
        # Scope presence follows the raw lists: an entry that can never match
        # still makes the rule domain-scoped (and include-restricted).
        self.has_domain_includes = bool(includes)
        self.domain_scoped = bool(includes or excludes)
        self.denyallow: tuple[tuple[bool, str], ...] = ()
        self.host_test: tuple[bool, str] | None = None
        self.needle = ""
        self.regex: re.Pattern[str] | None = None

        value_options = rule.get("value_options") or {}
        if rule.get("misc_options") or not isinstance(value_options, dict):
            # Like ABP and uBlock Origin, discard a filter carrying an option
            # this engine does not understand rather than enforcing it without
            # the restriction (or non-blocking meaning) that option adds.
            self.unusable = True
            return
        if "badfilter" in behavior_options or (
            (behavior_options | set(value_options.keys()))
            & _NON_BLOCKING_MODIFIER_OPTIONS
        ):
            self.unusable = True
            return
        if "method" in value_options:
            method_values = value_options["method"]
            # An explicitly present but malformed method= must not become an
            # unrestricted rule merely because it has no usable values.
            if not isinstance(method_values, list) or not method_values:
                self.unusable = True
                return
            included: set[str] = set()
            excluded: set[str] = set()
            for item in method_values:
                option_value = str(item or "").strip().upper()
                negated = option_value.startswith("~")
                option_method = option_value[1:] if negated else option_value
                if option_method not in SUPPORTED_REQUEST_METHODS:
                    self.unusable = True
                    return
                (excluded if negated else included).add(option_method)
            self.included_methods = frozenset(included)
            self.excluded_methods = frozenset(excluded)
        self.denyallow = _compiled_domain_tests(value_options.get("denyallow"))
        self._compile_pattern()

    def _compile_pattern(self) -> None:
        rule = self.rule
        kind = self.kind
        pattern = str(rule.get("pattern") or "")
        ignore_case = not self.case_sensitive
        if kind == "domain_only":
            self.host_test = _compiled_domain_test(rule.get("host") or "")
        elif kind == "absolute_url":
            self.regex = _compile_regex(
                str(rule.get("compiled_regex") or _abp_to_regex(pattern)),
                ignore_case=ignore_case,
            )
        elif kind == "host_anchored":
            self.host_test = _compiled_domain_test(rule.get("host") or "")
            self.regex = _compile_regex(
                str(
                    rule.get("compiled_regex")
                    or _abp_host_anchored_to_regex(
                        str(rule.get("host") or ""),
                        str(rule.get("suffix") or ""),
                    )
                ),
                ignore_case=ignore_case,
            )
        elif kind in {"host_anchored_pattern", "absolute_url_pattern"}:
            self.regex = _compile_regex(
                str(rule.get("compiled_regex") or ""),
                ignore_case=ignore_case,
            )
        elif kind in {"left_anchored", "right_anchored", "wildcard"}:
            self.regex = _compile_regex(
                str(rule.get("compiled_regex") or _abp_to_regex(pattern)),
                ignore_case=ignore_case,
            )
        elif kind == "regex":
            self.regex = _compile_regex(
                str(rule.get("regex") or pattern),
                ignore_case=ignore_case,
            )
        elif kind == "substring":
            needle = _unescape_abp_literal(pattern)
            self.needle = needle if self.case_sensitive else needle.lower()

    def matches(self, context: _RequestContext) -> bool:
        return (
            not self.unusable
            and self._options_match(context)
            and self._pattern_matches(context)
        )

    def _options_match(self, context: _RequestContext) -> bool:
        included_methods = self.included_methods
        if included_methods is not None:
            request_method = context.method
            if request_method not in SUPPORTED_REQUEST_METHODS:
                return False
            if included_methods and request_method not in included_methods:
                return False
            if request_method in self.excluded_methods:
                return False
        resource_type = context.resource_type
        if self.resource_types and resource_type not in self.resource_types:
            return False
        if resource_type in self.excluded_resource_types:
            return False
        if resource_type == "document" and not self.applies_to_document:
            return False
        third_party = self.third_party
        if third_party == "only" and context.third_party is not True:
            return False
        if third_party == "exclude" and context.third_party is not False:
            return False
        if self.domain_scoped and not self._domain_scope_matches(context):
            return False
        return not (
            self.denyallow
            and _any_domain_matches(
                context.request_host, context.request_suffixes, self.denyallow
            )
        )

    def _domain_scope_matches(self, context: _RequestContext) -> bool:
        source_host = context.source_host
        if not source_host:
            # Like ABP and uBO, an unknown context is in no listed domain: a
            # filter limited to listed domains does not apply, one that only
            # excludes domains does.
            return not self.has_domain_includes
        suffixes = context.source_suffixes
        if _any_domain_matches(source_host, suffixes, self.domain_excludes):
            return False
        if self.has_domain_includes:
            return _any_domain_matches(source_host, suffixes, self.domain_includes)
        return True

    def _pattern_matches(self, context: _RequestContext) -> bool:
        kind = self.kind
        if kind == "option_only":
            return True
        if kind == "domain_only":
            return self.host_test is not None and _any_domain_matches(
                context.request_host, context.request_suffixes, (self.host_test,)
            )
        if kind == "host_anchored" and (
            self.host_test is None
            or not _any_domain_matches(
                context.request_host, context.request_suffixes, (self.host_test,)
            )
        ):
            return False
        if self.regex is not None:
            return self.regex.search(context.url) is not None
        if kind == "substring":
            haystack = context.url if self.case_sensitive else context.url_lower
            return self.needle in haystack
        return False


class AdblockDecisionEngine:
    def __init__(
        self,
        db_path: str | Path,
        *,
        cache_ttl_seconds: int = 3600,
        cache_max: int = 50000,
        rule_cache_max: int = 50000,
    ) -> None:
        self.lookup = AdblockLookupIndex(
            db_path,
            rule_cache_max=rule_cache_max,
            prepare_rule=_RuleMatcher,
        )
        self.cache_ttl_seconds = max(0, int(cache_ttl_seconds or 0))
        self.cache_max = max(0, int(cache_max or 0))
        self._cache: OrderedDict[
            tuple[str, str, str, str, str], tuple[float, AdblockDecision]
        ] = OrderedDict()
        self._cache_lock = threading.Lock()

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
        # Rules only see the source page through its host, so key the cache on
        # that rather than on every distinct Referer path/query.
        source_host = _source_host(effective_source_url)
        cache_key = (
            _normalize_method(method),
            url or "",
            effective_resource_type,
            source_host,
            str(effective_third_party_hint),
        )
        cached = self._get_cached(cache_key)
        if cached is not None:
            return cached

        context = self._request_context(
            url,
            method=method,
            resource_type=effective_resource_type,
            source_host=source_host,
            third_party_hint=effective_third_party_hint,
        )
        if context is None:
            decision = _NO_MATCH
            self._put_cached(cache_key, decision)
            return decision

        candidates = self.lookup.candidate_rules(
            url,
            resource_type=effective_resource_type,
        )
        matches = [matcher for matcher in candidates if matcher.matches(context)]
        decision = _decision_for_matches(matches)
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
        source_host: str,
        third_party_hint: bool | None,
    ) -> _RequestContext | None:
        parsed = _safe_urlsplit(url)
        if parsed is None:
            return None
        request_host = _normalize_host(parsed.hostname or "")
        third_party = _is_third_party(request_host, source_host)
        if third_party is None and third_party_hint is not None:
            third_party = bool(third_party_hint)
        return _RequestContext(
            url=url,
            url_lower=url.lower(),
            method=_normalize_method(method),
            resource_type=resource_type,
            request_host=request_host,
            request_suffixes=_host_suffix_set(request_host),
            source_host=source_host,
            source_suffixes=_host_suffix_set(source_host),
            third_party=third_party,
        )
