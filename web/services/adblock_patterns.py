from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping

ABP_SEPARATOR_REGEX = r"(?:[^A-Za-z0-9_.%-]|$)"
_ABP_ESCAPABLE_PATTERN_CHARS = frozenset("*^|$\\")


def _is_escaped(text: str, index: int) -> bool:
    backslashes = 0
    cursor = index - 1
    while cursor >= 0 and text[cursor] == "\\":
        backslashes += 1
        cursor -= 1
    return backslashes % 2 == 1


def _abp_to_regex(pattern: str, *, recognize_left_anchor: bool) -> str:
    p = pattern or ""
    left_anchored = (
        recognize_left_anchor and p.startswith("|") and not p.startswith("||")
    )
    right_anchored = p.endswith("|") and not _is_escaped(p, len(p) - 1)
    if left_anchored:
        p = p[1:]
    if right_anchored:
        p = p[:-1]

    parts: list[str] = []
    index = 0
    while index < len(p):
        ch = p[index]
        if (
            ch == "\\"
            and index + 1 < len(p)
            and p[index + 1] in _ABP_ESCAPABLE_PATTERN_CHARS
        ):
            parts.append(re.escape(p[index + 1]))
            index += 2
            continue
        if ch == "*":
            parts.append(".*")
        elif ch == "^":
            parts.append(ABP_SEPARATOR_REGEX)
        else:
            parts.append(re.escape(ch))
        index += 1
    body = "".join(parts)
    if left_anchored:
        body = "^" + body
    if right_anchored:
        body += "$"
    return body


def abp_to_regex(pattern: str) -> str:
    return _abp_to_regex(pattern, recognize_left_anchor=True)


def abp_suffix_to_regex(pattern: str) -> str:
    return _abp_to_regex(pattern, recognize_left_anchor=False)


def abp_host_anchored_to_regex(host_pattern: str, suffix: str) -> str:
    # A trailing dot is part of the pattern (||ads. needs a following label).
    host = (host_pattern or "").strip().lower()
    host_regex = abp_to_regex(host)
    suffix_regex = abp_suffix_to_regex(suffix)
    if not host_regex:
        return suffix_regex
    return (
        r"^[a-z][a-z0-9+.-]*://(?:[^/?#@]*@)?(?:[^/?#]*\.)?" + host_regex + suffix_regex
    )


# Candidate token prefilter shared by the compiler (one key per rule) and the
# lookup (the token set of each request URL); both sides must tokenize alike.
# A token is a maximal run of these characters in the lowercased text.
_TOKEN_RE = re.compile(r"[a-z0-9%]+")


def url_tokens(url: str) -> set[str]:
    """Return the prefilter tokens of a request URL."""
    return set(_TOKEN_RE.findall((url or "").lower()))


def pattern_tokens(pattern: str) -> list[str]:
    """Return the tokens every URL matching ABP ``pattern`` contains.

    A pattern token qualifies only when it is a whole URL token in every match:
    each side must be bounded by a literal non-token character, a ``^``
    separator, or an anchor (``||``/``|`` start, ``|`` end). Tokens touching the
    unanchored pattern edge, a ``*`` wildcard, or an escape can extend into
    surrounding URL characters (``-ad-banner.`` matches ``x-ad-banner.js``).
    A non-ASCII pattern has no tokens: its host part matches IDNA-encoded.
    """
    p = (pattern or "").lower()
    if not p.isascii():
        return []
    start_bounded = p.startswith("|")
    if p.startswith("||"):
        p = p[2:]
    elif start_bounded:
        p = p[1:]
    end_bounded = p.endswith("|") and not _is_escaped(p, len(p) - 1)
    if end_bounded:
        p = p[:-1]
    tokens: list[str] = []
    for match in _TOKEN_RE.finditer(p):
        start, end = match.span()
        left_ok = start_bounded if start == 0 else p[start - 1] not in "*\\"
        right_ok = end_bounded if end == len(p) else p[end] not in "*\\"
        if left_ok and right_ok:
            tokens.append(match.group())
    return tokens


def pattern_token_key(pattern: str, token_counts: Mapping[str, int]) -> str:
    """Return the candidate key of ABP ``pattern``: its rarest qualifying token.

    ``token_counts`` holds how many compiled patterns qualify each token; the
    rarest one keeps candidate buckets small (ties prefer the longer token). Rules without a qualifying token are keyed "" and evaluated for
    every request.
    """
    tokens = pattern_tokens(pattern)
    if not tokens:
        return ""
    return min(
        tokens,
        key=lambda token: (
            token_counts.get(token, 0),
            -len(token),
            token,
        ),
    )
