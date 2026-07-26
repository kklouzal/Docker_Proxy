from __future__ import annotations

import re

ABP_SEPARATOR_REGEX = r"(?:[^A-Za-z0-9_.%-]|$)"
_ABP_ESCAPABLE_PATTERN_CHARS = frozenset("*^|$\\")


def _is_escaped(text: str, index: int) -> bool:
    backslashes = 0
    cursor = index - 1
    while cursor >= 0 and text[cursor] == "\\":
        backslashes += 1
        cursor -= 1
    return backslashes % 2 == 1


def abp_to_regex(pattern: str) -> str:
    p = pattern or ""
    left_anchored = p.startswith("|") and not p.startswith("||")
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
