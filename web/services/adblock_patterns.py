from __future__ import annotations

import re

ABP_SEPARATOR_REGEX = r"(?:[^A-Za-z0-9_.%-]|$)"


def abp_to_regex(pattern: str) -> str:
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
            parts.append(ABP_SEPARATOR_REGEX)
        else:
            parts.append(re.escape(ch))
    body = "".join(parts)
    if left_anchored:
        body = "^" + body
    if right_anchored:
        body += "$"
    return body
