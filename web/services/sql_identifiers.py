from __future__ import annotations

import re

_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def quote_mysql_identifier(identifier: str) -> str:
    value = (identifier or "").strip()
    if not _IDENTIFIER_RE.fullmatch(value):
        msg = f"Unsafe MySQL identifier: {identifier!r}"
        raise ValueError(msg)
    return f"`{value}`"
