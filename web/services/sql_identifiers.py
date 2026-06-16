from __future__ import annotations


def quote_mysql_identifier(identifier: str) -> str:
    value = (identifier or "").strip()
    if not value or not value.replace("_", "").isalnum():
        msg = f"Unsafe MySQL identifier: {identifier!r}"
        raise ValueError(msg)
    return f"`{value}`"
