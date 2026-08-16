from __future__ import annotations

_ASCII_HEX_DIGITS = frozenset("0123456789ABCDEFabcdef")


def has_malformed_percent_encoding(value: str) -> bool:
    """Return whether any percent sign is not followed by two ASCII hex digits."""
    start = 0
    while True:
        index = value.find("%", start)
        if index == -1:
            return False
        if (
            index + 2 >= len(value)
            or value[index + 1] not in _ASCII_HEX_DIGITS
            or value[index + 2] not in _ASCII_HEX_DIGITS
        ):
            return True
        start = index + 3
