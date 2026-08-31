from __future__ import annotations

from dataclasses import dataclass
from typing import Literal
from urllib.parse import unquote

_ASCII_HEX_DIGITS = frozenset("0123456789ABCDEFabcdef")


@dataclass(frozen=True)
class RepeatedPercentDecodeResult:
    """Bounded percent-decoding outcome, including every inspected layer."""

    values: tuple[str, ...]
    malformed: bool = False
    invalid_utf8: bool = False
    excessive_nesting: bool = False


def has_ascii_control_chars(value: str) -> bool:
    """Return whether text contains a C0 control or ASCII DEL."""
    return any(ord(char) < 32 or ord(char) == 127 for char in value)


def has_url_whitespace_or_control_chars(value: str) -> bool:
    """Return whether URL text contains Unicode whitespace or ASCII controls."""
    return any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value)


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


def repeatedly_percent_decode(
    value: str,
    *,
    max_passes: int,
    errors: Literal["replace", "strict"] = "replace",
    reject_malformed: bool = True,
) -> RepeatedPercentDecodeResult:
    """Decode at most ``max_passes`` layers without hiding an incomplete result.

    ``values`` contains the original text and each changed decoded layer. When
    ``reject_malformed`` is true, malformed percent syntax at any layer stops
    decoding. Strict UTF-8 failures are reported separately. If another valid
    encoded octet remains after the bound, ``excessive_nesting`` is true.
    """
    if max_passes < 0:
        msg = "max_passes must be non-negative"
        raise ValueError(msg)

    values = [str(value)]
    current = values[0]
    for _ in range(max_passes):
        if reject_malformed and has_malformed_percent_encoding(current):
            return RepeatedPercentDecodeResult(tuple(values), malformed=True)
        try:
            decoded = unquote(current, errors=errors)
        except UnicodeDecodeError:
            return RepeatedPercentDecodeResult(tuple(values), invalid_utf8=True)
        if decoded == current:
            return RepeatedPercentDecodeResult(tuple(values))
        values.append(decoded)
        current = decoded

    if reject_malformed and has_malformed_percent_encoding(current):
        return RepeatedPercentDecodeResult(tuple(values), malformed=True)
    try:
        next_decoded = unquote(current, errors=errors)
    except UnicodeDecodeError:
        return RepeatedPercentDecodeResult(tuple(values), invalid_utf8=True)
    return RepeatedPercentDecodeResult(
        tuple(values), excessive_nesting=next_decoded != current
    )
