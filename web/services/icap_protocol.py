"""Shared, policy-neutral ICAP wire syntax primitives.

REQMOD and RESPMOD impose different section layouts.  This module only parses
syntax common to both; callers remain responsible for method-specific policy.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Set as AbstractSet

_DECIMAL_RE = re.compile(r"[0-9]+\Z")


class IcapWireSyntaxError(ValueError):
    """A malformed policy-neutral ICAP wire token."""


@dataclass(frozen=True)
class ChunkHeader:
    size: int
    has_ieof: bool


def parse_encapsulated_sections(
    value: str,
    *,
    supported_names: AbstractSet[str],
    require_nondecreasing_offsets: bool = False,
    max_significant_digits: int = 16,
    strip_offset_whitespace: bool = True,
) -> dict[str, int]:
    """Parse Encapsulated entries without imposing REQMOD/RESPMOD layout."""
    offsets: dict[str, int] = {}
    previous = -1
    for raw_item in value.split(","):
        item = raw_item.lstrip()
        if not item or "=" not in item:
            message = f"malformed Encapsulated section: {item}"
            raise IcapWireSyntaxError(message)
        name, raw_offset = item.split("=", 1)
        name = name.strip().lower()
        if strip_offset_whitespace:
            raw_offset = raw_offset.strip()
        if name not in supported_names:
            message = f"unknown Encapsulated section token: {name}"
            raise IcapWireSyntaxError(message)
        if name in offsets:
            message = f"duplicate Encapsulated section name: {name}"
            raise IcapWireSyntaxError(message)
        if not _DECIMAL_RE.fullmatch(raw_offset):
            message = f"invalid Encapsulated offset: {item}"
            raise IcapWireSyntaxError(message)
        significant = raw_offset.lstrip("0") or "0"
        if len(significant) > max_significant_digits:
            message = f"invalid Encapsulated offset: {item}"
            raise IcapWireSyntaxError(message)
        offset = int(significant)
        if require_nondecreasing_offsets and offset < previous:
            message = f"decreasing Encapsulated offset: {item}"
            raise IcapWireSyntaxError(message)
        offsets[name] = offset
        previous = offset
    return offsets


_CHUNK_OWS = b" \t"
_CHUNK_TCHARS = frozenset(
    b"!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)
_HEX_DIGITS = frozenset(b"0123456789abcdefABCDEF")
MAX_CHUNK_SIZE_DIGITS = 16
# Fields that RFC 7230 section 4.1.2 / RFC 3507 forbid in a chunked trailer:
# framing and ICAP routing must come from the headers alone.
_FORBIDDEN_TRAILER_FIELDS = frozenset(
    {
        b"allow",
        b"content-length",
        b"encapsulated",
        b"preview",
        b"trailer",
        b"transfer-encoding",
    }
)


def _skip_ows(line: bytes, index: int) -> int:
    while index < len(line) and line[index] in _CHUNK_OWS:
        index += 1
    return index


def _quoted_string_end(line: bytes, index: int) -> int | None:
    """Index just past the quoted-string starting at ``index``, else None."""
    escaped = False
    index += 1
    while index < len(line):
        ch = line[index]
        if escaped:
            if ch not in _CHUNK_OWS and not (0x21 <= ch <= 0x7E):
                return None
            escaped = False
        elif ch == 0x5C:  # backslash
            escaped = True
        elif ch == 0x22:
            return index + 1
        elif ch < 0x20 or ch >= 0x7F:
            return None
        index += 1
    return None


def parse_chunk_header(line: bytes) -> ChunkHeader:
    """Parse a chunk-size line (RFC 7230 chunk-ext grammar, RFC 3507 ``ieof``).

    Rejects control bytes, more than 16 hex digits, malformed or duplicate
    extensions, and an ``ieof`` that carries a value or ends a non-empty chunk.
    """
    if any((ch < 0x20 and ch not in _CHUNK_OWS) or ch >= 0x7F for ch in line):
        message = "invalid ICAP chunk-size line"
        raise IcapWireSyntaxError(message)
    first_extension = line.find(b";")
    size_token = line if first_extension < 0 else line[:first_extension]
    if (
        not size_token
        or len(size_token) > MAX_CHUNK_SIZE_DIGITS
        or any(ch not in _HEX_DIGITS for ch in size_token)
    ):
        message = "invalid ICAP chunk-size line"
        raise IcapWireSyntaxError(message)
    extensions: set[bytes] = set()
    index = first_extension
    while 0 <= index < len(line):
        if line[index] != 0x3B:  # semicolon
            message = "invalid ICAP chunk extension"
            raise IcapWireSyntaxError(message)
        index = _skip_ows(line, index + 1)
        name_start = index
        while index < len(line) and line[index] in _CHUNK_TCHARS:
            index += 1
        name = line[name_start:index].lower()
        if not name:
            message = "invalid ICAP chunk extension"
            raise IcapWireSyntaxError(message)
        index = _skip_ows(line, index)
        valued = index < len(line) and line[index] == 0x3D  # equals
        if valued:
            index = _skip_ows(line, index + 1)
            if index < len(line) and line[index] == 0x22:  # double quote
                end = _quoted_string_end(line, index)
                if end is None:
                    message = "invalid ICAP chunk extension"
                    raise IcapWireSyntaxError(message)
                index = end
            else:
                value_start = index
                while index < len(line) and line[index] in _CHUNK_TCHARS:
                    index += 1
                if index == value_start:
                    message = "invalid ICAP chunk extension"
                    raise IcapWireSyntaxError(message)
            index = _skip_ows(line, index)
        if index < len(line) and line[index] != 0x3B:
            message = "invalid ICAP chunk extension"
            raise IcapWireSyntaxError(message)
        if name in extensions:
            message = f"duplicate ICAP chunk extension: {name.decode('ascii')}"
            raise IcapWireSyntaxError(message)
        if name == b"ieof" and valued:
            message = "invalid ICAP ieof chunk extension"
            raise IcapWireSyntaxError(message)
        extensions.add(name)
    size = int(size_token, 16)
    has_ieof = b"ieof" in extensions
    if has_ieof and size != 0:
        message = "invalid ICAP ieof chunk extension on nonzero chunk"
        raise IcapWireSyntaxError(message)
    return ChunkHeader(size=size, has_ieof=has_ieof)


def validate_chunk_trailer(line: bytes) -> None:
    """Validate one trailer field line (without its terminating CRLF)."""
    if b":" not in line:
        message = "invalid ICAP chunk trailer"
        raise IcapWireSyntaxError(message)
    name, value = line.split(b":", 1)
    if not name or any(ch not in _CHUNK_TCHARS for ch in name):
        message = "invalid ICAP chunk trailer field name"
        raise IcapWireSyntaxError(message)
    if name.lower() in _FORBIDDEN_TRAILER_FIELDS:
        message = f"forbidden ICAP chunk trailer field: {name.lower().decode('ascii')}"
        raise IcapWireSyntaxError(message)
    if any((char < 32 and char != 9) or char >= 127 for char in value):
        message = "invalid ICAP chunk trailer value"
        raise IcapWireSyntaxError(message)
