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

_TOKEN_BYTES_RE = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_HEX_BYTES_RE = re.compile(rb"[0-9A-Fa-f]+\Z")
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


def parse_chunk_header(line: bytes) -> ChunkHeader:
    """Parse strict ICAP chunk-size syntax and the ICAP ``ieof`` extension."""
    parts = line.split(b";")
    size_token = parts[0]
    if not size_token or not _HEX_BYTES_RE.fullmatch(size_token):
        message = "invalid ICAP chunk size"
        raise IcapWireSyntaxError(message)
    size = int(size_token, 16)
    ieof_count = 0
    for extension in parts[1:]:
        name = extension.split(b"=", 1)[0].strip().lower()
        if name == b"ieof":
            ieof_count += 1
    return ChunkHeader(size=size, has_ieof=bool(ieof_count))


def validate_chunk_trailer(line: bytes) -> None:
    """Validate one trailer field line (without its terminating CRLF)."""
    if b":" not in line:
        message = "malformed ICAP chunk trailer"
        raise IcapWireSyntaxError(message)
    name, value = line.split(b":", 1)
    if not name or not _TOKEN_BYTES_RE.fullmatch(name):
        message = "malformed ICAP chunk trailer"
        raise IcapWireSyntaxError(message)
    if any((char < 32 and char != 9) or char == 127 for char in value):
        message = "malformed ICAP chunk trailer"
        raise IcapWireSyntaxError(message)
