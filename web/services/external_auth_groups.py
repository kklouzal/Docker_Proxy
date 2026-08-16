from __future__ import annotations

import re
from typing import Any

_LDAP_ATTRIBUTE_RE = re.compile(r"[a-z][a-z0-9-]*|[0-9.]+")
_HEX_BYTE_RE = re.compile(r"[0-9A-Fa-f]{2}")


def normalize_group_token(value: Any) -> str:
    """Return the common case-insensitive token used by external auth providers."""
    return str(value or "").strip().casefold()


def required_group_match_tokens(value: Any, *, preserve_full_dn: bool) -> set[str]:
    """Build required-group tokens without weakening a configured full DN."""
    text = str(value or "").strip()
    if not text:
        return set()
    tokens = {normalize_group_token(text)}
    if preserve_full_dn and (dn_key := ldap_dn_match_key(text)):
        tokens.add(f"dn:{dn_key}")
    return {token for token in tokens if token}


def candidate_group_match_tokens(value: Any, *, preserve_full_dn: bool) -> set[str]:
    """Build exact and safe alias tokens for an asserted external group."""
    text = str(value or "").strip()
    if not text:
        return set()
    tokens = {normalize_group_token(text)}
    if preserve_full_dn and (dn_key := ldap_dn_match_key(text)):
        tokens.add(f"dn:{dn_key}")
    if rdn_value := first_ldap_group_rdn_value(text):
        tokens.add(normalize_group_token(rdn_value))
    if local_name := domain_group_local_name(text):
        tokens.add(normalize_group_token(local_name))
    return {token for token in tokens if token}


def ldap_dn_match_key(value: str) -> str:
    text = (value or "").strip()
    if not text:
        return ""
    normalized: list[str] = []
    for raw_rdn in split_ldap_escaped(text, ","):
        rdn = raw_rdn.strip()
        parts = split_ldap_escaped(rdn, "=", maxsplit=1)
        if len(parts) != 2:
            return ""
        attribute = parts[0].strip().casefold()
        if not attribute or not _LDAP_ATTRIBUTE_RE.fullmatch(attribute):
            return ""
        name = unescape_ldap_rdn_value(parts[1].strip()).strip().casefold()
        if not name:
            return ""
        normalized.append(f"{attribute}={name}")
    return ",".join(normalized)


def first_ldap_group_rdn_value(value: str) -> str:
    text = (value or "").strip()
    if not text:
        return ""
    first_rdn = split_ldap_escaped(text, ",", maxsplit=1)[0].strip()
    parts = split_ldap_escaped(first_rdn, "=", maxsplit=1)
    if len(parts) != 2 or parts[0].strip().casefold() not in {"cn", "name"}:
        return ""
    return unescape_ldap_rdn_value(parts[1].strip()).strip()


def domain_group_local_name(value: str) -> str:
    text = (value or "").strip()
    if "\\" in text:
        local_name = text.rsplit("\\", 1)[1].strip()
        if local_name:
            return local_name
    if "@" in text:
        local_name, domain = text.rsplit("@", 1)
        if local_name.strip() and domain.strip():
            return local_name.strip()
    return ""


def split_ldap_escaped(value: str, delimiter: str, *, maxsplit: int = -1) -> list[str]:
    parts: list[str] = []
    start = 0
    splits = 0
    escaped = False
    for index, char in enumerate(value):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == delimiter and (maxsplit < 0 or splits < maxsplit):
            parts.append(value[start:index])
            start = index + 1
            splits += 1
    parts.append(value[start:])
    return parts


def unescape_ldap_rdn_value(value: str) -> str:
    result: list[str] = []
    hex_bytes = bytearray()

    def flush_hex_bytes() -> None:
        if not hex_bytes:
            return
        try:
            result.append(hex_bytes.decode("utf-8"))
        except UnicodeDecodeError:
            # Preserve the historical one-codepoint-per-octet behavior for
            # non-UTF-8 directory data while decoding valid UTF-8 sequences.
            result.append(hex_bytes.decode("latin-1"))
        hex_bytes.clear()

    index = 0
    while index < len(value):
        char = value[index]
        if char == "\\" and index + 2 < len(value):
            escaped = value[index + 1 : index + 3]
            if _HEX_BYTE_RE.fullmatch(escaped):
                hex_bytes.append(int(escaped, 16))
                index += 3
                continue
        flush_hex_bytes()
        if char == "\\" and index + 1 < len(value):
            result.append(value[index + 1])
            index += 2
        else:
            result.append(char)
            index += 1
    flush_hex_bytes()
    return "".join(result)
