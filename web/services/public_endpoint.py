from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit


def _is_ambiguous_ipv4_host(value: str) -> bool:
    candidate = value.rstrip(".").lower()
    if not candidate:
        return False
    labels = candidate.split(".")
    if not 1 <= len(labels) <= 4:
        return False
    for label in labels:
        if not label:
            return False
        if label.isdecimal():
            continue
        if label.startswith("0x"):
            digits = label.removeprefix("0x")
            if digits and all(ch in "0123456789abcdef" for ch in digits):
                continue
        return False
    return True


def _canonical_public_dns_host(
    value: str,
    *,
    allow_single_label: bool = False,
) -> str:
    candidate = value.rstrip(".").lower()
    if not candidate:
        return ""
    try:
        candidate = candidate.encode("idna").decode("ascii")
    except Exception:
        return ""
    if not candidate or len(candidate) > 253:
        return ""
    labels = candidate.split(".")
    if len(labels) < 2 and not allow_single_label:
        return ""
    if any(
        not label
        or len(label) > 63
        or not label[0].isalnum()
        or not label[-1].isalnum()
        or any(not (ch.isalnum() or ch == "-") for ch in label)
        for label in labels
    ):
        return ""
    return candidate


def _has_empty_explicit_authority_port(netloc: str) -> bool:
    return netloc.endswith(":")


def _is_reserved_public_dns_host(value: str) -> bool:
    candidate = value.rstrip(".").lower()
    if not candidate:
        return True
    if candidate in {
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
    }:
        return True
    return candidate.endswith(
        (
            ".localhost",
            ".local",
            ".localdomain",
            ".internal",
            ".home.arpa",
        ),
    )


def normalize_public_host(
    value: object | None,
    default: str = "",
    *,
    allow_single_label: bool = False,
) -> str:
    candidate = str(value or "").strip()
    fallback = str(default or "").strip()
    if not candidate:
        return fallback
    if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in candidate):
        return fallback

    host = candidate
    if "://" in candidate:
        try:
            parsed = urlsplit(candidate)
            port = parsed.port
        except Exception:
            return fallback
        if parsed.scheme.lower() not in {"http", "https"}:
            return fallback
        if parsed.username is not None or parsed.password is not None:
            return fallback
        if _has_empty_explicit_authority_port(parsed.netloc):
            return fallback
        if port == 0:
            return fallback
        host = parsed.hostname or ""
    elif candidate.startswith("[") or candidate.count(":") == 1:
        try:
            parsed = urlsplit(f"//{candidate}")
            port = parsed.port
        except Exception:
            return fallback
        if parsed.username is not None or parsed.password is not None:
            return fallback
        if _has_empty_explicit_authority_port(parsed.netloc):
            return fallback
        if port == 0:
            return fallback
        host = parsed.hostname or ""
    elif candidate.count(":") > 1:
        host = candidate

    host = host.strip()
    if not host or "[" in host or "]" in host:
        return fallback
    try:
        parsed_ip = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        if getattr(parsed_ip, "scope_id", None):
            return fallback
        if parsed_ip.is_multicast or not parsed_ip.is_global:
            return fallback
        return str(parsed_ip)
    dns_host = _canonical_public_dns_host(
        host,
        allow_single_label=allow_single_label,
    )
    if not dns_host:
        return fallback
    if _is_ambiguous_ipv4_host(dns_host):
        return fallback
    if _is_reserved_public_dns_host(dns_host):
        return fallback
    return dns_host


def normalize_public_scheme(value: object | None) -> str:
    candidate = str(value or "").strip().lower()
    if candidate in {"http", "https"}:
        return candidate
    return "http"


def coerce_public_port(value: object | None, default: int) -> int:
    try:
        parsed = int(str(value or "").strip() or str(default))
    except Exception:
        parsed = int(default)
    if parsed < 1 or parsed > 65535:
        return int(default)
    return parsed


def coerce_public_bool(value: object | None, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return bool(default)
    candidate = str(value).strip().lower()
    if not candidate:
        return bool(default)
    if candidate in {"1", "true", "yes", "on"}:
        return True
    if candidate in {"0", "false", "no", "off"}:
        return False
    return bool(default)
