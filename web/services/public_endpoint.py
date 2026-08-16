from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

from services.domain_normalization import is_ambiguous_ipv4_like_host
from services.runtime_helpers import authority_has_empty_explicit_port


def _canonical_public_dns_host(
    value: str,
    *,
    allow_single_label: bool = False,
) -> str:
    candidate = value.removesuffix(".").lower()
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


def _is_reserved_public_dns_host(value: str) -> bool:
    candidate = value.rstrip(".").lower()
    if not candidate:
        return True
    if candidate in {
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
        "home.arpa",
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


def _is_unsafe_request_host_ip(
    parsed_ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    if getattr(parsed_ip, "scope_id", None):
        return True
    mapped_ipv4 = getattr(parsed_ip, "ipv4_mapped", None)
    candidates = (parsed_ip, mapped_ipv4) if mapped_ipv4 is not None else (parsed_ip,)
    return any(
        candidate.is_loopback
        or candidate.is_unspecified
        or candidate.is_multicast
        or candidate.is_link_local
        for candidate in candidates
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
        if authority_has_empty_explicit_port(parsed.netloc):
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
        if parsed.path or parsed.query or parsed.fragment:
            return fallback
        if parsed.username is not None or parsed.password is not None:
            return fallback
        if authority_has_empty_explicit_port(parsed.netloc):
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
    if is_ambiguous_ipv4_like_host(dns_host):
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
