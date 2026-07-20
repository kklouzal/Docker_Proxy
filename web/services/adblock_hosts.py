from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlsplit

_HOST_RE = re.compile(
    r"^(?=.{1,255}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$",
    re.IGNORECASE,
)


def normalize_adblock_host(host: str) -> str:
    value = (host or "").strip().lower().rstrip(".")
    if not value:
        return ""
    if value.startswith("[") and "]" in value:
        literal = value[1:].split("]", 1)[0].strip()
        try:
            ip = ipaddress.ip_address(literal)
            return (
                f"[{ip.compressed.lower()}]"
                if ip.version == 6
                else ip.compressed.lower()
            )
        except ValueError:
            return value.split("]", 1)[0] + "]"
    if ":" in value:
        try:
            ip = ipaddress.ip_address(value)
            return (
                f"[{ip.compressed.lower()}]"
                if ip.version == 6
                else ip.compressed.lower()
            )
        except ValueError:
            if value.count(":") == 1:
                value = value.split(":", 1)[0]
            else:
                return value
    try:
        ip = ipaddress.ip_address(value)
        return (
            f"[{ip.compressed.lower()}]" if ip.version == 6 else ip.compressed.lower()
        )
    except ValueError:
        pass
    try:
        return value.encode("idna").decode("ascii").lower().rstrip(".")
    except Exception:
        return value


def safe_adblock_urlsplit(url: str) -> Any | None:
    try:
        parsed = urlsplit(url or "")
        _hostname = parsed.hostname
        _port = parsed.port
        return parsed
    except ValueError:
        return None


def adblock_host_suffix_candidates(host: str) -> list[str]:
    normalized = normalize_adblock_host(host)
    if not normalized:
        return []
    if normalized.startswith("["):
        return [normalized]
    if "%" in normalized:
        # urlsplit() deliberately does not percent-decode hostnames.  Treat
        # encoded authority delimiters/labels as a single parser-ambiguous host
        # instead of letting suffix rules for the decoded-looking tail match.
        return [normalized]
    labels = [part for part in normalized.split(".") if part]
    if len(labels) < 2:
        return [normalized]
    return [".".join(labels[index:]) for index in range(len(labels) - 1)]


def adblock_host_matches(host: str, rule_host: str) -> bool:
    normalized_rule = normalize_adblock_host(rule_host)
    return bool(
        normalized_rule
        and normalized_rule in adblock_host_suffix_candidates(host)
    )


def looks_like_adblock_host(host: str) -> bool:
    normalized = normalize_adblock_host(host)
    if not normalized:
        return False
    try:
        ipaddress.ip_address(normalized.strip("[]"))
        return True
    except ValueError:
        pass
    if "." not in normalized or ".." in normalized:
        return False
    return _HOST_RE.match(normalized) is not None
