from __future__ import annotations

import ipaddress
import re
import urllib.parse

_DOMAIN_RE = re.compile(
    r"^(?=.{1,255}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$",
    re.IGNORECASE,
)


def _valid_dns_hostname(raw: str) -> bool:
    if len(raw) > 253:
        return False
    labels = raw.split(".")
    if not labels or any(not label for label in labels):
        return False
    for label in labels:
        if len(label) > 63 or not label[0].isalnum() or not label[-1].isalnum():
            return False
        if any(not (ch.isalnum() or ch == "-") for ch in label):
            return False
    return True


def _is_ambiguous_ipv4_host(raw: str) -> bool:
    candidate = raw.rstrip(".").lower()
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


def _is_valid_port(raw: str) -> bool:
    return raw.isdigit() and 1 <= int(raw) <= 65535


def _strip_bare_userinfo_authority(raw: str) -> str:
    """Accept legacy user@host:port authority tokens without raw credentials."""
    if "@" not in raw:
        return raw
    userinfo, authority = raw.rsplit("@", 1)
    if not userinfo or not authority:
        return ""
    if any(ch in userinfo for ch in (":", ".", "[", "]")):
        return ""
    if authority.startswith("["):
        closing = authority.find("]")
        if closing < 0:
            return ""
        suffix = authority[closing + 1 :]
        if not suffix.startswith(":") or not _is_valid_port(suffix[1:]):
            return ""
        return authority
    if authority.count(":") != 1:
        return ""
    host, port = authority.rsplit(":", 1)
    return authority if host and _is_valid_port(port) else ""


def normalize_domain(value: object) -> str:
    """Normalize host/domain strings shared by webcat builders and ACL helpers."""
    raw = str(value or "").strip().lower().rstrip(".")
    if not raw:
        return ""
    if "://" in raw:
        try:
            parsed = urllib.parse.urlsplit(raw)
            try:
                _ = parsed.port
            except ValueError:
                return ""
            if parsed.hostname:
                raw = parsed.hostname
        except Exception:
            raw = raw.split("://", 1)[1]
    raw = raw.strip().rstrip(".")
    raw = raw.removeprefix(".")
    if any(ch in raw for ch in ("/", "?", "#")):
        return ""
    raw = _strip_bare_userinfo_authority(raw)
    if not raw:
        return ""
    if raw.startswith("[") and "]" in raw:
        suffix = raw[raw.index("]") + 1 :].strip()
        if suffix:
            if not suffix.startswith(":") or not suffix[1:].isdigit():
                return ""
        raw = raw[1 : raw.index("]")]
    elif ":" in raw and raw.count(":") == 1:
        host, port = raw.rsplit(":", 1)
        if port.isdigit():
            raw = host
        else:
            return ""
    raw = raw.strip().strip("[]").rstrip(".")
    if not raw:
        return ""
    try:
        parsed_ip = ipaddress.ip_address(raw)
    except ValueError:
        if ":" in raw:
            return ""
    else:
        return str(parsed_ip)
    labels = raw.split(".")
    if not labels or any(not label for label in labels):
        return ""
    try:
        labels = [label.encode("idna").decode("ascii").lower() for label in labels]
    except Exception:
        return ""
    normalized = ".".join(labels).rstrip(".")
    if _is_ambiguous_ipv4_host(normalized):
        return ""
    return normalized if _valid_dns_hostname(normalized) else ""


def looks_like_domain(value: object) -> bool:
    domain = normalize_domain(value)
    if not domain or "." not in domain or ".." in domain or ":" in domain:
        return False
    return _DOMAIN_RE.match(domain) is not None
