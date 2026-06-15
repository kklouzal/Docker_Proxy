from __future__ import annotations

import ipaddress
import re

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
