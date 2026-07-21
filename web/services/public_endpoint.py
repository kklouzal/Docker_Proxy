from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit


def _valid_public_dns_host(value: str) -> bool:
    candidate = value.rstrip(".").lower()
    if not candidate or len(candidate) > 253:
        return False
    labels = candidate.split(".")
    return not any(
        not label
        or len(label) > 63
        or not label.isascii()
        or not label[0].isalnum()
        or not label[-1].isalnum()
        or any(not (ch.isalnum() or ch == "-") for ch in label)
        for label in labels
    )


def normalize_public_host(value: object | None, default: str = "") -> str:
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
            _port = parsed.port
        except Exception:
            return fallback
        if parsed.scheme.lower() not in {"http", "https"}:
            return fallback
        if parsed.username is not None or parsed.password is not None:
            return fallback
        host = parsed.hostname or ""
    elif candidate.startswith("[") or candidate.count(":") == 1:
        try:
            parsed = urlsplit(f"//{candidate}")
            _port = parsed.port
        except Exception:
            return fallback
        if parsed.username is not None or parsed.password is not None:
            return fallback
        host = parsed.hostname or ""
    elif candidate.count(":") > 1:
        host = candidate

    host = host.strip().strip("[]")
    if not host:
        return fallback
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    return host.rstrip(".").lower() if _valid_public_dns_host(host) else fallback


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
