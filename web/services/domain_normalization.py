from __future__ import annotations

import re
import urllib.parse

_DOMAIN_RE = re.compile(
    r"^(?=.{1,255}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$",
    re.IGNORECASE,
)


def normalize_domain(value: object) -> str:
    """Normalize host/domain strings shared by webcat builders and ACL helpers."""
    raw = str(value or "").strip().lower().rstrip(".")
    if not raw:
        return ""
    if "://" in raw:
        try:
            parsed = urllib.parse.urlsplit(raw)
            if parsed.hostname:
                raw = parsed.hostname
        except Exception:
            raw = raw.split("://", 1)[1]
    raw = raw.strip().rstrip(".")
    raw = raw.removeprefix(".")
    raw = raw.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in raw:
        raw = raw.rsplit("@", 1)[1]
    if raw.startswith("[") and "]" in raw:
        raw = raw[1 : raw.index("]")]
    elif ":" in raw and raw.count(":") == 1:
        host, port = raw.rsplit(":", 1)
        if port.isdigit():
            raw = host
    raw = raw.strip().strip("[]").rstrip(".")
    if not raw:
        return ""
    if ":" in raw:
        return raw
    labels = [label for label in raw.split(".") if label]
    if not labels:
        return ""
    try:
        labels = [label.encode("idna").decode("ascii").lower() for label in labels]
    except Exception:
        labels = [label.lower() for label in labels]
    return ".".join(labels).rstrip(".")


def looks_like_domain(value: object) -> bool:
    domain = normalize_domain(value)
    if not domain or "." not in domain or ".." in domain or ":" in domain:
        return False
    return _DOMAIN_RE.match(domain) is not None
