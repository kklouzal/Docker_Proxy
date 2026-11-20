from __future__ import annotations

import os
import re

from services.runtime_helpers import normalize_config_bool

_COMPRESSIBLE_MIMETYPES = frozenset(
    {
        "application/javascript",
        "application/json",
        "application/x-javascript",
        "application/x-ns-proxy-autoconfig",
        "text/css",
        "text/csv",
        "text/html",
        "text/javascript",
        "text/plain",
        "text/xml",
    },
)
_QVALUE_PATTERN = re.compile(r"(?:0(?:\.\d{0,3})?|1(?:\.0{0,3})?)\Z")
TRANSFORMATION_INVALIDATED_HEADERS = (
    "ETag",
    "Content-Digest",
    "Repr-Digest",
    "Digest",
    "Content-MD5",
)


def gzip_responses_enabled(config_value: object | None = None) -> bool:
    """Whether opportunistic gzip is on (``ENABLE_GZIP_RESPONSES``, default on)."""
    return normalize_config_bool(
        os.environ.get("ENABLE_GZIP_RESPONSES") or config_value,
        default=True,
    )


def compressible_mimetype(content_type: str | None) -> bool:
    mimetype = (content_type or "").split(";", 1)[0].strip().lower()
    return mimetype in _COMPRESSIBLE_MIMETYPES or mimetype.endswith("+json")


def client_accepts_gzip(header: str) -> bool:
    """Parse an ``Accept-Encoding`` value; explicit gzip wins over ``*``."""
    gzip_seen = False
    gzip_accepted = True
    wildcard_seen = False
    wildcard_accepted = True
    for part in header.split(","):
        bits = [bit.strip().lower() for bit in part.split(";")]
        if not bits or bits[0] not in {"gzip", "*"}:
            continue
        quality = 1.0
        for parameter in bits[1:]:
            if not parameter.startswith("q="):
                continue
            raw_quality = parameter.split("=", 1)[1]
            quality = (
                float(raw_quality) if _QVALUE_PATTERN.fullmatch(raw_quality) else 0.0
            )
            break
        if bits[0] == "gzip":
            gzip_seen = True
            gzip_accepted = gzip_accepted and quality > 0.0
        else:
            wildcard_seen = True
            wildcard_accepted = wildcard_accepted and quality > 0.0
    if gzip_seen:
        return gzip_accepted
    return wildcard_seen and wildcard_accepted
