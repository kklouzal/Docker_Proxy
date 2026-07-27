from __future__ import annotations

import hashlib
import re

from services.proxy_context import get_proxy_id

_PSEUDONYM_DIGEST_RE = re.compile(r"^[0-9a-f]{10}$")


def pseudonymize(value: object, *, namespace: str) -> str:
    raw = str(value or "").strip().casefold()
    if not raw:
        return ""
    digest = hashlib.sha256(
        f"{get_proxy_id()}:{namespace}:{raw}".encode("utf-8", errors="replace"),
    ).hexdigest()
    return f"{namespace}-{digest[:10]}"


def is_pseudonymized_label(value: object, *, namespace: str) -> bool:
    text = str(value or "").strip()
    prefix = f"{namespace}-"
    if not text.startswith(prefix):
        return False
    return bool(_PSEUDONYM_DIGEST_RE.fullmatch(text[len(prefix) :]))
