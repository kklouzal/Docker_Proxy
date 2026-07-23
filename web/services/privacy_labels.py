from __future__ import annotations

import hashlib

from services.proxy_context import get_proxy_id


def pseudonymize(value: object, *, namespace: str) -> str:
    raw = str(value or "").strip().casefold()
    if not raw:
        return ""
    digest = hashlib.sha256(
        f"{get_proxy_id()}:{namespace}:{raw}".encode("utf-8", errors="replace"),
    ).hexdigest()
    return f"{namespace}-{digest[:10]}"
