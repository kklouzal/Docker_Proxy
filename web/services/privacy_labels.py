from __future__ import annotations

import hashlib
import hmac
import re

from services.proxy_context import get_proxy_id

_PSEUDONYM_DIGEST_RE = re.compile(r"^[0-9a-f]{10}$")
_PSEUDONYM_KEY: bytes | None = None
_KEY_DERIVATION_CONTEXT = b"docker-proxy/observability-pseudonyms/v1"


def configure_pseudonym_secret(secret: str | bytes) -> None:
    """Derive the process-local pseudonym key from the persistent app secret."""
    raw_secret = secret.encode("utf-8") if isinstance(secret, str) else secret
    if not raw_secret:
        msg = "Observability pseudonym secret must not be empty."
        raise RuntimeError(msg)
    global _PSEUDONYM_KEY
    _PSEUDONYM_KEY = hmac.digest(raw_secret, _KEY_DERIVATION_CONTEXT, "sha256")


def pseudonymize(value: object, *, namespace: str) -> str:
    raw = str(value or "").strip().casefold()
    if not raw:
        return ""
    if _PSEUDONYM_KEY is None:
        msg = "Observability pseudonym key material is unavailable."
        raise RuntimeError(msg)
    digest = hmac.new(
        _PSEUDONYM_KEY,
        f"{get_proxy_id()}:{namespace}:{raw}".encode("utf-8", errors="replace"),
        hashlib.sha256,
    ).hexdigest()
    return f"{namespace}-{digest[:10]}"


def is_pseudonymized_label(value: object, *, namespace: str) -> bool:
    text = str(value or "").strip()
    prefix = f"{namespace}-"
    if not text.startswith(prefix):
        return False
    return bool(_PSEUDONYM_DIGEST_RE.fullmatch(text[len(prefix) :]))
