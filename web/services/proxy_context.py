from __future__ import annotations

import os
import re
from contextvars import ContextVar, Token

_PROXY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,62}$")
_PROXY_ID_UNSAFE_RUN_RE = re.compile(r"[^A-Za-z0-9_.:-]+")
_PROXY_ID_TRAVERSAL_TOKEN_RE = re.compile(r"\.\.")
_ACTIVE_PROXY_ID: ContextVar[str | None] = ContextVar("active_proxy_id", default=None)
_DEFAULT_PROXY_ID = "default"


def normalize_proxy_id(value: object | None) -> str:
    raw = "" if value is None else str(value).strip()
    if not raw or _PROXY_ID_TRAVERSAL_TOKEN_RE.search(raw):
        return _DEFAULT_PROXY_ID

    return _sanitize_proxy_id(raw)


def normalize_route_proxy_id(value: object | None) -> str:
    """Normalize a proxy selector from a URL route/query parameter.

    Route links historically tolerated pasted/display proxy labels with spaces or
    other delimiters and canonicalized them before matching the registered proxy
    inventory.  Keep the generic proxy-id normalizer strict for raw IDs used in
    stateful or destructive contexts, but allow URL selection to resolve only to
    a syntactically safe canonical ID.
    """
    raw = "" if value is None else str(value).strip()
    if not raw:
        return _DEFAULT_PROXY_ID

    return _sanitize_proxy_id(raw)


def _sanitize_proxy_id(raw: str) -> str:
    """Return a safe canonical proxy id from an already stripped value."""
    cleaned = _PROXY_ID_UNSAFE_RUN_RE.sub("-", raw)
    if len(cleaned) > 63:
        cleaned = cleaned[:63]
    cleaned = cleaned.strip("-._:")
    if not cleaned or _PROXY_ID_TRAVERSAL_TOKEN_RE.search(cleaned):
        return _DEFAULT_PROXY_ID
    if not _PROXY_ID_RE.match(cleaned):
        return _DEFAULT_PROXY_ID
    return cleaned


def get_default_proxy_id() -> str:
    return normalize_proxy_id(
        os.environ.get("DEFAULT_PROXY_ID")
        or os.environ.get("PROXY_INSTANCE_ID")
        or os.environ.get("PROXY_ID")
        or _DEFAULT_PROXY_ID,
    )


def get_proxy_id(default: object | None = None) -> str:
    current = _ACTIVE_PROXY_ID.get()
    if current:
        return normalize_proxy_id(current)
    if default is not None:
        return normalize_proxy_id(default)
    return get_default_proxy_id()


def set_proxy_id(value: object | None) -> Token[str | None]:
    return _ACTIVE_PROXY_ID.set(normalize_proxy_id(value))


def reset_proxy_id(token: Token[str | None]) -> None:
    _ACTIVE_PROXY_ID.reset(token)
