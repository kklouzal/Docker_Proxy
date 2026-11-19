from __future__ import annotations

import os
import re
from contextvars import ContextVar, Token
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

_PROXY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,62}$")
_PROXY_ID_UNSAFE_RUN_RE = re.compile(r"[^A-Za-z0-9_.:-]+")
_PROXY_ID_TRAVERSAL_TOKEN_RE = re.compile(r"\.\.")
_ACTIVE_PROXY_ID: ContextVar[str | None] = ContextVar("active_proxy_id", default=None)
_DEFAULT_PROXY_ID = "default"
_RESOLVING_DEFAULT: ContextVar[bool] = ContextVar(
    "resolving_default_proxy_id", default=False
)
_implicit_default_resolver: Callable[[], object] | None = None


def normalize_proxy_id(value: object | None) -> str:
    raw = "" if value is None else str(value).strip()
    if not raw or _PROXY_ID_TRAVERSAL_TOKEN_RE.search(raw):
        return _DEFAULT_PROXY_ID

    return _sanitize_proxy_id(raw)


def normalize_route_proxy_id(value: object | None) -> str:
    """Return an exact, syntactically safe proxy ID from a route selector.

    Route selection must not rewrite labels, traversal-shaped values, or
    overlong values into a different registered ID.  Exact IDs and historical
    aliases remain resolvable by the registry; lossy selectors fail safely to
    the default proxy.
    """
    raw = "" if value is None else str(value).strip()
    if (
        not raw
        or _PROXY_ID_TRAVERSAL_TOKEN_RE.search(raw)
        or not _PROXY_ID_RE.fullmatch(raw)
    ):
        return _DEFAULT_PROXY_ID

    return raw


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


def get_env_default_proxy_id() -> str:
    """Return the process environment's proxy identity (never touches MySQL).

    Proxy containers use this as their runtime identity; the Admin UI uses it
    only as the bootstrap default until an administrator chooses one.
    """
    return normalize_proxy_id(
        os.environ.get("DEFAULT_PROXY_ID")
        or os.environ.get("PROXY_INSTANCE_ID")
        or os.environ.get("PROXY_ID")
        or _DEFAULT_PROXY_ID,
    )


def set_implicit_default_proxy_resolver(
    resolver: Callable[[], object] | None,
) -> None:
    """Install the process-wide resolver for the implicit default proxy.

    Only the Admin UI web process installs one (see ``web/wsgi.py``) so that
    proxy-scoped work without a bound proxy follows the administrator's
    selection. Proxy containers never install a resolver and keep their
    environment identity without any MySQL dependency.
    """
    global _implicit_default_resolver
    _implicit_default_resolver = resolver


def get_default_proxy_id() -> str:
    """Return the implicit proxy for work with no bound proxy context.

    With an installed resolver its errors propagate (no silent environment
    fallback); re-entering the resolver is a programming error.
    """
    resolver = _implicit_default_resolver
    if resolver is None:
        return get_env_default_proxy_id()
    if _RESOLVING_DEFAULT.get():
        msg = "Implicit default proxy resolver re-entered get_default_proxy_id()."
        raise RuntimeError(msg)
    token = _RESOLVING_DEFAULT.set(True)
    try:
        return normalize_proxy_id(resolver())
    finally:
        _RESOLVING_DEFAULT.reset(token)


def get_bound_proxy_id() -> str | None:
    """Return the explicitly bound proxy, or None without resolving a default."""
    current = _ACTIVE_PROXY_ID.get()
    return normalize_proxy_id(current) if current else None


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
