from __future__ import annotations

# ruff: file-ignore[raw-string-in-exception, f-string-in-exception, raise-vanilla-args, typing-only-standard-library-import, docstring-missing-yields]
import hashlib
import os
import threading
import time
from collections.abc import Callable, Generator, Iterable, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from typing import Any

from services.db import DATABASE_ERRORS, mysql_error_code
from services.proxy_context import normalize_proxy_id
from services.proxy_lifecycle import ensure_lifecycle_schema
from services.row_access import row_value

_BLOCKING_ACTIONS = {"removing", "removed", "renaming"}
_RENAMED_ACTIONS = {"renamed"}
_LIFECYCLE_LOCK_TIMEOUT_SECONDS = 10


class ProxyLifecycleWriteError(ValueError):
    """Raised when a proxy-scoped write would bypass lifecycle state."""

    proxy_lifecycle_write_error = True


def is_proxy_lifecycle_write_error(exc: BaseException) -> bool:
    """Return whether an exception represents a lifecycle write block.

    Test suites and long-lived helper processes may reload this module while a
    writer still holds references imported before the reload.  The explicit
    marker keeps classification stable across those reload/import-order splits
    without treating same-named unrelated exceptions as lifecycle blocks.
    """
    return isinstance(exc, ProxyLifecycleWriteError) or (
        getattr(exc, "proxy_lifecycle_write_error", False) is True
    )


@dataclass(frozen=True)
class GuardedProxyBatch:
    """Canonical proxy id and prevalidated row materializer for a batch write."""

    decision: ProxyWriteDecision
    rows: tuple[tuple[Any, ...], ...]

    @property
    def proxy_id(self) -> str:
        return self.decision.proxy_id

    @property
    def requested_proxy_id(self) -> str:
        return self.decision.requested_proxy_id


@dataclass(frozen=True)
class ProxyWriteDecision:
    requested_proxy_id: str
    proxy_id: str
    resolved_alias: bool = False
    alias_action: str = ""


@dataclass(frozen=True)
class _CacheEntry:
    expires_at: float
    decision: ProxyWriteDecision


_cache_lock = threading.Lock()
_decision_cache: dict[tuple[str, bool, bool], _CacheEntry] = {}


def proxy_lifecycle_lock_name(proxy_id: object | None) -> str:
    prefix = "docker_proxy:proxy_lifecycle:"
    proxy_key = normalize_proxy_id(proxy_id)
    if len(prefix) + len(proxy_key) <= 64:
        return f"{prefix}{proxy_key}"

    digest = hashlib.sha256(proxy_key.encode("utf-8")).hexdigest()[:16]
    readable_prefix_size = 64 - len(prefix) - len(digest) - 1
    return f"{prefix}{proxy_key[:readable_prefix_size]}-{digest}"


def clear_proxy_write_guard_cache(proxy_id: object | None = None) -> None:
    if proxy_id is None:
        _reset_metadata_schema_flag()
    with _cache_lock:
        if proxy_id is None:
            _decision_cache.clear()
            return
        proxy_key = normalize_proxy_id(proxy_id)
        for key in list(_decision_cache):
            if proxy_key in {key[0], _decision_cache[key].decision.proxy_id}:
                _decision_cache.pop(key, None)


def _cache_ttl_seconds() -> float:
    raw = (os.environ.get("MYSQL_PROXY_WRITE_GUARD_CACHE_SECONDS") or "1").strip()
    try:
        return max(0.0, min(5.0, float(raw or "0")))
    except Exception:
        return 0.0


def _cache_get(key: tuple[str, bool, bool]) -> ProxyWriteDecision | None:
    ttl = _cache_ttl_seconds()
    if ttl <= 0:
        return None
    now = time.monotonic()
    with _cache_lock:
        entry = _decision_cache.get(key)
        if entry is None:
            return None
        if entry.expires_at <= now:
            _decision_cache.pop(key, None)
            return None
        return entry.decision


def _cache_put(key: tuple[str, bool, bool], decision: ProxyWriteDecision) -> None:
    ttl = _cache_ttl_seconds()
    if ttl <= 0:
        return
    with _cache_lock:
        _decision_cache[key] = _CacheEntry(time.monotonic() + ttl, decision)


def _metadata_error(
    message: str, exc: BaseException | None = None
) -> ProxyLifecycleWriteError:
    if exc is None:
        return ProxyLifecycleWriteError(message)
    return ProxyLifecycleWriteError(f"{message}: {exc}")


def _row_value(row: object, key: str, default: object = "") -> object:
    return row_value(row, key, default=default)


_schema_lock = threading.Lock()
_tombstone_schema_ensured = False

# One round trip returns every lifecycle fact the guard needs for one proxy id.
# Each subquery is a primary-key lookup; every selected column is NOT NULL, so a
# NULL value means "no row".  A missing table raises (fail closed) instead of
# being treated as "no metadata".  Alias and registry lookups are included only
# when the caller's contract consults them.
_TOMBSTONE_STATE_SQL = (
    "SELECT"
    " (SELECT action FROM proxy_lifecycle_tombstones WHERE proxy_id=%s LIMIT 1) AS tombstone_action,"
    " (SELECT target_proxy_id FROM proxy_lifecycle_tombstones WHERE proxy_id=%s LIMIT 1) AS tombstone_target,"
)
_ALIAS_STATE_SQL = " (SELECT proxy_id FROM proxy_id_aliases WHERE alias_proxy_id=%s LIMIT 1) AS alias_target,"
_REGISTRY_STATE_SQL = (
    " (SELECT status FROM proxy_instances WHERE proxy_id=%s LIMIT 1) AS registry_status"
)


def _lifecycle_state_sql(*, allow_alias: bool, require_registered: bool) -> str:
    return (
        _TOMBSTONE_STATE_SQL
        + (_ALIAS_STATE_SQL if allow_alias else " NULL AS alias_target,")
        + (_REGISTRY_STATE_SQL if require_registered else " NULL AS registry_status")
    )


@dataclass(frozen=True)
class _LifecycleState:
    tombstone_action: str | None
    tombstone_target: str
    alias_target: str | None
    registry_status: str | None


def _ensure_metadata_tables(conn: Any) -> None:
    """Create the tombstone table once per process instead of once per write.

    Schema migrations own the lifecycle tables; this keeps the historical
    self-healing CREATE for the tombstone table without issuing DDL on every
    guarded write.  A later "table missing" error resets the flag so the next
    write re-ensures it.
    """
    global _tombstone_schema_ensured
    if _tombstone_schema_ensured:
        return
    with _schema_lock:
        if _tombstone_schema_ensured:
            return
        try:
            ensure_lifecycle_schema(conn)
        except DATABASE_ERRORS as exc:
            raise _metadata_error(
                "Proxy lifecycle metadata is unavailable", exc
            ) from exc
        except Exception as exc:
            raise _metadata_error(
                "Proxy lifecycle metadata is unavailable", exc
            ) from exc
        _tombstone_schema_ensured = True


def _reset_metadata_schema_flag() -> None:
    global _tombstone_schema_ensured
    with _schema_lock:
        _tombstone_schema_ensured = False


def _lookup_lifecycle_state(
    conn: Any,
    proxy_key: str,
    *,
    allow_alias: bool,
    require_registered: bool,
) -> _LifecycleState:
    try:
        sql = _lifecycle_state_sql(
            allow_alias=allow_alias, require_registered=require_registered
        )
        row = conn.execute(sql, (proxy_key,) * sql.count("%s")).fetchone()
    except DATABASE_ERRORS as exc:
        if mysql_error_code(exc) == 1146:
            _reset_metadata_schema_flag()
        raise _metadata_error("Proxy lifecycle metadata is unavailable", exc) from exc
    except Exception as exc:
        raise _metadata_error("Proxy lifecycle metadata is unavailable", exc) from exc
    if row is None:
        raise _metadata_error("Proxy lifecycle metadata is unavailable")

    def _optional(key: str, index: int) -> str | None:
        value = row_value(row, key, index)
        return None if value is None else str(value)

    return _LifecycleState(
        tombstone_action=_optional("tombstone_action", 0),
        tombstone_target=_optional("tombstone_target", 1) or "",
        alias_target=_optional("alias_target", 2),
        registry_status=_optional("registry_status", 3),
    )


def _tombstone_redirect(
    proxy_key: str, state: _LifecycleState, *, allow_alias: bool
) -> str | None:
    if state.tombstone_action is None:
        return None
    action = state.tombstone_action or "removed"
    target = state.tombstone_target
    if action in _BLOCKING_ACTIONS:
        if action == "renaming" and target:
            msg = f"Proxy {proxy_key!r} is being renamed to {target!r}; proxy-scoped writes are blocked."
        elif action in {"removing", "removed"}:
            msg = f"Proxy {proxy_key!r} has been removed or is being removed; proxy-scoped writes are blocked."
        else:
            msg = f"Proxy {proxy_key!r} is in lifecycle state {action!r}; proxy-scoped writes are blocked."
        raise ProxyLifecycleWriteError(msg)
    if action in _RENAMED_ACTIONS:
        if not (allow_alias and target):
            raise ProxyLifecycleWriteError(
                f"Proxy {proxy_key!r} was renamed to {target!r}; stale proxy-scoped writes are blocked.",
            )
        return normalize_proxy_id(target)
    # Unknown lifecycle states fail closed rather than recreating orphan rows.
    raise ProxyLifecycleWriteError(
        f"Proxy {proxy_key!r} is in unknown lifecycle state {action!r}; proxy-scoped writes are blocked.",
    )


def _ensure_registered(proxy_key: str, state: _LifecycleState) -> None:
    if state.registry_status is None:
        raise ProxyLifecycleWriteError(
            f"Proxy {proxy_key!r} is not registered; proxy-scoped writes are blocked.",
        )
    status = state.registry_status or "unknown"
    if status in {
        "renaming",
        "rename_pending",
        "removing",
        "remove_pending",
        "removed",
    }:
        raise ProxyLifecycleWriteError(
            f"Proxy {proxy_key!r} is in lifecycle status {status!r}; proxy-scoped writes are blocked.",
        )


def resolve_proxy_write_id(
    conn: Any,
    proxy_id: object | None,
    *,
    allow_alias: bool = True,
    require_registered: bool = True,
    use_cache: bool = False,
) -> ProxyWriteDecision:
    """Resolve and validate a proxy id immediately before a proxy-owned write.

    The guard fails closed when tombstone/alias/registry metadata cannot be read.
    Each hop of the alias chain costs one combined metadata query; the common
    unaliased case is a single round trip.  Positive cache entries are opt-in and
    bounded; lifecycle transitions clear the in-process cache, and guarded writes
    re-check after acquiring the lifecycle lock.
    """
    requested = normalize_proxy_id(proxy_id)
    cache_key = (requested, bool(allow_alias), bool(require_registered))
    if use_cache:
        cached = _cache_get(cache_key)
        if cached is not None:
            return cached

    _ensure_metadata_tables(conn)
    current = requested
    resolved_alias = False
    alias_action = ""
    seen = {requested}
    for _ in range(4):
        state = _lookup_lifecycle_state(
            conn,
            current,
            allow_alias=allow_alias,
            require_registered=require_registered,
        )
        tombstone_target = _tombstone_redirect(current, state, allow_alias=allow_alias)
        if tombstone_target is not None:
            if tombstone_target in seen:
                raise ProxyLifecycleWriteError(
                    f"Proxy alias cycle detected for {requested!r}; proxy-scoped writes are blocked.",
                )
            seen.add(tombstone_target)
            current = tombstone_target
            resolved_alias = True
            alias_action = "renamed"
            continue
        if allow_alias and state.alias_target is not None:
            target = normalize_proxy_id(state.alias_target)
            if target != current:
                if target in seen:
                    raise ProxyLifecycleWriteError(
                        f"Proxy alias cycle detected for {requested!r}; proxy-scoped writes are blocked.",
                    )
                seen.add(target)
                current = target
                resolved_alias = True
                alias_action = alias_action or "alias"
                continue
        break
    else:
        raise ProxyLifecycleWriteError(
            f"Proxy alias chain for {requested!r} is too deep; proxy-scoped writes are blocked.",
        )

    # ``state`` was read for ``current`` in the final loop iteration and showed
    # no tombstone, so the registry status from the same statement is checked.
    if require_registered:
        _ensure_registered(current, state)
    decision = ProxyWriteDecision(
        requested_proxy_id=requested,
        proxy_id=current,
        resolved_alias=resolved_alias,
        alias_action=alias_action,
    )
    if use_cache:
        _cache_put(cache_key, decision)
    return decision


@contextmanager
def guarded_proxy_write(
    conn: Any,
    proxy_id: object | None,
    *,
    allow_alias: bool = True,
    require_registered: bool = True,
    timeout_seconds: int = _LIFECYCLE_LOCK_TIMEOUT_SECONDS,
) -> Generator[ProxyWriteDecision]:
    """Hold the proxy lifecycle lock while validating and performing a write."""
    if not hasattr(conn, "native"):
        yield ProxyWriteDecision(
            requested_proxy_id=normalize_proxy_id(proxy_id),
            proxy_id=normalize_proxy_id(proxy_id),
        )
        return
    first = resolve_proxy_write_id(
        conn,
        proxy_id,
        allow_alias=allow_alias,
        require_registered=require_registered,
        use_cache=True,
    )
    lock_name = proxy_lifecycle_lock_name(first.proxy_id)
    acquired = False
    try:
        row = conn.execute(
            "SELECT GET_LOCK(%s, %s) AS acquired",
            (lock_name, int(timeout_seconds)),
        ).fetchone()
        try:
            acquired = int(_row_value(row, "acquired", 0) or 0) == 1
        except Exception:
            acquired = False
        if not acquired:
            raise ProxyLifecycleWriteError(
                f"Timed out acquiring lifecycle write lock for proxy {first.proxy_id!r}.",
            )
        decision = resolve_proxy_write_id(
            conn,
            proxy_id,
            allow_alias=allow_alias,
            require_registered=require_registered,
            use_cache=False,
        )
        if decision.proxy_id != first.proxy_id:
            raise ProxyLifecycleWriteError(
                f"Proxy {first.proxy_id!r} changed lifecycle identity to {decision.proxy_id!r}; retry the write.",
            )
        yield decision
    finally:
        if acquired:
            with suppress(Exception):
                conn.execute("DO RELEASE_LOCK(%s)", (lock_name,))


def resolve_proxy_write_id_cached(
    conn: Any,
    proxy_id: object | None,
    *,
    allow_alias: bool = True,
    require_registered: bool = True,
) -> ProxyWriteDecision:
    """Resolve a proxy write id using the bounded positive lifecycle cache."""
    return resolve_proxy_write_id(
        conn,
        proxy_id,
        allow_alias=allow_alias,
        require_registered=require_registered,
        use_cache=True,
    )


def resolve_proxy_read_id_cached(
    conn: Any,
    proxy_id: object | None,
    *,
    allow_alias: bool = True,
    require_registered: bool = True,
) -> ProxyWriteDecision:
    """Resolve a proxy id for proxy-scoped reads using write-path identity rules.

    Proxy-owned writers canonicalize aliases through ``guarded_proxy_write`` before
    inserting rows. Read paths that look up those rows must use the same identity
    resolution or operator-visible evidence can disappear under renamed/aliased
    proxy ids even though the runtime write succeeded.
    """
    if not hasattr(conn, "native"):
        proxy_key = normalize_proxy_id(proxy_id)
        return ProxyWriteDecision(requested_proxy_id=proxy_key, proxy_id=proxy_key)
    return resolve_proxy_write_id_cached(
        conn,
        proxy_id,
        allow_alias=allow_alias,
        require_registered=require_registered,
    )


def guarded_proxy_rows(
    conn: Any,
    proxy_id: object | None,
    rows: Iterable[Any],
    row_factory: Callable[[str, Any], Sequence[Any]],
    *,
    allow_alias: bool = True,
    require_registered: bool = True,
    timeout_seconds: int = _LIFECYCLE_LOCK_TIMEOUT_SECONDS,
) -> GuardedProxyBatch:
    """Validate once, then materialize a batch with one canonical proxy id.

    High-volume observability writers use this at flush boundaries so lifecycle
    validation is one bounded/cacheable metadata check plus one recheck under the
    lifecycle lock per batch, not one registry/tombstone query per row.  If
    metadata is unavailable or the requested id is removed/removing/renaming, the
    call raises ProxyLifecycleWriteError before any rows are materialized.
    """
    original_rows = tuple(rows)
    if not original_rows:
        decision = resolve_proxy_write_id_cached(
            conn,
            proxy_id,
            allow_alias=allow_alias,
            require_registered=require_registered,
        )
        return GuardedProxyBatch(decision=decision, rows=())
    with guarded_proxy_write(
        conn,
        proxy_id,
        allow_alias=allow_alias,
        require_registered=require_registered,
        timeout_seconds=timeout_seconds,
    ) as decision:
        materialized = tuple(
            tuple(row_factory(decision.proxy_id, row)) for row in original_rows
        )
    return GuardedProxyBatch(decision=decision, rows=materialized)


def is_duplicate_key_error(exc: BaseException) -> bool:
    return mysql_error_code(exc) == 1062
