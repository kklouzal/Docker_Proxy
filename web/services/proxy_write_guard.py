from __future__ import annotations

# ruff: noqa: EM101,EM102,TRY003,TC003,DOC402
import os
import threading
import time
from collections.abc import Callable, Iterable, Iterator, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from typing import Any

from services.db import DATABASE_ERRORS, mysql_error_code, table_exists
from services.proxy_context import normalize_proxy_id
from services.proxy_lifecycle import ensure_lifecycle_schema

_BLOCKING_ACTIONS = {"removing", "removed", "renaming"}
_RENAMED_ACTIONS = {"renamed"}
_LIFECYCLE_LOCK_TIMEOUT_SECONDS = 10


class ProxyLifecycleWriteError(ValueError):
    """Raised when a proxy-scoped write would bypass lifecycle state."""


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
    return f"docker_proxy:proxy_lifecycle:{normalize_proxy_id(proxy_id)}"[:64]


def clear_proxy_write_guard_cache(proxy_id: object | None = None) -> None:
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


def _metadata_error(message: str, exc: BaseException | None = None) -> ProxyLifecycleWriteError:
    if exc is None:
        return ProxyLifecycleWriteError(message)
    return ProxyLifecycleWriteError(f"{message}: {exc}")


def _row_value(row: object, key: str, default: object = "") -> object:
    try:
        return row[key]  # type: ignore[index]
    except Exception:
        return default


def _ensure_metadata_tables(conn: Any) -> None:
    try:
        ensure_lifecycle_schema(conn)
    except DATABASE_ERRORS as exc:
        raise _metadata_error("Proxy lifecycle metadata is unavailable", exc) from exc
    except Exception as exc:
        raise _metadata_error("Proxy lifecycle metadata is unavailable", exc) from exc


def _table_available(conn: Any, table_name: str) -> bool:
    try:
        return table_exists(conn, table_name)
    except DATABASE_ERRORS as exc:
        raise _metadata_error("Proxy lifecycle metadata is unavailable", exc) from exc
    except Exception as exc:
        raise _metadata_error("Proxy lifecycle metadata is unavailable", exc) from exc


def _check_tombstone(conn: Any, proxy_key: str, *, allow_alias: bool) -> str | None:
    try:
        row = conn.execute(
            "SELECT action, target_proxy_id FROM proxy_lifecycle_tombstones WHERE proxy_id=%s LIMIT 1",
            (proxy_key,),
        ).fetchone()
    except DATABASE_ERRORS as exc:
        raise _metadata_error("Proxy lifecycle tombstones are unavailable", exc) from exc
    except Exception as exc:
        raise _metadata_error("Proxy lifecycle tombstones are unavailable", exc) from exc
    if row is None:
        return None
    action = str(_row_value(row, "action") or "removed")
    target = str(_row_value(row, "target_proxy_id") or "")
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


def _alias_target(conn: Any, proxy_key: str) -> str | None:
    if not _table_available(conn, "proxy_id_aliases"):
        return None
    try:
        row = conn.execute(
            "SELECT proxy_id FROM proxy_id_aliases WHERE alias_proxy_id=%s LIMIT 1",
            (proxy_key,),
        ).fetchone()
    except DATABASE_ERRORS as exc:
        raise _metadata_error("Proxy alias metadata is unavailable", exc) from exc
    except Exception as exc:
        raise _metadata_error("Proxy alias metadata is unavailable", exc) from exc
    if row is None:
        return None
    return normalize_proxy_id(_row_value(row, "proxy_id"))


def _ensure_registered(conn: Any, proxy_key: str) -> None:
    if not _table_available(conn, "proxy_instances"):
        if not hasattr(conn, "native"):
            # Unit tests commonly use lightweight fake connections that only model
            # the service table under test. Real MySQL connections must have
            # registry metadata and fail closed above.
            return
        raise ProxyLifecycleWriteError(
            "Proxy registry metadata is unavailable; proxy-scoped writes are blocked.",
        )
    try:
        row = conn.execute(
            "SELECT status FROM proxy_instances WHERE proxy_id=%s LIMIT 1",
            (proxy_key,),
        ).fetchone()
    except DATABASE_ERRORS as exc:
        raise _metadata_error("Proxy registry metadata is unavailable", exc) from exc
    except Exception as exc:
        raise _metadata_error("Proxy registry metadata is unavailable", exc) from exc
    if row is None:
        raise ProxyLifecycleWriteError(
            f"Proxy {proxy_key!r} is not registered; proxy-scoped writes are blocked.",
        )
    status = str(_row_value(row, "status") or "unknown")
    if status in {"renaming", "rename_pending", "removing", "remove_pending"}:
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
    Positive cache entries are opt-in and bounded; lifecycle transitions clear the
    in-process cache, and guarded writes re-check after acquiring the lifecycle lock.
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
        tombstone_target = _check_tombstone(conn, current, allow_alias=allow_alias)
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
        if allow_alias:
            target = _alias_target(conn, current)
            if target is not None and target != current:
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

    _check_tombstone(conn, current, allow_alias=False)
    if require_registered:
        _ensure_registered(conn, current)
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
) -> Iterator[ProxyWriteDecision]:
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
        materialized = tuple(tuple(row_factory(decision.proxy_id, row)) for row in original_rows)
    return GuardedProxyBatch(decision=decision, rows=materialized)


def is_duplicate_key_error(exc: BaseException) -> bool:
    return mysql_error_code(exc) == 1062
