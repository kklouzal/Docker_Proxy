"""Small in-process cache concurrency helpers.

The coordinator serializes refreshes per cache key while allowing unrelated keys to
refresh independently.  Invalidations advance a generation so work started before
a clear cannot repopulate the cache afterward.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING, Any, TypeVar

if TYPE_CHECKING:
    from collections.abc import Callable, MutableMapping

K = TypeVar("K")
V = TypeVar("V")


class KeyedSingleFlight:
    """Coordinate check-refresh-publish cache sequences per key."""

    def __init__(self) -> None:
        self._state_lock = threading.RLock()
        self._key_locks: dict[Any, threading.RLock] = {}
        self._generation = 0

    def _lock_for(self, key: Any) -> threading.RLock:
        with self._state_lock:
            return self._key_locks.setdefault(key, threading.RLock())

    def get_or_build(
        self,
        cache: MutableMapping[K, tuple[float, V]],
        key: K,
        *,
        now: Callable[[], float],
        ttl_seconds: float,
        builder: Callable[[], V],
        copy_value: Callable[[V], V],
        prune: Callable[[], None] | None = None,
    ) -> V:
        key_lock = self._lock_for(key)
        with key_lock:
            checked_at = now()
            with self._state_lock:
                cached = cache.get(key)
                generation = self._generation
            if cached is not None and checked_at - cached[0] <= max(0.0, ttl_seconds):
                return copy_value(cached[1])

            value = builder()
            stored = copy_value(value)
            with self._state_lock:
                if generation == self._generation:
                    cache[key] = (checked_at, stored)
                    if prune is not None:
                        prune()
            return copy_value(stored)

    def run(self, key: Any, operation: Callable[[], V]) -> V:
        """Run an arbitrary cache transaction under the key's re-entrant lock."""
        with self._lock_for(key):
            return operation()

    def run_cache_transaction(
        self,
        cache: MutableMapping[K, Any],
        key: K,
        operation: Callable[[], V],
    ) -> V:
        """Run a cache transaction without publishing across an invalidation."""
        with self._lock_for(key):
            with self._state_lock:
                generation = self._generation
            value = operation()
            with self._state_lock:
                if generation != self._generation:
                    cache.pop(key, None)
            return value

    def clear(self, *caches: MutableMapping[Any, Any]) -> None:
        with self._state_lock:
            self._generation += 1
            for cache in caches:
                cache.clear()
