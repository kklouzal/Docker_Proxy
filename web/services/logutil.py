from __future__ import annotations

import math
import threading
import time
from typing import TYPE_CHECKING

from services.errors import public_error_message

if TYPE_CHECKING:
    import logging

_lock = threading.Lock()
_last_log: dict[str, float] = {}
_last_log_interval: dict[str, float] = {}
_last_prune = 0.0

# Keep recently seen throttle keys long enough that low-frequency failures remain
# quiet, but periodically shed one-off/dynamic keys from long-running workers.
_THROTTLE_KEY_MIN_RETENTION_SECONDS = 3600.0
_THROTTLE_KEY_PRUNE_INTERVAL_SECONDS = 300.0


def _normalize_interval_seconds(interval_seconds: float) -> float:
    try:
        interval = float(interval_seconds)
    except (TypeError, ValueError, OverflowError):
        return 0.0
    if not math.isfinite(interval) or interval < 0.0:
        return 0.0
    return interval


def _retention_seconds(interval_seconds: float) -> float:
    return max(_THROTTLE_KEY_MIN_RETENTION_SECONDS, interval_seconds)


def _remember_interval(key: str, interval_seconds: float) -> None:
    _last_log_interval[key] = max(_last_log_interval.get(key, 0.0), interval_seconds)


def _prune_stale_locked(now: float, *, protected_key: str | None = None) -> None:
    for stored_key, last in list(_last_log.items()):
        if stored_key == protected_key:
            continue
        age = now - last
        interval = _last_log_interval.get(stored_key, 0.0)
        if age >= _retention_seconds(interval):
            _last_log.pop(stored_key, None)
            _last_log_interval.pop(stored_key, None)


def _maybe_prune_stale_locked(now: float, *, protected_key: str | None = None) -> None:
    global _last_prune

    if (now - _last_prune) < _THROTTLE_KEY_PRUNE_INTERVAL_SECONDS:
        return
    _last_prune = now
    _prune_stale_locked(now, protected_key=protected_key)


def should_log(key: str, *, interval_seconds: float) -> bool:
    interval = _normalize_interval_seconds(interval_seconds)
    now = time.monotonic()
    with _lock:
        last = _last_log.get(key)
        if last is not None and (now - last) < interval:
            _remember_interval(key, interval)
            _maybe_prune_stale_locked(now, protected_key=key)
            return False
        _maybe_prune_stale_locked(now)
        _last_log[key] = now
        _remember_interval(key, interval)
        return True


def log_exception_throttled(
    logger,
    key: str,
    *args,
    interval_seconds: float,
    message: str,
) -> None:
    """Log exceptions at most once per interval per key.

    Intended for long-running background loops where repeated failures would otherwise
    spam stderr.
    """
    try:
        if should_log(key, interval_seconds=interval_seconds):
            logger.exception(message, *args)  # noqa: LOG004
    except Exception:
        # Never let logging break the worker loop.
        pass


def log_database_unavailable(
    logger: logging.Logger,
    key: str,
    message: str,
    exc: BaseException,
    *,
    interval_seconds: float = 1800.0,
) -> None:
    """Log recoverable database outages without traceback noise."""
    try:
        if should_log(key, interval_seconds=interval_seconds):
            logger.warning(
                "%s: %s",
                message,
                public_error_message(exc, default="Database is unavailable."),
            )
    except Exception:
        pass
