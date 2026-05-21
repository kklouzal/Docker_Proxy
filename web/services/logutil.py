from __future__ import annotations

import threading
import time
from typing import TYPE_CHECKING

from services.errors import public_error_message

if TYPE_CHECKING:
    import logging

_lock = threading.Lock()
_last_log: dict[str, float] = {}


def should_log(key: str, *, interval_seconds: float) -> bool:
    now = time.monotonic()
    with _lock:
        last = _last_log.get(key, 0.0)
        if (now - last) < float(interval_seconds):
            return False
        _last_log[key] = now
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
