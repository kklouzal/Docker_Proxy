from __future__ import annotations

import threading
import time
from typing import Dict


_lock = threading.Lock()
_last_log: Dict[str, float] = {}


def should_log(key: str, *, interval_seconds: float) -> bool:
    now = time.monotonic()
    with _lock:
        last = _last_log.get(key, 0.0)
        if (now - last) < float(interval_seconds):
            return False
        _last_log[key] = now
        return True


def log_exception_throttled(logger, key: str, *args, interval_seconds: float, message: str) -> None:
    """Log exceptions at most once per interval per key.

    Intended for long-running background loops where repeated failures would otherwise
    spam stderr.
    """
    try:
        if should_log(key, interval_seconds=interval_seconds):
            logger.exception(message, *args)
    except Exception:
        # Never let logging break the worker loop.
        pass
