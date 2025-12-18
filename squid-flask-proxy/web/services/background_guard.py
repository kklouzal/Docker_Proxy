from __future__ import annotations

import logging
import os
from typing import Optional

from services.logutil import log_exception_throttled


logger = logging.getLogger(__name__)


_LOCK_FD: Optional[int] = None


def acquire_background_lock() -> bool:
    """Best-effort multi-process guard for background workers.

    In production, app servers may spawn multiple processes (e.g., gunicorn workers).
    Without a guard, each process would start its own tailers/samplers and contend
    on the same SQLite files.

    Returns True if this process should start background tasks, False otherwise.

    Env overrides:
      - BACKGROUND_FORCE=1: always start background tasks (no locking)
      - BACKGROUND_LOCK_PATH: lock file path (default: /var/lib/squid-flask-proxy/background.lock)
    """

    if (os.environ.get("BACKGROUND_FORCE") or "").strip() == "1":
        return True

    lock_path = (os.environ.get("BACKGROUND_LOCK_PATH") or "").strip() or "/var/lib/squid-flask-proxy/background.lock"
    lock_dir = os.path.dirname(lock_path)
    if lock_dir:
        try:
            os.makedirs(lock_dir, exist_ok=True)
        except Exception:
            # If we can't create directories, don't block startup.
            log_exception_throttled(
                logger,
                "background_guard.makedirs",
                interval_seconds=300.0,
                message="Failed to create BACKGROUND_LOCK_PATH directory; allowing background tasks to start",
            )
            return True

    try:
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o644)
    except Exception:
        return True

    try:
        import fcntl  # type: ignore[import-not-found]

        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)  # type: ignore[attr-defined]
        except BlockingIOError:
            try:
                os.close(fd)
            except Exception:
                log_exception_throttled(
                    logger,
                    "background_guard.close.blocking",
                    interval_seconds=300.0,
                    message="Failed to close background lock fd after contention",
                )
            return False
        except Exception:
            try:
                os.close(fd)
            except Exception:
                log_exception_throttled(
                    logger,
                    "background_guard.close.flock_error",
                    interval_seconds=300.0,
                    message="Failed to close background lock fd after flock error",
                )
            return True
    except Exception:
        # Non-POSIX environment (or locking unavailable): allow background.
        try:
            os.close(fd)
        except Exception:
            log_exception_throttled(
                logger,
                "background_guard.close.non_posix",
                interval_seconds=300.0,
                message="Failed to close background lock fd in non-POSIX environment",
            )
        return True

    global _LOCK_FD
    _LOCK_FD = fd
    return True
