from __future__ import annotations

import logging
import os
import pathlib

from services.logutil import log_exception_throttled, should_log

logger = logging.getLogger(__name__)


_LOCK_FD: int | None = None
_LOCK_PID: int | None = None


def _close_lock_fd(fd: int, *, log_key: str, message: str) -> None:
    try:
        os.close(fd)
    except Exception:
        log_exception_throttled(
            logger,
            log_key,
            interval_seconds=300.0,
            message=message,
        )


def _log_guard_failure(log_key: str, message: str) -> None:
    """Report a guard failure without exposing exception or path details."""
    try:
        if should_log(log_key, interval_seconds=300.0):
            logger.error("%s; background tasks disabled", message)
    except Exception:
        # Logging must not prevent application startup.
        pass


def acquire_background_lock() -> bool:
    """Multi-process guard for background workers.

    In production, app servers may spawn multiple processes (e.g., gunicorn workers).
    Without a guard, each process would start its own tailers/samplers and contend
    on the same runtime tables and log ingestion loops.

    Returns True if this process should start background tasks, False otherwise.

    Env overrides:
      - BACKGROUND_FORCE=1: always start background tasks (no locking)
      - BACKGROUND_LOCK_PATH: lock file path (default: /var/lib/squid-flask-proxy/background.lock)
    """
    if (os.environ.get("BACKGROUND_FORCE") or "").strip() == "1":
        return True

    try:
        return _acquire_background_lock_unforced()
    except Exception:
        _log_guard_failure(
            "background_guard.unexpected",
            "Unexpected background lock guard failure",
        )
        return False


def _acquire_background_lock_unforced() -> bool:
    global _LOCK_FD, _LOCK_PID

    current_pid = os.getpid()
    if _LOCK_FD is not None and current_pid == _LOCK_PID:
        return True

    lock_path = (
        os.environ.get("BACKGROUND_LOCK_PATH") or ""
    ).strip() or "/var/lib/squid-flask-proxy/background.lock"
    lock_dir = pathlib.Path(lock_path).parent
    if lock_dir:
        try:
            pathlib.Path(lock_dir).mkdir(exist_ok=True, parents=True)
        except Exception:
            _log_guard_failure(
                "background_guard.makedirs",
                "Failed to create background lock directory",
            )
            return False

    try:
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o644)
    except Exception:
        _log_guard_failure(
            "background_guard.open",
            "Failed to open background lock file",
        )
        return False

    try:
        import fcntl  # type: ignore[import-not-found]

        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)  # type: ignore[attr-defined]
        except BlockingIOError:
            _close_lock_fd(
                fd,
                log_key="background_guard.close.blocking",
                message="Failed to close background lock fd after contention",
            )
            return False
        except Exception:
            _close_lock_fd(
                fd,
                log_key="background_guard.close.flock_error",
                message="Failed to close background lock fd after flock error",
            )
            _log_guard_failure(
                "background_guard.flock",
                "Failed to acquire background lock",
            )
            return False
    except Exception:
        _close_lock_fd(
            fd,
            log_key="background_guard.close.non_posix",
            message="Failed to close background lock fd when locking was unavailable",
        )
        _log_guard_failure(
            "background_guard.locking_unavailable",
            "Background file locking is unavailable",
        )
        return False

    _LOCK_FD = fd
    _LOCK_PID = current_pid
    return True
