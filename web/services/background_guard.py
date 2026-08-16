from __future__ import annotations

import logging
import os
import pathlib
import threading
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

from services.logutil import log_exception_throttled, should_log

logger = logging.getLogger(__name__)


_LOCK_FD: int | None = None
_LOCK_PID: int | None = None


class BackgroundServiceCoordinator:
    """Lazily establish process ownership and retry incomplete startup.

    Deferring this work until a worker handles a request avoids creating threads
    in a Gunicorn preload/master process.  Processes that lose lock contention
    keep retrying, so an existing or replacement worker can take over when the
    owner exits.
    """

    def __init__(
        self,
        starters: Iterable[Callable[[], None]],
        stoppers: Iterable[Callable[[], object]] = (),
    ) -> None:
        self._starters = tuple(starters)
        self._stoppers = tuple(stoppers)
        if self._stoppers and len(self._stoppers) != len(self._starters):
            msg = "background service starters and stoppers must have equal length"
            raise ValueError(msg)
        self._started: set[int] = set()
        self._pid: int | None = None
        self._mutex = threading.Lock()

    def ensure_started(self) -> bool:
        """Start every service in the lock-owning process; retry failures later."""
        with self._mutex:
            current_pid = os.getpid()
            if current_pid != self._pid:
                self._pid = current_pid
                self._started.clear()
            if not acquire_background_lock():
                return False

            for index, starter in enumerate(self._starters):
                if index in self._started:
                    continue
                try:
                    starter()
                except Exception:
                    log_exception_throttled(
                        logger,
                        f"background_guard.start.{index}",
                        interval_seconds=300.0,
                        message="Failed to start background service",
                    )
                else:
                    self._started.add(index)
            return len(self._started) == len(self._starters)

    def stop(self) -> bool:
        """Stop services started by this coordinator and release its process lock."""
        with self._mutex:
            current_pid = os.getpid()
            if current_pid != self._pid:
                self._pid = current_pid
                self._started.clear()
                return release_background_lock()

            stopped = True
            for index in sorted(self._started, reverse=True):
                if not self._stoppers:
                    stopped = False
                    continue
                try:
                    result = self._stoppers[index]()
                except Exception:
                    stopped = False
                    log_exception_throttled(
                        logger,
                        f"background_guard.stop.{index}",
                        interval_seconds=300.0,
                        message="Failed to stop background service",
                    )
                else:
                    if result is False:
                        stopped = False
                    else:
                        self._started.discard(index)

            if self._started:
                return False
            return release_background_lock() and stopped


def _close_lock_fd(fd: int, *, log_key: str, message: str) -> bool:
    try:
        os.close(fd)
    except Exception:
        log_exception_throttled(
            logger,
            log_key,
            interval_seconds=300.0,
            message=message,
        )
        return False
    return True


def _log_guard_failure(log_key: str, message: str) -> None:
    """Report a guard failure without exposing exception or path details."""
    try:
        if should_log(log_key, interval_seconds=300.0):
            logger.error("%s; background tasks disabled", message)
    except Exception:
        # Logging must not prevent application startup.
        pass


def _release_background_lock_for_force() -> bool:
    global _LOCK_FD, _LOCK_PID

    if _LOCK_FD is None:
        _LOCK_PID = None
        return True

    if not _close_lock_fd(
        _LOCK_FD,
        log_key="background_guard.close.force",
        message="Failed to close background lock fd for forced mode",
    ):
        return False

    _LOCK_FD = None
    _LOCK_PID = None
    return True


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
    try:
        if (os.environ.get("BACKGROUND_FORCE") or "").strip() == "1":
            return _release_background_lock_for_force()
        return _acquire_background_lock_unforced()
    except Exception:
        _log_guard_failure(
            "background_guard.unexpected",
            "Unexpected background lock guard failure",
        )
        return False


def release_background_lock() -> bool:
    """Release this process's background lock, without unlocking an inherited fd."""
    global _LOCK_FD, _LOCK_PID

    current_pid = os.getpid()
    if _LOCK_FD is None:
        _LOCK_PID = None
        return True
    if current_pid != _LOCK_PID:
        # A child must only close its inherited descriptor; explicit flock unlock
        # would also release the parent's shared open-file-description lock.
        fd = _LOCK_FD
        if not _close_lock_fd(
            fd,
            log_key="background_guard.close.release_inherited",
            message="Failed to close inherited background lock fd during release",
        ):
            return False
    else:
        fd = _LOCK_FD
        if not _close_lock_fd(
            fd,
            log_key="background_guard.close.release",
            message="Failed to close background lock fd during release",
        ):
            return False
    _LOCK_FD = None
    _LOCK_PID = None
    return True


def _acquire_background_lock_unforced() -> bool:
    global _LOCK_FD, _LOCK_PID

    current_pid = os.getpid()
    if _LOCK_FD is not None and current_pid == _LOCK_PID:
        return True
    if _LOCK_FD is not None:
        inherited_fd = _LOCK_FD
        # Forked descriptors share flock state; close this process's copy rather
        # than explicitly unlocking the parent's open file description.
        if not _close_lock_fd(
            inherited_fd,
            log_key="background_guard.close.inherited",
            message="Failed to close inherited background lock fd",
        ):
            return False
        _LOCK_FD = None
        _LOCK_PID = None

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
