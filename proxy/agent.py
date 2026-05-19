from __future__ import annotations

import logging
import threading
import time

from services.db import DATABASE_ERRORS
from services.errors import public_error_message
from services.logutil import log_exception_throttled, should_log
from services.runtime_helpers import env_float as _env_float

from proxy.runtime import get_runtime

logger = logging.getLogger(__name__)

_started = False
_start_lock = threading.Lock()


def _loop(interval: float, func) -> None:
    loop_name = getattr(func, "__name__", "agent-loop")
    while True:
        try:
            func()
        except Exception as exc:
            _log_recoverable_or_unexpected(
                f"proxy.agent.{loop_name}",
                interval_seconds=max(5.0, float(interval)),
                recoverable_message=f"Proxy agent loop '{loop_name}' is waiting for database availability",
                unexpected_message=f"Proxy agent loop '{loop_name}' failed",
                exc=exc,
            )
        time.sleep(interval)


def _log_recoverable_or_unexpected(
    key: str,
    *,
    interval_seconds: float,
    recoverable_message: str,
    unexpected_message: str,
    exc: BaseException,
) -> None:
    if isinstance(exc, DATABASE_ERRORS):
        if should_log(key, interval_seconds=interval_seconds):
            detail = public_error_message(exc, default="Database is unavailable.")
            logger.warning("%s: %s", recoverable_message, detail)
        return
    log_exception_throttled(
        logger,
        key,
        interval_seconds=interval_seconds,
        message=unexpected_message,
    )


def _run_once_logged(key: str, message: str, func) -> None:
    try:
        func()
    except Exception as exc:
        _log_recoverable_or_unexpected(
            key,
            interval_seconds=30.0,
            recoverable_message=message,
            unexpected_message=message,
            exc=exc,
        )


def _sync_loop(runtime, *, force: bool = False):
    runtime.start_background_tasks()
    return runtime.sync_from_db(force=force)


def start_agent() -> None:
    global _started
    with _start_lock:
        if _started:
            return
        _started = True

        runtime = get_runtime()

        # MySQL/control-plane outages must not kill the local proxy agent.  The
        # proxy data plane, public PAC/WPAD listener, and supervisor health are
        # local services and should remain alive while control-plane DB work is
        # retried by the regular loops below.
        _run_once_logged(
            "proxy.agent.initial_register",
            "Initial proxy registration failed",
            runtime.ensure_registered,
        )
        _run_once_logged(
            "proxy.agent.initial_bootstrap",
            "Initial proxy revision bootstrap failed",
            runtime.bootstrap_revision_if_missing,
        )
        _run_once_logged(
            "proxy.agent.initial_background",
            "Initial proxy background task startup failed",
            runtime.start_background_tasks,
        )
        _run_once_logged(
            "proxy.agent.initial_sync",
            "Initial proxy sync failed",
            lambda: runtime.sync_from_db(force=False),
        )

        heartbeat_interval = _env_float(
            "PROXY_HEARTBEAT_INTERVAL_SECONDS", 90.0, minimum=1.0, maximum=3600.0,
        )
        sync_interval = _env_float(
            "PROXY_SYNC_INTERVAL_SECONDS", 30.0, minimum=1.0, maximum=3600.0,
        )

        threading.Thread(
            target=_loop,
            args=(heartbeat_interval, runtime.heartbeat),
            name="proxy-heartbeat",
            daemon=True,
        ).start()
        threading.Thread(
            target=_loop,
            args=(sync_interval, lambda: _sync_loop(runtime, force=False)),
            name="proxy-sync-loop",
            daemon=True,
        ).start()


def main() -> None:
    start_agent()
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
