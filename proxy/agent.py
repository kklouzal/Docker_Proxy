from __future__ import annotations

import logging
import signal
import threading
import time

from services.db import DATABASE_ERRORS
from services.errors import public_error_message
from services.logutil import log_exception_throttled, should_log
from services.runtime_helpers import env_float as _env_float

from proxy.runtime import get_runtime

logger = logging.getLogger(__name__)

_started = False
_started_loop_names: set[str] = set()
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


def _run_once_logged(key: str, message: str, func) -> tuple[bool, object | None]:
    try:
        return True, func()
    except Exception as exc:
        _log_recoverable_or_unexpected(
            key,
            interval_seconds=30.0,
            recoverable_message=message,
            unexpected_message=message,
            exc=exc,
        )
        return False, None


def _sync_result_ok(result: object | None) -> bool:
    return bool(
        getattr(result, "get", lambda _key, _default=None: _default)("ok", False),
    )


def _sync_loop(runtime, *, force: bool = False):
    if bool(getattr(runtime, "recovery_initial_capture_required", False)):
        ensure_startup_schema = getattr(runtime, "ensure_startup_schema", None)
        if callable(ensure_startup_schema):
            ensure_startup_schema()
    runtime.start_background_tasks()
    result = runtime.sync_from_db(force=force)
    capture_recovery_bundle = getattr(runtime, "capture_recovery_bundle", None)
    if (
        callable(capture_recovery_bundle)
        and bool(getattr(runtime, "recovery_initial_capture_required", False))
        and _sync_result_ok(result)
    ):
        capture_recovery_bundle(
            reason="startup_initial",
            required=True,
            changed=bool(
                getattr(result, "get", lambda _key, _default=None: _default)(
                    "changed",
                    False,
                ),
            ),
        )
    return result


def start_agent() -> None:
    global _started
    with _start_lock:
        if _started:
            return

        runtime = get_runtime()
        startup_recovery = None
        startup_schema_ok = True
        ensure_startup_schema = getattr(runtime, "ensure_startup_schema", None)
        run_startup_recovery = getattr(runtime, "run_startup_recovery", None)
        if callable(run_startup_recovery):
            startup_recovery = run_startup_recovery()
        if callable(ensure_startup_schema) and (
            startup_recovery is None
            or bool(getattr(startup_recovery, "capture_required", False))
        ):
            # A present bundle path runs schema inside recovery before adoption.
            # For brand-new/no-bundle proxies, migrate explicitly here before
            # normal registration/default refresh/apply can write DB state.
            startup_schema_ok, _schema = _run_once_logged(
                "proxy.agent.startup_schema",
                "Initial startup schema migration failed",
                ensure_startup_schema,
            )

        # MySQL/control-plane outages must not kill the local proxy agent.  The
        # proxy data plane, public PAC/WPAD listener, and supervisor health are
        # local services and should remain alive while control-plane DB work is
        # retried by the regular loops below.
        if startup_schema_ok:
            registered_ok, _registered = _run_once_logged(
                "proxy.agent.initial_register",
                "Initial proxy registration failed",
                runtime.ensure_registered,
            )
            bootstrap_ok, _bootstrap = _run_once_logged(
                "proxy.agent.initial_bootstrap",
                "Initial proxy revision bootstrap failed",
                runtime.bootstrap_revision_if_missing,
            )
            background_ok, _background = _run_once_logged(
                "proxy.agent.initial_background",
                "Initial proxy background task startup failed",
                runtime.start_background_tasks,
            )
            sync_ok, sync_result = _run_once_logged(
                "proxy.agent.initial_sync",
                "Initial proxy sync failed",
                lambda: runtime.sync_from_db(force=False),
            )
        else:
            registered_ok = bootstrap_ok = background_ok = sync_ok = False
            sync_result = None
        capture_recovery_bundle = getattr(runtime, "capture_recovery_bundle", None)
        if (
            callable(capture_recovery_bundle)
            and startup_recovery is not None
            and bool(getattr(startup_recovery, "capture_required", False))
        ):
            if (
                registered_ok
                and bootstrap_ok
                and background_ok
                and sync_ok
                and _sync_result_ok(sync_result)
            ):
                capture_recovery_bundle(
                    reason="startup_initial",
                    required=True,
                    changed=bool(
                        getattr(
                            sync_result, "get", lambda _key, _default=None: _default
                        )(
                            "changed",
                            False,
                        ),
                    ),
                )
            else:
                logger.warning(
                    "Proxy recovery initial capture deferred for proxy_id=%s because initial DB startup did not complete",
                    getattr(startup_recovery, "proxy_id", ""),
                )

        heartbeat_interval = _env_float(
            "PROXY_HEARTBEAT_INTERVAL_SECONDS",
            90.0,
            minimum=1.0,
            maximum=3600.0,
        )
        sync_interval = _env_float(
            "PROXY_SYNC_INTERVAL_SECONDS",
            30.0,
            minimum=1.0,
            maximum=3600.0,
        )

        loops = (
            ("proxy-heartbeat", heartbeat_interval, runtime.heartbeat),
            (
                "proxy-sync-loop",
                sync_interval,
                lambda: _sync_loop(runtime, force=False),
            ),
        )
        for name, interval, func in loops:
            if name in _started_loop_names:
                continue
            threading.Thread(
                target=_loop,
                args=(interval, func),
                name=name,
                daemon=True,
            ).start()
            _started_loop_names.add(name)
        _started = True
        _started_loop_names.clear()


def main() -> None:
    stop_event = threading.Event()

    def request_shutdown(_signum, _frame) -> None:
        stop_event.set()

    signal.signal(signal.SIGTERM, request_shutdown)
    signal.signal(signal.SIGINT, request_shutdown)
    start_agent()
    stop_event.wait()
    runtime = get_runtime()
    if not runtime.stop_background_tasks(timeout=10.0):
        logger.warning(
            "Proxy background telemetry shutdown exceeded its flush deadline"
        )


if __name__ == "__main__":
    main()
