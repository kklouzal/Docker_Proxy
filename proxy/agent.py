from __future__ import annotations

import logging
import signal
import threading
import time
from typing import Any

from services.db import (
    DATABASE_ERRORS,
    add_mysql_recovery_listener,
    transient_mysql_cause,
)
from services.errors import public_error_message
from services.logutil import (
    configure_process_logging,
    log_exception_throttled,
    should_log,
)
from services.observability_backoff import DatabaseWriteBackoff
from services.runtime_helpers import env_float as _env_float

from proxy.control_plane_state import (
    clear_control_plane_ready,
    mark_control_plane_ready,
)
from proxy.runtime import get_runtime

logger = logging.getLogger(__name__)

_started = False
_started_loop_names: set[str] = set()
_loop_threads: list[threading.Thread] = []
_start_lock = threading.Lock()
_SHUTDOWN_TIMEOUT_SECONDS = 10.0
_WAKE_POLL_SECONDS = 1.0
# How soon Squid work left unfinished by an exited process is resumed.
SQUID_TRANSACTION_WATCH_SECONDS = 10.0


def _transient_control_plane_cause(exc: BaseException) -> BaseException | None:
    """Return the availability failure in exc's cause chain, if any."""
    return transient_mysql_cause(exc, also=(TimeoutError,))


def _wait_for_next_cycle(
    delay: float,
    stop_event: threading.Event,
    wake_event: threading.Event | None,
) -> None:
    """Wait up to delay, returning early on shutdown or a control-plane wake-up."""
    if wake_event is None:
        stop_event.wait(delay)
        return
    deadline = time.monotonic() + max(0.0, delay)
    while not stop_event.is_set():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        if wake_event.wait(min(remaining, _WAKE_POLL_SECONDS)):
            wake_event.clear()
            return


def _loop(
    interval: float,
    func,
    stop_event: threading.Event,
    wake_event: threading.Event | None = None,
    retry_backoff: DatabaseWriteBackoff | None = None,
) -> None:
    """Run func every interval.

    With retry_backoff, a database-unavailable exception or a False result
    (pending control-plane work) schedules the next attempt with bounded
    exponential backoff and jitter instead of the steady interval; a set
    wake_event (MySQL reachable again, startup completed) runs it at once.
    """
    loop_name = getattr(func, "__name__", "agent-loop")
    while not stop_event.is_set():
        delay = interval
        try:
            pending = func() is False
        except Exception as exc:
            pending = isinstance(exc, DATABASE_ERRORS)
            _log_recoverable_or_unexpected(
                f"proxy.agent.{loop_name}",
                interval_seconds=max(5.0, float(interval)),
                recoverable_message=f"Proxy agent loop '{loop_name}' is waiting for database availability",
                unexpected_message=f"Proxy agent loop '{loop_name}' failed",
                exc=exc,
            )
        if retry_backoff is not None:
            if pending:
                delay = min(interval, retry_backoff.record_failure())
            else:
                retry_backoff.record_success()
        _wait_for_next_cycle(delay, stop_event, wake_event)


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


def _sync_result_ok(result: dict[str, Any] | None) -> bool:
    return bool(result is not None and result.get("ok", False))


def _sync_loop(
    runtime,
    *,
    force: bool = False,
    stop_event: threading.Event | None = None,
):
    if stop_event is not None and stop_event.is_set():
        return None
    initial_capture_required = runtime.recovery_initial_capture_required
    if initial_capture_required:
        runtime.ensure_startup_schema()
    else:
        runtime.start_background_tasks()

    if stop_event is not None and stop_event.is_set():
        return None
    result = runtime.sync_from_db(force=force)
    if stop_event is not None and stop_event.is_set():
        return result
    if runtime.recovery_initial_capture_required and _sync_result_ok(result):
        runtime.capture_recovery_bundle(
            reason="startup_initial",
            required=True,
            changed=bool(result.get("changed", False)),
        )
    if (
        initial_capture_required
        and not runtime.recovery_initial_capture_required
        and not (stop_event is not None and stop_event.is_set())
    ):
        runtime.start_background_tasks()
    return result


_RECOVERY_PENDING = object()


class _ControlPlaneStartup:
    """DB-dependent startup that may complete long after the local data plane.

    Recovery adoption and the startup schema must complete before any normal
    registration/default refresh/apply touches the control plane (see
    docs/proxy-recovery.md), so both are retried here, never skipped. While they
    are pending the agent only runs local self-healing; Squid, PAC/WPAD, adblock,
    policy helpers and health keep serving the last materialized local state.
    """

    def __init__(self, runtime) -> None:
        self.runtime = runtime
        self.recovery: Any = _RECOVERY_PENDING
        self.schema_ok = False
        self.complete = False

    def _recover(self) -> bool:
        if self.recovery is not _RECOVERY_PENDING:
            return True
        try:
            self.recovery = self.runtime.run_startup_recovery()
        except Exception as exc:
            cause = _transient_control_plane_cause(exc)
            if cause is not None:
                if should_log("proxy.agent.startup_recovery", interval_seconds=60.0):
                    logger.warning(
                        "Proxy startup recovery is waiting for the control-plane "
                        "database; local proxy services keep serving the last "
                        "materialized state: %s",
                        public_error_message(cause, default="Database is unavailable."),
                    )
            else:
                # Fail closed: normal DB mutation stays blocked until recovery
                # succeeds. Keep retrying slowly so a repaired/replaced control
                # plane is adopted without a container restart.
                log_exception_throttled(
                    logger,
                    "proxy.agent.startup_recovery_failed",
                    interval_seconds=300.0,
                    message=(
                        "Proxy startup recovery failed closed; normal control-plane "
                        "sync stays blocked until recovery succeeds"
                    ),
                )
            return False
        return True

    def run(self, stop_event: threading.Event | None = None) -> bool:
        """Advance pending startup work; return True once it has completed."""
        if self.complete:
            return True
        runtime = self.runtime
        if not self._recover():
            return False
        if stop_event is not None and stop_event.is_set():
            return False
        startup_recovery = self.recovery
        if not self.schema_ok and startup_recovery.capture_required:
            # A present bundle path runs schema inside recovery before adoption.
            # For brand-new/no-bundle proxies, migrate explicitly here before
            # normal registration/default refresh/apply can write DB state.
            self.schema_ok, _schema = _run_once_logged(
                "proxy.agent.startup_schema",
                "Initial startup schema migration failed",
                runtime.ensure_startup_schema,
            )
            if not self.schema_ok:
                return False
        self.schema_ok = True
        if stop_event is not None and stop_event.is_set():
            return False

        # Registration, bootstrap, telemetry startup and the first sync are
        # retried by every regular sync cycle (sync_from_db re-registers and
        # bootstraps), so their failures do not hold startup open.
        registered_ok, _registered = _run_once_logged(
            "proxy.agent.initial_register",
            "Initial proxy registration failed",
            runtime.ensure_registered,
        )
        bootstrap_ok = background_ok = sync_ok = False
        sync_result = None
        if not (stop_event is not None and stop_event.is_set()):
            bootstrap_ok, _bootstrap = _run_once_logged(
                "proxy.agent.initial_bootstrap",
                "Initial proxy revision bootstrap failed",
                runtime.bootstrap_revision_if_missing,
            )
        if not (stop_event is not None and stop_event.is_set()):
            background_ok, _background = _run_once_logged(
                "proxy.agent.initial_background",
                "Initial proxy background task startup failed",
                runtime.start_background_tasks,
            )
        if not (stop_event is not None and stop_event.is_set()):
            sync_ok, sync_result = _run_once_logged(
                "proxy.agent.initial_sync",
                "Initial proxy sync failed",
                lambda: runtime.sync_from_db(force=False),
            )
        if stop_event is not None and stop_event.is_set():
            return False
        if startup_recovery.capture_required:
            if (
                registered_ok
                and bootstrap_ok
                and background_ok
                and sync_ok
                and _sync_result_ok(sync_result)
            ):
                # A failed required capture stays pending; the sync loop retries
                # it after each successful sync (recovery_initial_capture_required).
                _run_once_logged(
                    "proxy.agent.initial_capture",
                    "Proxy recovery initial capture failed",
                    lambda: runtime.capture_recovery_bundle(
                        reason="startup_initial",
                        required=True,
                        changed=bool(sync_result.get("changed", False)),
                    ),
                )
            else:
                logger.warning(
                    "Proxy recovery initial capture deferred for proxy_id=%s because initial DB startup did not complete",
                    startup_recovery.proxy_id,
                )
        self.complete = True
        _publish_control_plane_ready()
        logger.info(
            "Proxy control-plane startup completed: recovery=%s registered=%s "
            "bootstrap=%s initial_sync=%s",
            startup_recovery.status,
            registered_ok,
            bootstrap_ok,
            bool(sync_ok and _sync_result_ok(sync_result)),
        )
        return True


def _publish_control_plane_ready() -> None:
    try:
        mark_control_plane_ready()
    except Exception:
        # Fail closed: management mutations stay refused (503) until the
        # marker can be written; local proxy services are unaffected.
        log_exception_throttled(
            logger,
            "proxy.agent.control_plane_ready",
            interval_seconds=300.0,
            message="Failed to publish proxy control-plane readiness",
        )


def _control_plane_cycle(
    runtime,
    startup: _ControlPlaneStartup,
    stop_event: threading.Event | None,
    heartbeat_wake: threading.Event | None = None,
):
    """One sync-loop cycle: finish pending startup first, then regular sync.

    Returns False while startup work is still pending so the loop retries with
    backoff instead of the steady sync interval.
    """
    if not startup.complete:
        if not startup.run(stop_event):
            return False
        if heartbeat_wake is not None:
            # Report the proxy to the control plane right after startup.
            heartbeat_wake.set()
        return True
    return _sync_loop(runtime, force=False, stop_event=stop_event)


def _recover_interrupted_squid_transaction(runtime) -> None:
    """Restart Squid work a killed or stopped process left unfinished.

    This agent is the always-running local owner of Squid recovery: the
    management API that started a cache clear may be gone for good.
    """
    try:
        runtime.recover_interrupted_squid_transaction()
    except Exception:
        log_exception_throttled(
            logger,
            "proxy.agent.squid_transaction_watch",
            interval_seconds=60.0,
            message="Interrupted Squid transaction recovery failed",
        )


def _heartbeat_cycle(runtime, startup: _ControlPlaneStartup):
    if startup.complete:
        return runtime.heartbeat()
    # Until recovery adoption/schema complete, keep Squid and the ICAP helpers
    # self-healing locally but write nothing to the control plane.
    runtime.run_local_self_heal(reason="heartbeat")
    return None


def start_agent(*, stop_event: threading.Event | None = None) -> None:
    global _started
    with _start_lock:
        if _started:
            return

        # A marker from an earlier agent process must not let the management
        # API mutate the control plane before this process finishes startup.
        clear_control_plane_ready()
        runtime = get_runtime()
        logger.info(
            "Proxy agent starting control-plane startup for proxy_id=%s",
            runtime.proxy_id,
        )
        if stop_event is not None and stop_event.is_set():
            return
        # A mutation cut off by a process exit may have left Squid stopped;
        # startup applies would also refuse the unfinished journal.
        _recover_interrupted_squid_transaction(runtime)
        loop_stop = stop_event or threading.Event()
        startup = _ControlPlaneStartup(runtime)
        # MySQL/control-plane outages must not kill the local proxy agent.  The
        # proxy data plane, public PAC/WPAD listener, and supervisor health are
        # local services and should remain alive while control-plane DB work is
        # retried by the loops below.
        startup.run(stop_event)
        if stop_event is not None and stop_event.is_set():
            return

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
        heartbeat_wake = threading.Event()
        sync_wake = threading.Event()

        def _wake_after_mysql_recovery() -> None:
            # Re-register, finish skipped startup, resync and report at once
            # instead of waiting out the steady intervals.
            logger.info(
                "Control-plane database reachable again; resynchronizing proxy now",
            )
            sync_wake.set()
            heartbeat_wake.set()

        add_mysql_recovery_listener(_wake_after_mysql_recovery)

        loops = (
            (
                "proxy-heartbeat",
                (
                    heartbeat_interval,
                    lambda: _heartbeat_cycle(runtime, startup),
                    loop_stop,
                    heartbeat_wake,
                ),
            ),
            (
                "proxy-sync-loop",
                (
                    sync_interval,
                    lambda: _control_plane_cycle(
                        runtime,
                        startup,
                        stop_event,
                        heartbeat_wake,
                    ),
                    loop_stop,
                    sync_wake,
                    DatabaseWriteBackoff.from_env(
                        "PROXY_CONTROL_PLANE_RETRY",
                        default_base=2.0,
                        default_max=30.0,
                    ),
                ),
            ),
            (
                "squid-transaction-watch",
                (
                    SQUID_TRANSACTION_WATCH_SECONDS,
                    lambda: _recover_interrupted_squid_transaction(runtime),
                    loop_stop,
                ),
            ),
        )
        for name, args in loops:
            if name in _started_loop_names:
                continue
            thread = threading.Thread(
                target=_loop,
                args=args,
                name=name,
                daemon=True,
            )
            thread.start()
            _loop_threads.append(thread)
            _started_loop_names.add(name)
        _started = True
        _started_loop_names.clear()


def _shutdown(runtime, *, timeout: float = _SHUTDOWN_TIMEOUT_SECONDS) -> bool:
    """Stop agent work within one deadline, without racing active loop callbacks."""
    deadline = time.monotonic() + max(0.0, timeout)
    threads = tuple(_loop_threads)
    for thread in threads:
        thread.join(timeout=max(0.0, deadline - time.monotonic()))

    live_threads = [thread.name for thread in threads if thread.is_alive()]
    if live_threads:
        logger.warning(
            "Proxy agent shutdown deadline exceeded with active loops: %s; "
            "background services were not stopped to avoid racing loop mutations",
            ", ".join(live_threads),
        )
        return False

    remaining = max(0.0, deadline - time.monotonic())
    if not runtime.stop_background_tasks(timeout=remaining):
        logger.warning(
            "Proxy background telemetry shutdown exceeded the agent shutdown deadline"
        )
        return False
    return True


def main() -> None:
    configure_process_logging()
    stop_event = threading.Event()

    def request_shutdown(_signum, _frame) -> None:
        stop_event.set()

    signal.signal(signal.SIGTERM, request_shutdown)
    signal.signal(signal.SIGINT, request_shutdown)
    start_agent(stop_event=stop_event)
    stop_event.wait()
    runtime = get_runtime()
    _shutdown(runtime)


if __name__ == "__main__":
    main()
