from __future__ import annotations

import contextlib
import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Any

from services.adblock_store import get_adblock_store
from services.audit_store import get_audit_store
from services.control_plane_maintenance import (
    maintain_control_plane_tables,
    prune_control_plane_tables,
)
from services.db import OPERATIONAL_ERRORS
from services.diagnostic_store import get_diagnostic_store
from services.live_stats import get_store
from services.logutil import log_exception_throttled
from services.observability_maintenance import (
    ObservabilityMaintenanceAlreadyRunningError,
    acquire_observability_maintenance_lock,
    get_observability_retention_settings,
    maintain_observability_tables,
    normalize_retention_days,
    public_detail,
    record_observability_maintenance_run,
    release_observability_maintenance_lock,
)
from services.ssl_errors_store import get_ssl_errors_store

logger = logging.getLogger(__name__)


_started = False
_lock = threading.Lock()

_SUNDAY = 6


def _is_db_locked(exc: BaseException) -> bool:
    if not isinstance(exc, OPERATIONAL_ERRORS):
        return False
    text = str(exc).lower()
    return (
        "database is locked" in text
        or "lock wait timeout" in text
        or "deadlock found" in text
    )


def _run_with_db_lock_retry(
    fn,
    *,
    attempts: int = 8,
    base_sleep_seconds: float = 0.5,
) -> Any:
    """Run `fn` with exponential backoff on transient database lock errors."""
    last_exc: BaseException | None = None
    for i in range(max(1, int(attempts))):
        try:
            return fn()
        except Exception as exc:
            last_exc = exc
            if not _is_db_locked(exc):
                raise
            # Backoff: 0.5s, 1s, 2s, 4s, ... (capped)
            sleep_s = min(30.0, float(base_sleep_seconds) * (2**i))
            time.sleep(sleep_s)
    if last_exc is not None:
        raise last_exc
    return None


def current_retention_days(default: int = 30) -> int:
    try:
        settings = get_observability_retention_settings()
        return normalize_retention_days(settings.get("retention_days", default))
    except Exception:
        return normalize_retention_days(default)


def _run_prune_once(*, retention_days: int) -> dict[str, Any]:
    # Best-effort: one failed table family must not block unrelated cleanup.
    results: list[dict[str, Any]] = []

    def run_step(name: str, fn) -> None:
        try:
            value = _run_with_db_lock_retry(fn)
            results.append({"name": name, "ok": True, "result": value or {}})
        except Exception as exc:
            results.append({"name": name, "ok": False, "detail": str(exc)[:300]})
            log_exception_throttled(
                logger,
                f"housekeeping.prune.{name}",
                interval_seconds=300,
                message=f"Housekeeping prune step failed: {name}",
            )

    run_step(
        "live_stats",
        lambda: get_store().prune_old_entries(retention_days=retention_days),
    )
    run_step(
        "diagnostics",
        lambda: get_diagnostic_store().prune_old_entries(retention_days=retention_days),
    )
    run_step(
        "adblock",
        lambda: get_adblock_store().prune_old_entries(retention_days=retention_days),
    )
    run_step(
        "ssl_errors",
        lambda: get_ssl_errors_store().prune_old_entries(retention_days=retention_days),
    )
    run_step(
        "audit",
        lambda: get_audit_store().prune_old_entries(retention_days=retention_days),
    )
    run_step(
        "control_plane",
        prune_control_plane_tables,
    )
    return {
        "ok": all(bool(row.get("ok")) for row in results),
        "steps": results,
    }


def _combine_maintenance_results(
    observability: dict[str, Any] | None,
    control_plane: dict[str, Any] | None,
) -> dict[str, Any]:
    observed = observability or {}
    control = control_plane or {}
    tables = []
    for scope, result in (("observability", observed), ("control_plane", control)):
        for table in result.get("tables") or []:
            row = dict(table)
            row["scope"] = scope
            tables.append(row)
    return {
        "ok": bool(observed.get("ok", True)) and bool(control.get("ok", True)),
        "maintained_tables": int(observed.get("maintained_tables") or 0)
        + int(control.get("maintained_tables") or 0),
        "tables": tables,
        "observability": observed,
        "control_plane": control,
    }


def _failed_maintenance_result(scope: str, exc: BaseException) -> dict[str, Any]:
    return {
        "ok": False,
        "maintained_tables": 0,
        "tables": [
            {
                "table": scope,
                "status": "failed",
                "maintenance": "failed",
                "detail": public_detail(exc),
            },
        ],
    }


def _run_maintenance_once(*, analyze: bool, optimize: bool) -> dict[str, Any]:
    observability_maintenance: dict[str, Any] | None = None
    control_plane_maintenance: dict[str, Any] | None = None
    try:
        observability_maintenance = _run_with_db_lock_retry(
            lambda: maintain_observability_tables(analyze=analyze, optimize=optimize),
        )
    except Exception as exc:
        observability_maintenance = _failed_maintenance_result("observability", exc)
        log_exception_throttled(
            logger,
            "housekeeping.maintenance.observability",
            interval_seconds=300,
            message="Housekeeping observability maintenance failed",
        )

    try:
        control_plane_maintenance = _run_with_db_lock_retry(
            lambda: maintain_control_plane_tables(analyze=analyze, optimize=optimize),
        )
    except Exception as exc:
        control_plane_maintenance = _failed_maintenance_result("control_plane", exc)
        log_exception_throttled(
            logger,
            "housekeeping.maintenance.control_plane",
            interval_seconds=300,
            message="Housekeeping control-plane maintenance failed",
        )

    return _combine_maintenance_results(
        observability_maintenance,
        control_plane_maintenance,
    )


def run_housekeeping_once(
    *,
    retention_days: int | None = None,
    analyze: bool = False,
    optimize: bool = False,
    run_type: str | None = None,
) -> dict[str, Any]:
    started = time.time()
    days = (
        current_retention_days(30)
        if retention_days is None
        else normalize_retention_days(retention_days)
    )
    resolved_run_type = run_type or ("weekly" if analyze or optimize else "daily")
    lock_conn = acquire_observability_maintenance_lock()
    if lock_conn is None:
        skipped = {
            "ok": False,
            "status": "skipped",
            "started_ts": int(started),
            "finished_ts": int(time.time()),
            "duration_ms": int((time.time() - started) * 1000),
            "retention_days": days,
            "pruned": False,
            "analyze": bool(analyze),
            "optimize": bool(optimize),
            "maintenance": {},
            "detail": "another observability maintenance run is already active",
        }
        with contextlib.suppress(Exception):
            record_observability_maintenance_run(
                run_type=resolved_run_type,
                result=skipped,
                status="skipped",
            )
        raise ObservabilityMaintenanceAlreadyRunningError(skipped["detail"])

    try:
        prune = _run_prune_once(retention_days=days) or {"ok": True, "steps": []}
        maintenance: dict[str, Any] | None = None
        if analyze or optimize:
            maintenance = _run_maintenance_once(analyze=analyze, optimize=optimize)
        maintenance_ok = bool(maintenance.get("ok", True)) if maintenance else True
        prune_ok = bool(prune.get("ok", True))
        result = {
            "ok": maintenance_ok and prune_ok,
            "status": "ok" if maintenance_ok and prune_ok else "failed",
            "started_ts": int(started),
            "finished_ts": int(time.time()),
            "duration_ms": int((time.time() - started) * 1000),
            "retention_days": days,
            "pruned": prune_ok,
            "analyze": bool(analyze),
            "optimize": bool(optimize),
            "prune": prune,
            "maintenance": maintenance or {},
        }
        with contextlib.suppress(Exception):
            record_observability_maintenance_run(
                run_type=resolved_run_type, result=result
            )
        return result
    except Exception as exc:
        failed = {
            "ok": False,
            "status": "failed",
            "started_ts": int(started),
            "finished_ts": int(time.time()),
            "duration_ms": int((time.time() - started) * 1000),
            "retention_days": days,
            "pruned": False,
            "analyze": bool(analyze),
            "optimize": bool(optimize),
            "maintenance": {},
            "detail": str(exc)[:300],
        }
        with contextlib.suppress(Exception):
            record_observability_maintenance_run(
                run_type=resolved_run_type, result=failed
            )
        raise
    finally:
        with contextlib.suppress(Exception):
            release_observability_maintenance_lock(lock_conn)


def _next_local_run(
    *,
    hour: int,
    minute: int = 0,
    weekday: int | None = None,
    now: datetime | None = None,
) -> datetime:
    current = now or datetime.now().astimezone()
    target = current.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if weekday is not None:
        days_ahead = (weekday - target.weekday()) % 7
        target += timedelta(days=days_ahead)
    if target <= current:
        target += timedelta(days=7 if weekday is not None else 1)
    return target


def _sleep_until(target: datetime) -> None:
    while True:
        remaining = target.timestamp() - time.time()
        if remaining <= 0:
            return
        time.sleep(min(300.0, max(1.0, remaining)))


def start_housekeeping(
    *,
    retention_days: int = 30,
    daily_hour: int = 2,
    weekly_weekday: int = _SUNDAY,
    weekly_hour: int = 3,
    interval_seconds: int | None = None,
) -> None:
    """Start scheduled database housekeeping."""
    global _started
    with _lock:
        if _started:
            return
        _started = True

    def loop() -> None:
        if interval_seconds is not None:
            while True:
                try:
                    run_housekeeping_once(
                        retention_days=current_retention_days(retention_days),
                    )
                except Exception:
                    log_exception_throttled(
                        logger,
                        "housekeeping.loop",
                        interval_seconds=300,
                        message="Housekeeping run failed",
                    )
                time.sleep(float(interval_seconds))

        next_daily = _next_local_run(hour=daily_hour)
        next_weekly = _next_local_run(hour=weekly_hour, weekday=weekly_weekday)
        while True:
            target = min(next_daily, next_weekly)
            _sleep_until(target)
            try:
                now = datetime.now().astimezone()
                if now >= next_daily:
                    run_housekeeping_once(
                        retention_days=current_retention_days(retention_days),
                    )
                    next_daily = _next_local_run(hour=daily_hour, now=now)
                if now >= next_weekly:
                    run_housekeeping_once(
                        retention_days=current_retention_days(retention_days),
                        analyze=True,
                        optimize=True,
                    )
                    next_weekly = _next_local_run(
                        hour=weekly_hour,
                        weekday=weekly_weekday,
                        now=now,
                    )
            except Exception:
                log_exception_throttled(
                    logger,
                    "housekeeping.loop",
                    interval_seconds=300,
                    message="Housekeeping run failed",
                )

    t = threading.Thread(target=loop, name="db-housekeeping", daemon=True)
    t.start()
