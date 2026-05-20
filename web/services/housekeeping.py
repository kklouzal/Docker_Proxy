from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Any

from services.adblock_store import get_adblock_store
from services.audit_store import get_audit_store
from services.db import OPERATIONAL_ERRORS
from services.diagnostic_store import get_diagnostic_store
from services.live_stats import get_store
from services.logutil import log_exception_throttled
from services.observability_maintenance import (
    get_observability_retention_settings,
    maintain_observability_tables,
    normalize_retention_days,
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


def _run_prune_once(*, retention_days: int) -> None:
    # Best-effort: each store handles its own DB locks and failures.
    _run_with_db_lock_retry(
        lambda: get_store().prune_old_entries(retention_days=retention_days),
    )
    _run_with_db_lock_retry(
        lambda: get_diagnostic_store().prune_old_entries(retention_days=retention_days),
    )
    _run_with_db_lock_retry(
        lambda: get_adblock_store().prune_old_entries(retention_days=retention_days),
    )
    _run_with_db_lock_retry(
        lambda: get_ssl_errors_store().prune_old_entries(retention_days=retention_days),
    )
    _run_with_db_lock_retry(
        lambda: get_audit_store().prune_old_entries(retention_days=retention_days),
    )


def run_housekeeping_once(
    *,
    retention_days: int | None = None,
    analyze: bool = False,
    optimize: bool = False,
) -> dict[str, Any]:
    days = (
        current_retention_days(30)
        if retention_days is None
        else normalize_retention_days(retention_days)
    )
    _run_prune_once(retention_days=days)
    maintenance: dict[str, Any] | None = None
    if analyze or optimize:
        maintenance = _run_with_db_lock_retry(
            lambda: maintain_observability_tables(analyze=analyze, optimize=optimize),
        )
    return {
        "ok": bool(maintenance.get("ok", True)) if maintenance else True,
        "retention_days": days,
        "pruned": True,
        "analyze": bool(analyze),
        "optimize": bool(optimize),
        "maintenance": maintenance or {},
    }


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
