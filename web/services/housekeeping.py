from __future__ import annotations

import sqlite3
import threading
import time

import logging

from services.adblock_store import get_adblock_store
from services.audit_store import get_audit_store
from services.live_stats import get_store
from services.socks_store import get_socks_store
from services.ssl_errors_store import get_ssl_errors_store
from services.logutil import log_exception_throttled


logger = logging.getLogger(__name__)


_started = False
_lock = threading.Lock()


def _is_db_locked(exc: BaseException) -> bool:
    return isinstance(exc, sqlite3.OperationalError) and "database is locked" in str(exc).lower()


def _run_with_db_lock_retry(fn, *, attempts: int = 8, base_sleep_seconds: float = 0.5) -> None:
    """Run `fn` with exponential backoff on transient SQLite lock errors."""
    last_exc: BaseException | None = None
    for i in range(max(1, int(attempts))):
        try:
            fn()
            return
        except Exception as exc:
            last_exc = exc
            if not _is_db_locked(exc):
                raise
            # Backoff: 0.5s, 1s, 2s, 4s, ... (capped)
            sleep_s = min(30.0, float(base_sleep_seconds) * (2 ** i))
            time.sleep(sleep_s)
    if last_exc is not None:
        raise last_exc


def _run_once(*, retention_days: int) -> None:
    # Best-effort: each store handles its own DB locks and failures.
    _run_with_db_lock_retry(lambda: get_store().prune_old_entries(retention_days=retention_days, vacuum=True))
    _run_with_db_lock_retry(lambda: get_socks_store().prune_old_entries(retention_days=retention_days, vacuum=True))
    _run_with_db_lock_retry(lambda: get_adblock_store().prune_old_entries(retention_days=retention_days, vacuum=True))
    _run_with_db_lock_retry(lambda: get_ssl_errors_store().prune_old_entries(retention_days=retention_days, vacuum=True))
    _run_with_db_lock_retry(lambda: get_audit_store().prune_old_entries(retention_days=retention_days, vacuum=True))


def start_housekeeping(*, retention_days: int = 30, interval_seconds: int = 24 * 60 * 60) -> None:
    """Start daily SQLite housekeeping.

    Prunes benign log/aggregate data older than `retention_days` and performs a
    best-effort VACUUM to prevent uncontrolled DB growth.
    """
    global _started
    with _lock:
        if _started:
            return
        _started = True

    def loop() -> None:
        while True:
            try:
                _run_once(retention_days=int(retention_days))
            except Exception:
                log_exception_throttled(
                    logger,
                    "housekeeping.loop",
                    interval_seconds=300,
                    message="Housekeeping run failed",
                )
            time.sleep(float(interval_seconds))

    t = threading.Thread(target=loop, name="sqlite-housekeeping", daemon=True)
    t.start()
