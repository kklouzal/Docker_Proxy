from __future__ import annotations

import threading
import time

from services.adblock_store import get_adblock_store
from services.audit_store import get_audit_store
from services.live_stats import get_store
from services.socks_store import get_socks_store
from services.ssl_errors_store import get_ssl_errors_store


_started = False
_lock = threading.Lock()


def _run_once(*, retention_days: int) -> None:
    # Best-effort: each store handles its own DB locks and failures.
    get_store().prune_old_entries(retention_days=retention_days, vacuum=True)
    get_socks_store().prune_old_entries(retention_days=retention_days, vacuum=True)
    get_adblock_store().prune_old_entries(retention_days=retention_days, vacuum=True)
    get_ssl_errors_store().prune_old_entries(retention_days=retention_days, vacuum=True)
    get_audit_store().prune_old_entries(retention_days=retention_days, vacuum=True)


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
                pass
            time.sleep(float(interval_seconds))

    t = threading.Thread(target=loop, name="sqlite-housekeeping", daemon=True)
    t.start()
