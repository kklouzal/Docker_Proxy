"""Background refresh of the SAML IdP metadata cache.

Runs in the Admin UI process that owns background services (see
``BackgroundServiceCoordinator``); ``SamlAuthStore.refresh_metadata_if_due``
makes each refresh single-flight across processes and pods and keeps the
schedule (success: part-way through the cache window; failure: capped
exponential backoff with jitter) in MySQL.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import TYPE_CHECKING

from services.logutil import log_exception_throttled

if TYPE_CHECKING:
    from collections.abc import Callable

    from services.saml_auth import SamlAuthStore

logger = logging.getLogger(__name__)

# Bounds on the wait between due checks: the lower bound keeps a schedule that
# is already due (or a lock held elsewhere) from spinning; the upper bound picks
# up an operator enabling SAML or a manual refresh within five minutes.
MIN_POLL_SECONDS = 30
MAX_POLL_SECONDS = 300

_lock = threading.Lock()
_stop_event = threading.Event()
_thread: threading.Thread | None = None


def next_poll_delay(next_due_ts: int, now: int) -> int:
    if next_due_ts <= 0:
        return MAX_POLL_SECONDS
    return max(MIN_POLL_SECONDS, min(MAX_POLL_SECONDS, next_due_ts - now))


def run_once(store: SamlAuthStore) -> int:
    """One due check; returns seconds to wait before the next one."""
    try:
        next_due_ts = store.refresh_metadata_if_due()
    except Exception:
        # MySQL unavailable or similar; refresh_metadata itself records fetch
        # failures. Retry after the minimum poll interval.
        log_exception_throttled(
            logger,
            "saml_metadata_refresh.run_once",
            interval_seconds=300.0,
            message="SAML metadata background refresh check failed",
        )
        return MIN_POLL_SECONDS
    return next_poll_delay(next_due_ts, int(time.time()))


def start_saml_metadata_refresh(store_factory: Callable[[], SamlAuthStore]) -> None:
    global _thread

    def loop() -> None:
        while not _stop_event.is_set():
            delay = run_once(store_factory())
            _stop_event.wait(delay)

    with _lock:
        if _thread is not None and _thread.is_alive():
            return
        _stop_event.clear()
        thread = threading.Thread(
            target=loop, name="saml-metadata-refresh", daemon=True
        )
        thread.start()
        _thread = thread


def stop_saml_metadata_refresh(*, timeout: float = 5.0) -> bool:
    global _thread
    with _lock:
        _stop_event.set()
        thread = _thread
    if thread is not None:
        thread.join(max(0.0, timeout))
    stopped = thread is None or not thread.is_alive()
    if stopped:
        with _lock:
            if _thread is thread:
                _thread = None
    return stopped
