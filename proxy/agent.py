from __future__ import annotations

import logging
import threading
import time

from services.logutil import log_exception_throttled
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
        except Exception:
            log_exception_throttled(
                logger,
                f"proxy.agent.{loop_name}",
                interval_seconds=max(5.0, float(interval)),
                message=f"Proxy agent loop '{loop_name}' failed",
            )
        time.sleep(interval)


def start_agent() -> None:
    global _started
    with _start_lock:
        if _started:
            return
        _started = True

        runtime = get_runtime()
        runtime.ensure_registered()
        runtime.bootstrap_revision_if_missing()
        runtime.start_background_tasks()
        try:
            runtime.sync_from_db(force=False)
        except Exception:
            log_exception_throttled(
                logger,
                "proxy.agent.initial_sync",
                interval_seconds=30.0,
                message="Initial proxy sync failed",
            )

        heartbeat_interval = _env_float("PROXY_HEARTBEAT_INTERVAL_SECONDS", 90.0, minimum=1.0, maximum=3600.0)
        sync_interval = _env_float("PROXY_SYNC_INTERVAL_SECONDS", 30.0, minimum=1.0, maximum=3600.0)

        threading.Thread(target=_loop, args=(heartbeat_interval, runtime.heartbeat), name="proxy-heartbeat", daemon=True).start()
        threading.Thread(target=_loop, args=(sync_interval, runtime.sync_from_db), name="proxy-sync-loop", daemon=True).start()


def main() -> None:
    start_agent()
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
