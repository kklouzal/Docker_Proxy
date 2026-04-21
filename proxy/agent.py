from __future__ import annotations

import os
import threading
import time

from proxy.runtime import get_runtime


_started = False
_start_lock = threading.Lock()


def _env_float(name: str, default: float) -> float:
    try:
        value = float((os.environ.get(name) or str(default)).strip() or str(default))
    except Exception:
        value = float(default)
    return max(1.0, min(3600.0, value))


def _loop(interval: float, func) -> None:
    while True:
        try:
            func()
        except Exception:
            pass
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
            pass

        heartbeat_interval = _env_float("PROXY_HEARTBEAT_INTERVAL_SECONDS", 15.0)
        sync_interval = _env_float("PROXY_SYNC_INTERVAL_SECONDS", 30.0)

        threading.Thread(target=_loop, args=(heartbeat_interval, runtime.heartbeat), name="proxy-heartbeat", daemon=True).start()
        threading.Thread(target=_loop, args=(sync_interval, runtime.sync_from_db), name="proxy-sync-loop", daemon=True).start()


def main() -> None:
    start_agent()
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
