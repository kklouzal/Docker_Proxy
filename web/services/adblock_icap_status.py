"""Load status that adblock ICAP helper processes publish for the proxy runtime.

The helper (web/tools/adblock_icap_server.py) reloads its artifact in process
on SIGHUP. Every worker process writes ``worker-<n>.json`` after each load:
the helper's main pid, the worker count, a load generation (0 = startup, +1
per reload) and whether the load succeeded. A failed reload keeps the previous engine serving and reports the
error. The runtime compares these records before and after a signal to confirm
that every worker loaded the artifact materialized before the signal.
"""

from __future__ import annotations

import contextlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_STATUS_DIR = "/run/squid-flask-proxy/adblock-icap"
_FILE_PREFIX = "worker-"


def status_dir() -> str:
    return (
        os.environ.get("ADBLOCK_ICAP_STATUS_DIR") or DEFAULT_STATUS_DIR
    ).strip() or DEFAULT_STATUS_DIR


@dataclass(frozen=True)
class WorkerLoadStatus:
    helper_pid: int
    worker: int
    processes: int
    generation: int
    ok: bool
    error: str


def clear_worker_statuses(directory: str) -> None:
    """Remove records of an earlier helper run (called before workers start)."""
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    for path in root.glob(f"{_FILE_PREFIX}*"):
        with contextlib.suppress(FileNotFoundError):
            path.unlink()


def write_worker_status(directory: str, status: WorkerLoadStatus) -> None:
    root = Path(directory)
    path = root / f"{_FILE_PREFIX}{status.worker}.json"
    tmp = root / f".{path.name}.{os.getpid()}.tmp"
    payload = {
        "helper_pid": status.helper_pid,
        "worker": status.worker,
        "processes": status.processes,
        "generation": status.generation,
        "ok": status.ok,
        "error": status.error[:500],
    }
    tmp.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    tmp.replace(path)


def read_worker_statuses(directory: str) -> dict[int, WorkerLoadStatus]:
    """Return the readable worker records keyed by worker number."""
    statuses: dict[int, WorkerLoadStatus] = {}
    for path in Path(directory).glob(f"{_FILE_PREFIX}*.json"):
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            status = WorkerLoadStatus(
                helper_pid=int(raw["helper_pid"]),
                worker=int(raw["worker"]),
                processes=int(raw["processes"]),
                generation=int(raw["generation"]),
                ok=raw["ok"] is True,
                error=str(raw["error"]),
            )
        except OSError, ValueError, KeyError, TypeError:
            continue
        statuses[status.worker] = status
    return statuses
