"""Cross-process signal that the proxy agent finished control-plane startup.

Recovery adoption and the startup schema must run before any normal
control-plane mutation (docs/proxy-recovery.md). The agent owns that ordering;
the management API runs in a different process (proxy_api), so the agent
publishes completion as a marker file that the API checks before mutating
endpoints run. The entrypoint and every agent start remove the marker, so a
stale marker from an earlier container run or agent process never counts.
"""

from __future__ import annotations

import contextlib
import os
from pathlib import Path

_DEFAULT_READY_FILE = "/run/squid-flask-proxy/control-plane-ready"


def ready_file() -> Path:
    return Path(
        (
            os.environ.get("PROXY_CONTROL_PLANE_READY_FILE") or _DEFAULT_READY_FILE
        ).strip()
        or _DEFAULT_READY_FILE,
    )


def clear_control_plane_ready() -> None:
    with contextlib.suppress(FileNotFoundError):
        ready_file().unlink()


def mark_control_plane_ready() -> None:
    """Atomically publish readiness for the current agent process."""
    path = ready_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text(f"{os.getpid()}\n", encoding="utf-8")
    tmp.replace(path)


def control_plane_ready() -> bool:
    return ready_file().is_file()
