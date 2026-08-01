from __future__ import annotations

import contextlib
import os
import tempfile
from pathlib import Path


def emit_helper_failure(helper: str, event: str, exc: Exception) -> None:
    with contextlib.suppress(Exception):
        from services.helper_runtime import helper_failure_event  # type: ignore

        helper_failure_event(helper, event, exc)


def _fsync_parent_dir(path: Path) -> None:
    """Best-effort fsync for directory entries created/replaced near path."""
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    fd: int | None = None
    try:
        fd = os.open(path.parent, flags)
        os.fsync(fd)
    except OSError:
        return
    finally:
        if fd is not None:
            with contextlib.suppress(OSError):
                os.close(fd)


def write_safe_include(path: str, content: str) -> None:
    target = Path(path)
    target.parent.mkdir(exist_ok=True, parents=True)
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            delete=False,
            dir=target.parent,
            prefix=f".{target.name}.",
            suffix=".tmp",
        ) as handle:
            temp_path = Path(handle.name)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        temp_path.replace(target)
        _fsync_parent_dir(target)
    except Exception:
        if temp_path is not None:
            cleaned = False
            with contextlib.suppress(FileNotFoundError):
                temp_path.unlink()
                cleaned = True
            if cleaned:
                _fsync_parent_dir(temp_path)
        raise
