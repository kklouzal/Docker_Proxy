from __future__ import annotations

import contextlib
import json
import os
import sys
import tempfile
from pathlib import Path


def _bounded_event_label(value: object, *, fallback: str) -> str:
    text = " ".join(str(value or fallback).replace("\r", " ").replace("\n", " ").split())
    return (text[:79].rstrip() + "...") if len(text) > 80 else text


def emit_helper_failure(helper: str, event: str, exc: Exception) -> None:
    try:
        from services.helper_runtime import helper_failure_event  # type: ignore

        helper_failure_event(helper, event, exc)
        return
    except Exception:
        pass

    # Keep diagnostics available even when the app runtime cannot be imported.
    # Exception messages are intentionally excluded because they may contain secrets.
    with contextlib.suppress(Exception):
        payload = {
            "helper": _bounded_event_label(helper, fallback="helper"),
            "event": _bounded_event_label(event, fallback="failure"),
            "error_type": _bounded_event_label(type(exc).__name__, fallback="Exception"),
            "reason": "Operation failed. Check server logs for details.",
        }
        sys.stderr.write(
            json.dumps(payload, allow_nan=False, sort_keys=True, separators=(",", ":"))
            + "\n"
        )
        sys.stderr.flush()


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
    try:
        stat = target.stat()
        mode = stat.st_mode & 0o777
        owner: tuple[int, int] | None = (stat.st_uid, stat.st_gid)
    except FileNotFoundError:
        mode = 0o644
        owner = None
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
        temp_path.chmod(mode)
        if owner is not None:
            os.chown(temp_path, owner[0], owner[1])
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
