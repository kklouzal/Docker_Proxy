from __future__ import annotations

import contextlib
from pathlib import Path


def emit_helper_failure(helper: str, event: str, exc: Exception) -> None:
    with contextlib.suppress(Exception):
        from services.helper_runtime import helper_failure_event  # type: ignore

        helper_failure_event(helper, event, exc)


def write_safe_include(path: str, content: str) -> None:
    target = Path(path)
    target.parent.mkdir(exist_ok=True, parents=True)
    target.write_text(content, encoding="utf-8")
