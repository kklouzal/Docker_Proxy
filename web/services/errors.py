from __future__ import annotations

import os
import re
from typing import Optional


def expose_internal_errors() -> bool:
    return (os.environ.get("EXPOSE_INTERNAL_ERRORS") or "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


def clean_text(text: str, *, max_len: int = 200) -> str:
    s = (text or "").replace("\r", " ").replace("\n", " ").strip()
    # Remove other control chars.
    s = "".join(ch if (ch >= " " and ch != "\x7f") else " " for ch in s)
    s = re.sub(r"\s+", " ", s).strip()
    if max_len and len(s) > max_len:
        s = s[: max_len - 1].rstrip() + "…"
    return s


def public_error_message(
    e: Exception,
    *,
    default: str = "Operation failed. Check server logs for details.",
    max_len: int = 200,
) -> str:
    """Return a user-safe error message.

    - By default, avoids leaking internal exception details.
    - For ValueError, returns the message (commonly validation/user input).
    - If EXPOSE_INTERNAL_ERRORS is set, returns the exception type + message.
    """
    if expose_internal_errors():
        detail = clean_text(f"{type(e).__name__}: {e}", max_len=max_len)
        return detail or default

    if isinstance(e, ValueError):
        msg = clean_text(str(e), max_len=max_len)
        return msg or default

    return default
