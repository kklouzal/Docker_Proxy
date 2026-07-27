from __future__ import annotations

import os
import re


_SENSITIVE_KEY_RE = re.compile(
    r"""
    (?P<prefix>
        \b(?:
            password|passwd|pwd|
            secret|client[_-]?secret|
            token|access[_-]?token|refresh[_-]?token|
            api[_-]?key|apikey
        )\b
        \s*[:=]\s*
    )
    (?:
        (?P<quote>["'])(?P<quoted_value>.*?)(?P=quote)
        |
        (?P<value>[^\s,;&]+)
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)

_AUTH_VALUE_RE = re.compile(
    r"(?i)\b(?P<scheme>bearer|basic)\s+(?P<value>[^\s,;&]+)"
)

_URL_USERINFO_RE = re.compile(
    r"(?i)\b(?P<scheme>[a-z][a-z0-9+.-]*://)(?P<userinfo>[^/\s@]+)@"
)


def expose_internal_errors() -> bool:
    return (os.environ.get("EXPOSE_INTERNAL_ERRORS") or "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def clean_text(text: str, *, max_len: int = 200) -> str:
    s = (text or "").replace("\r", " ").replace("\n", " ").strip()
    # Remove other control chars.
    s = "".join(ch if (ch >= " " and ch != "\x7f") else " " for ch in s)
    s = re.sub(r"\s+", " ", s).strip()
    if max_len and len(s) > max_len:
        s = s[: max_len - 1].rstrip() + "…"
    return s


def _redact_sensitive_text(text: str) -> str:
    """Redact credential-like values while preserving useful context."""
    if not text:
        return text

    text = _URL_USERINFO_RE.sub(r"\g<scheme>[redacted]@", text)
    text = _AUTH_VALUE_RE.sub(r"\g<scheme> [redacted]", text)

    def _replace_sensitive_key(match: re.Match[str]) -> str:
        quote = match.group("quote") or ""
        return f"{match.group('prefix')}{quote}[redacted]{quote}"

    return _SENSITIVE_KEY_RE.sub(_replace_sensitive_key, text)


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
        detail = clean_text(
            _redact_sensitive_text(f"{type(e).__name__}: {e}"), max_len=max_len
        )
        return detail or default

    if isinstance(e, ValueError):
        msg = clean_text(_redact_sensitive_text(str(e)), max_len=max_len)
        return msg or default

    return default
