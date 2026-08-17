from __future__ import annotations

import os
import re
from urllib.parse import unquote_plus, urlsplit, urlunsplit

_SENSITIVE_KEY_RE = re.compile(
    r"""
    (?P<prefix>
        \b(?:
            password|passwd|pwd|
            secret|client[_-]?secret|
            token|access[_-]?token|refresh[_-]?token|
            api[_-]?key|apikey|samlresponse|relaystate|signature
        )\b
        \s*[:=]\s*
    )
    (?:
        (?P<quote>["'])
        (?P<quoted_value>(?:\\.|(?!(?P=quote)).)*)
        (?P=quote)
        |
        (?P<value>[^\s,;&]+)
    )
    """,
    re.DOTALL | re.IGNORECASE | re.VERBOSE,
)

_AUTH_VALUE_RE = re.compile(r"(?i)\b(?P<scheme>bearer|basic)\s+(?P<value>[^\s,;&]+)")

_URL_RE = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s\"'<>]+")

_URL_QUERY_CREDENTIAL_RE = re.compile(
    r"""
    (?P<prefix>
        [?&](?:
            password|passwd|pwd|
            secret|client[_-]?secret|
            token|access[_-]?token|refresh[_-]?token|
            api[_-]?key|apikey|key|samlresponse|relaystate|signature
        )=
    )
    (?P<value>[^&#\s,;\"'<>]*)
    """,
    re.IGNORECASE | re.VERBOSE,
)

_URL_USERINFO_RE = re.compile(
    r"(?i)\b(?P<scheme>[a-z][a-z0-9+.-]*://)(?P<userinfo>[^/\s@]+)@"
)

_SENSITIVE_QUERY_KEYS_RE = re.compile(
    r"^(?:password|passwd|pwd|secret|client[_-]?secret|token|access[_-]?token|refresh[_-]?token|api[_-]?key|apikey|key|samlresponse|relaystate|signature)$",
    re.IGNORECASE,
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

    def _replace_url_query_credentials(match: re.Match[str]) -> str:
        return _URL_QUERY_CREDENTIAL_RE.sub(
            lambda m: f"{m.group('prefix')}[redacted]", match.group(0)
        )

    text = _URL_RE.sub(_replace_url_query_credentials, text)

    def _replace_sensitive_key(match: re.Match[str]) -> str:
        quote = match.group("quote") or ""
        return f"{match.group('prefix')}{quote}[redacted]{quote}"

    return _SENSITIVE_KEY_RE.sub(_replace_sensitive_key, text)


def redact_sensitive_text(text: object) -> str:
    """Return text with credential-like values redacted for UI/audit surfaces."""
    return _redact_sensitive_text("" if text is None else str(text))


def redact_url_for_display(value: object, *, max_len: int = 2000) -> str:
    """Redact a URL for persistence/UI while retaining non-secret diagnostics."""
    raw = clean_text(str(value or ""), max_len=max_len)
    text = redact_sensitive_text(raw)
    if not text:
        return ""
    fallback = _URL_USERINFO_RE.sub(r"\g<scheme>", text).split("#", 1)[0]
    try:
        parsed = urlsplit(raw)
        host = parsed.hostname or ""
    except (TypeError, ValueError):
        return clean_text(fallback, max_len=max_len)
    if not (parsed.scheme and parsed.netloc and host):
        return clean_text(fallback, max_len=max_len)
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    netloc = host
    try:
        if parsed.port is not None:
            netloc = f"{netloc}:{parsed.port}"
    except ValueError:
        pass

    parts = re.split(r"([&;])", parsed.query)
    query_parts: list[str] = []
    for part in parts:
        if part in {"&", ";"}:
            query_parts.append(part)
            continue
        key, separator, _value = part.partition("=")
        if _SENSITIVE_QUERY_KEYS_RE.fullmatch(unquote_plus(key).strip()):
            query_parts.append(f"{key}=[redacted]")
        else:
            query_parts.append(redact_sensitive_text(part) if separator else part)
    return clean_text(
        urlunsplit((parsed.scheme, netloc, parsed.path, "".join(query_parts), "")),
        max_len=max_len,
    )


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
            redact_sensitive_text(f"{type(e).__name__}: {e}"), max_len=max_len
        )
        return detail or default

    if isinstance(e, ValueError):
        msg = clean_text(redact_sensitive_text(str(e)), max_len=max_len)
        return msg or default

    return default
