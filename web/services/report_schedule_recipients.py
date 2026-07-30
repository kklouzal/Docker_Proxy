from __future__ import annotations

import re

_REPORT_SCHEDULE_RECIPIENTS_MAX_CHARS = 512
_REPORT_SCHEDULE_EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)
_REPORT_SCHEDULE_RECIPIENT_SEPARATOR_RE = re.compile(r"[,; ]+")


def normalize_report_schedule_recipients(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        msg = "At least one report recipient is required."
        raise ValueError(msg)
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
        msg = "Report recipients must not contain control characters or newlines."
        raise ValueError(msg)
    if re.search(r"(?:^|[,;]) *([,;]|$)", text):
        msg = "Report recipients must not contain empty recipient entries."
        raise ValueError(msg)

    normalized: list[str] = []
    seen: set[str] = set()
    for token in _REPORT_SCHEDULE_RECIPIENT_SEPARATOR_RE.split(text):
        recipient = token.strip()
        if not recipient:
            msg = "Report recipients must not contain empty recipient entries."
            raise ValueError(msg)
        if not _valid_report_schedule_email(recipient):
            msg = "Report recipients must be valid email addresses."
            raise ValueError(msg)
        key = recipient.lower()
        if key not in seen:
            seen.add(key)
            normalized.append(recipient)

    normalized_text = ", ".join(normalized)
    if not normalized_text:
        msg = "At least one report recipient is required."
        raise ValueError(msg)
    if len(normalized_text) > _REPORT_SCHEDULE_RECIPIENTS_MAX_CHARS:
        msg = "Report recipients must be 512 characters or fewer after normalization."
        raise ValueError(msg)
    return normalized_text


def _valid_report_schedule_email(value: str) -> bool:
    if len(value) > 254 or "@" not in value:
        return False
    if not _REPORT_SCHEDULE_EMAIL_RE.fullmatch(value):
        return False
    local, domain = value.rsplit("@", 1)
    if len(local) > 64 or len(domain) > 253:
        return False
    if local.startswith(".") or local.endswith(".") or ".." in local:
        return False
    return ".." not in domain
