from __future__ import annotations

import re

_REPORT_SCHEDULE_RECIPIENTS_MAX_CHARS = 512
_REPORT_SCHEDULE_EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)
_REPORT_SCHEDULE_RECIPIENT_SEPARATOR_RE = re.compile(r"[,; ]+")

REPORT_SCHEDULE_RECIPIENT_ERROR_MESSAGES = {
    "required": "At least one report recipient is required.",
    "control_chars": (
        "Report recipients must not contain control characters or newlines."
    ),
    "empty_entry": "Report recipients must not contain empty recipient entries.",
    "invalid_email": "Report recipients must be valid email addresses.",
    "too_long": (
        "Report recipients must be 512 characters or fewer after normalization."
    ),
}
_REPORT_SCHEDULE_RECIPIENT_ERROR_CODES = {
    message: code for code, message in REPORT_SCHEDULE_RECIPIENT_ERROR_MESSAGES.items()
}


def report_schedule_recipient_error_code(error: object) -> str:
    return _REPORT_SCHEDULE_RECIPIENT_ERROR_CODES.get(str(error or ""), "invalid")


def normalize_report_schedule_recipients(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(REPORT_SCHEDULE_RECIPIENT_ERROR_MESSAGES["required"])
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
        raise ValueError(REPORT_SCHEDULE_RECIPIENT_ERROR_MESSAGES["control_chars"])
    if re.search(r"(?:^|[,;]) *([,;]|$)", text):
        raise ValueError(REPORT_SCHEDULE_RECIPIENT_ERROR_MESSAGES["empty_entry"])

    normalized: list[str] = []
    seen: set[str] = set()
    for token in _REPORT_SCHEDULE_RECIPIENT_SEPARATOR_RE.split(text):
        recipient = token.strip()
        if not recipient:
            raise ValueError(REPORT_SCHEDULE_RECIPIENT_ERROR_MESSAGES["empty_entry"])
        if not _valid_report_schedule_email(recipient):
            raise ValueError(REPORT_SCHEDULE_RECIPIENT_ERROR_MESSAGES["invalid_email"])
        key = recipient.lower()
        if key not in seen:
            seen.add(key)
            normalized.append(recipient)

    normalized_text = ", ".join(normalized)
    if not normalized_text:
        raise ValueError(REPORT_SCHEDULE_RECIPIENT_ERROR_MESSAGES["required"])
    if len(normalized_text) > _REPORT_SCHEDULE_RECIPIENTS_MAX_CHARS:
        raise ValueError(REPORT_SCHEDULE_RECIPIENT_ERROR_MESSAGES["too_long"])
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
