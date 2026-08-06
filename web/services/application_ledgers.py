from __future__ import annotations

import re
import unicodedata
from typing import Any

from services.errors import redact_sensitive_text

APPLICATION_DETAIL_MAX = 4000
APPLICATION_ACTOR_MAX = 255
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_INVISIBLE_ACTOR_CATEGORIES = {"Cc", "Cf"}


def row_value(row: Any, key: str, default: object = "") -> object:
    try:
        return row[key]  # type: ignore[index]
    except Exception:
        return default


def normalize_application_detail(
    value: object, *, max_len: int = APPLICATION_DETAIL_MAX
) -> str:
    """Redact and bound operator-visible apply details without flattening useful lines."""
    text = redact_sensitive_text("" if value is None else str(value))
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = "".join(ch if ch in {"\n", "\t"} or ch >= " " else " " for ch in text)
    return text[: max(0, int(max_len))]


def normalize_application_actor(value: object, *, default: str = "proxy") -> str:
    def _single_line_actor(candidate: object) -> str:
        text = "" if candidate is None else str(candidate)
        text = "".join(
            " "
            if ch.isspace() or unicodedata.category(ch) in _INVISIBLE_ACTOR_CATEGORIES
            else ch
            for ch in text
        )
        return redact_sensitive_text(re.sub(r" +", " ", text).strip())

    actor = _single_line_actor(value) or _single_line_actor(default) or "proxy"
    return actor[:APPLICATION_ACTOR_MAX]


def normalize_sha256_evidence(
    value: object,
    *,
    fallback: object = "",
    ok: bool = False,
    label: str = "application evidence SHA-256",
) -> str:
    """Return valid lower-case SHA-256 evidence, using revision evidence as fallback.

    Successful application rows must not claim a different valid digest than the
    revision they reference. Failed rows may carry different valid runtime/current
    evidence, but malformed evidence is never persisted.
    """
    fallback_text = str(fallback or "").strip().lower()
    fallback_sha = fallback_text if _SHA256_RE.fullmatch(fallback_text) else ""
    candidate = str(value or "").strip().lower()
    if not candidate:
        return fallback_sha
    if not _SHA256_RE.fullmatch(candidate):
        return fallback_sha
    if ok and fallback_sha and candidate != fallback_sha:
        msg = f"{label} does not match the referenced revision."
        raise ValueError(msg)
    return candidate
