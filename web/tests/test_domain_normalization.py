from __future__ import annotations

import sys
from pathlib import Path


def _add_web_to_path() -> None:
    web_dir = Path(__file__).resolve().parents[1]
    if str(web_dir) not in sys.path:
        sys.path.insert(0, str(web_dir))


_add_web_to_path()

from services.domain_normalization import (  # type: ignore  # noqa: E402
    looks_like_domain,
    normalize_domain,
)


def test_normalize_domain_rejects_consecutive_empty_labels() -> None:
    assert normalize_domain("bad..example") == ""
    assert normalize_domain("https://bad..example/path") == ""
    assert looks_like_domain("bad..example") is False


def test_normalize_domain_preserves_intentional_leading_and_trailing_dot_cleanup() -> None:
    assert normalize_domain(".Example.COM.") == "example.com"
