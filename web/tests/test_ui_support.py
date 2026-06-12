from __future__ import annotations

import pytest
from services.ui_support import append_query_to_local_return, safe_local_return_url


@pytest.mark.parametrize(
    "value",
    [
        "http://[::1",
        "//[::1",
        "https://example.invalid/admin",
    ],
)
def test_safe_local_return_url_rejects_absolute_or_malformed(value: str) -> None:
    assert safe_local_return_url(value) is None


def test_safe_local_return_url_preserves_valid_local_return() -> None:
    assert safe_local_return_url(" /admin?pane=ssl#top ") == "/admin?pane=ssl#top"


def test_append_query_to_local_return_fails_closed_for_malformed_return() -> None:
    assert append_query_to_local_return("http://[::1", ok=1) is None


def test_append_query_to_local_return_preserves_and_replaces_query_values() -> None:
    assert (
        append_query_to_local_return("/admin?pane=old&keep=1#top", pane="ssl", ok=1)
        == "/admin?keep=1&pane=ssl&ok=1#top"
    )
