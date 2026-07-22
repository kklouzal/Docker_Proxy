from __future__ import annotations

import pytest
from services.ui_support import (
    append_query_to_local_return,
    present_top_tag_rows,
    present_top_value_rows,
    safe_local_return_url,
)


@pytest.mark.parametrize(
    "value",
    [
        "http://[::1",
        "//[::1",
        "https://example.invalid/admin",
        "/%2F%2Fevil.example/path",
        "/%5Cevil.example/path",
        "/safe\\..\\login",
        "/admin%0d%0aLocation:%20//evil.example",
        "/admin%00",
        "/admin%2Fsettings",
        "/%252fevil.example/path",
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


def test_append_query_to_local_return_preserves_valid_query_and_fragment() -> None:
    assert (
        append_query_to_local_return("/admin/ssl?pane=old&keep=1#details", pane="tls")
        == "/admin/ssl?keep=1&pane=tls#details"
    )


def test_present_top_value_rows_skips_empty_values_and_preserves_full_label() -> None:
    rows = [
        {"value": "  ", "count": 5, "last_seen": 100},
        {"value": "client.example.test", "count": "7", "last_seen": "123"},
    ]

    assert present_top_value_rows(rows, max_label=10) == [
        {
            "label": "client.ex…",
            "full_label": "client.example.test",
            "count": 7,
            "last_seen": 123,
        },
    ]


def test_present_top_tag_rows_uses_tag_key_and_tag_label_default() -> None:
    long_tag = f"cache:{'x' * 80}"

    presented = present_top_tag_rows([{"tag": long_tag, "count": 2}])

    assert presented == [
        {
            "label": f"cache:{'x' * 65}…",
            "full_label": long_tag,
            "count": 2,
            "last_seen": 0,
        },
    ]
