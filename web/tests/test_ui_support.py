from __future__ import annotations

import pytest
from services.ui_support import (
    append_query_to_local_return,
    present_top_tag_rows,
    present_top_value_rows,
    present_transaction_rows,
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
        "/%2525252fevil.example/path",
        "/%E0%A4%A",
        "/%C0%AF",
        "/admin?next=%ZZ",
        "/admin#%ZZ",
        "/admin?next=%0d%0aLocation:%20//evil.example",
    ],
)
def test_safe_local_return_url_rejects_absolute_or_malformed(value: str) -> None:
    assert safe_local_return_url(value) is None


@pytest.mark.parametrize(
    "value",
    [
        "/../admin",
        "/./admin",
        "/admin/../login",
        "/admin/./login",
        "/%2e%2e/admin",
        "/%2e/admin",
        "/admin/%2e%2e/login",
        "/admin/%2e/login",
        "/%252e%252e/admin",
        "/admin/%252e/login",
    ],
)
def test_safe_local_return_url_rejects_raw_or_encoded_dot_segments(
    value: str,
) -> None:
    assert safe_local_return_url(value) is None


def test_safe_local_return_url_preserves_valid_local_return() -> None:
    assert safe_local_return_url(" /admin?pane=ssl#top ") == "/admin?pane=ssl#top"
    assert (
        safe_local_return_url("/admin/v1.2/login?next=..#section.1")
        == "/admin/v1.2/login?next=..#section.1"
    )


def test_safe_local_return_url_allows_encoded_slashes_in_query_and_fragment() -> None:
    assert safe_local_return_url("/login?next=%2Fadmin") == "/login?next=%2Fadmin"
    assert safe_local_return_url("/admin#%2Fsection") == "/admin#%2Fsection"
    assert (
        safe_local_return_url("/admin?next=%252Fadmin#tab=%252Fsection")
        == "/admin?next=%252Fadmin#tab=%252Fsection"
    )


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


def test_append_query_to_local_return_allows_encoded_slash_next_value() -> None:
    assert (
        append_query_to_local_return("/login?next=%2Fadmin#%2Fsection", ok=1)
        == "/login?next=%2Fadmin&ok=1#%2Fsection"
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


def test_present_transaction_rows_omits_leading_separator_without_result_code() -> None:
    rows = [
        {
            "result_code": "",
            "http_status": 200,
            "hierarchy_status": "HIER_DIRECT/203.0.113.10",
        },
    ]

    presented = present_transaction_rows(rows)

    assert presented[0]["result_summary"] == "HTTP 200 · HIER_DIRECT/203.0.113.10"


def test_present_transaction_rows_treats_whitespace_result_code_as_blank() -> None:
    rows = [
        {
            "result_code": "   ",
            "http_status": "204",
            "hierarchy_status": "HIER_NONE/-",
        },
    ]

    presented = present_transaction_rows(rows)

    assert presented[0]["result_summary"] == "HTTP 204 · HIER_NONE/-"


def test_present_transaction_rows_preserves_summary_when_result_code_exists() -> None:
    rows = [
        {
            "result_code": "TCP_MISS",
            "http_status": 200,
            "hierarchy_status": "HIER_DIRECT/203.0.113.10",
        },
    ]

    presented = present_transaction_rows(rows)

    assert presented[0]["result_summary"] == "TCP_MISS · HTTP 200 · HIER_DIRECT/203.0.113.10"
