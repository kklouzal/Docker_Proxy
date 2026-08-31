from __future__ import annotations

import pytest
from services.url_validation import (
    has_ascii_control_chars,
    has_malformed_percent_encoding,
    has_url_whitespace_or_control_chars,
    repeatedly_percent_decode,
)


@pytest.mark.parametrize(
    "value",
    [
        "plain",
        "%00",
        "%09%2f%2F",
        "%aB%Ab%AB",
        "prefix%20suffix",
        "non-ascii-文字",
    ],
)
def test_percent_encoding_primitive_accepts_complete_ascii_hex_octets(
    value: str,
) -> None:
    assert not has_malformed_percent_encoding(value)


@pytest.mark.parametrize(
    "value",
    [
        "%",
        "%0",
        "%GG",
        "%2g",
        "%g2",
        "ok%20then%",
        "%２F",  # noqa: RUF001 - fullwidth digit is intentionally not ASCII hex.
        "%2Ｆ",  # noqa: RUF001 - fullwidth letter is intentionally not ASCII hex.
        "%é0",
    ],
)
def test_percent_encoding_primitive_rejects_malformed_truncated_or_non_ascii_hex(
    value: str,
) -> None:
    assert has_malformed_percent_encoding(value)


def test_repeated_percent_decode_reports_each_nested_layer() -> None:
    result = repeatedly_percent_decode("safe%252520value", max_passes=4)

    assert result.values == (
        "safe%252520value",
        "safe%2520value",
        "safe%20value",
        "safe value",
    )
    assert not result.malformed
    assert not result.excessive_nesting


@pytest.mark.parametrize("value", ["bad%", "%25GG", "%2525GG"])
def test_repeated_percent_decode_reports_malformed_input_at_any_layer(
    value: str,
) -> None:
    result = repeatedly_percent_decode(value, max_passes=4)

    assert result.malformed


def test_repeated_percent_decode_reports_strict_utf8_failure() -> None:
    result = repeatedly_percent_decode("%FF", max_passes=1, errors="strict")

    assert result.invalid_utf8


def test_repeated_percent_decode_reports_decode_limit_exhaustion() -> None:
    result = repeatedly_percent_decode("%25252520", max_passes=2)

    assert result.values[-1] == "%2520"
    assert result.excessive_nesting


def test_repeated_percent_decode_can_preserve_legacy_malformed_text_semantics() -> None:
    result = repeatedly_percent_decode("%25GG", max_passes=2, reject_malformed=False)

    assert result.values == ("%25GG", "%GG")
    assert not result.malformed


@pytest.mark.parametrize("value", ["line\nfeed", "tab\there", "delete\x7f"])
def test_ascii_control_detection_covers_c0_and_delete(value: str) -> None:
    assert has_ascii_control_chars(value)


def test_url_text_detection_includes_unicode_whitespace_but_control_check_does_not() -> (
    None
):
    value = "path\u00a0segment"

    assert has_url_whitespace_or_control_chars(value)
    assert not has_ascii_control_chars(value)


def test_url_text_detection_allows_visible_backslash_and_delimiters() -> None:
    # Consumers retain authority for backslash and URL-delimiter policy.
    assert not has_url_whitespace_or_control_chars(r"path\segment?query#fragment")
