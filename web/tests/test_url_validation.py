from __future__ import annotations

import pytest
from services.url_validation import has_malformed_percent_encoding


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
