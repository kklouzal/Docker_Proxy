from __future__ import annotations

import pytest
from services.icap_protocol import (
    IcapWireSyntaxError,
    parse_chunk_header,
    parse_encapsulated_sections,
    validate_chunk_trailer,
)


def test_encapsulated_parser_leaves_method_layout_to_callers() -> None:
    assert parse_encapsulated_sections(
        "req-hdr=0, res-hdr=42, res-body=84",
        supported_names={"req-hdr", "res-hdr", "res-body"},
    ) == {"req-hdr": 0, "res-hdr": 42, "res-body": 84}


@pytest.mark.parametrize(
    "value",
    [
        "req-hdr=0,req-hdr=1",
        "req-hdr=+0",
        "req-hdr=0,res-hdr=184467440737095516160",
        "req-hdr=0,unknown=1",
    ],
)
def test_encapsulated_parser_rejects_shared_malformed_syntax(value: str) -> None:
    with pytest.raises(IcapWireSyntaxError):
        parse_encapsulated_sections(
            value,
            supported_names={"req-hdr", "res-hdr", "res-body"},
        )


@pytest.mark.parametrize("line", [b"", b"+0", b"0x10", b"G"])
def test_chunk_header_rejects_shapes_rejected_by_helpers(line: bytes) -> None:
    with pytest.raises(IcapWireSyntaxError):
        parse_chunk_header(line)


def test_chunk_header_reports_ieof_for_caller_policy() -> None:
    parsed = parse_chunk_header(b"1;ieof")
    assert parsed.size == 1
    assert parsed.has_ieof is True


def test_chunk_header_reports_zero_ieof_and_ignores_other_extensions() -> None:
    parsed = parse_chunk_header(b"0; ext=value; ieof=yes")
    assert parsed.size == 0
    assert parsed.has_ieof is True


@pytest.mark.parametrize(
    "line",
    [b"missing-colon", b": value", b"bad name: value", b"Name: bad\x00value"],
)
def test_chunk_trailer_rejects_malformed_field_syntax(line: bytes) -> None:
    with pytest.raises(IcapWireSyntaxError):
        validate_chunk_trailer(line)


def test_chunk_trailer_accepts_token_name_ows_and_visible_value() -> None:
    validate_chunk_trailer(b"X-Scan_Result:\tclean result")
