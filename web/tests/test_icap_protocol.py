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


@pytest.mark.parametrize(
    "line",
    [
        b"",
        b"+0",
        b"0x10",
        b"G",
        b"1 ",
        b"F" * 17,
        b"0;",
        b"0;bad extension",
        b"0;name=",
        b'0;name="bad',
        b"0;name=bad\x01",
        b"0;ieof;IEOF",
        b"0;x;x",
        b"0;ieof=yes",
        b"1;ieof",
    ],
)
def test_chunk_header_rejects_shapes_rejected_by_helpers(line: bytes) -> None:
    with pytest.raises(IcapWireSyntaxError):
        parse_chunk_header(line)


def test_chunk_header_reports_zero_ieof_and_accepts_other_extensions() -> None:
    parsed = parse_chunk_header(b'0; ext=value; q="a b;c"; ieof')
    assert parsed.size == 0
    assert parsed.has_ieof is True


@pytest.mark.parametrize(
    "line",
    [
        b"missing-colon",
        b": value",
        b"bad name: value",
        b"Name: bad\x00value",
        b"Content-Length: 5",
        b"Transfer-Encoding: chunked",
    ],
)
def test_chunk_trailer_rejects_malformed_field_syntax(line: bytes) -> None:
    with pytest.raises(IcapWireSyntaxError):
        validate_chunk_trailer(line)


def test_chunk_trailer_accepts_token_name_ows_and_visible_value() -> None:
    validate_chunk_trailer(b"X-Scan_Result:\tclean result")
