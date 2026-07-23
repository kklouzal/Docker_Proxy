#!/usr/bin/env python3
"""Run optional/required c-icap AV without spawning probe helper processes."""

from __future__ import annotations

import os
import re
import socket
import socketserver
import sys
from pathlib import Path
from urllib.parse import urlsplit

TRUE_VALUES = {"1", "true", "yes", "on", "required", "strict"}
CRLF = b"\r\n"
HEADER_END = CRLF + CRLF
DEFAULT_MAX_HEADER_BYTES = 64 * 1024
CLAMD_READY_MAX_REPLY_BYTES = 64
MAX_ENCAPSULATED_OFFSET_DIGITS = 20
MAX_HTTP_CONTENT_LENGTH_DIGITS = 20
MAX_ICAP_PREVIEW_DIGITS = 20
MAX_ICAP_CHUNK_SIZE_DIGITS = 16
MAX_ICAP_HEADER_LINE_BYTES = 8192
MAX_ICAP_TRAILER_LINE_BYTES = 8192
MAX_ICAP_TRAILERS_BYTES = DEFAULT_MAX_HEADER_BYTES
FALLBACK_OPEN_ISTAG = '"clamav-fail-open-unavailable"'
FALLBACK_CLOSED_ISTAG = '"clamav-fail-closed-unavailable"'
_CHUNK_OWS = b" \t"
_CHUNK_TCHARS = frozenset(
    b"!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)
_ICAP_FIELD_NAME_TCHARS = _CHUNK_TCHARS
_HTTP_FIELD_NAME_TCHARS = _CHUNK_TCHARS
_FORBIDDEN_ICAP_TRAILER_FIELDS = {
    b"allow",
    b"content-length",
    b"encapsulated",
    b"preview",
    b"trailer",
    b"transfer-encoding",
}
_SINGLETON_ICAP_HEADERS = {
    "allow": "Allow",
    "encapsulated": "Encapsulated",
    "preview": "Preview",
}
_ICAP_METHOD_TCHARS = _CHUNK_TCHARS


class IcapProtocolError(Exception):
    pass


def _parse_icap_start_line(header: bytes) -> tuple[str, str, str]:
    raw_start_line = header.split(CRLF, 1)[0] if header else b""
    if any(ch < 0x20 or ch >= 0x7F for ch in raw_start_line):
        message = "invalid ICAP request start line"
        raise IcapProtocolError(message)
    try:
        method_token, service_uri, version = raw_start_line.decode("ascii").split(" ")
    except ValueError as exc:
        message = "malformed ICAP request start line"
        raise IcapProtocolError(message) from exc
    if not method_token or any(
        ch not in _ICAP_METHOD_TCHARS for ch in method_token.encode("ascii")
    ):
        message = "invalid ICAP method token"
        raise IcapProtocolError(message)
    if version != "ICAP/1.0":
        message = "unsupported ICAP version"
        raise IcapProtocolError(message)
    try:
        parsed_uri = urlsplit(service_uri)
        hostname = parsed_uri.hostname
        _port = parsed_uri.port
    except ValueError as exc:
        message = "invalid ICAP service URI"
        raise IcapProtocolError(message) from exc
    if (
        parsed_uri.scheme.lower() != "icap"
        or not parsed_uri.netloc
        or not hostname
        or parsed_uri.path in {"", "/"}
        or parsed_uri.fragment
    ):
        message = "invalid ICAP service URI"
        raise IcapProtocolError(message)
    return method_token.upper(), service_uri, version


def env_enabled(value: str | None) -> bool:
    return (value or "").strip().lower() in TRUE_VALUES


def _recv_clamd_ping_reply(sock: socket.socket) -> bytes:
    data = bytearray()
    while len(data) < CLAMD_READY_MAX_REPLY_BYTES:
        chunk = sock.recv(CLAMD_READY_MAX_REPLY_BYTES - len(data))
        if not chunk:
            break
        data.extend(chunk)
        if b"\n" in chunk or b"\0" in chunk:
            break
    return bytes(data)


def _clamd_ping_reply_is_pong(data: bytes) -> bool:
    if data.endswith(b"\r\n"):
        payload = data[:-2]
    elif data.endswith((b"\n", b"\0")):
        payload = data[:-1]
    else:
        return False
    return payload == b"PONG"


def clamd_ready(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(b"PING\n")
            return _clamd_ping_reply_is_pong(_recv_clamd_ping_reply(sock))
    except OSError:
        return False


def _conf_listen_address(conf_path: str) -> tuple[str, int]:
    text = Path(conf_path).read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = re.match(r"(?i)^port\s+(?:(\S+):)?(\d+)\s*$", stripped)
        if not match:
            continue
        host = (match.group(1) or "127.0.0.1").strip() or "127.0.0.1"
        port = int(match.group(2))
        if 1 <= port <= 65535:
            return host, port
    fallback_port_raw = (os.environ.get("CICAP_AV_PORT") or "14001").strip()
    try:
        fallback_port = int(fallback_port_raw or "14001")
    except ValueError:
        fallback_port = 14001
    if not 1 <= fallback_port <= 65535:
        fallback_port = 14001
    return "127.0.0.1", fallback_port


def _validate_icap_field_line(line: bytes) -> tuple[str, str]:
    if line[:1] in _CHUNK_OWS:
        message = "obsolete folded ICAP header line"
        raise IcapProtocolError(message)
    if b":" not in line:
        message = "malformed ICAP header field line"
        raise IcapProtocolError(message)
    raw_name, raw_value = line.split(b":", 1)
    if not raw_name or any(ch not in _ICAP_FIELD_NAME_TCHARS for ch in raw_name):
        message = "invalid ICAP header field name"
        raise IcapProtocolError(message)
    if any(ch != 0x09 and (ch < 0x20 or ch == 0x7F) for ch in raw_value):
        message = "invalid ICAP header field value"
        raise IcapProtocolError(message)
    header_name = raw_name.decode("ascii").lower()
    header_value = raw_value.strip(b" \t").decode("iso-8859-1")
    return header_name, header_value


def _split_headers(header_bytes: bytes) -> tuple[str, dict[str, str]]:
    lines = header_bytes.split(CRLF)
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line:
            continue
        header_name, header_value = _validate_icap_field_line(line)
        if header_name in _SINGLETON_ICAP_HEADERS and header_name in headers:
            display_name = _SINGLETON_ICAP_HEADERS[header_name]
            message = f"duplicate ICAP {display_name} header"
            raise IcapProtocolError(message)
        headers[header_name] = header_value
    start_line = lines[0].decode("iso-8859-1", errors="replace") if lines else ""
    return start_line, headers


def _parse_encapsulated(value: str) -> dict[str, int]:
    supported_names = {"req-hdr", "req-body", "res-hdr", "res-body", "null-body"}
    offsets: dict[str, int] = {}
    for raw_item in value.split(","):
        item = raw_item.strip()
        if not item or "=" not in item:
            message = f"malformed Encapsulated section item: {item}"
            raise IcapProtocolError(message)
        name, raw_offset = item.split("=", 1)
        name = name.strip().lower()
        if name not in supported_names:
            message = f"unknown Encapsulated section token: {name}"
            raise IcapProtocolError(message)
        if name in offsets:
            message = f"duplicate Encapsulated section name: {name}"
            raise IcapProtocolError(message)
        offset_text = raw_offset.strip()
        if (
            not offset_text
            or len(offset_text) > MAX_ENCAPSULATED_OFFSET_DIGITS
            or any(ch < "0" or ch > "9" for ch in offset_text)
        ):
            message = f"invalid Encapsulated offset: {item}"
            raise IcapProtocolError(message)
        offset = int(offset_text, 10)
        offsets[name] = offset
    return offsets


def _parse_icap_preview_header(value: str | None, *, max_bytes: int) -> int | None:
    if value is None:
        return None
    if (
        not value
        or len(value) > MAX_ICAP_PREVIEW_DIGITS
        or any(ch < "0" or ch > "9" for ch in value)
    ):
        message = "invalid ICAP Preview header"
        raise IcapProtocolError(message)
    preview_size = int(value, 10)
    if preview_size > max_bytes:
        message = f"ICAP Preview header exceeds {max_bytes} bytes"
        raise IcapProtocolError(message)
    return preview_size


def _respmod_allow_204_eligible(value: str | None) -> bool:
    if value is None or value == "":
        return False
    allow_204 = False
    for raw_item in value.split(","):
        item = raw_item.strip(" \t")
        if not item:
            return False
        try:
            token = item.encode("ascii")
        except UnicodeEncodeError:
            return False
        if any(ch not in _CHUNK_TCHARS for ch in token):
            return False
        if item == "204":
            allow_204 = True
    return allow_204


def _validate_respmod_encapsulated_offsets(
    offsets: dict[str, int],
    *,
    max_header_bytes: int = DEFAULT_MAX_HEADER_BYTES,
) -> None:
    request_header_offset = offsets.get("req-hdr")
    response_header_offset = offsets.get("res-hdr")
    body_offset = offsets.get("res-body")
    null_body_offset = offsets.get("null-body")

    if "req-body" in offsets:
        message = "RESPMOD request has unsupported req-body"
        raise IcapProtocolError(message)
    if response_header_offset is None:
        message = "RESPMOD request missing res-hdr"
        raise IcapProtocolError(message)
    if body_offset is not None and null_body_offset is not None:
        message = "RESPMOD request has both res-body and null-body"
        raise IcapProtocolError(message)

    terminal_offset = body_offset if body_offset is not None else null_body_offset
    if terminal_offset is None:
        message = "RESPMOD request missing res-body/null-body"
        raise IcapProtocolError(message)

    if request_header_offset is None:
        if response_header_offset != 0:
            message = "RESPMOD res-hdr offset must be zero without req-hdr"
            raise IcapProtocolError(message)
    elif request_header_offset != 0:
        message = "RESPMOD req-hdr offset must be zero"
        raise IcapProtocolError(message)
    elif response_header_offset <= request_header_offset:
        message = "invalid RESPMOD encapsulated request/response offsets"
        raise IcapProtocolError(message)

    if terminal_offset > max_header_bytes:
        message = f"RESPMOD encapsulated headers exceed {max_header_bytes} bytes"
        raise IcapProtocolError(message)
    if terminal_offset <= response_header_offset:
        message = "invalid RESPMOD encapsulated response offsets"
        raise IcapProtocolError(message)


def _validate_respmod_encapsulated_boundaries(
    encapsulated_headers: bytes, offsets: dict[str, int]
) -> None:
    response_header_offset = offsets["res-hdr"]
    terminal_offset = offsets.get("res-body", offsets.get("null-body"))
    if terminal_offset is None:  # pragma: no cover - offset validation guards this
        message = "RESPMOD request missing res-body/null-body"
        raise IcapProtocolError(message)

    if offsets.get("req-hdr") is not None:
        request_header = encapsulated_headers[:response_header_offset]
        if not request_header.endswith(HEADER_END):
            message = "invalid RESPMOD encapsulated req-hdr boundary"
            raise IcapProtocolError(message)

    response_header = encapsulated_headers[response_header_offset:terminal_offset]
    if not response_header.endswith(HEADER_END):
        message = "invalid RESPMOD encapsulated res-hdr boundary"
        raise IcapProtocolError(message)


def _validate_reqmod_encapsulated_offsets(
    offsets: dict[str, int],
    *,
    max_header_bytes: int = DEFAULT_MAX_HEADER_BYTES,
) -> None:
    request_header_offset = offsets.get("req-hdr")
    body_offset = offsets.get("req-body")
    null_body_offset = offsets.get("null-body")

    if "res-hdr" in offsets or "res-body" in offsets:
        message = "REQMOD request has unsupported response section"
        raise IcapProtocolError(message)
    if body_offset is not None and null_body_offset is not None:
        message = "REQMOD request has both req-body and null-body"
        raise IcapProtocolError(message)

    terminal_offset = body_offset if body_offset is not None else null_body_offset
    if terminal_offset is None:
        message = "REQMOD request missing req-body/null-body"
        raise IcapProtocolError(message)

    if request_header_offset is None:
        if body_offset is not None:
            message = "REQMOD request missing req-hdr"
            raise IcapProtocolError(message)
        if null_body_offset != 0:
            message = "REQMOD null-body offset must be zero without req-hdr"
            raise IcapProtocolError(message)
        return

    if request_header_offset != 0:
        message = "REQMOD req-hdr offset must be zero"
        raise IcapProtocolError(message)
    if terminal_offset > max_header_bytes:
        message = f"REQMOD encapsulated headers exceed {max_header_bytes} bytes"
        raise IcapProtocolError(message)
    if terminal_offset <= request_header_offset:
        message = "invalid REQMOD encapsulated request offsets"
        raise IcapProtocolError(message)


def _validate_reqmod_encapsulated_boundaries(
    encapsulated_headers: bytes, offsets: dict[str, int]
) -> None:
    terminal_offset = offsets.get("req-body", offsets.get("null-body"))
    if terminal_offset is None:  # pragma: no cover - offset validation guards this
        message = "REQMOD request missing req-body/null-body"
        raise IcapProtocolError(message)

    if offsets.get("req-hdr") is not None:
        request_header = encapsulated_headers[:terminal_offset]
        if not request_header.endswith(HEADER_END):
            message = "invalid REQMOD encapsulated req-hdr boundary"
            raise IcapProtocolError(message)


def _recv_more(sock: socket.socket, data: bytes, size: int) -> bytes:
    while len(data) < size:
        chunk = sock.recv(min(65536, size - len(data)))
        if not chunk:
            break
        data += chunk
    return data


def _recv_until(
    sock: socket.socket, data: bytes, delimiter: bytes, *, max_bytes: int
) -> bytes:
    while delimiter not in data and len(data) < max_bytes:
        chunk = sock.recv(min(8192, max_bytes - len(data)))
        if not chunk:
            break
        data += chunk
    return data


def _raise_icap_header_read_error(data: bytes) -> None:
    for line in data.split(CRLF):
        if len(line) > MAX_ICAP_HEADER_LINE_BYTES:
            message = f"ICAP header line exceeds {MAX_ICAP_HEADER_LINE_BYTES} bytes"
            raise IcapProtocolError(message)
    if len(data) > DEFAULT_MAX_HEADER_BYTES:
        message = f"ICAP header block exceeds {DEFAULT_MAX_HEADER_BYTES} bytes"
        raise IcapProtocolError(message)
    message = "truncated ICAP header"
    raise IcapProtocolError(message)


def _validate_icap_header_read_bounds(header: bytes) -> None:
    if len(header) > DEFAULT_MAX_HEADER_BYTES:
        message = f"ICAP header block exceeds {DEFAULT_MAX_HEADER_BYTES} bytes"
        raise IcapProtocolError(message)
    for line in header.split(CRLF):
        if len(line) > MAX_ICAP_HEADER_LINE_BYTES:
            message = f"ICAP header line exceeds {MAX_ICAP_HEADER_LINE_BYTES} bytes"
            raise IcapProtocolError(message)


def _read_icap_outer_header(sock: socket.socket) -> tuple[bytes, bytes]:
    read_limit = DEFAULT_MAX_HEADER_BYTES + len(HEADER_END)
    try:
        data = _recv_until(sock, b"", HEADER_END, max_bytes=read_limit)
    except TimeoutError as exc:
        message = "truncated ICAP header"
        raise IcapProtocolError(message) from exc
    if HEADER_END not in data:
        _raise_icap_header_read_error(data)
    header, remainder = data.split(HEADER_END, 1)
    _validate_icap_header_read_bounds(header)
    return header, remainder


def _drain_chunked_body(
    sock: socket.socket,
    data: bytes,
    *,
    max_bytes: int = 1024 * 1024 * 1024,
    preview: bool = False,
) -> bytes:
    _body, remainder = _read_chunked_body(
        sock, data, max_bytes=max_bytes, preview=preview
    )
    return remainder


def _valid_chunk_token(value: bytes) -> bool:
    return bool(value) and all(ch in _CHUNK_TCHARS for ch in value)


def _skip_chunk_ows(line: bytes, index: int) -> int:
    while index < len(line) and line[index] in _CHUNK_OWS:
        index += 1
    return index


def _parse_chunk_quoted_string(line: bytes, index: int) -> int | None:
    escaped = False
    index += 1
    while index < len(line):
        ch = line[index]
        if escaped:
            if ch not in _CHUNK_OWS and not (0x21 <= ch <= 0x7E):
                return None
            escaped = False
        elif ch == 0x5C:  # backslash
            escaped = True
        elif ch == 0x22:
            return index + 1
        elif ch < 0x20 or ch >= 0x7F:
            return None
        index += 1
    return None


def _parse_chunk_line(line: bytes) -> tuple[int, set[bytes]]:
    if any(ch < 0x20 and ch not in _CHUNK_OWS for ch in line) or any(
        ch >= 0x7F for ch in line
    ):
        message = "invalid ICAP chunk-size line"
        raise IcapProtocolError(message)
    first_extension = line.find(b";")
    size_token = line if first_extension < 0 else line[:first_extension]
    if (
        not size_token
        or len(size_token) > MAX_ICAP_CHUNK_SIZE_DIGITS
        or any(ch not in b"0123456789abcdefABCDEF" for ch in size_token)
    ):
        message = "invalid ICAP chunk-size line"
        raise IcapProtocolError(message)
    extensions: set[bytes] = set()
    index = first_extension
    while index >= 0 and index < len(line):
        if line[index] != 0x3B:  # semicolon
            message = "invalid ICAP chunk extension"
            raise IcapProtocolError(message)
        index = _skip_chunk_ows(line, index + 1)
        name_start = index
        while index < len(line) and line[index] in _CHUNK_TCHARS:
            index += 1
        name = line[name_start:index]
        if not name:
            message = "invalid ICAP chunk extension"
            raise IcapProtocolError(message)
        index = _skip_chunk_ows(line, index)
        separator = index < len(line) and line[index] == 0x3D  # equals
        if separator:
            index = _skip_chunk_ows(line, index + 1)
            if index < len(line) and line[index] == 0x22:  # double quote
                index = _parse_chunk_quoted_string(line, index) or -1
            else:
                value_start = index
                while index < len(line) and line[index] in _CHUNK_TCHARS:
                    index += 1
                if index == value_start:
                    message = "invalid ICAP chunk extension"
                    raise IcapProtocolError(message)
            if index < 0:
                message = "invalid ICAP chunk extension"
                raise IcapProtocolError(message)
            index = _skip_chunk_ows(line, index)
        if index < len(line) and line[index] != 0x3B:
            message = "invalid ICAP chunk extension"
            raise IcapProtocolError(message)
        name = name.lower()
        if name in extensions:
            message = f"duplicate ICAP chunk extension: {name.decode('ascii')}"
            raise IcapProtocolError(message)
        if name == b"ieof" and separator:
            message = "invalid ICAP preview ieof chunk extension"
            raise IcapProtocolError(message)
        extensions.add(name)
    size = int(size_token, 16)
    if size != 0 and b"ieof" in extensions:
        message = "invalid ICAP preview ieof chunk extension"
        raise IcapProtocolError(message)
    return size, extensions


def _parse_chunk_size(line: bytes) -> int:
    size, _extensions = _parse_chunk_line(line)
    return size


def _validate_chunk_trailer(line: bytes) -> None:
    if b":" not in line:
        message = "invalid ICAP chunk trailer"
        raise IcapProtocolError(message)
    field_name, field_value = line.split(b":", 1)
    if not field_name or any(ch not in _CHUNK_TCHARS for ch in field_name):
        message = "invalid ICAP chunk trailer field name"
        raise IcapProtocolError(message)
    field_name = field_name.lower()
    if field_name in _FORBIDDEN_ICAP_TRAILER_FIELDS:
        message = f"forbidden ICAP chunk trailer field: {field_name.decode('ascii')}"
        raise IcapProtocolError(message)
    if any(ch != 0x09 and (ch < 0x20 or ch >= 0x7F) for ch in field_value):
        message = "invalid ICAP chunk trailer value"
        raise IcapProtocolError(message)


def _read_chunk_trailers(sock: socket.socket, data: bytes) -> bytes:
    total = 0
    while True:
        try:
            data = _recv_until(
                sock, data, CRLF, max_bytes=MAX_ICAP_TRAILER_LINE_BYTES + len(CRLF)
            )
        except OSError as exc:
            message = "truncated ICAP chunk trailers"
            raise IcapProtocolError(message) from exc
        if CRLF not in data:
            if len(data) > MAX_ICAP_TRAILER_LINE_BYTES:
                message = (
                    "ICAP chunk trailer line exceeds "
                    f"{MAX_ICAP_TRAILER_LINE_BYTES} bytes"
                )
            else:
                message = "truncated ICAP chunk trailers"
            raise IcapProtocolError(message)
        if data.index(CRLF) > MAX_ICAP_TRAILER_LINE_BYTES:
            message = (
                f"ICAP chunk trailer line exceeds {MAX_ICAP_TRAILER_LINE_BYTES} bytes"
            )
            raise IcapProtocolError(message)
        line, data = data.split(CRLF, 1)
        total += len(line) + len(CRLF)
        if total > MAX_ICAP_TRAILERS_BYTES:
            message = f"ICAP chunk trailers exceed {MAX_ICAP_TRAILERS_BYTES} bytes"
            raise IcapProtocolError(message)
        if not line:
            return data
        _validate_chunk_trailer(line)


def _read_chunked_body(
    sock: socket.socket,
    data: bytes,
    *,
    max_bytes: int = 1024 * 1024 * 1024,
    preview: bool = False,
    preview_size: int | None = None,
) -> tuple[bytes, bytes]:
    body = bytearray()
    total = 0
    preview_pending = preview or preview_size is not None
    while True:
        try:
            data = _recv_until(sock, data, CRLF, max_bytes=8192)
        except OSError as exc:
            message = "truncated ICAP chunk-size line"
            raise IcapProtocolError(message) from exc
        if CRLF not in data:
            message = "truncated ICAP chunk-size line"
            raise IcapProtocolError(message)
        line, data = data.split(CRLF, 1)
        size, extensions = _parse_chunk_line(line)
        if size == 0:
            data = _read_chunk_trailers(sock, data)
            if preview_pending:
                if b"ieof" in extensions:
                    return bytes(body), data
                if preview_size is not None and total < preview_size:
                    message = "ICAP preview terminated before Preview header size"
                    raise IcapProtocolError(message)
                try:
                    sock.sendall(b"ICAP/1.0 100 Continue\r\n\r\n")
                except OSError as exc:
                    message = "failed to send ICAP preview continuation"
                    raise IcapProtocolError(message) from exc
                preview_pending = False
                continue
            return bytes(body), data
        total += size
        if total > max_bytes:
            message = f"ICAP chunked body exceeds {max_bytes} bytes"
            raise IcapProtocolError(message)
        if preview_pending and preview_size is not None and total > preview_size:
            message = "ICAP preview body exceeds Preview header"
            raise IcapProtocolError(message)
        try:
            data = _recv_more(sock, data, size + 2)
        except OSError as exc:
            message = "truncated ICAP chunk payload"
            raise IcapProtocolError(message) from exc
        if len(data) < size + 2:
            message = "truncated ICAP chunk payload"
            raise IcapProtocolError(message)
        if data[size : size + 2] != CRLF:
            message = "invalid ICAP chunk payload terminator"
            raise IcapProtocolError(message)
        body.extend(data[:size])
        data = data[size + 2 :]


def _drain_encapsulated_body(
    sock: socket.socket, header: bytes, remainder: bytes
) -> None:
    _start_line, headers = _split_headers(header)
    if "encapsulated" not in headers:
        message = "REQMOD request missing Encapsulated header"
        raise IcapProtocolError(message)
    offsets = _parse_encapsulated(headers["encapsulated"])
    _validate_reqmod_encapsulated_offsets(offsets)
    body_offset = offsets.get("req-body")
    preview_size = _parse_icap_preview_header(
        headers.get("preview"), max_bytes=1024 * 1024 * 1024
    )
    terminal_offset = body_offset if body_offset is not None else offsets.get("null-body")
    if terminal_offset is None:  # pragma: no cover - offset validation guards this
        message = "REQMOD request missing req-body/null-body"
        raise IcapProtocolError(message)
    try:
        data = _recv_more(sock, remainder, terminal_offset)
    except OSError as exc:
        message = "REQMOD encapsulated headers ended before declared offsets"
        raise IcapProtocolError(message) from exc
    if len(data) < terminal_offset:
        message = "REQMOD encapsulated headers ended before declared offsets"
        raise IcapProtocolError(message)
    encapsulated_header = data[:terminal_offset]
    _validate_reqmod_encapsulated_boundaries(encapsulated_header, offsets)
    request_header = encapsulated_header[:terminal_offset]
    if body_offset is None:
        if preview_size is not None:
            message = "ICAP Preview header requires req-body"
            raise IcapProtocolError(message)
        if offsets.get("req-hdr") is not None:
            _validate_reqmod_http_request_for_204(
                request_header, body_length=0, body_present=False
            )
        return
    body = data[body_offset:]
    decoded_body, _unused = _read_chunked_body(
        sock, body, preview_size=preview_size
    )
    if offsets.get("req-hdr") is not None:
        _validate_reqmod_http_request_for_204(
            request_header, body_length=len(decoded_body), body_present=True
        )


def _read_respmod_payload(
    sock: socket.socket, header: bytes, remainder: bytes
) -> tuple[bytes, bytes, bool, bytes | None]:
    _start_line, headers = _split_headers(header)
    offsets = _parse_encapsulated(headers.get("encapsulated", ""))
    _validate_respmod_encapsulated_offsets(offsets)
    body_offset = offsets.get("res-body")
    null_body_offset = offsets.get("null-body")
    preview_size = _parse_icap_preview_header(
        headers.get("preview"), max_bytes=1024 * 1024 * 1024
    )
    terminal_offset = body_offset if body_offset is not None else null_body_offset
    if terminal_offset is None:  # pragma: no cover - offset validation guards this
        message = "RESPMOD request missing res-body/null-body"
        raise IcapProtocolError(message)
    response_header_offset = offsets["res-hdr"]
    try:
        data = _recv_more(sock, remainder, terminal_offset)
    except OSError as exc:
        message = "RESPMOD encapsulated headers ended before declared offsets"
        raise IcapProtocolError(message) from exc
    if len(data) < terminal_offset:
        message = "RESPMOD encapsulated headers ended before declared offsets"
        raise IcapProtocolError(message)
    _validate_respmod_encapsulated_boundaries(data[:terminal_offset], offsets)
    request_method = None
    if offsets.get("req-hdr") is not None:
        request_method = _validate_respmod_http_request_header(
            data[:response_header_offset]
        )
    http_header = data[response_header_offset:terminal_offset]
    if body_offset is None:
        if preview_size is not None:
            message = "ICAP Preview header requires res-body"
            raise IcapProtocolError(message)
        return http_header, b"", True, request_method
    body, _unused = _read_chunked_body(
        sock, data[body_offset:], preview_size=preview_size
    )
    return http_header, body, False, request_method


def _icap_response(status: str, headers: dict[str, str] | None = None) -> bytes:
    lines = [f"ICAP/1.0 {status}"]
    response_headers = {"Connection": "close"}
    response_headers.update(headers or {})
    return (
        "\r\n".join(
            [*lines, *[f"{key}: {value}" for key, value in response_headers.items()]]
        )
        + "\r\n\r\n"
    ).encode("ascii", errors="replace")


def _http_header_lines(http_header: bytes) -> list[bytes]:
    header_block = http_header.split(HEADER_END, 1)[0]
    return header_block.split(CRLF) if header_block else []


def _validate_reqmod_http_request_start_line(raw_start_line: bytes) -> None:
    try:
        method, target, version = raw_start_line.split(b" ")
    except ValueError as exc:
        message = "malformed REQMOD encapsulated HTTP request start line"
        raise IcapProtocolError(message) from exc

    if not method or any(ch not in _HTTP_FIELD_NAME_TCHARS for ch in method):
        message = "invalid REQMOD encapsulated HTTP request method token"
        raise IcapProtocolError(message)
    if not target or any(ch < 0x21 or ch > 0x7E for ch in target):
        message = "invalid REQMOD encapsulated HTTP request target"
        raise IcapProtocolError(message)
    if version not in {b"HTTP/1.0", b"HTTP/1.1"}:
        message = "unsupported REQMOD encapsulated HTTP request version"
        raise IcapProtocolError(message)


def _validate_reqmod_http_field_line(line: bytes) -> tuple[bytes, bytes]:
    if line[:1] in _CHUNK_OWS:
        message = "obsolete folded REQMOD encapsulated HTTP header line"
        raise IcapProtocolError(message)
    if b":" not in line:
        message = "malformed REQMOD encapsulated HTTP header field line"
        raise IcapProtocolError(message)
    raw_name, raw_value = line.split(b":", 1)
    if not raw_name or any(ch not in _HTTP_FIELD_NAME_TCHARS for ch in raw_name):
        message = "invalid REQMOD encapsulated HTTP header field name"
        raise IcapProtocolError(message)
    if any(ch != 0x09 and (ch < 0x20 or ch == 0x7F) for ch in raw_value):
        message = "invalid REQMOD encapsulated HTTP header field value"
        raise IcapProtocolError(message)
    return raw_name.lower(), raw_value.strip(b" \t")


def _parse_reqmod_http_content_length(value: bytes) -> int:
    if (
        not value
        or len(value) > MAX_HTTP_CONTENT_LENGTH_DIGITS
        or any(ch < 0x30 or ch > 0x39 for ch in value)
    ):
        message = "invalid REQMOD encapsulated HTTP Content-Length header"
        raise IcapProtocolError(message)
    return int(value, 10)


def _reqmod_http_transfer_codings(value: bytes) -> list[bytes]:
    codings: list[bytes] = []
    for raw_coding in value.split(b","):
        coding = raw_coding.strip(b" \t").lower()
        if not coding or any(ch not in _HTTP_FIELD_NAME_TCHARS for ch in coding):
            message = (
                "unsupported REQMOD encapsulated HTTP Transfer-Encoding header"
            )
            raise IcapProtocolError(message)
        codings.append(coding)
    return codings


def _validate_reqmod_http_request_fields_for_204(
    lines: list[bytes], *, body_length: int, body_present: bool
) -> None:
    content_length: int | None = None
    transfer_encoding_seen = False
    transfer_codings: list[bytes] = []
    for line in lines[1:]:
        if not line:
            continue
        name, value = _validate_reqmod_http_field_line(line)
        if name == b"content-length":
            parsed_length = _parse_reqmod_http_content_length(value)
            if content_length is None:
                content_length = parsed_length
            elif content_length != parsed_length:
                message = "conflicting REQMOD encapsulated HTTP Content-Length headers"
                raise IcapProtocolError(message)
        elif name == b"transfer-encoding":
            if transfer_encoding_seen:
                message = "duplicate REQMOD encapsulated HTTP Transfer-Encoding header"
                raise IcapProtocolError(message)
            transfer_encoding_seen = True
            transfer_codings = _reqmod_http_transfer_codings(value)

    if transfer_codings:
        if content_length is not None:
            message = (
                "ambiguous REQMOD encapsulated HTTP Content-Length with "
                "Transfer-Encoding"
            )
            raise IcapProtocolError(message)
        if transfer_codings.count(b"chunked") > 1:
            message = "duplicate REQMOD encapsulated HTTP chunked transfer-coding"
            raise IcapProtocolError(message)
        if transfer_codings != [b"chunked"]:
            message = "unsupported REQMOD encapsulated HTTP Transfer-Encoding header"
            raise IcapProtocolError(message)
        if not body_present:
            message = "REQMOD encapsulated HTTP Transfer-Encoding requires req-body"
            raise IcapProtocolError(message)
    elif content_length is not None and content_length != body_length:
        message = "REQMOD encapsulated HTTP Content-Length mismatches decoded body"
        raise IcapProtocolError(message)


def _validate_reqmod_http_request_for_204(
    http_header: bytes, *, body_length: int, body_present: bool
) -> None:
    lines = _http_header_lines(http_header)
    raw_start_line = lines[0] if lines else b""
    _validate_reqmod_http_request_start_line(raw_start_line)
    _validate_reqmod_http_request_fields_for_204(
        lines, body_length=body_length, body_present=body_present
    )


def _validate_respmod_http_request_start_line(raw_start_line: bytes) -> bytes:
    try:
        method, target, version = raw_start_line.split(b" ")
    except ValueError as exc:
        message = "malformed RESPMOD encapsulated HTTP request start line"
        raise IcapProtocolError(message) from exc

    if not method or any(ch not in _HTTP_FIELD_NAME_TCHARS for ch in method):
        message = "invalid RESPMOD encapsulated HTTP request method token"
        raise IcapProtocolError(message)
    if not target or any(ch < 0x21 or ch > 0x7E for ch in target):
        message = "invalid RESPMOD encapsulated HTTP request target"
        raise IcapProtocolError(message)
    if version not in {b"HTTP/1.0", b"HTTP/1.1"}:
        message = "unsupported RESPMOD encapsulated HTTP request version"
        raise IcapProtocolError(message)
    return method


def _validate_respmod_http_request_field_line(line: bytes) -> tuple[bytes, bytes]:
    if line[:1] in _CHUNK_OWS:
        message = "obsolete folded RESPMOD encapsulated HTTP request header line"
        raise IcapProtocolError(message)
    if b":" not in line:
        message = "malformed RESPMOD encapsulated HTTP request header field line"
        raise IcapProtocolError(message)
    raw_name, raw_value = line.split(b":", 1)
    if not raw_name or any(ch not in _HTTP_FIELD_NAME_TCHARS for ch in raw_name):
        message = "invalid RESPMOD encapsulated HTTP request header field name"
        raise IcapProtocolError(message)
    if any(ch != 0x09 and (ch < 0x20 or ch == 0x7F) for ch in raw_value):
        message = "invalid RESPMOD encapsulated HTTP request header field value"
        raise IcapProtocolError(message)
    return raw_name.lower(), raw_value.strip(b" \t")


def _parse_respmod_http_request_content_length(value: bytes) -> int:
    if (
        not value
        or len(value) > MAX_HTTP_CONTENT_LENGTH_DIGITS
        or any(ch < 0x30 or ch > 0x39 for ch in value)
    ):
        message = "invalid RESPMOD encapsulated HTTP request Content-Length header"
        raise IcapProtocolError(message)
    return int(value, 10)


def _respmod_http_request_transfer_codings(value: bytes) -> list[bytes]:
    codings: list[bytes] = []
    for raw_coding in value.split(b","):
        coding = raw_coding.strip(b" \t").lower()
        if not coding or any(ch not in _HTTP_FIELD_NAME_TCHARS for ch in coding):
            message = (
                "invalid RESPMOD encapsulated HTTP request "
                "Transfer-Encoding header"
            )
            raise IcapProtocolError(message)
        codings.append(coding)
    return codings


def _validate_respmod_http_request_fields(lines: list[bytes]) -> None:
    content_length: int | None = None
    transfer_encoding_seen = False
    transfer_codings: list[bytes] = []
    for line in lines[1:]:
        if not line:
            continue
        name, value = _validate_respmod_http_request_field_line(line)
        if name == b"content-length":
            parsed_length = _parse_respmod_http_request_content_length(value)
            if content_length is None:
                content_length = parsed_length
            elif content_length != parsed_length:
                message = (
                    "conflicting RESPMOD encapsulated HTTP request "
                    "Content-Length headers"
                )
                raise IcapProtocolError(message)
        elif name == b"transfer-encoding":
            if transfer_encoding_seen:
                message = (
                    "duplicate RESPMOD encapsulated HTTP request "
                    "Transfer-Encoding header"
                )
                raise IcapProtocolError(message)
            transfer_encoding_seen = True
            transfer_codings = _respmod_http_request_transfer_codings(value)

    if transfer_codings:
        if content_length is not None:
            message = (
                "ambiguous RESPMOD encapsulated HTTP request Content-Length with "
                "Transfer-Encoding"
            )
            raise IcapProtocolError(message)
        if transfer_codings.count(b"chunked") > 1:
            message = (
                "duplicate RESPMOD encapsulated HTTP request chunked transfer-coding"
            )
            raise IcapProtocolError(message)
        if b"chunked" not in transfer_codings or transfer_codings[-1] != b"chunked":
            message = (
                "invalid RESPMOD encapsulated HTTP request "
                "Transfer-Encoding header"
            )
            raise IcapProtocolError(message)


def _validate_respmod_http_request_header(http_header: bytes) -> bytes:
    lines = _http_header_lines(http_header)
    raw_start_line = lines[0] if lines else b""
    method = _validate_respmod_http_request_start_line(raw_start_line)
    _validate_respmod_http_request_fields(lines)
    return method


def _validate_respmod_http_field_line(line: bytes) -> tuple[bytes, bytes]:
    if line[:1] in _CHUNK_OWS:
        message = "obsolete folded RESPMOD encapsulated HTTP header line"
        raise IcapProtocolError(message)
    if b":" not in line:
        message = "malformed RESPMOD encapsulated HTTP header field line"
        raise IcapProtocolError(message)
    raw_name, raw_value = line.split(b":", 1)
    if not raw_name or any(ch not in _HTTP_FIELD_NAME_TCHARS for ch in raw_name):
        message = "invalid RESPMOD encapsulated HTTP header field name"
        raise IcapProtocolError(message)
    if any(ch != 0x09 and (ch < 0x20 or ch == 0x7F) for ch in raw_value):
        message = "invalid RESPMOD encapsulated HTTP header field value"
        raise IcapProtocolError(message)
    return raw_name.lower(), raw_value.strip(b" \t")


def _parse_http_content_length(value: bytes) -> int:
    if (
        not value
        or len(value) > MAX_HTTP_CONTENT_LENGTH_DIGITS
        or any(ch < 0x30 or ch > 0x39 for ch in value)
    ):
        message = "invalid RESPMOD encapsulated HTTP Content-Length header"
        raise IcapProtocolError(message)
    return int(value, 10)


def _http_transfer_codings(value: bytes) -> list[bytes]:
    codings: list[bytes] = []
    for raw_coding in value.split(b","):
        coding = raw_coding.strip(b" \t").lower()
        if not coding or any(ch not in _HTTP_FIELD_NAME_TCHARS for ch in coding):
            message = "unsupported RESPMOD encapsulated HTTP Transfer-Encoding header"
            raise IcapProtocolError(message)
        codings.append(coding)
    return codings


def _validate_respmod_http_response_fields_for_replay(
    lines: list[bytes], *, body_length: int, body_present: bool
) -> tuple[int | None, list[bytes]]:
    content_length: int | None = None
    transfer_encoding_seen = False
    transfer_codings: list[bytes] = []
    for line in lines[1:]:
        if not line:
            continue
        name, value = _validate_respmod_http_field_line(line)
        if name == b"content-length":
            parsed_length = _parse_http_content_length(value)
            if content_length is None:
                content_length = parsed_length
            elif content_length != parsed_length:
                message = (
                    "conflicting RESPMOD encapsulated HTTP Content-Length headers"
                )
                raise IcapProtocolError(message)
        elif name == b"transfer-encoding":
            if transfer_encoding_seen:
                message = "duplicate RESPMOD encapsulated HTTP Transfer-Encoding header"
                raise IcapProtocolError(message)
            transfer_encoding_seen = True
            transfer_codings = _http_transfer_codings(value)

    if transfer_codings:
        if content_length is not None:
            message = (
                "ambiguous RESPMOD encapsulated HTTP Content-Length with "
                "Transfer-Encoding"
            )
            raise IcapProtocolError(message)
        if transfer_codings.count(b"chunked") > 1:
            message = "duplicate RESPMOD encapsulated HTTP chunked transfer-coding"
            raise IcapProtocolError(message)
        if transfer_codings != [b"chunked"]:
            message = "unsupported RESPMOD encapsulated HTTP Transfer-Encoding header"
            raise IcapProtocolError(message)
    elif body_present and content_length is not None and content_length != body_length:
        message = "RESPMOD encapsulated HTTP Content-Length mismatches decoded body"
        raise IcapProtocolError(message)
    return content_length, transfer_codings


def _validate_respmod_http_response_for_replay(
    http_header: bytes, *, body_length: int, body_present: bool
) -> tuple[int, int | None, list[bytes]]:
    lines = _http_header_lines(http_header)
    raw_start_line = lines[0] if lines else b""
    if raw_start_line.startswith((b"HTTP/1.0 ", b"HTTP/1.1 ")):
        remainder = raw_start_line[len(b"HTTP/1.1 ") :]
    else:
        message = "invalid RESPMOD encapsulated HTTP response start line"
        raise IcapProtocolError(message)

    if len(remainder) < 4 or remainder[3:4] != b" ":
        message = "malformed RESPMOD encapsulated HTTP response start line"
        raise IcapProtocolError(message)
    raw_status = remainder[:3]
    if any(ch < 0x30 or ch > 0x39 for ch in raw_status):
        message = "invalid RESPMOD encapsulated HTTP response status"
        raise IcapProtocolError(message)
    status = int(raw_status, 10)
    if status < 100 or status > 599:
        message = "invalid RESPMOD encapsulated HTTP response status"
        raise IcapProtocolError(message)

    reason = remainder[4:]
    if (reason[:1] and reason[0] in _CHUNK_OWS) or any(
        ch < 0x20 or ch >= 0x7F for ch in reason
    ):
        message = "invalid RESPMOD encapsulated HTTP response reason phrase"
        raise IcapProtocolError(message)

    if body_length and (100 <= status < 200 or status in {204, 304}):
        message = "RESPMOD encapsulated HTTP response status forbids a body"
        raise IcapProtocolError(message)

    content_length, transfer_codings = _validate_respmod_http_response_fields_for_replay(
        lines, body_length=body_length, body_present=body_present
    )
    return status, content_length, transfer_codings


def _validate_respmod_null_body_framing_for_replay(
    http_header: bytes, *, request_method: bytes | None
) -> None:
    status, content_length, transfer_codings = _validate_respmod_http_response_for_replay(
        http_header, body_length=0, body_present=False
    )
    if request_method is None or request_method == b"HEAD":
        return
    if 100 <= status < 200 or status in {204, 304}:
        return
    if transfer_codings or (content_length is not None and content_length > 0):
        message = "RESPMOD null-body response framing requires HEAD request metadata"
        raise IcapProtocolError(message)


def _http_header_for_body_replay(http_header: bytes, body_length: int) -> bytes:
    lines = _http_header_lines(http_header)
    if not lines or not lines[0].startswith(b"HTTP/"):
        return http_header
    replay_lines = [lines[0]]
    for line in lines[1:]:
        if b":" not in line:
            continue
        name = line.split(b":", 1)[0].strip().lower()
        if name in {b"content-length", b"transfer-encoding"}:
            continue
        replay_lines.append(line)
    replay_lines.append(f"Content-Length: {body_length}".encode("ascii"))
    return CRLF.join(replay_lines) + HEADER_END


def _encode_icap_body_chunk(body: bytes) -> bytes:
    return f"{len(body):X}\r\n".encode("ascii") + body + CRLF + b"0\r\n\r\n"


def _clean_respmod_response(http_header: bytes, body: bytes, istag: str) -> bytes:
    _validate_respmod_http_response_for_replay(
        http_header, body_length=len(body), body_present=True
    )
    http_header = _http_header_for_body_replay(http_header, len(body))
    return _icap_response(
        "200 OK",
        {"ISTag": istag, "Encapsulated": f"res-hdr=0, res-body={len(http_header)}"},
    ) + http_header + _encode_icap_body_chunk(body)


def _clean_respmod_no_body_response(
    *, allow_204: bool, http_header: bytes, istag: str, request_method: bytes | None
) -> bytes:
    _validate_respmod_null_body_framing_for_replay(
        http_header, request_method=request_method
    )
    if allow_204:
        return _icap_response("204 No Content", {"ISTag": istag})
    if http_header and not http_header.endswith(HEADER_END):
        http_header += HEADER_END
    return _icap_response(
        "200 OK",
        {"ISTag": istag, "Encapsulated": f"res-hdr=0, null-body={len(http_header)}"},
    ) + http_header


def _error_response(message: str, istag: str) -> bytes:
    payload = ("ClamAV fallback ICAP protocol error.\n" + message + "\n").encode(
        "utf-8"
    )
    http_header = (
        b"HTTP/1.1 502 Bad Gateway\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        + f"Content-Length: {len(payload)}\r\n".encode("ascii")
        + b"Connection: close\r\n\r\n"
    )
    return _icap_response(
        "200 OK",
        {"ISTag": istag, "Encapsulated": f"res-hdr=0, res-body={len(http_header)}"},
    ) + http_header + _encode_icap_body_chunk(payload)


class _FailOpenAvHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(2.0)
        fail_open = bool(getattr(self.server, "fail_open", True))
        istag = FALLBACK_OPEN_ISTAG if fail_open else FALLBACK_CLOSED_ISTAG
        try:
            header, remainder = _read_icap_outer_header(self.request)
            method, _service_uri, _version = _parse_icap_start_line(header)
            if method == "OPTIONS":
                headers = {
                    "Methods": "REQMOD, RESPMOD",
                    "Service": "ClamAV placeholder; backend unavailable",
                    "ISTag": istag,
                    "Preview": "0",
                    "Options-TTL": "30",
                    "Encapsulated": "null-body=0",
                }
                if fail_open:
                    headers["Allow"] = "204"
                response = _icap_response(
                    "200 OK",
                    headers,
                )
            elif method in {"REQMOD", "RESPMOD"}:
                if fail_open:
                    try:
                        if method == "RESPMOD":
                            _start_line, headers = _split_headers(header)
                            allow_204 = _respmod_allow_204_eligible(
                                headers.get("allow")
                            )
                            http_header, body, null_body, request_method = (
                                _read_respmod_payload(self.request, header, remainder)
                            )
                            if null_body:
                                response = _clean_respmod_no_body_response(
                                    allow_204=allow_204,
                                    http_header=http_header,
                                    istag=istag,
                                    request_method=request_method,
                                )
                            else:
                                response = _clean_respmod_response(
                                    http_header, body, istag
                                )
                        else:
                            _drain_encapsulated_body(self.request, header, remainder)
                            response = _icap_response(
                                "204 No Content",
                                {"ISTag": istag, "Encapsulated": "null-body=0"},
                            )
                    except IcapProtocolError as exc:
                        response = _error_response(str(exc), istag)
                else:
                    response = _icap_response(
                        "500 Service Unavailable",
                        {"ISTag": istag, "Encapsulated": "null-body=0"},
                    )
            else:
                response = _icap_response(
                    "405 Method Not Allowed",
                    {
                        "Allow": "REQMOD, RESPMOD, OPTIONS",
                        "Encapsulated": "null-body=0",
                    },
                )
        except IcapProtocolError as exc:
            response = _error_response(str(exc), istag)
        self.request.sendall(response)


class _FailOpenAvServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    fail_open = True


def run_unavailable_placeholder(
    conf_path: str,
    *,
    host: str,
    port: int,
    fail_open: bool,
) -> None:
    listen_host, listen_port = _conf_listen_address(conf_path)
    sys.stderr.write(
        f"ClamAV backend {host}:{port} is unavailable; "
        f"serving {'fail-open' if fail_open else 'fail-closed'} ICAP placeholder "
        f"on {listen_host}:{listen_port}\n"
    )
    with _FailOpenAvServer((listen_host, listen_port), _FailOpenAvHandler) as server:
        server.fail_open = fail_open
        server.serve_forever()


def run_fail_open_placeholder(conf_path: str, *, host: str, port: int) -> None:
    run_unavailable_placeholder(conf_path, host=host, port=port, fail_open=True)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        sys.stderr.write("usage: cicap_av_runner.py <c-icap-av.conf>\n")
        return 64

    conf_path = argv[1]
    host = (os.environ.get("CLAMD_HOST") or "127.0.0.1").strip() or "127.0.0.1"
    try:
        port = int((os.environ.get("CLAMD_PORT") or "3310").strip())
    except ValueError:
        port = 3310
    required = env_enabled(os.environ.get("CLAMAV_REQUIRED")) or env_enabled(
        os.environ.get("FILE_SECURITY_AV_REQUIRED")
    )

    if clamd_ready(host, port):
        os.execv(  # noqa: S606 - replace runner with c-icap in the container.
            "/usr/bin/c-icap",
            ["/usr/bin/c-icap", "-N", "-f", conf_path],
        )

    run_unavailable_placeholder(
        conf_path,
        host=host,
        port=port,
        fail_open=not required,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
