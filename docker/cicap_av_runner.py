#!/usr/bin/env python3
"""Run optional/required c-icap AV without spawning probe helper processes."""

from __future__ import annotations

import os
import re
import socket
import socketserver
import sys
from pathlib import Path

TRUE_VALUES = {"1", "true", "yes", "on", "required", "strict"}
CRLF = b"\r\n"
HEADER_END = CRLF + CRLF
DEFAULT_MAX_HEADER_BYTES = 64 * 1024
MAX_ENCAPSULATED_OFFSET_DIGITS = 20
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


class IcapProtocolError(Exception):
    pass


def env_enabled(value: str | None) -> bool:
    return (value or "").strip().lower() in TRUE_VALUES


def clamd_ready(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(b"PING\n")
            return sock.recv(16).startswith(b"PONG")
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
    return "127.0.0.1", int(os.environ.get("CICAP_AV_PORT", "14001") or "14001")


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
        data = _recv_until(
            sock, data, CRLF, max_bytes=MAX_ICAP_TRAILER_LINE_BYTES + len(CRLF)
        )
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
) -> tuple[bytes, bytes]:
    body = bytearray()
    total = 0
    preview_pending = preview
    while True:
        data = _recv_until(sock, data, CRLF, max_bytes=8192)
        if CRLF not in data:
            message = "truncated ICAP chunk-size line"
            raise IcapProtocolError(message)
        line, data = data.split(CRLF, 1)
        size, extensions = _parse_chunk_line(line)
        if size == 0:
            data = _read_chunk_trailers(sock, data)
            if preview_pending and b"ieof" not in extensions:
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
        data = _recv_more(sock, data, size + 2)
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
    terminal_offset = body_offset if body_offset is not None else offsets.get("null-body")
    if terminal_offset is None:  # pragma: no cover - offset validation guards this
        message = "REQMOD request missing req-body/null-body"
        raise IcapProtocolError(message)
    data = _recv_more(sock, remainder, terminal_offset)
    if len(data) < terminal_offset:
        message = "REQMOD encapsulated headers ended before declared offsets"
        raise IcapProtocolError(message)
    _validate_reqmod_encapsulated_boundaries(data[:terminal_offset], offsets)
    if body_offset is None:
        return
    body = data[body_offset:]
    _drain_chunked_body(sock, body, preview="preview" in headers)


def _read_respmod_payload(
    sock: socket.socket, header: bytes, remainder: bytes
) -> tuple[bytes, bytes, bool]:
    _start_line, headers = _split_headers(header)
    offsets = _parse_encapsulated(headers.get("encapsulated", ""))
    _validate_respmod_encapsulated_offsets(offsets)
    body_offset = offsets.get("res-body")
    null_body_offset = offsets.get("null-body")
    terminal_offset = body_offset if body_offset is not None else null_body_offset
    if terminal_offset is None:  # pragma: no cover - offset validation guards this
        message = "RESPMOD request missing res-body/null-body"
        raise IcapProtocolError(message)
    response_header_offset = offsets["res-hdr"]
    data = _recv_more(sock, remainder, terminal_offset)
    if len(data) < terminal_offset:
        message = "RESPMOD encapsulated headers ended before declared offsets"
        raise IcapProtocolError(message)
    _validate_respmod_encapsulated_boundaries(data[:terminal_offset], offsets)
    http_header = data[response_header_offset:terminal_offset]
    if body_offset is None:
        return http_header, b"", True
    body, _unused = _read_chunked_body(
        sock, data[body_offset:], preview="preview" in headers
    )
    return http_header, body, False


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
    http_header = _http_header_for_body_replay(http_header, len(body))
    return _icap_response(
        "200 OK",
        {"ISTag": istag, "Encapsulated": f"res-hdr=0, res-body={len(http_header)}"},
    ) + http_header + _encode_icap_body_chunk(body)


def _clean_respmod_no_body_response(
    *, allow_204: bool, http_header: bytes, istag: str
) -> bytes:
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
            first = (
                header.split(CRLF, 1)[0]
                .split(b"\n", 1)[0]
                .decode("ascii", errors="replace")
            )
            method = first.split(" ", 1)[0].upper() if first else ""
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
                            allow_204 = "204" in {
                                part.strip()
                                for part in headers.get("allow", "").split(",")
                            }
                            http_header, body, null_body = _read_respmod_payload(
                                self.request, header, remainder
                            )
                            if null_body:
                                response = _clean_respmod_no_body_response(
                                    allow_204=allow_204,
                                    http_header=http_header,
                                    istag=istag,
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
