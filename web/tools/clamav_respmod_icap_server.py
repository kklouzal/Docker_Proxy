"""Minimal RESPMOD ICAP helper that streams response bodies to clamd.

c-icap's virus_scan/clamd_mod path can hand proxy-local temporary file names to
clamd. That is unsafe when clamd is on another host because the daemon cannot
read the proxy container's filesystem. This helper keeps the Squid-facing ICAP
contract local, but sends response bytes to clamd with the INSTREAM TCP protocol.
"""

from __future__ import annotations

import argparse
import contextlib
import logging
import os
import re
import socket
import socketserver
import struct
import threading
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, BinaryIO, Self

if TYPE_CHECKING:
    from collections.abc import Callable

CRLF = b"\r\n"
HEADER_END = CRLF + CRLF
DEFAULT_MAX_SCAN_BYTES = 256 * 1024 * 1024
DEFAULT_CHUNK_SIZE = 1024 * 1024
DEFAULT_CLIENT_TIMEOUT = 2.0
DEFAULT_MAX_CONNECTIONS = 64
DEFAULT_MAX_SCANS = 16
DEFAULT_MAX_HEADER_BYTES = 64 * 1024
DEFAULT_SQUID_204_BACKUP_LIMIT = 64 * 1024
_ICAP_CHUNK_SIZE_RE = re.compile(r"[0-9A-Fa-f]{1,16}")
_ENCAPSULATED_OFFSET_RE = re.compile(r"[0-9]+")
ISTAG = '"clamav-respmod-instream-1"'
CLAMD_INSTREAM_COMMAND = b"zINSTREAM\0"
CLAMD_REPLY_TERMINATOR = b"\0"
ICAP_METHOD_TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9!#$%&'*+.^_`|~-]*\Z")


@dataclass(frozen=True)
class ClamdResult:
    clean: bool
    infected: bool = False
    signature: str | None = None
    detail: str = ""


class IcapProtocolError(Exception):
    pass


class BodyTooLargeError(Exception):
    pass


class ScanFailedAfterBodyError(RuntimeError):
    def __init__(self, message: str, *, body: bytes) -> None:
        super().__init__(message)
        self.body = body


logger = logging.getLogger("clamav-respmod")


class _BoundedWarning:
    def __init__(self, *, interval_seconds: float = 5.0) -> None:
        self.interval_seconds = interval_seconds
        self._lock = threading.Lock()
        self._next_log_at = 0.0
        self._suppressed = 0

    def warning(self, message: str, *args) -> None:
        now = time.monotonic()
        with self._lock:
            if now < self._next_log_at:
                self._suppressed += 1
                return
            suppressed = self._suppressed
            self._suppressed = 0
            self._next_log_at = now + self.interval_seconds
        if suppressed:
            try:
                display = message % args
            except Exception:
                display = message
            logger.warning("%s (suppressed %d similar events)", display, suppressed)
        else:
            logger.warning(message, *args)


scan_error_warning = _BoundedWarning()


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _split_headers(header_bytes: bytes) -> tuple[str, dict[str, str]]:
    try:
        text = header_bytes.decode("iso-8859-1")
    except UnicodeDecodeError as exc:  # pragma: no cover - iso-8859-1 is total
        message = "invalid ICAP header bytes"
        raise IcapProtocolError(message) from exc
    lines = text.split("\r\n")
    if not lines or not lines[0]:
        message = "empty ICAP request"
        raise IcapProtocolError(message)
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        name, value = line.split(":", 1)
        header_name = name.strip().lower()
        if header_name in {"encapsulated", "preview"} and header_name in headers:
            display_name = "Encapsulated" if header_name == "encapsulated" else "Preview"
            message = f"duplicate ICAP {display_name} header"
            raise IcapProtocolError(message)
        headers[header_name] = value.strip()
    return lines[0], headers


def _parse_start_line(start_line: str) -> str:
    parts = start_line.split(" ")
    if len(parts) != 3 or any(not part for part in parts):
        message = f"malformed ICAP start line: {start_line!r}"
        raise IcapProtocolError(message)
    method, request_target, version = parts
    if not ICAP_METHOD_TOKEN_RE.fullmatch(method):
        message = f"malformed ICAP method token: {method!r}"
        raise IcapProtocolError(message)
    if any(char.isspace() for char in request_target):  # pragma: no cover - split guard
        message = f"malformed ICAP request target: {request_target!r}"
        raise IcapProtocolError(message)
    if version != "ICAP/1.0":
        message = f"unsupported ICAP version: {version!r}"
        raise IcapProtocolError(message)
    return method.upper()


def _parse_encapsulated(value: str) -> dict[str, int]:
    supported_names = {"req-hdr", "res-hdr", "res-body", "null-body"}
    offsets: dict[str, int] = {}
    for raw_item in value.split(","):
        item = raw_item.lstrip()
        if not item or "=" not in item:
            continue
        name, raw_offset = item.split("=", 1)
        name = name.strip().lower()
        if name not in supported_names:
            message = f"unknown Encapsulated section token: {name}"
            raise IcapProtocolError(message)
        if name in offsets:
            message = f"duplicate Encapsulated section name: {name}"
            raise IcapProtocolError(message)
        if not _ENCAPSULATED_OFFSET_RE.fullmatch(raw_offset):
            message = f"invalid Encapsulated offset: {item}"
            raise IcapProtocolError(message)
        significant_offset = raw_offset.lstrip("0") or "0"
        if len(significant_offset) > 16:
            message = f"invalid Encapsulated offset: {item}"
            raise IcapProtocolError(message)
        offset = int(significant_offset)
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
    terminal_offsets = [
        offset
        for offset in (body_offset, null_body_offset)
        if offset is not None
    ]

    if response_header_offset is None:
        message = "RESPMOD request missing res-hdr"
        raise IcapProtocolError(message)
    if body_offset is not None and null_body_offset is not None:
        message = "RESPMOD request has both res-body and null-body"
        raise IcapProtocolError(message)
    if not terminal_offsets:
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

    terminal_offset = terminal_offsets[0]
    if terminal_offset > max_header_bytes:
        message = f"RESPMOD encapsulated headers exceed {max_header_bytes} bytes"
        raise IcapProtocolError(message)
    if terminal_offset <= response_header_offset:
        message = "invalid RESPMOD encapsulated response offsets"
        raise IcapProtocolError(message)


def _validate_respmod_encapsulated_header_boundaries(
    encapsulated_headers: bytes, offsets: dict[str, int]
) -> None:
    """Reject RESPMOD offsets that split or overrun HTTP header sections."""
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


def _parse_preview_size(
    headers: dict[str, str],
    *,
    has_body: bool,
    max_bytes: int = DEFAULT_MAX_SCAN_BYTES,
) -> int | None:
    value = headers.get("preview")
    if value is None:
        return None
    if not has_body:
        message = "ICAP Preview header requires res-body"
        raise IcapProtocolError(message)
    if not re.fullmatch(r"[0-9]+", value):
        message = f"invalid ICAP Preview header: {value!r}"
        raise IcapProtocolError(message)
    significant_value = value.lstrip("0") or "0"
    max_value = str(max_bytes)
    if len(significant_value) > len(max_value) or (
        len(significant_value) == len(max_value) and significant_value > max_value
    ):
        message = f"ICAP Preview header exceeds {max_bytes} bytes"
        raise IcapProtocolError(message)
    return int(significant_value)


def _read_some(stream: BinaryIO, size: int) -> bytes:
    # StreamRequestHandler wraps sockets in BufferedReader. read(size) can wait
    # for the full size or EOF on an open ICAP keep-alive connection, which
    # turns a complete short OPTIONS request into a listener-visible hang.
    # read1(size) performs one socket read and returns the available header data.
    read1 = getattr(stream, "read1", None)
    if read1 is not None:
        return read1(size)
    return stream.read(size)


def _read_until(
    stream: BinaryIO,
    delimiter: bytes,
    initial: bytes = b"",
    *,
    max_bytes: int = DEFAULT_MAX_HEADER_BYTES,
) -> tuple[bytes, bytes]:
    data = bytearray(initial)
    while True:
        idx = data.find(delimiter)
        if idx >= 0:
            end = idx + len(delimiter)
            return bytes(data[:end]), bytes(data[end:])
        if len(data) >= max_bytes:
            message = f"ICAP header/line exceeds {max_bytes} bytes"
            raise IcapProtocolError(message)
        chunk = _read_some(stream, min(4096, max_bytes - len(data)))
        if not chunk:
            message = "unexpected EOF"
            raise IcapProtocolError(message)
        data.extend(chunk)


def _read_exact(
    stream: BinaryIO, size: int, initial: bytes = b""
) -> tuple[bytes, bytes]:
    if size < 0:
        message = "negative read size"
        raise IcapProtocolError(message)
    data = bytearray(initial)
    while len(data) < size:
        chunk = stream.read(size - len(data))
        if not chunk:
            message = "unexpected EOF"
            raise IcapProtocolError(message)
        data.extend(chunk)
    return bytes(data[:size]), bytes(data[size:])


def _read_chunk_header(stream: BinaryIO, initial: bytes = b"") -> tuple[str, bytes]:
    line, remainder = _read_until(stream, CRLF, initial)
    return line[:-2].decode("ascii", errors="replace"), remainder


def _parse_icap_chunk_size(line: str) -> int:
    size_token = line.split(";", 1)[0]
    if not _ICAP_CHUNK_SIZE_RE.fullmatch(size_token):
        message = f"invalid ICAP chunk size: {line!r}"
        raise IcapProtocolError(message)
    return int(size_token, 16)


def _drain_chunk_trailers(stream: BinaryIO, initial: bytes = b"") -> bytes:
    remainder = initial
    while True:
        line, remainder = _read_until(stream, CRLF, remainder)
        if line == CRLF:
            return remainder
        trailer = line[:-2]
        if b":" not in trailer or not trailer.split(b":", 1)[0].strip():
            message = "malformed ICAP chunk trailer"
            raise IcapProtocolError(message)


def _chunk_has_ieof_extension(line: str) -> bool:
    for extension in line.split(";")[1:]:
        name = extension.split("=", 1)[0].strip().lower()
        if name == "ieof":
            return True
    return False


def read_icap_chunked_body(
    stream: BinaryIO,
    initial: bytes = b"",
    *,
    max_bytes: int = DEFAULT_MAX_SCAN_BYTES,
    preview: bool = False,
    preview_size: int | None = None,
    continue_callback=None,
    chunk_callback: Callable[[bytes], None] | None = None,
    buffer_body: bool = True,
) -> tuple[bytes, bytes]:
    """Read an ICAP chunked body, including Squid preview continuation.

    Returns (body, remainder). If a preview terminator without ``ieof`` is seen,
    ``continue_callback`` is called before reading the rest of the chunks.
    If ``chunk_callback`` is provided, each decoded body chunk is passed through
    as it is read so clamd INSTREAM scanning can proceed without waiting for the
    full response body. Set ``buffer_body`` to false when the caller can return
    ICAP 204 for clean objects and does not need to replay the original body.
    """
    body = bytearray()
    total_size = 0
    remainder = initial
    preview_terminator_seen = False
    post_preview_chunk_seen = False
    while True:
        line, remainder = _read_chunk_header(stream, remainder)
        size = _parse_icap_chunk_size(line)
        has_ieof = _chunk_has_ieof_extension(line)
        if has_ieof and size != 0:
            message = "invalid ICAP ieof chunk extension on nonzero chunk"
            raise IcapProtocolError(message)
        if size == 0:
            remainder = _drain_chunk_trailers(stream, remainder)
            if preview and not preview_terminator_seen and not has_ieof:
                if preview_size is not None and total_size < preview_size:
                    message = "ICAP preview terminated before Preview header size"
                    raise IcapProtocolError(message)
                preview_terminator_seen = True
                if continue_callback is not None:
                    continue_callback()
                continue
            if preview and preview_terminator_seen and not post_preview_chunk_seen:
                message = "duplicate ICAP preview terminator without continuation"
                raise IcapProtocolError(message)
            return bytes(body), remainder
        if size > max_bytes - total_size:
            message = f"ICAP body exceeds {max_bytes} bytes"
            raise BodyTooLargeError(message)
        chunk, remainder = _read_exact(stream, size + 2, remainder)
        if chunk[-2:] != CRLF:
            message = "ICAP chunk missing CRLF terminator"
            raise IcapProtocolError(message)
        decoded = chunk[:-2]
        total_size += len(decoded)
        if total_size > max_bytes:
            message = f"ICAP body exceeds {max_bytes} bytes"
            raise BodyTooLargeError(message)
        if preview_size is not None and not preview_terminator_seen:
            if total_size > preview_size:
                message = "ICAP preview body exceeds Preview header"
                raise IcapProtocolError(message)
        if chunk_callback is not None:
            chunk_callback(decoded)
        if buffer_body:
            body.extend(decoded)
        if preview_terminator_seen:
            post_preview_chunk_seen = True


def _parse_clamd_response(response: str) -> ClamdResult:
    if response.endswith("OK"):
        return ClamdResult(clean=True, detail=response)
    match = re.search(r":\s*(?P<signature>.+?)\s+FOUND\b", response)
    if match:
        return ClamdResult(
            clean=False,
            infected=True,
            signature=match.group("signature"),
            detail=response,
        )
    message = f"clamd returned an error response: {response or '<empty>'}"
    raise RuntimeError(message)


class ClamdInstreamSession:
    """Incremental clamd INSTREAM sender.

    The caller owns ICAP response buffering/replay decisions; this class only
    streams decoded body bytes to clamd using INSTREAM chunk frames and parses
    the final verdict.
    """

    def __init__(
        self,
        *,
        host: str,
        port: int,
        timeout: float = 30.0,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        concurrency_gate: threading.BoundedSemaphore | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.chunk_size = chunk_size
        self.concurrency_gate = concurrency_gate
        self._sock = None
        self._gate_acquired = False

    def __enter__(self) -> Self:
        if self.concurrency_gate is not None:
            if not self.concurrency_gate.acquire(blocking=False):
                message = "clamd INSTREAM scan capacity exhausted"
                raise RuntimeError(message)
            self._gate_acquired = True
        try:
            self._sock = socket.create_connection(
                (self.host, self.port), timeout=self.timeout
            )
            self._sock.settimeout(self.timeout)
            self._sock.sendall(CLAMD_INSTREAM_COMMAND)
        except OSError as exc:
            if self._gate_acquired and self.concurrency_gate is not None:
                self.concurrency_gate.release()
                self._gate_acquired = False
            message = f"clamd INSTREAM scan failed: {exc}"
            raise RuntimeError(message) from exc
        return self

    def __exit__(self, *_exc) -> None:
        if self._sock is not None:
            self._sock.close()
            self._sock = None
        if self._gate_acquired and self.concurrency_gate is not None:
            self.concurrency_gate.release()
            self._gate_acquired = False

    def send_chunk(self, data: bytes) -> None:
        if not data:
            return
        if self._sock is None:
            message = "clamd INSTREAM session is not open"
            raise RuntimeError(message)
        try:
            for offset in range(0, len(data), self.chunk_size):
                chunk = data[offset : offset + self.chunk_size]
                self._sock.sendall(struct.pack("!I", len(chunk)))
                self._sock.sendall(chunk)
        except OSError as exc:
            message = f"clamd INSTREAM scan failed: {exc}"
            raise RuntimeError(message) from exc

    def finish(self) -> ClamdResult:
        if self._sock is None:
            message = "clamd INSTREAM session is not open"
            raise RuntimeError(message)
        try:
            self._sock.sendall(struct.pack("!I", 0))
            response_bytes = bytearray()
            while True:
                chunk = self._sock.recv(4096)
                if not chunk:
                    break
                response_bytes.extend(chunk)
                if CLAMD_REPLY_TERMINATOR in chunk or b"\n" in chunk:
                    break
            response = (
                bytes(response_bytes)
                .split(CLAMD_REPLY_TERMINATOR, 1)[0]
                .split(b"\n", 1)[0]
                .decode("utf-8", errors="replace")
                .strip()
            )
        except OSError as exc:
            message = f"clamd INSTREAM scan failed: {exc}"
            raise RuntimeError(message) from exc
        return _parse_clamd_response(response)


def scan_stream_with_clamd(
    body: bytes,
    *,
    host: str,
    port: int,
    timeout: float = 30.0,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> ClamdResult:
    """Send body bytes to clamd using INSTREAM and parse the scan result."""
    with ClamdInstreamSession(
        host=host, port=port, timeout=timeout, chunk_size=chunk_size
    ) as session:
        session.send_chunk(body)
        return session.finish()


def _icap_response(
    status: str,
    headers: dict[str, str] | None = None,
    body: bytes = b"",
    *,
    close: bool = True,
) -> bytes:
    lines = [f"ICAP/1.0 {status}"]
    response_headers = {"Connection": "close"} if close else {}
    response_headers.update(headers or {})
    for name, value in response_headers.items():
        lines.append(f"{name}: {value}")
    return "\r\n".join(lines).encode("ascii") + HEADER_END + body


def options_response() -> bytes:
    return _icap_response(
        "200 OK",
        {
            "Methods": "RESPMOD",
            "Service": "ClamAV RESPMOD INSTREAM scanner",
            "ISTag": ISTAG,
            "Options-TTL": "3600",
            "Max-Connections": "64",
            "Allow": "204",
            "Preview": "0",
            "Transfer-Preview": "*",
            "Encapsulated": "null-body=0",
        },
    )


def clean_response(
    *,
    allow_204: bool,
    http_header: bytes,
    body: bytes,
) -> bytes:
    # Be conservative for RESPMOD clean verdicts: replaying the already-drained
    # response body avoids Squid's late-204 backup edge cases across Preview,
    # unknown/chunked framing, and persistent ICAP connection churn.  Fail-open
    # paths still use 204 only when the body is complete and known backup-safe.
    encoded = _encode_icap_body_chunk(body)
    http_header = _http_header_for_body_replay(http_header, len(body))
    return _icap_response(
        "200 OK",
        {"ISTag": ISTAG, "Encapsulated": f"res-hdr=0, res-body={len(http_header)}"},
        http_header + encoded,
    )


def clean_no_body_response(*, allow_204: bool, http_header: bytes) -> bytes:
    """Return a clean RESPMOD verdict for responses without an HTTP body."""
    if allow_204:
        return _icap_response("204 No Content", {"ISTag": ISTAG})
    if http_header and not http_header.endswith(HEADER_END):
        http_header += HEADER_END
    return _icap_response(
        "200 OK",
        {"ISTag": ISTAG, "Encapsulated": f"res-hdr=0, null-body={len(http_header)}"},
        http_header,
    )


def _http_header_lines(http_header: bytes) -> list[bytes]:
    header_block = http_header.split(HEADER_END, 1)[0]
    return header_block.split(CRLF) if header_block else []


def _http_response_allows_squid_204_backup(http_header: bytes) -> bool:
    """Return true only when Squid can safely use an ICAP 204 response.

    Squid can only honor a late RESPMOD 204 when it has backed up the original
    response.  Unknown-length/chunked responses (and larger known-length ones)
    can be streamed to the ICAP service without a usable backup.  Returning 204
    for those responses makes Squid report ICAP_RESPMOD_EARLY/ERR_ICAP_FAILURE
    even though the scanner verdict is clean.  For those cases, replay the
    scanned response body in a normal ICAP 200 response instead.
    """
    lines = _http_header_lines(http_header)
    if not lines or not lines[0].startswith(b"HTTP/"):
        return False
    content_lengths: list[int] = []
    for line in lines[1:]:
        if b":" not in line:
            continue
        name, value = line.split(b":", 1)
        header_name = name.strip().lower()
        if header_name == b"transfer-encoding":
            if value.strip().lower() not in {b"", b"identity"}:
                return False
        elif header_name == b"content-length":
            try:
                length = int(value.strip())
            except ValueError:
                return False
            if length < 0:
                return False
            content_lengths.append(length)
    if not content_lengths:
        return False
    if len(set(content_lengths)) != 1:
        return False
    return content_lengths[0] <= DEFAULT_SQUID_204_BACKUP_LIMIT


def _http_header_for_body_replay(http_header: bytes, body_length: int) -> bytes:
    """Normalize HTTP framing when replaying a clean response body to Squid."""
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


def blocked_response(signature: str | None) -> bytes:
    reason = signature or "malware"
    payload = (
        f"Blocked by Docker_Proxy ClamAV response scanner.\nDetection: {reason}\n"
    ).encode()
    http_header = (
        b"HTTP/1.1 403 Forbidden\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        + f"Content-Length: {len(payload)}\r\n".encode("ascii")
        + b"Connection: close\r\n\r\n"
    )
    return _icap_response(
        "200 OK",
        {"ISTag": ISTAG, "Encapsulated": f"res-hdr=0, res-body={len(http_header)}"},
        http_header + _encode_icap_body_chunk(payload),
    )


def error_response(message: str) -> bytes:
    payload = ("ClamAV response scan failed.\n" + message + "\n").encode("utf-8")
    http_header = (
        b"HTTP/1.1 502 Bad Gateway\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        + f"Content-Length: {len(payload)}\r\n".encode("ascii")
        + b"Connection: close\r\n\r\n"
    )
    return _icap_response(
        "200 OK",
        {"ISTag": ISTAG, "Encapsulated": f"res-hdr=0, res-body={len(http_header)}"},
        http_header + _encode_icap_body_chunk(payload),
    )


def _encode_icap_body_chunk(body: bytes) -> bytes:
    return f"{len(body):X}\r\n".encode("ascii") + body + CRLF + b"0\r\n\r\n"


class ClamAvRespmodHandler(socketserver.StreamRequestHandler):
    server: ClamAvRespmodServer

    def setup(self) -> None:
        self.request.settimeout(self.server.client_timeout)
        super().setup()

    def _send_100_continue(self) -> None:
        self.wfile.write(b"ICAP/1.0 100 Continue\r\n\r\n")
        self.wfile.flush()

    def _write_response(self, response: bytes) -> None:
        self.wfile.write(response)
        self.wfile.flush()

    def _send_fail_open_response(
        self,
        *,
        allow_204: bool,
        http_header: bytes,
        body: bytes,
        body_complete: bool,
        null_body: bool = False,
    ) -> None:
        if allow_204 and body_complete:
            self._write_response(_icap_response("204 No Content", {"ISTag": ISTAG}))
            return
        if null_body and body_complete:
            self._write_response(
                clean_no_body_response(allow_204=False, http_header=http_header)
            )
            return
        if body_complete:
            self._write_response(
                clean_response(allow_204=False, http_header=http_header, body=body)
            )
            return
        self._write_response(error_response("scan failed before complete response body"))

    def _read_respmod_body_for_scan(
        self,
        *,
        initial: bytes,
        allow_204: bool,
        preview_size: int | None,
    ) -> tuple[bytes, ClamdResult]:
        """Read the full ICAP body while best-effort streaming to clamd.

        Squid may still be writing the encapsulated response body when a remote
        clamd connection fails or resets.  A fail-open 204 is only safe after the
        helper has consumed that body (including post-preview continuation); if
        the helper replies and closes early, Squid can record ICAP_ERR_OTHER and
        turn an otherwise-good web response into HTTP 500/missing subresources.
        """
        scan_error: Exception | None = None
        result: ClamdResult | None = None

        with contextlib.ExitStack() as stack:
            scanner: ClamdInstreamSession | None
            try:
                scanner = stack.enter_context(self.server.open_scan())
            except Exception as exc:
                scanner = None
                scan_error = exc

            def send_chunk_or_degrade(chunk: bytes) -> None:
                nonlocal scan_error
                if scanner is None or scan_error is not None:
                    return
                try:
                    scanner.send_chunk(chunk)
                except Exception as exc:
                    scan_error = exc

            body, remainder = read_icap_chunked_body(
                self.rfile,
                initial,
                max_bytes=self.server.max_scan_bytes,
                preview=preview_size is not None,
                preview_size=preview_size,
                continue_callback=self._send_100_continue,
                chunk_callback=send_chunk_or_degrade,
                buffer_body=not allow_204,
            )
            if remainder:
                # Terminal chunk trailers have already been drained.  This
                # helper handles one ICAP request per connection and always
                # replies Connection: close, so buffered bytes are not a
                # reusable pipelined exchange for this handler.
                message = "unexpected data after terminal ICAP body"
                raise IcapProtocolError(message)
            if scanner is not None and scan_error is None:
                try:
                    result = scanner.finish()
                except Exception as exc:
                    scan_error = exc

        if scan_error is not None:
            raise ScanFailedAfterBodyError(str(scan_error), body=body) from scan_error
        if result is None:
            message = "clamd INSTREAM scan failed without a verdict"
            raise ScanFailedAfterBodyError(message, body=body)
        return body, result

    def handle(self) -> None:
        allow_204 = False
        http_header = b""
        body = b""
        body_complete = False
        null_body = False
        try:
            raw_header, remainder = _read_until(self.rfile, HEADER_END)
            start_line, headers = _split_headers(raw_header[:-4])
            method = _parse_start_line(start_line)
            if method == "OPTIONS":
                self._write_response(options_response())
                return
            if method != "RESPMOD":
                self._write_response(
                    _icap_response(
                        "405 Method Not Allowed", {"Allow": "RESPMOD, OPTIONS"}
                    )
                )
                return

            offsets = _parse_encapsulated(headers.get("encapsulated", ""))
            _validate_respmod_encapsulated_offsets(offsets)
            body_offset = offsets.get("res-body")
            null_body_offset = offsets.get("null-body")
            null_body = null_body_offset is not None
            response_header_offset = offsets["res-hdr"]
            preview_size = _parse_preview_size(
                headers,
                has_body=body_offset is not None,
                max_bytes=self.server.max_scan_bytes,
            )
            allow_204 = "204" in {
                part.strip() for part in headers.get("allow", "").split(",")
            }
            result: ClamdResult
            if body_offset is not None:
                encapsulated_headers, remainder = _read_exact(
                    self.rfile, body_offset, remainder
                )
                _validate_respmod_encapsulated_header_boundaries(
                    encapsulated_headers, offsets
                )
                http_header = encapsulated_headers[response_header_offset:body_offset]
                can_use_204 = allow_204 and _http_response_allows_squid_204_backup(
                    http_header
                )
                allow_204 = can_use_204
                # ICAP 204 lets Squid keep the original clean response, so the
                # proxy does not need to retain the full body in memory when
                # Squid can safely back it up. If Squid advertised Allow: 204
                # for an unknown/chunked/large response, still buffer and replay
                # the body to avoid ICAP_RESPMOD_EARLY failures.
                try:
                    body, result = self._read_respmod_body_for_scan(
                        initial=remainder,
                        allow_204=False,
                        preview_size=preview_size,
                    )
                    body_complete = True
                except ScanFailedAfterBodyError as exc:
                    body = exc.body
                    body_complete = True
                    raise
            else:
                encapsulated_headers, remainder = _read_exact(
                    self.rfile, null_body_offset or 0, remainder
                )
                _validate_respmod_encapsulated_header_boundaries(
                    encapsulated_headers, offsets
                )
                http_header = encapsulated_headers[
                    response_header_offset : null_body_offset or 0
                ]
                body_complete = True
                result = self.server.scan_body(body)
                can_use_204 = allow_204
            if result.infected:
                response = blocked_response(result.signature)
            elif null_body:
                response = clean_no_body_response(
                    allow_204=can_use_204, http_header=http_header
                )
            else:
                response = clean_response(
                    allow_204=can_use_204, http_header=http_header, body=body
                )
            self._write_response(response)
        except Exception as exc:
            if self.server.fail_open:
                scan_error_warning.warning(
                    "fail-open after scan/protocol error: %s", exc
                )
                try:
                    self._send_fail_open_response(
                        allow_204=allow_204,
                        http_header=http_header,
                        body=body,
                        body_complete=body_complete,
                        null_body=null_body,
                    )
                except OSError as write_exc:
                    scan_error_warning.warning(
                        "failed writing fail-open ICAP response: %s", write_exc
                    )
            else:
                scan_error_warning.warning(
                    "fail-closed after scan/protocol error: %s", exc
                )
                try:
                    self._write_response(error_response(str(exc)))
                except OSError as write_exc:
                    scan_error_warning.warning(
                        "failed writing fail-closed ICAP response: %s", write_exc
                    )


class ClamAvRespmodServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 128

    def __init__(
        self,
        server_address: tuple[str, int],
        handler_class=ClamAvRespmodHandler,
        *,
        clamd_host: str,
        clamd_port: int,
        clamd_timeout: float,
        fail_open: bool,
        max_scan_bytes: int,
        client_timeout: float = DEFAULT_CLIENT_TIMEOUT,
        max_connections: int = DEFAULT_MAX_CONNECTIONS,
        max_scans: int = DEFAULT_MAX_SCANS,
    ) -> None:
        super().__init__(server_address, handler_class)
        self.clamd_host = clamd_host
        self.clamd_port = clamd_port
        self.clamd_timeout = clamd_timeout
        self.fail_open = fail_open
        self.max_scan_bytes = max_scan_bytes
        self.client_timeout = client_timeout
        self.max_connections = max_connections
        self.max_scans = max_scans
        self._request_slots = threading.BoundedSemaphore(max_connections)
        self._scan_slots = threading.BoundedSemaphore(max_scans)

    def process_request(
        self,
        request: socket.socket,
        client_address: tuple[str, int],
    ) -> None:
        if not self._request_slots.acquire(blocking=False):
            try:
                request.settimeout(0.2)
                request.sendall(
                    _icap_response(
                        "503 Service Unavailable",
                        {"ISTag": ISTAG, "Connection": "close"},
                    ),
                )
            except OSError:
                pass
            self.shutdown_request(request)
            return

        def finish_guarded() -> None:
            try:
                try:
                    self.finish_request(request, client_address)
                except Exception:
                    self.handle_error(request, client_address)
                finally:
                    self.shutdown_request(request)
            finally:
                self._request_slots.release()

        thread = threading.Thread(target=finish_guarded)
        thread.daemon = self.daemon_threads
        thread.start()

    def open_scan(self) -> ClamdInstreamSession:
        return ClamdInstreamSession(
            host=self.clamd_host,
            port=self.clamd_port,
            timeout=self.clamd_timeout,
            concurrency_gate=self._scan_slots,
        )

    def scan_body(self, body: bytes) -> ClamdResult:
        with self.open_scan() as scanner:
            scanner.send_chunk(body)
            return scanner.finish()


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--host", default=os.environ.get("CLAMAV_RESPMOD_HOST", "127.0.0.1")
    )
    parser.add_argument(
        "--port", type=int, default=int(os.environ.get("CLAMAV_RESPMOD_PORT", "15001"))
    )
    parser.add_argument(
        "--clamd-host", default=os.environ.get("CLAMD_HOST", "127.0.0.1")
    )
    parser.add_argument(
        "--clamd-port", type=int, default=int(os.environ.get("CLAMD_PORT", "3310"))
    )
    parser.add_argument(
        "--clamd-timeout",
        type=float,
        default=float(os.environ.get("CLAMD_TIMEOUT", "5")),
    )
    parser.add_argument(
        "--max-scan-bytes",
        type=int,
        default=int(
            os.environ.get("CLAMAV_STREAM_MAX_BYTES", str(DEFAULT_MAX_SCAN_BYTES))
        ),
    )
    parser.add_argument(
        "--client-timeout",
        type=float,
        default=float(
            os.environ.get("CLAMAV_RESPMOD_CLIENT_TIMEOUT", str(DEFAULT_CLIENT_TIMEOUT))
        ),
    )
    parser.add_argument(
        "--max-connections",
        type=int,
        default=int(
            os.environ.get(
                "CLAMAV_RESPMOD_MAX_CONNECTIONS", str(DEFAULT_MAX_CONNECTIONS)
            )
        ),
    )
    parser.add_argument(
        "--max-scans",
        type=int,
        default=int(os.environ.get("CLAMAV_RESPMOD_MAX_SCANS", str(DEFAULT_MAX_SCANS))),
    )
    parser.add_argument("--fail-open", dest="fail_open", action="store_true")
    parser.add_argument("--fail-closed", dest="fail_open", action="store_false")
    parser.set_defaults(
        fail_open=not _env_bool("CLAMAV_REQUIRED")
        and not _env_bool("FILE_SECURITY_AV_REQUIRED")
    )
    args = parser.parse_args(argv)
    args.client_timeout = max(0.1, args.client_timeout)
    args.max_connections = max(1, args.max_connections)
    args.max_scans = max(1, min(args.max_scans, args.max_connections))
    return args


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    with ClamAvRespmodServer(
        (args.host, args.port),
        clamd_host=args.clamd_host,
        clamd_port=args.clamd_port,
        clamd_timeout=args.clamd_timeout,
        fail_open=args.fail_open,
        max_scan_bytes=args.max_scan_bytes,
        client_timeout=args.client_timeout,
        max_connections=args.max_connections,
        max_scans=args.max_scans,
    ) as server:
        logger.warning(
            "listening on %s:%s, clamd=%s:%s, fail_open=%s, client_timeout=%s, max_connections=%s, max_scans=%s",
            args.host,
            args.port,
            args.clamd_host,
            args.clamd_port,
            args.fail_open,
            args.client_timeout,
            args.max_connections,
            args.max_scans,
        )
        server.serve_forever()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
