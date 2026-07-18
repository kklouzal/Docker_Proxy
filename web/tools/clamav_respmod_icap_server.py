"""Minimal RESPMOD ICAP helper that streams response bodies to clamd.

c-icap's virus_scan/clamd_mod path can hand proxy-local temporary file names to
clamd. That is unsafe when clamd is on another host because the daemon cannot
read the proxy container's filesystem. This helper keeps the Squid-facing ICAP
contract local, but sends response bytes to clamd with the INSTREAM TCP protocol.
"""

from __future__ import annotations

import argparse
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
ISTAG = '"clamav-respmod-instream-1"'
CLAMD_INSTREAM_COMMAND = b"zINSTREAM\0"
CLAMD_REPLY_TERMINATOR = b"\0"


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
        headers[name.strip().lower()] = value.strip()
    return lines[0], headers


def _parse_encapsulated(value: str) -> dict[str, int]:
    offsets: dict[str, int] = {}
    for raw_item in value.split(","):
        item = raw_item.strip()
        if not item or "=" not in item:
            continue
        name, raw_offset = item.split("=", 1)
        try:
            offsets[name.strip().lower()] = int(raw_offset.strip())
        except ValueError as exc:
            message = f"invalid Encapsulated offset: {item}"
            raise IcapProtocolError(message) from exc
    return offsets


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


def _drain_chunk_trailers(stream: BinaryIO, initial: bytes = b"") -> bytes:
    remainder = initial
    while True:
        line, remainder = _read_until(stream, CRLF, remainder)
        if line == CRLF:
            return remainder


def read_icap_chunked_body(
    stream: BinaryIO,
    initial: bytes = b"",
    *,
    max_bytes: int = DEFAULT_MAX_SCAN_BYTES,
    preview: bool = False,
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
    while True:
        line, remainder = _read_chunk_header(stream, remainder)
        size_token = line.split(";", 1)[0].strip()
        try:
            size = int(size_token, 16)
        except ValueError as exc:
            message = f"invalid ICAP chunk size: {line!r}"
            raise IcapProtocolError(message) from exc
        if size == 0:
            remainder = _drain_chunk_trailers(stream, remainder)
            if preview and not preview_terminator_seen and "ieof" not in line.lower():
                preview_terminator_seen = True
                if continue_callback is not None:
                    continue_callback()
                continue
            return bytes(body), remainder
        chunk, remainder = _read_exact(stream, size + 2, remainder)
        if chunk[-2:] != CRLF:
            message = "ICAP chunk missing CRLF terminator"
            raise IcapProtocolError(message)
        decoded = chunk[:-2]
        total_size += len(decoded)
        if total_size > max_bytes:
            message = f"ICAP body exceeds {max_bytes} bytes"
            raise BodyTooLargeError(message)
        if chunk_callback is not None:
            chunk_callback(decoded)
        if buffer_body:
            body.extend(decoded)


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
    if allow_204:
        return _icap_response("204 No Content", {"ISTag": ISTAG})
    encoded = _encode_icap_body_chunk(body)
    return _icap_response(
        "200 OK",
        {"ISTag": ISTAG, "Encapsulated": f"res-hdr=0, res-body={len(http_header)}"},
        http_header + encoded,
    )


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
    ) -> None:
        if allow_204:
            self._write_response(_icap_response("204 No Content", {"ISTag": ISTAG}))
            return
        if body_complete:
            self._write_response(
                clean_response(allow_204=False, http_header=http_header, body=body)
            )
            return
        self._write_response(error_response("scan failed after partial response body"))

    def handle(self) -> None:
        allow_204 = False
        http_header = b""
        body = b""
        body_complete = False
        try:
            raw_header, remainder = _read_until(self.rfile, HEADER_END)
            start_line, headers = _split_headers(raw_header[:-4])
            method = start_line.split(" ", 1)[0].upper()
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
            body_offset = offsets.get("res-body")
            null_body = "null-body" in offsets
            if body_offset is None and not null_body:
                message = "RESPMOD request missing res-body/null-body"
                raise IcapProtocolError(message)
            allow_204 = "204" in {
                part.strip() for part in headers.get("allow", "").split(",")
            }
            result: ClamdResult
            if body_offset is not None:
                http_header, remainder = _read_exact(self.rfile, body_offset, remainder)
                # ICAP 204 lets Squid keep the original clean response, so the
                # proxy does not need to retain the full body in memory. If the
                # client did not advertise Allow: 204, we must buffer the body
                # while streaming it to clamd so a clean 200 response can replay
                # the original encapsulated HTTP payload.
                with self.server.open_scan() as scanner:
                    body, _remainder = read_icap_chunked_body(
                        self.rfile,
                        remainder,
                        max_bytes=self.server.max_scan_bytes,
                        preview="preview" in headers,
                        continue_callback=self._send_100_continue,
                        chunk_callback=scanner.send_chunk,
                        buffer_body=not allow_204,
                    )
                    body_complete = True
                    result = scanner.finish()
            else:
                result = self.server.scan_body(body)
                body_complete = True
            if result.infected:
                response = blocked_response(result.signature)
            else:
                response = clean_response(
                    allow_204=allow_204, http_header=http_header, body=body
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
