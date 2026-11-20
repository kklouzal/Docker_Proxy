#!/usr/bin/env python3
# The sans-IO ICAP readers return their result through StopIteration.
# ruff: file-ignore[return-in-generator]
from __future__ import annotations

import argparse
import csv
import errno
import html
import io
import math
import os
import re
import selectors
import socket
import socketserver
import sys
import threading
import time
from collections.abc import Generator
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

_ALLOWED_URL_SCHEMES = {"http", "https"}
# C0 controls, space, DEL, and backslash.
_CONTROL_OR_BACKSLASH_RE = re.compile(r"[\x00-\x20\x7f\\]")
_HEADER_FIELD_NAME_CHARS = frozenset(
    "!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
)

# This script lives in /app/tools; add /app to sys.path.
here = Path(Path(__file__).parent).resolve()
app_root = Path(os.path.join(here, "..")).resolve()
if str(app_root) not in sys.path:
    sys.path.insert(0, str(app_root))

from services.adblock_decision import (  # ruff: ignore[module-import-not-at-top-of-file]
    SUPPORTED_REQUEST_METHODS,
    AdblockDecision,
    AdblockDecisionEngine,
    artifact_decision_cache_settings,
)
from services.helper_runtime import HelperStats  # ruff: ignore[module-import-not-at-top-of-file]
from services.icap_protocol import (  # ruff: ignore[module-import-not-at-top-of-file]
    IcapWireSyntaxError,
    parse_chunk_header,
    parse_encapsulated_sections,
    validate_chunk_trailer,
)
from services.runtime_helpers import env_float, env_int  # ruff: ignore[module-import-not-at-top-of-file]

_CRLF = b"\r\n"


def _parse_headers(lines: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in lines:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()
    return headers


def _header_values(lines: list[str], name: str) -> list[str]:
    expected = name.strip().lower()
    values: list[str] = []
    for line in lines:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        if key.strip().lower() == expected:
            values.append(value.strip())
    return values


def _has_malformed_header_line(lines: list[str]) -> bool:
    for line in lines:
        if ":" not in line:
            return True
        key, _value = line.split(":", 1)
        if not key or any(ch not in _HEADER_FIELD_NAME_CHARS for ch in key):
            return True
    return False


def _has_duplicate_header(lines: list[str], name: str) -> bool:
    expected = name.strip().lower()
    seen = False
    for line in lines:
        if ":" not in line:
            continue
        key, _value = line.split(":", 1)
        if key.strip().lower() != expected:
            continue
        if seen:
            return True
        seen = True
    return False


def _has_invalid_preview_header(lines: list[str], *, max_preview_bytes: int) -> bool:
    values = _header_values(lines, "preview")
    if not values:
        return False
    parsed_values: set[int] = set()
    max_preview_bytes = max(0, int(max_preview_bytes or 0))
    for value in values:
        if not value.isdigit():
            return True
        preview_bytes = int(value)
        if preview_bytes > max_preview_bytes:
            return True
        parsed_values.add(preview_bytes)
    return len(parsed_values) > 1


def _parse_encapsulated_offsets(value: str) -> dict[str, int] | None:
    try:
        offsets = parse_encapsulated_sections(
            value or "",
            supported_names={"req-hdr", "req-body", "null-body"},
            require_nondecreasing_offsets=True,
        )
    except IcapWireSyntaxError:
        return None
    if "req-body" in offsets and "null-body" in offsets:
        return None
    return offsets


def _has_encapsulated_http_boundary(offsets: dict[str, int]) -> bool:
    return "req-body" in offsets or "null-body" in offsets


def _encapsulated_http_request(data: bytes) -> bytes:
    header_blob, _, rest = data.partition(b"\r\n\r\n")
    header_lines = header_blob.decode("iso-8859-1", errors="replace").splitlines()[1:]
    if _has_duplicate_header(header_lines, "encapsulated"):
        return b""
    headers = _parse_headers(header_lines)
    offsets = _parse_encapsulated_offsets(headers.get("encapsulated", ""))
    if (
        offsets is None
        or "req-hdr" not in offsets
        or not _has_encapsulated_http_boundary(offsets)
    ):
        return b""
    start = int(offsets.get("req-hdr", 0) or 0)
    end_candidates = [
        int(offsets[name])
        for name in ("req-body", "null-body")
        if name in offsets and int(offsets[name]) >= start
    ]
    end = min(end_candidates) if end_candidates else len(rest)
    return rest[start:end]


def _has_control_or_backslash(value: str) -> bool:
    return _CONTROL_OR_BACKSLASH_RE.search(value) is not None


def _has_authority_contamination(value: str) -> bool:
    return _has_control_or_backslash(value) or "%" in value


def _valid_absolute_or_scheme_relative_url(target: str, *, scheme: str = "") -> str:
    if not target or _has_control_or_backslash(target):
        return ""
    try:
        parsed = urlsplit(target)
        port = parsed.port
    except ValueError:
        return ""
    if not parsed.netloc or not parsed.hostname:
        return ""
    if _has_authority_contamination(parsed.netloc):
        return ""
    if parsed.username is not None or parsed.password is not None:
        return ""
    if port is not None and port <= 0:
        return ""
    expected_scheme = (parsed.scheme or scheme).lower()
    if expected_scheme not in _ALLOWED_URL_SCHEMES:
        return ""
    if parsed.scheme and parsed.scheme.lower() not in _ALLOWED_URL_SCHEMES:
        return ""
    if parsed.fragment:
        return ""
    if parsed.path and not parsed.path.startswith("/"):
        return ""
    normalized = urlunsplit(
        (
            expected_scheme,
            parsed.netloc,
            parsed.path or "/",
            parsed.query,
            "",
        ),
    )
    reparsed = urlsplit(normalized)
    try:
        normalized_port = reparsed.port
    except ValueError:
        return ""
    if (
        reparsed.scheme != expected_scheme
        or reparsed.netloc != parsed.netloc
        or reparsed.hostname != parsed.hostname
        or reparsed.username is not None
        or reparsed.password is not None
        or normalized_port != port
    ):
        return ""
    return normalized


def _authority_url(authority: str, *, scheme: str, require_port: bool = False) -> str:
    if _has_authority_contamination(authority) or any(
        ch in authority for ch in ("/", "?", "#")
    ):
        return ""
    candidate = _valid_absolute_or_scheme_relative_url(f"//{authority}/", scheme=scheme)
    if not candidate:
        return ""
    try:
        port = urlsplit(candidate).port
    except ValueError:
        return ""
    if require_port and port is None:
        return ""
    return candidate


def _connect_authority_url(authority: str) -> str:
    # Do not let encoded delimiters such as %2f, %3a, or %40, or
    # backslash-vs-slash parser disagreement, alter how a malformed CONNECT
    # target is interpreted by the URL parser/decision engine.
    # Authority-form should be a literal host:port token here.
    return _authority_url(authority, scheme="https", require_port=True)


def _parse_http_request(data: bytes) -> tuple[str, str, dict[str, str]]:
    text = data.decode("iso-8859-1", errors="replace")
    header_text = text.split("\r\n\r\n", 1)[0].split("\n\n", 1)[0]
    lines = [line.rstrip("\r") for line in header_text.splitlines()]
    if not lines:
        return "", "", {}
    request_line = lines[0]
    parts = request_line.split()
    method = parts[0].upper() if parts else ""
    target = parts[1] if len(parts) > 1 else ""
    headers = _parse_headers(lines[1:])
    valid_request_line = (
        len(parts) == 3 and request_line == f"{parts[0]} {parts[1]} {parts[2]}"
    )
    if not valid_request_line:
        return method, "", headers
    scheme = "https" if headers.get("x-forwarded-proto") == "https" else "http"
    if method == "CONNECT" and target and "://" not in target:
        # Squid sends CONNECT requests to REQMOD helpers in authority form
        # ("host:port") rather than absolute-form.  Normalize only well-formed
        # authority-form targets to HTTPS URLs so malformed CONNECT targets do
        # not manufacture misleading hosts/paths for the decision engine.
        target = _connect_authority_url(target)
    elif target.startswith("//"):
        target = _valid_absolute_or_scheme_relative_url(target, scheme=scheme)
    elif target.startswith("/"):
        host = headers.get("host", "")
        host_url = _authority_url(host, scheme=scheme) if host else ""
        target = (
            _valid_absolute_or_scheme_relative_url(host_url.rstrip("/") + target)
            if host_url
            else ""
        )
    elif "://" in target:
        target = _valid_absolute_or_scheme_relative_url(target)
    return method, target, headers


def _decision_list_key(decision: AdblockDecision) -> str:
    list_key = "".join(
        ch
        for ch in str(getattr(decision, "list_key", "") or "").strip()
        if ch.isalnum() or ch in {"-", "_", "."}
    )
    if list_key:
        return list_key[:64]
    return "matched" if str(getattr(decision, "raw", "") or "").strip() else "unknown"


def _icap_response(
    status: str,
    headers: dict[str, str] | None = None,
    *,
    close: bool = False,
) -> bytes:
    lines = [f"ICAP/1.0 {status}"]
    response_headers = {"Connection": "close"} if close else {}
    response_headers.update(headers or {})
    for key, value in response_headers.items():
        lines.append(f"{key}: {value}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii", errors="replace")


def _options_response(*, close: bool = False) -> bytes:
    return _icap_response(
        "200 OK",
        {
            "Methods": "REQMOD",
            "Service": "squid-flask-proxy sqlite adblock",
            "ISTag": '"adblock-sqlite"',
            "Allow": "204",
            "Preview": "0",
            "Options-TTL": "300",
            "Encapsulated": "null-body=0",
        },
        close=close,
    )


def _allow_response(*, close: bool = False) -> bytes:
    return _icap_response(
        "204 No Content",
        {
            "ISTag": '"adblock-sqlite"',
        },
        close=close,
    )


def _block_response(url: str, raw_rule: str, *, close: bool = False) -> bytes:
    escaped_url = html.escape(url or "", quote=True)
    escaped_rule = html.escape(raw_rule or "adblock rule", quote=True)
    body = (
        "<!doctype html><html><head><title>Access Denied</title></head>"
        "<body><h1>Access Denied</h1>"
        "<p>Blocked by proxy adblock.</p>"
        f"<p>{escaped_url}</p><p>Rule: {escaped_rule}</p></body></html>"
    ).encode()
    http_headers = (
        "HTTP/1.1 403 Forbidden\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii")
    close_header = "Connection: close\r\n" if close else ""
    # ICAP encapsulated HTTP bodies are chunked.
    icap_headers = (
        "ICAP/1.0 200 OK\r\n"
        'ISTag: "adblock-sqlite"\r\n'
        f"{close_header}"
        f"Encapsulated: res-hdr=0, res-body={len(http_headers)}\r\n"
        "\r\n"
    ).encode("ascii")
    chunk = f"{len(body):X}\r\n".encode("ascii") + body + b"\r\n0\r\n\r\n"
    return icap_headers + http_headers + chunk


def _parse_chunk_size_line(line: bytes) -> int | None:
    try:
        return parse_chunk_header(line).size
    except IcapWireSyntaxError:
        return None


def _chunk_trailers_parse(
    data: bytes | bytearray,
    cursor: int,
) -> tuple[int | None, bool]:
    while True:
        line_end = data.find(_CRLF, cursor)
        if line_end < 0:
            return None, False
        if line_end == cursor:
            return cursor + len(_CRLF), False
        trailer_line = bytes(data[cursor:line_end])
        try:
            validate_chunk_trailer(trailer_line)
        except IcapWireSyntaxError:
            return None, True
        cursor = line_end + len(_CRLF)


def _preview_body_parse(rest: bytes, body_offset: int) -> tuple[int | None, bool]:
    if body_offset < 0 or len(rest) < body_offset:
        return None, True
    cursor = body_offset
    while True:
        line_end = rest.find(_CRLF, cursor)
        if line_end < 0:
            return None, False
        chunk_size = _parse_chunk_size_line(rest[cursor:line_end])
        if chunk_size is None:
            return None, True
        cursor = line_end + len(_CRLF)
        if chunk_size == 0:
            trailers_end, invalid_trailers = _chunk_trailers_parse(rest, cursor)
            if trailers_end is not None:
                return trailers_end, False
            return None, invalid_trailers
        cursor += chunk_size
        if len(rest) < cursor + len(_CRLF):
            return None, False
        if rest[cursor : cursor + len(_CRLF)] != _CRLF:
            return None, True
        cursor += len(_CRLF)


# The ICAP message readers below are sans-IO generators: each ``yield n`` asks
# the driver for up to n more bytes and receives them (b"" at end of stream,
# None when the read timed out or failed). The server's event loop drives them
# from non-blocking sockets, so one slow client never blocks the others.
_ReadRequest = Generator[int, bytes | None, Any]


def _drain_chunked_body(
    body: bytes,
    *,
    max_drain_bytes: int,
) -> Generator[int, bytes | None, bool]:
    """Consume one chunked body; return whether it ended cleanly in bounds.

    Yields:
        The most bytes wanted next from the connection.

    """
    max_drain_bytes = max(0, int(max_drain_bytes or 0))
    data = bytearray(body)
    cursor = 0

    def ensure(size: int) -> Generator[int, bytes | None, bool]:
        while len(data) < size and len(data) < max_drain_bytes:
            chunk = yield min(8192, max_drain_bytes - len(data))
            if not chunk:
                return False
            data.extend(chunk)
        return len(data) >= size

    while len(data) <= max_drain_bytes:
        line_end = data.find(_CRLF, cursor)
        while line_end < 0:
            if len(data) >= max_drain_bytes or not (yield from ensure(len(data) + 1)):
                return False
            line_end = data.find(_CRLF, cursor)
        chunk_size = _parse_chunk_size_line(bytes(data[cursor:line_end]))
        if chunk_size is None:
            return False
        cursor = line_end + len(_CRLF)
        if chunk_size == 0:
            while True:
                trailers_end, invalid_trailers = _chunk_trailers_parse(data, cursor)
                if trailers_end is not None:
                    return True
                if invalid_trailers:
                    return False
                if len(data) >= max_drain_bytes or not (
                    yield from ensure(len(data) + 1)
                ):
                    return False
        if not (yield from ensure(cursor + chunk_size + len(_CRLF))):
            return False
        cursor += chunk_size
        if data[cursor : cursor + len(_CRLF)] != _CRLF:
            return False
        cursor += len(_CRLF)
    return False


def _read_icap_message(
    *,
    max_bytes: int,
    max_body_drain_bytes: int,
    pending: bytes = b"",
) -> Generator[int, bytes | None, tuple[bytes, bytes, bool]]:
    """Read one ICAP message; return (message, bytes after it, force close).

    Yields:
        The most bytes wanted next from the connection.

    """
    data = bytearray(pending)
    force_close = False
    while b"\r\n\r\n" not in data and len(data) < max_bytes:
        chunk = yield min(8192, max_bytes - len(data))
        if chunk is None:
            return bytes(data), b"", True
        if not chunk:
            break
        data.extend(chunk)
    if b"\r\n\r\n" not in data:
        return bytes(data), b"", True
    header_blob, rest = bytes(data).split(b"\r\n\r\n", 1)
    header_lines = header_blob.decode("iso-8859-1", errors="replace").splitlines()[1:]
    if _has_malformed_header_line(header_lines):
        return bytes(data), b"", True
    if _has_invalid_preview_header(header_lines, max_preview_bytes=max_bytes):
        return bytes(data), b"", True
    if _has_duplicate_header(header_lines, "encapsulated"):
        return bytes(data), b"", True
    headers = _parse_headers(header_lines)
    offsets = _parse_encapsulated_offsets(headers.get("encapsulated", ""))
    if offsets is None:
        return bytes(data), b"", True
    if "req-hdr" not in offsets:
        header_end = len(header_blob) + len(b"\r\n\r\n")
        return bytes(data[:header_end]), bytes(data[header_end:]), False

    req_hdr_offset = int(offsets.get("req-hdr", 0) or 0)
    if not _has_encapsulated_http_boundary(offsets):
        return bytes(data), b"", True
    end_candidates = [
        int(offsets[name])
        for name in ("req-body", "null-body")
        if name in offsets and int(offsets[name]) >= req_hdr_offset
    ]
    required_rest_bytes = min(end_candidates) if end_candidates else len(rest)

    while len(rest) < required_rest_bytes and len(data) < max_bytes:
        chunk = yield min(8192, max_bytes - len(data))
        if chunk is None:
            force_close = True
            break
        if not chunk:
            break
        data.extend(chunk)
        rest += chunk
    while not end_candidates and b"\r\n\r\n" not in rest and len(data) < max_bytes:
        chunk = yield min(8192, max_bytes - len(data))
        if chunk is None:
            force_close = True
            break
        if not chunk:
            break
        data.extend(chunk)
        rest += chunk

    if "preview" in headers and "req-body" in offsets:
        body_offset = int(offsets.get("req-body", 0) or 0)
        body_end, invalid_preview = _preview_body_parse(rest, body_offset)
        while body_end is None and not invalid_preview and len(data) < max_bytes:
            chunk = yield min(8192, max_bytes - len(data))
            if chunk is None:
                force_close = True
                break
            if not chunk:
                break
            data.extend(chunk)
            rest += chunk
            body_end, invalid_preview = _preview_body_parse(rest, body_offset)
        if body_end is None or invalid_preview:
            return bytes(data), b"", True
        message_end = len(header_blob) + len(b"\r\n\r\n") + body_end
        return bytes(data[:message_end]), bytes(data[message_end:]), force_close

    if "req-body" in offsets:
        body_offset = int(offsets.get("req-body", 0) or 0)
        if body_offset < 0 or len(rest) < body_offset:
            return bytes(data), b"", True
        # An unpreviewed body is drained (bounded) so closing afterwards does
        # not reset the connection under the response.
        yield from _drain_chunked_body(
            rest[body_offset:],
            max_drain_bytes=max_body_drain_bytes,
        )
        force_close = True

    message_end = len(header_blob) + len(b"\r\n\r\n") + required_rest_bytes
    return bytes(data[:message_end]), bytes(data[message_end:]), force_close


def _connection_close_requested(header_blob: bytes) -> bool:
    header_lines = header_blob.decode("iso-8859-1", errors="replace").splitlines()[1:]
    connection_values = _header_values(header_lines, "connection")
    token_sets = {
        frozenset(item.strip().lower() for item in value.split(",") if item.strip())
        for value in connection_values
    }
    return any("close" in tokens for tokens in token_sets) or len(token_sets) > 1


_QUIET_SEND_ERRNOS = frozenset({errno.ECONNRESET, errno.EPIPE, errno.ETIMEDOUT})


class _AppendLog:
    """Append-mode log file kept open between blocked requests.

    Each append re-checks the path, so a log removed or replaced on disk is
    reopened (with its directory recreated) rather than written to a stale
    file; copytruncate rotation keeps the same file and needs no reopen.
    """

    def __init__(self, path: str) -> None:
        self.path = path
        self._fd = -1
        self._identity: tuple[int, int] | None = None

    def append(self, data: bytes) -> None:
        try:
            current = os.stat(self.path)
            identity: tuple[int, int] | None = (current.st_dev, current.st_ino)
        except FileNotFoundError:
            identity = None
        if self._fd < 0 or identity is None or identity != self._identity:
            self._reopen()
        view = memoryview(data)
        try:
            while view:
                view = view[os.write(self._fd, view) :]
        except OSError:
            self.close()
            raise

    def _reopen(self) -> None:
        self.close()
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o666)
        stat = os.fstat(fd)
        self._fd = fd
        self._identity = (stat.st_dev, stat.st_ino)

    def close(self) -> None:
        fd, self._fd = self._fd, -1
        self._identity = None
        if fd >= 0:
            os.close(fd)


class _Connection:
    """One Squid ICAP connection owned by the server's event loop."""

    __slots__ = (
        "client_ip",
        "close_after_send",
        "deadline",
        "outgoing",
        "pending",
        "reader",
        "receiving",
        "request_count",
        "sock",
        "wanted",
        "writing",
    )

    def __init__(self, sock: socket.socket, client_ip: str) -> None:
        self.sock = sock
        self.client_ip = client_ip
        self.reader: _ReadRequest | None = None
        # Whether any byte of the current message has arrived.
        self.receiving = False
        self.wanted = 0
        self.outgoing = b""
        self.pending = b""
        self.close_after_send = False
        self.request_count = 0
        self.deadline = 0.0
        self.writing = False


class _AdblockIcapServer(socketserver.TCPServer):
    """Single-threaded, event-driven adblock REQMOD service.

    Decisions are CPU-bound Python work, so connection threads only add GIL
    hand-offs: one event loop serves every persistent Squid connection with
    one SQLite connection and no per-connection thread or cache.
    """

    allow_reuse_address = True
    # Squid opens one ICAP connection per concurrent transaction, so a page
    # load burst connects dozens at once. socketserver's default backlog of 5
    # overflows and the dropped handshakes retry only after the 1 s TCP
    # retransmission timeout.
    request_queue_size = 128
    # How often idle and stalled connections are checked against their
    # read/write timeout.
    _deadline_sweep_seconds = 0.1

    def __init__(
        self,
        server_address: tuple[str, int],
        *,
        engine: AdblockDecisionEngine,
        access_log_path: str,
        max_request_bytes: int,
        max_body_drain_bytes: int = 8388608,
        request_timeout_seconds: float = 5.0,
        max_keepalive_requests: int = 1000,
        stats: HelperStats | None = None,
    ) -> None:
        self.engine = engine
        # Set before binding: a bind failure calls server_close().
        self._selector = selectors.DefaultSelector()
        self._access_log = _AppendLog(access_log_path)
        super().__init__(server_address, socketserver.BaseRequestHandler)
        self.max_request_bytes = max_request_bytes
        self.max_body_drain_bytes = max(8192, int(max_body_drain_bytes or 8192))
        self.request_timeout_seconds = max(0.1, float(request_timeout_seconds or 0))
        self.max_keepalive_requests = max(1, int(max_keepalive_requests or 1))
        self.stats = stats
        self._connections: dict[int, _Connection] = {}
        self._shutdown_requested = False
        self._stopped = threading.Event()
        self._stopped.set()

    def serve_forever(self, poll_interval: float = 0.5) -> None:
        self._stopped.clear()
        self._shutdown_requested = False
        self.socket.setblocking(False)
        selector = self._selector
        selector.register(self.socket, selectors.EVENT_READ, None)
        next_sweep = time.monotonic() + self._deadline_sweep_seconds
        try:
            while not self._shutdown_requested:
                timeout = min(poll_interval, self._deadline_sweep_seconds)
                for key, _mask in selector.select(timeout):
                    conn = key.data
                    if conn is None:
                        self._accept_ready()
                    elif conn.sock.fileno() >= 0:
                        self._guarded(self._ready, conn)
                now = time.monotonic()
                if now >= next_sweep:
                    next_sweep = now + self._deadline_sweep_seconds
                    self._expire(now)
        finally:
            for conn in list(self._connections.values()):
                self._close(conn)
            selector.unregister(self.socket)
            self._stopped.set()

    def shutdown(self) -> None:
        self._shutdown_requested = True
        self._stopped.wait()

    def server_close(self) -> None:
        try:
            super().server_close()
        finally:
            try:
                self._selector.close()
                self._access_log.close()
            finally:
                self.engine.close()

    def _accept_ready(self) -> None:
        while True:
            try:
                sock, address = self.socket.accept()
            except BlockingIOError, InterruptedError:
                return
            except OSError:
                # Out of descriptors or the peer vanished during the
                # handshake: keep serving the established connections.
                self.increment_stat("accept_failed")
                return
            sock.setblocking(False)
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass
            conn = _Connection(sock, str(address[0]))
            self._connections[sock.fileno()] = conn
            self._selector.register(sock, selectors.EVENT_READ, conn)
            self._guarded(self._serve, conn, b"", start=True)

    def _guarded(self, step: Any, conn: _Connection, *args: Any, **kwargs: Any) -> None:
        try:
            step(conn, *args, **kwargs)
        except Exception:
            # Same outcome as an unhandled error in a per-connection handler:
            # report it and drop this connection (Squid then applies the
            # service failure policy) while the others keep being served.
            self.handle_error(conn.sock, (conn.client_ip, 0))
            self._close(conn)

    def _ready(self, conn: _Connection) -> None:
        if conn.outgoing:
            if self._flush(conn):
                self._serve(conn, b"", start=True)
            return
        try:
            chunk: bytes | None = conn.sock.recv(conn.wanted)
        except BlockingIOError, InterruptedError:
            return
        except OSError:
            chunk = None
        self._serve(conn, chunk)

    def _serve(
        self,
        conn: _Connection,
        chunk: bytes | None,
        *,
        start: bool = False,
    ) -> None:
        """Feed ``chunk`` to the connection's reader and answer what completes.

        Pipelined messages already buffered are answered in turn; the loop
        stops when the reader needs more bytes, a response is waiting for the
        socket, or the connection closed.
        """
        while True:
            reader = conn.reader
            if start or reader is None:
                start = True
                reader = conn.reader = _read_icap_message(
                    max_bytes=self.max_request_bytes,
                    max_body_drain_bytes=self.max_body_drain_bytes,
                    pending=conn.pending,
                )
                conn.receiving = bool(conn.pending)
                conn.pending = b""
            elif chunk:
                conn.receiving = True
            try:
                conn.wanted = next(reader) if start else reader.send(chunk)
            except StopIteration as done:
                conn.reader = None
                data, conn.pending, read_close = done.value
            else:
                # Squid owns the lifetime of idle persistent connections
                # (server_idle_pconn_timeout): closing one here races with
                # Squid reusing it, and with icap_retry_limit 0 that request
                # fails. Only a started message is held to the read timeout.
                conn.deadline = (
                    time.monotonic() + self.request_timeout_seconds
                    if conn.receiving
                    else math.inf
                )
                return
            if not data:
                self._close(conn)
                return
            conn.request_count += 1
            header_blob, _, _rest = data.partition(b"\r\n\r\n")
            conn.close_after_send = (
                read_close
                or _connection_close_requested(header_blob)
                or (conn.request_count >= self.max_keepalive_requests)
            )
            conn.outgoing = self._response(
                data,
                header_blob,
                conn.client_ip,
                close=conn.close_after_send,
            )
            if not self._flush(conn):
                return
            start = True

    def _response(
        self,
        data: bytes,
        header_blob: bytes,
        client_ip: str,
        *,
        close: bool,
    ) -> bytes:
        lines = header_blob.decode("iso-8859-1", errors="replace").splitlines()
        request_line = lines[0] if lines else ""
        parts = request_line.split()
        method = parts[0].upper() if parts else ""
        if method == "OPTIONS":
            self.increment_stat("options")
            return _options_response(close=close)
        if method != "REQMOD":
            self.increment_stat("method_not_allowed")
            return _icap_response(
                "405 Method Not Allowed",
                {"Encapsulated": "null-body=0"},
                close=close,
            )

        http_method, url, http_headers = _parse_http_request(
            _encapsulated_http_request(data),
        )
        if not url:
            self.increment_stat("parse_miss")
            return _allow_response(close=close)

        # Current Squid routing sends only this method set to adblock. Fail
        # open, with distinct attribution, if a legacy/custom config sends
        # CONNECT or another unsupported method rather than applying a
        # generic URL rule under semantics the engine does not support.
        if http_method not in SUPPORTED_REQUEST_METHODS:
            self.increment_stat("unsupported_http_method")
            self.increment_stat("allowed")
            return _allow_response(close=close)

        self.increment_stat("reqmod")
        decision = self.engine.decide(
            url,
            method=http_method,
            headers=http_headers,
        )
        if not decision.blocked:
            self.increment_stat("allowed")
            return _allow_response(close=close)
        self.increment_stat("blocked")
        self.log_access(
            client_ip=client_ip,
            method=http_method,
            url=url,
            icap_status=200,
            http_status=403,
            http_resp_line="HTTP/1.1 403 Forbidden",
            list_key=_decision_list_key(decision),
            rule_id=decision.rule_id,
            decision_action=decision.action,
            decision_reason=decision.reason,
        )
        return _block_response(url, decision.raw, close=close)

    def _flush(self, conn: _Connection) -> bool:
        """Send the pending response; True when the next message may be read."""
        while conn.outgoing:
            try:
                sent = conn.sock.send(conn.outgoing)
            except BlockingIOError, InterruptedError:
                break
            except BrokenPipeError, ConnectionResetError, TimeoutError:
                self._close(conn)
                return False
            except OSError as exc:
                if exc.errno in _QUIET_SEND_ERRNOS:
                    self._close(conn)
                    return False
                raise
            conn.outgoing = conn.outgoing[sent:]
        selector = self._selector
        if conn.outgoing:
            # Wait for the peer to drain its receive window; like a read, a
            # stalled write times out.
            conn.deadline = time.monotonic() + self.request_timeout_seconds
            if not conn.writing:
                selector.modify(conn.sock, selectors.EVENT_WRITE, conn)
                conn.writing = True
            return False
        if conn.close_after_send:
            self._close(conn)
            return False
        if conn.writing:
            selector.modify(conn.sock, selectors.EVENT_READ, conn)
            conn.writing = False
        return True

    def _expire(self, now: float) -> None:
        for conn in [c for c in self._connections.values() if c.deadline <= now]:
            if conn.outgoing:
                self._close(conn)
            elif conn.reader is not None:
                # The read timed out: the reader decides what is left to do.
                self._guarded(self._serve, conn, None)

    def _close(self, conn: _Connection) -> None:
        if self._connections.pop(conn.sock.fileno(), None) is None:
            return
        self._selector.unregister(conn.sock)
        if conn.reader is not None:
            conn.reader.close()
            conn.reader = None
        conn.sock.close()

    def increment_stat(self, key: str, amount: int = 1) -> None:
        if self.stats is None:
            return
        self.stats.increment(key, amount)
        self.stats.emit_if_due()

    def log_access(
        self,
        *,
        client_ip: str,
        method: str,
        url: str,
        icap_status: int,
        http_status: int,
        http_resp_line: str,
        list_key: str = "",
        rule_id: str = "",
        decision_action: str = "",
        decision_reason: str = "",
    ) -> None:
        output = io.StringIO(newline="")
        csv.writer(output, delimiter="\t", lineterminator="\n").writerow(
            [
                str(int(time.time())),
                client_ip or "-",
                client_ip or "-",
                "REQMOD",
                "/adblockreq",
                str(int(icap_status)),
                f"{method or '-'} {url or '-'} HTTP/1.1",
                url or "-",
                http_resp_line if http_status else "-",
                list_key or "-",
                rule_id or "-",
                decision_action or "-",
                decision_reason or "-",
            ],
        )
        try:
            self._access_log.append(output.getvalue().encode("utf-8"))
        except Exception:
            self.increment_stat("access_log_write_failed")


def _explicit_env_int(name: str) -> int | None:
    try:
        return int((os.environ.get(name) or "").strip())
    except ValueError:
        return None


def _decision_cache_settings(args: argparse.Namespace) -> tuple[int, int]:
    artifact_ttl, artifact_max = artifact_decision_cache_settings(args.db)
    cache_ttl = args.cache_ttl
    if cache_ttl is None:
        cache_ttl = artifact_ttl if artifact_ttl is not None else 3600
    cache_max = args.cache_max
    if cache_max is None:
        cache_max = artifact_max if artifact_max is not None else 50000
    return cache_ttl, cache_max


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="SQLite-backed adblock ICAP server")
    parser.add_argument("--host", default=os.environ.get("CICAP_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=env_int("CICAP_PORT", 14000))
    parser.add_argument(
        "--db",
        default=os.environ.get(
            "ADBLOCK_LOOKUP_DB",
            "/var/lib/squid-flask-proxy/adblock/compiled/request_lookup.sqlite",
        ),
    )
    parser.add_argument(
        "--access-log",
        default=os.environ.get("ADBLOCK_ICAP_ACCESS_LOG", "/var/log/cicap-access.log"),
    )
    # Unset means: use the Admin UI value published in the artifact's
    # settings.json, else the built-in default.
    parser.add_argument(
        "--cache-ttl",
        type=int,
        default=_explicit_env_int("ADBLOCK_CACHE_TTL"),
    )
    parser.add_argument(
        "--cache-max",
        type=int,
        default=_explicit_env_int("ADBLOCK_CACHE_MAX"),
    )
    parser.add_argument(
        "--rule-cache-max",
        type=int,
        default=env_int("ADBLOCK_RULE_CACHE_MAX", 50000),
    )
    parser.add_argument(
        "--max-request-bytes",
        type=int,
        default=env_int("ADBLOCK_ICAP_MAX_REQUEST_BYTES", 262144),
    )
    parser.add_argument(
        "--max-body-drain-bytes",
        type=int,
        default=env_int("ADBLOCK_ICAP_MAX_BODY_DRAIN_BYTES", 8388608),
    )
    parser.add_argument(
        "--request-timeout",
        type=float,
        default=env_float("ADBLOCK_ICAP_REQUEST_TIMEOUT", 5.0),
        help=(
            "Seconds a started ICAP message (or a pending response) may stall; "
            "idle persistent connections are left for Squid to close."
        ),
    )
    parser.add_argument(
        "--max-keepalive-requests",
        type=int,
        default=env_int("ADBLOCK_ICAP_MAX_KEEPALIVE_REQUESTS", 1000),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    cache_ttl, cache_max = _decision_cache_settings(args)
    engine = AdblockDecisionEngine(
        args.db,
        cache_ttl_seconds=cache_ttl,
        cache_max=cache_max,
        rule_cache_max=args.rule_cache_max,
    )
    # Refuse to serve an unsupported lookup database: the runtime retries the
    # helper and keeps its last applied artifact instead of matching against
    # tables this reader does not know.
    engine.lookup.check_schema()
    # Load the in-memory candidate indexes before listening, not on the first
    # request Squid sends.
    engine.lookup.load_indexes()
    stats = HelperStats("adblock_icap")
    stats.started(
        host=args.host,
        port=int(args.port),
        db=args.db,
        max_request_bytes=max(8192, int(args.max_request_bytes)),
        max_body_drain_bytes=max(8192, int(args.max_body_drain_bytes)),
        request_timeout_seconds=max(0.1, float(args.request_timeout)),
        max_keepalive_requests=max(1, int(args.max_keepalive_requests)),
    )
    try:
        with _AdblockIcapServer(
            (args.host, int(args.port)),
            engine=engine,
            access_log_path=args.access_log,
            max_request_bytes=max(8192, int(args.max_request_bytes)),
            max_body_drain_bytes=max(8192, int(args.max_body_drain_bytes)),
            request_timeout_seconds=max(0.1, float(args.request_timeout)),
            max_keepalive_requests=max(1, int(args.max_keepalive_requests)),
            stats=stats,
        ) as server:
            sys.stdout.write(
                f"adblock sqlite ICAP listening on {args.host}:{args.port} using {args.db}\n",
            )
            sys.stdout.flush()
            server.serve_forever()
    finally:
        stats.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
