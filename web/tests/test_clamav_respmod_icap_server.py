from __future__ import annotations

import importlib.util
import io
import math
import socket
import struct
import sys
import threading
import time
from pathlib import Path

CLIENT_CREATE_CONNECTION = socket.create_connection


def _load_server():
    path = (
        Path(__file__).resolve().parents[1] / "tools" / "clamav_respmod_icap_server.py"
    )
    spec = importlib.util.spec_from_file_location("clamav_respmod_icap_server", path)
    assert spec
    assert spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class FakeSocket:
    def __init__(self, response: bytes = b"stream: OK\0") -> None:
        self.sent = bytearray()
        self.response = response
        self.timeout = None
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def settimeout(self, timeout):
        self.timeout = timeout

    def sendall(self, data: bytes) -> None:
        self.sent.extend(data)

    def recv(self, _size: int) -> bytes:
        return self.response

    def close(self) -> None:
        self.closed = True


class ResetBeforeVerdictSocket(FakeSocket):
    def recv(self, _size: int) -> bytes:
        message = "connection reset by peer"
        raise ConnectionResetError(message)


class ResetMidStreamSocket(FakeSocket):
    def __init__(self, *, fail_after_chunks: int = 1) -> None:
        super().__init__()
        self.fail_after_chunks = fail_after_chunks
        self._body_chunks = 0
        self._expecting_body = False

    def sendall(self, data: bytes) -> None:
        if self._expecting_body:
            self._expecting_body = False
            self._body_chunks += 1
            if self._body_chunks > self.fail_after_chunks:
                message = "connection reset by peer"
                raise ConnectionResetError(message)
        elif len(data) == 4 and data != struct.pack("!I", 0):
            self._expecting_body = True
        super().sendall(data)


def test_clamd_instream_scan_sends_body_chunks(monkeypatch) -> None:
    server = _load_server()
    fake = FakeSocket()

    monkeypatch.setattr(
        server.socket, "create_connection", lambda address, timeout: fake
    )

    result = server.scan_stream_with_clamd(
        b"abcdef",
        host="192.168.1.10",
        port=3310,
        timeout=2,
        chunk_size=4,
    )

    assert result.clean is True
    assert fake.sent == (
        server.CLAMD_INSTREAM_COMMAND
        + struct.pack("!I", 4)
        + b"abcd"
        + struct.pack("!I", 2)
        + b"ef"
        + struct.pack("!I", 0)
    )


def test_icap_chunks_stream_to_clamd_incrementally(monkeypatch) -> None:
    server = _load_server()
    fake = FakeSocket()

    monkeypatch.setattr(
        server.socket, "create_connection", lambda address, timeout: fake
    )

    with server.ClamdInstreamSession(
        host="192.168.1.10",
        port=3310,
        timeout=2,
        chunk_size=1024,
    ) as scanner:
        body, remainder = server.read_icap_chunked_body(
            io.BytesIO(b"3\r\nabc\r\n3\r\ndef\r\n0\r\n\r\n"),
            chunk_callback=scanner.send_chunk,
            buffer_body=False,
        )
        assert fake.sent == (
            server.CLAMD_INSTREAM_COMMAND
            + struct.pack("!I", 3)
            + b"abc"
            + struct.pack("!I", 3)
            + b"def"
        )
        result = scanner.finish()

    assert result.clean is True
    assert body == b""
    assert remainder == b""
    assert fake.sent == (
        server.CLAMD_INSTREAM_COMMAND
        + struct.pack("!I", 3)
        + b"abc"
        + struct.pack("!I", 3)
        + b"def"
        + struct.pack("!I", 0)
    )


def test_clamd_instream_scan_reports_found(monkeypatch) -> None:
    server = _load_server()
    fake = FakeSocket(b"stream: Eicar-Test-Signature FOUND\n")

    monkeypatch.setattr(
        server.socket, "create_connection", lambda address, timeout: fake
    )

    result = server.scan_stream_with_clamd(b"eicar", host="192.168.1.10", port=3310)

    assert result.clean is False
    assert result.infected is True
    assert result.signature == "Eicar-Test-Signature"


class ProtocolCheckingSocket(FakeSocket):
    def __init__(self) -> None:
        super().__init__()
        self._saw_command = False
        self._rejecting_old_command = False

    def sendall(self, data: bytes) -> None:
        if not self._saw_command:
            self._saw_command = True
            if data == b"INSTREAM\n":
                self.sent.extend(data)
                self.response = b"UNKNOWN COMMAND\0"
                self._rejecting_old_command = True
                return
            if data != b"zINSTREAM\0":
                message = f"unexpected clamd command frame: {data!r}"
                raise AssertionError(message)
        elif self._rejecting_old_command:
            message = "clamd closed after UNKNOWN COMMAND"
            raise BrokenPipeError(message)
        self.sent.extend(data)


def test_clamd_instream_uses_explicit_z_framing_not_legacy_command(
    monkeypatch,
) -> None:
    server = _load_server()

    old = ProtocolCheckingSocket()
    old.sendall(b"INSTREAM\n")
    try:
        old.sendall(struct.pack("!I", 1) + b"x")
    except BrokenPipeError:
        pass
    else:  # pragma: no cover - regression guard should always reject this path
        message = "old bare INSTREAM command was not rejected"
        raise AssertionError(message)
    assert old.recv(4096) == b"UNKNOWN COMMAND\0"

    accepted = ProtocolCheckingSocket()
    monkeypatch.setattr(
        server.socket, "create_connection", lambda address, timeout: accepted
    )

    result = server.scan_stream_with_clamd(b"x", host="192.168.1.10", port=3310)

    assert result.clean is True
    assert accepted.sent == (
        server.CLAMD_INSTREAM_COMMAND
        + struct.pack("!I", 1)
        + b"x"
        + struct.pack("!I", 0)
    )


def test_icap_chunked_body_handles_preview_continue() -> None:
    server = _load_server()
    continues = 0

    def on_continue() -> None:
        nonlocal continues
        continues += 1

    stream = io.BytesIO(b"3\r\nabc\r\n0\r\n\r\n3\r\ndef\r\n0\r\n\r\n")

    body, remainder = server.read_icap_chunked_body(
        stream,
        preview=True,
        continue_callback=on_continue,
    )

    assert body == b"abcdef"
    assert remainder == b""
    assert continues == 1


def test_icap_chunked_body_only_treats_ieof_extension_as_preview_eof() -> None:
    server = _load_server()
    continues = 0

    def on_continue() -> None:
        nonlocal continues
        continues += 1

    stream = io.BytesIO(b"2\r\nhe\r\n0; notieof\r\n\r\n3\r\nllo\r\n0\r\n\r\n")

    body, remainder = server.read_icap_chunked_body(
        stream,
        preview=True,
        continue_callback=on_continue,
    )

    assert body == b"hello"
    assert remainder == b""
    assert continues == 1


def test_icap_chunked_body_allows_zero_ieof_with_trailers() -> None:
    server = _load_server()
    continues = 0

    def on_continue() -> None:
        nonlocal continues
        continues += 1

    body, remainder = server.read_icap_chunked_body(
        io.BytesIO(b"2\r\nhe\r\n0; ieof\r\nX-Trailer: ok\r\n\r\n"),
        preview=True,
        continue_callback=on_continue,
    )

    assert body == b"he"
    assert remainder == b""
    assert continues == 0


def test_icap_chunked_body_valued_ieof_extension_is_preview_eof() -> None:
    server = _load_server()
    continues = 0

    def on_continue() -> None:
        nonlocal continues
        continues += 1

    body, remainder = server.read_icap_chunked_body(
        io.BytesIO(b"2\r\nhe\r\n0; foo=bar; ieof=value\r\n\r\n3\r\nllo\r\n0\r\n\r\n"),
        preview=True,
        continue_callback=on_continue,
    )

    assert body == b"he"
    assert remainder == b"3\r\nllo\r\n0\r\n\r\n"
    assert continues == 0


def test_icap_chunked_body_rejects_ieof_on_nonzero_chunk() -> None:
    server = _load_server()

    try:
        server.read_icap_chunked_body(
            io.BytesIO(b"2;ieof\r\nhe\r\n0;ieof\r\n\r\n"),
            preview=True,
        )
    except server.IcapProtocolError as exc:
        assert str(exc) == "invalid ICAP ieof chunk extension on nonzero chunk"
    else:  # pragma: no cover - regression guard should always raise
        message = "ieof on a nonzero chunk was accepted"
        raise AssertionError(message)


def test_icap_chunked_body_leaves_bytes_after_ieof_terminator_as_remainder() -> None:
    server = _load_server()

    body, remainder = server.read_icap_chunked_body(
        io.BytesIO(b"2\r\nhe\r\n0;ieof\r\n\r\n1\r\nX\r\n0\r\n\r\n"),
        preview=True,
    )

    assert body == b"he"
    assert remainder == b"1\r\nX\r\n0\r\n\r\n"


def test_icap_chunked_body_rejects_oversize_declared_chunk_before_body_read() -> None:
    server = _load_server()

    class OversizeChunkStream:
        def __init__(self) -> None:
            self.data = bytearray(b"B\r\n")
            self.read_sizes: list[int] = []

        def read(self, size: int = -1) -> bytes:
            self.read_sizes.append(size)
            if self.data:
                chunk = bytes(self.data[:size])
                del self.data[:size]
                return chunk
            message = f"oversize chunk body read attempted: read({size})"
            raise AssertionError(message)

    stream = OversizeChunkStream()

    try:
        server.read_icap_chunked_body(stream, max_bytes=10)
    except server.BodyTooLargeError as exc:
        assert str(exc) == "ICAP body exceeds 10 bytes"
    else:  # pragma: no cover - regression guard should always raise
        message = "oversize chunk was accepted"
        raise AssertionError(message)

    assert stream.read_sizes == [4096]


def test_icap_chunked_body_accepts_exact_limit_chunk() -> None:
    server = _load_server()
    seen_chunks: list[bytes] = []

    body, remainder = server.read_icap_chunked_body(
        io.BytesIO(b"A\r\n0123456789\r\n0\r\n\r\n"),
        max_bytes=10,
        chunk_callback=seen_chunks.append,
    )

    assert body == b"0123456789"
    assert remainder == b""
    assert seen_chunks == [b"0123456789"]


def test_clean_icap_response_replays_body_even_when_204_allowed() -> None:
    server = _load_server()

    response = server.clean_response(
        allow_204=True,
        http_header=b"HTTP/1.1 200 OK\r\n\r\n",
        body=b"clean",
    )

    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 200 OK" in response
    assert b"Content-Length: 5\r\n" in response
    assert b"5\r\nclean\r\n0\r\n\r\n" in response


def test_unknown_length_clean_respmod_replays_body_instead_of_late_204() -> None:
    server = _load_server()

    class FailOpenServer(server.ClamAvRespmodServer):
        def open_scan(self):
            return CleanScanner()

    with FailOpenServer(
        ("127.0.0.1", 0),
        clamd_host="127.0.0.1",
        clamd_port=3310,
        clamd_timeout=0.1,
        fail_open=True,
        max_scan_bytes=1024,
        client_timeout=0.5,
        max_connections=4,
    ) as icap_server:
        thread = _serve_in_thread(icap_server)
        port = icap_server.server_address[1]
        response = _recv_icap_response(
            port, _sample_unknown_length_respmod_request(port), timeout=0.5
        )
        icap_server.shutdown()
        thread.join(timeout=1)

    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 200 OK" in response
    assert b"Content-Length: 5\r\n" in response
    assert b"5\r\nhello\r\n0\r\n\r\n" in response


def test_chunked_clean_respmod_replays_with_normalized_framing() -> None:
    server = _load_server()

    class FailOpenServer(server.ClamAvRespmodServer):
        def open_scan(self):
            return CleanScanner()

    with FailOpenServer(
        ("127.0.0.1", 0),
        clamd_host="127.0.0.1",
        clamd_port=3310,
        clamd_timeout=0.1,
        fail_open=True,
        max_scan_bytes=1024,
        client_timeout=0.5,
        max_connections=4,
    ) as icap_server:
        thread = _serve_in_thread(icap_server)
        port = icap_server.server_address[1]
        response = _recv_icap_response(
            port, _sample_chunked_respmod_request(port), timeout=0.5
        )
        icap_server.shutdown()
        thread.join(timeout=1)

    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 200 OK" in response
    assert b"Transfer-Encoding" not in response
    assert b"Content-Length: 5\r\n" in response
    assert b"5\r\nhello\r\n0\r\n\r\n" in response


def test_small_clean_respmod_with_allow_204_still_replays_complete_body() -> None:
    server = _load_server()

    class FailOpenServer(server.ClamAvRespmodServer):
        def open_scan(self):
            return CleanScanner()

    with FailOpenServer(
        ("127.0.0.1", 0),
        clamd_host="127.0.0.1",
        clamd_port=3310,
        clamd_timeout=0.1,
        fail_open=True,
        max_scan_bytes=1024,
        client_timeout=0.5,
        max_connections=4,
    ) as icap_server:
        thread = _serve_in_thread(icap_server)
        port = icap_server.server_address[1]
        response = _recv_icap_response(port, _sample_respmod_request(port), timeout=0.5)
        icap_server.shutdown()
        thread.join(timeout=1)

    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"Content-Length: 5\r\n" in response
    assert b"5\r\nhello\r\n0\r\n\r\n" in response


def test_respmod_with_req_hdr_offset_replays_only_response_header() -> None:
    server = _load_server()

    class FailOpenServer(server.ClamAvRespmodServer):
        def open_scan(self):
            return CleanScanner()

    with FailOpenServer(
        ("127.0.0.1", 0),
        clamd_host="127.0.0.1",
        clamd_port=3310,
        clamd_timeout=0.1,
        fail_open=True,
        max_scan_bytes=1024,
        client_timeout=0.5,
        max_connections=4,
    ) as icap_server:
        thread = _serve_in_thread(icap_server)
        port = icap_server.server_address[1]
        response = _recv_icap_response(
            port, _sample_respmod_request_with_req_hdr(port), timeout=0.5
        )
        icap_server.shutdown()
        thread.join(timeout=1)

    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 200 OK" in response
    assert b"GET /asset.js HTTP/1.1" not in response
    assert b"5\r\nhello\r\n0\r\n\r\n" in response


def test_null_body_respmod_with_req_hdr_replays_only_response_header() -> None:
    server = _load_server()

    class FailOpenServer(server.ClamAvRespmodServer):
        def open_scan(self):
            return CleanScanner()

    with FailOpenServer(
        ("127.0.0.1", 0),
        clamd_host="127.0.0.1",
        clamd_port=3310,
        clamd_timeout=0.1,
        fail_open=True,
        max_scan_bytes=1024,
        client_timeout=0.5,
        max_connections=4,
    ) as icap_server:
        thread = _serve_in_thread(icap_server)
        port = icap_server.server_address[1]
        response = _recv_icap_response(
            port,
            _sample_null_body_respmod_request(port, allow_204=False),
            timeout=0.5,
        )
        icap_server.shutdown()
        thread.join(timeout=1)

    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"Encapsulated: res-hdr=0, null-body=" in response
    assert b"HTTP/1.1 204 No Content" in response
    assert b"GET /generate_204 HTTP/1.1" not in response
    assert not response.endswith(b"0\r\n\r\n")


def test_null_body_respmod_with_allow_204_uses_safe_no_content_verdict() -> None:
    server = _load_server()

    class FailOpenServer(server.ClamAvRespmodServer):
        def open_scan(self):
            return CleanScanner()

    with FailOpenServer(
        ("127.0.0.1", 0),
        clamd_host="127.0.0.1",
        clamd_port=3310,
        clamd_timeout=0.1,
        fail_open=True,
        max_scan_bytes=1024,
        client_timeout=0.5,
        max_connections=4,
    ) as icap_server:
        thread = _serve_in_thread(icap_server)
        port = icap_server.server_address[1]
        response = _recv_icap_response(
            port,
            _sample_null_body_respmod_request(port, allow_204=True),
            timeout=0.5,
        )
        icap_server.shutdown()
        thread.join(timeout=1)

    assert response.startswith(b"ICAP/1.0 204 No Content\r\n")


def test_duplicate_encapsulated_header_is_rejected_before_boundary_selection() -> None:
    server = _load_server()

    class FailClosedServer(server.ClamAvRespmodServer):
        def scan_body(self, body: bytes):
            assert body == b""
            return server.ClamdResult(clean=True)

    with FailClosedServer(
        ("127.0.0.1", 0),
        clamd_host="127.0.0.1",
        clamd_port=3310,
        clamd_timeout=0.1,
        fail_open=False,
        max_scan_bytes=1024,
        client_timeout=0.5,
        max_connections=4,
    ) as icap_server:
        thread = _serve_in_thread(icap_server)
        port = icap_server.server_address[1]
        request = _sample_respmod_request(port).replace(
            b"Encapsulated: res-hdr=0, res-body=64\r\n",
            b"Encapsulated: res-hdr=0, res-body=64\r\n"
            b"Encapsulated: res-hdr=0, null-body=0\r\n",
        )
        response = _recv_icap_response(port, request, timeout=0.5)
        icap_server.shutdown()
        thread.join(timeout=1)

    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 502 Bad Gateway" in response
    assert b"duplicate ICAP Encapsulated header" in response


def test_duplicate_encapsulated_section_name_is_rejected_before_scanning() -> None:
    server = _load_server()
    scan_attempts = 0

    class FailClosedServer(server.ClamAvRespmodServer):
        def open_scan(self):
            nonlocal scan_attempts
            scan_attempts += 1
            return CleanScanner()

    with FailClosedServer(
        ("127.0.0.1", 0),
        clamd_host="127.0.0.1",
        clamd_port=3310,
        clamd_timeout=0.1,
        fail_open=False,
        max_scan_bytes=1024,
        client_timeout=0.5,
        max_connections=4,
    ) as icap_server:
        thread = _serve_in_thread(icap_server)
        port = icap_server.server_address[1]
        request = _sample_respmod_request(port).replace(
            b"Encapsulated: res-hdr=0, res-body=64",
            b"Encapsulated: res-hdr=999, res-hdr=0, res-body=64",
        )
        response = _recv_icap_response(port, request, timeout=0.5)
        icap_server.shutdown()
        thread.join(timeout=1)

    assert scan_attempts == 0
    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 502 Bad Gateway" in response
    assert b"duplicate Encapsulated section name: res-hdr" in response
    assert b"5\r\nhello\r\n0\r\n\r\n" not in response


def test_respmod_res_hdr_offset_inside_req_hdr_rejected_before_scanning() -> None:
    server = _load_server()
    scan_attempts = 0

    class FailClosedServer(server.ClamAvRespmodServer):
        def open_scan(self):
            nonlocal scan_attempts
            scan_attempts += 1
            return CleanScanner()

    with FailClosedServer(
        ("127.0.0.1", 0),
        clamd_host="127.0.0.1",
        clamd_port=3310,
        clamd_timeout=0.1,
        fail_open=False,
        max_scan_bytes=1024,
        client_timeout=0.5,
        max_connections=4,
    ) as icap_server:
        thread = _serve_in_thread(icap_server)
        port = icap_server.server_address[1]
        request = _sample_respmod_request_with_req_hdr(port).replace(
            b"Encapsulated: req-hdr=0, res-hdr=46, res-body=122",
            b"Encapsulated: req-hdr=0, res-hdr=5, res-body=122",
        )
        response = _recv_icap_response(port, request, timeout=0.5)
        icap_server.shutdown()
        thread.join(timeout=1)

    assert scan_attempts == 0
    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 502 Bad Gateway" in response
    assert b"invalid RESPMOD encapsulated req-hdr boundary" in response
    assert b"/asset.js HTTP/1.1" not in response


def test_respmod_body_offset_inside_response_header_rejected_before_scanning() -> None:
    server = _load_server()
    scan_attempts = 0

    class FailClosedServer(server.ClamAvRespmodServer):
        def open_scan(self):
            nonlocal scan_attempts
            scan_attempts += 1
            return CleanScanner()

    with FailClosedServer(
        ("127.0.0.1", 0),
        clamd_host="127.0.0.1",
        clamd_port=3310,
        clamd_timeout=0.1,
        fail_open=False,
        max_scan_bytes=1024,
        client_timeout=0.5,
        max_connections=4,
    ) as icap_server:
        thread = _serve_in_thread(icap_server)
        port = icap_server.server_address[1]
        request = _sample_respmod_request(port).replace(
            b"Encapsulated: res-hdr=0, res-body=64",
            b"Encapsulated: res-hdr=0, res-body=20",
        )
        response = _recv_icap_response(port, request, timeout=0.5)
        icap_server.shutdown()
        thread.join(timeout=1)

    assert scan_attempts == 0
    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 502 Bad Gateway" in response
    assert b"invalid RESPMOD encapsulated res-hdr boundary" in response


def test_respmod_huge_terminal_offset_with_short_eof_payload_is_bounded() -> None:
    server = _load_server()
    scan_attempts = 0

    class FailClosedServer(server.ClamAvRespmodServer):
        def open_scan(self):
            nonlocal scan_attempts
            scan_attempts += 1
            return CleanScanner()

    with FailClosedServer(
        ("127.0.0.1", 0),
        clamd_host="127.0.0.1",
        clamd_port=3310,
        clamd_timeout=0.1,
        fail_open=False,
        max_scan_bytes=1024,
        client_timeout=0.5,
        max_connections=4,
    ) as icap_server:
        thread = _serve_in_thread(icap_server)
        port = icap_server.server_address[1]
        huge_offset = server.DEFAULT_MAX_HEADER_BYTES + 1
        request = _sample_respmod_request(port).replace(
            b"Encapsulated: res-hdr=0, res-body=64",
            f"Encapsulated: res-hdr=0, res-body={huge_offset}".encode("ascii"),
        )
        response = _recv_icap_response(port, request, timeout=0.5)
        icap_server.shutdown()
        thread.join(timeout=1)

    assert scan_attempts == 0
    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 502 Bad Gateway" in response
    assert b"RESPMOD encapsulated headers exceed" in response


def test_respmod_truncated_res_hdr_before_declared_terminal_offset_is_bounded() -> None:
    server = _load_server()
    scan_attempts = 0

    class FailClosedServer(server.ClamAvRespmodServer):
        def open_scan(self):
            nonlocal scan_attempts
            scan_attempts += 1
            return CleanScanner()

    with FailClosedServer(
        ("127.0.0.1", 0),
        clamd_host="127.0.0.1",
        clamd_port=3310,
        clamd_timeout=0.1,
        fail_open=False,
        max_scan_bytes=1024,
        client_timeout=0.5,
        max_connections=4,
    ) as icap_server:
        thread = _serve_in_thread(icap_server)
        port = icap_server.server_address[1]
        huge_offset = server.DEFAULT_MAX_HEADER_BYTES + 1
        request = (
            (
                f"RESPMOD icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
                "Host: 127.0.0.1\r\n"
                f"Encapsulated: res-hdr=0, res-body={huge_offset}\r\n\r\n"
            ).encode("ascii")
            + b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"
        )
        response = _recv_icap_response(port, request, timeout=0.5)
        icap_server.shutdown()
        thread.join(timeout=1)

    assert scan_attempts == 0
    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 502 Bad Gateway" in response
    assert b"RESPMOD encapsulated headers exceed" in response


def test_respmod_truncated_req_hdr_res_hdr_combination_is_bounded() -> None:
    server = _load_server()
    scan_attempts = 0

    class FailClosedServer(server.ClamAvRespmodServer):
        def open_scan(self):
            nonlocal scan_attempts
            scan_attempts += 1
            return CleanScanner()

    with FailClosedServer(
        ("127.0.0.1", 0),
        clamd_host="127.0.0.1",
        clamd_port=3310,
        clamd_timeout=0.1,
        fail_open=False,
        max_scan_bytes=1024,
        client_timeout=0.5,
        max_connections=4,
    ) as icap_server:
        thread = _serve_in_thread(icap_server)
        port = icap_server.server_address[1]
        request_header = b"GET /asset.js HTTP/1.1\r\nHost: example.test\r\n\r\n"
        huge_offset = server.DEFAULT_MAX_HEADER_BYTES + 1
        request = (
            (
                f"RESPMOD icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
                "Host: 127.0.0.1\r\n"
                "Encapsulated: "
                f"req-hdr=0, res-hdr={len(request_header)}, "
                f"res-body={huge_offset}\r\n\r\n"
            ).encode("ascii")
            + request_header
            + b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"
        )
        response = _recv_icap_response(port, request, timeout=0.5)
        icap_server.shutdown()
        thread.join(timeout=1)

    assert scan_attempts == 0
    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 502 Bad Gateway" in response
    assert b"RESPMOD encapsulated headers exceed" in response


def test_respmod_scanner_not_opened_before_complete_validated_headers() -> None:
    server = _load_server()
    scan_attempts = 0

    class FailClosedServer(server.ClamAvRespmodServer):
        def open_scan(self):
            nonlocal scan_attempts
            scan_attempts += 1
            return CleanScanner()

    with FailClosedServer(
        ("127.0.0.1", 0),
        clamd_host="127.0.0.1",
        clamd_port=3310,
        clamd_timeout=0.1,
        fail_open=False,
        max_scan_bytes=1024,
        client_timeout=0.5,
        max_connections=4,
    ) as icap_server:
        thread = _serve_in_thread(icap_server)
        port = icap_server.server_address[1]
        response_header = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"
        request = (
            (
                f"RESPMOD icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
                "Host: 127.0.0.1\r\n"
                f"Encapsulated: res-hdr=0, res-body={len(response_header)}\r\n\r\n"
            ).encode("ascii")
            + response_header
            + b"5\r\nhello\r\n0\r\n\r\n"
        )
        response = _recv_icap_response(port, request, timeout=0.5)
        icap_server.shutdown()
        thread.join(timeout=1)

    assert scan_attempts == 0
    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 502 Bad Gateway" in response
    assert b"invalid RESPMOD encapsulated res-hdr boundary" in response


def test_respmod_unknown_section_token_rejected_before_scanning() -> None:
    server = _load_server()
    scan_attempts = 0

    class FailClosedServer(server.ClamAvRespmodServer):
        def open_scan(self):
            nonlocal scan_attempts
            scan_attempts += 1
            return CleanScanner()

    with FailClosedServer(
        ("127.0.0.1", 0),
        clamd_host="127.0.0.1",
        clamd_port=3310,
        clamd_timeout=0.1,
        fail_open=False,
        max_scan_bytes=1024,
        client_timeout=0.5,
        max_connections=4,
    ) as icap_server:
        thread = _serve_in_thread(icap_server)
        port = icap_server.server_address[1]
        request = _sample_respmod_request(port).replace(
            b"Encapsulated: res-hdr=0, res-body=64",
            b"Encapsulated: res-hdr=0, bogus=0, res-body=64",
        )
        response = _recv_icap_response(port, request, timeout=0.5)
        icap_server.shutdown()
        thread.join(timeout=1)

    assert scan_attempts == 0
    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 502 Bad Gateway" in response
    assert b"unknown Encapsulated section token: bogus" in response


def test_single_encapsulated_header_with_null_body_is_preserved() -> None:
    server = _load_server()

    class CleanServer(server.ClamAvRespmodServer):
        def scan_body(self, body: bytes):
            assert body == b""
            return server.ClamdResult(clean=True)

    with CleanServer(
        ("127.0.0.1", 0),
        clamd_host="127.0.0.1",
        clamd_port=3310,
        clamd_timeout=0.1,
        fail_open=False,
        max_scan_bytes=1024,
        client_timeout=0.5,
        max_connections=4,
    ) as icap_server:
        thread = _serve_in_thread(icap_server)
        port = icap_server.server_address[1]
        response = _recv_icap_response(
            port,
            _sample_null_body_respmod_request(port, allow_204=False),
            timeout=0.5,
        )
        icap_server.shutdown()
        thread.join(timeout=1)

    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"Encapsulated: res-hdr=0, null-body=" in response
    assert b"HTTP/1.1 204 No Content" in response


def test_respmod_without_res_hdr_is_rejected_before_empty_body_scan() -> None:
    server = _load_server()
    scanned_bodies: list[bytes] = []

    class FailClosedServer(server.ClamAvRespmodServer):
        def scan_body(self, body: bytes):
            scanned_bodies.append(body)
            return server.ClamdResult(clean=True)

    with FailClosedServer(
        ("127.0.0.1", 0),
        clamd_host="127.0.0.1",
        clamd_port=3310,
        clamd_timeout=0.1,
        fail_open=False,
        max_scan_bytes=1024,
        client_timeout=0.5,
        max_connections=4,
    ) as icap_server:
        thread = _serve_in_thread(icap_server)
        port = icap_server.server_address[1]
        request = _sample_null_body_respmod_request(port, allow_204=False).replace(
            b"req-hdr=0, res-hdr=67, null-body=156",
            b"req-hdr=0, null-body=156",
        )
        response = _recv_icap_response(port, request, timeout=0.5)
        icap_server.shutdown()
        thread.join(timeout=1)

    assert scanned_bodies == []
    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 502 Bad Gateway" in response
    assert b"RESPMOD request missing res-hdr" in response


def test_respmod_body_before_res_hdr_is_rejected_before_scanning() -> None:
    server = _load_server()
    scan_attempts = 0

    class FailClosedServer(server.ClamAvRespmodServer):
        def open_scan(self):
            nonlocal scan_attempts
            scan_attempts += 1
            return CleanScanner()

    with FailClosedServer(
        ("127.0.0.1", 0),
        clamd_host="127.0.0.1",
        clamd_port=3310,
        clamd_timeout=0.1,
        fail_open=False,
        max_scan_bytes=1024,
        client_timeout=0.5,
        max_connections=4,
    ) as icap_server:
        thread = _serve_in_thread(icap_server)
        port = icap_server.server_address[1]
        request = _sample_respmod_request_with_req_hdr(port).replace(
            b"Encapsulated: req-hdr=0, res-hdr=46, res-body=122",
            b"Encapsulated: req-hdr=0, res-body=46, res-hdr=122",
        )
        response = _recv_icap_response(port, request, timeout=0.5)
        icap_server.shutdown()
        thread.join(timeout=1)

    assert scan_attempts == 0
    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 502 Bad Gateway" in response
    assert b"invalid RESPMOD encapsulated response offsets" in response


def test_respmod_negative_offset_is_rejected_before_scanning() -> None:
    server = _load_server()
    scan_attempts = 0

    class FailClosedServer(server.ClamAvRespmodServer):
        def open_scan(self):
            nonlocal scan_attempts
            scan_attempts += 1
            return CleanScanner()

    with FailClosedServer(
        ("127.0.0.1", 0),
        clamd_host="127.0.0.1",
        clamd_port=3310,
        clamd_timeout=0.1,
        fail_open=False,
        max_scan_bytes=1024,
        client_timeout=0.5,
        max_connections=4,
    ) as icap_server:
        thread = _serve_in_thread(icap_server)
        port = icap_server.server_address[1]
        request = _sample_respmod_request(port).replace(
            b"Encapsulated: res-hdr=0, res-body=64",
            b"Encapsulated: res-hdr=-1, res-body=64",
        )
        response = _recv_icap_response(port, request, timeout=0.5)
        icap_server.shutdown()
        thread.join(timeout=1)

    assert scan_attempts == 0
    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 502 Bad Gateway" in response
    assert b"negative Encapsulated offset" in response


def test_respmod_nonzero_res_hdr_without_req_hdr_is_rejected() -> None:
    server = _load_server()
    scan_attempts = 0

    class FailClosedServer(server.ClamAvRespmodServer):
        def open_scan(self):
            nonlocal scan_attempts
            scan_attempts += 1
            return CleanScanner()

    with FailClosedServer(
        ("127.0.0.1", 0),
        clamd_host="127.0.0.1",
        clamd_port=3310,
        clamd_timeout=0.1,
        fail_open=False,
        max_scan_bytes=1024,
        client_timeout=0.5,
        max_connections=4,
    ) as icap_server:
        thread = _serve_in_thread(icap_server)
        port = icap_server.server_address[1]
        request = _sample_respmod_request(port).replace(
            b"Encapsulated: res-hdr=0, res-body=64",
            b"Encapsulated: res-hdr=1, res-body=64",
        )
        response = _recv_icap_response(port, request, timeout=0.5)
        icap_server.shutdown()
        thread.join(timeout=1)

    assert scan_attempts == 0
    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 502 Bad Gateway" in response
    assert b"RESPMOD res-hdr offset must be zero without req-hdr" in response


def test_malformed_respmod_start_line_rejects_before_scanning() -> None:
    server = _load_server()
    scan_attempts = 0

    class FailClosedServer(server.ClamAvRespmodServer):
        def open_scan(self):
            nonlocal scan_attempts
            scan_attempts += 1
            return CleanScanner()

    with FailClosedServer(
        ("127.0.0.1", 0),
        clamd_host="127.0.0.1",
        clamd_port=3310,
        clamd_timeout=0.1,
        fail_open=False,
        max_scan_bytes=1024,
        client_timeout=0.5,
        max_connections=4,
    ) as icap_server:
        thread = _serve_in_thread(icap_server)
        port = icap_server.server_address[1]
        response = _recv_icap_response(
            port,
            _replace_request_start_line(
                _sample_respmod_request(port),
                f"RESPMOD icap://127.0.0.1:{port}/avrespmod ICAP/2.0".encode(
                    "ascii"
                ),
            ),
            timeout=0.5,
        )
        icap_server.shutdown()
        thread.join(timeout=1)

    assert scan_attempts == 0
    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 502 Bad Gateway" in response
    assert b"unsupported ICAP version" in response


def test_clean_icap_responses_close_connections_to_prevent_reuse_races() -> None:
    server = _load_server()

    options = server.options_response()
    clean = server.clean_response(
        allow_204=True, http_header=b"HTTP/1.1 200 OK\r\n\r\n", body=b"clean"
    )
    replay = server.clean_response(
        allow_204=False, http_header=b"HTTP/1.1 200 OK\r\n\r\n", body=b"clean"
    )

    assert b"Connection: close\r\n" in options
    assert b"Connection: close\r\n" in clean
    assert b"Connection: close\r\n" in replay


def test_burst_respmod_requests_close_each_exchange_and_succeed() -> None:
    server = _load_server()

    class FailOpenServer(server.ClamAvRespmodServer):
        def open_scan(self):
            return CleanScanner()

    with FailOpenServer(
        ("127.0.0.1", 0),
        clamd_host="127.0.0.1",
        clamd_port=3310,
        clamd_timeout=0.1,
        fail_open=True,
        max_scan_bytes=1024,
        client_timeout=0.5,
        max_connections=16,
        max_scans=4,
    ) as icap_server:
        thread = _serve_in_thread(icap_server)
        port = icap_server.server_address[1]
        responses: list[bytes] = []
        workers = [
            threading.Thread(
                target=lambda index=index: responses.append(
                    _recv_icap_response(
                        port,
                        _sample_respmod_request(port).replace(
                            b"hello", f"h{index:04d}".encode("ascii")
                        ),
                        timeout=1.0,
                    )
                )
            )
            for index in range(24)
        ]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=2)
        icap_server.shutdown()
        thread.join(timeout=1)

    assert len(responses) == 24
    assert all(
        response.startswith(b"ICAP/1.0 200 OK\r\n") for response in responses
    )
    assert all(b"Connection: close\r\n" in response for response in responses)


def test_blocked_icap_response_contains_detection() -> None:
    server = _load_server()

    response = server.blocked_response("Eicar-Test-Signature")

    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 403 Forbidden" in response
    assert b"Eicar-Test-Signature" in response


def test_respmod_default_clamd_timeout_is_bounded_for_fail_open_browsing() -> None:
    server = _load_server()

    args = server._parse_args([])

    assert args.clamd_timeout == 5


def _serve_in_thread(icap_server):
    thread = threading.Thread(target=icap_server.serve_forever, daemon=True)
    thread.start()
    return thread


def _recv_icap_response(port: int, request: bytes, *, timeout: float = 1.0) -> bytes:
    with CLIENT_CREATE_CONNECTION(("127.0.0.1", port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(request)
        return sock.recv(4096)


def _recv_icap_exchange(port: int, request: bytes, *, timeout: float = 1.0) -> bytes:
    response = bytearray()
    with CLIENT_CREATE_CONNECTION(("127.0.0.1", port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(request)
        while True:
            try:
                chunk = sock.recv(4096)
            except TimeoutError:
                break
            if not chunk:
                break
            response.extend(chunk)
    return bytes(response)


def _recv_icap_exchange_state(
    port: int, request: bytes, *, timeout: float = 1.0
) -> tuple[bytes, bool]:
    response = bytearray()
    with CLIENT_CREATE_CONNECTION(("127.0.0.1", port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(request)
        while True:
            try:
                chunk = sock.recv(4096)
            except TimeoutError:
                return bytes(response), False
            if not chunk:
                return bytes(response), True
            response.extend(chunk)


def _options_request(port: int) -> bytes:
    return (
        f"OPTIONS icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
        "Host: 127.0.0.1\r\n"
        "Encapsulated: null-body=0\r\n\r\n"
    ).encode("ascii")


def _replace_request_start_line(request: bytes, start_line: bytes) -> bytes:
    return start_line + request[request.index(b"\r\n") :]


def _sample_respmod_request(port: int) -> bytes:
    body = b"hello"
    http_header = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        + f"Content-Length: {len(body)}\r\n".encode("ascii")
        + b"\r\n"
    )
    chunked_body = b"5\r\n" + body + b"\r\n0\r\n\r\n"
    return (
        (
            f"RESPMOD icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
            "Host: 127.0.0.1\r\n"
            "Allow: 204\r\n"
            f"Encapsulated: res-hdr=0, res-body={len(http_header)}\r\n\r\n"
        ).encode("ascii")
        + http_header
        + chunked_body
    )


def _sample_unknown_length_respmod_request(port: int) -> bytes:
    http_header = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"
    body = b"hello"
    chunked_body = b"5\r\n" + body + b"\r\n0\r\n\r\n"
    return (
        (
            f"RESPMOD icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
            "Host: 127.0.0.1\r\n"
            "Allow: 204\r\n"
            f"Encapsulated: res-hdr=0, res-body={len(http_header)}\r\n\r\n"
        ).encode("ascii")
        + http_header
        + chunked_body
    )


def _sample_chunked_respmod_request(port: int) -> bytes:
    http_header = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n"
    )
    body = b"hello"
    chunked_body = b"5\r\n" + body + b"\r\n0\r\n\r\n"
    return (
        (
            f"RESPMOD icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
            "Host: 127.0.0.1\r\n"
            "Allow: 204\r\n"
            f"Encapsulated: res-hdr=0, res-body={len(http_header)}\r\n\r\n"
        ).encode("ascii")
        + http_header
        + chunked_body
    )


def _sample_respmod_request_without_allow_204(port: int) -> bytes:
    return _sample_respmod_request(port).replace(b"Allow: 204\r\n", b"")


def _sample_respmod_request_with_req_hdr(port: int) -> bytes:
    request_header = b"GET /asset.js HTTP/1.1\r\nHost: example.test\r\n\r\n"
    body = b"hello"
    http_header = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/javascript\r\n"
        + f"Content-Length: {len(body)}\r\n".encode("ascii")
        + b"\r\n"
    )
    response_offset = len(request_header)
    body_offset = response_offset + len(http_header)
    chunked_body = b"5\r\n" + body + b"\r\n0\r\n\r\n"
    return (
        (
            f"RESPMOD icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
            "Host: 127.0.0.1\r\n"
            "Allow: 204\r\n"
            "Encapsulated: "
            f"req-hdr=0, res-hdr={response_offset}, res-body={body_offset}"
            "\r\n\r\n"
        ).encode("ascii")
        + request_header
        + http_header
        + chunked_body
    )


def _sample_preview_respmod_request(port: int) -> bytes:
    http_header = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"Content-Length: 5\r\n\r\n"
    )
    preview_body = b"2\r\nhe\r\n0\r\n\r\n3\r\nllo\r\n0\r\n\r\n"
    return (
        (
            f"RESPMOD icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
            "Host: 127.0.0.1\r\n"
            "Allow: 204\r\n"
            "Preview: 2\r\n"
            f"Encapsulated: res-hdr=0, res-body={len(http_header)}\r\n\r\n"
        ).encode("ascii")
        + http_header
        + preview_body
    )


def _sample_null_body_respmod_request(port: int, *, allow_204: bool = True) -> bytes:
    request_header = (
        b"GET /generate_204 HTTP/1.1\r\n"
        b"Host: connectivitycheck.gstatic.com\r\n\r\n"
    )
    response_header = (
        b"HTTP/1.1 204 No Content\r\n"
        b"Date: Sun, 19 Jul 2026 16:36:00 GMT\r\n"
        b"Cache-Control: no-store\r\n\r\n"
    )
    response_offset = len(request_header)
    null_offset = response_offset + len(response_header)
    allow = "Allow: 204\r\n" if allow_204 else ""
    return (
        (
            f"RESPMOD icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
            "Host: 127.0.0.1\r\n"
            f"{allow}"
            "Encapsulated: "
            f"req-hdr=0, res-hdr={response_offset}, null-body={null_offset}"
            "\r\n\r\n"
        ).encode("ascii")
        + request_header
        + response_header
    )


class CleanScanner:
    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def send_chunk(self, _data: bytes) -> None:
        pass

    def finish(self):
        server = _load_server()
        return server.ClamdResult(clean=True)


class RecordingScanner(CleanScanner):
    def __init__(self) -> None:
        self.chunks: list[bytes] = []
        self.closed = False
        self.finished = False

    def __exit__(self, *_exc):
        self.closed = True
        return False

    def send_chunk(self, data: bytes) -> None:
        self.chunks.append(data)

    def finish(self):
        self.finished = True
        return super().finish()


class SlowScanner(CleanScanner):
    def finish(self):
        message = "clamd INSTREAM scan timed out"
        raise TimeoutError(message)


class FailingSendAfterPreviewScanner(CleanScanner):
    def __init__(self) -> None:
        self.chunks = 0

    def send_chunk(self, _data: bytes) -> None:
        self.chunks += 1
        if self.chunks > 1:
            message = "clamd closed after UNKNOWN COMMAND"
            raise BrokenPipeError(message)


class BlockingFakeSocket(FakeSocket):
    def __init__(
        self,
        *,
        blocked: threading.Event,
        release: threading.Event,
    ) -> None:
        super().__init__()
        self.blocked = blocked
        self.release = release

    def recv(self, _size: int) -> bytes:
        self.blocked.set()
        if not self.release.wait(timeout=1):
            message = "fake clamd did not release"
            raise TimeoutError(message)
        return self.response


def test_options_response_is_immediate_while_client_keeps_connection_open() -> None:
    server = _load_server()

    with server.ClamAvRespmodServer(
        ("127.0.0.1", 0),
        clamd_host="127.0.0.1",
        clamd_port=3310,
        clamd_timeout=0.1,
        fail_open=True,
        max_scan_bytes=1024,
        client_timeout=0.5,
        max_connections=4,
    ) as icap_server:
        thread = _serve_in_thread(icap_server)
        port = icap_server.server_address[1]
        response = _recv_icap_response(port, _options_request(port), timeout=0.5)
        icap_server.shutdown()
        thread.join(timeout=1)

    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"Encapsulated: null-body=0" in response


def test_partial_client_times_out_and_releases_listener_capacity() -> None:
    server = _load_server()

    with server.ClamAvRespmodServer(
        ("127.0.0.1", 0),
        clamd_host="127.0.0.1",
        clamd_port=3310,
        clamd_timeout=0.1,
        fail_open=True,
        max_scan_bytes=1024,
        client_timeout=0.1,
        max_connections=1,
    ) as icap_server:
        thread = _serve_in_thread(icap_server)
        port = icap_server.server_address[1]
        slow = socket.create_connection(("127.0.0.1", port), timeout=0.5)
        try:
            slow.sendall(b"OPT")
            time.sleep(0.2)
            response = _recv_icap_response(port, _options_request(port), timeout=0.5)
        finally:
            slow.close()
            icap_server.shutdown()
            thread.join(timeout=1)

    assert response.startswith(b"ICAP/1.0 200 OK\r\n")


def test_concurrent_options_requests_do_not_touch_clamd() -> None:
    server = _load_server()

    with server.ClamAvRespmodServer(
        ("127.0.0.1", 0),
        clamd_host="127.0.0.1",
        clamd_port=3310,
        clamd_timeout=0.1,
        fail_open=True,
        max_scan_bytes=1024,
        client_timeout=0.5,
        max_connections=16,
    ) as icap_server:
        thread = _serve_in_thread(icap_server)
        port = icap_server.server_address[1]
        responses: list[bytes] = []
        workers = [
            threading.Thread(
                target=lambda: responses.append(
                    _recv_icap_response(port, _options_request(port), timeout=0.5),
                ),
            )
            for _ in range(8)
        ]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=1)
        icap_server.shutdown()
        thread.join(timeout=1)

    assert len(responses) == 8
    assert all(response.startswith(b"ICAP/1.0 200 OK\r\n") for response in responses)


def test_slow_clamd_scan_fails_open_with_bounded_204() -> None:
    server = _load_server()

    class FailOpenServer(server.ClamAvRespmodServer):
        def open_scan(self):
            return SlowScanner()

    with FailOpenServer(
        ("127.0.0.1", 0),
        clamd_host="127.0.0.1",
        clamd_port=3310,
        clamd_timeout=0.1,
        fail_open=True,
        max_scan_bytes=1024,
        client_timeout=0.5,
        max_connections=4,
    ) as icap_server:
        thread = _serve_in_thread(icap_server)
        port = icap_server.server_address[1]
        response = _recv_icap_response(port, _sample_respmod_request(port), timeout=0.5)
        icap_server.shutdown()
        thread.join(timeout=1)

    assert response.startswith(b"ICAP/1.0 204 No Content\r\n")


def test_scan_finish_failure_without_allow_204_replays_clean_response() -> None:
    server = _load_server()

    class FailOpenServer(server.ClamAvRespmodServer):
        def open_scan(self):
            return SlowScanner()

    with FailOpenServer(
        ("127.0.0.1", 0),
        clamd_host="127.0.0.1",
        clamd_port=3310,
        clamd_timeout=0.1,
        fail_open=True,
        max_scan_bytes=1024,
        client_timeout=0.5,
        max_connections=4,
    ) as icap_server:
        thread = _serve_in_thread(icap_server)
        port = icap_server.server_address[1]
        response = _recv_icap_response(
            port, _sample_respmod_request_without_allow_204(port), timeout=0.5
        )
        icap_server.shutdown()
        thread.join(timeout=1)

    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 200 OK" in response
    assert b"5\r\nhello\r\n0\r\n\r\n" in response


def test_post_preview_scan_write_failure_fails_open_after_100_continue() -> None:
    server = _load_server()

    class FailOpenServer(server.ClamAvRespmodServer):
        def open_scan(self):
            return FailingSendAfterPreviewScanner()

    with FailOpenServer(
        ("127.0.0.1", 0),
        clamd_host="127.0.0.1",
        clamd_port=3310,
        clamd_timeout=0.1,
        fail_open=True,
        max_scan_bytes=1024,
        client_timeout=0.5,
        max_connections=4,
    ) as icap_server:
        thread = _serve_in_thread(icap_server)
        port = icap_server.server_address[1]
        response = _recv_icap_exchange(
            port, _sample_preview_respmod_request(port), timeout=0.5
        )
        icap_server.shutdown()
        thread.join(timeout=1)

    assert response.startswith(b"ICAP/1.0 100 Continue\r\n\r\n")
    assert b"ICAP/1.0 204 No Content\r\n" in response


def test_preview_terminator_without_ieof_eof_after_continue_is_not_clean_fail_open() -> None:
    server = _load_server()
    scanner = RecordingScanner()

    class FailOpenServer(server.ClamAvRespmodServer):
        def open_scan(self):
            return scanner

    with FailOpenServer(
        ("127.0.0.1", 0),
        clamd_host="127.0.0.1",
        clamd_port=3310,
        clamd_timeout=0.1,
        fail_open=True,
        max_scan_bytes=1024,
        client_timeout=0.2,
        max_connections=4,
    ) as icap_server:
        thread = _serve_in_thread(icap_server)
        port = icap_server.server_address[1]
        request = _sample_preview_respmod_request(port).replace(
            b"2\r\nhe\r\n0\r\n\r\n3\r\nllo\r\n0\r\n\r\n",
            b"2\r\nhe\r\n0\r\n\r\n",
        )
        response = _recv_icap_exchange(port, request, timeout=1)
        icap_server.shutdown()
        thread.join(timeout=1)

    assert scanner.closed is True
    assert scanner.chunks == [b"he"]
    assert scanner.finished is False
    assert response.startswith(b"ICAP/1.0 100 Continue\r\n\r\n")
    assert b"ICAP/1.0 200 OK\r\n" in response
    assert b"HTTP/1.1 502 Bad Gateway" in response
    assert b"he\r\n0\r\n\r\n" not in response


def test_duplicate_preview_zero_terminator_does_not_cleanly_replay_partial_body() -> None:
    server = _load_server()
    scanner = RecordingScanner()

    class FailOpenServer(server.ClamAvRespmodServer):
        def open_scan(self):
            return scanner

    with FailOpenServer(
        ("127.0.0.1", 0),
        clamd_host="127.0.0.1",
        clamd_port=3310,
        clamd_timeout=0.1,
        fail_open=True,
        max_scan_bytes=1024,
        client_timeout=0.5,
        max_connections=4,
    ) as icap_server:
        thread = _serve_in_thread(icap_server)
        port = icap_server.server_address[1]
        request = _sample_preview_respmod_request(port).replace(
            b"2\r\nhe\r\n0\r\n\r\n3\r\nllo\r\n0\r\n\r\n",
            b"2\r\nhe\r\n0\r\n\r\n0\r\n\r\n3\r\nllo\r\n0\r\n\r\n",
        )
        response = _recv_icap_exchange(port, request, timeout=1)
        icap_server.shutdown()
        thread.join(timeout=1)

    assert scanner.closed is True
    assert scanner.chunks == [b"he"]
    assert scanner.finished is False
    assert response.startswith(b"ICAP/1.0 100 Continue\r\n\r\n")
    assert b"ICAP/1.0 200 OK\r\n" in response
    assert b"HTTP/1.1 502 Bad Gateway" in response
    assert b"2\r\nhe\r\n0\r\n\r\n" not in response


def test_malformed_zero_chunk_trailer_after_valid_chunk_fails_closed() -> None:
    server = _load_server()
    scanner = RecordingScanner()

    class FailOpenServer(server.ClamAvRespmodServer):
        def open_scan(self):
            return scanner

    with FailOpenServer(
        ("127.0.0.1", 0),
        clamd_host="127.0.0.1",
        clamd_port=3310,
        clamd_timeout=0.1,
        fail_open=True,
        max_scan_bytes=1024,
        client_timeout=0.5,
        max_connections=4,
    ) as icap_server:
        thread = _serve_in_thread(icap_server)
        port = icap_server.server_address[1]
        request = _sample_respmod_request(port).replace(
            b"5\r\nhello\r\n0\r\n\r\n",
            b"5\r\nhello\r\n0\r\nnot-a-trailer\r\n\r\n",
        )
        response = _recv_icap_exchange(port, request, timeout=1)
        icap_server.shutdown()
        thread.join(timeout=1)

    assert scanner.closed is True
    assert scanner.chunks == [b"hello"]
    assert scanner.finished is False
    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 502 Bad Gateway" in response
    assert b"scan failed before complete response body" in response
    assert b"5\r\nhello\r\n0\r\n\r\n" not in response


def test_respmod_preview_ieof_rejects_extra_chunk_without_clean_replay() -> None:
    server = _load_server()
    scanner = RecordingScanner()

    class FailOpenServer(server.ClamAvRespmodServer):
        def open_scan(self):
            return scanner

    with FailOpenServer(
        ("127.0.0.1", 0),
        clamd_host="127.0.0.1",
        clamd_port=3310,
        clamd_timeout=0.1,
        fail_open=True,
        max_scan_bytes=1024,
        client_timeout=0.5,
        max_connections=4,
    ) as icap_server:
        thread = _serve_in_thread(icap_server)
        port = icap_server.server_address[1]
        request = _sample_preview_respmod_request(port).replace(
            b"2\r\nhe\r\n0\r\n\r\n3\r\nllo\r\n0\r\n\r\n",
            b"2\r\nhe\r\n0;ieof\r\n\r\n1\r\nX\r\n0\r\n\r\n",
        )
        response, closed = _recv_icap_exchange_state(port, request, timeout=1)
        icap_server.shutdown()
        thread.join(timeout=1)

    assert closed is True
    assert scanner.closed is True
    assert scanner.chunks == [b"he"]
    assert scanner.finished is False
    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 502 Bad Gateway" in response
    assert b"scan failed before complete response body" in response
    assert b"2\r\nhe\r\n0\r\n\r\n" not in response


def test_respmod_preview_ieof_rejects_arbitrary_remainder_fail_closed() -> None:
    server = _load_server()
    scanner = RecordingScanner()

    class FailClosedServer(server.ClamAvRespmodServer):
        def open_scan(self):
            return scanner

    with FailClosedServer(
        ("127.0.0.1", 0),
        clamd_host="127.0.0.1",
        clamd_port=3310,
        clamd_timeout=0.1,
        fail_open=False,
        max_scan_bytes=1024,
        client_timeout=0.5,
        max_connections=4,
    ) as icap_server:
        thread = _serve_in_thread(icap_server)
        port = icap_server.server_address[1]
        request = _sample_preview_respmod_request(port).replace(
            b"2\r\nhe\r\n0\r\n\r\n3\r\nllo\r\n0\r\n\r\n",
            b"2\r\nhe\r\n0;ieof\r\n\r\nnot-an-icap-message\r\n\r\n",
        )
        response, closed = _recv_icap_exchange_state(port, request, timeout=1)
        icap_server.shutdown()
        thread.join(timeout=1)

    assert closed is True
    assert scanner.closed is True
    assert scanner.chunks == [b"he"]
    assert scanner.finished is False
    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 502 Bad Gateway" in response
    assert b"unexpected data after terminal ICAP body" in response
    assert b"2\r\nhe\r\n0\r\n\r\n" not in response


def test_respmod_preview_ieof_rejects_pipelined_request_on_close_lifecycle() -> None:
    server = _load_server()
    scanner = RecordingScanner()

    class FailOpenServer(server.ClamAvRespmodServer):
        def open_scan(self):
            return scanner

    with FailOpenServer(
        ("127.0.0.1", 0),
        clamd_host="127.0.0.1",
        clamd_port=3310,
        clamd_timeout=0.1,
        fail_open=True,
        max_scan_bytes=1024,
        client_timeout=0.5,
        max_connections=4,
    ) as icap_server:
        thread = _serve_in_thread(icap_server)
        port = icap_server.server_address[1]
        request = _sample_preview_respmod_request(port).replace(
            b"2\r\nhe\r\n0\r\n\r\n3\r\nllo\r\n0\r\n\r\n",
            b"2\r\nhe\r\n0;ieof\r\n\r\n" + _options_request(port),
        )
        response, closed = _recv_icap_exchange_state(port, request, timeout=1)
        icap_server.shutdown()
        thread.join(timeout=1)

    assert closed is True
    assert scanner.closed is True
    assert scanner.chunks == [b"he"]
    assert scanner.finished is False
    assert response.count(b"ICAP/1.0 ") == 1
    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 502 Bad Gateway" in response
    assert b"scan failed before complete response body" in response


def test_respmod_preview_nonzero_ieof_fails_closed_without_clean_replay() -> None:
    server = _load_server()
    scanner = RecordingScanner()

    class FailOpenServer(server.ClamAvRespmodServer):
        def open_scan(self):
            return scanner

    with FailOpenServer(
        ("127.0.0.1", 0),
        clamd_host="127.0.0.1",
        clamd_port=3310,
        clamd_timeout=0.1,
        fail_open=True,
        max_scan_bytes=1024,
        client_timeout=0.5,
        max_connections=4,
    ) as icap_server:
        thread = _serve_in_thread(icap_server)
        port = icap_server.server_address[1]
        request = _sample_preview_respmod_request(port).replace(
            b"2\r\nhe\r\n0\r\n\r\n3\r\nllo\r\n0\r\n\r\n",
            b"2;ieof\r\nhe\r\n0;ieof\r\n\r\n",
        )
        response = _recv_icap_exchange(port, request, timeout=1)
        icap_server.shutdown()
        thread.join(timeout=1)

    assert scanner.closed is True
    assert scanner.chunks == []
    assert scanner.finished is False
    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 502 Bad Gateway" in response
    assert b"he\r\n0\r\n\r\n" not in response


def test_truncated_later_chunk_after_valid_chunk_fails_closed_without_partial_replay() -> None:
    server = _load_server()
    scanner = RecordingScanner()

    class FailOpenServer(server.ClamAvRespmodServer):
        def open_scan(self):
            return scanner

    with FailOpenServer(
        ("127.0.0.1", 0),
        clamd_host="127.0.0.1",
        clamd_port=3310,
        clamd_timeout=0.1,
        fail_open=True,
        max_scan_bytes=1024,
        client_timeout=0.2,
        max_connections=4,
    ) as icap_server:
        thread = _serve_in_thread(icap_server)
        port = icap_server.server_address[1]
        request = _sample_respmod_request_without_allow_204(port).replace(
            b"5\r\nhello\r\n0\r\n\r\n",
            b"2\r\nhe\r\n3\r\nll",
        )
        response = _recv_icap_response(port, request, timeout=1)
        icap_server.shutdown()
        thread.join(timeout=1)

    assert scanner.closed is True
    assert scanner.chunks == [b"he"]
    assert scanner.finished is False
    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 502 Bad Gateway" in response
    assert b"he\r\n0\r\n\r\n" not in response


def test_clamd_reset_before_verdict_drains_body_then_fails_open_204(
    monkeypatch,
) -> None:
    server = _load_server()
    fake = ResetBeforeVerdictSocket()

    monkeypatch.setattr(
        server.socket, "create_connection", lambda address, timeout: fake
    )

    with server.ClamAvRespmodServer(
        ("127.0.0.1", 0),
        clamd_host="127.0.0.1",
        clamd_port=3310,
        clamd_timeout=0.1,
        fail_open=True,
        max_scan_bytes=1024,
        client_timeout=0.5,
        max_connections=4,
    ) as icap_server:
        thread = _serve_in_thread(icap_server)
        port = icap_server.server_address[1]
        response = _recv_icap_response(port, _sample_respmod_request(port), timeout=1)
        icap_server.shutdown()
        thread.join(timeout=1)

    assert response.startswith(b"ICAP/1.0 204 No Content\r\n")
    assert fake.closed is True
    assert fake.sent.endswith(struct.pack("!I", 0))


def test_clamd_reset_mid_stream_drains_remaining_preview_then_fails_open_204(
    monkeypatch,
) -> None:
    server = _load_server()
    fake = ResetMidStreamSocket(fail_after_chunks=1)

    monkeypatch.setattr(
        server.socket, "create_connection", lambda address, timeout: fake
    )

    with server.ClamAvRespmodServer(
        ("127.0.0.1", 0),
        clamd_host="127.0.0.1",
        clamd_port=3310,
        clamd_timeout=0.1,
        fail_open=True,
        max_scan_bytes=1024,
        client_timeout=0.5,
        max_connections=4,
    ) as icap_server:
        thread = _serve_in_thread(icap_server)
        port = icap_server.server_address[1]
        response = _recv_icap_exchange(
            port, _sample_preview_respmod_request(port), timeout=1
        )
        icap_server.shutdown()
        thread.join(timeout=1)

    assert response.startswith(b"ICAP/1.0 100 Continue\r\n\r\n")
    assert b"ICAP/1.0 204 No Content\r\n" in response
    assert fake.closed is True
    assert fake._body_chunks == 2


def test_unavailable_clamd_drains_body_and_fails_open_204(monkeypatch) -> None:
    server = _load_server()

    def create_connection(_address, _timeout):
        message = "connection refused"
        raise ConnectionRefusedError(message)

    monkeypatch.setattr(server.socket, "create_connection", create_connection)

    with server.ClamAvRespmodServer(
        ("127.0.0.1", 0),
        clamd_host="127.0.0.1",
        clamd_port=3310,
        clamd_timeout=0.1,
        fail_open=True,
        max_scan_bytes=1024,
        client_timeout=0.5,
        max_connections=4,
    ) as icap_server:
        thread = _serve_in_thread(icap_server)
        port = icap_server.server_address[1]
        response = _recv_icap_exchange(
            port, _sample_preview_respmod_request(port), timeout=1
        )
        icap_server.shutdown()
        thread.join(timeout=1)

    assert response.startswith(b"ICAP/1.0 100 Continue\r\n\r\n")
    assert b"ICAP/1.0 204 No Content\r\n" in response


def test_unavailable_clamd_fail_open_stress_handles_mixed_respmod_shapes(
    monkeypatch,
) -> None:
    server = _load_server()

    def create_connection(_address, _timeout):
        message = "connection refused"
        raise ConnectionRefusedError(message)

    monkeypatch.setattr(server.socket, "create_connection", create_connection)

    with server.ClamAvRespmodServer(
        ("127.0.0.1", 0),
        clamd_host="127.0.0.1",
        clamd_port=3310,
        clamd_timeout=0.1,
        fail_open=True,
        max_scan_bytes=1024,
        client_timeout=0.5,
        max_connections=24,
        max_scans=4,
    ) as icap_server:
        thread = _serve_in_thread(icap_server)
        port = icap_server.server_address[1]

        def request_for(index: int) -> bytes:
            builders = (
                _sample_respmod_request,
                _sample_unknown_length_respmod_request,
                _sample_chunked_respmod_request,
                _sample_preview_respmod_request,
                _sample_null_body_respmod_request,
                lambda p: _sample_null_body_respmod_request(p, allow_204=False),
            )
            return builders[index % len(builders)](port)

        def fetch(index: int) -> bytes:
            request = request_for(index)
            if b"Preview:" in request:
                return _recv_icap_exchange(port, request, timeout=1)
            return _recv_icap_response(port, request, timeout=1)

        responses: list[bytes] = []
        workers = [threading.Thread(target=lambda i=i: responses.append(fetch(i))) for i in range(36)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=2)
        icap_server.shutdown()
        thread.join(timeout=1)

    assert len(responses) == 36
    assert all(b"ICAP/1.0 5" not in response for response in responses)
    assert all(b"HTTP/1.1 502 Bad Gateway" not in response for response in responses)
    assert any(response.startswith(b"ICAP/1.0 204 No Content\r\n") for response in responses)
    assert any(b"Encapsulated: res-hdr=0, null-body=" in response for response in responses)
    assert any(b"5\r\nhello\r\n0\r\n\r\n" in response for response in responses)


def test_fail_open_without_allow_204_replays_after_clamd_reset(monkeypatch) -> None:
    server = _load_server()
    fake = ResetBeforeVerdictSocket()

    monkeypatch.setattr(
        server.socket, "create_connection", lambda address, timeout: fake
    )

    with server.ClamAvRespmodServer(
        ("127.0.0.1", 0),
        clamd_host="127.0.0.1",
        clamd_port=3310,
        clamd_timeout=0.1,
        fail_open=True,
        max_scan_bytes=1024,
        client_timeout=0.5,
        max_connections=4,
    ) as icap_server:
        thread = _serve_in_thread(icap_server)
        port = icap_server.server_address[1]
        response = _recv_icap_response(
            port, _sample_respmod_request_without_allow_204(port), timeout=1
        )
        icap_server.shutdown()
        thread.join(timeout=1)

    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 200 OK" in response
    assert b"5\r\nhello\r\n0\r\n\r\n" in response


def test_infected_verdict_blocks_after_complete_body(monkeypatch) -> None:
    server = _load_server()
    fake = FakeSocket(b"stream: Eicar-Test-Signature FOUND\0")

    monkeypatch.setattr(
        server.socket, "create_connection", lambda address, timeout: fake
    )

    with server.ClamAvRespmodServer(
        ("127.0.0.1", 0),
        clamd_host="127.0.0.1",
        clamd_port=3310,
        clamd_timeout=0.1,
        fail_open=True,
        max_scan_bytes=1024,
        client_timeout=0.5,
        max_connections=4,
    ) as icap_server:
        thread = _serve_in_thread(icap_server)
        port = icap_server.server_address[1]
        response = _recv_icap_response(port, _sample_respmod_request(port), timeout=1)
        icap_server.shutdown()
        thread.join(timeout=1)

    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 403 Forbidden" in response
    assert b"Eicar-Test-Signature" in response


def test_scan_capacity_exhaustion_fails_open_without_wedging_options(
    monkeypatch,
) -> None:
    server = _load_server()
    blocked = threading.Event()
    release = threading.Event()
    fake = BlockingFakeSocket(blocked=blocked, release=release)
    connections = 0

    def create_connection(_address, timeout):
        nonlocal connections
        connections += 1
        return fake

    monkeypatch.setattr(server.socket, "create_connection", create_connection)

    with server.ClamAvRespmodServer(
        ("127.0.0.1", 0),
        clamd_host="127.0.0.1",
        clamd_port=3310,
        clamd_timeout=0.5,
        fail_open=True,
        max_scan_bytes=1024,
        client_timeout=0.5,
        max_connections=4,
        max_scans=1,
    ) as icap_server:
        thread = _serve_in_thread(icap_server)
        port = icap_server.server_address[1]
        first_response: list[bytes] = []
        first = threading.Thread(
            target=lambda: first_response.append(
                _recv_icap_response(port, _sample_respmod_request(port), timeout=2),
            ),
        )
        first.start()
        assert blocked.wait(timeout=1)

        second = _recv_icap_response(port, _sample_respmod_request(port), timeout=0.5)
        options = _recv_icap_response(port, _options_request(port), timeout=0.5)

        release.set()
        first.join(timeout=2)
        icap_server.shutdown()
        thread.join(timeout=1)

    assert connections == 1
    assert second.startswith(b"ICAP/1.0 204 No Content\r\n")
    assert options.startswith(b"ICAP/1.0 200 OK\r\n")
    assert first_response
    assert first_response[0].startswith(b"ICAP/1.0 200 OK\r\n")


def test_slow_clamd_scan_fails_closed_with_error_payload() -> None:
    server = _load_server()

    class FailClosedServer(server.ClamAvRespmodServer):
        def open_scan(self):
            return SlowScanner()

    with FailClosedServer(
        ("127.0.0.1", 0),
        clamd_host="127.0.0.1",
        clamd_port=3310,
        clamd_timeout=0.1,
        fail_open=False,
        max_scan_bytes=1024,
        client_timeout=0.5,
        max_connections=4,
    ) as icap_server:
        thread = _serve_in_thread(icap_server)
        port = icap_server.server_address[1]
        response = _recv_icap_response(port, _sample_respmod_request(port), timeout=0.5)
        icap_server.shutdown()
        thread.join(timeout=1)

    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 502 Bad Gateway" in response
    assert b"clamd INSTREAM scan timed out" in response


def test_respmod_runtime_args_bound_clients_and_concurrency(monkeypatch) -> None:
    server = _load_server()
    monkeypatch.setenv("CLAMAV_RESPMOD_CLIENT_TIMEOUT", "0.05")
    monkeypatch.setenv("CLAMAV_RESPMOD_MAX_CONNECTIONS", "0")
    monkeypatch.setenv("CLAMAV_RESPMOD_MAX_SCANS", "10")

    args = server._parse_args([])

    assert math.isclose(args.client_timeout, 0.1)
    assert args.max_connections == 1
    assert args.max_scans == 1
