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


def test_icap_chunked_body_rejects_malformed_trailer_fields() -> None:
    server = _load_server()

    malformed = (
        b"bad trailer: ok",
        b"Bad@Trailer: ok",
        b": ok",
        b"X-Trailer: bad\x00value",
        b"X-Trailer: bad\x7fvalue",
    )
    for trailer in malformed:
        try:
            server.read_icap_chunked_body(
                io.BytesIO(b"2\r\nhe\r\n0; ieof\r\n" + trailer + b"\r\n\r\n"),
                preview=True,
            )
        except server.IcapProtocolError as exc:
            assert str(exc) == "malformed ICAP chunk trailer"
        else:  # pragma: no cover - regression guard should always raise
            message = f"malformed ICAP chunk trailer was accepted: {trailer!r}"
            raise AssertionError(message)


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


def test_preview_terminator_before_declared_size_without_ieof_is_rejected() -> None:
    server = _load_server()
    continues = 0

    def on_continue() -> None:
        nonlocal continues
        continues += 1

    try:
        server.read_icap_chunked_body(
            io.BytesIO(b"2\r\nhe\r\n0\r\n\r\n1\r\nX\r\n0\r\n\r\n"),
            preview=True,
            preview_size=3,
            continue_callback=on_continue,
        )
    except server.IcapProtocolError as exc:
        assert str(exc) == "ICAP preview terminated before Preview header size"
    else:  # pragma: no cover - regression guard should always raise
        message = "short preview terminator without ieof was accepted"
        raise AssertionError(message)

    assert continues == 0


def test_preview_ieof_before_declared_size_allows_short_object() -> None:
    server = _load_server()
    continues = 0

    def on_continue() -> None:
        nonlocal continues
        continues += 1

    body, remainder = server.read_icap_chunked_body(
        io.BytesIO(b"2\r\nhe\r\n0;ieof\r\n\r\n"),
        preview=True,
        preview_size=3,
        continue_callback=on_continue,
    )

    assert body == b"he"
    assert remainder == b""
    assert continues == 0


def test_preview_zero_allows_immediate_continue_then_body() -> None:
    server = _load_server()
    continues = 0

    def on_continue() -> None:
        nonlocal continues
        continues += 1

    body, remainder = server.read_icap_chunked_body(
        io.BytesIO(b"0\r\n\r\n5\r\nhello\r\n0\r\n\r\n"),
        preview=True,
        preview_size=0,
        continue_callback=on_continue,
    )

    assert body == b"hello"
    assert remainder == b""
    assert continues == 1


def test_no_preview_early_zero_chunk_leaves_extra_body_as_remainder() -> None:
    server = _load_server()

    body, remainder = server.read_icap_chunked_body(
        io.BytesIO(b"2\r\nhe\r\n0\r\n\r\n1\r\nX\r\n0\r\n\r\n"),
        preview=False,
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


def test_icap_chunked_body_accepts_strict_hex_size_tokens() -> None:
    server = _load_server()
    seen_chunks: list[bytes] = []

    body, remainder = server.read_icap_chunked_body(
        io.BytesIO(b"000a; foo=bar\r\n0123456789\r\nF\r\nabcdefghijklmno\r\n0;ieof\r\n\r\n"),
        max_bytes=25,
        chunk_callback=seen_chunks.append,
    )

    assert body == b"0123456789abcdefghijklmno"
    assert remainder == b""
    assert seen_chunks == [b"0123456789", b"abcdefghijklmno"]


def test_icap_chunked_body_rejects_non_hex_size_token_grammar() -> None:
    server = _load_server()

    malformed = (
        b"+1",
        b"1_0",
        b"0x10",
        b" 1",
        b"1 ",
        b"1 0",
        b"",
        b"10000000000000000",
    )
    for token in malformed:
        seen_chunks: list[bytes] = []
        try:
            server.read_icap_chunked_body(
                io.BytesIO(token + b"\r\n0123456789abcdef\r\n0\r\n\r\n"),
                max_bytes=1024,
                chunk_callback=seen_chunks.append,
            )
        except server.IcapProtocolError as exc:
            assert str(exc).startswith("invalid ICAP chunk size:")
        else:  # pragma: no cover - regression guard should always raise
            message = f"malformed ICAP chunk size was accepted: {token!r}"
            raise AssertionError(message)

        assert seen_chunks == []


def test_outer_icap_header_parser_rejects_malformed_field_lines() -> None:
    server = _load_server()

    valid_header = (
        b"RESPMOD icap://example.test/av ICAP/1.0\r\n"
        b"Host: example.test\r\n"
        b"Allow: 204\r\n"
        b"Preview: 0\r\n"
        b"Encapsulated: res-hdr=0, res-body=64\r\n"
        b"X-Extension_123:  value with optional whitespace  \r\n"
        b"X!#$%&'*+.^_`|~0-9A-Za-z-: token-name ok"
    )
    start, headers = server._split_headers(valid_header)
    assert start == "RESPMOD icap://example.test/av ICAP/1.0"
    assert headers["host"] == "example.test"
    assert headers["allow"] == "204"
    assert headers["preview"] == "0"
    assert headers["encapsulated"] == "res-hdr=0, res-body=64"
    assert headers["x-extension_123"] == "value with optional whitespace"
    assert headers["x!#$%&'*+.^_`|~0-9a-za-z-"] == "token-name ok"

    malformed_lines = (
        b"Encapsulated res-hdr=0, res-body=64",
        b" Encapsulated: res-hdr=0, res-body=64",
        b"Encapsulated : res-hdr=0, res-body=64",
        b"\tPreview: 0",
        b"Preview\t: 0",
        b": 204",
        b"Allow",
        b"Allow: 2\x040",
        b"Allow: 2\x7f0",
        b"Allow: 204\x00",
        "Préview: 0".encode(),
        b"Encapsulated: res-hdr=0, res-body=64\r\n res-body=0",
        b"Encapsulated: res-hdr=0, res-body=64\r\n\tPreview: 0",
    )
    for line in malformed_lines:
        try:
            server._split_headers(
                b"RESPMOD icap://example.test/av ICAP/1.0\r\n" + line
            )
        except server.IcapProtocolError as exc:
            assert str(exc) == "malformed ICAP header line"
        else:  # pragma: no cover - regression guard should always reject
            message = f"malformed ICAP header line was accepted: {line!r}"
            raise AssertionError(message)


def test_malformed_outer_icap_control_header_lookalikes_do_not_fail_open_204(
    monkeypatch,
) -> None:
    server = _load_server()
    scan_attempts = 0

    def create_connection(*_args, **_kwargs):
        message = "connection refused"
        raise ConnectionRefusedError(message)

    class FailOpenServer(server.ClamAvRespmodServer):
        def open_scan(self):
            nonlocal scan_attempts
            scan_attempts += 1
            return super().open_scan()

    monkeypatch.setattr(server.socket, "create_connection", create_connection)

    malformed_replacements = (
        (b"Allow: 204\r\n", b"Allow : 204\r\n"),
        (
            b"Encapsulated: res-hdr=0, res-body=64\r\n",
            b"Encapsulated : res-hdr=0, res-body=64\r\n",
        ),
        (b"Allow: 204\r\n", b"Allow: 204\r\nPreview : 0\r\n"),
    )
    for original, replacement in malformed_replacements:
        scan_attempts = 0
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
            request = _sample_respmod_request(port).replace(original, replacement)
            response = _recv_icap_exchange(port, request, timeout=1)
            icap_server.shutdown()
            thread.join(timeout=1)

        assert scan_attempts == 0
        assert not response.startswith(b"ICAP/1.0 204 No Content\r\n")
        assert response.startswith(b"ICAP/1.0 200 OK\r\n")
        assert b"HTTP/1.1 502 Bad Gateway" in response
        assert b"scan failed before complete response body" in response
        assert b"5\r\nhello\r\n0\r\n\r\n" not in response


def test_encapsulated_offsets_accept_ascii_decimals_and_comma_sections() -> None:
    server = _load_server()

    assert server._parse_encapsulated(
        "req-hdr=000, res-hdr=046, res-body=00122"
    ) == {"req-hdr": 0, "res-hdr": 46, "res-body": 122}
    assert server._parse_encapsulated("res-hdr=0,null-body=64") == {
        "res-hdr": 0,
        "null-body": 64,
    }


def test_encapsulated_offsets_reject_non_strict_decimal_tokens() -> None:
    server = _load_server()

    malformed = (
        "+1",
        "-0",
        "1_0",
        "\uff11\uff12",
        "\t1",
        "1\t",
        "",
        "1e0",
        "0x10",
        "9" * 17,
        "0" * 5000 + "1" * 17,
    )
    for token in malformed:
        try:
            server._parse_encapsulated(f"res-hdr=0, res-body={token}")
        except server.IcapProtocolError as exc:
            assert str(exc).startswith("invalid Encapsulated offset:")
        else:  # pragma: no cover - regression guard should always raise
            message = f"malformed Encapsulated offset was accepted: {token!r}"
            raise AssertionError(message)


def test_respmod_rejects_malformed_chunk_size_without_clean_replay() -> None:
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
        request = _sample_respmod_request(port).replace(b"5\r\nhello", b"+5\r\nhello")
        response = _recv_icap_response(port, request, timeout=0.5)
        icap_server.shutdown()
        thread.join(timeout=1)

    assert scanner.chunks == []
    assert scanner.finished is False
    assert scanner.closed is True
    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 502 Bad Gateway" in response
    assert b"invalid ICAP chunk size" in response
    assert b"5\r\nhello\r\n0\r\n\r\n" not in response


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


def test_http_response_204_backup_content_length_and_te_matrix() -> None:
    server = _load_server()

    cases = {
        "valid single ASCII Content-Length": (
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n",
            True,
        ),
        "duplicate same Content-Length": (
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n",
            True,
        ),
        "duplicate conflicting Content-Length": (
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n",
            False,
        ),
        "comma-list Content-Length": (
            b"HTTP/1.1 200 OK\r\nContent-Length: 5, 5\r\n\r\n",
            False,
        ),
        "signed Content-Length": (
            b"HTTP/1.1 200 OK\r\nContent-Length: +5\r\n\r\n",
            False,
        ),
        "underscore Content-Length": (
            b"HTTP/1.1 200 OK\r\nContent-Length: 1_0\r\n\r\n",
            False,
        ),
        "Unicode-like Content-Length bytes": (
            b"HTTP/1.1 200 OK\r\nContent-Length: \xef\xbc\x95\r\n\r\n",
            False,
        ),
        "very long Content-Length": (
            b"HTTP/1.1 200 OK\r\nContent-Length: " + b"9" * 5000 + b"\r\n\r\n",
            False,
        ),
        "Content-Length plus Transfer-Encoding chunked": (
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"
                b"Transfer-Encoding: chunked\r\n\r\n"
            ),
            False,
        ),
        "mixed-case Transfer-Encoding chunked": (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: ChUnKeD\r\n\r\n",
            False,
        ),
        "chunked Transfer-Encoding with OWS": (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: \tchunked \r\n\r\n",
            False,
        ),
        "duplicate mixed Transfer-Encoding tokens": (
            (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: identity\r\n"
                b"Transfer-Encoding: gzip\r\nContent-Length: 5\r\n\r\n"
            ),
            False,
        ),
        "invalid chunked not final Transfer-Encoding": (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\n",
            False,
        ),
        "malformed Content-Length line": (
            b"HTTP/1.1 200 OK\r\nContent-Length 5\r\n\r\n",
            False,
        ),
    }

    for name, (http_header, expected) in cases.items():
        assert server._http_response_allows_squid_204_backup(http_header) is expected, name


def test_respmod_rejects_malformed_http_status_lines_before_scan_or_replay() -> None:
    server = _load_server()

    malformed_cases = {
        "unsupported major version": b"HTTP/2.0 200 OK",
        "unsupported minor version": b"HTTP/1.2 200 OK",
        "missing version-status space": b"HTTP/1.1200 OK",
        "extra version-status space": b"HTTP/1.1  200 OK",
        "missing status-reason space": b"HTTP/1.1 200",
        "non-3-digit status": b"HTTP/1.1 20 OK",
        "signed status": b"HTTP/1.1 +200 OK",
        "non-digit status": b"HTTP/1.1 2OO OK",
        "control in reason": b"HTTP/1.1 200 O\x01K",
        "non-ascii reason": b"HTTP/1.1 200 Caf\xe9",
        "HTTP request-line masquerading as response": b"GET / HTTP/1.1",
    }

    for name, status_line in malformed_cases.items():
        scanner = RecordingScanner()

        class TestServer(server.ClamAvRespmodServer):
            def open_scan(self):
                return scanner

        http_header = (
            status_line
            + b"\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\n"
        )
        with TestServer(
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
            response = _recv_icap_exchange(
                port,
                _respmod_request_with_http_header(
                    port, http_header, b"5\r\nhello\r\n0\r\n\r\n"
                ),
                timeout=1,
            )
            icap_server.shutdown()
            thread.join(timeout=1)

        assert scanner.finished is False, name
        assert response.startswith(b"ICAP/1.0 200 OK\r\n"), name
        assert b"HTTP/1.1 502 Bad Gateway" in response, name
        assert b"malformed HTTP response status line" in response, name
        assert b"5\r\nhello\r\n0\r\n\r\n" not in response, name


def test_http_status_line_validation_preserves_supported_response_lines() -> None:
    server = _load_server()

    valid_cases = (
        b"HTTP/1.0 200 OK",
        b"HTTP/1.1 200 OK",
        b"HTTP/1.1 204 ",
        b"HTTP/1.1 404 Not Found",
        b"HTTP/1.1 200 OK EXTRA",
        b"HTTP/1.1 599 Ordinary reason-text!?",
    )

    for status_line in valid_cases:
        server._validate_http_status_line(status_line)


def test_body_forbidden_status_res_body_rejected_before_scan_or_replay() -> None:
    server = _load_server()

    cases = {
        "informational": (b"HTTP/1.1 100 Continue", b"100"),
        "no content": (b"HTTP/1.1 204 No Content", b"204"),
        "not modified": (b"HTTP/1.1 304 Not Modified", b"304"),
    }

    for name, (status_line, status_code) in cases.items():
        scanner = RecordingScanner()

        class TestServer(server.ClamAvRespmodServer):
            def open_scan(self):
                return scanner

        http_header = status_line + b"\r\nContent-Length: 5\r\n\r\n"
        with TestServer(
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
            response = _recv_icap_exchange(
                port,
                _respmod_request_with_http_header(
                    port, http_header, b"5\r\nhello\r\n0\r\n\r\n"
                ),
                timeout=1,
            )
            icap_server.shutdown()
            thread.join(timeout=1)

        assert scanner.chunks == [], name
        assert scanner.finished is False, name
        assert response.startswith(b"ICAP/1.0 200 OK\r\n"), name
        assert b"HTTP/1.1 502 Bad Gateway" in response, name
        assert b"HTTP status " + status_code + b" forbids ICAP res-body" in response, name
        assert b"5\r\nhello\r\n0\r\n\r\n" not in response, name


def test_http_response_body_semantics_preserves_protocol_valid_null_body_cases() -> None:
    server = _load_server()

    valid_cases = (
        b"HTTP/1.1 100 Continue\r\n\r\n",
        b"HTTP/1.1 204 No Content\r\nDate: Mon, 20 Jul 2026 20:08:00 GMT\r\n\r\n",
        b"HTTP/1.1 304 Not Modified\r\nContent-Length: 123\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    )
    for http_header in valid_cases:
        server._validate_http_response_body_semantics(
            http_header, has_body_section=False
        )

    invalid_cases = {
        "204 content length": (
            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n",
            "HTTP status 204 forbids Content-Length",
        ),
        "100 transfer encoding": (
            b"HTTP/1.1 100 Continue\r\nTransfer-Encoding: identity\r\n\r\n",
            "HTTP status 100 forbids Transfer-Encoding",
        ),
        "304 transfer encoding": (
            b"HTTP/1.1 304 Not Modified\r\nTransfer-Encoding: chunked\r\n\r\n",
            "HTTP status 304 forbids Transfer-Encoding",
        ),
    }
    for name, (http_header, expected) in invalid_cases.items():
        try:
            server._validate_http_response_body_semantics(
                http_header, has_body_section=False
            )
        except server.HttpFramingError as exc:
            assert str(exc) == expected, name
        else:  # pragma: no cover - regression guard should always raise
            message = f"invalid no-body status framing was accepted: {name}"
            raise AssertionError(message)


def test_http_header_field_validation_preserves_valid_response_metadata() -> None:
    server = _load_server()

    server._validate_http_header_field_names(
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Length: 5\r\n"
        b"Content-Length: 5\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"X-Unknown-Token: \tbenign value \r\n\r\n"
    )


def test_respmod_rejects_malformed_http_header_values_before_scan_or_replay() -> None:
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
        http_header = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\x00charset=utf-8\r\n"
            b"Content-Length: 5\r\n\r\n"
        )
        response = _recv_icap_response(
            port,
            _respmod_request_with_http_header(
                port, http_header, b"5\r\nhello\r\n0\r\n\r\n"
            ),
            timeout=0.5,
        )
        icap_server.shutdown()
        thread.join(timeout=1)

    assert scan_attempts == 0
    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 502 Bad Gateway" in response
    assert b"malformed HTTP response header field value" in response
    assert b"5\r\nhello\r\n0\r\n\r\n" not in response


def test_respmod_rejects_malformed_http_header_lines_before_scan_or_replay() -> None:
    server = _load_server()

    malformed_cases = {
        "missing colon unknown": b"X Missing Colon",
        "empty field name": b": hidden",
        "whitespace before colon content length lookalike": b"Content-Length : 5",
        "control in field name": b"Bad\x01Name: value",
        "non-ascii field name byte": b"Bad\xffName: value",
        "obs-fold continuation": b" folded-continuation",
        "embedded NUL in field name": b"Bad\x00Name: value",
        "content length missing colon lookalike": b"Content-Length 5",
        "transfer encoding missing colon lookalike": b"Transfer-Encoding chunked",
    }

    for name, header_line in malformed_cases.items():
        scanner = RecordingScanner()

        class TestServer(server.ClamAvRespmodServer):
            def open_scan(self):
                return scanner

        http_header = (
            b"HTTP/1.1 200 OK\r\n"
            + header_line
            + b"\r\nContent-Type: text/plain\r\n\r\n"
        )
        with TestServer(
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
            response = _recv_icap_exchange(
                port,
                _respmod_request_with_http_header(
                    port, http_header, b"5\r\nhello\r\n0\r\n\r\n"
                ),
                timeout=1,
            )
            icap_server.shutdown()
            thread.join(timeout=1)

        assert scanner.finished is False, name
        assert response.startswith(b"ICAP/1.0 200 OK\r\n"), name
        assert b"HTTP/1.1 502 Bad Gateway" in response, name
        assert b"malformed HTTP response header" in response, name
        assert b"5\r\nhello\r\n0\r\n\r\n" not in response, name


def test_clean_respmod_rejects_known_content_length_body_mismatches() -> None:
    server = _load_server()

    cases = {
        "declared Content-Length smaller than decoded body": (
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n",
            b"5\r\nhello\r\n0\r\n\r\n",
            False,
            b"HTTP Content-Length 3 does not match decoded ICAP body length 5",
        ),
        "declared Content-Length larger than decoded body": (
            b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n",
            b"5\r\nhello\r\n0\r\n\r\n",
            False,
            b"HTTP Content-Length 7 does not match decoded ICAP body length 5",
        ),
        "declared zero Content-Length with non-empty decoded body": (
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            b"5\r\nhello\r\n0\r\n\r\n",
            False,
            b"HTTP Content-Length 0 does not match decoded ICAP body length 5",
        ),
        "declared positive Content-Length with empty terminal body": (
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n",
            b"0\r\n\r\n",
            False,
            b"HTTP Content-Length 5 does not match decoded ICAP body length 0",
        ),
        "duplicate conflicting Content-Length is ambiguous": (
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n",
            b"5\r\nhello\r\n0\r\n\r\n",
            False,
            b"ambiguous HTTP Content-Length headers",
        ),
        "comma-list Content-Length is ambiguous": (
            b"HTTP/1.1 200 OK\r\nContent-Length: 5, 5\r\n\r\n",
            b"5\r\nhello\r\n0\r\n\r\n",
            False,
            b"invalid HTTP Content-Length header",
        ),
        "malformed Content-Length is ambiguous": (
            b"HTTP/1.1 200 OK\r\nContent-Length: +5\r\n\r\n",
            b"5\r\nhello\r\n0\r\n\r\n",
            False,
            b"invalid HTTP Content-Length header",
        ),
        "Content-Length plus Transfer-Encoding chunked is ambiguous": (
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"
                b"Transfer-Encoding: chunked\r\n\r\n"
            ),
            b"5\r\nhello\r\n0\r\n\r\n",
            False,
            b"ambiguous HTTP response framing",
        ),
        "duplicate identical Content-Length matches decoded body": (
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n",
            b"5\r\nhello\r\n0\r\n\r\n",
            True,
            b"Content-Length: 5\r\n",
        ),
        "no Content-Length replays decoded body with normalized length": (
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n",
            b"5\r\nhello\r\n0\r\n\r\n",
            True,
            b"Content-Length: 5\r\n",
        ),
        "chunked Transfer-Encoding replays decoded body with normalized length": (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"5\r\nhello\r\n0\r\n\r\n",
            True,
            b"Content-Length: 5\r\n",
        ),
        "mixed-case chunked Transfer-Encoding is valid": (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: ChUnKeD\r\n\r\n",
            b"5\r\nhello\r\n0\r\n\r\n",
            True,
            b"Content-Length: 5\r\n",
        ),
        "OWS around chunked Transfer-Encoding is valid": (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: \tchunked \r\n\r\n",
            b"5\r\nhello\r\n0\r\n\r\n",
            True,
            b"Content-Length: 5\r\n",
        ),
        "identity Transfer-Encoding replays decoded body": (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: identity\r\n\r\n",
            b"5\r\nhello\r\n0\r\n\r\n",
            True,
            b"Content-Length: 5\r\n",
        ),
    }

    for name, (http_header, chunked_body, should_replay, expected) in cases.items():
        scanner = RecordingScanner()

        class TestServer(server.ClamAvRespmodServer):
            def open_scan(self):
                return scanner

        with TestServer(
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
            response = _recv_icap_exchange(
                port,
                _respmod_request_with_http_header(port, http_header, chunked_body),
                timeout=1,
            )
            icap_server.shutdown()
            thread.join(timeout=1)

        if should_replay:
            assert scanner.finished is True, name
            assert response.startswith(b"ICAP/1.0 200 OK\r\n"), name
            assert b"HTTP/1.1 200 OK" in response, name
            assert expected in response, name
            assert b"5\r\nhello\r\n0\r\n\r\n" in response, name
        else:
            assert scanner.finished is False, name
            assert response.startswith(b"ICAP/1.0 200 OK\r\n"), name
            assert b"HTTP/1.1 502 Bad Gateway" in response, name
            assert expected in response, name
            assert b"5\r\nhello\r\n0\r\n\r\n" not in response, name


def test_fail_open_content_length_mismatch_never_returns_204_or_normalized_replay(
    monkeypatch,
) -> None:
    server = _load_server()

    cases = {
        "smaller": (
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n",
            b"5\r\nhello\r\n0\r\n\r\n",
        ),
        "larger": (
            b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n",
            b"5\r\nhello\r\n0\r\n\r\n",
        ),
        "zero-with-body": (
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            b"5\r\nhello\r\n0\r\n\r\n",
        ),
        "positive-with-empty-body": (
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n",
            b"0\r\n\r\n",
        ),
    }

    for name, (http_header, chunked_body) in cases.items():
        monkeypatch.setattr(
            server.socket,
            "create_connection",
            lambda address, timeout: ResetBeforeVerdictSocket(),
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
                port,
                _respmod_request_with_http_header(port, http_header, chunked_body),
                timeout=1,
            )
            icap_server.shutdown()
            thread.join(timeout=1)

        assert not response.startswith(b"ICAP/1.0 204 No Content\r\n"), name
        assert b"HTTP/1.1 200 OK" not in response, name
        assert b"5\r\nhello\r\n0\r\n\r\n" not in response, name
        assert b"HTTP/1.1 502 Bad Gateway" in response, name


def test_fail_open_ambiguous_http_framing_never_returns_204_or_normalized_replay(
    monkeypatch,
) -> None:
    server = _load_server()

    cases = {
        "conflicting duplicate Content-Length": (
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n",
            b"ambiguous HTTP Content-Length headers",
        ),
        "comma-list Content-Length": (
            b"HTTP/1.1 200 OK\r\nContent-Length: 5, 5\r\n\r\n",
            b"invalid HTTP Content-Length header",
        ),
        "malformed Content-Length": (
            b"HTTP/1.1 200 OK\r\nContent-Length: +5\r\n\r\n",
            b"invalid HTTP Content-Length header",
        ),
        "Content-Length plus Transfer-Encoding chunked": (
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"
                b"Transfer-Encoding: chunked\r\n\r\n"
            ),
            b"ambiguous HTTP response framing",
        ),
        "duplicate Transfer-Encoding lines": (
            (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n"
                b"Transfer-Encoding: chunked\r\n\r\n"
            ),
            b"unsupported HTTP Transfer-Encoding before chunked",
        ),
        "comma-list Transfer-Encoding before chunked": (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
            b"unsupported HTTP Transfer-Encoding before chunked",
        ),
        "Transfer-Encoding chunked not final": (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\n",
            b"invalid HTTP Transfer-Encoding header: chunked must be final",
        ),
        "repeated chunked Transfer-Encoding": (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, chunked\r\n\r\n",
            b"invalid HTTP Transfer-Encoding header: repeated chunked",
        ),
        "identity mixed with chunked": (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: identity, chunked\r\n\r\n",
            b"ambiguous HTTP Transfer-Encoding header: identity with chunked",
        ),
        "malformed empty Transfer-Encoding token": (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip,, chunked\r\n\r\n",
            b"invalid HTTP Transfer-Encoding header",
        ),
        "signed-looking unsupported Transfer-Encoding token": (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: +chunked\r\n\r\n",
            b"unsupported HTTP Transfer-Encoding: +chunked",
        ),
        "unsupported Transfer-Encoding coding": (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n",
            b"unsupported HTTP Transfer-Encoding: gzip",
        ),
    }

    for name, (http_header, expected) in cases.items():
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
                port,
                _respmod_request_with_http_header(
                    port, http_header, b"5\r\nhello\r\n0\r\n\r\n"
                ),
                timeout=1,
            )
            icap_server.shutdown()
            thread.join(timeout=1)

        assert response.startswith(b"ICAP/1.0 200 OK\r\n"), name
        assert not response.startswith(b"ICAP/1.0 204 No Content\r\n"), name
        assert b"HTTP/1.1 200 OK" not in response, name
        assert b"5\r\nhello\r\n0\r\n\r\n" not in response, name
        assert b"HTTP/1.1 502 Bad Gateway" in response, name
        assert expected in response, name
        assert fake.sent == b"", name


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


def test_unavailable_clamd_status_204_encoded_as_empty_res_body_preserves_response(
    monkeypatch,
) -> None:
    server = _load_server()

    def create_connection(_address, timeout):
        message = "connection refused"
        raise ConnectionRefusedError(message)

    monkeypatch.setattr(server.socket, "create_connection", create_connection)

    http_header = b"HTTP/1.1 204 No Content\r\nCache-Control: no-store\r\n\r\n"
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
            port,
            _respmod_request_with_http_header(port, http_header, b"0\r\n\r\n"),
            timeout=1,
        )
        icap_server.shutdown()
        thread.join(timeout=1)

    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"Encapsulated: res-hdr=0, null-body=" in response
    assert b"HTTP/1.1 204 No Content" in response
    assert b"ClamAV response scan failed" not in response
    assert not response.endswith(b"0\r\n\r\n")


def test_unavailable_clamd_squid_preview_zero_status_204_res_body_preserves_response(
    monkeypatch,
) -> None:
    server = _load_server()

    def create_connection(_address, timeout):
        _ = timeout
        message = "connection refused"
        raise ConnectionRefusedError(message)

    monkeypatch.setattr(server.socket, "create_connection", create_connection)

    request_header = (
        b"GET /no-body/remote_respmod_stress HTTP/1.1\r\n"
        b"Host: live-fixture:8080\r\n"
        b"Cache-Control: no-cache\r\n"
        b"Pragma: no-cache\r\n\r\n"
    )
    response_header = (
        b"HTTP/1.0 204 No Content\r\n"
        b"Server: LiveFixture/1.0 Python/3.14\r\n"
        b"Date: Tue, 21 Jul 2026 13:30:00 GMT\r\n"
        b"Cache-Control: no-store\r\n\r\n"
    )
    response_offset = len(request_header)
    body_offset = response_offset + len(response_header)

    with server.ClamAvRespmodServer(
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
        for chunked_tail in (b"", b"0\r\n\r\n"):
            request = (
                (
                    f"RESPMOD icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
                    "Host: 127.0.0.1\r\n"
                    "Allow: 204\r\n"
                    "Preview: 0\r\n"
                    "Encapsulated: "
                    f"req-hdr=0, res-hdr={response_offset}, res-body={body_offset}"
                    "\r\n\r\n"
                ).encode("ascii")
                + request_header
                + response_header
                + chunked_tail
            )
            response = _recv_icap_exchange(port, request, timeout=1)
            assert not response.startswith(b"ICAP/1.0 100 Continue\r\n")
            assert response.startswith(b"ICAP/1.0 200 OK\r\n")
            assert b"Encapsulated: res-hdr=0, null-body=" in response
            assert b"HTTP/1.0 204 No Content" in response
            assert b"HTTP/1.1 502 Bad Gateway" not in response
            assert b"scan failed before complete response body" not in response
        icap_server.shutdown()
        thread.join(timeout=1)


def _null_body_respmod_request_with_headers(
    port: int,
    *,
    request_header: bytes | None,
    response_header: bytes,
    allow_204: bool = True,
) -> bytes:
    allow = "Allow: 204\r\n" if allow_204 else ""
    if request_header is None:
        return (
            (
                f"RESPMOD icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
                "Host: 127.0.0.1\r\n"
                f"{allow}"
                f"Encapsulated: res-hdr=0, null-body={len(response_header)}"
                "\r\n\r\n"
            ).encode("ascii")
            + response_header
        )

    response_offset = len(request_header)
    null_offset = response_offset + len(response_header)
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


def _run_null_body_respmod_exchange(
    server,
    *,
    request_header: bytes | None,
    response_header: bytes,
    allow_204: bool = True,
) -> tuple[bytes, list[bytes]]:
    scanned_bodies: list[bytes] = []

    class CleanServer(server.ClamAvRespmodServer):
        def scan_body(self, body: bytes):
            scanned_bodies.append(body)
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
            _null_body_respmod_request_with_headers(
                port,
                request_header=request_header,
                response_header=response_header,
                allow_204=allow_204,
            ),
            timeout=0.5,
        )
        icap_server.shutdown()
        thread.join(timeout=1)

    return response, scanned_bodies


def test_non_head_null_body_positive_framing_is_rejected_before_clean_scan() -> None:
    server = _load_server()

    cases = {
        "GET positive Content-Length": (
            b"GET /asset.js HTTP/1.1\r\nHost: example.test\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n",
            b"HTTP null-body for GET response conflicts with Content-Length 5",
        ),
        "POST positive Content-Length": (
            b"POST /submit HTTP/1.1\r\nHost: example.test\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n",
            b"HTTP null-body for POST response conflicts with Content-Length 5",
        ),
        "GET Transfer-Encoding chunked": (
            b"GET /stream HTTP/1.1\r\nHost: example.test\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"HTTP null-body for GET response conflicts with Transfer-Encoding",
        ),
        "POST Transfer-Encoding chunked": (
            b"POST /stream HTTP/1.1\r\nHost: example.test\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"HTTP null-body for POST response conflicts with Transfer-Encoding",
        ),
    }

    for name, (request_header, response_header, expected) in cases.items():
        response, scanned_bodies = _run_null_body_respmod_exchange(
            server,
            request_header=request_header,
            response_header=response_header,
        )

        assert scanned_bodies == [], name
        assert response.startswith(b"ICAP/1.0 200 OK\r\n"), name
        assert b"HTTP/1.1 502 Bad Gateway" in response, name
        assert expected in response, name
        assert not response.startswith(b"ICAP/1.0 204 No Content\r\n"), name


def test_head_null_body_preserves_representation_content_length() -> None:
    server = _load_server()

    response, scanned_bodies = _run_null_body_respmod_exchange(
        server,
        request_header=b"HEAD /asset.js HTTP/1.1\r\nHost: example.test\r\n\r\n",
        response_header=(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/javascript\r\n"
            b"Content-Length: 12345\r\n\r\n"
        ),
        allow_204=False,
    )

    assert scanned_bodies == [b""]
    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"Encapsulated: res-hdr=0, null-body=" in response
    assert b"HTTP/1.1 200 OK" in response
    assert b"Content-Length: 12345\r\n" in response


def test_null_body_without_req_hdr_preserves_framing_ambiguity() -> None:
    server = _load_server()

    response, scanned_bodies = _run_null_body_respmod_exchange(
        server,
        request_header=None,
        response_header=b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n",
        allow_204=False,
    )

    assert scanned_bodies == [b""]
    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 200 OK" in response
    assert b"Content-Length: 5\r\n" in response
    assert b"HTTP/1.1 502 Bad Gateway" not in response


def test_get_null_body_zero_content_length_remains_valid() -> None:
    server = _load_server()

    response, scanned_bodies = _run_null_body_respmod_exchange(
        server,
        request_header=b"GET /empty HTTP/1.1\r\nHost: example.test\r\n\r\n",
        response_header=b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        allow_204=False,
    )

    assert scanned_bodies == [b""]
    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 200 OK" in response
    assert b"Content-Length: 0\r\n" in response


def test_malformed_present_req_hdr_rejected_before_null_body_scan() -> None:
    server = _load_server()
    malformed_cases = {
        "missing version": b"GET /missing-version\r\nHost: example.test\r\n\r\n",
        "space in method": b"GE T /asset.js HTTP/1.1\r\nHost: example.test\r\n\r\n",
        "bad method token": b"BAD/METHOD /asset.js HTTP/1.1\r\nHost: example.test\r\n\r\n",
        "unsupported version": b"GET /asset.js HTTP/1.2\r\nHost: example.test\r\n\r\n",
        "extra start-line spacing": b"GET  /asset.js HTTP/1.1\r\nHost: example.test\r\n\r\n",
        "control byte in target": b"GET /bad\x01target HTTP/1.1\r\nHost: example.test\r\n\r\n",
        "response masquerade": b"HTTP/1.1 200 OK\r\nHost: example.test\r\n\r\n",
        "missing colon field": b"GET /asset.js HTTP/1.1\r\nHost example.test\r\n\r\n",
        "obs-fold continuation": b"GET /asset.js HTTP/1.1\r\n folded\r\nHost: example.test\r\n\r\n",
        "bad field name": b"GET /asset.js HTTP/1.1\r\nBad Name: value\r\n\r\n",
        "nul in field name": b"GET /asset.js HTTP/1.1\r\nBad\x00Name: value\r\n\r\n",
        "nul in field value": b"GET /asset.js HTTP/1.1\r\nHost: ex\x00ample.test\r\n\r\n",
    }

    for name, request_header in malformed_cases.items():
        response, scanned_bodies = _run_null_body_respmod_exchange(
            server,
            request_header=request_header,
            response_header=b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n",
            allow_204=False,
        )

        assert scanned_bodies == [], name
        assert response.startswith(b"ICAP/1.0 200 OK\r\n"), name
        assert b"HTTP/1.1 502 Bad Gateway" in response, name
        assert b"malformed HTTP request" in response or b"unsupported HTTP request" in response, name
        assert b"Content-Length: 5\r\n" not in response, name


def test_valid_present_req_hdr_methods_preserve_null_body_semantics() -> None:
    server = _load_server()
    valid_cases = (
        (
            b"GET /empty HTTP/1.0\r\nHost: example.test\r\n\r\n",
            b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n",
            b"Content-Length: 0\r\n",
        ),
        (
            b"HEAD /asset.js HTTP/1.1\r\nHost: example.test\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 12345\r\n\r\n",
            b"Content-Length: 12345\r\n",
        ),
        (
            b"POST /submit HTTP/1.1\r\nHost: example.test\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            b"Content-Length: 0\r\n",
        ),
    )

    for request_header, response_header, expected in valid_cases:
        response, scanned_bodies = _run_null_body_respmod_exchange(
            server,
            request_header=request_header,
            response_header=response_header,
            allow_204=False,
        )

        assert scanned_bodies == [b""]
        assert response.startswith(b"ICAP/1.0 200 OK\r\n")
        assert b"HTTP/1." in response
        assert expected in response
        assert b"HTTP/1.1 502 Bad Gateway" not in response


def test_malformed_present_req_hdr_rejected_before_res_body_scan_finish() -> None:
    server = _load_server()

    for request_header in (
        b"POST /submit HTTP/9.9\r\nHost: example.test\r\n\r\n",
        b"GET /asset.js HTTP/1.1\r\nBad\x00Name: value\r\n\r\n",
    ):
        scanner = RecordingScanner()

        class TestServer(server.ClamAvRespmodServer):
            def open_scan(self):
                return scanner

        response_header = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"
        response_offset = len(request_header)
        body_offset = response_offset + len(response_header)
        chunked_body = b"5\r\nhello\r\n0\r\n\r\n"

        with TestServer(
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
            request = (
                (
                    f"RESPMOD icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
                    "Host: 127.0.0.1\r\n"
                    "Allow: 204\r\n"
                    "Encapsulated: "
                    f"req-hdr=0, res-hdr={response_offset}, res-body={body_offset}"
                    "\r\n\r\n"
                ).encode("ascii")
                + request_header
                + response_header
                + chunked_body
            )
            response = _recv_icap_exchange(port, request, timeout=1)
            icap_server.shutdown()
            thread.join(timeout=1)

        assert scanner.chunks == []
        assert scanner.finished is False
        assert response.startswith(b"ICAP/1.0 200 OK\r\n")
        assert b"HTTP/1.1 502 Bad Gateway" in response
        assert b"HTTP request" in response
        assert b"5\r\nhello\r\n0\r\n\r\n" not in response


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


def test_malformed_encapsulated_section_item_is_rejected_before_scanning() -> None:
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
            b"Encapsulated: res-hdr=0, garbage, res-body=64",
        )
        response = _recv_icap_response(port, request, timeout=0.5)
        icap_server.shutdown()
        thread.join(timeout=1)

    assert scan_attempts == 0
    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 502 Bad Gateway" in response
    assert b"malformed Encapsulated section" in response
    assert b"5\r\nhello\r\n0\r\n\r\n" not in response


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


def test_respmod_signed_offset_rejected_before_scanning() -> None:
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
            b"Encapsulated: res-hdr=0, res-body=+64",
        )
        response = _recv_icap_response(port, request, timeout=0.5)
        icap_server.shutdown()
        thread.join(timeout=1)

    assert scan_attempts == 0
    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 502 Bad Gateway" in response
    assert b"invalid Encapsulated offset" in response
    assert b"5\r\nhello\r\n0\r\n\r\n" not in response


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
    assert b"invalid Encapsulated offset" in response


def test_preview_header_parser_accepts_decimal_whitespace_and_rejects_bad_values() -> None:
    server = _load_server()

    _start, headers = server._split_headers(
        b"RESPMOD icap://127.0.0.1/avrespmod ICAP/1.0\r\n"
        b"Preview:   2   \r\n"
    )
    assert server._parse_preview_size(headers, has_body=True, max_bytes=2) == 2
    assert server._parse_preview_size({"preview": "0"}, has_body=True) == 0
    assert server._parse_preview_size(
        {"preview": "0" * 5000}, has_body=True, max_bytes=2
    ) == 0
    assert server._parse_preview_size(
        {"preview": "0" * 5000 + "2"}, has_body=True, max_bytes=2
    ) == 2
    assert server._parse_preview_size(
        {"preview": "0" * 5000 + str(server.DEFAULT_MAX_SCAN_BYTES)},
        has_body=True,
    ) == server.DEFAULT_MAX_SCAN_BYTES
    assert server._parse_preview_size(
        {"preview": str(server.DEFAULT_MAX_SCAN_BYTES)}, has_body=True
    ) == server.DEFAULT_MAX_SCAN_BYTES

    for value in ("two", "-1", "2, 3", "١٢", "+1", " 1"):
        try:
            server._parse_preview_size({"preview": value}, has_body=True)
        except server.IcapProtocolError as exc:
            assert str(exc).startswith("invalid ICAP Preview header")
        else:  # pragma: no cover - regression guard should always raise
            message = f"bad Preview value {value!r} was accepted"
            raise AssertionError(message)

    for value in (
        "3",
        "0" * 5000 + "3",
        str(server.DEFAULT_MAX_SCAN_BYTES + 1),
        "1" * 5000,
    ):
        try:
            server._parse_preview_size({"preview": value}, has_body=True, max_bytes=2)
        except server.IcapProtocolError as exc:
            assert str(exc) == "ICAP Preview header exceeds 2 bytes"
        else:  # pragma: no cover - regression guard should always raise
            message = f"oversize Preview value {value!r} was accepted"
            raise AssertionError(message)


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


def _respmod_request_with_http_header(
    port: int, http_header: bytes, chunked_body: bytes
) -> bytes:
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


def test_duplicate_preview_header_rejected_before_scanning_or_continue() -> None:
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
        request = _sample_preview_respmod_request(port).replace(
            b"Preview: 2\r\n",
            b"Preview: 2\r\nPreview: 2\r\n",
        )
        response = _recv_icap_exchange(port, request, timeout=1)
        icap_server.shutdown()
        thread.join(timeout=1)

    assert scan_attempts == 0
    assert not response.startswith(b"ICAP/1.0 100 Continue\r\n\r\n")
    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 502 Bad Gateway" in response
    assert b"duplicate ICAP Preview header" in response


def test_duplicate_allow_header_rejected_before_scanning_or_fail_open_204(
    monkeypatch,
) -> None:
    server = _load_server()
    scan_attempts = 0

    for first, second in ((b"foo", b"204"), (b"204", b"foo")):
        try:
            server._split_headers(
                b"RESPMOD icap://example.test/av ICAP/1.0\r\n"
                b"Allow: "
                + first
                + b"\r\nAllow: "
                + second
            )
        except server.IcapProtocolError as exc:
            assert str(exc) == "duplicate ICAP Allow header"
        else:  # pragma: no cover - regression guard should always reject this path
            message = f"duplicate Allow headers {first!r}/{second!r} were accepted"
            raise AssertionError(message)

    def create_connection(*_args, **_kwargs):
        message = "connection refused"
        raise ConnectionRefusedError(message)

    class FailOpenServer(server.ClamAvRespmodServer):
        def open_scan(self):
            nonlocal scan_attempts
            scan_attempts += 1
            return super().open_scan()

    monkeypatch.setattr(server.socket, "create_connection", create_connection)

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
        request = _sample_respmod_request_without_allow_204(port).replace(
            b"Host: 127.0.0.1\r\n",
            b"Host: 127.0.0.1\r\nAllow: foo\r\nAllow: 204\r\n",
        )
        response = _recv_icap_response(port, request, timeout=1)
        icap_server.shutdown()
        thread.join(timeout=1)

    assert scan_attempts == 0
    assert not response.startswith(b"ICAP/1.0 204 No Content\r\n")
    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 502 Bad Gateway" in response
    assert b"scan failed before complete response body" in response
    assert b"5\r\nhello\r\n0\r\n\r\n" not in response


def test_allow_204_parsing_accepts_exact_comma_tokens_only() -> None:
    server = _load_server()

    assert server._icap_allows_204("204") is True
    assert server._icap_allows_204("206, 204") is True
    assert server._icap_allows_204(" , 206,, 204 ,") is True
    assert server._icap_allows_204(None) is False
    assert server._icap_allows_204("") is False
    assert server._icap_allows_204("206") is False
    assert server._icap_allows_204("204foo") is False
    assert server._icap_allows_204("+204") is False
    assert server._icap_allows_204("-204") is False
    assert server._icap_allows_204("2 04") is False


def test_malformed_preview_header_rejected_before_scanning_or_continue() -> None:
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
        request = _sample_preview_respmod_request(port).replace(
            b"Preview: 2\r\n",
            b"Preview: 2, 3\r\n",
        )
        response = _recv_icap_exchange(port, request, timeout=1)
        icap_server.shutdown()
        thread.join(timeout=1)

    assert scan_attempts == 0
    assert not response.startswith(b"ICAP/1.0 100 Continue\r\n\r\n")
    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 502 Bad Gateway" in response
    assert b"invalid ICAP Preview header" in response


def test_very_long_preview_header_rejected_before_scanning_or_continue() -> None:
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
        request = _sample_preview_respmod_request(port).replace(
            b"Preview: 2\r\n",
            b"Preview: " + b"1" * 5000 + b"\r\n",
        )
        response = _recv_icap_exchange(port, request, timeout=1)
        icap_server.shutdown()
        thread.join(timeout=1)

    assert scan_attempts == 0
    assert not response.startswith(b"ICAP/1.0 100 Continue\r\n\r\n")
    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 502 Bad Gateway" in response
    assert b"ICAP Preview header exceeds 1024 bytes" in response
    assert b"Exceeds the limit" not in response


def test_very_long_zero_preview_header_remains_valid_and_opens_scanner() -> None:
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
        http_header = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
        request = (
            (
                f"RESPMOD icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
                "Host: 127.0.0.1\r\n"
                f"Preview: {'0' * 5000}\r\n"
                f"Encapsulated: res-hdr=0, res-body={len(http_header)}\r\n\r\n"
            ).encode("ascii")
            + http_header
            + b"0; ieof\r\n\r\n"
        )
        response = _recv_icap_exchange(port, request, timeout=1)
        icap_server.shutdown()
        thread.join(timeout=1)

    assert scanner.closed is True
    assert scanner.chunks == []
    assert scanner.finished is True
    assert not response.startswith(b"ICAP/1.0 100 Continue\r\n\r\n")
    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 502 Bad Gateway" not in response


def test_preview_body_larger_than_header_rejected_before_scanner_chunk() -> None:
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
            b"Preview: 2\r\n",
            b"Preview: 1\r\n",
        )
        response = _recv_icap_exchange(port, request, timeout=1)
        icap_server.shutdown()
        thread.join(timeout=1)

    assert scanner.closed is True
    assert scanner.chunks == []
    assert scanner.finished is False
    assert not response.startswith(b"ICAP/1.0 100 Continue\r\n\r\n")
    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 502 Bad Gateway" in response
    assert b"ICAP preview body exceeds Preview header" in response


def test_zero_preview_header_on_null_body_allows_clean_allow_204_verdict(
    monkeypatch,
) -> None:
    server = _load_server()

    def create_connection(_address, timeout):
        _ = timeout
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
        request = _sample_null_body_respmod_request(port, allow_204=True).replace(
            b"Encapsulated: ",
            b"Preview: 0\r\nEncapsulated: ",
        )
        response = _recv_icap_exchange(port, request, timeout=1)
        icap_server.shutdown()
        thread.join(timeout=1)

    assert response.startswith(b"ICAP/1.0 204 No Content\r\n")
    assert b"HTTP/1.1 502 Bad Gateway" not in response
    assert b"ICAP Preview header requires res-body" not in response


def test_nonzero_preview_header_on_null_body_rejected_before_allow_204_verdict() -> None:
    server = _load_server()
    scan_attempts = 0

    class FailClosedServer(server.ClamAvRespmodServer):
        def scan_body(self, body: bytes):
            nonlocal scan_attempts
            scan_attempts += 1
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
        request = _sample_null_body_respmod_request(port, allow_204=True).replace(
            b"Encapsulated: ",
            b"Preview: 1\r\nEncapsulated: ",
        )
        response = _recv_icap_exchange(port, request, timeout=1)
        icap_server.shutdown()
        thread.join(timeout=1)

    assert scan_attempts == 0
    assert not response.startswith(b"ICAP/1.0 204 No Content\r\n")
    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 502 Bad Gateway" in response
    assert b"ICAP Preview header requires res-body" in response


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

    def create_connection(_address, timeout):
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

    def create_connection(_address, timeout):
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
                lambda p: _sample_null_body_respmod_request(p).replace(
                    b"Encapsulated: ", b"Preview: 0\r\nEncapsulated: "
                ),
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
