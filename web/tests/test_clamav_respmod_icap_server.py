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
        pass


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


def test_clean_icap_response_prefers_204_when_allowed() -> None:
    server = _load_server()

    response = server.clean_response(
        allow_204=True,
        http_header=b"HTTP/1.1 200 OK\r\n\r\n",
        body=b"clean",
    )

    assert response.startswith(b"ICAP/1.0 204 No Content\r\n")
    assert b"ISTag" in response


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


def _options_request(port: int) -> bytes:
    return (
        f"OPTIONS icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
        "Host: 127.0.0.1\r\n"
        "Encapsulated: null-body=0\r\n\r\n"
    ).encode("ascii")


def _sample_respmod_request(port: int) -> bytes:
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


def _sample_respmod_request_without_allow_204(port: int) -> bytes:
    return _sample_respmod_request(port).replace(b"Allow: 204\r\n", b"")


def _sample_preview_respmod_request(port: int) -> bytes:
    http_header = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"
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
    assert first_response[0].startswith(b"ICAP/1.0 204 No Content\r\n")


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
