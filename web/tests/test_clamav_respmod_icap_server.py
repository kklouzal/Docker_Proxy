from __future__ import annotations

import importlib.util
import io
import struct
import sys
from pathlib import Path


def _load_server():
    path = Path(__file__).resolve().parents[1] / "tools" / "clamav_respmod_icap_server.py"
    spec = importlib.util.spec_from_file_location("clamav_respmod_icap_server", path)
    assert spec
    assert spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class FakeSocket:
    def __init__(self, response: bytes = b"stream: OK\n") -> None:
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

    monkeypatch.setattr(server.socket, "create_connection", lambda address, timeout: fake)

    result = server.scan_stream_with_clamd(
        b"abcdef",
        host="192.168.1.10",
        port=3310,
        timeout=2,
        chunk_size=4,
    )

    assert result.clean is True
    assert fake.sent == (
        b"INSTREAM\n"
        + struct.pack("!I", 4)
        + b"abcd"
        + struct.pack("!I", 2)
        + b"ef"
        + struct.pack("!I", 0)
    )


def test_icap_chunks_stream_to_clamd_incrementally(monkeypatch) -> None:
    server = _load_server()
    fake = FakeSocket()

    monkeypatch.setattr(server.socket, "create_connection", lambda address, timeout: fake)

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
            b"INSTREAM\n"
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
        b"INSTREAM\n"
        + struct.pack("!I", 3)
        + b"abc"
        + struct.pack("!I", 3)
        + b"def"
        + struct.pack("!I", 0)
    )


def test_clamd_instream_scan_reports_found(monkeypatch) -> None:
    server = _load_server()
    fake = FakeSocket(b"stream: Eicar-Test-Signature FOUND\n")

    monkeypatch.setattr(server.socket, "create_connection", lambda address, timeout: fake)

    result = server.scan_stream_with_clamd(b"eicar", host="192.168.1.10", port=3310)

    assert result.clean is False
    assert result.infected is True
    assert result.signature == "Eicar-Test-Signature"


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
