from __future__ import annotations

from .live_fixture_server import LiveFixtureHandler


class _DisconnectingWriter:
    def write(self, _payload: bytes) -> None:
        raise BrokenPipeError


class _RecordingWriter:
    def __init__(self) -> None:
        self.payload = b""

    def write(self, payload: bytes) -> None:
        self.payload = payload


class _HandlerStub:
    def __init__(self, writer: object) -> None:
        self.wfile = writer
        self.status = 0
        self.headers: list[tuple[str, str]] = []
        self.ended = False

    def send_response(self, status: int) -> None:
        self.status = status

    def send_header(self, name: str, value: str) -> None:
        self.headers.append((name, value))

    def end_headers(self) -> None:
        self.ended = True


def test_live_fixture_send_json_ignores_downstream_disconnect() -> None:
    handler = _HandlerStub(_DisconnectingWriter())

    LiveFixtureHandler._send_json(handler, b'{"ok": true}')  # type: ignore[arg-type]

    assert handler.status == 200
    assert handler.ended is True


def test_live_fixture_send_json_writes_payload() -> None:
    writer = _RecordingWriter()
    handler = _HandlerStub(writer)

    LiveFixtureHandler._send_json(handler, b'{"ok": true}')  # type: ignore[arg-type]

    assert handler.status == 200
    assert handler.ended is True
    assert writer.payload == b'{"ok": true}'
