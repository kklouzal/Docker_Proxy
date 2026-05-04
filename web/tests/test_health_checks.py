from __future__ import annotations

import sys
from pathlib import Path


def _add_web_to_path() -> None:
    web_dir = Path(__file__).resolve().parents[1]
    if str(web_dir) not in sys.path:
        sys.path.insert(0, str(web_dir))


class _FakeSocket:
    def __init__(self, chunks: list[bytes] | None = None):
        self.chunks = list(chunks or [])
        self.sent: list[bytes] = []
        self.timeout = None

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def settimeout(self, timeout):
        self.timeout = timeout

    def sendall(self, data: bytes):
        self.sent.append(data)

    def recv(self, size: int) -> bytes:
        if not self.chunks:
            return b""
        chunk = self.chunks.pop(0)
        if len(chunk) > size:
            self.chunks.insert(0, chunk[size:])
            return chunk[:size]
        return chunk


def test_health_check_local_host_listener_and_target_helpers(tmp_path, monkeypatch) -> None:
    _add_web_to_path()
    import services.health_checks as health_checks  # type: ignore

    assert health_checks.is_local_host("") is True
    assert health_checks.is_local_host("LOCALHOST") is True
    assert health_checks.is_local_host("proxy") is False

    proc_tcp = tmp_path / "tcp"
    proc_tcp.write_text("sl local_address rem_address st\n0: 0100007F:36B0 00000000:0000 0A\n", encoding="utf-8")
    assert health_checks.has_listen_socket(str(proc_tcp), 14000) is True
    assert health_checks.has_listen_socket(str(proc_tcp), 14001) is False
    assert health_checks.has_listen_socket(str(tmp_path / "missing"), 14000) is False

    assert health_checks.annotate_service_target({"ok": 1, "detail": "ready"}, host="127.0.0.1", port=3310, service="clamd") == {
        "ok": True,
        "detail": "ready",
        "host": "127.0.0.1",
        "port": 3310,
        "target": "127.0.0.1:3310",
        "service": "clamd",
    }

    monkeypatch.setenv("TEST_HOST", "")
    monkeypatch.setenv("TEST_PORT", "not-int")
    assert health_checks.resolve_host_port(host_env="TEST_HOST", port_env="TEST_PORT", default_host="host", default_port=1234) == ("host", 1234)


def test_recv_clamd_reply_stops_on_null_or_newline() -> None:
    _add_web_to_path()
    import services.health_checks as health_checks  # type: ignore

    assert health_checks._recv_clamd_reply(_FakeSocket([b"PONG\0extra"]), max_bytes=64) == b"PONG\0extra"
    assert health_checks._recv_clamd_reply(_FakeSocket([b"OK\nmore"]), max_bytes=64) == b"OK\nmore"
    assert health_checks._recv_clamd_reply(_FakeSocket([b"ab", b"cd", b""]), max_bytes=3) == b"abc"


def test_check_tcp_success_and_failure(monkeypatch) -> None:
    _add_web_to_path()
    import services.health_checks as health_checks  # type: ignore

    monkeypatch.setattr(health_checks.socket, "create_connection", lambda *_args, **_kwargs: _FakeSocket())
    assert health_checks.check_tcp("127.0.0.1", 3310) == {"ok": True, "detail": "tcp connect ok"}

    monkeypatch.setattr(
        health_checks.socket,
        "create_connection",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("refused")),
    )
    assert health_checks.check_tcp("127.0.0.1", 3310, error_formatter=lambda exc: f"formatted {exc}") == {
        "ok": False,
        "detail": "formatted refused",
    }


def test_check_icap_service_and_clamd_protocol_helpers(monkeypatch) -> None:
    _add_web_to_path()
    import services.health_checks as health_checks  # type: ignore

    icap_sock = _FakeSocket([b"ICAP/1.0 200 OK\r\n\r\n"])
    monkeypatch.setattr(health_checks.socket, "create_connection", lambda *_args, **_kwargs: icap_sock)
    assert health_checks.check_icap_service("127.0.0.1", 14000, "adblockreq")["ok"] is True
    assert b"OPTIONS icap://127.0.0.1:14000/adblockreq ICAP/1.0" in icap_sock.sent[0]

    icap_error_sock = _FakeSocket([b"ICAP/1.0 404 Not Found\r\n"])
    monkeypatch.setattr(health_checks.socket, "create_connection", lambda *_args, **_kwargs: icap_error_sock)
    assert health_checks.check_icap_service("127.0.0.1", 14000, "/missing") == {"ok": False, "detail": "ICAP/1.0 404 Not Found"}

    clamd_sock = _FakeSocket([b"PONG\0"])
    monkeypatch.setattr(health_checks.socket, "create_connection", lambda *_args, **_kwargs: clamd_sock)
    clamd = health_checks.check_clamd("clamd", 3310)
    assert clamd["ok"] is True
    assert "PONG" in clamd["detail"]
    assert clamd_sock.sent == [b"PING\n"]

    combined = health_checks.build_clamav_health({"ok": True, "detail": "clamd ok"}, {"ok": False, "detail": "icap down"})
    assert combined["ok"] is False
    assert combined["components"]["clamd"]["detail"] == "clamd ok"
