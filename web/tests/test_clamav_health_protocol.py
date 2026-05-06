from __future__ import annotations

import os
import socket
import sys
import threading
from pathlib import Path


def _add_web_to_path() -> None:
    web_dir = Path(__file__).resolve().parents[1]
    if str(web_dir) not in sys.path:
        sys.path.insert(0, str(web_dir))


def test_check_clamd_uses_tcp_ping() -> None:
    _add_web_to_path()
    from services.proxy_health import check_clamd_health  # type: ignore

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    seen = {"request": b""}

    def serve() -> None:
        conn, _addr = listener.accept()
        with conn:
            buf = b""
            while b"\n" not in buf:
                chunk = conn.recv(64)
                if not chunk:
                    break
                buf += chunk
            seen["request"] = buf
            conn.sendall(b"PONG\n")

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        result = check_clamd_health(host="127.0.0.1", port=port, timeout=1.0)
        assert result.get("ok") is True
        assert "PONG" in str(result.get("detail") or "")
        assert seen["request"] == b"PING\n"
    finally:
        listener.close()
        thread.join(timeout=2)


def test_eicar_uses_clamd_instream_protocol() -> None:
    _add_web_to_path()
    from services.proxy_health import test_eicar  # type: ignore

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    captured = {"command": b"", "payload": b""}

    def serve() -> None:
        conn, _addr = listener.accept()
        with conn:
            prefix = b"zINSTREAM\0"
            buf = b""
            while len(buf) < len(prefix):
                chunk = conn.recv(128)
                if not chunk:
                    break
                buf += chunk
            captured["command"] = buf[: len(prefix)]
            rest = buf[len(prefix) :]
            payload = b""
            while True:
                while len(rest) < 4:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    rest += chunk
                if len(rest) < 4:
                    break
                size = int.from_bytes(rest[:4], "big")
                rest = rest[4:]
                if size == 0:
                    break
                while len(rest) < size:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    rest += chunk
                payload += rest[:size]
                rest = rest[size:]
            captured["payload"] = payload
            conn.sendall(b"stream: Eicar-Test-Signature FOUND\0")

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        result = test_eicar(host="127.0.0.1", port=port, timeout=1.0)
        assert result.get("ok") is True
        assert "FOUND" in str(result.get("detail") or "")
        assert captured["command"] == b"zINSTREAM\0"
        assert b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in captured["payload"]
    finally:
        listener.close()
        thread.join(timeout=2)


def test_eicar_reports_socket_failure_without_filesystem_side_effects(tmp_path, monkeypatch) -> None:
    _add_web_to_path()
    from services.proxy_health import test_eicar  # type: ignore

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.close()

    before = set(os.listdir(tmp_path))
    monkeypatch.chdir(tmp_path)
    result = test_eicar(host="127.0.0.1", port=port, timeout=0.2)
    assert result.get("ok") is False
    assert f"127.0.0.1:{port}" in str(result.get("detail") or "")
    assert set(os.listdir(tmp_path)) == before