from __future__ import annotations

import importlib.util
import socket
import threading
from pathlib import Path


def _load_runner():
    path = Path(__file__).resolve().parents[2] / "docker" / "cicap_av_runner.py"
    spec = importlib.util.spec_from_file_location("cicap_av_runner", path)
    assert spec
    assert spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_optional_unavailable_clamd_serves_fail_open_placeholder(monkeypatch) -> None:
    runner = _load_runner()
    calls: list[tuple[str, str, int, bool]] = []

    monkeypatch.delenv("CLAMAV_REQUIRED", raising=False)
    monkeypatch.delenv("FILE_SECURITY_AV_REQUIRED", raising=False)
    monkeypatch.setattr(runner, "clamd_ready", lambda _host, _port: False)
    monkeypatch.setattr(
        runner,
        "run_unavailable_placeholder",
        lambda conf_path, *, host, port, fail_open: calls.append(
            (conf_path, host, port, fail_open),
        ),
    )

    assert runner.main(["cicap_av_runner.py", "/etc/c-icap/av.conf"]) == 0

    assert calls == [("/etc/c-icap/av.conf", "127.0.0.1", 3310, True)]


def test_required_unavailable_clamd_serves_fail_closed_placeholder(monkeypatch) -> None:
    runner = _load_runner()
    calls: list[tuple[str, str, int, bool]] = []

    monkeypatch.setenv("CLAMAV_REQUIRED", "1")
    monkeypatch.setattr(runner, "clamd_ready", lambda _host, _port: False)
    monkeypatch.setattr(
        runner,
        "run_unavailable_placeholder",
        lambda conf_path, *, host, port, fail_open: calls.append(
            (conf_path, host, port, fail_open),
        ),
    )

    assert runner.main(["cicap_av_runner.py", "/etc/c-icap/av.conf"]) == 0
    assert calls == [("/etc/c-icap/av.conf", "127.0.0.1", 3310, False)]


def test_ready_clamd_execs_c_icap(monkeypatch) -> None:
    runner = _load_runner()
    exec_calls: list[tuple[str, list[str]]] = []

    class ExecCalledError(Exception):
        pass

    def fake_execv(path, argv):
        exec_calls.append((path, argv))
        raise ExecCalledError

    monkeypatch.setattr(runner, "clamd_ready", lambda _host, _port: True)
    monkeypatch.setattr(runner.os, "execv", fake_execv)

    try:
        runner.main(["cicap_av_runner.py", "/etc/c-icap/av.conf"])
    except ExecCalledError:
        pass

    assert exec_calls == [
        ("/usr/bin/c-icap", ["/usr/bin/c-icap", "-N", "-f", "/etc/c-icap/av.conf"]),
    ]


def _placeholder_exchange(runner, *, fail_open: bool, method: str) -> bytes:
    with runner._FailOpenAvServer(
        ("127.0.0.1", 0), runner._FailOpenAvHandler
    ) as server:
        server.fail_open = fail_open
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        request = (
            f"{method} icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
            "Host: 127.0.0.1\r\n"
            "Allow: 204\r\n"
            "Encapsulated: null-body=0\r\n\r\n"
        ).encode("ascii")
        with socket.create_connection(("127.0.0.1", port), timeout=1) as sock:
            sock.settimeout(1)
            sock.sendall(request)
            response = sock.recv(4096)
        server.shutdown()
        thread.join(timeout=1)
    return response


def test_fail_open_placeholder_returns_204_for_transactions() -> None:
    runner = _load_runner()

    reqmod = _placeholder_exchange(runner, fail_open=True, method="REQMOD")
    respmod = _placeholder_exchange(runner, fail_open=True, method="RESPMOD")

    assert reqmod.startswith(b"ICAP/1.0 204 No Content\r\n")
    assert respmod.startswith(b"ICAP/1.0 204 No Content\r\n")
    assert b"clamav-fail-open-unavailable" in reqmod
    assert b"clamav-fail-open-unavailable" in respmod


def test_fail_closed_placeholder_keeps_service_unavailable_transactions() -> None:
    runner = _load_runner()

    response = _placeholder_exchange(runner, fail_open=False, method="RESPMOD")

    assert response.startswith(b"ICAP/1.0 500 Service Unavailable\r\n")
    assert b"clamav-fail-closed-unavailable" in response


def _placeholder_exchange_with_body(
    runner, *, fail_open: bool, method: str, body: bytes
) -> tuple[bytes, float]:
    with runner._FailOpenAvServer(
        ("127.0.0.1", 0), runner._FailOpenAvHandler
    ) as server:
        server.fail_open = fail_open
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        http_header = (
            b"POST /upload HTTP/1.1\r\n"
            b"Content-Type: application/octet-stream\r\n"
            + f"Content-Length: {len(body)}\r\n".encode("ascii")
            + b"\r\n"
        )
        chunked = f"{len(body):X}\r\n".encode("ascii") + body + b"\r\n0\r\n\r\n"
        encapsulated = "req-body" if method == "REQMOD" else "res-body"
        request = (
            (
                f"{method} icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
                "Host: 127.0.0.1\r\n"
                "Allow: 204\r\n"
                f"Encapsulated: req-hdr=0, {encapsulated}={len(http_header)}\r\n\r\n"
            ).encode("ascii")
            + http_header
            + chunked
        )
        with socket.create_connection(("127.0.0.1", port), timeout=1) as sock:
            sock.settimeout(1)
            started = __import__("time").monotonic()
            sock.sendall(request)
            response = sock.recv(4096)
            elapsed = __import__("time").monotonic() - started
        server.shutdown()
        thread.join(timeout=1)
    return response, elapsed


def test_fail_open_placeholder_drains_large_reqmod_body_before_204() -> None:
    runner = _load_runner()

    response, elapsed = _placeholder_exchange_with_body(
        runner, fail_open=True, method="REQMOD", body=b"x" * (1024 * 1024)
    )

    assert response.startswith(b"ICAP/1.0 204 No Content\r\n")
    assert elapsed < 1


def test_fail_open_placeholder_drains_respmod_body_before_204() -> None:
    runner = _load_runner()

    response, elapsed = _placeholder_exchange_with_body(
        runner, fail_open=True, method="RESPMOD", body=b"hello" * 1024
    )

    assert response.startswith(b"ICAP/1.0 204 No Content\r\n")
    assert elapsed < 1


def _placeholder_preview_exchange(
    runner, *, method: str
) -> tuple[bytes, bytes, bytes]:
    with runner._FailOpenAvServer(
        ("127.0.0.1", 0), runner._FailOpenAvHandler
    ) as server:
        server.fail_open = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        http_header = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/octet-stream\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"
        )
        encapsulated = "req-body" if method == "REQMOD" else "res-body"
        request_prefix = (
            (
                f"{method} icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
                "Host: 127.0.0.1\r\n"
                "Allow: 204\r\n"
                "Preview: 4\r\n"
                f"Encapsulated: req-hdr=0, {encapsulated}={len(http_header)}\r\n\r\n"
            ).encode("ascii")
            + http_header
        )
        preview = b"4\r\ntest\r\n0\r\n\r\n"
        remainder = b"5\r\n-rest\r\n0\r\n\r\n"
        with socket.create_connection(("127.0.0.1", port), timeout=1) as sock:
            sock.settimeout(1)
            sock.sendall(request_prefix + preview)
            interim = sock.recv(4096)
            sock.sendall(remainder)
            final = sock.recv(4096)
            extra = sock.recv(4096)
        server.shutdown()
        thread.join(timeout=1)
    return interim, final, extra


def test_fail_open_placeholder_continues_reqmod_preview_before_204() -> None:
    runner = _load_runner()

    interim, final, extra = _placeholder_preview_exchange(runner, method="REQMOD")

    assert interim == b"ICAP/1.0 100 Continue\r\n\r\n"
    assert final.startswith(b"ICAP/1.0 204 No Content\r\n")
    assert extra == b""


def test_fail_open_placeholder_continues_respmod_preview_before_204() -> None:
    runner = _load_runner()

    interim, final, extra = _placeholder_preview_exchange(runner, method="RESPMOD")

    assert interim == b"ICAP/1.0 100 Continue\r\n\r\n"
    assert final.startswith(b"ICAP/1.0 204 No Content\r\n")
    assert extra == b""
