from __future__ import annotations

import os
import re
import socket
import subprocess
import threading
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
HEALTHCHECK = REPO_ROOT / "docker" / "healthcheck.sh"


def _extract_remote_clamd_probe() -> str:
    script = HEALTHCHECK.read_text(encoding="utf-8")
    match = re.search(
        r"^remote_clamd_responding\(\) \{\n(?P<body>.*?)^\}\n",
        script,
        flags=re.MULTILINE | re.DOTALL,
    )
    if not match:
        message = "remote_clamd_responding function not found"
        raise AssertionError(message)
    return match.group("body")


def _run_probe_against_chunks(
    chunks: list[bytes],
    *,
    delay: float = 0.0,
) -> tuple[bool, bytes]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    seen = bytearray()

    def serve() -> None:
        try:
            conn, _addr = listener.accept()
        except OSError:
            return
        with conn:
            while b"\n" not in seen:
                data = conn.recv(64)
                if not data:
                    break
                seen.extend(data)
            for chunk in chunks:
                if delay:
                    time.sleep(delay)
                conn.sendall(chunk)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        env = {
            **os.environ,
            "CLAMD_HOST": "127.0.0.1",
            "CLAMD_PORT": str(port),
        }
        result = subprocess.run(
            ["sh", "-c", _extract_remote_clamd_probe()],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            timeout=3,
            check=False,
        )
        return result.returncode == 0, bytes(seen)
    finally:
        listener.close()
        thread.join(timeout=1)


@pytest.mark.parametrize(
    ("name", "chunks", "delay", "expected_ok"),
    [
        ("lf terminator", [b"PONG\n"], 0.0, True),
        ("crlf terminator", [b"PONG\r\n"], 0.0, True),
        ("nul terminator", [b"PONG\0"], 0.0, True),
        ("fragmented reply", [b"PO", b"NG\n"], 0.05, True),
        ("extra bytes after terminator", [b"PONG\nVERSION\n"], 0.0, False),
        ("pong prefix wrong command", [b"PONG-OLD\n"], 0.0, False),
        ("leading whitespace", [b" PONG\n"], 0.0, False),
        ("trailing whitespace", [b"PONG \n"], 0.0, False),
        ("lowercase", [b"pong\n"], 0.0, False),
        ("unterminated eof", [b"PONG"], 0.0, False),
        ("oversized unterminated", [b"PONG" + (b"X" * 128)], 0.0, False),
        ("empty eof", [], 0.0, False),
    ],
)
def test_healthcheck_remote_clamd_probe_accepts_only_exact_bounded_ping_pong(
    name: str,
    chunks: list[bytes],
    delay: float,
    expected_ok: bool,
) -> None:
    ok, request = _run_probe_against_chunks(chunks, delay=delay)

    assert ok is expected_ok, name
    assert request == b"PING\n", name


def test_healthcheck_remote_clamd_probe_reports_timeout() -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    seen = bytearray()

    def serve() -> None:
        try:
            conn, _addr = listener.accept()
        except OSError:
            return
        with conn:
            while b"\n" not in seen:
                data = conn.recv(64)
                if not data:
                    break
                seen.extend(data)
            time.sleep(2.0)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        env = {
            **os.environ,
            "CLAMD_HOST": "127.0.0.1",
            "CLAMD_PORT": str(port),
        }
        result = subprocess.run(
            ["sh", "-c", _extract_remote_clamd_probe()],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            timeout=4,
            check=False,
        )
    finally:
        listener.close()
        thread.join(timeout=1)

    assert result.returncode != 0
    assert bytes(seen) == b"PING\n"


def test_healthcheck_remote_clamd_probe_reports_oserror() -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.close()
    env = {
        **os.environ,
        "CLAMD_HOST": "127.0.0.1",
        "CLAMD_PORT": str(port),
    }

    result = subprocess.run(
        ["sh", "-c", _extract_remote_clamd_probe()],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        timeout=3,
        check=False,
    )

    assert result.returncode != 0
