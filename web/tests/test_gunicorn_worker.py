"""The Admin UI gunicorn worker keeps serving while browsers hold idle connections open."""

from __future__ import annotations

import datetime as dt
import http.client
import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

WEB_DIR = Path(__file__).resolve().parents[1]

APP_SOURCE = """
def app(environ, start_response):
    start_response("200 OK", [("Content-Type", "text/plain"), ("Content-Length", "2")])
    return [b"ok"]
"""


def _self_signed(tmp_path: Path) -> tuple[Path, Path]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
def tls_server(tmp_path: Path):
    cert, key = _self_signed(tmp_path)
    (tmp_path / "tinyapp.py").write_text(APP_SOURCE)
    port = _free_port()
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "gunicorn",
            "-b",
            f"127.0.0.1:{port}",
            "--chdir",
            str(tmp_path),
            "--pythonpath",
            str(WEB_DIR),
            "--worker-class",
            "gunicorn_worker.AdminThreadWorker",
            "--workers",
            "1",
            "--threads",
            "2",
            "--keep-alive",
            "5",
            "--certfile",
            str(cert),
            "--keyfile",
            str(key),
            "--no-control-socket",
            "tinyapp:app",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    context = ssl._create_unverified_context()  # ruff: ignore[suspicious-unverified-context-usage] - self-signed test cert
    deadline = time.monotonic() + 20
    while True:
        try:
            _get(port, context, timeout=2)
            break
        except OSError:
            if proc.poll() is not None or time.monotonic() > deadline:
                proc.kill()
                stderr = proc.communicate(timeout=5)[1].decode(errors="replace")
                pytest.fail(f"gunicorn did not start: {stderr[-2000:]}")
            time.sleep(0.1)
    try:
        yield port, context
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


def _get(port: int, context: ssl.SSLContext, *, timeout: float) -> int:
    conn = http.client.HTTPSConnection(
        "127.0.0.1", port, timeout=timeout, context=context
    )
    try:
        conn.request("GET", "/")
        response = conn.getresponse()
        response.read()
        return response.status
    finally:
        conn.close()


def test_idle_connections_do_not_block_requests(tls_server) -> None:
    port, context = tls_server
    idle: list[socket.socket] = []
    try:
        # More idle connections than pool threads: after the handshake (the
        # browser preconnect case) and before any bytes (a bare TCP connect).
        for _ in range(3):
            raw = socket.create_connection(("127.0.0.1", port), timeout=5)
            idle.append(context.wrap_socket(raw, server_hostname="localhost"))
        idle.extend(
            socket.create_connection(("127.0.0.1", port), timeout=5) for _ in range(2)
        )
        time.sleep(0.3)

        for _ in range(5):
            started = time.monotonic()
            assert _get(port, context, timeout=3) == 200
            assert time.monotonic() - started < 1.0
    finally:
        for sock in idle:
            sock.close()


def test_request_on_a_deferred_tls_connection_is_served(tls_server) -> None:
    port, context = tls_server
    raw = socket.create_connection(("127.0.0.1", port), timeout=5)
    with context.wrap_socket(raw, server_hostname="localhost") as sock:
        time.sleep(0.5)  # deferred to the poller meanwhile
        sock.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        response = b""
        while not response.endswith(b"\r\n\r\nok"):
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
    assert response.startswith(b"HTTP/1.1 200 OK")
    assert response.endswith(b"ok")
