#!/usr/bin/env python3
"""Run optional/required c-icap AV without spawning probe helper processes."""

from __future__ import annotations

import os
import re
import socket
import socketserver
import sys
from pathlib import Path

TRUE_VALUES = {"1", "true", "yes", "on", "required", "strict"}
CRLF = b"\r\n"
HEADER_END = CRLF + CRLF
FALLBACK_OPEN_ISTAG = '"clamav-fail-open-unavailable"'
FALLBACK_CLOSED_ISTAG = '"clamav-fail-closed-unavailable"'


def env_enabled(value: str | None) -> bool:
    return (value or "").strip().lower() in TRUE_VALUES


def clamd_ready(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(b"PING\n")
            return sock.recv(16).startswith(b"PONG")
    except OSError:
        return False


def _conf_listen_address(conf_path: str) -> tuple[str, int]:
    text = Path(conf_path).read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = re.match(r"(?i)^port\s+(?:(\S+):)?(\d+)\s*$", stripped)
        if not match:
            continue
        host = (match.group(1) or "127.0.0.1").strip() or "127.0.0.1"
        port = int(match.group(2))
        if 1 <= port <= 65535:
            return host, port
    return "127.0.0.1", int(os.environ.get("CICAP_AV_PORT", "14001") or "14001")


def _icap_response(status: str, headers: dict[str, str] | None = None) -> bytes:
    lines = [f"ICAP/1.0 {status}"]
    response_headers = {"Connection": "close"}
    response_headers.update(headers or {})
    return ("\r\n".join([*lines, *[f"{key}: {value}" for key, value in response_headers.items()]]) + "\r\n\r\n").encode("ascii", errors="replace")


class _FailOpenAvHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(2.0)
        data = b""
        while len(data) < 8192 and HEADER_END not in data:
            chunk = self.request.recv(512)
            if not chunk:
                break
            data += chunk
        first = data.split(CRLF, 1)[0].split(b"\n", 1)[0].decode("ascii", errors="replace")
        method = first.split(" ", 1)[0].upper() if first else ""
        fail_open = bool(getattr(self.server, "fail_open", True))
        istag = FALLBACK_OPEN_ISTAG if fail_open else FALLBACK_CLOSED_ISTAG
        if method == "OPTIONS":
            headers = {
                "Methods": "REQMOD, RESPMOD",
                "Service": "ClamAV placeholder; backend unavailable",
                "ISTag": istag,
                "Preview": "0",
                "Options-TTL": "30",
                "Encapsulated": "null-body=0",
            }
            if fail_open:
                headers["Allow"] = "204"
            response = _icap_response(
                "200 OK",
                headers,
            )
        elif method in {"REQMOD", "RESPMOD"}:
            if fail_open:
                response = _icap_response(
                    "204 No Content",
                    {"ISTag": istag, "Encapsulated": "null-body=0"},
                )
            else:
                response = _icap_response(
                    "500 Service Unavailable",
                    {"ISTag": istag, "Encapsulated": "null-body=0"},
                )
        else:
            response = _icap_response(
                "405 Method Not Allowed",
                {"Allow": "REQMOD, RESPMOD, OPTIONS", "Encapsulated": "null-body=0"},
            )
        self.request.sendall(response)


class _FailOpenAvServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    fail_open = True


def run_unavailable_placeholder(
    conf_path: str,
    *,
    host: str,
    port: int,
    fail_open: bool,
) -> None:
    listen_host, listen_port = _conf_listen_address(conf_path)
    sys.stderr.write(
        f"ClamAV backend {host}:{port} is unavailable; "
        f"serving {'fail-open' if fail_open else 'fail-closed'} ICAP placeholder "
        f"on {listen_host}:{listen_port}\n"
    )
    with _FailOpenAvServer((listen_host, listen_port), _FailOpenAvHandler) as server:
        server.fail_open = fail_open
        server.serve_forever()


def run_fail_open_placeholder(conf_path: str, *, host: str, port: int) -> None:
    run_unavailable_placeholder(conf_path, host=host, port=port, fail_open=True)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        sys.stderr.write("usage: cicap_av_runner.py <c-icap-av.conf>\n")
        return 64

    conf_path = argv[1]
    host = (os.environ.get("CLAMD_HOST") or "127.0.0.1").strip() or "127.0.0.1"
    try:
        port = int((os.environ.get("CLAMD_PORT") or "3310").strip())
    except ValueError:
        port = 3310
    required = env_enabled(os.environ.get("CLAMAV_REQUIRED")) or env_enabled(
        os.environ.get("FILE_SECURITY_AV_REQUIRED")
    )

    if clamd_ready(host, port):
        os.execv(  # noqa: S606 - replace runner with c-icap in the container.
            "/usr/bin/c-icap",
            ["/usr/bin/c-icap", "-N", "-f", conf_path],
        )

    run_unavailable_placeholder(
        conf_path,
        host=host,
        port=port,
        fail_open=not required,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
