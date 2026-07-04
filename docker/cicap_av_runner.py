#!/usr/bin/env python3
"""Run optional/required c-icap AV without spawning probe helper processes."""

from __future__ import annotations

import os
import socket
import sys
import time

TRUE_VALUES = {"1", "true", "yes", "on", "required", "strict"}


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

    if required:
        for _ in range(120):
            if clamd_ready(host, port):
                os.execv(  # noqa: S606 - replace runner with c-icap in the container.
                    "/usr/bin/c-icap",
                    ["/usr/bin/c-icap", "-N", "-f", conf_path],
                )
            time.sleep(1)
        sys.stderr.write(f"required ClamAV backend {host}:{port} is not responding\n")
        return 1

    if clamd_ready(host, port):
        os.execv(  # noqa: S606 - replace runner with c-icap in the container.
            "/usr/bin/c-icap",
            ["/usr/bin/c-icap", "-N", "-f", conf_path],
        )

    sys.stderr.write(
        f"optional ClamAV backend {host}:{port} is unavailable; "
        "AV ICAP service remains disabled while Squid bypasses AV adaptation\n"
    )
    os.execv(  # noqa: S606 - keep the optional AV supervisor process alive.
        "/bin/sleep",
        ["/bin/sleep", "infinity"],
    )
    message = "exec sleep infinity returned unexpectedly"
    raise RuntimeError(message)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
