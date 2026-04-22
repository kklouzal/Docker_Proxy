from __future__ import annotations

import os
import socket
from typing import Any, Callable

from services.errors import public_error_message


ErrorFormatter = Callable[[Exception], str]


def _format_error(
    exc: Exception,
    *,
    error_formatter: ErrorFormatter | None = None,
    default: str = "Operation failed. Check server logs for details.",
) -> str:
    if error_formatter is not None:
        try:
            return str(error_formatter(exc))
        except Exception:
            pass
    return public_error_message(exc, default=default)


def check_tcp(
    host: str,
    port: int,
    *,
    timeout: float = 0.75,
    error_formatter: ErrorFormatter | None = None,
) -> dict[str, Any]:
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return {"ok": True, "detail": "tcp connect ok"}
    except Exception as exc:
        return {"ok": False, "detail": _format_error(exc, error_formatter=error_formatter)}


def is_local_host(host: str) -> bool:
    normalized = (host or "").strip().lower()
    return normalized in ("", "127.0.0.1", "localhost", "::1", "0.0.0.0", "::")


def has_listen_socket(path: str, port: int) -> bool:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            next(fh, None)
            for line in fh:
                parts = line.split()
                if len(parts) < 4:
                    continue
                local_addr = parts[1]
                state = parts[3]
                if state != "0A":
                    continue
                try:
                    _addr, port_hex = local_addr.rsplit(":", 1)
                    if int(port_hex, 16) == int(port):
                        return True
                except Exception:
                    continue
    except FileNotFoundError:
        return False
    except Exception:
        return False
    return False


def check_local_listener(service_name: str, host: str, port: int) -> dict[str, Any]:
    if has_listen_socket("/proc/net/tcp", port) or has_listen_socket("/proc/net/tcp6", port):
        return {"ok": True, "detail": f"{service_name} listening on {host}:{port}"}
    return {"ok": False, "detail": f"{service_name} is not listening on {host}:{port}"}


def check_icap_service(
    host: str,
    port: int,
    service: str,
    *,
    timeout: float = 1.0,
    user_agent: str = "squid-flask-proxy",
    success_detail: str | None = None,
    error_formatter: ErrorFormatter | None = None,
) -> dict[str, Any]:
    path = service if service.startswith("/") else f"/{service}"
    req = (
        f"OPTIONS icap://{host}:{port}{path} ICAP/1.0\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {user_agent}\r\n"
        "Encapsulated: null-body=0\r\n\r\n"
    ).encode("ascii", errors="replace")
    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(req)
            data = sock.recv(512)
        first = data.split(b"\r\n", 1)[0].decode("ascii", errors="replace") if data else "no data"
        if data.startswith(b"ICAP/1.0 200"):
            return {"ok": True, "detail": success_detail or first}
        return {"ok": False, "detail": first}
    except Exception as exc:
        return {"ok": False, "detail": _format_error(exc, error_formatter=error_formatter)}


def _resolve_clamd_target(host: str | None = None, port: int | None = None) -> tuple[str, int]:
    resolved_host = (host or os.environ.get("CLAMD_HOST") or "127.0.0.1").strip() or "127.0.0.1"
    try:
        resolved_port = int(port if port is not None else (os.environ.get("CLAMD_PORT") or "3310"))
    except Exception:
        resolved_port = 3310
    return resolved_host, resolved_port


def _recv_clamd_reply(sock: socket.socket, *, max_bytes: int = 64) -> bytes:
    buf = b""
    while len(buf) < max_bytes:
        chunk = sock.recv(min(512, max_bytes - len(buf)))
        if not chunk:
            break
        buf += chunk
        if b"\0" in buf or b"\n" in buf:
            break
    return buf


def check_clamd(
    host: str | None = None,
    port: int | None = None,
    *,
    timeout: float = 1.0,
    error_formatter: ErrorFormatter | None = None,
) -> dict[str, Any]:
    resolved_host, resolved_port = _resolve_clamd_target(host=host, port=port)
    try:
        with socket.create_connection((resolved_host, resolved_port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(b"PING\n")
            data = _recv_clamd_reply(sock, max_bytes=64)
        detail = data.replace(b"\0", b"\n").decode("utf-8", errors="replace").strip() or "no data"
        return {"ok": data.startswith(b"PONG"), "detail": f"{detail} ({resolved_host}:{resolved_port})"}
    except Exception as exc:
        error_detail = _format_error(exc, error_formatter=error_formatter)
        return {"ok": False, "detail": f"{resolved_host}:{resolved_port}: {error_detail}"}