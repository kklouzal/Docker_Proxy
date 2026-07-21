from __future__ import annotations

import json
import os
import pathlib
import re
import socket
from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qs, urlsplit, urlunsplit

from services.errors import public_error_message

ErrorFormatter = Callable[[Exception], str]

_ICAP_STATUS_LINE_RE = re.compile(
    r"^ICAP/1\.0 (?P<code>[0-9]{3}) (?P<reason>[!-~](?:[ -~]*[!-~])?)$",
)
_ICAP_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


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
        return {
            "ok": False,
            "detail": _format_error(exc, error_formatter=error_formatter),
        }


def is_local_host(host: str) -> bool:
    normalized = (host or "").strip().lower()
    return normalized in {"", "127.0.0.1", "localhost", "::1", "0.0.0.0", "::"}


def has_listen_socket(path: str, port: int) -> bool:
    try:
        with pathlib.Path(path).open(encoding="utf-8", errors="replace") as fh:
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
    if has_listen_socket("/proc/net/tcp", port) or has_listen_socket(
        "/proc/net/tcp6",
        port,
    ):
        return {"ok": True, "detail": f"{service_name} listening on {host}:{port}"}
    return {"ok": False, "detail": f"{service_name} is not listening on {host}:{port}"}


def _recv_status_line(sock: socket.socket, *, max_bytes: int = 512) -> bytes:
    buf = b""
    while len(buf) < max_bytes:
        chunk = sock.recv(min(512, max_bytes - len(buf)))
        if not chunk:
            break
        buf += chunk
        if b"\n" in buf:
            break
    return buf.split(b"\r\n", 1)[0].split(b"\n", 1)[0].strip()


def _recv_response_head(sock: socket.socket, *, max_bytes: int = 8192) -> bytes:
    buf = b""
    while len(buf) < max_bytes:
        chunk = sock.recv(min(512, max_bytes - len(buf)))
        if not chunk:
            break
        buf += chunk
        if b"\r\n\r\n" in buf or b"\n\n" in buf:
            break
    if b"\r\n\r\n" in buf:
        return buf.split(b"\r\n\r\n", 1)[0]
    if b"\n\n" in buf:
        return buf.split(b"\n\n", 1)[0]
    return buf


def _read_icap_response_head(
    sock: socket.socket,
    *,
    max_bytes: int = 8192,
) -> tuple[bytes, bool, bool]:
    buf = b""
    while len(buf) < max_bytes:
        chunk = sock.recv(min(512, max_bytes - len(buf)))
        if not chunk:
            break
        buf += chunk
        if b"\r\n\r\n" in buf:
            head, tail = buf.split(b"\r\n\r\n", 1)
            return head, True, bool(tail)
        if b"\n\n" in buf:
            return buf, False, False
    return buf, False, False


def _decode_status_line(data: bytes) -> str:
    return data.decode("ascii", errors="replace") if data else "no data"


def _http_header_value(headers: dict[str, list[str]], name: str) -> str:
    values = headers.get(name.lower()) or []
    return values[-1] if values else ""


def _parse_http_response_head(data: bytes) -> tuple[str, dict[str, list[str]]]:
    lines = data.decode("iso-8859-1", errors="replace").split("\r\n")
    if len(lines) == 1:
        lines = lines[0].split("\n")
    status = (lines[0] if lines else "").strip()
    headers: dict[str, list[str]] = {}
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        name, value = line.split(":", 1)
        normalized = name.strip().lower()
        if normalized:
            headers.setdefault(normalized, []).append(value.strip())
    return status, headers


def _parse_protocol_status_code(status_line: str) -> int | None:
    parts = str(status_line or "").split(None, 2)
    if len(parts) < 2:
        return None
    try:
        return int(parts[1])
    except Exception:
        return None


def _icap_status_reason(status_line: str) -> str:
    parts = str(status_line or "").split(None, 2)
    return parts[2] if len(parts) >= 3 else ""


def _parse_icap_options_response_head(
    head: bytes,
    *,
    headers_complete: bool,
    has_extra_data: bool,
) -> tuple[bool, str]:
    if not head:
        return False, "no ICAP response headers"
    if not headers_complete:
        if b"\n\n" in head:
            return False, "malformed ICAP header terminator"
        first = head.split(b"\r\n", 1)[0].split(b"\n", 1)[0]
        try:
            first_line = first.decode("ascii")
        except UnicodeDecodeError:
            return False, "non-ASCII ICAP response header"
        match = _ICAP_STATUS_LINE_RE.fullmatch(first_line)
        if match and match.group("code") != "200":
            return False, first_line
        return False, "incomplete ICAP response headers"

    block = head
    if b"\n" in block.replace(b"\r\n", b"") or b"\r" in block.replace(b"\r\n", b""):
        return False, "malformed ICAP header line endings"
    lines = block.split(b"\r\n")
    try:
        decoded = [line.decode("ascii") for line in lines]
    except UnicodeDecodeError:
        return False, "non-ASCII ICAP response header"
    for line in decoded:
        if any((ord(char) < 32 and char != "\t") or ord(char) == 127 for char in line):
            return False, "control character in ICAP response header"
    first_line = decoded[0] if decoded else ""
    match = _ICAP_STATUS_LINE_RE.fullmatch(first_line)
    if not match:
        return False, f"malformed ICAP status line: {first_line or 'empty'}"
    if match.group("code") != "200":
        return False, first_line
    if has_extra_data:
        return False, "unexpected data after ICAP response headers"

    headers: dict[str, list[str]] = {}
    for line in decoded[1:]:
        if not line:
            return False, "malformed ICAP header line: empty"
        if ":" not in line:
            return False, f"malformed ICAP header line: {line}"
        key, value = line.split(":", 1)
        if not _ICAP_HEADER_NAME_RE.fullmatch(key):
            return False, f"malformed ICAP header name: {key or 'empty'}"
        headers.setdefault(key.lower(), []).append(value.strip())
    duplicates = sorted(name for name, values in headers.items() if len(values) > 1)
    if duplicates:
        return False, f"duplicate ICAP response header: {duplicates[0]}"
    return True, first_line


def _normalize_icap_istag(value: str) -> str:
    return str(value or "").strip().strip('"').lower()


def _read_http_response(
    sock: socket.socket,
    *,
    max_header_bytes: int = 8192,
    max_body_bytes: int = 65536,
) -> tuple[bytes, bytes, bool, bool]:
    """Read a bounded HTTP response head and enough body to validate /health."""
    data = b""
    headers_complete = False
    while len(data) < max_header_bytes:
        chunk = sock.recv(min(512, max_header_bytes - len(data)))
        if not chunk:
            break
        data += chunk
        if b"\r\n\r\n" in data or b"\n\n" in data:
            headers_complete = True
            break
    if b"\r\n\r\n" in data:
        head, body = data.split(b"\r\n\r\n", 1)
    elif b"\n\n" in data:
        head, body = data.split(b"\n\n", 1)
    else:
        return data, b"", headers_complete, False

    _status, headers = _parse_http_response_head(head)
    body_complete = False
    transfer_encoding = _http_header_value(headers, "transfer-encoding").lower()
    content_length_header = _http_header_value(headers, "content-length")
    content_length: int | None = None
    if content_length_header:
        try:
            content_length = max(0, int(content_length_header))
        except Exception:
            content_length = None

    if content_length is not None:
        desired = min(content_length, max_body_bytes)
        while len(body) < desired:
            chunk = sock.recv(min(512, desired - len(body)))
            if not chunk:
                break
            body += chunk
        body = body[:desired]
        body_complete = len(body) >= desired and content_length <= max_body_bytes
    elif "chunked" in transfer_encoding:
        while len(body) < max_body_bytes:
            if b"\r\n0\r\n" in body or b"\n0\n" in body:
                body_complete = True
                break
            chunk = sock.recv(min(512, max_body_bytes - len(body)))
            if not chunk:
                break
            body += chunk
    else:
        while len(body) < max_body_bytes:
            chunk = sock.recv(min(512, max_body_bytes - len(body)))
            if not chunk:
                body_complete = True
                break
            body += chunk
    return head, body[:max_body_bytes], headers_complete, body_complete


def _decode_chunked_body(data: bytes) -> tuple[bytes, bool]:
    body = bytearray()
    index = 0
    while index < len(data):
        line_end = data.find(b"\n", index)
        if line_end < 0:
            return bytes(body), False
        size_line = data[index:line_end].strip().split(b";", 1)[0]
        try:
            size = int(size_line, 16)
        except Exception:
            return bytes(body), False
        index = line_end + 1
        if size == 0:
            return bytes(body), True
        if len(data) - index < size:
            return bytes(body), False
        body.extend(data[index : index + size])
        index += size
        if data[index : index + 2] == b"\r\n":
            index += 2
        elif data[index : index + 1] == b"\n":
            index += 1
    return bytes(body), False


def _target_is_local_json_health(target_url: str) -> bool:
    parsed = urlsplit(str(target_url or ""))
    return parsed.scheme.lower() == "http" and parsed.path.rstrip("/") in {
        "/health",
        "/__docker_proxy_forwarding_canary",
    }


def _target_is_forwarding_canary(target_url: str) -> bool:
    parsed = urlsplit(str(target_url or ""))
    return (
        parsed.scheme.lower() == "http"
        and parsed.path.rstrip("/") == "/__docker_proxy_forwarding_canary"
    )


def _target_points_at_proxy_listener(
    *,
    target_url: str,
    proxy_host: str,
    proxy_port: int,
) -> bool:
    parsed = urlsplit(str(target_url or ""))
    if parsed.scheme.lower() != "http":
        return False
    target_host = parsed.hostname or ""
    target_port = int(parsed.port or 80)
    return (
        target_port == int(proxy_port)
        and is_local_host(target_host)
        and is_local_host(proxy_host)
    )


def _target_host_header(target_url: str) -> str:
    parsed = urlsplit(str(target_url or ""))
    if not parsed.hostname:
        return "127.0.0.1"
    host = parsed.hostname
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    if parsed.port is not None:
        return f"{host}:{parsed.port}"
    return host


def _append_forwarding_canary_probe(target_url: str) -> str:
    if not _target_is_forwarding_canary(target_url):
        return target_url
    parsed = urlsplit(str(target_url or ""))
    existing_probe = (
        parse_qs(parsed.query, keep_blank_values=True).get("probe") or [""]
    )[-1]
    if existing_probe:
        return target_url
    separator = "&" if parsed.query else "?"
    return f"{target_url}{separator}probe=squid-respmod"


def _forwarding_canary_probe_token(target_url: str) -> str:
    parsed = urlsplit(str(target_url or ""))
    return (parse_qs(parsed.query, keep_blank_values=True).get("probe") or [""])[-1]


def _safe_forwarding_probe_url(target_url: str) -> tuple[str, str]:
    raw = str(target_url or "").strip()
    if not raw:
        return "", "unsafe forwarding probe target URL: empty"
    if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in raw):
        return "", "unsafe forwarding probe target URL: whitespace/control character"
    if "\\" in raw:
        return "", "unsafe forwarding probe target URL: backslash"
    try:
        parsed = urlsplit(raw)
        _port = parsed.port
    except Exception:
        return "", "unsafe forwarding probe target URL: malformed"
    if parsed.scheme.lower() != "http" or not parsed.netloc or not parsed.hostname:
        return "", "unsafe forwarding probe target URL: expected absolute http URL"
    if parsed.username is not None or parsed.password is not None:
        return "", "unsafe forwarding probe target URL: embedded credentials"
    if parsed.fragment:
        return "", "unsafe forwarding probe target URL: fragment"
    return urlunsplit(("http", parsed.netloc, parsed.path or "/", parsed.query, "")), ""


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
            head, headers_complete, has_extra_data = _read_icap_response_head(sock)
        ok, detail = _parse_icap_options_response_head(
            head,
            headers_complete=headers_complete,
            has_extra_data=has_extra_data,
        )
        if ok:
            return {"ok": True, "detail": success_detail or detail}
        return {"ok": False, "detail": detail}
    except Exception as exc:
        return {
            "ok": False,
            "detail": _format_error(exc, error_formatter=error_formatter),
        }


def check_http_proxy_forwarding(
    *,
    proxy_host: str = "127.0.0.1",
    proxy_port: int,
    target_url: str,
    timeout: float = 1.0,
    user_agent: str = "squid-flask-proxy-forwarding-health",
    error_formatter: ErrorFormatter | None = None,
) -> dict[str, Any]:
    """Probe the explicit Squid request path without external traffic.

    The probe sends a tiny absolute-form HTTP request through Squid to a local
    canary origin. A TCP-only listener check can pass while Squid's forwarding
    or adaptation path is wedged; this bounded request exercises forwarding,
    loopback origin reachability, and any response ICAP path configured for
    ordinary GET traffic without relying on the public PAC listener that serves
    clients.
    """
    safe_target_url, unsafe_detail = _safe_forwarding_probe_url(target_url)
    if unsafe_detail:
        return {
            "ok": False,
            "detail": unsafe_detail,
            "probe_url": str(target_url or ""),
        }
    request_url = _append_forwarding_canary_probe(safe_target_url)
    if _target_points_at_proxy_listener(
        target_url=request_url,
        proxy_host=proxy_host,
        proxy_port=proxy_port,
    ):
        return {
            "ok": False,
            "detail": (
                "refusing forwarding probe target that points back at the "
                "explicit proxy listener"
            ),
            "probe_url": request_url,
        }

    try:
        with socket.create_connection(
            (proxy_host, int(proxy_port)),
            timeout=timeout,
        ) as sock:
            sock.settimeout(timeout)
            request = (
                f"GET {request_url} HTTP/1.1\r\n"
                f"Host: {_target_host_header(request_url)}\r\n"
                f"User-Agent: {user_agent}\r\n"
                "Accept: application/json, */*;q=0.1\r\n"
                "Cache-Control: no-cache\r\n"
                "Pragma: no-cache\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii", errors="replace")
            sock.sendall(request)
            head, body, headers_complete, body_complete = _read_http_response(sock)
        first, headers = _parse_http_response_head(head)
        if not headers_complete:
            return {
                "ok": False,
                "detail": first
                or "incomplete HTTP response from proxy forwarding path",
                "probe_url": request_url,
                "headers_complete": False,
            }
        parts = first.split()
        try:
            code = int(parts[1]) if len(parts) > 1 else 0
        except Exception:
            code = 0
        status_ok = first.startswith("HTTP/") and 200 <= code < 400
        detail = first or "no HTTP status from proxy forwarding path"
        local_health_ok: bool | None = None
        canary_probe_ok: bool | None = None
        if status_ok and _target_is_local_json_health(request_url):
            response_body = body
            if "chunked" in _http_header_value(headers, "transfer-encoding").lower():
                response_body, body_complete = _decode_chunked_body(body)
            if not body_complete:
                detail = f"{detail}; incomplete local health response body"
                status_ok = False
                local_health_ok = False
            else:
                try:
                    payload = json.loads(response_body.decode("utf-8"))
                    local_health_ok = bool(
                        isinstance(payload, dict) and payload.get("ok") is True,
                    )
                    if _target_is_forwarding_canary(request_url):
                        expected_probe = _forwarding_canary_probe_token(request_url)
                        canary_probe_ok = bool(
                            isinstance(payload, dict)
                            and payload.get("service")
                            == "docker-proxy-forwarding-canary"
                            and payload.get("probe") == expected_probe
                        )
                        local_health_ok = local_health_ok and canary_probe_ok
                except Exception:
                    local_health_ok = False
                    canary_probe_ok = (
                        False if _target_is_forwarding_canary(request_url) else None
                    )
                if local_health_ok:
                    detail = f"{detail}; local health ok"
                else:
                    detail = f"{detail}; local health body did not confirm ok"
                status_ok = status_ok and local_health_ok
        return {
            "ok": status_ok,
            "detail": detail,
            "status_code": code,
            "probe_url": request_url,
            "headers_complete": True,
            "body_complete": body_complete,
            "local_health_ok": local_health_ok,
            "canary_probe_ok": canary_probe_ok,
        }
    except Exception as exc:
        return {
            "ok": False,
            "detail": _format_error(
                exc,
                error_formatter=error_formatter,
                default=(
                    f"Failed to forward local health request through Squid at "
                    f"{proxy_host}:{proxy_port}."
                ),
            ),
        }


def annotate_service_target(
    result: dict[str, Any],
    *,
    host: str,
    port: int,
    service: str = "",
) -> dict[str, Any]:
    status = dict(result or {})
    status["ok"] = bool(status.get("ok"))
    status["detail"] = str(status.get("detail") or "unavailable")
    status["host"] = host
    status["port"] = int(port)
    status["target"] = f"{host}:{port}"
    if service:
        status["service"] = service
    return status


def resolve_host_port(
    *,
    host_env: str,
    port_env: str,
    default_host: str = "127.0.0.1",
    default_port: int,
) -> tuple[str, int]:
    resolved_host = (os.environ.get(host_env) or default_host).strip() or default_host
    try:
        resolved_port = int(os.environ.get(port_env, default_port))
    except Exception:
        resolved_port = int(default_port)
    return resolved_host, resolved_port


def _resolve_clamd_target(
    host: str | None = None,
    port: int | None = None,
) -> tuple[str, int]:
    resolved_host = (
        host or os.environ.get("CLAMD_HOST") or "127.0.0.1"
    ).strip() or "127.0.0.1"
    try:
        resolved_port = int(
            port if port is not None else (os.environ.get("CLAMD_PORT") or "3310"),
        )
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


def _clamd_ping_reply_is_pong(data: bytes) -> bool:
    if data.endswith(b"\r\n"):
        payload = data[:-2]
    elif data.endswith((b"\n", b"\0")):
        payload = data[:-1]
    else:
        return False
    return payload == b"PONG"


def check_clamd(
    host: str | None = None,
    port: int | None = None,
    *,
    timeout: float = 1.0,
    error_formatter: ErrorFormatter | None = None,
) -> dict[str, Any]:
    resolved_host, resolved_port = _resolve_clamd_target(host=host, port=port)
    try:
        with socket.create_connection(
            (resolved_host, resolved_port),
            timeout=timeout,
        ) as sock:
            sock.settimeout(timeout)
            sock.sendall(b"PING\n")
            data = _recv_clamd_reply(sock, max_bytes=64)
        detail = (
            data.replace(b"\0", b"\n").decode("utf-8", errors="replace").strip()
            or "no data"
        )
        return {
            "ok": _clamd_ping_reply_is_pong(data),
            "detail": f"{detail} ({resolved_host}:{resolved_port})",
        }
    except Exception as exc:
        error_detail = _format_error(exc, error_formatter=error_formatter)
        return {
            "ok": False,
            "detail": f"{resolved_host}:{resolved_port}: {error_detail}",
        }


def test_clamd_eicar(
    host: str | None = None,
    port: int | None = None,
    *,
    timeout: float = 2.0,
    error_formatter: ErrorFormatter | None = None,
) -> dict[str, Any]:
    data = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    resolved_host, resolved_port = _resolve_clamd_target(host=host, port=port)
    try:
        with socket.create_connection(
            (resolved_host, resolved_port),
            timeout=timeout,
        ) as sock:
            sock.settimeout(timeout)
            sock.sendall(b"zINSTREAM\0")
            view = memoryview(data)
            chunk_size = 8192
            for offset in range(0, len(data), chunk_size):
                chunk = view[offset : offset + chunk_size]
                sock.sendall(len(chunk).to_bytes(4, "big"))
                sock.sendall(chunk.tobytes())
            sock.sendall((0).to_bytes(4, "big"))
            reply = _recv_clamd_reply(sock, max_bytes=4096)

        detail = (
            reply.replace(b"\0", b"\n").decode("ascii", errors="replace").strip()
            if reply
            else ""
        )
        ok = ("Eicar" in detail) or ("FOUND" in detail)
        return {
            "ok": ok,
            "detail": detail or f"no data from {resolved_host}:{resolved_port}",
        }
    except Exception as exc:
        error_detail = _format_error(exc, error_formatter=error_formatter)
        return {
            "ok": False,
            "detail": f"{resolved_host}:{resolved_port}: {error_detail}",
        }


def send_sample_respmod_to(
    host: str,
    port: int,
    *,
    service: str = "/avrespmod",
    timeout: float = 1.2,
    error_formatter: ErrorFormatter | None = None,
) -> dict[str, Any]:
    path = service if service.startswith("/") else f"/{service}"
    http_body = b"Hello from ICAP sample"
    http_hdr = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/plain\r\n\r\n"
    chunk = f"{len(http_body):X}\r\n".encode("ascii") + http_body + b"\r\n0\r\n\r\n"
    res_body_off = len(http_hdr)
    icap_req = (
        (
            f"RESPMOD icap://{host}:{port}{path} ICAP/1.0\r\n"
            f"Host: {host}\r\n"
            "Allow: 204\r\n"
            f"Encapsulated: res-hdr=0, res-body={res_body_off}\r\n"
            "\r\n"
        ).encode("ascii")
        + http_hdr
        + chunk
    )
    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(icap_req)
            head = _recv_response_head(sock)
        first_line, headers = _parse_http_response_head(head)
        status_code = _parse_protocol_status_code(first_line)
        istag = _http_header_value(headers, "istag")
        normalized_istag = _normalize_icap_istag(istag)
        fail_open_placeholder = normalized_istag == "clamav-fail-open-unavailable"
        fail_closed_placeholder = normalized_istag == "clamav-fail-closed-unavailable"
        backend_unavailable = fail_open_placeholder or fail_closed_placeholder
        transport_ok = first_line.startswith("ICAP/1.0 ") and status_code is not None
        icap_transaction_ok = status_code is not None and 200 <= status_code < 300
        protection_ready = transport_ok and icap_transaction_ok and not backend_unavailable
        detail = first_line
        if fail_open_placeholder:
            detail = (
                f"{first_line}; ClamAV backend unavailable; fail-open placeholder "
                "transport is responsive but malware scanning is degraded."
            )
        elif fail_closed_placeholder:
            detail = (
                f"{first_line}; ClamAV backend unavailable; fail-closed placeholder "
                "transport is responsive but malware scanning is unavailable."
            )
        status = (
            "healthy"
            if protection_ready
            else "degraded"
            if transport_ok
            else "unavailable"
        )
        fail_mode = "unknown"
        if fail_open_placeholder:
            fail_mode = "open"
        elif fail_closed_placeholder:
            fail_mode = "closed"
        return {
            "ok": protection_ready,
            "status": status,
            "detail": detail,
            "transport_ok": transport_ok,
            "icap_transaction_ok": icap_transaction_ok,
            "protection_ready": protection_ready,
            "fail_open": fail_open_placeholder,
            "fail_mode": fail_mode,
            "backend_available": not backend_unavailable if transport_ok else False,
            "icap_status_code": status_code,
            "icap_status_reason": _icap_status_reason(first_line),
            "icap_istag": istag,
        }
    except Exception as exc:
        return {
            "ok": False,
            "status": "unavailable",
            "detail": _format_error(
                exc,
                error_formatter=error_formatter,
                default=f"Failed to contact ICAP service at {host}:{port}.",
            ),
            "transport_ok": False,
            "icap_transaction_ok": False,
            "protection_ready": False,
            "fail_open": False,
            "fail_mode": "unknown",
            "backend_available": False,
            "icap_status_code": None,
            "icap_status_reason": "",
            "icap_istag": "",
        }


def build_clamav_health(
    clamd_health: dict[str, Any],
    av_icap_health: dict[str, Any],
) -> dict[str, Any]:
    return {
        "ok": bool(clamd_health.get("ok")) and bool(av_icap_health.get("ok")),
        "detail": f"AV c-icap={av_icap_health.get('detail')} | clamd={clamd_health.get('detail')}",
        "components": {
            "clamd": clamd_health,
            "av_icap": av_icap_health,
        },
    }
