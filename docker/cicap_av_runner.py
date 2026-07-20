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
_SINGLETON_ICAP_HEADERS = {
    "allow": "Allow",
    "encapsulated": "Encapsulated",
    "preview": "Preview",
}


class IcapProtocolError(Exception):
    pass


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


def _split_headers(header_bytes: bytes) -> tuple[str, dict[str, str]]:
    text = header_bytes.decode("iso-8859-1", errors="replace")
    lines = text.split("\r\n")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        name, value = line.split(":", 1)
        header_name = name.strip().lower()
        if header_name in _SINGLETON_ICAP_HEADERS and header_name in headers:
            display_name = _SINGLETON_ICAP_HEADERS[header_name]
            message = f"duplicate ICAP {display_name} header"
            raise IcapProtocolError(message)
        headers[header_name] = value.strip()
    return lines[0] if lines else "", headers


def _parse_encapsulated(value: str) -> dict[str, int]:
    offsets: dict[str, int] = {}
    for raw_item in value.split(","):
        item = raw_item.strip()
        if not item or "=" not in item:
            continue
        name, raw_offset = item.split("=", 1)
        name = name.strip().lower()
        if name in offsets:
            message = f"duplicate Encapsulated section name: {name}"
            raise IcapProtocolError(message)
        try:
            offsets[name] = int(raw_offset.strip())
        except ValueError:
            continue
    return offsets


def _recv_more(sock: socket.socket, data: bytes, size: int) -> bytes:
    while len(data) < size:
        chunk = sock.recv(min(65536, size - len(data)))
        if not chunk:
            break
        data += chunk
    return data


def _recv_until(
    sock: socket.socket, data: bytes, delimiter: bytes, *, max_bytes: int
) -> bytes:
    while delimiter not in data and len(data) < max_bytes:
        chunk = sock.recv(min(8192, max_bytes - len(data)))
        if not chunk:
            break
        data += chunk
    return data


def _drain_chunked_body(
    sock: socket.socket,
    data: bytes,
    *,
    max_bytes: int = 1024 * 1024 * 1024,
    preview: bool = False,
) -> bytes:
    _body, remainder = _read_chunked_body(
        sock, data, max_bytes=max_bytes, preview=preview
    )
    return remainder


def _read_chunked_body(
    sock: socket.socket,
    data: bytes,
    *,
    max_bytes: int = 1024 * 1024 * 1024,
    preview: bool = False,
) -> tuple[bytes, bytes]:
    body = bytearray()
    total = 0
    preview_pending = preview
    while True:
        data = _recv_until(sock, data, CRLF, max_bytes=8192)
        if CRLF not in data:
            return bytes(body), data
        line, data = data.split(CRLF, 1)
        try:
            size = int(line.split(b";", 1)[0].strip(), 16)
        except ValueError:
            return bytes(body), data
        if size == 0:
            data = _recv_until(sock, data, CRLF, max_bytes=8192)
            if data.startswith(CRLF):
                data = data[len(CRLF) :]
            else:
                return bytes(body), data
            if preview_pending and b"ieof" not in line.lower():
                try:
                    sock.sendall(b"ICAP/1.0 100 Continue\r\n\r\n")
                except OSError:
                    return bytes(body), data
                preview_pending = False
                continue
            return bytes(body), data
        total += size
        if total > max_bytes:
            return bytes(body), data
        data = _recv_more(sock, data, size + 2)
        if len(data) < size + 2:
            return bytes(body), data
        body.extend(data[:size])
        data = data[size + 2 :]


def _drain_encapsulated_body(
    sock: socket.socket, header: bytes, remainder: bytes
) -> None:
    _start_line, headers = _split_headers(header)
    offsets = _parse_encapsulated(headers.get("encapsulated", ""))
    if "null-body" in offsets:
        return
    body_offset = offsets.get("req-body")
    if body_offset is None:
        body_offset = offsets.get("res-body")
    if body_offset is None:
        return
    data = _recv_more(sock, remainder, body_offset)
    body = data[body_offset:] if len(data) >= body_offset else b""
    _drain_chunked_body(sock, body, preview="preview" in headers)


def _read_respmod_payload(
    sock: socket.socket, header: bytes, remainder: bytes
) -> tuple[bytes, bytes, bool]:
    _start_line, headers = _split_headers(header)
    offsets = _parse_encapsulated(headers.get("encapsulated", ""))
    body_offset = offsets.get("res-body")
    null_body_offset = offsets.get("null-body")
    terminal_offset = body_offset if body_offset is not None else null_body_offset
    if terminal_offset is None:
        return b"", b"", True
    response_header_offset = offsets.get("res-hdr", 0)
    if response_header_offset < 0 or terminal_offset < response_header_offset:
        return b"", b"", True
    data = _recv_more(sock, remainder, terminal_offset)
    if len(data) < terminal_offset:
        return b"", b"", True
    http_header = data[response_header_offset:terminal_offset]
    if body_offset is None:
        return http_header, b"", True
    body, _unused = _read_chunked_body(
        sock, data[body_offset:], preview="preview" in headers
    )
    return http_header, body, False


def _icap_response(status: str, headers: dict[str, str] | None = None) -> bytes:
    lines = [f"ICAP/1.0 {status}"]
    response_headers = {"Connection": "close"}
    response_headers.update(headers or {})
    return (
        "\r\n".join(
            [*lines, *[f"{key}: {value}" for key, value in response_headers.items()]]
        )
        + "\r\n\r\n"
    ).encode("ascii", errors="replace")


def _http_header_lines(http_header: bytes) -> list[bytes]:
    header_block = http_header.split(HEADER_END, 1)[0]
    return header_block.split(CRLF) if header_block else []


def _http_header_for_body_replay(http_header: bytes, body_length: int) -> bytes:
    lines = _http_header_lines(http_header)
    if not lines or not lines[0].startswith(b"HTTP/"):
        return http_header
    replay_lines = [lines[0]]
    for line in lines[1:]:
        if b":" not in line:
            continue
        name = line.split(b":", 1)[0].strip().lower()
        if name in {b"content-length", b"transfer-encoding"}:
            continue
        replay_lines.append(line)
    replay_lines.append(f"Content-Length: {body_length}".encode("ascii"))
    return CRLF.join(replay_lines) + HEADER_END


def _encode_icap_body_chunk(body: bytes) -> bytes:
    return f"{len(body):X}\r\n".encode("ascii") + body + CRLF + b"0\r\n\r\n"


def _clean_respmod_response(http_header: bytes, body: bytes, istag: str) -> bytes:
    http_header = _http_header_for_body_replay(http_header, len(body))
    return _icap_response(
        "200 OK",
        {"ISTag": istag, "Encapsulated": f"res-hdr=0, res-body={len(http_header)}"},
    ) + http_header + _encode_icap_body_chunk(body)


def _clean_respmod_no_body_response(
    *, allow_204: bool, http_header: bytes, istag: str
) -> bytes:
    if allow_204:
        return _icap_response("204 No Content", {"ISTag": istag})
    if http_header and not http_header.endswith(HEADER_END):
        http_header += HEADER_END
    return _icap_response(
        "200 OK",
        {"ISTag": istag, "Encapsulated": f"res-hdr=0, null-body={len(http_header)}"},
    ) + http_header


def _error_response(message: str, istag: str) -> bytes:
    payload = ("ClamAV fallback ICAP protocol error.\n" + message + "\n").encode(
        "utf-8"
    )
    http_header = (
        b"HTTP/1.1 502 Bad Gateway\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        + f"Content-Length: {len(payload)}\r\n".encode("ascii")
        + b"Connection: close\r\n\r\n"
    )
    return _icap_response(
        "200 OK",
        {"ISTag": istag, "Encapsulated": f"res-hdr=0, res-body={len(http_header)}"},
    ) + http_header + _encode_icap_body_chunk(payload)


class _FailOpenAvHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(2.0)
        data = b""
        while len(data) < 8192 and HEADER_END not in data:
            chunk = self.request.recv(512)
            if not chunk:
                break
            data += chunk
        if HEADER_END in data:
            header, remainder = data.split(HEADER_END, 1)
        else:
            header, remainder = data, b""
        first = (
            header.split(CRLF, 1)[0]
            .split(b"\n", 1)[0]
            .decode("ascii", errors="replace")
        )
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
                try:
                    if method == "RESPMOD":
                        _start_line, headers = _split_headers(header)
                        allow_204 = "204" in {
                            part.strip()
                            for part in headers.get("allow", "").split(",")
                        }
                        http_header, body, null_body = _read_respmod_payload(
                            self.request, header, remainder
                        )
                        if null_body:
                            response = _clean_respmod_no_body_response(
                                allow_204=allow_204,
                                http_header=http_header,
                                istag=istag,
                            )
                        else:
                            response = _clean_respmod_response(http_header, body, istag)
                    else:
                        _drain_encapsulated_body(self.request, header, remainder)
                        response = _icap_response(
                            "204 No Content",
                            {"ISTag": istag, "Encapsulated": "null-body=0"},
                        )
                except IcapProtocolError as exc:
                    response = _error_response(str(exc), istag)
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
