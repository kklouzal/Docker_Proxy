#!/usr/bin/env python3
from __future__ import annotations

import argparse
import errno
import html
import os
import socket
import socketserver
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

_ALLOWED_URL_SCHEMES = {"http", "https"}

# This script lives in /app/tools; add /app to sys.path.
here = Path(Path(__file__).parent).resolve()
app_root = Path(os.path.join(here, "..")).resolve()
if str(app_root) not in sys.path:
    sys.path.insert(0, str(app_root))

from services.adblock_decision import (  # noqa: E402
    AdblockDecision,
    AdblockDecisionEngine,
)
from services.helper_runtime import HelperStats, helper_event  # noqa: E402

_CRLF = b"\r\n"


def _parse_headers(lines: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in lines:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()
    return headers


def _parse_encapsulated_offsets(value: str) -> dict[str, int] | None:
    offsets: dict[str, int] = {}
    last_offset = -1
    for item in (value or "").split(","):
        if "=" not in item:
            return None
        name, raw_offset = item.split("=", 1)
        name = name.strip().lower()
        raw_offset = raw_offset.strip()
        if not raw_offset.isdigit():
            return None
        offset = int(raw_offset)
        if not name or name in offsets or offset < last_offset:
            return None
        offsets[name] = offset
        last_offset = offset
    if "req-body" in offsets and "null-body" in offsets:
        return None
    return offsets


def _encapsulated_http_request(data: bytes) -> bytes:
    header_blob, _, rest = data.partition(b"\r\n\r\n")
    headers = _parse_headers(
        header_blob.decode("iso-8859-1", errors="replace").splitlines()[1:],
    )
    offsets = _parse_encapsulated_offsets(headers.get("encapsulated", ""))
    if offsets is None or "req-hdr" not in offsets:
        return b""
    start = int(offsets.get("req-hdr", 0) or 0)
    end_candidates = [
        int(offsets[name])
        for name in ("req-body", "null-body")
        if name in offsets and int(offsets[name]) >= start
    ]
    end = min(end_candidates) if end_candidates else len(rest)
    return rest[start:end]


def _has_control_or_backslash(value: str) -> bool:
    return any(ord(ch) <= 0x20 or ord(ch) == 0x7F for ch in value) or "\\" in value


def _has_authority_contamination(value: str) -> bool:
    return _has_control_or_backslash(value) or "%" in value


def _valid_absolute_or_scheme_relative_url(target: str, *, scheme: str = "") -> str:
    if not target or _has_control_or_backslash(target):
        return ""
    try:
        parsed = urlsplit(target)
        port = parsed.port
    except ValueError:
        return ""
    if not parsed.netloc or not parsed.hostname:
        return ""
    if _has_authority_contamination(parsed.netloc):
        return ""
    if parsed.username is not None or parsed.password is not None:
        return ""
    if port is not None and port <= 0:
        return ""
    expected_scheme = (parsed.scheme or scheme).lower()
    if expected_scheme not in _ALLOWED_URL_SCHEMES:
        return ""
    if parsed.scheme and parsed.scheme.lower() not in _ALLOWED_URL_SCHEMES:
        return ""
    if parsed.fragment:
        return ""
    if parsed.path and not parsed.path.startswith("/"):
        return ""
    normalized = urlunsplit(
        (
            expected_scheme,
            parsed.netloc,
            parsed.path or "/",
            parsed.query,
            "",
        ),
    )
    reparsed = urlsplit(normalized)
    try:
        normalized_port = reparsed.port
    except ValueError:
        return ""
    if (
        reparsed.scheme != expected_scheme
        or reparsed.netloc != parsed.netloc
        or reparsed.hostname != parsed.hostname
        or reparsed.username is not None
        or reparsed.password is not None
        or normalized_port != port
    ):
        return ""
    return normalized


def _authority_url(authority: str, *, scheme: str, require_port: bool = False) -> str:
    if _has_authority_contamination(authority) or any(
        ch in authority for ch in ("/", "?", "#")
    ):
        return ""
    candidate = _valid_absolute_or_scheme_relative_url(f"//{authority}/", scheme=scheme)
    if not candidate:
        return ""
    try:
        port = urlsplit(candidate).port
    except ValueError:
        return ""
    if require_port and port is None:
        return ""
    return candidate


def _connect_authority_url(authority: str) -> str:
    # Do not let encoded delimiters such as %2f, %3a, or %40, or
    # backslash-vs-slash parser disagreement, alter how a malformed CONNECT
    # target is interpreted by the URL parser/decision engine.
    # Authority-form should be a literal host:port token here.
    return _authority_url(authority, scheme="https", require_port=True)


def _parse_http_request(data: bytes) -> tuple[str, str, dict[str, str]]:
    text = data.decode("iso-8859-1", errors="replace")
    header_text = text.split("\r\n\r\n", 1)[0].split("\n\n", 1)[0]
    lines = [line.rstrip("\r") for line in header_text.splitlines()]
    if not lines:
        return "", "", {}
    request_line = lines[0]
    parts = request_line.split()
    method = parts[0].upper() if parts else ""
    target = parts[1] if len(parts) > 1 else ""
    headers = _parse_headers(lines[1:])
    valid_request_line = (
        len(parts) == 3 and request_line == f"{parts[0]} {parts[1]} {parts[2]}"
    )
    if not valid_request_line:
        return method, "", headers
    scheme = "https" if headers.get("x-forwarded-proto") == "https" else "http"
    if method == "CONNECT" and target and "://" not in target:
        # Squid sends CONNECT requests to REQMOD helpers in authority form
        # ("host:port") rather than absolute-form.  Normalize only well-formed
        # authority-form targets to HTTPS URLs so malformed CONNECT targets do
        # not manufacture misleading hosts/paths for the decision engine.
        target = _connect_authority_url(target)
    elif target.startswith("//"):
        target = _valid_absolute_or_scheme_relative_url(target, scheme=scheme)
    elif target.startswith("/"):
        host = headers.get("host", "")
        host_url = _authority_url(host, scheme=scheme) if host else ""
        target = (
            _valid_absolute_or_scheme_relative_url(host_url.rstrip("/") + target)
            if host_url
            else ""
        )
    elif "://" in target:
        target = _valid_absolute_or_scheme_relative_url(target)
    return method, target, headers


def _decision_list_key(decision: AdblockDecision) -> str:
    list_key = "".join(
        ch
        for ch in str(getattr(decision, "list_key", "") or "").strip()
        if ch.isalnum() or ch in {"-", "_", "."}
    )
    if list_key:
        return list_key[:64]
    return "matched" if str(getattr(decision, "raw", "") or "").strip() else "unknown"


def _icap_response(
    status: str,
    headers: dict[str, str] | None = None,
    *,
    close: bool = False,
) -> bytes:
    lines = [f"ICAP/1.0 {status}"]
    response_headers = {"Connection": "close"} if close else {}
    response_headers.update(headers or {})
    for key, value in response_headers.items():
        lines.append(f"{key}: {value}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii", errors="replace")


def _options_response(*, close: bool = False) -> bytes:
    return _icap_response(
        "200 OK",
        {
            "Methods": "REQMOD",
            "Service": "squid-flask-proxy sqlite adblock",
            "ISTag": '"adblock-sqlite"',
            "Allow": "204",
            "Preview": "0",
            "Options-TTL": "300",
            "Encapsulated": "null-body=0",
        },
        close=close,
    )


def _allow_response(*, close: bool = False) -> bytes:
    return _icap_response(
        "204 No Content",
        {
            "ISTag": '"adblock-sqlite"',
        },
        close=close,
    )


def _block_response(url: str, raw_rule: str, *, close: bool = False) -> bytes:
    escaped_url = html.escape(url or "", quote=True)
    escaped_rule = html.escape(raw_rule or "adblock rule", quote=True)
    body = (
        "<!doctype html><html><head><title>Access Denied</title></head>"
        "<body><h1>Access Denied</h1>"
        "<p>Blocked by proxy adblock.</p>"
        f"<p>{escaped_url}</p><p>Rule: {escaped_rule}</p></body></html>"
    ).encode()
    http_headers = (
        "HTTP/1.1 403 Forbidden\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii")
    close_header = "Connection: close\r\n" if close else ""
    # ICAP encapsulated HTTP bodies are chunked.
    icap_headers = (
        "ICAP/1.0 200 OK\r\n"
        'ISTag: "adblock-sqlite"\r\n'
        f"{close_header}"
        f"Encapsulated: res-hdr=0, res-body={len(http_headers)}\r\n"
        "\r\n"
    ).encode("ascii")
    chunk = f"{len(body):X}\r\n".encode("ascii") + body + b"\r\n0\r\n\r\n"
    return icap_headers + http_headers + chunk


def _preview_body_end(rest: bytes, body_offset: int) -> int | None:
    if body_offset < 0 or len(rest) < body_offset:
        return None
    cursor = body_offset
    while True:
        line_end = rest.find(_CRLF, cursor)
        if line_end < 0:
            return None
        size_token = rest[cursor:line_end].split(b";", 1)[0].strip()
        try:
            chunk_size = int(size_token or b"0", 16)
        except ValueError:
            return None
        cursor = line_end + len(_CRLF)
        if chunk_size == 0:
            trailers_end = rest.find(_CRLF + _CRLF, cursor)
            if trailers_end >= 0:
                return trailers_end + len(_CRLF + _CRLF)
            if rest[cursor : cursor + len(_CRLF)] == _CRLF:
                return cursor + len(_CRLF)
            return None
        cursor += chunk_size
        if len(rest) < cursor + len(_CRLF):
            return None
        if rest[cursor : cursor + len(_CRLF)] != _CRLF:
            return None
        cursor += len(_CRLF)


def _drain_chunked_body(
    sock: Any,
    body: bytes,
    *,
    max_drain_bytes: int,
) -> bool:
    max_drain_bytes = max(0, int(max_drain_bytes or 0))
    data = bytearray(body)
    cursor = 0

    def ensure(size: int) -> bool:
        while len(data) < size and len(data) < max_drain_bytes:
            try:
                chunk = sock.recv(min(8192, max_drain_bytes - len(data)))
            except (TimeoutError, OSError):
                return False
            if not chunk:
                return False
            data.extend(chunk)
        return len(data) >= size

    while len(data) <= max_drain_bytes:
        line_end = data.find(_CRLF, cursor)
        while line_end < 0:
            if len(data) >= max_drain_bytes or not ensure(len(data) + 1):
                return False
            line_end = data.find(_CRLF, cursor)
        size_token = data[cursor:line_end].split(b";", 1)[0].strip()
        try:
            chunk_size = int(size_token or b"0", 16)
        except ValueError:
            return False
        cursor = line_end + len(_CRLF)
        if chunk_size == 0:
            while True:
                trailers_end = data.find(_CRLF + _CRLF, cursor)
                if trailers_end >= 0:
                    return True
                if data[cursor : cursor + len(_CRLF)] == _CRLF:
                    return True
                if len(data) >= max_drain_bytes or not ensure(len(data) + 1):
                    return False
        if not ensure(cursor + chunk_size + len(_CRLF)):
            return False
        cursor += chunk_size
        if data[cursor : cursor + len(_CRLF)] != _CRLF:
            return False
        cursor += len(_CRLF)
    return False


def _read_icap_message(
    sock: Any,
    *,
    max_bytes: int,
    max_body_drain_bytes: int,
    timeout_seconds: float,
    pending: bytes = b"",
) -> tuple[bytes, bytes, bool]:
    sock.settimeout(max(0.1, float(timeout_seconds or 0)))
    data = bytearray(pending)
    force_close = False
    while b"\r\n\r\n" not in data and len(data) < max_bytes:
        try:
            chunk = sock.recv(min(8192, max_bytes - len(data)))
        except (TimeoutError, OSError):
            return bytes(data), b"", True
        if not chunk:
            break
        data.extend(chunk)
    if b"\r\n\r\n" not in data:
        return bytes(data), b"", True
    header_blob, rest = bytes(data).split(b"\r\n\r\n", 1)
    headers = _parse_headers(
        header_blob.decode("iso-8859-1", errors="replace").splitlines()[1:],
    )
    offsets = _parse_encapsulated_offsets(headers.get("encapsulated", ""))
    if offsets is None:
        return bytes(data), b"", True
    if "req-hdr" not in offsets:
        header_end = len(header_blob) + len(b"\r\n\r\n")
        return bytes(data[:header_end]), bytes(data[header_end:]), False

    req_hdr_offset = int(offsets.get("req-hdr", 0) or 0)
    end_candidates = [
        int(offsets[name])
        for name in ("req-body", "null-body")
        if name in offsets and int(offsets[name]) >= req_hdr_offset
    ]
    required_rest_bytes = min(end_candidates) if end_candidates else len(rest)

    while len(rest) < required_rest_bytes and len(data) < max_bytes:
        try:
            chunk = sock.recv(min(8192, max_bytes - len(data)))
        except (TimeoutError, OSError):
            force_close = True
            break
        if not chunk:
            break
        data.extend(chunk)
        rest += chunk
    while not end_candidates and b"\r\n\r\n" not in rest and len(data) < max_bytes:
        try:
            chunk = sock.recv(min(8192, max_bytes - len(data)))
        except (TimeoutError, OSError):
            force_close = True
            break
        if not chunk:
            break
        data.extend(chunk)
        rest += chunk

    if "preview" in headers and "req-body" in offsets:
        body_offset = int(offsets.get("req-body", 0) or 0)
        while _preview_body_end(rest, body_offset) is None and len(data) < max_bytes:
            try:
                chunk = sock.recv(min(8192, max_bytes - len(data)))
            except (TimeoutError, OSError):
                force_close = True
                break
            if not chunk:
                break
            data.extend(chunk)
            rest += chunk
        body_end = _preview_body_end(rest, body_offset)
        if body_end is None:
            return bytes(data), b"", True
        message_end = len(header_blob) + len(b"\r\n\r\n") + body_end
        return bytes(data[:message_end]), bytes(data[message_end:]), force_close

    if "req-body" in offsets:
        body_offset = int(offsets.get("req-body", 0) or 0)
        if body_offset < 0 or len(rest) < body_offset:
            return bytes(data), b"", True
        if not _drain_chunked_body(
            sock,
            rest[body_offset:],
            max_drain_bytes=max_body_drain_bytes,
        ):
            force_close = True
        force_close = True

    message_end = len(header_blob) + len(b"\r\n\r\n") + required_rest_bytes
    return bytes(data[:message_end]), bytes(data[message_end:]), force_close


def _connection_close_requested(header_blob: bytes) -> bool:
    headers = _parse_headers(
        header_blob.decode("iso-8859-1", errors="replace").splitlines()[1:],
    )
    tokens = {
        item.strip().lower()
        for item in headers.get("connection", "").split(",")
        if item.strip()
    }
    return "close" in tokens


def _send_icap_response(sock: socket.socket, response: bytes) -> bool:
    try:
        sock.sendall(response)
        return True
    except (BrokenPipeError, ConnectionResetError, TimeoutError):
        return False
    except OSError as exc:
        if exc.errno in {errno.ECONNRESET, errno.EPIPE, errno.ETIMEDOUT}:
            return False
        raise


class _AdblockIcapHandler(socketserver.BaseRequestHandler):
    server: _AdblockIcapServer

    def setup(self) -> None:
        super().setup()
        try:
            self.request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass

    def handle(self) -> None:
        max_request_bytes = int(getattr(self.server, "max_request_bytes", 262144))
        max_body_drain_bytes = int(
            getattr(self.server, "max_body_drain_bytes", 8388608),
        )
        timeout_seconds = float(getattr(self.server, "request_timeout_seconds", 5.0))
        max_keepalive_requests = max(
            1,
            int(getattr(self.server, "max_keepalive_requests", 1000)),
        )
        request_count = 0
        pending = b""
        while request_count < max_keepalive_requests:
            data, pending, read_close = _read_icap_message(
                self.request,
                max_bytes=max_request_bytes,
                max_body_drain_bytes=max_body_drain_bytes,
                timeout_seconds=timeout_seconds,
                pending=pending,
            )
            if not data:
                return
            request_count += 1
            header_blob, _, _rest = data.partition(b"\r\n\r\n")
            close = (
                read_close
                or _connection_close_requested(header_blob)
                or (request_count >= max_keepalive_requests)
            )
            lines = header_blob.decode("iso-8859-1", errors="replace").splitlines()
            request_line = lines[0] if lines else ""
            parts = request_line.split()
            method = parts[0].upper() if parts else ""
            if method == "OPTIONS":
                self.server.increment_stat("options")
                if not _send_icap_response(
                    self.request, _options_response(close=close)
                ):
                    return
                if close:
                    return
                continue
            if method != "REQMOD":
                self.server.increment_stat("method_not_allowed")
                if not _send_icap_response(
                    self.request,
                    _icap_response(
                        "405 Method Not Allowed",
                        {"Encapsulated": "null-body=0"},
                        close=close,
                    ),
                ):
                    return
                if close:
                    return
                continue

            http_method, url, http_headers = _parse_http_request(
                _encapsulated_http_request(data),
            )
            if not url:
                self.server.increment_stat("parse_miss")
                if not _send_icap_response(self.request, _allow_response(close=close)):
                    return
                if close:
                    return
                continue

            self.server.increment_stat("reqmod")
            decision = self.server.engine.decide(
                url,
                method=http_method,
                headers=http_headers,
            )
            if decision.blocked:
                self.server.increment_stat("blocked")
                list_key = _decision_list_key(decision)
                self.server.log_access(
                    client_ip=self.client_address[0],
                    method=http_method,
                    url=url,
                    icap_status=200,
                    http_status=403,
                    http_resp_line="HTTP/1.1 403 Forbidden",
                    list_key=list_key,
                    rule_id=decision.rule_id,
                )
                self.server.record_block(list_key)
                if not _send_icap_response(
                    self.request,
                    _block_response(url, decision.raw, close=close),
                ):
                    return
            else:
                self.server.increment_stat("allowed")
                if not _send_icap_response(self.request, _allow_response(close=close)):
                    return
            if close:
                return


class _AdblockIcapServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        *,
        engine: AdblockDecisionEngine,
        access_log_path: str,
        max_request_bytes: int,
        max_body_drain_bytes: int = 8388608,
        request_timeout_seconds: float = 5.0,
        max_keepalive_requests: int = 1000,
        block_recorder: Any | None = None,
        stats: HelperStats | None = None,
    ) -> None:
        super().__init__(server_address, _AdblockIcapHandler)
        self.engine = engine
        self.access_log_path = access_log_path
        self.max_request_bytes = max_request_bytes
        self.max_body_drain_bytes = max(8192, int(max_body_drain_bytes or 8192))
        self.request_timeout_seconds = max(0.1, float(request_timeout_seconds or 0))
        self.max_keepalive_requests = max(1, int(max_keepalive_requests or 1))
        self.block_recorder = block_recorder
        self.stats = stats

    def increment_stat(self, key: str, amount: int = 1) -> None:
        if self.stats is None:
            return
        self.stats.increment(key, amount)
        self.stats.emit_if_due()

    def log_access(
        self,
        *,
        client_ip: str,
        method: str,
        url: str,
        icap_status: int,
        http_status: int,
        http_resp_line: str,
        list_key: str = "",
        rule_id: str = "",
    ) -> None:
        line = "\t".join(
            [
                str(int(time.time())),
                client_ip or "-",
                client_ip or "-",
                "REQMOD",
                "/adblockreq",
                str(int(icap_status)),
                f"{method or '-'} {url or '-'} HTTP/1.1",
                url or "-",
                http_resp_line if http_status else "-",
                list_key or "-",
                rule_id or "-",
            ],
        )
        try:
            Path(self.access_log_path).parent.mkdir(parents=True, exist_ok=True)
            with Path(self.access_log_path).open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        except Exception:
            pass

    def record_block(self, list_key: str) -> None:
        recorder = self.block_recorder
        if recorder is None:
            return
        try:
            recorder(list_key or "unknown")
        except Exception:
            pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SQLite-backed adblock ICAP server")
    parser.add_argument("--host", default=os.environ.get("CICAP_HOST", "127.0.0.1"))
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("CICAP_PORT", "14000") or "14000"),
    )
    parser.add_argument(
        "--db",
        default=os.environ.get(
            "ADBLOCK_LOOKUP_DB",
            "/var/lib/squid-flask-proxy/adblock/compiled/request_lookup.sqlite",
        ),
    )
    parser.add_argument(
        "--access-log",
        default=os.environ.get("ADBLOCK_ICAP_ACCESS_LOG", "/var/log/cicap-access.log"),
    )
    parser.add_argument(
        "--cache-ttl",
        type=int,
        default=int(os.environ.get("ADBLOCK_CACHE_TTL", "3600") or "3600"),
    )
    parser.add_argument(
        "--cache-max",
        type=int,
        default=int(os.environ.get("ADBLOCK_CACHE_MAX", "200000") or "200000"),
    )
    parser.add_argument(
        "--rule-cache-max",
        type=int,
        default=int(
            os.environ.get("ADBLOCK_RULE_CACHE_MAX", "50000") or "50000",
        ),
    )
    parser.add_argument(
        "--max-request-bytes",
        type=int,
        default=int(
            os.environ.get("ADBLOCK_ICAP_MAX_REQUEST_BYTES", "262144") or "262144"
        ),
    )
    parser.add_argument(
        "--max-body-drain-bytes",
        type=int,
        default=int(
            os.environ.get("ADBLOCK_ICAP_MAX_BODY_DRAIN_BYTES", "8388608") or "8388608"
        ),
    )
    parser.add_argument(
        "--request-timeout",
        type=float,
        default=float(os.environ.get("ADBLOCK_ICAP_REQUEST_TIMEOUT", "5") or "5"),
    )
    parser.add_argument(
        "--max-keepalive-requests",
        type=int,
        default=int(
            os.environ.get("ADBLOCK_ICAP_MAX_KEEPALIVE_REQUESTS", "1000") or "1000"
        ),
    )
    args = parser.parse_args(argv)

    engine = AdblockDecisionEngine(
        args.db,
        cache_ttl_seconds=args.cache_ttl,
        cache_max=args.cache_max,
        rule_cache_max=args.rule_cache_max,
    )
    block_recorder = None
    try:
        from services.adblock_store import get_adblock_store  # type: ignore

        adblock_store = get_adblock_store()
        try:
            adblock_store.init_db()
        except Exception:
            pass
        block_recorder = adblock_store.record_block
    except Exception:
        block_recorder = None

    stats = HelperStats("adblock_icap")
    helper_event(
        "adblock_icap",
        "startup",
        host=args.host,
        port=int(args.port),
        db=args.db,
        max_request_bytes=max(8192, int(args.max_request_bytes)),
        max_body_drain_bytes=max(8192, int(args.max_body_drain_bytes)),
        request_timeout_seconds=max(0.1, float(args.request_timeout)),
        max_keepalive_requests=max(1, int(args.max_keepalive_requests)),
    )
    with _AdblockIcapServer(
        (args.host, int(args.port)),
        engine=engine,
        access_log_path=args.access_log,
        max_request_bytes=max(8192, int(args.max_request_bytes)),
        max_body_drain_bytes=max(8192, int(args.max_body_drain_bytes)),
        request_timeout_seconds=max(0.1, float(args.request_timeout)),
        max_keepalive_requests=max(1, int(args.max_keepalive_requests)),
        block_recorder=block_recorder,
        stats=stats,
    ) as server:
        sys.stdout.write(
            f"adblock sqlite ICAP listening on {args.host}:{args.port} using {args.db}\n",
        )
        sys.stdout.flush()
        try:
            server.serve_forever()
        finally:
            stats.emit_if_due(force=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
