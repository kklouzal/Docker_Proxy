#!/usr/bin/env python3
from __future__ import annotations

import argparse
import html
import os
import socketserver
import sys
import time
from pathlib import Path
from typing import Any

# This script lives in /app/tools; add /app to sys.path.
here = Path(Path(__file__).parent).resolve()
app_root = Path(os.path.join(here, "..")).resolve()
if str(app_root) not in sys.path:
    sys.path.insert(0, str(app_root))

from services.adblock_decision import AdblockDecisionEngine  # noqa: E402

_CRLF = b"\r\n"


def _parse_headers(lines: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in lines:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()
    return headers


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
    if target.startswith("/"):
        host = headers.get("host", "")
        scheme = "https" if headers.get("x-forwarded-proto") == "https" else "http"
        target = f"{scheme}://{host}{target}" if host else target
    return method, target, headers


def _icap_response(status: str, headers: dict[str, str] | None = None) -> bytes:
    lines = [f"ICAP/1.0 {status}"]
    for key, value in (headers or {}).items():
        lines.append(f"{key}: {value}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii", errors="replace")


def _options_response() -> bytes:
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
    )


def _allow_response() -> bytes:
    return _icap_response(
        "204 No Content",
        {
            "ISTag": '"adblock-sqlite"',
        },
    )


def _block_response(url: str, raw_rule: str) -> bytes:
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
    # ICAP encapsulated HTTP bodies are chunked.
    icap_headers = (
        "ICAP/1.0 200 OK\r\n"
        'ISTag: "adblock-sqlite"\r\n'
        f"Encapsulated: res-hdr=0, res-body={len(http_headers)}\r\n"
        "\r\n"
    ).encode("ascii")
    chunk = f"{len(body):X}\r\n".encode("ascii") + body + b"\r\n0\r\n\r\n"
    return icap_headers + http_headers + chunk


def _read_icap_message(sock: Any, *, max_bytes: int) -> bytes:
    sock.settimeout(5.0)
    data = b""
    while b"\r\n\r\n" not in data and len(data) < max_bytes:
        chunk = sock.recv(min(8192, max_bytes - len(data)))
        if not chunk:
            break
        data += chunk
    if b"\r\n\r\n" not in data:
        return data
    header_blob, rest = data.split(b"\r\n\r\n", 1)
    headers = _parse_headers(
        header_blob.decode("iso-8859-1", errors="replace").splitlines()[1:],
    )
    encapsulated = headers.get("encapsulated", "")
    if "req-hdr=" not in encapsulated:
        return data
    while b"\r\n\r\n" not in rest and len(data) < max_bytes:
        chunk = sock.recv(min(8192, max_bytes - len(data)))
        if not chunk:
            break
        data += chunk
        rest += chunk
    return data


class _AdblockIcapHandler(socketserver.BaseRequestHandler):
    server: _AdblockIcapServer

    def handle(self) -> None:
        data = _read_icap_message(
            self.request,
            max_bytes=int(getattr(self.server, "max_request_bytes", 262144)),
        )
        if not data:
            return
        header_blob, _, rest = data.partition(b"\r\n\r\n")
        lines = header_blob.decode("iso-8859-1", errors="replace").splitlines()
        request_line = lines[0] if lines else ""
        parts = request_line.split()
        method = parts[0].upper() if parts else ""
        if method == "OPTIONS":
            self.request.sendall(_options_response())
            return
        if method != "REQMOD":
            self.request.sendall(
                _icap_response(
                    "405 Method Not Allowed",
                    {"Encapsulated": "null-body=0"},
                ),
            )
            return

        http_method, url, http_headers = _parse_http_request(rest)
        if not url:
            self.request.sendall(_allow_response())
            return

        decision = self.server.engine.decide(
            url,
            method=http_method,
            headers=http_headers,
        )
        if decision.blocked:
            self.server.log_access(
                client_ip=self.client_address[0],
                method=http_method,
                url=url,
                icap_status=200,
                http_status=403,
                http_resp_line="HTTP/1.1 403 Forbidden",
            )
            self.request.sendall(_block_response(url, decision.raw))
        else:
            self.request.sendall(_allow_response())


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
    ) -> None:
        super().__init__(server_address, _AdblockIcapHandler)
        self.engine = engine
        self.access_log_path = access_log_path
        self.max_request_bytes = max_request_bytes

    def log_access(
        self,
        *,
        client_ip: str,
        method: str,
        url: str,
        icap_status: int,
        http_status: int,
        http_resp_line: str,
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
            ],
        )
        try:
            Path(self.access_log_path).parent.mkdir(parents=True, exist_ok=True)
            with Path(self.access_log_path).open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
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
    args = parser.parse_args(argv)

    engine = AdblockDecisionEngine(
        args.db,
        cache_ttl_seconds=args.cache_ttl,
        cache_max=args.cache_max,
        rule_cache_max=args.rule_cache_max,
    )
    with _AdblockIcapServer(
        (args.host, int(args.port)),
        engine=engine,
        access_log_path=args.access_log,
        max_request_bytes=max(8192, int(args.max_request_bytes)),
    ) as server:
        sys.stdout.write(
            f"adblock sqlite ICAP listening on {args.host}:{args.port} using {args.db}\n",
        )
        sys.stdout.flush()
        server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
