from __future__ import annotations

import json
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

DEFAULT_CANARY_HOST = "127.0.0.1"
DEFAULT_CANARY_PORT = 18080
DEFAULT_CANARY_PATH = "/__docker_proxy_forwarding_canary"
CANARY_SERVICE = "docker-proxy-forwarding-canary"


def _canary_host() -> str:
    candidate = (
        os.environ.get("FORWARDING_CANARY_HOST") or DEFAULT_CANARY_HOST
    ).strip()
    if candidate in {"", "0.0.0.0", "::", "[::]"}:  # noqa: S104 - unsafe bind env is coerced to loopback below.
        return DEFAULT_CANARY_HOST
    if candidate.lower() in {"::1", "[::1]"}:
        return DEFAULT_CANARY_HOST
    if candidate.lower() in {"localhost", "127.0.0.1"} or candidate.startswith("127."):
        return candidate.strip("[]")
    return DEFAULT_CANARY_HOST


def _canary_port() -> int:
    try:
        port = int(
            (
                os.environ.get("FORWARDING_CANARY_PORT") or str(DEFAULT_CANARY_PORT)
            ).strip()
        )
    except Exception:
        port = DEFAULT_CANARY_PORT
    return port if 1 <= port <= 65535 else DEFAULT_CANARY_PORT


def _canary_path() -> str:
    candidate = (
        os.environ.get("FORWARDING_CANARY_PATH") or DEFAULT_CANARY_PATH
    ).strip()
    if not candidate.startswith("/"):
        return DEFAULT_CANARY_PATH
    if "?" in candidate or "#" in candidate or "\\" in candidate or "//" in candidate:
        return DEFAULT_CANARY_PATH
    return candidate


class ForwardingCanaryHandler(BaseHTTPRequestHandler):
    server_version = "DockerProxyForwardingCanary/1"
    sys_version = ""

    def log_message(self, _format: str, *_args: Any) -> None:
        return

    def do_GET(self) -> None:
        self._handle_canary(include_body=True)

    def do_HEAD(self) -> None:
        self._handle_canary(include_body=False)

    def _handle_canary(self, *, include_body: bool) -> None:
        parsed = urlsplit(self.path)
        if parsed.path != _canary_path():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        query = parse_qs(parsed.query, keep_blank_values=True)
        probe = (query.get("probe") or [""])[-1]
        payload = {
            "ok": True,
            "service": CANARY_SERVICE,
            "probe": probe,
        }
        body = (
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(
                "utf-8",
            )
            + b"\n"
        )
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, no-cache, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Docker-Proxy-Forwarding-Canary", probe)
        self.end_headers()
        if include_body:
            self.wfile.write(body)


def main() -> int:
    server = ThreadingHTTPServer(
        (_canary_host(), _canary_port()), ForwardingCanaryHandler
    )
    server.daemon_threads = True
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
