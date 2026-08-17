from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

from services.forwarding_canary_config import (
    forwarding_canary_listener_host,
    forwarding_canary_path,
    forwarding_canary_port,
)

DEFAULT_CANARY_HOST = "127.0.0.1"
DEFAULT_CANARY_PORT = 18080
DEFAULT_CANARY_PATH = "/__docker_proxy_forwarding_canary"
CANARY_SERVICE = "docker-proxy-forwarding-canary"
MAX_PROBE_HEADER_VALUE_LEN = 128


def _probe_header_value(probe: str) -> str:
    bounded = probe[:MAX_PROBE_HEADER_VALUE_LEN]
    return "".join(
        char if 0x20 <= ord(char) <= 0xFF and ord(char) != 0x7F else "?"
        for char in bounded
    )


def _canary_host() -> str:
    return forwarding_canary_listener_host()


def _canary_port() -> int:
    return forwarding_canary_port()


def _canary_path() -> str:
    return forwarding_canary_path()


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
        safe_probe = _probe_header_value(probe)
        payload = {
            "ok": True,
            "service": CANARY_SERVICE,
            "probe": safe_probe,
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
        self.send_header("X-Docker-Proxy-Forwarding-Canary", safe_probe)
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
