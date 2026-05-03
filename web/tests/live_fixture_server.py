from __future__ import annotations

import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


class LiveFixtureHandler(BaseHTTPRequestHandler):
    server_version = "LiveFixture/1.0"

    def log_message(self, format: str, *args: object) -> None:  # pragma: no cover - keep test logs quiet
        return None

    def _parsed_request(self) -> tuple[object, dict[str, list[str]]]:
        parsed = urlsplit(self.path)
        query = parse_qs(parsed.query)
        try:
            delay_ms = max(0, min(int((query.get("delay_ms") or ["0"])[0] or "0"), 5_000))
        except ValueError:
            delay_ms = 0
        if delay_ms:
            time.sleep(delay_ms / 1000.0)
        return parsed, query

    def _payload(self, body: bytes = b"") -> bytes:
        parsed, query = self._parsed_request()
        payload = {
            "ok": True,
            "method": self.command,
            "path": parsed.path,
            "query": query,
            "content_length": len(body),
            "body_text": body.decode("utf-8", errors="replace")[:512],
            "headers": {
                "host": self.headers.get("Host", ""),
                "via": self.headers.get("Via", ""),
                "user_agent": self.headers.get("User-Agent", ""),
                "content_type": self.headers.get("Content-Type", ""),
            },
        }
        return json.dumps(payload, sort_keys=True).encode("utf-8")

    def _send_json(self, payload: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "public, max-age=60")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        if self.path.startswith("/health"):
            self._send_json(b'{"ok": true}')
            return
        self._send_json(self._payload())

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length) if length else b""
        self._send_json(self._payload(body))


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", 8080), LiveFixtureHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()