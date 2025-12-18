import os
import sys
import urllib.request
from urllib.parse import urlparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


UPSTREAM = os.environ.get("PAC_UPSTREAM", "http://127.0.0.1:5000/proxy.pac")
LISTEN_HOST = os.environ.get("PAC_HTTP_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("PAC_HTTP_PORT", "80"))


class Handler(BaseHTTPRequestHandler):
    server_version = "pac-http/1.0"

    def log_message(self, fmt, *args):
        # Log to stdout (supervisord captures it)
        sys.stdout.write("%s - - [%s] %s\n" % (self.address_string(), self.log_date_time_string(), fmt % args))

    def do_GET(self):
        path = (self.path or "").split("?", 1)[0]
        if path == "/" or path == "":
            path = "/wpad.dat"
        if path not in ("/wpad.dat", "/proxy.pac"):
            self.send_response(404)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"Not found")
            return

        client_ip = (self.client_address[0] or "").strip()
        host = (self.headers.get("Host") or "").strip()

        headers = {
            "X-Requested-With": "pac-http",
        }
        if client_ip:
            headers["X-Forwarded-For"] = client_ip
        if host:
            # Ensure the generated PAC uses the externally-reachable hostname.
            headers["Host"] = host

        u = urlparse(UPSTREAM or "")
        if u.scheme not in ("http", "https"):
            self.send_response(502)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"Bad gateway")
            return

        req = urllib.request.Request(UPSTREAM, headers=headers, method="GET")

        max_bytes = int(os.environ.get("PAC_MAX_BYTES", str(2 * 1024 * 1024)))
        if max_bytes <= 0:
            max_bytes = 2 * 1024 * 1024

        try:
            with urllib.request.urlopen(req, timeout=3) as r:
                try:
                    cl = r.headers.get("Content-Length")
                    if cl is not None and int(cl) > max_bytes:
                        raise ValueError("PAC too large")
                except Exception:
                    pass

                total = 0
                chunks: list[bytes] = []
                while True:
                    chunk = r.read(64 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise ValueError("PAC too large")
                    chunks.append(chunk)
                data = b"".join(chunks)
                content_type = r.headers.get("Content-Type") or "application/x-ns-proxy-autoconfig"
        except Exception:
            self.send_response(502)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"Bad gateway")
            return

        self.send_response(200)
        self.send_header("Content-Type", content_type)
        if path == "/wpad.dat":
            self.send_header("Content-Disposition", 'inline; filename="wpad.dat"')
        else:
            self.send_header("Content-Disposition", 'inline; filename="proxy.pac"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main() -> int:
    httpd = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    sys.stdout.write(f"[pac-http] listening on {LISTEN_HOST}:{LISTEN_PORT}, upstream={UPSTREAM}\n")
    httpd.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
