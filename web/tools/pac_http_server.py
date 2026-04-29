import json
import os
import sys
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


HERE = os.path.abspath(os.path.dirname(__file__))
APP_ROOT = os.path.abspath(os.path.join(HERE, ".."))
if APP_ROOT not in sys.path:
    sys.path.insert(0, APP_ROOT)

from services.pac_renderer import (  # noqa: E402
    PAC_MANIFEST_FILENAME,
    PAC_RENDER_DIR,
    PAC_STATE_SHA_FILENAME,
    select_manifest_file,
    substitute_request_host,
)


UPSTREAM = (os.environ.get("PAC_UPSTREAM") or "").strip()
LISTEN_HOST = os.environ.get("PAC_HTTP_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("PAC_HTTP_PORT", "80"))
PAC_DIR = (os.environ.get("PAC_RENDER_DIR") or PAC_RENDER_DIR).strip() or PAC_RENDER_DIR
PAC_CONTENT_TYPE = "application/x-ns-proxy-autoconfig"


def _client_ip(headers, client_address) -> str:
    xff = (headers.get("X-Forwarded-For") or "").strip()
    if xff:
        candidate = (xff.split(",")[0] or "").strip()
        if candidate:
            return candidate
    xri = (headers.get("X-Real-IP") or "").strip()
    if xri:
        return xri
    try:
        return (client_address[0] or "").strip()
    except Exception:
        return ""


def _request_host(headers) -> str:
    return (headers.get("Host") or "").strip() or "127.0.0.1"


def _default_pac(request_host: str) -> bytes:
    content = (
        "function FindProxyForURL(url, host) {\n"
        "  return 'PROXY __PAC_PROXY_HOST__:3128; DIRECT';\n"
        "}\n"
    )
    return substitute_request_host(content, request_host).encode("utf-8")


class LocalPacCache:
    def __init__(self, pac_dir: str):
        self.pac_dir = Path(pac_dir)
        self._lock = threading.Lock()
        self._state_sha = ""
        self._manifest: dict[str, object] = {}
        self._files: dict[str, str] = {}

    def _read_state_sha(self) -> str:
        try:
            return (self.pac_dir / PAC_STATE_SHA_FILENAME).read_text(encoding="utf-8", errors="replace").strip()
        except Exception:
            return ""

    def _load_locked(self) -> bool:
        state_sha = self._read_state_sha()
        if state_sha and state_sha == self._state_sha and self._manifest and self._files:
            return True

        manifest_path = self.pac_dir / PAC_MANIFEST_FILENAME
        if not manifest_path.exists():
            self._state_sha = ""
            self._manifest = {}
            self._files = {}
            return False

        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8", errors="replace") or "{}")
        except Exception:
            self._state_sha = ""
            self._manifest = {}
            self._files = {}
            return False
        if not isinstance(manifest, dict):
            self._state_sha = ""
            self._manifest = {}
            self._files = {}
            return False

        files: dict[str, str] = {}
        fallback_file = str(manifest.get("fallback_file") or "fallback.pac")
        candidates = {fallback_file}
        profiles = manifest.get("profiles")
        if isinstance(profiles, list):
            for entry in profiles:
                if not isinstance(entry, dict):
                    continue
                path = str(entry.get("file") or "").strip()
                if path:
                    candidates.add(path)
        for rel_path in sorted(candidates):
            file_path = self.pac_dir / rel_path
            if not file_path.exists() or not file_path.is_file():
                continue
            try:
                files[rel_path] = file_path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

        if not files:
            self._state_sha = ""
            self._manifest = {}
            self._files = {}
            return False

        self._state_sha = state_sha or str(manifest.get("state_sha256") or "")
        self._manifest = manifest
        self._files = files
        return True

    def resolve(self, *, client_ip: str, request_host: str) -> bytes | None:
        with self._lock:
            if not self._load_locked():
                return None
            selected = select_manifest_file(self._manifest, client_ip)
            fallback = str(self._manifest.get("fallback_file") or "fallback.pac")
            content = self._files.get(selected) or self._files.get(fallback)
            if not content:
                return None
            return substitute_request_host(content, request_host).encode("utf-8")


_LOCAL_CACHE = LocalPacCache(PAC_DIR)


def _fetch_upstream(client_ip: str, request_host: str) -> bytes | None:
    upstream = (UPSTREAM or "").strip()
    if not upstream:
        return None

    parsed = urlparse(upstream)
    if parsed.scheme not in ("http", "https"):
        return None

    headers = {"X-Requested-With": "pac-http"}
    if client_ip:
        headers["X-Forwarded-For"] = client_ip
    if request_host:
        headers["Host"] = request_host
    req = urllib.request.Request(upstream, headers=headers, method="GET")

    max_bytes = int(os.environ.get("PAC_MAX_BYTES", str(2 * 1024 * 1024)))
    if max_bytes <= 0:
        max_bytes = 2 * 1024 * 1024

    try:
        with urllib.request.urlopen(req, timeout=3) as response:
            try:
                content_length = response.headers.get("Content-Length")
                if content_length is not None and int(content_length) > max_bytes:
                    raise ValueError("PAC too large")
            except Exception:
                pass

            total = 0
            chunks: list[bytes] = []
            while True:
                chunk = response.read(64 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise ValueError("PAC too large")
                chunks.append(chunk)
            return b"".join(chunks)
    except Exception:
        return None


class Handler(BaseHTTPRequestHandler):
    server_version = "pac-http/2.0"

    def log_message(self, fmt, *args):
        sys.stdout.write("%s - - [%s] %s\n" % (self.address_string(), self.log_date_time_string(), fmt % args))

    def do_GET(self):
        path = (self.path or "").split("?", 1)[0]
        if path in ("", "/"):
            path = "/wpad.dat"
        if path not in ("/wpad.dat", "/proxy.pac"):
            self.send_response(404)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"Not found")
            return

        client_ip = _client_ip(self.headers, self.client_address)
        request_host = _request_host(self.headers)

        data = _LOCAL_CACHE.resolve(client_ip=client_ip, request_host=request_host)
        if data is None:
            data = _fetch_upstream(client_ip, request_host)
        if data is None:
            data = _default_pac(request_host)

        self.send_response(200)
        self.send_header("Content-Type", PAC_CONTENT_TYPE)
        if path == "/wpad.dat":
            self.send_header("Content-Disposition", 'inline; filename="wpad.dat"')
        else:
            self.send_header("Content-Disposition", 'inline; filename="proxy.pac"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main() -> int:
    httpd = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    sys.stdout.write(
        f"[pac-http] listening on {LISTEN_HOST}:{LISTEN_PORT}, pac_dir={PAC_DIR}, upstream={(UPSTREAM or '<disabled>')}\n"
    )
    httpd.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
