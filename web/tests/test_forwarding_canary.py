from __future__ import annotations

import json
import socket
import sys
import threading
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import urlopen

import pytest


def _add_repo_paths() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    web_root = repo_root / "web"
    for path in (repo_root, web_root):
        path_str = str(path)
        if path_str not in sys.path:
            sys.path.insert(0, path_str)


def test_forwarding_canary_listener_serves_only_static_loopback_canary() -> None:
    _add_repo_paths()
    from http.server import ThreadingHTTPServer

    from proxy.forwarding_canary import ForwardingCanaryHandler

    server = ThreadingHTTPServer(("127.0.0.1", 0), ForwardingCanaryHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        with urlopen(
            f"http://127.0.0.1:{port}/__docker_proxy_forwarding_canary?probe=squid-respmod",
            timeout=2,
        ) as response:
            payload = json.loads(response.read().decode("utf-8"))
            assert response.status == 200
            assert response.headers["Cache-Control"] == "no-store, no-cache, max-age=0"
        assert payload == {
            "ok": True,
            "probe": "squid-respmod",
            "service": "docker-proxy-forwarding-canary",
        }
        with pytest.raises(HTTPError) as error:
            urlopen(f"http://127.0.0.1:{port}/anything-else", timeout=2)
        assert error.value.code == 404
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_forwarding_canary_env_hardening_keeps_listener_loopback_only(
    monkeypatch,
) -> None:
    _add_repo_paths()
    from proxy import forwarding_canary

    monkeypatch.setenv("FORWARDING_CANARY_HOST", "0.0.0.0")  # noqa: S104 - verifies unsafe bind env is coerced.
    monkeypatch.setenv("FORWARDING_CANARY_PORT", "not-a-port")
    monkeypatch.setenv("FORWARDING_CANARY_PATH", "http://example.test/proxy")

    assert forwarding_canary._canary_host() == "127.0.0.1"
    assert forwarding_canary._canary_port() == 18080
    assert forwarding_canary._canary_path() == "/__docker_proxy_forwarding_canary"


def test_forwarding_canary_rejects_dns_names_that_look_like_loopback(
    monkeypatch,
) -> None:
    _add_repo_paths()
    from proxy import forwarding_canary

    for host in ("127.evil.test", "127.0.0.1.evil.test"):
        monkeypatch.setenv("FORWARDING_CANARY_HOST", host)

        assert forwarding_canary._canary_host() == "127.0.0.1"


def test_forwarding_canary_probe_header_cannot_inject_response_headers() -> None:
    _add_repo_paths()
    from http.server import ThreadingHTTPServer

    from proxy.forwarding_canary import ForwardingCanaryHandler

    server = ThreadingHTTPServer(("127.0.0.1", 0), ForwardingCanaryHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        request = (
            b"GET /__docker_proxy_forwarding_canary?"
            b"probe=ok%0d%0aX-Injected:%20yes HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
            client.sendall(request)
            response = b""
            while chunk := client.recv(4096):
                response += chunk

        header_block, body = response.split(b"\r\n\r\n", 1)
        headers = header_block.decode("iso-8859-1")
        assert "\r\nX-Injected:" not in headers
        assert "X-Docker-Proxy-Forwarding-Canary: ok??X-Injected: yes" in headers
        assert json.loads(body.decode("utf-8"))["probe"] == "ok\r\nX-Injected: yes"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_forwarding_canary_probe_header_value_is_control_safe_and_bounded() -> None:
    _add_repo_paths()
    from proxy.forwarding_canary import (
        MAX_PROBE_HEADER_VALUE_LEN,
        _probe_header_value,
    )

    probe = "safe\n\r\t" + "x" * (MAX_PROBE_HEADER_VALUE_LEN + 10)
    sanitized = _probe_header_value(probe)

    assert sanitized == "safe???" + "x" * (MAX_PROBE_HEADER_VALUE_LEN - 7)
    assert len(sanitized) == MAX_PROBE_HEADER_VALUE_LEN
