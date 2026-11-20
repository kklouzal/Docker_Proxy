"""Connection contract of ``proxy.management_server`` (the ``proxy_api`` listener).

The server reuses gunicorn's HTTP/1.1 parser and response writer; these
tests pin what it owns: the parser settings and error replies equal
gunicorn's, keep-alive and pipelining, slow-client and body timeouts, the
request-thread floor that keeps health polls answered during long
operations, and the graceful stop.
"""

from __future__ import annotations

import re
import socket
import threading
import time
from pathlib import Path

import pytest
from gunicorn import http as gunicorn_http
from gunicorn.config import Config
from gunicorn.http import errors as http_errors
from gunicorn.workers import base as gunicorn_worker_base

from proxy import management_server
from proxy.management_server import ManagementServer
from proxy.wsgi_http import BodyReadError, read_body

_OK = b"HTTP/1.1 200 OK\r\n"


def _app(environ, start_response):
    path = environ["PATH_INFO"]
    if path == "/slow":
        time.sleep(float(environ.get("QUERY_STRING") or "1"))
    if path == "/body":
        try:
            body = read_body(environ["wsgi.input"], 1024)
        except BodyReadError:
            start_response("400 BAD REQUEST", [("Content-Length", "0")])
            return []
    else:
        body = b""
    out = f"{environ['REQUEST_METHOD']} {path} {len(body)}".encode()
    start_response(
        "200 OK", [("Content-Type", "text/plain"), ("Content-Length", str(len(out)))]
    )
    return [out]


@pytest.fixture
def serve():
    started: list[tuple[ManagementServer, threading.Thread]] = []

    def start(**options) -> ManagementServer:
        options.setdefault("keepalive", 2)
        options.setdefault("io_timeout", 2)
        options.setdefault("graceful_timeout", 5)
        options.setdefault("head_timeout", 1)
        server = ManagementServer(_app, host="127.0.0.1", port=0, **options)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        started.append((server, thread))
        return server

    yield start
    for server, thread in started:
        server.request_stop()
        thread.join(10)
        assert not thread.is_alive()


def _connect(server: ManagementServer) -> socket.socket:
    sock = socket.create_connection(server.address[:2], timeout=5)
    sock.settimeout(5)
    return sock


def _read_all(sock: socket.socket) -> bytes:
    data = b""
    while chunk := sock.recv(65536):
        data += chunk
    return data


def _read_until(sock: socket.socket, end: bytes) -> bytes:
    data = b""
    while not data.endswith(end):
        chunk = sock.recv(65536)
        assert chunk, data
        data += chunk
    return data


def _exchange(server: ManagementServer, raw: bytes) -> bytes:
    with _connect(server) as sock:
        sock.sendall(raw)
        return _read_all(sock)


def _get(path: str, *, close: bool = True) -> bytes:
    connection = b"Connection: close\r\n" if close else b""
    return b"GET " + path.encode() + b" HTTP/1.1\r\nHost: x\r\n" + connection + b"\r\n"


def test_parser_settings_are_gunicorns_defaults() -> None:
    source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in Path(gunicorn_http.__file__).parent.glob("*.py")
    )
    used = set(re.findall(r"\bcfg\.([a-z_]+)", source))
    used |= set(re.findall(r"getattr\((?:self\.)?cfg,\s*['\"]([a-z_]+)", source))
    defaults = Config()
    config = management_server._PARSER_CONFIG
    for name in sorted(used):
        expected = getattr(defaults, name)
        actual = getattr(config, name)
        if callable(expected):
            expected, actual = expected(), actual()
        if name == "workers":
            continue  # only feeds wsgi.multiprocess: one process here
        if isinstance(expected, list):
            actual = list(actual)
        assert actual == expected, name


def _error_class_instances() -> list[BaseException]:
    instances: list[BaseException] = []
    for name in dir(http_errors):
        error_type = getattr(http_errors, name)
        if (
            not isinstance(error_type, type)
            or not issubclass(error_type, http_errors.ParseException)
            or error_type is http_errors.InvalidH2CPreface  # HTTP/2 is not served
        ):
            continue
        try:
            instances.append(error_type("detail"))
        except TypeError:
            instances.append(error_type())
    return instances


@pytest.mark.parametrize(
    "exc", _error_class_instances(), ids=lambda e: type(e).__name__
)
def test_error_replies_match_gunicorn_worker(monkeypatch, exc) -> None:
    written = []
    monkeypatch.setattr(
        gunicorn_worker_base.util,
        "write_error",
        lambda _sock, status, reason, message: written.append(
            (status, reason, message)
        ),
    )

    class _Log:
        def warning(self, *_args, **_kwargs): ...
        def exception(self, *_args, **_kwargs): ...

    class _Worker:
        log = _Log()
        cfg = management_server._PARSER_CONFIG

    gunicorn_worker_base.Worker.handle_error(_Worker(), None, None, ("1.2.3.4", 1), exc)
    reply = management_server._error_reply(exc) or (500, "Internal Server Error", "")
    assert written == [reply]


def test_keep_alive_pipelining_and_close(serve) -> None:
    server = serve()
    with _connect(server) as sock:
        sock.sendall(_get("/a", close=False))
        first = _read_until(sock, b"GET /a 0")
        assert first.startswith(_OK)
        assert b"Connection: keep-alive" in first
        # Two pipelined requests on the kept-alive connection.
        sock.sendall(_get("/b", close=False) + _get("/c"))
        rest = _read_all(sock)
    assert rest.count(_OK) == 2
    assert rest.endswith(b"GET /c 0")


def test_keep_alive_disabled_closes_after_each_response(serve) -> None:
    server = serve(keepalive=0)
    with _connect(server) as sock:
        sock.sendall(_get("/a", close=False))
        reply = _read_all(sock)
    assert b"Connection: close" in reply


def test_idle_kept_alive_connection_is_closed(serve) -> None:
    server = serve(keepalive=0.3)
    with _connect(server) as sock:
        sock.sendall(_get("/a", close=False))
        assert _read_until(sock, b"GET /a 0").startswith(_OK)
        started = time.monotonic()
        assert sock.recv(1) == b""
    assert time.monotonic() - started < 2


@pytest.mark.parametrize(
    ("raw", "status"),
    [
        (b"BAD\r\n\r\n", b"400 Bad Request"),
        (b"GET / HTTP/1.1\nHost: x\n\n", b"400 Bad Request"),
        (b"GET / HTTP/1.1\r\nHost: x\n\r\n", b"400 Bad Request"),
        (b"GET /" + b"a" * 5000 + b" HTTP/1.1\r\nHost: x\r\n\r\n", b"414 URI Too Long"),
        (
            b"GET / HTTP/1.1\r\nHost: x\r\n" + b"X-A: b\r\n" * 101 + b"\r\n",
            b"431 Request Header Fields Too Large",
        ),
        (
            b"GET / HTTP/1.1\r\nHost: x\r\nX-A: " + b"b" * 9000 + b"\r\n\r\n",
            b"431 Request Header Fields Too Large",
        ),
        (b"GET / HTTP/1.1\r\nHost: x\r\nBad Name: y\r\n\r\n", b"400 Bad Request"),
        (
            b"POST /x HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip\r\n\r\n",
            b"400 Bad Request",
        ),
        (
            (
                b"POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\n"
                b"Content-Length: 2\r\n\r\nab"
            ),
            b"400 Bad Request",
        ),
    ],
)
def test_malformed_requests_get_gunicorns_error_replies(serve, raw, status) -> None:
    reply = _exchange(serve(), raw)
    assert reply.startswith(b"HTTP/1.1 " + status + b"\r\n")
    assert b"Connection: close\r\n" in reply


def test_chunked_bodies_are_decoded_and_bad_framing_is_rejected(serve) -> None:
    server = serve()
    good = _exchange(
        server,
        b"POST /body HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n"
        b"Connection: close\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n",
    )
    assert good.startswith(_OK)
    assert good.endswith(b"POST /body 5")
    bad = _exchange(
        server,
        b"POST /body HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"zz\r\nabc\r\n0\r\n\r\n",
    )
    # The application reads the body and answers the framing error itself.
    assert bad.startswith(b"HTTP/1.1 400 BAD REQUEST\r\n")


def test_stalled_body_times_out(serve) -> None:
    server = serve(io_timeout=0.5)
    started = time.monotonic()
    reply = _exchange(
        server,
        b"POST /body HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\nab",
    )
    assert reply.startswith(b"HTTP/1.1 400 BAD REQUEST\r\n")
    assert time.monotonic() - started < 3


def test_slow_heads_hold_no_request_thread_and_expire(serve) -> None:
    server = serve(threads=1, head_timeout=1)
    slow = [_connect(server) for _ in range(4)]
    try:
        for sock in slow:
            sock.sendall(b"GET /health HTTP/1.1\r\nHost")
        started = time.monotonic()
        assert _exchange(server, _get("/health")).startswith(_OK)
        assert time.monotonic() - started < 0.5
        for sock in slow:
            # Closed without a reply once the head deadline passes.
            assert sock.recv(65536) == b""
        assert time.monotonic() - started < 3
    finally:
        for sock in slow:
            sock.close()


def test_long_request_does_not_starve_health(serve) -> None:
    server = serve(threads=1)  # the production setting: floored at two
    assert server.threads == 2
    replies: list[bytes] = []
    long_request = threading.Thread(
        target=lambda: replies.append(_exchange(server, _get("/slow?1.5")))
    )
    long_request.start()
    time.sleep(0.2)
    started = time.monotonic()
    assert _exchange(server, _get("/health")).startswith(_OK)
    assert time.monotonic() - started < 0.5
    long_request.join(5)
    assert replies[0].startswith(_OK)


def test_graceful_stop_finishes_in_flight_requests(serve) -> None:
    server = serve()
    replies: list[bytes] = []
    in_flight = threading.Thread(
        target=lambda: replies.append(_exchange(server, _get("/slow?1", close=False)))
    )
    in_flight.start()
    idle = _connect(server)
    time.sleep(0.3)
    server.request_stop()
    in_flight.join(5)
    assert replies[0].startswith(_OK)
    assert b"Connection: close" in replies[0]
    assert idle.recv(1) == b""  # idle connections are closed at once
    idle.close()
    with pytest.raises(OSError):
        socket.create_connection(server.address[:2], timeout=1).close()


def test_graceful_stop_is_bounded() -> None:
    server = ManagementServer(
        _app, host="127.0.0.1", port=0, graceful_timeout=0.5, head_timeout=1
    )
    results: list[bool] = []
    serving = threading.Thread(target=lambda: results.append(server.serve_forever()))
    serving.start()
    threading.Thread(
        target=lambda: _exchange(server, _get("/slow?3")), daemon=True
    ).start()
    time.sleep(0.3)
    started = time.monotonic()
    server.request_stop()
    serving.join(5)
    assert results == [False]  # requests outlived the grace period
    assert time.monotonic() - started < 1.5
