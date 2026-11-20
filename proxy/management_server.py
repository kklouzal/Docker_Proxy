"""Single-process HTTP/1.1 server for the proxy management API (``proxy_api``).

Replaces ``gunicorn proxy.wsgi:app`` for the management listener only: one
process instead of a gunicorn arbiter plus one worker, which saves the
arbiter's resident memory on the router. ``proxy_public`` stays on gunicorn.

The listener keeps gunicorn's HTTP/1.1 behaviour by running gunicorn's own
request parser (request-line/header limits, Content-Length and chunked
framing, ``Expect: 100-continue``, forwarded-scheme handling), WSGI environ
builder and response writer from the pinned ``gunicorn`` distribution; only
the process/connection management below is owned here. ``_PARSER_CONFIG``
holds gunicorn's default settings for exactly the attributes those modules
read, and malformed requests get gunicorn's error replies (status, reason
and body) from ``_error_reply``. Both are checked against gunicorn itself by
``web/tests/test_proxy_management_server.py``.

Connection handling contract:

* The main thread owns the listening socket and every connection that is
  waiting for a request head. It reads heads without blocking, so a slow or
  silent client never occupies a request thread. A new connection must
  deliver a complete head within ``REQUEST_HEAD_TIMEOUT``; a kept-alive one
  may idle ``WEB_KEEPALIVE`` seconds and then gets the same head deadline.
  Expired connections are closed without a reply.
* Complete heads go to a pool of ``max(2, WEB_THREADS)`` request threads, so
  a long operation (cache clear, config apply) never starves health polls.
  The parser enforces gunicorn's limits; every socket read or write of the
  body and response has a ``WEB_TIMEOUT`` inactivity limit.
* At most ``MAX_CONNECTIONS`` connections are open; further clients wait in
  the listen backlog. Keep-alive follows the response (``WEB_KEEPALIVE`` 0
  disables it); unread request bodies are drained as gunicorn does, bounded.
* SIGTERM/SIGINT stop accepting, close idle connections and let accepted
  requests finish (with ``Connection: close``) for ``WEB_GRACEFUL_TIMEOUT``
  seconds at most; supervisor's stop window bounds that from outside.
* No access log (gunicorn ran without one). Rejected requests are logged as
  warnings and server-side failures with tracebacks, through the process
  logging the application configures.
"""

from __future__ import annotations

import errno
import logging
import os
import selectors
import signal
import socket
import sys
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING, Any

from gunicorn import util as gunicorn_util
from gunicorn.http import RequestParser
from gunicorn.http import errors as http_errors
from gunicorn.http import wsgi as gunicorn_wsgi

if TYPE_CHECKING:
    from collections.abc import Callable

_LOGGER = logging.getLogger(__name__)

BIND_HOST = "0.0.0.0"  # ruff: ignore[hardcoded-bind-all-interfaces] -- management listener, as before
BIND_PORT = 5000
LISTEN_BACKLOG = 2048  # gunicorn's default backlog
MAX_CONNECTIONS = 100
MIN_REQUEST_THREADS = 2
REQUEST_HEAD_TIMEOUT = 10.0
# Bytes of request head read by the main thread before a request thread takes
# over; far above any management request head, below gunicorn's head limits.
HEAD_BUFFER_LIMIT = 64 * 1024
# gthread's bound for draining an unread request body before keep-alive.
BODY_DRAIN_TIMEOUT = 5.0


class _ParserConfig:
    """gunicorn's default settings for the attributes its HTTP modules read.

    ``gunicorn.config.Config`` would load argparse and every server setting;
    the parser needs only these. Values equal ``Config()`` defaults (pinned by
    the tests) except ``workers``, which only feeds ``wsgi.multiprocess``.
    """

    casefold_http_method = False
    errorlog = "-"
    forwarded_allow_ips = ("127.0.0.1", "::1")
    forwarder_headers = ("SCRIPT_NAME", "PATH_INFO")
    header_map = "drop"
    http_parser = "auto"
    is_ssl = None
    limit_request_field_size = 8190
    limit_request_fields = 100
    limit_request_line = 4094
    permit_obsolete_folding = False
    permit_unconventional_http_method = False
    permit_unconventional_http_version = False
    protocol = "http"
    proxy_allow_ips = ("127.0.0.1", "::1")
    proxy_protocol = "off"
    secure_scheme_headers = {  # ruff: ignore[mutable-class-default] -- read-only, as gunicorn's
        "X-FORWARDED-PROTOCOL": "ssl",
        "X-FORWARDED-PROTO": "https",
        "X-FORWARDED-SSL": "on",
    }
    sendfile = True
    strip_header_spaces = False
    workers = 1

    def __init__(self) -> None:
        import ipaddress

        self._forwarded = [ipaddress.ip_network(a) for a in self.forwarded_allow_ips]
        self._proxy = [ipaddress.ip_network(a) for a in self.proxy_allow_ips]

    def forwarded_allow_networks(self) -> list[Any]:
        return self._forwarded

    def proxy_allow_networks(self) -> list[Any]:
        return self._proxy


_PARSER_CONFIG = _ParserConfig()

# gunicorn ``Worker.handle_error``: client errors in its order, as
# (exception, status, reason, message format); anything else is a 500.
_CLIENT_ERRORS: tuple[tuple[type[BaseException], int, str, str], ...] = (
    (http_errors.InvalidRequestLine, 400, "Bad Request", "Invalid Request Line '%s'"),
    (http_errors.InvalidRequestMethod, 400, "Bad Request", "Invalid Method '%s'"),
    (http_errors.InvalidHTTPVersion, 400, "Bad Request", "Invalid HTTP Version '%s'"),
    (http_errors.UnsupportedTransferCoding, 501, "Bad Request", "%s"),
    (http_errors.ConfigurationProblem, 500, "Bad Request", "%s"),
    (http_errors.ObsoleteFolding, 400, "Bad Request", "%s"),
    (http_errors.InvalidHeaderName, 400, "Bad Request", "%s"),
    (http_errors.InvalidHeader, 400, "Bad Request", "%s"),
    (http_errors.LimitRequestLine, 414, "URI Too Long", "%s"),
    (http_errors.ExpectationFailed, 417, "Expectation Failed", "%s"),
    (
        http_errors.LimitRequestHeaders,
        431,
        "Request Header Fields Too Large",
        "Error parsing headers: '%s'",
    ),
    (http_errors.InvalidProxyLine, 400, "Bad Request", "'%s'"),
    (http_errors.ForbiddenProxyRequest, 403, "Forbidden", "Request forbidden"),
    (http_errors.InvalidSchemeHeaders, 400, "Bad Request", "%s"),
    (http_errors.InvalidChunkSize, 400, "Bad Request", "%s"),
    (http_errors.ChunkMissingTerminator, 400, "Bad Request", "%s"),
    (http_errors.InvalidChunkExtension, 400, "Bad Request", "%s"),
)
_APPLICATION_HEADER_ERRORS = (
    http_errors.InvalidResponseHeader,
    http_errors.InvalidResponseHeaderName,
)


def _error_reply(exc: BaseException) -> tuple[int, str, str] | None:
    """The ``(status, reason, message)`` gunicorn sends for a client error, else None."""
    if isinstance(exc, _APPLICATION_HEADER_ERRORS):
        return None
    for error_type, status, reason, message in _CLIENT_ERRORS:
        if isinstance(exc, error_type):
            return status, reason, message % exc if "%s" in message else message
    return None


class _Connection:
    """A client socket plus the head bytes the main thread already read.

    gunicorn's parser reads through ``recv``: buffered head bytes first, then
    the socket, bounded by the head deadline while the head is parsed.
    """

    __slots__ = ("addr", "buffer", "deadline", "head_deadline", "parser", "sock")

    def __init__(self, sock: socket.socket, addr: Any, deadline: float) -> None:
        self.sock = sock
        self.addr = addr
        self.buffer = bytearray()
        self.parser: Any = None
        # Main thread: when this waiting connection expires.
        self.deadline = deadline
        # Request thread: absolute limit for the rest of the head, or None.
        self.head_deadline: float | None = None

    def recv(self, size: int) -> bytes:
        if self.buffer:
            data = bytes(self.buffer[:size])
            del self.buffer[:size]
            return data
        if self.head_deadline is not None:
            remaining = self.head_deadline - time.monotonic()
            if remaining <= 0:
                message = "request head timed out"
                raise TimeoutError(message)
            self.sock.settimeout(remaining)
        return self.sock.recv(size)

    # gunicorn's body drain bounds its reads through these.
    def gettimeout(self) -> float | None:
        return self.sock.gettimeout()

    def settimeout(self, value: float | None) -> None:
        self.sock.settimeout(value)

    def has_pending_input(self) -> bool:
        """Whether bytes of a further request were already read."""
        return bool(self.buffer) or bool(
            self.parser is not None and self.parser.unreader.buf.getvalue()
        )


class ManagementServer:
    def __init__(
        self,
        app: Callable[..., Any],
        *,
        host: str = BIND_HOST,
        port: int = BIND_PORT,
        threads: int = MIN_REQUEST_THREADS,
        keepalive: float = 5.0,
        io_timeout: float = 120.0,
        graceful_timeout: float = 30.0,
        head_timeout: float = REQUEST_HEAD_TIMEOUT,
        max_connections: int = MAX_CONNECTIONS,
    ) -> None:
        self.app = app
        self.threads = max(MIN_REQUEST_THREADS, threads)
        self.keepalive = keepalive
        self.io_timeout = io_timeout
        self.graceful_timeout = graceful_timeout
        self.head_timeout = head_timeout
        self.max_connections = max_connections
        self.listener = socket.create_server((host, port), backlog=LISTEN_BACKLOG)
        self.listener.setblocking(False)
        self.address = self.listener.getsockname()
        self._wake_r, self._wake_w = socket.socketpair()
        self._wake_r.setblocking(False)
        self._wake_w.setblocking(False)
        self._selector = selectors.DefaultSelector()
        self._waiting: dict[_Connection, None] = {}
        self._active = 0  # connections owned by request threads
        self._finished: deque[tuple[_Connection, bool]] = deque()
        self._accepting = False
        self._stopping = False
        self._pool = ThreadPoolExecutor(
            max_workers=self.threads, thread_name_prefix="proxy-api"
        )

    # -- main thread -------------------------------------------------------

    def request_stop(self) -> None:
        """Begin a graceful stop; safe from a signal handler."""
        self._stopping = True
        try:
            self._wake_w.send(b"\0")
        except OSError:
            pass  # the wake-up pipe is full: the loop is already being woken

    def serve_forever(self) -> bool:
        """Serve until stopped; False when requests outlived the grace period."""
        selector = self._selector
        selector.register(self._wake_r, selectors.EVENT_READ, None)
        self._set_accepting(True)
        stop_deadline: float | None = None
        try:
            while True:
                if self._stopping and stop_deadline is None:
                    stop_deadline = time.monotonic() + self.graceful_timeout
                    self._begin_stop()
                if stop_deadline is not None:
                    if self._active == 0:
                        break
                    if time.monotonic() >= stop_deadline:
                        _LOGGER.warning(
                            "Stopping with %d request(s) still in progress.",
                            self._active,
                        )
                        return False
                self._set_accepting(
                    not self._stopping
                    and len(self._waiting) + self._active < self.max_connections
                )
                for key, _events in selector.select(
                    self._select_timeout(stop_deadline)
                ):
                    if key.data is None:
                        self._drain_wake()
                    elif key.data is self.listener:
                        self._accept()
                    else:
                        self._read_head(key.data)
                self._collect_finished()
                self._expire_waiting()
        finally:
            self._shutdown()
        return True

    def _select_timeout(self, stop_deadline: float | None) -> float:
        deadlines = [conn.deadline for conn in self._waiting]
        if stop_deadline is not None:
            deadlines.append(stop_deadline)
        if not deadlines:
            return 1.0
        return min(1.0, max(0.0, min(deadlines) - time.monotonic()))

    def _set_accepting(self, enabled: bool) -> None:
        if enabled == self._accepting:
            return
        if enabled:
            self._selector.register(self.listener, selectors.EVENT_READ, self.listener)
        else:
            self._selector.unregister(self.listener)
        self._accepting = enabled

    def _drain_wake(self) -> None:
        try:
            while self._wake_r.recv(4096):
                pass
        except BlockingIOError:
            pass

    def _accept(self) -> None:
        while len(self._waiting) + self._active < self.max_connections:
            try:
                sock, addr = self.listener.accept()
            except BlockingIOError:
                return
            except OSError as exc:
                if exc.errno in {errno.ECONNABORTED, errno.EPROTO}:
                    continue
                if exc.errno in {
                    errno.EMFILE,
                    errno.ENFILE,
                    errno.ENOBUFS,
                    errno.ENOMEM,
                }:
                    _LOGGER.warning("Cannot accept a management connection: %s", exc)
                    return
                raise
            sock.setblocking(False)
            self._wait(_Connection(sock, addr, time.monotonic() + self.head_timeout))

    def _wait(self, conn: _Connection) -> None:
        self._waiting[conn] = None
        self._selector.register(conn.sock, selectors.EVENT_READ, conn)

    def _unwait(self, conn: _Connection) -> None:
        del self._waiting[conn]
        self._selector.unregister(conn.sock)

    def _read_head(self, conn: _Connection) -> None:
        had_bytes = bool(conn.buffer)
        try:
            data = conn.sock.recv(HEAD_BUFFER_LIMIT - len(conn.buffer))
        except BlockingIOError:
            return
        except OSError:
            data = b""
        if not data:
            self._unwait(conn)
            conn.sock.close()
            return
        conn.buffer += data
        if not had_bytes and conn.parser is not None:
            # A kept-alive connection began its next request.
            conn.deadline = time.monotonic() + self.head_timeout
        if b"\r\n\r\n" in conn.buffer or len(conn.buffer) >= HEAD_BUFFER_LIMIT:
            self._unwait(conn)
            self._dispatch(conn)

    def _dispatch(self, conn: _Connection) -> None:
        conn.sock.setblocking(True)
        conn.head_deadline = conn.deadline
        self._active += 1
        future = self._pool.submit(self._serve, conn)
        future.add_done_callback(lambda done: self._finish(conn, done))

    def _finish(self, conn: _Connection, future: Any) -> None:
        # Runs on the request thread (or here, for a cancelled future).
        keep_alive = (
            not future.cancelled() and future.exception() is None and future.result()
        )
        self._finished.append((conn, keep_alive))
        try:
            self._wake_w.send(b"\0")
        except OSError:
            pass  # the wake-up pipe is full: the loop is already being woken

    def _collect_finished(self) -> None:
        while self._finished:
            conn, keep_alive = self._finished.popleft()
            self._active -= 1
            if not keep_alive or self._stopping:
                conn.sock.close()  # a no-op after the request thread closed it
                continue
            if conn.has_pending_input():
                # Pipelined bytes are already read: no socket event will come.
                conn.deadline = time.monotonic() + self.head_timeout
                self._dispatch(conn)
                continue
            conn.sock.setblocking(False)
            conn.deadline = time.monotonic() + self.keepalive
            self._wait(conn)

    def _expire_waiting(self) -> None:
        now = time.monotonic()
        for conn in [c for c in self._waiting if c.deadline <= now]:
            self._unwait(conn)
            conn.sock.close()

    def _begin_stop(self) -> None:
        _LOGGER.info(
            "Stopping management listener; %d request(s) in progress.", self._active
        )
        self._set_accepting(False)
        self.listener.close()
        # Idle and partially received connections hold no accepted request.
        for conn in list(self._waiting):
            self._unwait(conn)
            conn.sock.close()

    def _shutdown(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)
        for conn in list(self._waiting):
            self._unwait(conn)
            conn.sock.close()
        self._selector.close()
        self.listener.close()
        self._wake_r.close()
        self._wake_w.close()

    # -- request threads ---------------------------------------------------

    def _serve(self, conn: _Connection) -> bool:
        """Serve one request; True when the connection may be kept alive."""
        req = None
        sock = conn.sock
        try:
            if conn.parser is None:
                conn.parser = RequestParser(_PARSER_CONFIG, conn, conn.addr)
            req = next(conn.parser)
            conn.head_deadline = None
            sock.settimeout(self.io_timeout)
            if not self._respond(req, conn):
                return False
            # Unread body bytes would look like the next request: drain them
            # within gthread's bounds, or close.
            return bool(
                conn.parser.finish_body(deadline=time.monotonic() + BODY_DRAIN_TIMEOUT)
            )
        except http_errors.NoMoreData as exc:
            _LOGGER.debug("Ignored premature client disconnection. %s", exc)
        except StopIteration as exc:
            _LOGGER.debug("Closing connection. %s", exc)
        except TimeoutError:
            _LOGGER.debug("Client connection timed out from %s", conn.addr)
        except OSError as exc:
            if exc.errno not in {errno.EPIPE, errno.ECONNRESET, errno.ENOTCONN}:
                _LOGGER.exception("Socket error processing request.")
        except Exception as exc:
            self._handle_error(req, sock, conn.addr, exc)
        finally:
            conn.head_deadline = None
        gunicorn_util.close_graceful(sock)
        return False

    def _respond(self, req: Any, conn: _Connection) -> bool:
        """Run the application; True unless the response ends the connection."""
        resp, environ = gunicorn_wsgi.create(
            req, conn.sock, conn.addr, self.address, _PARSER_CONFIG
        )
        environ["wsgi.multithread"] = True
        if not self.keepalive:
            resp.force_close()

        def start_response(*args: Any) -> Any:
            # A stop that began during the request still ends the connection.
            if self._stopping:
                resp.force_close()
            return resp.start_response(*args)

        try:
            respiter = self.app(environ, start_response)
            try:
                for item in respiter:
                    resp.write(item)
                resp.close()
            finally:
                if hasattr(respiter, "close"):
                    respiter.close()
        except OSError:
            raise
        except Exception:
            if resp.headers_sent:
                # A 500 now would corrupt the response already started.
                _LOGGER.exception("Error handling request")
                return False
            raise
        return not resp.should_close()

    def _handle_error(
        self, req: Any, sock: socket.socket, addr: Any, exc: Exception
    ) -> None:
        reply = _error_reply(exc)
        if reply is None:
            if req is not None:
                _LOGGER.error(
                    "Error handling request %s %s", req.method, req.uri, exc_info=exc
                )
            else:
                _LOGGER.error("Error handling request (no URI read)", exc_info=exc)
            status, reason, message = 500, "Internal Server Error", ""
        else:
            status, reason, message = reply
            _LOGGER.warning("Invalid request from ip=%s: %s", addr[0], exc)
        try:
            gunicorn_util.write_error(sock, status, reason, message)
        except Exception:
            _LOGGER.debug("Failed to send error message.")


def _env_number(name: str, default: int, minimum: int) -> int:
    raw = (os.environ.get(name) or "").strip()
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value >= minimum else default


def main() -> None:
    from proxy.app import app

    server = ManagementServer(
        app,
        threads=_env_number("WEB_THREADS", MIN_REQUEST_THREADS, 1),
        keepalive=_env_number("WEB_KEEPALIVE", 5, 0),
        io_timeout=_env_number("WEB_TIMEOUT", 120, 1),
        graceful_timeout=_env_number("WEB_GRACEFUL_TIMEOUT", 30, 1),
    )
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda _signum, _frame: server.request_stop())
    host, port = server.address[:2]
    _LOGGER.info(
        "Management listener at http://%s:%d (pid %d, %d request threads).",
        host,
        port,
        os.getpid(),
        server.threads,
    )
    drained = server.serve_forever()
    _LOGGER.info("Management listener stopped.")
    if not drained:
        # Like gunicorn after its graceful timeout: abandon the requests
        # still running instead of waiting for their threads at exit.
        logging.shutdown()
        os._exit(0)
    sys.exit(0)


if __name__ == "__main__":
    main()
