"""Response plumbing shared by the proxy's plain-WSGI listeners.

``proxy.public_app`` (PAC/WPAD) and ``proxy.app`` (management API) replaced
Flask apps whose import graph dominated each worker's resident memory. Both
keep the former client-observable bytes: Werkzeug's status lines and error
pages, Flask's ``jsonify`` encoding, Werkzeug's header order and the
``install_http_optimizations`` cache/gzip policy. The golden contract tests
(``web/tests/test_proxy_public_wsgi_contract.py`` and
``web/tests/test_proxy_management_wsgi_contract.py``) pin those bytes.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import gzip
import json
import re
from email.utils import format_datetime
from typing import TYPE_CHECKING, Any

from services.http_optimizations import (
    TRANSFORMATION_INVALIDATED_HEADERS,
    client_accepts_gzip,
    compressible_mimetype,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

# Werkzeug's ``HTTP_STATUS_CODES`` names, upper-cased as Werkzeug sends them.
STATUS_LINES = {
    200: "200 OK",
    304: "304 NOT MODIFIED",
    308: "308 PERMANENT REDIRECT",
    400: "400 BAD REQUEST",
    403: "403 FORBIDDEN",
    404: "404 NOT FOUND",
    405: "405 METHOD NOT ALLOWED",
    409: "409 CONFLICT",
    412: "412 PRECONDITION FAILED",
    413: "413 REQUEST ENTITY TOO LARGE",
    429: "429 TOO MANY REQUESTS",
    500: "500 INTERNAL SERVER ERROR",
    503: "503 SERVICE UNAVAILABLE",
}
HTML = "text/html; charset=utf-8"
GZIP_MIN_SIZE = 1024
GZIP_LEVEL = 5
# Entity headers Werkzeug strips from a 304 (``remove_entity_headers``).
_NOT_MODIFIED_DROPPED_HEADERS = frozenset(
    {
        "allow",
        "content-encoding",
        "content-language",
        "content-length",
        "content-md5",
        "content-range",
        "content-type",
        "last-modified",
    },
)


def error_page(code: int, name: str, description: str) -> bytes:
    """Werkzeug's default ``HTTPException`` body."""
    return (
        "<!doctype html>\n<html lang=en>\n"
        f"<title>{code} {name}</title>\n<h1>{name}</h1>\n<p>{description}</p>\n"
    ).encode()


BAD_REQUEST_PAGE = error_page(
    400,
    "Bad Request",
    "The browser (or proxy) sent a request that this server could not understand.",
)
NOT_FOUND_PAGE = error_page(
    404,
    "Not Found",
    "The requested URL was not found on the server. If you entered the URL"
    " manually please check your spelling and try again.",
)
METHOD_NOT_ALLOWED_PAGE = error_page(
    405, "Method Not Allowed", "The method is not allowed for the requested URL."
)
INTERNAL_ERROR_PAGE = error_page(
    500,
    "Internal Server Error",
    "The server encountered an internal error and was unable to complete your"
    " request. Either the server is overloaded or there is an error in the"
    " application.",
)


def _json_default(value: Any) -> Any:
    """Flask ``DefaultJSONProvider`` conversions for non-JSON types.

    Only reached for values ``json`` cannot encode, so ``decimal`` and ``uuid``
    are imported here rather than in every listener.
    """
    import decimal
    import uuid

    if isinstance(value, dt.date):
        if not isinstance(value, dt.datetime):
            # Werkzeug ``http_date``: a plain date is midnight UTC.
            value = dt.datetime.combine(value, dt.time(), tzinfo=dt.UTC)
        elif value.tzinfo is None:
            value = value.replace(tzinfo=dt.UTC)
        elif value.tzinfo != dt.UTC:
            value = value.astimezone(dt.UTC)
        return format_datetime(value, usegmt=True)
    if isinstance(value, (decimal.Decimal, uuid.UUID)):
        return str(value)
    if dataclasses.is_dataclass(value):
        return dataclasses.asdict(value)  # type: ignore[arg-type]
    if hasattr(value, "__html__"):
        return str(value.__html__())  # ruff: ignore[unnecessary-dunder-call] -- markupsafe protocol, as Flask
    message = f"Object of type {type(value).__name__} is not JSON serializable"
    raise TypeError(message)


def json_body(payload: Any) -> bytes:
    """Flask ``jsonify`` bytes: sorted keys, compact, ASCII, trailing newline."""
    return (
        json.dumps(
            payload, default=_json_default, sort_keys=True, separators=(",", ":")
        )
        + "\n"
    ).encode()


MANAGEMENT_NOT_FOUND_BODY = json_body(
    {
        "ok": False,
        "status": "not_found",
        "detail": "Proxy management endpoint was not found. Check that the registered management URL points to the proxy management listener, not the public PAC/proxy listener.",
    },
)


class Response:
    """A fully buffered response whose header list keeps Werkzeug's order.

    ``Allow`` precedes ``Content-Length`` (Werkzeug error/OPTIONS responses);
    headers added afterwards follow it.
    """

    __slots__ = ("body", "headers", "status")

    def __init__(
        self,
        status: int,
        content_type: str,
        body: bytes,
        *,
        allow: tuple[str, ...] = (),
    ) -> None:
        self.status = status
        self.headers = [("Content-Type", content_type)]
        if allow:
            self.headers.append(("Allow", ", ".join(allow)))
        if body:
            self.headers.append(("Content-Length", str(len(body))))
        self.body = body

    def get(self, name: str) -> str | None:
        lowered = name.lower()
        for key, value in self.headers:
            if key.lower() == lowered:
                return value
        return None

    def set(self, name: str, value: str) -> None:
        """Replace the first ``name`` header in place, like Werkzeug ``Headers.set``."""
        lowered = name.lower()
        for index, (key, _old) in enumerate(self.headers):
            if key.lower() == lowered:
                self.headers[index] = (key, value)
                self.headers[index + 1 :] = [
                    item
                    for item in self.headers[index + 1 :]
                    if item[0].lower() != lowered
                ]
                return
        self.headers.append((name, value))

    def remove(self, name: str) -> None:
        lowered = name.lower()
        self.headers = [item for item in self.headers if item[0].lower() != lowered]


def json_response(payload: Any, status: int = 200) -> Response:
    return Response(status, "application/json", json_body(payload))


class RequestHeaders:
    """Header lookup over a WSGI environ, like Werkzeug ``EnvironHeaders.get``."""

    __slots__ = ("_environ",)

    def __init__(self, environ: dict[str, Any]) -> None:
        self._environ = environ

    def get(self, name: str, default: str | None = None) -> str | None:
        key = name.upper().replace("-", "_")
        if key not in {"CONTENT_TYPE", "CONTENT_LENGTH"}:
            key = f"HTTP_{key}"
        return self._environ.get(key, default)


_DECIMAL_LENGTH = re.compile(r"[0-9]+", re.ASCII)


def declared_content_length(environ: dict[str, Any]) -> int | None:
    """The request body length declared by ``Content-Length``.

    None when no length is declared: the header is absent or empty (PEP 3333)
    or a chunked Transfer-Encoding frames the body instead (RFC 9112 section
    6.3). Any other value that is not ``1*DIGIT`` (RFC 9110 section 8.6),
    optional whitespace aside, raises ``ValueError``: it frames no body, so
    the request is a bad request rather than one without a body.
    """
    raw_length = environ.get("CONTENT_LENGTH")
    if not raw_length:
        return None
    transfer_encoding = environ.get("HTTP_TRANSFER_ENCODING")
    if transfer_encoding is not None and "chunked" in {
        token.strip().lower() for token in transfer_encoding.split(",")
    }:
        return None
    value = raw_length.strip(" \t")
    if not _DECIMAL_LENGTH.fullmatch(value):
        message = f"invalid Content-Length {raw_length!r}"
        raise ValueError(message)
    return int(value)


def request_path(environ: dict[str, Any]) -> str:
    """Werkzeug ``Request.path``: UTF-8 decoded PATH_INFO with one leading slash."""
    raw_path = environ.get("PATH_INFO") or ""
    return "/" + raw_path.encode("latin-1").decode(errors="replace").lstrip("/")


def apply_http_optimizations(
    response: Response,
    environ: dict[str, Any],
    method: str,
    *,
    gzip_enabled: bool,
) -> None:
    """The ``install_http_optimizations`` policy with dynamic max-age 0.

    Only fixed, fully buffered bodies reach this point: none carries a
    Content-Encoding, Content-Range or ``no-transform`` directive.
    """
    if response.get("Cache-Control") is None:
        if method not in {"GET", "HEAD"}:
            cache_control = "no-store"
        elif (environ.get("HTTP_X_REQUESTED_WITH") or "").lower() == "spa":
            cache_control = "no-store, private"
        else:
            cache_control = "no-cache"
        response.headers.append(("Cache-Control", cache_control))
    status = response.status
    if (
        not gzip_enabled
        or (status != 304 and not 200 <= status < 300)
        or not compressible_mimetype(response.get("Content-Type"))
        or len(response.body) < GZIP_MIN_SIZE
    ):
        return
    vary_tokens = {
        token.strip().lower()
        for key, value in response.headers
        if key.lower() == "vary"
        for token in value.split(",")
        if token.strip()
    }
    if "*" not in vary_tokens and "accept-encoding" not in vary_tokens:
        vary = response.get("Vary")
        response.set("Vary", f"{vary}, Accept-Encoding" if vary else "Accept-Encoding")
    if status == 304 or not client_accepts_gzip(
        environ.get("HTTP_ACCEPT_ENCODING", "")
    ):
        return
    compressed = gzip.compress(response.body, compresslevel=GZIP_LEVEL)
    if len(compressed) >= len(response.body):
        return
    response.body = compressed
    response.set("Content-Length", str(len(compressed)))
    response.headers.append(("Content-Encoding", "gzip"))
    # Validators and integrity values for the identity bytes no longer apply.
    for header in TRANSFORMATION_INVALIDATED_HEADERS:
        response.remove(header)


def send(
    response: Response,
    environ: dict[str, Any],
    start_response: Callable[..., Any],
) -> Iterable[bytes]:
    """Emit ``response`` as Werkzeug's ``Response.__call__`` would."""
    headers = response.headers
    body = response.body
    if response.status == 304:
        headers = [
            item
            for item in headers
            if item[0].lower() not in _NOT_MODIFIED_DROPPED_HEADERS
        ]
        body = b""
    else:
        if response.get("Content-Length") is None:
            headers.append(("Content-Length", str(len(body))))
        if environ.get("REQUEST_METHOD") == "HEAD":
            body = b""
    start_response(STATUS_LINES[response.status], headers)
    return [body] if body else []
