"""Public PAC/WPAD listener (``proxy_public`` supervisor program).

Runs in its own small gunicorn process so client auto-configuration never
shares worker threads with management or control-plane database work. PAC,
WPAD and ``/health`` are served from the proxy's local materialized files and
import nothing database-backed; only the rare block-page policy request
submission touches MySQL, imported lazily on that request.

This is a plain WSGI callable rather than a Flask app: the listener has a
handful of fixed routes and Flask's import graph dominated the worker's
resident memory. Responses match the former Flask implementation (status
lines, header order, Werkzeug error pages, the shared gzip policy) except for
deliberate fixes: a single charset on policy pages, RFC 9110 If-Match /
If-None-Match evaluation, and policy bodies that are over the limit
(including unknown-length ones), truncated or of invalid length being rejected
instead of truncated or partially recorded.
``web/tests/golden/proxy_public_responses.json`` records that contract.
Werkzeug is imported only to parse policy-request form bodies.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import logging
import os
import re
from email.utils import formatdate
from typing import TYPE_CHECKING, Any

from services.errors import public_error_message
from services.http_optimizations import (
    TRANSFORMATION_INVALIDATED_HEADERS,
    client_accepts_gzip,
    compressible_mimetype,
    gzip_responses_enabled,
)
from services.logutil import (
    configure_process_logging,
    log_database_unavailable,
    log_exception_throttled,
)
from services.pac_http import (
    PAC_CONTENT_TYPE,
    client_ip_from_headers,
    forwarded_client_ip_from_headers,
    forwarded_headers_trusted,
    pac_content_disposition,
    public_pac_request_allowed,
    public_pac_request_path_safe,
    request_host_from_headers,
    resolve_pac,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

_LOGGER = logging.getLogger(__name__)
_PUBLIC_NON_PAC_PATHS = frozenset({"/", "/health", "/policy-request"})
_POLICY_REQUEST_DEFAULT_MAX_CONTENT_LENGTH = 16 * 1024
# Flask's MAX_FORM_MEMORY_SIZE / MAX_FORM_PARTS defaults, kept for multipart.
_POLICY_REQUEST_MAX_FORM_MEMORY_SIZE = 500_000
_POLICY_REQUEST_MAX_FORM_PARTS = 1000
_GZIP_MIN_SIZE = 1024
_GZIP_LEVEL = 5
_GZIP_ENABLED = gzip_responses_enabled()

_STATUS_LINES = {
    200: "200 OK",
    304: "304 NOT MODIFIED",
    400: "400 BAD REQUEST",
    404: "404 NOT FOUND",
    405: "405 METHOD NOT ALLOWED",
    412: "412 PRECONDITION FAILED",
    413: "413 REQUEST ENTITY TOO LARGE",
    429: "429 TOO MANY REQUESTS",
    500: "500 INTERNAL SERVER ERROR",
    503: "503 SERVICE UNAVAILABLE",
}
_HTML = "text/html; charset=utf-8"
_PAC_VARY = "Host, X-Forwarded-For, X-Forwarded-Host, X-Real-IP"
_GET_METHODS = ("GET", "HEAD", "OPTIONS")
_POLICY_METHODS = ("GET", "HEAD", "OPTIONS", "POST")
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


def _error_page(code: int, name: str, description: str) -> bytes:
    """Werkzeug's default ``HTTPException`` body."""
    return (
        "<!doctype html>\n<html lang=en>\n"
        f"<title>{code} {name}</title>\n<h1>{name}</h1>\n<p>{description}</p>\n"
    ).encode()


_NOT_FOUND_PAGE = _error_page(
    404,
    "Not Found",
    "The requested URL was not found on the server. If you entered the URL"
    " manually please check your spelling and try again.",
)
_METHOD_NOT_ALLOWED_PAGE = _error_page(
    405, "Method Not Allowed", "The method is not allowed for the requested URL."
)
_INTERNAL_ERROR_PAGE = _error_page(
    500,
    "Internal Server Error",
    "The server encountered an internal error and was unable to complete your"
    " request. Either the server is overloaded or there is an error in the"
    " application.",
)


def _json_body(payload: dict[str, Any]) -> bytes:
    """Flask ``jsonify`` bytes: sorted keys, compact, ASCII, trailing newline."""
    return (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()


_HEALTH_BODY = _json_body(
    {
        "ok": True,
        "service": "proxy",
        "status": "serving_public_pac",
        "health_scope": "public-listener",
        "forwarding_checked": False,
        "detail": "Public PAC/WPAD listener is serving. This lightweight endpoint does not assert Squid forwarding readiness; use authenticated /api/manage/health?full=1 for deep proxy health.",
        "components": {
            "proxy_api": "ok",
            "pac": "ok",
            "forwarding": "not_checked",
        },
    },
)
_MANAGEMENT_NOT_FOUND_BODY = _json_body(
    {
        "ok": False,
        "status": "not_found",
        "detail": "Proxy management endpoint was not found. Check that the registered management URL points to the proxy management listener, not the public PAC/proxy listener.",
    },
)

# Werkzeug's ``parse_etags`` grammar, including its lenient invalid forms.
_ETAG_PATTERN = re.compile(
    r"""
    [ \t]*  # ignore leading space
    ([Ww]/)?  # optional weak marker
    (?:
        "([^"]*)"  # quoted value
    |
        ([^" \t,]+)  # invalid unquoted value, exclude syntax characters
    )
    [ \t]*  # ignore trailing space
    (?:,|\Z)  # only if followed by comma or end
    """,
    flags=re.ASCII | re.VERBOSE,
)


class _Response:
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


class _RequestHeaders:
    """Header lookup over a WSGI environ, like Werkzeug ``EnvironHeaders.get``."""

    __slots__ = ("_environ",)

    def __init__(self, environ: dict[str, Any]) -> None:
        self._environ = environ

    def get(self, name: str, default: str | None = None) -> str | None:
        key = name.upper().replace("-", "_")
        if key not in {"CONTENT_TYPE", "CONTENT_LENGTH"}:
            key = f"HTTP_{key}"
        return self._environ.get(key, default)


def _policy_request_max_content_length() -> int:
    raw = (os.environ.get("POLICY_REQUEST_MAX_CONTENT_LENGTH") or "").strip()
    try:
        value = int(raw) if raw else _POLICY_REQUEST_DEFAULT_MAX_CONTENT_LENGTH
    except TypeError, ValueError:
        return _POLICY_REQUEST_DEFAULT_MAX_CONTENT_LENGTH
    return value if value >= 1 else _POLICY_REQUEST_DEFAULT_MAX_CONTENT_LENGTH


def _is_public_path(environ: dict[str, Any], path: str, query_string: bytes) -> bool:
    raw_target = environ.get("RAW_URI") or environ.get("REQUEST_URI") or path
    raw_path = str(raw_target).split("?", 1)[0]
    if not public_pac_request_path_safe(raw_path):
        return path in _PUBLIC_NON_PAC_PATHS
    if path in _PUBLIC_NON_PAC_PATHS:
        return True
    try:
        return public_pac_request_allowed(path, query_string)
    except Exception:
        return path in {"/proxy.pac", "/wpad.dat"}


def _not_found(path: str) -> _Response:
    if path.startswith("/api/manage/"):
        return _Response(404, "application/json", _MANAGEMENT_NOT_FOUND_BODY)
    return _Response(404, _HTML, _NOT_FOUND_PAGE)


def _method_not_allowed(allowed: tuple[str, ...] = ()) -> _Response:
    return _Response(405, _HTML, _METHOD_NOT_ALLOWED_PAGE, allow=allowed)


def _parse_etags(value: str | None) -> tuple[bool, frozenset, frozenset]:
    """Return ``(star, strong, weak)`` exactly as Werkzeug ``parse_etags`` does."""
    if not value:
        return False, frozenset(), frozenset()
    if value == "*":
        return True, frozenset(), frozenset()
    strong = []
    weak = []
    position = 0
    while True:
        match = _ETAG_PATTERN.match(value, position)
        if match is None:
            # Skip invalid characters until the next comma.
            position = value.find(",", position) + 1
            if position == 0:
                break
            continue
        is_weak, tag, invalid_unquoted = match.groups()
        position = match.end()
        (weak if is_weak else strong).append(tag or invalid_unquoted)
    return False, frozenset(strong), frozenset(weak)


def _conditional_status(environ: dict[str, Any], etag: str) -> int | None:
    """RFC 9110 section 13.2.2 preconditions for the PAC's strong ETag.

    The PAC always exists and only carries an ETag (no Last-Modified, no
    ranges), so If-Match is evaluated first (``*`` matches; otherwise strong
    comparison, so weak tags never match), then If-None-Match (``*`` matches;
    weak comparison).
    """
    match_star, match_strong, match_weak = _parse_etags(environ.get("HTTP_IF_MATCH"))
    if (match_star or match_strong or match_weak) and not (
        match_star or etag in match_strong
    ):
        return 412
    none_star, none_strong, none_weak = _parse_etags(environ.get("HTTP_IF_NONE_MATCH"))
    if none_star or etag in none_strong or etag in none_weak:
        return 304
    return None


def _public_pac(environ: dict[str, Any], path: str) -> _Response:
    headers = _RequestHeaders(environ)
    remote_addr = environ.get("REMOTE_ADDR")
    resolution = resolve_pac(
        client_ip=client_ip_from_headers(headers, remote_addr),
        request_host=request_host_from_headers(headers, remote_addr),
    )
    data = resolution.content
    etag_material = b"\0".join(
        (
            resolution.source.encode("utf-8", errors="replace"),
            resolution.state_sha256.encode("utf-8", errors="replace"),
            resolution.selected_file.encode("utf-8", errors="replace"),
            data,
        ),
    )
    etag = hashlib.sha256(etag_material).hexdigest()
    cache_control = (
        "private, max-age=30"
        if resolution.source == "materialized"
        else "no-store, private"
    )
    disposition = pac_content_disposition("/wpad.dat" if path == "/" else path)
    response = _Response(200, PAC_CONTENT_TYPE, data)
    response.headers += (
        ("Content-Disposition", disposition),
        ("Cache-Control", cache_control),
        ("Vary", _PAC_VARY),
        ("ETag", f'"{etag}"'),
    )
    if environ["REQUEST_METHOD"] in {"GET", "HEAD"}:
        response.headers.append(("Date", formatdate(usegmt=True)))
        status = _conditional_status(environ, etag)
        if status is not None:
            response.status = status
    return response


def _html_response(title: str, body: str, *, status: int = 200) -> _Response:
    return _Response(
        status,
        _HTML,
        f"<!doctype html><title>{title}</title><h1>{title}</h1><p>{body}</p>".encode(),
    )


def _too_large(max_content_length: int) -> _Response:
    return _html_response(
        "Request too large",
        f"Policy request submissions are limited to {max_content_length} bytes.",
        status=413,
    )


def _read_policy_body(
    environ: dict[str, Any], max_content_length: int
) -> bytes | _Response:
    """Read the whole bounded body, or the response that rejects it.

    A declared Content-Length must be a valid decimal within the limit and be
    delivered in full: a truncated submission is never recorded. Without one,
    a terminated input stream (gunicorn chunked bodies) is read to at most the
    limit; anything beyond it is rejected rather than truncated. Without either,
    WSGI allows no body to be read.
    """
    stream = environ["wsgi.input"]
    raw_length = environ.get("CONTENT_LENGTH") or ""
    if raw_length:
        if not (raw_length.isascii() and raw_length.isdigit()):
            return _unparsable()
        length = int(raw_length)
        if length > max_content_length:
            return _too_large(max_content_length)
        limit = length
    elif environ.get("wsgi.input_terminated"):
        length = None
        limit = max_content_length + 1
    else:
        return b""
    chunks: list[bytes] = []
    received = 0
    while received < limit:
        chunk = stream.read(limit - received)
        if not chunk:
            break
        chunks.append(chunk)
        received += len(chunk)
    body = b"".join(chunks)
    if length is not None and received < length:
        return _unparsable()
    if received > max_content_length:
        return _too_large(max_content_length)
    return body


def _unparsable() -> _Response:
    return _html_response(
        "Request failed",
        "The policy request form could not be parsed.",
        status=400,
    )


def _policy_request_client_ip(request: Any, form: Any, normalize_client_ip) -> str:
    forwarded_ip = forwarded_client_ip_from_headers(
        request.headers, request.remote_addr
    )
    if forwarded_ip:
        return forwarded_ip
    remote_ip = request.remote_addr or ""
    form_ip = form.get("client_ip") or ""
    if forwarded_headers_trusted(remote_ip) and normalize_client_ip(form_ip):
        return form_ip
    return remote_ip


def _policy_request_store_unavailable(exc: BaseException) -> bool:
    """Classify retryable persistence/control-plane availability failures."""
    from services.db import transient_mysql_cause

    return transient_mysql_cause(exc) is not None


def _public_policy_request(environ: dict[str, Any]) -> _Response:
    max_content_length = _policy_request_max_content_length()
    body = _read_policy_body(environ, max_content_length)
    if isinstance(body, _Response):
        return body
    # Block-page submissions are rare; keep form parsing and the
    # database-backed store out of the PAC listener until one arrives.
    from werkzeug.wrappers import Request

    request = Request(
        {
            **environ,
            "wsgi.input": io.BytesIO(body),
            "CONTENT_LENGTH": str(len(body)),
            "wsgi.input_terminated": False,
        },
    )
    request.max_content_length = max_content_length
    request.max_form_memory_size = _POLICY_REQUEST_MAX_FORM_MEMORY_SIZE
    request.max_form_parts = _POLICY_REQUEST_MAX_FORM_PARTS
    try:
        return _record_policy_request(request)
    finally:
        # Releases spooled multipart file parts.
        request.close()


def _record_policy_request(request: Any) -> _Response:
    from werkzeug.exceptions import RequestEntityTooLarge

    try:
        form = request.form
    except RequestEntityTooLarge:
        # Multipart part-count or in-memory field limits.
        return _too_large(request.max_content_length)
    from markupsafe import escape
    from services.policy_requests import (
        PolicyRequestAdmissionError,
        get_policy_request_store,
        normalize_client_ip,
    )
    from services.proxy_context import get_proxy_id

    client_ip = _policy_request_client_ip(request, form, normalize_client_ip)
    try:
        req = get_policy_request_store().create_request(
            proxy_id=get_proxy_id(),
            block_type=form.get("block_type") or "webfilter",
            client_ip=client_ip,
            request_url=form.get("request_url") or "",
            domain=form.get("domain") or form.get("destination") or "",
            category=form.get("category") or "",
            method=form.get("method") or "",
            squid_error=form.get("squid_error") or form.get("error") or "",
            user_note=form.get("user_note") or "",
        )
        body = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Request submitted</title><style>body{{font-family:system-ui;margin:0;background:#0b1220;color:#eef4ff}}main{{max-width:760px;margin:48px auto;padding:24px}}.card{{border:1px solid rgba(255,255,255,.16);border-radius:18px;padding:28px;background:rgba(255,255,255,.08)}}code{{overflow-wrap:anywhere}}</style></head><body><main><section class="card"><p>Docker Proxy · Policy request</p><h1>Request submitted</h1><p>Your administrator can now review this blocked destination.</p><p>Request #{req.id}: <code>{escape(req.domain)}</code></p></section></main></body></html>"""
        return _Response(200, _HTML, body.encode())
    except PolicyRequestAdmissionError as exc:
        return _html_response(
            "Request not accepted",
            str(escape(public_error_message(exc))),
            status=429,
        )
    except Exception as exc:
        unavailable = _policy_request_store_unavailable(exc)
        if unavailable:
            log_database_unavailable(
                _LOGGER,
                "proxy_public.policy_request.store_unavailable",
                "Policy request not recorded while MySQL is unavailable",
                exc,
                interval_seconds=60.0,
            )
        else:
            log_exception_throttled(
                _LOGGER,
                "proxy_public.policy_request.record",
                interval_seconds=60.0,
                message="Policy request could not be recorded",
            )
        detail = (
            "The request service is temporarily unavailable. Please try again later."
            if unavailable
            else "The request could not be recorded due to an internal error."
        )
        return _html_response(
            "Request failed", detail, status=503 if unavailable else 500
        )


def _dispatch(
    environ: dict[str, Any], method: str, path: str, query_string: bytes
) -> _Response:
    if not _is_public_path(environ, path, query_string):
        return _not_found(path)
    allowed = _POLICY_METHODS if path == "/policy-request" else _GET_METHODS
    if method == "OPTIONS":
        return _Response(200, _HTML, b"", allow=allowed)
    if method not in allowed:
        return _method_not_allowed(allowed)
    if path == "/policy-request":
        if method == "POST":
            return _public_policy_request(environ)
        # GET/HEAD must never fall through to the PAC route.
        return _method_not_allowed()
    if path == "/health":
        return _Response(200, "application/json", _HEALTH_BODY)
    return _public_pac(environ, path)


def _apply_http_optimizations(
    response: _Response, environ: dict[str, Any], method: str
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
        not _GZIP_ENABLED
        or (status != 304 and not 200 <= status < 300)
        or not compressible_mimetype(response.get("Content-Type"))
        or len(response.body) < _GZIP_MIN_SIZE
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
    compressed = gzip.compress(response.body, compresslevel=_GZIP_LEVEL)
    if len(compressed) >= len(response.body):
        return
    response.body = compressed
    response.set("Content-Length", str(len(compressed)))
    response.headers.append(("Content-Encoding", "gzip"))
    # Validators and integrity values for the identity bytes no longer apply.
    for header in TRANSFORMATION_INVALIDATED_HEADERS:
        response.remove(header)


def app(environ: dict[str, Any], start_response: Callable[..., Any]) -> Iterable[bytes]:
    raw_method = environ.get("REQUEST_METHOD", "GET")
    method = raw_method.upper()
    raw_path = environ.get("PATH_INFO") or ""
    path = "/" + raw_path.encode("latin-1").decode(errors="replace").lstrip("/")
    query_string = environ.get("QUERY_STRING", "").encode("latin-1")
    try:
        response = _dispatch(environ, method, path, query_string)
    except Exception:
        _LOGGER.exception("Exception on %s [%s]", path, method)
        response = _Response(500, _HTML, _INTERNAL_ERROR_PAGE)
    _apply_http_optimizations(response, environ, method)
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
        if raw_method == "HEAD":
            body = b""
    start_response(_STATUS_LINES[response.status], headers)
    return [body] if body else []


configure_process_logging()
application = app
