"""Proxy management API listener (``proxy_api`` supervisor program).

A plain WSGI callable rather than a Flask app: the listener has a fixed set
of routes, and Flask/Werkzeug/Jinja were the largest import cost of the
container's biggest Python worker. Responses match the former Flask
implementation (routing, automatic HEAD/OPTIONS, 405 ``Allow``, Werkzeug's
merge-slashes 308 redirects and error pages, the JSON 403/404 handlers,
``request.args`` decoding, ``request.get_json`` admission and the shared
cache/gzip policy) except for deliberate fixes: a non-ASCII management token
is rejected with 403 instead of failing with 500, a JSON body of unknown
length over the limit is rejected with 413 instead of being truncated at the
limit, a Content-Length that is not a decimal byte count is rejected with
400 instead of being read as an empty body, invalid chunked framing is a
400 instead of a logged 500, and ``/static/...`` is an unknown path (404)
instead of Flask's default static route for a folder the proxy never had.
``web/tests/golden/proxy_management_responses.json`` records that contract.
"""

from __future__ import annotations

import codecs
import hashlib
import hmac
import json
import logging
import os
import re
import time
from typing import TYPE_CHECKING, Any, NoReturn
from urllib.parse import parse_qsl, quote, urlsplit, urlunsplit

from services.errors import public_error_message
from services.http_optimizations import gzip_responses_enabled
from services.logutil import configure_process_logging
from services.proxy_logs import (
    parse_proxy_log_max_bytes,
    proxy_log_status_code,
    read_proxy_log,
)
from services.version_status import current_component_metadata

from proxy.agent import start_agent
from proxy.control_plane_state import control_plane_ready
from proxy.runtime import get_runtime
from proxy.wsgi_http import (
    BAD_REQUEST_PAGE,
    HTML,
    INTERNAL_ERROR_PAGE,
    MANAGEMENT_NOT_FOUND_BODY,
    METHOD_NOT_ALLOWED_PAGE,
    NOT_FOUND_PAGE,
    BodyReadError,
    RequestHeaders,
    Response,
    apply_http_optimizations,
    declared_content_length,
    json_response,
    read_body,
    request_path,
    send,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

_LOGGER = logging.getLogger(__name__)
runtime: Any | None = None
_GZIP_ENABLED = gzip_responses_enabled()
_MANAGEMENT_JSON_DEFAULT_MAX_CONTENT_LENGTH = 1024 * 1024
_GET = ("GET", "HEAD", "OPTIONS")
_POST = ("OPTIONS", "POST")
_FORBIDDEN_BODY = {
    "ok": False,
    "status": "forbidden",
    "detail": "Proxy management authentication failed. Check that PROXY_MANAGEMENT_TOKEN matches between the Admin UI and this proxy runtime.",
}
_CONTROL_PLANE_STARTING_BODY = {
    "ok": False,
    "status": "control_plane_starting",
    "retryable": True,
    "detail": "Proxy control-plane startup (recovery adoption, schema, registration) has not completed yet; retry shortly.",
}
_LISTENER_HEALTH_BODY = {
    "ok": True,
    "service": "proxy-management",
    "status": "serving_management_api",
    "health_scope": "management-listener",
    "forwarding_checked": False,
}
# Werkzeug rule converters: the default ``[^/]+`` segment and ``path``.
_SUPERVISOR_RULE = re.compile(r"/api/manage/test/supervisor/([^/]+)/([^/]+)")
_MERGED_SLASHES = re.compile(r"/{2,}")
# Werkzeug ``sansio.utils._host_re``: a Host with other characters is treated
# as empty when building redirect URLs.
_HOST_PATTERN = re.compile(
    r"([a-z0-9.-]+|\[[a-f0-9]*:[a-f0-9.:]+])(?::([1-9][0-9]{,4}))?",
    flags=re.ASCII | re.IGNORECASE,
)
_HTML_ESCAPES = str.maketrans(
    {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&#34;", "'": "&#39;"}
)
_QUERY_ERRORS = "proxy.management.url_quote"


def _requote_invalid_bytes(error: UnicodeError) -> tuple[str, int]:
    """Werkzeug's ``werkzeug.url_quote`` codec error handler for query args."""
    invalid = error.object[error.start : error.end]  # type: ignore[attr-defined]
    return quote(invalid, safe=""), error.end  # type: ignore[attr-defined]


codecs.register_error(_QUERY_ERRORS, _requote_invalid_bytes)


class _HTTPError(Exception):
    """Ends request handling with ``response`` (Flask ``abort``)."""

    def __init__(self, response: Response) -> None:
        super().__init__(response.status)
        self.response = response


class _Request:
    """The parts of a Werkzeug request the management routes read."""

    __slots__ = ("_args", "_data", "environ", "headers", "method", "path")

    def __init__(self, environ: dict[str, Any], method: str, path: str) -> None:
        self.environ = environ
        self.method = method
        self.path = path
        self.headers = RequestHeaders(environ)
        self._args: dict[str, str] | None = None
        self._data: bytes | None = None

    def arg(self, name: str) -> str | None:
        """First value of a query argument, like ``request.args.get``."""
        if self._args is None:
            query = self.environ.get("QUERY_STRING", "").encode("latin-1").decode()
            args: dict[str, str] = {}
            for key, value in parse_qsl(
                query, keep_blank_values=True, errors=_QUERY_ERRORS
            ):
                args.setdefault(key, value)
            self._args = args
        return self._args.get(name)

    @property
    def content_length(self) -> int | None:
        """The declared body length; None when chunked or not declared."""
        try:
            return declared_content_length(self.environ)
        except ValueError:
            _abort_management_json_payload(
                "Management request Content-Length must be a decimal byte count."
            )

    @property
    def is_json(self) -> bool:
        content_type = self.environ.get("CONTENT_TYPE") or ""
        mimetype = content_type.split(";", 1)[0].strip().lower()
        return mimetype == "application/json" or (
            mimetype.startswith("application/") and mimetype.endswith("+json")
        )

    def data(self, max_content_length: int) -> bytes:
        """The request body, read once and bounded like Werkzeug's input stream.

        A server that terminates the input stream (gunicorn) is read up to the
        limit, plus one byte that proves an unknown-length body is over it.
        Without termination only a declared Content-Length may be read, and
        must arrive in full. Read failures (disconnects, invalid chunked
        framing) are a bad request, as Werkzeug's ``ClientDisconnected``.
        """
        if self._data is None:
            terminated = "wsgi.input_terminated" in self.environ
            limit = max_content_length + 1 if terminated else self.content_length or 0
            try:
                data = read_body(self.environ["wsgi.input"], limit)
            except BodyReadError as exc:
                raise _HTTPError(Response(400, HTML, BAD_REQUEST_PAGE)) from exc
            if not terminated and len(data) < limit:
                raise _HTTPError(Response(400, HTML, BAD_REQUEST_PAGE))
            if len(data) > max_content_length:
                _abort_management_json_payload(
                    _management_payload_too_large_detail(max_content_length),
                    status_code=413,
                )
            self._data = data
        return self._data


def _bounded_env_int(
    name: str,
    *,
    default: int,
    minimum: int = 1,
    maximum: int | None = None,
) -> int:
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except TypeError, ValueError:
        return default
    if value < minimum:
        return default
    if maximum is not None:
        return min(value, maximum)
    return value


def _management_json_max_content_length() -> int:
    return _bounded_env_int(
        "PROXY_MANAGEMENT_JSON_MAX_CONTENT_LENGTH",
        default=_MANAGEMENT_JSON_DEFAULT_MAX_CONTENT_LENGTH,
        maximum=16 * 1024 * 1024,
    )


def _runtime() -> Any:
    global runtime
    if runtime is None:
        runtime = get_runtime()
    return runtime


def _expected_token() -> str:
    return (os.environ.get("PROXY_MANAGEMENT_TOKEN") or "").strip()


def _provided_token(request: _Request) -> str:
    auth = (request.headers.get("Authorization") or "").strip()
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return (request.headers.get("X-Proxy-Token") or "").strip()


def _authorized(request: _Request) -> bool:
    expected = _expected_token()
    if not expected:
        return False
    provided = _provided_token(request)
    # Bytes: compare_digest raises TypeError for non-ASCII str operands.
    return bool(provided) and hmac.compare_digest(
        provided.encode("utf-8", errors="surrogatepass"),
        expected.encode("utf-8", errors="surrogatepass"),
    )


def _control_plane_starting() -> Response:
    """Refuse control-plane mutations until the agent finished startup.

    Recovery adoption and the startup schema must precede any normal
    control-plane write (docs/proxy-recovery.md); the agent signals completion
    for its current process lifetime through proxy.control_plane_state.
    """
    response = json_response(_CONTROL_PLANE_STARTING_BODY, 503)
    response.headers.append(("Retry-After", "5"))
    return response


def _test_mode_enabled() -> bool:
    return (os.environ.get("ENABLE_TEST_MODE") or "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _abort_management_json_payload(detail: str, *, status_code: int = 400) -> NoReturn:
    raise _HTTPError(json_response({"ok": False, "detail": detail}, status_code))


def _management_payload_too_large_detail(max_content_length: int) -> str:
    return f"Management JSON payload is limited to {max_content_length} bytes."


def _management_request_has_body(request: _Request, max_content_length: int) -> bool:
    content_length = request.content_length
    if content_length is not None:
        if content_length > max_content_length:
            _abort_management_json_payload(
                _management_payload_too_large_detail(max_content_length),
                status_code=413,
            )
        return content_length > 0
    return bool(request.data(max_content_length))


def _management_json_payload(request: _Request) -> dict[str, Any]:
    max_content_length = _management_json_max_content_length()
    if not _management_request_has_body(request, max_content_length):
        return {}
    if not request.is_json:
        _abort_management_json_payload(
            "Management JSON payload must use Content-Type application/json.",
        )
    try:
        payload = json.loads(request.data(max_content_length))
    except _HTTPError as exc:
        if exc.response.status == 413:
            raise
        _abort_management_json_payload("Management JSON payload is malformed.")
    except ValueError:
        _abort_management_json_payload("Management JSON payload is malformed.")
    if payload is None:
        return {}
    if not isinstance(payload, dict):
        _abort_management_json_payload("Management JSON payload must be an object.")
    return payload


def _parse_management_force(payload: dict[str, Any]) -> tuple[bool, str | None]:
    if "force" not in payload:
        return False, None
    value = payload.get("force")
    if isinstance(value, bool):
        return value, None
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True, None
        if normalized in {"0", "false", "no", "off"}:
            return False, None
    return False, "force must be a boolean."


def _management_config_text_or_abort(payload: dict[str, Any]) -> str:
    if "config_text" not in payload:
        return ""
    config_text = payload.get("config_text")
    if not isinstance(config_text, str):
        _abort_management_json_payload("config_text must be a string.")
    return config_text


def _not_found(request: _Request) -> Response:
    if request.path.startswith("/api/manage/"):
        return Response(404, "application/json", MANAGEMENT_NOT_FOUND_BODY)
    return Response(404, HTML, NOT_FOUND_PAGE)


def health(_request: _Request) -> Response:
    # The public PAC/WPAD listener runs as its own program (proxy.public_app);
    # this process serves only the management listener.
    return json_response(_LISTENER_HEALTH_BODY)


def manage_health(request: _Request) -> Response:
    try:
        current_runtime = _runtime()
        full = str(request.arg("full") or "").strip().lower() in {
            "1",
            "true",
            "yes",
            "full",
        }
        force = str(request.arg("force") or "").strip().lower() in {
            "1",
            "true",
            "yes",
        }
        if full:
            return json_response(current_runtime.collect_health(force=force))
        return json_response(current_runtime.collect_navigation_health(force=force))
    except Exception as exc:
        detail = public_error_message(exc, default="Proxy health collection failed.")
        return json_response(
            {
                "ok": False,
                "status": "degraded",
                "proxy_id": getattr(runtime, "proxy_id", ""),
                "proxy_status": detail,
                "stats": {},
                "services": {},
                "version": current_component_metadata("proxy"),
                "state_errors": [detail],
                "timestamp": int(time.time()),
            },
        )


def manage_clamav_health(request: _Request) -> Response:
    try:
        current_runtime = _runtime()
        force = str(request.arg("force") or "").strip().lower() in {
            "1",
            "true",
            "yes",
        }
        return json_response(current_runtime.collect_clamav_health(force=force))
    except Exception as exc:
        detail = public_error_message(
            exc,
            default="Proxy ClamAV health collection failed.",
        )
        return json_response(
            {
                "ok": False,
                "status": "degraded",
                "proxy_id": getattr(runtime, "proxy_id", ""),
                "proxy_status": detail,
                "services": {},
                "state_errors": [detail],
                "timestamp": int(time.time()),
            },
        )


def manage_logs(request: _Request) -> Response:
    max_bytes = parse_proxy_log_max_bytes(request.arg("max_bytes"))
    if max_bytes is None:
        result = read_proxy_log(request.arg("log"))
    else:
        result = read_proxy_log(request.arg("log"), max_bytes=max_bytes)
    return json_response(result, proxy_log_status_code(result))


def manage_sync(request: _Request) -> Response:
    payload = _management_json_payload(request)
    operation_id = payload.get("operation_id")
    if operation_id is not None:
        if type(operation_id) is not int:
            return json_response(
                {"ok": False, "detail": "operation_id must be an integer."}, 400
            )
        if operation_id <= 0:
            return json_response(
                {"ok": False, "detail": "operation_id must be a positive integer."},
                400,
            )
    force, force_error = _parse_management_force(payload)
    if force_error is not None:
        return json_response({"ok": False, "detail": force_error}, 400)

    try:
        result = _runtime().sync_from_db(
            force=force,
            operation_id=operation_id,
        )
    except Exception as exc:
        detail = public_error_message(exc, default="Proxy reconciliation failed.")
        return json_response({"ok": False, "detail": detail}, 500)
    return json_response(result, 200 if result.get("ok") else 409)


def manage_config_current(_request: _Request) -> Response:
    current_runtime = _runtime()
    config_text = str(current_runtime.get_current_config_text() or "")
    config_sha256 = ""
    if config_text:
        config_sha256 = hashlib.sha256(
            config_text.encode("utf-8", errors="replace"),
        ).hexdigest()
    return json_response(
        {
            "ok": bool(config_text.strip()),
            "proxy_id": current_runtime.proxy_id,
            "config_text": config_text,
            "config_sha256": config_sha256,
            "detail": "Running Squid config returned."
            if config_text.strip()
            else "Running Squid config is empty or unavailable.",
        },
    )


def manage_config_validate(request: _Request) -> Response:
    payload = _management_json_payload(request)
    config_text = _management_config_text_or_abort(payload)
    return json_response(_runtime().validate_config_text(config_text))


def manage_config_rollback(request: _Request) -> Response:
    payload = _management_json_payload(request)
    result = _runtime().rollback_last_known_good_config(
        reason=str(payload.get("reason") or "Rollback requested by management API."),
    )
    return json_response(result, 200 if result.get("ok") else 409)


def manage_cache_clear(request: _Request) -> Response:
    _management_json_payload(request)
    result = _runtime().clear_cache()
    return json_response(result, 200 if result.get("ok") else 500)


def manage_clamav_test_eicar(request: _Request) -> Response:
    _management_json_payload(request)
    result = _runtime().test_clamav_eicar()
    return json_response(result, 200 if result.get("ok") else 503)


def manage_clamav_test_icap(request: _Request) -> Response:
    _management_json_payload(request)
    result = _runtime().test_clamav_icap()
    return json_response(result, 200 if result.get("ok") else 503)


def manage_test_supervisor(
    request: _Request, program_name: str, action: str
) -> Response:
    if not _test_mode_enabled():
        return _not_found(request)
    _management_json_payload(request)
    result = _runtime().test_control_supervisor_program(program_name, action=action)
    return json_response(result, 200 if result.get("ok") else 409)


type _View = Callable[..., Response]
# path -> (methods, view, requires the management token, mutates the control plane)
_ROUTES: dict[str, tuple[tuple[str, ...], _View, bool, bool]] = {
    "/health": (_GET, health, False, False),
    "/api/manage/health": (_GET, manage_health, True, False),
    "/api/manage/health/clamav": (_GET, manage_clamav_health, True, False),
    "/api/manage/logs": (_GET, manage_logs, True, False),
    "/api/manage/sync": (_POST, manage_sync, True, True),
    "/api/manage/config/current": (_GET, manage_config_current, True, False),
    "/api/manage/config/validate": (_POST, manage_config_validate, True, False),
    "/api/manage/config/rollback": (_POST, manage_config_rollback, True, True),
    "/api/manage/cache/clear": (_POST, manage_cache_clear, True, True),
    "/api/manage/clamav/test-eicar": (_POST, manage_clamav_test_eicar, True, False),
    "/api/manage/clamav/test-icap": (_POST, manage_clamav_test_icap, True, False),
}


def _rule(
    path: str,
) -> tuple[tuple[str, ...], _View, bool, bool, tuple[str, ...]] | None:
    route = _ROUTES.get(path)
    if route is not None:
        return (*route, ())
    match = _SUPERVISOR_RULE.fullmatch(path)
    if match is not None:
        return _POST, manage_test_supervisor, True, False, match.groups()
    return None


def _server_name(environ: dict[str, Any]) -> str:
    """The host Werkzeug's router binds to, as used in its redirect URLs.

    Werkzeug ``get_host`` without trusted hosts, lower-cased, with the name
    IDNA-encoded; a name IDNA rejects (empty or over-long labels) is a bad
    request (Werkzeug ``BadHost``).
    """
    scheme = environ.get("wsgi.url_scheme")
    host = environ.get("HTTP_HOST")
    if host is None:
        name = environ.get("SERVER_NAME")
        try:
            port = int(environ.get("SERVER_PORT"))  # type: ignore[arg-type]
        except TypeError, ValueError:
            return ""
        if name is None:
            return ""
        if ":" in name and name[0] != "[":
            name = f"[{name}]"
        host = f"{name}:{port}"
    if scheme in {"http", "ws"}:
        host = host.removesuffix(":80")
    elif scheme in {"https", "wss"}:
        host = host.removesuffix(":443")
    match = _HOST_PATTERN.fullmatch(host)
    if match is None or (match.group(2) and not 1 <= int(match.group(2)) <= 65535):
        return ""
    name, separator, port = host.lower().partition(":")
    try:
        name = name.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise _HTTPError(Response(400, HTML, BAD_REQUEST_PAGE)) from exc
    return f"{name}{separator}{port}"


def _iri_to_uri(iri: str) -> str:
    """Werkzeug ``iri_to_uri`` for the redirect URLs built here (no userinfo)."""
    parts = urlsplit(iri)
    path = quote(parts.path, safe="%!$&'()*+,/:;=@")
    query = quote(parts.query, safe="%!$&'()*+,/:;=?@")
    fragment = quote(parts.fragment, safe="%!#$&'()*+,/:;=?@")
    netloc = parts.hostname.encode("idna").decode("ascii") if parts.hostname else ""
    if ":" in netloc:
        netloc = f"[{netloc}]"
    if parts.port is not None:
        netloc = f"{netloc}:{parts.port}"
    return urlunsplit((parts.scheme, netloc, path, query, fragment))


def _merge_slashes_redirect(
    environ: dict[str, Any], server_name: str, merged_path: str
) -> Response:
    """Werkzeug's 308 to the merged-slashes path, with its HTML body."""
    script_name = (
        environ.get("SCRIPT_NAME", "").encode("latin-1").decode(errors="replace")
    )
    query = environ.get("QUERY_STRING", "").encode("latin-1").decode(errors="replace")
    path = quote(merged_path, safe="!$&'()*+,/:;=@")
    location = urlunsplit(
        (
            environ.get("wsgi.url_scheme") or "http",
            server_name,
            "/".join((script_name.strip("/"), path.lstrip("/"))),
            query or None,
            None,
        ),
    )
    html_location = location.translate(_HTML_ESCAPES)
    response = Response(
        308,
        HTML,
        (
            "<!doctype html>\n<html lang=en>\n<title>Redirecting...</title>\n"
            "<h1>Redirecting...</h1>\n"
            "<p>You should be redirected automatically to the target URL: "
            f'<a href="{html_location}">{html_location}</a>. If not, click the link.\n'
        ).encode(),
    )
    response.headers.append(("Location", _iri_to_uri(location)))
    return response


def _route(environ: dict[str, Any], request: _Request) -> Response:
    """Werkzeug routing plus Flask's automatic OPTIONS, guards and handlers."""
    method = request.method
    server_name = _server_name(environ)
    websocket = (
        any(
            token.strip(" \t") == "upgrade"
            for token in environ.get("HTTP_CONNECTION", "").lower().split(",")
        )
        and environ.get("HTTP_UPGRADE", "").lower() == "websocket"
    )
    allowed: set[str] = set()
    websocket_mismatch = False
    # Werkzeug retries an unmatched path with its slashes merged and
    # redirects to the merged path when that matches.
    merged_path = _MERGED_SLASHES.sub("/", request.path)
    for candidate in dict.fromkeys((request.path, merged_path)):
        rule = _rule(candidate)
        if rule is None:
            continue
        methods, view, needs_token, mutates, args = rule
        if method not in methods:
            allowed.update(methods)
            continue
        if websocket:
            websocket_mismatch = True
            continue
        if candidate != request.path:
            return _merge_slashes_redirect(environ, server_name, candidate)
        if method == "OPTIONS":
            return Response(200, HTML, b"", allow=methods)
        if needs_token and not _authorized(request):
            return json_response(_FORBIDDEN_BODY, 403)
        if mutates and not control_plane_ready():
            return _control_plane_starting()
        return view(request, *args)
    if allowed:
        return Response(
            405, HTML, METHOD_NOT_ALLOWED_PAGE, allow=tuple(sorted(allowed))
        )
    if websocket_mismatch:
        return Response(400, HTML, BAD_REQUEST_PAGE)
    return _not_found(request)


def app(environ: dict[str, Any], start_response: Callable[..., Any]) -> Iterable[bytes]:
    method = environ.get("REQUEST_METHOD", "GET").upper()
    request = _Request(environ, method, request_path(environ))
    try:
        response = _route(environ, request)
    except _HTTPError as exc:
        response = exc.response
    except Exception:
        _LOGGER.exception("Exception on %s [%s]", request.path, method)
        response = Response(500, HTML, INTERNAL_ERROR_PAGE)
    apply_http_optimizations(response, environ, method, gzip_enabled=_GZIP_ENABLED)
    return send(response, environ, start_response)


# proxy_api runs under gunicorn, which only configures its own gunicorn.* loggers.
configure_process_logging()

if (os.environ.get("DISABLE_PROXY_AGENT") or "").strip() != "1":
    start_agent()
