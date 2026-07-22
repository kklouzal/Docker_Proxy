from __future__ import annotations

import hashlib
import os
import time
from collections.abc import Callable
from functools import wraps
from typing import TYPE_CHECKING, Any, TypeVar

from flask import Flask, Response, abort, jsonify, request
from markupsafe import escape
from services.errors import public_error_message
from services.http_optimizations import install_http_optimizations
from services.pac_http import (
    PAC_CONTENT_TYPE,
    client_ip_from_headers,
    pac_content_disposition,
    public_pac_request_allowed,
    request_host_from_headers,
    resolve_pac_bytes,
)
from services.policy_requests import get_policy_request_store
from services.proxy_context import get_proxy_id
from services.proxy_logs import proxy_log_status_code, read_proxy_log
from services.version_status import current_component_metadata

from proxy.agent import start_agent
from proxy.runtime import get_runtime

if TYPE_CHECKING:
    from werkzeug.exceptions import HTTPException

F = TypeVar("F", bound=Callable[..., Any])
app = Flask(__name__)
install_http_optimizations(app, default_dynamic_max_age_seconds=0)
runtime: Any | None = None
_PUBLIC_LISTENER_NON_PAC_PATHS = frozenset({"/", "/health", "/policy-request"})


def _runtime() -> Any:
    global runtime
    if runtime is None:
        runtime = get_runtime()
    return runtime


def _expected_token() -> str:
    return (os.environ.get("PROXY_MANAGEMENT_TOKEN") or "").strip()


def _provided_token() -> str:
    auth = (request.headers.get("Authorization") or "").strip()
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return (request.headers.get("X-Proxy-Token") or "").strip()


def _require_management_auth[F: Callable[..., Any]](func: F) -> F:
    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any):
        expected = _expected_token()
        if expected:
            provided = _provided_token()
            if not provided or provided != expected:
                abort(403)
        return func(*args, **kwargs)

    return wrapper  # type: ignore[return-value]


def _test_mode_enabled() -> bool:
    return (os.environ.get("ENABLE_TEST_MODE") or "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


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


def _public_pac_port() -> str:
    raw = (os.environ.get("PAC_HTTP_PORT") or "80").strip() or "80"
    try:
        port = int(raw)
    except Exception:
        port = 80
    if port < 1 or port > 65535:
        port = 80
    return str(port)


def _request_server_port() -> str:
    return str(request.environ.get("SERVER_PORT") or "").strip()


def _is_public_listener_request() -> bool:
    return _request_server_port() == _public_pac_port()


def _is_public_listener_path(
    path: str,
    query_string: object | None = None,
) -> bool:
    normalized_path = str(path or "/")
    if normalized_path in _PUBLIC_LISTENER_NON_PAC_PATHS:
        return True
    try:
        return public_pac_request_allowed(normalized_path, query_string)
    except Exception:
        return normalized_path in {"/proxy.pac", "/wpad.dat"}


@app.before_request
def _restrict_public_listener() -> None:
    if _is_public_listener_request() and not _is_public_listener_path(
        request.path,
        request.query_string,
    ):
        abort(404)


@app.errorhandler(403)
def _management_forbidden(exc: HTTPException):
    if request.path.startswith("/api/manage/"):
        return jsonify(
            {
                "ok": False,
                "status": "forbidden",
                "detail": "Proxy management authentication failed. Check that PROXY_MANAGEMENT_TOKEN matches between the Admin UI and this proxy runtime.",
            },
        ), 403
    return exc


@app.errorhandler(404)
def _management_not_found(exc: HTTPException):
    if request.path.startswith("/api/manage/"):
        return jsonify(
            {
                "ok": False,
                "status": "not_found",
                "detail": "Proxy management endpoint was not found. Check that the registered management URL points to the proxy management listener, not the public PAC/proxy listener.",
            },
        ), 404
    return exc


@app.route("/health", methods=["GET"])
def health() -> Any:
    if _is_public_listener_request():
        return jsonify(
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
        ), 200
    return jsonify(
        {
            "ok": True,
            "service": "proxy-management",
            "status": "serving_management_api",
            "health_scope": "management-listener",
            "forwarding_checked": False,
        },
    ), 200


@app.route("/", methods=["GET"])
@app.route("/proxy.pac", methods=["GET"])
@app.route("/wpad.dat", methods=["GET"])
@app.route("/<path:_pac_path>", methods=["GET"])
def public_pac(_pac_path: str = "") -> Any:
    if not _is_public_listener_request():
        abort(404)
    path = "/wpad.dat" if request.path == "/" else request.path
    data = resolve_pac_bytes(
        client_ip=client_ip_from_headers(request.headers, request.remote_addr),
        request_host=request_host_from_headers(request.headers, request.remote_addr),
    )
    response = Response(data, content_type=PAC_CONTENT_TYPE)
    response.headers["Content-Disposition"] = pac_content_disposition(path)
    response.headers["Cache-Control"] = "private, max-age=30"
    response.headers["Vary"] = "Host, X-Forwarded-For, X-Forwarded-Host, X-Real-IP"
    response.set_etag(hashlib.sha256(data).hexdigest())
    return response.make_conditional(request)


@app.route("/policy-request", methods=["GET"])
def public_policy_request_get() -> Any:
    if not _is_public_listener_request():
        abort(404)
    abort(405)


@app.route("/policy-request", methods=["POST"])
def public_policy_request() -> Any:
    if not _is_public_listener_request():
        abort(404)
    form = request.form
    client_ip = client_ip_from_headers(request.headers, request.remote_addr) or (
        form.get("client_ip") or ""
    )
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
        return Response(body, mimetype="text/html; charset=utf-8")
    except Exception as exc:
        detail = escape(
            public_error_message(exc, default="The request could not be recorded."),
        )
        return Response(
            f"<!doctype html><title>Request failed</title><h1>Request failed</h1><p>{detail}</p>",
            status=400,
            mimetype="text/html; charset=utf-8",
        )


@app.route("/api/manage/health", methods=["GET"])
@_require_management_auth
def manage_health() -> Any:
    try:
        current_runtime = _runtime()
        full = str(request.args.get("full") or "").strip().lower() in {
            "1",
            "true",
            "yes",
            "full",
        }
        force = str(request.args.get("force") or "").strip().lower() in {
            "1",
            "true",
            "yes",
        }
        if full:
            return jsonify(current_runtime.collect_health(force=force)), 200
        collector = getattr(current_runtime, "collect_navigation_health", None)
        if collector is not None:
            return jsonify(collector(force=force)), 200
        return jsonify(current_runtime.collect_health(force=force)), 200
    except Exception as exc:
        detail = public_error_message(exc, default="Proxy health collection failed.")
        return jsonify(
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
        ), 200


@app.route("/api/manage/health/clamav", methods=["GET"])
@_require_management_auth
def manage_clamav_health() -> Any:
    try:
        current_runtime = _runtime()
        collector = getattr(current_runtime, "collect_clamav_health", None)
        if collector is None:
            return jsonify(current_runtime.collect_health()), 200
        return jsonify(collector()), 200
    except Exception as exc:
        detail = public_error_message(
            exc,
            default="Proxy ClamAV health collection failed.",
        )
        return jsonify(
            {
                "ok": False,
                "status": "degraded",
                "proxy_id": getattr(runtime, "proxy_id", ""),
                "proxy_status": detail,
                "services": {},
                "state_errors": [detail],
                "timestamp": int(time.time()),
            },
        ), 200


@app.route("/api/manage/logs", methods=["GET"])
@_require_management_auth
def manage_logs() -> Any:
    result = read_proxy_log(request.args.get("log"))
    return jsonify(result), proxy_log_status_code(result)


@app.route("/api/manage/sync", methods=["POST"])
@_require_management_auth
def manage_sync() -> Any:
    payload = request.get_json(silent=True) or {}
    operation_id = None
    if payload.get("operation_id") is not None:
        try:
            operation_id = int(payload.get("operation_id") or 0)
        except Exception:
            return jsonify(
                {"ok": False, "detail": "operation_id must be an integer."},
            ), 400
        if operation_id <= 0:
            return jsonify(
                {"ok": False, "detail": "operation_id must be a positive integer."},
            ), 400
    force, force_error = _parse_management_force(payload)
    if force_error is not None:
        return jsonify({"ok": False, "detail": force_error}), 400

    result = _runtime().sync_from_db(
        force=force,
        operation_id=operation_id,
    )
    return jsonify(result), (200 if result.get("ok") else 409)


@app.route("/api/manage/config/validate", methods=["POST"])
@_require_management_auth
def manage_config_validate() -> Any:
    payload = request.get_json(silent=True) or {}
    result = _runtime().validate_config_text(str(payload.get("config_text") or ""))
    return jsonify(result), 200


@app.route("/api/manage/config/rollback", methods=["POST"])
@_require_management_auth
def manage_config_rollback() -> Any:
    payload = request.get_json(silent=True) or {}
    result = _runtime().rollback_last_known_good_config(
        reason=str(payload.get("reason") or "Rollback requested by management API."),
    )
    return jsonify(result), (200 if result.get("ok") else 409)


@app.route("/api/manage/cache/clear", methods=["POST"])
@_require_management_auth
def manage_cache_clear() -> Any:
    result = _runtime().clear_cache()
    return jsonify(result), (200 if result.get("ok") else 500)


@app.route("/api/manage/clamav/test-eicar", methods=["POST"])
@_require_management_auth
def manage_clamav_test_eicar() -> Any:
    result = _runtime().test_clamav_eicar()
    return jsonify(result), (200 if result.get("ok") else 503)


@app.route("/api/manage/clamav/test-icap", methods=["POST"])
@_require_management_auth
def manage_clamav_test_icap() -> Any:
    result = _runtime().test_clamav_icap()
    return jsonify(result), (200 if result.get("ok") else 503)


@app.route("/api/manage/test/supervisor/<program_name>/<action>", methods=["POST"])
@_require_management_auth
def manage_test_supervisor(program_name: str, action: str) -> Any:
    if not _test_mode_enabled():
        abort(404)
    result = _runtime().test_control_supervisor_program(program_name, action=action)
    return jsonify(result), (200 if result.get("ok") else 409)


if (os.environ.get("DISABLE_PROXY_AGENT") or "").strip() != "1":
    start_agent()
