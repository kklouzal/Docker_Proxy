from __future__ import annotations

import hashlib
import hmac
import os
import time
from collections.abc import Callable
from functools import wraps
from typing import TYPE_CHECKING, Any, NoReturn, TypeVar

from flask import Flask, abort, jsonify, make_response, request
from services.errors import public_error_message
from services.http_optimizations import install_http_optimizations
from services.logutil import configure_process_logging
from services.proxy_logs import (
    parse_proxy_log_max_bytes,
    proxy_log_status_code,
    read_proxy_log,
)
from services.version_status import current_component_metadata
from werkzeug.exceptions import BadRequest, RequestEntityTooLarge

from proxy.agent import start_agent
from proxy.control_plane_state import control_plane_ready
from proxy.runtime import get_runtime

if TYPE_CHECKING:
    from werkzeug.exceptions import HTTPException

F = TypeVar("F", bound=Callable[..., Any])
# proxy_api runs under gunicorn, which only configures its own gunicorn.* loggers.
configure_process_logging()
app = Flask(__name__)
install_http_optimizations(app, default_dynamic_max_age_seconds=0)
runtime: Any | None = None
_MANAGEMENT_JSON_DEFAULT_MAX_CONTENT_LENGTH = 1024 * 1024


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


def _provided_token() -> str:
    auth = (request.headers.get("Authorization") or "").strip()
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return (request.headers.get("X-Proxy-Token") or "").strip()


def _require_management_auth[F: Callable[..., Any]](func: F) -> F:
    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any):
        expected = _expected_token()
        if not expected:
            abort(403)
        provided = _provided_token()
        if not provided or not hmac.compare_digest(provided, expected):
            abort(403)
        return func(*args, **kwargs)

    return wrapper  # type: ignore[return-value]


def _require_control_plane_ready[F: Callable[..., Any]](func: F) -> F:
    """Refuse control-plane mutations until the agent finished startup.

    Recovery adoption and the startup schema must precede any normal
    control-plane write (docs/proxy-recovery.md); the agent signals completion
    for its current process lifetime through proxy.control_plane_state.
    """

    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any):
        if not control_plane_ready():
            response = jsonify(
                {
                    "ok": False,
                    "status": "control_plane_starting",
                    "retryable": True,
                    "detail": "Proxy control-plane startup (recovery adoption, schema, registration) has not completed yet; retry shortly.",
                },
            )
            response.headers["Retry-After"] = "5"
            return response, 503
        return func(*args, **kwargs)

    return wrapper  # type: ignore[return-value]


def _test_mode_enabled() -> bool:
    return (os.environ.get("ENABLE_TEST_MODE") or "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _abort_management_json_payload(detail: str, *, status_code: int = 400) -> NoReturn:
    abort(
        make_response(
            jsonify(
                {
                    "ok": False,
                    "detail": detail,
                },
            ),
            status_code,
        ),
    )


def _management_payload_too_large_detail(max_content_length: int) -> str:
    return f"Management JSON payload is limited to {max_content_length} bytes."


def _management_request_has_body(max_content_length: int) -> bool:
    request.max_content_length = max_content_length
    content_length = request.content_length
    if content_length is not None:
        if content_length > max_content_length:
            _abort_management_json_payload(
                _management_payload_too_large_detail(max_content_length),
                status_code=413,
            )
        return content_length > 0
    try:
        return bool(request.get_data(cache=True))
    except RequestEntityTooLarge:
        _abort_management_json_payload(
            _management_payload_too_large_detail(max_content_length),
            status_code=413,
        )


def _management_json_payload() -> dict[str, Any]:
    max_content_length = _management_json_max_content_length()
    if not _management_request_has_body(max_content_length):
        return {}
    if not request.is_json:
        _abort_management_json_payload(
            "Management JSON payload must use Content-Type application/json.",
        )
    try:
        payload = request.get_json(silent=False)
    except RequestEntityTooLarge:
        _abort_management_json_payload(
            _management_payload_too_large_detail(max_content_length),
            status_code=413,
        )
    except BadRequest:
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
    # The public PAC/WPAD listener runs as its own program (proxy.public_app);
    # this process serves only the management listener.
    return jsonify(
        {
            "ok": True,
            "service": "proxy-management",
            "status": "serving_management_api",
            "health_scope": "management-listener",
            "forwarding_checked": False,
        },
    ), 200


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
        return jsonify(current_runtime.collect_navigation_health(force=force)), 200
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
        force = str(request.args.get("force") or "").strip().lower() in {
            "1",
            "true",
            "yes",
        }
        return jsonify(current_runtime.collect_clamav_health(force=force)), 200
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
    max_bytes = parse_proxy_log_max_bytes(request.args.get("max_bytes"))
    if max_bytes is None:
        result = read_proxy_log(request.args.get("log"))
    else:
        result = read_proxy_log(request.args.get("log"), max_bytes=max_bytes)
    return jsonify(result), proxy_log_status_code(result)


@app.route("/api/manage/sync", methods=["POST"])
@_require_management_auth
@_require_control_plane_ready
def manage_sync() -> Any:
    payload = _management_json_payload()
    operation_id = payload.get("operation_id")
    if operation_id is not None:
        if type(operation_id) is not int:
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

    try:
        result = _runtime().sync_from_db(
            force=force,
            operation_id=operation_id,
        )
    except Exception as exc:
        detail = public_error_message(exc, default="Proxy reconciliation failed.")
        return jsonify({"ok": False, "detail": detail}), 500
    return jsonify(result), (200 if result.get("ok") else 409)


@app.route("/api/manage/config/current", methods=["GET"])
@_require_management_auth
def manage_config_current() -> Any:
    current_runtime = _runtime()
    config_text = str(current_runtime.get_current_config_text() or "")
    config_sha256 = ""
    if config_text:
        config_sha256 = hashlib.sha256(
            config_text.encode("utf-8", errors="replace"),
        ).hexdigest()
    return jsonify(
        {
            "ok": bool(config_text.strip()),
            "proxy_id": current_runtime.proxy_id,
            "config_text": config_text,
            "config_sha256": config_sha256,
            "detail": "Running Squid config returned."
            if config_text.strip()
            else "Running Squid config is empty or unavailable.",
        },
    ), 200


@app.route("/api/manage/config/validate", methods=["POST"])
@_require_management_auth
def manage_config_validate() -> Any:
    payload = _management_json_payload()
    config_text = _management_config_text_or_abort(payload)
    result = _runtime().validate_config_text(config_text)
    return jsonify(result), 200


@app.route("/api/manage/config/rollback", methods=["POST"])
@_require_management_auth
@_require_control_plane_ready
def manage_config_rollback() -> Any:
    payload = _management_json_payload()
    result = _runtime().rollback_last_known_good_config(
        reason=str(payload.get("reason") or "Rollback requested by management API."),
    )
    return jsonify(result), (200 if result.get("ok") else 409)


@app.route("/api/manage/cache/clear", methods=["POST"])
@_require_management_auth
@_require_control_plane_ready
def manage_cache_clear() -> Any:
    _management_json_payload()
    result = _runtime().clear_cache()
    return jsonify(result), (200 if result.get("ok") else 500)


@app.route("/api/manage/clamav/test-eicar", methods=["POST"])
@_require_management_auth
def manage_clamav_test_eicar() -> Any:
    _management_json_payload()
    result = _runtime().test_clamav_eicar()
    return jsonify(result), (200 if result.get("ok") else 503)


@app.route("/api/manage/clamav/test-icap", methods=["POST"])
@_require_management_auth
def manage_clamav_test_icap() -> Any:
    _management_json_payload()
    result = _runtime().test_clamav_icap()
    return jsonify(result), (200 if result.get("ok") else 503)


@app.route("/api/manage/test/supervisor/<program_name>/<action>", methods=["POST"])
@_require_management_auth
def manage_test_supervisor(program_name: str, action: str) -> Any:
    if not _test_mode_enabled():
        abort(404)
    _management_json_payload()
    result = _runtime().test_control_supervisor_program(program_name, action=action)
    return jsonify(result), (200 if result.get("ok") else 409)


if (os.environ.get("DISABLE_PROXY_AGENT") or "").strip() != "1":
    start_agent()
