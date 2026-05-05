from __future__ import annotations

import os
import time
from functools import wraps
from typing import Any, Callable, TypeVar

from flask import Flask, abort, jsonify, request

from proxy.agent import start_agent
from proxy.runtime import get_runtime
from services.errors import public_error_message


F = TypeVar("F", bound=Callable[..., Any])
app = Flask(__name__)
runtime = get_runtime()



def _expected_token() -> str:
    return (os.environ.get("PROXY_MANAGEMENT_TOKEN") or "").strip()



def _provided_token() -> str:
    auth = (request.headers.get("Authorization") or "").strip()
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return (request.headers.get("X-Proxy-Token") or "").strip()



def _require_management_auth(func: F) -> F:
    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any):
        expected = _expected_token()
        if expected:
            provided = _provided_token()
            if not provided or provided != expected:
                abort(403)
        return func(*args, **kwargs)

    return wrapper  # type: ignore[return-value]


@app.route("/health", methods=["GET"])
def health() -> Any:
    return jsonify({"ok": True, "service": "proxy-management"}), 200


@app.route("/api/manage/health", methods=["GET"])
@_require_management_auth
def manage_health() -> Any:
    try:
        return jsonify(runtime.collect_health()), 200
    except Exception as exc:
        detail = public_error_message(exc, default="Proxy health collection failed.")
        return jsonify(
            {
                "ok": False,
                "status": "degraded",
                "proxy_id": runtime.proxy_id,
                "proxy_status": detail,
                "stats": {},
                "services": {},
                "state_errors": [detail],
                "timestamp": int(time.time()),
            }
        ), 200


@app.route("/api/manage/sync", methods=["POST"])
@_require_management_auth
def manage_sync() -> Any:
    payload = request.get_json(silent=True) or {}
    result = runtime.sync_from_db(force=bool(payload.get("force")))
    return jsonify(result), (200 if result.get("ok") else 409)


@app.route("/api/manage/config/validate", methods=["POST"])
@_require_management_auth
def manage_config_validate() -> Any:
    payload = request.get_json(silent=True) or {}
    result = runtime.validate_config_text(str(payload.get("config_text") or ""))
    return jsonify(result), 200


@app.route("/api/manage/config/rollback", methods=["POST"])
@_require_management_auth
def manage_config_rollback() -> Any:
    payload = request.get_json(silent=True) or {}
    result = runtime.rollback_last_known_good_config(reason=str(payload.get("reason") or "Rollback requested by management API."))
    return jsonify(result), (200 if result.get("ok") else 409)


@app.route("/api/manage/cache/clear", methods=["POST"])
@_require_management_auth
def manage_cache_clear() -> Any:
    result = runtime.clear_cache()
    return jsonify(result), (200 if result.get("ok") else 500)


@app.route("/api/manage/clamav/test-eicar", methods=["POST"])
@_require_management_auth
def manage_clamav_test_eicar() -> Any:
    result = runtime.test_clamav_eicar()
    return jsonify(result), (200 if result.get("ok") else 503)


@app.route("/api/manage/clamav/test-icap", methods=["POST"])
@_require_management_auth
def manage_clamav_test_icap() -> Any:
    result = runtime.test_clamav_icap()
    return jsonify(result), (200 if result.get("ok") else 503)


if (os.environ.get("DISABLE_PROXY_AGENT") or "").strip() != "1":
    start_agent()
