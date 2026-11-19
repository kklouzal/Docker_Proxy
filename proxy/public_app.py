"""Public PAC/WPAD listener (``proxy_public`` supervisor program).

Runs in its own small gunicorn process so client auto-configuration never
shares worker threads with management or control-plane database work. PAC,
WPAD and ``/health`` are served from the proxy's local materialized files and
import nothing database-backed; only the rare block-page policy request
submission touches MySQL, imported lazily on that request.
"""

from __future__ import annotations

import hashlib
import os
from typing import Any

from flask import Flask, Response, abort, jsonify, request
from markupsafe import escape
from services.errors import public_error_message
from services.http_optimizations import install_http_optimizations
from services.logutil import configure_process_logging
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
from werkzeug.exceptions import BadRequest, RequestEntityTooLarge

app = Flask(__name__)
install_http_optimizations(app, default_dynamic_max_age_seconds=0)
_PUBLIC_NON_PAC_PATHS = frozenset({"/", "/health", "/policy-request"})
_POLICY_REQUEST_DEFAULT_MAX_CONTENT_LENGTH = 16 * 1024


def _policy_request_max_content_length() -> int:
    raw = (os.environ.get("POLICY_REQUEST_MAX_CONTENT_LENGTH") or "").strip()
    try:
        value = int(raw) if raw else _POLICY_REQUEST_DEFAULT_MAX_CONTENT_LENGTH
    except (TypeError, ValueError):
        return _POLICY_REQUEST_DEFAULT_MAX_CONTENT_LENGTH
    return value if value >= 1 else _POLICY_REQUEST_DEFAULT_MAX_CONTENT_LENGTH


def _is_public_path(path: str, query_string: object | None = None) -> bool:
    normalized_path = str(path or "/")
    raw_target = (
        request.environ.get("RAW_URI")
        or request.environ.get("REQUEST_URI")
        or request.full_path
    )
    raw_path = str(raw_target or normalized_path).split("?", 1)[0]
    if not public_pac_request_path_safe(raw_path):
        return normalized_path in _PUBLIC_NON_PAC_PATHS
    if normalized_path in _PUBLIC_NON_PAC_PATHS:
        return True
    try:
        return public_pac_request_allowed(normalized_path, query_string)
    except Exception:
        return normalized_path in {"/proxy.pac", "/wpad.dat"}


@app.before_request
def _restrict_to_public_paths() -> None:
    if not _is_public_path(request.path, request.query_string):
        abort(404)


@app.errorhandler(404)
def _management_path_not_found(exc: Exception):
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


@app.route("/", methods=["GET"])
@app.route("/proxy.pac", methods=["GET"])
@app.route("/wpad.dat", methods=["GET"])
@app.route("/<path:_pac_path>", methods=["GET"])
def public_pac(_pac_path: str = "") -> Any:
    path = "/wpad.dat" if request.path == "/" else request.path
    resolution = resolve_pac(
        client_ip=client_ip_from_headers(request.headers, request.remote_addr),
        request_host=request_host_from_headers(request.headers, request.remote_addr),
    )
    data = resolution.content
    response = Response(data, content_type=PAC_CONTENT_TYPE)
    response.headers["Content-Disposition"] = pac_content_disposition(path)
    response.headers["Cache-Control"] = (
        "private, max-age=30"
        if resolution.source == "materialized"
        else "no-store, private"
    )
    response.headers["Vary"] = "Host, X-Forwarded-For, X-Forwarded-Host, X-Real-IP"
    etag_material = b"\0".join(
        (
            resolution.source.encode("utf-8", errors="replace"),
            resolution.state_sha256.encode("utf-8", errors="replace"),
            resolution.selected_file.encode("utf-8", errors="replace"),
            data,
        ),
    )
    response.set_etag(hashlib.sha256(etag_material).hexdigest())
    return response.make_conditional(request)


@app.route("/policy-request", methods=["GET"])
def public_policy_request_get() -> Any:
    abort(405)


def _html_response(title: str, body: str, *, status: int = 200) -> Response:
    return Response(
        f"<!doctype html><title>{title}</title><h1>{title}</h1><p>{body}</p>",
        status=status,
        mimetype="text/html; charset=utf-8",
    )


def _policy_request_form_or_error() -> tuple[Any | None, Response | None]:
    max_content_length = _policy_request_max_content_length()
    too_large = _html_response(
        "Request too large",
        f"Policy request submissions are limited to {max_content_length} bytes.",
        status=413,
    )
    request.max_content_length = max_content_length
    content_length = request.content_length
    if content_length is not None and content_length > max_content_length:
        return None, too_large
    try:
        return request.form, None
    except RequestEntityTooLarge:
        return None, too_large
    except BadRequest:
        return None, _html_response(
            "Request failed",
            "The policy request form could not be parsed.",
            status=400,
        )


def _policy_request_client_ip(form: Any, normalize_client_ip) -> str:
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


@app.route("/policy-request", methods=["POST"])
def public_policy_request() -> Any:
    form, form_error = _policy_request_form_or_error()
    if form_error is not None:
        return form_error
    # Block-page submissions are rare; keep the database-backed store out of
    # the PAC listener until one arrives.
    from services.policy_requests import (
        PolicyRequestAdmissionError,
        get_policy_request_store,
        normalize_client_ip,
    )
    from services.proxy_context import get_proxy_id

    client_ip = _policy_request_client_ip(form, normalize_client_ip)
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
    except PolicyRequestAdmissionError as exc:
        return _html_response(
            "Request not accepted",
            str(escape(public_error_message(exc))),
            status=429,
        )
    except Exception as exc:
        unavailable = _policy_request_store_unavailable(exc)
        detail = (
            "The request service is temporarily unavailable. Please try again later."
            if unavailable
            else "The request could not be recorded due to an internal error."
        )
        return _html_response(
            "Request failed", detail, status=503 if unavailable else 500
        )


configure_process_logging()
application = app
