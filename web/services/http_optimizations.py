from __future__ import annotations

import gzip
import os
from typing import Any

from flask import request


_COMPRESSIBLE_MIMETYPES = frozenset(
    {
        "application/javascript",
        "application/json",
        "application/x-javascript",
        "application/x-ns-proxy-autoconfig",
        "text/css",
        "text/csv",
        "text/html",
        "text/javascript",
        "text/plain",
        "text/xml",
    }
)


def _bool_env(value: str | None, *, default: bool) -> bool:
    raw = str(value or "").strip().lower()
    if not raw:
        return bool(default)
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    return bool(default)


def _client_accepts_gzip() -> bool:
    header = request.headers.get("Accept-Encoding", "")
    return "gzip" in {part.split(";", 1)[0].strip().lower() for part in header.split(",")}


def _should_compress(response: Any, *, min_size: int) -> bool:
    if request.method == "HEAD":
        return False
    if not _client_accepts_gzip():
        return False
    if response.status_code < 200 or response.status_code >= 300:
        return False
    if response.direct_passthrough:
        return False
    if response.headers.get("Content-Encoding"):
        return False
    if "no-transform" in (response.headers.get("Cache-Control") or "").lower():
        return False
    mimetype = (response.mimetype or "").split(";", 1)[0].strip().lower()
    if mimetype not in _COMPRESSIBLE_MIMETYPES and not mimetype.endswith("+json"):
        return False
    try:
        data = response.get_data()
    except Exception:
        return False
    return len(data or b"") >= max(1, int(min_size))


def _compress_response(response: Any, *, min_size: int, compresslevel: int) -> Any:
    if not _should_compress(response, min_size=min_size):
        return response
    data = response.get_data()
    compressed = gzip.compress(data, compresslevel=max(1, min(9, int(compresslevel))))
    if len(compressed) >= len(data):
        return response
    response.set_data(compressed)
    response.headers["Content-Encoding"] = "gzip"
    response.headers["Content-Length"] = str(len(compressed))
    response.headers.add("Vary", "Accept-Encoding")
    # Strong validators no longer apply after representation transformation.
    response.headers.pop("ETag", None)
    return response


def install_http_optimizations(
    app: Any,
    *,
    static_max_age_seconds: int = 31536000,
    default_dynamic_max_age_seconds: int = 0,
    compress_min_size: int = 1024,
    compresslevel: int = 5,
) -> None:
    """Install low-footprint serving optimizations on a Flask app.

    The middleware intentionally avoids extra workers, threads, caches, or large
    in-memory buffers. It only adds cache headers and opportunistic gzip for
    already-buffered text-like responses.
    """

    compression_enabled = _bool_env(
        os.environ.get("ENABLE_GZIP_RESPONSES") or getattr(app, "config", {}).get("ENABLE_GZIP_RESPONSES"),
        default=True,
    )

    @app.after_request
    def _http_optimizations_after_request(response: Any):
        endpoint = request.endpoint or ""
        if endpoint == "static":
            response.headers["Cache-Control"] = f"public, max-age={int(static_max_age_seconds)}, immutable"
        elif default_dynamic_max_age_seconds <= 0:
            response.headers.setdefault("Cache-Control", "no-store" if request.method != "GET" else "no-cache")
        else:
            response.headers.setdefault("Cache-Control", f"private, max-age={int(default_dynamic_max_age_seconds)}")

        if compression_enabled:
            response = _compress_response(response, min_size=compress_min_size, compresslevel=compresslevel)
        return response