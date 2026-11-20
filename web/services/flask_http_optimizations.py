"""Flask hook for the shared HTTP serving policy (Admin UI only).

Kept apart from ``services.http_optimizations`` so the proxy image, whose
listeners are plain WSGI callables (``proxy.wsgi_http`` applies the same
policy), packages no Flask-dependent code.
"""

from __future__ import annotations

import gzip
from typing import Any

from flask import request

from services.http_optimizations import (
    TRANSFORMATION_INVALIDATED_HEADERS,
    client_accepts_gzip,
    compressible_mimetype,
    gzip_responses_enabled,
)


def _ensure_accept_encoding_vary(response: Any) -> None:
    vary_tokens = {
        token.strip().lower()
        for value in response.headers.getlist("Vary")
        for token in value.split(",")
        if token.strip()
    }
    if "*" not in vary_tokens and "accept-encoding" not in vary_tokens:
        response.vary.add("Accept-Encoding")


def _compressed_body_candidate(
    response: Any, *, min_size: int, accept_encoding: str
) -> bytes | None:
    if response.status_code != 304 and not 200 <= response.status_code < 300:
        return None
    if response.status_code in {204, 205, 206} or response.headers.get("Content-Range"):
        return None
    if response.direct_passthrough:
        return None
    if response.headers.get("Content-Encoding"):
        return None
    if "no-transform" in (response.headers.get("Cache-Control") or "").lower():
        return None
    if not compressible_mimetype(response.mimetype):
        return None
    try:
        data = response.get_data()
    except Exception:
        return None
    if len(data or b"") < max(1, int(min_size)):
        return None
    _ensure_accept_encoding_vary(response)
    if response.status_code == 304:
        return None
    if not client_accepts_gzip(accept_encoding):
        return None
    return data


def _compress_response(
    response: Any, *, min_size: int, compresslevel: int, accept_encoding: str
) -> Any:
    data = _compressed_body_candidate(
        response, min_size=min_size, accept_encoding=accept_encoding
    )
    if data is None:
        return response
    compressed = gzip.compress(data, compresslevel=max(1, min(9, int(compresslevel))))
    if len(compressed) >= len(data):
        return response
    response.set_data(compressed)
    response.headers["Content-Encoding"] = "gzip"
    response.headers["Content-Length"] = str(len(compressed))
    # Validators and integrity values for the identity bytes no longer apply.
    for header in TRANSFORMATION_INVALIDATED_HEADERS:
        response.headers.pop(header, None)
    return response


def install_http_optimizations(
    app: Any,
    *,
    static_max_age_seconds: int = 31536000,
    compress_min_size: int = 1024,
    compresslevel: int = 5,
) -> None:
    """Install low-footprint serving optimizations on a Flask app.

    The middleware intentionally avoids extra workers, threads, caches, or large
    in-memory buffers. It only adds cache headers and opportunistic gzip for
    already-buffered text-like responses.
    """
    compression_enabled = gzip_responses_enabled(
        getattr(app, "config", {}).get("ENABLE_GZIP_RESPONSES"),
    )

    @app.after_request
    def _http_optimizations_after_request(response: Any):
        endpoint = request.endpoint or ""
        if endpoint == "static" and response.status_code in {200, 304}:
            response.headers["Cache-Control"] = (
                f"public, max-age={int(static_max_age_seconds)}, immutable"
            )
        elif endpoint == "static":
            # A missing asset must not be pinned in caches for a year.
            response.headers["Cache-Control"] = "no-store"
        elif (
            request.method in {"GET", "HEAD"}
            and (request.headers.get("X-Requested-With") or "").lower() == "spa"
        ):
            response.headers.setdefault("Cache-Control", "no-store, private")
        else:
            response.headers.setdefault(
                "Cache-Control",
                "no-store" if request.method not in {"GET", "HEAD"} else "no-cache",
            )

        if compression_enabled:
            response = _compress_response(
                response,
                min_size=compress_min_size,
                compresslevel=compresslevel,
                accept_encoding=request.headers.get("Accept-Encoding", ""),
            )
        return response
