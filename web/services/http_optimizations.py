from __future__ import annotations

import gzip
import os
import re
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
    },
)
_QVALUE_PATTERN = re.compile(r"(?:0(?:\.\d{0,3})?|1(?:\.0{0,3})?)\Z")
_TRANSFORMATION_INVALIDATED_HEADERS = (
    "ETag",
    "Content-Digest",
    "Repr-Digest",
    "Digest",
    "Content-MD5",
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
    gzip_seen = False
    gzip_accepted = True
    wildcard_seen = False
    wildcard_accepted = True
    for part in header.split(","):
        bits = [bit.strip().lower() for bit in part.split(";")]
        if not bits or bits[0] not in {"gzip", "*"}:
            continue
        quality = 1.0
        for parameter in bits[1:]:
            if not parameter.startswith("q="):
                continue
            raw_quality = parameter.split("=", 1)[1]
            quality = float(raw_quality) if _QVALUE_PATTERN.fullmatch(raw_quality) else 0.0
            break
        if bits[0] == "gzip":
            gzip_seen = True
            gzip_accepted = gzip_accepted and quality > 0.0
        else:
            wildcard_seen = True
            wildcard_accepted = wildcard_accepted and quality > 0.0
    if gzip_seen:
        return gzip_accepted
    return wildcard_seen and wildcard_accepted


def _ensure_accept_encoding_vary(response: Any) -> None:
    vary_tokens = {
        token.strip().lower()
        for value in response.headers.getlist("Vary")
        for token in value.split(",")
        if token.strip()
    }
    if "*" not in vary_tokens and "accept-encoding" not in vary_tokens:
        response.vary.add("Accept-Encoding")


def _compressed_body_candidate(response: Any, *, min_size: int) -> bytes | None:
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
    mimetype = (response.mimetype or "").split(";", 1)[0].strip().lower()
    if mimetype not in _COMPRESSIBLE_MIMETYPES and not mimetype.endswith("+json"):
        return None
    try:
        data = response.get_data()
    except Exception:
        return None
    if len(data or b"") < max(1, int(min_size)):
        return None
    _ensure_accept_encoding_vary(response)
    if request.method == "HEAD" or response.status_code == 304:
        return None
    if not _client_accepts_gzip():
        return None
    return data


def _compress_response(response: Any, *, min_size: int, compresslevel: int) -> Any:
    data = _compressed_body_candidate(response, min_size=min_size)
    if data is None:
        return response
    compressed = gzip.compress(data, compresslevel=max(1, min(9, int(compresslevel))))
    if len(compressed) >= len(data):
        return response
    response.set_data(compressed)
    response.headers["Content-Encoding"] = "gzip"
    response.headers["Content-Length"] = str(len(compressed))
    # Validators and integrity values for the identity bytes no longer apply.
    for header in _TRANSFORMATION_INVALIDATED_HEADERS:
        response.headers.pop(header, None)
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
        os.environ.get("ENABLE_GZIP_RESPONSES")
        or getattr(app, "config", {}).get("ENABLE_GZIP_RESPONSES"),
        default=True,
    )

    @app.after_request
    def _http_optimizations_after_request(response: Any):
        endpoint = request.endpoint or ""
        if endpoint == "static":
            response.headers["Cache-Control"] = (
                f"public, max-age={int(static_max_age_seconds)}, immutable"
            )
        elif default_dynamic_max_age_seconds <= 0:
            if (
                request.method == "GET"
                and (request.headers.get("X-Requested-With") or "").lower() == "spa"
            ):
                response.headers.setdefault("Cache-Control", "no-store, private")
            else:
                response.headers.setdefault(
                    "Cache-Control",
                    "no-store" if request.method != "GET" else "no-cache",
                )
        else:
            response.headers.setdefault(
                "Cache-Control",
                f"private, max-age={int(default_dynamic_max_age_seconds)}",
            )

        if compression_enabled:
            response = _compress_response(
                response,
                min_size=compress_min_size,
                compresslevel=compresslevel,
            )
        return response
