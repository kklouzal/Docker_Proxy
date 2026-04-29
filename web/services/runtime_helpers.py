from __future__ import annotations

import os
import time
from urllib.parse import urlsplit


def now_ts() -> int:
    return int(time.time())


def escape_like(value: str) -> str:
    """Escape special SQL LIKE pattern characters for safe ESCAPE '\\' queries."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def normalize_hostish(value: object | None) -> str:
    host = str(value or "").strip().lower().lstrip(".")
    if not host or host in {"-", "(nil)", "none", "null"}:
        return ""
    if "/" in host:
        host = host.split("/", 1)[0]
    if "?" in host:
        host = host.split("?", 1)[0]
    if "#" in host:
        host = host.split("#", 1)[0]
    if "@" in host:
        host = host.split("@", 1)[1]
    if host.startswith("[") and "]" in host:
        host = host[1 : host.find("]")]
    elif ":" in host and host.count(":") == 1:
        host_part, port = host.rsplit(":", 1)
        if port.isdigit():
            host = host_part
    return host.strip().strip(".")


def extract_domain(value: object | None, *, host: object | None = "", sni: object | None = "") -> str:
    for candidate in (sni, host):
        normalized = normalize_hostish(candidate)
        if normalized:
            return normalized

    raw = str(value or "").strip()
    if not raw:
        return ""

    try:
        parsed = urlsplit(raw)
        if parsed.hostname:
            return normalize_hostish(parsed.hostname)
    except Exception:
        pass

    candidate = raw.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    return normalize_hostish(candidate)


def not_cached_reason(method: object | None, result_code: object | None, http_status: object | None = None) -> str:
    m = str(method or "").strip().upper()
    rc = str(result_code or "").strip().upper()

    status: int | None = None
    try:
        if http_status is not None and str(http_status).strip() != "":
            status = int(http_status)
    except Exception:
        status = None
    if status is None:
        try:
            if "/" in rc:
                status = int(rc.rsplit("/", 1)[1])
        except Exception:
            status = None

    if m and m not in ("GET", "HEAD", "CONNECT"):
        return f"{m} method (not cacheable by default)"

    if m == "CONNECT" or rc.startswith("TCP_TUNNEL") or rc.startswith("TCP_CONNECT"):
        return "HTTPS tunnel (CONNECT) — not cacheable without SSL-bump"

    if status is not None:
        if status in (301, 302, 303, 307, 308):
            return f"Redirect response ({status}) (often not cached without explicit freshness)"
        if status >= 400:
            return f"Error response status {status} (often not cached)"

    if "DENIED" in rc or rc.startswith("TCP_DENIED"):
        return "Denied by ACL"
    if "BYPASS" in rc:
        return "Bypassed (cache deny rule or client no-cache)"
    if "ABORTED" in rc:
        return "Aborted (client/upstream closed connection)"
    if "SWAPFAIL" in rc:
        return "Cache swap failure"
    if "MISS" in rc:
        return "Cache miss (object not in cache)"
    return "Not served from cache"


def cache_hit_sql(result_column: str = "result_code") -> str:
    return (
        f"(COALESCE({result_column}, '') <> '' "
        f"AND {result_column} NOT LIKE 'TCP_DENIED%%' "
        f"AND {result_column} LIKE '%%HIT%%')"
    )


def present_value_sql(column: str) -> str:
    return f"COALESCE(NULLIF(TRIM({column}), ''), '') <> ''"


def not_cached_reason_sql(
    *,
    method_column: str = "method",
    result_column: str = "result_code",
    status_column: str = "http_status",
) -> str:
    return (
        "CASE "
        f"WHEN COALESCE(NULLIF(TRIM({method_column}), ''), '') <> '' "
        f"AND UPPER({method_column}) NOT IN ('GET', 'HEAD', 'CONNECT') "
        f"THEN CONCAT(UPPER({method_column}), ' method (not cacheable by default)') "
        f"WHEN UPPER({method_column}) = 'CONNECT' "
        f"OR {result_column} LIKE 'TCP_TUNNEL%%' "
        f"OR {result_column} LIKE 'TCP_CONNECT%%' "
        "THEN 'HTTPS tunnel (CONNECT) — not cacheable without SSL-bump' "
        f"WHEN {status_column} IN (301, 302, 303, 307, 308) "
        f"THEN CONCAT('Redirect response (', {status_column}, ') (often not cached without explicit freshness)') "
        f"WHEN {status_column} >= 400 "
        f"THEN CONCAT('Error response status ', {status_column}, ' (often not cached)') "
        f"WHEN {result_column} LIKE 'TCP_DENIED%%' OR {result_column} LIKE '%%DENIED%%' "
        "THEN 'Denied by ACL' "
        f"WHEN {result_column} LIKE '%%BYPASS%%' "
        "THEN 'Bypassed (cache deny rule or client no-cache)' "
        f"WHEN {result_column} LIKE '%%ABORTED%%' "
        "THEN 'Aborted (client/upstream closed connection)' "
        f"WHEN {result_column} LIKE '%%SWAPFAIL%%' "
        "THEN 'Cache swap failure' "
        f"WHEN {result_column} LIKE '%%MISS%%' "
        "THEN 'Cache miss (object not in cache)' "
        "ELSE 'Not served from cache' END"
    )


def env_int(
    name: str,
    default: int,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    try:
        value = int((os.environ.get(name) or str(default)).strip() or str(default))
    except Exception:
        value = int(default)
    if minimum is not None:
        value = max(int(minimum), value)
    if maximum is not None:
        value = min(int(maximum), value)
    return value


def env_float(
    name: str,
    default: float,
    *,
    minimum: float | None = None,
    maximum: float | None = None,
) -> float:
    try:
        value = float((os.environ.get(name) or str(default)).strip() or str(default))
    except Exception:
        value = float(default)
    if minimum is not None:
        value = max(float(minimum), value)
    if maximum is not None:
        value = min(float(maximum), value)
    return value