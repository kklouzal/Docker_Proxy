from __future__ import annotations

import contextlib
import errno
import ipaddress
import math
import os
import time
from pathlib import Path
from urllib.parse import unquote, urlsplit

_UNSUPPORTED_DIRECTORY_FSYNC_ERRNOS = {
    errno.EBADF,
    errno.EINVAL,
    errno.ENOSYS,
    getattr(errno, "ENOTSUP", errno.EINVAL),
    getattr(errno, "EOPNOTSUPP", errno.EINVAL),
}


def fsync_parent_dir(path: str | os.PathLike[str]) -> None:
    """Best-effort fsync of the directory containing path."""
    directory = Path(path).parent or Path()
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    fd: int | None = None
    try:
        fd = os.open(directory, flags)
        os.fsync(fd)
    except OSError as exc:
        if exc.errno is None or exc.errno in _UNSUPPORTED_DIRECTORY_FSYNC_ERRNOS:
            return
        raise
    finally:
        if fd is not None:
            with contextlib.suppress(OSError):
                os.close(fd)


def now_ts() -> int:
    return int(time.time())


def escape_like(value: str) -> str:
    r"""Escape special SQL LIKE pattern characters for safe ESCAPE '\\' queries."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def decode_bytes(value: object | None) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace").strip()
    return str(value or "").strip()


def _decoded_hostish_has_delimiters(value: str) -> bool:
    if "%" not in value:
        return False
    decoded = unquote(value, errors="replace")
    return any(delimiter in decoded for delimiter in ("/", "\\", "?", "#", "@"))


def _is_valid_port(value: str) -> bool:
    return value.isdigit() and 1 <= int(value) <= 65535


def _is_ambiguous_ipv4_host(value: str) -> bool:
    candidate = value.rstrip(".").lower()
    if not candidate:
        return False
    labels = candidate.split(".")
    if not 1 <= len(labels) <= 4:
        return False
    for label in labels:
        if not label:
            return False
        if label.isdecimal():
            continue
        if label.startswith("0x"):
            digits = label.removeprefix("0x")
            if digits and all(ch in "0123456789abcdef" for ch in digits):
                continue
        return False
    return True


def _valid_dns_hostname(value: str) -> bool:
    candidate = value.rstrip(".")
    if not candidate or len(candidate) > 253:
        return False
    labels = candidate.split(".")
    if not labels or any(not label for label in labels):
        return False
    for label in labels:
        if len(label) > 63 or not label[0].isalnum() or not label[-1].isalnum():
            return False
        if any(not (ch.isalnum() or ch == "-") for ch in label):
            return False
    return True


def _normalize_host_token(host: str) -> str:
    candidate = host.strip()
    if not candidate:
        return ""
    try:
        parsed_ip = ipaddress.ip_address(candidate)
    except ValueError:
        if ":" in candidate or _is_ambiguous_ipv4_host(candidate):
            return ""
    else:
        return str(parsed_ip)
    try:
        candidate = candidate.encode("idna").decode("ascii").lower()
    except Exception:
        return ""
    if candidate.startswith(".") or candidate.endswith(".."):
        return ""
    candidate = candidate.removesuffix(".")
    if _is_ambiguous_ipv4_host(candidate):
        return ""
    return candidate if _valid_dns_hostname(candidate) else ""


def authority_has_empty_explicit_port(netloc: str) -> bool:
    """Return whether a parsed URL authority explicitly ends with an empty port."""
    authority = str(netloc or "").rsplit("@", 1)[-1]
    if authority.startswith("["):
        closing_bracket = authority.find("]")
        return authority[closing_bracket + 1 :] == ":" if closing_bracket >= 0 else False
    return authority.endswith(":") and ":" in authority


def normalize_hostish(value: object | None) -> str:
    host = str(value or "").strip().lower()
    if not host or host in {"-", "(nil)", "none", "null"}:
        return ""
    if "\\" in host or _decoded_hostish_has_delimiters(host):
        return ""

    try:
        parsed = urlsplit(host)
        if (parsed.scheme or parsed.netloc) and parsed.hostname:
            if authority_has_empty_explicit_port(parsed.netloc):
                return ""
            try:
                parsed_port = parsed.port
            except ValueError:
                return ""
            if parsed_port is not None and not _is_valid_port(str(parsed_port)):
                return ""
            host = parsed.hostname
    except Exception:
        pass

    if "/" in host:
        host = host.split("/", 1)[0]
    if "?" in host:
        host = host.split("?", 1)[0]
    if "#" in host:
        host = host.split("#", 1)[0]
    if "@" in host:
        return ""
    bracketed_authority = False
    if host.startswith("["):
        closing_bracket = host.find("]")
        if closing_bracket < 0:
            return ""
        remainder = host[closing_bracket + 1 :]
        if remainder:
            if not remainder.startswith(":") or not _is_valid_port(remainder[1:]):
                return ""
        host = host[1:closing_bracket]
        bracketed_authority = True
    elif ":" in host and host.count(":") == 1:
        host_part, port = host.rsplit(":", 1)
        if not _is_valid_port(port):
            return ""
        host = host_part
    normalized = _normalize_host_token(host)
    if bracketed_authority and normalized and ":" not in normalized:
        return ""
    return normalized


def extract_domain(
    value: object | None,
    *,
    host: object | None = "",
    sni: object | None = "",
) -> str:
    for candidate in (sni, host):
        normalized = normalize_hostish(candidate)
        if normalized:
            return normalized

    raw = str(value or "").strip()
    if not raw or "\\" in raw:
        return ""

    try:
        parsed = urlsplit(raw)
        if parsed.hostname:
            if authority_has_empty_explicit_port(parsed.netloc):
                return ""
            try:
                parsed_port = parsed.port
            except ValueError:
                return ""
            if parsed_port is not None and not _is_valid_port(str(parsed_port)):
                return ""
            return normalize_hostish(parsed.hostname)
    except Exception:
        pass

    candidate = raw.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    return normalize_hostish(candidate)


def not_cached_reason(
    method: object | None,
    result_code: object | None,
    http_status: object | None = None,
) -> str:
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

    if m and m not in {"GET", "HEAD", "CONNECT"}:
        return f"{m} method (not cacheable by default)"

    if m == "CONNECT" or rc.startswith(("TCP_TUNNEL", "TCP_CONNECT")):
        return "HTTPS tunnel (CONNECT) — not cacheable without SSL-bump"

    if status is not None:
        if status in {301, 302, 303, 307, 308}:
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
        if not math.isfinite(value):
            msg = f"{name} must be finite"
            raise ValueError(msg)
    except Exception:
        value = float(default)
    if minimum is not None:
        value = max(float(minimum), value)
    if maximum is not None:
        value = min(float(maximum), value)
    return value
