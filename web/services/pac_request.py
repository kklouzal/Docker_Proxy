"""Pure PAC request-serving helpers.

The public PAC/WPAD listener serves materialized files from the proxy's local
volume. Everything it needs per request lives here, free of database-backed
modules, so that process stays small and independent of the control plane.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from services.domain_normalization import is_ambiguous_ipv4_like_host
from services.public_endpoint import (
    _is_reserved_public_dns_host,
    _is_unsafe_request_host_ip,
)
from services.url_validation import (
    has_ascii_control_chars,
    has_url_whitespace_or_control_chars,
    repeatedly_percent_decode,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

PAC_HOST_PLACEHOLDER = "__PAC_PROXY_HOST__"

PAC_MANIFEST_FILENAME = "manifest.json"

PAC_STATE_SHA_FILENAME = ".state-sha256"

PAC_RENDER_DIR = "/var/lib/squid-flask-proxy/pac"


@dataclass(frozen=True)
class RenderedPacFile:
    relative_path: str
    content: str


def _request_host_only(raw_host: str) -> str:
    candidate = (raw_host or "").strip()
    if not candidate:
        return "127.0.0.1"
    if "://" in candidate:
        try:
            parsed = urlsplit(candidate)
            if parsed.hostname:
                return parsed.hostname
        except Exception:
            pass
    if candidate.count(":") > 1 and not candidate.startswith("["):
        return candidate
    try:
        parsed = urlsplit(f"//{candidate}")
        if parsed.hostname:
            return parsed.hostname
    except Exception:
        pass
    if candidate.startswith("[") and "]" in candidate:
        return candidate[1 : candidate.find("]")]
    if candidate.count(":") == 1:
        host, port = candidate.rsplit(":", 1)
        if port.isdigit():
            return host or "127.0.0.1"
    return candidate


def _valid_proxy_dns_host(value: str) -> bool:
    candidate = value.rstrip(".").lower()
    if not candidate or len(candidate) > 253:
        return False
    labels = candidate.split(".")
    return not any(
        not label
        or len(label) > 63
        or not ("a" <= label[0] <= "z" or "0" <= label[0] <= "9")
        or not ("a" <= label[-1] <= "z" or "0" <= label[-1] <= "9")
        or any(not ("a" <= ch <= "z" or "0" <= ch <= "9" or ch == "-") for ch in label)
        for label in labels
    )


def _normalize_proxy_host_only(host: str, *, allow_private: bool = False) -> str:
    candidate = str(host or "").strip()
    if not candidate:
        return "127.0.0.1"
    try:
        parsed_ip = ipaddress.ip_address(candidate)
    except ValueError:
        normalized_dns = candidate.rstrip(".").lower()
        if (
            is_ambiguous_ipv4_like_host(normalized_dns)
            or not _valid_proxy_dns_host(normalized_dns)
            or _is_reserved_public_dns_host(normalized_dns)
        ):
            return "127.0.0.1"
        return normalized_dns
    if getattr(parsed_ip, "scope_id", None):
        return "127.0.0.1"
    if allow_private and not _is_unsafe_request_host_ip(parsed_ip):
        return str(parsed_ip)
    if parsed_ip.is_multicast or not parsed_ip.is_global:
        return "127.0.0.1"
    return str(parsed_ip)


def format_proxy_host(raw_host: str) -> str:
    host = _normalize_proxy_host_only(_request_host_only(raw_host))
    return _format_host_only_for_pac(host)


def _format_request_proxy_host(raw_host: str) -> str:
    host = _normalize_proxy_host_only(
        _request_host_only(raw_host),
        allow_private=True,
    )
    return _format_host_only_for_pac(host)


def _format_host_only_for_pac(host: str) -> str:
    if ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host or "127.0.0.1"


def calculate_pac_state_sha(
    files: Sequence[RenderedPacFile] | Iterable[RenderedPacFile],
) -> str:
    digest = hashlib.sha256()
    for item in sorted(files, key=lambda current: current.relative_path):
        digest.update(str(item.relative_path).encode("utf-8", errors="replace"))
        digest.update(b"\0")
        digest.update(str(item.content or "").encode("utf-8", errors="replace"))
        digest.update(b"\0")
    return digest.hexdigest()


def _safe_pac_state_relative_path(value: object) -> str:
    candidate = str(value or "").strip().replace("\\", "/")
    if not candidate or candidate.startswith("/"):
        return ""
    parts = candidate.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        return ""
    if ":" in parts[0]:
        return ""
    rel_path = os.path.normpath(candidate).replace("\\", "/")
    if not rel_path or rel_path in {".", ".."} or rel_path.startswith("../"):
        return ""
    return rel_path


def _safe_manifest_relative_path(value: object) -> str:
    return _safe_pac_state_relative_path(value)


def _manifest_fallback_file(manifest: dict[str, object]) -> str:
    return _safe_manifest_relative_path(manifest.get("fallback_file")) or "fallback.pac"


def _manifest_profile_id(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        candidate = value.strip()
        if candidate.isdecimal():
            return int(candidate)
    return None


def _manifest_profile_order_key(
    profile_id: int | None, order: int
) -> tuple[int, int, int]:
    if profile_id is not None:
        return (0, profile_id, order)
    return (1, order, order)


def select_manifest_file(manifest: dict[str, object], client_ip: str) -> str:
    fallback_file = _manifest_fallback_file(manifest)
    profiles = manifest.get("profiles")
    if not isinstance(profiles, list):
        return fallback_file

    try:
        parsed_ip = ipaddress.ip_address((client_ip or "").strip())
    except Exception:
        parsed_ip = None
    if parsed_ip is not None and getattr(parsed_ip, "ipv4_mapped", None) is not None:
        # Some WSGI/proxy stacks report IPv4 clients as IPv4-mapped IPv6
        # addresses (for example ::ffff:10.2.3.4).  PAC client profiles are
        # operator-facing source networks, so mapped IPv4 clients should select
        # the same IPv4 CIDR profiles as their canonical dotted-quad form.
        parsed_ip = parsed_ip.ipv4_mapped

    catch_all = ""
    catch_all_key: tuple[int, int, int] | None = None
    best_match = ""
    best_match_key: tuple[int, int, int, int] | None = None
    for order, entry in enumerate(profiles):
        if not isinstance(entry, dict):
            continue
        client_cidr = str(entry.get("client_cidr") or "").strip()
        file_name = _safe_manifest_relative_path(entry.get("file"))
        if not file_name:
            continue
        profile_id = _manifest_profile_id(entry.get("profile_id"))
        profile_order_key = _manifest_profile_order_key(profile_id, order)
        if not client_cidr:
            if catch_all_key is None or profile_order_key < catch_all_key:
                catch_all = file_name
                catch_all_key = profile_order_key
            continue
        if parsed_ip is None:
            continue
        try:
            network = ipaddress.ip_network(client_cidr, strict=False)
        except Exception:
            continue
        if parsed_ip.version != network.version:
            continue
        if parsed_ip in network:
            match_key = (-int(network.prefixlen), *profile_order_key)
            if best_match_key is None or match_key < best_match_key:
                best_match = file_name
                best_match_key = match_key

    if best_match:
        return best_match
    if catch_all:
        return catch_all
    return fallback_file


def _pac_string_literal_fragment(value: str) -> str:
    # PAC artifacts place the placeholder inside JavaScript string literals.
    # Replace it with the JSON/JavaScript-escaped payload without adding a
    # second pair of quotes, so malformed Host headers cannot break PAC syntax.
    return json.dumps(str(value or ""))[1:-1]


def substitute_request_host(content: str, request_host: str) -> str:
    return str(content or "").replace(
        PAC_HOST_PLACEHOLDER,
        _pac_string_literal_fragment(_format_request_proxy_host(request_host)),
    )


def _has_unsafe_url_text(value: str) -> bool:
    return has_url_whitespace_or_control_chars(value)


def _has_unsafe_query_text(value: str) -> bool:
    return has_ascii_control_chars(value)


_MAX_PERCENT_DECODE_PASSES = 8


def _strict_percent_unquote(value: str) -> str | None:
    result = repeatedly_percent_decode(value, max_passes=1, errors="strict")
    if result.malformed or result.invalid_utf8:
        return None
    return result.values[-1]


def _bounded_repeated_unquote(value: str) -> str | None:
    # Preserve the historical initial decode plus eight additional bounded passes.
    result = repeatedly_percent_decode(
        value,
        max_passes=_MAX_PERCENT_DECODE_PASSES + 1,
        errors="strict",
    )
    if result.malformed or result.invalid_utf8 or result.excessive_nesting:
        return None
    return result.values[-1]


def _safe_decoded_path_segments(path: str) -> list[str] | None:
    raw_segments = path.split("/")
    decoded_segments = []
    repeatedly_decoded_segments = []
    for segment in raw_segments:
        decoded_segment = _strict_percent_unquote(segment)
        if decoded_segment is None:
            return None
        repeatedly_decoded_segment = _bounded_repeated_unquote(segment)
        if repeatedly_decoded_segment is None:
            return None
        decoded_segments.append(decoded_segment)
        repeatedly_decoded_segments.append(repeatedly_decoded_segment)
    if any(
        "/" in segment or "\\" in segment or _has_unsafe_url_text(segment)
        for segment in repeatedly_decoded_segments
    ):
        return None
    segments = [segment for segment in repeatedly_decoded_segments if segment]
    if any(segment in {".", ".."} for segment in segments):
        return None
    return decoded_segments


def _safe_repeatedly_decoded_query(query: str) -> bool:
    decoded_query = _bounded_repeated_unquote(query)
    if decoded_query is None:
        return False
    return "\\" not in decoded_query and not _has_unsafe_query_text(decoded_query)


def normalize_public_pac_path(value: object | None, default: str = "/proxy.pac") -> str:
    fallback = str(default if default is not None else "/proxy.pac").strip()
    if fallback and not fallback.startswith("/"):
        fallback = f"/{fallback}"
    candidate = str(value or "").strip()
    if not candidate:
        return fallback
    if _has_unsafe_url_text(candidate):
        return fallback
    try:
        parsed = urlsplit(candidate)
    except Exception:
        return fallback
    if parsed.username is not None or parsed.password is not None:
        return fallback
    if parsed.fragment:
        return fallback
    if parsed.netloc and not parsed.scheme:
        return fallback
    if parsed.scheme and parsed.scheme.lower() not in {"http", "https"}:
        return fallback
    if parsed.scheme and not parsed.netloc:
        return fallback
    path = parsed.path or fallback
    if path.startswith("//") or "\\" in path:
        return fallback
    if not path.startswith("/"):
        path = f"/{path}"
    if _safe_decoded_path_segments(path) is None:
        return fallback
    query = parsed.query
    if query:
        if not _safe_repeatedly_decoded_query(query):
            return fallback
    return f"{path}?{query}" if query else path
