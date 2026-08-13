from __future__ import annotations

import base64
import binascii
import contextlib
import hashlib
import ipaddress
import json
import logging
import posixpath
import re
import threading
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import TYPE_CHECKING

from services.db import (
    DATABASE_ERRORS,
    connect,
    mysql_advisory_lock,
    mysql_schema_lock_timeout_seconds,
)
from services.domain_normalization import normalize_domain as _norm_domain
from services.errors import public_error_message
from services.logutil import log_database_unavailable
from services.runtime_helpers import env_int as _env_int
from services.runtime_helpers import now_ts as _now
from services.schema_lifecycle import ensure_column, ensure_index

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

SAFE_BROWSING_LISTS: dict[str, str] = {
    "se-4b": "SOCIAL_ENGINEERING",
    "mw-4b": "MALWARE",
    "uws-4b": "UNWANTED_SOFTWARE",
    "uwsa-4b": "UNWANTED_SOFTWARE_ANDROID",
    "pha-4b": "POTENTIALLY_HARMFUL_APPLICATION",
}
DEFAULT_SAFE_BROWSING_LISTS = ("se-4b", "mw-4b", "uws-4b")
SAFE_BROWSING_PROVIDER_CATEGORY = "google-safe-browsing"
_API_BASE = "https://safebrowsing.googleapis.com/v5"
_VALID_THREAT_TYPES = {
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "UNWANTED_SOFTWARE_ANDROID",
    "POTENTIALLY_HARMFUL_APPLICATION",
}
_IGNORED_THREAT_ATTRIBUTES = {"THREAT_ATTRIBUTE_UNSPECIFIED", "CANARY", "FRAME_ONLY"}
_COMMON_SECOND_LEVEL_PUBLIC_SUFFIXES = {"ac", "co", "com", "edu", "gov", "net", "org"}
logger = logging.getLogger(__name__)


class _RejectSafeBrowsingRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        error = "Google Safe Browsing redirects are not allowed"
        raise RuntimeError(error)


_SAFE_BROWSING_OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    _RejectSafeBrowsingRedirects(),
)


def _open_safe_browsing_request(request: urllib.request.Request, *, timeout: int):
    """Open directly and reject redirects so the API key stays with Google."""
    return _SAFE_BROWSING_OPENER.open(request, timeout=timeout)


def parse_duration_seconds(value: object, default: int = 0) -> int:
    text = str(value or "").strip()
    if not text:
        return int(default)
    text = text.removesuffix("s")
    try:
        return max(0, int(float(text)))
    except Exception:
        return int(default)


def _urlsafe_b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _decode_b64(text: object, *, field: str) -> bytes:
    if text is None:
        return b""
    if not isinstance(text, str):
        msg = f"Google Safe Browsing {field} must be base64-encoded"
        raise ValueError(msg)
    raw = text.strip()
    if not raw:
        return b""
    if not re.fullmatch(r"[A-Za-z0-9+/_-]+={0,2}", raw):
        msg = f"Google Safe Browsing {field} must be base64-encoded"
        raise ValueError(msg)
    data = raw.rstrip("=")
    padding_length = len(raw) - len(data)
    if ({"+", "/"} & set(data)) and ({"-", "_"} & set(data)):
        msg = f"Google Safe Browsing {field} must use one base64 alphabet"
        raise ValueError(msg)
    expected_padding = (-len(data)) % 4
    if expected_padding == 3 or (padding_length and padding_length != expected_padding):
        msg = f"Google Safe Browsing {field} must be correctly padded base64"
        raise ValueError(msg)
    try:
        encoded = data.encode("ascii") + b"=" * expected_padding
        return base64.b64decode(encoded, altchars=b"-_", validate=True)
    except (binascii.Error, UnicodeEncodeError, ValueError) as exc:
        msg = f"Google Safe Browsing {field} must be base64-encoded"
        raise ValueError(msg) from exc


def _decode_search_full_hash(value: object) -> bytes:
    if not isinstance(value, str) or not value or value != value.strip():
        msg = "Google Safe Browsing hash search fullHash must be base64-encoded"
        raise ValueError(msg)
    full_hash = _decode_b64(value, field="hash search fullHash")
    if len(full_hash) != 32:
        msg = "Google Safe Browsing hash search fullHash must be exactly 32 bytes"
        raise ValueError(msg)
    return full_hash


def _strip_control_url_chars(value: str) -> str:
    return (value or "").replace("\t", "").replace("\r", "").replace("\n", "")


def _recursive_unquote(value: str, *, limit: int = 8) -> str:
    current = value or ""
    for _ in range(limit):
        decoded = urllib.parse.unquote(current)
        if decoded == current:
            break
        current = decoded
    return current


def _split_url_preserving_escaped_fragment(raw: str) -> urllib.parse.SplitResult:
    parsed = urllib.parse.urlsplit(raw)
    if not parsed.fragment:
        return parsed

    # Safe Browsing canonicalization removes literal URL fragments before
    # repeated percent-unescaping. Escaped '#'/ '?' bytes inside the path/query
    # are URL data after unescaping, not fragment/query delimiters, so a second
    # parse would incorrectly truncate them.
    without_fragment = urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, parsed.query, ""),
    )
    return urllib.parse.urlsplit(without_fragment)


def _escape_safe_browsing_url_chars(value: str) -> str:
    out: list[str] = []
    for b in value.encode("utf-8", errors="surrogatepass"):
        ch = chr(b)
        if b <= 32 or b >= 127 or ch in "#%":
            out.append(f"%{b:02X}")
        else:
            out.append(ch)
    return "".join(out)


def _escape_safe_browsing_component(value: str, *, safe: str) -> str:
    out: list[str] = []
    allowed = set(safe)
    for b in value.encode("utf-8", errors="surrogatepass"):
        ch = chr(b)
        if b <= 32 or b >= 127 or ch in "#%":
            out.append(f"%{b:02X}")
        elif ch.isalnum() or ch in allowed:
            out.append(ch)
        else:
            out.append(f"%{b:02X}")
    return "".join(out)


def _normalize_ipv4_loose(host: str) -> str | None:
    text = (host or "").strip().lower()
    if not text:
        return None
    try:
        return str(ipaddress.IPv4Address(text))
    except Exception:
        pass
    parts = text.split(".")
    if not 1 <= len(parts) <= 4:
        return None
    values: list[int] = []
    try:
        for part in parts:
            if not part:
                return None
            if part.startswith("0x"):
                value = int(part, 16)
            elif len(part) > 1 and part.startswith("0"):
                value = int(part, 8)
            else:
                value = int(part, 10)
            if value < 0:
                return None
            values.append(value)
        if len(values) == 1:
            number = values[0]
            if number > 0xFFFFFFFF:
                return None
            return str(ipaddress.IPv4Address(number))
        if any(v > 255 for v in values[:-1]):
            return None
        last_bits = 8 * (5 - len(values))
        if values[-1] >= (1 << last_bits):
            return None
        number = 0
        for v in values[:-1]:
            number = (number << 8) | v
        number = (number << last_bits) | values[-1]
        return str(ipaddress.IPv4Address(number))
    except Exception:
        return None


def _normalize_host(host: str) -> str:
    text = (host or "").strip().strip(".").lower()
    text = re.sub(r"\.+", ".", text)
    if not text:
        return ""
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    ipv4 = _normalize_ipv4_loose(text)
    if ipv4:
        return ipv4
    try:
        ip6 = ipaddress.IPv6Address(text)
        if ip6.ipv4_mapped is not None:
            return str(ip6.ipv4_mapped)
        nat64_prefix = ipaddress.IPv6Network("64:ff9b::/96")
        if ip6 in nat64_prefix:
            return str(ipaddress.IPv4Address(int(ip6) & 0xFFFFFFFF))
        return ip6.compressed
    except Exception:
        pass
    try:
        return text.encode("idna").decode("ascii")
    except Exception:
        return _norm_domain(text)


def _canonical_path(path: str) -> str:
    path = _recursive_unquote(path or "/")
    if not path.startswith("/"):
        path = "/" + path
    path = re.sub(r"/{2,}", "/", path)
    trailing = path.endswith("/")
    normalized = posixpath.normpath(path)
    if normalized == ".":
        normalized = "/"
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    if trailing and normalized != "/":
        normalized += "/"
    return _escape_safe_browsing_component(normalized, safe="/-._~!$&'()*+,;=:@")


def canonicalize_url(value: str) -> str:
    raw = _strip_control_url_chars((value or "").strip())
    if not raw:
        return ""
    if "://" not in raw:
        raw = "http://" + raw
    try:
        parsed = _split_url_preserving_escaped_fragment(raw)
        hostname = parsed.hostname
    except ValueError:
        return ""
    scheme = (parsed.scheme or "http").lower()
    if _has_malformed_authority(parsed):
        return ""
    decoded_host = _recursive_unquote(
        hostname or parsed.netloc.split("@")[-1].split(":")[0],
    )
    if _has_decoded_authority_delimiter(decoded_host):
        return ""
    host = _normalize_host(decoded_host)
    if not host:
        return ""
    if not _is_ip_literal(host):
        host = _escape_safe_browsing_url_chars(host)
    path = _canonical_path(parsed.path or "/")
    query = _escape_safe_browsing_component(
        _recursive_unquote(parsed.query or ""),
        safe="=&?/:;+,$-_.!~*'()@",
    )
    # Safe Browsing expression generation discards scheme, credentials, and port;
    # the canonical URL keeps only host/path/query for stable hashing input.
    # Keep IPv6 literals bracketed in the URL form so the later urlsplit() pass
    # sees the whole literal as the hostname instead of treating the first hextet
    # as an IPv4-ish decimal hostname.
    netloc = f"[{host}]" if ":" in host and _is_ip_literal(host) else host
    return urllib.parse.urlunsplit((scheme, netloc, path, query, ""))


def _has_malformed_authority(parsed: urllib.parse.SplitResult) -> bool:
    netloc = parsed.netloc or ""
    if not netloc:
        return False
    if "\\" in netloc:
        return True
    try:
        _ = parsed.port
    except ValueError:
        return True

    hostport = netloc.rsplit("@", 1)[-1]
    if hostport.startswith("["):
        closing = hostport.find("]")
        if closing < 0:
            return True
        remainder = hostport[closing + 1 :]
        return remainder == ":"
    return hostport.endswith(":")


def _has_decoded_authority_delimiter(host: str) -> bool:
    if any(ch in host for ch in ("@", "/", "\\", "?", "#", "[", "]")):
        return True
    return ":" in host and not _is_ip_literal(host)


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except Exception:
        return False


def _etld_plus_one_index(parts: list[str]) -> int:
    if len(parts) <= 2:
        return 0
    # Prefer a PSL library when present; keep a deterministic fallback for the
    # common second-level public suffixes used by the docs and many ccTLDs.
    host = ".".join(parts)
    try:  # pragma: no cover - optional dependency path
        from publicsuffix2 import get_sld  # type: ignore

        sld = get_sld(host)
        if sld:
            sld_parts = sld.split(".")
            return max(0, len(parts) - len(sld_parts))
    except Exception:
        pass
    if (
        len(parts) >= 3
        and len(parts[-1]) == 2
        and parts[-2] in _COMMON_SECOND_LEVEL_PUBLIC_SUFFIXES
    ):
        return len(parts) - 3
    return len(parts) - 2


def _host_suffixes(host: str) -> list[str]:
    host = _normalize_host(host)
    if not host:
        return []
    if _is_ip_literal(host):
        return [host]
    parts = [p for p in host.split(".") if p]
    if not parts:
        return []
    exact = ".".join(parts)
    etld1_index = _etld_plus_one_index(parts)
    # Google's examples order the exact host first, then up to four suffixes
    # from the last five hostname components, stopping at eTLD+1.
    start = max(0, etld1_index - 3, len(parts) - 5)
    suffixes = [".".join(parts[i:]) for i in range(start, etld1_index + 1)]
    out: list[str] = [exact]
    for suffix in suffixes:
        if suffix and suffix not in out:
            out.append(suffix)
    return out[:5]


def _path_prefixes(path: str, query: str = "") -> list[str]:
    path = path or "/"
    if not path.startswith("/"):
        path = "/" + path
    out: list[str] = []
    if query:
        out.append(path + "?" + query)
    out.append(path)
    if path != "/":
        if "/" not in out:
            out.append("/")
        segments = [s for s in path.split("/") if s]
        current = "/"
        for segment in segments[:-1][:4]:
            current += segment + "/"
            if current not in out:
                out.append(current)
    dedup: list[str] = []
    for item in out:
        if item not in dedup:
            dedup.append(item)
    return dedup[:6]


def url_expressions(url: str) -> list[str]:
    canonical = canonicalize_url(url)
    if not canonical:
        return []
    parsed = urllib.parse.urlsplit(canonical)
    host = parsed.hostname or ""
    expressions: list[str] = []
    for suffix in _host_suffixes(host):
        expressions.extend(
            suffix + prefix
            for prefix in _path_prefixes(parsed.path or "/", parsed.query)
        )
    return expressions


def expression_hashes(url: str) -> list[bytes]:
    return [
        hashlib.sha256(expr.encode("utf-8")).digest() for expr in url_expressions(url)
    ]


class _BitReader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.bit = 0

    def read_bit(self) -> int:
        if self.bit >= len(self.data) * 8:
            msg = "Google Safe Browsing compressed Rice data is truncated"
            raise ValueError(msg)
        value = (self.data[self.bit // 8] >> (self.bit % 8)) & 1
        self.bit += 1
        return value

    def read_bits(self, count: int) -> int:
        value = 0
        for i in range(int(count)):
            value |= self.read_bit() << i
        return value


def decode_rice_delta_32(payload: dict[str, object] | None) -> list[int]:
    if payload is None:
        return []

    def integer_field(name: str, maximum: int) -> int:
        value = payload.get(name, 0)
        if isinstance(value, bool) or not isinstance(value, int):
            msg = "Google Safe Browsing compressed Rice parameters are invalid"
            raise ValueError(msg)
        if value < 0 or value > maximum:
            msg = "Google Safe Browsing compressed Rice parameters are invalid"
            raise ValueError(msg)
        return value

    first = integer_field("firstValue", (1 << 32) - 1)
    count = integer_field("entriesCount", (1 << 31) - 1)
    rice = integer_field("riceParameter", (1 << 31) - 1)
    if count > 0 and not 3 <= rice <= 30:
        msg = "Google Safe Browsing compressed Rice parameters are invalid"
        raise ValueError(msg)
    if count <= 0:
        return [first]
    reader = _BitReader(
        _decode_b64(payload.get("encodedData"), field="compressed Rice encodedData")
    )
    values = [first]
    previous = first
    for _ in range(count):
        quotient = 0
        while reader.read_bit() == 1:
            quotient += 1
        remainder = reader.read_bits(rice)
        delta = (quotient << rice) + remainder
        previous += delta
        if previous > (1 << 32) - 1:
            msg = "Google Safe Browsing compressed Rice parameters are invalid"
            raise ValueError(msg)
        values.append(previous)
    return values


def _ints_to_prefixes(values: Iterable[int]) -> list[bytes]:
    return [int(v).to_bytes(4, "big", signed=False) for v in values]


def _checksum_for_prefixes(prefixes: Sequence[bytes]) -> bytes:
    digest = hashlib.sha256()
    for prefix in sorted(prefixes):
        digest.update(prefix)
    return digest.digest()


def _enforceable_threat(
    details: object,
    allowed: set[str] | None = None,
) -> str:
    if not isinstance(details, list):
        return ""
    for detail in details:
        if not isinstance(detail, dict):
            continue
        threat = detail.get("threatType")
        attributes = detail.get("attributes", [])
        if not isinstance(threat, str) or not isinstance(attributes, list):
            continue
        if any(not isinstance(attribute, str) for attribute in attributes):
            continue
        attrs = set(attributes)
        if threat not in _VALID_THREAT_TYPES:
            continue
        if allowed is not None and threat not in allowed:
            continue
        # Unknown enum values are forward-compatible protocol data, but the v5
        # contract requires clients to disregard the enclosing detail until
        # they understand every attribute in it.
        if any(attribute not in _IGNORED_THREAT_ATTRIBUTES for attribute in attrs):
            continue
        if attrs & _IGNORED_THREAT_ATTRIBUTES:
            continue
        return threat
    return ""


def _threat_type_for_list(name: str) -> str:
    return SAFE_BROWSING_LISTS.get(
        (name or "").strip(),
        (name or "UNKNOWN").strip() or "UNKNOWN",
    )


def _threat_types_for_lists(names: Sequence[str]) -> set[str]:
    return {_threat_type_for_list(name) for name in names if name}


def _list_name_for_threat(names: Sequence[str], threat: str) -> str:
    for name in names:
        if _threat_type_for_list(name) == threat:
            return name
    return str(names[0]) if names else ""


@dataclass(frozen=True)
class SafeBrowsingSettings:
    enabled: bool
    api_key: str
    lists: tuple[str, ...]
    last_success: int
    last_attempt: int
    last_error: str
    next_run_ts: int


@dataclass(frozen=True)
class SafeBrowsingStatus:
    enabled: bool
    configured: bool
    lists: tuple[str, ...]
    list_count: int
    prefix_count: int
    cache_entries: int
    positive_cache_entries: int
    negative_cache_entries: int
    last_success: int
    last_attempt: int
    last_error: str
    next_run_ts: int


@dataclass(frozen=True)
class SafeBrowsingVerdict:
    verdict: str
    threat_type: str = ""
    list_name: str = ""
    cache_hit: bool = False
    reason: str = ""


class SafeBrowsingStore:
    _schema_ready = False
    _schema_lock = threading.Lock()

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._started = False
        self._pending_status: tuple[bool, str, int] | None = None

    def _connect(self):
        return connect()

    def init_db(self) -> None:
        if SafeBrowsingStore._schema_ready:
            return
        with SafeBrowsingStore._schema_lock:
            if SafeBrowsingStore._schema_ready:
                return
            with self._connect() as conn:
                try:
                    from services.schema_lifecycle import (
                        runtime_schema_ready_for_lazy_store,
                    )

                    if runtime_schema_ready_for_lazy_store(conn):
                        SafeBrowsingStore._schema_ready = True
                        return
                except Exception:
                    pass
                with mysql_advisory_lock(
                    conn,
                    "safe_browsing_v5:schema",
                    mysql_schema_lock_timeout_seconds(),
                ):
                    self.init_schema(conn)
            SafeBrowsingStore._schema_ready = True

    @staticmethod
    def init_schema(conn) -> None:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS safe_browsing_hash_lists("
            "name VARCHAR(32) PRIMARY KEY, version VARBINARY(255), threat_type VARCHAR(64) NOT NULL, "
            "last_success BIGINT NOT NULL DEFAULT 0, last_attempt BIGINT NOT NULL DEFAULT 0, "
            "last_error TEXT, next_run_ts BIGINT NOT NULL DEFAULT 0, prefix_count BIGINT NOT NULL DEFAULT 0)",
        )
        conn.execute(
            "CREATE TABLE IF NOT EXISTS safe_browsing_hash_prefixes("
            "list_name VARCHAR(32) NOT NULL, prefix VARBINARY(4) NOT NULL, "
            "PRIMARY KEY(list_name, prefix), KEY idx_safe_browsing_prefix(prefix))",
        )
        conn.execute(
            "CREATE TABLE IF NOT EXISTS safe_browsing_full_hash_cache("
            "prefix VARBINARY(4) NOT NULL, full_hash VARBINARY(32) NOT NULL, threat_type VARCHAR(64) NOT NULL, "
            "list_name VARCHAR(32) NOT NULL, expires_ts BIGINT NOT NULL, "
            "PRIMARY KEY(prefix, full_hash), KEY idx_safe_browsing_cache_expiry(expires_ts))",
        )
        conn.execute(
            "CREATE TABLE IF NOT EXISTS safe_browsing_negative_cache("
            "prefix VARBINARY(4) PRIMARY KEY, expires_ts BIGINT NOT NULL, "
            "KEY idx_safe_browsing_negative_expiry(expires_ts))",
        )
        SafeBrowsingStore._ensure_index(
            conn,
            "safe_browsing_full_hash_cache",
            "idx_safe_browsing_cache_expiry",
            "ALTER TABLE safe_browsing_full_hash_cache ADD INDEX idx_safe_browsing_cache_expiry (expires_ts)",
        )
        SafeBrowsingStore._ensure_index(
            conn,
            "safe_browsing_negative_cache",
            "idx_safe_browsing_negative_expiry",
            "ALTER TABLE safe_browsing_negative_cache ADD INDEX idx_safe_browsing_negative_expiry (expires_ts)",
        )
        SafeBrowsingStore._ensure_column(
            conn,
            "safe_browsing_hash_prefixes",
            "generation",
            "ALTER TABLE safe_browsing_hash_prefixes ADD COLUMN generation BIGINT NOT NULL DEFAULT 0",
        )
        SafeBrowsingStore._ensure_index(
            conn,
            "safe_browsing_hash_prefixes",
            "idx_safe_browsing_list_generation",
            "ALTER TABLE safe_browsing_hash_prefixes ADD INDEX idx_safe_browsing_list_generation (list_name, generation)",
        )

    @staticmethod
    def _ensure_index(conn, table_name: str, index_name: str, ddl: str) -> None:
        ensure_index(conn, table_name=table_name, index_name=index_name, ddl=ddl)

    @staticmethod
    def _ensure_column(conn, table_name: str, column_name: str, ddl: str) -> None:
        ensure_column(conn, table_name=table_name, column_name=column_name, ddl=ddl)

    @staticmethod
    def selected_lists(values: Sequence[str] | str | None) -> tuple[str, ...]:
        if isinstance(values, str):
            raw = values.replace("\n", ",").split(",")
        else:
            raw = list(values or [])
        out: list[str] = []
        for item in raw:
            name = (item or "").strip().lower()
            if name in SAFE_BROWSING_LISTS and name not in out:
                out.append(name)
        return tuple(out)

    @staticmethod
    def normalize_lists(values: Sequence[str] | str | None) -> tuple[str, ...]:
        out = SafeBrowsingStore.selected_lists(values)
        return tuple(out or DEFAULT_SAFE_BROWSING_LISTS)

    @staticmethod
    def settings_from_webfilter(conn, get_setting) -> SafeBrowsingSettings:
        return SafeBrowsingSettings(
            enabled=get_setting(conn, "safe_browsing_enabled", "0") == "1",
            api_key=get_setting(conn, "safe_browsing_api_key", ""),
            lists=SafeBrowsingStore.normalize_lists(
                get_setting(
                    conn,
                    "safe_browsing_lists",
                    ",".join(DEFAULT_SAFE_BROWSING_LISTS),
                ),
            ),
            last_success=int(get_setting(conn, "safe_browsing_last_success", "0") or 0),
            last_attempt=int(get_setting(conn, "safe_browsing_last_attempt", "0") or 0),
            last_error=get_setting(conn, "safe_browsing_last_error", ""),
            next_run_ts=int(get_setting(conn, "safe_browsing_next_run_ts", "0") or 0),
        )

    def _request_json(
        self,
        path: str,
        api_key: str,
        params: list[tuple[str, str]],
        timeout: int = 30,
    ) -> dict[str, object]:
        query = urllib.parse.urlencode([*params, ("key", api_key)], doseq=True)
        req = urllib.request.Request(
            f"{_API_BASE}{path}?{query}",
            headers={"Accept": "application/json"},
        )
        max_response_bytes = _env_int(
            "SAFE_BROWSING_MAX_RESPONSE_BYTES",
            64 * 1024 * 1024,
            minimum=1024,
            maximum=256 * 1024 * 1024,
        )
        with _open_safe_browsing_request(req, timeout=timeout) as resp:
            data = resp.read(max_response_bytes + 1)
        if len(data) > max_response_bytes:
            msg = (
                "Google Safe Browsing response exceeded "
                f"SAFE_BROWSING_MAX_RESPONSE_BYTES ({max_response_bytes} bytes)"
            )
            raise ValueError(msg)
        return json.loads(data.decode("utf-8")) if data else {}

    def update_lists(self, settings: SafeBrowsingSettings) -> tuple[bool, str, int]:
        if not settings.enabled:
            return True, "Safe Browsing disabled", 0
        if not settings.api_key:
            return False, "Google Safe Browsing API key is required", 3600
        self.init_db()
        _now()
        waits: list[int] = []
        try:
            requested_names = tuple(settings.lists)
            if len(requested_names) != len(set(requested_names)):
                msg = "Google Safe Browsing request contains duplicate hash list names"
                raise ValueError(msg)

            versions: dict[str, str] = {}
            with self._connect() as conn:
                for name in requested_names:
                    row = conn.execute(
                        "SELECT version FROM safe_browsing_hash_lists WHERE name=%s",
                        (name,),
                    ).fetchone()
                    if row and row[0]:
                        version = row[0]
                        if isinstance(version, bytes):
                            version = _urlsafe_b64(version)
                        versions[name] = str(version)
            params: list[tuple[str, str]] = [
                ("names", name) for name in requested_names
            ]
            params.extend(("version", version) for version in versions.values())
            response = self._request_json(
                "/hashLists:batchGet",
                settings.api_key,
                params,
                timeout=120,
            )
            if not isinstance(response, dict):
                msg = "Google Safe Browsing batch response must be an object"
                raise ValueError(msg)
            items = response.get("hashLists")
            if not isinstance(items, list):
                msg = "Google Safe Browsing batch response hashLists must be an array"
                raise ValueError(msg)

            response_names: list[str] = []
            for item in items:
                if not isinstance(item, dict):
                    msg = "Google Safe Browsing batch hashLists entries must be objects"
                    raise ValueError(msg)
                name = item.get("name")
                if not isinstance(name, str) or not name:
                    msg = "Google Safe Browsing batch hash list name must be a string"
                    raise ValueError(msg)
                response_names.append(name)

            if len(response_names) != len(set(response_names)):
                msg = "Google Safe Browsing batch response contains duplicate names"
                raise ValueError(msg)
            if any(name not in requested_names for name in response_names):
                msg = "Google Safe Browsing batch response contains an unexpected name"
                raise ValueError(msg)
            if any(name not in response_names for name in requested_names):
                msg = "Google Safe Browsing batch response omitted a requested name"
                raise ValueError(msg)
            if tuple(response_names) != requested_names:
                msg = "Google Safe Browsing batch response order does not match the request"
                raise ValueError(msg)

            with self._connect() as conn:
                for item in items:
                    self._apply_hash_list(conn, item)
                    waits.append(
                        parse_duration_seconds(
                            item.get("minimumWaitDuration"),
                            default=0,
                        ),
                    )
                # Each wait applies to fetching its hash list again. Because the
                # next request refreshes every selected list, its batch schedule
                # must honor the strictest per-list minimum. Omitted/zero waits
                # intentionally permit an immediate follow-up update.
                return True, "", max(waits, default=0)
        except Exception as exc:
            return (
                False,
                public_error_message(
                    exc,
                    default="Google Safe Browsing list update failed.",
                    max_len=500,
                ),
                1800,
            )

    def status(self, settings: SafeBrowsingSettings) -> SafeBrowsingStatus:
        selected = self.normalize_lists(settings.lists)
        try:
            self.init_db()
            now = _now()
            placeholders = ",".join(["%s"] * len(selected))
            with self._connect() as conn:
                list_count = int(
                    conn.execute(
                        f"SELECT COUNT(*) FROM safe_browsing_hash_lists WHERE name IN ({placeholders})",
                        selected,
                    ).fetchone()[0]
                    or 0,
                )
                prefix_count = int(
                    conn.execute(
                        f"SELECT COUNT(*) FROM safe_browsing_hash_prefixes WHERE list_name IN ({placeholders})",
                        selected,
                    ).fetchone()[0]
                    or 0,
                )
                positive_cache = int(
                    conn.execute(
                        "SELECT COUNT(*) FROM safe_browsing_full_hash_cache "
                        f"WHERE expires_ts >= %s AND list_name IN ({placeholders})",
                        (now, *selected),
                    ).fetchone()[0]
                    or 0,
                )
                negative_cache = int(
                    conn.execute(
                        "SELECT COUNT(*) FROM safe_browsing_negative_cache WHERE expires_ts >= %s",
                        (now,),
                    ).fetchone()[0]
                    or 0,
                )
            return SafeBrowsingStatus(
                enabled=settings.enabled,
                configured=bool(settings.api_key),
                lists=selected,
                list_count=list_count,
                prefix_count=prefix_count,
                cache_entries=positive_cache + negative_cache,
                positive_cache_entries=positive_cache,
                negative_cache_entries=negative_cache,
                last_success=settings.last_success,
                last_attempt=settings.last_attempt,
                last_error=settings.last_error,
                next_run_ts=settings.next_run_ts,
            )
        except Exception as exc:
            return SafeBrowsingStatus(
                enabled=settings.enabled,
                configured=bool(settings.api_key),
                lists=selected,
                list_count=0,
                prefix_count=0,
                cache_entries=0,
                positive_cache_entries=0,
                negative_cache_entries=0,
                last_success=settings.last_success,
                last_attempt=settings.last_attempt,
                last_error=settings.last_error
                or public_error_message(
                    exc,
                    default="Safe Browsing status unavailable.",
                    max_len=300,
                ),
                next_run_ts=settings.next_run_ts,
            )

    def _apply_hash_list(self, conn, item: dict[str, object]) -> None:
        name = str(item.get("name") or "").strip()
        if name not in SAFE_BROWSING_LISTS:
            return
        removals_payload = item.get("compressedRemovals")
        additions_payload = item.get("additionsFourBytes")
        if removals_payload is not None and not isinstance(removals_payload, dict):
            msg = "Google Safe Browsing compressed Rice parameters are invalid"
            raise ValueError(msg)
        if additions_payload is not None and not isinstance(additions_payload, dict):
            msg = "Google Safe Browsing compressed Rice parameters are invalid"
            raise ValueError(msg)
        removals = decode_rice_delta_32(removals_payload)
        addition_values = decode_rice_delta_32(additions_payload)
        checksum = _decode_b64(item.get("sha256Checksum"), field="sha256Checksum")
        if checksum and len(checksum) != hashlib.sha256().digest_size:
            msg = "Google Safe Browsing sha256Checksum must decode to exactly 32 bytes"
            raise ValueError(msg)
        version = _decode_b64(item.get("version"), field="version")
        self.init_schema(conn)
        partial = bool(item.get("partialUpdate"))
        current = [
            bytes(row[0])
            for row in conn.execute(
                "SELECT prefix FROM safe_browsing_hash_prefixes WHERE list_name=%s ORDER BY prefix ASC",
                (name,),
            ).fetchall()
        ]
        if not partial:
            current = []
        batch_size = _env_int(
            "SAFE_BROWSING_PREFIX_WRITE_BATCH_SIZE",
            5000,
            minimum=100,
            maximum=50000,
        )

        def require_full_refresh(reason: str) -> None:
            while True:
                result = conn.execute(
                    "DELETE FROM safe_browsing_hash_prefixes WHERE list_name=%s ORDER BY prefix ASC LIMIT %s",
                    (name, batch_size),
                )
                if int(getattr(result, "rowcount", 0) or 0) < batch_size:
                    break
            conn.execute("DELETE FROM safe_browsing_hash_lists WHERE name=%s", (name,))
            with contextlib.suppress(Exception):
                conn.commit()
            msg = f"Google Safe Browsing {reason} for {name}; full refresh required"
            raise ValueError(msg)

        if len(removals) != len(set(removals)):
            require_full_refresh("removal indices contain duplicates")
        if any(index < 0 or index >= len(current) for index in removals):
            require_full_refresh("removal index is out of range")
        removed_prefixes: list[bytes] = []
        for index in sorted(removals, reverse=True):
            removed_prefixes.append(current[index])
            del current[index]
        additions = _ints_to_prefixes(addition_values)
        merged = sorted(set(current).union(additions))
        if checksum and _checksum_for_prefixes(merged) != checksum:
            # The v5 local database spec requires a full refresh whenever the
            # post-update checksum disagrees. Drop local state/version for this
            # list so the next scheduler pass requests a complete replacement.
            require_full_refresh("checksum mismatch")
        now = _now()
        generation = int(time.time_ns())

        def upsert_prefixes(prefixes: Sequence[bytes]) -> None:
            if not prefixes:
                return
            rows = [(name, prefix, generation) for prefix in prefixes]
            for index in range(0, len(rows), batch_size):
                conn.executemany(
                    "INSERT INTO safe_browsing_hash_prefixes(list_name, prefix, generation) VALUES(%s,%s,%s) AS incoming "
                    "ON DUPLICATE KEY UPDATE generation=incoming.generation",
                    rows[index : index + batch_size],
                )

        if partial:
            for index in range(0, len(removed_prefixes), batch_size):
                batch = removed_prefixes[index : index + batch_size]
                placeholders = ",".join(["%s"] * len(batch))
                conn.execute(
                    f"DELETE FROM safe_browsing_hash_prefixes WHERE list_name=%s AND prefix IN ({placeholders})",
                    (name, *batch),
                )
            upsert_prefixes(sorted(set(additions)))
        else:
            upsert_prefixes(merged)
            while True:
                result = conn.execute(
                    "DELETE FROM safe_browsing_hash_prefixes WHERE list_name=%s AND generation <> %s ORDER BY prefix ASC LIMIT %s",
                    (name, generation, batch_size),
                )
                if int(getattr(result, "rowcount", 0) or 0) < batch_size:
                    break
        conn.execute(
            "INSERT INTO safe_browsing_hash_lists(name, version, threat_type, last_success, last_attempt, last_error, next_run_ts, prefix_count) "
            "VALUES(%s,%s,%s,%s,%s,%s,%s,%s) AS incoming ON DUPLICATE KEY UPDATE version=incoming.version, threat_type=incoming.threat_type, "
            "last_success=incoming.last_success, last_attempt=incoming.last_attempt, last_error='', prefix_count=incoming.prefix_count",
            (name, version, _threat_type_for_list(name), now, now, "", 0, len(merged)),
        )

    def search_hashes(
        self,
        api_key: str,
        prefixes: Sequence[bytes],
    ) -> tuple[list[dict[str, object]], int]:
        if not api_key or not prefixes:
            return [], 0
        requested_prefixes = tuple(prefixes[:30])
        if any(
            not isinstance(prefix, bytes) or len(prefix) != 4
            for prefix in requested_prefixes
        ):
            msg = "Google Safe Browsing hash search request prefixes must be 4 bytes"
            raise ValueError(msg)
        params = [
            ("hashPrefixes", _urlsafe_b64(prefix)) for prefix in requested_prefixes
        ]
        response = self._request_json("/hashes:search", api_key, params, timeout=8)
        if not isinstance(response, dict):
            msg = "Google Safe Browsing hash search response must be an object"
            raise ValueError(msg)
        items = response.get("fullHashes", [])
        if not isinstance(items, list):
            msg = (
                "Google Safe Browsing hash search response fullHashes must be an array"
            )
            raise ValueError(msg)

        details_by_hash: dict[bytes, list[dict[str, object]]] = {}
        normalized_items: list[dict[str, object]] = []
        for item in items:
            if not isinstance(item, dict):
                msg = "Google Safe Browsing hash search fullHashes entries must be objects"
                raise ValueError(msg)
            full_hash = _decode_search_full_hash(item.get("fullHash"))
            if not any(full_hash.startswith(prefix) for prefix in requested_prefixes):
                msg = "Google Safe Browsing hash search returned an unrequested prefix"
                raise ValueError(msg)
            details = item.get("fullHashDetails", [])
            if not isinstance(details, list):
                msg = (
                    "Google Safe Browsing hash search fullHashDetails must be an array"
                )
                raise ValueError(msg)
            normalized_details: list[dict[str, object]] = []
            for detail in details:
                if not isinstance(detail, dict):
                    msg = "Google Safe Browsing hash search details must be objects"
                    raise ValueError(msg)
                threat = detail.get("threatType")
                if not isinstance(threat, str) or not threat:
                    msg = "Google Safe Browsing hash search threatType must be a string"
                    raise ValueError(msg)
                attributes = detail.get("attributes", [])
                if not isinstance(attributes, list) or any(
                    not isinstance(attribute, str) for attribute in attributes
                ):
                    msg = "Google Safe Browsing hash search attributes must be strings"
                    raise ValueError(msg)
                normalized_detail: dict[str, object] = {"threatType": threat}
                if attributes:
                    normalized_detail["attributes"] = list(attributes)
                if normalized_detail not in normalized_details:
                    normalized_details.append(normalized_detail)

            existing_details = details_by_hash.get(full_hash)
            if existing_details is not None:
                existing_details.extend(
                    detail
                    for detail in normalized_details
                    if detail not in existing_details
                )
                continue
            normalized_item = {
                "fullHash": _urlsafe_b64(full_hash),
                "fullHashDetails": normalized_details,
            }
            details_by_hash[full_hash] = normalized_details
            normalized_items.append(normalized_item)

        cache_duration = response.get("cacheDuration")
        if cache_duration is not None and (
            not isinstance(cache_duration, str)
            or re.fullmatch(r"\d+(?:\.\d{1,9})?s", cache_duration) is None
        ):
            msg = "Google Safe Browsing hash search cacheDuration is invalid"
            raise ValueError(msg)
        return normalized_items, parse_duration_seconds(cache_duration, default=300)

    def start_background(self, get_settings, set_status) -> None:
        with self._lock:
            if self._started:
                return
            self._stop_event.clear()
            thread = threading.Thread(
                target=self._loop,
                args=(get_settings, set_status),
                name="safe-browsing-updater",
                daemon=True,
            )
            self._thread = thread
            self._started = True
            try:
                thread.start()
            except Exception:
                self._thread = None
                self._started = False
                raise

    def stop_background(self, *, timeout: float = 5.0) -> bool:
        with self._lock:
            self._stop_event.set()
            thread = self._thread
        if thread is not None:
            thread.join(max(0.0, timeout))
        stopped = thread is None or not thread.is_alive()
        if stopped:
            with self._lock:
                if self._thread is thread:
                    self._thread = None
                    self._started = False
        return stopped

    def _persist_updater_status(
        self, set_status, status: tuple[bool, str, int]
    ) -> None:
        self._pending_status = status
        set_status(*status)
        self._pending_status = None

    def _run_updater_once(self, get_settings, set_status) -> None:
        if self._pending_status is not None:
            self._persist_updater_status(set_status, self._pending_status)

        settings = get_settings()
        now = _now()
        if not (
            settings.enabled
            and settings.api_key
            and (settings.next_run_ts <= 0 or now >= settings.next_run_ts)
        ):
            return

        failure_wait = 1800
        # Persist the attempt and a retry floor before provider/database work.
        # If final status persistence fails, this durable reservation prevents
        # every scheduler poll from repeating the provider request.
        self._persist_updater_status(
            set_status,
            (False, settings.last_error, now + failure_wait),
        )
        try:
            ok, err, wait = self.update_lists(settings)
        except Exception as exc:
            ok = False
            err = public_error_message(
                exc,
                default="Google Safe Browsing list update failed.",
                max_len=500,
            )
            wait = failure_wait
        finished_at = _now()
        self._persist_updater_status(
            set_status,
            (ok, err, finished_at + max(60, int(wait or failure_wait))),
        )

    def _loop(self, get_settings, set_status) -> None:
        poll = _env_int("SAFE_BROWSING_POLL_SECONDS", 300, minimum=30, maximum=3600)
        while not self._stop_event.is_set():
            try:
                self._run_updater_once(get_settings, set_status)
            except DATABASE_ERRORS as exc:
                log_database_unavailable(
                    logger,
                    "safe_browsing.loop.db_unavailable",
                    "Safe Browsing updater deferred database work while MySQL is unavailable",
                    exc,
                )
            except Exception:
                pass
            self._stop_event.wait(poll)


class SafeBrowsingLocalChecker:
    def __init__(
        self,
        *,
        api_key: str = "",
        prefix_hit_ttl_seconds: int | None = None,
        prefix_miss_ttl_seconds: int | None = None,
        cache_max_entries: int | None = None,
        selected_lists: Sequence[str] | str | None = None,
        selected_lists_ttl_seconds: int | None = None,
    ) -> None:
        self.api_key = api_key
        self._conn = None
        self._store = SafeBrowsingStore()
        self._prefix_cache: dict[
            tuple[bytes, tuple[str, ...]], tuple[float, tuple[str, ...]]
        ] = {}
        self._verdict_cache: dict[
            tuple[str, tuple[str, ...]], tuple[float, SafeBrowsingVerdict]
        ] = {}
        self._list_version_state: tuple[tuple[str, bytes | None], ...] | None = None
        self._list_version_state_verified = False
        # Prevent an old concurrent lookup from repopulating helper caches after
        # another lookup observes a newly committed hash-list version.
        self._local_cache_generation = 0
        self._local_cache_lock = threading.RLock()
        self._cache_max = cache_max_entries or _env_int(
            "SAFE_BROWSING_HELPER_CACHE_ENTRIES",
            200000,
            minimum=1000,
            maximum=1000000,
        )
        self._prefix_hit_ttl = (
            int(prefix_hit_ttl_seconds)
            if prefix_hit_ttl_seconds is not None
            else _env_int(
                "SAFE_BROWSING_HELPER_PREFIX_HIT_TTL_SECONDS",
                3600,
                minimum=60,
                maximum=86400,
            )
        )
        self._prefix_miss_ttl = (
            int(prefix_miss_ttl_seconds)
            if prefix_miss_ttl_seconds is not None
            else _env_int(
                "SAFE_BROWSING_HELPER_PREFIX_MISS_TTL_SECONDS",
                60,
                minimum=5,
                maximum=3600,
            )
        )
        self._configured_selected_lists = (
            SafeBrowsingStore.normalize_lists(selected_lists)
            if selected_lists is not None
            else None
        )
        self._selected_lists_cache: tuple[float, tuple[str, ...]] | None = None
        self._selected_lists_ttl = (
            int(selected_lists_ttl_seconds)
            if selected_lists_ttl_seconds is not None
            else _env_int(
                "SAFE_BROWSING_SELECTED_LISTS_TTL_SECONDS",
                60,
                minimum=5,
                maximum=3600,
            )
        )

    def _connect(self):
        conn = connect()
        try:
            SafeBrowsingStore.init_schema(conn)
        except Exception:
            with contextlib.suppress(Exception):
                conn.close()
            raise
        return conn

    def close(self) -> None:
        conn = self._conn
        self._conn = None
        if conn is not None:
            with contextlib.suppress(Exception):
                conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.close()
        return False

    def _api_key_from_settings(self) -> str:
        if self.api_key:
            return self.api_key
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT v FROM webfilter_settings WHERE proxy_id=%s AND k=%s",
                    ("__global__", "safe_browsing_api_key"),
                ).fetchone()
            return str(row[0] or "") if row else ""
        except Exception:
            self.close()
            return ""

    def _selected_lists_for_lookup(self) -> tuple[str, ...]:
        if self._configured_selected_lists is not None:
            return self._configured_selected_lists
        with self._local_cache_lock:
            now_mono = time.monotonic()
            cached = self._selected_lists_cache
            if cached and cached[0] > now_mono:
                return cached[1]
            lists = SafeBrowsingStore.normalize_lists(None)
            try:
                with self._connect() as conn:
                    row = conn.execute(
                        "SELECT v FROM webfilter_settings WHERE proxy_id=%s AND k=%s",
                        ("__global__", "safe_browsing_lists"),
                    ).fetchone()
                if row and row[0] is not None:
                    lists = SafeBrowsingStore.normalize_lists(str(row[0] or ""))
            except Exception:
                self.close()
                if cached:
                    lists = cached[1]
            self._selected_lists_cache = (now_mono + self._selected_lists_ttl, lists)
            return lists

    def _list_versions_for_lookup(
        self,
        selected_lists: tuple[str, ...],
    ) -> tuple[tuple[str, bytes | None], ...] | None:
        try:
            placeholders = ",".join(["%s"] * len(selected_lists))
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT name, version FROM safe_browsing_hash_lists "
                    f"WHERE name IN ({placeholders})",
                    selected_lists,
                ).fetchall()
            versions: dict[str, bytes] = {}
            for row in rows:
                if not row or not row[0]:
                    continue
                value = row[1]
                if isinstance(value, bytes):
                    version = value
                elif isinstance(value, memoryview):
                    version = value.tobytes()
                else:
                    version = str(value or "").encode("utf-8")
                versions[str(row[0])] = version
            return tuple((name, versions.get(name)) for name in selected_lists)
        except Exception:
            self.close()
            return None

    def _synchronize_local_cache_versions(
        self,
        selected_lists: tuple[str, ...],
    ) -> int:
        # The updater commits each hash-list version with its prefix mutation.
        # Only helper-local caches depend on that snapshot; Google's persistent
        # full-hash cache remains valid until its provider-supplied expiration.
        with self._local_cache_lock:
            current = self._list_versions_for_lookup(selected_lists)
            if (
                current is None
                or not self._list_version_state_verified
                or current != self._list_version_state
            ):
                self._prefix_cache.clear()
                self._verdict_cache.clear()
                self._local_cache_generation += 1
            if current is None:
                self._list_version_state = None
                self._list_version_state_verified = False
                return self._local_cache_generation
            self._list_version_state = current
            self._list_version_state_verified = True
            return self._local_cache_generation

    def _local_lists_for_prefix(self, prefix: bytes) -> tuple[str, ...]:
        selected_lists = self._selected_lists_for_lookup()
        cache_key = (prefix, selected_lists)
        now_mono = time.monotonic()
        with self._local_cache_lock:
            cache_generation = self._local_cache_generation
            cached = self._prefix_cache.get(cache_key)
            if cached and cached[0] > now_mono:
                return cached[1]
        try:
            placeholders = ",".join(["%s"] * len(selected_lists))
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT list_name FROM safe_browsing_hash_prefixes "
                    f"WHERE prefix=%s AND list_name IN ({placeholders})",
                    (prefix, *selected_lists),
                ).fetchall()
            lists = tuple(str(row[0]) for row in rows if row and row[0])
        except Exception:
            self.close()
            lists = ()
        ttl = self._prefix_hit_ttl if lists else self._prefix_miss_ttl
        with self._local_cache_lock:
            if cache_generation == self._local_cache_generation:
                self._prefix_cache[cache_key] = (now_mono + ttl, lists)
                if len(self._prefix_cache) > self._cache_max:
                    self._prefix_cache.clear()
        return lists

    def _cache_lookup(
        self,
        prefix: bytes,
        full_hashes: set[bytes],
        local_lists: Sequence[str] | None = None,
    ) -> SafeBrowsingVerdict | None:
        now = _now()
        try:
            with self._connect() as conn:
                params: tuple[object, ...] = (prefix, now)
                list_filter = ""
                if local_lists:
                    lists = SafeBrowsingStore.normalize_lists(local_lists)
                    if lists:
                        placeholders = ",".join(["%s"] * len(lists))
                        list_filter = f" AND list_name IN ({placeholders})"
                        params = (prefix, now, *lists)
                rows = conn.execute(
                    "SELECT full_hash, threat_type, list_name "
                    "FROM safe_browsing_full_hash_cache "
                    "WHERE prefix=%s AND expires_ts >= %s"
                    f"{list_filter}",
                    params,
                ).fetchall()
                for row in rows:
                    if bytes(row[0]) in full_hashes:
                        return SafeBrowsingVerdict(
                            "unsafe",
                            str(row[1] or ""),
                            str(row[2] or ""),
                            True,
                            "cached full-hash match",
                        )
                # Do not use persistent negative prefix cache for verdicts. The
                # legacy table is keyed only by prefix, while selected Safe
                # Browsing lists are mutable. A miss for one list set must not
                # suppress full-hash confirmation after operators enable another
                # list that happens to share the same 4-byte prefix.
        except Exception:
            self.close()
            return None
        return None

    def _cache_search_response(
        self,
        prefix: bytes,
        response: Sequence[object],
        cache_duration: int,
        local_lists: Sequence[str] | None = None,
    ) -> None:
        expires = _now() + max(60, min(24 * 60 * 60, int(cache_duration or 300)))
        try:
            with self._connect() as conn:
                seen_hashes: set[bytes] = set()
                for item in response:
                    if not isinstance(item, dict):
                        continue
                    try:
                        full = _decode_search_full_hash(item.get("fullHash"))
                    except ValueError:
                        continue
                    if not full.startswith(prefix) or full in seen_hashes:
                        continue
                    threat = _enforceable_threat(
                        item.get("fullHashDetails") or [],
                        allowed=_threat_types_for_lists(local_lists)
                        if local_lists
                        else None,
                    )
                    if not threat:
                        continue
                    seen_hashes.add(full)
                    list_name = _list_name_for_threat(local_lists or (), threat)
                    conn.execute(
                        "INSERT INTO safe_browsing_full_hash_cache(prefix, full_hash, threat_type, list_name, expires_ts) VALUES(%s,%s,%s,%s,%s) AS incoming "
                        "ON DUPLICATE KEY UPDATE threat_type=incoming.threat_type, list_name=incoming.list_name, expires_ts=incoming.expires_ts",
                        (prefix, full, threat, list_name, expires),
                    )
        except Exception:
            self.close()

    def _cache_verdict(
        self,
        key: tuple[str, tuple[str, ...]],
        verdict: SafeBrowsingVerdict,
        cache_generation: int | None = None,
    ) -> None:
        with self._local_cache_lock:
            if (
                cache_generation is not None
                and cache_generation != self._local_cache_generation
            ):
                return
            self._verdict_cache[key] = (time.monotonic() + 300, verdict)
            if len(self._verdict_cache) > self._cache_max:
                self._verdict_cache.clear()

    def check_url(self, url: str) -> SafeBrowsingVerdict:
        canonical = canonicalize_url(url)
        if not canonical:
            return SafeBrowsingVerdict("safe", reason="invalid or empty url")
        selected_lists = self._selected_lists_for_lookup()
        cache_generation = self._synchronize_local_cache_versions(selected_lists)
        cache_key = (canonical, selected_lists)
        with self._local_cache_lock:
            cached = self._verdict_cache.get(cache_key)
            if (
                cache_generation == self._local_cache_generation
                and cached
                and cached[0] > time.monotonic()
            ):
                return cached[1]
        hashes = expression_hashes(canonical)
        full_set = set(hashes)
        saw_local_match = False
        cache_final_verdict = True
        last_safe_verdict = SafeBrowsingVerdict(
            "safe",
            reason="no local hash-prefix match",
        )
        for full_hash in hashes:
            prefix = full_hash[:4]
            local_lists = self._local_lists_for_prefix(prefix)
            if not local_lists:
                continue
            local_threat_types = _threat_types_for_lists(local_lists)
            saw_local_match = True
            cached_verdict = self._cache_lookup(prefix, full_set, local_lists)
            if cached_verdict is not None:
                if (
                    cached_verdict.verdict == "unsafe"
                    and cached_verdict.threat_type not in local_threat_types
                ):
                    cached_verdict = None
                else:
                    verdict = cached_verdict
            if cached_verdict is None:
                api_key = self._api_key_from_settings()
                if not api_key:
                    cache_final_verdict = False
                    verdict = SafeBrowsingVerdict(
                        "safe",
                        reason="api key unavailable for full-hash confirmation",
                    )
                else:
                    try:
                        response, duration = self._store.search_hashes(
                            api_key, [prefix]
                        )
                    except Exception:
                        self.close()
                        cache_final_verdict = False
                        verdict = SafeBrowsingVerdict(
                            "safe",
                            reason="full-hash confirmation unavailable",
                        )
                        last_safe_verdict = verdict
                        continue
                    self._cache_search_response(prefix, response, duration, local_lists)
                    verdict = SafeBrowsingVerdict(
                        "safe",
                        reason="full hash not returned",
                    )
                    for item in response:
                        if not isinstance(item, dict):
                            continue
                        try:
                            returned = _decode_search_full_hash(item.get("fullHash"))
                        except ValueError:
                            continue
                        if returned.startswith(prefix) and returned in full_set:
                            threat = _enforceable_threat(
                                item.get("fullHashDetails") or [],
                                allowed=local_threat_types,
                            )
                            if not threat or threat not in local_threat_types:
                                continue
                            verdict = SafeBrowsingVerdict(
                                "unsafe",
                                threat,
                                _list_name_for_threat(local_lists, threat),
                                False,
                                "confirmed by hashes.search",
                            )
                            break
            if verdict.verdict == "unsafe":
                self._cache_verdict(cache_key, verdict, cache_generation)
                return verdict
            last_safe_verdict = verdict
        verdict = (
            last_safe_verdict
            if saw_local_match
            else SafeBrowsingVerdict("safe", reason="no local hash-prefix match")
        )
        if not saw_local_match:
            cache_final_verdict = False
        if cache_final_verdict:
            self._cache_verdict(cache_key, verdict, cache_generation)
        return verdict
