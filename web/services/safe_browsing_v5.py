from __future__ import annotations

import base64
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

from services.db import DATABASE_ERRORS, connect
from services.domain_normalization import normalize_domain as _norm_domain
from services.errors import public_error_message
from services.logutil import log_database_unavailable
from services.runtime_helpers import env_int as _env_int
from services.runtime_helpers import now_ts as _now

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


def _decode_b64(text: object) -> bytes:
    raw = str(text or "").strip()
    if not raw:
        return b""
    raw += "=" * (-len(raw) % 4)
    return base64.urlsafe_b64decode(raw.encode("ascii"))


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
    raw = urllib.parse.urldefrag(raw)[0]
    raw = _recursive_unquote(raw)
    if "://" not in raw:
        raw = "http://" + raw
    parsed = urllib.parse.urlsplit(raw)
    scheme = (parsed.scheme or "http").lower()
    host = _normalize_host(
        parsed.hostname or parsed.netloc.split("@")[-1].split(":")[0],
    )
    if not host:
        return ""
    path = _canonical_path(parsed.path or "/")
    query = _escape_safe_browsing_component(
        _recursive_unquote(parsed.query or ""),
        safe="=&?/:;+,$-_.!~*'()@",
    )
    # Safe Browsing expression generation discards scheme, credentials, and port;
    # the canonical URL keeps only host/path/query for stable hashing input.
    return urllib.parse.urlunsplit((scheme, host, path, query, ""))


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
            return 0
        value = (self.data[self.bit // 8] >> (self.bit % 8)) & 1
        self.bit += 1
        return value

    def read_bits(self, count: int) -> int:
        value = 0
        for i in range(int(count)):
            value |= self.read_bit() << i
        return value


def decode_rice_delta_32(payload: dict[str, object] | None) -> list[int]:
    if not payload:
        return []
    first = int(payload.get("firstValue") or 0)
    count = int(payload.get("entriesCount") or 0)
    rice = int(payload.get("riceParameter") or 0)
    if count <= 0:
        return [first]
    reader = _BitReader(_decode_b64(payload.get("encodedData")))
    values = [first]
    previous = first
    for _ in range(count):
        quotient = 0
        while reader.read_bit() == 1:
            quotient += 1
        remainder = reader.read_bits(rice)
        delta = (quotient << rice) + remainder
        previous += delta
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
    fallback: str = "",
    allowed: set[str] | None = None,
) -> str:
    if not isinstance(details, list):
        if fallback in _VALID_THREAT_TYPES and (allowed is None or fallback in allowed):
            return fallback
        return ""
    for detail in details:
        if not isinstance(detail, dict):
            continue
        threat = str(detail.get("threatType") or "")
        attrs = {str(a or "") for a in (detail.get("attributes") or [])}
        if threat not in _VALID_THREAT_TYPES:
            continue
        if allowed is not None and threat not in allowed:
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
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._started = False

    def _connect(self):
        return connect()

    def init_db(self) -> None:
        with self._connect() as conn:
            self.init_schema(conn)

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
            "prefix VARBINARY(4) PRIMARY KEY, expires_ts BIGINT NOT NULL)",
        )

    @staticmethod
    def normalize_lists(values: Sequence[str] | str | None) -> tuple[str, ...]:
        if isinstance(values, str):
            raw = values.replace("\n", ",").split(",")
        else:
            raw = list(values or [])
        out: list[str] = []
        for item in raw:
            name = (item or "").strip().lower()
            if name in SAFE_BROWSING_LISTS and name not in out:
                out.append(name)
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
        with urllib.request.urlopen(req, timeout=timeout) as resp:
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
        min_wait = 24 * 60 * 60
        try:
            versions: dict[str, str] = {}
            with self._connect() as conn:
                for name in settings.lists:
                    row = conn.execute(
                        "SELECT version FROM safe_browsing_hash_lists WHERE name=%s",
                        (name,),
                    ).fetchone()
                    if row and row[0]:
                        version = row[0]
                        if isinstance(version, bytes):
                            version = _urlsafe_b64(version)
                        versions[name] = str(version)
            params: list[tuple[str, str]] = [("names", name) for name in settings.lists]
            params.extend(("version", version) for version in versions.values())
            response = self._request_json(
                "/hashLists:batchGet",
                settings.api_key,
                params,
                timeout=120,
            )
            with self._connect() as conn:
                for item in response.get("hashLists", []) or []:
                    if not isinstance(item, dict):
                        continue
                    self._apply_hash_list(conn, item)
                    wait = parse_duration_seconds(
                        item.get("minimumWaitDuration"),
                        default=24 * 60 * 60,
                    )
                    if wait > 0:
                        min_wait = min(min_wait, wait)
                return True, "", min_wait
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
                        "SELECT COUNT(*) FROM safe_browsing_full_hash_cache WHERE expires_ts >= %s",
                        (now,),
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
        removals = sorted(
            decode_rice_delta_32(
                item.get("compressedRemovals")
                if isinstance(item.get("compressedRemovals"), dict)
                else None,
            ),
            reverse=True,
        )
        for index in removals:
            if 0 <= index < len(current):
                del current[index]
        additions_payload = item.get("additionsFourBytes")
        additions = _ints_to_prefixes(
            decode_rice_delta_32(
                additions_payload if isinstance(additions_payload, dict) else None,
            ),
        )
        merged = sorted(set(current).union(additions))
        checksum = _decode_b64(item.get("sha256Checksum"))
        if checksum and _checksum_for_prefixes(merged) != checksum:
            # The v5 local database spec requires a full refresh whenever the
            # post-update checksum disagrees. Drop local state/version for this
            # list so the next scheduler pass requests a complete replacement.
            conn.execute(
                "DELETE FROM safe_browsing_hash_prefixes WHERE list_name=%s",
                (name,),
            )
            conn.execute("DELETE FROM safe_browsing_hash_lists WHERE name=%s", (name,))
            msg = f"Google Safe Browsing checksum mismatch for {name}; full refresh required"
            raise ValueError(msg)
        conn.execute(
            "DELETE FROM safe_browsing_hash_prefixes WHERE list_name=%s",
            (name,),
        )
        if merged:
            conn.executemany(
                "INSERT IGNORE INTO safe_browsing_hash_prefixes(list_name, prefix) VALUES(%s,%s)",
                [(name, p) for p in merged],
            )
        version = _decode_b64(item.get("version"))
        now = _now()
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
        params = [("hashPrefixes", _urlsafe_b64(prefix)) for prefix in prefixes[:30]]
        response = self._request_json("/hashes:search", api_key, params, timeout=8)
        return list(response.get("fullHashes", []) or []), parse_duration_seconds(
            response.get("cacheDuration"),
            default=300,
        )

    def start_background(self, get_settings, set_status) -> None:
        with self._lock:
            if self._started:
                return
            thread = threading.Thread(
                target=self._loop,
                args=(get_settings, set_status),
                name="safe-browsing-updater",
                daemon=True,
            )
            thread.start()
            self._started = True

    def _loop(self, get_settings, set_status) -> None:
        poll = _env_int("SAFE_BROWSING_POLL_SECONDS", 300, minimum=30, maximum=3600)
        while True:
            try:
                settings = get_settings()
                now = _now()
                if (
                    settings.enabled
                    and settings.api_key
                    and (settings.next_run_ts <= 0 or now >= settings.next_run_ts)
                ):
                    ok, err, wait = self.update_lists(settings)
                    set_status(ok, err, now + max(60, int(wait or 1800)))
            except DATABASE_ERRORS as exc:
                log_database_unavailable(
                    logger,
                    "safe_browsing.loop.db_unavailable",
                    "Safe Browsing updater deferred database work while MySQL is unavailable",
                    exc,
                )
            except Exception:
                pass
            time.sleep(poll)


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

    def _local_lists_for_prefix(self, prefix: bytes) -> tuple[str, ...]:
        selected_lists = self._selected_lists_for_lookup()
        cache_key = (prefix, selected_lists)
        cached = self._prefix_cache.get(cache_key)
        now_mono = time.monotonic()
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
                conn.execute(
                    "DELETE FROM safe_browsing_full_hash_cache WHERE expires_ts < %s",
                    (now,),
                )
                conn.execute(
                    "DELETE FROM safe_browsing_negative_cache WHERE expires_ts < %s",
                    (now,),
                )
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
        response: Sequence[dict[str, object]],
        cache_duration: int,
        local_lists: Sequence[str] | None = None,
    ) -> None:
        expires = _now() + max(60, min(24 * 60 * 60, int(cache_duration or 300)))
        try:
            with self._connect() as conn:
                for item in response:
                    full = _decode_b64(item.get("fullHash"))
                    if len(full) != 32:
                        continue
                    threat = _enforceable_threat(
                        item.get("fullHashDetails") or [],
                        allowed=_threat_types_for_lists(local_lists)
                        if local_lists
                        else None,
                    )
                    if not threat:
                        continue
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
    ) -> None:
        self._verdict_cache[key] = (time.monotonic() + 300, verdict)
        if len(self._verdict_cache) > self._cache_max:
            self._verdict_cache.clear()

    def check_url(self, url: str) -> SafeBrowsingVerdict:
        canonical = canonicalize_url(url)
        if not canonical:
            return SafeBrowsingVerdict("safe", reason="invalid or empty url")
        selected_lists = self._selected_lists_for_lookup()
        cache_key = (canonical, selected_lists)
        cached = self._verdict_cache.get(cache_key)
        if cached and cached[0] > time.monotonic():
            return cached[1]
        hashes = expression_hashes(canonical)
        full_set = set(hashes)
        saw_local_match = False
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
                    verdict = SafeBrowsingVerdict(
                        "safe",
                        reason="api key unavailable for full-hash confirmation",
                    )
                else:
                    response, duration = self._store.search_hashes(api_key, [prefix])
                    self._cache_search_response(prefix, response, duration, local_lists)
                    verdict = SafeBrowsingVerdict(
                        "safe",
                        reason="full hash not returned",
                    )
                    for item in response:
                        returned = _decode_b64(item.get("fullHash"))
                        if returned in full_set:
                            threat = _enforceable_threat(
                                item.get("fullHashDetails") or [],
                                _threat_type_for_list(local_lists[0]),
                                local_threat_types,
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
                self._cache_verdict(cache_key, verdict)
                return verdict
            last_safe_verdict = verdict
        verdict = (
            last_safe_verdict
            if saw_local_match
            else SafeBrowsingVerdict("safe", reason="no local hash-prefix match")
        )
        self._cache_verdict(cache_key, verdict)
        return verdict
