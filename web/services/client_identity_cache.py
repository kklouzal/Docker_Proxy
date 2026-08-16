from __future__ import annotations

import ipaddress
import re
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import TYPE_CHECKING

from services.domain_normalization import is_ambiguous_ipv4_like_host
from services.runtime_helpers import env_float as _env_float
from services.runtime_helpers import env_int as _env_int

if TYPE_CHECKING:
    from collections.abc import Iterable

_REVERSE_DNS_LOOKUP_THREAD_LIMIT = 4
_REVERSE_DNS_LOOKUP_SLOTS = threading.BoundedSemaphore(_REVERSE_DNS_LOOKUP_THREAD_LIMIT)
_INFLIGHT_PUBLICATION_GRACE_SECONDS = 0.05
_DNS_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)
_IDNA_DOT_TRANSLATION = str.maketrans(
    {
        "\u3002": ".",
        "\uff0e": ".",
        "\uff61": ".",
    }
)
_RESERVED_RDNS_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
}


class _ReverseDNSLookupCapacityError(RuntimeError):
    """Indicate that no bounded reverse-DNS worker slot was available."""


@dataclass
class _CacheEntry:
    hostname: str
    source: str
    status: str
    expires_at: float


def _gethostbyaddr_with_timeout(
    ip: str,
    *,
    timeout_seconds: float,
) -> tuple[str, list[str], list[str]] | None:
    """Run reverse DNS with bounded caller latency and bounded stuck workers.

    socket.gethostbyaddr does not accept a per-call timeout. Avoid using
    socket.setdefaulttimeout here: that mutates process-global socket defaults and
    can leak the temporary DNS timeout into unrelated socket creation in other
    Admin UI threads. If libc/NSS blocks past the deadline, return ``None`` and
    let the daemon lookup thread release its slot if it eventually finishes.
    Raise ``_ReverseDNSLookupCapacityError`` when no worker slot is available so
    transient local saturation is not cached as a DNS failure.
    """
    if not _REVERSE_DNS_LOOKUP_SLOTS.acquire(blocking=False):
        raise _ReverseDNSLookupCapacityError

    completed = threading.Event()
    result: list[tuple[str, list[str], list[str]]] = []
    errors: list[Exception] = []

    def lookup() -> None:
        try:
            result.append(socket.gethostbyaddr(ip))
        except Exception as exc:  # propagate synchronous failures below
            errors.append(exc)
        finally:
            _REVERSE_DNS_LOOKUP_SLOTS.release()
            completed.set()

    worker = threading.Thread(
        target=lookup,
        name=f"client-rdns-lookup-{ip}",
        daemon=True,
    )
    try:
        worker.start()
    except Exception:
        _REVERSE_DNS_LOOKUP_SLOTS.release()
        raise

    if not completed.wait(timeout=max(0.001, timeout_seconds)):
        return None
    if errors:
        raise errors[0]
    return result[0]


class ClientIdentityCache:
    def __init__(
        self,
        *,
        success_ttl_seconds: float = 3600.0,
        failure_ttl_seconds: float = 300.0,
        lookup_timeout_seconds: float = 0.35,
        max_entries: int = 1024,
    ) -> None:
        self.success_ttl_seconds = max(30.0, float(success_ttl_seconds or 3600.0))
        self.failure_ttl_seconds = max(10.0, float(failure_ttl_seconds or 300.0))
        self.lookup_timeout_seconds = max(
            0.05,
            min(5.0, float(lookup_timeout_seconds or 0.35)),
        )
        self.max_entries = max(64, int(max_entries or 1024))
        self._cache: dict[str, _CacheEntry] = {}
        self._inflight: dict[str, threading.Event] = {}
        self._lock = threading.Lock()

    def _normalize_ip(self, value: object) -> str:
        raw = str(value or "").strip()
        if not raw:
            return ""
        try:
            return str(ipaddress.ip_address(raw))
        except Exception:
            return ""

    def _is_ip_literal_hostname(self, hostname: str) -> bool:
        candidate = hostname.strip("[]")
        try:
            ipaddress.ip_address(candidate)
            return True
        except ValueError:
            pass

        labels = candidate.split(".")
        if not 1 <= len(labels) <= 4:
            return False
        return all(label.isdecimal() for label in labels if label)

    def _is_ambiguous_ipv4_hostname(self, hostname: str) -> bool:
        return is_ambiguous_ipv4_like_host(hostname.strip("[]"))

    def _normalize_rdns_hostname(self, hostname: object) -> str:
        cleaned = (
            str(hostname or "")
            .strip()
            .translate(_IDNA_DOT_TRANSLATION)
            .rstrip(".")
            .lower()
        )
        if not cleaned:
            return ""
        if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in cleaned):
            return ""
        labels = cleaned.split(".")
        if not labels or any(not label for label in labels):
            return ""
        try:
            normalized = ".".join(
                label.encode("idna").decode("ascii").lower() for label in labels
            )
        except Exception:
            return ""
        if normalized in _RESERVED_RDNS_HOSTNAMES or normalized.endswith(".localhost"):
            return ""
        if self._is_ip_literal_hostname(normalized):
            return ""
        if self._is_ambiguous_ipv4_hostname(normalized):
            return ""
        if len(normalized) > 253:
            return ""

        labels = normalized.split(".")
        if not labels or any(not label for label in labels):
            return ""
        if any(_DNS_LABEL_RE.fullmatch(label) is None for label in labels):
            return ""
        return normalized

    def _lookup_hostname(self, ip: str) -> tuple[str, str, str]:
        try:
            lookup_result = _gethostbyaddr_with_timeout(
                ip,
                timeout_seconds=self.lookup_timeout_seconds,
            )
        except (socket.herror, socket.gaierror, TimeoutError, OSError):
            return "", "", "unresolved"
        if lookup_result is None:
            return "", "", "unresolved"

        hostname, _aliases, _addresses = lookup_result
        cleaned = self._normalize_rdns_hostname(hostname)
        if not cleaned:
            return "", "", "unresolved"
        return cleaned, "rdns", "resolved"

    def _get_cached_locked(self, ip: str, *, now: float) -> _CacheEntry | None:
        cached = self._cache.get(ip)
        if cached is None:
            return None
        if cached.expires_at <= now:
            self._cache.pop(ip, None)
            return None
        return cached

    def _get_cached(self, ip: str) -> _CacheEntry | None:
        with self._lock:
            return self._get_cached_locked(ip, now=time.monotonic())

    def _store(
        self,
        ip: str,
        *,
        hostname: str,
        source: str,
        status: str,
        ttl_seconds: float,
    ) -> _CacheEntry:
        entry = _CacheEntry(
            hostname=hostname,
            source=source,
            status=status,
            expires_at=time.monotonic() + max(1.0, ttl_seconds),
        )
        with self._lock:
            if len(self._cache) >= self.max_entries:
                oldest_key = min(
                    self._cache.items(),
                    key=lambda item: item[1].expires_at,
                )[0]
                self._cache.pop(oldest_key, None)
            self._cache[ip] = entry
        return entry

    def _resolve_normalized(self, normalized: str) -> dict[str, str]:
        with self._lock:
            cached = self._get_cached_locked(normalized, now=time.monotonic())
            if cached is not None:
                return {
                    "hostname": cached.hostname,
                    "hostname_source": cached.source,
                    "hostname_status": cached.status,
                }

            inflight = self._inflight.get(normalized)
            if inflight is None:
                inflight = threading.Event()
                self._inflight[normalized] = inflight
                owns_lookup = True
            else:
                owns_lookup = False

        if not owns_lookup:
            # The owner can finish its bounded resolver wait at the same instant as a
            # duplicate exhausts the nominal lookup budget. Allow a small, bounded
            # handoff window for the owner to publish and signal rather than racing
            # that valid result with a false local timeout.
            inflight.wait(
                timeout=(
                    self.lookup_timeout_seconds + _INFLIGHT_PUBLICATION_GRACE_SECONDS
                )
            )
            cached = self._get_cached(normalized)
            if cached is None:
                return {
                    "hostname": "",
                    "hostname_source": "",
                    "hostname_status": "unresolved",
                }
            return {
                "hostname": cached.hostname,
                "hostname_source": cached.source,
                "hostname_status": cached.status,
            }

        try:
            try:
                hostname, source, status = self._lookup_hostname(normalized)
            except _ReverseDNSLookupCapacityError:
                entry = None
            else:
                ttl = self.success_ttl_seconds if hostname else self.failure_ttl_seconds
                entry = self._store(
                    normalized,
                    hostname=hostname,
                    source=source,
                    status=status,
                    ttl_seconds=ttl,
                )
        finally:
            with self._lock:
                if self._inflight.get(normalized) is inflight:
                    self._inflight.pop(normalized, None)
                    inflight.set()

        if entry is None:
            return {
                "hostname": "",
                "hostname_source": "",
                "hostname_status": "unresolved",
            }
        return {
            "hostname": entry.hostname,
            "hostname_source": entry.source,
            "hostname_status": entry.status,
        }

    def resolve(self, ip: object) -> dict[str, str]:
        normalized = self._normalize_ip(ip)
        if not normalized:
            return {
                "hostname": "",
                "hostname_source": "",
                "hostname_status": "invalid",
            }
        return self._resolve_normalized(normalized)

    def resolve_many(self, ips: Iterable[object]) -> dict[str, dict[str, str]]:
        normalized_ips: list[str] = []
        seen: set[str] = set()
        for ip in ips:
            normalized = self._normalize_ip(ip)
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            normalized_ips.append(normalized)

        if len(normalized_ips) <= 1:
            return {
                normalized: self._resolve_normalized(normalized)
                for normalized in normalized_ips
            }

        worker_count = min(
            len(normalized_ips),
            _REVERSE_DNS_LOOKUP_THREAD_LIMIT,
        )
        with ThreadPoolExecutor(
            max_workers=worker_count,
            thread_name_prefix="client-rdns-batch",
        ) as executor:
            results = executor.map(self._resolve_normalized, normalized_ips)
            return dict(zip(normalized_ips, results, strict=True))


_cache: ClientIdentityCache | None = None
_cache_lock = threading.Lock()


def get_client_identity_cache() -> ClientIdentityCache:
    global _cache
    if _cache is not None:
        return _cache
    with _cache_lock:
        if _cache is None:
            _cache = ClientIdentityCache(
                success_ttl_seconds=_env_float(
                    "OBS_CLIENT_HOSTNAME_TTL_SECONDS",
                    3600.0,
                    minimum=30.0,
                    maximum=86400.0,
                ),
                failure_ttl_seconds=_env_float(
                    "OBS_CLIENT_HOSTNAME_FAILURE_TTL_SECONDS",
                    300.0,
                    minimum=10.0,
                    maximum=3600.0,
                ),
                lookup_timeout_seconds=_env_float(
                    "OBS_CLIENT_HOSTNAME_TIMEOUT_SECONDS",
                    0.35,
                    minimum=0.05,
                    maximum=5.0,
                ),
                max_entries=_env_int(
                    "OBS_CLIENT_HOSTNAME_CACHE_MAX",
                    1024,
                    minimum=64,
                    maximum=8192,
                ),
            )
        return _cache
