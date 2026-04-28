from __future__ import annotations

import ipaddress
import socket
import threading
import time
from dataclasses import dataclass
from typing import Dict, Iterable

from services.runtime_helpers import env_float as _env_float, env_int as _env_int


_TIMEOUT_LOCK = threading.Lock()


@dataclass
class _CacheEntry:
    hostname: str
    source: str
    status: str
    expires_at: float


class ClientIdentityCache:
    def __init__(
        self,
        *,
        success_ttl_seconds: float = 3600.0,
        failure_ttl_seconds: float = 300.0,
        lookup_timeout_seconds: float = 0.35,
        max_entries: int = 1024,
    ):
        self.success_ttl_seconds = max(30.0, float(success_ttl_seconds or 3600.0))
        self.failure_ttl_seconds = max(10.0, float(failure_ttl_seconds or 300.0))
        self.lookup_timeout_seconds = max(0.05, min(5.0, float(lookup_timeout_seconds or 0.35)))
        self.max_entries = max(64, int(max_entries or 1024))
        self._cache: Dict[str, _CacheEntry] = {}
        self._lock = threading.Lock()

    def _normalize_ip(self, value: object) -> str:
        raw = str(value or "").strip()
        if not raw:
            return ""
        try:
            return str(ipaddress.ip_address(raw))
        except Exception:
            return ""

    def _lookup_hostname(self, ip: str) -> tuple[str, str, str]:
        with _TIMEOUT_LOCK:
            previous_timeout = socket.getdefaulttimeout()
            try:
                socket.setdefaulttimeout(self.lookup_timeout_seconds)
                hostname, _aliases, _addresses = socket.gethostbyaddr(ip)
            except (socket.herror, socket.gaierror, TimeoutError, OSError):
                return "", "", "unresolved"
            finally:
                socket.setdefaulttimeout(previous_timeout)

        cleaned = str(hostname or "").strip().rstrip(".")
        if not cleaned:
            return "", "", "unresolved"
        return cleaned, "rdns", "resolved"

    def _get_cached(self, ip: str) -> _CacheEntry | None:
        now = time.time()
        with self._lock:
            cached = self._cache.get(ip)
            if cached is None:
                return None
            if cached.expires_at <= now:
                self._cache.pop(ip, None)
                return None
            return cached

    def _store(self, ip: str, *, hostname: str, source: str, status: str, ttl_seconds: float) -> _CacheEntry:
        entry = _CacheEntry(
            hostname=hostname,
            source=source,
            status=status,
            expires_at=time.time() + max(1.0, ttl_seconds),
        )
        with self._lock:
            if len(self._cache) >= self.max_entries:
                oldest_key = min(self._cache.items(), key=lambda item: item[1].expires_at)[0]
                self._cache.pop(oldest_key, None)
            self._cache[ip] = entry
        return entry

    def resolve(self, ip: object) -> Dict[str, str]:
        normalized = self._normalize_ip(ip)
        if not normalized:
            return {
                "hostname": "",
                "hostname_source": "",
                "hostname_status": "invalid",
            }

        cached = self._get_cached(normalized)
        if cached is not None:
            return {
                "hostname": cached.hostname,
                "hostname_source": cached.source,
                "hostname_status": cached.status,
            }

        hostname, source, status = self._lookup_hostname(normalized)
        ttl = self.success_ttl_seconds if hostname else self.failure_ttl_seconds
        entry = self._store(normalized, hostname=hostname, source=source, status=status, ttl_seconds=ttl)
        return {
            "hostname": entry.hostname,
            "hostname_source": entry.source,
            "hostname_status": entry.status,
        }

    def resolve_many(self, ips: Iterable[object]) -> Dict[str, Dict[str, str]]:
        resolved: Dict[str, Dict[str, str]] = {}
        for ip in ips:
            normalized = self._normalize_ip(ip)
            if not normalized or normalized in resolved:
                continue
            resolved[normalized] = self.resolve(normalized)
        return resolved


_cache: ClientIdentityCache | None = None
_cache_lock = threading.Lock()


def get_client_identity_cache() -> ClientIdentityCache:
    global _cache
    if _cache is not None:
        return _cache
    with _cache_lock:
        if _cache is None:
            _cache = ClientIdentityCache(
                success_ttl_seconds=_env_float("OBS_CLIENT_HOSTNAME_TTL_SECONDS", 3600.0, minimum=30.0, maximum=86400.0),
                failure_ttl_seconds=_env_float("OBS_CLIENT_HOSTNAME_FAILURE_TTL_SECONDS", 300.0, minimum=10.0, maximum=3600.0),
                lookup_timeout_seconds=_env_float("OBS_CLIENT_HOSTNAME_TIMEOUT_SECONDS", 0.35, minimum=0.05, maximum=5.0),
                max_entries=_env_int("OBS_CLIENT_HOSTNAME_CACHE_MAX", 1024, minimum=64, maximum=8192),
            )
        return _cache
