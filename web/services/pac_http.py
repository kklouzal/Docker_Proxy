from __future__ import annotations

import ipaddress
import json
import os
import threading
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from services.pac_renderer import (
    PAC_MANIFEST_FILENAME,
    PAC_RENDER_DIR,
    PAC_STATE_SHA_FILENAME,
    build_emergency_pac,
    select_manifest_file,
    substitute_request_host,
)

PAC_CONTENT_TYPE = "application/x-ns-proxy-autoconfig"
DEFAULT_PUBLIC_PAC_PATHS = frozenset({"/proxy.pac", "/wpad.dat"})


@lru_cache(maxsize=1)
def pac_render_dir() -> str:
    return (
        os.environ.get("PAC_RENDER_DIR") or PAC_RENDER_DIR
    ).strip() or PAC_RENDER_DIR


def _trusted_pac_header_networks() -> tuple[
    ipaddress.IPv4Network | ipaddress.IPv6Network, ...
]:
    raw = (os.environ.get("PAC_TRUSTED_PROXY_CIDRS") or "").strip()
    if not raw:
        return ()

    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for item in raw.replace(";", ",").split(","):
        candidate = item.strip()
        if not candidate:
            continue
        try:
            networks.append(ipaddress.ip_network(candidate, strict=False))
        except ValueError:
            continue
    return tuple(networks)


def _remote_addr_trusts_forwarded_headers(remote_addr: str | None) -> bool:
    try:
        remote_ip = ipaddress.ip_address((remote_addr or "").strip())
    except ValueError:
        return False
    return any(remote_ip in network for network in _trusted_pac_header_networks())


def _first_header_value(value: object | None) -> str:
    return (str(value or "").split(",")[0] or "").strip()


def _first_forwarded_ip(value: object | None) -> str:
    first = _first_header_value(value)
    if not first:
        return ""
    try:
        return str(ipaddress.ip_address(first))
    except ValueError:
        return ""


def client_ip_from_headers(headers: Any, remote_addr: str | None = None) -> str:
    if headers is not None and _remote_addr_trusts_forwarded_headers(remote_addr):
        xff = _first_forwarded_ip(headers.get("X-Forwarded-For"))
        if xff:
            return xff
        xri = _first_forwarded_ip(headers.get("X-Real-IP"))
        if xri:
            return xri
    return str(remote_addr or "").strip()


def request_host_from_headers(headers: Any, remote_addr: str | None = None) -> str:
    if headers is not None and _remote_addr_trusts_forwarded_headers(remote_addr):
        forwarded_host = _first_header_value(headers.get("X-Forwarded-Host"))
        if forwarded_host:
            return forwarded_host
    return (
        str((headers.get("Host") if headers is not None else "") or "").strip()
        or "127.0.0.1"
    )


def _public_target_from_manifest(value: object) -> tuple[str, str | None]:
    candidate = str(value or "").strip()
    if not candidate:
        return "", None
    try:
        parsed = urlsplit(candidate)
    except Exception:
        return "", None

    has_query = "?" in candidate
    if parsed.scheme or parsed.netloc:
        path = parsed.path
        query = parsed.query if has_query else None
    elif has_query:
        path, query = candidate.split("?", 1)
    else:
        path, query = candidate, None

    path = str(path or "").strip()
    if not path:
        return "", None
    if not path.startswith("/"):
        path = f"/{path}"
    return path, query


def _public_path_from_manifest(value: object) -> str:
    path, _query = _public_target_from_manifest(value)
    return path


def _request_query_text(query_string: object | None) -> str:
    if query_string is None:
        return ""
    if isinstance(query_string, bytes):
        return query_string.decode("latin-1", errors="replace")
    return str(query_string)


def _safe_manifest_file_path(value: object) -> str:
    rel_path = os.path.normpath(str(value or "").strip()).replace("\\", "/")
    if not rel_path or rel_path in {".", ".."}:
        return ""
    if rel_path.startswith(("/", "../")):
        return ""
    first_segment = rel_path.split("/", 1)[0]
    if ":" in first_segment:
        return ""
    return rel_path


def default_pac_bytes(request_host: str) -> bytes:
    content = build_emergency_pac()
    return substitute_request_host(content, request_host).encode("utf-8")


class LocalPacCache:
    def __init__(self, pac_dir: str) -> None:
        self.pac_dir = Path(pac_dir)
        self._lock = threading.Lock()
        self._state_sha = ""
        self._manifest: dict[str, object] = {}
        self._files: dict[str, str] = {}

    def _read_state_sha(self) -> str:
        try:
            return (
                (self.pac_dir / PAC_STATE_SHA_FILENAME)
                .read_text(encoding="utf-8", errors="replace")
                .strip()
            )
        except Exception:
            return ""

    def _load_locked(self) -> bool:
        state_sha = self._read_state_sha()
        if (
            state_sha
            and state_sha == self._state_sha
            and self._manifest
            and self._files
        ):
            return True

        manifest_path = self.pac_dir / PAC_MANIFEST_FILENAME
        if not manifest_path.exists():
            self._state_sha = ""
            self._manifest = {}
            self._files = {}
            return False

        try:
            manifest = json.loads(
                manifest_path.read_text(encoding="utf-8", errors="replace") or "{}",
            )
        except Exception:
            self._state_sha = ""
            self._manifest = {}
            self._files = {}
            return False
        if not isinstance(manifest, dict):
            self._state_sha = ""
            self._manifest = {}
            self._files = {}
            return False

        files: dict[str, str] = {}
        fallback_file = _safe_manifest_file_path(manifest.get("fallback_file"))
        if not fallback_file:
            fallback_file = "fallback.pac"
        candidates = {fallback_file}
        profiles = manifest.get("profiles")
        if isinstance(profiles, list):
            for entry in profiles:
                if not isinstance(entry, dict):
                    continue
                path = _safe_manifest_file_path(entry.get("file"))
                if path:
                    candidates.add(path)
        for rel_path in sorted(candidates):
            file_path = self.pac_dir / rel_path
            if not file_path.exists() or not file_path.is_file():
                continue
            try:
                files[rel_path] = file_path.read_text(
                    encoding="utf-8",
                    errors="replace",
                )
            except Exception:
                continue

        if not files:
            self._state_sha = ""
            self._manifest = {}
            self._files = {}
            return False

        self._state_sha = state_sha or str(manifest.get("state_sha256") or "")
        self._manifest = manifest
        self._files = files
        return True

    def public_paths(self) -> frozenset[str]:
        with self._lock:
            paths = set(DEFAULT_PUBLIC_PAC_PATHS)
            if not self._load_locked():
                return frozenset(paths)
            for path, _query in self._public_request_targets_locked():
                if path:
                    paths.add(path)
            return frozenset(paths)

    def _public_request_targets_locked(self) -> frozenset[tuple[str, str | None]]:
        targets: set[tuple[str, str | None]] = {
            (path, None) for path in DEFAULT_PUBLIC_PAC_PATHS
        }
        for key in ("public_pac_path", "public_pac_url"):
            public_path, public_query = _public_target_from_manifest(
                self._manifest.get(key),
            )
            if public_path:
                targets.add((public_path, public_query))
        return frozenset(targets)

    def public_request_allowed(
        self,
        path: str,
        query_string: object | None = None,
    ) -> bool:
        request_path = str(path or "/")
        request_query = _request_query_text(query_string)
        with self._lock:
            if not self._load_locked():
                targets = {(path, None) for path in DEFAULT_PUBLIC_PAC_PATHS}
            else:
                targets = self._public_request_targets_locked()
        return any(
            request_path == public_path
            and (public_query is None or request_query == public_query)
            for public_path, public_query in targets
        )

    def resolve(self, *, client_ip: str, request_host: str) -> bytes | None:
        with self._lock:
            if not self._load_locked():
                return None
            selected = _safe_manifest_file_path(
                select_manifest_file(self._manifest, client_ip)
            )
            fallback = _safe_manifest_file_path(self._manifest.get("fallback_file"))
            if not fallback:
                fallback = "fallback.pac"
            content = self._files.get(selected) or self._files.get(fallback)
            if not content:
                return None
            return substitute_request_host(content, request_host).encode("utf-8")


_CACHE_LOCK = threading.Lock()
_CACHES: dict[str, LocalPacCache] = {}


def get_pac_cache(pac_dir: str | None = None) -> LocalPacCache:
    resolved_dir = str(pac_dir or pac_render_dir())
    with _CACHE_LOCK:
        cache = _CACHES.get(resolved_dir)
        if cache is None:
            cache = LocalPacCache(resolved_dir)
            _CACHES[resolved_dir] = cache
        return cache


def public_pac_paths(pac_dir: str | None = None) -> frozenset[str]:
    return get_pac_cache(pac_dir).public_paths()


def public_pac_request_allowed(
    path: str,
    query_string: object | None = None,
    pac_dir: str | None = None,
) -> bool:
    return get_pac_cache(pac_dir).public_request_allowed(path, query_string)


def resolve_pac_bytes(
    *,
    client_ip: str,
    request_host: str,
    pac_dir: str | None = None,
) -> bytes:
    data = get_pac_cache(pac_dir).resolve(
        client_ip=client_ip,
        request_host=request_host,
    )
    if data is not None:
        return data
    return default_pac_bytes(request_host)


def pac_content_disposition(path: str) -> str:
    name = str(path or "").split("?", 1)[0].rstrip("/").rsplit("/", 1)[-1]
    if name == "wpad.dat":
        return 'inline; filename="wpad.dat"'
    return 'inline; filename="proxy.pac"'
