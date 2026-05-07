from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any

from services.pac_renderer import (
    PAC_MANIFEST_FILENAME,
    PAC_RENDER_DIR,
    PAC_STATE_SHA_FILENAME,
    build_emergency_pac,
    select_manifest_file,
    substitute_request_host,
)


PAC_CONTENT_TYPE = "application/x-ns-proxy-autoconfig"


def pac_render_dir() -> str:
    return (os.environ.get("PAC_RENDER_DIR") or PAC_RENDER_DIR).strip() or PAC_RENDER_DIR


def client_ip_from_headers(headers: Any, remote_addr: str | None = None) -> str:
    xff = str((headers.get("X-Forwarded-For") if headers is not None else "") or "").strip()
    if xff:
        candidate = (xff.split(",")[0] or "").strip()
        if candidate:
            return candidate
    xri = str((headers.get("X-Real-IP") if headers is not None else "") or "").strip()
    if xri:
        return xri
    return str(remote_addr or "").strip()


def request_host_from_headers(headers: Any) -> str:
    return str((headers.get("Host") if headers is not None else "") or "").strip() or "127.0.0.1"


def default_pac_bytes(request_host: str) -> bytes:
    content = build_emergency_pac()
    return substitute_request_host(content, request_host).encode("utf-8")


class LocalPacCache:
    def __init__(self, pac_dir: str):
        self.pac_dir = Path(pac_dir)
        self._lock = threading.Lock()
        self._state_sha = ""
        self._manifest: dict[str, object] = {}
        self._files: dict[str, str] = {}

    def _read_state_sha(self) -> str:
        try:
            return (self.pac_dir / PAC_STATE_SHA_FILENAME).read_text(encoding="utf-8", errors="replace").strip()
        except Exception:
            return ""

    def _load_locked(self) -> bool:
        state_sha = self._read_state_sha()
        if state_sha and state_sha == self._state_sha and self._manifest and self._files:
            return True

        manifest_path = self.pac_dir / PAC_MANIFEST_FILENAME
        if not manifest_path.exists():
            self._state_sha = ""
            self._manifest = {}
            self._files = {}
            return False

        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8", errors="replace") or "{}")
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
        fallback_file = str(manifest.get("fallback_file") or "fallback.pac")
        candidates = {fallback_file}
        profiles = manifest.get("profiles")
        if isinstance(profiles, list):
            for entry in profiles:
                if not isinstance(entry, dict):
                    continue
                path = str(entry.get("file") or "").strip()
                if path:
                    candidates.add(path)
        for rel_path in sorted(candidates):
            file_path = self.pac_dir / rel_path
            if not file_path.exists() or not file_path.is_file():
                continue
            try:
                files[rel_path] = file_path.read_text(encoding="utf-8", errors="replace")
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

    def resolve(self, *, client_ip: str, request_host: str) -> bytes | None:
        with self._lock:
            if not self._load_locked():
                return None
            selected = select_manifest_file(self._manifest, client_ip)
            fallback = str(self._manifest.get("fallback_file") or "fallback.pac")
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


def resolve_pac_bytes(*, client_ip: str, request_host: str, pac_dir: str | None = None) -> bytes:
    data = get_pac_cache(pac_dir).resolve(client_ip=client_ip, request_host=request_host)
    if data is not None:
        return data
    return default_pac_bytes(request_host)


def pac_content_disposition(path: str) -> str:
    if path == "/wpad.dat":
        return 'inline; filename="wpad.dat"'
    return 'inline; filename="proxy.pac"'