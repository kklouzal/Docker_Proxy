from __future__ import annotations

import json
import os
import threading
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Optional

from services.proxy_registry import get_proxy_registry
from services.proxy_context import normalize_proxy_id


class ProxyClientError(RuntimeError):
    pass


@dataclass(frozen=True)
class ProxyResponse:
    ok: bool
    status_code: int
    data: dict[str, Any]


class ProxyClient:
    def __init__(self, *, timeout_seconds: float = 5.0):
        self.timeout_seconds = timeout_seconds

    def _auth_headers(self) -> dict[str, str]:
        token = (os.environ.get("PROXY_MANAGEMENT_TOKEN") or "").strip()
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def _proxy_base_url(self, proxy_id: object | None) -> str:
        proxy_key = normalize_proxy_id(proxy_id)
        info = get_proxy_registry().get_proxy(proxy_key)
        if info is None or not info.management_url:
            raise ProxyClientError(f"Proxy '{proxy_key}' is not registered with a management URL.")
        return info.management_url.rstrip("/") + "/"

    def _request(
        self,
        proxy_id: object | None,
        *,
        method: str,
        path: str,
        payload: Optional[dict[str, Any]] = None,
        timeout_seconds: float | None = None,
    ) -> ProxyResponse:
        base = self._proxy_base_url(proxy_id)
        url = urllib.parse.urljoin(base, path.lstrip("/"))
        body = None
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=body,
            method=method.upper(),
            headers=self._auth_headers(),
        )
        timeout = float(timeout_seconds or self.timeout_seconds)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw = response.read().decode("utf-8", errors="replace")
                data = json.loads(raw) if raw else {}
                return ProxyResponse(ok=bool(data.get("ok", True)), status_code=int(response.status), data=data)
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace") if hasattr(exc, "read") else ""
            try:
                data = json.loads(raw) if raw else {}
            except Exception:
                data = {"ok": False, "detail": raw or str(exc)}
            raise ProxyClientError(data.get("detail") or f"Proxy request failed with HTTP {exc.code}.") from exc
        except urllib.error.URLError as exc:
            raise ProxyClientError(str(exc.reason) or str(exc)) from exc
        except Exception as exc:
            raise ProxyClientError(str(exc)) from exc

    def get_health(self, proxy_id: object | None, *, timeout_seconds: float = 2.0) -> dict[str, Any]:
        return self._request(
            proxy_id,
            method="GET",
            path="/api/manage/health",
            timeout_seconds=timeout_seconds,
        ).data

    def sync_proxy(self, proxy_id: object | None, *, force: bool = False, timeout_seconds: float = 15.0) -> dict[str, Any]:
        return self._request(
            proxy_id,
            method="POST",
            path="/api/manage/sync",
            payload={"force": bool(force)},
            timeout_seconds=timeout_seconds,
        ).data

    def clear_proxy_cache(self, proxy_id: object | None, *, timeout_seconds: float = 60.0) -> dict[str, Any]:
        return self._request(
            proxy_id,
            method="POST",
            path="/api/manage/cache/clear",
            payload={},
            timeout_seconds=timeout_seconds,
        ).data

    def test_clamav_eicar(self, proxy_id: object | None, *, timeout_seconds: float = 10.0) -> dict[str, Any]:
        return self._request(
            proxy_id,
            method="POST",
            path="/api/manage/clamav/test-eicar",
            payload={},
            timeout_seconds=timeout_seconds,
        ).data

    def test_clamav_icap(self, proxy_id: object | None, *, timeout_seconds: float = 10.0) -> dict[str, Any]:
        return self._request(
            proxy_id,
            method="POST",
            path="/api/manage/clamav/test-icap",
            payload={},
            timeout_seconds=timeout_seconds,
        ).data


_store: Optional[ProxyClient] = None
_store_lock = threading.Lock()


def get_proxy_client() -> ProxyClient:
    global _store
    if _store is not None:
        return _store
    with _store_lock:
        if _store is None:
            _store = ProxyClient()
        return _store
