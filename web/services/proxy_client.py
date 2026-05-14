from __future__ import annotations

import json
import os
import socket
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

    def _safe_error_detail(self, raw: str, *, status_code: int | None = None) -> str:
        text = (raw or "").strip()
        if "<html" in text.lower() or "<!doctype" in text.lower():
            if status_code == 403:
                return "Proxy management authentication failed. Check that PROXY_MANAGEMENT_TOKEN matches between the Admin UI and the selected proxy runtime."
            if status_code == 404:
                return "Proxy management endpoint was not found. Check that the registered management URL points to the proxy management listener, not the public PAC/proxy listener."
            return f"Proxy management request failed with HTTP {status_code or 'error'} and returned an HTML error page. Check the registered management URL and proxy runtime logs."
        if text:
            return text[:1000]
        if status_code is not None:
            return f"Proxy management request failed with HTTP {status_code}."
        return "Proxy management request failed."

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
                data = {"ok": False, "detail": self._safe_error_detail(raw, status_code=int(exc.code))}
            detail = data.get("detail") or self._safe_error_detail(raw, status_code=int(exc.code))
            raise ProxyClientError(f"{detail} (proxy={normalize_proxy_id(proxy_id)}, url={url})") from exc
        except urllib.error.URLError as exc:
            reason = str(exc.reason) or str(exc)
            raise ProxyClientError(f"Proxy management request failed: {reason} (proxy={normalize_proxy_id(proxy_id)}, url={url})") from exc
        except socket.timeout as exc:
            raise ProxyClientError(
                f"Proxy management request timed out after {timeout:.1f}s (proxy={normalize_proxy_id(proxy_id)}, url={url}). Check that the proxy runtime is reachable from the Admin UI container."
            ) from exc
        except TimeoutError as exc:
            raise ProxyClientError(
                f"Proxy management request timed out after {timeout:.1f}s (proxy={normalize_proxy_id(proxy_id)}, url={url}). Check that the proxy runtime is reachable from the Admin UI container."
            ) from exc
        except Exception as exc:
            raise ProxyClientError(f"Proxy management request failed: {exc} (proxy={normalize_proxy_id(proxy_id)}, url={url})") from exc

    def get_health(self, proxy_id: object | None, *, timeout_seconds: float = 5.0, full: bool = False) -> dict[str, Any]:
        path = "/api/manage/health?full=1" if full else "/api/manage/health"
        return self._request(
            proxy_id,
            method="GET",
            path=path,
            timeout_seconds=timeout_seconds,
        ).data

    def get_clamav_health(self, proxy_id: object | None, *, timeout_seconds: float = 5.0) -> dict[str, Any]:
        return self._request(
            proxy_id,
            method="GET",
            path="/api/manage/health/clamav",
            timeout_seconds=timeout_seconds,
        ).data

    def sync_proxy(self, proxy_id: object | None, *, force: bool = False, operation_id: int | None = None, timeout_seconds: float = 15.0) -> dict[str, Any]:
        payload: dict[str, Any] = {"force": bool(force)}
        if operation_id is not None:
            payload["operation_id"] = int(operation_id)
        return self._request(
            proxy_id,
            method="POST",
            path="/api/manage/sync",
            payload=payload,
            timeout_seconds=timeout_seconds,
        ).data

    def validate_config(self, proxy_id: object | None, config_text: str, *, timeout_seconds: float = 20.0) -> dict[str, Any]:
        return self._request(
            proxy_id,
            method="POST",
            path="/api/manage/config/validate",
            payload={"config_text": config_text or ""},
            timeout_seconds=timeout_seconds,
        ).data

    def rollback_config(self, proxy_id: object | None, *, reason: str = "", timeout_seconds: float = 60.0) -> dict[str, Any]:
        return self._request(
            proxy_id,
            method="POST",
            path="/api/manage/config/rollback",
            payload={"reason": reason or "Rollback requested by admin UI."},
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
