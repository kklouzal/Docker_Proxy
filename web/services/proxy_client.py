from __future__ import annotations

import json
import os
import threading
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

from services.proxy_context import normalize_proxy_id
from services.proxy_registry import get_proxy_registry, normalize_management_url


class ProxyClientError(RuntimeError):
    pass


_UNSAFE_EMPTY_MANAGEMENT_PATH = "Unsafe proxy management path: empty path."
_UNSAFE_MANAGEMENT_PATH_TEXT = (
    "Unsafe proxy management path: control, whitespace, or backslash."
)
_UNSAFE_SCHEME_RELATIVE_MANAGEMENT_PATH = (
    "Unsafe proxy management path: scheme-relative path."
)
_UNSAFE_UNPARSABLE_MANAGEMENT_PATH = "Unsafe proxy management path: unparsable path."
_UNSAFE_ABSOLUTE_MANAGEMENT_PATH = (
    "Unsafe proxy management path: absolute URL or authority."
)
_UNSAFE_FRAGMENT_MANAGEMENT_PATH = (
    "Unsafe proxy management path: fragments are not allowed."
)
_UNSAFE_AMBIGUOUS_ROOT_MANAGEMENT_PATH = (
    "Unsafe proxy management path: ambiguous path root."
)
_UNSAFE_ENCODED_MANAGEMENT_PATH = (
    "Unsafe proxy management path: ambiguous encoded path."
)
_UNSAFE_QUERY_MANAGEMENT_PATH = "Unsafe proxy management path: ambiguous query string."


def _has_unsafe_management_path_text(value: str) -> bool:
    return any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in value)


def _safe_decoded_management_path(path: str) -> bool:
    raw_segments = path.split("/")
    decoded_segments = [urllib.parse.unquote(segment) for segment in raw_segments]
    if any(
        "/" in segment or "\\" in segment or _has_unsafe_management_path_text(segment)
        for segment in decoded_segments
    ):
        return False
    segments = [segment for segment in decoded_segments if segment]
    return not any(segment in {".", ".."} for segment in segments)


@dataclass(frozen=True)
class ProxyResponse:
    ok: bool
    status_code: int
    data: dict[str, Any]


class ProxyClient:
    def __init__(self, *, timeout_seconds: float = 5.0) -> None:
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

    def _non_object_json_detail(self) -> str:
        return (
            "Proxy management endpoint returned JSON that was not an object. "
            "Check that the registered management URL points to the proxy "
            "management listener."
        )

    def _timeout_error_detail(
        self,
        *,
        proxy_id: object | None,
        url: str,
        timeout: float,
    ) -> str:
        return (
            f"Proxy management request timed out after {timeout:.1f}s "
            f"(proxy={normalize_proxy_id(proxy_id)}, url={url}). Check that "
            "the proxy runtime is reachable from the Admin UI container."
        )

    def _proxy_base_url(self, proxy_id: object | None) -> str:
        proxy_key = normalize_proxy_id(proxy_id)
        info = get_proxy_registry().get_proxy(proxy_key)
        management_url = normalize_management_url(
            getattr(info, "management_url", "") if info is not None else ""
        )
        if info is None or not management_url:
            msg = f"Proxy '{proxy_key}' is not registered with a management URL."
            raise ProxyClientError(msg)
        return management_url.rstrip("/") + "/"

    def _management_url(self, base: str, path: str) -> str:
        relative_path = self._management_relative_path(path)
        return base.rstrip("/") + "/" + relative_path

    def _management_relative_path(self, path: str) -> str:
        candidate = str(path or "").strip()
        if not candidate:
            raise ProxyClientError(_UNSAFE_EMPTY_MANAGEMENT_PATH)
        if _has_unsafe_management_path_text(candidate) or "\\" in candidate:
            raise ProxyClientError(_UNSAFE_MANAGEMENT_PATH_TEXT)
        if candidate.startswith("//"):
            raise ProxyClientError(_UNSAFE_SCHEME_RELATIVE_MANAGEMENT_PATH)
        try:
            parsed = urllib.parse.urlsplit(candidate)
        except Exception as exc:
            raise ProxyClientError(_UNSAFE_UNPARSABLE_MANAGEMENT_PATH) from exc
        if parsed.scheme or parsed.netloc:
            raise ProxyClientError(_UNSAFE_ABSOLUTE_MANAGEMENT_PATH)
        if parsed.fragment:
            raise ProxyClientError(_UNSAFE_FRAGMENT_MANAGEMENT_PATH)

        raw_path = parsed.path or ""
        if not raw_path:
            raise ProxyClientError(_UNSAFE_EMPTY_MANAGEMENT_PATH)
        if raw_path.startswith("//"):
            raise ProxyClientError(_UNSAFE_AMBIGUOUS_ROOT_MANAGEMENT_PATH)
        if not raw_path.startswith("/"):
            raw_path = f"/{raw_path}"
        if not _safe_decoded_management_path(raw_path):
            raise ProxyClientError(_UNSAFE_ENCODED_MANAGEMENT_PATH)

        query = parsed.query
        if query:
            decoded_query = urllib.parse.unquote(query)
            if _has_unsafe_management_path_text(decoded_query) or "\\" in decoded_query:
                raise ProxyClientError(_UNSAFE_QUERY_MANAGEMENT_PATH)

        relative_path = raw_path.lstrip("/")
        return f"{relative_path}?{query}" if query else relative_path

    def _request(
        self,
        proxy_id: object | None,
        *,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        timeout_seconds: float | None = None,
    ) -> ProxyResponse:
        base = self._proxy_base_url(proxy_id)
        url = self._management_url(base, path)
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
                try:
                    data = json.loads(raw) if raw else {}
                except Exception as exc:
                    detail = self._safe_error_detail(
                        raw,
                        status_code=int(response.status),
                    )
                    msg = f"{detail} (proxy={normalize_proxy_id(proxy_id)}, url={url})"
                    raise ProxyClientError(msg) from exc
                if not isinstance(data, dict):
                    detail = self._non_object_json_detail()
                    msg = f"{detail} (proxy={normalize_proxy_id(proxy_id)}, url={url})"
                    raise ProxyClientError(msg)
                return ProxyResponse(
                    ok=bool(data.get("ok", True)),
                    status_code=int(response.status),
                    data=data,
                )
        except urllib.error.HTTPError as exc:
            raw = (
                exc.read().decode("utf-8", errors="replace")
                if hasattr(exc, "read")
                else ""
            )
            try:
                data = json.loads(raw) if raw else {}
            except Exception:
                data = {
                    "ok": False,
                    "detail": self._safe_error_detail(raw, status_code=int(exc.code)),
                }
            if not isinstance(data, dict):
                data = {"ok": False, "detail": self._non_object_json_detail()}
            detail = data.get("detail") or self._safe_error_detail(
                raw,
                status_code=int(exc.code),
            )
            msg = f"{detail} (proxy={normalize_proxy_id(proxy_id)}, url={url})"
            raise ProxyClientError(msg) from exc
        except ProxyClientError:
            raise
        except urllib.error.URLError as exc:
            reason = exc.reason
            if isinstance(reason, TimeoutError):
                raise ProxyClientError(
                    self._timeout_error_detail(
                        proxy_id=proxy_id,
                        url=url,
                        timeout=timeout,
                    ),
                ) from exc
            reason_detail = str(reason) or str(exc)
            msg = f"Proxy management request failed: {reason_detail} (proxy={normalize_proxy_id(proxy_id)}, url={url})"
            raise ProxyClientError(msg) from exc
        except TimeoutError as exc:
            raise ProxyClientError(
                self._timeout_error_detail(
                    proxy_id=proxy_id,
                    url=url,
                    timeout=timeout,
                ),
            ) from exc
        except Exception as exc:
            msg = f"Proxy management request failed: {exc} (proxy={normalize_proxy_id(proxy_id)}, url={url})"
            raise ProxyClientError(msg) from exc

    def get_health(
        self,
        proxy_id: object | None,
        *,
        timeout_seconds: float = 5.0,
        full: bool = False,
    ) -> dict[str, Any]:
        path = "/api/manage/health?full=1" if full else "/api/manage/health"
        return self._request(
            proxy_id,
            method="GET",
            path=path,
            timeout_seconds=timeout_seconds,
        ).data

    def get_clamav_health(
        self,
        proxy_id: object | None,
        *,
        timeout_seconds: float = 5.0,
    ) -> dict[str, Any]:
        return self._request(
            proxy_id,
            method="GET",
            path="/api/manage/health/clamav",
            timeout_seconds=timeout_seconds,
        ).data

    def get_logs(
        self,
        proxy_id: object | None,
        *,
        log_key: object | None = None,
        timeout_seconds: float = 5.0,
    ) -> dict[str, Any]:
        query = ""
        if log_key is not None:
            query = "?" + urllib.parse.urlencode({"log": str(log_key)})
        return self._request(
            proxy_id,
            method="GET",
            path=f"/api/manage/logs{query}",
            timeout_seconds=timeout_seconds,
        ).data

    def sync_proxy(
        self,
        proxy_id: object | None,
        *,
        force: bool = False,
        operation_id: int | None = None,
        timeout_seconds: float = 15.0,
    ) -> dict[str, Any]:
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

    def validate_config(
        self,
        proxy_id: object | None,
        config_text: str,
        *,
        timeout_seconds: float = 20.0,
    ) -> dict[str, Any]:
        return self._request(
            proxy_id,
            method="POST",
            path="/api/manage/config/validate",
            payload={"config_text": config_text or ""},
            timeout_seconds=timeout_seconds,
        ).data

    def rollback_config(
        self,
        proxy_id: object | None,
        *,
        reason: str = "",
        timeout_seconds: float = 60.0,
    ) -> dict[str, Any]:
        return self._request(
            proxy_id,
            method="POST",
            path="/api/manage/config/rollback",
            payload={"reason": reason or "Rollback requested by admin UI."},
            timeout_seconds=timeout_seconds,
        ).data

    def clear_proxy_cache(
        self,
        proxy_id: object | None,
        *,
        timeout_seconds: float = 60.0,
    ) -> dict[str, Any]:
        return self._request(
            proxy_id,
            method="POST",
            path="/api/manage/cache/clear",
            payload={},
            timeout_seconds=timeout_seconds,
        ).data

    def test_clamav_eicar(
        self,
        proxy_id: object | None,
        *,
        timeout_seconds: float = 10.0,
    ) -> dict[str, Any]:
        return self._request(
            proxy_id,
            method="POST",
            path="/api/manage/clamav/test-eicar",
            payload={},
            timeout_seconds=timeout_seconds,
        ).data

    def test_clamav_icap(
        self,
        proxy_id: object | None,
        *,
        timeout_seconds: float = 10.0,
    ) -> dict[str, Any]:
        return self._request(
            proxy_id,
            method="POST",
            path="/api/manage/clamav/test-icap",
            payload={},
            timeout_seconds=timeout_seconds,
        ).data


_store: ProxyClient | None = None
_store_lock = threading.Lock()


def get_proxy_client() -> ProxyClient:
    global _store
    if _store is not None:
        return _store
    with _store_lock:
        if _store is None:
            _store = ProxyClient()
        return _store
