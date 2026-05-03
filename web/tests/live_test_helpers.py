from __future__ import annotations

import http.cookiejar
import json
import os
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable

import pytest


_CSRF_META_RE = re.compile(r'<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\']([^"\']+)', re.IGNORECASE)
_CSRF_INPUT_RE = re.compile(r'<input[^>]+name=["\']csrf_token["\'][^>]+value=["\']([^"\']+)', re.IGNORECASE)


def _env_text(name: str, default: str) -> str:
    return (os.environ.get(name) or default).strip()


def _env_bool(name: str, default: str = "0") -> bool:
    return _env_text(name, default).lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class LiveStackConfig:
    enabled: bool
    primary_proxy_id: str
    remote_proxy_id: str
    admin_url: str
    proxy_management_url: str
    remote_proxy_management_url: str
    http_proxy_url: str
    traffic_fixture_url: str
    pac_url: str
    remote_pac_url: str
    wpad_url: str
    proxy_token: str
    username: str
    password: str
    wait_timeout_seconds: float
    request_timeout_seconds: float


LIVE_CONFIG = LiveStackConfig(
    enabled=_env_bool("LIVE_TEST_ENABLE"),
    primary_proxy_id=_env_text("LIVE_TEST_PRIMARY_PROXY_ID", "live"),
    remote_proxy_id=_env_text("LIVE_TEST_REMOTE_PROXY_ID", "edge-2"),
    admin_url=_env_text("LIVE_TEST_ADMIN_URL", "http://admin-ui:5000").rstrip("/"),
    proxy_management_url=_env_text("LIVE_TEST_PROXY_MANAGEMENT_URL", "http://proxy:5000").rstrip("/"),
    remote_proxy_management_url=_env_text("LIVE_TEST_REMOTE_PROXY_MANAGEMENT_URL", "http://proxy-edge-2:5000").rstrip("/"),
    http_proxy_url=_env_text("LIVE_TEST_HTTP_PROXY_URL", "http://proxy:3128").rstrip("/"),
    traffic_fixture_url=_env_text("LIVE_TEST_TRAFFIC_FIXTURE_URL", "http://traffic-fixture:8080").rstrip("/"),
    pac_url=_env_text("LIVE_TEST_PAC_URL", "http://proxy/proxy.pac"),
    remote_pac_url=_env_text("LIVE_TEST_REMOTE_PAC_URL", "http://proxy-edge-2/proxy.pac"),
    wpad_url=_env_text("LIVE_TEST_WPAD_URL", urllib.parse.urljoin(_env_text("LIVE_TEST_PAC_URL", "http://proxy/proxy.pac"), "/wpad.dat")),
    proxy_token=_env_text("LIVE_TEST_PROXY_TOKEN", ""),
    username=_env_text("LIVE_TEST_USERNAME", "admin"),
    password=_env_text("LIVE_TEST_PASSWORD", "admin"),
    wait_timeout_seconds=max(5.0, float(_env_text("LIVE_TEST_WAIT_TIMEOUT_SECONDS", "180"))),
    request_timeout_seconds=max(1.0, float(_env_text("LIVE_TEST_REQUEST_TIMEOUT_SECONDS", "10"))),
)

_READY_CACHE: dict[str, dict[str, Any]] | None = None


@dataclass(frozen=True)
class HttpResponse:
    url: str
    status: int
    body: bytes
    headers: dict[str, str]

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self) -> Any:
        payload = self.text.strip()
        return json.loads(payload) if payload else None


def require_live_mode() -> None:
    if not LIVE_CONFIG.enabled:
        pytest.skip("Set LIVE_TEST_ENABLE=1 to run live stack tests.")


def unique_token(prefix: str) -> str:
    safe_prefix = re.sub(r"[^a-zA-Z0-9_.-]+", "_", prefix).strip("_") or "live"
    return f"{safe_prefix}_{time.time_ns()}"


def unique_dns_label(prefix: str) -> str:
    safe_prefix = re.sub(r"[^a-zA-Z0-9-]+", "-", prefix).strip("-").lower() or "live"
    label = f"{safe_prefix[:24]}-{time.time_ns()}"
    return label[:63].strip("-") or "live"


def unique_domain(prefix: str, zone: str = "example.test") -> str:
    return f"{unique_dns_label(prefix)}.{zone.strip('.')}"


def query_params(url: str) -> dict[str, list[str]]:
    return urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)


def with_query_params(path_or_url: str, **params: Any) -> str:
    parsed = urllib.parse.urlsplit(path_or_url)
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    for key, value in params.items():
        if value is None:
            query.pop(str(key), None)
        elif isinstance(value, (list, tuple)):
            query[str(key)] = [str(item) for item in value]
        else:
            query[str(key)] = [str(value)]
    return urllib.parse.urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            urllib.parse.urlencode(query, doseq=True),
            parsed.fragment,
        )
    )


def with_proxy_id(path_or_url: str, proxy_id: object | None) -> str:
    return with_query_params(path_or_url, proxy_id=str(proxy_id or "").strip() or None)


def resolve_url(base_url: str, path_or_url: str | None = None) -> str:
    if not path_or_url:
        return base_url
    if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
        return path_or_url
    return urllib.parse.urljoin(base_url.rstrip("/") + "/", path_or_url.lstrip("/"))


def live_client_ip(target_url: str | None = None) -> str:
    parsed = urllib.parse.urlsplit(target_url or LIVE_CONFIG.http_proxy_url)
    host = parsed.hostname or "proxy"
    port = int(parsed.port or (443 if parsed.scheme == "https" else 80))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect((host, port))
        return str(sock.getsockname()[0])


def extract_csrf_token(html: str) -> str:
    for pattern in (_CSRF_META_RE, _CSRF_INPUT_RE):
        match = pattern.search(html)
        if match:
            return match.group(1)
    raise AssertionError("Could not locate a CSRF token in the rendered HTML.")


def _read_response(opener: Any, request: urllib.request.Request, *, timeout_seconds: float | None = None) -> HttpResponse:
    timeout_value = timeout_seconds if timeout_seconds is not None else LIVE_CONFIG.request_timeout_seconds
    try:
        with opener.open(request, timeout=timeout_value) as response:
            return HttpResponse(
                url=response.geturl(),
                status=int(response.status),
                body=response.read(),
                headers=dict(response.headers.items()),
            )
    except urllib.error.HTTPError as exc:
        return HttpResponse(
            url=exc.geturl(),
            status=int(exc.code),
            body=exc.read(),
            headers=dict(exc.headers.items()),
        )


def _wait_for_response(
    requester: Callable[[], HttpResponse],
    *,
    accept: Callable[[HttpResponse], bool],
    description: str,
    timeout_seconds: float | None = None,
) -> HttpResponse:
    deadline = time.time() + (timeout_seconds or LIVE_CONFIG.wait_timeout_seconds)
    last_error: Exception | None = None
    last_response: HttpResponse | None = None
    while time.time() < deadline:
        try:
            response = requester()
            last_response = response
            if accept(response):
                return response
            last_error = AssertionError(f"Unexpected response while waiting for {description}: HTTP {response.status} @ {response.url}")
        except Exception as exc:  # pragma: no cover - only used during stack convergence failures
            last_error = exc
        time.sleep(1.0)

    detail = f" Last response was HTTP {last_response.status} @ {last_response.url}." if last_response is not None else ""
    raise AssertionError(f"Timed out waiting for {description}.{detail}") from last_error


def _wait_for_value(
    reader: Callable[[], Any],
    *,
    accept: Callable[[Any], bool],
    description: str,
    timeout_seconds: float | None = None,
) -> Any:
    deadline = time.time() + (timeout_seconds or LIVE_CONFIG.wait_timeout_seconds)
    last_error: Exception | None = None
    last_value: Any = None
    while time.time() < deadline:
        try:
            value = reader()
            last_value = value
            if accept(value):
                return value
            last_error = AssertionError(f"Unexpected value while waiting for {description}: {value!r}")
        except Exception as exc:  # pragma: no cover - only used during convergence failures
            last_error = exc
        time.sleep(1.0)

    detail = f" Last value was {last_value!r}." if last_value is not None else ""
    raise AssertionError(f"Timed out waiting for {description}.{detail}") from last_error


def wait_for_json_url(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    description: str,
    accept: Callable[[dict[str, Any], HttpResponse], bool] | None = None,
) -> dict[str, Any]:
    def _request() -> HttpResponse:
        request = urllib.request.Request(url, headers=headers or {}, method="GET")
        return _read_response(urllib.request.build_opener(), request)

    def _accept(response: HttpResponse) -> bool:
        if response.status != 200:
            return False
        payload = response.json()
        if not isinstance(payload, dict):
            return False
        if accept is None:
            return payload.get("ok") is True
        return accept(payload, response)

    response = _wait_for_response(_request, accept=_accept, description=description)
    payload = response.json()
    if not isinstance(payload, dict):
        raise AssertionError(f"Expected a JSON object from {url!r}, got {type(payload).__name__}.")
    return payload


def management_auth_headers(*, include_content_type: bool = False) -> dict[str, str]:
    headers: dict[str, str] = {}
    if LIVE_CONFIG.proxy_token:
        headers["Authorization"] = f"Bearer {LIVE_CONFIG.proxy_token}"
    if include_content_type:
        headers["Content-Type"] = "application/json"
    return headers


def wait_for_proxy_management_payload(*, require_ok: bool | None = None) -> dict[str, Any]:
    return wait_for_json_url(
        resolve_url(LIVE_CONFIG.proxy_management_url, "/api/manage/health"),
        headers=management_auth_headers(),
        description="proxy management health",
        accept=lambda payload, _response: payload.get("status") in {"healthy", "degraded"}
        and str(payload.get("proxy_id") or "") == LIVE_CONFIG.primary_proxy_id
        and (require_ok is None or bool(payload.get("ok")) is require_ok),
    )


def wait_for_remote_proxy_management_payload(*, require_ok: bool | None = None) -> dict[str, Any]:
    return wait_for_json_url(
        resolve_url(LIVE_CONFIG.remote_proxy_management_url, "/api/manage/health"),
        headers=management_auth_headers(),
        description="remote proxy management health",
        accept=lambda payload, _response: payload.get("status") in {"healthy", "degraded"}
        and str(payload.get("proxy_id") or "") == LIVE_CONFIG.remote_proxy_id
        and (require_ok is None or bool(payload.get("ok")) is require_ok),
    )


def ensure_live_stack_ready() -> dict[str, dict[str, Any]]:
    global _READY_CACHE
    if _READY_CACHE is not None:
        return _READY_CACHE
    require_live_mode()
    proxy_client = LiveStackClient()
    _READY_CACHE = {
        "admin": wait_for_json_url(resolve_url(LIVE_CONFIG.admin_url, "/health"), description="admin health"),
        "proxy": wait_for_json_url(resolve_url(LIVE_CONFIG.proxy_management_url, "/health"), description="proxy public health"),
        "remote_proxy": wait_for_remote_proxy_management_payload(),
        "traffic_fixture": wait_for_json_url(resolve_url(LIVE_CONFIG.traffic_fixture_url, "/health"), description="traffic fixture health"),
        "http_proxy": wait_for_proxy_fixture_response(proxy_client, "/health").json(),
    }
    return _READY_CACHE


def wait_for_proxy_inventory(
    client: "LiveStackClient",
    proxy_ids: list[str] | tuple[str, ...],
    *,
    timeout_seconds: float | None = None,
) -> HttpResponse:
    wanted = [str(proxy_id).strip() for proxy_id in proxy_ids if str(proxy_id).strip()]
    return _wait_for_response(
        lambda: client.admin_request("/proxies"),
        accept=lambda response: response.status == 200 and all(proxy_id in response.text for proxy_id in wanted),
        description=f"proxy inventory containing {wanted!r}",
        timeout_seconds=timeout_seconds,
    )


def _config_revisions_store() -> Any:
    from services.config_revisions import get_config_revisions  # type: ignore

    return get_config_revisions()


def _proxy_registry_store() -> Any:
    from services.proxy_registry import get_proxy_registry  # type: ignore

    return get_proxy_registry()


def _certificate_bundle_store() -> Any:
    from services.certificate_bundles import get_certificate_bundles  # type: ignore

    return get_certificate_bundles()


def active_config_text(proxy_id: object | None) -> str:
    return str(_config_revisions_store().get_active_config_text(proxy_id) or "")


def active_config_revision(proxy_id: object | None) -> Any:
    return _config_revisions_store().get_active_revision(proxy_id)


def latest_config_apply(proxy_id: object | None) -> Any:
    return _config_revisions_store().latest_apply(proxy_id)


def wait_for_config_apply(
    proxy_id: object | None,
    *,
    revision_id: int | None = None,
    after_ts: int | None = None,
    timeout_seconds: float | None = None,
) -> Any:
    def _accept(application: Any) -> bool:
        if application is None:
            return False
        if revision_id is not None and int(getattr(application, "revision_id", 0) or 0) != int(revision_id):
            return False
        if after_ts is not None and int(getattr(application, "applied_ts", 0) or 0) <= int(after_ts):
            return False
        return True

    return _wait_for_value(
        lambda: latest_config_apply(proxy_id),
        accept=_accept,
        description=f"config apply for proxy {proxy_id!r}",
        timeout_seconds=timeout_seconds,
    )


def registry_proxy(proxy_id: object | None) -> Any:
    proxy = _proxy_registry_store().get_proxy(proxy_id)
    if proxy is None:
        raise AssertionError(f"Proxy {proxy_id!r} is not registered.")
    return proxy


def active_certificate_bundle() -> Any:
    return _certificate_bundle_store().get_active_bundle()


def latest_certificate_apply(proxy_id: object | None) -> Any:
    return _certificate_bundle_store().latest_apply(proxy_id)


def wait_for_certificate_apply(
    proxy_id: object | None,
    *,
    revision_id: int | None = None,
    after_ts: int | None = None,
    timeout_seconds: float | None = None,
) -> Any:
    def _accept(application: Any) -> bool:
        if application is None:
            return False
        if revision_id is not None and int(getattr(application, "revision_id", 0) or 0) != int(revision_id):
            return False
        if after_ts is not None and int(getattr(application, "applied_ts", 0) or 0) <= int(after_ts):
            return False
        return True

    return _wait_for_value(
        lambda: latest_certificate_apply(proxy_id),
        accept=_accept,
        description=f"certificate apply for proxy {proxy_id!r}",
        timeout_seconds=timeout_seconds,
    )


def wait_for_admin_contains(
    client: "LiveStackClient",
    path_or_url: str,
    needle: str,
    *,
    timeout_seconds: float | None = None,
) -> HttpResponse:
    resolved_url = resolve_url(LIVE_CONFIG.admin_url, path_or_url)
    return _wait_for_response(
        lambda: client.admin_request(resolved_url),
        accept=lambda response: response.status == 200 and needle in response.text,
        description=f"admin page {resolved_url!r} containing {needle!r}",
        timeout_seconds=timeout_seconds,
    )


def wait_for_proxy_fixture_response(
    client: "LiveStackClient",
    path_or_url: str | None = None,
    *,
    method: str = "GET",
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout_seconds: float | None = None,
    needle: str | None = None,
) -> HttpResponse:
    resolved_url = resolve_url(LIVE_CONFIG.traffic_fixture_url, path_or_url)
    return _wait_for_response(
        lambda: client.proxy_fixture_request(
            resolved_url,
            method=method,
            data=data,
            headers=headers,
            timeout_seconds=timeout_seconds,
        ),
        accept=lambda response: response.status == 200 and (needle is None or needle in response.text),
        description=f"proxy fixture request {resolved_url!r}",
        timeout_seconds=timeout_seconds,
    )


class LiveStackClient:
    def __init__(self) -> None:
        cookie_jar = http.cookiejar.CookieJar()
        self._opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie_jar))
        self._proxy_opener = urllib.request.build_opener(
            urllib.request.ProxyHandler(
                {
                    "http": LIVE_CONFIG.http_proxy_url,
                    "https": LIVE_CONFIG.http_proxy_url,
                }
            )
        )
        self._csrf_token = ""

    def request(
        self,
        url: str,
        *,
        method: str = "GET",
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
        timeout_seconds: float | None = None,
    ) -> HttpResponse:
        request = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
        response = _read_response(self._opener, request, timeout_seconds=timeout_seconds)
        try:
            self._csrf_token = extract_csrf_token(response.text)
        except Exception:
            pass
        return response

    def admin_request(self, path_or_url: str, **kwargs: Any) -> HttpResponse:
        return self.request(resolve_url(LIVE_CONFIG.admin_url, path_or_url), **kwargs)

    def request_to_base(self, base_url: str, path_or_url: str | None = None, **kwargs: Any) -> HttpResponse:
        return self.request(resolve_url(base_url, path_or_url), **kwargs)

    def proxy_public_request(self, path_or_url: str, **kwargs: Any) -> HttpResponse:
        return self.request(resolve_url(LIVE_CONFIG.proxy_management_url, path_or_url), **kwargs)

    def remote_proxy_public_request(self, path_or_url: str, **kwargs: Any) -> HttpResponse:
        return self.request(resolve_url(LIVE_CONFIG.remote_proxy_management_url, path_or_url), **kwargs)

    def proxy_management_request(self, path_or_url: str, *, auth: bool = True, headers: dict[str, str] | None = None, **kwargs: Any) -> HttpResponse:
        merged_headers: dict[str, str] = {}
        if auth:
            merged_headers.update(management_auth_headers())
        if headers:
            merged_headers.update(headers)
        return self.request(resolve_url(LIVE_CONFIG.proxy_management_url, path_or_url), headers=merged_headers, **kwargs)

    def pac_request(self, path_or_url: str | None = None, **kwargs: Any) -> HttpResponse:
        return self.request(resolve_url(LIVE_CONFIG.pac_url, path_or_url), **kwargs)

    def remote_pac_request(self, path_or_url: str | None = None, **kwargs: Any) -> HttpResponse:
        return self.request(resolve_url(LIVE_CONFIG.remote_pac_url, path_or_url), **kwargs)

    def wpad_request(self, path_or_url: str | None = None, **kwargs: Any) -> HttpResponse:
        return self.request(resolve_url(LIVE_CONFIG.wpad_url, path_or_url), **kwargs)

    def traffic_fixture_request(self, path_or_url: str | None = None, **kwargs: Any) -> HttpResponse:
        return self.request(resolve_url(LIVE_CONFIG.traffic_fixture_url, path_or_url), **kwargs)

    def proxy_fixture_request(
        self,
        path_or_url: str | None = None,
        *,
        method: str = "GET",
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
        timeout_seconds: float | None = None,
    ) -> HttpResponse:
        request = urllib.request.Request(
            resolve_url(LIVE_CONFIG.traffic_fixture_url, path_or_url),
            data=data,
            headers=headers or {},
            method=method,
        )
        return _read_response(self._proxy_opener, request, timeout_seconds=timeout_seconds)

    def refresh_csrf(self, path: str = "/") -> str:
        response = self.admin_request(path)
        self._csrf_token = extract_csrf_token(response.text)
        return self._csrf_token

    def login(self, username: str | None = None, password: str | None = None, *, next_url: str = "", expect_success: bool = True) -> HttpResponse:
        login_page = self.admin_request("/login")
        token = extract_csrf_token(login_page.text)
        payload = urllib.parse.urlencode(
            {
                "username": username or LIVE_CONFIG.username,
                "password": password or LIVE_CONFIG.password,
                "csrf_token": token,
                "next": next_url,
            }
        ).encode("utf-8")
        response = self.admin_request(
            "/login",
            method="POST",
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if expect_success:
            assert response.status == 200, f"Expected successful login flow, got HTTP {response.status} @ {response.url}."
            assert "Sign-in failed" not in response.text
            if not self._csrf_token:
                self._csrf_token = token
        else:
            assert response.status == 200, f"Expected failed login page render, got HTTP {response.status} @ {response.url}."
            assert "Sign-in failed" in response.text
        return response

    def logout(self) -> HttpResponse:
        return self.admin_post_form("/logout", {})

    def admin_post_form(
        self,
        path_or_url: str,
        fields: dict[str, Any],
        *,
        csrf_path: str = "/",
        include_csrf: bool = True,
        timeout_seconds: float | None = None,
    ) -> HttpResponse:
        payload = dict(fields)
        if include_csrf and "csrf_token" not in payload:
            payload["csrf_token"] = self._csrf_token or self.refresh_csrf(csrf_path)
        encoded = urllib.parse.urlencode({key: "" if value is None else value for key, value in payload.items()}).encode("utf-8")
        return self.admin_request(
            path_or_url,
            method="POST",
            data=encoded,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout_seconds=timeout_seconds,
        )

    def admin_post_json(self, path_or_url: str, payload: dict[str, Any]) -> HttpResponse:
        return self.admin_request(
            path_or_url,
            method="POST",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "X-CSRF-Token": self._csrf_token or self.refresh_csrf("/")},
        )

    def proxy_management_post_json(
        self,
        path_or_url: str,
        payload: dict[str, Any],
        *,
        auth: bool = True,
        timeout_seconds: float | None = None,
    ) -> HttpResponse:
        headers = management_auth_headers(include_content_type=True) if auth else {"Content-Type": "application/json"}
        return self.proxy_management_request(
            path_or_url,
            auth=False,
            method="POST",
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            timeout_seconds=timeout_seconds,
        )

    def remote_proxy_management_request(self, path_or_url: str, *, auth: bool = True, headers: dict[str, str] | None = None, **kwargs: Any) -> HttpResponse:
        merged_headers: dict[str, str] = {}
        if auth:
            merged_headers.update(management_auth_headers())
        if headers:
            merged_headers.update(headers)
        return self.request(resolve_url(LIVE_CONFIG.remote_proxy_management_url, path_or_url), headers=merged_headers, **kwargs)

    def remote_proxy_management_post_json(
        self,
        path_or_url: str,
        payload: dict[str, Any],
        *,
        auth: bool = True,
        timeout_seconds: float | None = None,
    ) -> HttpResponse:
        headers = management_auth_headers(include_content_type=True) if auth else {"Content-Type": "application/json"}
        return self.remote_proxy_management_request(
            path_or_url,
            auth=False,
            method="POST",
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            timeout_seconds=timeout_seconds,
        )


@pytest.fixture(scope="session")
def live_stack_ready() -> dict[str, dict[str, Any]]:
    return ensure_live_stack_ready()


@pytest.fixture
def admin_client() -> LiveStackClient:
    _ = ensure_live_stack_ready()
    client = LiveStackClient()
    client.login()
    return client