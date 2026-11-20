"""Golden client-observable contract of the ``proxy_api`` management listener.

Every scenario drives ``proxy.app.app`` through a raw, gunicorn-shaped WSGI
environ and compares the status line, the full ordered header list and the
body bytes against ``golden/proxy_management_responses.json``, together with
the runtime calls the request made. The golden file was recorded from the
Flask implementation (Flask 3.1.3 / Werkzeug 3.1.9) and is the independent
oracle for any replacement implementation, except for the entries of
deliberate behaviour fixes made afterwards, which the dedicated tests at the
end of this file pin independently.

Normalizations, each for a value that is not stable between runs:
- ``Date`` values (wall clock) become ``<http-date>`` after a format check;
- ``Allow`` tokens are sorted (Flask emits them in hash-seed order);
- gzip bodies are recorded as their identity bytes after checking that the
  member is exactly the level-5 compression with MTIME zeroed.
"""

from __future__ import annotations

import base64
import datetime as dt
import decimal
import gzip
import importlib
import io
import json
import re
import sys
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import unquote_to_bytes

import pytest

GOLDEN_PATH = Path(__file__).with_name("golden") / "proxy_management_responses.json"
TOKEN = "secret-token"
_HTTP_DATE = re.compile(
    r"(Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} "
    r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} "
    r"\d{2}:\d{2}:\d{2} GMT\Z",
)
_FIXED_TIME = 1_700_000_000.75
_AUTH = ("Authorization", f"Bearer {TOKEN}")
_JSON = "application/json"
_LARGE_CONFIG = "".join(
    f"acl net{index} src 10.{index}.0.0/16\n" for index in range(80)
)
_ACCESS_LOG = "".join(
    f"1700000000.{index:03d} 12 10.0.0.{index} TCP_MISS/200 512 GET http://site{index}.example/ - HIER_DIRECT\n"
    for index in range(40)
)


class _Recorder:
    """Deterministic fake ``ProxyRuntime`` whose behaviour a scenario selects."""

    proxy_id = "edge-a"

    def __init__(self, mode: str, calls: list[Any]) -> None:
        self.mode = mode
        self.calls = calls

    def _call(self, name: str, **kwargs: Any) -> None:
        self.calls.append([name, {key: kwargs[key] for key in sorted(kwargs)}])
        if self.mode == "raises":
            message = "runtime failure password=hunter2"
            raise RuntimeError(message)
        if self.mode == "raises_value":
            message = "invalid input token=abc123"
            raise ValueError(message)

    def _result(self, name: str) -> dict[str, Any]:
        ok = self.mode != "fail"
        return {"ok": ok, "detail": f"{name} {'done' if ok else 'failed'}"}

    def collect_health(self, *, force: bool = False) -> dict[str, Any]:
        self._call("collect_health", force=force)
        if self.mode == "rich":
            return {
                "ok": True,
                "status": "healthy",
                "proxy_id": self.proxy_id,
                "checked_at": dt.datetime(2026, 1, 2, 3, 4, 5, tzinfo=dt.UTC),
                "naive": dt.datetime(2026, 1, 2, 3, 4, 5),  # ruff: ignore[call-datetime-without-tzinfo] -- Flask treats naive as UTC
                "day": dt.date(2026, 1, 2),
                "ratio": decimal.Decimal("1.50"),
                "id": uuid.UUID("12345678-1234-5678-1234-567812345678"),
                "label": "café ☕ \u2028 </script>",
                "floats": [0.1, 1e20, -0.0],
                "nested": {"b": [1, 2, {"z": None, "a": True}], "a": "x" * 1200},
                "tuple": (1, "two"),
            }
        return {
            "ok": True,
            "status": "healthy",
            "proxy_id": self.proxy_id,
            "health_scope": "full",
            "services": {"squid": {"ok": True}},
            "stats": {},
        }

    def collect_navigation_health(self, *, force: bool = False) -> dict[str, Any]:
        self._call("collect_navigation_health", force=force)
        return {
            "ok": True,
            "status": "healthy",
            "proxy_id": self.proxy_id,
            "health_scope": "navigation",
            "services": {},
            "stats": {},
        }

    def collect_clamav_health(self, *, force: bool = False) -> dict[str, Any]:
        self._call("collect_clamav_health", force=force)
        return {"ok": True, "status": "healthy", "services": {"clamd": {"ok": True}}}

    def sync_from_db(self, *, force: bool = False, operation_id: Any = None):
        self._call("sync_from_db", force=force, operation_id=operation_id)
        return self._result("sync")

    def get_current_config_text(self) -> Any:
        self._call("get_current_config_text")
        return {
            "fail": "",
            "none": None,
            "blank": "  \n",
            "large": _LARGE_CONFIG,
            "unicode": "visible_hostname café\n",
        }.get(self.mode, "http_port 3128\n")

    def validate_config_text(self, config_text: str) -> dict[str, Any]:
        self._call("validate_config_text", config_text=config_text)
        return self._result("validate")

    def rollback_last_known_good_config(self, *, reason: str) -> dict[str, Any]:
        self._call("rollback_last_known_good_config", reason=reason)
        return self._result("rollback")

    def clear_cache(self) -> dict[str, Any]:
        self._call("clear_cache")
        return self._result("cache_clear")

    def test_clamav_eicar(self) -> dict[str, Any]:
        self._call("test_clamav_eicar")
        return self._result("eicar")

    def test_clamav_icap(self) -> dict[str, Any]:
        self._call("test_clamav_icap")
        return self._result("icap")

    def test_control_supervisor_program(self, program_name: str, *, action: str):
        self._call(
            "test_control_supervisor_program",
            program_name=program_name,
            action=action,
        )
        return {
            "ok": program_name == "cicap_adblock",
            "program": program_name,
            "action": action,
        }


def _fake_read_proxy_log(calls: list[Any]):
    """Deterministic ``read_proxy_log`` stand-in that records its arguments."""

    def read_proxy_log(key: Any, **kwargs: Any) -> dict[str, Any]:
        calls.append(["read_proxy_log", {"key": key, **kwargs}])
        normalized = str(key or "").strip()
        if normalized in {"access", "icap"}:
            content = _ACCESS_LOG if normalized == "access" else "icap line\n"
            return {
                "ok": True,
                "status": "ok",
                "key": normalized,
                "content": content[-kwargs.get("max_bytes", len(content)) :],
                "max_bytes": kwargs.get("max_bytes", 262144),
            }
        if normalized == "cache":
            return {"ok": False, "status": "missing", "key": "cache", "content": ""}
        if normalized == "boom":
            return {"ok": False, "status": "unavailable", "detail": "read failed"}
        return {"ok": False, "status": "not_found", "detail": "not allowlisted"}

    return read_proxy_log


def _s(name: str, method: str, target: str, **extra: Any) -> dict[str, Any]:
    scenario: dict[str, Any] = {
        "name": name,
        "method": method,
        "target": target,
        "headers": [_AUTH],
    }
    scenario.update(extra)
    return scenario


def _post(name: str, target: str, body: bytes | None = None, **extra: Any):
    headers = [_AUTH]
    if body is not None:
        headers += [("Content-Type", _JSON), ("Content-Length", str(len(body)))]
    headers += extra.pop("extra_headers", [])
    return _s(name, "POST", target, headers=headers, body=body or b"", **extra)


_NO_AUTH: list[tuple[str, str]] = []

SCENARIOS: list[dict[str, Any]] = [
    # --- unauthenticated listener health ---------------------------------
    _s("health_get", "GET", "/health", headers=_NO_AUTH),
    _s("health_head", "HEAD", "/health", headers=_NO_AUTH),
    _s("health_options", "OPTIONS", "/health", headers=_NO_AUTH),
    _s("health_post", "POST", "/health", headers=_NO_AUTH),
    _s("health_delete", "DELETE", "/health", headers=_NO_AUTH),
    _s("health_query", "GET", "/health?full=1", headers=_NO_AUTH),
    _s("health_trailing_slash", "GET", "/health/", headers=_NO_AUTH),
    _s("health_double_slash", "GET", "//health", headers=_NO_AUTH),
    _s("health_double_slash_query", "GET", "//health?a=1&b=%20", headers=_NO_AUTH),
    _s(
        "health_double_slash_no_host",
        "GET",
        "//health",
        headers=_NO_AUTH,
        host=None,
    ),
    _s(
        "health_double_slash_host_port",
        "GET",
        "//health",
        headers=_NO_AUTH,
        host="Proxy.Example:80",
    ),
    _s("health_double_slash_post", "POST", "//health", headers=_NO_AUTH),
    _s("health_spa", "GET", "/health", headers=[("X-Requested-With", "SPA")]),
    _s(
        "health_gzip_small",
        "GET",
        "/health",
        headers=[("Accept-Encoding", "gzip")],
    ),
    _s(
        "health_websocket",
        "GET",
        "/health",
        headers=[("Connection", "Upgrade"), ("Upgrade", "websocket")],
    ),
    # --- authentication --------------------------------------------------
    _s("auth_missing", "GET", "/api/manage/health", headers=_NO_AUTH),
    _s(
        "auth_wrong",
        "GET",
        "/api/manage/health",
        headers=[("Authorization", "Bearer wrong")],
    ),
    _s(
        "auth_lowercase_bearer",
        "GET",
        "/api/manage/health",
        headers=[("Authorization", f"bearer {TOKEN}")],
    ),
    _s(
        "auth_bearer_spaces",
        "GET",
        "/api/manage/health",
        headers=[("Authorization", f"  Bearer   {TOKEN}  ")],
    ),
    _s(
        "auth_bearer_empty",
        "GET",
        "/api/manage/health",
        headers=[("Authorization", "Bearer "), ("X-Proxy-Token", TOKEN)],
    ),
    _s(
        "auth_x_proxy_token",
        "GET",
        "/api/manage/health",
        headers=[("X-Proxy-Token", f" {TOKEN} ")],
    ),
    _s(
        "auth_basic_with_x_proxy_token",
        "GET",
        "/api/manage/health",
        headers=[("Authorization", "Basic abc"), ("X-Proxy-Token", TOKEN)],
    ),
    _s(
        "auth_bad_bearer_with_x_proxy_token",
        "GET",
        "/api/manage/health",
        headers=[("Authorization", "Bearer wrong"), ("X-Proxy-Token", TOKEN)],
    ),
    _s("auth_no_expected_token", "GET", "/api/manage/health", token=None),
    _s(
        "auth_no_expected_token_empty_provided",
        "GET",
        "/api/manage/health",
        token="  ",
        headers=[("Authorization", "Bearer ")],
    ),
    _s(
        "auth_expected_token_whitespace",
        "GET",
        "/api/manage/health",
        token=f"  {TOKEN}\t",
    ),
    _s(
        "auth_non_ascii_token",
        "GET",
        "/api/manage/health",
        headers=[("Authorization", "Bearer s\xe9cret")],
    ),
    _s("auth_missing_post_sync", "POST", "/api/manage/sync", headers=_NO_AUTH),
    _s(
        "auth_missing_not_ready",
        "POST",
        "/api/manage/sync",
        headers=_NO_AUTH,
        ready=False,
    ),
    _s(
        "auth_missing_supervisor",
        "POST",
        "/api/manage/test/supervisor/cicap_adblock/restart",
        headers=_NO_AUTH,
    ),
    _s("auth_missing_head", "HEAD", "/api/manage/health", headers=_NO_AUTH),
    # --- management health -----------------------------------------------
    _s("manage_health", "GET", "/api/manage/health"),
    _s("manage_health_head", "HEAD", "/api/manage/health"),
    _s("manage_health_options", "OPTIONS", "/api/manage/health", headers=_NO_AUTH),
    _s("manage_health_post", "POST", "/api/manage/health"),
    _s("manage_health_full", "GET", "/api/manage/health?full=1"),
    _s("manage_health_full_word", "GET", "/api/manage/health?full=%20FULL%20"),
    _s("manage_health_full_yes_force", "GET", "/api/manage/health?full=yes&force=YES"),
    _s("manage_health_full_zero", "GET", "/api/manage/health?full=0&force=1"),
    _s("manage_health_full_repeated", "GET", "/api/manage/health?full=0&full=1"),
    _s("manage_health_full_plus", "GET", "/api/manage/health?full=+true+"),
    _s("manage_health_force_full_word", "GET", "/api/manage/health?force=full"),
    _s("manage_health_bad_percent", "GET", "/api/manage/health?full=%zz&force=%FF"),
    _s("manage_health_semicolon", "GET", "/api/manage/health?full=1;force=1"),
    _s("manage_health_blank_key", "GET", "/api/manage/health?full&force="),
    _s(
        "manage_health_full_rich_gzip",
        "GET",
        "/api/manage/health?full=1",
        runtime="rich",
        headers=[_AUTH, ("Accept-Encoding", "gzip, deflate")],
    ),
    _s(
        "manage_health_full_rich_plain",
        "GET",
        "/api/manage/health?full=1",
        runtime="rich",
    ),
    _s(
        "manage_health_full_rich_gzip_disabled",
        "GET",
        "/api/manage/health?full=1",
        runtime="rich",
        env={"ENABLE_GZIP_RESPONSES": "0"},
        headers=[_AUTH, ("Accept-Encoding", "gzip")],
    ),
    _s(
        "manage_health_full_rich_head_gzip",
        "HEAD",
        "/api/manage/health?full=1",
        runtime="rich",
        headers=[_AUTH, ("Accept-Encoding", "gzip")],
    ),
    _s("manage_health_raises", "GET", "/api/manage/health", runtime="raises"),
    _s(
        "manage_health_full_raises",
        "GET",
        "/api/manage/health?full=1",
        runtime="raises",
    ),
    _s(
        "manage_health_raises_value",
        "GET",
        "/api/manage/health",
        runtime="raises_value",
    ),
    _s(
        "manage_health_raises_exposed",
        "GET",
        "/api/manage/health",
        runtime="raises",
        env={"EXPOSE_INTERNAL_ERRORS": "1"},
    ),
    _s(
        "manage_health_get_runtime_raises",
        "GET",
        "/api/manage/health",
        runtime="get_runtime_raises",
    ),
    _s(
        "manage_health_lazy_runtime",
        "GET",
        "/api/manage/health",
        runtime="lazy",
    ),
    _s("manage_health_trailing_slash", "GET", "/api/manage/health/"),
    _s("manage_health_double_slash", "GET", "/api//manage/health?full=1"),
    _s(
        "manage_health_spa",
        "GET",
        "/api/manage/health",
        headers=[_AUTH, ("X-Requested-With", "spa")],
    ),
    _s("clamav_health", "GET", "/api/manage/health/clamav"),
    _s("clamav_health_force", "GET", "/api/manage/health/clamav?force=true"),
    _s("clamav_health_raises", "GET", "/api/manage/health/clamav", runtime="raises"),
    _s(
        "clamav_health_get_runtime_raises",
        "GET",
        "/api/manage/health/clamav",
        runtime="get_runtime_raises",
    ),
    # --- logs ------------------------------------------------------------
    _s("logs_access", "GET", "/api/manage/logs?log=access"),
    _s(
        "logs_access_gzip",
        "GET",
        "/api/manage/logs?log=access",
        headers=[_AUTH, ("Accept-Encoding", "gzip")],
    ),
    _s("logs_access_tail", "GET", "/api/manage/logs?log=access&max_bytes=100"),
    _s("logs_max_bytes_invalid", "GET", "/api/manage/logs?log=access&max_bytes=abc"),
    _s("logs_max_bytes_zero", "GET", "/api/manage/logs?log=access&max_bytes=0"),
    _s("logs_max_bytes_blank", "GET", "/api/manage/logs?log=access&max_bytes=%20"),
    _s("logs_max_bytes_huge", "GET", "/api/manage/logs?log=access&max_bytes=99999999"),
    _s("logs_missing_file", "GET", "/api/manage/logs?log=cache"),
    _s("logs_unknown", "GET", "/api/manage/logs?log=passwd"),
    _s("logs_no_param", "GET", "/api/manage/logs"),
    _s("logs_padded_key", "GET", "/api/manage/logs?log=%20icap%20"),
    _s("logs_bad_utf8", "GET", "/api/manage/logs?log=%FF"),
    _s("logs_head", "HEAD", "/api/manage/logs?log=access"),
    _s("logs_unavailable", "GET", "/api/manage/logs?log=boom"),
    _s("logs_post", "POST", "/api/manage/logs"),
    # --- sync ------------------------------------------------------------
    _post("sync_no_body", "/api/manage/sync"),
    _post("sync_empty_object", "/api/manage/sync", b"{}"),
    _post(
        "sync_operation_id", "/api/manage/sync", b'{"operation_id": 7, "force": true}'
    ),
    _post("sync_operation_id_string", "/api/manage/sync", b'{"operation_id": "7"}'),
    _post("sync_operation_id_zero", "/api/manage/sync", b'{"operation_id": 0}'),
    _post("sync_operation_id_negative", "/api/manage/sync", b'{"operation_id": -3}'),
    _post("sync_operation_id_bool", "/api/manage/sync", b'{"operation_id": true}'),
    _post("sync_operation_id_float", "/api/manage/sync", b'{"operation_id": 1.0}'),
    _post("sync_operation_id_null", "/api/manage/sync", b'{"operation_id": null}'),
    _post("sync_force_string_yes", "/api/manage/sync", b'{"force": " YES "}'),
    _post("sync_force_string_off", "/api/manage/sync", b'{"force": "off"}'),
    _post("sync_force_string_bad", "/api/manage/sync", b'{"force": "maybe"}'),
    _post("sync_force_int", "/api/manage/sync", b'{"force": 1}'),
    _post("sync_force_null", "/api/manage/sync", b'{"force": null}'),
    _post("sync_ok", "/api/manage/sync", b"{}", runtime="ok"),
    _post("sync_fail_409", "/api/manage/sync", b"{}", runtime="fail"),
    _post("sync_raises", "/api/manage/sync", b"{}", runtime="raises"),
    _post("sync_raises_value", "/api/manage/sync", b"{}", runtime="raises_value"),
    _post("sync_not_ready", "/api/manage/sync", b"{}", ready=False),
    _post("sync_not_ready_bad_body", "/api/manage/sync", b"[", ready=False),
    _s("sync_get", "GET", "/api/manage/sync"),
    _s("sync_head", "HEAD", "/api/manage/sync"),
    _s("sync_options", "OPTIONS", "/api/manage/sync", headers=_NO_AUTH),
    _s("sync_put", "PUT", "/api/manage/sync"),
    _post("sync_double_slash", "/api/manage//sync", b"{}"),
    # --- JSON payload admission ------------------------------------------
    _post("payload_array", "/api/manage/sync", b"[1, 2]"),
    _post("payload_string", "/api/manage/sync", b'"x"'),
    _post("payload_null", "/api/manage/sync", b"null"),
    _post("payload_malformed", "/api/manage/sync", b'{"force": tru'),
    _post("payload_whitespace", "/api/manage/sync", b"   "),
    _post("payload_nan", "/api/manage/sync", b'{"force": false, "x": NaN}'),
    _post("payload_bad_utf8", "/api/manage/sync", b'{"x": "\xff"}'),
    _post(
        "payload_utf16",
        "/api/manage/sync",
        '{"force": true}'.encode("utf-16"),
    ),
    _post("payload_utf8_bom", "/api/manage/sync", b'\xef\xbb\xbf{"force": true}'),
    _post(
        "payload_duplicate_keys", "/api/manage/sync", b'{"force": "x", "force": true}'
    ),
    _s(
        "payload_text_plain",
        "POST",
        "/api/manage/sync",
        headers=[_AUTH, ("Content-Type", "text/plain"), ("Content-Length", "2")],
        body=b"{}",
    ),
    _s(
        "payload_no_content_type",
        "POST",
        "/api/manage/sync",
        headers=[_AUTH, ("Content-Length", "2")],
        body=b"{}",
    ),
    _s(
        "payload_json_charset",
        "POST",
        "/api/manage/sync",
        headers=[
            _AUTH,
            ("Content-Type", "Application/JSON; charset=utf-8"),
            ("Content-Length", "2"),
        ],
        body=b"{}",
    ),
    _s(
        "payload_vendor_json",
        "POST",
        "/api/manage/sync",
        headers=[
            _AUTH,
            ("Content-Type", "application/vnd.proxy+json"),
            ("Content-Length", "2"),
        ],
        body=b"{}",
    ),
    _s(
        "payload_text_json_suffix",
        "POST",
        "/api/manage/sync",
        headers=[_AUTH, ("Content-Type", "text/x+json"), ("Content-Length", "2")],
        body=b"{}",
    ),
    _s(
        "payload_zero_length_text_plain",
        "POST",
        "/api/manage/sync",
        headers=[_AUTH, ("Content-Type", "text/plain"), ("Content-Length", "0")],
    ),
    _s(
        "payload_chunked_ok",
        "POST",
        "/api/manage/sync",
        headers=[_AUTH, ("Content-Type", _JSON), ("Transfer-Encoding", "chunked")],
        body=b'{"force": true}',
    ),
    _s(
        "payload_chunked_with_length",
        "POST",
        "/api/manage/sync",
        headers=[
            _AUTH,
            ("Content-Type", _JSON),
            ("Transfer-Encoding", "gzip, chunked"),
            ("Content-Length", "999999999"),
        ],
        body=b'{"force": true}',
    ),
    _s(
        "payload_chunked_empty_text_plain",
        "POST",
        "/api/manage/sync",
        headers=[_AUTH, ("Content-Type", "text/plain")],
    ),
    _s(
        "payload_chunked_text_plain",
        "POST",
        "/api/manage/sync",
        headers=[_AUTH, ("Content-Type", "text/plain")],
        body=b"{}",
    ),
    _s(
        "payload_declared_too_large",
        "POST",
        "/api/manage/sync",
        headers=[_AUTH, ("Content-Type", _JSON), ("Content-Length", "1048577")],
        body=b"{}",
    ),
    _s(
        "payload_declared_at_limit",
        "POST",
        "/api/manage/config/validate",
        env={"PROXY_MANAGEMENT_JSON_MAX_CONTENT_LENGTH": "20"},
        headers=[_AUTH, ("Content-Type", _JSON), ("Content-Length", "20")],
        body=b'{"config_text":"ab"}',
    ),
    _s(
        "payload_declared_over_env_limit",
        "POST",
        "/api/manage/config/validate",
        env={"PROXY_MANAGEMENT_JSON_MAX_CONTENT_LENGTH": "19"},
        headers=[_AUTH, ("Content-Type", _JSON), ("Content-Length", "20")],
        body=b'{"config_text":"ab"}',
    ),
    _s(
        "payload_env_limit_invalid",
        "POST",
        "/api/manage/config/validate",
        env={"PROXY_MANAGEMENT_JSON_MAX_CONTENT_LENGTH": "abc"},
        headers=[_AUTH, ("Content-Type", _JSON), ("Content-Length", "1048577")],
        body=b"{}",
    ),
    _s(
        "payload_env_limit_zero",
        "POST",
        "/api/manage/config/validate",
        env={"PROXY_MANAGEMENT_JSON_MAX_CONTENT_LENGTH": "0"},
        headers=[_AUTH, ("Content-Type", _JSON), ("Content-Length", "1048577")],
        body=b"{}",
    ),
    _s(
        "payload_env_limit_capped",
        "POST",
        "/api/manage/config/validate",
        env={"PROXY_MANAGEMENT_JSON_MAX_CONTENT_LENGTH": "99999999999"},
        headers=[_AUTH, ("Content-Type", _JSON), ("Content-Length", "16777217")],
        body=b"{}",
    ),
    _s(
        "payload_chunked_at_limit",
        "POST",
        "/api/manage/config/validate",
        env={"PROXY_MANAGEMENT_JSON_MAX_CONTENT_LENGTH": "20"},
        headers=[_AUTH, ("Content-Type", _JSON)],
        body=b'{"config_text":"ab"}',
    ),
    _s(
        "payload_bad_content_length",
        "POST",
        "/api/manage/sync",
        headers=[_AUTH, ("Content-Type", _JSON), ("Content-Length", "abc")],
        body=b"{}",
    ),
    _s(
        "payload_negative_content_length",
        "POST",
        "/api/manage/sync",
        headers=[_AUTH, ("Content-Type", _JSON), ("Content-Length", "-5")],
        body=b"{}",
    ),
    _s(
        "payload_short_body",
        "POST",
        "/api/manage/sync",
        headers=[_AUTH, ("Content-Type", _JSON), ("Content-Length", "50")],
        body=b'{"force": true}',
    ),
    _s(
        "payload_long_body",
        "POST",
        "/api/manage/sync",
        headers=[_AUTH, ("Content-Type", _JSON), ("Content-Length", "2")],
        body=b'{}{"force": true}',
    ),
    _s(
        "payload_not_terminated_chunked",
        "POST",
        "/api/manage/sync",
        headers=[_AUTH, ("Content-Type", _JSON)],
        body=b'{"force": true}',
        environ={"wsgi.input_terminated": None},
    ),
    _s(
        "payload_not_terminated_length",
        "POST",
        "/api/manage/sync",
        headers=[_AUTH, ("Content-Type", _JSON), ("Content-Length", "15")],
        body=b'{"force": true}',
        environ={"wsgi.input_terminated": None},
    ),
    # --- config ----------------------------------------------------------
    _s("config_current", "GET", "/api/manage/config/current"),
    _s("config_current_empty", "GET", "/api/manage/config/current", runtime="fail"),
    _s("config_current_none", "GET", "/api/manage/config/current", runtime="none"),
    _s("config_current_blank", "GET", "/api/manage/config/current", runtime="blank"),
    _s(
        "config_current_unicode", "GET", "/api/manage/config/current", runtime="unicode"
    ),
    _s(
        "config_current_large_gzip",
        "GET",
        "/api/manage/config/current",
        runtime="large",
        headers=[_AUTH, ("Accept-Encoding", "x-gzip;q=1, GZIP;q=0.5")],
    ),
    _s(
        "config_current_large_gzip_refused",
        "GET",
        "/api/manage/config/current",
        runtime="large",
        headers=[_AUTH, ("Accept-Encoding", "gzip;q=0, *")],
    ),
    _s(
        "config_current_large_plain",
        "GET",
        "/api/manage/config/current",
        runtime="large",
    ),
    _s("config_current_raises", "GET", "/api/manage/config/current", runtime="raises"),
    _s(
        "config_current_raises_head",
        "HEAD",
        "/api/manage/config/current",
        runtime="raises",
    ),
    _s(
        "config_current_raises_gzip",
        "GET",
        "/api/manage/config/current",
        runtime="raises",
        headers=[_AUTH, ("Accept-Encoding", "gzip")],
    ),
    _s(
        "config_current_get_runtime_raises",
        "GET",
        "/api/manage/config/current",
        runtime="get_runtime_raises",
    ),
    _s("config_current_not_ready", "GET", "/api/manage/config/current", ready=False),
    _post(
        "config_validate",
        "/api/manage/config/validate",
        b'{"config_text": "http_port 3128\\n"}',
    ),
    _post("config_validate_no_body", "/api/manage/config/validate"),
    _post(
        "config_validate_missing_text", "/api/manage/config/validate", b'{"other": 1}'
    ),
    _post(
        "config_validate_null_text",
        "/api/manage/config/validate",
        b'{"config_text": null}',
    ),
    _post(
        "config_validate_int_text", "/api/manage/config/validate", b'{"config_text": 5}'
    ),
    _post(
        "config_validate_not_ready", "/api/manage/config/validate", b"{}", ready=False
    ),
    _post(
        "config_validate_raises", "/api/manage/config/validate", b"{}", runtime="raises"
    ),
    _post("config_rollback", "/api/manage/config/rollback", b'{"reason": "operator"}'),
    _post("config_rollback_default_reason", "/api/manage/config/rollback"),
    _post(
        "config_rollback_zero_reason", "/api/manage/config/rollback", b'{"reason": 0}'
    ),
    _post(
        "config_rollback_list_reason",
        "/api/manage/config/rollback",
        b'{"reason": [1, "a"]}',
    ),
    _post("config_rollback_ok", "/api/manage/config/rollback", b"{}", runtime="ok"),
    _post("config_rollback_fail", "/api/manage/config/rollback", b"{}", runtime="fail"),
    _post(
        "config_rollback_not_ready", "/api/manage/config/rollback", b"{}", ready=False
    ),
    _post(
        "config_rollback_raises", "/api/manage/config/rollback", b"{}", runtime="raises"
    ),
    # --- cache / clamav --------------------------------------------------
    _post("cache_clear_ok", "/api/manage/cache/clear", b"{}"),
    _post("cache_clear_fail", "/api/manage/cache/clear", b"{}", runtime="fail"),
    _post("cache_clear_bad_payload", "/api/manage/cache/clear", b"[]"),
    _post("cache_clear_not_ready", "/api/manage/cache/clear", ready=False),
    _post("cache_clear_raises", "/api/manage/cache/clear", runtime="raises"),
    _post("eicar_ok", "/api/manage/clamav/test-eicar"),
    _post("eicar_fail", "/api/manage/clamav/test-eicar", runtime="fail"),
    _post("eicar_bad_payload", "/api/manage/clamav/test-eicar", b"1"),
    _post("eicar_not_ready", "/api/manage/clamav/test-eicar", ready=False),
    _post("icap_ok", "/api/manage/clamav/test-icap", b"{}"),
    _post("icap_fail", "/api/manage/clamav/test-icap", b"{}", runtime="fail"),
    _s("icap_get", "GET", "/api/manage/clamav/test-icap"),
    # --- test-mode supervisor control ------------------------------------
    _post(
        "supervisor_test_mode_off", "/api/manage/test/supervisor/cicap_adblock/restart"
    ),
    _post(
        "supervisor_ok",
        "/api/manage/test/supervisor/cicap_adblock/restart",
        test_mode="yes",
    ),
    _post(
        "supervisor_not_allowlisted",
        "/api/manage/test/supervisor/squid/stop",
        b"{}",
        test_mode="1",
    ),
    _post(
        "supervisor_encoded_name",
        "/api/manage/test/supervisor/caf%C3%A9/st%20op",
        test_mode="true",
    ),
    _post(
        "supervisor_encoded_slash",
        "/api/manage/test/supervisor/a%2Fb/stop",
        test_mode="on",
    ),
    _post(
        "supervisor_bad_payload",
        "/api/manage/test/supervisor/cicap_adblock/restart",
        b"[]",
        test_mode="ON",
    ),
    _post(
        "supervisor_test_mode_bad_value",
        "/api/manage/test/supervisor/cicap_adblock/restart",
        test_mode="enabled",
    ),
    _post(
        "supervisor_trailing_slash",
        "/api/manage/test/supervisor/cicap_adblock/restart/",
        test_mode="1",
    ),
    _post(
        "supervisor_missing_action",
        "/api/manage/test/supervisor/cicap_adblock",
        test_mode="1",
    ),
    _post(
        "supervisor_empty_action",
        "/api/manage/test/supervisor/cicap_adblock/",
        test_mode="1",
    ),
    _post(
        "supervisor_not_ready",
        "/api/manage/test/supervisor/cicap_adblock/restart",
        test_mode="1",
        ready=False,
    ),
    _s(
        "supervisor_get",
        "GET",
        "/api/manage/test/supervisor/cicap_adblock/restart",
        test_mode="1",
    ),
    _s(
        "supervisor_options",
        "OPTIONS",
        "/api/manage/test/supervisor/cicap_adblock/restart",
        headers=_NO_AUTH,
    ),
    # --- unknown routes --------------------------------------------------
    _s("unknown_manage", "GET", "/api/manage/nope"),
    _s("unknown_manage_no_auth", "GET", "/api/manage/nope", headers=_NO_AUTH),
    _s("unknown_manage_post", "POST", "/api/manage/nope"),
    _s("unknown_manage_head", "HEAD", "/api/manage/nope"),
    _s("unknown_manage_options", "OPTIONS", "/api/manage/nope"),
    _s("unknown_manage_slash", "GET", "/api/manage/"),
    _s("unknown_manage_bare", "GET", "/api/manage"),
    _s("unknown_manage_case", "GET", "/API/manage/health"),
    _s("unknown_root", "GET", "/"),
    _s("unknown_pac", "GET", "/proxy.pac"),
    _s("unknown_encoded_manage", "GET", "/api/manage/caf%C3%A9"),
    _s("unknown_bad_utf8_manage", "GET", "/api/manage/%FF"),
    _s("unknown_double_slash_manage", "GET", "//api/manage/nope"),
    _s("unknown_api_double_slash", "GET", "/api//manage/nope"),
    _s("static_missing", "GET", "/static/app.js"),
    _s("static_missing_head", "HEAD", "/static/app.js"),
    _s("static_missing_post", "POST", "/static/app.js"),
    _s("static_missing_options", "OPTIONS", "/static/app.js"),
    _s("static_traversal", "GET", "/static/../app.py"),
    _s("static_nested", "GET", "/static/a//b/"),
    _s("static_root", "GET", "/static/"),
    _s("static_bare", "GET", "/static"),
    _s("static_double_slash", "GET", "//static/x.css"),
    _s("static_inner_double_slash", "GET", "/static//x.css"),
    # --- Werkzeug merge-slashes redirects ----------------------------------
    _s("redirect_no_host", "GET", "/api//manage/health", host=None),
    _s("redirect_host_port80", "GET", "/api//manage/health", host="Proxy.Example:80"),
    _s("redirect_host_invalid", "GET", "/api//manage/health", host="bad host!"),
    _s("redirect_host_ipv6", "GET", "/api//manage/health", host="[2001:db8::1]:5000"),
    _s("redirect_host_bad_port", "GET", "/api//manage/health", host="proxy:99999"),
    _s(
        "redirect_https",
        "GET",
        "/api//manage/health",
        environ={"wsgi.url_scheme": "https"},
        host="proxy.example:443",
    ),
    _s("redirect_head", "HEAD", "/api///manage/health/clamav?force=1"),
    _s("redirect_wrong_method", "GET", "/api/manage//sync"),
    _s("redirect_options", "OPTIONS", "/api/manage//sync"),
    _post(
        "redirect_encoded_args",
        "/api/manage/test//supervisor/caf%C3%A9/a%25b%20c%3F",
        test_mode="1",
    ),
    _s("redirect_unknown_manage", "GET", "/api/manage//nope"),
    _s("redirect_query_raw", "GET", "/api//manage/logs?log=acc%65ss&x=%zz&caf\xe9"),
    _s(
        "redirect_websocket",
        "GET",
        "/api//manage/health",
        headers=[
            _AUTH,
            ("Connection", "keep-alive, Upgrade"),
            ("Upgrade", "WebSocket"),
        ],
    ),
    _s(
        "websocket_wrong_method",
        "POST",
        "/health",
        headers=[("Connection", "upgrade"), ("Upgrade", "websocket")],
    ),
    _s(
        "websocket_unknown",
        "GET",
        "/nope",
        headers=[("Connection", "upgrade"), ("Upgrade", "websocket")],
    ),
    _s(
        "websocket_manage",
        "GET",
        "/api/manage/health",
        headers=[_AUTH, ("Connection", "upgrade"), ("Upgrade", "websocket")],
    ),
]


def build_environ(scenario: dict[str, Any]) -> dict[str, Any]:
    """Return the WSGI environ gunicorn would build for ``scenario``."""
    target = scenario["target"]
    path, _, query = target.partition("?")
    body = scenario.get("body", b"")
    environ: dict[str, Any] = {
        "REQUEST_METHOD": scenario["method"],
        "SCRIPT_NAME": "",
        "PATH_INFO": unquote_to_bytes(path.encode("utf-8")).decode("latin-1"),
        "QUERY_STRING": query,
        "RAW_URI": target,
        "SERVER_NAME": "0.0.0.0",  # ruff: ignore[hardcoded-bind-all-interfaces] -- gunicorn bind address
        "SERVER_PORT": "5000",
        "SERVER_PROTOCOL": "HTTP/1.1",
        "SERVER_SOFTWARE": "gunicorn/23.0.0",
        "REMOTE_ADDR": "172.18.0.5",
        "REMOTE_PORT": "50123",
        "wsgi.input": io.BytesIO(body),
        "wsgi.errors": sys.stderr,
        "wsgi.url_scheme": "http",
        "wsgi.input_terminated": True,
        "wsgi.version": (1, 0),
        "wsgi.multithread": False,
        "wsgi.multiprocess": False,
        "wsgi.run_once": False,
    }
    host = scenario.get("host", "proxy.example:5000")
    if host is not None:
        environ["HTTP_HOST"] = host
    for name, value in scenario.get("headers", ()):
        key = name.upper().replace("-", "_")
        if key in {"CONTENT_TYPE", "CONTENT_LENGTH"}:
            environ[key] = value
        else:
            environ[f"HTTP_{key}"] = value
    for key, value in scenario.get("environ", {}).items():
        if value is None:
            environ.pop(key, None)
        else:
            environ[key] = value
    return environ


def _normalize(
    status: str, headers: list[tuple[str, str]], body: bytes
) -> dict[str, Any]:
    normalized_headers = []
    for name, value in headers:
        normalized = value
        if name.lower() == "date":
            assert _HTTP_DATE.match(value), value
            normalized = "<http-date>"
        elif name.lower() == "allow":
            normalized = ", ".join(sorted(token.strip() for token in value.split(",")))
        normalized_headers.append([name, normalized])
    record: dict[str, Any] = {"status": status, "headers": normalized_headers}
    encoding = {k.lower(): v for k, v in headers}.get("content-encoding")
    if encoding == "gzip" and body:
        # Bodies may carry the per-test log directory, so the identity bytes
        # are recorded; the exact gzip member (level 5, MTIME zeroed) is pinned
        # by recompressing them.
        identity = gzip.decompress(body)
        assert body[:4] + b"\0\0\0\0" + body[8:] == gzip.compress(
            identity, compresslevel=5, mtime=0
        )
        record["gzip"] = True
        body = identity
    try:
        record["body"] = body.decode("utf-8")
    except UnicodeDecodeError:
        record["body_b64"] = base64.b64encode(body).decode("ascii")
    return record


def run_scenario(scenario, *, monkeypatch, tmp_path) -> dict[str, Any]:
    """Execute one scenario; return its normalized response and runtime calls."""
    monkeypatch.setenv("DISABLE_PROXY_AGENT", "1")
    monkeypatch.setenv(
        "PROXY_CONTROL_PLANE_READY_FILE", str(tmp_path / "control-plane-ready")
    )
    for key, value in {
        "APP_VERSION": "1.2.3",
        "GIT_COMMIT": "0123456789abcdef0123456789abcdef01234567",
        "GIT_REF_NAME": "main",
        "BUILD_DATE": "2026-01-02T03:04:05Z",
        "IMAGE_NAME": "proxy",
    }.items():
        monkeypatch.setenv(key, value)
    for key in (
        "PROXY_MANAGEMENT_JSON_MAX_CONTENT_LENGTH",
        "ENABLE_GZIP_RESPONSES",
        "EXPOSE_INTERNAL_ERRORS",
        "ENABLE_TEST_MODE",
        "DOCKER_PROXY_VERSION",
        "IMAGE_VERSION",
        "GITHUB_SHA",
        "SOURCE_COMMIT",
        "GITHUB_REF_NAME",
        "SOURCE_REF",
        "BUILD_CREATED",
    ):
        monkeypatch.delenv(key, raising=False)
    token = scenario.get("token", TOKEN)
    if token is None:
        monkeypatch.delenv("PROXY_MANAGEMENT_TOKEN", raising=False)
    else:
        monkeypatch.setenv("PROXY_MANAGEMENT_TOKEN", token)
    if "test_mode" in scenario:
        monkeypatch.setenv("ENABLE_TEST_MODE", scenario["test_mode"])
    for key, value in scenario.get("env", {}).items():
        monkeypatch.setenv(key, value)

    from proxy.control_plane_state import (  # type: ignore
        clear_control_plane_ready,
        mark_control_plane_ready,
    )

    if scenario.get("ready", True):
        mark_control_plane_ready()
    else:
        clear_control_plane_ready()

    import proxy.app as proxy_app  # type: ignore

    proxy_app = importlib.reload(proxy_app)
    calls: list[Any] = []
    mode = scenario.get("runtime", "ok")
    if mode == "get_runtime_raises":

        def _get_runtime():
            calls.append(["get_runtime", {}])
            message = "database password=hunter2 unavailable"
            raise RuntimeError(message)

        proxy_app.runtime = None
        monkeypatch.setattr(proxy_app, "get_runtime", _get_runtime)
    elif mode == "lazy":
        lazy = _Recorder("ok", calls)

        def _get_runtime_lazy():
            calls.append(["get_runtime", {}])
            return lazy

        proxy_app.runtime = None
        monkeypatch.setattr(proxy_app, "get_runtime", _get_runtime_lazy)
    else:
        proxy_app.runtime = _Recorder(mode, calls)
    monkeypatch.setattr(proxy_app, "read_proxy_log", _fake_read_proxy_log(calls))
    monkeypatch.setattr(time, "time", lambda: _FIXED_TIME)  # ruff: ignore[shared-clock-mock] -- degraded payload timestamps

    environ = build_environ(scenario)
    captured: dict[str, Any] = {}

    def start_response(status, headers, exc_info=None):
        captured["status"] = status
        captured["headers"] = list(headers)
        return lambda _data: None

    iterable = proxy_app.app(environ, start_response)
    try:
        body = b"".join(iterable)
    finally:
        close = getattr(iterable, "close", None)
        if close is not None:
            close()
    if mode == "lazy":
        calls.append(["runtime_cached", proxy_app.runtime is lazy])
    return {
        "response": _normalize(captured["status"], captured["headers"], body),
        "runtime_calls": calls,
    }


def _load_golden() -> dict[str, Any]:
    return json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s["name"] for s in SCENARIOS])
def test_proxy_management_matches_golden_response(
    scenario, monkeypatch, tmp_path
) -> None:
    expected = _load_golden()[scenario["name"]]
    assert (
        run_scenario(scenario, monkeypatch=monkeypatch, tmp_path=tmp_path) == expected
    )


def test_golden_covers_every_scenario_exactly() -> None:
    names = [s["name"] for s in SCENARIOS]
    assert len(names) == len(set(names))
    assert sorted(_load_golden()) == sorted(names)
