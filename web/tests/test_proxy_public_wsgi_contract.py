"""Golden client-observable contract of the ``proxy_public`` WSGI listener.

Every scenario drives ``proxy.public_app.app`` through a raw, gunicorn-shaped
WSGI environ and compares the status line, the full ordered header list and
the body bytes against ``golden/proxy_public_responses.json``. The golden file
was recorded from the Flask implementation (Flask 3.1.3 / Werkzeug 3.1.9) and
is the independent oracle for any replacement implementation.

Normalizations, each for a value Flask itself does not keep stable:
- ``Date`` values (wall clock) become ``<http-date>`` after a format check;
- ``Allow`` tokens are sorted (Flask emits them in hash-seed order);
- the gzip header MTIME field (wall clock) is zeroed.
"""

from __future__ import annotations

import base64
import importlib
import io
import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import unquote_to_bytes

import pytest

GOLDEN_PATH = Path(__file__).with_name("golden") / "proxy_public_responses.json"
_HTTP_DATE = re.compile(
    r"(Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} "
    r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} "
    r"\d{2}:\d{2}:\d{2} GMT\Z",
)

SMALL_PAC = (
    'function FindProxyForURL(url, host) { return "PROXY __PAC_PROXY_HOST__:3128"; }\n'
)
LARGE_PAC = (
    "function FindProxyForURL(url, host) {\n"
    + "".join(
        f'  if (shExpMatch(host, "*.site{index}.example")) return "PROXY __PAC_PROXY_HOST__:3128";\n'
        for index in range(40)
    )
    + '  return "DIRECT";\n}\n'
)
EMERGENCY_PAC = (
    "function FindProxyForURL(url, host) {\n  // emergency\n"
    + "".join(
        f"  // padding line {index:03d} keeps this above the gzip floor\n"
        for index in range(30)
    )
    + '  return "PROXY __PAC_PROXY_HOST__:3128; DIRECT";\n}\n'
)
LONG_DOMAIN = ".".join([f"sub{index}" + "x" * 50 for index in range(10)]) + ".example"

STATES: dict[str, dict[str, Any] | None] = {
    "small": {
        "manifest": {
            "fallback_file": "fallback.pac",
            "public_pac_path": "/download/wpad.dat?site=lab",
        },
        "files": {"fallback.pac": SMALL_PAC},
    },
    "large": {
        "manifest": {"fallback_file": "fallback.pac"},
        "files": {"fallback.pac": LARGE_PAC},
    },
    "odd_paths": {
        "manifest": {
            "fallback_file": "fallback.pac",
            "public_pac_path": "/pac/dir/",
            "public_pac_url": "http://pac.example/a//b.pac",
        },
        "files": {"fallback.pac": SMALL_PAC},
    },
    "encoded": {
        "manifest": {
            "fallback_file": "fallback.pac",
            "public_pac_path": "/caf%C3%A9/proxy.pac",
        },
        "files": {"fallback.pac": SMALL_PAC},
    },
    "emergency": None,
}

_ETAG_SMALL = None  # filled from the golden file when needed


def _s(name: str, method: str, target: str, **extra: Any) -> dict[str, Any]:
    scenario = {"name": name, "method": method, "target": target, "state": "small"}
    scenario.update(extra)
    return scenario


_FORM = "application/x-www-form-urlencoded"
_OK_FORM = b"request_url=https%3A%2F%2Fbad.example%2F&client_ip=1.2.3.4&domain=bad.example&user_note=need"
_MULTIPART_BOUNDARY = "XyZb0undary"
_MULTIPART_BODY = (
    f"--{_MULTIPART_BOUNDARY}\r\n"
    'Content-Disposition: form-data; name="domain"\r\n\r\n'
    "multi.example\r\n"
    f"--{_MULTIPART_BOUNDARY}\r\n"
    'Content-Disposition: form-data; name="request_url"\r\n\r\n'
    "https://multi.example/x\r\n"
    f"--{_MULTIPART_BOUNDARY}\r\n"
    'Content-Disposition: form-data; name="file"; filename="a.txt"\r\n'
    "Content-Type: text/plain\r\n\r\n"
    "ignored\r\n"
    f"--{_MULTIPART_BOUNDARY}--\r\n"
).encode()

SCENARIOS: list[dict[str, Any]] = [
    # --- routing / public path restriction -------------------------------
    _s("get_root", "GET", "/"),
    _s("get_proxy_pac", "GET", "/proxy.pac"),
    _s("get_wpad", "GET", "/wpad.dat"),
    _s("get_proxy_pac_query", "GET", "/proxy.pac?x=1&y=%20"),
    _s("head_proxy_pac", "HEAD", "/proxy.pac"),
    _s("head_root", "HEAD", "/"),
    _s("get_configured_path", "GET", "/download/wpad.dat?site=lab"),
    _s("get_configured_path_wrong_query", "GET", "/download/wpad.dat?site=other"),
    _s("get_configured_path_no_query", "GET", "/download/wpad.dat"),
    _s("get_configured_path_encoded_char", "GET", "/download/%77pad.dat?site=lab"),
    _s("get_configured_path_encoded_sep", "GET", "/download%2Fwpad.dat?site=lab"),
    _s("get_unconfigured_path", "GET", "/download/other.pac"),
    _s("get_double_slash_pac", "GET", "//proxy.pac"),
    _s("get_dot_segment", "GET", "/./proxy.pac"),
    _s("get_dotdot_encoded", "GET", "/%2e%2e/proxy.pac"),
    _s("get_dotdot_health_raw_unsafe", "GET", "/%2e%2e/health"),
    _s(
        "get_health_raw_uri_unsafe",
        "GET",
        "/health",
        environ={"RAW_URI": "/x/%2e%2e/health"},
    ),
    _s(
        "get_pac_raw_uri_unsafe",
        "GET",
        "/proxy.pac",
        environ={"RAW_URI": "/x/%2e%2e/proxy.pac"},
    ),
    _s(
        "get_pac_request_uri_unsafe",
        "GET",
        "/proxy.pac",
        environ={"RAW_URI": None, "REQUEST_URI": "/%2e%2e/proxy.pac"},
    ),
    _s(
        "get_pac_request_uri_safe",
        "GET",
        "/proxy.pac",
        environ={"RAW_URI": None, "REQUEST_URI": "/proxy.pac?z=1"},
    ),
    _s("get_pac_no_raw_uri", "GET", "/proxy.pac", environ={"RAW_URI": None}),
    _s(
        "get_pac_absolute_form",
        "GET",
        "/proxy.pac",
        environ={"RAW_URI": "http://proxy.example/proxy.pac"},
    ),
    _s("get_pac_backslash", "GET", "/a%5c..%5cproxy.pac"),
    _s("get_pac_ctrl_char", "GET", "/proxy.pac%00"),
    _s("get_bad_percent", "GET", "/%zz/proxy.pac"),
    _s("get_nope", "GET", "/nope"),
    _s("head_nope", "HEAD", "/nope"),
    _s("options_nope", "OPTIONS", "/nope"),
    _s("post_nope", "POST", "/nope"),
    _s("get_health_trailing_slash", "GET", "/health/"),
    _s("get_pac_trailing_slash", "GET", "/proxy.pac/"),
    _s(
        "get_api_manage_health",
        "GET",
        "/api/manage/health",
        headers=[("Authorization", "Bearer x")],
    ),
    _s("head_api_manage", "HEAD", "/api/manage/sync"),
    _s(
        "post_api_manage",
        "POST",
        "/api/manage/sync",
        headers=[("Content-Type", _FORM), ("Content-Length", "3")],
        body=b"a=1",
    ),
    _s("get_api_manage_bare", "GET", "/api/manage"),
    _s("get_api_manage_slash", "GET", "/api/manage/"),
    # --- health ----------------------------------------------------------
    _s("get_health", "GET", "/health"),
    _s("get_health_query", "GET", "/health?full=1"),
    _s("head_health", "HEAD", "/health"),
    _s("options_health", "OPTIONS", "/health"),
    _s("post_health", "POST", "/health"),
    _s("put_health", "PUT", "/health"),
    _s("get_health_spa", "GET", "/health", headers=[("X-Requested-With", "SPA")]),
    _s("get_health_gzip", "GET", "/health", headers=[("Accept-Encoding", "gzip")]),
    # --- methods on PAC / policy-request ---------------------------------
    _s("post_proxy_pac", "POST", "/proxy.pac"),
    _s("delete_wpad", "DELETE", "/wpad.dat"),
    _s("options_proxy_pac", "OPTIONS", "/proxy.pac"),
    _s("options_root", "OPTIONS", "/"),
    _s("options_configured", "OPTIONS", "/download/wpad.dat?site=lab"),
    _s("post_configured", "POST", "/download/wpad.dat?site=lab"),
    _s("get_pac_spa", "GET", "/proxy.pac", headers=[("X-Requested-With", "spa")]),
    _s("get_policy_request", "GET", "/policy-request"),
    _s("head_policy_request", "HEAD", "/policy-request"),
    _s("options_policy_request", "OPTIONS", "/policy-request"),
    _s("put_policy_request", "PUT", "/policy-request"),
    _s("get_policy_request_slash", "GET", "/policy-request/"),
    # --- conditional / range ---------------------------------------------
    _s("cond_inm_match", "GET", "/proxy.pac", headers=[("If-None-Match", "{etag}")]),
    _s(
        "cond_inm_match_head",
        "HEAD",
        "/proxy.pac",
        headers=[("If-None-Match", "{etag}")],
    ),
    _s("cond_inm_weak", "GET", "/proxy.pac", headers=[("If-None-Match", "W/{etag}")]),
    _s(
        "cond_inm_list",
        "GET",
        "/proxy.pac",
        headers=[("If-None-Match", '"zz", {etag}')],
    ),
    _s("cond_inm_star", "GET", "/proxy.pac", headers=[("If-None-Match", "*")]),
    _s(
        "cond_inm_unquoted",
        "GET",
        "/proxy.pac",
        headers=[("If-None-Match", "{etag_bare}")],
    ),
    _s("cond_inm_other", "GET", "/proxy.pac", headers=[("If-None-Match", '"other"')]),
    _s(
        "cond_inm_garbage",
        "GET",
        "/proxy.pac",
        headers=[("If-None-Match", '"a" junk"x, ,{etag}')],
    ),
    _s("cond_if_match_other", "GET", "/proxy.pac", headers=[("If-Match", '"other"')]),
    _s("cond_if_match_star", "GET", "/proxy.pac", headers=[("If-Match", "*")]),
    _s("cond_if_match_same", "GET", "/proxy.pac", headers=[("If-Match", "{etag}")]),
    _s(
        "cond_if_match_weak_same",
        "GET",
        "/proxy.pac",
        headers=[("If-Match", "W/{etag}")],
    ),
    _s(
        "cond_inm_and_if_match_same",
        "GET",
        "/proxy.pac",
        headers=[("If-None-Match", "{etag}"), ("If-Match", "{etag}")],
    ),
    _s(
        "cond_inm_and_if_match_other",
        "GET",
        "/proxy.pac",
        headers=[("If-None-Match", "{etag}"), ("If-Match", '"other"')],
    ),
    _s(
        "cond_ims",
        "GET",
        "/proxy.pac",
        headers=[("If-Modified-Since", "Fri, 20 Nov 2099 00:00:00 GMT")],
    ),
    _s(
        "cond_ius",
        "GET",
        "/proxy.pac",
        headers=[("If-Unmodified-Since", "Fri, 20 Nov 1999 00:00:00 GMT")],
    ),
    _s("range_bytes", "GET", "/proxy.pac", headers=[("Range", "bytes=0-10")]),
    _s("range_invalid", "GET", "/proxy.pac", headers=[("Range", "bytes=99999-")]),
    _s(
        "range_if_range",
        "GET",
        "/proxy.pac",
        headers=[("Range", "bytes=0-1"), ("If-Range", "{etag}")],
    ),
    _s("cond_inm_match_health", "GET", "/health", headers=[("If-None-Match", "*")]),
    _s("cond_if_match_post_health", "POST", "/health", headers=[("If-Match", '"x"')]),
    _s("cond_if_match_options", "OPTIONS", "/proxy.pac", headers=[("If-Match", '"x"')]),
    # --- compression -----------------------------------------------------
    _s("small_gzip", "GET", "/proxy.pac", headers=[("Accept-Encoding", "gzip")]),
    _s("large_plain", "GET", "/proxy.pac", state="large"),
    _s(
        "large_gzip",
        "GET",
        "/proxy.pac",
        state="large",
        headers=[("Accept-Encoding", "gzip, deflate, br")],
    ),
    _s(
        "large_gzip_head",
        "HEAD",
        "/proxy.pac",
        state="large",
        headers=[("Accept-Encoding", "gzip")],
    ),
    _s(
        "large_gzip_q0",
        "GET",
        "/proxy.pac",
        state="large",
        headers=[("Accept-Encoding", "gzip;q=0, *")],
    ),
    _s(
        "large_gzip_qbad",
        "GET",
        "/proxy.pac",
        state="large",
        headers=[("Accept-Encoding", "gzip;q=2")],
    ),
    _s(
        "large_gzip_q_low",
        "GET",
        "/proxy.pac",
        state="large",
        headers=[("Accept-Encoding", "GZIP; Q=0.001")],
    ),
    _s(
        "large_star",
        "GET",
        "/proxy.pac",
        state="large",
        headers=[("Accept-Encoding", "*")],
    ),
    _s(
        "large_star_q0",
        "GET",
        "/proxy.pac",
        state="large",
        headers=[("Accept-Encoding", "*;q=0")],
    ),
    _s(
        "large_identity",
        "GET",
        "/proxy.pac",
        state="large",
        headers=[("Accept-Encoding", "identity")],
    ),
    _s(
        "large_dup_gzip",
        "GET",
        "/proxy.pac",
        state="large",
        headers=[("Accept-Encoding", "gzip, gzip;q=0")],
    ),
    _s(
        "large_gzip_304",
        "GET",
        "/proxy.pac",
        state="large",
        headers=[("Accept-Encoding", "gzip"), ("If-None-Match", "{etag}")],
    ),
    _s(
        "large_gzip_412",
        "GET",
        "/proxy.pac",
        state="large",
        headers=[("Accept-Encoding", "gzip"), ("If-Match", '"other"')],
    ),
    _s(
        "large_gzip_disabled",
        "GET",
        "/proxy.pac",
        state="large",
        headers=[("Accept-Encoding", "gzip")],
        env={"ENABLE_GZIP_RESPONSES": "0"},
    ),
    _s(
        "large_range_gzip",
        "GET",
        "/proxy.pac",
        state="large",
        headers=[("Accept-Encoding", "gzip"), ("Range", "bytes=0-5")],
    ),
    # --- emergency PAC ---------------------------------------------------
    _s("emergency_pac", "GET", "/proxy.pac", state="emergency"),
    _s(
        "emergency_wpad_gzip",
        "GET",
        "/wpad.dat",
        state="emergency",
        headers=[("Accept-Encoding", "gzip")],
    ),
    _s(
        "emergency_304",
        "GET",
        "/proxy.pac",
        state="emergency",
        headers=[("If-None-Match", "{etag}")],
    ),
    _s(
        "emergency_configured_path",
        "GET",
        "/download/wpad.dat?site=lab",
        state="emergency",
    ),
    # --- odd configured paths --------------------------------------------
    _s("odd_trailing_slash", "GET", "/pac/dir/", state="odd_paths"),
    _s("odd_trailing_slash_missing", "GET", "/pac/dir", state="odd_paths"),
    _s("odd_double_slash", "GET", "/a//b.pac", state="odd_paths"),
    _s("odd_double_slash_merged", "GET", "/a/b.pac", state="odd_paths"),
    _s("encoded_utf8_path", "GET", "/caf%C3%A9/proxy.pac", state="encoded"),
    _s("encoded_utf8_path_raw", "GET", "/café/proxy.pac", state="encoded"),
    _s("encoded_bad_utf8_path", "GET", "/caf%E9/proxy.pac", state="encoded"),
    # --- host / client identity ------------------------------------------
    _s("host_with_port", "GET", "/proxy.pac", host="PROXY.Example:8080"),
    _s("host_ipv6", "GET", "/proxy.pac", host="[2001:db8::1]:80"),
    _s("host_missing", "GET", "/proxy.pac", host=None),
    _s("host_single_label", "GET", "/proxy.pac", host="proxy"),
    _s("host_invalid", "GET", "/proxy.pac", host="bad host!"),
    _s(
        "host_forwarded_untrusted",
        "GET",
        "/proxy.pac",
        headers=[("X-Forwarded-Host", "evil.example")],
    ),
    _s(
        "host_forwarded_trusted",
        "GET",
        "/proxy.pac",
        remote_addr="192.0.2.10",
        env={"PAC_TRUSTED_PROXY_CIDRS": "192.0.2.0/24"},
        headers=[("X-Forwarded-Host", "fwd.example"), ("X-Forwarded-For", "10.1.2.3")],
    ),
    # --- server error ----------------------------------------------------
    _s("pac_raises_500", "GET", "/proxy.pac", fault="pac_raises"),
    _s("pac_raises_500_head", "HEAD", "/proxy.pac", fault="pac_raises"),
    # --- policy-request submission ---------------------------------------
    _s(
        "policy_ok",
        "POST",
        "/policy-request",
        store="ok",
        headers=[("Content-Type", _FORM), ("Content-Length", str(len(_OK_FORM)))],
        body=_OK_FORM,
    ),
    _s(
        "policy_ok_query",
        "POST",
        "/policy-request?x=1",
        store="ok",
        headers=[("Content-Type", _FORM), ("Content-Length", str(len(_OK_FORM)))],
        body=_OK_FORM,
    ),
    _s(
        "policy_ok_escaped",
        "POST",
        "/policy-request",
        store="ok",
        headers=[("Content-Type", _FORM)],
        body=b"domain=%3Cb%3E%26%22%27x.example&block_type=sslfilter&destination=d&error=e",
    ),
    _s(
        "policy_ok_multipart",
        "POST",
        "/policy-request",
        store="ok",
        headers=[
            ("Content-Type", f"multipart/form-data; boundary={_MULTIPART_BOUNDARY}"),
            ("Content-Length", str(len(_MULTIPART_BODY))),
        ],
        body=_MULTIPART_BODY,
    ),
    _s(
        "policy_multipart_no_boundary",
        "POST",
        "/policy-request",
        store="ok",
        headers=[("Content-Type", "multipart/form-data")],
        body=_MULTIPART_BODY,
    ),
    _s(
        "policy_multipart_broken",
        "POST",
        "/policy-request",
        store="ok",
        headers=[("Content-Type", "multipart/form-data; boundary=zzz")],
        body=b"--zzz\r\ngarbage",
    ),
    _s(
        "policy_long_domain_gzip",
        "POST",
        "/policy-request",
        store="ok",
        headers=[("Content-Type", _FORM), ("Accept-Encoding", "gzip")],
        body=f"domain={LONG_DOMAIN}".encode(),
    ),
    _s(
        "policy_long_domain_plain",
        "POST",
        "/policy-request",
        store="ok",
        headers=[("Content-Type", _FORM)],
        body=f"domain={LONG_DOMAIN}".encode(),
    ),
    _s(
        "policy_text_plain",
        "POST",
        "/policy-request",
        store="ok",
        headers=[("Content-Type", "text/plain")],
        body=b"domain=x.example",
    ),
    _s(
        "policy_no_content_type",
        "POST",
        "/policy-request",
        store="ok",
        body=b"domain=x.example",
    ),
    _s(
        "policy_uppercase_mimetype",
        "POST",
        "/policy-request",
        store="ok",
        headers=[
            ("Content-Type", "Application/X-WWW-Form-Urlencoded; charset=latin-1")
        ],
        body=b"domain=upper.example",
    ),
    _s(
        "policy_invalid_utf8",
        "POST",
        "/policy-request",
        store="ok",
        headers=[("Content-Type", _FORM)],
        body=b"domain=\xff\xfe",
    ),
    _s(
        "policy_bad_percent",
        "POST",
        "/policy-request",
        store="ok",
        headers=[("Content-Type", _FORM)],
        body=b"domain=%zz&request_url=%",
    ),
    _s(
        "policy_oversized_declared",
        "POST",
        "/policy-request",
        store="ok",
        headers=[("Content-Type", _FORM), ("Content-Length", "20000")],
        body=b"domain=x",
    ),
    _s(
        "policy_oversized_chunked",
        "POST",
        "/policy-request",
        store="ok",
        headers=[("Content-Type", _FORM)],
        body=b"domain=" + b"x" * 20000,
    ),
    _s(
        "policy_oversized_env_limit",
        "POST",
        "/policy-request",
        store="ok",
        env={"POLICY_REQUEST_MAX_CONTENT_LENGTH": "128"},
        headers=[("Content-Type", _FORM)],
        body=b"domain=" + b"x" * 300,
    ),
    _s(
        "policy_env_limit_exact",
        "POST",
        "/policy-request",
        store="ok",
        env={"POLICY_REQUEST_MAX_CONTENT_LENGTH": "20"},
        headers=[("Content-Type", _FORM), ("Content-Length", "20")],
        body=b"domain=abcdefghijklm",
    ),
    _s(
        "policy_env_limit_invalid",
        "POST",
        "/policy-request",
        store="ok",
        env={"POLICY_REQUEST_MAX_CONTENT_LENGTH": "nope"},
        headers=[("Content-Type", _FORM)],
        body=b"domain=x.example",
    ),
    _s(
        "policy_env_limit_zero",
        "POST",
        "/policy-request",
        store="ok",
        env={"POLICY_REQUEST_MAX_CONTENT_LENGTH": "0"},
        headers=[("Content-Type", _FORM), ("Content-Length", "17000")],
        body=b"domain=x.example",
    ),
    _s(
        "policy_truncated_body",
        "POST",
        "/policy-request",
        store="ok",
        headers=[("Content-Type", _FORM), ("Content-Length", "100")],
        body=b"domain=x.example",
        environ={"wsgi.input_terminated": False},
    ),
    _s(
        "policy_bad_content_length",
        "POST",
        "/policy-request",
        store="ok",
        headers=[("Content-Type", _FORM), ("Content-Length", "abc")],
        body=b"domain=x.example",
        environ={"wsgi.input_terminated": False},
    ),
    _s(
        "policy_multipart_too_many_parts",
        "POST",
        "/policy-request",
        store="ok",
        env={"POLICY_REQUEST_MAX_CONTENT_LENGTH": "400000"},
        headers=[("Content-Type", "multipart/form-data; boundary=b")],
        body=b"".join(
            b'--b\r\nContent-Disposition: form-data; name="f"\r\n\r\nv\r\n'
            for _ in range(1001)
        )
        + b"--b--\r\n",
    ),
    _s(
        "policy_trusted_forwarded",
        "POST",
        "/policy-request",
        store="ok",
        remote_addr="192.0.2.10",
        env={"PAC_TRUSTED_PROXY_CIDRS": "192.0.2.0/24"},
        headers=[
            ("Content-Type", _FORM),
            ("X-Forwarded-For", "10.11.12.13, 192.0.2.10"),
        ],
        body=b"domain=fwd.example",
    ),
    _s(
        "policy_trusted_form_ip",
        "POST",
        "/policy-request",
        store="ok",
        remote_addr="192.0.2.10",
        env={"PAC_TRUSTED_PROXY_CIDRS": "192.0.2.0/24"},
        headers=[("Content-Type", _FORM)],
        body=b"domain=form.example&client_ip=10.11.12.14",
    ),
    _s(
        "policy_admission_429",
        "POST",
        "/policy-request",
        store="admission",
        headers=[("Content-Type", _FORM)],
        body=b"domain=x.example",
    ),
    _s(
        "policy_transient_503",
        "POST",
        "/policy-request",
        store="transient",
        headers=[("Content-Type", _FORM)],
        body=b"domain=x.example",
    ),
    _s(
        "policy_control_plane_503",
        "POST",
        "/policy-request",
        store="control_plane",
        headers=[("Content-Type", _FORM)],
        body=b"domain=x.example",
    ),
    _s(
        "policy_generic_500",
        "POST",
        "/policy-request",
        store="generic",
        headers=[("Content-Type", _FORM)],
        body=b"domain=x.example",
    ),
    _s(
        "policy_unsafe_raw_uri",
        "POST",
        "/policy-request",
        store="ok",
        environ={"RAW_URI": "/x/%2e%2e/policy-request"},
        headers=[("Content-Type", _FORM)],
        body=b"domain=x.example",
    ),
]


def _write_state(pac_dir: Path, state: dict[str, Any] | None) -> None:
    pac_dir.mkdir(parents=True, exist_ok=True)
    if state is None:
        return
    from services.pac_request import (  # type: ignore
        calculate_pac_manifest_state_sha,
        render_pac_manifest_text,
    )

    manifest, files = state["manifest"], state["files"]
    state_sha = calculate_pac_manifest_state_sha(manifest, files)
    for rel_path, content in files.items():
        (pac_dir / rel_path).write_text(content, encoding="utf-8")
    (pac_dir / "manifest.json").write_text(
        render_pac_manifest_text({**manifest, "state_sha256": state_sha}),
        encoding="utf-8",
    )
    (pac_dir / ".state-sha256").write_text(state_sha + "\n", encoding="utf-8")


def _store_factory(kind: str, recorded: dict[str, Any]):
    class Store:
        def create_request(self, **kwargs):
            recorded.update(kwargs)
            if kind == "admission":
                from services.policy_requests import PolicyRequestAdmissionError

                raise PolicyRequestAdmissionError.proxy_capacity()
            if kind == "transient":
                import pymysql

                raise pymysql.OperationalError(2003, "password=secret host=db")
            if kind == "control_plane":
                import pymysql
                from services.proxy_write_guard import ProxyLifecycleWriteError

                try:
                    raise pymysql.OperationalError(2013, "token=secret")
                except pymysql.OperationalError as exc:
                    message = "metadata unavailable"
                    raise ProxyLifecycleWriteError(message) from exc
            if kind == "generic":
                message = "sql detail password=secret"
                raise RuntimeError(message)
            from services.policy_requests import PolicyRequest

            return PolicyRequest(
                321,
                kwargs.get("proxy_id") or "default",
                "pending",
                kwargs["block_type"],
                kwargs["client_ip"],
                kwargs["request_url"],
                kwargs["domain"],
                kwargs["category"],
                kwargs["method"],
                kwargs["squid_error"],
                kwargs["user_note"],
                "",
                1,
                1,
                0,
                "",
                None,
            )

    return Store


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
        "RAW_URI": target.encode("utf-8").decode("latin-1"),
        "SERVER_NAME": "proxy.example",
        "SERVER_PORT": "80",
        "SERVER_PROTOCOL": "HTTP/1.1",
        "SERVER_SOFTWARE": "gunicorn/23.0.0",
        "REMOTE_ADDR": scenario.get("remote_addr", "192.168.1.20"),
        "REMOTE_PORT": "50123",
        "wsgi.input": io.BytesIO(body),
        "wsgi.errors": sys.stderr,
        "wsgi.url_scheme": "http",
        "wsgi.input_terminated": True,
        "wsgi.version": (1, 0),
        "wsgi.multithread": True,
        "wsgi.multiprocess": False,
        "wsgi.run_once": False,
    }
    host = scenario.get("host", "proxy.example")
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
    encoding = {k.lower(): v for k, v in headers}.get("content-encoding")
    if encoding == "gzip" and body:
        body = body[:4] + b"\0\0\0\0" + body[8:]
    record: dict[str, Any] = {"status": status, "headers": normalized_headers}
    try:
        record["body"] = body.decode("utf-8")
    except UnicodeDecodeError:
        record["body_b64"] = base64.b64encode(body).decode("ascii")
    return record


def _substitute(value: str, etag: str) -> str:
    return value.replace("{etag}", etag).replace("{etag_bare}", etag.strip('"'))


def run_scenario(scenario, *, monkeypatch, tmp_path, golden_etags: dict[str, str]):
    """Execute one scenario and return its normalized record and store kwargs."""
    pac_dir = tmp_path / "pac"
    _write_state(pac_dir, STATES[scenario["state"]])
    monkeypatch.setenv("PAC_RENDER_DIR", str(pac_dir))
    monkeypatch.setenv("PAC_HTTP_PORT", "80")
    monkeypatch.setenv("DISABLE_PROXY_AGENT", "1")
    for key in (
        "POLICY_REQUEST_MAX_CONTENT_LENGTH",
        "ENABLE_GZIP_RESPONSES",
        "PAC_TRUSTED_PROXY_CIDRS",
        "EXPOSE_INTERNAL_ERRORS",
    ):
        monkeypatch.delenv(key, raising=False)
    for key, value in scenario.get("env", {}).items():
        monkeypatch.setenv(key, value)

    from services import pac_http  # type: ignore

    pac_http.pac_render_dir.cache_clear()
    pac_http._CACHES.clear()
    from services import pac_renderer  # type: ignore

    monkeypatch.setattr(pac_renderer, "build_emergency_pac", lambda: EMERGENCY_PAC)
    from proxy import public_app  # type: ignore

    public_app = importlib.reload(public_app)
    if scenario.get("fault") == "pac_raises":

        def _raise(**_kwargs):
            message = "pac failure detail"
            raise RuntimeError(message)

        monkeypatch.setattr(public_app, "resolve_pac", _raise)
    recorded: dict[str, Any] = {}
    if "store" in scenario:
        monkeypatch.setattr(
            "services.policy_requests.get_policy_request_store",
            _store_factory(scenario["store"], recorded),
        )
    etag = golden_etags.get(scenario["state"], '"none"')
    resolved = {
        **scenario,
        "headers": [
            (name, _substitute(value, etag))
            for name, value in scenario.get("headers", ())
        ],
    }
    environ = build_environ(resolved)
    captured: dict[str, Any] = {}

    def start_response(status, headers, exc_info=None):
        captured["status"] = status
        captured["headers"] = list(headers)
        return lambda _data: None

    iterable = public_app.app(environ, start_response)
    try:
        body = b"".join(iterable)
    finally:
        close = getattr(iterable, "close", None)
        if close is not None:
            close()
    record = _normalize(captured["status"], captured["headers"], body)
    return record, recorded


def _load_golden() -> dict[str, Any]:
    return json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))


def _golden_etags(golden: dict[str, Any]) -> dict[str, str]:
    sources = {
        "small": "get_proxy_pac",
        "large": "large_plain",
        "emergency": "emergency_pac",
    }
    etags = {}
    for state, name in sources.items():
        for header, value in golden[name]["response"]["headers"]:
            if header == "ETag":
                etags[state] = value
    return etags


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s["name"] for s in SCENARIOS])
def test_proxy_public_matches_golden_response(scenario, monkeypatch, tmp_path) -> None:
    golden = _load_golden()
    expected = golden[scenario["name"]]
    record, recorded = run_scenario(
        scenario,
        monkeypatch=monkeypatch,
        tmp_path=tmp_path,
        golden_etags=_golden_etags(golden),
    )
    assert record == expected["response"]
    assert recorded == expected["store_kwargs"]


def test_golden_covers_every_scenario_exactly() -> None:
    assert sorted(_load_golden()) == sorted(s["name"] for s in SCENARIOS)


_IMPORT_PROBE = """
import io, json, sys
from proxy import public_app

def call(method, path, headers=()):
    environ = {"REQUEST_METHOD": method, "SCRIPT_NAME": "", "PATH_INFO": path,
               "QUERY_STRING": "", "RAW_URI": path, "SERVER_NAME": "0.0.0.0",
               "SERVER_PORT": "80", "SERVER_PROTOCOL": "HTTP/1.1",
               "REMOTE_ADDR": "192.168.1.20", "HTTP_HOST": "proxy.example",
               "wsgi.input": io.BytesIO(), "wsgi.errors": sys.stderr,
               "wsgi.url_scheme": "http", "wsgi.input_terminated": True}
    environ.update(headers)
    statuses = []
    body = b"".join(public_app.app(environ, lambda s, h, e=None: statuses.append(s)))
    return statuses[0], body

results = [call(m, p, h)[0] for m, p, h in (
    ("GET", "/proxy.pac", {}), ("GET", "/wpad.dat", {"HTTP_ACCEPT_ENCODING": "gzip"}),
    ("HEAD", "/", {}), ("GET", "/proxy.pac", {"HTTP_IF_NONE_MATCH": "*"}),
    ("GET", "/health", {}), ("OPTIONS", "/health", {}), ("POST", "/proxy.pac", {}),
    ("GET", "/policy-request", {}), ("GET", "/nope", {}), ("GET", "/api/manage/x", {}),
)]
watched = {"pymysql", "services.db", "services.policy_requests", "services.pac_renderer",
           "proxy.runtime", "proxy.agent"}
print(json.dumps({"statuses": results,
                  "loaded": sorted(m for m in sys.modules if m in watched)}))
"""


def test_pac_and_health_requests_load_no_database_modules(tmp_path) -> None:
    """Serving PAC/WPAD/health must not pull the DB-backed policy-request path."""
    import os
    import subprocess

    repo_root = Path(__file__).resolve().parents[2]
    pac_dir = tmp_path / "pac"
    _write_state(pac_dir, STATES["large"])
    result = subprocess.run(
        [sys.executable, "-c", _IMPORT_PROBE],
        check=True,
        capture_output=True,
        text=True,
        cwd=repo_root,
        env={
            **os.environ,
            "PYTHONPATH": f"{repo_root}:{repo_root / 'web'}",
            "PAC_RENDER_DIR": str(pac_dir),
            "PAC_HTTP_PORT": "80",
        },
    )
    report = json.loads(result.stdout)
    assert report["statuses"] == [
        "200 OK",
        "200 OK",
        "200 OK",
        "304 NOT MODIFIED",
        "200 OK",
        "200 OK",
        "405 METHOD NOT ALLOWED",
        "405 METHOD NOT ALLOWED",
        "404 NOT FOUND",
        "404 NOT FOUND",
    ]
    assert report["loaded"] == []
