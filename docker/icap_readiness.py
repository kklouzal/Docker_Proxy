#!/usr/bin/env python3
"""Bounded ICAP readiness probes for Squid startup/restart gates.

The proxy renders Squid ICAP services dynamically.  Squid must not bind its
client HTTP ports until those ICAP endpoints are not only listening, but able to
answer ICAP OPTIONS for the method Squid will use.  TCP-only checks can pass
while a helper is still booting and the first client transactions would see
ICAP_FAILURE.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import math
import os
import re
import socket
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

DEFAULT_CONFIG = "/etc/squid/conf.d/20-icap.conf"
DEFAULT_STATUS_FILE = "/var/lib/squid-flask-proxy/icap-readiness.json"
DEFAULT_TIMEOUT_SECONDS = 75.0
DEFAULT_PROBE_TIMEOUT_SECONDS = 1.0
DEFAULT_INTERVAL_SECONDS = 0.25
MAX_CONCURRENT_PROBES = 12
MAX_ICAP_HEADER_BYTES = 8192
ICAP_STATUS_LINE_RE = re.compile(
    r"^ICAP/1\.0 (?P<code>[0-9]{3}) (?P<reason>[!-~](?:[ -~]*[!-~])?)$"
)
ICAP_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


class ProbeDeadlineExceededError(TimeoutError):
    def __init__(self) -> None:
        super().__init__("ICAP OPTIONS probe deadline exceeded")


@dataclass(frozen=True)
class IcapService:
    name: str
    method: str
    url: str
    host: str
    port: int
    path: str
    bypass: bool

    @property
    def required(self) -> bool:
        return not self.bypass


@dataclass(frozen=True)
class ProbeResult:
    service: IcapService
    ok: bool
    detail: str
    status_line: str = ""
    methods: str = ""


def _finite_float(value: str) -> float:
    error = "must be a finite number"
    try:
        number = float(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError(error) from exc
    if not math.isfinite(number):
        raise argparse.ArgumentTypeError(error)
    return number


def _env_float(name: str, default: float, *, minimum: float) -> float:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        value = float(default)
    else:
        try:
            value = _finite_float(raw)
        except argparse.ArgumentTypeError:
            value = float(default)
    return max(float(minimum), value)


def _logical_lines(text: str):
    pending: list[str] = []
    for raw in text.splitlines():
        stripped = raw.strip()
        if not pending and (not stripped or stripped.startswith("#")):
            continue
        pending.append(raw)
        if raw.rstrip().endswith("\\"):
            continue
        yield " ".join(line.rstrip().rstrip("\\").strip() for line in pending).strip()
        pending.clear()
    if pending:
        yield " ".join(line.rstrip().rstrip("\\").strip() for line in pending).strip()


def _parse_bool_option(tokens: list[str], name: str, *, default: bool) -> bool:
    prefix = f"{name.lower()}="
    for token in tokens:
        lower = token.strip().lower()
        if lower.startswith(prefix):
            return lower.split("=", 1)[1] in {"1", "yes", "true", "on"}
    return default


def _parse_icap_url(raw_url: str) -> tuple[str, int, str] | None:
    parsed = urlsplit(raw_url)
    if parsed.scheme.lower() != "icap":
        return None
    host = parsed.hostname or ""
    try:
        port = parsed.port
    except ValueError:
        return None
    if not host or port is None or port < 1 or port > 65535 or parsed.fragment:
        return None
    path = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
    return host, int(port), path


def parse_services(paths: list[str]) -> list[IcapService]:
    services: list[IcapService] = []
    seen: set[tuple[str, int, str, str]] = set()
    for path in paths:
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
        except FileNotFoundError:
            continue
        for logical in _logical_lines(text):
            if not logical or logical.startswith("#"):
                continue
            parts = logical.split()
            if len(parts) < 4 or parts[0].lower() != "icap_service":
                continue
            name = parts[1]
            mode = parts[2].lower()
            if mode.startswith("reqmod"):
                method = "REQMOD"
            elif mode.startswith("respmod"):
                method = "RESPMOD"
            else:
                continue
            parsed = _parse_icap_url(parts[3])
            if parsed is None:
                continue
            host, port, path_value = parsed
            bypass = _parse_bool_option(parts[4:], "bypass", default=False)
            key = (host, port, path_value, method)
            if key in seen:
                continue
            seen.add(key)
            services.append(
                IcapService(
                    name=name,
                    method=method,
                    url=parts[3],
                    host=host,
                    port=port,
                    path=path_value,
                    bypass=bypass,
                )
            )
    return services


def _read_icap_headers(
    sock: socket.socket,
    *,
    deadline: float,
    max_bytes: int = MAX_ICAP_HEADER_BYTES,
) -> bytes:
    data = b""
    while len(data) < max_bytes:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ProbeDeadlineExceededError
        sock.settimeout(remaining)
        chunk = sock.recv(min(512, max_bytes - len(data)))
        if not chunk:
            break
        data += chunk
        if b"\r\n\r\n" in data or b"\n\n" in data:
            break
    return data


def _parse_icap_response_head(
    head: bytes,
) -> tuple[bool, str, str, dict[str, list[str]]]:
    if not head:
        return False, "no ICAP response headers", "", {}
    if b"\r\n\r\n" not in head:
        if b"\n\n" in head:
            return False, "malformed ICAP header terminator", "", {}
        return False, "incomplete ICAP response headers", "", {}
    block = head.split(b"\r\n\r\n", 1)[0]
    if b"\n" in block.replace(b"\r\n", b"") or b"\r" in block.replace(b"\r\n", b""):
        return False, "malformed ICAP header line endings", "", {}
    lines = block.split(b"\r\n")
    try:
        decoded = [line.decode("ascii") for line in lines]
    except UnicodeDecodeError:
        return False, "non-ASCII ICAP response header", "", {}
    for line in decoded:
        if any((ord(char) < 32 and char != "\t") or ord(char) == 127 for char in line):
            return False, "control character in ICAP response header", "", {}
    first_line = decoded[0] if decoded else ""
    match = ICAP_STATUS_LINE_RE.fullmatch(first_line)
    if not match:
        return (
            False,
            f"malformed ICAP status line: {first_line or 'empty'}",
            first_line,
            {},
        )
    if match.group("code") != "200":
        return False, first_line, first_line, {}
    headers: dict[str, list[str]] = {}
    for line in decoded[1:]:
        if ":" not in line:
            return (
                False,
                f"malformed ICAP header line: {line or 'empty'}",
                first_line,
                {},
            )
        key, value = line.split(":", 1)
        if not ICAP_HEADER_NAME_RE.fullmatch(key):
            return (
                False,
                f"malformed ICAP header name: {key or 'empty'}",
                first_line,
                {},
            )
        headers.setdefault(key.lower(), []).append(value.strip())
    return True, first_line or "ICAP OPTIONS ok", first_line, headers


def probe_service(service: IcapService, *, timeout: float) -> ProbeResult:
    deadline = time.monotonic() + timeout
    host_header = service.host
    if ":" in host_header and not host_header.startswith("["):
        host_header = f"[{host_header}]"
    request_host = f"{host_header}:{service.port}"
    request = (
        f"OPTIONS icap://{request_host}{service.path} ICAP/1.0\r\n"
        f"Host: {request_host}\r\n"
        "User-Agent: docker-proxy-icap-readiness\r\n"
        "Connection: close\r\n"
        "Encapsulated: null-body=0\r\n\r\n"
    ).encode("ascii", errors="replace")
    try:
        with socket.create_connection(
            (service.host, service.port), timeout=timeout
        ) as sock:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProbeDeadlineExceededError
            sock.settimeout(remaining)
            sock.sendall(request)
            head = _read_icap_headers(sock, deadline=deadline)
    except OSError as exc:
        return ProbeResult(
            service=service, ok=False, detail=f"connect/options failed: {exc}"
        )

    ok, detail, first_line, headers = _parse_icap_response_head(head)
    methods_values = headers.get("methods", [])
    methods = methods_values[0] if methods_values else ""
    if not ok:
        return ProbeResult(
            service=service,
            ok=False,
            detail=detail,
            status_line=first_line,
            methods=methods,
        )
    if len(methods_values) > 1:
        return ProbeResult(
            service=service,
            ok=False,
            detail="duplicate OPTIONS Methods headers",
            status_line=first_line,
            methods=", ".join(methods_values),
        )
    if methods:
        allowed = {
            part.strip().upper()
            for part in re.split(r"[,\s]+", methods)
            if part.strip()
        }
        if service.method.upper() not in allowed:
            return ProbeResult(
                service=service,
                ok=False,
                detail=f"OPTIONS Methods {methods!r} does not include {service.method}",
                status_line=first_line,
                methods=methods,
            )
    return ProbeResult(
        service=service,
        ok=True,
        detail=detail,
        status_line=first_line,
        methods=methods,
    )


def _result_to_json(result: ProbeResult) -> dict[str, object]:
    data = asdict(result.service)
    data.update(
        {
            "ok": result.ok,
            "detail": result.detail,
            "status_line": result.status_line,
            "methods": result.methods,
            "required": result.service.required,
        }
    )
    return data


def _write_status(path: str, payload: dict[str, object]) -> str | None:
    if not path:
        return None
    tmp_path: str | None = None
    try:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(
            prefix=f".{target.name}.", suffix=".tmp", dir=target.parent
        )
        with os.fdopen(fd, "w", encoding="utf-8") as tmp_file:
            os.fchmod(tmp_file.fileno(), 0o600)
            tmp_file.write(json.dumps(payload, sort_keys=True) + "\n")
            tmp_file.flush()
            os.fsync(tmp_file.fileno())
        Path(tmp_path).replace(target)
        tmp_path = None
        directory_fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as exc:
        return f"failed to write ICAP readiness status file {path}: {exc}"
    finally:
        if tmp_path is not None:
            try:
                Path(tmp_path).unlink()
            except FileNotFoundError:
                pass
    return None


def check_once(
    configs: list[str], *, probe_timeout: float
) -> tuple[bool, str, dict[str, object]]:
    services = parse_services(configs)
    if not services:
        payload = {
            "ok": True,
            "services": [],
            "detail": "No ICAP services are configured.",
        }
        return True, payload["detail"], payload
    # Supported generated configurations currently render at most twelve
    # services. Bound operator-supplied/future expanded configurations to that
    # same concurrency instead of creating one thread per parsed service.
    # executor.map still probes every service and preserves config/result order;
    # each probe retains its own absolute timeout once its worker starts.
    max_workers = min(len(services), MAX_CONCURRENT_PROBES)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = list(
            executor.map(
                lambda service: probe_service(service, timeout=probe_timeout),
                services,
            )
        )
    failures = [result for result in results if not result.ok]
    blocking_failures = [result for result in failures if result.service.required]
    degraded_failures = [result for result in failures if not result.service.required]

    def describe(items: list[ProbeResult]) -> str:
        return "; ".join(
            f"{item.service.name}@{item.service.host}:{item.service.port}{item.service.path} "
            f"{item.service.method}: {item.detail}"
            for item in items
        )

    if blocking_failures:
        detail = f"Required ICAP services are not OPTIONS-ready: {describe(blocking_failures)}"
        if degraded_failures:
            detail += (
                f"; optional ICAP services also degraded: {describe(degraded_failures)}"
            )
    elif degraded_failures:
        detail = (
            "Required ICAP services are OPTIONS-ready; optional ICAP services are degraded "
            f"(fail-open): {describe(degraded_failures)}"
        )
    else:
        detail = "All configured ICAP services answered OPTIONS."
    payload = {
        "ok": not blocking_failures,
        "degraded": bool(degraded_failures),
        "blocking_failure_count": len(blocking_failures),
        "optional_failure_count": len(degraded_failures),
        "services": [_result_to_json(result) for result in results],
        "detail": detail,
    }
    return not blocking_failures, detail, payload


def wait_ready(
    configs: list[str],
    *,
    timeout: float,
    probe_timeout: float,
    interval: float,
    status_file: str,
) -> tuple[bool, str, dict[str, object]]:
    deadline = time.monotonic() + max(0.1, timeout)
    last_detail = "ICAP readiness has not been checked yet."
    last_payload: dict[str, object] = {
        "ok": False,
        "detail": last_detail,
        "services": [],
    }
    while True:
        ok, detail, payload = check_once(configs, probe_timeout=probe_timeout)
        payload = {
            **payload,
            "checked_at": int(time.time()),
            "timeout_seconds": timeout,
        }
        status_error = _write_status(status_file, payload)
        if status_error:
            payload = {**payload, "status_file_error": status_error}
        if ok:
            return True, detail, payload
        last_detail = detail
        last_payload = payload
        if time.monotonic() >= deadline:
            timeout_payload = {**last_payload, "ok": False, "timed_out": True}
            status_error = _write_status(status_file, timeout_payload)
            if status_error:
                timeout_payload = {**timeout_payload, "status_file_error": status_error}
            return False, last_detail, timeout_payload
        time.sleep(max(0.05, min(interval, deadline - time.monotonic())))


def _configs_from_args(values: list[str] | None) -> list[str]:
    configs = [item for item in (values or []) if str(item or "").strip()]
    if configs:
        return configs
    env_value = os.environ.get("SQUID_ICAP_READY_CONFIGS") or os.environ.get(
        "SQUID_ICAP_INCLUDE_PATH"
    )
    if env_value:
        return [item for item in re.split(r"[:,]", env_value) if item.strip()]
    return [DEFAULT_CONFIG]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("check", "wait"):
        sub = subparsers.add_parser(name)
        sub.add_argument("--config", action="append", dest="configs")
        sub.add_argument(
            "--probe-timeout",
            type=_finite_float,
            default=_env_float(
                "SQUID_ICAP_READY_PROBE_TIMEOUT_SECONDS",
                DEFAULT_PROBE_TIMEOUT_SECONDS,
                minimum=0.1,
            ),
        )
        sub.add_argument("--json", action="store_true")
        if name == "wait":
            sub.add_argument(
                "--timeout",
                type=_finite_float,
                default=_env_float(
                    "SQUID_ICAP_READY_TIMEOUT_SECONDS",
                    DEFAULT_TIMEOUT_SECONDS,
                    minimum=0.1,
                ),
            )
            sub.add_argument(
                "--interval",
                type=_finite_float,
                default=_env_float(
                    "SQUID_ICAP_READY_INTERVAL_SECONDS",
                    DEFAULT_INTERVAL_SECONDS,
                    minimum=0.05,
                ),
            )
            sub.add_argument(
                "--status-file",
                default=os.environ.get(
                    "SQUID_ICAP_READY_STATUS_FILE", DEFAULT_STATUS_FILE
                ),
            )
    args = parser.parse_args(argv)
    configs = _configs_from_args(args.configs)
    if args.command == "check":
        ok, detail, payload = check_once(
            configs, probe_timeout=max(0.1, args.probe_timeout)
        )
        if args.json:
            sys.stdout.write(json.dumps(payload, sort_keys=True) + "\n")
        else:
            sys.stdout.write(detail + "\n")
        return 0 if ok else 1
    ok, detail, payload = wait_ready(
        configs,
        timeout=max(0.1, args.timeout),
        probe_timeout=max(0.1, args.probe_timeout),
        interval=max(0.05, args.interval),
        status_file=args.status_file,
    )
    if args.json:
        sys.stdout.write(json.dumps(payload, sort_keys=True) + "\n")
    else:
        sys.stdout.write(detail + "\n")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
