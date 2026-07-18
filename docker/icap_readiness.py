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
import json
import os
import re
import socket
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urlsplit

TRUE_VALUES = {"1", "true", "yes", "on", "enabled", "required", "strict"}
DEFAULT_CONFIG = "/etc/squid/conf.d/20-icap.conf"
DEFAULT_STATUS_FILE = "/var/lib/squid-flask-proxy/icap-readiness.json"
DEFAULT_TIMEOUT_SECONDS = 75.0
DEFAULT_PROBE_TIMEOUT_SECONDS = 1.0


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


def _env_enabled(name: str, *, default: bool = False) -> bool:
    raw = (os.environ.get(name) or "").strip().lower()
    if not raw:
        return default
    return raw in TRUE_VALUES


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
    port = parsed.port
    if not host or port is None or port < 1 or port > 65535:
        return None
    path = parsed.path or "/"
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


def _read_icap_headers(sock: socket.socket, *, max_bytes: int = 8192) -> bytes:
    data = b""
    while len(data) < max_bytes:
        chunk = sock.recv(min(512, max_bytes - len(data)))
        if not chunk:
            break
        data += chunk
        if b"\r\n\r\n" in data or b"\n\n" in data:
            break
    return data


def _header_value(head: bytes, name: str) -> str:
    needle = name.lower()
    try:
        lines = head.decode("iso-8859-1", errors="replace").replace("\r\n", "\n").split("\n")
    except Exception:
        return ""
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        if key.strip().lower() == needle:
            return value.strip()
    return ""


def probe_service(service: IcapService, *, timeout: float) -> ProbeResult:
    host_header = service.host
    if ":" in host_header and not host_header.startswith("["):
        host_header = f"[{host_header}]"
    request = (
        f"OPTIONS icap://{host_header}:{service.port}{service.path} ICAP/1.0\r\n"
        f"Host: {host_header}\r\n"
        "User-Agent: docker-proxy-icap-readiness\r\n"
        "Connection: close\r\n"
        "Encapsulated: null-body=0\r\n\r\n"
    ).encode("ascii", errors="replace")
    try:
        with socket.create_connection((service.host, service.port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(request)
            head = _read_icap_headers(sock)
    except Exception as exc:
        return ProbeResult(service=service, ok=False, detail=f"connect/options failed: {exc}")

    first_line = (
        head.split(b"\r\n", 1)[0]
        .split(b"\n", 1)[0]
        .decode("ascii", errors="replace")
        .strip()
    )
    methods = _header_value(head, "Methods")
    if not first_line.startswith("ICAP/1.0 200"):
        return ProbeResult(
            service=service,
            ok=False,
            detail=first_line or "no ICAP status line",
            status_line=first_line,
            methods=methods,
        )
    if methods:
        allowed = {part.strip().upper() for part in re.split(r"[,\s]+", methods) if part.strip()}
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
        detail=first_line or "ICAP OPTIONS ok",
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


def _write_status(path: str, payload: dict[str, object]) -> None:
    if not path:
        return
    try:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_name(f".{target.name}.{os.getpid()}.tmp")
        tmp.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
        tmp.replace(target)
    except Exception:
        pass


def check_once(configs: list[str], *, probe_timeout: float) -> tuple[bool, str, dict[str, object]]:
    services = parse_services(configs)
    if not services:
        payload = {"ok": True, "services": [], "detail": "No ICAP services are configured."}
        return True, payload["detail"], payload
    results = [probe_service(service, timeout=probe_timeout) for service in services]
    failures = [result for result in results if not result.ok]
    payload = {
        "ok": not failures,
        "services": [_result_to_json(result) for result in results],
        "detail": "All configured ICAP services answered OPTIONS." if not failures else "; ".join(
            f"{item.service.name}@{item.service.host}:{item.service.port}{item.service.path} {item.service.method}: {item.detail}"
            for item in failures
        ),
    }
    return not failures, str(payload["detail"]), payload


def wait_ready(
    configs: list[str],
    *,
    timeout: float,
    probe_timeout: float,
    interval: float,
    status_file: str,
) -> tuple[bool, str]:
    deadline = time.monotonic() + max(0.1, timeout)
    last_detail = "ICAP readiness has not been checked yet."
    last_payload: dict[str, object] = {"ok": False, "detail": last_detail, "services": []}
    while True:
        ok, detail, payload = check_once(configs, probe_timeout=probe_timeout)
        payload = {**payload, "checked_at": int(time.time()), "timeout_seconds": timeout}
        _write_status(status_file, payload)
        if ok:
            return True, detail
        last_detail = detail
        last_payload = payload
        if time.monotonic() >= deadline:
            _write_status(status_file, {**last_payload, "ok": False, "timed_out": True})
            return False, last_detail
        time.sleep(max(0.05, min(interval, deadline - time.monotonic())))


def _configs_from_args(values: list[str] | None) -> list[str]:
    configs = [item for item in (values or []) if str(item or "").strip()]
    if configs:
        return configs
    env_value = os.environ.get("SQUID_ICAP_READY_CONFIGS") or os.environ.get("SQUID_ICAP_INCLUDE_PATH")
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
            type=float,
            default=float(os.environ.get("SQUID_ICAP_READY_PROBE_TIMEOUT_SECONDS", DEFAULT_PROBE_TIMEOUT_SECONDS)),
        )
        sub.add_argument("--json", action="store_true")
        if name == "wait":
            sub.add_argument(
                "--timeout",
                type=float,
                default=float(os.environ.get("SQUID_ICAP_READY_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS)),
            )
            sub.add_argument(
                "--interval",
                type=float,
                default=float(os.environ.get("SQUID_ICAP_READY_INTERVAL_SECONDS", "0.25")),
            )
            sub.add_argument(
                "--status-file",
                default=os.environ.get("SQUID_ICAP_READY_STATUS_FILE", DEFAULT_STATUS_FILE),
            )
    args = parser.parse_args(argv)
    configs = _configs_from_args(args.configs)
    if args.command == "check":
        ok, detail, payload = check_once(configs, probe_timeout=max(0.1, args.probe_timeout))
        if args.json:
            sys.stdout.write(json.dumps(payload, sort_keys=True) + "\n")
        else:
            sys.stdout.write(detail + "\n")
        return 0 if ok else 1
    ok, detail = wait_ready(
        configs,
        timeout=max(0.1, args.timeout),
        probe_timeout=max(0.1, args.probe_timeout),
        interval=max(0.05, args.interval),
        status_file=args.status_file,
    )
    if args.json:
        _ok, _detail, payload = check_once(configs, probe_timeout=max(0.1, args.probe_timeout))
        sys.stdout.write(json.dumps(payload, sort_keys=True) + "\n")
    else:
        sys.stdout.write(detail + "\n")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
