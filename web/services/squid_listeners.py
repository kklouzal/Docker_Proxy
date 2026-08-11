from __future__ import annotations

import ipaddress
from pathlib import Path


def logical_lines(text: str):
    pending: list[str] = []
    for raw in (text or "").splitlines():
        pending.append(raw)
        if raw.rstrip().endswith("\\"):
            continue
        yield " ".join(line.rstrip().rstrip("\\").strip() for line in pending).strip()
        pending.clear()
    if pending:
        yield " ".join(line.rstrip().rstrip("\\").strip() for line in pending).strip()


def parse_squid_listeners(
    text: str, *, fallback_port: int = 3128
) -> tuple[dict[str, object], ...]:
    listeners: list[dict[str, object]] = []
    for logical in logical_lines(text):
        if not logical or logical.startswith("#"):
            continue
        parts = logical.split()
        directive = parts[0].lower() if parts else ""
        if directive not in {"http_port", "https_port"} or len(parts) < 2:
            continue
        token = parts[1]
        host: str | None = None
        candidate = token
        if token.startswith("[") and "]:" in token:
            host, candidate = token[1:].rsplit("]:", 1)
        elif ":" in token:
            host, candidate = token.rsplit(":", 1)
        try:
            port = int(candidate)
        except ValueError:
            continue
        if not 1 <= port <= 65535:
            continue
        modes = {part.lower() for part in parts[2:]}
        transparent = "intercept" in modes or "tproxy" in modes
        mode = (
            "intercept"
            if "intercept" in modes
            else "tproxy"
            if "tproxy" in modes
            else "explicit"
        )
        if directive == "https_port":
            mode = f"https-{mode}" if transparent else "https"
        item = {"host": host, "port": port, "mode": mode, "response": not transparent}
        if item not in listeners:
            listeners.append(item)
    if listeners:
        return tuple(listeners)
    return (
        {"host": None, "port": fallback_port, "mode": "explicit", "response": True},
    )


def _proc_address(hex_address: str) -> ipaddress._BaseAddress:
    raw = bytes.fromhex(hex_address)
    if len(raw) == 4:
        raw = raw[::-1]
    elif len(raw) == 16:
        raw = b"".join(raw[index : index + 4][::-1] for index in range(0, 16, 4))
    return ipaddress.ip_address(raw)


def listening_endpoints(
    paths=("/proc/net/tcp", "/proc/net/tcp6"),
) -> set[tuple[str, int]]:
    endpoints: set[tuple[str, int]] = set()
    for path in paths:
        try:
            handle = Path(path).open(encoding="utf-8", errors="replace")
        except FileNotFoundError:
            continue
        with handle:
            next(handle, None)
            for line in handle:
                parts = line.split()
                if len(parts) < 4 or parts[3] != "0A":
                    continue
                address_hex, port_hex = parts[1].rsplit(":", 1)
                try:
                    endpoints.add((str(_proc_address(address_hex)), int(port_hex, 16)))
                except (ValueError, IndexError):
                    continue
    return endpoints


def listener_is_present(
    listener: dict[str, object], endpoints: set[tuple[str, int]]
) -> bool:
    port = int(listener["port"])
    host = listener.get("host")
    if not host:
        return any(endpoint_port == port for _address, endpoint_port in endpoints)
    try:
        expected = ipaddress.ip_address(str(host).split("%", 1)[0])
    except ValueError:
        return any(endpoint_port == port for _address, endpoint_port in endpoints)
    for address, endpoint_port in endpoints:
        if endpoint_port != port:
            continue
        actual = ipaddress.ip_address(address)
        if actual == expected or actual.is_unspecified:
            return True
    return False
