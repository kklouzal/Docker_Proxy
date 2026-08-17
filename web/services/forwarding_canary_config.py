from __future__ import annotations

import ipaddress
import os

DEFAULT_FORWARDING_CANARY_HOST = "127.0.0.1"
DEFAULT_FORWARDING_CANARY_PORT = 18080
DEFAULT_FORWARDING_CANARY_PATH = "/__docker_proxy_forwarding_canary"


def normalize_forwarding_canary_path(value: object) -> str:
    candidate = str(value or DEFAULT_FORWARDING_CANARY_PATH)
    if (
        not candidate.startswith("/")
        or "?" in candidate
        or "#" in candidate
        or "\\" in candidate
        or "//" in candidate
        or any(
            char.isspace() or ord(char) < 0x20 or 0x7F <= ord(char) <= 0x9F
            for char in candidate
        )
    ):
        return DEFAULT_FORWARDING_CANARY_PATH
    return candidate


def forwarding_canary_path() -> str:
    return normalize_forwarding_canary_path(os.environ.get("FORWARDING_CANARY_PATH"))


def normalize_forwarding_canary_port(value: object) -> int:
    try:
        port = int(str(value or DEFAULT_FORWARDING_CANARY_PORT).strip())
    except (TypeError, ValueError):
        return DEFAULT_FORWARDING_CANARY_PORT
    return port if 1 <= port <= 65535 else DEFAULT_FORWARDING_CANARY_PORT


def forwarding_canary_port() -> int:
    return normalize_forwarding_canary_port(os.environ.get("FORWARDING_CANARY_PORT"))


def normalize_forwarding_canary_listener_host(value: object) -> str:
    candidate = str(value or DEFAULT_FORWARDING_CANARY_HOST).strip().strip("[]")
    if candidate.lower() == "localhost":
        return candidate
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return DEFAULT_FORWARDING_CANARY_HOST
    # The listener is deliberately IPv4-only so its Squid destination ACL and
    # health target cannot diverge across environments.
    if address.version == 4 and address.is_loopback:
        return candidate
    return DEFAULT_FORWARDING_CANARY_HOST


def forwarding_canary_listener_host() -> str:
    return normalize_forwarding_canary_listener_host(
        os.environ.get("FORWARDING_CANARY_HOST")
    )


def forwarding_canary_target_url() -> str:
    return (
        f"http://{forwarding_canary_listener_host()}:{forwarding_canary_port()}"
        f"{forwarding_canary_path()}"
    )
