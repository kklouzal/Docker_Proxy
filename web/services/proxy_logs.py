from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_LOG_TAIL_BYTES = 256 * 1024


@dataclass(frozen=True)
class ProxyLogSpec:
    key: str
    label: str
    path: str


PROXY_LOG_SPECS: tuple[ProxyLogSpec, ...] = (
    ProxyLogSpec("access", "Squid access log", "access.log"),
    ProxyLogSpec("cache", "Squid cache log", "cache.log"),
    ProxyLogSpec("access_observe", "Observability access log", "access-observe.log"),
    ProxyLogSpec("icap", "ICAP log", "icap.log"),
)


def _log_dir() -> Path:
    return Path(
        (os.environ.get("LOG_DIR") or "/var/log/squid").strip() or "/var/log/squid"
    )


def _tail_bytes(path: Path, *, max_bytes: int) -> tuple[str, int, bool]:
    size = path.stat().st_size
    offset = max(0, size - max_bytes)
    with path.open("rb") as handle:
        handle.seek(offset)
        raw = handle.read(max_bytes)
    return raw.decode("utf-8", errors="replace"), size, offset > 0


def list_proxy_logs() -> list[dict[str, Any]]:
    base = _log_dir().resolve()
    logs: list[dict[str, Any]] = []
    for spec in PROXY_LOG_SPECS:
        path = (base / spec.path).resolve()
        logs.append(
            {
                "key": spec.key,
                "label": spec.label,
                "path": str(path),
                "available": path.is_file(),
            }
        )
    return logs


def read_proxy_log(
    key: object | None,
    *,
    max_bytes: int = DEFAULT_LOG_TAIL_BYTES,
) -> dict[str, Any]:
    normalized = str(key or "").strip()
    spec = next((item for item in PROXY_LOG_SPECS if item.key == normalized), None)
    if spec is None:
        return {
            "ok": False,
            "status": "not_found",
            "detail": "Log file is not allowlisted.",
            "logs": list_proxy_logs(),
        }

    cap = max(1, min(int(max_bytes or DEFAULT_LOG_TAIL_BYTES), DEFAULT_LOG_TAIL_BYTES))
    base = _log_dir().resolve()
    path = (base / spec.path).resolve()
    try:
        path.relative_to(base)
    except ValueError:
        return {
            "ok": False,
            "status": "not_found",
            "detail": "Log file is not allowlisted.",
            "logs": list_proxy_logs(),
        }

    if not path.is_file():
        return {
            "ok": False,
            "status": "missing",
            "detail": f"{spec.label} is not available on this proxy.",
            "key": spec.key,
            "label": spec.label,
            "path": str(path),
            "content": "",
            "size_bytes": 0,
            "truncated": False,
            "max_bytes": cap,
            "logs": list_proxy_logs(),
        }

    try:
        content, size, truncated = _tail_bytes(path, max_bytes=cap)
    except OSError as exc:
        return {
            "ok": False,
            "status": "unavailable",
            "detail": f"{spec.label} could not be read: {exc}",
            "key": spec.key,
            "label": spec.label,
            "path": str(path),
            "content": "",
            "size_bytes": 0,
            "truncated": False,
            "max_bytes": cap,
            "logs": list_proxy_logs(),
        }

    return {
        "ok": True,
        "status": "ok",
        "detail": "Loaded current log file tail.",
        "key": spec.key,
        "label": spec.label,
        "path": str(path),
        "content": content,
        "size_bytes": size,
        "truncated": truncated,
        "max_bytes": cap,
        "logs": list_proxy_logs(),
    }
