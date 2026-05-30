from __future__ import annotations

import json
import sys
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any


def _monotonic_now() -> float:
    return time.monotonic()


def split_acl_channel(line: str) -> tuple[str | None, list[str]]:
    parts = (line or "").strip().split()
    if parts and parts[0].isdigit():
        return parts[0], parts[1:]
    return None, parts


def write_acl_response(channel_id: str | None, ok: bool) -> None:
    prefix = f"{channel_id} " if channel_id is not None else ""
    sys.stdout.write(f"{prefix}{'OK' if ok else 'ERR'}\n")
    sys.stdout.flush()


def helper_event(helper: str, event: str, **fields: Any) -> None:
    payload = {
        "ts": int(time.time()),
        "helper": str(helper or "helper"),
        "event": str(event or "event"),
    }
    for key, value in fields.items():
        if value is None:
            continue
        payload[str(key)] = value
    try:
        sys.stderr.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
        sys.stderr.flush()
    except Exception:
        pass


@dataclass
class HelperStats:
    helper: str
    emit_interval_seconds: float = 60.0
    counters: dict[str, int] = field(default_factory=dict)
    _last_emit: float = field(default_factory=_monotonic_now)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def increment(self, key: str, amount: int = 1) -> None:
        if not key:
            return
        with self._lock:
            self.counters[key] = int(self.counters.get(key, 0)) + int(amount or 0)

    def emit_if_due(self, *, force: bool = False) -> None:
        now = time.monotonic()
        with self._lock:
            if not force and (now - self._last_emit) < self.emit_interval_seconds:
                return
            self._last_emit = now
            counters = dict(self.counters)
        if counters:
            helper_event(self.helper, "stats", **counters)


class TtlLruCache:
    def __init__(self, *, max_entries: int, ttl_seconds: float) -> None:
        self.max_entries = max(0, int(max_entries or 0))
        self.ttl_seconds = max(0.0, float(ttl_seconds or 0.0))
        self._items: OrderedDict[Any, tuple[float, Any]] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: Any) -> Any | None:
        if not self.max_entries or not self.ttl_seconds:
            return None
        with self._lock:
            item = self._items.get(key)
            if item is None:
                return None
            expires_at, value = item
            if expires_at <= time.monotonic():
                self._items.pop(key, None)
                return None
            self._items.move_to_end(key)
            return value

    def put(self, key: Any, value: Any) -> Any:
        if not self.max_entries or not self.ttl_seconds:
            return value
        with self._lock:
            self._items[key] = (time.monotonic() + self.ttl_seconds, value)
            self._items.move_to_end(key)
            while len(self._items) > self.max_entries:
                self._items.popitem(last=False)
        return value

    def clear(self) -> None:
        with self._lock:
            self._items.clear()
