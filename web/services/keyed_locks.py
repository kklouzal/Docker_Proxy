from __future__ import annotations

import contextlib
import threading
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator


@dataclass
class _LockEntry:
    lock: threading.Lock
    users: int = 0


class KeyedLockRegistry[Key]:
    """Serialize active users by key without retaining idle keys."""

    def __init__(self) -> None:
        self._guard = threading.Lock()
        self._entries: dict[Key, _LockEntry] = {}

    @contextlib.contextmanager
    def locked(self, keys: list[Key]) -> Iterator[None]:
        ordered_keys = sorted(set(keys))
        with self._guard:
            entries: list[tuple[Key, _LockEntry]] = []
            for key in ordered_keys:
                entry = self._entries.get(key)
                if entry is None:
                    entry = _LockEntry(lock=threading.Lock())
                    self._entries[key] = entry
                entry.users += 1
                entries.append((key, entry))

        acquired: list[_LockEntry] = []
        try:
            for _key, entry in entries:
                entry.lock.acquire()
                acquired.append(entry)
            yield
        finally:
            for entry in reversed(acquired):
                entry.lock.release()
            with self._guard:
                for key, entry in entries:
                    entry.users -= 1
                    if entry.users == 0:
                        del self._entries[key]

    def __len__(self) -> int:
        with self._guard:
            return len(self._entries)
