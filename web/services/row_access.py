from __future__ import annotations

from typing import Any


def row_value(row: Any, key: str, index: int = 0, default: Any = None) -> Any:
    """Read a mapping key or positional index, returning ``default`` when absent."""
    if row is None:
        return default
    try:
        return row[key]
    except (KeyError, IndexError, TypeError):
        try:
            return row[index]
        except (KeyError, IndexError, TypeError):
            return default
