from __future__ import annotations

from typing import Any


def row_value(row: Any, key: str, index: int = 0) -> Any:
    """Read a mapping key or positional index, returning None when both are absent."""
    if row is None:
        return None
    try:
        return row[key]
    except (KeyError, IndexError, TypeError):
        try:
            return row[index]
        except (KeyError, IndexError, TypeError):
            return None
