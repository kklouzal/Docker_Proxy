"""Shared fake-connection support for the proxy write guard's metadata query."""

from __future__ import annotations

LIFECYCLE_STATE_QUERY_PREFIX = (
    "SELECT (SELECT action FROM proxy_lifecycle_tombstones WHERE proxy_id=%s"
)


def is_lifecycle_state_query(sql: str) -> bool:
    """Return whether whitespace-normalized ``sql`` is the guard state lookup."""
    return " ".join(str(sql).split()).startswith(LIFECYCLE_STATE_QUERY_PREFIX)


def lifecycle_state_row(
    *,
    tombstone: tuple[str, str] | None = None,
    alias_target: str | None = None,
    registry_status: str | None = None,
) -> dict[str, object]:
    """Build the single row the guard's combined lookup returns.

    ``None`` values model a missing row, exactly as the scalar subqueries do.
    """
    return {
        "tombstone_action": None if tombstone is None else tombstone[0],
        "tombstone_target": None if tombstone is None else tombstone[1],
        "alias_target": alias_target,
        "registry_status": registry_status,
    }
