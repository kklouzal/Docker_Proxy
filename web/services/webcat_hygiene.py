from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass

from services.sql_identifiers import quote_mysql_identifier

DEFAULT_WEBCAT_STALE_BUILD_TABLE_TTL_SECONDS = 6 * 60 * 60

_WEBCAT_BUILD_TABLE_RE = re.compile(
    r"^webcat_(?:domains|categories|aliases|meta|pairs)_(?:stage|old)_(\d+)_(\d+)$",
)


@dataclass(frozen=True)
class WebCatBuildTableCleanupResult:
    dropped_tables: tuple[str, ...] = ()
    discovered_tables: int = 0
    stale_tables: int = 0
    detail: str = ""


def webcat_stale_build_table_ttl_seconds() -> int | None:
    try:
        ttl = int(
            (
                os.environ.get("WEBCAT_STALE_STAGE_TTL_SECONDS")
                or str(DEFAULT_WEBCAT_STALE_BUILD_TABLE_TTL_SECONDS)
            ).strip()
            or str(DEFAULT_WEBCAT_STALE_BUILD_TABLE_TTL_SECONDS),
        )
    except Exception:
        ttl = DEFAULT_WEBCAT_STALE_BUILD_TABLE_TTL_SECONDS
    if ttl < 0:
        return None
    return max(0, ttl)


def webcat_build_table_suffix(table_name: str) -> str | None:
    match = _WEBCAT_BUILD_TABLE_RE.match(table_name or "")
    if not match:
        return None
    return f"{match.group(1)}_{match.group(2)}"


def is_stale_webcat_build_table(
    table_name: str,
    *,
    now_ts: int | None = None,
    ttl_seconds: int | None = None,
    current_suffix: str = "",
) -> bool:
    match = _WEBCAT_BUILD_TABLE_RE.match(table_name or "")
    if not match:
        return False
    suffix = f"{match.group(1)}_{match.group(2)}"
    if current_suffix and suffix == current_suffix:
        return False
    if ttl_seconds is None:
        ttl_seconds = webcat_stale_build_table_ttl_seconds()
    if ttl_seconds is None:
        return False
    try:
        built_ts = int(match.group(2))
    except Exception:
        return False
    cutoff = int(time.time() if now_ts is None else now_ts) - max(0, int(ttl_seconds))
    return built_ts <= cutoff


def _table_name_from_row(row) -> str:
    if isinstance(row, dict):
        return str(row.get("TABLE_NAME") or row.get("table_name") or "")
    if isinstance(row, (list, tuple)):
        return str(row[0] if row else "")
    return str(row or "")


def commit_if_supported(conn) -> None:
    commit = getattr(conn, "commit", None)
    if callable(commit):
        commit()


def list_webcat_build_tables(conn) -> list[str]:
    rows = conn.execute(
        "SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME LIKE 'webcat\\_%' ESCAPE '\\'",
    ).fetchall()
    tables: list[str] = []
    for row in rows:
        table = _table_name_from_row(row)
        if _WEBCAT_BUILD_TABLE_RE.match(table):
            tables.append(table)
    return tables


def drop_tables(conn, tables) -> None:
    for table in sorted(set(tables)):
        conn.execute(f"DROP TABLE IF EXISTS {quote_mysql_identifier(table)}")


def cleanup_stale_webcat_build_tables(
    conn,
    *,
    current_suffix: str = "",
    now_ts: int | None = None,
    ttl_seconds: int | None = None,
    commit: bool = True,
) -> WebCatBuildTableCleanupResult:
    if ttl_seconds is None:
        ttl_seconds = webcat_stale_build_table_ttl_seconds()
    if ttl_seconds is None:
        return WebCatBuildTableCleanupResult(detail="disabled")

    tables = list_webcat_build_tables(conn)
    stale = [
        table
        for table in tables
        if is_stale_webcat_build_table(
            table,
            now_ts=now_ts,
            ttl_seconds=ttl_seconds,
            current_suffix=current_suffix,
        )
    ]
    if stale:
        drop_tables(conn, stale)
        if commit:
            commit_if_supported(conn)
    return WebCatBuildTableCleanupResult(
        dropped_tables=tuple(sorted(set(stale))),
        discovered_tables=len(tables),
        stale_tables=len(set(stale)),
    )
