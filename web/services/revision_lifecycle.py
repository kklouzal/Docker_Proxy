from __future__ import annotations

import hashlib
import re
from contextlib import contextmanager, suppress
from typing import Any

from services.db import DATABASE_ERRORS, mysql_error_code

_ADVISORY_LOCK_TIMEOUT_SECONDS = 10
_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _safe_identifier(value: str) -> str:
    if not _IDENTIFIER_RE.fullmatch(value or ""):
        msg = f"Unsafe MySQL identifier: {value!r}"
        raise ValueError(msg)
    return value


def column_exists(conn: Any, table_name: str, column_name: str) -> bool:
    row = conn.execute(
        """
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = DATABASE()
          AND table_name = %s
          AND column_name = %s
        LIMIT 1
        """,
        (table_name, column_name),
    ).fetchone()
    return row is not None


def index_exists(conn: Any, table_name: str, index_name: str) -> bool:
    row = conn.execute(
        """
        SELECT 1
        FROM information_schema.statistics
        WHERE table_schema = DATABASE()
          AND table_name = %s
          AND index_name = %s
        LIMIT 1
        """,
        (table_name, index_name),
    ).fetchone()
    return row is not None


def ensure_generated_column(
    conn: Any,
    *,
    table_name: str,
    column_name: str,
    ddl: str,
) -> None:
    if column_exists(conn, table_name, column_name):
        return
    try:
        conn.execute(ddl)
    except DATABASE_ERRORS as exc:
        if mysql_error_code(exc) != 1060:
            raise


def ensure_index(
    conn: Any,
    *,
    table_name: str,
    index_name: str,
    ddl: str,
) -> None:
    if index_exists(conn, table_name, index_name):
        return
    try:
        conn.execute(ddl)
    except DATABASE_ERRORS as exc:
        if mysql_error_code(exc) != 1061:
            raise


def repair_duplicate_active_rows(
    conn: Any,
    *,
    table_name: str,
    scope_column: str | None = None,
) -> int:
    """Demote legacy duplicate active rows, preserving the newest active per scope.

    The newest active row is chosen deterministically by (created_ts DESC, id DESC).
    Older duplicate rows are retained as inactive history; payload columns are not
    modified.
    """
    safe_table = _safe_identifier(table_name)
    safe_scope = _safe_identifier(scope_column) if scope_column else ""
    partition = f"PARTITION BY {safe_scope}" if safe_scope else ""
    sql = f"""
        UPDATE {safe_table} target
        JOIN (
            SELECT id,
                   ROW_NUMBER() OVER ({partition} ORDER BY created_ts DESC, id DESC) AS active_rank
            FROM {safe_table}
            WHERE is_active=1
        ) ranked ON ranked.id=target.id
        SET target.is_active=0
        WHERE ranked.active_rank > 1
        """  # noqa: S608 - identifiers are validated constants; values are not interpolated.
    result = conn.execute(sql)
    return max(0, int(getattr(result, "rowcount", 0) or 0))


def scoped_lock_name(namespace: str, scope: object | None = None) -> str:
    raw = f"{namespace}:{'' if scope is None else str(scope)}"
    digest = hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:24]
    prefix = namespace.replace("`", "").replace(" ", "_")[:32]
    return f"docker_proxy:{prefix}:{digest}"[:64]


@contextmanager
def mysql_advisory_lock(
    conn: Any,
    *,
    namespace: str,
    scope: object | None = None,
    timeout_seconds: int = _ADVISORY_LOCK_TIMEOUT_SECONDS,
):
    name = scoped_lock_name(namespace, scope)
    row = conn.execute("SELECT GET_LOCK(%s, %s) AS acquired", (name, timeout_seconds)).fetchone()
    acquired = False
    if row is not None:
        try:
            acquired = int(row["acquired"] or 0) == 1
        except (IndexError, KeyError, TypeError, ValueError):
            try:
                acquired = int(row[0] or 0) == 1
            except (IndexError, TypeError, ValueError):
                acquired = False
    if not acquired:
        msg = f"Timed out acquiring MySQL lifecycle lock {name}."
        raise RuntimeError(msg)
    try:
        yield name
    except Exception:
        with suppress(Exception):
            conn.rollback()
        raise
    else:
        with suppress(Exception):
            conn.commit()
    finally:
        try:
            conn.execute("DO RELEASE_LOCK(%s)", (name,))
        except Exception:
            # The connection wrapper will discard/rollback broken connections as needed.
            pass
