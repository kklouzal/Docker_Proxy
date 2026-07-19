from __future__ import annotations

import hashlib
import re
from contextlib import contextmanager, suppress
from typing import Any

from services import schema_lifecycle as _schema_lifecycle

_ADVISORY_LOCK_TIMEOUT_SECONDS = 10
_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _safe_identifier(value: str) -> str:
    if not _IDENTIFIER_RE.fullmatch(value or ""):
        msg = f"Unsafe MySQL identifier: {value!r}"
        raise ValueError(msg)
    return value


def column_exists(conn: Any, table_name: str, column_name: str) -> bool:
    return _schema_lifecycle.column_exists(conn, table_name, column_name)


def index_exists(conn: Any, table_name: str, index_name: str) -> bool:
    return _schema_lifecycle.index_exists(conn, table_name, index_name)


def repair_duplicate_active_rows(
    conn: Any,
    *,
    table_name: str,
    scope_column: str | None = None,
) -> int:
    return _schema_lifecycle.repair_duplicate_active_rows(
        conn,
        table_name=table_name,
        scope_column=scope_column,
    )


def ensure_generated_column(
    conn: Any,
    *,
    table_name: str,
    column_name: str,
    ddl: str,
) -> None:
    _schema_lifecycle.ensure_column(conn, table_name=table_name, column_name=column_name, ddl=ddl)


def ensure_index(
    conn: Any,
    *,
    table_name: str,
    index_name: str,
    ddl: str,
) -> None:
    _schema_lifecycle.ensure_index(conn, table_name=table_name, index_name=index_name, ddl=ddl)


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
