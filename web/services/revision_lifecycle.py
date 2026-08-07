from __future__ import annotations

import hashlib
import re
from contextlib import contextmanager, suppress
from typing import Any

from services import schema_lifecycle as _schema_lifecycle

_ADVISORY_LOCK_TIMEOUT_SECONDS = 10
_SCOPED_LOCK_PREFIX = "docker_proxy"
_SCOPED_LOCK_DIGEST_HEX_LENGTH = 24
_SCOPED_LOCK_MAX_BYTES = 64
_SCOPED_LOCK_MAX_READABLE_PREFIX = (
    _SCOPED_LOCK_MAX_BYTES
    - len(_SCOPED_LOCK_PREFIX.encode("ascii"))
    - 2  # separating colons
    - _SCOPED_LOCK_DIGEST_HEX_LENGTH
)
_LOCK_PREFIX_UNSAFE_RE = re.compile(r"[^A-Za-z0-9_.-]+")
_LOCK_PREFIX_SEPARATORS_RE = re.compile(r"_+")


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


def _lock_readable_prefix(namespace: str) -> str:
    normalized = _LOCK_PREFIX_UNSAFE_RE.sub("_", namespace)
    normalized = _LOCK_PREFIX_SEPARATORS_RE.sub("_", normalized).strip("_")
    if not normalized:
        normalized = "lock"
    return normalized[:_SCOPED_LOCK_MAX_READABLE_PREFIX]


def scoped_lock_name(namespace: str, scope: object | None = None) -> str:
    raw = f"{namespace}:{'' if scope is None else str(scope)}"
    digest = hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[
        :_SCOPED_LOCK_DIGEST_HEX_LENGTH
    ]
    prefix = _lock_readable_prefix(namespace)
    name = f"{_SCOPED_LOCK_PREFIX}:{prefix}:{digest}"
    if len(name.encode("ascii")) > _SCOPED_LOCK_MAX_BYTES:
        msg = f"MySQL lifecycle lock name exceeded {_SCOPED_LOCK_MAX_BYTES} bytes: {name!r}"
        raise AssertionError(msg)
    return name


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
        commit = getattr(conn, "commit", None)
        if callable(commit):
            try:
                commit()
            except Exception:
                with suppress(Exception):
                    conn.rollback()
                raise
    finally:
        try:
            conn.execute("DO RELEASE_LOCK(%s)", (name,))
        except Exception:
            # The connection wrapper will discard/rollback broken connections as needed.
            pass
