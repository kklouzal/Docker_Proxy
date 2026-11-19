from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, Any

from services.db import connect_unpooled, resolve_database_config
from services.runtime_helpers import env_int
from services.sql_identifiers import quote_mysql_identifier

# OPTIMIZE rebuilds the whole table; on multi-GB tables that takes far longer
# than the default 15 s client read timeout. A timed-out client does not stop
# the server-side rebuild, so the run was reported failed while the rebuild
# kept running and the next table's maintenance overlapped it.
DEFAULT_MAINTENANCE_READ_TIMEOUT_SECONDS = 4 * 60 * 60

if TYPE_CHECKING:
    from collections.abc import Callable


def looks_like_stale_connection(exc: BaseException) -> bool:
    name = exc.__class__.__name__.lower()
    text = str(exc).lower()
    return (
        "interfaceerror" in name
        or "server has gone away" in text
        or "lost connection" in text
        or "connection already closed" in text
        or "(0, '')" in text
        or "2006" in text
        or "2013" in text
    )


def maintenance_connect() -> Any:
    """Open an unpooled connection whose read timeout covers table rebuilds."""
    cfg = resolve_database_config()
    read_timeout = env_int(
        "MYSQL_MAINTENANCE_READ_TIMEOUT",
        DEFAULT_MAINTENANCE_READ_TIMEOUT_SECONDS,
        minimum=1,
        maximum=24 * 60 * 60,
    )
    return connect_unpooled(
        replace(cfg, read_timeout=max(int(cfg.read_timeout), read_timeout)),
    )


def connect_with_stale_retry(connect_factory: Callable[[], Any]) -> Any:
    """Retry only connection acquisition, before any statement can reach MySQL."""
    try:
        return connect_factory()
    except Exception as exc:
        if not looks_like_stale_connection(exc):
            raise
    return connect_factory()


def run_mysql_table_maintenance(
    connect_factory: Callable[[], Any],
    table: str,
    *,
    analyze: bool,
    optimize: bool,
) -> str:
    """Run requested implicit-commit maintenance without replaying a statement.

    A stale pooled connection may be replaced only while acquiring the connection.
    Once execution starts, replay is unsafe: ANALYZE and OPTIMIZE may have completed
    on the server even when the client did not receive the acknowledgement.
    """
    quoted = quote_mysql_identifier(table)
    actions: list[str] = []
    conn = connect_with_stale_retry(connect_factory)
    try:
        with conn:
            if analyze:
                conn.execute(f"ANALYZE TABLE {quoted}")
                actions.append("analyzed")
            if optimize:
                conn.execute(f"OPTIMIZE TABLE {quoted}")
                actions.append("optimized")
    except Exception:
        # A context-manager failure after acknowledged implicit-commit statements
        # cannot undo those statements. Report only acknowledgements actually seen.
        if actions and len(actions) == int(analyze) + int(optimize):
            return ",".join(actions)
        raise
    return ",".join(actions)
