from __future__ import annotations

# ruff: noqa: S608
import logging
import os
from dataclasses import dataclass
from typing import Any, Protocol

from services.sql_identifiers import quote_mysql_identifier

logger = logging.getLogger(__name__)


class _ConnectionFactory(Protocol):
    def __call__(self) -> Any: ...


@dataclass(frozen=True)
class BoundedDeleteResult:
    table: str
    deleted_rows: int
    iterations: int
    truncated: bool


class BoundedDeleteIncompleteError(RuntimeError):
    """A bounded delete stopped after zero or more confirmed commits.

    ``deleted_rows`` counts only chunks whose connection context exited
    successfully. When ``outcome_uncertain`` is true, the next chunk reached
    COMMIT but the client did not observe a successful connection-context exit.
    """

    def __init__(
        self,
        *,
        table: str,
        deleted_rows: int,
        iterations: int,
        outcome_uncertain: bool,
        cause: BaseException,
    ) -> None:
        self.table = table
        self.deleted_rows = int(deleted_rows)
        self.iterations = int(iterations)
        self.outcome_uncertain = bool(outcome_uncertain)
        self.cause = cause
        super().__init__(str(cause) or cause.__class__.__name__)


def env_int(name: str, default: int, *, minimum: int, maximum: int) -> int:
    try:
        value = int((os.environ.get(name) or str(default)).strip() or str(default))
    except Exception:
        value = int(default)
    return max(int(minimum), min(int(maximum), value))


def default_chunk_size() -> int:
    return env_int(
        "MYSQL_HOUSEKEEPING_DELETE_CHUNK_SIZE",
        500,
        minimum=1,
        maximum=10_000,
    )


def default_max_rows() -> int:
    return env_int(
        "MYSQL_HOUSEKEEPING_DELETE_MAX_ROWS_PER_STEP",
        50_000,
        minimum=0,
        maximum=1_000_000,
    )


def delete_where_in_chunks(
    connect_factory: _ConnectionFactory,
    *,
    table: str,
    where_sql: str,
    params: tuple[Any, ...] = (),
    chunk_size: int | None = None,
    max_rows: int | None = None,
    log_key: str | None = None,
    log_label: str | None = None,
    order_by_columns: tuple[str, ...] = (),
) -> BoundedDeleteResult:
    """Delete matching rows using short transactions and no OFFSET pagination.

    MySQL's DELETE ... LIMIT repeatedly removes the next matching chunk from the
    indexed predicate. Each chunk is executed in its own connection context so
    callers using CompatConnection keep row locks/undo work bounded per commit.
    """
    safe_table = quote_mysql_identifier(table)
    predicate = (where_sql or "").strip()
    if not predicate:
        msg = "where_sql is required for bounded delete"
        raise ValueError(msg)
    per_chunk = int(chunk_size if chunk_size is not None else default_chunk_size())
    per_run = int(max_rows if max_rows is not None else default_max_rows())
    per_chunk = max(1, per_chunk)
    per_run = max(0, per_run)
    if per_run <= 0:
        return BoundedDeleteResult(
            table=table,
            deleted_rows=0,
            iterations=0,
            truncated=False,
        )
    order_sql = ""
    if order_by_columns:
        order_sql = " ORDER BY " + ", ".join(
            f"{quote_mysql_identifier(column)} ASC" for column in order_by_columns
        )

    total = 0
    iterations = 0
    remaining = None
    while total < per_run:
        limit = min(per_chunk, per_run - total)
        body_completed = False
        try:
            with connect_factory() as conn:
                result = conn.execute(
                    f"DELETE FROM {safe_table} WHERE {predicate}{order_sql} LIMIT %s",
                    (*tuple(params), int(limit)),
                )
                deleted = max(0, int(getattr(result, "rowcount", 0) or 0))
                # Probe after the cap-reaching delete in the same short transaction so
                # ``truncated`` means matching rows remain, not merely that the cap hit.
                if total + deleted >= per_run:
                    remaining = conn.execute(
                        f"SELECT 1 FROM {safe_table} WHERE {predicate} LIMIT 1",
                        tuple(params),
                    ).fetchone()
                body_completed = True
        except Exception as exc:
            # A completed body followed by __exit__ failure means COMMIT may have
            # succeeded even though its acknowledgement was lost. Earlier chunks
            # remain confirmed because each uses its own connection context.
            if total > 0 or body_completed:
                raise BoundedDeleteIncompleteError(
                    table=table,
                    deleted_rows=total,
                    iterations=iterations,
                    outcome_uncertain=body_completed,
                    cause=exc,
                ) from exc
            raise
        total += deleted
        iterations += 1
        if deleted < limit:
            break

    truncated = total >= per_run and remaining is not None
    if truncated and log_key:
        logger.warning(
            "%s reached max_rows=%s; remaining rows will be cleaned up later.",
            log_label or log_key,
            per_run,
        )
    return BoundedDeleteResult(
        table=table,
        deleted_rows=total,
        iterations=iterations,
        truncated=truncated,
    )


def delete_older_than_in_chunks(
    connect_factory: _ConnectionFactory,
    *,
    table: str,
    timestamp_column: str,
    cutoff_ts: int,
    chunk_size: int | None = None,
    max_rows: int | None = None,
    log_key: str | None = None,
    log_label: str | None = None,
    order_by_columns: tuple[str, ...] | None = None,
) -> BoundedDeleteResult:
    column = quote_mysql_identifier(timestamp_column)
    return delete_where_in_chunks(
        connect_factory,
        table=table,
        where_sql=f"{column} < %s",
        params=(int(cutoff_ts),),
        chunk_size=chunk_size,
        max_rows=max_rows,
        log_key=log_key,
        log_label=log_label,
        order_by_columns=order_by_columns or (timestamp_column,),
    )
