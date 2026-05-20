from __future__ import annotations

import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, TypeVar

from services.db import DATABASE_ERRORS, connect, table_exists

if TYPE_CHECKING:
    from collections.abc import Callable

DEFAULT_OBSERVABILITY_RETENTION_DAYS = 30
MIN_OBSERVABILITY_RETENTION_DAYS = 1
MAX_OBSERVABILITY_RETENTION_DAYS = 3650

OBSERVABILITY_LOG_TABLES: tuple[str, ...] = (
    "diagnostic_requests",
    "diagnostic_icap_events",
    "ssl_errors",
    "adblock_events",
    "adblock_counts",
    "adblock_cache_stats",
    "webfilter_blocked_log",
    "ts_1s",
    "ts_1m",
    "ts_1h",
    "ts_1d",
    "ts_1w",
    "ts_1mo",
    "ts_1y",
)


@dataclass(frozen=True)
class ObservabilityLogTableResult:
    table: str
    status: str
    deleted_rows: int = 0
    maintenance: str = ""
    detail: str = ""


def _quote_identifier(identifier: str) -> str:
    value = (identifier or "").strip()
    if not value or not value.replace("_", "").isalnum():
        msg = f"Unsafe MySQL identifier: {identifier!r}"
        raise ValueError(msg)
    return f"`{value}`"


def _looks_like_stale_connection(exc: BaseException) -> bool:
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


T = TypeVar("T")


def _retry_stale_connection[T](operation: Callable[[], T]) -> T:
    last_exc: BaseException | None = None
    for attempt in range(2):
        try:
            return operation()
        except Exception as exc:
            last_exc = exc
            if attempt == 0 and _looks_like_stale_connection(exc):
                continue
            raise
    assert last_exc is not None
    raise last_exc


def _table_exists(table: str) -> bool:
    def check() -> bool:
        with connect() as conn:
            return table_exists(conn, table)

    return _retry_stale_connection(check)


def _truncate_table(table: str) -> None:
    quoted = _quote_identifier(table)

    def truncate() -> None:
        with connect() as conn:
            # TRUNCATE is intentionally used instead of DELETE/OPTIMIZE here.
            # It is the closest match for an operator-facing "clear all stored
            # log history" action: fast, fleet-wide, and it resets auto-increment
            # counters without holding one long delete transaction open long
            # enough for PyMySQL read timeouts/stale pooled connections.
            conn.execute(f"TRUNCATE TABLE {quoted}")

    _retry_stale_connection(truncate)


def _delete_table(table: str) -> int:
    quoted = _quote_identifier(table)

    def delete() -> int:
        with connect() as conn:
            result = conn.execute(f"DELETE FROM {quoted}")
            return max(0, int(getattr(result, "rowcount", 0) or 0))

    return _retry_stale_connection(delete)


def _run_table_maintenance(table: str, *, analyze: bool, optimize: bool) -> str:
    quoted = _quote_identifier(table)
    actions: list[str] = []

    def run() -> None:
        with connect() as conn:
            if analyze:
                conn.execute(f"ANALYZE TABLE {quoted}")
                actions.append("analyzed")
            if optimize:
                conn.execute(f"OPTIMIZE TABLE {quoted}")
                actions.append("optimized")

    _retry_stale_connection(run)
    return ",".join(actions)


def _best_effort_delete_fallback(table: str) -> tuple[str, int, str]:
    try:
        deleted = _delete_table(table)
        return "cleared", deleted, "delete_fallback"
    except DATABASE_ERRORS as exc:
        return "failed", 0, public_detail(exc)
    except Exception as exc:
        return "failed", 0, public_detail(exc)


def public_detail(exc: BaseException) -> str:
    text = str(exc).strip()
    return text[:300] if text else exc.__class__.__name__


def normalize_retention_days(value: object) -> int:
    try:
        days = int(value or DEFAULT_OBSERVABILITY_RETENTION_DAYS)
    except Exception:
        days = DEFAULT_OBSERVABILITY_RETENTION_DAYS
    return max(
        MIN_OBSERVABILITY_RETENTION_DAYS,
        min(MAX_OBSERVABILITY_RETENTION_DAYS, days),
    )


def _ensure_observability_settings_table() -> None:
    now = int(time.time())

    def ensure() -> None:
        with connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS observability_settings (
                    id TINYINT PRIMARY KEY,
                    retention_days INT NOT NULL DEFAULT 30,
                    updated_ts BIGINT NOT NULL
                )
                """,
            )
            conn.execute(
                """
                INSERT INTO observability_settings(id, retention_days, updated_ts)
                VALUES(1, %s, %s)
                ON DUPLICATE KEY UPDATE id = id
                """,
                (DEFAULT_OBSERVABILITY_RETENTION_DAYS, now),
            )

    _retry_stale_connection(ensure)


def get_observability_retention_settings() -> dict[str, int]:
    _ensure_observability_settings_table()

    def load() -> dict[str, int]:
        with connect() as conn:
            row = conn.execute(
                """
                SELECT retention_days, updated_ts
                FROM observability_settings
                WHERE id = 1
                """,
            ).fetchone()
        if not row:
            return {
                "retention_days": DEFAULT_OBSERVABILITY_RETENTION_DAYS,
                "updated_ts": 0,
            }
        return {
            "retention_days": normalize_retention_days(row[0]),
            "updated_ts": int(row[1] or 0),
        }

    return _retry_stale_connection(load)


def set_observability_retention_settings(*, retention_days: object) -> dict[str, int]:
    days = normalize_retention_days(retention_days)
    now = int(time.time())
    _ensure_observability_settings_table()

    def save() -> None:
        with connect() as conn:
            conn.execute(
                """
                INSERT INTO observability_settings(id, retention_days, updated_ts)
                VALUES(1, %s, %s)
                ON DUPLICATE KEY UPDATE
                    retention_days = VALUES(retention_days),
                    updated_ts = VALUES(updated_ts)
                """,
                (days, now),
            )

    _retry_stale_connection(save)
    return {"retention_days": days, "updated_ts": now}


def maintain_observability_tables(
    *,
    analyze: bool = True,
    optimize: bool = False,
) -> dict[str, Any]:
    """Run explicit MySQL table maintenance for stored observability data.

    ANALYZE is cheap enough for regular optimizer-stat refreshes. OPTIMIZE can
    rebuild InnoDB tables and is intentionally caller-controlled so scheduled
    policy can run it on a slower cadence than daily pruning.
    """
    table_results: list[ObservabilityLogTableResult] = []
    failed: list[ObservabilityLogTableResult] = []

    for table in OBSERVABILITY_LOG_TABLES:
        if not _table_exists(table):
            table_results.append(
                ObservabilityLogTableResult(table=table, status="missing"),
            )
            continue

        try:
            maintenance = _run_table_maintenance(
                table,
                analyze=analyze,
                optimize=optimize,
            )
            table_results.append(
                ObservabilityLogTableResult(
                    table=table,
                    status="maintained",
                    maintenance=maintenance,
                ),
            )
        except DATABASE_ERRORS as exc:
            row = ObservabilityLogTableResult(
                table=table,
                status="failed",
                maintenance="failed",
                detail=public_detail(exc),
            )
            table_results.append(row)
            failed.append(row)
        except Exception as exc:
            row = ObservabilityLogTableResult(
                table=table,
                status="failed",
                maintenance="failed",
                detail=public_detail(exc),
            )
            table_results.append(row)
            failed.append(row)

    return {
        "ok": not failed,
        "maintained_tables": sum(
            1 for row in table_results if row.status == "maintained"
        ),
        "tables": [r.__dict__.copy() for r in table_results],
    }


def clear_observability_logs(*, optimize: bool = False) -> dict[str, Any]:
    """Wipe stored MySQL observability/log history across the whole fleet.

    This intentionally does not take a proxy_id. The Observability overview
    action is fleet-wide by design: it clears historical request/security/
    performance records for every proxy while leaving proxy configuration,
    policy settings, credentials, audit history, and registry state intact.

    ``optimize`` is accepted for compatibility with earlier call sites/tests,
    but the live button path no longer runs OPTIMIZE TABLE. TRUNCATE already
    resets table storage/auto-increment and avoids the long transaction that
    made the first implementation fragile against MySQL read timeouts.
    """
    table_results: list[ObservabilityLogTableResult] = []
    failed: list[ObservabilityLogTableResult] = []
    total_deleted = 0

    for table in OBSERVABILITY_LOG_TABLES:
        if not _table_exists(table):
            table_results.append(
                ObservabilityLogTableResult(table=table, status="missing"),
            )
            continue

        try:
            _truncate_table(table)
            table_results.append(
                ObservabilityLogTableResult(
                    table=table,
                    status="cleared",
                    maintenance="truncated",
                ),
            )
        except DATABASE_ERRORS:
            status, deleted, detail = _best_effort_delete_fallback(table)
            total_deleted += deleted
            row = ObservabilityLogTableResult(
                table=table,
                status=status,
                deleted_rows=deleted,
                maintenance="delete_fallback" if status == "cleared" else "failed",
                detail=detail,
            )
            table_results.append(row)
            if status == "failed":
                failed.append(row)
        except Exception:
            status, deleted, detail = _best_effort_delete_fallback(table)
            total_deleted += deleted
            row = ObservabilityLogTableResult(
                table=table,
                status=status,
                deleted_rows=deleted,
                maintenance="delete_fallback" if status == "cleared" else "failed",
                detail=detail,
            )
            table_results.append(row)
            if status == "failed":
                failed.append(row)

    return {
        "ok": not failed,
        "cleared_tables": sum(1 for row in table_results if row.status == "cleared"),
        "deleted_rows": total_deleted,
        "tables": [r.__dict__.copy() for r in table_results],
    }
