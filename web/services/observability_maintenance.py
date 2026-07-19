from __future__ import annotations

import contextlib
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, TypeVar

from services.bounded_delete import BoundedDeleteResult, delete_where_in_chunks, env_int
from services.db import DATABASE_ERRORS, connect, connect_unpooled, table_exists
from services.sql_identifiers import quote_mysql_identifier

if TYPE_CHECKING:
    from collections.abc import Callable

DEFAULT_OBSERVABILITY_RETENTION_DAYS = 30
MIN_OBSERVABILITY_RETENTION_DAYS = 1
MAX_OBSERVABILITY_RETENTION_DAYS = 3650

OBSERVABILITY_LOG_TABLES: tuple[str, ...] = (
    "diagnostic_requests",
    "diagnostic_icap_events",
    "diagnostic_policy_tags",
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

_OBSERVABILITY_MAINTENANCE_LOCK_NAME = "docker_proxy_observability_maintenance"
_MAINTENANCE_HISTORY_LIMIT = 5


def _clear_fallback_max_rows_per_table() -> int:
    return env_int(
        "MYSQL_OBSERVABILITY_CLEAR_MAX_ROWS_PER_TABLE",
        1_000_000,
        minimum=1,
        maximum=10_000_000,
    )


@dataclass(frozen=True)
class ObservabilityLogTableResult:
    table: str
    status: str
    deleted_rows: int = 0
    maintenance: str = ""
    detail: str = ""


class ObservabilityMaintenanceAlreadyRunningError(RuntimeError):
    """Raised when another scheduled or manual maintenance run is active."""


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
    quoted = quote_mysql_identifier(table)

    def truncate() -> None:
        with connect() as conn:
            # TRUNCATE is intentionally used instead of DELETE/OPTIMIZE here.
            # It is the closest match for an operator-facing "clear all stored
            # log history" action: fast, fleet-wide, and it resets auto-increment
            # counters without holding one long delete transaction open long
            # enough for PyMySQL read timeouts/stale pooled connections.
            conn.execute(f"TRUNCATE TABLE {quoted}")

    _retry_stale_connection(truncate)


def _delete_table_in_chunks(table: str) -> BoundedDeleteResult:
    def delete() -> BoundedDeleteResult:
        return delete_where_in_chunks(
            connect,
            table=table,
            where_sql="1 = 1",
            max_rows=_clear_fallback_max_rows_per_table(),
            log_key=f"observability.clear.{table}",
            log_label=f"Observability clear fallback for {table}",
        )

    return _retry_stale_connection(delete)


def _run_table_maintenance(table: str, *, analyze: bool, optimize: bool) -> str:
    quoted = quote_mysql_identifier(table)
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
        result = _delete_table_in_chunks(table)
        if result.truncated:
            return (
                "partial",
                result.deleted_rows,
                f"delete_fallback partial iterations={result.iterations}",
            )
        return (
            "cleared",
            result.deleted_rows,
            f"delete_fallback iterations={result.iterations}",
        )
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
                VALUES(1, %s, %s) AS incoming
                ON DUPLICATE KEY UPDATE id = observability_settings.id
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
                VALUES(1, %s, %s) AS incoming
                ON DUPLICATE KEY UPDATE
                    retention_days = incoming.retention_days,
                    updated_ts = incoming.updated_ts
                """,
                (days, now),
            )

    _retry_stale_connection(save)
    return {"retention_days": days, "updated_ts": now}


def _ensure_observability_maintenance_runs_table() -> None:
    def ensure() -> None:
        with connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS observability_maintenance_runs (
                    id BIGINT PRIMARY KEY AUTO_INCREMENT,
                    run_type VARCHAR(32) NOT NULL,
                    started_ts BIGINT NOT NULL,
                    finished_ts BIGINT NOT NULL,
                    duration_ms BIGINT NOT NULL DEFAULT 0,
                    status VARCHAR(16) NOT NULL,
                    retention_days INT NOT NULL,
                    analyze TINYINT NOT NULL DEFAULT 0,
                    optimize TINYINT NOT NULL DEFAULT 0,
                    pruned TINYINT NOT NULL DEFAULT 0,
                    maintained_tables INT NOT NULL DEFAULT 0,
                    detail VARCHAR(512) NOT NULL DEFAULT '',
                    KEY idx_observability_maintenance_runs_started (started_ts),
                    KEY idx_observability_maintenance_runs_status (status)
                )
                """,
            )

    _retry_stale_connection(ensure)


def _maintenance_row_to_dict(row: Any) -> dict[str, Any]:
    return {
        "id": int(row[0] or 0),
        "run_type": str(row[1] or ""),
        "started_ts": int(row[2] or 0),
        "finished_ts": int(row[3] or 0),
        "duration_ms": int(row[4] or 0),
        "status": str(row[5] or ""),
        "retention_days": normalize_retention_days(row[6]),
        "analyze": bool(row[7]),
        "optimize": bool(row[8]),
        "pruned": bool(row[9]),
        "maintained_tables": int(row[10] or 0),
        "detail": str(row[11] or ""),
    }


def get_observability_maintenance_status(*, limit: int = 5) -> dict[str, Any]:
    _ensure_observability_maintenance_runs_table()
    history_limit = max(1, min(_MAINTENANCE_HISTORY_LIMIT, int(limit or 5)))

    def load() -> dict[str, Any]:
        with connect() as conn:
            rows = conn.execute(
                """
                SELECT id, run_type, started_ts, finished_ts, duration_ms, status,
                       retention_days, analyze, optimize, pruned, maintained_tables, detail
                FROM observability_maintenance_runs
                ORDER BY id DESC
                LIMIT %s
                """,
                (history_limit,),
            ).fetchall()
        history = [_maintenance_row_to_dict(row) for row in rows]
        latest = next((row for row in history if row.get("status") != "skipped"), None)
        if latest is None and history:
            latest = history[0]
        return {"latest": latest or {}, "history": history}

    return _retry_stale_connection(load)


def _maintenance_detail_from_result(result: dict[str, Any]) -> str:
    detail = str(result.get("detail") or "").strip()
    if detail:
        return detail[:512]
    maintenance = result.get("maintenance") or {}
    for table in maintenance.get("tables") or []:
        if table.get("status") == "failed" and table.get("detail"):
            return str(table.get("detail"))[:512]
    return ""


def record_observability_maintenance_run(
    *,
    run_type: str,
    result: dict[str, Any],
    status: str | None = None,
) -> None:
    _ensure_observability_maintenance_runs_table()
    maintenance = result.get("maintenance") or {}
    started_ts = int(result.get("started_ts") or time.time())
    finished_ts = int(result.get("finished_ts") or started_ts)
    duration_ms = max(0, int(result.get("duration_ms") or 0))
    status_value = str(
        status
        or result.get("status")
        or ("ok" if result.get("ok", True) else "failed"),
    )[:16]

    def save() -> None:
        with connect() as conn:
            conn.execute(
                """
                INSERT INTO observability_maintenance_runs(
                    run_type, started_ts, finished_ts, duration_ms, status,
                    retention_days, analyze, optimize, pruned, maintained_tables, detail
                )
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """,
                (
                    str(run_type or "manual")[:32],
                    started_ts,
                    finished_ts,
                    duration_ms,
                    status_value,
                    normalize_retention_days(result.get("retention_days", 30)),
                    1 if result.get("analyze") else 0,
                    1 if result.get("optimize") else 0,
                    1 if result.get("pruned") else 0,
                    int(maintenance.get("maintained_tables") or 0),
                    _maintenance_detail_from_result(result),
                ),
            )

    _retry_stale_connection(save)


def acquire_observability_maintenance_lock():
    conn = connect_unpooled()
    try:
        row = conn.execute(
            "SELECT GET_LOCK(%s, 0)",
            (_OBSERVABILITY_MAINTENANCE_LOCK_NAME,),
        ).fetchone()
        if not row or int(row[0] or 0) != 1:
            conn.close()
            return None
        return conn
    except Exception:
        with contextlib.suppress(Exception):
            conn.close()
        raise


def release_observability_maintenance_lock(conn: Any) -> None:
    if conn is None:
        return
    try:
        conn.execute(
            "SELECT RELEASE_LOCK(%s)",
            (_OBSERVABILITY_MAINTENANCE_LOCK_NAME,),
        )
    finally:
        conn.close()


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
                maintenance=(
                    "delete_fallback" if status in {"cleared", "partial"} else "failed"
                ),
                detail=detail,
            )
            table_results.append(row)
            if status != "cleared":
                failed.append(row)
        except Exception:
            status, deleted, detail = _best_effort_delete_fallback(table)
            total_deleted += deleted
            row = ObservabilityLogTableResult(
                table=table,
                status=status,
                deleted_rows=deleted,
                maintenance=(
                    "delete_fallback" if status in {"cleared", "partial"} else "failed"
                ),
                detail=detail,
            )
            table_results.append(row)
            if status != "cleared":
                failed.append(row)

    return {
        "ok": not failed,
        "cleared_tables": sum(1 for row in table_results if row.status == "cleared"),
        "deleted_rows": total_deleted,
        "tables": [r.__dict__.copy() for r in table_results],
    }
