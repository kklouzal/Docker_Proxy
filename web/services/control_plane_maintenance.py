from __future__ import annotations

# ruff: noqa: S608
import os
import time
from dataclasses import dataclass
from typing import Any

from services.db import DATABASE_ERRORS, connect, table_exists
from services.observability_maintenance import public_detail

DEFAULT_CONTROL_PLANE_RETENTION_DAYS = 90
MIN_CONTROL_PLANE_RETENTION_DAYS = 1
MAX_CONTROL_PLANE_RETENTION_DAYS = 3650

CONTROL_PLANE_MAINTENANCE_TABLES: tuple[str, ...] = (
    "proxy_config_revisions",
    "proxy_config_applications",
    "certificate_bundle_revisions",
    "proxy_certificate_applications",
    "adblock_artifact_revisions",
    "proxy_adblock_artifact_applications",
    "proxy_operations",
    "policy_requests",
    "policy_exceptions",
    "safe_browsing_full_hash_cache",
    "safe_browsing_negative_cache",
    "observability_maintenance_runs",
)


@dataclass(frozen=True)
class ControlPlaneMaintenanceResult:
    table: str
    status: str
    deleted_rows: int = 0
    updated_rows: int = 0
    maintenance: str = ""
    detail: str = ""


def _env_int(name: str, default: int, *, minimum: int, maximum: int) -> int:
    try:
        value = int((os.environ.get(name) or str(default)).strip() or str(default))
    except Exception:
        value = int(default)
    return max(int(minimum), min(int(maximum), value))


def normalize_control_plane_retention_days(value: object) -> int:
    try:
        days = int(
            value
            or os.environ.get("MYSQL_CONTROL_PLANE_RETENTION_DAYS")
            or DEFAULT_CONTROL_PLANE_RETENTION_DAYS
        )
    except Exception:
        days = DEFAULT_CONTROL_PLANE_RETENTION_DAYS
    return max(
        MIN_CONTROL_PLANE_RETENTION_DAYS,
        min(MAX_CONTROL_PLANE_RETENTION_DAYS, days),
    )


def _quote_identifier(identifier: str) -> str:
    value = (identifier or "").strip()
    if not value or not value.replace("_", "").isalnum():
        msg = f"Unsafe MySQL identifier: {identifier!r}"
        raise ValueError(msg)
    return f"`{value}`"


def _table_exists(table: str) -> bool:
    with connect() as conn:
        return table_exists(conn, table)


def _delete_ranked_rows(
    *,
    table: str,
    timestamp_column: str,
    cutoff_ts: int,
    keep_rows: int,
    partition_column: str | None = None,
    where_sql: str = "",
    where_params: tuple[object, ...] = (),
) -> int:
    quoted = _quote_identifier(table)
    ts_col = _quote_identifier(timestamp_column)
    partition = (
        f"PARTITION BY {_quote_identifier(partition_column)} "
        if partition_column
        else ""
    )
    sql = f"""
        DELETE FROM {quoted}
        WHERE id IN (
            SELECT id FROM (
                SELECT id, {ts_col} AS row_ts,
                       ROW_NUMBER() OVER ({partition}ORDER BY {ts_col} DESC, id DESC) AS rn
                FROM {quoted}
                WHERE {where_sql or "1=1"}
            ) AS ranked
            WHERE row_ts < %s AND rn > %s
        )
    """
    with connect() as conn:
        result = conn.execute(sql, (*where_params, int(cutoff_ts), int(keep_rows)))
        return max(0, int(getattr(result, "rowcount", 0) or 0))


def _delete_revision_rows(
    *,
    table: str,
    timestamp_column: str,
    active_column: str,
    cutoff_ts: int,
    keep_rows: int,
    partition_column: str | None = None,
) -> int:
    quoted = _quote_identifier(table)
    ts_col = _quote_identifier(timestamp_column)
    active_col = _quote_identifier(active_column)
    partition = (
        f"PARTITION BY {_quote_identifier(partition_column)} "
        if partition_column
        else ""
    )
    sql = f"""
        DELETE FROM {quoted}
        WHERE id IN (
            SELECT id FROM (
                SELECT id, {active_col} AS active_flag, {ts_col} AS row_ts,
                       ROW_NUMBER() OVER ({partition}ORDER BY {ts_col} DESC, id DESC) AS rn
                FROM {quoted}
            ) AS ranked
            WHERE active_flag = 0 AND row_ts < %s AND rn > %s
        )
    """
    with connect() as conn:
        result = conn.execute(sql, (int(cutoff_ts), int(keep_rows)))
        return max(0, int(getattr(result, "rowcount", 0) or 0))


def _delete_expired_cache(table: str, *, now_ts: int) -> int:
    quoted = _quote_identifier(table)
    with connect() as conn:
        result = conn.execute(
            f"DELETE FROM {quoted} WHERE expires_ts < %s",
            (int(now_ts),),
        )
        return max(0, int(getattr(result, "rowcount", 0) or 0))


def _expire_policy_exceptions(*, now_ts: int) -> int:
    with connect() as conn:
        result = conn.execute(
            """
            UPDATE policy_exceptions
            SET status='expired', updated_ts=%s
            WHERE status='active' AND expires_ts > 0 AND expires_ts <= %s
            """,
            (int(now_ts), int(now_ts)),
        )
        return max(0, int(getattr(result, "rowcount", 0) or 0))


def _run_one_prune(
    table: str,
    *,
    cutoff_ts: int,
    now_ts: int,
) -> ControlPlaneMaintenanceResult:
    if not _table_exists(table):
        return ControlPlaneMaintenanceResult(table=table, status="missing")

    keep_revisions = _env_int(
        "MYSQL_HOUSEKEEPING_KEEP_REVISIONS",
        25,
        minimum=1,
        maximum=1000,
    )
    keep_applications = _env_int(
        "MYSQL_HOUSEKEEPING_KEEP_APPLICATIONS",
        200,
        minimum=1,
        maximum=10000,
    )
    keep_operations = _env_int(
        "MYSQL_HOUSEKEEPING_KEEP_OPERATIONS",
        500,
        minimum=1,
        maximum=50000,
    )
    keep_policy_rows = _env_int(
        "MYSQL_HOUSEKEEPING_KEEP_POLICY_ROWS",
        1000,
        minimum=1,
        maximum=100000,
    )
    keep_maintenance_runs = _env_int(
        "MYSQL_HOUSEKEEPING_KEEP_MAINTENANCE_RUNS",
        20,
        minimum=1,
        maximum=1000,
    )

    if table == "proxy_config_revisions":
        deleted = _delete_revision_rows(
            table=table,
            timestamp_column="created_ts",
            active_column="is_active",
            cutoff_ts=cutoff_ts,
            keep_rows=keep_revisions,
            partition_column="proxy_id",
        )
        return ControlPlaneMaintenanceResult(
            table=table,
            status="pruned",
            deleted_rows=deleted,
        )
    if table in {"certificate_bundle_revisions", "adblock_artifact_revisions"}:
        deleted = _delete_revision_rows(
            table=table,
            timestamp_column="created_ts",
            active_column="is_active",
            cutoff_ts=cutoff_ts,
            keep_rows=keep_revisions,
        )
        return ControlPlaneMaintenanceResult(
            table=table,
            status="pruned",
            deleted_rows=deleted,
        )
    if table in {
        "proxy_config_applications",
        "proxy_certificate_applications",
        "proxy_adblock_artifact_applications",
    }:
        deleted = _delete_ranked_rows(
            table=table,
            timestamp_column="applied_ts",
            cutoff_ts=cutoff_ts,
            keep_rows=keep_applications,
            partition_column="proxy_id",
        )
        return ControlPlaneMaintenanceResult(
            table=table,
            status="pruned",
            deleted_rows=deleted,
        )
    if table == "proxy_operations":
        deleted = _delete_ranked_rows(
            table=table,
            timestamp_column="updated_ts",
            cutoff_ts=cutoff_ts,
            keep_rows=keep_operations,
            partition_column="proxy_id",
            where_sql="status IN ('applied','superseded','failed')",
        )
        return ControlPlaneMaintenanceResult(
            table=table,
            status="pruned",
            deleted_rows=deleted,
        )
    if table == "policy_requests":
        deleted = _delete_ranked_rows(
            table=table,
            timestamp_column="updated_ts",
            cutoff_ts=cutoff_ts,
            keep_rows=keep_policy_rows,
            partition_column="proxy_id",
            where_sql="status IN ('rejected','closed')",
        )
        return ControlPlaneMaintenanceResult(
            table=table,
            status="pruned",
            deleted_rows=deleted,
        )
    if table == "policy_exceptions":
        updated = _expire_policy_exceptions(now_ts=now_ts)
        deleted = _delete_ranked_rows(
            table=table,
            timestamp_column="updated_ts",
            cutoff_ts=cutoff_ts,
            keep_rows=keep_policy_rows,
            partition_column="proxy_id",
            where_sql="status IN ('revoked','expired')",
        )
        return ControlPlaneMaintenanceResult(
            table=table,
            status="pruned",
            deleted_rows=deleted,
            updated_rows=updated,
        )
    if table in {"safe_browsing_full_hash_cache", "safe_browsing_negative_cache"}:
        deleted = _delete_expired_cache(table, now_ts=now_ts)
        return ControlPlaneMaintenanceResult(
            table=table,
            status="pruned",
            deleted_rows=deleted,
        )
    if table == "observability_maintenance_runs":
        deleted = _delete_ranked_rows(
            table=table,
            timestamp_column="started_ts",
            cutoff_ts=cutoff_ts,
            keep_rows=keep_maintenance_runs,
        )
        return ControlPlaneMaintenanceResult(
            table=table,
            status="pruned",
            deleted_rows=deleted,
        )

    return ControlPlaneMaintenanceResult(table=table, status="skipped")


def prune_control_plane_tables(*, retention_days: object = None) -> dict[str, Any]:
    days = normalize_control_plane_retention_days(retention_days)
    now_ts = int(time.time())
    cutoff_ts = now_ts - (days * 24 * 60 * 60)
    table_results: list[ControlPlaneMaintenanceResult] = []
    failed: list[ControlPlaneMaintenanceResult] = []

    for table in CONTROL_PLANE_MAINTENANCE_TABLES:
        try:
            result = _run_one_prune(table, cutoff_ts=cutoff_ts, now_ts=now_ts)
        except DATABASE_ERRORS as exc:
            result = ControlPlaneMaintenanceResult(
                table=table,
                status="failed",
                maintenance="failed",
                detail=public_detail(exc),
            )
            failed.append(result)
        except Exception as exc:
            result = ControlPlaneMaintenanceResult(
                table=table,
                status="failed",
                maintenance="failed",
                detail=public_detail(exc),
            )
            failed.append(result)
        table_results.append(result)

    return {
        "ok": not failed,
        "retention_days": days,
        "pruned_tables": sum(1 for row in table_results if row.status == "pruned"),
        "deleted_rows": sum(row.deleted_rows for row in table_results),
        "updated_rows": sum(row.updated_rows for row in table_results),
        "tables": [row.__dict__.copy() for row in table_results],
    }


def _run_table_maintenance(table: str, *, analyze: bool, optimize: bool) -> str:
    quoted = _quote_identifier(table)
    actions: list[str] = []
    with connect() as conn:
        if analyze:
            conn.execute(f"ANALYZE TABLE {quoted}")
            actions.append("analyzed")
        if optimize:
            conn.execute(f"OPTIMIZE TABLE {quoted}")
            actions.append("optimized")
    return ",".join(actions)


def maintain_control_plane_tables(
    *,
    analyze: bool = True,
    optimize: bool = False,
) -> dict[str, Any]:
    table_results: list[ControlPlaneMaintenanceResult] = []
    failed: list[ControlPlaneMaintenanceResult] = []

    for table in CONTROL_PLANE_MAINTENANCE_TABLES:
        if not _table_exists(table):
            table_results.append(
                ControlPlaneMaintenanceResult(table=table, status="missing"),
            )
            continue
        try:
            maintenance = _run_table_maintenance(
                table,
                analyze=analyze,
                optimize=optimize,
            )
            table_results.append(
                ControlPlaneMaintenanceResult(
                    table=table,
                    status="maintained",
                    maintenance=maintenance,
                ),
            )
        except DATABASE_ERRORS as exc:
            result = ControlPlaneMaintenanceResult(
                table=table,
                status="failed",
                maintenance="failed",
                detail=public_detail(exc),
            )
            table_results.append(result)
            failed.append(result)
        except Exception as exc:
            result = ControlPlaneMaintenanceResult(
                table=table,
                status="failed",
                maintenance="failed",
                detail=public_detail(exc),
            )
            table_results.append(result)
            failed.append(result)

    return {
        "ok": not failed,
        "maintained_tables": sum(
            1 for row in table_results if row.status == "maintained"
        ),
        "tables": [row.__dict__.copy() for row in table_results],
    }
