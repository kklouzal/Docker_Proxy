from __future__ import annotations

# ruff: noqa: S608
import os
import time
from dataclasses import dataclass
from typing import Any

from services.bounded_delete import (
    BoundedDeleteResult,
    default_chunk_size,
    default_max_rows,
    delete_where_in_chunks,
)
from services.db import DATABASE_ERRORS, connect, mysql_error_code, table_exists
from services.observability_maintenance import public_detail
from services.sql_identifiers import quote_mysql_identifier
from services.webcat_hygiene import cleanup_stale_webcat_build_tables

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

WEBCAT_BUILD_TABLE_CLEANUP_TABLE = "webcat_build_tables"

_RETENTION_ID_COLUMN = "id"


CONTROL_PLANE_RETENTION_INDEXES: dict[str, tuple[tuple[str, str], ...]] = {
    "proxy_config_revisions": (
        (
            "idx_proxy_config_revisions_proxy_created_id",
            "ALTER TABLE proxy_config_revisions ADD INDEX idx_proxy_config_revisions_proxy_created_id (proxy_id, created_ts, id)",
        ),
        (
            "idx_proxy_config_revisions_proxy_active_created_id",
            "ALTER TABLE proxy_config_revisions ADD INDEX idx_proxy_config_revisions_proxy_active_created_id (proxy_id, is_active, created_ts, id)",
        ),
    ),
    "certificate_bundle_revisions": (
        (
            "idx_certificate_bundle_revisions_created_id",
            "ALTER TABLE certificate_bundle_revisions ADD INDEX idx_certificate_bundle_revisions_created_id (created_ts, id)",
        ),
        (
            "idx_certificate_bundle_revisions_active_created_id",
            "ALTER TABLE certificate_bundle_revisions ADD INDEX idx_certificate_bundle_revisions_active_created_id (is_active, created_ts, id)",
        ),
    ),
    "proxy_config_applications": (
        (
            "idx_proxy_config_applications_proxy_applied_id",
            "ALTER TABLE proxy_config_applications ADD INDEX idx_proxy_config_applications_proxy_applied_id (proxy_id, applied_ts, id)",
        ),
    ),
    "proxy_certificate_applications": (
        (
            "idx_proxy_certificate_applications_proxy_applied_id",
            "ALTER TABLE proxy_certificate_applications ADD INDEX idx_proxy_certificate_applications_proxy_applied_id (proxy_id, applied_ts, id)",
        ),
    ),
    "proxy_adblock_artifact_applications": (
        (
            "idx_proxy_adblock_artifact_apply_proxy_applied_id",
            "ALTER TABLE proxy_adblock_artifact_applications ADD INDEX idx_proxy_adblock_artifact_apply_proxy_applied_id (proxy_id, applied_ts, id)",
        ),
    ),
    "proxy_operations": (
        (
            "idx_proxy_operations_proxy_updated_id",
            "ALTER TABLE proxy_operations ADD INDEX idx_proxy_operations_proxy_updated_id (proxy_id, updated_ts, id)",
        ),
    ),
    "policy_requests": (
        (
            "idx_policy_requests_proxy_updated_id",
            "ALTER TABLE policy_requests ADD INDEX idx_policy_requests_proxy_updated_id (proxy_id, updated_ts, id)",
        ),
    ),
    "policy_exceptions": (
        (
            "idx_policy_exceptions_status_expires",
            "ALTER TABLE policy_exceptions ADD INDEX idx_policy_exceptions_status_expires (status, expires_ts, id)",
        ),
        (
            "idx_policy_exceptions_proxy_updated_id",
            "ALTER TABLE policy_exceptions ADD INDEX idx_policy_exceptions_proxy_updated_id (proxy_id, updated_ts, id)",
        ),
    ),
    "observability_maintenance_runs": (
        (
            "idx_observability_maintenance_runs_started_id",
            "ALTER TABLE observability_maintenance_runs ADD INDEX idx_observability_maintenance_runs_started_id (started_ts, id)",
        ),
    ),
}


def _format_webcat_cleanup_detail(cleanup) -> str:
    if cleanup.detail:
        return cleanup.detail
    return (
        f"dropped={len(cleanup.dropped_tables)} discovered={cleanup.discovered_tables}"
    )


def _cleanup_stale_webcat_build_tables_result(
    *,
    now_ts: int,
) -> ControlPlaneMaintenanceResult:
    with connect() as conn:
        cleanup = cleanup_stale_webcat_build_tables(conn, now_ts=now_ts)
    return ControlPlaneMaintenanceResult(
        table=WEBCAT_BUILD_TABLE_CLEANUP_TABLE,
        status="pruned" if cleanup.dropped_tables else "noop",
        deleted_rows=len(cleanup.dropped_tables),
        maintenance="drop_stale",
        detail=_format_webcat_cleanup_detail(cleanup),
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


def _table_exists(table: str) -> bool:
    with connect() as conn:
        return table_exists(conn, table)


def _index_exists(conn, table_name: str, index_name: str) -> bool:
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


def _ensure_control_plane_retention_indexes(table: str) -> None:
    indexes = CONTROL_PLANE_RETENTION_INDEXES.get(table, ())
    if not indexes:
        return
    with connect() as conn:
        for index_name, ddl in indexes:
            if _index_exists(conn, table, index_name):
                continue
            try:
                conn.execute(ddl)
            except DATABASE_ERRORS as exc:
                if mysql_error_code(exc) != 1061:
                    raise


def _bounded_retention_detail(result: BoundedDeleteResult) -> str:
    detail = f"iterations={result.iterations}"
    if result.truncated:
        detail += " truncated=true"
    return detail


def _delete_retained_rows_in_chunks(
    *,
    table: str,
    timestamp_column: str,
    cutoff_ts: int,
    keep_rows: int,
    partition_column: str | None = None,
    candidate_scope_sql: str = "",
    newer_scope_sql: str = "",
    scope_params: tuple[object, ...] = (),
    candidate_only_sql: str = "",
    candidate_only_params: tuple[object, ...] = (),
) -> BoundedDeleteResult:
    """Delete old rows beyond a keep-N floor using bounded candidate batches.

    The candidate subquery walks the oldest indexed rows and proves each victim has
    at least ``keep_rows`` newer peers in the same retention scope. It does not use
    full-table ROW_NUMBER/rank windows or OFFSET pagination; every DELETE is capped
    by chunk size and the whole housekeeping step is capped by max_rows.
    """
    safe_table = quote_mysql_identifier(table)
    id_col = quote_mysql_identifier(_RETENTION_ID_COLUMN)
    ts_col = quote_mysql_identifier(timestamp_column)
    per_chunk = default_chunk_size()
    per_run = default_max_rows()
    if per_run <= 0:
        return BoundedDeleteResult(
            table=table,
            deleted_rows=0,
            iterations=0,
            truncated=False,
        )

    candidate_predicates = [f"candidate.{ts_col} < %s"]
    params_prefix: list[object] = [int(cutoff_ts)]
    if candidate_scope_sql.strip():
        candidate_predicates.append(f"({candidate_scope_sql.strip()})")
        params_prefix.extend(scope_params)
    if candidate_only_sql.strip():
        candidate_predicates.append(f"({candidate_only_sql.strip()})")
        params_prefix.extend(candidate_only_params)

    newer_predicates = []
    newer_params: list[object] = []
    if partition_column:
        partition_col = quote_mysql_identifier(partition_column)
        newer_predicates.append(f"newer.{partition_col} = candidate.{partition_col}")
    if newer_scope_sql.strip():
        newer_predicates.append(f"({newer_scope_sql.strip()})")
        newer_params.extend(scope_params)
    newer_predicates.append(
        f"(newer.{ts_col} > candidate.{ts_col} "
        f"OR (newer.{ts_col} = candidate.{ts_col} AND newer.{id_col} > candidate.{id_col}))",
    )
    newer_where = " AND ".join(newer_predicates)
    candidate_where = " AND ".join(candidate_predicates)

    total = 0
    iterations = 0
    while total < per_run:
        limit = min(per_chunk, per_run - total)
        sql = f"""
            DELETE target FROM {safe_table} AS target
            JOIN (
                SELECT victim_id FROM (
                    SELECT candidate.{id_col} AS victim_id
                    FROM {safe_table} AS candidate
                    WHERE {candidate_where}
                      AND (
                          SELECT COUNT(*)
                          FROM {safe_table} AS newer
                          WHERE {newer_where}
                      ) >= %s
                    ORDER BY candidate.{ts_col} ASC, candidate.{id_col} ASC
                    LIMIT %s
                ) AS limited_victims
            ) AS victims ON victims.victim_id = target.{id_col}
        """
        params = (
            *tuple(params_prefix),
            *tuple(newer_params),
            int(keep_rows),
            int(limit),
        )
        with connect() as conn:
            result = conn.execute(sql, params)
            deleted = max(0, int(getattr(result, "rowcount", 0) or 0))
        total += deleted
        iterations += 1
        if deleted < limit:
            break

    truncated = total >= per_run
    return BoundedDeleteResult(
        table=table,
        deleted_rows=total,
        iterations=iterations,
        truncated=truncated,
    )


def _delete_ranked_rows(
    *,
    table: str,
    timestamp_column: str,
    cutoff_ts: int,
    keep_rows: int,
    partition_column: str | None = None,
    candidate_scope_sql: str = "",
    newer_scope_sql: str = "",
    scope_params: tuple[object, ...] = (),
) -> BoundedDeleteResult:
    if candidate_scope_sql and not candidate_scope_sql.strip().startswith("candidate."):
        candidate_scope_sql = candidate_scope_sql.replace("status", "candidate.status")
    if newer_scope_sql and not newer_scope_sql.strip().startswith("newer."):
        newer_scope_sql = newer_scope_sql.replace("status", "newer.status")
    return _delete_retained_rows_in_chunks(
        table=table,
        timestamp_column=timestamp_column,
        cutoff_ts=cutoff_ts,
        keep_rows=keep_rows,
        partition_column=partition_column,
        candidate_scope_sql=candidate_scope_sql,
        newer_scope_sql=newer_scope_sql or candidate_scope_sql,
        scope_params=scope_params,
    )


def _delete_revision_rows(
    *,
    table: str,
    timestamp_column: str,
    active_column: str,
    cutoff_ts: int,
    keep_rows: int,
    partition_column: str | None = None,
) -> BoundedDeleteResult:
    active_col = quote_mysql_identifier(active_column)
    return _delete_retained_rows_in_chunks(
        table=table,
        timestamp_column=timestamp_column,
        cutoff_ts=cutoff_ts,
        keep_rows=keep_rows,
        partition_column=partition_column,
        candidate_only_sql=f"candidate.{active_col} = 0",
    )


def _delete_expired_cache(table: str, *, now_ts: int) -> BoundedDeleteResult:
    return delete_where_in_chunks(
        connect,
        table=table,
        where_sql="expires_ts < %s",
        params=(int(now_ts),),
        order_by_columns=("expires_ts",),
        log_key=f"control_plane.prune.{table}",
        log_label=f"Control-plane expired cache prune for {table}",
    )


def _expire_policy_exceptions(*, now_ts: int) -> BoundedDeleteResult:
    per_chunk = default_chunk_size()
    per_run = default_max_rows()
    if per_run <= 0:
        return BoundedDeleteResult(
            table="policy_exceptions",
            deleted_rows=0,
            iterations=0,
            truncated=False,
        )
    total = 0
    iterations = 0
    while total < per_run:
        limit = min(per_chunk, per_run - total)
        with connect() as conn:
            result = conn.execute(
                """
                UPDATE policy_exceptions
                SET status='expired', updated_ts=%s
                WHERE status='active' AND expires_ts > 0 AND expires_ts <= %s
                ORDER BY expires_ts ASC, id ASC
                LIMIT %s
                """,
                (int(now_ts), int(now_ts), int(limit)),
            )
            updated = max(0, int(getattr(result, "rowcount", 0) or 0))
        total += updated
        iterations += 1
        if updated < limit:
            break
    return BoundedDeleteResult(
        table="policy_exceptions",
        deleted_rows=total,
        iterations=iterations,
        truncated=total >= per_run,
    )


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

    _ensure_control_plane_retention_indexes(table)

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
            deleted_rows=deleted.deleted_rows,
            maintenance="bounded_retention_delete",
            detail=_bounded_retention_detail(deleted),
        )
    if table == "certificate_bundle_revisions":
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
            deleted_rows=deleted.deleted_rows,
            maintenance="bounded_retention_delete",
            detail=_bounded_retention_detail(deleted),
        )
    if table == "adblock_artifact_revisions":
        from services.adblock_artifacts import AdblockArtifactStore

        deleted = AdblockArtifactStore().prune_revisions(
            max_batches=_env_int(
                "MYSQL_HOUSEKEEPING_ADBLOCK_ARTIFACT_PRUNE_MAX_BATCHES",
                10,
                minimum=1,
                maximum=1000,
            ),
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
            deleted_rows=deleted.deleted_rows,
            maintenance="bounded_retention_delete",
            detail=_bounded_retention_detail(deleted),
        )
    if table == "proxy_operations":
        deleted = _delete_ranked_rows(
            table=table,
            timestamp_column="updated_ts",
            cutoff_ts=cutoff_ts,
            keep_rows=keep_operations,
            partition_column="proxy_id",
            candidate_scope_sql="candidate.status IN ('applied','superseded','failed')",
            newer_scope_sql="newer.status IN ('applied','superseded','failed')",
        )
        return ControlPlaneMaintenanceResult(
            table=table,
            status="pruned",
            deleted_rows=deleted.deleted_rows,
            maintenance="bounded_retention_delete",
            detail=_bounded_retention_detail(deleted),
        )
    if table == "policy_requests":
        deleted = _delete_ranked_rows(
            table=table,
            timestamp_column="updated_ts",
            cutoff_ts=cutoff_ts,
            keep_rows=keep_policy_rows,
            partition_column="proxy_id",
            candidate_scope_sql="candidate.status IN ('rejected','closed')",
            newer_scope_sql="newer.status IN ('rejected','closed')",
        )
        return ControlPlaneMaintenanceResult(
            table=table,
            status="pruned",
            deleted_rows=deleted.deleted_rows,
            maintenance="bounded_retention_delete",
            detail=_bounded_retention_detail(deleted),
        )
    if table == "policy_exceptions":
        updated = _expire_policy_exceptions(now_ts=now_ts)
        deleted = _delete_ranked_rows(
            table=table,
            timestamp_column="updated_ts",
            cutoff_ts=cutoff_ts,
            keep_rows=keep_policy_rows,
            partition_column="proxy_id",
            candidate_scope_sql="candidate.status IN ('revoked','expired')",
            newer_scope_sql="newer.status IN ('revoked','expired')",
        )
        details = [_bounded_retention_detail(deleted)]
        if updated.iterations or updated.truncated:
            details.append("expired_" + _bounded_retention_detail(updated))
        return ControlPlaneMaintenanceResult(
            table=table,
            status="pruned",
            deleted_rows=deleted.deleted_rows,
            updated_rows=updated.deleted_rows,
            maintenance="bounded_retention_delete",
            detail=" ".join(details),
        )
    if table in {"safe_browsing_full_hash_cache", "safe_browsing_negative_cache"}:
        deleted = _delete_expired_cache(table, now_ts=now_ts)
        detail = (
            f"iterations={deleted.iterations}"
            + (" truncated=true" if deleted.truncated else "")
        )
        return ControlPlaneMaintenanceResult(
            table=table,
            status="pruned",
            deleted_rows=deleted.deleted_rows,
            maintenance="bounded_expiry_delete",
            detail=detail,
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
            deleted_rows=deleted.deleted_rows,
            maintenance="bounded_retention_delete",
            detail=_bounded_retention_detail(deleted),
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

    try:
        table_results.append(_cleanup_stale_webcat_build_tables_result(now_ts=now_ts))
    except DATABASE_ERRORS as exc:
        result = ControlPlaneMaintenanceResult(
            table=WEBCAT_BUILD_TABLE_CLEANUP_TABLE,
            status="failed",
            maintenance="failed",
            detail=public_detail(exc),
        )
        failed.append(result)
        table_results.append(result)
    except Exception as exc:
        result = ControlPlaneMaintenanceResult(
            table=WEBCAT_BUILD_TABLE_CLEANUP_TABLE,
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
    quoted = quote_mysql_identifier(table)
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
        try:
            exists = _table_exists(table)
        except DATABASE_ERRORS as exc:
            result = ControlPlaneMaintenanceResult(
                table=table,
                status="failed",
                maintenance="failed",
                detail=public_detail(exc),
            )
            table_results.append(result)
            failed.append(result)
            continue
        except Exception as exc:
            result = ControlPlaneMaintenanceResult(
                table=table,
                status="failed",
                maintenance="failed",
                detail=public_detail(exc),
            )
            table_results.append(result)
            failed.append(result)
            continue
        if not exists:
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
