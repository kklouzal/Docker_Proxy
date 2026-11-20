from __future__ import annotations

# ruff: file-ignore[hardcoded-sql-expression]
import logging
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
from services.db import DATABASE_ERRORS, connect, table_exists
from services.mysql_table_maintenance import (
    maintenance_connect,
    run_mysql_table_maintenance,
)
from services.observability_maintenance import public_detail
from services.row_access import row_value
from services.runtime_helpers import env_int as _env_int
from services.sql_identifiers import quote_mysql_identifier
from services.webcat_hygiene import cleanup_stale_webcat_build_tables

logger = logging.getLogger(__name__)

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
    "saml_assertion_replay",
    "observability_maintenance_runs",
)
_EXPIRY_CACHE_TABLES = frozenset(
    {
        "safe_browsing_full_hash_cache",
        "safe_browsing_negative_cache",
        # Replay-cache rows are dead once expires_ts passes; the expiry already
        # carries the cross-worker clock-drift margin (services.saml_auth).
        "saml_assertion_replay",
    }
)

WEBCAT_BUILD_TABLE_CLEANUP_TABLE = "webcat_build_tables"

_RETENTION_ID_COLUMN = "id"


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
    # True when bounded work stopped with eligible rows remaining, so the
    # housekeeping scheduler can run a catch-up pass before the next daily run.
    truncated: bool = False


@dataclass(frozen=True)
class PolicyExceptionExpiryResult(BoundedDeleteResult):
    queued_proxies: tuple[str, ...] = ()
    queue_attempts: int = 0
    queue_failures: int = 0
    queue_failure_detail: str = ""


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


def _bounded_retention_detail(result: BoundedDeleteResult) -> str:
    detail = f"iterations={result.iterations}"
    if result.truncated:
        detail += " truncated=true"
    return detail


def _retention_partitions(
    table: str,
    partition_column: str | None,
) -> list[object]:
    if not partition_column:
        return [None]
    safe_table = quote_mysql_identifier(table)
    partition_col = quote_mysql_identifier(partition_column)
    with connect() as conn:
        rows = conn.execute(
            f"SELECT DISTINCT {partition_col} AS partition_value FROM {safe_table}",
        ).fetchall()
    values = {row_value(row, "partition_value", 0, None) for row in rows}
    return sorted(value for value in values if value is not None)


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
    """Delete old rows beyond a keep-N floor using bounded index-ordered chunks.

    A row is a victim when it is older than ``cutoff_ts``, matches the candidate
    scope, and at least ``keep_rows`` rows of its partition matching the newer
    scope are strictly newer by ``(timestamp, id)``. That is equivalent to being
    strictly older than the partition's keep-th newest in-scope row, so each
    chunk reads that boundary row through the ``(partition, timestamp, id)``
    index (``OFFSET`` bounded by ``keep_rows``) and deletes the oldest victims
    below it. The boundary is re-read in every chunk transaction, so concurrent
    deletes of newer rows can never shrink the retained floor. Cost per chunk is
    O(keep_rows + chunk) index entries, unlike a correlated per-candidate
    ``COUNT(*)`` (quadratic in partition size). Every DELETE is capped by the
    chunk size and the whole step by max_rows.
    """
    safe_table = quote_mysql_identifier(table)
    id_col = quote_mysql_identifier(_RETENTION_ID_COLUMN)
    ts_col = quote_mysql_identifier(timestamp_column)
    per_chunk = default_chunk_size()
    per_run = default_max_rows()
    keep = max(1, int(keep_rows))
    if per_run <= 0:
        return BoundedDeleteResult(
            table=table,
            deleted_rows=0,
            iterations=0,
            truncated=False,
        )

    partition_col = quote_mysql_identifier(partition_column) if partition_column else ""
    boundary_predicates: list[str] = []
    if partition_col:
        boundary_predicates.append(f"newer.{partition_col} = %s")
    if newer_scope_sql.strip():
        boundary_predicates.append(f"({newer_scope_sql.strip()})")
    boundary_where = (
        " WHERE " + " AND ".join(boundary_predicates) if boundary_predicates else ""
    )
    boundary_sql = (
        f"SELECT newer.{ts_col} AS boundary_ts, newer.{id_col} AS boundary_id "
        f"FROM {safe_table} AS newer{boundary_where} "
        f"ORDER BY newer.{ts_col} DESC, newer.{id_col} DESC "
        "LIMIT 1 OFFSET %s"
    )

    victim_predicates = [f"candidate.{ts_col} < %s"]
    if partition_col:
        victim_predicates.insert(0, f"candidate.{partition_col} = %s")
    if candidate_scope_sql.strip():
        victim_predicates.append(f"({candidate_scope_sql.strip()})")
    if candidate_only_sql.strip():
        victim_predicates.append(f"({candidate_only_sql.strip()})")
    victim_predicates.append(
        f"(candidate.{ts_col} < %s "
        f"OR (candidate.{ts_col} = %s AND candidate.{id_col} < %s))",
    )
    victim_where = " AND ".join(victim_predicates)
    delete_sql = (
        f"DELETE FROM {safe_table} AS candidate WHERE {victim_where} "
        f"ORDER BY candidate.{ts_col} ASC, candidate.{id_col} ASC LIMIT %s"
    )
    probe_sql = f"SELECT 1 FROM {safe_table} AS candidate WHERE {victim_where} LIMIT 1"

    def partition_params(partition: object) -> tuple[object, ...]:
        return (partition,) if partition_col else ()

    def victim_params(
        partition: object,
        boundary_ts: int,
        boundary_id: int,
    ) -> tuple[object, ...]:
        return (
            *partition_params(partition),
            int(cutoff_ts),
            *tuple(scope_params if candidate_scope_sql.strip() else ()),
            *tuple(candidate_only_params),
            int(boundary_ts),
            int(boundary_ts),
            int(boundary_id),
        )

    def read_boundary(conn, partition: object) -> tuple[int, int] | None:
        row = conn.execute(
            boundary_sql,
            (
                *partition_params(partition),
                *tuple(scope_params if newer_scope_sql.strip() else ()),
                keep - 1,
            ),
        ).fetchone()
        if row is None:
            return None
        return (
            int(row_value(row, "boundary_ts", 0, 0) or 0),
            int(row_value(row, "boundary_id", 1, 0) or 0),
        )

    total = 0
    iterations = 0
    truncated = False
    partitions = _retention_partitions(table, partition_column)
    for index, partition in enumerate(partitions):
        if total >= per_run:
            truncated = True
            break
        while total < per_run:
            limit = min(per_chunk, per_run - total)
            remaining = None
            with connect() as conn:
                boundary = read_boundary(conn, partition)
                if boundary is None:
                    deleted = 0
                else:
                    result = conn.execute(
                        delete_sql,
                        (*victim_params(partition, *boundary), int(limit)),
                    )
                    deleted = max(0, int(getattr(result, "rowcount", 0) or 0))
                    # Probe after the cap-reaching delete in the same short
                    # transaction so ``truncated`` reports an eligible victim,
                    # not merely an exact cap hit.
                    if total + deleted >= per_run:
                        remaining = conn.execute(
                            probe_sql,
                            victim_params(partition, *boundary),
                        ).fetchone()
            total += deleted
            iterations += 1
            if remaining is not None or (
                total >= per_run and index < len(partitions) - 1
            ):
                truncated = True
            if deleted < limit:
                break

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
        newer_scope_sql=newer_scope_sql
        or candidate_scope_sql.replace("candidate.", "newer."),
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
    application_table: str = "",
    application_proxy_scoped: bool = False,
) -> BoundedDeleteResult:
    active_col = quote_mysql_identifier(active_column)
    candidate_only = [f"candidate.{active_col} = 0"]
    if application_table:
        app_table = quote_mysql_identifier(application_table)
        app_predicate = f"NOT EXISTS (SELECT 1 FROM {app_table} app WHERE app.revision_id = candidate.id"
        if application_proxy_scoped:
            app_predicate += " AND app.proxy_id = candidate.proxy_id"
        app_predicate += ")"
        candidate_only.append(app_predicate)
    return _delete_retained_rows_in_chunks(
        table=table,
        timestamp_column=timestamp_column,
        cutoff_ts=cutoff_ts,
        keep_rows=keep_rows,
        partition_column=partition_column,
        candidate_only_sql=" AND ".join(candidate_only),
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


def _queue_policy_exception_expiry_policy_sync(proxy_id: str) -> bool:
    from services.operation_ledger import normalize_operation_target_ref
    from services.policy_materializer import build_proxy_policy_state
    from services.proxy_sync import request_proxy_reconcile

    desired_policy_sha = ""
    detail = (
        "Policy exceptions expired; proxy should refresh materialized policy files."
    )
    try:
        desired_policy_sha = normalize_operation_target_ref(
            "policy_state",
            build_proxy_policy_state(proxy_id).policy_sha256,
        )
    except Exception as exc:
        detail = (
            "Policy exceptions expired; policy reconciliation was not queued because "
            f"desired policy SHA was unavailable or invalid. {public_detail(exc)}"
        )
        logger.warning(detail)
        return False

    summary = "Expired policy exceptions queued for reconciliation."
    if desired_policy_sha:
        summary = (
            f"Policy state {desired_policy_sha[:12]} queued after exception expiry."
        )
        detail = f"Desired policy SHA after exception expiry: {desired_policy_sha}"
    operation = request_proxy_reconcile(
        proxy_id,
        operation_type="policy_sync",
        subject="Policy reconciliation",
        summary=summary,
        target_kind="policy_state",
        target_ref=desired_policy_sha,
        detail=detail,
        created_by="control-plane-maintenance",
        force=True,
    )
    return bool(
        getattr(operation, "operation_id", 0)
        and str(getattr(operation, "status", "") or "") in {"pending", "applying"}
    )


def _expire_policy_exceptions(*, now_ts: int) -> PolicyExceptionExpiryResult:
    per_chunk = default_chunk_size()
    per_run = default_max_rows()
    if per_run <= 0:
        return PolicyExceptionExpiryResult(
            table="policy_exceptions",
            deleted_rows=0,
            iterations=0,
            truncated=False,
        )
    total = 0
    iterations = 0
    affected_proxy_ids: set[str] = set()
    while total < per_run:
        limit = min(per_chunk, per_run - total)
        with connect() as conn:
            rows = conn.execute(
                """
                SELECT id, proxy_id
                FROM policy_exceptions
                WHERE status='active' AND expires_ts > 0 AND expires_ts <= %s
                ORDER BY expires_ts ASC, id ASC
                LIMIT %s
                """,
                (int(now_ts), int(limit)),
            ).fetchall()
            ids_by_proxy: dict[str, list[int]] = {}
            for row in rows:
                row_id = int(row_value(row, "id", 0, 0) or 0)
                if row_id <= 0:
                    continue
                proxy_id = str(row_value(row, "proxy_id", 1, "") or "").strip().lower()
                ids_by_proxy.setdefault(proxy_id, []).append(row_id)

            updated = 0
            # The candidate read is non-locking, so recheck expiry in the write.
            # Per-proxy writes make each rowcount safe to use for reconciliation.
            for proxy_id, ids in ids_by_proxy.items():
                placeholders = ",".join(["%s"] * len(ids))
                result = conn.execute(
                    f"""
                    UPDATE policy_exceptions
                    SET status='expired', updated_ts=%s
                    WHERE status='active'
                      AND expires_ts > 0 AND expires_ts <= %s
                      AND id IN ({placeholders})
                    """,
                    (int(now_ts), int(now_ts), *ids),
                )
                proxy_updated = max(
                    0,
                    int(getattr(result, "rowcount", 0) or 0),
                )
                updated += proxy_updated
                if proxy_updated > 0 and proxy_id:
                    affected_proxy_ids.add(proxy_id)
        total += updated
        iterations += 1
        if updated < limit:
            break

    queued_proxies: list[str] = []
    queue_failures = 0
    queue_failure_detail = ""
    for proxy_id in sorted(affected_proxy_ids):
        try:
            queued = _queue_policy_exception_expiry_policy_sync(proxy_id)
        except Exception as exc:
            queued = False
            if not queue_failure_detail:
                queue_failure_detail = public_detail(exc)
        if queued:
            queued_proxies.append(proxy_id)
        else:
            queue_failures += 1

    return PolicyExceptionExpiryResult(
        table="policy_exceptions",
        deleted_rows=total,
        iterations=iterations,
        truncated=total >= per_run,
        queued_proxies=tuple(queued_proxies),
        queue_attempts=len(affected_proxy_ids),
        queue_failures=queue_failures,
        queue_failure_detail=queue_failure_detail,
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
        128,
        minimum=1,
        maximum=128,
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
            application_table="proxy_config_applications",
            application_proxy_scoped=True,
        )
        return ControlPlaneMaintenanceResult(
            table=table,
            status="pruned",
            deleted_rows=deleted.deleted_rows,
            maintenance="bounded_retention_delete",
            detail=_bounded_retention_detail(deleted),
            truncated=deleted.truncated,
        )
    if table == "certificate_bundle_revisions":
        deleted = _delete_revision_rows(
            table=table,
            timestamp_column="created_ts",
            active_column="is_active",
            cutoff_ts=cutoff_ts,
            keep_rows=keep_revisions,
            application_table="proxy_certificate_applications",
        )
        return ControlPlaneMaintenanceResult(
            table=table,
            status="pruned",
            deleted_rows=deleted.deleted_rows,
            maintenance="bounded_retention_delete",
            detail=_bounded_retention_detail(deleted),
            truncated=deleted.truncated,
        )
    if table == "adblock_artifact_revisions":
        from services.adblock_artifacts import AdblockArtifactStore

        pruned = AdblockArtifactStore().prune_revisions(
            max_batches=_env_int(
                "MYSQL_HOUSEKEEPING_ADBLOCK_ARTIFACT_PRUNE_MAX_BATCHES",
                10,
                minimum=1,
                maximum=1000,
            ),
        )
        detail = f"stripped_archives={pruned.stripped_archives}"
        if pruned.truncated:
            detail += " truncated=true"
        return ControlPlaneMaintenanceResult(
            table=table,
            status="pruned",
            deleted_rows=pruned.deleted_rows,
            updated_rows=pruned.stripped_archives,
            maintenance="bounded_retention_delete",
            detail=detail,
            truncated=pruned.truncated,
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
            truncated=deleted.truncated,
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
            truncated=deleted.truncated,
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
            truncated=deleted.truncated,
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
        if updated.queue_attempts:
            details.append(
                "expired_policy_sync="
                f"queued={len(updated.queued_proxies)}"
                f" attempted={updated.queue_attempts}"
                f" failed={updated.queue_failures}",
            )
            if updated.queue_failure_detail:
                details.append(f"queue_detail={updated.queue_failure_detail[:200]}")
        return ControlPlaneMaintenanceResult(
            table=table,
            status="failed" if updated.queue_failures else "pruned",
            deleted_rows=deleted.deleted_rows,
            updated_rows=updated.deleted_rows,
            maintenance="bounded_retention_delete",
            detail=" ".join(details),
            truncated=deleted.truncated or updated.truncated,
        )
    if table in _EXPIRY_CACHE_TABLES:
        deleted = _delete_expired_cache(table, now_ts=now_ts)
        detail = f"iterations={deleted.iterations}" + (
            " truncated=true" if deleted.truncated else ""
        )
        return ControlPlaneMaintenanceResult(
            table=table,
            status="pruned",
            deleted_rows=deleted.deleted_rows,
            maintenance="bounded_expiry_delete",
            detail=detail,
            truncated=deleted.truncated,
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
            truncated=deleted.truncated,
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
        except Exception as exc:
            result = ControlPlaneMaintenanceResult(
                table=table,
                status="failed",
                maintenance="failed",
                detail=public_detail(exc),
            )
        if result.status == "failed":
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
    return run_mysql_table_maintenance(
        maintenance_connect,
        table,
        analyze=analyze,
        optimize=optimize,
    )


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
