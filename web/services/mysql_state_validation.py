from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field
from typing import Any

from services.db import connect
from services.row_access import row_value as _row_value
from services.schema_lifecycle import (
    latest_schema_checksum,
    latest_schema_version,
    schema_history_error,
)

_REQUIRED_TABLES: tuple[str, ...] = (
    "schema_migrations",
    "schema_migration_events",
    "users",
    "proxy_instances",
    "proxy_lifecycle_tombstones",
    "proxy_id_aliases",
    "proxy_recovery_adoptions",
    "proxy_config_revisions",
    "proxy_config_applications",
    "certificate_bundle_revisions",
    "proxy_certificate_applications",
    "admin_ui_https_settings",
    "adblock_artifact_revisions",
    "proxy_adblock_artifact_applications",
    "proxy_operations",
    "audit_events",
    "adblock_lists",
    "adblock_meta",
    "adblock_cache_stats",
    "adblock_settings",
    "adblock_counts",
    "adblock_events",
    "adblock_proxy_meta",
    "webfilter_settings",
    "webfilter_meta",
    "webfilter_whitelist",
    "webfilter_blocked_log",
    "safe_browsing_hash_lists",
    "safe_browsing_hash_prefixes",
    "safe_browsing_full_hash_cache",
    "safe_browsing_negative_cache",
    "sslfilter_domains",
    "sslfilter_src_nets",
    "sslfilter_settings",
    "diagnostic_requests",
    "diagnostic_policy_tags",
    "diagnostic_icap_events",
    "ssl_errors",
    "live_stats_domains",
    "live_stats_clients",
    "live_stats_client_domains",
    "live_stats_client_domain_nocache",
    "live_stats_seed_state",
    "ts_1s",
    "ts_1m",
    "ts_1h",
    "ts_1d",
    "ts_1w",
    "ts_1mo",
    "ts_1y",
    "observability_settings",
    "observability_maintenance_runs",
    "observability_report_schedules",
    "directory_auth_profiles",
    "saml_auth_profiles",
    "policy_requests",
    "policy_exceptions",
    "pac_profiles",
    "pac_direct_domains",
    "pac_direct_dst_nets",
    "pac_backup_proxies",
    "pac_proxy_chain_settings",
)

_TIMESERIES_METRIC_COUNT_COLUMNS: tuple[tuple[str, str], ...] = tuple(
    (table, column)
    for table in ("ts_1s", "ts_1m", "ts_1h", "ts_1d", "ts_1w", "ts_1mo", "ts_1y")
    for column in (
        "cpu_count",
        "mem_count",
        "disk_used_count",
        "cache_dir_size_count",
        "hit_rate_count",
    )
)

_REQUIRED_COLUMNS: tuple[tuple[str, str], ...] = (
    ("proxy_config_revisions", "active_proxy_id"),
    ("proxy_config_applications", "config_sha256"),
    ("certificate_bundle_revisions", "active_global_slot"),
    ("proxy_certificate_applications", "bundle_sha256"),
    ("adblock_artifact_revisions", "active_global_slot"),
    ("proxy_adblock_artifact_applications", "artifact_sha256"),
    ("proxy_operations", "proxy_id"),
    ("proxy_operations", "status"),
    ("proxy_operations", "request_key"),
    ("proxy_operations", "claim_token"),
    ("proxy_operations", "stale_requeue_count"),
    ("webfilter_blocked_log", "proxy_id"),
    ("proxy_recovery_adoptions", "bundle_content_sha256"),
    ("proxy_recovery_adoptions", "status"),
    ("proxy_recovery_adoptions", "detail"),
    ("saml_auth_profiles", "public_base_url"),
    ("saml_auth_profiles", "username_attribute"),
    ("saml_auth_profiles", "groups_attribute"),
    ("saml_auth_profiles", "required_group"),
    *_TIMESERIES_METRIC_COUNT_COLUMNS,
)

_REQUIRED_INDEXES: tuple[tuple[str, str], ...] = (
    ("proxy_config_revisions", "uniq_proxy_config_revisions_active_proxy"),
    ("proxy_config_applications", "idx_proxy_config_applications_proxy_revision_ts"),
    ("certificate_bundle_revisions", "uniq_certificate_bundle_revisions_active"),
    (
        "proxy_certificate_applications",
        "idx_proxy_certificate_applications_proxy_revision_ts",
    ),
    ("adblock_artifact_revisions", "uniq_adblock_artifact_revisions_active"),
    (
        "proxy_adblock_artifact_applications",
        "idx_proxy_adblock_artifact_apply_proxy_revision_ts",
    ),
    ("proxy_operations", "idx_proxy_operations_proxy_status_created_id"),
    ("proxy_operations", "idx_proxy_operations_proxy_started_id"),
    ("proxy_operations", "idx_proxy_operations_proxy_updated_id"),
    ("proxy_operations", "uniq_proxy_operations_active_request"),
    ("webfilter_blocked_log", "idx_webfilter_blocked_log_ts_id"),
    ("webfilter_blocked_log", "idx_webfilter_blocked_log_proxy_ts"),
    ("proxy_recovery_adoptions", "idx_proxy_recovery_adoptions_source"),
    ("proxy_recovery_adoptions", "idx_proxy_recovery_adoptions_bundle"),
)


@dataclass
class MysqlStateValidationResult:
    ok: bool = True
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def error(self, message: str) -> None:
        self.ok = False
        self.errors.append(message)

    def warning(self, message: str) -> None:
        self.warnings.append(message)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "errors": self.errors,
            "warnings": self.warnings,
            "details": self.details,
        }


def _rows(conn: Any, sql: str, params: tuple[Any, ...] = ()) -> list[Any]:
    return list(conn.execute(sql, params).fetchall())


def _table_names(conn: Any) -> set[str]:
    return {
        str(
            _row_value(row, "table_name")
            or _row_value(row, "TABLE_NAME")
            or _row_value(row, "table_name", 0)
        )
        for row in _rows(
            conn,
            """
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = DATABASE()
            """,
        )
    }


def _column_names(conn: Any) -> set[tuple[str, str]]:
    return {
        (
            str(
                _row_value(row, "table_name")
                or _row_value(row, "TABLE_NAME")
                or _row_value(row, "table_name", 0)
            ),
            str(
                _row_value(row, "column_name")
                or _row_value(row, "COLUMN_NAME")
                or _row_value(row, "column_name", 1)
            ),
        )
        for row in _rows(
            conn,
            """
            SELECT table_name, column_name
            FROM information_schema.columns
            WHERE table_schema = DATABASE()
            """,
        )
    }


def _index_names(conn: Any) -> set[tuple[str, str]]:
    return {
        (
            str(
                _row_value(row, "table_name")
                or _row_value(row, "TABLE_NAME")
                or _row_value(row, "table_name", 0)
            ),
            str(
                _row_value(row, "index_name")
                or _row_value(row, "INDEX_NAME")
                or _row_value(row, "index_name", 1)
            ),
        )
        for row in _rows(
            conn,
            """
            SELECT table_name, index_name
            FROM information_schema.statistics
            WHERE table_schema = DATABASE()
            """,
        )
    }


class MysqlStateInvariantQueryError(RuntimeError):
    def __init__(self, context: str, reason: str) -> None:
        super().__init__(
            f"failed MySQL state validation invariant query ({context}): {reason}"
        )
        self.context = context
        self.reason = reason

    @classmethod
    def from_exception(
        cls, context: str, exc: Exception
    ) -> MysqlStateInvariantQueryError:
        return cls(context, f"{type(exc).__name__}: {exc}")


def _count_row(conn: Any, sql: str, *, context: str) -> int:
    try:
        row = conn.execute(sql).fetchone()
        value = _row_value(row, "n")
        if value is None:
            value = _row_value(row, "COUNT(*)")
        if value is None:
            value = _row_value(row, "n", 0)
        if value is None:
            reason = "COUNT query returned no count value"
            raise MysqlStateInvariantQueryError(context, reason)
        return int(value)
    except MysqlStateInvariantQueryError:
        raise
    except Exception as exc:
        raise MysqlStateInvariantQueryError.from_exception(context, exc) from exc


def validate_mysql_state(
    conn: Any | None = None, *, phase: str = "post-restore"
) -> MysqlStateValidationResult:
    """Validate backup/export preflight and restored MySQL state invariants.

    The check is read-only and intentionally conservative. It verifies that the
    schema lifecycle reached the current code version with a recorded checksum,
    persistent table families exist, generated active-slot columns/indexes
    survived dump/restore, and application invariants that protect lifecycle,
    ownership, and idempotency are still true.
    """
    result = MysqlStateValidationResult(details={"phase": phase})
    owns_connection = conn is None
    active_conn = connect() if owns_connection else conn
    try:
        tables = _table_names(active_conn)
        result.details["table_count"] = len(tables)
        missing_tables = [table for table in _REQUIRED_TABLES if table not in tables]
        if missing_tables:
            result.error("missing required MySQL tables: " + ", ".join(missing_tables))
            return result

        history_error = schema_history_error(active_conn)
        if history_error is not None:
            result.error(history_error)

        latest = latest_schema_version()
        row = active_conn.execute(
            """
            SELECT status, checksum, error
            FROM schema_migrations
            WHERE version=%s
            LIMIT 1
            """,
            (latest,),
        ).fetchone()
        status = str(_row_value(row, "status") or "")
        checksum = str(_row_value(row, "checksum", 1) or "")
        error = str(_row_value(row, "error", 2) or "")
        if status != "applied":
            result.error(
                f"schema migration version {latest} is not applied (status={status or 'missing'})"
            )
        expected_checksum = latest_schema_checksum()
        if not checksum or len(checksum) != 64:
            result.error(
                f"schema migration version {latest} has missing/invalid checksum"
            )
        elif checksum != expected_checksum:
            result.error(
                f"schema migration version {latest} checksum drift: database has {checksum}, code expects {expected_checksum}"
            )
        if status == "applied" and error:
            result.warning(
                f"schema migration version {latest} is applied but retains error text"
            )
        result.details["schema_version"] = latest
        result.details["schema_status"] = status
        result.details["schema_checksum"] = checksum
        result.details["expected_schema_checksum"] = expected_checksum

        columns = _column_names(active_conn)
        missing_columns = [
            f"{table}.{column}"
            for table, column in _REQUIRED_COLUMNS
            if (table, column) not in columns
        ]
        if missing_columns:
            result.error(
                "missing generated/idempotency columns: " + ", ".join(missing_columns)
            )
            return result

        indexes = _index_names(active_conn)
        missing_indexes = [
            f"{table}.{index}"
            for table, index in _REQUIRED_INDEXES
            if (table, index) not in indexes
        ]
        if missing_indexes:
            result.error(
                "missing generated/idempotency indexes: " + ", ".join(missing_indexes)
            )

        try:
            duplicate_active_config = _count_row(
                active_conn,
                """
                SELECT COUNT(*) AS n
                FROM (
                    SELECT proxy_id
                    FROM proxy_config_revisions
                    WHERE is_active=1
                    GROUP BY proxy_id
                    HAVING COUNT(*) > 1
                ) duplicates
                """,
                context="proxy_config_revisions duplicate active proxy scopes",
            )
            if duplicate_active_config:
                result.error(
                    f"proxy_config_revisions has {duplicate_active_config} proxy scopes with multiple active rows"
                )

            active_certificate = _count_row(
                active_conn,
                "SELECT COUNT(*) AS n FROM certificate_bundle_revisions WHERE is_active=1",
                context="certificate_bundle_revisions active rows",
            )
            if active_certificate > 1:
                result.error("certificate_bundle_revisions has multiple active rows")

            active_adblock = _count_row(
                active_conn,
                "SELECT COUNT(*) AS n FROM adblock_artifact_revisions WHERE is_active=1",
                context="adblock_artifact_revisions active rows",
            )
            if active_adblock > 1:
                result.error("adblock_artifact_revisions has multiple active rows")

            duplicate_active_ops = _count_row(
                active_conn,
                """
                SELECT COUNT(*) AS n
                FROM (
                    SELECT proxy_id, request_key
                    FROM proxy_operations
                    WHERE status IN ('pending','applying') AND request_key IS NOT NULL
                    GROUP BY proxy_id, request_key
                    HAVING COUNT(*) > 1
                ) duplicates
                """,
                context="proxy_operations duplicate active idempotency keys",
            )
            if duplicate_active_ops:
                result.error(
                    f"proxy_operations has {duplicate_active_ops} duplicate active idempotency keys"
                )

            orphan_aliases = _count_row(
                active_conn,
                """
                SELECT COUNT(*) AS n
                FROM proxy_id_aliases alias
                LEFT JOIN proxy_instances proxy ON proxy.proxy_id=alias.proxy_id
                WHERE proxy.proxy_id IS NULL
                """,
                context="proxy_id_aliases orphan targets",
            )
            if orphan_aliases:
                result.error(
                    f"proxy_id_aliases has {orphan_aliases} aliases targeting missing proxy_instances rows"
                )

            tombstone_conflicts = _count_row(
                active_conn,
                """
                SELECT COUNT(*) AS n
                FROM proxy_lifecycle_tombstones tombstone
                JOIN proxy_instances proxy ON proxy.proxy_id=tombstone.proxy_id
                WHERE tombstone.action IN ('removed','renamed')
                """,
                context="proxy_lifecycle_tombstones terminal live conflicts",
            )
            if tombstone_conflicts:
                result.error(
                    f"proxy_lifecycle_tombstones has {tombstone_conflicts} terminal tombstone(s) that still have live proxy_instances rows"
                )

            alias_tombstone_conflicts = _count_row(
                active_conn,
                """
                SELECT COUNT(*) AS n
                FROM proxy_id_aliases alias
                JOIN proxy_lifecycle_tombstones tombstone ON tombstone.proxy_id=alias.alias_proxy_id
                WHERE tombstone.action NOT IN ('renamed')
                """,
                context="proxy_id_aliases lifecycle tombstone consistency",
            )
            if alias_tombstone_conflicts:
                result.error(
                    f"proxy_id_aliases has {alias_tombstone_conflicts} aliases inconsistent with lifecycle tombstones"
                )

            invalid_recovery_adoptions = _count_row(
                active_conn,
                """
                SELECT COUNT(*) AS n
                FROM proxy_recovery_adoptions
                WHERE status <> 'adopted'
                   OR detail <> ''
                   OR bundle_content_sha256 NOT REGEXP '^[0-9a-f]{64}$'
                """,
                context="proxy_recovery_adoptions marker contract",
            )
            if invalid_recovery_adoptions:
                result.error(
                    f"proxy_recovery_adoptions has {invalid_recovery_adoptions} invalid marker contract row(s)"
                )

            blocked_recovery_adoptions = _count_row(
                active_conn,
                """
                SELECT COUNT(*) AS n
                FROM proxy_recovery_adoptions marker
                JOIN proxy_lifecycle_tombstones tombstone ON tombstone.proxy_id=marker.proxy_id
                WHERE tombstone.action IN ('renaming','renamed','removing','removed')
                """,
                context="proxy_recovery_adoptions lifecycle-blocked markers",
            )
            if blocked_recovery_adoptions:
                result.error(
                    f"proxy_recovery_adoptions has {blocked_recovery_adoptions} marker row(s) on lifecycle-blocked proxy ids"
                )

            orphan_config_revisions = _count_row(
                active_conn,
                """
                SELECT COUNT(*) AS n
                FROM proxy_config_revisions revision
                LEFT JOIN proxy_instances proxy ON proxy.proxy_id=revision.proxy_id
                LEFT JOIN proxy_lifecycle_tombstones tombstone ON tombstone.proxy_id=revision.proxy_id
                WHERE proxy.proxy_id IS NULL AND tombstone.proxy_id IS NULL
                """,
                context="proxy_config_revisions orphan ownership",
            )
            if orphan_config_revisions:
                result.error(
                    f"proxy_config_revisions has {orphan_config_revisions} row(s) owned by missing proxies without tombstones"
                )

            orphan_application_owners = _count_row(
                active_conn,
                """
                SELECT COUNT(*) AS n
                FROM (
                    SELECT app.proxy_id FROM proxy_config_applications app
                    LEFT JOIN proxy_instances proxy ON proxy.proxy_id=app.proxy_id
                    LEFT JOIN proxy_lifecycle_tombstones tombstone ON tombstone.proxy_id=app.proxy_id
                    WHERE proxy.proxy_id IS NULL AND tombstone.proxy_id IS NULL
                    UNION ALL
                    SELECT app.proxy_id FROM proxy_certificate_applications app
                    LEFT JOIN proxy_instances proxy ON proxy.proxy_id=app.proxy_id
                    LEFT JOIN proxy_lifecycle_tombstones tombstone ON tombstone.proxy_id=app.proxy_id
                    WHERE proxy.proxy_id IS NULL AND tombstone.proxy_id IS NULL
                    UNION ALL
                    SELECT app.proxy_id FROM proxy_adblock_artifact_applications app
                    LEFT JOIN proxy_instances proxy ON proxy.proxy_id=app.proxy_id
                    LEFT JOIN proxy_lifecycle_tombstones tombstone ON tombstone.proxy_id=app.proxy_id
                    WHERE proxy.proxy_id IS NULL AND tombstone.proxy_id IS NULL
                ) orphan_applications
                """,
                context="proxy application ledgers orphan ownership",
            )
            if orphan_application_owners:
                result.error(
                    f"proxy application ledgers have {orphan_application_owners} row(s) owned by missing proxies without tombstones"
                )

            invalid_config_applications = _count_row(
                active_conn,
                """
                SELECT COUNT(*) AS n
                FROM proxy_config_applications app
                LEFT JOIN proxy_config_revisions revision
                  ON revision.id=app.revision_id AND revision.proxy_id=app.proxy_id
                WHERE revision.id IS NULL
                   OR (app.config_sha256 <> '' AND app.config_sha256 NOT REGEXP '^[0-9a-f]{64}$')
                   OR (app.ok=1 AND app.config_sha256 <> '' AND revision.config_sha256 REGEXP '^[0-9a-f]{64}$' AND app.config_sha256 <> revision.config_sha256)
                """,
                context="proxy_config_applications revision/evidence integrity",
            )
            if invalid_config_applications:
                result.error(
                    f"proxy_config_applications has {invalid_config_applications} invalid revision/evidence row(s)"
                )

            invalid_certificate_applications = _count_row(
                active_conn,
                """
                SELECT COUNT(*) AS n
                FROM proxy_certificate_applications app
                LEFT JOIN certificate_bundle_revisions revision ON revision.id=app.revision_id
                WHERE revision.id IS NULL
                   OR (app.bundle_sha256 <> '' AND app.bundle_sha256 NOT REGEXP '^[0-9a-f]{64}$')
                   OR (app.ok=1 AND app.bundle_sha256 <> '' AND revision.bundle_sha256 REGEXP '^[0-9a-f]{64}$' AND app.bundle_sha256 <> revision.bundle_sha256)
                """,
                context="proxy_certificate_applications revision/evidence integrity",
            )
            if invalid_certificate_applications:
                result.error(
                    f"proxy_certificate_applications has {invalid_certificate_applications} invalid revision/evidence row(s)"
                )

            invalid_adblock_applications = _count_row(
                active_conn,
                """
                SELECT COUNT(*) AS n
                FROM proxy_adblock_artifact_applications app
                LEFT JOIN adblock_artifact_revisions revision ON revision.id=app.revision_id
                WHERE revision.id IS NULL
                   OR (app.artifact_sha256 <> '' AND app.artifact_sha256 NOT REGEXP '^[0-9a-f]{64}$')
                   OR (app.ok=1 AND app.artifact_sha256 <> '' AND revision.artifact_sha256 REGEXP '^[0-9a-f]{64}$' AND app.artifact_sha256 <> revision.artifact_sha256)
                """,
                context="proxy_adblock_artifact_applications revision/evidence integrity",
            )
            if invalid_adblock_applications:
                result.error(
                    f"proxy_adblock_artifact_applications has {invalid_adblock_applications} invalid revision/evidence row(s)"
                )

            orphan_operations = _count_row(
                active_conn,
                """
                SELECT COUNT(*) AS n
                FROM proxy_operations op
                LEFT JOIN proxy_instances proxy ON proxy.proxy_id=op.proxy_id
                LEFT JOIN proxy_lifecycle_tombstones tombstone ON tombstone.proxy_id=op.proxy_id
                WHERE proxy.proxy_id IS NULL AND tombstone.proxy_id IS NULL
                """,
                context="proxy_operations orphan ownership",
            )
            if orphan_operations:
                result.error(
                    f"proxy_operations has {orphan_operations} row(s) owned by missing proxies without tombstones"
                )

            orphan_pac_profiles = _count_row(
                active_conn,
                """
                SELECT COUNT(*) AS n
                FROM pac_profiles pac_profile
                LEFT JOIN proxy_instances proxy ON proxy.proxy_id=pac_profile.proxy_id
                LEFT JOIN proxy_lifecycle_tombstones tombstone ON tombstone.proxy_id=pac_profile.proxy_id
                WHERE proxy.proxy_id IS NULL AND tombstone.proxy_id IS NULL
                """,
                context="pac_profiles orphan ownership",
            )
            if orphan_pac_profiles:
                result.error(
                    f"pac_profiles has {orphan_pac_profiles} row(s) owned by missing proxies without tombstones"
                )

            orphan_pac_direct_domains = _count_row(
                active_conn,
                """
                SELECT COUNT(*) AS n
                FROM pac_direct_domains direct_domain
                LEFT JOIN pac_profiles pac_profile ON pac_profile.id=direct_domain.profile_id
                WHERE pac_profile.id IS NULL
                """,
                context="pac_direct_domains orphan profile ownership",
            )
            if orphan_pac_direct_domains:
                result.error(
                    f"pac_direct_domains has {orphan_pac_direct_domains} row(s) with missing pac_profiles parents"
                )

            orphan_pac_direct_dst_nets = _count_row(
                active_conn,
                """
                SELECT COUNT(*) AS n
                FROM pac_direct_dst_nets direct_net
                LEFT JOIN pac_profiles pac_profile ON pac_profile.id=direct_net.profile_id
                WHERE pac_profile.id IS NULL
                """,
                context="pac_direct_dst_nets orphan profile ownership",
            )
            if orphan_pac_direct_dst_nets:
                result.error(
                    f"pac_direct_dst_nets has {orphan_pac_direct_dst_nets} row(s) with missing pac_profiles parents"
                )

            orphan_pac_backup_proxies = _count_row(
                active_conn,
                """
                SELECT COUNT(*) AS n
                FROM pac_backup_proxies backup_proxy
                LEFT JOIN proxy_instances proxy ON proxy.proxy_id=backup_proxy.proxy_id
                LEFT JOIN proxy_lifecycle_tombstones tombstone ON tombstone.proxy_id=backup_proxy.proxy_id
                WHERE proxy.proxy_id IS NULL AND tombstone.proxy_id IS NULL
                """,
                context="pac_backup_proxies orphan ownership",
            )
            if orphan_pac_backup_proxies:
                result.error(
                    f"pac_backup_proxies has {orphan_pac_backup_proxies} row(s) owned by missing proxies without tombstones"
                )

            orphan_pac_chain_settings = _count_row(
                active_conn,
                """
                SELECT COUNT(*) AS n
                FROM pac_proxy_chain_settings chain_settings
                LEFT JOIN proxy_instances proxy ON proxy.proxy_id=chain_settings.proxy_id
                LEFT JOIN proxy_lifecycle_tombstones tombstone ON tombstone.proxy_id=chain_settings.proxy_id
                WHERE proxy.proxy_id IS NULL AND tombstone.proxy_id IS NULL
                """,
                context="pac_proxy_chain_settings orphan ownership",
            )
            if orphan_pac_chain_settings:
                result.error(
                    f"pac_proxy_chain_settings has {orphan_pac_chain_settings} row(s) owned by missing proxies without tombstones"
                )

            orphan_report_schedules = _count_row(
                active_conn,
                """
                SELECT COUNT(*) AS n
                FROM observability_report_schedules schedule
                LEFT JOIN proxy_instances proxy ON proxy.proxy_id=schedule.proxy_id
                LEFT JOIN proxy_lifecycle_tombstones tombstone ON tombstone.proxy_id=schedule.proxy_id
                WHERE proxy.proxy_id IS NULL AND tombstone.proxy_id IS NULL
                """,
                context="observability_report_schedules orphan ownership",
            )
            if orphan_report_schedules:
                result.error(
                    f"observability_report_schedules has {orphan_report_schedules} row(s) owned by missing proxies without tombstones"
                )

            invalid_report_schedule_cadence = _count_row(
                active_conn,
                """
                SELECT COUNT(*) AS n
                FROM observability_report_schedules
                WHERE cadence NOT IN ('manual') OR recipients <> '' OR next_run_ts <> 0
                   OR last_run_ts <> 0 OR last_status <> 'manual_export_only'
                """,
                context="observability_report_schedules cadence values",
            )
            if invalid_report_schedule_cadence:
                result.error(
                    f"observability_report_schedules has {invalid_report_schedule_cadence} row(s) violating manual-export preset semantics"
                )

            invalid_report_schedule_format = _count_row(
                active_conn,
                """
                SELECT COUNT(*) AS n
                FROM observability_report_schedules
                WHERE report_format NOT IN ('csv','json','jsonl')
                """,
                context="observability_report_schedules format values",
            )
            if invalid_report_schedule_format:
                result.error(
                    f"observability_report_schedules has {invalid_report_schedule_format} row(s) with invalid format values"
                )

            invalid_report_schedule_times = _count_row(
                active_conn,
                """
                SELECT COUNT(*) AS n
                FROM observability_report_schedules
                WHERE updated_ts < created_ts OR next_run_ts < 0 OR last_run_ts < 0
                """,
                context="observability_report_schedules timestamp values",
            )
            if invalid_report_schedule_times:
                result.error(
                    f"observability_report_schedules has {invalid_report_schedule_times} row(s) with invalid timestamp values"
                )

            invalid_operation_states = _count_row(
                active_conn,
                """
                SELECT COUNT(*) AS n
                FROM proxy_operations
                WHERE status NOT IN ('pending','applying','applied','superseded','failed')
                """,
                context="proxy_operations invalid status values",
            )
            if invalid_operation_states:
                result.error(
                    f"proxy_operations has {invalid_operation_states} row(s) with invalid status values"
                )

            stale_claim_tokens = _count_row(
                active_conn,
                """
                SELECT COUNT(*) AS n
                FROM proxy_operations
                WHERE status NOT IN ('pending','applying')
                  AND (request_key IS NOT NULL OR claim_token IS NOT NULL)
                """,
                context="proxy_operations terminal active request/claim state",
            )
            if stale_claim_tokens:
                result.error(
                    f"proxy_operations has {stale_claim_tokens} terminal row(s) retaining active request/claim state"
                )

            active_lifecycle = _count_row(
                active_conn,
                """
                SELECT COUNT(*) AS n
                FROM proxy_instances
                WHERE status IN ('renaming','rename_pending','removing','remove_pending')
                """,
                context="proxy_instances active lifecycle transitions",
            )
            if active_lifecycle:
                result.warning(
                    f"{active_lifecycle} proxy lifecycle transition(s) are in progress or paused"
                )
        except MysqlStateInvariantQueryError as exc:
            result.error(str(exc))
    finally:
        if owns_connection:
            active_conn.close()
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate Docker_Proxy MySQL backup/restore invariants."
    )
    parser.add_argument(
        "--phase",
        default="post-restore",
        choices=("pre-backup", "post-restore", "audit"),
    )
    args = parser.parse_args(argv)
    result = validate_mysql_state(phase=args.phase)
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))  # noqa: T201
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
