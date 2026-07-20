from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field
from typing import Any

from services.db import connect
from services.schema_lifecycle import latest_schema_checksum, latest_schema_version

_REQUIRED_TABLES: tuple[str, ...] = (
    "schema_migrations",
    "schema_migration_events",
    "users",
    "proxy_instances",
    "proxy_lifecycle_tombstones",
    "proxy_id_aliases",
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
    "policy_requests",
    "policy_exceptions",
    "pac_profiles",
    "pac_direct_domains",
    "pac_direct_dst_nets",
    "pac_backup_proxies",
    "pac_proxy_chain_settings",
)

_REQUIRED_COLUMNS: tuple[tuple[str, str], ...] = (
    ("proxy_config_revisions", "active_proxy_id"),
    ("certificate_bundle_revisions", "active_global_slot"),
    ("adblock_artifact_revisions", "active_global_slot"),
    ("proxy_operations", "request_key"),
    ("proxy_operations", "claim_token"),
)

_REQUIRED_INDEXES: tuple[tuple[str, str], ...] = (
    ("proxy_config_revisions", "uniq_proxy_config_revisions_active_proxy"),
    ("certificate_bundle_revisions", "uniq_certificate_bundle_revisions_active"),
    ("adblock_artifact_revisions", "uniq_adblock_artifact_revisions_active"),
    ("proxy_operations", "uniq_proxy_operations_active_request"),
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


def _row_value(row: Any, key: str, index: int = 0) -> Any:
    if row is None:
        return None
    try:
        return row[key]
    except Exception:
        try:
            return row[index]
        except Exception:
            return None


def _table_names(conn: Any) -> set[str]:
    return {
        str(_row_value(row, "table_name") or _row_value(row, "TABLE_NAME") or _row_value(row, "table_name", 0))
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
            str(_row_value(row, "table_name") or _row_value(row, "TABLE_NAME") or _row_value(row, "table_name", 0)),
            str(_row_value(row, "column_name") or _row_value(row, "COLUMN_NAME") or _row_value(row, "column_name", 1)),
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
            str(_row_value(row, "table_name") or _row_value(row, "TABLE_NAME") or _row_value(row, "table_name", 0)),
            str(_row_value(row, "index_name") or _row_value(row, "INDEX_NAME") or _row_value(row, "index_name", 1)),
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


def _count_row(conn: Any, sql: str) -> int:
    row = conn.execute(sql).fetchone()
    try:
        return int(_row_value(row, "n") or _row_value(row, "COUNT(*)") or _row_value(row, "n", 0) or 0)
    except Exception:
        return 0


def validate_mysql_state(conn: Any | None = None, *, phase: str = "post-restore") -> MysqlStateValidationResult:
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
            result.error(f"schema migration version {latest} is not applied (status={status or 'missing'})")
        expected_checksum = latest_schema_checksum()
        if not checksum or len(checksum) != 64:
            result.error(f"schema migration version {latest} has missing/invalid checksum")
        elif checksum != expected_checksum:
            result.error(f"schema migration version {latest} checksum drift: database has {checksum}, code expects {expected_checksum}")
        if status == "applied" and error:
            result.warning(f"schema migration version {latest} is applied but retains error text")
        result.details["schema_version"] = latest
        result.details["schema_status"] = status
        result.details["schema_checksum"] = checksum
        result.details["expected_schema_checksum"] = expected_checksum

        columns = _column_names(active_conn)
        missing_columns = [f"{table}.{column}" for table, column in _REQUIRED_COLUMNS if (table, column) not in columns]
        if missing_columns:
            result.error("missing generated/idempotency columns: " + ", ".join(missing_columns))

        indexes = _index_names(active_conn)
        missing_indexes = [f"{table}.{index}" for table, index in _REQUIRED_INDEXES if (table, index) not in indexes]
        if missing_indexes:
            result.error("missing generated/idempotency indexes: " + ", ".join(missing_indexes))

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
        )
        if duplicate_active_config:
            result.error(f"proxy_config_revisions has {duplicate_active_config} proxy scopes with multiple active rows")

        active_certificate = _count_row(
            active_conn,
            "SELECT COUNT(*) AS n FROM certificate_bundle_revisions WHERE is_active=1",
        )
        if active_certificate > 1:
            result.error("certificate_bundle_revisions has multiple active rows")

        active_adblock = _count_row(
            active_conn,
            "SELECT COUNT(*) AS n FROM adblock_artifact_revisions WHERE is_active=1",
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
        )
        if duplicate_active_ops:
            result.error(f"proxy_operations has {duplicate_active_ops} duplicate active idempotency keys")

        orphan_aliases = _count_row(
            active_conn,
            """
            SELECT COUNT(*) AS n
            FROM proxy_id_aliases alias
            LEFT JOIN proxy_instances proxy ON proxy.proxy_id=alias.proxy_id
            WHERE proxy.proxy_id IS NULL
            """,
        )
        if orphan_aliases:
            result.error(f"proxy_id_aliases has {orphan_aliases} aliases targeting missing proxy_instances rows")

        tombstone_conflicts = _count_row(
            active_conn,
            """
            SELECT COUNT(*) AS n
            FROM proxy_lifecycle_tombstones tombstone
            JOIN proxy_instances proxy ON proxy.proxy_id=tombstone.proxy_id
            WHERE tombstone.action IN ('removed','renamed')
            """,
        )
        if tombstone_conflicts:
            result.error(f"proxy_lifecycle_tombstones has {tombstone_conflicts} terminal tombstone(s) that still have live proxy_instances rows")

        alias_tombstone_conflicts = _count_row(
            active_conn,
            """
            SELECT COUNT(*) AS n
            FROM proxy_id_aliases alias
            JOIN proxy_lifecycle_tombstones tombstone ON tombstone.proxy_id=alias.alias_proxy_id
            WHERE tombstone.action NOT IN ('renamed')
            """,
        )
        if alias_tombstone_conflicts:
            result.error(f"proxy_id_aliases has {alias_tombstone_conflicts} aliases inconsistent with lifecycle tombstones")

        orphan_config_revisions = _count_row(
            active_conn,
            """
            SELECT COUNT(*) AS n
            FROM proxy_config_revisions revision
            LEFT JOIN proxy_instances proxy ON proxy.proxy_id=revision.proxy_id
            LEFT JOIN proxy_lifecycle_tombstones tombstone ON tombstone.proxy_id=revision.proxy_id
            WHERE proxy.proxy_id IS NULL AND tombstone.proxy_id IS NULL
            """,
        )
        if orphan_config_revisions:
            result.error(f"proxy_config_revisions has {orphan_config_revisions} row(s) owned by missing proxies without tombstones")

        orphan_operations = _count_row(
            active_conn,
            """
            SELECT COUNT(*) AS n
            FROM proxy_operations op
            LEFT JOIN proxy_instances proxy ON proxy.proxy_id=op.proxy_id
            LEFT JOIN proxy_lifecycle_tombstones tombstone ON tombstone.proxy_id=op.proxy_id
            WHERE proxy.proxy_id IS NULL AND tombstone.proxy_id IS NULL
            """,
        )
        if orphan_operations:
            result.error(f"proxy_operations has {orphan_operations} row(s) owned by missing proxies without tombstones")

        invalid_operation_states = _count_row(
            active_conn,
            """
            SELECT COUNT(*) AS n
            FROM proxy_operations
            WHERE status NOT IN ('pending','applying','applied','superseded','failed')
            """,
        )
        if invalid_operation_states:
            result.error(f"proxy_operations has {invalid_operation_states} row(s) with invalid status values")

        stale_claim_tokens = _count_row(
            active_conn,
            """
            SELECT COUNT(*) AS n
            FROM proxy_operations
            WHERE status NOT IN ('pending','applying')
              AND (request_key IS NOT NULL OR claim_token IS NOT NULL)
            """,
        )
        if stale_claim_tokens:
            result.error(f"proxy_operations has {stale_claim_tokens} terminal row(s) retaining active request/claim state")

        active_lifecycle = _count_row(
            active_conn,
            """
            SELECT COUNT(*) AS n
            FROM proxy_instances
            WHERE status IN ('renaming','rename_pending','removing','remove_pending')
            """,
        )
        if active_lifecycle:
            result.warning(f"{active_lifecycle} proxy lifecycle transition(s) are in progress or paused")
    finally:
        if owns_connection:
            active_conn.close()
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate Docker_Proxy MySQL backup/restore invariants.")
    parser.add_argument("--phase", default="post-restore", choices=("pre-backup", "post-restore", "audit"))
    args = parser.parse_args(argv)
    result = validate_mysql_state(phase=args.phase)
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))  # noqa: T201
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
