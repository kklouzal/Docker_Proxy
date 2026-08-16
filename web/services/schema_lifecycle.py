from __future__ import annotations

import contextlib
import hashlib
import importlib
import json
import os
import re
import threading
import time
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

from services.db import (
    DATABASE_ERRORS,
    connect,
    mysql_advisory_lock,
    mysql_error_code,
    mysql_schema_lock_timeout_seconds,
    run_mysql_operation_with_retry,
)
from services.row_access import row_value as _row_value
from services.sql_identifiers import normalize_mysql_identifier

if False:  # pragma: no cover - type checkers only
    pass

_SCHEMA_VERSION = 30
_MIGRATOR_NAME = "docker_proxy_schema_lifecycle"
_MIGRATION_LOCK_NAME = "docker_proxy:schema_lifecycle:migrate"
_RUNTIME_LOCK_NAME = "docker_proxy:schema_lifecycle:runtime_ddl"
_CONTROL_PLANE_ID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
)
_HOT_PATH_ENSURE_LOCK = threading.Lock()
_HOT_PATH_ENSURED = False
_MIGRATION_CONTEXT = threading.local()


@dataclass(frozen=True)
class SchemaMigrationResult:
    version: int
    name: str
    status: str
    checksum: str
    started_ts: int
    finished_ts: int
    error: str = ""


@dataclass(frozen=True)
class SchemaObjectSpec:
    table: str
    create_sql: str


@dataclass(frozen=True)
class SchemaIndexSpec:
    table: str
    name: str
    ddl: str
    unique: bool = False


@dataclass(frozen=True)
class SchemaColumnSpec:
    table: str
    name: str
    ddl: str


@dataclass(frozen=True)
class SchemaDataStep:
    name: str
    apply: Callable[[Any], None]


@dataclass(frozen=True)
class SchemaMigrationSpec:
    version: int
    name: str
    tables: tuple[SchemaObjectSpec, ...] = ()
    columns: tuple[SchemaColumnSpec, ...] = ()
    indexes: tuple[SchemaIndexSpec, ...] = ()
    data_steps: tuple[SchemaDataStep, ...] = ()

    @property
    def checksum(self) -> str:
        payload = {
            "version": self.version,
            "name": self.name,
            "tables": [
                (item.table, _normalize_sql(item.create_sql)) for item in self.tables
            ],
            "columns": [
                (item.table, item.name, _normalize_sql(item.ddl))
                for item in self.columns
            ],
            "indexes": [
                (item.table, item.name, item.unique, _normalize_sql(item.ddl))
                for item in self.indexes
            ],
            "data_steps": [item.name for item in self.data_steps],
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()


def _normalize_sql(sql: str) -> str:
    return " ".join(str(sql or "").split())


def normalize_control_plane_identity(value: str) -> str:
    normalized = str(value or "").strip().lower()
    if not _CONTROL_PLANE_ID_RE.fullmatch(normalized):
        msg = "invalid control plane identity"
        raise ValueError(msg)
    return normalized


def _raise_privilege_error(exc: BaseException) -> None:
    code = mysql_error_code(exc)
    if code in {1044, 1045, 1142, 1227}:
        msg = (
            "MySQL schema migration requires CREATE, ALTER, INDEX, DROP, INSERT, "
            "UPDATE, and SELECT privileges at startup; run migrations with a privileged "
            "account before switching normal runtime to least-privilege DML."
        )
        raise PermissionError(msg) from exc
    raise exc


def _migration_assertion_error(
    table_name: str, object_name: str, object_type: str
) -> RuntimeError:
    return RuntimeError(
        f"MySQL schema migration is incomplete: missing {object_type} "
        f"{table_name}.{object_name}. Run startup schema migrations with a "
        "DDL-capable account before using DML-only runtime paths."
    )


def assert_table(conn: Any, table_name: str) -> None:
    if not table_exists(conn, table_name):
        raise _migration_assertion_error(table_name, table_name, "table")


def assert_column(conn: Any, table_name: str, column_name: str) -> None:
    if not column_exists(conn, table_name, column_name):
        raise _migration_assertion_error(table_name, column_name, "column")


def assert_index(conn: Any, table_name: str, index_name: str) -> None:
    if not index_exists(conn, table_name, index_name):
        raise _migration_assertion_error(table_name, index_name, "index")


def schema_migration_in_progress() -> bool:
    return bool(getattr(_MIGRATION_CONTEXT, "active", False))


def runtime_schema_current_applied(conn: Any) -> bool:
    row = _existing_migration(conn, _SCHEMA_VERSION)
    return row is not None and str(_row_value(row, "status", 3) or "") == "applied"


def runtime_schema_ready_for_lazy_store(conn: Any) -> bool:
    return (not schema_migration_in_progress()) and runtime_schema_current_applied(conn)


def table_exists(conn: Any, table_name: str) -> bool:
    row = conn.execute(
        """
        SELECT 1
        FROM information_schema.tables
        WHERE table_schema = DATABASE()
          AND table_name = %s
        LIMIT 1
        """,
        (table_name,),
    ).fetchone()
    return row is not None


def column_exists(conn: Any, table_name: str, column_name: str) -> bool:
    row = conn.execute(
        """
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = DATABASE()
          AND table_name = %s
          AND column_name = %s
        LIMIT 1
        """,
        (table_name, column_name),
    ).fetchone()
    return row is not None


def index_exists(conn: Any, table_name: str, index_name: str) -> bool:
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


def ensure_column(conn: Any, *, table_name: str, column_name: str, ddl: str) -> bool:
    if column_exists(conn, table_name, column_name):
        return False
    try:
        conn.execute(ddl)
        return True
    except DATABASE_ERRORS as exc:
        if mysql_error_code(exc) != 1060:
            raise
        return False


def ensure_index(conn: Any, *, table_name: str, index_name: str, ddl: str) -> bool:
    if index_exists(conn, table_name, index_name):
        return False
    try:
        conn.execute(ddl)
        return True
    except DATABASE_ERRORS as exc:
        if mysql_error_code(exc) != 1061:
            raise
        return False


def require_migration_privileges(conn: Any) -> None:
    probe = f"schema_privilege_probe_{int(time.time() * 1000)}"
    table = normalize_mysql_identifier(probe)
    try:
        conn.execute(f"CREATE TABLE {table} (id INT PRIMARY KEY)")
        conn.execute(f"ALTER TABLE {table} ADD COLUMN touched INT NOT NULL DEFAULT 0")
        conn.execute(f"ALTER TABLE {table} ADD INDEX idx_{table}_touched (touched)")
        conn.execute(f"DROP TABLE {table}")
    except DATABASE_ERRORS as exc:
        with contextlib.suppress(Exception):
            conn.execute(f"DROP TABLE IF EXISTS {table}")
        code = mysql_error_code(exc)
        if code in {1044, 1045, 1142, 1227}:
            msg = (
                "MySQL schema migration requires CREATE, ALTER, INDEX, and DROP privileges at startup; "
                "grant DDL privileges to the startup account, run migrations with a privileged account, "
                "then use a DML-only runtime account after migrations complete."
            )
            raise PermissionError(msg) from exc
        raise


def read_control_plane_identity(conn: Any) -> str | None:
    row = conn.execute(
        """
        SELECT control_plane_id
        FROM control_plane_identity
        WHERE id=1
        LIMIT 1
        """,
    ).fetchone()
    if row is None:
        return None
    return normalize_control_plane_identity(
        str(_row_value(row, "control_plane_id", 0) or "")
    )


def ensure_control_plane_identity(conn: Any) -> str:
    candidate = str(uuid.uuid4())
    conn.execute(
        """
        INSERT IGNORE INTO control_plane_identity(id, control_plane_id, created_ts)
        VALUES(1, %s, %s)
        """,
        (candidate, int(time.time())),
    )
    identity = read_control_plane_identity(conn)
    if identity is None:
        msg = "control plane identity was not created"
        raise RuntimeError(msg)
    return identity


def _init_control_plane_identity(conn: Any) -> None:
    ensure_control_plane_identity(conn)


def _ensure_migration_tables(conn: Any) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INT PRIMARY KEY,
            name VARCHAR(190) NOT NULL,
            checksum CHAR(64) NOT NULL,
            status VARCHAR(16) NOT NULL,
            started_ts BIGINT NOT NULL,
            finished_ts BIGINT NOT NULL DEFAULT 0,
            error TEXT,
            applied_by VARCHAR(128) NOT NULL DEFAULT 'app',
            KEY idx_schema_migrations_status_version (status, version),
            KEY idx_schema_migrations_finished (finished_ts)
        )
        """,
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migration_events (
            id BIGINT PRIMARY KEY AUTO_INCREMENT,
            version INT NOT NULL,
            name VARCHAR(190) NOT NULL,
            phase VARCHAR(32) NOT NULL,
            status VARCHAR(16) NOT NULL,
            detail TEXT,
            ts BIGINT NOT NULL,
            KEY idx_schema_migration_events_version_ts (version, ts),
            KEY idx_schema_migration_events_status_ts (status, ts)
        )
        """,
    )


def _record_event(
    conn: Any,
    *,
    version: int,
    name: str,
    phase: str,
    status: str,
    detail: str = "",
) -> None:
    conn.execute(
        """
        INSERT INTO schema_migration_events(version, name, phase, status, detail, ts)
        VALUES(%s,%s,%s,%s,%s,%s)
        """,
        (
            int(version),
            name[:190],
            phase[:32],
            status[:16],
            detail[:4000],
            int(time.time()),
        ),
    )


def _existing_migration(conn: Any, version: int) -> Any | None:
    return conn.execute(
        """
        SELECT version, name, checksum, status, error
        FROM schema_migrations
        WHERE version=%s
        LIMIT 1
        """,
        (int(version),),
    ).fetchone()


def _start_migration(conn: Any, spec: SchemaMigrationSpec) -> None:
    now = int(time.time())
    conn.execute(
        """
        INSERT INTO schema_migrations(version, name, checksum, status, started_ts, finished_ts, error, applied_by)
        VALUES(%s,%s,%s,'running',%s,0,'','app') AS incoming
        ON DUPLICATE KEY UPDATE
            name = incoming.name,
            status = 'running',
            started_ts = incoming.started_ts,
            finished_ts = 0,
            error = '',
            applied_by = incoming.applied_by
        """,
        (int(spec.version), spec.name[:190], spec.checksum, now),
    )
    _record_event(
        conn, version=spec.version, name=spec.name, phase="start", status="running"
    )


def _finish_migration(conn: Any, spec: SchemaMigrationSpec) -> SchemaMigrationResult:
    now = int(time.time())
    conn.execute(
        """
        UPDATE schema_migrations
        SET status='applied', finished_ts=%s, error=''
        WHERE version=%s
        """,
        (now, int(spec.version)),
    )
    _record_event(
        conn, version=spec.version, name=spec.name, phase="finish", status="applied"
    )
    row = _existing_migration(conn, spec.version)
    return SchemaMigrationResult(
        version=spec.version,
        name=spec.name,
        status="applied",
        checksum=spec.checksum,
        started_ts=int(_row_value(row, "started_ts", 4) or now),
        finished_ts=now,
    )


def _fail_migration(conn: Any, spec: SchemaMigrationSpec, exc: BaseException) -> None:
    detail = f"{exc.__class__.__name__}: {exc}"[:4000]
    now = int(time.time())
    conn.execute(
        """
        UPDATE schema_migrations
        SET status='failed', finished_ts=%s, error=%s
        WHERE version=%s
        """,
        (now, detail, int(spec.version)),
    )
    _record_event(
        conn,
        version=spec.version,
        name=spec.name,
        phase="error",
        status="failed",
        detail=detail,
    )


def repair_duplicate_active_rows(
    conn: Any,
    *,
    table_name: str,
    scope_column: str | None = None,
) -> int:
    safe_table = normalize_mysql_identifier(table_name)
    safe_scope = normalize_mysql_identifier(scope_column) if scope_column else ""
    partition = f"PARTITION BY {safe_scope}" if safe_scope else ""
    sql = f"""
        UPDATE {safe_table} target
        JOIN (
            SELECT id,
                   ROW_NUMBER() OVER ({partition} ORDER BY created_ts DESC, id DESC) AS active_rank
            FROM {safe_table}
            WHERE is_active=1
        ) ranked ON ranked.id=target.id
        SET target.is_active=0
        WHERE ranked.active_rank > 1
        """
    result = conn.execute(sql)
    return max(0, int(getattr(result, "rowcount", 0) or 0))


def _apply_spec(conn: Any, spec: SchemaMigrationSpec) -> None:
    for table in spec.tables:
        conn.execute(table.create_sql)
        _record_event(
            conn,
            version=spec.version,
            name=spec.name,
            phase=f"table:{table.table}",
            status="ok",
        )
    for step in spec.data_steps:
        step.apply(conn)
        _record_event(
            conn,
            version=spec.version,
            name=spec.name,
            phase=f"data:{step.name}",
            status="ok",
        )
    for column in spec.columns:
        changed = ensure_column(
            conn,
            table_name=column.table,
            column_name=column.name,
            ddl=column.ddl,
        )
        _record_event(
            conn,
            version=spec.version,
            name=spec.name,
            phase=f"column:{column.table}.{column.name}",
            status="applied" if changed else "noop",
        )
    for index in spec.indexes:
        changed = ensure_index(
            conn,
            table_name=index.table,
            index_name=index.name,
            ddl=index.ddl,
        )
        _record_event(
            conn,
            version=spec.version,
            name=spec.name,
            phase=f"index:{index.table}.{index.name}",
            status="applied" if changed else "noop",
        )


def _apply_embedded_schema(conn: Any, spec: SchemaMigrationSpec) -> None:
    for table in spec.tables:
        conn.execute(table.create_sql)
    for step in spec.data_steps:
        step.apply(conn)
    for column in spec.columns:
        ensure_column(
            conn, table_name=column.table, column_name=column.name, ddl=column.ddl
        )
    for index in spec.indexes:
        ensure_index(conn, table_name=index.table, index_name=index.name, ddl=index.ddl)


def _repair_revision_uniques(conn: Any) -> None:
    if table_exists(conn, "proxy_config_revisions"):
        repair_duplicate_active_rows(
            conn, table_name="proxy_config_revisions", scope_column="proxy_id"
        )
    if table_exists(conn, "certificate_bundle_revisions"):
        repair_duplicate_active_rows(conn, table_name="certificate_bundle_revisions")
    if table_exists(conn, "adblock_artifact_revisions"):
        repair_duplicate_active_rows(conn, table_name="adblock_artifact_revisions")


def _init_auth_schema(conn: Any) -> None:
    _apply_embedded_schema(
        conn,
        SchemaMigrationSpec(
            version=0,
            name="auth_store_tables",
            tables=(
                SchemaObjectSpec(
                    "users",
                    """
                    CREATE TABLE IF NOT EXISTS users (
                        username VARCHAR(64) PRIMARY KEY,
                        password_hash TEXT NOT NULL,
                        created_ts BIGINT NOT NULL,
                        updated_ts BIGINT NOT NULL
                    )
                    """,
                ),
            ),
        ),
    )


def _init_proxy_registry_schema(_conn: Any) -> None:
    importlib.import_module("services.proxy_registry").get_proxy_registry().init_db()


def _init_config_revision_schema(_conn: Any) -> None:
    importlib.import_module(
        "services.config_revisions"
    ).get_config_revisions().init_db()


def _init_certificate_bundle_schema(_conn: Any) -> None:
    importlib.import_module(
        "services.certificate_bundles"
    ).get_certificate_bundles().init_db()


def _init_adblock_artifact_schema(_conn: Any) -> None:
    importlib.import_module(
        "services.adblock_artifacts"
    ).get_adblock_artifacts().init_db()


def _init_operation_ledger_schema(_conn: Any) -> None:
    importlib.import_module(
        "services.operation_ledger"
    ).get_operation_ledger().init_db()


def _backfill_operation_ledger_active_request_keys(conn: Any) -> None:
    importlib.import_module(
        "services.operation_ledger"
    ).get_operation_ledger()._backfill_active_request_keys(conn)


def _prune_operation_ledger_history(conn: Any) -> None:
    importlib.import_module(
        "services.operation_ledger"
    ).get_operation_ledger()._prune_all_history(conn)


def _init_audit_schema(conn: Any) -> None:
    _apply_embedded_schema(
        conn,
        SchemaMigrationSpec(
            version=0,
            name="audit_store_tables",
            tables=(
                SchemaObjectSpec(
                    "audit_events",
                    """
                    CREATE TABLE IF NOT EXISTS audit_events (
                        id BIGINT PRIMARY KEY AUTO_INCREMENT,
                        proxy_id VARCHAR(64) NOT NULL DEFAULT 'default',
                        ts BIGINT NOT NULL,
                        kind VARCHAR(80) NOT NULL,
                        ok TINYINT(1) NOT NULL,
                        remote_addr VARCHAR(64),
                        user_agent VARCHAR(256),
                        detail TEXT,
                        config_sha256 CHAR(64),
                        config_text LONGTEXT,
                        KEY idx_audit_ts (ts),
                        KEY idx_audit_ts_id (ts, id),
                        KEY idx_audit_kind (kind),
                        KEY idx_audit_proxy_ts (proxy_id, ts)
                    )
                    """,
                ),
            ),
        ),
    )


def _init_adblock_runtime_schema(conn: Any) -> None:
    store_module = importlib.import_module("services.adblock_store")
    store_module.AdblockStore(
        lists_dir=os.environ.get("ADBLOCK_LISTS_DIR", ".")
    )._init_schema(conn)


def _seed_proxy_adblock_runtime_enabled(conn: Any) -> None:
    """Preserve legacy global enablement as each proxy's initial runtime state."""
    conn.execute(
        """
        INSERT IGNORE INTO adblock_proxy_meta(proxy_id, k, v)
        SELECT proxy.proxy_id, 'enabled',
               CASE WHEN setting.v='1' THEN '1' ELSE '0' END
        FROM proxy_instances proxy
        LEFT JOIN adblock_settings setting ON setting.k='enabled'
        """,
    )


def _init_webfilter_runtime_schema(conn: Any) -> None:
    _apply_embedded_schema(
        conn,
        SchemaMigrationSpec(
            version=0,
            name="webfilter_runtime_tables",
            tables=(
                SchemaObjectSpec(
                    "webfilter_settings",
                    """
                    CREATE TABLE IF NOT EXISTS webfilter_settings (
                        proxy_id VARCHAR(64) NOT NULL DEFAULT 'default',
                        k VARCHAR(64) NOT NULL,
                        v LONGTEXT NOT NULL,
                        PRIMARY KEY(proxy_id, k)
                    )
                    """,
                ),
                SchemaObjectSpec(
                    "webfilter_meta",
                    """
                    CREATE TABLE IF NOT EXISTS webfilter_meta (
                        k VARCHAR(64) PRIMARY KEY,
                        v LONGTEXT NOT NULL
                    )
                    """,
                ),
                SchemaObjectSpec(
                    "webfilter_whitelist",
                    """
                    CREATE TABLE IF NOT EXISTS webfilter_whitelist (
                        proxy_id VARCHAR(64) NOT NULL DEFAULT 'default',
                        pattern VARCHAR(255) NOT NULL,
                        added_ts BIGINT NOT NULL,
                        PRIMARY KEY(proxy_id, pattern),
                        KEY idx_webfilter_whitelist_proxy_ts (proxy_id, added_ts)
                    )
                    """,
                ),
                SchemaObjectSpec(
                    "webfilter_blocked_log",
                    """
                    CREATE TABLE IF NOT EXISTS webfilter_blocked_log (
                        id BIGINT PRIMARY KEY AUTO_INCREMENT,
                        proxy_id VARCHAR(64) NOT NULL DEFAULT 'default',
                        ts BIGINT NOT NULL,
                        src_ip VARCHAR(64) NOT NULL,
                        url TEXT NOT NULL,
                        category VARCHAR(128) NOT NULL,
                        KEY idx_webfilter_blocked_log_ts_id (ts, id),
                        KEY idx_webfilter_blocked_log_proxy_ts (proxy_id, ts, id)
                    )
                    """,
                ),
            ),
        ),
    )
    _seed_webfilter_defaults(conn)


def _init_sslfilter_schema(_conn: Any) -> None:
    importlib.import_module("services.sslfilter_store").get_sslfilter_store().init_db()


def _init_safe_browsing_schema(conn: Any) -> None:
    importlib.import_module("services.safe_browsing_v5").SafeBrowsingStore.init_schema(
        conn
    )


def _init_diagnostic_schema(_conn: Any) -> None:
    importlib.import_module(
        "services.diagnostic_store"
    ).get_diagnostic_store().init_db()


def _init_ssl_errors_schema(_conn: Any) -> None:
    importlib.import_module(
        "services.ssl_errors_store"
    ).get_ssl_errors_store().init_db()


def _init_live_stats_schema(_conn: Any) -> None:
    importlib.import_module("services.live_stats").get_store().init_db()


def _init_timeseries_schema(_conn: Any) -> None:
    importlib.import_module(
        "services.timeseries_store"
    ).get_timeseries_store().init_db()


def _init_timeseries_metric_count_schema(conn: Any) -> None:
    timeseries_store = importlib.import_module("services.timeseries_store")
    timeseries_store._ensure_metric_count_columns(conn)


def _init_observability_schema(conn: Any) -> None:
    _apply_embedded_schema(
        conn,
        SchemaMigrationSpec(
            version=0,
            name="observability_control_tables",
            tables=(
                SchemaObjectSpec(
                    "observability_settings",
                    """
                    CREATE TABLE IF NOT EXISTS observability_settings (
                        id TINYINT PRIMARY KEY,
                        retention_days INT NOT NULL DEFAULT 30,
                        updated_ts BIGINT NOT NULL
                    )
                    """,
                ),
                SchemaObjectSpec(
                    "observability_maintenance_runs",
                    """
                    CREATE TABLE IF NOT EXISTS observability_maintenance_runs (
                        id BIGINT PRIMARY KEY AUTO_INCREMENT,
                        run_type VARCHAR(32) NOT NULL,
                        started_ts BIGINT NOT NULL,
                        finished_ts BIGINT NOT NULL,
                        duration_ms BIGINT NOT NULL DEFAULT 0,
                        status VARCHAR(16) NOT NULL,
                        retention_days INT NOT NULL,
                        `analyze` TINYINT NOT NULL DEFAULT 0,
                        `optimize` TINYINT NOT NULL DEFAULT 0,
                        pruned TINYINT NOT NULL DEFAULT 0,
                        maintained_tables INT NOT NULL DEFAULT 0,
                        detail VARCHAR(512) NOT NULL DEFAULT '',
                        KEY idx_observability_maintenance_runs_started (started_ts),
                        KEY idx_observability_maintenance_runs_status (status)
                    )
                    """,
                ),
                SchemaObjectSpec(
                    "observability_report_schedules",
                    """
                    CREATE TABLE IF NOT EXISTS observability_report_schedules (
                        id BIGINT PRIMARY KEY AUTO_INCREMENT,
                        proxy_id VARCHAR(64) NOT NULL DEFAULT 'default',
                        enabled TINYINT(1) NOT NULL DEFAULT 1,
                        name VARCHAR(120) NOT NULL,
                        cadence VARCHAR(16) NOT NULL,
                        recipients VARCHAR(512) NOT NULL,
                        pane VARCHAR(32) NOT NULL,
                        report_format VARCHAR(16) NOT NULL,
                        privacy TINYINT(1) NOT NULL DEFAULT 1,
                        window_seconds INT NOT NULL,
                        created_ts BIGINT NOT NULL,
                        updated_ts BIGINT NOT NULL,
                        next_run_ts BIGINT NOT NULL DEFAULT 0,
                        last_run_ts BIGINT NOT NULL DEFAULT 0,
                        last_status VARCHAR(64) NOT NULL DEFAULT '',
                        KEY idx_obs_report_schedules_proxy_next (proxy_id, enabled, next_run_ts),
                        KEY idx_obs_report_schedules_proxy_updated (proxy_id, updated_ts)
                    )
                    """,
                ),
            ),
        ),
    )
    _seed_observability_settings(conn)


def _init_policy_schema(_conn: Any) -> None:
    importlib.import_module(
        "services.policy_requests"
    ).get_policy_request_store().init_db()


def _init_pac_schema(_conn: Any) -> None:
    importlib.import_module(
        "services.pac_profiles_store"
    ).get_pac_profiles_store().init_db()


def _init_directory_auth_schema(conn: Any) -> None:
    _apply_embedded_schema(
        conn,
        SchemaMigrationSpec(
            version=0,
            name="directory_auth_profile_tables",
            tables=(
                SchemaObjectSpec(
                    "directory_auth_profiles",
                    """
                    CREATE TABLE IF NOT EXISTS directory_auth_profiles (
                        provider VARCHAR(32) PRIMARY KEY,
                        enabled TINYINT(1) NOT NULL DEFAULT 0,
                        server_urls TEXT NOT NULL,
                        use_starttls TINYINT(1) NOT NULL DEFAULT 0,
                        verify_tls TINYINT(1) NOT NULL DEFAULT 1,
                        ca_bundle TEXT NOT NULL,
                        bind_dn TEXT NOT NULL,
                        bind_password TEXT NOT NULL,
                        base_dn TEXT NOT NULL,
                        user_search_base TEXT NOT NULL,
                        user_filter TEXT NOT NULL,
                        user_attribute VARCHAR(64) NOT NULL,
                        group_search_base TEXT NOT NULL,
                        group_filter TEXT NOT NULL,
                        required_admin_group TEXT NOT NULL,
                        timeout_seconds INT NOT NULL DEFAULT 5,
                        last_test_ok TINYINT(1) NOT NULL DEFAULT 0,
                        last_test_ts BIGINT NOT NULL DEFAULT 0,
                        last_test_detail TEXT NOT NULL,
                        updated_ts BIGINT NOT NULL
                    )
                    """,
                ),
            ),
        ),
    )
    _seed_directory_auth_profiles(conn)


def _init_saml_auth_schema(conn: Any) -> None:
    _apply_embedded_schema(
        conn,
        SchemaMigrationSpec(
            version=0,
            name="saml_auth_profile_tables",
            tables=(
                SchemaObjectSpec(
                    "saml_auth_profiles",
                    """
                    CREATE TABLE IF NOT EXISTS saml_auth_profiles (
                        provider VARCHAR(32) PRIMARY KEY,
                        enabled TINYINT(1) NOT NULL DEFAULT 0,
                        metadata_url TEXT NOT NULL,
                        require_https TINYINT(1) NOT NULL DEFAULT 1,
                        verify_tls TINYINT(1) NOT NULL DEFAULT 1,
                        ca_bundle TEXT NOT NULL,
                        timeout_seconds INT NOT NULL DEFAULT 10,
                        max_metadata_bytes INT NOT NULL DEFAULT 2097152,
                        raw_metadata_xml LONGTEXT NOT NULL,
                        parsed_metadata_json LONGTEXT NOT NULL,
                        entity_id TEXT NOT NULL,
                        fetched_ts BIGINT NOT NULL DEFAULT 0,
                        cache_expires_ts BIGINT NOT NULL DEFAULT 0,
                        valid_until_ts BIGINT NOT NULL DEFAULT 0,
                        last_refresh_ok TINYINT(1) NOT NULL DEFAULT 0,
                        last_refresh_ts BIGINT NOT NULL DEFAULT 0,
                        last_refresh_detail TEXT NOT NULL,
                        public_base_url TEXT NOT NULL,
                        username_attribute VARCHAR(255) NOT NULL DEFAULT 'NameID',
                        groups_attribute VARCHAR(255) NOT NULL DEFAULT 'groups',
                        required_group TEXT NOT NULL,
                        updated_ts BIGINT NOT NULL
                    )
                    """,
                ),
            ),
        ),
    )
    _seed_saml_auth_profile(conn)


def _init_proxy_lifecycle_schema(conn: Any) -> None:
    lifecycle = importlib.import_module("services.proxy_lifecycle")
    lifecycle.ensure_lifecycle_schema(conn)
    for table in lifecycle.PROXY_LIFECYCLE_TABLES:
        lifecycle.ensure_proxy_lifecycle_index(conn, table)


_CONTROL_PLANE_RETENTION_INDEXES: dict[str, tuple[tuple[str, str], ...]] = {
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
        (
            "idx_policy_requests_proxy_status_client_id",
            "ALTER TABLE policy_requests ADD INDEX idx_policy_requests_proxy_status_client_id (proxy_id, status, client_ip, id)",
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


def _init_control_plane_retention_indexes(conn: Any) -> None:
    for table, indexes in _CONTROL_PLANE_RETENTION_INDEXES.items():
        if table_exists(conn, table):
            for index_name, ddl in indexes:
                ensure_index(conn, table_name=table, index_name=index_name, ddl=ddl)


def _seed_webfilter_defaults(conn: Any) -> None:
    defaults = {
        "enabled": "0",
        "source_url": "https://dsi.ut-capitole.fr/blacklists/download/all.tar.gz",
        "source_provider": "auto",
        "blocked_categories": "",
        "last_success": "0",
        "last_attempt": "0",
        "last_error": "",
        "next_run_ts": "0",
        "safe_browsing_enabled": "0",
        "safe_browsing_api_key": "",
        "safe_browsing_lists": "se-4b,mw-4b,uws-4b",
        "safe_browsing_last_success": "0",
        "safe_browsing_last_attempt": "0",
        "safe_browsing_last_error": "",
        "safe_browsing_next_run_ts": "0",
    }
    global_keys = {
        "source_url",
        "source_provider",
        "last_success",
        "last_attempt",
        "last_error",
        "next_run_ts",
        "safe_browsing_enabled",
        "safe_browsing_api_key",
        "safe_browsing_lists",
        "safe_browsing_last_success",
        "safe_browsing_last_attempt",
        "safe_browsing_last_error",
        "safe_browsing_next_run_ts",
    }
    for key, value in defaults.items():
        scope = "__global__" if key in global_keys else "default"
        conn.execute(
            "INSERT IGNORE INTO webfilter_settings(proxy_id, k, v) VALUES(%s,%s,%s)",
            (scope, key, value),
        )


def _seed_observability_settings(conn: Any) -> None:
    conn.execute(
        """
        INSERT INTO observability_settings(id, retention_days, updated_ts)
        VALUES(1, %s, %s) AS incoming
        ON DUPLICATE KEY UPDATE id = observability_settings.id
        """,
        (30, int(time.time())),
    )


def _directory_auth_default_profiles(now: int) -> tuple[tuple[Any, ...], ...]:
    return (
        (
            "ldap",
            0,
            "ldaps://ldap.example.org:636",
            0,
            1,
            "",
            "cn=proxy-bind,ou=service,dc=example,dc=org",
            "",
            "dc=example,dc=org",
            "ou=people",
            "(uid={username})",
            "uid",
            "ou=groups",
            "(|(member={user_dn})(uniqueMember={user_dn})(memberUid={username}))",
            "cn=docker-proxy-admins,ou=groups,dc=example,dc=org",
            5,
            0,
            0,
            "",
            now,
        ),
        (
            "active_directory",
            0,
            "ldaps://dc.example.local:636",
            0,
            1,
            "",
            "svc-docker-proxy@example.local",
            "",
            "DC=example,DC=local",
            "",
            "(|(sAMAccountName={username})(userPrincipalName={username}))",
            "sAMAccountName",
            "",
            "(member:1.2.840.113556.1.4.1941:={user_dn})",
            "CN=Docker Proxy Admins,OU=Groups,DC=example,DC=local",
            5,
            0,
            0,
            "",
            now,
        ),
    )


def _seed_directory_auth_profiles(conn: Any) -> None:
    for row in _directory_auth_default_profiles(int(time.time())):
        conn.execute(
            """
            INSERT IGNORE INTO directory_auth_profiles(
                provider, enabled, server_urls, use_starttls, verify_tls,
                ca_bundle, bind_dn, bind_password, base_dn,
                user_search_base, user_filter, user_attribute,
                group_search_base, group_filter, required_admin_group,
                timeout_seconds, last_test_ok, last_test_ts,
                last_test_detail, updated_ts
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            row,
        )


def _seed_saml_auth_profile(conn: Any) -> None:
    conn.execute(
        """
        INSERT IGNORE INTO saml_auth_profiles(
            provider, enabled, metadata_url, require_https, verify_tls,
            ca_bundle, timeout_seconds, max_metadata_bytes,
            raw_metadata_xml, parsed_metadata_json, entity_id,
            fetched_ts, cache_expires_ts, valid_until_ts,
            last_refresh_ok, last_refresh_ts, last_refresh_detail,
            public_base_url, username_attribute, groups_attribute,
            required_group, updated_ts
        ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """,
        (
            "saml",
            0,
            "https://adfs.example.local/FederationMetadata/2007-06/FederationMetadata.xml",
            1,
            1,
            "",
            10,
            2 * 1024 * 1024,
            "",
            "",
            "",
            0,
            0,
            0,
            0,
            0,
            "",
            "",
            "NameID",
            "groups",
            "",
            int(time.time()),
        ),
    )


def _backfill_application_ledger_evidence(conn: Any) -> None:
    ensure_column(
        conn,
        table_name="proxy_config_applications",
        column_name="config_sha256",
        ddl="ALTER TABLE proxy_config_applications ADD COLUMN config_sha256 CHAR(64) NOT NULL DEFAULT '' AFTER applied_ts",
    )
    ensure_column(
        conn,
        table_name="proxy_certificate_applications",
        column_name="bundle_sha256",
        ddl="ALTER TABLE proxy_certificate_applications ADD COLUMN bundle_sha256 CHAR(64) NOT NULL DEFAULT '' AFTER applied_ts",
    )
    ensure_column(
        conn,
        table_name="proxy_adblock_artifact_applications",
        column_name="artifact_sha256",
        ddl="ALTER TABLE proxy_adblock_artifact_applications ADD COLUMN artifact_sha256 CHAR(64) NOT NULL DEFAULT '' AFTER applied_ts",
    )
    if column_exists(conn, "proxy_config_applications", "config_sha256"):
        conn.execute(
            """
            UPDATE proxy_config_applications app
            JOIN proxy_config_revisions revision
              ON revision.id=app.revision_id AND revision.proxy_id=app.proxy_id
            SET app.config_sha256=revision.config_sha256
            WHERE app.config_sha256=''
              AND revision.config_sha256 REGEXP '^[0-9a-f]{64}$'
            """,
        )
    if column_exists(conn, "proxy_certificate_applications", "bundle_sha256"):
        conn.execute(
            """
            UPDATE proxy_certificate_applications app
            JOIN certificate_bundle_revisions revision ON revision.id=app.revision_id
            SET app.bundle_sha256=revision.bundle_sha256
            WHERE app.bundle_sha256=''
              AND revision.bundle_sha256 REGEXP '^[0-9a-f]{64}$'
            """,
        )
    if column_exists(conn, "proxy_adblock_artifact_applications", "artifact_sha256"):
        conn.execute(
            """
            UPDATE proxy_adblock_artifact_applications app
            JOIN adblock_artifact_revisions revision ON revision.id=app.revision_id
            SET app.artifact_sha256=revision.artifact_sha256
            WHERE app.artifact_sha256=''
              AND revision.artifact_sha256 REGEXP '^[0-9a-f]{64}$'
            """,
        )


def _migration_specs() -> tuple[SchemaMigrationSpec, ...]:
    return (
        SchemaMigrationSpec(
            version=1,
            name="bootstrap_mysql_schema_lifecycle",
            data_steps=(
                SchemaDataStep("auth_users", _init_auth_schema),
                SchemaDataStep("proxy_registry", _init_proxy_registry_schema),
                SchemaDataStep("config_revisions", _init_config_revision_schema),
                SchemaDataStep("certificate_bundles", _init_certificate_bundle_schema),
                SchemaDataStep("adblock_artifacts", _init_adblock_artifact_schema),
                SchemaDataStep("operation_ledger", _init_operation_ledger_schema),
                SchemaDataStep("audit_store", _init_audit_schema),
            ),
        ),
        SchemaMigrationSpec(
            version=2,
            name="adblock_runtime_tables",
            data_steps=(SchemaDataStep("adblock_store", _init_adblock_runtime_schema),),
        ),
        SchemaMigrationSpec(
            version=3,
            name="webfilter_and_safe_browsing_tables",
            data_steps=(
                SchemaDataStep("safe_browsing_v5", _init_safe_browsing_schema),
                SchemaDataStep("webfilter_store", _init_webfilter_runtime_schema),
            ),
        ),
        SchemaMigrationSpec(
            version=4,
            name="sslfilter_policy_tables",
            data_steps=(SchemaDataStep("sslfilter_store", _init_sslfilter_schema),),
        ),
        SchemaMigrationSpec(
            version=5,
            name="diagnostic_request_and_icap_tables",
            data_steps=(SchemaDataStep("diagnostic_store", _init_diagnostic_schema),),
        ),
        SchemaMigrationSpec(
            version=6,
            name="ssl_error_aggregate_tables",
            data_steps=(SchemaDataStep("ssl_errors_store", _init_ssl_errors_schema),),
        ),
        SchemaMigrationSpec(
            version=7,
            name="live_stats_aggregate_tables",
            data_steps=(SchemaDataStep("live_stats", _init_live_stats_schema),),
        ),
        SchemaMigrationSpec(
            version=8,
            name="timeseries_resolution_tables",
            data_steps=(SchemaDataStep("timeseries_store", _init_timeseries_schema),),
        ),
        SchemaMigrationSpec(
            version=9,
            name="observability_control_tables",
            data_steps=(SchemaDataStep("observability", _init_observability_schema),),
        ),
        SchemaMigrationSpec(
            version=10,
            name="policy_request_tables",
            data_steps=(SchemaDataStep("policy_requests", _init_policy_schema),),
        ),
        SchemaMigrationSpec(
            version=11,
            name="pac_profile_tables",
            data_steps=(SchemaDataStep("pac_profiles", _init_pac_schema),),
        ),
        SchemaMigrationSpec(
            version=12,
            name="proxy_lifecycle_indexes",
            data_steps=(
                SchemaDataStep("proxy_lifecycle", _init_proxy_lifecycle_schema),
            ),
        ),
        SchemaMigrationSpec(
            version=13,
            name="control_plane_retention_indexes",
            data_steps=(
                SchemaDataStep(
                    "control_plane_retention", _init_control_plane_retention_indexes
                ),
            ),
        ),
        SchemaMigrationSpec(
            version=14,
            name="schema_lifecycle_complete_runtime_assertions",
            data_steps=(
                SchemaDataStep("runtime_assertion_cutover", lambda _conn: None),
            ),
        ),
        SchemaMigrationSpec(
            version=15,
            name="auth_provider_profile_tables",
            data_steps=(
                SchemaDataStep("directory_auth_profiles", _init_directory_auth_schema),
                SchemaDataStep("saml_auth_profiles", _init_saml_auth_schema),
            ),
        ),
        SchemaMigrationSpec(
            version=16,
            name="control_plane_identity",
            tables=(
                SchemaObjectSpec(
                    "control_plane_identity",
                    """
                    CREATE TABLE IF NOT EXISTS control_plane_identity (
                        id TINYINT PRIMARY KEY,
                        control_plane_id CHAR(36) NOT NULL,
                        created_ts BIGINT NOT NULL,
                        UNIQUE KEY uniq_control_plane_identity (control_plane_id)
                    )
                    """,
                ),
            ),
            data_steps=(
                SchemaDataStep(
                    "ensure_control_plane_identity", _init_control_plane_identity
                ),
            ),
        ),
        SchemaMigrationSpec(
            version=17,
            name="proxy_recovery_adoptions",
            tables=(
                SchemaObjectSpec(
                    "proxy_recovery_adoptions",
                    """
                    CREATE TABLE IF NOT EXISTS proxy_recovery_adoptions (
                        proxy_id VARCHAR(64) NOT NULL,
                        target_control_plane_id CHAR(36) NOT NULL,
                        source_control_plane_id CHAR(36) NOT NULL,
                        bundle_content_sha256 CHAR(64) NOT NULL,
                        status VARCHAR(16) NOT NULL,
                        adopted_ts BIGINT NOT NULL,
                        detail VARCHAR(512) NOT NULL DEFAULT '',
                        PRIMARY KEY(proxy_id, target_control_plane_id),
                        KEY idx_proxy_recovery_adoptions_source (source_control_plane_id, adopted_ts),
                        KEY idx_proxy_recovery_adoptions_bundle (bundle_content_sha256, adopted_ts)
                    )
                    """,
                ),
            ),
        ),
        SchemaMigrationSpec(
            version=18,
            name="policy_exception_method_scope",
            columns=(
                SchemaColumnSpec(
                    "policy_exceptions",
                    "method",
                    "ALTER TABLE policy_exceptions ADD COLUMN method VARCHAR(16) NOT NULL DEFAULT '' AFTER category",
                ),
            ),
            indexes=(
                SchemaIndexSpec(
                    "policy_exceptions",
                    "idx_policy_exceptions_scope",
                    "CREATE INDEX idx_policy_exceptions_scope ON policy_exceptions(proxy_id,status,block_type,client_ip,domain,category,method,expires_ts)",
                ),
            ),
        ),
        SchemaMigrationSpec(
            version=19,
            name="operation_ledger_stale_requeue_lifecycle",
            columns=(
                SchemaColumnSpec(
                    "proxy_operations",
                    "stale_requeue_count",
                    "ALTER TABLE proxy_operations ADD COLUMN stale_requeue_count INT NOT NULL DEFAULT 0 AFTER updated_ts",
                ),
            ),
            indexes=(
                SchemaIndexSpec(
                    "proxy_operations",
                    "idx_proxy_operations_proxy_status_created_id",
                    "ALTER TABLE proxy_operations ADD INDEX idx_proxy_operations_proxy_status_created_id (proxy_id, status, created_ts, id)",
                ),
                SchemaIndexSpec(
                    "proxy_operations",
                    "idx_proxy_operations_proxy_started_id",
                    "ALTER TABLE proxy_operations ADD INDEX idx_proxy_operations_proxy_started_id (proxy_id, started_ts, id)",
                ),
                SchemaIndexSpec(
                    "proxy_operations",
                    "idx_proxy_operations_proxy_updated_id",
                    "ALTER TABLE proxy_operations ADD INDEX idx_proxy_operations_proxy_updated_id (proxy_id, updated_ts, id)",
                ),
                SchemaIndexSpec(
                    "proxy_operations",
                    "uniq_proxy_operations_active_request",
                    "ALTER TABLE proxy_operations ADD UNIQUE KEY uniq_proxy_operations_active_request (proxy_id, request_key)",
                    unique=True,
                ),
            ),
            data_steps=(
                SchemaDataStep(
                    "operation_ledger_active_request_key_backfill",
                    _backfill_operation_ledger_active_request_keys,
                ),
            ),
        ),
        SchemaMigrationSpec(
            version=20,
            name="webfilter_blocked_log_lifecycle_indexes",
            columns=(
                SchemaColumnSpec(
                    "webfilter_blocked_log",
                    "proxy_id",
                    "ALTER TABLE webfilter_blocked_log ADD COLUMN proxy_id VARCHAR(64) NOT NULL DEFAULT 'default' AFTER id",
                ),
            ),
            indexes=(
                SchemaIndexSpec(
                    "webfilter_blocked_log",
                    "idx_webfilter_blocked_log_ts_id",
                    "ALTER TABLE webfilter_blocked_log ADD INDEX idx_webfilter_blocked_log_ts_id (ts, id)",
                ),
                SchemaIndexSpec(
                    "webfilter_blocked_log",
                    "idx_webfilter_blocked_log_proxy_ts",
                    "ALTER TABLE webfilter_blocked_log ADD INDEX idx_webfilter_blocked_log_proxy_ts (proxy_id, ts, id)",
                ),
            ),
        ),
        SchemaMigrationSpec(
            version=21,
            name="application_ledger_evidence_indexes",
            columns=(
                SchemaColumnSpec(
                    "proxy_config_applications",
                    "config_sha256",
                    "ALTER TABLE proxy_config_applications ADD COLUMN config_sha256 CHAR(64) NOT NULL DEFAULT '' AFTER applied_ts",
                ),
            ),
            indexes=(
                SchemaIndexSpec(
                    "proxy_config_applications",
                    "idx_proxy_config_applications_proxy_revision_ts",
                    "ALTER TABLE proxy_config_applications ADD INDEX idx_proxy_config_applications_proxy_revision_ts (proxy_id, revision_id, applied_ts, id)",
                ),
            ),
            data_steps=(
                SchemaDataStep(
                    "application_ledger_evidence_backfill",
                    _backfill_application_ledger_evidence,
                ),
            ),
        ),
        SchemaMigrationSpec(
            version=22,
            name="timeseries_metric_count_columns",
            data_steps=(
                SchemaDataStep(
                    "timeseries_metric_count_columns",
                    _init_timeseries_metric_count_schema,
                ),
            ),
        ),
        SchemaMigrationSpec(
            version=23,
            name="application_ledger_evidence_completion",
            columns=(
                SchemaColumnSpec(
                    "proxy_config_applications",
                    "config_sha256",
                    "ALTER TABLE proxy_config_applications ADD COLUMN config_sha256 CHAR(64) NOT NULL DEFAULT '' AFTER applied_ts",
                ),
                SchemaColumnSpec(
                    "proxy_certificate_applications",
                    "bundle_sha256",
                    "ALTER TABLE proxy_certificate_applications ADD COLUMN bundle_sha256 CHAR(64) NOT NULL DEFAULT '' AFTER applied_ts",
                ),
                SchemaColumnSpec(
                    "proxy_adblock_artifact_applications",
                    "artifact_sha256",
                    "ALTER TABLE proxy_adblock_artifact_applications ADD COLUMN artifact_sha256 CHAR(64) NOT NULL DEFAULT '' AFTER applied_ts",
                ),
            ),
            indexes=(
                SchemaIndexSpec(
                    "proxy_config_applications",
                    "idx_proxy_config_applications_proxy_revision_ts",
                    "ALTER TABLE proxy_config_applications ADD INDEX idx_proxy_config_applications_proxy_revision_ts (proxy_id, revision_id, applied_ts, id)",
                ),
                SchemaIndexSpec(
                    "proxy_certificate_applications",
                    "idx_proxy_certificate_applications_proxy_revision_ts",
                    "ALTER TABLE proxy_certificate_applications ADD INDEX idx_proxy_certificate_applications_proxy_revision_ts (proxy_id, revision_id, applied_ts, id)",
                ),
                SchemaIndexSpec(
                    "proxy_adblock_artifact_applications",
                    "idx_proxy_adblock_artifact_apply_proxy_revision_ts",
                    "ALTER TABLE proxy_adblock_artifact_applications ADD INDEX idx_proxy_adblock_artifact_apply_proxy_revision_ts (proxy_id, revision_id, applied_ts, id)",
                ),
            ),
            data_steps=(
                SchemaDataStep(
                    "application_ledger_evidence_completion_backfill",
                    _backfill_application_ledger_evidence,
                ),
            ),
        ),
        SchemaMigrationSpec(
            version=24,
            name="live_stats_seed_checkpoint",
            tables=(
                SchemaObjectSpec(
                    "live_stats_seed_state",
                    """
                    CREATE TABLE IF NOT EXISTS live_stats_seed_state (
                        proxy_id VARCHAR(64) NOT NULL DEFAULT 'default',
                        source_path VARCHAR(1024) NOT NULL,
                        device_id BIGINT UNSIGNED NOT NULL,
                        inode BIGINT UNSIGNED NOT NULL,
                        byte_offset BIGINT UNSIGNED NOT NULL,
                        checkpoint_sha256 CHAR(64) NOT NULL,
                        updated_ts BIGINT NOT NULL,
                        PRIMARY KEY (proxy_id)
                    )
                    """,
                ),
            ),
        ),
        SchemaMigrationSpec(
            version=25,
            name="diagnostic_icap_extended_metadata",
            columns=(
                SchemaColumnSpec(
                    "diagnostic_icap_events",
                    "icap_service",
                    "ALTER TABLE diagnostic_icap_events ADD COLUMN icap_service VARCHAR(128) NOT NULL DEFAULT '' AFTER service_family",
                ),
                SchemaColumnSpec(
                    "diagnostic_icap_events",
                    "icap_outcome",
                    "ALTER TABLE diagnostic_icap_events ADD COLUMN icap_outcome VARCHAR(64) NOT NULL DEFAULT '' AFTER icap_service",
                ),
                SchemaColumnSpec(
                    "diagnostic_icap_events",
                    "icap_status",
                    "ALTER TABLE diagnostic_icap_events ADD COLUMN icap_status INT NOT NULL DEFAULT 0 AFTER icap_outcome",
                ),
                SchemaColumnSpec(
                    "diagnostic_icap_events",
                    "icap_response_time_ms",
                    "ALTER TABLE diagnostic_icap_events ADD COLUMN icap_response_time_ms INT NOT NULL DEFAULT 0 AFTER icap_status",
                ),
                SchemaColumnSpec(
                    "diagnostic_icap_events",
                    "icap_io_time_ms",
                    "ALTER TABLE diagnostic_icap_events ADD COLUMN icap_io_time_ms INT NOT NULL DEFAULT 0 AFTER icap_response_time_ms",
                ),
                SchemaColumnSpec(
                    "diagnostic_icap_events",
                    "icap_bytes_sent",
                    "ALTER TABLE diagnostic_icap_events ADD COLUMN icap_bytes_sent BIGINT NOT NULL DEFAULT 0 AFTER icap_io_time_ms",
                ),
                SchemaColumnSpec(
                    "diagnostic_icap_events",
                    "icap_bytes_received",
                    "ALTER TABLE diagnostic_icap_events ADD COLUMN icap_bytes_received BIGINT NOT NULL DEFAULT 0 AFTER icap_bytes_sent",
                ),
            ),
        ),
        SchemaMigrationSpec(
            version=26,
            name="observability_manual_export_preset_contract",
            data_steps=(
                SchemaDataStep(
                    "canonicalize_observability_manual_export_presets",
                    lambda conn: conn.execute(
                        """
                        UPDATE observability_report_schedules
                        SET cadence='manual', recipients='', next_run_ts=0,
                            last_run_ts=0, last_status='manual_export_only'
                        WHERE cadence<>'manual' OR recipients<>'' OR next_run_ts<>0
                           OR last_run_ts<>0 OR last_status<>'manual_export_only'
                        """
                    ),
                ),
            ),
        ),
        SchemaMigrationSpec(
            version=27,
            name="operation_ledger_hard_retention_cap",
            data_steps=(
                SchemaDataStep(
                    "prune_operation_ledger_history",
                    _prune_operation_ledger_history,
                ),
            ),
        ),
        SchemaMigrationSpec(
            version=28,
            name="policy_request_public_admission_index",
            indexes=(
                SchemaIndexSpec(
                    "policy_requests",
                    "idx_policy_requests_proxy_status_client_id",
                    "ALTER TABLE policy_requests ADD INDEX idx_policy_requests_proxy_status_client_id (proxy_id, status, client_ip, id)",
                ),
            ),
        ),
        SchemaMigrationSpec(
            version=29,
            name="diagnostic_file_security_policy_attribution",
            columns=(
                SchemaColumnSpec(
                    "diagnostic_requests",
                    "file_security_policy",
                    "ALTER TABLE diagnostic_requests ADD COLUMN file_security_policy VARCHAR(64) NOT NULL DEFAULT '' AFTER cache_bypass",
                ),
            ),
        ),
        SchemaMigrationSpec(
            version=30,
            name="proxy_scoped_adblock_runtime_enablement",
            data_steps=(
                SchemaDataStep(
                    "seed_proxy_adblock_runtime_enabled",
                    _seed_proxy_adblock_runtime_enabled,
                ),
            ),
        ),
    )


def _default_spec() -> SchemaMigrationSpec:
    return _migration_specs()[-1]


def apply_schema_migration(
    spec: SchemaMigrationSpec,
    *,
    require_privileges: bool = True,
    connect_factory: Callable[[], Any] = connect,
) -> list[SchemaMigrationResult]:
    results: list[SchemaMigrationResult] = []

    def _run() -> list[SchemaMigrationResult]:
        with connect_factory() as conn:
            with mysql_advisory_lock(
                conn,
                _MIGRATION_LOCK_NAME,
                mysql_schema_lock_timeout_seconds(60),
            ):
                migrations_table_exists = table_exists(conn, "schema_migrations")
                row = (
                    _existing_migration(conn, spec.version)
                    if migrations_table_exists
                    else None
                )
                if row is not None:
                    status = str(_row_value(row, "status", 3) or "")
                    checksum = str(_row_value(row, "checksum", 2) or "")
                    if status == "applied" and checksum == spec.checksum:
                        now = int(time.time())
                        results.append(
                            SchemaMigrationResult(
                                version=spec.version,
                                name=spec.name,
                                status="noop",
                                checksum=spec.checksum,
                                started_ts=now,
                                finished_ts=now,
                            ),
                        )
                        return results
                    if status == "applied" and checksum != spec.checksum:
                        msg = (
                            f"Schema migration {spec.version} checksum drift: "
                            f"database has {checksum}, code expects {spec.checksum}."
                        )
                        raise RuntimeError(msg)
                try:
                    _ensure_migration_tables(conn)
                except DATABASE_ERRORS as exc:
                    _raise_privilege_error(exc)
                if require_privileges:
                    require_migration_privileges(conn)
                _start_migration(conn, spec)
                conn.commit()
                try:
                    previous_context = bool(
                        getattr(_MIGRATION_CONTEXT, "active", False)
                    )
                    _MIGRATION_CONTEXT.active = True
                    try:
                        _apply_spec(conn, spec)
                    finally:
                        _MIGRATION_CONTEXT.active = previous_context
                except Exception as exc:
                    try:
                        conn.rollback()
                    except Exception as rollback_exc:
                        exc.add_note(
                            "Schema migration rollback failed; failure status was not recorded: "
                            f"{rollback_exc.__class__.__name__}: {rollback_exc}"
                        )
                        raise exc from rollback_exc
                    try:
                        _fail_migration(conn, spec, exc)
                        conn.commit()
                    except Exception as recording_exc:
                        exc.add_note(
                            "Schema migration failure status could not be committed: "
                            f"{recording_exc.__class__.__name__}: {recording_exc}"
                        )
                    raise
                result = _finish_migration(conn, spec)
                # A failed COMMIT has an ambiguous outcome, so it must not be
                # handled by writing a compensating failed status.
                conn.commit()
                results.append(result)
                return results

    return run_mysql_operation_with_retry(_run)


def migrate_schema(*, require_privileges: bool = True) -> list[SchemaMigrationResult]:
    results: list[SchemaMigrationResult] = []
    for spec in _migration_specs():
        results.extend(
            apply_schema_migration(
                spec,
                require_privileges=require_privileges,
                connect_factory=connect,
            ),
        )
    return results


def ensure_startup_schema() -> list[SchemaMigrationResult]:
    return migrate_schema(require_privileges=True)


def startup_schema_configured() -> bool:
    if (os.environ.get("MYSQL_SCHEMA_MIGRATIONS_DISABLED") or "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }:
        return False
    return any(
        (os.environ.get(name) or "").strip()
        for name in ("DATABASE_URL", "MYSQL_HOST", "MYSQL_DATABASE", "MYSQL_USER")
    )


def ensure_startup_schema_if_configured() -> list[SchemaMigrationResult]:
    if not startup_schema_configured():
        return []
    return ensure_startup_schema()


def latest_schema_version() -> int:
    return _SCHEMA_VERSION


def latest_schema_checksum() -> str:
    return _default_spec().checksum


def assert_schema_current(conn: Any | None = None) -> None:
    owns_connection = conn is None
    active_conn = connect() if owns_connection else conn
    try:
        row = _existing_migration(active_conn, _SCHEMA_VERSION)
        if row is None or str(_row_value(row, "status", 3) or "") != "applied":
            msg = (
                f"MySQL schema migration {_SCHEMA_VERSION} is not applied. "
                "Run startup schema migrations with a DDL-capable account before normal runtime."
            )
            raise RuntimeError(msg)
    finally:
        if owns_connection:
            active_conn.close()


def ensure_runtime_schema_current_once() -> None:
    global _HOT_PATH_ENSURED
    if _HOT_PATH_ENSURED:
        return
    with _HOT_PATH_ENSURE_LOCK:
        if _HOT_PATH_ENSURED:
            return
        with connect() as conn:
            assert_schema_current(conn)
        _HOT_PATH_ENSURED = True


def ensure_hot_path_schema_once() -> None:
    # Backward-compatible name for callers that used to allow runtime DDL.
    # Hot paths now perform only a one-time migration assertion; startup owns DDL.
    ensure_runtime_schema_current_once()


def schema_migration_status() -> list[dict[str, Any]]:
    with connect() as conn:
        if not table_exists(conn, "schema_migrations"):
            return []
        rows = conn.execute(
            """
            SELECT version, name, checksum, status, started_ts, finished_ts, error
            FROM schema_migrations
            ORDER BY version ASC
            """,
        ).fetchall()
    return [
        {
            "version": int(_row_value(row, "version", 0) or 0),
            "name": str(_row_value(row, "name", 1) or ""),
            "checksum": str(_row_value(row, "checksum", 2) or ""),
            "status": str(_row_value(row, "status", 3) or ""),
            "started_ts": int(_row_value(row, "started_ts", 4) or 0),
            "finished_ts": int(_row_value(row, "finished_ts", 5) or 0),
            "error": str(_row_value(row, "error", 6) or ""),
        }
        for row in rows
    ]


def reset_schema_lifecycle_for_tests() -> None:
    global _HOT_PATH_ENSURED
    with _HOT_PATH_ENSURE_LOCK:
        _HOT_PATH_ENSURED = False
