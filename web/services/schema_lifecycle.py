from __future__ import annotations

import contextlib
import hashlib
import importlib
import json
import os
import re
import threading
import time
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

if False:  # pragma: no cover - type checkers only
    pass

_SCHEMA_VERSION = 15
_MIGRATOR_NAME = "docker_proxy_schema_lifecycle"
_MIGRATION_LOCK_NAME = "docker_proxy:schema_lifecycle:migrate"
_RUNTIME_LOCK_NAME = "docker_proxy:schema_lifecycle:runtime_ddl"
_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
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
            "tables": [(item.table, _normalize_sql(item.create_sql)) for item in self.tables],
            "columns": [(item.table, item.name, _normalize_sql(item.ddl)) for item in self.columns],
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


def _safe_identifier(identifier: str) -> str:
    value = str(identifier or "").strip()
    if not _IDENTIFIER_RE.fullmatch(value):
        msg = f"Unsafe MySQL identifier: {identifier!r}"
        raise ValueError(msg)
    return value


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


def _migration_assertion_error(table_name: str, object_name: str, object_type: str) -> RuntimeError:
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
    try:
        row = _existing_migration(conn, _SCHEMA_VERSION)
    except Exception:
        return False
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
    table = _safe_identifier(probe)
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
        (int(version), name[:190], phase[:32], status[:16], detail[:4000], int(time.time())),
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
    _record_event(conn, version=spec.version, name=spec.name, phase="start", status="running")


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
    _record_event(conn, version=spec.version, name=spec.name, phase="finish", status="applied")
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
    safe_table = _safe_identifier(table_name)
    safe_scope = _safe_identifier(scope_column) if scope_column else ""
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
        _record_event(conn, version=spec.version, name=spec.name, phase=f"table:{table.table}", status="ok")
    for step in spec.data_steps:
        step.apply(conn)
        _record_event(conn, version=spec.version, name=spec.name, phase=f"data:{step.name}", status="ok")
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


def _repair_revision_uniques(conn: Any) -> None:
    if table_exists(conn, "proxy_config_revisions"):
        repair_duplicate_active_rows(conn, table_name="proxy_config_revisions", scope_column="proxy_id")
    if table_exists(conn, "certificate_bundle_revisions"):
        repair_duplicate_active_rows(conn, table_name="certificate_bundle_revisions")
    if table_exists(conn, "adblock_artifact_revisions"):
        repair_duplicate_active_rows(conn, table_name="adblock_artifact_revisions")


def _init_auth_schema(_conn: Any) -> None:
    importlib.import_module("services.auth_store").get_auth_store().ensure_schema()


def _init_proxy_registry_schema(_conn: Any) -> None:
    importlib.import_module("services.proxy_registry").get_proxy_registry().init_db()


def _init_config_revision_schema(_conn: Any) -> None:
    importlib.import_module("services.config_revisions").get_config_revisions().init_db()


def _init_certificate_bundle_schema(_conn: Any) -> None:
    importlib.import_module("services.certificate_bundles").get_certificate_bundles().init_db()


def _init_adblock_artifact_schema(_conn: Any) -> None:
    importlib.import_module("services.adblock_artifacts").get_adblock_artifacts().init_db()


def _init_operation_ledger_schema(_conn: Any) -> None:
    importlib.import_module("services.operation_ledger").get_operation_ledger().init_db()


def _init_audit_schema(_conn: Any) -> None:
    importlib.import_module("services.audit_store").get_audit_store().init_db()


def _init_adblock_runtime_schema(conn: Any) -> None:
    store_module = importlib.import_module("services.adblock_store")
    store_module.AdblockStore(lists_dir=os.environ.get("ADBLOCK_LISTS_DIR", "."))._init_schema(conn)


def _init_webfilter_runtime_schema(_conn: Any) -> None:
    importlib.import_module("services.webfilter_store").get_webfilter_store().init_db()


def _init_sslfilter_schema(_conn: Any) -> None:
    importlib.import_module("services.sslfilter_store").get_sslfilter_store().init_db()


def _init_safe_browsing_schema(conn: Any) -> None:
    importlib.import_module("services.safe_browsing_v5").SafeBrowsingStore.init_schema(conn)


def _init_diagnostic_schema(_conn: Any) -> None:
    importlib.import_module("services.diagnostic_store").get_diagnostic_store().init_db()


def _init_ssl_errors_schema(_conn: Any) -> None:
    importlib.import_module("services.ssl_errors_store").get_ssl_errors_store().init_db()


def _init_live_stats_schema(_conn: Any) -> None:
    importlib.import_module("services.live_stats").get_store().init_db()


def _init_timeseries_schema(_conn: Any) -> None:
    importlib.import_module("services.timeseries_store").get_timeseries_store().init_db()


def _init_observability_schema(_conn: Any) -> None:
    maintenance = importlib.import_module("services.observability_maintenance")
    queries = importlib.import_module("services.observability_queries")
    maintenance._ensure_observability_settings_table()
    maintenance._ensure_observability_maintenance_runs_table()
    queries.get_observability_queries()._ensure_report_schedule_db()


def _init_policy_schema(_conn: Any) -> None:
    importlib.import_module("services.policy_requests").get_policy_request_store().init_db()


def _init_pac_schema(_conn: Any) -> None:
    importlib.import_module("services.pac_profiles_store").get_pac_profiles_store().init_db()


def _init_directory_auth_schema(_conn: Any) -> None:
    importlib.import_module("services.directory_auth").get_directory_auth_store().ensure_default_profiles()


def _init_saml_auth_schema(_conn: Any) -> None:
    importlib.import_module("services.saml_auth").get_saml_auth_store().ensure_default_profile()


def _init_proxy_lifecycle_schema(conn: Any) -> None:
    lifecycle = importlib.import_module("services.proxy_lifecycle")
    lifecycle.ensure_lifecycle_schema(conn)
    for table in lifecycle.PROXY_LIFECYCLE_TABLES:
        lifecycle.ensure_proxy_lifecycle_index(conn, table)


def _init_control_plane_retention_indexes(_conn: Any) -> None:
    maintenance = importlib.import_module("services.control_plane_maintenance")
    for table in maintenance.CONTROL_PLANE_RETENTION_INDEXES:
        if table_exists(_conn, table):
            for index_name, ddl in maintenance.CONTROL_PLANE_RETENTION_INDEXES[table]:
                ensure_index(_conn, table_name=table, index_name=index_name, ddl=ddl)


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
            data_steps=(SchemaDataStep("proxy_lifecycle", _init_proxy_lifecycle_schema),),
        ),
        SchemaMigrationSpec(
            version=13,
            name="control_plane_retention_indexes",
            data_steps=(SchemaDataStep("control_plane_retention", _init_control_plane_retention_indexes),),
        ),
        SchemaMigrationSpec(
            version=14,
            name="schema_lifecycle_complete_runtime_assertions",
            data_steps=(SchemaDataStep("runtime_assertion_cutover", lambda _conn: None),),
        ),
        SchemaMigrationSpec(
            version=15,
            name="auth_provider_profile_tables",
            data_steps=(
                SchemaDataStep("directory_auth_profiles", _init_directory_auth_schema),
                SchemaDataStep("saml_auth_profiles", _init_saml_auth_schema),
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
                row = _existing_migration(conn, spec.version) if migrations_table_exists else None
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
                    previous_context = bool(getattr(_MIGRATION_CONTEXT, "active", False))
                    _MIGRATION_CONTEXT.active = True
                    try:
                        _apply_spec(conn, spec)
                    finally:
                        _MIGRATION_CONTEXT.active = previous_context
                    results.append(_finish_migration(conn, spec))
                    conn.commit()
                except Exception as exc:
                    _fail_migration(conn, spec, exc)
                    conn.commit()
                    raise
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
    if (os.environ.get("MYSQL_SCHEMA_MIGRATIONS_DISABLED") or "").strip().lower() in {"1", "true", "yes", "on"}:
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
