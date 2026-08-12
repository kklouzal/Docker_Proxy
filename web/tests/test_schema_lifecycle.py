from __future__ import annotations

import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

WEB_ROOT = Path(__file__).resolve().parents[1]
if str(WEB_ROOT) not in sys.path:
    sys.path.insert(0, str(WEB_ROOT))

from services import schema_lifecycle  # type: ignore  # noqa: E402


class _Result:
    def __init__(self, rows: list[Any] | None = None, *, rowcount: int = 0) -> None:
        self._rows = rows or []
        self.rowcount = rowcount

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return list(self._rows)


class _Conn:
    def __init__(self) -> None:
        self.migrations: dict[int, dict[str, Any]] = {}
        self.events: list[tuple[Any, ...]] = []
        self.ops: list[str] = []

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def commit(self) -> None:
        self.ops.append("commit")

    def rollback(self) -> None:
        self.ops.append("rollback")

    def execute(self, sql: str, params=()):
        text = " ".join(str(sql).split())
        params = tuple(params or ())
        self.ops.append(text)
        if "GET_LOCK" in text:
            return _Result([{"acquired": 1}])
        if "RELEASE_LOCK" in text:
            return _Result()
        if text.startswith("CREATE TABLE IF NOT EXISTS schema_migrations"):
            return _Result()
        if text.startswith("CREATE TABLE IF NOT EXISTS schema_migration_events"):
            return _Result()
        if text.startswith("CREATE TABLE schema_privilege_probe_"):
            return _Result()
        if text.startswith("ALTER TABLE schema_privilege_probe_"):
            return _Result()
        if text.startswith("DROP TABLE schema_privilege_probe_"):
            return _Result()
        if "FROM information_schema.tables" in text:
            exists = params and params[0] == "schema_migrations" and bool(self.migrations)
            return _Result([{"1": 1}] if exists else [])
        if text.startswith("SELECT version, name, checksum, status, error FROM schema_migrations"):
            row = self.migrations.get(int(params[0]))
            return _Result([row] if row else [])
        if text.startswith("INSERT INTO schema_migrations"):
            version, name, checksum, started = params[:4]
            self.migrations[int(version)] = {
                "version": int(version),
                "name": name,
                "checksum": checksum,
                "status": "running",
                "started_ts": int(started),
                "finished_ts": 0,
                "error": "",
            }
            return _Result(rowcount=1)
        if text.startswith("UPDATE schema_migrations SET status='applied'"):
            finished, version = params[:2]
            row = self.migrations[int(version)]
            row["status"] = "applied"
            row["finished_ts"] = int(finished)
            row["error"] = ""
            return _Result(rowcount=1)
        if text.startswith("UPDATE schema_migrations SET status='failed'"):
            finished, error, version = params[:3]
            row = self.migrations[int(version)]
            row["status"] = "failed"
            row["finished_ts"] = int(finished)
            row["error"] = error
            return _Result(rowcount=1)
        if text.startswith("INSERT INTO schema_migration_events"):
            self.events.append(params)
            return _Result(rowcount=1)
        msg = f"unexpected SQL: {text}"
        raise AssertionError(msg)


def _spec(version: int = 1, *, fn=None) -> schema_lifecycle.SchemaMigrationSpec:
    def step(conn):
        if fn is not None:
            fn(conn)

    return schema_lifecycle.SchemaMigrationSpec(
        version=version,
        name=f"test_{version}",
        data_steps=(schema_lifecycle.SchemaDataStep("step", step),),
    )


def test_runtime_schema_readiness_propagates_probe_failure() -> None:
    class SchemaReadinessProbeError(RuntimeError):
        pass

    probe_error = SchemaReadinessProbeError("schema readiness query failed")

    class FailingProbeConnection:
        def execute(self, _sql: str, _params=()):
            raise probe_error

    with pytest.raises(SchemaReadinessProbeError) as caught:
        schema_lifecycle.runtime_schema_current_applied(FailingProbeConnection())

    assert caught.value is probe_error


def test_schema_migration_records_applied_and_skips_already_applied() -> None:
    conn = _Conn()
    calls = 0

    def fn(_conn):
        nonlocal calls
        calls += 1

    spec = _spec(fn=fn)
    first = schema_lifecycle.apply_schema_migration(
        spec,
        connect_factory=lambda: conn,
        require_privileges=True,
    )
    second = schema_lifecycle.apply_schema_migration(
        spec,
        connect_factory=lambda: conn,
        require_privileges=True,
    )

    assert [row.status for row in first] == ["applied"]
    assert [row.status for row in second] == ["noop"]
    assert calls == 1
    assert conn.migrations[1]["status"] == "applied"


def test_schema_migration_checksum_drift_blocks_startup() -> None:
    conn = _Conn()
    spec = _spec()
    conn.migrations[spec.version] = {
        "version": spec.version,
        "name": spec.name,
        "checksum": "0" * 64,
        "status": "applied",
        "started_ts": 1,
        "finished_ts": 2,
        "error": "",
    }

    with pytest.raises(RuntimeError, match="checksum drift"):
        schema_lifecycle.apply_schema_migration(
            spec,
            connect_factory=lambda: conn,
            require_privileges=False,
        )


def test_schema_migration_failure_is_observable_and_retryable() -> None:
    conn = _Conn()
    attempts = 0

    def fn(_conn):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            msg = "boom"
            raise RuntimeError(msg)

    spec = _spec(fn=fn)
    with pytest.raises(RuntimeError, match="boom"):
        schema_lifecycle.apply_schema_migration(
            spec,
            connect_factory=lambda: conn,
            require_privileges=False,
        )
    assert conn.migrations[1]["status"] == "failed"
    assert "boom" in conn.migrations[1]["error"]

    result = schema_lifecycle.apply_schema_migration(
        spec,
        connect_factory=lambda: conn,
        require_privileges=False,
    )
    assert [row.status for row in result] == ["applied"]
    assert attempts == 2


def test_schema_lifecycle_declares_every_deferred_mysql_family() -> None:
    all_specs = schema_lifecycle._migration_specs()
    specs = all_specs[:-2]
    versions = [spec.version for spec in all_specs]
    names = {spec.name for spec in all_specs}

    assert versions == list(range(1, schema_lifecycle.latest_schema_version() + 1))
    assert {
        "adblock_runtime_tables",
        "webfilter_and_safe_browsing_tables",
        "sslfilter_policy_tables",
        "diagnostic_request_and_icap_tables",
        "ssl_error_aggregate_tables",
        "live_stats_aggregate_tables",
        "timeseries_resolution_tables",
        "observability_control_tables",
        "policy_request_tables",
        "pac_profile_tables",
        "proxy_lifecycle_indexes",
        "control_plane_retention_indexes",
        "schema_lifecycle_complete_runtime_assertions",
        "auth_provider_profile_tables",
        "control_plane_identity",
        "proxy_recovery_adoptions",
        "policy_exception_method_scope",
        "operation_ledger_stale_requeue_lifecycle",
        "webfilter_blocked_log_lifecycle_indexes",
        "application_ledger_evidence_indexes",
        "timeseries_metric_count_columns",
        "application_ledger_evidence_completion",
        "live_stats_seed_checkpoint",
        "diagnostic_icap_extended_metadata",
    } <= names
    assert schema_lifecycle.latest_schema_version() == 26
    manual_spec = all_specs[-1]
    assert manual_spec.version == 26
    assert manual_spec.name == "observability_manual_export_preset_contract"
    assert manual_spec.data_steps[0].name == "canonicalize_observability_manual_export_presets"
    assert specs[-9].version == 16
    assert specs[-9].name == "control_plane_identity"
    assert specs[-8].version == 17
    assert specs[-8].name == "proxy_recovery_adoptions"
    assert specs[-7].version == 18
    assert specs[-7].name == "policy_exception_method_scope"
    assert specs[-6].version == 19
    assert specs[-6].name == "operation_ledger_stale_requeue_lifecycle"
    assert specs[-5].version == 20
    assert specs[-5].name == "webfilter_blocked_log_lifecycle_indexes"
    assert specs[-4].version == 21
    assert specs[-4].name == "application_ledger_evidence_indexes"
    assert specs[-3].version == 22
    assert specs[-3].name == "timeseries_metric_count_columns"
    assert specs[-2].version == 23
    assert specs[-2].name == "application_ledger_evidence_completion"
    assert specs[-1].version == 24
    assert specs[-1].name == "live_stats_seed_checkpoint"
    assert schema_lifecycle.latest_schema_checksum() == all_specs[-1].checksum
    assert specs[-9].tables[0].table == "control_plane_identity"
    assert "control_plane_id CHAR(36) NOT NULL" in specs[-9].tables[0].create_sql
    assert specs[-8].tables[0].table == "proxy_recovery_adoptions"
    assert "proxy_id VARCHAR(64) NOT NULL" in specs[-8].tables[0].create_sql
    assert "PRIMARY KEY(proxy_id, target_control_plane_id)" in specs[-8].tables[0].create_sql
    assert specs[-7].columns[0].table == "policy_exceptions"
    assert specs[-7].columns[0].name == "method"
    assert specs[-6].columns[0].table == "proxy_operations"
    assert specs[-6].columns[0].name == "stale_requeue_count"
    assert [index.name for index in specs[-6].indexes] == [
        "idx_proxy_operations_proxy_status_created_id",
        "idx_proxy_operations_proxy_started_id",
        "idx_proxy_operations_proxy_updated_id",
        "uniq_proxy_operations_active_request",
    ]
    assert specs[-6].indexes[-1].unique is True
    assert specs[-6].data_steps[0].name == "operation_ledger_active_request_key_backfill"
    assert specs[-5].columns[0].table == "webfilter_blocked_log"
    assert specs[-5].columns[0].name == "proxy_id"
    assert [index.name for index in specs[-5].indexes] == [
        "idx_webfilter_blocked_log_ts_id",
        "idx_webfilter_blocked_log_proxy_ts",
    ]
    assert specs[-4].columns[0].table == "proxy_config_applications"
    assert specs[-4].columns[0].name == "config_sha256"
    assert [index.name for index in specs[-4].indexes] == [
        "idx_proxy_config_applications_proxy_revision_ts",
    ]
    assert specs[-3].data_steps[0].name == "timeseries_metric_count_columns"
    assert [(column.table, column.name) for column in specs[-2].columns] == [
        ("proxy_config_applications", "config_sha256"),
        ("proxy_certificate_applications", "bundle_sha256"),
        ("proxy_adblock_artifact_applications", "artifact_sha256"),
    ]
    assert [(index.table, index.name) for index in specs[-2].indexes] == [
        ("proxy_config_applications", "idx_proxy_config_applications_proxy_revision_ts"),
        ("proxy_certificate_applications", "idx_proxy_certificate_applications_proxy_revision_ts"),
        ("proxy_adblock_artifact_applications", "idx_proxy_adblock_artifact_apply_proxy_revision_ts"),
    ]
    assert specs[-2].data_steps[0].name == "application_ledger_evidence_completion_backfill"
    assert specs[-1].tables[0].table == "live_stats_seed_state"
    assert [(column.table, column.name) for column in all_specs[-2].columns] == [
        ("diagnostic_icap_events", "icap_service"),
        ("diagnostic_icap_events", "icap_outcome"),
        ("diagnostic_icap_events", "icap_status"),
        ("diagnostic_icap_events", "icap_response_time_ms"),
        ("diagnostic_icap_events", "icap_io_time_ms"),
        ("diagnostic_icap_events", "icap_bytes_sent"),
        ("diagnostic_icap_events", "icap_bytes_received"),
    ]


class _ApplicationLedgerEvidenceBackfillConn:
    def __init__(self) -> None:
        self.columns: set[tuple[str, str]] = {
            ("proxy_config_applications", "config_sha256"),
        }
        self.ops: list[str] = []

    def execute(self, sql: str, params=()):
        text = " ".join(str(sql).split())
        params = tuple(params or ())
        self.ops.append(text)
        if "FROM information_schema.columns" in text:
            return _Result([{"1": 1}] if (str(params[0]), str(params[1])) in self.columns else [])
        if text.startswith("ALTER TABLE") and "ADD COLUMN" in text:
            if text.startswith("ALTER TABLE proxy_config_applications ADD COLUMN config_sha256"):
                self.columns.add(("proxy_config_applications", "config_sha256"))
                return _Result()
            if text.startswith("ALTER TABLE proxy_certificate_applications ADD COLUMN bundle_sha256"):
                self.columns.add(("proxy_certificate_applications", "bundle_sha256"))
                return _Result()
            if text.startswith("ALTER TABLE proxy_adblock_artifact_applications ADD COLUMN artifact_sha256"):
                self.columns.add(("proxy_adblock_artifact_applications", "artifact_sha256"))
                return _Result()
        if text.startswith("UPDATE proxy_config_applications app"):
            return _Result(rowcount=1)
        if text.startswith("UPDATE proxy_certificate_applications app"):
            return _Result(rowcount=1)
        if text.startswith("UPDATE proxy_adblock_artifact_applications app"):
            return _Result(rowcount=1)
        msg = f"unexpected SQL: {text}"
        raise AssertionError(msg)


def test_application_ledger_evidence_backfill_repairs_all_missing_evidence_columns() -> None:
    conn = _ApplicationLedgerEvidenceBackfillConn()

    schema_lifecycle._backfill_application_ledger_evidence(conn)

    assert conn.columns == {
        ("proxy_config_applications", "config_sha256"),
        ("proxy_certificate_applications", "bundle_sha256"),
        ("proxy_adblock_artifact_applications", "artifact_sha256"),
    }
    assert any(
        op.startswith("ALTER TABLE proxy_certificate_applications ADD COLUMN bundle_sha256")
        for op in conn.ops
    )
    assert any(
        op.startswith("ALTER TABLE proxy_adblock_artifact_applications ADD COLUMN artifact_sha256")
        for op in conn.ops
    )
    assert any(op.startswith("UPDATE proxy_config_applications app") for op in conn.ops)
    assert any(op.startswith("UPDATE proxy_certificate_applications app") for op in conn.ops)
    assert any(op.startswith("UPDATE proxy_adblock_artifact_applications app") for op in conn.ops)


class _IdentityConn:
    def __init__(self) -> None:
        self.identity: str | None = None
        self.lock = threading.Lock()
        self.insert_candidates: list[str] = []

    def execute(self, sql: str, params=()):
        text = " ".join(str(sql).split())
        params = tuple(params or ())
        if text.startswith("INSERT IGNORE INTO control_plane_identity"):
            candidate = str(params[0])
            with self.lock:
                self.insert_candidates.append(candidate)
                if self.identity is None:
                    self.identity = candidate
            return _Result(rowcount=1)
        if text.startswith("SELECT control_plane_id FROM control_plane_identity"):
            with self.lock:
                row = {"control_plane_id": self.identity} if self.identity else None
            return _Result([row] if row else [])
        msg = f"unexpected SQL: {text}"
        raise AssertionError(msg)


def test_control_plane_identity_is_stable_idempotent_and_concurrency_safe() -> None:
    conn = _IdentityConn()

    with ThreadPoolExecutor(max_workers=8) as executor:
        identities = list(
            executor.map(lambda _i: schema_lifecycle.ensure_control_plane_identity(conn), range(24)),
        )

    assert len(set(identities)) == 1
    assert schema_lifecycle.read_control_plane_identity(conn) == identities[0]
    assert schema_lifecycle.ensure_control_plane_identity(conn) == identities[0]
    assert schema_lifecycle.normalize_control_plane_identity(identities[0].upper()) == identities[0]
    assert len(conn.insert_candidates) == 25
    assert identities[0] in conn.insert_candidates

    with pytest.raises(ValueError, match="invalid control plane identity"):
        schema_lifecycle.normalize_control_plane_identity("not-a-stable-id")


class _CurrentSchemaConn:
    native = object()

    def __init__(self) -> None:
        self.ops: list[str] = []

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def execute(self, sql: str, params=()):
        text = " ".join(str(sql).split())
        self.ops.append(text)
        if text.startswith("SELECT version, name, checksum, status, error FROM schema_migrations"):
            return _Result(
                [
                    {
                        "version": schema_lifecycle.latest_schema_version(),
                        "name": "schema_lifecycle_complete_runtime_assertions",
                        "checksum": "ignored",
                        "status": "applied",
                        "error": "",
                    },
                ],
            )
        return _Result()


def _split_top_level_sql_defs(definitions: str) -> list[str]:
    parts: list[str] = []
    start = 0
    depth = 0
    for index, char in enumerate(definitions):
        if char == "(":
            depth += 1
        elif char == ")" and depth:
            depth -= 1
        elif char == "," and depth == 0:
            parts.append(definitions[start:index].strip())
            start = index + 1
    tail = definitions[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def _column_names_from_create_table(sql: str) -> list[str]:
    body = sql[sql.index("(") + 1 : sql.rindex(")")]
    names: list[str] = []
    for definition in _split_top_level_sql_defs(body):
        first = definition.split(maxsplit=1)[0].strip("`").lower()
        if first in {
            "primary",
            "key",
            "index",
            "unique",
            "constraint",
            "foreign",
        }:
            continue
        names.append(first)
    return names


class _FreshLazySchemaConn:
    def __init__(self) -> None:
        self.ops: list[str] = []

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def execute(self, sql: str, params=()):
        text = " ".join(str(sql).split())
        self.ops.append(text)
        if text.startswith("SELECT version, name, checksum, status, error FROM schema_migrations"):
            return _Result()
        if text.startswith("CREATE TABLE IF NOT EXISTS "):
            columns = _column_names_from_create_table(text)
            assert len(columns) == len(set(columns))
            return _Result()
        msg = f"unexpected SQL: {text}"
        raise AssertionError(msg)


def test_sslfilter_lazy_fresh_schema_has_unique_columns(monkeypatch) -> None:
    from services.sslfilter_store import SslFilterStore

    conn = _FreshLazySchemaConn()
    store = SslFilterStore()
    monkeypatch.setattr(store, "_connect", lambda: conn)

    store.init_db()

    sslfilter_domains_ddl = next(
        op
        for op in conn.ops
        if op.startswith("CREATE TABLE IF NOT EXISTS sslfilter_domains(")
    )
    assert _column_names_from_create_table(sslfilter_domains_ddl) == [
        "proxy_id",
        "policy",
        "domain",
        "added_ts",
    ]


def test_lazy_store_init_db_skips_hot_path_ddl_when_schema_current(tmp_path, monkeypatch) -> None:
    from services.adblock_artifacts import AdblockArtifactStore
    from services.adblock_store import AdblockStore
    from services.audit_store import AuditStore
    from services.auth_store import AuthStore
    from services.certificate_bundles import CertificateBundleStore
    from services.config_revisions import ConfigRevisionStore
    from services.directory_auth import DirectoryAuthStore
    from services.observability_queries import ObservabilityQueries
    from services.operation_ledger import OperationLedger
    from services.pac_profiles_store import PacProfilesStore
    from services.policy_requests import PolicyRequestStore
    from services.proxy_registry import ProxyRegistry
    from services.safe_browsing_v5 import SafeBrowsingStore
    from services.saml_auth import SamlAuthStore
    from services.sslfilter_store import SslFilterStore

    stores_and_methods = [
        (AdblockStore(lists_dir=str(tmp_path / "adblock")), "init_db"),
        (SslFilterStore(), "init_db"),
        (PacProfilesStore(), "init_db"),
        (PolicyRequestStore(), "init_db"),
        (SafeBrowsingStore(), "init_db"),
        (AuthStore(secret_path=str(tmp_path / "secret.key")), "ensure_schema"),
        (AuditStore(), "init_db"),
        (ConfigRevisionStore(), "init_db"),
        (CertificateBundleStore(), "init_db"),
        (AdblockArtifactStore(compiled_dir=str(tmp_path / "compiled")), "init_db"),
        (ProxyRegistry(), "init_db"),
        (OperationLedger(), "init_db"),
        (DirectoryAuthStore(lambda: "secret"), "ensure_schema"),
        (SamlAuthStore(), "ensure_schema"),
        (ObservabilityQueries(), "_ensure_report_schedule_db"),
    ]
    SafeBrowsingStore._schema_ready = False

    for store, method_name in stores_and_methods:
        conn = _CurrentSchemaConn()
        monkeypatch.setattr(store, "_connect", lambda conn=conn: conn)
        getattr(store, method_name)()
        forbidden = [
            op
            for op in conn.ops
            if "information_schema" in op.lower()
            or op.startswith(("ALTER TABLE", "CREATE TABLE"))
        ]
        assert forbidden == []
