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
    specs = schema_lifecycle._migration_specs()
    versions = [spec.version for spec in specs]
    names = {spec.name for spec in specs}

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
    } <= names
    assert schema_lifecycle.latest_schema_version() == 17
    assert specs[-2].version == 16
    assert specs[-2].name == "control_plane_identity"
    assert specs[-1].version == 17
    assert specs[-1].name == "proxy_recovery_adoptions"
    assert schema_lifecycle.latest_schema_checksum() == specs[-1].checksum
    assert specs[-2].tables[0].table == "control_plane_identity"
    assert "control_plane_id CHAR(36) NOT NULL" in specs[-2].tables[0].create_sql
    assert specs[-1].tables[0].table == "proxy_recovery_adoptions"
    assert "proxy_id VARCHAR(64) NOT NULL" in specs[-1].tables[0].create_sql
    assert "PRIMARY KEY(proxy_id, target_control_plane_id)" in specs[-1].tables[0].create_sql


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
