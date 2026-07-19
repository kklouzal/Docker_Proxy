from __future__ import annotations

import sys
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
