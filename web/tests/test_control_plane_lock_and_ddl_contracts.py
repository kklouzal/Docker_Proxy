"""Contracts for named-lock release, in-transaction DDL and registry heartbeats."""

from __future__ import annotations

from typing import Any, Self

import pymysql
import pytest
from services import observability_maintenance, proxy_recovery_restore
from services import proxy_write_guard as guard
from services.proxy_registry import ProxyRegistry


class _Result:
    def __init__(self, rows: list[Any] | None = None) -> None:
        self._rows = rows or []

    def fetchone(self) -> Any:
        return self._rows[0] if self._rows else None

    def fetchall(self) -> list[Any]:
        return list(self._rows)


class _GuardConn:
    """Minimal pooled-session stand-in for the proxy write guard."""

    native = object()

    def __init__(self, *, tombstone_table: bool = True, fail_release: bool = False):
        self.statements: list[str] = []
        self.tombstone_table = tombstone_table
        self.fail_release = fail_release
        self._discard_on_close = False

    def execute(self, sql: str, params: Any = None) -> _Result:
        text = " ".join(str(sql).split())
        self.statements.append(text)
        if "information_schema.tables" in text:
            return _Result([(1,)] if self.tombstone_table else [])
        if text.startswith("CREATE TABLE"):
            self.tombstone_table = True
            return _Result()
        if "GET_LOCK" in text:
            return _Result([{"acquired": 1}])
        if "RELEASE_LOCK" in text:
            if self.fail_release:
                msg = "release failed"
                raise RuntimeError(msg)
            return _Result()
        if text.startswith("SELECT (SELECT action FROM proxy_lifecycle_tombstones"):
            return _Result(
                [
                    {
                        "tombstone_action": None,
                        "tombstone_target": None,
                        "alias_target": None,
                        "registry_status": "healthy",
                    }
                ]
            )
        msg = f"Unexpected SQL: {text}"
        raise AssertionError(msg)


@pytest.fixture
def fresh_guard() -> Any:
    guard.clear_proxy_write_guard_cache()
    yield
    guard.clear_proxy_write_guard_cache()


def test_write_guard_issues_no_ddl_when_tombstone_table_exists(fresh_guard) -> None:
    # CREATE TABLE IF NOT EXISTS implicitly commits the caller's transaction
    # even when the table exists, so the guard must only probe for it.
    conn = _GuardConn(tombstone_table=True)

    with guard.guarded_proxy_write(conn, "edge-a") as decision:
        assert decision.proxy_id == "edge-a"

    assert not any(sql.startswith("CREATE") for sql in conn.statements)


def test_write_guard_creates_missing_tombstone_table_once(fresh_guard) -> None:
    conn = _GuardConn(tombstone_table=False)

    with guard.guarded_proxy_write(conn, "edge-a"):
        pass
    with guard.guarded_proxy_write(conn, "edge-a"):
        pass

    assert sum(sql.startswith("CREATE TABLE") for sql in conn.statements) == 1


def test_write_guard_discards_session_when_lock_release_fails(fresh_guard) -> None:
    conn = _GuardConn(fail_release=True)

    with guard.guarded_proxy_write(conn, "edge-a"):
        pass

    assert conn._discard_on_close is True


def test_recovery_restore_uses_shared_named_lock_helpers() -> None:
    assert not hasattr(proxy_recovery_restore, "_acquire_lifecycle_lock")
    assert not hasattr(proxy_recovery_restore, "_release_lifecycle_lock")
    assert (
        proxy_recovery_restore.release_mysql_named_lock
        is guard.release_mysql_named_lock
    )


class _RegistryConn:
    def __init__(self, row: dict[str, Any] | None) -> None:
        self.row = row
        self.statements: list[tuple[str, Any]] = []
        self.commits = 0

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: object, *_args: object) -> bool:
        if exc_type is None:
            self.commits += 1
        return False

    def execute(self, sql: str, params: Any = None) -> _Result:
        text = " ".join(str(sql).split())
        self.statements.append((text, params))
        if text.startswith("SELECT action, target_proxy_id FROM proxy_lifecycle"):
            return _Result()
        if text.startswith("SELECT") and "FROM proxy_instances" in text:
            return _Result([self.row] if self.row else [])
        if text.startswith(("UPDATE proxy_instances", "INSERT INTO proxy_instances")):
            return _Result()
        msg = f"Unexpected SQL: {text}"
        raise AssertionError(msg)


def _existing_row() -> dict[str, Any]:
    return {
        "proxy_id": "edge-a",
        "display_name": "Edge A",
        "hostname": "old-host",
        "management_url": "http://edge-a:5000",
        "public_host": "",
        "public_pac_scheme": "http",
        "public_pac_port": 80,
        "public_pac_path": "/proxy.pac",
        "public_http_proxy_port": 3128,
        "status": "healthy",
        "last_heartbeat": 5,
        "last_apply_ts": 7,
        "last_apply_ok": 1,
        "current_config_sha": "a" * 64,
        "detail": "",
        "created_ts": 1,
        "updated_ts": 2,
    }


def _registry_with(monkeypatch, conn: _RegistryConn) -> ProxyRegistry:
    registry = ProxyRegistry()
    monkeypatch.setattr(registry, "init_db", lambda: None)
    connects: list[int] = []

    def _connect() -> _RegistryConn:
        connects.append(1)
        return conn

    monkeypatch.setattr(registry, "_connect", _connect)
    registry.connects = connects  # type: ignore[attr-defined]
    return registry


def test_ensure_not_tombstoned_issues_no_ddl_inside_lifecycle_transactions(
    monkeypatch,
) -> None:
    conn = _RegistryConn(_existing_row())
    registry = _registry_with(monkeypatch, conn)

    registry._ensure_not_tombstoned(conn, "edge-a")

    assert [sql for sql, _ in conn.statements if sql.startswith("CREATE")] == []


def test_heartbeat_is_one_registry_transaction(monkeypatch) -> None:
    conn = _RegistryConn(_existing_row())
    registry = _registry_with(monkeypatch, conn)

    instance = registry.heartbeat(
        "edge-a",
        status="healthy",
        hostname="new-host",
        current_config_sha="b" * 64,
    )

    assert registry.connects == [1]  # type: ignore[attr-defined]
    updates = [
        (sql, params)
        for sql, params in conn.statements
        if sql.startswith("UPDATE proxy_instances")
    ]
    assert len(updates) == 1
    assert instance.hostname == "new-host"
    assert instance.current_config_sha == "b" * 64
    assert instance.last_heartbeat > 5
    assert instance.last_apply_ts == 7


def test_heartbeat_keeps_stored_config_sha_when_none_reported(monkeypatch) -> None:
    conn = _RegistryConn(_existing_row())
    registry = _registry_with(monkeypatch, conn)

    instance = registry.heartbeat("edge-a", current_config_sha="")

    assert instance.current_config_sha == "a" * 64


def test_heartbeat_registers_missing_proxy_with_heartbeat(monkeypatch) -> None:
    conn = _RegistryConn(None)
    registry = _registry_with(monkeypatch, conn)
    monkeypatch.setattr(
        "services.proxy_registry._seed_new_proxy_adblock_runtime_default",
        lambda *_args: None,
    )

    instance = registry.heartbeat("edge-a", current_config_sha="c" * 64)

    assert instance.last_heartbeat > 0
    assert instance.current_config_sha == "c" * 64
    assert registry.connects == [1]  # type: ignore[attr-defined]


def test_maintenance_run_history_insert_is_not_replayed_after_lost_session(
    monkeypatch,
) -> None:
    inserts: list[str] = []

    class Conn:
        def __enter__(self) -> Self:
            return self

        def __exit__(self, *_args: object) -> bool:
            return False

        def execute(self, sql: str, _params: Any = None) -> _Result:
            inserts.append(sql)
            raise pymysql.err.OperationalError(2013, "Lost connection to MySQL")

    monkeypatch.setattr(
        observability_maintenance, "_MAINTENANCE_RUNS_SCHEMA_READY", True
    )
    monkeypatch.setattr(observability_maintenance, "connect", Conn)

    with pytest.raises(pymysql.err.OperationalError):
        observability_maintenance.record_observability_maintenance_run(
            run_type="manual", result={"ok": True}
        )

    assert len(inserts) == 1


def test_stale_connection_classifier_uses_mysql_error_codes() -> None:
    from services.mysql_table_maintenance import looks_like_stale_connection

    assert looks_like_stale_connection(pymysql.err.OperationalError(2013, "x"))
    assert looks_like_stale_connection(pymysql.err.InterfaceError(0, ""))
    # Text that merely mentions an error number is not a lost session.
    assert not looks_like_stale_connection(
        pymysql.err.IntegrityError(1062, "Duplicate entry '2006' for key 'PRIMARY'")
    )
    assert not looks_like_stale_connection(RuntimeError("lost connection 2013"))


def test_recovery_bundle_write_reports_directory_fsync_failure(
    monkeypatch, tmp_path
) -> None:
    # A failed directory fsync means the rename may not be durable; it must
    # surface instead of being silently ignored.
    import errno
    import os
    import stat

    from services import proxy_recovery

    real_fsync = os.fsync

    def fsync(fd: int) -> None:
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError(errno.EIO, "I/O error")
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", fsync)

    with pytest.raises(OSError, match="I/O error"):
        proxy_recovery._atomic_write_private(
            tmp_path / "edge.bundle.json", b"{}", 0o600
        )


def test_recovery_bundle_write_tolerates_unsupported_directory_fsync(
    monkeypatch, tmp_path
) -> None:
    import errno
    import os
    import stat

    from services import proxy_recovery

    real_fsync = os.fsync

    def fsync(fd: int) -> None:
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, "unsupported")
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", fsync)
    target = tmp_path / "edge.bundle.json"

    proxy_recovery._atomic_write_private(target, b"{}", 0o600)

    assert target.read_bytes() == b"{}"
