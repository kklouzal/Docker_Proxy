from __future__ import annotations

import importlib
import sys
from pathlib import Path
from unittest import SkipTest

import pytest

from .mysql_test_utils import configure_test_mysql_env


def _add_web_to_path() -> None:
    web_dir = Path(__file__).resolve().parents[1]
    if str(web_dir) not in sys.path:
        sys.path.insert(0, str(web_dir))


class _Result:
    def __init__(self, rows=(), *, rowcount: int = 0) -> None:
        self._rows = list(rows)
        self.rowcount = rowcount

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return list(self._rows)


class _GuardConn:
    def __init__(self) -> None:
        self.tombstones: dict[str, dict[str, object]] = {}
        self.aliases: dict[str, str] = {}
        self.instances: dict[str, str] = {}
        self.calls: list[str] = []
        self.fail_tombstone = False

    def execute(self, sql, params=()):
        text = " ".join(str(sql).split())
        self.calls.append(text)
        params = tuple(params or ())
        if "CREATE TABLE IF NOT EXISTS proxy_lifecycle_tombstones" in text:
            return _Result()
        if "FROM proxy_lifecycle_tombstones" in text:
            if self.fail_tombstone:
                msg = "metadata offline"
                raise RuntimeError(msg)
            row = self.tombstones.get(str(params[0]))
            return _Result([] if row is None else [row])
        if "FROM proxy_id_aliases" in text:
            target = self.aliases.get(str(params[0]))
            return _Result([] if target is None else [{"proxy_id": target}])
        if "FROM proxy_instances" in text:
            status = self.instances.get(str(params[0]))
            return _Result([] if status is None else [{"status": status}])
        if "GET_LOCK" in text:
            return _Result([{"acquired": 1}])
        if "RELEASE_LOCK" in text:
            return _Result()
        msg = f"Unexpected SQL: {text}"
        raise AssertionError(msg)


def _guard_module(monkeypatch):
    _add_web_to_path()
    from services import proxy_write_guard  # type: ignore

    module = importlib.reload(proxy_write_guard)
    monkeypatch.setattr(module, "table_exists", lambda _conn, name: name in {"proxy_id_aliases", "proxy_instances"})
    module.clear_proxy_write_guard_cache()
    return module


def test_proxy_write_guard_resolves_alias_and_caches_positive_decision(monkeypatch) -> None:
    guard = _guard_module(monkeypatch)
    monkeypatch.setenv("MYSQL_PROXY_WRITE_GUARD_CACHE_SECONDS", "30")
    conn = _GuardConn()
    conn.instances["edge-new"] = "healthy"
    conn.tombstones["edge-old"] = {
        "action": "renamed",
        "target_proxy_id": "edge-new",
    }

    first = guard.resolve_proxy_write_id(conn, "edge-old", use_cache=True)
    calls_after_first = len(conn.calls)
    second = guard.resolve_proxy_write_id(conn, "edge-old", use_cache=True)

    assert first.proxy_id == "edge-new"
    assert first.resolved_alias is True
    assert second == first
    assert len(conn.calls) == calls_after_first


def test_proxy_write_guard_cache_invalidates_and_expires(monkeypatch) -> None:
    guard = _guard_module(monkeypatch)
    monkeypatch.setenv("MYSQL_PROXY_WRITE_GUARD_CACHE_SECONDS", "30")
    conn = _GuardConn()
    conn.instances["edge-a"] = "healthy"

    assert guard.resolve_proxy_write_id(conn, "edge-a", use_cache=True).proxy_id == "edge-a"
    guard.clear_proxy_write_guard_cache("edge-a")
    conn.tombstones["edge-a"] = {"action": "removing", "target_proxy_id": ""}
    with pytest.raises(guard.ProxyLifecycleWriteError, match=r"removed|removing"):
        guard.resolve_proxy_write_id(conn, "edge-a", use_cache=True)

    monkeypatch.setenv("MYSQL_PROXY_WRITE_GUARD_CACHE_SECONDS", "0")
    guard.clear_proxy_write_guard_cache()
    conn.tombstones.clear()
    assert guard.resolve_proxy_write_id(conn, "edge-a", use_cache=True).proxy_id == "edge-a"
    conn.tombstones["edge-a"] = {"action": "removing", "target_proxy_id": ""}
    with pytest.raises(guard.ProxyLifecycleWriteError):
        guard.resolve_proxy_write_id(conn, "edge-a", use_cache=True)


def test_proxy_write_guard_fails_closed_for_metadata_errors(monkeypatch) -> None:
    guard = _guard_module(monkeypatch)
    conn = _GuardConn()
    conn.instances["edge-a"] = "healthy"
    conn.fail_tombstone = True

    with pytest.raises(guard.ProxyLifecycleWriteError, match="unavailable"):
        guard.resolve_proxy_write_id(conn, "edge-a")


def test_guarded_proxy_write_rechecks_after_lifecycle_lock(monkeypatch) -> None:
    guard = _guard_module(monkeypatch)
    conn = _GuardConn()
    conn.native = object()
    conn.instances["edge-a"] = "healthy"

    with guard.guarded_proxy_write(conn, "edge-a") as decision:
        assert decision.proxy_id == "edge-a"

    assert any("GET_LOCK" in call for call in conn.calls)
    assert any("RELEASE_LOCK" in call for call in conn.calls)


def _fresh_mysql_modules(tmp_path: Path):
    configure_test_mysql_env(tmp_path, secret_path=tmp_path / "flask_secret.key")
    _add_web_to_path()
    from services import (
        config_revisions,  # type: ignore
        operation_ledger,  # type: ignore
        proxy_registry,  # type: ignore
    )

    return (
        importlib.reload(proxy_registry),
        importlib.reload(config_revisions),
        importlib.reload(operation_ledger),
    )


@pytest.mark.integration
@pytest.mark.mysql
def test_mysql_lifecycle_write_guard_aliases_and_stale_rejection(tmp_path: Path) -> None:
    try:
        proxy_registry, config_revisions, operation_ledger = _fresh_mysql_modules(tmp_path / "mysql-lifecycle-guard")
    except SkipTest as exc:
        pytest.skip(str(exc))

    registry = proxy_registry.ProxyRegistry()
    registry.ensure_proxy("edge-old")
    config_store = config_revisions.ConfigRevisionStore()
    ledger = operation_ledger.OperationLedger()

    before = config_store.create_revision("edge-old", "before\n", created_by="pytest")
    assert before.proxy_id == "edge-old"

    registry.rename_proxy("edge-old", "edge-new", display_name="Edge New")

    after = config_store.create_revision("edge-old", "after\n", created_by="pytest")
    queued = ledger.create_operation(
        "edge-old",
        operation_type="sync",
        subject="config",
        summary="alias should canonicalize",
    )
    assert after.proxy_id == "edge-new"
    assert queued.proxy_id == "edge-new"

    with registry._connect() as conn:
        conn.execute(
            "UPDATE proxy_instances SET status='renaming' WHERE proxy_id=%s",
            ("edge-new",),
        )
        conn.execute(
            "INSERT INTO proxy_lifecycle_tombstones(proxy_id, action, target_proxy_id, detail, created_ts, updated_ts) VALUES(%s,'renaming',%s,'test',1,1) ON DUPLICATE KEY UPDATE action=VALUES(action), target_proxy_id=VALUES(target_proxy_id)",
            ("edge-new", "edge-final"),
        )
    with pytest.raises(config_revisions.ProxyLifecycleWriteError if hasattr(config_revisions, "ProxyLifecycleWriteError") else ValueError):
        config_store.create_revision("edge-new", "blocked\n", created_by="pytest")

    with registry._connect() as conn:
        conn.execute("DELETE FROM proxy_lifecycle_tombstones WHERE proxy_id=%s", ("edge-new",))
        conn.execute("UPDATE proxy_instances SET status='unknown' WHERE proxy_id=%s", ("edge-new",))

    registry.remove_proxy("edge-new")

    with pytest.raises(ValueError):
        config_store.create_revision("edge-new", "removed\n", created_by="pytest")
    with pytest.raises(ValueError):
        config_store.create_revision("edge-old", "stale alias\n", created_by="pytest")

    with registry._connect() as conn:
        rows = conn.execute(
            "SELECT proxy_id, COUNT(*) AS c FROM proxy_config_revisions GROUP BY proxy_id",
        ).fetchall()
    assert rows == []
