from __future__ import annotations

import ast
from pathlib import Path

import pytest
from services import (  # type: ignore
    adblock_artifacts,
    auth_store,
    blocked_log_runtime,
    operation_ledger,
    schema_lifecycle,
)


class _Connection:
    def __init__(self) -> None:
        self.executed: list[str] = []
        self.closed = False
        self.native = object()

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def execute(self, sql, params=None):
        self.executed.append(str(sql))

    def close(self) -> None:
        self.closed = True


@pytest.mark.parametrize(
    ("store", "initialize"),
    [
        (auth_store.AuthStore(), "ensure_schema"),
        (adblock_artifacts.AdblockArtifactStore(), "init_db"),
    ],
    ids=["same-connection-ddl", "second-connection-ddl"],
)
def test_lazy_store_readiness_fault_prevents_ddl_and_cache_publication(
    monkeypatch, store, initialize
) -> None:
    conn = _Connection()
    readiness_error = RuntimeError("migration ledger unavailable")
    connect_calls = 0

    def fake_connect():
        nonlocal connect_calls
        connect_calls += 1
        return conn

    def fail_readiness(_conn):
        raise readiness_error

    monkeypatch.setattr(store, "_connect", fake_connect)
    monkeypatch.setattr(
        schema_lifecycle,
        "runtime_schema_ready_for_lazy_store",
        fail_readiness,
    )

    with pytest.raises(RuntimeError, match="migration ledger unavailable") as caught:
        getattr(store, initialize)()

    assert caught.value is readiness_error
    assert conn.executed == []
    assert connect_calls == 1
    assert store._schema_ready is False


def test_operation_ledger_readiness_fault_is_not_reclassified_as_false(
    monkeypatch,
) -> None:
    ledger = operation_ledger.OperationLedger()
    conn = _Connection()
    readiness_error = RuntimeError("migration ledger unavailable")

    def fail_readiness(_conn):
        raise readiness_error

    monkeypatch.setattr(
        schema_lifecycle,
        "runtime_schema_ready_for_lazy_store",
        fail_readiness,
    )

    with pytest.raises(RuntimeError, match="migration ledger unavailable") as caught:
        ledger._schema_current_on_connection(conn)

    assert caught.value is readiness_error
    assert conn.executed == []
    assert ledger._schema_ready is False


def test_blocked_log_readiness_fault_closes_without_ddl_or_connection_adoption(
    monkeypatch,
) -> None:
    db = blocked_log_runtime.BlockedLogDb()
    conn = _Connection()
    readiness_error = RuntimeError("migration ledger unavailable")

    monkeypatch.setattr(blocked_log_runtime, "connect", lambda: conn)

    def fail_readiness(_conn):
        raise readiness_error

    monkeypatch.setattr(
        schema_lifecycle,
        "runtime_schema_ready_for_lazy_store",
        fail_readiness,
    )

    with pytest.raises(RuntimeError, match="migration ledger unavailable") as caught:
        db._connect()

    assert caught.value is readiness_error
    assert conn.executed == []
    assert conn.closed is True
    assert db._conn is None


def test_production_readiness_calls_are_not_inside_exception_handlers() -> None:
    services_dir = Path(__file__).parents[1] / "services"
    callers: set[str] = set()

    for path in services_dir.glob("*.py"):
        if path.name == "schema_lifecycle.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        parents: dict[ast.AST, ast.AST] = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                parents[child] = parent
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "runtime_schema_ready_for_lazy_store"
            ):
                continue
            callers.add(path.name)
            ancestor = parents.get(node)
            while ancestor is not None:
                if isinstance(ancestor, ast.Try):
                    assert all(
                        any(isinstance(item, ast.Raise) for item in ast.walk(handler))
                        for handler in ancestor.handlers
                    ), (
                        f"{path}: readiness fault can still fall through exception handling"
                    )
                ancestor = parents.get(ancestor)

    assert callers == {
        "adblock_artifacts.py",
        "adblock_store.py",
        "audit_store.py",
        "auth_store.py",
        "blocked_log_runtime.py",
        "certificate_bundles.py",
        "config_revisions.py",
        "diagnostic_store.py",
        "directory_auth.py",
        "live_stats.py",
        "observability_maintenance.py",
        "observability_queries.py",
        "operation_ledger.py",
        "pac_profiles_store.py",
        "policy_requests.py",
        "proxy_registry.py",
        "safe_browsing_v5.py",
        "saml_auth.py",
        "ssl_errors_store.py",
        "sslfilter_store.py",
        "timeseries_store.py",
        "webfilter_core.py",
    }
