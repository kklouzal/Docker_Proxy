from __future__ import annotations

import sys
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Iterable

WEB_DIR = Path(__file__).resolve().parents[1]
if str(WEB_DIR) not in sys.path:
    sys.path.insert(0, str(WEB_DIR))

from services import audit_store, schema_lifecycle  # type: ignore  # noqa: E402
from services.audit_store import AuditStore  # type: ignore  # noqa: E402


class _FakeResult:
    def __init__(self, rows: Iterable[object] = (), rowcount: int = 0) -> None:
        self._rows = list(rows)
        self.rowcount = rowcount

    def fetchall(self) -> list[object]:
        return list(self._rows)


class _FakeAuditConnection:
    def __init__(self, rows: list[dict[str, object]]) -> None:
        self.rows = rows

    def __enter__(self):
        return self

    def __exit__(self, *_exc: object) -> bool:
        return False

    def execute(
        self, sql: str, params: tuple[object, ...] | None = None
    ) -> _FakeResult:
        compact_sql = " ".join(str(sql).split())
        params = tuple(params or ())
        if compact_sql.startswith("SELECT DISTINCT proxy_id FROM audit_events"):
            return _FakeResult(
                {"proxy_id": proxy_id}
                for proxy_id in sorted({str(row["proxy_id"]) for row in self.rows})
            )
        if compact_sql.startswith("SELECT ts, id FROM audit_events WHERE proxy_id=%s"):
            proxy_id = str(params[0])
            limit = int(params[1])
            matching = [row for row in self.rows if row["proxy_id"] == proxy_id]
            matching.sort(
                key=lambda row: (int(row["ts"]), int(row["id"])), reverse=True
            )
            return _FakeResult(dict(row) for row in matching[:limit])
        if compact_sql.startswith("DELETE FROM `audit_events` WHERE proxy_id = %s"):
            proxy_id = str(params[0])
            boundary_ts = int(params[1])
            tie_ts = int(params[2])
            boundary_id = int(params[3])
            limit = int(params[4])
            delete_indexes = [
                index
                for index, row in enumerate(self.rows)
                if row["proxy_id"] == proxy_id
                and (
                    int(row["ts"]) < boundary_ts
                    or (int(row["ts"]) == tie_ts and int(row["id"]) < boundary_id)
                )
            ]
            delete_indexes.sort(
                key=lambda index: (
                    self.rows[index]["proxy_id"],
                    int(self.rows[index]["ts"]),
                    int(self.rows[index]["id"]),
                )
            )
            delete_indexes = delete_indexes[:limit]
            for index in reversed(delete_indexes):
                self.rows.pop(index)
            return _FakeResult(rowcount=len(delete_indexes))
        msg = f"Unexpected SQL: {compact_sql!r} params={params!r}"
        raise AssertionError(msg)


def _store_with_rows(rows: list[dict[str, object]]) -> AuditStore:
    store = AuditStore.__new__(AuditStore)
    store._schema_ready = True
    store._connect = lambda: _FakeAuditConnection(rows)  # type: ignore[method-assign]
    return store


class _SchemaInitResult:
    def __init__(self, rows: Iterable[object] = ()) -> None:
        self._rows = list(rows)

    def fetchone(self) -> object | None:
        return self._rows[0] if self._rows else None

    def fetchall(self) -> list[object]:
        return list(self._rows)


class _SchemaInitConnection:
    def __init__(
        self,
        *,
        migration_status: str | None = None,
        migration_checksum: str | None = None,
        probe_error: Exception | None = None,
    ) -> None:
        self.migration_status = migration_status
        self.migration_checksum = migration_checksum
        self.probe_error = probe_error
        self.ops: list[str] = []

    def __enter__(self):
        return self

    def __exit__(self, *_exc: object) -> bool:
        return False

    def execute(self, sql: str, params=()) -> _SchemaInitResult:
        text = " ".join(str(sql).split())
        self.ops.append(text)
        if text.startswith(
            "SELECT version, name, checksum, status, error FROM schema_migrations"
        ):
            if self.probe_error is not None:
                raise self.probe_error
            rows = []
            if self.migration_status is not None:
                rows = [
                    {
                        "version": spec.version,
                        "checksum": (
                            self.migration_checksum
                            if spec.version == schema_lifecycle._SCHEMA_VERSION
                            else spec.checksum
                        ),
                        "status": (
                            self.migration_status
                            if spec.version == schema_lifecycle._SCHEMA_VERSION
                            else "applied"
                        ),
                    }
                    for spec in schema_lifecycle._migration_specs()
                ]
            return _SchemaInitResult(rows)
        if text.startswith("CREATE TABLE IF NOT EXISTS audit_events"):
            return _SchemaInitResult()
        msg = f"Unexpected schema-init SQL: {text!r} params={tuple(params or ())!r}"
        raise AssertionError(msg)


def _patch_schema_fallback_index(monkeypatch) -> list[tuple[object, str, str, str]]:
    calls: list[tuple[object, str, str, str]] = []

    def record_index(conn, *, table_name: str, index_name: str, ddl: str) -> None:
        calls.append((conn, table_name, index_name, ddl))

    monkeypatch.setattr(audit_store, "ensure_index", record_index)
    return calls


def test_init_db_skips_runtime_ddl_when_lifecycle_schema_is_current(
    monkeypatch,
) -> None:
    conn = _SchemaInitConnection(
        migration_status="applied",
        migration_checksum=schema_lifecycle.latest_schema_checksum(),
    )
    store = AuditStore()
    monkeypatch.setattr(store, "_connect", lambda: conn)
    index_calls = _patch_schema_fallback_index(monkeypatch)

    store.init_db()

    assert store._schema_ready is True
    assert len(conn.ops) == 1
    assert "schema_migrations" in conn.ops[0]
    assert index_calls == []


def test_init_db_uses_runtime_ddl_when_lifecycle_schema_checksum_has_drifted(
    monkeypatch,
) -> None:
    conn = _SchemaInitConnection(
        migration_status="applied",
        migration_checksum="0" * 64,
    )
    store = AuditStore()
    monkeypatch.setattr(store, "_connect", lambda: conn)
    index_calls = _patch_schema_fallback_index(monkeypatch)

    store.init_db()

    assert store._schema_ready is True
    assert "schema_migrations" in conn.ops[0]
    assert any(
        op.startswith("CREATE TABLE IF NOT EXISTS audit_events") for op in conn.ops
    )
    assert len(index_calls) == 1


def test_init_db_uses_runtime_ddl_when_lifecycle_schema_is_not_current(
    monkeypatch,
) -> None:
    conn = _SchemaInitConnection()
    store = AuditStore()
    monkeypatch.setattr(store, "_connect", lambda: conn)
    index_calls = _patch_schema_fallback_index(monkeypatch)

    store.init_db()

    assert store._schema_ready is True
    assert "schema_migrations" in conn.ops[0]
    assert any(
        op.startswith("CREATE TABLE IF NOT EXISTS audit_events") for op in conn.ops
    )
    assert index_calls == [
        (
            conn,
            "audit_events",
            "idx_audit_ts_id",
            "ALTER TABLE audit_events ADD INDEX idx_audit_ts_id (ts, id)",
        )
    ]


def test_init_db_fails_closed_when_lifecycle_helper_is_unavailable(
    monkeypatch,
) -> None:
    conn = _SchemaInitConnection()
    store = AuditStore()
    monkeypatch.setattr(store, "_connect", lambda: conn)
    monkeypatch.setitem(sys.modules, "services.schema_lifecycle", None)
    with pytest.raises(ModuleNotFoundError):
        store.init_db()

    assert store._schema_ready is False
    assert conn.ops == []


def test_init_db_propagates_lifecycle_probe_failure_without_runtime_ddl(
    monkeypatch,
) -> None:
    probe_error = RuntimeError("schema readiness query failed")
    conn = _SchemaInitConnection(probe_error=probe_error)
    store = AuditStore()
    monkeypatch.setattr(store, "_connect", lambda: conn)
    index_calls = _patch_schema_fallback_index(monkeypatch)

    with pytest.raises(RuntimeError) as caught:
        store.init_db()

    assert caught.value is probe_error
    assert store._schema_ready is False
    assert len(conn.ops) == 1
    assert "schema_migrations" in conn.ops[0]
    assert not any(op.startswith(("CREATE TABLE", "ALTER TABLE")) for op in conn.ops)
    assert index_calls == []


def test_prune_to_last_events_preserves_quiet_proxy_when_another_proxy_is_noisy() -> (
    None
):
    rows = [
        {"id": 1, "proxy_id": "quiet", "ts": 10, "kind": "config_apply_manual"},
        {"id": 2, "proxy_id": "quiet", "ts": 20, "kind": "config_apply_manual"},
        {"id": 10, "proxy_id": "noisy", "ts": 100, "kind": "probe"},
        {"id": 11, "proxy_id": "noisy", "ts": 110, "kind": "probe"},
        {"id": 12, "proxy_id": "noisy", "ts": 120, "kind": "probe"},
        {"id": 13, "proxy_id": "noisy", "ts": 130, "kind": "probe"},
    ]
    store = _store_with_rows(rows)

    deleted = store._prune_to_last_events(max_events=3, max_rows=50)

    assert deleted == 1
    assert [row["id"] for row in rows if row["proxy_id"] == "quiet"] == [1, 2]
    assert [row["id"] for row in rows if row["proxy_id"] == "noisy"] == [11, 12, 13]


def test_prune_to_last_events_bounds_old_events_within_same_proxy() -> None:
    rows = [
        {"id": 1, "proxy_id": "quiet", "ts": 10, "kind": "config_apply_manual"},
        {"id": 2, "proxy_id": "quiet", "ts": 20, "kind": "config_apply_manual"},
        {"id": 3, "proxy_id": "quiet", "ts": 30, "kind": "config_apply_manual"},
        {"id": 4, "proxy_id": "quiet", "ts": 40, "kind": "config_apply_manual"},
        {"id": 10, "proxy_id": "noisy", "ts": 100, "kind": "probe"},
        {"id": 11, "proxy_id": "noisy", "ts": 110, "kind": "probe"},
        {"id": 12, "proxy_id": "noisy", "ts": 120, "kind": "probe"},
    ]
    store = _store_with_rows(rows)

    deleted = store._prune_to_last_events(max_events=2, max_rows=50)

    assert deleted == 3
    assert [row["id"] for row in rows if row["proxy_id"] == "quiet"] == [3, 4]
    assert [row["id"] for row in rows if row["proxy_id"] == "noisy"] == [11, 12]


def test_record_does_not_report_committed_event_failed_when_prune_fails(
    monkeypatch,
    caplog,
) -> None:
    executed: list[tuple[str, tuple[object, ...]]] = []

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_exc: object) -> bool:
            return False

        def execute(self, sql: str, params: tuple[object, ...]) -> _FakeResult:
            executed.append((" ".join(sql.split()), params))
            return _FakeResult(rowcount=1)

    @contextmanager
    def unguarded(_conn, proxy_id: str):
        yield type("Guard", (), {"proxy_id": proxy_id})()

    store = AuditStore()
    store._schema_ready = True
    monkeypatch.setattr(store, "_connect", Connection)
    monkeypatch.setattr(audit_store, "guarded_proxy_write", unguarded)
    monkeypatch.setattr(audit_store, "get_proxy_id", lambda: "edge-a")
    monkeypatch.setattr(
        store,
        "_prune_to_last_events",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("prune unavailable")),
    )

    with caplog.at_level("ERROR", logger="services.audit_store"):
        store.record("config_apply_manual", ok=True)

    assert len(executed) == 1
    assert executed[0][0].startswith("INSERT INTO audit_events")
    assert executed[0][1][0] == "edge-a"
    assert "event was recorded" in caplog.text
    assert "prune unavailable" in caplog.text
