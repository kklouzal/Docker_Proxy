from __future__ import annotations

import pytest

POLICY_SHA = "a" * 64


class _Result:
    def __init__(self, rows=None) -> None:
        self._rows = list(rows or [])
        self.rowcount = len(self._rows)
        self.lastrowid = None

    def fetchall(self):
        return list(self._rows)

    def fetchone(self):
        return self._rows[0] if self._rows else None


def _operation_row(**overrides):
    base = {
        "id": 11,
        "proxy_id": "edge-a",
        "status": "pending",
        "operation_type": "config_apply",
        "subject": "Squid config",
        "summary": "Apply revision",
        "target_kind": "config_revision",
        "target_ref": "42",
        "rollback_kind": "",
        "rollback_ref": "",
        "request_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "request_key": "".rjust(64, "a"),
        "detail": "",
        "created_by": "admin",
        "created_ts": 123,
        "started_ts": 0,
        "completed_ts": 0,
        "updated_ts": 123,
        "stale_requeue_count": 0,
        "force_sync": 0,
        "claim_token": "",
    }
    base.update(overrides)
    return base


class _Connection:
    def __init__(self) -> None:
        self.queries = []
        self.committed = False

    def execute(self, sql, params=()):
        compact = " ".join(str(sql).split())
        params = tuple(params or ())
        self.queries.append((compact, params))
        if compact.startswith("SELECT proxy_id FROM proxy_operations"):
            return _Result([{"proxy_id": "edge-a"}])
        if compact.startswith("SELECT id FROM proxy_operations"):
            return _Result([{"id": 7}, {"id": 8}])
        if (
            compact.startswith("SELECT id, proxy_id, status")
            and "claim_token=%s" in compact
        ):
            base = {
                "proxy_id": "edge-a",
                "status": "applying",
                "operation_type": "sync",
                "subject": "",
                "summary": "",
                "target_kind": "",
                "target_ref": "",
                "rollback_kind": "",
                "rollback_ref": "",
                "request_hash": "",
                "request_key": "".rjust(64, "b"),
                "detail": "",
                "created_by": "",
                "started_ts": 2,
                "completed_ts": 0,
                "updated_ts": 2,
                "force_sync": 0,
                "claim_token": "claim-0",
            }
            return _Result(
                [dict(base, id=7, created_ts=1), dict(base, id=8, created_ts=2)],
            )
        if compact.startswith("SELECT id, proxy_id, status"):
            return _Result([_operation_row(id=int(params[0] or 0))])
        return _Result()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is None:
            self.committed = True
        return False


class _LifecycleConnection:
    native = object()

    def __init__(
        self,
        *,
        aliases: dict[str, str] | None = None,
        tombstones: dict[str, tuple[str, str]] | None = None,
        registry: dict[str, str] | None = None,
    ) -> None:
        self.aliases = dict(aliases or {})
        self.tombstones = dict(tombstones or {})
        self.registry = dict(registry or {"edge-a": "active"})
        self.queries = []
        self.committed = False

    def execute(self, sql, params=()):
        compact = " ".join(str(sql).split())
        params = tuple(params or ())
        self.queries.append((compact, params))
        lifecycle_result = self._execute_lifecycle(compact, params)
        if lifecycle_result is not None:
            return lifecycle_result
        return self._execute_operation(compact, params)

    def _execute_lifecycle(self, compact: str, params: tuple[object, ...]):
        if compact.startswith("CREATE TABLE IF NOT EXISTS proxy_lifecycle_tombstones"):
            return _Result()
        if compact.startswith("SELECT 1 FROM information_schema.tables"):
            return _Result([{"1": 1}])
        if compact.startswith(
            "SELECT action, target_proxy_id FROM proxy_lifecycle_tombstones",
        ):
            row = self.tombstones.get(str(params[0]))
            if row is None:
                return _Result()
            action, target = row
            return _Result([{"action": action, "target_proxy_id": target}])
        if compact.startswith("SELECT proxy_id FROM proxy_id_aliases"):
            target = self.aliases.get(str(params[0]))
            if target is None:
                return _Result()
            return _Result([{"proxy_id": target}])
        if compact.startswith("SELECT status FROM proxy_instances"):
            status = self.registry.get(str(params[0]))
            if status is None:
                return _Result()
            return _Result([{"status": status}])
        if compact.startswith("SELECT GET_LOCK"):
            return _Result([{"acquired": 1}])
        if compact.startswith("DO RELEASE_LOCK"):
            return _Result()
        return None

    def _execute_operation(self, compact: str, params: tuple[object, ...]):
        return _Result()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is None:
            self.committed = True
        return False


class _RetentionConnection:
    def __init__(self, rows: list[dict[str, object]]) -> None:
        self.rows = {int(row["id"]): dict(row) for row in rows}
        self.queries: list[tuple[str, tuple[object, ...]]] = []

    def execute(self, sql, params=()):
        compact = " ".join(str(sql).split())
        params = tuple(params or ())
        self.queries.append((compact, params))
        if compact.startswith("SELECT DISTINCT proxy_id FROM proxy_operations"):
            proxies = sorted({str(row["proxy_id"]) for row in self.rows.values()})
            return _Result([{"proxy_id": proxy_id} for proxy_id in proxies])
        if compact.startswith("SELECT candidate.id AS victim_id"):
            proxy_id, protected_id, limit = params
            proxy_rows = [
                row for row in self.rows.values() if row["proxy_id"] == proxy_id
            ]
            active_count = sum(
                row["status"] in {"pending", "applying"} for row in proxy_rows
            )
            terminals = sorted(
                (
                    row
                    for row in proxy_rows
                    if row["status"] in {"applied", "superseded", "failed"}
                ),
                key=lambda row: (int(row["updated_ts"]), int(row["id"])),
                reverse=True,
            )
            keep_terminal = max(0, int(limit) - active_count)
            victims = {
                int(row["id"])
                for row in terminals[keep_terminal:]
                if int(row["id"]) != int(protected_id)
            }
            return _Result([{"victim_id": row_id} for row_id in sorted(victims)])
        if compact.startswith("DELETE FROM proxy_operations"):
            proxy_id, *victim_ids = params
            victims = {
                int(row_id)
                for row_id in victim_ids
                if int(row_id) in self.rows
                and self.rows[int(row_id)]["proxy_id"] == proxy_id
                and self.rows[int(row_id)]["status"]
                in {"applied", "superseded", "failed"}
            }
            for row_id in victims:
                del self.rows[row_id]
            result = _Result()
            result.rowcount = len(victims)
            return result
        return _Result()


def _retention_rows(
    proxy_id: str,
    count: int,
    *,
    status: str = "applied",
    first_id: int = 1,
    updated_ts: int | None = None,
) -> list[dict[str, object]]:
    return [
        _operation_row(
            id=first_id + offset,
            proxy_id=proxy_id,
            status=status,
            updated_ts=updated_ts if updated_ts is not None else first_id + offset,
        )
        for offset in range(count)
    ]


def test_retention_sql_avoids_mysql_1093_target_table_delete() -> None:
    from services.operation_ledger import OperationLedger

    conn = _RetentionConnection(_retention_rows("edge-a", 129))

    assert OperationLedger()._prune_proxy_history(conn, "edge-a") == 1
    statements = [sql for sql, _params in conn.queries]
    assert statements[0].startswith("SELECT candidate.id AS victim_id")
    assert statements[0].endswith("FOR UPDATE")
    assert statements[1].startswith("DELETE FROM proxy_operations")
    assert "JOIN (" not in statements[1]


def test_retention_keeps_exactly_128_terminal_operations() -> None:
    from services.operation_ledger import OperationLedger

    conn = _RetentionConnection(_retention_rows("edge-a", 128))

    assert OperationLedger()._prune_proxy_history(conn, "edge-a") == 0
    assert len(conn.rows) == 128


def test_retention_permanently_deletes_129th_terminal_with_deterministic_ties() -> None:
    from services.operation_ledger import OperationLedger

    conn = _RetentionConnection(
        _retention_rows("edge-a", 129, updated_ts=500),
    )

    assert OperationLedger()._prune_proxy_history(conn, "edge-a") == 1
    assert set(conn.rows) == set(range(2, 130))


def test_retention_protects_active_rows_and_converges_after_they_finish() -> None:
    from services.operation_ledger import OperationLedger

    rows = [
        *_retention_rows("edge-a", 129, status="pending"),
        *_retention_rows("edge-a", 3, first_id=1000),
    ]
    conn = _RetentionConnection(rows)
    ledger = OperationLedger()

    assert ledger._prune_proxy_history(conn, "edge-a") == 3
    assert len(conn.rows) == 129
    assert all(row["status"] == "pending" for row in conn.rows.values())

    conn.rows[1]["status"] = "applied"
    conn.rows[1]["updated_ts"] = 2000
    assert (
        ledger._prune_proxy_history(
            conn,
            "edge-a",
            protected_operation_id=1,
        )
        == 0
    )
    assert len(conn.rows) == 129
    assert 1 in conn.rows

    conn.rows[2]["status"] = "applied"
    conn.rows[2]["updated_ts"] = 2001
    assert (
        ledger._prune_proxy_history(
            conn,
            "edge-a",
            protected_operation_id=2,
        )
        == 1
    )
    assert len(conn.rows) == 128
    assert 1 not in conn.rows
    assert 2 in conn.rows


def test_retention_is_per_proxy_and_preexisting_oversized_ledgers_converge() -> None:
    from services.operation_ledger import OperationLedger

    rows = [
        *_retention_rows("edge-a", 140),
        *_retention_rows("edge-b", 135, first_id=1000),
    ]
    conn = _RetentionConnection(rows)

    assert OperationLedger()._prune_all_history(conn) == 19
    assert sum(row["proxy_id"] == "edge-a" for row in conn.rows.values()) == 128
    assert sum(row["proxy_id"] == "edge-b" for row in conn.rows.values()) == 128


def test_create_prunes_in_transaction_after_idempotent_upsert(monkeypatch) -> None:
    from services.operation_ledger import OperationLedger

    class _CreateConnection(_Connection):
        def execute(self, sql, params=()):
            compact = " ".join(str(sql).split())
            params = tuple(params or ())
            self.queries.append((compact, params))
            if compact.startswith("INSERT INTO proxy_operations"):
                result = _Result()
                result.lastrowid = 11
                return result
            if compact.startswith("SELECT id, proxy_id, status"):
                return _Result([_operation_row(id=11)])
            return _Result()

    conn = _CreateConnection()
    ledger = OperationLedger()
    monkeypatch.setattr(ledger, "init_db", lambda: None)
    monkeypatch.setattr(ledger, "_connect", lambda: conn)
    monkeypatch.setattr(
        ledger, "_prune_proxy_history", lambda _conn, proxy, **_kwargs: 0
    )
    monkeypatch.setattr("services.operation_ledger.time.time", lambda: 123)

    operation = ledger.create_operation(
        "edge-a",
        operation_type="config_apply",
        subject="Squid config",
        summary="Apply revision",
        target_kind="config_revision",
        target_ref=42,
        request_hash="a" * 64,
    )

    assert operation.operation_id == 11
    sql = [query for query, _params in conn.queries]
    assert sql[0].startswith("INSERT INTO proxy_operations")
    assert sql[-1].startswith("SELECT id, proxy_id, status")
    assert conn.committed is True


def test_mark_terminal_prunes_before_returning_retained_row(monkeypatch) -> None:
    from services.operation_ledger import OperationLedger

    conn = _Connection()
    ledger = OperationLedger()
    prune_calls: list[str] = []
    monkeypatch.setattr(ledger, "init_db", lambda: None)
    monkeypatch.setattr(ledger, "_connect", lambda: conn)
    monkeypatch.setattr(
        ledger,
        "_prune_proxy_history",
        lambda _conn, proxy, **_kwargs: prune_calls.append(proxy) or 0,
    )
    monkeypatch.setattr("services.operation_ledger.time.time", lambda: 456)

    operation = ledger.mark_status(7, status="applied")

    assert operation is not None
    assert operation.operation_id == 7
    assert prune_calls == ["edge-a"]


def test_create_prune_failure_rolls_back_and_returns_no_operation(monkeypatch) -> None:
    from services.operation_ledger import OperationLedger

    class _FailingCreateConnection(_Connection):
        def __init__(self) -> None:
            super().__init__()
            self.rolled_back = False

        def execute(self, sql, params=()):
            compact = " ".join(str(sql).split())
            params = tuple(params or ())
            self.queries.append((compact, params))
            if compact.startswith("INSERT INTO proxy_operations"):
                result = _Result()
                result.lastrowid = 11
                return result
            return _Result()

        def __exit__(self, exc_type, exc, tb):
            if exc_type is None:
                self.committed = True
            else:
                self.rolled_back = True
            return False

    conn = _FailingCreateConnection()
    ledger = OperationLedger()
    monkeypatch.setattr(ledger, "init_db", lambda: None)
    monkeypatch.setattr(ledger, "_connect", lambda: conn)
    monkeypatch.setattr(
        ledger,
        "_prune_proxy_history",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("prune failed")),
    )
    monkeypatch.setattr("services.operation_ledger.time.time", lambda: 123)

    with pytest.raises(RuntimeError, match="prune failed"):
        ledger.create_operation(
            "edge-a",
            operation_type="config_apply",
            subject="Squid config",
            summary="Apply revision",
            target_kind="config_revision",
            target_ref=42,
            request_hash="a" * 64,
        )

    assert conn.committed is False
    assert conn.rolled_back is True


def test_create_commits_prune_before_releasing_proxy_guard(monkeypatch) -> None:
    from contextlib import contextmanager
    from types import SimpleNamespace

    from services.operation_ledger import OperationLedger

    class _NativeCreateConnection(_Connection):
        native = object()

        def __init__(self) -> None:
            super().__init__()
            self.events: list[str] = []

        def execute(self, sql, params=()):
            compact = " ".join(str(sql).split())
            params = tuple(params or ())
            self.queries.append((compact, params))
            if compact.startswith("INSERT INTO proxy_operations"):
                result = _Result()
                result.lastrowid = 11
                return result
            if compact.startswith("SELECT id, proxy_id, status"):
                return _Result([_operation_row(id=11)])
            return _Result()

        def commit(self):
            self.events.append("commit")

    @contextmanager
    def observed_guard(_conn, proxy_id, **_kwargs):
        try:
            yield SimpleNamespace(proxy_id=str(proxy_id))
        finally:
            conn.events.append("guard-released")

    conn = _NativeCreateConnection()
    ledger = OperationLedger()
    monkeypatch.setattr(ledger, "init_db", lambda: None)
    monkeypatch.setattr(ledger, "_connect", lambda: conn)
    monkeypatch.setattr(
        ledger,
        "_prune_proxy_history",
        lambda *_args, **_kwargs: conn.events.append("prune") or 0,
    )
    monkeypatch.setattr(
        "services.operation_ledger.guarded_proxy_write",
        observed_guard,
    )
    monkeypatch.setattr("services.operation_ledger.time.time", lambda: 123)

    ledger.create_operation(
        "edge-a",
        operation_type="config_apply",
        subject="Squid config",
        summary="Apply revision",
        target_kind="config_revision",
        target_ref=42,
        request_hash="a" * 64,
    )

    assert conn.events[:3] == ["prune", "commit", "guard-released"]


def test_init_db_backfills_active_request_keys_before_unique_index(monkeypatch) -> None:
    from services.operation_ledger import OperationLedger

    conn = _Connection()
    ledger = OperationLedger()
    monkeypatch.setattr(ledger, "_connect", lambda: conn)
    monkeypatch.setattr("services.operation_ledger.time.time", lambda: 123)

    ledger.init_db()

    sql = [query for query, _params in conn.queries]
    create_index_pos = next(
        i
        for i, query in enumerate(sql)
        if query.startswith("ALTER TABLE proxy_operations ADD UNIQUE KEY")
    )
    terminal_clear_pos = next(
        i
        for i, query in enumerate(sql)
        if query.startswith("UPDATE proxy_operations SET request_key=NULL")
        and "status NOT IN ('pending','applying')" in query
    )
    supersede_pos = next(
        i
        for i, query in enumerate(sql)
        if query.startswith("UPDATE proxy_operations active JOIN")
    )
    mismatch_clear_pos = next(
        i
        for i, query in enumerate(sql)
        if query.startswith("UPDATE proxy_operations SET request_key=NULL")
        and "status IN ('pending','applying')" in query
    )
    backfill_pos = next(
        i
        for i, query in enumerate(sql)
        if query.startswith("UPDATE proxy_operations SET request_key=SHA2")
    )
    assert (
        terminal_clear_pos
        < supersede_pos
        < mismatch_clear_pos
        < backfill_pos
        < create_index_pos
    )
    supersede_sql, supersede_params = conn.queries[supersede_pos]
    assert "ROW_NUMBER" not in supersede_sql.upper()
    assert "JOIN proxy_operations keeper" in supersede_sql
    assert "CASE WHEN keeper.status='applying' THEN 0 ELSE 1 END" in supersede_sql
    assert "WHERE active.status IN ('pending','applying')" in supersede_sql
    assert "active.status='superseded'" in supersede_sql
    assert supersede_params == (123, 123)
    assert "WHERE status IN ('pending','applying')" in sql[backfill_pos]
    assert conn.committed is True


def test_init_db_trusts_current_runtime_schema_without_requirement_probes(
    monkeypatch,
) -> None:
    from services.operation_ledger import OperationLedger

    class _CurrentSchemaConnection(_Connection):
        native = object()

    conn = _CurrentSchemaConnection()
    ledger = OperationLedger()
    monkeypatch.setattr(ledger, "_connect", lambda: conn)
    monkeypatch.setattr(
        "services.schema_lifecycle.runtime_schema_ready_for_lazy_store",
        lambda _conn: True,
    )

    ledger.init_db()

    assert conn.queries == []


def test_init_db_repairs_missing_operation_requirements_when_schema_unknown(
    monkeypatch,
) -> None:
    from services.operation_ledger import OperationLedger

    conn = _Connection()
    ledger = OperationLedger()
    monkeypatch.setattr(ledger, "_connect", lambda: conn)
    monkeypatch.setattr(
        "services.schema_lifecycle.runtime_schema_ready_for_lazy_store",
        lambda _conn: False,
    )

    ledger.init_db()

    sql = [query for query, _params in conn.queries]
    assert any(
        query.startswith("CREATE TABLE IF NOT EXISTS proxy_operations") for query in sql
    )
    assert any("ADD COLUMN stale_requeue_count" in query for query in sql)


def test_claim_pending_locks_and_updates_claimed_rows_in_one_transaction(
    monkeypatch,
) -> None:
    from services.operation_ledger import OperationLedger

    conn = _Connection()
    ledger = OperationLedger()
    monkeypatch.setattr(ledger, "init_db", lambda: None)
    monkeypatch.setattr(ledger, "_connect", lambda: conn)
    monkeypatch.setattr("services.operation_ledger.time.time", lambda: 123)
    monkeypatch.setattr(
        "services.operation_ledger.secrets.token_hex", lambda _n: "claim-0"
    )
    claimed = ledger.claim_pending("edge-a", limit=2)
    assert [op.operation_id for op in claimed] == [7, 8]
    select_sql, select_params = conn.queries[0]
    assert "FOR UPDATE SKIP LOCKED" in select_sql
    assert "status='pending'" in select_sql
    assert select_params == ("edge-a", 2)
    update_sql, update_params = conn.queries[1]
    assert update_sql.startswith("UPDATE proxy_operations SET status='applying'")
    assert "request_key=NULL" not in update_sql
    assert "claim_token=%s" in update_sql
    assert update_params == (123, 123, "claim-0", "edge-a", 7, 8)
    assert conn.committed is True


def test_claim_pending_can_target_single_operation_id(monkeypatch) -> None:
    from services.operation_ledger import OperationLedger

    conn = _Connection()
    ledger = OperationLedger()
    monkeypatch.setattr(ledger, "init_db", lambda: None)
    monkeypatch.setattr(ledger, "_connect", lambda: conn)
    monkeypatch.setattr("services.operation_ledger.time.time", lambda: 123)
    monkeypatch.setattr(
        "services.operation_ledger.secrets.token_hex", lambda _n: "claim-0"
    )
    ledger.claim_pending("edge-a", limit=50, operation_id=7)
    select_sql, select_params = conn.queries[0]
    assert "AND id=%s" in select_sql
    assert "LIMIT %s FOR UPDATE SKIP LOCKED" in select_sql
    assert select_params == ("edge-a", 7, 1)


def test_claim_pending_preserves_force_flag(monkeypatch) -> None:
    from services.operation_ledger import OperationLedger

    conn = _Connection()
    ledger = OperationLedger()
    monkeypatch.setattr(ledger, "init_db", lambda: None)
    monkeypatch.setattr(ledger, "_connect", lambda: conn)
    monkeypatch.setattr("services.operation_ledger.time.time", lambda: 123)
    monkeypatch.setattr(
        "services.operation_ledger.secrets.token_hex", lambda _n: "claim-0"
    )

    claimed = ledger.claim_pending("edge-a", limit=2)

    assert claimed
    assert [op.force for op in claimed] == [False, False]


def test_claim_pending_accepts_lifecycle_alias_and_uses_canonical_proxy(
    monkeypatch,
) -> None:
    from services.operation_ledger import OperationLedger
    from services.proxy_write_guard import clear_proxy_write_guard_cache

    class _LifecycleClaimConnection(_LifecycleConnection):
        def _execute_operation(self, compact: str, params: tuple[object, ...]):
            if compact.startswith("SELECT id FROM proxy_operations"):
                return _Result([{"id": 7}]) if params[0] == "edge-new" else _Result()
            if compact.startswith("UPDATE proxy_operations SET status='applying'"):
                return _Result()
            if (
                compact.startswith("SELECT id, proxy_id, status")
                and "claim_token=%s" in compact
            ):
                return _Result(
                    [
                        _operation_row(
                            id=7,
                            proxy_id=params[0],
                            status="applying",
                            claim_token=params[1],
                        ),
                    ],
                )
            return _Result()

    clear_proxy_write_guard_cache()
    conn = _LifecycleClaimConnection(
        aliases={"edge-old": "edge-new"},
        registry={"edge-new": "active"},
    )
    ledger = OperationLedger()
    monkeypatch.setattr(ledger, "init_db", lambda: None)
    monkeypatch.setattr(ledger, "_connect", lambda: conn)
    monkeypatch.setattr("services.operation_ledger.time.time", lambda: 123)
    monkeypatch.setattr(
        "services.operation_ledger.secrets.token_hex", lambda _n: "claim-aliased"
    )

    claimed = ledger.claim_pending("edge-old", limit=5)

    assert [op.proxy_id for op in claimed] == ["edge-new"]
    claim_select = next(
        item
        for item in conn.queries
        if item[0].startswith("SELECT id FROM proxy_operations")
    )
    assert claim_select[1] == ("edge-new", 5)
    claim_update = next(
        item
        for item in conn.queries
        if item[0].startswith("UPDATE proxy_operations SET status='applying'")
    )
    assert claim_update[1] == (123, 123, "claim-aliased", "edge-new", 7)
    assert conn.committed is True


@pytest.mark.parametrize("action", ["renaming", "removing", "removed"])
def test_claim_pending_fails_closed_for_blocked_lifecycle_states(
    monkeypatch,
    action,
) -> None:
    from services.operation_ledger import OperationLedger
    from services.proxy_write_guard import (
        ProxyLifecycleWriteError,
        clear_proxy_write_guard_cache,
    )

    class _LifecycleClaimConnection(_LifecycleConnection):
        def _execute_operation(self, compact: str, params: tuple[object, ...]):
            if compact.startswith("SELECT id FROM proxy_operations"):
                pytest.fail("blocked lifecycle state must fail before claiming rows")
            return _Result()

    clear_proxy_write_guard_cache()
    conn = _LifecycleClaimConnection(
        tombstones={"edge-a": (action, "edge-b" if action == "renaming" else "")},
        registry={"edge-a": "active"},
    )
    ledger = OperationLedger()
    monkeypatch.setattr(ledger, "init_db", lambda: None)
    monkeypatch.setattr(ledger, "_connect", lambda: conn)

    with pytest.raises(ProxyLifecycleWriteError):
        ledger.claim_pending("edge-a", limit=2)
    assert conn.committed is False


def test_claim_pending_rejects_renamed_tombstone_when_alias_disabled(
    monkeypatch,
) -> None:
    from services.operation_ledger import OperationLedger
    from services.proxy_write_guard import (
        ProxyLifecycleWriteError,
        clear_proxy_write_guard_cache,
    )

    class _LifecycleClaimConnection(_LifecycleConnection):
        def _execute_operation(self, compact: str, params: tuple[object, ...]):
            if compact.startswith("SELECT id FROM proxy_operations"):
                pytest.fail(
                    "strict runtime claim must fail before selecting new proxy rows"
                )
            if compact.startswith("UPDATE proxy_operations"):
                pytest.fail("strict runtime claim must fail before mutating operations")
            return _Result()

    clear_proxy_write_guard_cache()
    conn = _LifecycleClaimConnection(
        aliases={"edge-old": "edge-new"},
        tombstones={"edge-old": ("renamed", "edge-new")},
        registry={"edge-new": "active"},
    )
    ledger = OperationLedger()
    monkeypatch.setattr(ledger, "init_db", lambda: None)
    monkeypatch.setattr(ledger, "_connect", lambda: conn)

    with pytest.raises(ProxyLifecycleWriteError):
        ledger.claim_pending("edge-old", limit=5, allow_alias=False)

    assert conn.committed is False
    assert not any(
        query.startswith(("SELECT id FROM proxy_operations", "UPDATE proxy_operations"))
        for query, _params in conn.queries
    )


def test_requeue_stale_applying_rejects_renamed_tombstone_when_alias_disabled(
    monkeypatch,
) -> None:
    from services.operation_ledger import OperationLedger
    from services.proxy_write_guard import (
        ProxyLifecycleWriteError,
        clear_proxy_write_guard_cache,
    )

    class _LifecycleRequeueConnection(_LifecycleConnection):
        def _execute_operation(self, compact: str, params: tuple[object, ...]):
            if compact.startswith("UPDATE proxy_operations"):
                pytest.fail(
                    "strict runtime requeue must fail before mutating operations"
                )
            return _Result()

    clear_proxy_write_guard_cache()
    conn = _LifecycleRequeueConnection(
        aliases={"edge-old": "edge-new"},
        tombstones={"edge-old": ("renamed", "edge-new")},
        registry={"edge-new": "active"},
    )
    ledger = OperationLedger()
    monkeypatch.setattr(ledger, "init_db", lambda: None)
    monkeypatch.setattr(ledger, "_connect", lambda: conn)

    with pytest.raises(ProxyLifecycleWriteError):
        ledger.requeue_stale_applying("edge-old", allow_alias=False)

    assert conn.committed is False
    assert not any(
        query.startswith("UPDATE proxy_operations") for query, _params in conn.queries
    )


def test_new_canonical_runtime_can_claim_and_complete_after_rename(
    monkeypatch,
) -> None:
    from services.operation_ledger import OperationLedger
    from services.proxy_write_guard import clear_proxy_write_guard_cache

    class _LifecycleClaimAndMarkConnection(_LifecycleConnection):
        def __init__(self) -> None:
            super().__init__(
                tombstones={"edge-old": ("renamed", "edge-new")},
                registry={"edge-new": "active"},
            )
            self.row = _operation_row(id=7, proxy_id="edge-new", status="pending")

        def _execute_operation(self, compact: str, params: tuple[object, ...]):
            if compact.startswith("SELECT id FROM proxy_operations"):
                return _Result([{"id": 7}]) if params[0] == "edge-new" else _Result()
            if compact.startswith("UPDATE proxy_operations SET status='applying'"):
                if params[3] == "edge-new" and self.row["status"] == "pending":
                    self.row["status"] = "applying"
                    self.row["started_ts"] = params[0]
                    self.row["updated_ts"] = params[1]
                    self.row["claim_token"] = params[2]
                return _Result()
            if compact.startswith("UPDATE proxy_operations SET status=%s"):
                if (
                    self.row["status"] == params[7]
                    and self.row["claim_token"] == params[8]
                    and params[-1] == "edge-new"
                ):
                    self.row["status"] = params[0]
                    self.row["detail"] = params[1]
                    self.row["completed_ts"] = params[2]
                    self.row["updated_ts"] = params[3]
                    if params[5]:
                        self.row["claim_token"] = None
                return _Result()
            if (
                compact.startswith("SELECT id, proxy_id, status")
                and "claim_token=%s" in compact
            ):
                if (
                    self.row["status"] == "applying"
                    and self.row["claim_token"] == params[1]
                ):
                    return _Result([self.row])
                return _Result()
            if compact.startswith("SELECT id, proxy_id, status"):
                return _Result([self.row])
            return _Result()

    clear_proxy_write_guard_cache()
    conn = _LifecycleClaimAndMarkConnection()
    ledger = OperationLedger()
    monkeypatch.setattr(ledger, "init_db", lambda: None)
    monkeypatch.setattr(ledger, "_connect", lambda: conn)
    monkeypatch.setattr("services.operation_ledger.time.time", lambda: 123)
    monkeypatch.setattr(
        "services.operation_ledger.secrets.token_hex", lambda _n: "claim-new"
    )

    claimed = ledger.claim_pending("edge-new", limit=5, allow_alias=False)
    ledger.mark_many(claimed, status="applied", detail="done")

    assert [op.proxy_id for op in claimed] == ["edge-new"]
    assert conn.row["status"] == "applied"
    assert conn.row["detail"] == "done"
    assert conn.row["claim_token"] is None


def test_list_recent_since_preserves_claim_token(monkeypatch) -> None:
    from services.operation_ledger import OperationLedger

    row = _operation_row(
        id=7,
        status="applying",
        updated_ts=456,
        force_sync=1,
        claim_token="claim-recent",
    )

    class _RecentConnection:
        def __init__(self) -> None:
            self.queries = []

        def execute(self, sql, params=()):
            compact = " ".join(str(sql).split())
            self.queries.append((compact, tuple(params or ())))
            if compact.startswith("SELECT id, proxy_id, status"):
                return _Result([row])
            return _Result()

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    conn = _RecentConnection()
    ledger = OperationLedger()
    monkeypatch.setattr(ledger, "init_db", lambda: None)
    monkeypatch.setattr(ledger, "_connect", lambda: conn)

    recent = ledger.list_recent_since(
        "edge-a",
        after_updated_ts=123,
        after_id=6,
        limit=5,
    )

    assert [op.operation_id for op in recent] == [7]
    assert recent[0].claim_token == "claim-recent"
    select_sql, select_params = conn.queries[0]
    assert "claim_token" in select_sql
    assert select_params == ("edge-a", 123, 123, 6, 5)


def test_requeue_stale_applying_recovers_without_active_key_collisions(
    monkeypatch,
) -> None:
    from services.operation_ledger import OperationLedger

    class _RequeueConnection:
        def __init__(self) -> None:
            self.queries = []
            self.committed = False

        def execute(self, sql, params=()):
            compact = " ".join(str(sql).split())
            params = tuple(params or ())
            self.queries.append((compact, params))
            result = _Result()
            result.rowcount = (
                3
                if compact.startswith("UPDATE proxy_operations stale LEFT JOIN")
                and "SET stale.status='pending'" in compact
                else 0
            )
            return result

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            if exc_type is None:
                self.committed = True
            return False

    conn = _RequeueConnection()
    ledger = OperationLedger()
    monkeypatch.setattr(ledger, "init_db", lambda: None)
    monkeypatch.setattr(ledger, "_connect", lambda: conn)
    monkeypatch.setattr("services.operation_ledger.time.time", lambda: 1000)

    requeued = ledger.requeue_stale_applying("edge-a", older_than_seconds=300)

    assert requeued == 3
    supersede_sql, supersede_params = conn.queries[0]
    assert supersede_sql.startswith("UPDATE proxy_operations active JOIN")
    assert "status IN ('pending','applying')" in supersede_sql
    assert "ROW_NUMBER" not in supersede_sql.upper()
    assert "JOIN ( SELECT proxy_id, request_key FROM" in supersede_sql
    assert "FROM proxy_operations stale_source" in supersede_sql
    assert "JOIN proxy_operations keeper" in supersede_sql
    assert (
        "CASE WHEN keeper.status='applying' AND keeper.started_ts>=%s THEN 0"
        in supersede_sql
    )
    assert "active.status='superseded'" in supersede_sql
    assert "active.request_key=NULL" in supersede_sql
    assert "active.claim_token=NULL" in supersede_sql
    assert supersede_params == ("edge-a", 700, 700, 700, 700, 700, 1000, 1000, "edge-a")
    quarantine_sql, quarantine_params = conn.queries[1]
    assert quarantine_sql.startswith("UPDATE proxy_operations stale LEFT JOIN")
    assert "SET stale.status='failed'" in quarantine_sql
    assert "repeated stale applying recoveries" in quarantine_sql
    assert "stale.request_key=NULL" in quarantine_sql
    assert "stale.claim_token=NULL" in quarantine_sql
    assert "stale.stale_requeue_count >= %s" in quarantine_sql
    assert quarantine_params == (1000, 1000, "edge-a", 700, 3)
    requeue_sql, requeue_params = conn.queries[2]
    assert requeue_sql.startswith("UPDATE proxy_operations stale LEFT JOIN")
    assert "active.status IN ('pending','applying')" in requeue_sql
    assert "active.id IS NULL" in requeue_sql
    assert "SET stale.status='pending'" in requeue_sql
    assert "stale.completed_ts=0" in requeue_sql
    assert "stale.stale_requeue_count=stale.stale_requeue_count+1" in requeue_sql
    assert "stale.stale_requeue_count < %s" in requeue_sql
    assert "request_key=SHA2(CONCAT(" in requeue_sql
    assert "stale.claim_token=NULL" in requeue_sql
    assert "COALESCE(NULLIF(stale.operation_type,''),'sync')" in requeue_sql
    assert requeue_params == (1000, "edge-a", 700, 3)
    assert conn.committed is True


def test_requeue_stale_applying_accepts_lifecycle_alias_and_scopes_canonical(
    monkeypatch,
) -> None:
    from services.operation_ledger import OperationLedger
    from services.proxy_write_guard import clear_proxy_write_guard_cache

    class _LifecycleRequeueConnection(_LifecycleConnection):
        def _execute_operation(self, compact: str, params: tuple[object, ...]):
            result = _Result()
            result.rowcount = (
                2
                if compact.startswith("UPDATE proxy_operations stale LEFT JOIN")
                and "SET stale.status='pending'" in compact
                else 0
            )
            return result

    clear_proxy_write_guard_cache()
    conn = _LifecycleRequeueConnection(
        aliases={"edge-old": "edge-new"},
        registry={"edge-new": "active"},
    )
    ledger = OperationLedger()
    monkeypatch.setattr(ledger, "init_db", lambda: None)
    monkeypatch.setattr(ledger, "_connect", lambda: conn)
    monkeypatch.setattr("services.operation_ledger.time.time", lambda: 1000)

    requeued = ledger.requeue_stale_applying("edge-old", older_than_seconds=300)

    assert requeued == 2
    operation_queries = [
        item for item in conn.queries if item[0].startswith("UPDATE proxy_operations")
    ]
    assert len(operation_queries) == 3
    assert operation_queries[0][1][0] == "edge-new"
    assert operation_queries[0][1][-1] == "edge-new"
    assert operation_queries[1][1][2] == "edge-new"
    assert operation_queries[2][1][1] == "edge-new"


def test_requeue_stale_applying_supersede_sql_preserves_valid_keeper_ordering(
    monkeypatch,
) -> None:
    from services.operation_ledger import OperationLedger

    class _RequeueConnection:
        def __init__(self) -> None:
            self.queries = []

        def execute(self, sql, params=()):
            compact = " ".join(str(sql).split())
            self.queries.append((compact, tuple(params or ())))
            return _Result()

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    conn = _RequeueConnection()
    ledger = OperationLedger()
    monkeypatch.setattr(ledger, "init_db", lambda: None)
    monkeypatch.setattr(ledger, "_connect", lambda: conn)
    monkeypatch.setattr("services.operation_ledger.time.time", lambda: 1000)

    ledger.requeue_stale_applying("edge-a", older_than_seconds=300)

    supersede_sql, supersede_params = conn.queries[0]
    assert "AND ( AND" not in supersede_sql

    priority_case = (
        "CASE WHEN keeper.status='applying' AND keeper.started_ts>=%s THEN 0 "
        "WHEN keeper.status='applying' THEN 1 ELSE 2 END"
    )
    active_priority_case = (
        "CASE WHEN active.status='applying' AND active.started_ts>=%s THEN 0 "
        "WHEN active.status='applying' THEN 1 ELSE 2 END"
    )
    assert supersede_sql.count(priority_case) == 2
    assert supersede_sql.count(active_priority_case) == 2
    assert supersede_sql.index(f"{priority_case} < {active_priority_case}") < (
        supersede_sql.index(f"{priority_case} = {active_priority_case}")
    )
    assert supersede_sql.index(
        f"{priority_case} = {active_priority_case}"
    ) < supersede_sql.index("keeper.created_ts < active.created_ts")
    assert (
        "OR (keeper.created_ts = active.created_ts AND keeper.id < active.id)"
        in supersede_sql
    )
    assert supersede_params == (
        "edge-a",
        700,
        700,
        700,
        700,
        700,
        1000,
        1000,
        "edge-a",
    )


def test_claim_pending_returns_only_rows_claimed_by_current_token(monkeypatch) -> None:
    from services.operation_ledger import OperationLedger

    class _LostUpdateConnection:
        def __init__(self) -> None:
            self.queries = []

        def execute(self, sql, params=()):
            compact = " ".join(str(sql).split())
            params = tuple(params or ())
            self.queries.append((compact, params))
            if compact.startswith("SELECT id FROM proxy_operations"):
                return _Result([{"id": 7}, {"id": 8}])
            if (
                compact.startswith("SELECT id, proxy_id, status")
                and "claim_token=%s" in compact
            ):
                base = _operation_row(status="applying", started_ts=123, updated_ts=123)
                # Row 8 was concurrently moved away/reclaimed after the SELECT. The
                # claimant must not execute or later complete it from a stale id list.
                return _Result([dict(base, id=7, claim_token=params[1])])
            return _Result()

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    conn = _LostUpdateConnection()
    ledger = OperationLedger()
    monkeypatch.setattr(ledger, "init_db", lambda: None)
    monkeypatch.setattr(ledger, "_connect", lambda: conn)
    monkeypatch.setattr("services.operation_ledger.time.time", lambda: 123)
    monkeypatch.setattr(
        "services.operation_ledger.secrets.token_hex", lambda _n: "claim-current"
    )

    claimed = ledger.claim_pending("edge-a", limit=2)

    assert [op.operation_id for op in claimed] == [7]
    select_claimed_sql, select_claimed_params = conn.queries[2]
    assert "status='applying'" in select_claimed_sql
    assert "claim_token=%s" in select_claimed_sql
    assert select_claimed_params == ("edge-a", "claim-current", 7, 8)


def test_mark_status_can_guard_applying_claim_token(monkeypatch) -> None:
    from services.operation_ledger import OperationLedger

    conn = _Connection()
    ledger = OperationLedger()
    monkeypatch.setattr(ledger, "init_db", lambda: None)
    monkeypatch.setattr(ledger, "_connect", lambda: conn)
    monkeypatch.setattr("services.operation_ledger.time.time", lambda: 456)

    ledger.mark_status(
        7,
        status="applied",
        detail="done",
        expected_status="applying",
        expected_claim_token="claim-a",
    )

    identity_sql, identity_params = conn.queries[0]
    assert identity_sql.startswith("SELECT id, proxy_id, status")
    assert identity_params == (7,)
    update_sql, update_params = conn.queries[1]
    assert (
        "WHERE id=%s AND status NOT IN ('applied','superseded','failed') AND status=%s AND claim_token=%s AND proxy_id=%s"
        in update_sql
    )
    assert update_params == (
        "applied",
        "done",
        456,
        456,
        True,
        True,
        7,
        "applying",
        "claim-a",
        "edge-a",
    )


def test_mark_status_empty_expected_claim_token_adds_claim_guard(monkeypatch) -> None:
    from services.operation_ledger import OperationLedger

    conn = _Connection()
    ledger = OperationLedger()
    monkeypatch.setattr(ledger, "init_db", lambda: None)
    monkeypatch.setattr(ledger, "_connect", lambda: conn)
    monkeypatch.setattr("services.operation_ledger.time.time", lambda: 456)

    ledger.mark_status(
        7,
        status="applied",
        detail="done",
        expected_status="applying",
        expected_claim_token="",
    )

    update_sql, update_params = conn.queries[1]
    assert (
        "WHERE id=%s AND status NOT IN ('applied','superseded','failed') AND status=%s AND claim_token=%s AND proxy_id=%s"
        in update_sql
    )
    assert update_params == (
        "applied",
        "done",
        456,
        456,
        True,
        True,
        7,
        "applying",
        "",
        "edge-a",
    )


def test_stale_claim_completion_does_not_overwrite_reclaimed_operation_detail(
    monkeypatch,
) -> None:
    from services.operation_ledger import OperationLedger

    class _GuardedConnection:
        def __init__(self) -> None:
            self.row = _operation_row(
                status="applying",
                detail="new claim is still running",
                claim_token="new-claim",
            )
            self.queries = []

        def execute(self, sql, params=()):
            compact = " ".join(str(sql).split())
            params = tuple(params or ())
            self.queries.append((compact, params))
            if compact.startswith("SELECT proxy_id FROM proxy_operations"):
                return _Result([{"proxy_id": self.row["proxy_id"]}])
            if compact.startswith("UPDATE proxy_operations SET status=%s"):
                expected_status = params[7] if len(params) > 7 else None
                expected_token = params[8] if len(params) > 8 else None
                if (
                    self.row["status"] == expected_status
                    and self.row["claim_token"] == expected_token
                ):
                    self.row["status"] = params[0]
                    self.row["detail"] = params[1]
                    self.row["completed_ts"] = params[2]
                    self.row["updated_ts"] = params[3]
                    if params[4]:
                        self.row["request_key"] = None
                    if params[5]:
                        self.row["claim_token"] = None
                    result = _Result()
                    result.rowcount = 1
                    return result
                result = _Result()
                result.rowcount = 0
                return result
            if compact.startswith("SELECT id, proxy_id, status"):
                return _Result([self.row])
            return _Result()

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    conn = _GuardedConnection()
    ledger = OperationLedger()
    monkeypatch.setattr(ledger, "init_db", lambda: None)
    monkeypatch.setattr(ledger, "_connect", lambda: conn)
    monkeypatch.setattr("services.operation_ledger.time.time", lambda: 500)

    current = ledger.mark_status(
        11,
        status="failed",
        detail="stale worker failed after recovery",
        expected_status="applying",
        expected_claim_token="old-claim",
    )

    assert current is not None
    assert current.status == "applying"
    assert current.detail == "new claim is still running"
    assert current.claim_token == "new-claim"
    update_sql, update_params = conn.queries[1]
    assert (
        "WHERE id=%s AND status NOT IN ('applied','superseded','failed') AND status=%s AND claim_token=%s AND proxy_id=%s"
        in update_sql
    )
    assert update_params[-4:] == (11, "applying", "old-claim", "edge-a")


def test_empty_stale_claim_completion_does_not_overwrite_reclaimed_operation_detail(
    monkeypatch,
) -> None:
    from services.operation_ledger import OperationLedger

    class _GuardedConnection:
        def __init__(self) -> None:
            self.row = _operation_row(
                status="applying",
                detail="new claim is still running",
                claim_token="new-claim",
            )
            self.queries = []

        def execute(self, sql, params=()):
            compact = " ".join(str(sql).split())
            params = tuple(params or ())
            self.queries.append((compact, params))
            if compact.startswith("SELECT proxy_id FROM proxy_operations"):
                return _Result([{"proxy_id": self.row["proxy_id"]}])
            if compact.startswith("UPDATE proxy_operations SET status=%s"):
                expected_status = params[7] if "AND status=%s" in compact else None
                expected_token = params[8] if "AND claim_token=%s" in compact else None
                status_matches = (
                    "AND status=%s" not in compact
                    or self.row["status"] == expected_status
                )
                token_matches = (
                    "AND claim_token=%s" not in compact
                    or self.row["claim_token"] == expected_token
                )
                if status_matches and token_matches:
                    self.row["status"] = params[0]
                    self.row["detail"] = params[1]
                    self.row["completed_ts"] = params[2]
                    self.row["updated_ts"] = params[3]
                    if params[4]:
                        self.row["request_key"] = None
                    if params[5]:
                        self.row["claim_token"] = None
                    result = _Result()
                    result.rowcount = 1
                    return result
                result = _Result()
                result.rowcount = 0
                return result
            if compact.startswith("SELECT id, proxy_id, status"):
                return _Result([self.row])
            return _Result()

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    conn = _GuardedConnection()
    ledger = OperationLedger()
    monkeypatch.setattr(ledger, "init_db", lambda: None)
    monkeypatch.setattr(ledger, "_connect", lambda: conn)
    monkeypatch.setattr("services.operation_ledger.time.time", lambda: 500)

    current = ledger.mark_status(
        11,
        status="failed",
        detail="stale worker with empty claim failed after recovery",
        expected_status="applying",
        expected_claim_token="",
    )

    assert current is not None
    assert current.status == "applying"
    assert current.detail == "new claim is still running"
    assert current.claim_token == "new-claim"
    update_sql, update_params = conn.queries[1]
    assert (
        "WHERE id=%s AND status NOT IN ('applied','superseded','failed') AND status=%s AND claim_token=%s AND proxy_id=%s"
        in update_sql
    )
    assert update_params[-4:] == (11, "applying", "", "edge-a")


@pytest.mark.parametrize("action", ["renaming", "removing", "removed"])
def test_mark_status_fails_closed_for_lifecycle_blocked_identity(
    monkeypatch,
    action,
) -> None:
    from services.operation_ledger import OperationLedger
    from services.proxy_write_guard import (
        ProxyLifecycleWriteError,
        clear_proxy_write_guard_cache,
    )

    class _LifecycleMarkConnection(_LifecycleConnection):
        def __init__(self) -> None:
            super().__init__(
                tombstones={
                    "edge-old": (
                        action,
                        "edge-new" if action in {"renamed", "renaming"} else "",
                    ),
                },
                registry={"edge-old": "active", "edge-new": "active"},
            )
            self.row = _operation_row(
                id=11,
                proxy_id="edge-old",
                status="applying",
                claim_token="claim-a",
            )

        def _execute_operation(self, compact: str, params: tuple[object, ...]):
            if compact.startswith("SELECT proxy_id FROM proxy_operations"):
                return _Result([{"proxy_id": self.row["proxy_id"]}])
            if compact.startswith("UPDATE proxy_operations SET status=%s"):
                pytest.fail("blocked lifecycle identity must fail before mark update")
            if compact.startswith("SELECT id, proxy_id, status"):
                return _Result([self.row])
            return _Result()

    clear_proxy_write_guard_cache()
    conn = _LifecycleMarkConnection()
    ledger = OperationLedger()
    monkeypatch.setattr(ledger, "init_db", lambda: None)
    monkeypatch.setattr(ledger, "_connect", lambda: conn)

    with pytest.raises(ProxyLifecycleWriteError):
        ledger.mark_status(
            11,
            status="applied",
            expected_status="applying",
            expected_claim_token="claim-a",
        )
    assert conn.committed is False


def test_mark_status_update_is_explicitly_scoped_to_initial_proxy_identity(
    monkeypatch,
) -> None:
    from services.operation_ledger import OperationLedger

    class _ProxyChangedConnection:
        def __init__(self) -> None:
            self.row = _operation_row(
                id=11,
                proxy_id="edge-a",
                status="applying",
                detail="still applying",
                claim_token="claim-a",
            )
            self.queries = []
            self.identity_read = False

        def execute(self, sql, params=()):
            compact = " ".join(str(sql).split())
            params = tuple(params or ())
            self.queries.append((compact, params))
            if (
                compact.startswith("SELECT id, proxy_id, status")
                and not self.identity_read
            ):
                self.identity_read = True
                initial_row = dict(self.row)
                self.row["proxy_id"] = "edge-b"
                return _Result([initial_row])
            if compact.startswith("UPDATE proxy_operations SET status=%s"):
                if self.row["proxy_id"] == params[-1]:
                    self.row["status"] = params[0]
                    self.row["detail"] = params[1]
                result = _Result()
                result.rowcount = 1 if self.row["proxy_id"] == params[-1] else 0
                return result
            if compact.startswith("SELECT id, proxy_id, status"):
                return _Result([self.row])
            return _Result()

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    conn = _ProxyChangedConnection()
    ledger = OperationLedger()
    monkeypatch.setattr(ledger, "init_db", lambda: None)
    monkeypatch.setattr(ledger, "_connect", lambda: conn)
    monkeypatch.setattr("services.operation_ledger.time.time", lambda: 600)

    current = ledger.mark_status(
        11,
        status="applied",
        detail="done",
        expected_status="applying",
        expected_claim_token="claim-a",
    )

    assert current is not None
    assert current.proxy_id == "edge-b"
    assert current.status == "applying"
    assert current.detail == "still applying"
    update_sql, update_params = conn.queries[1]
    assert "AND proxy_id=%s" in update_sql
    assert update_params[-4:] == (11, "applying", "claim-a", "edge-a")


def test_create_operation_uses_active_request_upsert(monkeypatch) -> None:
    from services.operation_ledger import OperationLedger

    class _CreateConnection:
        def __init__(self) -> None:
            self.queries = []
            self.committed = False

        def execute(self, sql, params=()):
            compact = " ".join(str(sql).split())
            params = tuple(params or ())
            self.queries.append((compact, params))
            if compact.startswith("INSERT INTO proxy_operations"):
                result = _Result()
                result.lastrowid = 11
                return result
            if compact.startswith("SELECT id, proxy_id, status"):
                return _Result([_operation_row()])
            return _Result()

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            if exc_type is None:
                self.committed = True
            return False

    conn = _CreateConnection()
    ledger = OperationLedger()
    monkeypatch.setattr(ledger, "init_db", lambda: None)
    monkeypatch.setattr(ledger, "_connect", lambda: conn)
    monkeypatch.setattr("services.operation_ledger.time.time", lambda: 123)

    op = ledger.create_operation(
        "edge-a",
        operation_type="config_apply",
        subject="Squid config",
        summary="Apply revision",
        target_kind="config_revision",
        target_ref=42,
        rollback_kind="config_revision",
        rollback_ref=3,
        request_hash="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        created_by="admin",
        force=True,
    )

    insert_sql, insert_params = conn.queries[0]
    assert "request_key" in insert_sql
    assert "force_sync" in insert_sql
    assert "ON DUPLICATE KEY UPDATE id=LAST_INSERT_ID(id)" in insert_sql
    assert "summary=VALUES(summary)" in insert_sql
    duplicate_update = insert_sql.split("ON DUPLICATE KEY UPDATE", 1)[1]
    assert "rollback_kind=VALUES(rollback_kind)" not in duplicate_update
    assert "rollback_ref=VALUES(rollback_ref)" not in duplicate_update
    assert "detail=VALUES(detail)" in insert_sql
    assert "created_by=VALUES(created_by)" in insert_sql
    assert "updated_ts=VALUES(updated_ts)" in insert_sql
    assert "force_sync=GREATEST(force_sync, VALUES(force_sync))" in insert_sql
    assert insert_params[6:8] == ("config_revision", "3")
    assert len(insert_params[9]) == 64
    assert insert_params[-1] == 1
    assert op.operation_id == 11
    assert conn.committed is True


def test_create_operation_normalizes_falsey_refs_and_redacts_operator_details(
    monkeypatch,
) -> None:
    from services.operation_ledger import OperationLedger

    class _CreateConnection:
        def __init__(self) -> None:
            self.queries = []
            self.row = None

        def execute(self, sql, params=()):
            compact = " ".join(str(sql).split())
            params = tuple(params or ())
            self.queries.append((compact, params))
            if compact.startswith("INSERT INTO proxy_operations"):
                result = _Result()
                result.lastrowid = 11
                self.row = _operation_row(
                    id=11,
                    proxy_id=params[0],
                    operation_type=params[1],
                    subject=params[2],
                    summary=params[3],
                    target_kind=params[4],
                    target_ref=params[5],
                    rollback_kind=params[6],
                    rollback_ref=params[7],
                    request_hash=params[8],
                    request_key=params[9],
                    detail=params[10],
                    created_by=params[11],
                )
                return result
            if compact.startswith("SELECT id, proxy_id, status"):
                return _Result([self.row])
            return _Result()

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    conn = _CreateConnection()
    ledger = OperationLedger()
    monkeypatch.setattr(ledger, "init_db", lambda: None)
    monkeypatch.setattr(ledger, "_connect", lambda: conn)
    monkeypatch.setattr("services.operation_ledger.time.time", lambda: 123)

    op = ledger.create_operation(
        "edge-a",
        operation_type="cache_clear",
        subject="Proxy cache clear",
        summary="Queued with token=summary-secret",
        target_kind="cache_epoch",
        target_ref=0,
        rollback_kind="cache_epoch",
        rollback_ref=0,
        request_hash=0,
        detail="Authorization: Bearer detail-secret password=detail-secret",
        created_by="admin",
    )

    insert_params = conn.queries[0][1]
    assert insert_params[3] == "Queued with token=[redacted]"
    assert insert_params[5] == "0"
    assert insert_params[7] == "0"
    assert insert_params[8] == ""
    assert insert_params[10] == "Authorization: Bearer [redacted] password=[redacted]"
    assert op.summary == "Queued with token=[redacted]"
    assert op.detail == "Authorization: Bearer [redacted] password=[redacted]"


def test_create_operation_normalizes_and_rejects_request_hash_evidence(
    monkeypatch,
) -> None:
    from services.operation_ledger import OperationLedger

    class _CreateConnection:
        def __init__(self) -> None:
            self.queries = []
            self.row = None

        def execute(self, sql, params=()):
            compact = " ".join(str(sql).split())
            params = tuple(params or ())
            self.queries.append((compact, params))
            if compact.startswith("INSERT INTO proxy_operations"):
                result = _Result()
                result.lastrowid = 11
                self.row = _operation_row(
                    id=11,
                    request_hash=params[8],
                    request_key=params[9],
                )
                return result
            if compact.startswith("SELECT id, proxy_id, status"):
                return _Result([self.row])
            return _Result()

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    conn = _CreateConnection()
    ledger = OperationLedger()
    monkeypatch.setattr(ledger, "init_db", lambda: None)
    monkeypatch.setattr(ledger, "_connect", lambda: conn)
    monkeypatch.setattr("services.operation_ledger.time.time", lambda: 123)

    operation = ledger.create_operation(
        "edge-a",
        operation_type="config_apply",
        subject="Squid config",
        summary="Apply revision",
        target_kind="config_revision",
        target_ref=42,
        request_hash="A" * 64,
    )

    assert operation.request_hash == "a" * 64
    assert conn.queries[0][1][8] == "a" * 64

    with pytest.raises(ValueError, match="request_hash"):
        ledger.create_operation(
            "edge-a",
            operation_type="config_apply",
            subject="Squid config",
            summary="Apply revision",
            target_kind="config_revision",
            target_ref=42,
            request_hash="a" * 65,
        )


def test_policy_and_pac_operation_target_refs_are_strict_sha256_and_normalized(
    monkeypatch,
) -> None:
    from services.operation_ledger import OperationLedger

    class _CreateConnection:
        def __init__(self) -> None:
            self.queries = []
            self.row = _operation_row(
                operation_type="policy_sync",
                target_kind="policy_state",
                target_ref=POLICY_SHA,
            )

        def execute(self, sql, params=()):
            compact = " ".join(str(sql).split())
            params = tuple(params or ())
            self.queries.append((compact, params))
            if compact.startswith("INSERT INTO proxy_operations"):
                self.row.update(
                    operation_type=params[1],
                    target_kind=params[4],
                    target_ref=params[5],
                    request_key=params[9],
                )
                result = _Result()
                result.lastrowid = 7
                return result
            if compact.startswith("SELECT id, proxy_id, status"):
                return _Result([self.row])
            return _Result()

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    conn = _CreateConnection()
    ledger = OperationLedger()
    monkeypatch.setattr(ledger, "init_db", lambda: None)
    monkeypatch.setattr(ledger, "_connect", lambda: conn)
    monkeypatch.setattr("services.operation_ledger.time.time", lambda: 123)

    operation = ledger.create_operation(
        "edge-a",
        operation_type="policy_sync",
        subject="Policy reconciliation",
        summary="Apply policy",
        target_kind="policy_state",
        target_ref=POLICY_SHA.upper(),
    )

    assert operation.target_ref == POLICY_SHA
    assert conn.queries[0][1][5] == POLICY_SHA

    with pytest.raises(ValueError, match=r"target_ref.*policy_state"):
        ledger.create_operation(
            "edge-a",
            operation_type="policy_sync",
            subject="Policy reconciliation",
            summary="Apply policy",
            target_kind="policy_state",
            target_ref="policy-sha",
        )

    with pytest.raises(ValueError, match=r"target_ref.*pac_state"):
        ledger.create_operation(
            "edge-a",
            operation_type="pac_refresh",
            subject="PAC refresh",
            summary="Apply PAC",
            target_kind="pac_state",
            target_ref="",
        )


def test_duplicate_active_request_preserves_original_rollback_metadata(
    monkeypatch,
) -> None:
    from services.operation_ledger import OperationLedger

    class _DuplicateConnection:
        def __init__(self) -> None:
            self.queries = []
            self.committed = False
            self.row = _operation_row(
                id=11,
                rollback_kind="config_revision",
                rollback_ref="3",
                summary="Duplicate summary",
                detail="Duplicate detail",
                created_by="operator-b",
                updated_ts=124,
                force_sync=1,
            )

        def execute(self, sql, params=()):
            compact = " ".join(str(sql).split())
            params = tuple(params or ())
            self.queries.append((compact, params))
            if compact.startswith("INSERT INTO proxy_operations"):
                result = _Result()
                result.lastrowid = 11
                return result
            if compact.startswith("SELECT id, proxy_id, status"):
                return _Result([self.row])
            return _Result()

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            if exc_type is None:
                self.committed = True
            return False

    conn = _DuplicateConnection()
    ledger = OperationLedger()
    monkeypatch.setattr(ledger, "init_db", lambda: None)
    monkeypatch.setattr(ledger, "_connect", lambda: conn)
    monkeypatch.setattr("services.operation_ledger.time.time", lambda: 124)

    op = ledger.create_operation(
        "edge-a",
        operation_type="config_apply",
        subject="Squid config",
        summary="Duplicate summary",
        target_kind="config_revision",
        target_ref=17,
        rollback_kind="config_revision",
        rollback_ref=17,
        request_hash="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        detail="Duplicate detail",
        created_by="operator-b",
        force=True,
    )

    insert_sql, insert_params = conn.queries[0]
    duplicate_update = insert_sql.split("ON DUPLICATE KEY UPDATE", 1)[1]
    assert "rollback_kind=VALUES(rollback_kind)" not in duplicate_update
    assert "rollback_ref=VALUES(rollback_ref)" not in duplicate_update
    assert "summary=VALUES(summary)" in duplicate_update
    assert "detail=VALUES(detail)" in duplicate_update
    assert "created_by=VALUES(created_by)" in duplicate_update
    assert "force_sync=GREATEST(force_sync, VALUES(force_sync))" in duplicate_update
    assert insert_params[5:8] == ("17", "config_revision", "17")
    assert op.operation_id == 11
    assert op.rollback_kind == "config_revision"
    assert op.rollback_ref == "3"
    assert op.summary == "Duplicate summary"
    assert op.detail == "Duplicate detail"
    assert op.created_by == "operator-b"
    assert op.force is True
    assert conn.committed is True


def test_duplicate_active_request_fills_missing_rollback_metadata(
    monkeypatch,
) -> None:
    from services.operation_ledger import OperationLedger

    class _StatefulCreateConnection:
        def __init__(self) -> None:
            self.queries = []
            self.committed = False
            self.rows: dict[int, dict[str, object]] = {}
            self.active_by_key: dict[tuple[str, str], int] = {}
            self.next_id = 11

        def execute(self, sql, params=()):
            compact = " ".join(str(sql).split())
            params = tuple(params or ())
            self.queries.append((compact, params))
            if compact.startswith("INSERT INTO proxy_operations"):
                (
                    proxy_id,
                    operation_type,
                    subject,
                    summary,
                    target_kind,
                    target_ref,
                    rollback_kind,
                    rollback_ref,
                    request_hash,
                    request_key,
                    detail,
                    created_by,
                    created_ts,
                    updated_ts,
                    force_sync,
                ) = params
                key = (str(proxy_id), str(request_key))
                result = _Result()
                existing_id = self.active_by_key.get(key)
                if existing_id is None:
                    row_id = self.next_id
                    self.next_id += 1
                    self.active_by_key[key] = row_id
                    self.rows[row_id] = _operation_row(
                        id=row_id,
                        proxy_id=proxy_id,
                        operation_type=operation_type,
                        subject=subject,
                        summary=summary,
                        target_kind=target_kind,
                        target_ref=target_ref,
                        rollback_kind=rollback_kind,
                        rollback_ref=rollback_ref,
                        request_hash=request_hash,
                        request_key=request_key,
                        detail=detail,
                        created_by=created_by,
                        created_ts=created_ts,
                        updated_ts=updated_ts,
                        force_sync=force_sync,
                    )
                else:
                    row_id = existing_id
                    row = self.rows[row_id]
                    row["summary"] = summary
                    row["detail"] = detail
                    row["created_by"] = created_by
                    row["updated_ts"] = updated_ts
                    row["force_sync"] = max(int(row["force_sync"]), int(force_sync))
                result.lastrowid = row_id
                return result
            if compact.startswith("UPDATE proxy_operations SET rollback_kind=%s"):
                rollback_kind, rollback_ref, row_id = params
                row = self.rows[int(row_id)]
                if not row.get("rollback_kind") or not row.get("rollback_ref"):
                    row["rollback_kind"] = rollback_kind
                    row["rollback_ref"] = rollback_ref
                return _Result()
            if compact.startswith("SELECT id, proxy_id, status"):
                row_id = int(params[0])
                return _Result([self.rows[row_id]])
            return _Result()

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            if exc_type is None:
                self.committed = True
            return False

    conn = _StatefulCreateConnection()
    ledger = OperationLedger()
    monkeypatch.setattr(ledger, "init_db", lambda: None)
    monkeypatch.setattr(ledger, "_connect", lambda: conn)
    now = iter([100, 101])
    monkeypatch.setattr("services.operation_ledger.time.time", lambda: next(now))

    first = ledger.create_operation(
        "edge-a",
        operation_type="config_apply",
        subject="Squid config",
        summary="Initial apply without rollback",
        target_kind="config_revision",
        target_ref=17,
        request_hash="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        detail="initial detail",
        created_by="operator-a",
    )
    duplicate = ledger.create_operation(
        "edge-a",
        operation_type="config_apply",
        subject="Squid config",
        summary="Duplicate apply with rollback",
        target_kind="config_revision",
        target_ref=17,
        rollback_kind="config_revision",
        rollback_ref=3,
        request_hash="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        detail="duplicate detail",
        created_by="operator-b",
        force=True,
    )

    assert first.operation_id == duplicate.operation_id
    assert first.can_revert is False
    assert duplicate.rollback_kind == "config_revision"
    assert duplicate.rollback_ref == "3"
    assert duplicate.can_revert is True
    assert duplicate.summary == "Duplicate apply with rollback"
    assert duplicate.detail == "duplicate detail"
    assert duplicate.created_by == "operator-b"
    assert duplicate.force is True
    rollback_updates = [
        query
        for query, _params in conn.queries
        if query.startswith("UPDATE proxy_operations SET rollback_kind=%s")
    ]
    assert rollback_updates == [
        "UPDATE proxy_operations SET rollback_kind=%s, rollback_ref=%s WHERE id=%s AND (rollback_kind='' OR rollback_ref='')",
    ]
    assert conn.committed is True


def test_duplicate_requests_refresh_mutable_fields_without_replacing_rollback(
    monkeypatch,
) -> None:
    from services.operation_ledger import OperationLedger

    class _StatefulCreateConnection:
        def __init__(self) -> None:
            self.queries = []
            self.committed = False
            self.rows: dict[int, dict[str, object]] = {}
            self.active_by_key: dict[tuple[str, str], int] = {}
            self.next_id = 11

        def execute(self, sql, params=()):
            compact = " ".join(str(sql).split())
            params = tuple(params or ())
            self.queries.append((compact, params))
            if compact.startswith("INSERT INTO proxy_operations"):
                (
                    proxy_id,
                    operation_type,
                    subject,
                    summary,
                    target_kind,
                    target_ref,
                    rollback_kind,
                    rollback_ref,
                    request_hash,
                    request_key,
                    detail,
                    created_by,
                    created_ts,
                    updated_ts,
                    force_sync,
                ) = params
                key = (str(proxy_id), str(request_key))
                result = _Result()
                existing_id = self.active_by_key.get(key)
                if existing_id is None:
                    row_id = self.next_id
                    self.next_id += 1
                    self.active_by_key[key] = row_id
                    self.rows[row_id] = _operation_row(
                        id=row_id,
                        proxy_id=proxy_id,
                        operation_type=operation_type,
                        subject=subject,
                        summary=summary,
                        target_kind=target_kind,
                        target_ref=target_ref,
                        rollback_kind=rollback_kind,
                        rollback_ref=rollback_ref,
                        request_hash=request_hash,
                        detail=detail,
                        created_by=created_by,
                        created_ts=created_ts,
                        updated_ts=updated_ts,
                        force_sync=force_sync,
                    )
                else:
                    row_id = existing_id
                    row = self.rows[row_id]
                    row["summary"] = summary
                    row["detail"] = detail
                    row["created_by"] = created_by
                    row["updated_ts"] = updated_ts
                    row["force_sync"] = max(int(row["force_sync"]), int(force_sync))
                    if "rollback_kind=VALUES(rollback_kind)" in compact:
                        row["rollback_kind"] = rollback_kind
                    if "rollback_ref=VALUES(rollback_ref)" in compact:
                        row["rollback_ref"] = rollback_ref
                result.lastrowid = row_id
                return result
            if compact.startswith("SELECT id, proxy_id, status"):
                row_id = int(params[0])
                return _Result([self.rows[row_id]])
            return _Result()

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            if exc_type is None:
                self.committed = True
            return False

    conn = _StatefulCreateConnection()
    ledger = OperationLedger()
    monkeypatch.setattr(ledger, "init_db", lambda: None)
    monkeypatch.setattr(ledger, "_connect", lambda: conn)
    now = iter([100, 101, 102])
    monkeypatch.setattr("services.operation_ledger.time.time", lambda: next(now))
    monkeypatch.setattr(
        "services.operation_ledger.secrets.token_hex", lambda _n: "claim-1"
    )

    first = ledger.create_operation(
        "edge-a",
        operation_type="config_apply",
        subject="Squid config",
        summary="First summary",
        target_kind="config_revision",
        target_ref=17,
        rollback_kind="config_revision",
        rollback_ref=3,
        request_hash="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        detail="first detail",
        created_by="operator-a",
        force=False,
    )
    duplicate = ledger.create_operation(
        "edge-a",
        operation_type="config_apply",
        subject="Squid config",
        summary="Duplicate summary",
        target_kind="config_revision",
        target_ref=17,
        rollback_kind="config_revision",
        rollback_ref=17,
        request_hash="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        detail="duplicate detail",
        created_by="operator-b",
        force=True,
    )
    distinct = ledger.create_operation(
        "edge-a",
        operation_type="config_apply",
        subject="Squid config",
        summary="Distinct summary",
        target_kind="config_revision",
        target_ref=18,
        rollback_kind="config_revision",
        rollback_ref=17,
        request_hash="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        detail="distinct detail",
        created_by="operator-c",
        force=False,
    )

    assert duplicate.operation_id == first.operation_id
    assert duplicate.rollback_kind == "config_revision"
    assert duplicate.rollback_ref == "3"
    assert duplicate.summary == "Duplicate summary"
    assert duplicate.detail == "duplicate detail"
    assert duplicate.created_by == "operator-b"
    assert duplicate.force is True
    assert distinct.operation_id != first.operation_id
    assert distinct.target_ref == "18"
    assert distinct.rollback_ref == "17"


@pytest.mark.parametrize(
    ("operation_type", "target_kind", "target_ref", "rollback_kind", "rollback_ref"),
    [
        ("config_apply", "config_revision", 17, "config_revision", 3),
        ("certificate_apply", "certificate_revision", 9, "certificate_revision", 5),
        ("policy_sync", "policy_state", POLICY_SHA, "", ""),
    ],
)
def test_duplicate_request_dedupes_existing_operation_types_without_regressing_updates(
    monkeypatch,
    operation_type,
    target_kind,
    target_ref,
    rollback_kind,
    rollback_ref,
) -> None:
    from services.operation_ledger import OperationLedger

    row = _operation_row(
        id=77,
        operation_type=operation_type,
        target_kind=target_kind,
        target_ref=str(target_ref),
        rollback_kind=str(rollback_kind),
        rollback_ref=str(rollback_ref),
        summary="new summary",
        detail="new detail",
        created_by="operator-b",
        force_sync=1,
    )

    class _Connection:
        def __init__(self) -> None:
            self.queries = []

        def execute(self, sql, params=()):
            compact = " ".join(str(sql).split())
            self.queries.append((compact, tuple(params or ())))
            if compact.startswith("INSERT INTO proxy_operations"):
                result = _Result()
                result.lastrowid = 77
                return result
            if compact.startswith("SELECT id, proxy_id, status"):
                return _Result([row])
            return _Result()

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    conn = _Connection()
    ledger = OperationLedger()
    monkeypatch.setattr(ledger, "init_db", lambda: None)
    monkeypatch.setattr(ledger, "_connect", lambda: conn)
    monkeypatch.setattr("services.operation_ledger.time.time", lambda: 200)

    op = ledger.create_operation(
        "edge-a",
        operation_type=operation_type,
        subject="Operation subject",
        summary="new summary",
        target_kind=target_kind,
        target_ref=target_ref,
        rollback_kind=rollback_kind,
        rollback_ref="replacement" if rollback_kind else "",
        request_hash="cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        detail="new detail",
        created_by="operator-b",
        force=True,
    )

    assert op.operation_id == 77
    assert op.rollback_kind == str(rollback_kind)
    assert op.rollback_ref == str(rollback_ref)
    assert op.summary == "new summary"
    assert op.detail == "new detail"
    assert op.created_by == "operator-b"
    assert op.force is True


def test_duplicate_while_applying_returns_same_id_preserves_rollback_and_no_pending(
    monkeypatch,
) -> None:
    from services.operation_ledger import OperationLedger

    class _ApplyingConnection:
        def __init__(self) -> None:
            self.rows: dict[int, dict[str, object]] = {}
            self.active_by_key: dict[tuple[str, str], int] = {}
            self.next_id = 1
            self.queries = []

        def execute(self, sql, params=()):
            compact = " ".join(str(sql).split())
            params = tuple(params or ())
            self.queries.append((compact, params))
            if compact.startswith("INSERT INTO proxy_operations"):
                (
                    proxy_id,
                    operation_type,
                    subject,
                    summary,
                    target_kind,
                    target_ref,
                    rollback_kind,
                    rollback_ref,
                    request_hash,
                    request_key,
                    detail,
                    created_by,
                    created_ts,
                    updated_ts,
                    force_sync,
                ) = params
                key = (str(proxy_id), str(request_key))
                row_id = self.active_by_key.get(key)
                if row_id is None:
                    row_id = self.next_id
                    self.next_id += 1
                    self.active_by_key[key] = row_id
                    self.rows[row_id] = _operation_row(
                        id=row_id,
                        proxy_id=proxy_id,
                        status="pending",
                        operation_type=operation_type,
                        subject=subject,
                        summary=summary,
                        target_kind=target_kind,
                        target_ref=target_ref,
                        rollback_kind=rollback_kind,
                        rollback_ref=rollback_ref,
                        request_hash=request_hash,
                        request_key=request_key,
                        detail=detail,
                        created_by=created_by,
                        created_ts=created_ts,
                        updated_ts=updated_ts,
                        force_sync=force_sync,
                    )
                else:
                    row = self.rows[row_id]
                    row["summary"] = summary
                    row["detail"] = detail
                    row["created_by"] = created_by
                    row["updated_ts"] = updated_ts
                    row["force_sync"] = max(int(row["force_sync"]), int(force_sync))
                result = _Result()
                result.lastrowid = row_id
                return result
            if compact.startswith("SELECT id FROM proxy_operations"):
                pending = [
                    {"id": row_id}
                    for row_id, row in sorted(self.rows.items())
                    if row.get("proxy_id") == params[0]
                    and row.get("status") == "pending"
                ]
                return _Result(pending[: int(params[-1])])
            if compact.startswith("UPDATE proxy_operations SET status='applying'"):
                for row_id in params[4:]:
                    row = self.rows[int(row_id)]
                    row["status"] = "applying"
                    row["started_ts"] = params[0]
                    row["updated_ts"] = params[1]
                    row["claim_token"] = params[2]
                    if "request_key=NULL" in compact:
                        key = (str(row["proxy_id"]), str(row["request_key"]))
                        row["request_key"] = None
                        self.active_by_key.pop(key, None)
                return _Result()
            if (
                compact.startswith("SELECT id, proxy_id, status")
                and "claim_token=%s" in compact
            ):
                ids = {int(value) for value in params[2:]}
                return _Result(
                    [
                        row
                        for row_id, row in sorted(self.rows.items())
                        if row.get("proxy_id") == params[0]
                        and row.get("status") == "applying"
                        and row_id in ids
                    ]
                )
            if compact.startswith("SELECT id, proxy_id, status"):
                return _Result([self.rows[int(params[0])]])
            return _Result()

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    conn = _ApplyingConnection()
    ledger = OperationLedger()
    monkeypatch.setattr(ledger, "init_db", lambda: None)
    monkeypatch.setattr(ledger, "_connect", lambda: conn)
    now = iter([100, 101, 102])
    monkeypatch.setattr("services.operation_ledger.time.time", lambda: next(now))
    monkeypatch.setattr(
        "services.operation_ledger.secrets.token_hex", lambda _n: "claim-1"
    )

    first = ledger.create_operation(
        "edge-a",
        operation_type="config_apply",
        subject="Squid config",
        summary="Apply revision 17",
        target_kind="config_revision",
        target_ref=17,
        rollback_kind="config_revision",
        rollback_ref=3,
        request_hash="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        detail="first",
        created_by="operator-a",
    )
    claimed = ledger.claim_pending("edge-a", limit=10)
    duplicate = ledger.create_operation(
        "edge-a",
        operation_type="config_apply",
        subject="Squid config",
        summary="Duplicate apply revision 17",
        target_kind="config_revision",
        target_ref=17,
        rollback_kind="config_revision",
        rollback_ref=17,
        request_hash="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        detail="duplicate",
        created_by="operator-b",
        force=True,
    )

    assert [op.operation_id for op in claimed] == [first.operation_id]
    assert duplicate.operation_id == first.operation_id
    assert duplicate.status == "applying"
    assert duplicate.rollback_ref == "3"
    assert duplicate.force is True
    assert [row["status"] for row in conn.rows.values()].count("pending") == 0
    assert len(conn.rows) == 1


def test_terminal_release_allows_genuine_retry_new_operation(monkeypatch) -> None:
    from services.operation_ledger import OperationLedger

    class _RetryConnection:
        def __init__(self) -> None:
            self.rows: dict[int, dict[str, object]] = {}
            self.active_by_key: dict[tuple[str, str], int] = {}
            self.next_id = 1

        def execute(self, sql, params=()):
            compact = " ".join(str(sql).split())
            params = tuple(params or ())
            if compact.startswith("INSERT INTO proxy_operations"):
                (
                    proxy_id,
                    operation_type,
                    subject,
                    summary,
                    target_kind,
                    target_ref,
                    rollback_kind,
                    rollback_ref,
                    request_hash,
                    request_key,
                    detail,
                    created_by,
                    created_ts,
                    updated_ts,
                    force_sync,
                ) = params
                key = (str(proxy_id), str(request_key))
                row_id = self.active_by_key.get(key)
                if row_id is None:
                    row_id = self.next_id
                    self.next_id += 1
                    self.active_by_key[key] = row_id
                    self.rows[row_id] = _operation_row(
                        id=row_id,
                        proxy_id=proxy_id,
                        operation_type=operation_type,
                        subject=subject,
                        summary=summary,
                        target_kind=target_kind,
                        target_ref=target_ref,
                        rollback_kind=rollback_kind,
                        rollback_ref=rollback_ref,
                        request_hash=request_hash,
                        request_key=request_key,
                        detail=detail,
                        created_by=created_by,
                        created_ts=created_ts,
                        updated_ts=updated_ts,
                        force_sync=force_sync,
                    )
                result = _Result()
                result.lastrowid = row_id
                return result
            if compact.startswith("SELECT proxy_id FROM proxy_operations"):
                return _Result([{"proxy_id": self.rows[int(params[0])]["proxy_id"]}])
            if compact.startswith("UPDATE proxy_operations SET status=%s"):
                (
                    status,
                    detail,
                    completed_ts,
                    updated_ts,
                    release_key,
                    release_claim,
                    row_id,
                    proxy_id,
                ) = params
                row = self.rows[int(row_id)]
                if row["proxy_id"] != proxy_id:
                    return _Result()
                if release_key:
                    self.active_by_key.pop(
                        (str(row["proxy_id"]), str(row["request_key"])), None
                    )
                    row["request_key"] = None
                if release_claim:
                    row["claim_token"] = None
                row["status"] = status
                row["detail"] = detail
                row["completed_ts"] = completed_ts
                row["updated_ts"] = updated_ts
                return _Result()
            if compact.startswith("SELECT id, proxy_id, status"):
                return _Result([self.rows[int(params[0])]])
            return _Result()

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    conn = _RetryConnection()
    ledger = OperationLedger()
    monkeypatch.setattr(ledger, "init_db", lambda: None)
    monkeypatch.setattr(ledger, "_connect", lambda: conn)
    now = iter([100, 101, 102])
    monkeypatch.setattr("services.operation_ledger.time.time", lambda: next(now))
    monkeypatch.setattr(
        "services.operation_ledger.secrets.token_hex", lambda _n: "claim-1"
    )

    first = ledger.create_operation(
        "edge-a",
        operation_type="cache_clear",
        subject="Proxy cache clear",
        summary="clear",
        request_hash="",
    )
    completed = ledger.mark_status(first.operation_id, status="applied", detail="done")
    retry = ledger.create_operation(
        "edge-a",
        operation_type="cache_clear",
        subject="Proxy cache clear",
        summary="clear again",
        request_hash="",
    )

    assert completed is not None
    assert completed.status == "applied"
    assert retry.operation_id != first.operation_id
    assert retry.status == "pending"
    assert len(conn.rows) == 2


def test_multi_proxy_same_request_key_is_isolated(monkeypatch) -> None:
    from services.operation_ledger import OperationLedger

    class _MultiProxyConnection:
        def __init__(self) -> None:
            self.rows: dict[int, dict[str, object]] = {}
            self.active_by_key: dict[tuple[str, str], int] = {}
            self.next_id = 1

        def execute(self, sql, params=()):
            compact = " ".join(str(sql).split())
            params = tuple(params or ())
            if compact.startswith("INSERT INTO proxy_operations"):
                proxy_id = str(params[0])
                request_key = str(params[9])
                row_id = self.active_by_key.get((proxy_id, request_key))
                if row_id is None:
                    row_id = self.next_id
                    self.next_id += 1
                    self.active_by_key[proxy_id, request_key] = row_id
                    self.rows[row_id] = _operation_row(
                        id=row_id,
                        proxy_id=proxy_id,
                        operation_type=params[1],
                        subject=params[2],
                        summary=params[3],
                        target_kind=params[4],
                        target_ref=params[5],
                        rollback_kind=params[6],
                        rollback_ref=params[7],
                        request_hash=params[8],
                        request_key=request_key,
                        detail=params[10],
                        created_by=params[11],
                        created_ts=params[12],
                        updated_ts=params[13],
                        force_sync=params[14],
                    )
                result = _Result()
                result.lastrowid = row_id
                return result
            if compact.startswith("SELECT id, proxy_id, status"):
                return _Result([self.rows[int(params[0])]])
            return _Result()

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    conn = _MultiProxyConnection()
    ledger = OperationLedger()
    monkeypatch.setattr(ledger, "init_db", lambda: None)
    monkeypatch.setattr(ledger, "_connect", lambda: conn)
    monkeypatch.setattr("services.operation_ledger.time.time", lambda: 123)

    kwargs = {
        "operation_type": "policy_sync",
        "subject": "Policy reconciliation",
        "summary": "policy",
        "target_kind": "policy_state",
        "target_ref": POLICY_SHA,
        "request_hash": "",
    }
    edge_a = ledger.create_operation("edge-a", **kwargs)
    edge_b = ledger.create_operation("edge-b", **kwargs)
    edge_a_duplicate = ledger.create_operation("edge-a", **kwargs)

    assert edge_a.operation_id != edge_b.operation_id
    assert edge_a_duplicate.operation_id == edge_a.operation_id
    assert len(conn.rows) == 2


def test_terminal_status_releases_active_request_key(monkeypatch) -> None:
    from services.operation_ledger import OperationLedger

    conn = _Connection()
    ledger = OperationLedger()
    monkeypatch.setattr(ledger, "init_db", lambda: None)
    monkeypatch.setattr(ledger, "_connect", lambda: conn)
    monkeypatch.setattr("services.operation_ledger.time.time", lambda: 456)

    ledger.mark_status(7, status="superseded", detail="newer revision applied")

    update_sql, update_params = conn.queries[1]
    assert "request_key=IF(%s, NULL, request_key)" in update_sql
    assert "claim_token=IF(%s, NULL, claim_token)" in update_sql
    assert update_params == (
        "superseded",
        "newer revision applied",
        456,
        456,
        True,
        True,
        7,
        "edge-a",
    )


def test_terminal_status_does_not_overwrite_existing_terminal_operation(
    monkeypatch,
) -> None:
    from services.operation_ledger import OperationLedger

    class _TerminalConnection:
        def __init__(self) -> None:
            self.row = _operation_row(
                id=7,
                status="applied",
                detail="already applied",
                completed_ts=600,
                updated_ts=600,
                request_key=None,
                claim_token=None,
            )
            self.queries = []

        def execute(self, sql, params=()):
            compact = " ".join(str(sql).split())
            params = tuple(params or ())
            self.queries.append((compact, params))
            if compact.startswith("SELECT proxy_id FROM proxy_operations"):
                return _Result([{"proxy_id": self.row["proxy_id"]}])
            if compact.startswith("UPDATE proxy_operations SET status=%s"):
                if "AND status NOT IN ('applied','superseded','failed')" not in compact:
                    self.row["status"] = params[0]
                    self.row["detail"] = params[1]
                result = _Result()
                result.rowcount = 0
                return result
            if compact.startswith("SELECT id, proxy_id, status"):
                return _Result([self.row])
            return _Result()

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    conn = _TerminalConnection()
    ledger = OperationLedger()
    monkeypatch.setattr(ledger, "init_db", lambda: None)
    monkeypatch.setattr(ledger, "_connect", lambda: conn)
    monkeypatch.setattr("services.operation_ledger.time.time", lambda: 789)

    current = ledger.mark_status(7, status="failed", detail="late failure")

    assert current is not None
    assert current.status == "applied"
    assert current.detail == "already applied"
    assert not any(
        query.startswith("UPDATE proxy_operations SET status=%s")
        for query, _params in conn.queries
    )


def test_non_terminal_status_keeps_active_request_key(monkeypatch) -> None:
    from services.operation_ledger import OperationLedger

    conn = _Connection()
    ledger = OperationLedger()
    monkeypatch.setattr(ledger, "init_db", lambda: None)
    monkeypatch.setattr(ledger, "_connect", lambda: conn)
    monkeypatch.setattr("services.operation_ledger.time.time", lambda: 789)

    ledger.mark_status(7, status="applying", detail="retrying")

    update_sql, update_params = conn.queries[1]
    assert "request_key=IF(%s, NULL, request_key)" in update_sql
    assert "claim_token=IF(%s, NULL, claim_token)" in update_sql
    assert "AND status NOT IN ('applied','superseded','failed')" in update_sql
    assert update_params == ("applying", "retrying", 0, 789, False, False, 7, "edge-a")


def test_non_terminal_status_cannot_reopen_terminal_operation(monkeypatch) -> None:
    from services.operation_ledger import OperationLedger

    class _TerminalConnection:
        def __init__(self) -> None:
            self.row = _operation_row(
                id=7,
                status="applied",
                detail="already completed",
                completed_ts=600,
                updated_ts=600,
                request_key=None,
                claim_token=None,
            )
            self.queries = []

        def execute(self, sql, params=()):
            compact = " ".join(str(sql).split())
            params = tuple(params or ())
            self.queries.append((compact, params))
            if compact.startswith("SELECT proxy_id FROM proxy_operations"):
                return _Result([{"proxy_id": self.row["proxy_id"]}])
            if compact.startswith("UPDATE proxy_operations SET status=%s"):
                if "AND status NOT IN ('applied','superseded','failed')" not in compact:
                    self.row["status"] = params[0]
                    self.row["detail"] = params[1]
                    self.row["completed_ts"] = params[2]
                    self.row["updated_ts"] = params[3]
                result = _Result()
                result.rowcount = 0
                return result
            if compact.startswith("SELECT id, proxy_id, status"):
                return _Result([self.row])
            return _Result()

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    conn = _TerminalConnection()
    ledger = OperationLedger()
    monkeypatch.setattr(ledger, "init_db", lambda: None)
    monkeypatch.setattr(ledger, "_connect", lambda: conn)
    monkeypatch.setattr("services.operation_ledger.time.time", lambda: 789)

    current = ledger.mark_status(7, status="applying", detail="late retry")

    assert current is not None
    assert current.status == "applied"
    assert current.detail == "already completed"
    assert not any(
        query.startswith("UPDATE proxy_operations SET status=%s")
        for query, _params in conn.queries
    )
