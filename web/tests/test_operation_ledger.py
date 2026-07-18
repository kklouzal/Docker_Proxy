from __future__ import annotations

import sys
from pathlib import Path

import pytest


def _add_repo_paths() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    for path in (repo_root, repo_root / "web"):
        path_text = str(path)
        if path_text not in sys.path:
            sys.path.insert(0, path_text)


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
        "request_hash": "abc123",
        "detail": "",
        "created_by": "admin",
        "created_ts": 123,
        "started_ts": 0,
        "completed_ts": 0,
        "updated_ts": 123,
        "force_sync": 0,
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
        if compact.startswith("SELECT id FROM proxy_operations"):
            return _Result([{"id": 7}, {"id": 8}])
        if compact.startswith("SELECT * FROM proxy_operations"):
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
                "detail": "",
                "created_by": "",
                "started_ts": 2,
                "completed_ts": 0,
                "updated_ts": 2,
                "force_sync": 0,
            }
            return _Result(
                [dict(base, id=7, created_ts=1), dict(base, id=8, created_ts=2)],
            )
        return _Result()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is None:
            self.committed = True
        return False


def test_init_db_backfills_active_request_keys_before_unique_index(monkeypatch) -> None:
    _add_repo_paths()
    from services.operation_ledger import OperationLedger

    conn = _Connection()
    ledger = OperationLedger()
    monkeypatch.setattr(ledger, "_connect", lambda: conn)
    monkeypatch.setattr(ledger, "_column_exists", lambda *_args: True)
    monkeypatch.setattr(ledger, "_index_exists", lambda *_args: False)
    monkeypatch.setattr("services.operation_ledger.time.time", lambda: 123)

    ledger.init_db()

    sql = [query for query, _params in conn.queries]
    create_index_pos = next(
        i
        for i, query in enumerate(sql)
        if query.startswith("ALTER TABLE proxy_operations ADD UNIQUE KEY")
    )
    clear_pos = next(
        i
        for i, query in enumerate(sql)
        if query.startswith("UPDATE proxy_operations SET request_key=NULL")
    )
    supersede_pos = next(
        i
        for i, query in enumerate(sql)
        if query.startswith("UPDATE proxy_operations pending JOIN")
    )
    backfill_pos = next(
        i
        for i, query in enumerate(sql)
        if query.startswith("UPDATE proxy_operations SET request_key=SHA2")
    )
    assert clear_pos < supersede_pos < backfill_pos < create_index_pos
    supersede_sql, supersede_params = conn.queries[supersede_pos]
    assert "ROW_NUMBER() OVER ( PARTITION BY proxy_id, SHA2(CONCAT(" in supersede_sql
    assert "WHERE status='pending'" in supersede_sql
    assert "pending.status='superseded'" in supersede_sql
    assert supersede_params == (123, 123)
    assert "WHERE status='pending'" in sql[backfill_pos]
    assert conn.committed is True


def test_claim_pending_locks_and_updates_claimed_rows_in_one_transaction(
    monkeypatch,
) -> None:
    _add_repo_paths()
    from services.operation_ledger import OperationLedger

    conn = _Connection()
    ledger = OperationLedger()
    monkeypatch.setattr(ledger, "init_db", lambda: None)
    monkeypatch.setattr(ledger, "_connect", lambda: conn)
    monkeypatch.setattr("services.operation_ledger.time.time", lambda: 123)
    claimed = ledger.claim_pending("edge-a", limit=2)
    assert [op.operation_id for op in claimed] == [7, 8]
    select_sql, select_params = conn.queries[0]
    assert "FOR UPDATE SKIP LOCKED" in select_sql
    assert "status='pending'" in select_sql
    assert select_params == ("edge-a", 2)
    update_sql, update_params = conn.queries[1]
    assert update_sql.startswith("UPDATE proxy_operations SET status='applying'")
    assert "request_key=NULL" in update_sql
    assert update_params == (123, 123, "edge-a", 7, 8)
    assert conn.committed is True


def test_claim_pending_can_target_single_operation_id(monkeypatch) -> None:
    _add_repo_paths()
    from services.operation_ledger import OperationLedger

    conn = _Connection()
    ledger = OperationLedger()
    monkeypatch.setattr(ledger, "init_db", lambda: None)
    monkeypatch.setattr(ledger, "_connect", lambda: conn)
    monkeypatch.setattr("services.operation_ledger.time.time", lambda: 123)
    ledger.claim_pending("edge-a", limit=50, operation_id=7)
    select_sql, select_params = conn.queries[0]
    assert "AND id=%s" in select_sql
    assert "LIMIT %s FOR UPDATE SKIP LOCKED" in select_sql
    assert select_params == ("edge-a", 7, 1)


def test_claim_pending_preserves_force_flag(monkeypatch) -> None:
    _add_repo_paths()
    from services.operation_ledger import OperationLedger

    conn = _Connection()
    ledger = OperationLedger()
    monkeypatch.setattr(ledger, "init_db", lambda: None)
    monkeypatch.setattr(ledger, "_connect", lambda: conn)
    monkeypatch.setattr("services.operation_ledger.time.time", lambda: 123)

    claimed = ledger.claim_pending("edge-a", limit=2)

    assert claimed
    assert [op.force for op in claimed] == [False, False]


def test_requeue_stale_applying_restores_active_request_key(monkeypatch) -> None:
    _add_repo_paths()
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
    assert supersede_sql.startswith("UPDATE proxy_operations stale JOIN")
    assert "pending.request_key=SHA2(CONCAT(" in supersede_sql
    assert "stale.request_key=NULL" in supersede_sql
    assert supersede_params == (1000, 1000, "edge-a", 700)
    duplicate_sql, duplicate_params = conn.queries[1]
    assert duplicate_sql.startswith("UPDATE proxy_operations stale JOIN")
    assert "JOIN proxy_operations dup" in duplicate_sql
    assert "dup.id>stale.id" in duplicate_sql
    assert "dup.status='applying'" in duplicate_sql
    assert "dup.request_hash" in duplicate_sql
    assert "stale.request_key=NULL" in duplicate_sql
    assert duplicate_params == (700, 1000, 1000, "edge-a", 700)
    requeue_sql, requeue_params = conn.queries[2]
    assert requeue_sql.startswith("UPDATE proxy_operations stale LEFT JOIN")
    assert "pending.request_key=SHA2(CONCAT(" in requeue_sql
    assert "pending.id IS NULL" in requeue_sql
    assert "SET stale.status='pending'" in requeue_sql
    assert "request_key=SHA2(CONCAT(" in requeue_sql
    assert "COALESCE(NULLIF(stale.operation_type,''),'sync')" in requeue_sql
    assert requeue_params == (1000, "edge-a", 700)
    assert conn.committed is True


def test_create_operation_uses_active_request_upsert(monkeypatch) -> None:
    _add_repo_paths()
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
        request_hash="abc123",
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


def test_duplicate_active_request_preserves_original_rollback_metadata(
    monkeypatch,
) -> None:
    _add_repo_paths()
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
        request_hash="abc123",
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


def test_duplicate_requests_refresh_mutable_fields_without_replacing_rollback(
    monkeypatch,
) -> None:
    _add_repo_paths()
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

    first = ledger.create_operation(
        "edge-a",
        operation_type="config_apply",
        subject="Squid config",
        summary="First summary",
        target_kind="config_revision",
        target_ref=17,
        rollback_kind="config_revision",
        rollback_ref=3,
        request_hash="abc123",
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
        request_hash="abc123",
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
        request_hash="def456",
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
        ("policy_sync", "policy_state", "policy-sha", "", ""),
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
    _add_repo_paths()
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
        request_hash="request-sha",
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


def test_terminal_status_releases_active_request_key(monkeypatch) -> None:
    _add_repo_paths()
    from services.operation_ledger import OperationLedger

    conn = _Connection()
    ledger = OperationLedger()
    monkeypatch.setattr(ledger, "init_db", lambda: None)
    monkeypatch.setattr(ledger, "_connect", lambda: conn)
    monkeypatch.setattr("services.operation_ledger.time.time", lambda: 456)

    ledger.mark_status(7, status="superseded", detail="newer revision applied")

    update_sql, update_params = conn.queries[0]
    assert "request_key=IF(%s, NULL, request_key)" in update_sql
    assert update_params == ("superseded", "newer revision applied", 456, 456, True, 7)


def test_non_terminal_status_keeps_active_request_key(monkeypatch) -> None:
    _add_repo_paths()
    from services.operation_ledger import OperationLedger

    conn = _Connection()
    ledger = OperationLedger()
    monkeypatch.setattr(ledger, "init_db", lambda: None)
    monkeypatch.setattr(ledger, "_connect", lambda: conn)
    monkeypatch.setattr("services.operation_ledger.time.time", lambda: 789)

    ledger.mark_status(7, status="applying", detail="retrying")

    update_sql, update_params = conn.queries[0]
    assert "request_key=IF(%s, NULL, request_key)" in update_sql
    assert update_params == ("applying", "retrying", 0, 789, False, 7)
