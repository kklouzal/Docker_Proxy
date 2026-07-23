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
        "request_key": "".rjust(64, "a"),
        "detail": "",
        "created_by": "admin",
        "created_ts": 123,
        "started_ts": 0,
        "completed_ts": 0,
        "updated_ts": 123,
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
    _add_repo_paths()
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
    _add_repo_paths()
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


def test_list_recent_since_preserves_claim_token(monkeypatch) -> None:
    _add_repo_paths()
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
    assert supersede_sql.startswith("UPDATE proxy_operations active JOIN")
    assert "status IN ('pending','applying')" in supersede_sql
    assert "ROW_NUMBER" not in supersede_sql.upper()
    assert "JOIN ( SELECT proxy_id, request_key FROM" in supersede_sql
    assert "FROM proxy_operations stale_source" in supersede_sql
    assert "JOIN proxy_operations keeper" in supersede_sql
    assert "CASE WHEN keeper.status='applying' AND keeper.started_ts>=%s THEN 0" in supersede_sql
    assert "active.status='superseded'" in supersede_sql
    assert "active.request_key=NULL" in supersede_sql
    assert "active.claim_token=NULL" in supersede_sql
    assert supersede_params == ("edge-a", 700, 700, 700, 700, 700, 1000, 1000, "edge-a")
    requeue_sql, requeue_params = conn.queries[1]
    assert requeue_sql.startswith("UPDATE proxy_operations stale LEFT JOIN")
    assert "active.status IN ('pending','applying')" in requeue_sql
    assert "active.id IS NULL" in requeue_sql
    assert "SET stale.status='pending'" in requeue_sql
    assert "request_key=SHA2(CONCAT(" in requeue_sql
    assert "stale.claim_token=NULL" in requeue_sql
    assert "COALESCE(NULLIF(stale.operation_type,''),'sync')" in requeue_sql
    assert requeue_params == (1000, "edge-a", 700)
    assert conn.committed is True


def test_claim_pending_returns_only_rows_claimed_by_current_token(monkeypatch) -> None:
    _add_repo_paths()
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
    _add_repo_paths()
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

    update_sql, update_params = conn.queries[0]
    assert "WHERE id=%s AND status=%s AND claim_token=%s" in update_sql
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
    )


def test_stale_claim_completion_does_not_overwrite_reclaimed_operation_detail(
    monkeypatch,
) -> None:
    _add_repo_paths()
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
    update_sql, update_params = conn.queries[0]
    assert "WHERE id=%s AND status=%s AND claim_token=%s" in update_sql
    assert update_params[-3:] == (11, "applying", "old-claim")


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


def test_duplicate_while_applying_returns_same_id_preserves_rollback_and_no_pending(
    monkeypatch,
) -> None:
    _add_repo_paths()
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
        request_hash="abc123",
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
        request_hash="abc123",
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
    _add_repo_paths()
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
            if compact.startswith("UPDATE proxy_operations SET status=%s"):
                (
                    status,
                    detail,
                    completed_ts,
                    updated_ts,
                    release_key,
                    release_claim,
                    row_id,
                ) = params
                row = self.rows[int(row_id)]
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
    _add_repo_paths()
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
        "target_ref": "same-sha",
        "request_hash": "same-sha",
    }
    edge_a = ledger.create_operation("edge-a", **kwargs)
    edge_b = ledger.create_operation("edge-b", **kwargs)
    edge_a_duplicate = ledger.create_operation("edge-a", **kwargs)

    assert edge_a.operation_id != edge_b.operation_id
    assert edge_a_duplicate.operation_id == edge_a.operation_id
    assert len(conn.rows) == 2


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
    assert "claim_token=IF(%s, NULL, claim_token)" in update_sql
    assert update_params == (
        "superseded",
        "newer revision applied",
        456,
        456,
        True,
        True,
        7,
    )


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
    assert "claim_token=IF(%s, NULL, claim_token)" in update_sql
    assert "AND status NOT IN ('applied','superseded','failed')" in update_sql
    assert update_params == ("applying", "retrying", 0, 789, False, False, 7)


def test_non_terminal_status_cannot_reopen_terminal_operation(monkeypatch) -> None:
    _add_repo_paths()
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
    update_sql, update_params = conn.queries[0]
    assert "AND status NOT IN ('applied','superseded','failed')" in update_sql
    assert update_params == ("applying", "late retry", 0, 789, False, False, 7)
