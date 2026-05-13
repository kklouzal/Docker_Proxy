from __future__ import annotations
from pathlib import Path
import sys


def _add_repo_paths() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    for path in (repo_root, repo_root / "web"):
        path_text = str(path)
        if path_text not in sys.path:
            sys.path.insert(0, path_text)


class _Result:
    def __init__(self, rows=None):
        self._rows = list(rows or [])
        self.rowcount = len(self._rows)
        self.lastrowid = None

    def fetchall(self):
        return list(self._rows)

    def fetchone(self):
        return self._rows[0] if self._rows else None


class _Connection:
    def __init__(self):
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
            }
            return _Result(
                [dict(base, id=7, created_ts=1), dict(base, id=8, created_ts=2)]
            )
        return _Result()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is None:
            self.committed = True
        return False


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
