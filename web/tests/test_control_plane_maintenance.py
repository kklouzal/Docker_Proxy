from __future__ import annotations

import pytest
from services import control_plane_maintenance as maintenance


class _CleanupResult:
    dropped_tables = ()
    discovered_tables = 0
    stale_tables = 0
    detail = ""


class _Result:
    def __init__(self, rowcount: int = 0, *, row=None) -> None:
        self.rowcount = rowcount
        self.row = row

    def fetchone(self):
        return self.row

    def fetchall(self):
        return [
            {"id": row_id, "proxy_id": f"edge-{row_id}"}
            for row_id in range(1, max(0, self.rowcount) + 1)
        ]


class _Connection:
    def __init__(self) -> None:
        self.queries: list[tuple[str, tuple[object, ...]]] = []

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def execute(self, sql, params=()):
        compact = " ".join(str(sql).split())
        params = tuple(params or ())
        self.queries.append((compact, params))
        return _Result(2)


def test_control_plane_prune_expires_policy_and_cache_rows(monkeypatch) -> None:
    conn = _Connection()
    tables = (
        "policy_exceptions",
        "safe_browsing_negative_cache",
        "proxy_operations",
    )
    monkeypatch.setattr(maintenance, "CONTROL_PLANE_MAINTENANCE_TABLES", tables)
    monkeypatch.setattr(maintenance, "_table_exists", lambda _table: True)
    monkeypatch.setattr(maintenance, "connect", lambda: conn)
    monkeypatch.setattr(
        maintenance,
        "_queue_policy_exception_expiry_policy_sync",
        lambda _proxy_id: True,
    )
    monkeypatch.setattr(maintenance.time, "time", lambda: 1_000_000)
    monkeypatch.setattr(
        maintenance,
        "cleanup_stale_webcat_build_tables",
        lambda *_args, **_kwargs: _CleanupResult(),
    )

    result = maintenance.prune_control_plane_tables(retention_days=1)

    assert result["ok"] is True
    assert result["pruned_tables"] == 3
    assert result["deleted_rows"] == 6
    assert result["updated_rows"] == 2
    sql = [query for query, _params in conn.queries]
    assert any(
        query.startswith("UPDATE policy_exceptions SET status='expired'")
        for query in sql
    )
    assert any(
        query.startswith("DELETE FROM `safe_browsing_negative_cache` WHERE expires_ts")
        for query in sql
    )
    assert any(
        "DELETE target FROM `proxy_operations` AS target" in query
        and "candidate.status IN ('applied','superseded','failed')" in query
        and "COUNT(*)" in query
        and "ROW_NUMBER" not in query.upper()
        for query in sql
    )


def test_control_plane_prune_keeps_active_blob_revisions(monkeypatch) -> None:
    from services import adblock_artifacts

    class FakeAdblockArtifactStore:
        def prune_revisions(self, *, max_batches=None):
            assert max_batches == 10
            return 3

    monkeypatch.setattr(
        maintenance,
        "CONTROL_PLANE_MAINTENANCE_TABLES",
        ("adblock_artifact_revisions",),
    )
    monkeypatch.setattr(maintenance, "_table_exists", lambda _table: True)
    monkeypatch.setattr(maintenance, "connect", _Connection)
    monkeypatch.setattr(
        adblock_artifacts, "AdblockArtifactStore", FakeAdblockArtifactStore
    )
    monkeypatch.setattr(maintenance.time, "time", lambda: 1_000_000)
    monkeypatch.setattr(
        maintenance,
        "cleanup_stale_webcat_build_tables",
        lambda *_args, **_kwargs: _CleanupResult(),
    )

    result = maintenance.prune_control_plane_tables(retention_days=30)

    assert result["ok"] is True
    assert result["deleted_rows"] == 3
    assert result["tables"][0]["table"] == "adblock_artifact_revisions"
    assert result["tables"][0]["status"] == "pruned"
    assert result["tables"][0]["deleted_rows"] == 3


def test_control_plane_prune_invokes_webcat_stale_build_table_cleanup(
    monkeypatch,
) -> None:
    conn = _Connection()
    calls: list[tuple[object, int]] = []

    class CleanupResult:
        dropped_tables = ("webcat_domains_stage_111_1000",)
        discovered_tables = 1
        stale_tables = 1
        detail = ""

    monkeypatch.setattr(maintenance, "CONTROL_PLANE_MAINTENANCE_TABLES", ())
    monkeypatch.setattr(maintenance, "connect", lambda: conn)
    monkeypatch.setattr(maintenance.time, "time", lambda: 5_000)

    def cleanup(cleanup_conn, *, now_ts: int):
        calls.append((cleanup_conn, now_ts))
        return CleanupResult()

    monkeypatch.setattr(maintenance, "cleanup_stale_webcat_build_tables", cleanup)

    result = maintenance.prune_control_plane_tables(retention_days=30)

    assert result["ok"] is True
    assert result["pruned_tables"] == 1
    assert result["deleted_rows"] == 1
    assert calls == [(conn, 5_000)]
    assert result["tables"] == [
        {
            "table": "webcat_build_tables",
            "status": "pruned",
            "deleted_rows": 1,
            "updated_rows": 0,
            "maintenance": "drop_stale",
            "detail": "dropped=1 discovered=1",
        },
    ]


def test_control_plane_prune_reports_webcat_cleanup_noop(monkeypatch) -> None:
    conn = _Connection()

    class CleanupResult:
        dropped_tables = ()
        discovered_tables = 0
        stale_tables = 0
        detail = "disabled"

    monkeypatch.setattr(maintenance, "CONTROL_PLANE_MAINTENANCE_TABLES", ())
    monkeypatch.setattr(maintenance, "connect", lambda: conn)
    monkeypatch.setattr(
        maintenance,
        "cleanup_stale_webcat_build_tables",
        lambda *_args, **_kwargs: CleanupResult(),
    )

    result = maintenance.prune_control_plane_tables(retention_days=30)

    assert result["ok"] is True
    assert result["pruned_tables"] == 0
    assert result["deleted_rows"] == 0
    assert result["tables"] == [
        {
            "table": "webcat_build_tables",
            "status": "noop",
            "deleted_rows": 0,
            "updated_rows": 0,
            "maintenance": "drop_stale",
            "detail": "disabled",
        },
    ]


def test_control_plane_maintenance_analyzes_existing_tables(monkeypatch) -> None:
    conn = _Connection()
    monkeypatch.setattr(
        maintenance,
        "CONTROL_PLANE_MAINTENANCE_TABLES",
        ("proxy_config_revisions", "missing_table"),
    )
    monkeypatch.setattr(
        maintenance,
        "_table_exists",
        lambda table: table == "proxy_config_revisions",
    )
    monkeypatch.setattr(maintenance, "connect", lambda: conn)

    result = maintenance.maintain_control_plane_tables(analyze=True, optimize=False)

    assert result["ok"] is True
    assert result["maintained_tables"] == 1
    assert ("ANALYZE TABLE `proxy_config_revisions`", ()) in conn.queries
    assert any(
        row["table"] == "missing_table" and row["status"] == "missing"
        for row in result["tables"]
    )


def test_control_plane_maintenance_records_table_exists_failures(monkeypatch) -> None:
    conn = _Connection()
    monkeypatch.setattr(
        maintenance,
        "CONTROL_PLANE_MAINTENANCE_TABLES",
        ("broken_table", "proxy_config_revisions"),
    )

    def table_exists(table: str) -> bool:
        if table == "broken_table":
            msg = "metadata lookup failed"
            raise RuntimeError(msg)
        return True

    monkeypatch.setattr(maintenance, "_table_exists", table_exists)
    monkeypatch.setattr(maintenance, "connect", lambda: conn)

    result = maintenance.maintain_control_plane_tables(analyze=True, optimize=False)

    assert result["ok"] is False
    assert result["maintained_tables"] == 1
    assert result["tables"][0]["table"] == "broken_table"
    assert result["tables"][0]["status"] == "failed"
    assert "metadata lookup failed" in result["tables"][0]["detail"]
    assert ("ANALYZE TABLE `proxy_config_revisions`", ()) in conn.queries


class _SequencedConnection:
    def __init__(self, rowcounts: list[int]) -> None:
        self.rowcounts = rowcounts
        self.queries: list[tuple[str, tuple[object, ...]]] = []
        self.committed = False
        self.rolled_back = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, _exc, _tb):
        if exc_type is None:
            self.committed = True
        else:
            self.rolled_back = True
        return False

    def execute(self, sql, params=()):
        compact = " ".join(str(sql).split())
        self.queries.append((compact, tuple(params or ())))
        return _Result(self.rowcounts.pop(0) if self.rowcounts else 0)


class _RetentionDeleteConnection(_SequencedConnection):
    def __init__(self, rowcounts: list[int], *, remaining_victim: bool) -> None:
        super().__init__(rowcounts)
        self.remaining_victim = remaining_victim

    def execute(self, sql, params=()):
        compact = " ".join(str(sql).split())
        if compact.startswith("SELECT 1 FROM"):
            self.queries.append((compact, tuple(params or ())))
            return _Result(0, row=(1,) if self.remaining_victim else None)
        return super().execute(sql, params)


def test_control_plane_keep_n_exact_cap_with_remaining_victim_is_truncated(
    monkeypatch,
) -> None:
    pending = [
        _SequencedConnection([2]),
        _RetentionDeleteConnection([1], remaining_victim=True),
    ]
    used: list[_SequencedConnection] = []

    def connect():
        conn = pending.pop(0)
        used.append(conn)
        return conn

    monkeypatch.setattr(maintenance, "connect", connect)
    monkeypatch.setattr(maintenance, "default_chunk_size", lambda: 2)
    monkeypatch.setattr(maintenance, "default_max_rows", lambda: 3)

    result = maintenance._delete_ranked_rows(
        table="proxy_operations",
        timestamp_column="updated_ts",
        cutoff_ts=1234,
        keep_rows=5,
        partition_column="proxy_id",
        candidate_scope_sql="candidate.status IN ('applied','superseded','failed')",
        newer_scope_sql="newer.status IN ('applied','superseded','failed')",
    )

    assert result.deleted_rows == 3
    assert result.iterations == 2
    assert result.truncated is True
    first_sql, first_params = used[0].queries[0]
    assert first_sql.startswith("DELETE target FROM `proxy_operations` AS target")
    assert "ROW_NUMBER" not in first_sql.upper()
    assert " OFFSET " not in first_sql.upper()
    assert "newer.`proxy_id` = candidate.`proxy_id`" in first_sql
    assert (
        "ORDER BY candidate.`updated_ts` ASC, candidate.`id` ASC LIMIT %s" in first_sql
    )
    assert first_params == (1234, 5, 2)
    probe_sql, probe_params = used[1].queries[1]
    assert probe_sql.startswith("SELECT 1 FROM `proxy_operations` AS candidate")
    assert "newer.`proxy_id` = candidate.`proxy_id`" in probe_sql
    assert "candidate.status IN ('applied','superseded','failed')" in probe_sql
    assert "newer.status IN ('applied','superseded','failed')" in probe_sql
    assert " OFFSET " not in probe_sql.upper()
    assert "ROW_NUMBER" not in probe_sql.upper()
    assert probe_params == (1234, 5)
    assert [conn.committed for conn in used] == [True, True]


def test_control_plane_keep_n_exact_cap_without_remaining_victim_is_not_truncated(
    monkeypatch,
) -> None:
    conn = _RetentionDeleteConnection([2], remaining_victim=False)
    monkeypatch.setattr(maintenance, "connect", lambda: conn)
    monkeypatch.setattr(maintenance, "default_chunk_size", lambda: 2)
    monkeypatch.setattr(maintenance, "default_max_rows", lambda: 2)

    result = maintenance._delete_revision_rows(
        table="proxy_config_revisions",
        timestamp_column="created_ts",
        active_column="is_active",
        cutoff_ts=100,
        keep_rows=25,
        partition_column="proxy_id",
    )

    assert result.deleted_rows == 2
    assert result.iterations == 1
    assert result.truncated is False
    assert len(conn.queries) == 2
    delete_sql, delete_params = conn.queries[0]
    probe_sql, probe_params = conn.queries[1]
    assert "candidate.`is_active` = 0" in delete_sql
    assert delete_params == (100, 25, 2)
    assert probe_sql.startswith("SELECT 1 FROM `proxy_config_revisions` AS candidate")
    assert "candidate.`is_active` = 0" in probe_sql
    assert "newer.`proxy_id` = candidate.`proxy_id`" in probe_sql
    assert probe_params == (100, 25)
    assert conn.committed is True


def test_control_plane_keep_n_low_row_noop(monkeypatch) -> None:
    conn = _SequencedConnection([0])
    monkeypatch.setattr(maintenance, "connect", lambda: conn)
    monkeypatch.setattr(maintenance, "default_chunk_size", lambda: 50)
    monkeypatch.setattr(maintenance, "default_max_rows", lambda: 500)

    result = maintenance._delete_revision_rows(
        table="proxy_config_revisions",
        timestamp_column="created_ts",
        active_column="is_active",
        cutoff_ts=100,
        keep_rows=25,
        partition_column="proxy_id",
    )

    assert result.deleted_rows == 0
    assert result.iterations == 1
    assert result.truncated is False
    sql, params = conn.queries[0]
    assert "candidate.`is_active` = 0" in sql
    assert "COUNT(*)" in sql
    assert params == (100, 25, 50)
    assert conn.committed is True


def test_control_plane_keep_n_failure_rolls_back_current_chunk(monkeypatch) -> None:
    class FailingConnection(_SequencedConnection):
        def execute(self, sql, params=()):
            self.queries.append((" ".join(str(sql).split()), tuple(params or ())))
            msg = "delete failed"
            raise RuntimeError(msg)

    conn = FailingConnection([])
    monkeypatch.setattr(maintenance, "connect", lambda: conn)
    monkeypatch.setattr(maintenance, "default_chunk_size", lambda: 10)
    monkeypatch.setattr(maintenance, "default_max_rows", lambda: 10)

    with pytest.raises(RuntimeError, match="delete failed"):
        maintenance._delete_ranked_rows(
            table="policy_requests",
            timestamp_column="updated_ts",
            cutoff_ts=100,
            keep_rows=10,
            partition_column="proxy_id",
            candidate_scope_sql="candidate.status IN ('rejected','closed')",
            newer_scope_sql="newer.status IN ('rejected','closed')",
        )

    assert conn.committed is False
    assert conn.rolled_back is True


def test_policy_exception_expiry_update_is_bounded(monkeypatch) -> None:
    pending = [
        _PolicyExpiryConnection(
            [{"id": 1, "proxy_id": "edge-a"}, {"id": 2, "proxy_id": "edge-b"}],
        ),
        _PolicyExpiryConnection([{"id": 3, "proxy_id": "edge-c"}]),
    ]
    used: list[_PolicyExpiryConnection] = []

    def connect():
        conn = pending.pop(0)
        used.append(conn)
        return conn

    monkeypatch.setattr(maintenance, "connect", connect)
    monkeypatch.setattr(maintenance, "default_chunk_size", lambda: 2)
    monkeypatch.setattr(maintenance, "default_max_rows", lambda: 3)
    monkeypatch.setattr(
        maintenance,
        "_queue_policy_exception_expiry_policy_sync",
        lambda _proxy_id: True,
    )

    result = maintenance._expire_policy_exceptions(now_ts=999)

    assert result.deleted_rows == 3
    assert result.iterations == 2
    assert result.truncated is True
    select_sql, select_params = used[0].queries[0]
    update_sql, update_params = used[0].queries[1]
    assert select_sql.startswith("SELECT id, proxy_id FROM policy_exceptions")
    assert "ORDER BY expires_ts ASC, id ASC LIMIT %s" in select_sql
    assert select_params == (999, 2)
    assert update_sql.startswith("UPDATE policy_exceptions SET status='expired'")
    assert "WHERE status='active' AND id IN (%s,%s)" in update_sql
    assert update_params == (999, 1, 2)


class _PolicyExpiryResult:
    def __init__(self, rows=None, rowcount: int = 0) -> None:
        self._rows = list(rows or [])
        self.rowcount = rowcount

    def fetchall(self):
        return list(self._rows)


class _PolicyExpiryConnection:
    def __init__(self, rows, rowcount: int | None = None) -> None:
        self.rows = list(rows)
        self.rowcount = len(self.rows) if rowcount is None else rowcount
        self.queries: list[tuple[str, tuple[object, ...]]] = []
        self.committed = False
        self.rolled_back = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, _exc, _tb):
        if exc_type is None:
            self.committed = True
        else:
            self.rolled_back = True
        return False

    def execute(self, sql, params=()):
        compact = " ".join(str(sql).split())
        params = tuple(params or ())
        self.queries.append((compact, params))
        if compact.startswith("SELECT id, proxy_id FROM policy_exceptions"):
            return _PolicyExpiryResult(rows=self.rows)
        if compact.startswith("UPDATE policy_exceptions SET status='expired'"):
            return _PolicyExpiryResult(rowcount=self.rowcount)
        return _PolicyExpiryResult(rowcount=0)


def test_policy_exception_expiry_queues_policy_sync_deduped_by_proxy(
    monkeypatch,
) -> None:
    pending = [
        _PolicyExpiryConnection(
            [
                {"id": 1, "proxy_id": "Edge-A"},
                {"id": 2, "proxy_id": "edge-a"},
            ],
        ),
        _PolicyExpiryConnection([{"id": 3, "proxy_id": "edge-b"}]),
    ]
    used: list[_PolicyExpiryConnection] = []
    queued: list[str] = []

    def connect():
        conn = pending.pop(0)
        used.append(conn)
        return conn

    monkeypatch.setattr(maintenance, "connect", connect)
    monkeypatch.setattr(maintenance, "default_chunk_size", lambda: 2)
    monkeypatch.setattr(maintenance, "default_max_rows", lambda: 3)
    monkeypatch.setattr(
        maintenance,
        "_queue_policy_exception_expiry_policy_sync",
        lambda proxy_id: queued.append(proxy_id) or True,
    )

    result = maintenance._expire_policy_exceptions(now_ts=999)

    assert result.deleted_rows == 3
    assert result.iterations == 2
    assert result.truncated is True
    assert result.queue_attempts == 2
    assert result.queue_failures == 0
    assert result.queued_proxies == ("edge-a", "edge-b")
    assert queued == ["edge-a", "edge-b"]
    first_select_sql, first_select_params = used[0].queries[0]
    first_update_sql, first_update_params = used[0].queries[1]
    assert first_select_sql.startswith("SELECT id, proxy_id FROM policy_exceptions")
    assert "ORDER BY expires_ts ASC, id ASC LIMIT %s" in first_select_sql
    assert first_select_params == (999, 2)
    assert first_update_sql.startswith("UPDATE policy_exceptions SET status='expired'")
    assert "WHERE status='active' AND id IN (%s,%s)" in first_update_sql
    assert first_update_params == (999, 1, 2)


def test_policy_exception_expiry_does_not_queue_without_expired_rows(
    monkeypatch,
) -> None:
    conn = _PolicyExpiryConnection([])
    queued: list[str] = []

    monkeypatch.setattr(maintenance, "connect", lambda: conn)
    monkeypatch.setattr(maintenance, "default_chunk_size", lambda: 50)
    monkeypatch.setattr(maintenance, "default_max_rows", lambda: 500)
    monkeypatch.setattr(
        maintenance,
        "_queue_policy_exception_expiry_policy_sync",
        lambda proxy_id: queued.append(proxy_id) or True,
    )

    result = maintenance._expire_policy_exceptions(now_ts=999)

    assert result.deleted_rows == 0
    assert result.iterations == 1
    assert result.truncated is False
    assert result.queue_attempts == 0
    assert result.queued_proxies == ()
    assert queued == []
    assert len(conn.queries) == 1
    assert conn.queries[0][0].startswith("SELECT id, proxy_id FROM policy_exceptions")


def test_policy_exception_expiry_reports_policy_sync_queue_failures(
    monkeypatch,
) -> None:
    conn = _PolicyExpiryConnection([{"id": 1, "proxy_id": "edge-a"}])

    monkeypatch.setattr(maintenance, "connect", lambda: conn)
    monkeypatch.setattr(maintenance, "default_chunk_size", lambda: 50)
    monkeypatch.setattr(maintenance, "default_max_rows", lambda: 500)
    monkeypatch.setattr(
        maintenance,
        "_queue_policy_exception_expiry_policy_sync",
        lambda _proxy_id: False,
    )

    result = maintenance._expire_policy_exceptions(now_ts=999)

    assert result.deleted_rows == 1
    assert result.queue_attempts == 1
    assert result.queue_failures == 1
    assert result.queued_proxies == ()


def test_policy_exception_expiry_policy_sync_uses_operation_ledger(monkeypatch) -> None:
    from services import policy_materializer, proxy_sync

    calls: list[dict[str, object]] = []

    class PolicyState:
        policy_sha256 = "b" * 64

    class Operation:
        operation_id = 42
        status = "pending"

    monkeypatch.setattr(
        policy_materializer,
        "build_proxy_policy_state",
        lambda proxy_id: PolicyState(),
    )

    def request_proxy_reconcile(proxy_id, **kwargs):
        calls.append({"proxy_id": proxy_id, **kwargs})
        return Operation()

    monkeypatch.setattr(proxy_sync, "request_proxy_reconcile", request_proxy_reconcile)

    assert maintenance._queue_policy_exception_expiry_policy_sync("edge-a") is True
    assert calls == [
        {
            "proxy_id": "edge-a",
            "operation_type": "policy_sync",
            "subject": "Policy reconciliation",
            "summary": "Policy state bbbbbbbbbbbb queued after exception expiry.",
            "target_kind": "policy_state",
            "target_ref": "b" * 64,
            "detail": "Desired policy SHA after exception expiry: " + "b" * 64,
            "created_by": "control-plane-maintenance",
            "force": True,
        },
    ]


def test_control_plane_prune_reports_policy_sync_failure_and_continues(
    monkeypatch,
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(
        maintenance,
        "CONTROL_PLANE_MAINTENANCE_TABLES",
        ("policy_exceptions", "safe_browsing_negative_cache"),
    )
    monkeypatch.setattr(maintenance, "_table_exists", lambda _table: True)
    monkeypatch.setattr(
        maintenance,
        "_ensure_control_plane_retention_indexes",
        lambda _table: None,
    )
    monkeypatch.setattr(
        maintenance,
        "_expire_policy_exceptions",
        lambda **_kwargs: maintenance.PolicyExceptionExpiryResult(
            table="policy_exceptions",
            deleted_rows=1,
            iterations=1,
            truncated=False,
            queue_attempts=1,
            queue_failures=1,
            queue_failure_detail="proxy reconcile unavailable",
        ),
    )
    monkeypatch.setattr(
        maintenance,
        "_delete_ranked_rows",
        lambda **_kwargs: maintenance.BoundedDeleteResult(
            table="policy_exceptions",
            deleted_rows=2,
            iterations=1,
            truncated=False,
        ),
    )

    def delete_expired_cache(table: str, *, now_ts: int):
        assert now_ts == 1_000_000
        calls.append(table)
        return maintenance.BoundedDeleteResult(
            table=table,
            deleted_rows=3,
            iterations=1,
            truncated=False,
        )

    monkeypatch.setattr(maintenance, "_delete_expired_cache", delete_expired_cache)
    monkeypatch.setattr(maintenance.time, "time", lambda: 1_000_000)
    monkeypatch.setattr(
        maintenance,
        "_cleanup_stale_webcat_build_tables_result",
        lambda **_kwargs: maintenance.ControlPlaneMaintenanceResult(
            table=maintenance.WEBCAT_BUILD_TABLE_CLEANUP_TABLE,
            status="noop",
        ),
    )

    result = maintenance.prune_control_plane_tables(retention_days=1)

    assert result["ok"] is False
    assert result["deleted_rows"] == 5
    assert result["updated_rows"] == 1
    assert calls == ["safe_browsing_negative_cache"]
    assert result["tables"][0]["status"] == "failed"
    assert "failed=1" in result["tables"][0]["detail"]
    assert "proxy reconcile unavailable" in result["tables"][0]["detail"]
    assert result["tables"][1]["status"] == "pruned"


def test_control_plane_prune_reports_truncated_backlog(monkeypatch) -> None:
    tables = ("proxy_config_applications",)
    conns = [
        _SequencedConnection([0]),  # index exists lookup
        _SequencedConnection([1]),
        _RetentionDeleteConnection([1], remaining_victim=True),
        _SequencedConnection([0]),  # webcat cleanup
    ]
    used: list[_SequencedConnection] = []

    def connect():
        conn = conns.pop(0)
        used.append(conn)
        return conn

    monkeypatch.setattr(maintenance, "CONTROL_PLANE_MAINTENANCE_TABLES", tables)
    monkeypatch.setattr(maintenance, "_table_exists", lambda _table: True)
    monkeypatch.setattr(maintenance, "connect", connect)
    monkeypatch.setattr(maintenance, "default_chunk_size", lambda: 1)
    monkeypatch.setattr(maintenance, "default_max_rows", lambda: 2)
    monkeypatch.setattr(maintenance.time, "time", lambda: 1_000_000)
    monkeypatch.setattr(
        maintenance,
        "cleanup_stale_webcat_build_tables",
        lambda *_args, **_kwargs: _CleanupResult(),
    )

    result = maintenance.prune_control_plane_tables(retention_days=1)

    assert result["ok"] is True
    row = result["tables"][0]
    assert row["deleted_rows"] == 2
    assert row["maintenance"] == "bounded_retention_delete"
    assert row["detail"] == "iterations=2 truncated=true"


def test_control_plane_ensures_retention_indexes_idempotently(monkeypatch) -> None:
    conn = _Connection()
    seen: set[tuple[str, str]] = set()

    def index_exists(_conn, table, index):
        seen.add((table, index))
        return index.endswith("active_created_id")

    monkeypatch.setattr(maintenance, "connect", lambda: conn)
    monkeypatch.setattr(maintenance, "_index_exists", index_exists)

    maintenance._ensure_control_plane_retention_indexes("proxy_config_revisions")

    sql = [query for query, _params in conn.queries]
    assert (
        "proxy_config_revisions",
        "idx_proxy_config_revisions_proxy_created_id",
    ) in seen
    assert any(
        query.startswith(
            "ALTER TABLE proxy_config_revisions ADD INDEX idx_proxy_config_revisions_proxy_created_id"
        )
        for query in sql
    )
    assert not any("active_created_id" in query for query in sql)
