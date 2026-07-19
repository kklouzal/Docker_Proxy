from __future__ import annotations

from services import control_plane_maintenance as maintenance


class _Result:
    def __init__(self, rowcount: int = 0) -> None:
        self.rowcount = rowcount

    def fetchone(self):
        return None


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
    monkeypatch.setattr(maintenance.time, "time", lambda: 1_000_000)

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
        "FROM `proxy_operations` WHERE status IN ('applied','superseded','failed')"
        in query
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
    monkeypatch.setattr(adblock_artifacts, "AdblockArtifactStore", FakeAdblockArtifactStore)
    monkeypatch.setattr(maintenance.time, "time", lambda: 1_000_000)

    result = maintenance.prune_control_plane_tables(retention_days=30)

    assert result["ok"] is True
    assert result["deleted_rows"] == 3
    assert result["tables"][0]["table"] == "adblock_artifact_revisions"
    assert result["tables"][0]["status"] == "pruned"
    assert result["tables"][0]["deleted_rows"] == 3


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
