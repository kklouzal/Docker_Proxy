from __future__ import annotations

from typing import Self

import pytest
from services import observability_maintenance as maintenance


class FakeResult:
    def __init__(self, rowcount: int = 0) -> None:
        self.rowcount = rowcount


class FakeConnection:
    def __init__(
        self, existing_tables: set[str], *, fail_first_table_exists: bool = False
    ) -> None:
        self.existing_tables = existing_tables
        self.statements: list[str] = []
        self.fail_first_table_exists = fail_first_table_exists
        self.table_exists_calls = 0

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> bool:
        return False

    def execute(self, sql: str, params: tuple[object, ...] | None = None) -> FakeResult:
        self.statements.append(sql)
        if "information_schema.tables" in sql:
            self.table_exists_calls += 1
            if self.fail_first_table_exists and self.table_exists_calls == 1:
                msg = "InterfaceError: (0, '')"
                raise RuntimeError(msg)
            return FakeResult(1)
        return FakeResult(0)


def test_clear_observability_logs_truncates_all_known_log_tables_without_proxy_filter(
    monkeypatch,
) -> None:
    existing = set(maintenance.OBSERVABILITY_LOG_TABLES)
    conn = FakeConnection(existing)

    monkeypatch.setattr(maintenance, "connect", lambda: conn)
    monkeypatch.setattr(
        maintenance, "table_exists", lambda _conn, table: table in existing
    )

    result = maintenance.clear_observability_logs(optimize=True)

    truncate_statements = [
        sql
        for sql in conn.statements
        if sql.strip().upper().startswith("TRUNCATE TABLE")
    ]
    assert len(truncate_statements) == len(maintenance.OBSERVABILITY_LOG_TABLES)
    assert all("WHERE" not in sql.upper() for sql in truncate_statements)
    assert all("proxy_id" not in sql for sql in truncate_statements)
    assert result["ok"] is True
    assert result["cleared_tables"] == len(maintenance.OBSERVABILITY_LOG_TABLES)
    assert {
        row["table"] for row in result["tables"] if row["status"] == "cleared"
    } == existing
    assert any(sql == "TRUNCATE TABLE `diagnostic_requests`" for sql in conn.statements)
    assert any(
        sql == "TRUNCATE TABLE `diagnostic_policy_tags`" for sql in conn.statements
    )
    assert not any(sql.startswith("OPTIMIZE TABLE") for sql in conn.statements)


def test_clear_observability_logs_skips_tables_that_do_not_exist(monkeypatch) -> None:
    existing = {"diagnostic_requests"}
    conn = FakeConnection(existing)

    monkeypatch.setattr(maintenance, "connect", lambda: conn)
    monkeypatch.setattr(
        maintenance, "table_exists", lambda _conn, table: table in existing
    )

    result = maintenance.clear_observability_logs(optimize=False)

    assert result["ok"] is True
    assert result["cleared_tables"] == 1
    assert any(
        row["table"] == "diagnostic_requests" and row["status"] == "cleared"
        for row in result["tables"]
    )
    assert any(
        row["table"] == "ssl_errors" and row["status"] == "missing"
        for row in result["tables"]
    )
    assert not any(
        "ssl_errors" in sql and sql.strip().upper().startswith("TRUNCATE TABLE")
        for sql in conn.statements
    )


def test_clear_observability_logs_retries_stale_connection_on_table_probe(
    monkeypatch,
) -> None:
    existing = set(maintenance.OBSERVABILITY_LOG_TABLES)
    conn = FakeConnection(existing, fail_first_table_exists=True)

    monkeypatch.setattr(maintenance, "connect", lambda: conn)

    def fake_table_exists(fake_conn: FakeConnection, table: str) -> bool:
        fake_conn.execute(
            "SELECT 1 FROM information_schema.tables WHERE table_name = %s", (table,)
        )
        return table in existing

    monkeypatch.setattr(maintenance, "table_exists", fake_table_exists)

    result = maintenance.clear_observability_logs()

    assert result["ok"] is True
    assert conn.table_exists_calls >= 2
    assert any(sql == "TRUNCATE TABLE `diagnostic_requests`" for sql in conn.statements)


def test_maintain_observability_tables_analyzes_and_optimizes_existing_tables(
    monkeypatch,
) -> None:
    existing = {"diagnostic_requests", "diagnostic_policy_tags", "ssl_errors"}
    conn = FakeConnection(existing)

    monkeypatch.setattr(maintenance, "connect", lambda: conn)
    monkeypatch.setattr(
        maintenance, "table_exists", lambda _conn, table: table in existing
    )

    result = maintenance.maintain_observability_tables(analyze=True, optimize=True)

    assert result["ok"] is True
    assert result["maintained_tables"] == 3
    assert "ANALYZE TABLE `diagnostic_requests`" in conn.statements
    assert "OPTIMIZE TABLE `diagnostic_requests`" in conn.statements
    assert "ANALYZE TABLE `diagnostic_policy_tags`" in conn.statements
    assert "OPTIMIZE TABLE `diagnostic_policy_tags`" in conn.statements
    assert "ANALYZE TABLE `ssl_errors`" in conn.statements
    assert "OPTIMIZE TABLE `ssl_errors`" in conn.statements
    assert not any("adblock_events" in sql for sql in conn.statements)


def test_observability_retention_settings_round_trip(monkeypatch) -> None:
    class SettingsResult:
        def __init__(self, row=None, rowcount: int = 0) -> None:
            self._row = row
            self.rowcount = rowcount

        def fetchone(self):
            return self._row

        def fetchall(self):
            return [] if self._row is None else [self._row]

    class SettingsConnection:
        def __init__(self) -> None:
            self.retention_days = maintenance.DEFAULT_OBSERVABILITY_RETENTION_DAYS
            self.updated_ts = 0
            self.statements: list[str] = []

        def __enter__(self):
            return self

        def __exit__(self, *_args: object) -> bool:
            return False

        def execute(self, sql: str, params: tuple[object, ...] | None = None):
            self.statements.append(sql)
            normalized = " ".join(sql.split()).upper()
            if normalized.startswith("SELECT RETENTION_DAYS"):
                return SettingsResult((self.retention_days, self.updated_ts))
            if "RETENTION_DAYS = INCOMING.RETENTION_DAYS" in normalized:
                assert params is not None
                self.retention_days = int(params[0])
                self.updated_ts = int(params[1])
            elif "INSERT INTO OBSERVABILITY_SETTINGS" in normalized:
                assert params is not None
                if not self.updated_ts:
                    self.retention_days = int(params[0])
                    self.updated_ts = int(params[1])
            return SettingsResult(rowcount=1)

    conn = SettingsConnection()
    monkeypatch.setattr(maintenance, "connect", lambda: conn)
    monkeypatch.setattr(maintenance.time, "time", lambda: 1234)

    initial = maintenance.get_observability_retention_settings()
    saved = maintenance.set_observability_retention_settings(retention_days="45")
    loaded = maintenance.get_observability_retention_settings()

    assert initial["retention_days"] == 30
    assert saved == {"retention_days": 45, "updated_ts": 1234}
    assert loaded == {"retention_days": 45, "updated_ts": 1234}
    assert any(
        "CREATE TABLE IF NOT EXISTS observability_settings" in sql
        for sql in conn.statements
    )


def test_observability_retention_days_are_bounded() -> None:
    assert (
        maintenance.normalize_retention_days("0")
        == maintenance.MIN_OBSERVABILITY_RETENTION_DAYS
    )
    assert (
        maintenance.normalize_retention_days("999999")
        == maintenance.MAX_OBSERVABILITY_RETENTION_DAYS
    )
    assert (
        maintenance.normalize_retention_days("not-a-number")
        == maintenance.DEFAULT_OBSERVABILITY_RETENTION_DAYS
    )


def test_observability_maintenance_public_detail_redacts_sensitive_values() -> None:
    detail = maintenance.public_detail(
        RuntimeError("database unavailable password=secret token='abc123'"),
    )

    assert "secret" not in detail
    assert "abc123" not in detail
    assert "password=[redacted]" in detail
    assert "token='[redacted]'" in detail


def test_observability_advisory_lock_uses_unpooled_connection(monkeypatch) -> None:
    pooled_calls: list[str] = []
    unpooled_calls: list[str] = []

    class Result:
        def fetchone(self):
            return (1,)

    class LockConn:
        def execute(self, sql, params=None):
            unpooled_calls.append(sql)
            return Result()

        def close(self):
            unpooled_calls.append("close")

    def record_pooled_call():
        pooled_calls.append("connect")

    monkeypatch.setattr(maintenance, "connect", record_pooled_call)
    monkeypatch.setattr(maintenance, "connect_unpooled", LockConn)

    conn = maintenance.acquire_observability_maintenance_lock()
    maintenance.release_observability_maintenance_lock(conn)

    assert pooled_calls == []
    assert unpooled_calls == [
        "SELECT GET_LOCK(%s, 0)",
        "SELECT RELEASE_LOCK(%s)",
        "close",
    ]


def test_clear_observability_logs_does_not_replay_commit_unknown_truncate(
    monkeypatch,
) -> None:
    statements: list[str] = []
    fallback_calls: list[str] = []

    class DisconnectingTruncateConnection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, sql, _params=None):
            statements.append(sql)
            msg = "Lost connection to MySQL server password=secret"
            raise RuntimeError(msg)

    monkeypatch.setattr(
        maintenance,
        "OBSERVABILITY_LOG_TABLES",
        ("diagnostic_requests",),
    )
    monkeypatch.setattr(maintenance, "_table_exists", lambda _table: True)
    monkeypatch.setattr(maintenance, "connect", DisconnectingTruncateConnection)
    monkeypatch.setattr(
        maintenance,
        "_delete_table_in_chunks",
        fallback_calls.append,
    )

    result = maintenance.clear_observability_logs()

    assert result["ok"] is False
    assert result["cleared_tables"] == 0
    assert result["deleted_rows"] == 0
    assert result["tables"][0]["status"] == "uncertain"
    assert result["tables"][0]["maintenance"] == "truncate"
    assert "secret" not in result["tables"][0]["detail"]
    assert statements == ["TRUNCATE TABLE `diagnostic_requests`"]
    assert fallback_calls == []


def test_clear_observability_logs_accepts_successful_truncate_before_commit_error(
    monkeypatch,
) -> None:
    statements: list[str] = []
    fallback_calls: list[str] = []

    class CommitFailingTruncateConnection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            msg = "Lost connection to MySQL server during commit"
            raise RuntimeError(msg)

        def execute(self, sql, _params=None):
            statements.append(sql)
            return FakeResult()

    monkeypatch.setattr(
        maintenance,
        "OBSERVABILITY_LOG_TABLES",
        ("diagnostic_requests",),
    )
    monkeypatch.setattr(maintenance, "_table_exists", lambda _table: True)
    monkeypatch.setattr(maintenance, "connect", CommitFailingTruncateConnection)
    monkeypatch.setattr(
        maintenance,
        "_delete_table_in_chunks",
        fallback_calls.append,
    )

    result = maintenance.clear_observability_logs()

    assert result["ok"] is True
    assert result["cleared_tables"] == 1
    assert result["tables"][0]["status"] == "cleared"
    assert result["tables"][0]["maintenance"] == "truncated"
    assert statements == ["TRUNCATE TABLE `diagnostic_requests`"]
    assert fallback_calls == []


def test_truncate_retries_only_connection_acquisition_before_issuing_sql(
    monkeypatch,
) -> None:
    calls = 0
    statements: list[str] = []

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, sql, _params=None):
            statements.append(sql)
            return FakeResult()

    def connect():
        nonlocal calls
        calls += 1
        if calls == 1:
            msg = "InterfaceError: (0, '')"
            raise RuntimeError(msg)
        return Connection()

    monkeypatch.setattr(maintenance, "connect", connect)

    maintenance._truncate_table("diagnostic_requests")

    assert calls == 2
    assert statements == ["TRUNCATE TABLE `diagnostic_requests`"]


def test_clear_observability_logs_reports_partial_bounded_delete_fallback(
    monkeypatch,
) -> None:
    existing = {"diagnostic_requests"}

    monkeypatch.setattr(maintenance, "_table_exists", lambda table: table in existing)

    def fail_truncate(_table: str) -> None:
        msg = "metadata lock timeout"
        raise RuntimeError(msg)

    monkeypatch.setattr(maintenance, "_truncate_table", fail_truncate)
    monkeypatch.setattr(
        maintenance,
        "_delete_table_in_chunks",
        lambda table: maintenance.BoundedDeleteResult(
            table=table,
            deleted_rows=7,
            iterations=2,
            truncated=True,
        ),
    )

    result = maintenance.clear_observability_logs()

    assert result["ok"] is False
    assert result["deleted_rows"] == 7
    assert any(
        row["table"] == "diagnostic_requests"
        and row["status"] == "partial"
        and row["maintenance"] == "delete_fallback"
        for row in result["tables"]
    )


@pytest.mark.parametrize(
    ("failure_stage", "expected_status"),
    [("execute", "partial"), ("commit", "uncertain")],
)
def test_clear_fallback_preserves_confirmed_count_and_does_not_replay_disconnect(
    monkeypatch,
    failure_stage: str,
    expected_status: str,
) -> None:
    statements: list[str] = []
    connection_calls = 0

    class DeleteConnection:
        def __init__(self, call_number: int) -> None:
            self.call_number = call_number

        def __enter__(self):
            return self

        def __exit__(self, exc_type, _exc, _tb):
            if exc_type is None and self.call_number == 2 and failure_stage == "commit":
                msg = "Lost connection during commit token=secret"
                raise RuntimeError(msg)
            return False

        def execute(self, sql, _params=None):
            statements.append(" ".join(sql.split()))
            if self.call_number == 2 and failure_stage == "execute":
                msg = "Lost connection during DELETE token=secret"
                raise RuntimeError(msg)
            return FakeResult(rowcount=2)

    def connect():
        nonlocal connection_calls
        connection_calls += 1
        return DeleteConnection(connection_calls)

    def fail_truncate(_table: str) -> None:
        msg = "metadata lock timeout"
        raise RuntimeError(msg)

    monkeypatch.setattr(
        maintenance,
        "OBSERVABILITY_LOG_TABLES",
        ("diagnostic_requests",),
    )
    monkeypatch.setattr(maintenance, "_table_exists", lambda _table: True)
    monkeypatch.setattr(maintenance, "_truncate_table", fail_truncate)
    monkeypatch.setattr(maintenance, "connect", connect)
    monkeypatch.setenv("MYSQL_HOUSEKEEPING_DELETE_CHUNK_SIZE", "2")

    result = maintenance.clear_observability_logs()

    table_result = result["tables"][0]
    assert result["ok"] is False
    assert result["deleted_rows"] == 2
    assert table_result["status"] == expected_status
    assert table_result["deleted_rows"] == 2
    assert table_result["maintenance"] == "delete_fallback"
    assert "confirmed_deleted_rows=2" in table_result["detail"]
    assert "secret" not in table_result["detail"]
    assert connection_calls == 2
    assert len(statements) == 2
    assert all(
        sql.startswith("DELETE FROM `diagnostic_requests`") for sql in statements
    )


def test_maintain_observability_tables_continues_after_table_probe_failure(
    monkeypatch,
) -> None:
    existing = {"diagnostic_requests"}
    calls: list[str] = []

    monkeypatch.setattr(
        maintenance,
        "OBSERVABILITY_LOG_TABLES",
        ("broken_table", "diagnostic_requests"),
    )

    def table_exists(table: str) -> bool:
        if table == "broken_table":
            msg = "metadata lookup failed password=secret"
            raise RuntimeError(msg)
        return table in existing

    def run_table(table: str, *, analyze: bool, optimize: bool) -> str:
        calls.append(f"{table}:{analyze}:{optimize}")
        return "analyzed"

    monkeypatch.setattr(maintenance, "_table_exists", table_exists)
    monkeypatch.setattr(maintenance, "_run_table_maintenance", run_table)

    result = maintenance.maintain_observability_tables(analyze=True, optimize=False)

    assert result["ok"] is False
    assert result["maintained_tables"] == 1
    assert calls == ["diagnostic_requests:True:False"]
    assert result["tables"][0]["table"] == "broken_table"
    assert result["tables"][0]["status"] == "failed"
    assert result["tables"][0]["maintenance"] == "table_exists"
    assert "secret" not in result["tables"][0]["detail"]


def test_clear_observability_logs_continues_after_table_probe_failure(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        maintenance,
        "OBSERVABILITY_LOG_TABLES",
        ("broken_table", "diagnostic_requests"),
    )
    truncated: list[str] = []

    def table_exists(table: str) -> bool:
        if table == "broken_table":
            msg = "metadata lookup failed token=secret"
            raise RuntimeError(msg)
        return True

    monkeypatch.setattr(maintenance, "_table_exists", table_exists)
    monkeypatch.setattr(maintenance, "_truncate_table", truncated.append)

    result = maintenance.clear_observability_logs()

    assert result["ok"] is False
    assert result["cleared_tables"] == 1
    assert truncated == ["diagnostic_requests"]
    assert result["tables"][0]["table"] == "broken_table"
    assert result["tables"][0]["status"] == "failed"
    assert result["tables"][0]["maintenance"] == "table_exists"
    assert "secret" not in result["tables"][0]["detail"]
