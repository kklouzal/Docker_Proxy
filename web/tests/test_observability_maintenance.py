from __future__ import annotations

from typing import Self

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
