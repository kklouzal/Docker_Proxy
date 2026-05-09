from __future__ import annotations

from typing import Any

from services import observability_maintenance as maintenance


class FakeResult:
    def __init__(self, rowcount: int = 0) -> None:
        self.rowcount = rowcount


class FakeConnection:
    def __init__(self, rowcounts: dict[str, int]) -> None:
        self.rowcounts = rowcounts
        self.statements: list[str] = []

    def __enter__(self) -> "FakeConnection":
        return self

    def __exit__(self, *_args: Any) -> bool:
        return False

    def execute(self, sql: str, params: tuple[object, ...] | None = None) -> FakeResult:
        self.statements.append(sql)
        normalized = sql.replace("`", "").strip()
        if normalized.upper().startswith("DELETE FROM "):
            table = normalized.split()[2]
            return FakeResult(self.rowcounts.get(table, 0))
        return FakeResult(0)


def test_clear_observability_logs_wipes_all_known_log_tables_without_proxy_filter(monkeypatch) -> None:
    rowcounts = {table: idx + 1 for idx, table in enumerate(maintenance.OBSERVABILITY_LOG_TABLES)}
    conn = FakeConnection(rowcounts)

    monkeypatch.setattr(maintenance, "connect", lambda: conn)
    monkeypatch.setattr(maintenance, "table_exists", lambda _conn, table: table in rowcounts)

    result = maintenance.clear_observability_logs(optimize=True)

    delete_statements = [sql for sql in conn.statements if sql.strip().upper().startswith("DELETE FROM")]
    assert len(delete_statements) == len(maintenance.OBSERVABILITY_LOG_TABLES)
    assert all("WHERE" not in sql.upper() for sql in delete_statements)
    assert all("proxy_id" not in sql for sql in delete_statements)
    assert result["deleted_rows"] == sum(rowcounts.values())
    assert {row["table"] for row in result["tables"] if row["status"] == "cleared"} == set(maintenance.OBSERVABILITY_LOG_TABLES)
    assert any(sql.startswith("ALTER TABLE `diagnostic_requests` AUTO_INCREMENT") for sql in conn.statements)
    assert any(sql.startswith("OPTIMIZE TABLE `diagnostic_requests`") for sql in conn.statements)


def test_clear_observability_logs_skips_tables_that_do_not_exist(monkeypatch) -> None:
    conn = FakeConnection({"diagnostic_requests": 3})

    monkeypatch.setattr(maintenance, "connect", lambda: conn)
    monkeypatch.setattr(maintenance, "table_exists", lambda _conn, table: table == "diagnostic_requests")

    result = maintenance.clear_observability_logs(optimize=False)

    assert result["deleted_rows"] == 3
    assert any(row["table"] == "diagnostic_requests" and row["status"] == "cleared" for row in result["tables"])
    assert any(row["table"] == "ssl_errors" and row["status"] == "missing" for row in result["tables"])
    assert not any(sql.startswith("OPTIMIZE TABLE") for sql in conn.statements)
