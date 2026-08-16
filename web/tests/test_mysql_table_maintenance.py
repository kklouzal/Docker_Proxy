from __future__ import annotations

import pytest
from services.mysql_table_maintenance import run_mysql_table_maintenance


class _Connection:
    def __init__(self, *, fail_sql: str = "", fail_exit: bool = False) -> None:
        self.statements: list[str] = []
        self.fail_sql = fail_sql
        self.fail_exit = fail_exit

    def __enter__(self):
        return self

    def __exit__(self, *_args: object) -> bool:
        if self.fail_exit:
            msg = "lost connection during commit"
            raise RuntimeError(msg)
        return False

    def execute(self, sql: str) -> None:
        self.statements.append(sql)
        if self.fail_sql and sql.startswith(self.fail_sql):
            msg = "lost connection during statement"
            raise RuntimeError(msg)


def test_retries_stale_connection_acquisition_before_maintenance() -> None:
    conn = _Connection()
    calls = 0

    def connect():
        nonlocal calls
        calls += 1
        if calls == 1:
            msg = "server has gone away"
            raise RuntimeError(msg)
        return conn

    result = run_mysql_table_maintenance(connect, "events", analyze=True, optimize=True)

    assert result == "analyzed,optimized"
    assert calls == 2
    assert conn.statements == ["ANALYZE TABLE `events`", "OPTIMIZE TABLE `events`"]


def test_does_not_replay_uncertain_maintenance_statement() -> None:
    connections = [_Connection(fail_sql="ANALYZE TABLE"), _Connection()]
    calls = 0

    def connect():
        nonlocal calls
        conn = connections[calls]
        calls += 1
        return conn

    with pytest.raises(RuntimeError, match="lost connection during statement"):
        run_mysql_table_maintenance(connect, "events", analyze=True, optimize=False)

    assert calls == 1
    assert connections[0].statements == ["ANALYZE TABLE `events`"]
    assert connections[1].statements == []


def test_reports_only_acknowledged_actions_when_later_statement_is_uncertain() -> None:
    conn = _Connection(fail_sql="OPTIMIZE TABLE")

    with pytest.raises(RuntimeError, match="lost connection during statement"):
        run_mysql_table_maintenance(lambda: conn, "events", analyze=True, optimize=True)

    assert conn.statements == ["ANALYZE TABLE `events`", "OPTIMIZE TABLE `events`"]


def test_ignores_context_exit_failure_after_all_actions_acknowledged() -> None:
    conn = _Connection(fail_exit=True)

    result = run_mysql_table_maintenance(
        lambda: conn, "events", analyze=True, optimize=False
    )

    assert result == "analyzed"
