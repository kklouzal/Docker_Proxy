from __future__ import annotations

import importlib
import sys
from pathlib import Path

WEB_ROOT = Path(__file__).resolve().parents[1]
if str(WEB_ROOT) not in sys.path:
    sys.path.insert(0, str(WEB_ROOT))


class _Result:
    def __init__(self, rows=(), *, rowcount: int = 0) -> None:
        self._rows = list(rows)
        self.rowcount = rowcount

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return list(self._rows)


class _LifecycleConn:
    def __init__(self, discovered_tables: tuple[str, ...]) -> None:
        self.discovered_tables = discovered_tables
        self.statements: list[str] = []
        self.params: list[tuple[object, ...]] = []
        self.commits = 0

    def execute(self, sql, params=()):
        text = " ".join(str(sql).split())
        self.statements.append(text)
        self.params.append(tuple(params or ()))
        if "FROM information_schema.columns c" in text:
            return _Result({"table_name": name} for name in self.discovered_tables)
        if text.startswith(("UPDATE", "DELETE")):
            return _Result(rowcount=1)
        msg = f"Unexpected SQL: {text}"
        raise AssertionError(msg)

    def commit(self) -> None:
        self.commits += 1


def _proxy_lifecycle():
    from services import proxy_lifecycle  # type: ignore

    return importlib.reload(proxy_lifecycle)


def test_lifecycle_inventory_excludes_metadata_and_includes_discovered_proxy_tables(
    monkeypatch,
) -> None:
    lifecycle = _proxy_lifecycle()
    conn = _LifecycleConn(
        (
            "adblock_counts",
            "proxy_id_aliases",
            "proxy_instances",
            "proxy_lifecycle_tombstones",
            "proxy_recovery_adoptions",
            "proxy_z_custom_rows",
        ),
    )
    monkeypatch.setattr(
        lifecycle,
        "_table_exists",
        lambda _conn, name: name in {"adblock_counts", "proxy_recovery_adoptions"},
    )

    inventory = lifecycle.lifecycle_inventory(conn)
    by_name = {table.table: table for table in inventory}

    assert "adblock_counts" in by_name
    assert "proxy_recovery_adoptions" in by_name
    assert not by_name["proxy_recovery_adoptions"].note.startswith("discovered")
    assert by_name["proxy_recovery_adoptions"].order_columns == (
        "proxy_id",
        "adopted_ts",
        "target_control_plane_id",
    )
    assert (
        by_name["proxy_z_custom_rows"].note
        == "discovered from information_schema.columns"
    )
    assert "proxy_instances" not in by_name
    assert "proxy_id_aliases" not in by_name
    assert "proxy_lifecycle_tombstones" not in by_name
    assert any(
        "ORDER BY c.table_name ASC" in statement for statement in conn.statements
    )


def test_rename_proxy_scoped_rows_skips_metadata_discovery_and_reports_custom_table(
    monkeypatch,
) -> None:
    lifecycle = _proxy_lifecycle()
    conn = _LifecycleConn(
        (
            "proxy_id_aliases",
            "proxy_instances",
            "proxy_lifecycle_tombstones",
            "proxy_recovery_adoptions",
            "proxy_z_custom_rows",
        ),
    )
    monkeypatch.setattr(
        lifecycle, "_table_exists", lambda _conn, name: name == "proxy_z_custom_rows"
    )
    monkeypatch.setattr(
        lifecycle, "_index_with_leftmost_column_exists", lambda *_args: True
    )
    monkeypatch.setattr(lifecycle, "_columns", lambda *_args: {"proxy_id"})
    monkeypatch.setattr(lifecycle, "lifecycle_chunk_size", lambda: 10)
    monkeypatch.setattr(lifecycle, "lifecycle_max_rows_per_table", lambda: 100)

    result = lifecycle.rename_proxy_scoped_rows(
        conn,
        old_proxy_id="edge-old",
        new_proxy_id="edge-new",
    )

    assert result.table_counts == {"proxy_z_custom_rows": 1}
    assert result.discovered_tables == ("proxy_z_custom_rows",)
    assert result.complete is True
    assert [step.table for step in result.table_results if step.discovered] == [
        "proxy_z_custom_rows",
    ]
    assert not any(
        statement.startswith(
            (
                "UPDATE `proxy_instances`",
                "UPDATE `proxy_id_aliases`",
                "UPDATE `proxy_lifecycle_tombstones`",
            ),
        )
        for statement in conn.statements
    )


def test_rename_proxy_scoped_rows_processes_proxy_recovery_adoptions(
    monkeypatch,
) -> None:
    lifecycle = _proxy_lifecycle()
    conn = _LifecycleConn(("proxy_recovery_adoptions",))
    monkeypatch.setattr(
        lifecycle,
        "_table_exists",
        lambda _conn, name: name == "proxy_recovery_adoptions",
    )
    monkeypatch.setattr(
        lifecycle, "_index_with_leftmost_column_exists", lambda *_args: True
    )
    monkeypatch.setattr(
        lifecycle,
        "_columns",
        lambda _conn, name: {
            "proxy_id",
            "adopted_ts",
            "target_control_plane_id",
        }
        if name == "proxy_recovery_adoptions"
        else set(),
    )
    monkeypatch.setattr(lifecycle, "lifecycle_chunk_size", lambda: 10)
    monkeypatch.setattr(lifecycle, "lifecycle_max_rows_per_table", lambda: 100)

    result = lifecycle.rename_proxy_scoped_rows(
        conn,
        old_proxy_id="edge-old",
        new_proxy_id="edge-new",
    )

    assert result.table_counts == {"proxy_recovery_adoptions": 1}
    assert result.discovered_tables == ()
    assert any(
        statement
        == "UPDATE `proxy_recovery_adoptions` SET `proxy_id`=%s WHERE `proxy_id`=%s ORDER BY `proxy_id`, `adopted_ts`, `target_control_plane_id` LIMIT %s"
        and params == ("edge-new", "edge-old", 10)
        for statement, params in zip(conn.statements, conn.params, strict=True)
    )


def test_remove_proxy_scoped_rows_processes_discovered_tables_in_inventory_order(
    monkeypatch,
) -> None:
    lifecycle = _proxy_lifecycle()
    conn = _LifecycleConn(
        (
            "proxy_alpha_custom_rows",
            "proxy_id_aliases",
            "proxy_instances",
            "proxy_lifecycle_tombstones",
            "proxy_beta_custom_rows",
        ),
    )
    existing = {"proxy_alpha_custom_rows", "proxy_beta_custom_rows"}
    monkeypatch.setattr(
        lifecycle, "_table_exists", lambda _conn, name: name in existing
    )
    monkeypatch.setattr(
        lifecycle, "_index_with_leftmost_column_exists", lambda *_args: True
    )
    monkeypatch.setattr(lifecycle, "_columns", lambda *_args: {"proxy_id"})
    monkeypatch.setattr(lifecycle, "lifecycle_chunk_size", lambda: 10)
    monkeypatch.setattr(lifecycle, "lifecycle_max_rows_per_table", lambda: 100)

    result = lifecycle.remove_proxy_scoped_rows(conn, proxy_id="edge-old")

    assert result.table_counts == {
        "proxy_alpha_custom_rows": 1,
        "proxy_beta_custom_rows": 1,
    }
    assert result.discovered_tables == (
        "proxy_alpha_custom_rows",
        "proxy_beta_custom_rows",
    )
    assert [step.table for step in result.table_results if step.discovered] == [
        "proxy_alpha_custom_rows",
        "proxy_beta_custom_rows",
    ]
    assert not any(
        statement.startswith(
            (
                "DELETE FROM `proxy_instances`",
                "DELETE FROM `proxy_id_aliases`",
                "DELETE FROM `proxy_lifecycle_tombstones`",
            ),
        )
        for statement in conn.statements
    )


def test_remove_proxy_scoped_rows_processes_proxy_recovery_adoptions(
    monkeypatch,
) -> None:
    lifecycle = _proxy_lifecycle()
    conn = _LifecycleConn(("proxy_recovery_adoptions",))
    monkeypatch.setattr(
        lifecycle,
        "_table_exists",
        lambda _conn, name: name == "proxy_recovery_adoptions",
    )
    monkeypatch.setattr(
        lifecycle, "_index_with_leftmost_column_exists", lambda *_args: True
    )
    monkeypatch.setattr(
        lifecycle,
        "_columns",
        lambda _conn, name: {
            "proxy_id",
            "adopted_ts",
            "target_control_plane_id",
        }
        if name == "proxy_recovery_adoptions"
        else set(),
    )
    monkeypatch.setattr(lifecycle, "lifecycle_chunk_size", lambda: 10)
    monkeypatch.setattr(lifecycle, "lifecycle_max_rows_per_table", lambda: 100)

    result = lifecycle.remove_proxy_scoped_rows(conn, proxy_id="edge-old")

    assert result.table_counts == {"proxy_recovery_adoptions": 1}
    assert result.discovered_tables == ()
    assert any(
        statement
        == "DELETE FROM `proxy_recovery_adoptions` WHERE `proxy_id`=%s ORDER BY `proxy_id`, `adopted_ts`, `target_control_plane_id` LIMIT %s"
        and params == ("edge-old", 10)
        for statement, params in zip(conn.statements, conn.params, strict=True)
    )


def test_rename_proxy_scoped_rows_fails_closed_when_prepared_index_missing(
    monkeypatch,
) -> None:
    lifecycle = _proxy_lifecycle()
    conn = _LifecycleConn(("proxy_unprepared_rows",))
    monkeypatch.setattr(
        lifecycle, "_table_exists", lambda _conn, name: name == "proxy_unprepared_rows"
    )
    monkeypatch.setattr(
        lifecycle, "_index_with_leftmost_column_exists", lambda *_args: False
    )

    result = lifecycle.rename_proxy_scoped_rows(
        conn,
        old_proxy_id="edge-old",
        new_proxy_id="edge-new",
        ensure_indexes=False,
    )

    truncated = next(step for step in result.table_results if step.truncated)
    assert result.complete is False
    assert result.table_counts == {}
    assert result.truncated_tables == ("proxy_unprepared_rows",)
    assert truncated.table == "proxy_unprepared_rows"
    assert truncated.detail == "missing_prepared_lifecycle_index"
    assert not any(statement.startswith("UPDATE ") for statement in conn.statements)
    assert not any(statement.startswith("ALTER TABLE ") for statement in conn.statements)


def test_remove_proxy_scoped_rows_fails_closed_when_prepared_index_missing(
    monkeypatch,
) -> None:
    lifecycle = _proxy_lifecycle()
    conn = _LifecycleConn(("proxy_unprepared_rows",))
    monkeypatch.setattr(
        lifecycle, "_table_exists", lambda _conn, name: name == "proxy_unprepared_rows"
    )
    monkeypatch.setattr(
        lifecycle, "_index_with_leftmost_column_exists", lambda *_args: False
    )

    result = lifecycle.remove_proxy_scoped_rows(
        conn,
        proxy_id="edge-old",
        ensure_indexes=False,
    )

    truncated = next(step for step in result.table_results if step.truncated)
    assert result.complete is False
    assert result.table_counts == {}
    assert result.truncated_tables == ("proxy_unprepared_rows",)
    assert truncated.table == "proxy_unprepared_rows"
    assert truncated.detail == "missing_prepared_lifecycle_index"
    assert not any(statement.startswith("DELETE FROM ") for statement in conn.statements)
    assert not any(statement.startswith("ALTER TABLE ") for statement in conn.statements)
