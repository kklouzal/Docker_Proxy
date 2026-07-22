from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace


def _add_web_to_path() -> None:
    web_dir = Path(__file__).resolve().parents[1]
    if str(web_dir) not in sys.path:
        sys.path.insert(0, str(web_dir))


class _Result:
    def __init__(self, rows):
        self._rows = rows

    def fetchall(self):
        return list(self._rows)

    def fetchone(self):
        return self._rows[0] if self._rows else None


class _ValidationConn:
    def __init__(
        self,
        module,
        *,
        missing_tables=(),
        missing_columns=(),
        duplicate_ops: int = 0,
        schema_checksum: str | None = None,
        terminal_claims: int = 0,
        orphan_operations: int = 0,
    ) -> None:
        self.tables = set(module._REQUIRED_TABLES) - set(missing_tables)
        self.columns = set(module._REQUIRED_COLUMNS) - set(missing_columns)
        self.indexes = set(module._REQUIRED_INDEXES)
        self.duplicate_ops = duplicate_ops
        self.schema_checksum = schema_checksum or module.latest_schema_checksum()
        self.terminal_claims = terminal_claims
        self.orphan_operations = orphan_operations

    def execute(self, sql, params=()):
        text = " ".join(str(sql).lower().split())
        if "from information_schema.tables" in text:
            return _Result([{"table_name": table} for table in sorted(self.tables)])
        if "from information_schema.columns" in text:
            return _Result(
                [
                    {"table_name": table, "column_name": column}
                    for table, column in sorted(self.columns)
                ],
            )
        if "from information_schema.statistics" in text:
            return _Result(
                [
                    {"table_name": table, "index_name": index}
                    for table, index in sorted(self.indexes)
                ],
            )
        if "from schema_migrations" in text:
            return _Result([{"status": "applied", "checksum": self.schema_checksum, "error": ""}])
        if "from proxy_operations" in text and "having count(*) > 1" in text:
            return _Result([{"n": self.duplicate_ops}])
        if "from proxy_operations" in text and "request_key is not null" in text:
            return _Result([{"n": self.terminal_claims}])
        if "from proxy_operations op" in text and "proxy.proxy_id is null" in text:
            return _Result([{"n": self.orphan_operations}])
        return _Result([{"n": 0}])

    def close(self):
        return None


def test_mysql_state_validation_passes_complete_restored_state() -> None:
    _add_web_to_path()
    from services import mysql_state_validation  # type: ignore

    result = mysql_state_validation.validate_mysql_state(
        _ValidationConn(mysql_state_validation),
        phase="post-restore",
    )

    assert result.ok is True
    assert result.errors == []
    assert result.details["schema_status"] == "applied"


def test_mysql_state_validation_fails_missing_lifecycle_tables() -> None:
    _add_web_to_path()
    from services import mysql_state_validation  # type: ignore

    result = mysql_state_validation.validate_mysql_state(
        _ValidationConn(mysql_state_validation, missing_tables=("proxy_id_aliases",)),
        phase="pre-backup",
    )

    assert result.ok is False
    assert any("proxy_id_aliases" in error for error in result.errors)


def test_mysql_state_validation_fails_duplicate_active_operation_keys() -> None:
    _add_web_to_path()
    from services import mysql_state_validation  # type: ignore

    result = mysql_state_validation.validate_mysql_state(
        _ValidationConn(mysql_state_validation, duplicate_ops=2),
        phase="post-restore",
    )

    assert result.ok is False
    assert any("duplicate active idempotency keys" in error for error in result.errors)


def test_mysql_state_validation_fails_missing_operation_status_before_invariants() -> None:
    _add_web_to_path()
    from services import mysql_state_validation  # type: ignore

    result = mysql_state_validation.validate_mysql_state(
        _ValidationConn(
            mysql_state_validation,
            missing_columns=(("proxy_operations", "status"),),
            duplicate_ops=2,
        ),
        phase="post-restore",
    )

    assert result.ok is False
    assert result.errors == ["missing generated/idempotency columns: proxy_operations.status"]


def test_mysql_state_validation_fails_missing_operation_proxy_id_before_invariants() -> None:
    _add_web_to_path()
    from services import mysql_state_validation  # type: ignore

    result = mysql_state_validation.validate_mysql_state(
        _ValidationConn(
            mysql_state_validation,
            missing_columns=(("proxy_operations", "proxy_id"),),
            orphan_operations=1,
        ),
        phase="post-restore",
    )

    assert result.ok is False
    assert result.errors == ["missing generated/idempotency columns: proxy_operations.proxy_id"]


def test_mysql_state_validation_fails_invalid_schema_checksum() -> None:
    _add_web_to_path()
    from services import mysql_state_validation  # type: ignore

    result = mysql_state_validation.validate_mysql_state(
        _ValidationConn(mysql_state_validation, schema_checksum="abc"),
        phase="post-restore",
    )

    assert result.ok is False
    assert any("missing/invalid checksum" in error for error in result.errors)


def test_mysql_state_validation_fails_terminal_operation_claim_state() -> None:
    _add_web_to_path()
    from services import mysql_state_validation  # type: ignore

    result = mysql_state_validation.validate_mysql_state(
        _ValidationConn(mysql_state_validation, terminal_claims=1),
        phase="post-restore",
    )

    assert result.ok is False
    assert any("retaining active request/claim state" in error for error in result.errors)


def test_mysql_state_validation_fails_orphan_operation_ownership() -> None:
    _add_web_to_path()
    from services import mysql_state_validation  # type: ignore

    result = mysql_state_validation.validate_mysql_state(
        _ValidationConn(mysql_state_validation, orphan_operations=1),
        phase="post-restore",
    )

    assert result.ok is False
    assert any("owned by missing proxies" in error for error in result.errors)


def test_mysql_state_validation_cli_returns_failure_for_invalid_state(monkeypatch, capsys) -> None:
    _add_web_to_path()
    from services import mysql_state_validation  # type: ignore

    monkeypatch.setattr(
        mysql_state_validation,
        "validate_mysql_state",
        lambda **_kwargs: SimpleNamespace(ok=False, to_dict=lambda: {"ok": False}),
    )

    assert mysql_state_validation.main(["--phase", "audit"]) == 1
    assert '"ok": false' in capsys.readouterr().out
