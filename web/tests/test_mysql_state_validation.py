from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


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
        orphan_pac_profiles: int = 0,
        orphan_pac_direct_domains: int = 0,
        orphan_pac_direct_dst_nets: int = 0,
        orphan_pac_backup_proxies: int = 0,
        orphan_pac_chain_settings: int = 0,
        count_query_error_contains: str | None = None,
    ) -> None:
        self.tables = set(module._REQUIRED_TABLES) - set(missing_tables)
        self.columns = set(module._REQUIRED_COLUMNS) - set(missing_columns)
        self.indexes = set(module._REQUIRED_INDEXES)
        self.duplicate_ops = duplicate_ops
        self.schema_checksum = schema_checksum or module.latest_schema_checksum()
        self.terminal_claims = terminal_claims
        self.orphan_operations = orphan_operations
        self.orphan_pac_profiles = orphan_pac_profiles
        self.orphan_pac_direct_domains = orphan_pac_direct_domains
        self.orphan_pac_direct_dst_nets = orphan_pac_direct_dst_nets
        self.orphan_pac_backup_proxies = orphan_pac_backup_proxies
        self.orphan_pac_chain_settings = orphan_pac_chain_settings
        self.count_query_error_contains = count_query_error_contains

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
        if self.count_query_error_contains and self.count_query_error_contains in text:
            message = "simulated invariant query failure"
            raise RuntimeError(message)
        if "from proxy_operations" in text and "having count(*) > 1" in text:
            return _Result([{"n": self.duplicate_ops}])
        if "from proxy_operations" in text and "request_key is not null" in text:
            return _Result([{"n": self.terminal_claims}])
        if "from proxy_operations op" in text and "proxy.proxy_id is null" in text:
            return _Result([{"n": self.orphan_operations}])
        if "from pac_profiles pac_profile" in text and "proxy.proxy_id is null" in text:
            return _Result([{"n": self.orphan_pac_profiles}])
        if "from pac_direct_domains direct_domain" in text and "pac_profile.id is null" in text:
            return _Result([{"n": self.orphan_pac_direct_domains}])
        if "from pac_direct_dst_nets direct_net" in text and "pac_profile.id is null" in text:
            return _Result([{"n": self.orphan_pac_direct_dst_nets}])
        if "from pac_backup_proxies backup_proxy" in text and "proxy.proxy_id is null" in text:
            return _Result([{"n": self.orphan_pac_backup_proxies}])
        if "from pac_proxy_chain_settings chain_settings" in text and "proxy.proxy_id is null" in text:
            return _Result([{"n": self.orphan_pac_chain_settings}])
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


def test_mysql_state_validation_fails_invariant_query_errors() -> None:
    _add_web_to_path()
    from services import mysql_state_validation  # type: ignore

    result = mysql_state_validation.validate_mysql_state(
        _ValidationConn(
            mysql_state_validation,
            count_query_error_contains="select proxy_id, request_key",
        ),
        phase="post-restore",
    )

    assert result.ok is False
    assert any(
        "failed MySQL state validation invariant query" in error
        and "proxy_operations duplicate active idempotency keys" in error
        and "simulated invariant query failure" in error
        for error in result.errors
    )


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


@pytest.mark.parametrize(
    ("conn_kwargs", "expected_error"),
    [
        (
            {"orphan_pac_profiles": 1},
            "pac_profiles has 1 row(s) owned by missing proxies without tombstones",
        ),
        (
            {"orphan_pac_direct_domains": 2},
            "pac_direct_domains has 2 row(s) with missing pac_profiles parents",
        ),
        (
            {"orphan_pac_direct_dst_nets": 3},
            "pac_direct_dst_nets has 3 row(s) with missing pac_profiles parents",
        ),
        (
            {"orphan_pac_backup_proxies": 4},
            "pac_backup_proxies has 4 row(s) owned by missing proxies without tombstones",
        ),
        (
            {"orphan_pac_chain_settings": 5},
            "pac_proxy_chain_settings has 5 row(s) owned by missing proxies without tombstones",
        ),
    ],
)
def test_mysql_state_validation_fails_pac_persistence_orphans(conn_kwargs, expected_error) -> None:
    _add_web_to_path()
    from services import mysql_state_validation  # type: ignore

    result = mysql_state_validation.validate_mysql_state(
        _ValidationConn(mysql_state_validation, **conn_kwargs),
        phase="post-restore",
    )

    assert result.ok is False
    assert expected_error in result.errors


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
