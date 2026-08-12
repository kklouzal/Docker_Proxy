from __future__ import annotations

from types import SimpleNamespace

import pytest


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
        missing_indexes=(),
        duplicate_ops: int = 0,
        schema_checksum: str | None = None,
        terminal_claims: int = 0,
        orphan_application_owners: int = 0,
        invalid_config_applications: int = 0,
        invalid_certificate_applications: int = 0,
        invalid_adblock_applications: int = 0,
        orphan_operations: int = 0,
        orphan_pac_profiles: int = 0,
        orphan_pac_direct_domains: int = 0,
        orphan_pac_direct_dst_nets: int = 0,
        orphan_pac_backup_proxies: int = 0,
        orphan_pac_chain_settings: int = 0,
        orphan_report_schedules: int = 0,
        invalid_recovery_adoptions: int = 0,
        blocked_recovery_adoptions: int = 0,
        invalid_report_schedule_cadence: int = 0,
        invalid_report_schedule_format: int = 0,
        invalid_report_schedule_times: int = 0,
        count_query_error_contains: str | None = None,
    ) -> None:
        self.tables = set(module._REQUIRED_TABLES) - set(missing_tables)
        self.columns = set(module._REQUIRED_COLUMNS) - set(missing_columns)
        self.indexes = set(module._REQUIRED_INDEXES) - set(missing_indexes)
        self.duplicate_ops = duplicate_ops
        self.schema_checksum = schema_checksum or module.latest_schema_checksum()
        self.terminal_claims = terminal_claims
        self.orphan_application_owners = orphan_application_owners
        self.invalid_config_applications = invalid_config_applications
        self.invalid_certificate_applications = invalid_certificate_applications
        self.invalid_adblock_applications = invalid_adblock_applications
        self.orphan_operations = orphan_operations
        self.orphan_pac_profiles = orphan_pac_profiles
        self.orphan_pac_direct_domains = orphan_pac_direct_domains
        self.orphan_pac_direct_dst_nets = orphan_pac_direct_dst_nets
        self.orphan_pac_backup_proxies = orphan_pac_backup_proxies
        self.orphan_pac_chain_settings = orphan_pac_chain_settings
        self.orphan_report_schedules = orphan_report_schedules
        self.invalid_recovery_adoptions = invalid_recovery_adoptions
        self.blocked_recovery_adoptions = blocked_recovery_adoptions
        self.invalid_report_schedule_cadence = invalid_report_schedule_cadence
        self.invalid_report_schedule_format = invalid_report_schedule_format
        self.invalid_report_schedule_times = invalid_report_schedule_times
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
            return _Result(
                [{"status": "applied", "checksum": self.schema_checksum, "error": ""}]
            )
        if self.count_query_error_contains and self.count_query_error_contains in text:
            message = "simulated invariant query failure"
            raise RuntimeError(message)
        if "from proxy_operations" in text and "having count(*) > 1" in text:
            return _Result([{"n": self.duplicate_ops}])
        if "from proxy_operations" in text and "request_key is not null" in text:
            return _Result([{"n": self.terminal_claims}])
        if "from ( select app.proxy_id from proxy_config_applications" in text:
            return _Result([{"n": self.orphan_application_owners}])
        if (
            "from proxy_config_applications app" in text
            and "revision/evidence" not in text
        ):
            return _Result([{"n": self.invalid_config_applications}])
        if (
            "from proxy_certificate_applications app" in text
            and "left join certificate_bundle_revisions" in text
        ):
            return _Result([{"n": self.invalid_certificate_applications}])
        if (
            "from proxy_adblock_artifact_applications app" in text
            and "left join adblock_artifact_revisions" in text
        ):
            return _Result([{"n": self.invalid_adblock_applications}])
        if "from proxy_operations op" in text and "proxy.proxy_id is null" in text:
            return _Result([{"n": self.orphan_operations}])
        if "from pac_profiles pac_profile" in text and "proxy.proxy_id is null" in text:
            return _Result([{"n": self.orphan_pac_profiles}])
        if (
            "from pac_direct_domains direct_domain" in text
            and "pac_profile.id is null" in text
        ):
            return _Result([{"n": self.orphan_pac_direct_domains}])
        if (
            "from pac_direct_dst_nets direct_net" in text
            and "pac_profile.id is null" in text
        ):
            return _Result([{"n": self.orphan_pac_direct_dst_nets}])
        if (
            "from pac_backup_proxies backup_proxy" in text
            and "proxy.proxy_id is null" in text
        ):
            return _Result([{"n": self.orphan_pac_backup_proxies}])
        if (
            "from pac_proxy_chain_settings chain_settings" in text
            and "proxy.proxy_id is null" in text
        ):
            return _Result([{"n": self.orphan_pac_chain_settings}])
        if (
            "from observability_report_schedules schedule" in text
            and "proxy.proxy_id is null" in text
        ):
            return _Result([{"n": self.orphan_report_schedules}])
        if (
            "from proxy_recovery_adoptions marker" in text
            and "join proxy_lifecycle_tombstones" in text
        ):
            return _Result([{"n": self.blocked_recovery_adoptions}])
        if "from proxy_recovery_adoptions" in text and "status <> 'adopted'" in text:
            return _Result([{"n": self.invalid_recovery_adoptions}])
        if "from observability_report_schedules" in text and "cadence not in" in text:
            return _Result([{"n": self.invalid_report_schedule_cadence}])
        if (
            "from observability_report_schedules" in text
            and "report_format not in" in text
        ):
            return _Result([{"n": self.invalid_report_schedule_format}])
        if (
            "from observability_report_schedules" in text
            and "updated_ts < created_ts" in text
        ):
            return _Result([{"n": self.invalid_report_schedule_times}])
        return _Result([{"n": 0}])

    def close(self):
        return None


def test_mysql_state_validation_passes_complete_restored_state() -> None:
    from services import mysql_state_validation  # type: ignore

    result = mysql_state_validation.validate_mysql_state(
        _ValidationConn(mysql_state_validation),
        phase="post-restore",
    )

    assert result.ok is True
    assert result.errors == []
    assert result.details["schema_status"] == "applied"


def test_mysql_state_validation_fails_missing_lifecycle_tables() -> None:
    from services import mysql_state_validation  # type: ignore

    result = mysql_state_validation.validate_mysql_state(
        _ValidationConn(mysql_state_validation, missing_tables=("proxy_id_aliases",)),
        phase="pre-backup",
    )

    assert result.ok is False
    assert any("proxy_id_aliases" in error for error in result.errors)


def test_mysql_state_validation_fails_invalid_recovery_adoption_markers() -> None:
    from services import mysql_state_validation  # type: ignore

    result = mysql_state_validation.validate_mysql_state(
        _ValidationConn(
            mysql_state_validation,
            invalid_recovery_adoptions=1,
            blocked_recovery_adoptions=2,
        ),
        phase="post-restore",
    )

    assert result.ok is False
    assert any("invalid marker contract" in error for error in result.errors)
    assert any("lifecycle-blocked" in error for error in result.errors)


def test_mysql_state_validation_fails_duplicate_active_operation_keys() -> None:
    from services import mysql_state_validation  # type: ignore

    result = mysql_state_validation.validate_mysql_state(
        _ValidationConn(mysql_state_validation, duplicate_ops=2),
        phase="post-restore",
    )

    assert result.ok is False
    assert any("duplicate active idempotency keys" in error for error in result.errors)


def test_mysql_state_validation_fails_invariant_query_errors() -> None:
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


def test_mysql_state_validation_fails_missing_operation_status_before_invariants() -> (
    None
):
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
    assert result.errors == [
        "missing generated/idempotency columns: proxy_operations.status"
    ]


def test_mysql_state_validation_fails_missing_operation_proxy_id_before_invariants() -> (
    None
):
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
    assert result.errors == [
        "missing generated/idempotency columns: proxy_operations.proxy_id"
    ]


def test_mysql_state_validation_fails_missing_operation_progress_index() -> None:
    from services import mysql_state_validation  # type: ignore

    result = mysql_state_validation.validate_mysql_state(
        _ValidationConn(
            mysql_state_validation,
            missing_indexes=(
                ("proxy_operations", "idx_proxy_operations_proxy_started_id"),
            ),
        ),
        phase="post-restore",
    )

    assert result.ok is False
    assert any(
        "missing generated/idempotency indexes" in error
        and "proxy_operations.idx_proxy_operations_proxy_started_id" in error
        for error in result.errors
    )


def test_mysql_state_validation_fails_invalid_schema_checksum() -> None:
    from services import mysql_state_validation  # type: ignore

    result = mysql_state_validation.validate_mysql_state(
        _ValidationConn(mysql_state_validation, schema_checksum="abc"),
        phase="post-restore",
    )

    assert result.ok is False
    assert any("missing/invalid checksum" in error for error in result.errors)


def test_mysql_state_validation_fails_terminal_operation_claim_state() -> None:
    from services import mysql_state_validation  # type: ignore

    result = mysql_state_validation.validate_mysql_state(
        _ValidationConn(mysql_state_validation, terminal_claims=1),
        phase="post-restore",
    )

    assert result.ok is False
    assert any(
        "retaining active request/claim state" in error for error in result.errors
    )


def test_mysql_state_validation_fails_orphan_operation_ownership() -> None:
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
            {"orphan_application_owners": 2},
            "proxy application ledgers have 2 row(s) owned by missing proxies without tombstones",
        ),
        (
            {"invalid_config_applications": 1},
            "proxy_config_applications has 1 invalid revision/evidence row(s)",
        ),
        (
            {"invalid_certificate_applications": 3},
            "proxy_certificate_applications has 3 invalid revision/evidence row(s)",
        ),
        (
            {"invalid_adblock_applications": 4},
            "proxy_adblock_artifact_applications has 4 invalid revision/evidence row(s)",
        ),
    ],
)
def test_mysql_state_validation_fails_application_ledger_integrity(
    conn_kwargs, expected_error
) -> None:
    from services import mysql_state_validation  # type: ignore

    result = mysql_state_validation.validate_mysql_state(
        _ValidationConn(mysql_state_validation, **conn_kwargs),
        phase="post-restore",
    )

    assert result.ok is False
    assert expected_error in result.errors


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
def test_mysql_state_validation_fails_pac_persistence_orphans(
    conn_kwargs, expected_error
) -> None:
    from services import mysql_state_validation  # type: ignore

    result = mysql_state_validation.validate_mysql_state(
        _ValidationConn(mysql_state_validation, **conn_kwargs),
        phase="post-restore",
    )

    assert result.ok is False
    assert expected_error in result.errors


@pytest.mark.parametrize(
    ("conn_kwargs", "expected_error"),
    [
        (
            {"orphan_report_schedules": 1},
            "observability_report_schedules has 1 row(s) owned by missing proxies without tombstones",
        ),
        (
            {"invalid_report_schedule_cadence": 2},
            "observability_report_schedules has 2 row(s) violating manual-export preset semantics",
        ),
        (
            {"invalid_report_schedule_format": 3},
            "observability_report_schedules has 3 row(s) with invalid format values",
        ),
        (
            {"invalid_report_schedule_times": 4},
            "observability_report_schedules has 4 row(s) with invalid timestamp values",
        ),
    ],
)
def test_mysql_state_validation_fails_report_schedule_invariants(
    conn_kwargs, expected_error
) -> None:
    from services import mysql_state_validation  # type: ignore

    result = mysql_state_validation.validate_mysql_state(
        _ValidationConn(mysql_state_validation, **conn_kwargs),
        phase="post-restore",
    )

    assert result.ok is False
    assert expected_error in result.errors


def test_mysql_state_validation_cli_returns_failure_for_invalid_state(
    monkeypatch, capsys
) -> None:
    from services import mysql_state_validation  # type: ignore

    monkeypatch.setattr(
        mysql_state_validation,
        "validate_mysql_state",
        lambda **_kwargs: SimpleNamespace(ok=False, to_dict=lambda: {"ok": False}),
    )

    assert mysql_state_validation.main(["--phase", "audit"]) == 1
    assert '"ok": false' in capsys.readouterr().out
