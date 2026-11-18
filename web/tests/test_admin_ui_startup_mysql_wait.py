from __future__ import annotations

from types import SimpleNamespace

import pymysql
import pytest

from .test_packaging_contracts import _load_start_admin_ui_module


class _Clock:
    def __init__(self) -> None:
        self.now = 100.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def _unreachable() -> pymysql.err.OperationalError:
    return pymysql.err.OperationalError(
        2003,
        "Can't connect to MySQL server on 'mysql' ([Errno 113] Host is unreachable)",
    )


def test_wait_retries_transient_probe_failures_with_capped_backoff(capsys) -> None:
    module = _load_start_admin_ui_module()
    clock = _Clock()
    probe_failures = 40
    probes: list[int] = []
    operations: list[int] = []

    def probe() -> None:
        probes.append(1)
        if len(probes) <= probe_failures:
            raise _unreachable()

    def operation() -> str:
        operations.append(1)
        return "ready"

    result = module.run_when_mysql_ready(
        operation,
        probe=probe,
        sleep=clock.sleep,
        monotonic=clock.monotonic,
        uniform=lambda _low, high: high,
    )

    assert result == "ready"
    # The DB-dependent step runs exactly once, only after MySQL answered.
    assert operations == [1]
    assert len(clock.sleeps) == probe_failures
    assert clock.sleeps[:5] == [0.5, 1.0, 2.0, 4.0, 5.0]
    assert max(clock.sleeps) == module.MYSQL_WAIT_MAX_DELAY_SECONDS
    stderr = capsys.readouterr().err
    waiting_lines = [
        line for line in stderr.splitlines() if line.startswith("Waiting for MySQL")
    ]
    # First failure plus one line per elapsed minute, not one per attempt.
    total_wait = sum(clock.sleeps)
    assert 1 <= len(waiting_lines) <= 2 + int(total_wait // 60)
    assert len(waiting_lines) < probe_failures
    assert "Host is unreachable" in waiting_lines[0]
    assert f"({probe_failures} failed attempts)" in stderr
    assert "MySQL became reachable after" in stderr


def test_wait_jitter_stays_within_half_to_full_cap() -> None:
    module = _load_start_admin_ui_module()
    clock = _Clock()
    bounds: list[tuple[float, float]] = []
    failures = iter(range(3))

    def probe() -> None:
        if next(failures, None) is not None:
            raise _unreachable()

    def uniform(low: float, high: float) -> float:
        bounds.append((low, high))
        return low

    module.run_when_mysql_ready(
        lambda: None,
        probe=probe,
        sleep=clock.sleep,
        monotonic=clock.monotonic,
        uniform=uniform,
    )

    assert bounds == [(0.25, 0.5), (0.5, 1.0), (1.0, 2.0)]


def test_wait_logs_again_when_mysql_error_changes(capsys) -> None:
    module = _load_start_admin_ui_module()
    clock = _Clock()
    errors = iter(
        [
            _unreachable(),
            _unreachable(),
            pymysql.err.OperationalError(1053, "Server shutdown in progress"),
        ],
    )

    def probe() -> None:
        error = next(errors, None)
        if error is not None:
            raise error

    module.run_when_mysql_ready(
        lambda: None,
        probe=probe,
        sleep=clock.sleep,
        monotonic=clock.monotonic,
        uniform=lambda _low, high: high,
    )

    waiting = [
        line
        for line in capsys.readouterr().err.splitlines()
        if line.startswith("Waiting for MySQL")
    ]
    assert len(waiting) == 2
    assert "Server shutdown in progress" in waiting[1]


def test_wait_replays_whole_step_after_transient_operation_failure() -> None:
    module = _load_start_admin_ui_module()
    clock = _Clock()
    calls: list[str] = []

    def operation() -> str:
        calls.append("step")
        if len(calls) == 1:
            raise pymysql.err.OperationalError(2013, "Lost connection during query")
        return "done"

    assert (
        module.run_when_mysql_ready(
            operation,
            probe=lambda: None,
            sleep=clock.sleep,
            monotonic=clock.monotonic,
            uniform=lambda _low, high: high,
        )
        == "done"
    )
    assert calls == ["step", "step"]
    assert clock.sleeps == [0.5]


@pytest.mark.parametrize(
    "error",
    [
        pymysql.err.OperationalError(1045, "Access denied for user"),
        RuntimeError("Schema migration 31 checksum drift"),
        TimeoutError("Timed out waiting for MySQL advisory lock"),
    ],
)
def test_wait_propagates_non_transient_failures_without_waiting(error) -> None:
    module = _load_start_admin_ui_module()
    clock = _Clock()

    def operation() -> None:
        raise error

    with pytest.raises(type(error)):
        module.run_when_mysql_ready(
            operation,
            probe=lambda: None,
            sleep=clock.sleep,
            monotonic=clock.monotonic,
        )
    assert clock.sleeps == []


def test_https_resolution_does_not_pin_env_fallback_on_transient_mysql_error(
    capsys,
) -> None:
    module = _load_start_admin_ui_module()

    def loader():
        raise _unreachable()

    with pytest.raises(pymysql.err.OperationalError):
        module.resolve_admin_ui_https_config(
            {"ADMIN_UI_HTTPS_ENABLED": "1"},
            settings_loader=loader,
        )
    assert "environment fallback" not in capsys.readouterr().err


def test_https_resolution_keeps_env_fallback_for_non_transient_loader_error(
    capsys,
) -> None:
    module = _load_start_admin_ui_module()

    def loader():
        message = "MySQL configuration is required"
        raise RuntimeError(message)

    config = module.resolve_admin_ui_https_config(
        {"ADMIN_UI_HTTPS_ENABLED": "0"},
        settings_loader=loader,
    )

    assert config.source == "env"
    assert "environment fallback" in capsys.readouterr().err


def test_leaf_recovery_propagates_transient_mysql_error(monkeypatch) -> None:
    module = _load_start_admin_ui_module()
    from services import certificate_bundles

    class _Store:
        def get_admin_ui_https_settings(self):
            raise _unreachable()

    monkeypatch.setattr(certificate_bundles, "get_certificate_bundles", _Store)

    with pytest.raises(pymysql.err.OperationalError):
        module._try_materialize_saved_admin_ui_leaf({})


def test_main_waits_for_mysql_then_execs_with_db_https_settings(
    monkeypatch,
) -> None:
    module = _load_start_admin_ui_module()
    events: list[str] = []
    attempts = iter([_unreachable(), None])

    def probe() -> None:
        error = next(attempts)
        events.append("probe")
        if error is not None:
            raise error

    def ensure_schema():
        events.append("migrate")
        return []

    def loader():
        events.append("https-settings")
        return SimpleNamespace(enabled=False, updated_ts=7)

    from services import certificate_bundles, schema_lifecycle

    monkeypatch.setattr(
        schema_lifecycle, "ensure_startup_schema_if_configured", ensure_schema
    )
    monkeypatch.setattr(
        certificate_bundles,
        "get_certificate_bundles",
        lambda: SimpleNamespace(get_admin_ui_https_settings=loader),
    )
    monkeypatch.setattr(module, "_probe_mysql_server", probe)
    real_wait = module.run_when_mysql_ready
    monkeypatch.setattr(
        module,
        "run_when_mysql_ready",
        lambda operation: real_wait(
            operation, probe=module._probe_mysql_server, sleep=lambda _s: None
        ),
    )
    executed: list[list[str]] = []

    def execvp(_file, argv):
        executed.append(list(argv))
        raise SystemExit(0)

    monkeypatch.setattr(module.os, "execvp", execvp)
    monkeypatch.setattr(module.sys, "argv", ["start_admin_ui.py"])
    for name in (
        "ADMIN_UI_EFFECTIVE_HTTPS_ENABLED",
        "ADMIN_UI_EFFECTIVE_SSL_CERTFILE",
        "ADMIN_UI_EFFECTIVE_SSL_KEYFILE",
        "ADMIN_UI_EFFECTIVE_HTTPS_SOURCE",
        "ADMIN_UI_EFFECTIVE_HTTPS_ERROR",
    ):
        monkeypatch.setenv(name, "")
    monkeypatch.setenv("MYSQL_HOST", "mysql")
    monkeypatch.setenv("ADMIN_UI_HTTPS_ENABLED", "1")

    with pytest.raises(SystemExit):
        module.main()

    assert events == ["probe", "probe", "migrate", "https-settings"]
    assert len(executed) == 1
    assert "--certfile" not in executed[0]
    assert module.os.environ["ADMIN_UI_EFFECTIVE_HTTPS_SOURCE"] == "db"
    assert module.os.environ["ADMIN_UI_EFFECTIVE_HTTPS_ENABLED"] == "0"
