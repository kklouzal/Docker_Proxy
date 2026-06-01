from __future__ import annotations

import sys
import threading
from datetime import UTC, datetime
from pathlib import Path


def _add_web_to_path() -> None:
    web_dir = Path(__file__).resolve().parents[1]
    if str(web_dir) not in sys.path:
        sys.path.insert(0, str(web_dir))


class _FakeConn:
    def __init__(self, calls: list[str]) -> None:
        self.calls = calls

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def execute(self, sql, params=None):
        self.calls.append(str(sql))
        return []


def _fake_connect(calls: list[str]):
    def connect():
        return _FakeConn(calls)

    return connect


def test_prune_methods_initialize_tables_before_deleting(monkeypatch) -> None:
    _add_web_to_path()
    from services.adblock_store import AdblockStore  # type: ignore
    from services.diagnostic_store import DiagnosticStore  # type: ignore
    from services.live_stats import LiveStatsStore  # type: ignore
    from services.ssl_errors_store import SslErrorsStore  # type: ignore

    stores = []

    adblock = AdblockStore.__new__(AdblockStore)
    adblock.blocklog_retention_days = 30
    stores.append(adblock)

    diagnostic = DiagnosticStore.__new__(DiagnosticStore)
    diagnostic.retention_days = 30
    stores.append(diagnostic)

    live = LiveStatsStore.__new__(LiveStatsStore)
    stores.append(live)

    ssl_errors = SslErrorsStore.__new__(SslErrorsStore)
    stores.append(ssl_errors)

    for store in stores:
        calls: list[str] = []
        monkeypatch.setattr(
            store, "init_db", lambda calls=calls: calls.append("init_db")
        )
        monkeypatch.setattr(store, "_connect", _fake_connect(calls))

        store.prune_old_entries(retention_days=1)

        assert calls[0] == "init_db"
        assert any("DELETE FROM" in call for call in calls[1:])


class _TimeseriesConn:
    def __init__(
        self, calls: list[str], *, fail_insert: bool = False, fail_select: bool = False
    ) -> None:
        self.calls = calls
        self.fail_insert = fail_insert
        self.fail_select = fail_select

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def execute(self, sql, params=None):
        text = str(sql)
        self.calls.append(text)
        if self.fail_insert and "INSERT INTO ts_1s" in text:
            msg = "(1146, table 'squid_proxy.ts_1s' doesn't exist)"
            raise RuntimeError(msg)
        if self.fail_select and "FROM ts_" in text:
            msg = "(1146, table 'squid_proxy.ts_1s' doesn't exist)"
            raise RuntimeError(msg)
        return _TimeseriesResult(text)


class _TimeseriesResult:
    def __init__(self, sql: str) -> None:
        self.sql = sql

    def fetchone(self):
        return (0, None, None, None)

    def fetchall(self):
        if "SELECT ts, count, cpu, mem, hit_rate" in self.sql:
            return [(123, 1, 2.5, 50.0, 75.0)]
        return []


def test_timeseries_insert_reinitializes_after_external_schema_wipe(
    monkeypatch,
) -> None:
    _add_web_to_path()
    from services.timeseries_store import TimeSeriesStore  # type: ignore

    store = TimeSeriesStore.__new__(TimeSeriesStore)
    store._db_initialized = True
    store._db_init_lock = threading.Lock()
    calls: list[str] = []
    connections = iter(
        [
            _TimeseriesConn(calls, fail_insert=True),
            _TimeseriesConn(calls),
            _TimeseriesConn(calls),
        ]
    )
    monkeypatch.setattr(store, "_connect", lambda: next(connections))

    store.insert_snapshot({}, ts=123)

    assert store._db_initialized is True
    assert sum(1 for call in calls if "CREATE TABLE IF NOT EXISTS" in call) == 7
    assert sum(1 for call in calls if "INSERT INTO ts_1s" in call) == 2


def test_timeseries_summary_reinitializes_after_external_schema_wipe(
    monkeypatch,
) -> None:
    _add_web_to_path()
    from services.timeseries_store import TimeSeriesStore  # type: ignore

    store = TimeSeriesStore.__new__(TimeSeriesStore)
    store._db_initialized = True
    store._db_init_lock = threading.Lock()
    calls: list[str] = []
    connections = iter(
        [
            _TimeseriesConn(calls, fail_select=True),
            _TimeseriesConn(calls),
            _TimeseriesConn(calls),
        ]
    )
    monkeypatch.setattr(store, "_connect", lambda: next(connections))

    summary = store.summary()

    assert set(summary) == {"60s", "1h", "24h", "7d"}
    assert summary["60s"]["count"] == 0
    assert store._db_initialized is True
    assert sum(1 for call in calls if "CREATE TABLE IF NOT EXISTS" in call) == 7


def test_timeseries_query_reinitializes_after_external_schema_wipe(monkeypatch) -> None:
    _add_web_to_path()
    from services.timeseries_store import TimeSeriesStore  # type: ignore

    store = TimeSeriesStore.__new__(TimeSeriesStore)
    store._db_initialized = True
    store._db_init_lock = threading.Lock()
    calls: list[str] = []
    connections = iter(
        [
            _TimeseriesConn(calls, fail_select=True),
            _TimeseriesConn(calls),
            _TimeseriesConn(calls),
        ]
    )
    monkeypatch.setattr(store, "_connect", lambda: next(connections))

    rows = store.query("1s", since=0, limit=25)

    assert rows == [{"ts": 123, "count": 1, "cpu": 2.5, "mem": 50.0, "hit_rate": 75.0}]
    assert store._db_initialized is True
    assert sum(1 for call in calls if "CREATE TABLE IF NOT EXISTS" in call) == 7


def test_housekeeping_resolves_current_retention_setting(monkeypatch) -> None:
    _add_web_to_path()
    from services import housekeeping  # type: ignore

    monkeypatch.setattr(
        housekeeping,
        "get_observability_retention_settings",
        lambda: {"retention_days": "45"},
    )

    assert housekeeping.current_retention_days(30) == 45


def test_housekeeping_retention_setting_falls_back_to_default(monkeypatch) -> None:
    _add_web_to_path()
    from services import housekeeping  # type: ignore

    def fail():
        msg = "db unavailable"
        raise RuntimeError(msg)

    monkeypatch.setattr(housekeeping, "get_observability_retention_settings", fail)

    assert housekeeping.current_retention_days(30) == 30


def test_housekeeping_full_run_prunes_then_maintains_tables(monkeypatch) -> None:
    _add_web_to_path()
    from services import housekeeping  # type: ignore

    calls: list[str] = []

    monkeypatch.setattr(
        housekeeping,
        "_run_prune_once",
        lambda *, retention_days: calls.append(f"prune:{retention_days}"),
    )

    def maintain(*, analyze: bool, optimize: bool):
        calls.append(f"maintain-observability:{analyze}:{optimize}")
        return {"ok": True, "maintained_tables": 2, "tables": []}

    def maintain_control_plane(*, analyze: bool, optimize: bool):
        calls.append(f"maintain-control-plane:{analyze}:{optimize}")
        return {"ok": True, "maintained_tables": 3, "tables": []}

    monkeypatch.setattr(housekeeping, "maintain_observability_tables", maintain)
    monkeypatch.setattr(
        housekeeping,
        "maintain_control_plane_tables",
        maintain_control_plane,
    )

    def acquire_lock():
        return object()

    monkeypatch.setattr(
        housekeeping, "acquire_observability_maintenance_lock", acquire_lock
    )
    monkeypatch.setattr(
        housekeeping, "release_observability_maintenance_lock", lambda _conn: None
    )
    monkeypatch.setattr(
        housekeeping, "record_observability_maintenance_run", lambda **_kwargs: None
    )

    result = housekeeping.run_housekeeping_once(
        retention_days=45,
        analyze=True,
        optimize=True,
    )

    assert calls == [
        "prune:45",
        "maintain-observability:True:True",
        "maintain-control-plane:True:True",
    ]
    assert result["ok"] is True
    assert result["retention_days"] == 45
    assert result["maintenance"]["maintained_tables"] == 5


def test_housekeeping_maintenance_continues_after_observability_failure(
    monkeypatch,
) -> None:
    _add_web_to_path()
    from services import housekeeping  # type: ignore

    calls: list[str] = []

    monkeypatch.setattr(
        housekeeping,
        "_run_prune_once",
        lambda *, retention_days: {"ok": True, "steps": []},
    )

    def fail_observability(*, analyze: bool, optimize: bool):
        calls.append(f"maintain-observability:{analyze}:{optimize}")
        msg = "observability analyze failed"
        raise RuntimeError(msg)

    def maintain_control_plane(*, analyze: bool, optimize: bool):
        calls.append(f"maintain-control-plane:{analyze}:{optimize}")
        return {
            "ok": True,
            "maintained_tables": 3,
            "tables": [{"table": "proxy_operations", "status": "maintained"}],
        }

    monkeypatch.setattr(
        housekeeping, "maintain_observability_tables", fail_observability
    )
    monkeypatch.setattr(
        housekeeping,
        "maintain_control_plane_tables",
        maintain_control_plane,
    )

    def acquire_lock():
        return object()

    monkeypatch.setattr(
        housekeeping, "acquire_observability_maintenance_lock", acquire_lock
    )
    monkeypatch.setattr(
        housekeeping, "release_observability_maintenance_lock", lambda _conn: None
    )
    monkeypatch.setattr(
        housekeeping, "record_observability_maintenance_run", lambda **_kwargs: None
    )
    monkeypatch.setattr(
        housekeeping,
        "log_exception_throttled",
        lambda *_args, **_kwargs: None,
    )

    result = housekeeping.run_housekeeping_once(
        retention_days=45,
        analyze=True,
        optimize=True,
    )

    assert calls == [
        "maintain-observability:True:True",
        "maintain-control-plane:True:True",
    ]
    assert result["ok"] is False
    assert result["status"] == "failed"
    assert result["maintenance"]["maintained_tables"] == 3
    assert result["maintenance"]["observability"]["ok"] is False
    assert result["maintenance"]["control_plane"]["ok"] is True
    assert any(
        row["scope"] == "observability"
        and row["status"] == "failed"
        and "observability analyze failed" in row["detail"]
        for row in result["maintenance"]["tables"]
    )


def test_housekeeping_prune_continues_after_step_failure(monkeypatch) -> None:
    _add_web_to_path()
    from services import housekeeping  # type: ignore

    calls: list[str] = []

    class Store:
        def __init__(self, name: str, *, fail: bool = False) -> None:
            self.name = name
            self.fail = fail

        def prune_old_entries(self, *, retention_days: int) -> None:
            calls.append(f"{self.name}:{retention_days}")
            if self.fail:
                msg = f"{self.name} failed"
                raise RuntimeError(msg)

    monkeypatch.setattr(housekeeping, "get_store", lambda: Store("live"))
    monkeypatch.setattr(
        housekeeping,
        "get_diagnostic_store",
        lambda: Store("diagnostic", fail=True),
    )
    monkeypatch.setattr(housekeeping, "get_adblock_store", lambda: Store("adblock"))
    monkeypatch.setattr(housekeeping, "get_ssl_errors_store", lambda: Store("ssl"))
    monkeypatch.setattr(housekeeping, "get_audit_store", lambda: Store("audit"))

    def control_plane():
        calls.append("control")
        return {"ok": True, "tables": []}

    monkeypatch.setattr(housekeeping, "prune_control_plane_tables", control_plane)
    monkeypatch.setattr(
        housekeeping,
        "log_exception_throttled",
        lambda *_args, **_kwargs: None,
    )

    result = housekeeping._run_prune_once(retention_days=7)

    assert calls == [
        "live:7",
        "diagnostic:7",
        "adblock:7",
        "ssl:7",
        "audit:7",
        "control",
    ]
    assert result["ok"] is False
    assert [row["name"] for row in result["steps"] if row["ok"]] == [
        "live_stats",
        "adblock",
        "ssl_errors",
        "audit",
        "control_plane",
    ]


def test_housekeeping_schedules_next_daily_and_weekly_runs() -> None:
    _add_web_to_path()
    from services import housekeeping  # type: ignore

    saturday = datetime(2026, 5, 23, 1, 30, tzinfo=UTC)
    daily = housekeeping._next_local_run(hour=2, now=saturday)
    weekly = housekeeping._next_local_run(
        hour=3,
        weekday=6,
        now=saturday,
    )

    assert daily == datetime(2026, 5, 23, 2, 0, tzinfo=UTC)
    assert weekly == datetime(2026, 5, 24, 3, 0, tzinfo=UTC)
