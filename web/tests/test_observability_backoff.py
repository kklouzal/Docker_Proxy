from __future__ import annotations

import threading

import pymysql

from services.observability_backoff import DatabaseWriteBackoff, stagger_delay_from_env
from services import diagnostic_store, live_stats, timeseries_store


class _FakeThread:
    created: list["_FakeThread"] = []

    def __init__(self, *, target, name=None, args=(), daemon=None):
        self.target = target
        self.name = name
        self.args = args
        self.daemon = daemon
        self.started = False
        _FakeThread.created.append(self)

    def start(self) -> None:
        self.started = True


def test_database_write_backoff_defers_immediate_retries() -> None:
    backoff = DatabaseWriteBackoff(
        base_seconds=5.0,
        max_seconds=20.0,
        jitter_ratio=0.0,
    )

    assert backoff.can_attempt(10.0)
    assert backoff.record_failure(10.0) == 5.0
    assert not backoff.can_attempt(14.9)
    assert backoff.can_attempt(15.0)
    assert backoff.record_failure(15.0) == 10.0
    assert backoff.next_attempt_at == 25.0

    backoff.record_success()
    assert backoff.can_attempt(16.0)
    assert backoff.failures == 0


def test_stagger_delay_uses_env_span_and_random(monkeypatch) -> None:
    monkeypatch.setenv("TIMESERIES_STARTUP_JITTER_SECONDS", "12")
    monkeypatch.setattr("services.observability_backoff.random.uniform", lambda a, b: (a, b, 7.0)[2])

    assert stagger_delay_from_env("TIMESERIES_STARTUP_JITTER_SECONDS", 15.0, maximum=300.0) == 7.0


def test_live_stats_background_starts_even_when_initial_db_is_down(monkeypatch, tmp_path) -> None:
    _FakeThread.created.clear()
    log_path = tmp_path / "access.log"
    log_path.write_text("")
    store = live_stats.LiveStatsStore(access_log_path=str(log_path))

    def fail_init() -> None:
        raise pymysql.err.OperationalError(2013, "Lost connection to MySQL server during query")

    monkeypatch.setattr(store, "init_db", fail_init)
    monkeypatch.setattr(live_stats.threading, "Thread", _FakeThread)

    store.start_background()

    assert store._started is True
    assert [thread.name for thread in _FakeThread.created] == ["live-stats-tailer"]
    assert _FakeThread.created[0].started is True


def test_diagnostic_background_starts_even_when_initial_db_is_down(monkeypatch, tmp_path) -> None:
    _FakeThread.created.clear()
    access_log = tmp_path / "access.log"
    icap_log = tmp_path / "icap.log"
    access_log.write_text("")
    icap_log.write_text("")
    store = diagnostic_store.DiagnosticStore(
        access_log_path=str(access_log),
        icap_log_path=str(icap_log),
    )

    def fail_init() -> None:
        raise pymysql.err.OperationalError(2013, "Lost connection to MySQL server during query")

    monkeypatch.setattr(store, "init_db", fail_init)
    monkeypatch.setattr(diagnostic_store.threading, "Thread", _FakeThread)

    store.start_background()

    assert store._started is True
    assert sorted(thread.args[3] for thread in _FakeThread.created) == [
        "diagnostic-icap-tailer",
        "diagnostic-requests-tailer",
    ]
    assert all(thread.started for thread in _FakeThread.created)


def test_timeseries_rollup_cadence_is_configurable_and_not_every_snapshot(monkeypatch) -> None:
    class StopLoop(Exception):
        pass

    class RunningThread(_FakeThread):
        def start(self) -> None:
            self.started = True
            try:
                self.target(*self.args)
            except StopLoop:
                pass

    _FakeThread.created.clear()
    store = timeseries_store.TimeSeriesStore()
    calls: list[str] = []
    current = {"value": 0.0, "sleeps": 0}

    monkeypatch.setenv("TIMESERIES_STARTUP_JITTER_SECONDS", "0")
    monkeypatch.setenv("TIMESERIES_ROLLUP_INTERVAL_SECONDS", "30")
    monkeypatch.setattr(timeseries_store.threading, "Thread", RunningThread)
    monkeypatch.setattr(timeseries_store.time, "monotonic", lambda: current["value"])

    def fake_sleep(_seconds: float) -> None:
        current["sleeps"] += 1
        current["value"] += 10.0
        if current["sleeps"] >= 4:
            raise StopLoop()

    monkeypatch.setattr(timeseries_store.time, "sleep", fake_sleep)
    monkeypatch.setattr(store, "insert_snapshot", lambda _stats: calls.append("snapshot"))
    monkeypatch.setattr(store, "rollup_and_prune", lambda: calls.append("rollup"))

    store.start_background(lambda: {"ok": True})

    assert calls.count("snapshot") == 4
    assert calls.count("rollup") == 1
    assert calls[-2:] == ["snapshot", "rollup"]
