from __future__ import annotations

import threading
import time
from typing import ClassVar

import pymysql
import pytest
from services import diagnostic_store, live_stats, timeseries_store
from services.observability_backoff import DatabaseWriteBackoff, stagger_delay_from_env


class _FakeThread:
    created: ClassVar[list[_FakeThread]] = []

    def __init__(self, *, target, name=None, args=(), daemon=None):
        self.target = target
        self.name = name
        self.args = args
        self.daemon = daemon
        self.started = False
        _FakeThread.created.append(self)

    def start(self) -> None:
        self.started = True

    def is_alive(self) -> bool:
        return self.started


def test_database_write_backoff_defers_immediate_retries() -> None:
    backoff = DatabaseWriteBackoff(
        base_seconds=5.0,
        max_seconds=20.0,
        jitter_ratio=0.0,
    )

    assert backoff.can_attempt(10.0)
    assert backoff.record_failure(10.0) == pytest.approx(5.0)
    assert not backoff.can_attempt(14.9)
    assert backoff.can_attempt(15.0)
    assert backoff.record_failure(15.0) == pytest.approx(10.0)
    assert backoff.next_attempt_at == pytest.approx(25.0)

    backoff.record_success()
    assert backoff.can_attempt(16.0)
    assert backoff.failures == 0


def test_database_write_backoff_jitter_keeps_delay_within_configured_max() -> None:
    backoff = DatabaseWriteBackoff(
        base_seconds=5.0,
        max_seconds=20.0,
        jitter_ratio=0.5,
        _rand=lambda: 1.0,
    )

    assert backoff.record_failure(10.0) == pytest.approx(7.5)
    assert backoff.record_failure(20.0) == pytest.approx(15.0)
    assert backoff.record_failure(40.0) == pytest.approx(20.0)
    assert backoff.next_attempt_at == pytest.approx(60.0)


@pytest.mark.parametrize("rand_value", [float("nan"), float("inf"), -0.1, 1.1])
def test_database_write_backoff_invalid_random_value_uses_neutral_jitter(
    rand_value: float,
) -> None:
    backoff = DatabaseWriteBackoff(
        base_seconds=5.0,
        max_seconds=20.0,
        jitter_ratio=0.5,
        _rand=lambda: rand_value,
    )

    assert backoff.record_failure(10.0) == pytest.approx(5.0)
    assert backoff.next_attempt_at == pytest.approx(15.0)


def test_stagger_delay_uses_env_span_and_random(monkeypatch) -> None:
    monkeypatch.setenv("TIMESERIES_STARTUP_JITTER_SECONDS", "12")
    monkeypatch.setattr(
        "services.observability_backoff.random.uniform", lambda a, b: (a, b, 7.0)[2]
    )

    assert stagger_delay_from_env(
        "TIMESERIES_STARTUP_JITTER_SECONDS", 15.0, maximum=300.0
    ) == pytest.approx(7.0)


@pytest.mark.parametrize("random_delay", [float("nan"), float("inf"), -1.0, 13.0])
def test_stagger_delay_invalid_random_value_uses_zero_fallback(
    monkeypatch,
    random_delay: float,
) -> None:
    monkeypatch.setenv("TIMESERIES_STARTUP_JITTER_SECONDS", "12")
    monkeypatch.setattr(
        "services.observability_backoff.random.uniform",
        lambda _minimum, _maximum: random_delay,
    )

    assert stagger_delay_from_env(
        "TIMESERIES_STARTUP_JITTER_SECONDS", 15.0, maximum=300.0
    ) == pytest.approx(0.0)


def test_live_stats_background_starts_even_when_initial_db_is_down(
    monkeypatch, tmp_path
) -> None:
    _FakeThread.created.clear()
    log_path = tmp_path / "access.log"
    log_path.write_text("")
    store = live_stats.LiveStatsStore(access_log_path=str(log_path))

    def fail_init() -> None:
        raise pymysql.err.OperationalError(
            2013, "Lost connection to MySQL server during query"
        )

    monkeypatch.setattr(store, "init_db", fail_init)
    monkeypatch.setattr(live_stats.threading, "Thread", _FakeThread)

    store.start_background()

    assert store._started is True
    assert [thread.name for thread in _FakeThread.created] == ["live-stats-tailer"]
    assert _FakeThread.created[0].started is True


def test_live_stats_background_stop_allows_restart_without_duplicate_tailers(
    monkeypatch,
) -> None:
    store = live_stats.LiveStatsStore()
    entered = threading.Event()
    release = threading.Event()
    active = 0
    max_active = 0
    calls = 0
    counter_lock = threading.Lock()

    monkeypatch.setattr(store, "init_db", lambda: None)

    def tail_loop() -> None:
        nonlocal active, max_active, calls
        with counter_lock:
            active += 1
            max_active = max(max_active, active)
            calls += 1
            entered.set()
        release.wait()
        with counter_lock:
            active -= 1

    monkeypatch.setattr(store, "_tail_loop", tail_loop)

    starters = [threading.Thread(target=store.start_background) for _ in range(8)]
    for starter in starters:
        starter.start()
    for starter in starters:
        starter.join()
    assert entered.wait(1.0)
    assert calls == 1
    assert max_active == 1

    release.set()
    assert store.stop_background(timeout=1.0) is True
    assert store._started is False
    assert store._thread is None

    entered.clear()
    release.clear()
    store.start_background()
    assert entered.wait(1.0)
    assert calls == 2
    assert max_active == 1
    release.set()
    assert store.stop_background(timeout=1.0) is True


def test_live_stats_background_stop_timeout_preserves_live_tailer() -> None:
    class LiveThread:
        def join(self, _timeout: float) -> None:
            pass

        def is_alive(self) -> bool:
            return True

    store = live_stats.LiveStatsStore()
    worker = LiveThread()
    store._thread = worker  # type: ignore[assignment]
    store._started = True

    assert store.stop_background(timeout=0.0) is False
    assert store._thread is worker
    assert store._started is True


def test_live_stats_background_failed_thread_start_keeps_stopped_state(
    monkeypatch,
) -> None:
    class FailedThread:
        def __init__(self, **_kwargs) -> None:
            pass

        def start(self) -> None:
            message = "thread start failed"
            raise RuntimeError(message)

    store = live_stats.LiveStatsStore()
    monkeypatch.setattr(store, "init_db", lambda: None)
    monkeypatch.setattr(live_stats.threading, "Thread", FailedThread)

    with pytest.raises(RuntimeError, match="thread start failed"):
        store.start_background()

    assert store._started is False
    assert store._thread is None
    assert store._stop_event.is_set()


def test_diagnostic_background_starts_even_when_initial_db_is_down(
    monkeypatch, tmp_path
) -> None:
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
        raise pymysql.err.OperationalError(
            2013, "Lost connection to MySQL server during query"
        )

    monkeypatch.setattr(store, "init_db", fail_init)
    monkeypatch.setattr(diagnostic_store.threading, "Thread", _FakeThread)

    store.start_background()

    assert store._started is True
    assert sorted(thread.args[3] for thread in _FakeThread.created) == [
        "diagnostic-icap-tailer",
        "diagnostic-requests-tailer",
    ]
    assert all(thread.started for thread in _FakeThread.created)


def test_timeseries_sampler_stops_promptly_and_restarts_same_store(monkeypatch) -> None:
    store = timeseries_store.TimeSeriesStore()
    sampled = threading.Event()
    sample_count = 0

    monkeypatch.setenv("TIMESERIES_STARTUP_JITTER_SECONDS", "0")
    monkeypatch.setattr(store, "insert_snapshot", lambda _stats: sampled.set())

    def get_stats() -> dict[str, bool]:
        nonlocal sample_count
        sample_count += 1
        return {"ok": True}

    store.start_background(get_stats)
    assert sampled.wait(1.0)

    started = time.monotonic()
    assert store.stop_background(timeout=0.5) is True
    assert time.monotonic() - started < 0.5
    assert store._started is False
    assert store._thread is None

    sampled.clear()
    store.start_background(get_stats)
    assert sampled.wait(1.0)
    assert sample_count >= 2
    assert store.stop_background(timeout=0.5) is True


def test_timeseries_sampler_timeout_preserves_live_worker_ownership() -> None:
    class LiveThread:
        def start(self) -> None:
            pass

        def join(self, _timeout: float) -> None:
            pass

        def is_alive(self) -> bool:
            return True

    store = timeseries_store.TimeSeriesStore()
    worker = LiveThread()
    store._thread = worker  # type: ignore[assignment]
    store._started = True

    assert store.stop_background(timeout=0.0) is False
    store.start_background(dict)

    assert store._thread is worker
    assert store._started is True


def test_timeseries_rollup_cadence_is_configurable_and_not_every_snapshot(
    monkeypatch,
) -> None:
    class StopLoopError(Exception):
        pass

    class RunningThread(_FakeThread):
        def start(self) -> None:
            self.started = True
            try:
                self.target(*self.args)
            except StopLoopError:
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
            raise StopLoopError

    monkeypatch.setattr(store._stop_event, "wait", fake_sleep)
    monkeypatch.setattr(
        store, "insert_snapshot", lambda _stats: calls.append("snapshot")
    )
    monkeypatch.setattr(store, "rollup_and_prune", lambda: calls.append("rollup"))

    store.start_background(lambda: {"ok": True})

    assert calls.count("snapshot") == 4
    assert calls.count("rollup") == 1
    assert calls[-2:] == ["snapshot", "rollup"]
