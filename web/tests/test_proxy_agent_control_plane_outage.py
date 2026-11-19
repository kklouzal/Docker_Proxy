from __future__ import annotations

import threading
from types import SimpleNamespace
from typing import ClassVar

import pymysql
import pytest
from services.proxy_recovery_startup import ProxyRecoveryStartupError  # type: ignore


class _FakeThread:
    created: ClassVar[list[tuple[str, tuple]]] = []

    def __init__(self, *, target, args=(), name, daemon) -> None:
        assert daemon is True
        _FakeThread.created.append((name, args))

    def start(self) -> None:
        return None


def _db_down_recovery_error() -> ProxyRecoveryStartupError:
    try:
        try:
            raise pymysql.OperationalError(2003, "Can't connect to MySQL server")
        except pymysql.OperationalError as exc:
            msg = "schema migration/control-plane identity setup failed before recovery adoption"
            raise ProxyRecoveryStartupError(msg) from exc
    except ProxyRecoveryStartupError as wrapped:
        return wrapped


class _Runtime:
    def __init__(self, recovery_outcomes: list[object]) -> None:
        self.recovery_outcomes = recovery_outcomes
        self.calls: list[str] = []

    def run_startup_recovery(self):
        self.calls.append("recovery")
        outcome = self.recovery_outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    def ensure_startup_schema(self) -> None:
        self.calls.append("schema")

    def ensure_registered(self) -> None:
        self.calls.append("register")

    def bootstrap_revision_if_missing(self) -> None:
        self.calls.append("bootstrap")

    def start_background_tasks(self) -> None:
        self.calls.append("background")

    def sync_from_db(self, *, force=False):
        self.calls.append("sync")
        return {"ok": True, "changed": False}

    def capture_recovery_bundle(self, *, reason, required=False, changed=False):
        self.calls.append(f"capture:{reason}")
        return {"ok": True}

    def run_local_self_heal(self, *, reason):
        self.calls.append(f"local_self_heal:{reason}")

    def heartbeat(self):
        self.calls.append("heartbeat")
        return {}

    @property
    def recovery_initial_capture_required(self) -> bool:
        return False


@pytest.fixture
def agent(monkeypatch):
    from proxy import agent as agent_module  # type: ignore

    _FakeThread.created = []
    monkeypatch.setattr(agent_module, "_started", False)
    monkeypatch.setattr(agent_module, "_loop_threads", [])
    monkeypatch.setattr(agent_module.threading, "Thread", _FakeThread)
    monkeypatch.setattr(agent_module, "_env_float", lambda *_args, **_kwargs: 30.0)
    monkeypatch.setattr(agent_module, "should_log", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(
        agent_module, "log_exception_throttled", lambda *_args, **_kwargs: None
    )
    return agent_module


def _loop_args(name: str) -> tuple:
    return next(args for loop_name, args in _FakeThread.created if loop_name == name)


def test_cold_start_with_mysql_down_keeps_agent_alive_and_writes_nothing(
    agent, monkeypatch
) -> None:
    runtime = _Runtime([_db_down_recovery_error()])
    monkeypatch.setattr(agent, "get_runtime", lambda: runtime)

    agent.start_agent()

    # Recovery adoption must precede any normal control-plane mutation.
    assert runtime.calls == ["recovery"]
    assert [name for name, _args in _FakeThread.created] == [
        "proxy-heartbeat",
        "proxy-sync-loop",
    ]
    _interval, heartbeat, *_rest = _loop_args("proxy-heartbeat")
    heartbeat()
    assert runtime.calls[-1] == "local_self_heal:heartbeat"


def test_pending_startup_is_finished_by_the_sync_loop_once_mysql_returns(
    agent, monkeypatch
) -> None:
    recovered = SimpleNamespace(proxy_id="edge", capture_required=False)
    runtime = _Runtime([_db_down_recovery_error(), recovered])
    monkeypatch.setattr(agent, "get_runtime", lambda: runtime)
    agent.start_agent()
    _interval, sync_cycle, _stop, _wake, backoff = _loop_args("proxy-sync-loop")
    _hb_interval, heartbeat, _hb_stop, heartbeat_wake = _loop_args("proxy-heartbeat")
    assert backoff is not None

    assert sync_cycle() is not False
    assert runtime.calls == [
        "recovery",
        "recovery",
        "register",
        "bootstrap",
        "background",
        "sync",
    ]
    # Startup completion reports the proxy at once instead of after 90 s.
    assert heartbeat_wake.is_set()
    heartbeat()
    assert runtime.calls[-1] == "heartbeat"


def test_fail_closed_recovery_blocks_mutation_without_exiting_agent(
    agent, monkeypatch
) -> None:
    runtime = _Runtime(
        [
            ProxyRecoveryStartupError("recovery bundle/key validation failed"),
            ProxyRecoveryStartupError("recovery bundle/key validation failed"),
        ]
    )
    monkeypatch.setattr(agent, "get_runtime", lambda: runtime)

    agent.start_agent()
    _interval, sync_cycle, *_rest = _loop_args("proxy-sync-loop")

    assert sync_cycle() is False
    assert runtime.calls == ["recovery", "recovery"]


def test_mysql_recovery_listener_wakes_both_loops(agent, monkeypatch) -> None:
    from services import db  # type: ignore

    listeners = list(db._mysql_recovery_listeners)
    try:
        runtime = _Runtime([SimpleNamespace(proxy_id="edge", capture_required=False)])
        monkeypatch.setattr(agent, "get_runtime", lambda: runtime)
        agent.start_agent()
        heartbeat_wake = _loop_args("proxy-heartbeat")[3]
        sync_wake = _loop_args("proxy-sync-loop")[3]
        heartbeat_wake.clear()

        db._notify_mysql_recovery_listeners()

        assert heartbeat_wake.is_set()
        assert sync_wake.is_set()
    finally:
        db._mysql_recovery_listeners[:] = listeners


def test_loop_backs_off_while_pending_and_wakes_immediately(agent) -> None:
    from services.observability_backoff import DatabaseWriteBackoff  # type: ignore

    stop = threading.Event()
    wake = threading.Event()
    results = [False, False, None]
    waits: list[float] = []
    backoff = DatabaseWriteBackoff(base_seconds=2.0, max_seconds=30.0, jitter_ratio=0.0)

    def cycle():
        result = results.pop(0)
        if not results:
            stop.set()
        return result

    original_wait = agent._wait_for_next_cycle

    def record_wait(delay, stop_event, wake_event):
        waits.append(delay)
        original_wait(0.0, stop_event, wake_event)

    agent._wait_for_next_cycle, saved = record_wait, original_wait
    try:
        agent._loop(30.0, cycle, stop, wake, backoff)
    finally:
        agent._wait_for_next_cycle = saved

    assert waits == [2.0, 4.0, 30.0]

    wake.set()
    stop.clear()
    agent._wait_for_next_cycle(3600.0, stop, wake)
    assert not wake.is_set()


def test_transient_classification_covers_wrapped_connectivity_and_lock_waits(
    agent,
) -> None:
    assert agent._is_transient_control_plane_failure(_db_down_recovery_error())
    assert agent._is_transient_control_plane_failure(
        TimeoutError("Timed out waiting for MySQL advisory lock")
    )
    assert not agent._is_transient_control_plane_failure(
        ProxyRecoveryStartupError("recovery bundle/key validation failed")
    )
    assert not agent._is_transient_control_plane_failure(
        pymysql.OperationalError(1045, "Access denied")
    )


def test_agent_publishes_control_plane_readiness_only_after_startup(
    agent, monkeypatch
) -> None:
    from proxy.control_plane_state import (  # type: ignore
        control_plane_ready,
        mark_control_plane_ready,
    )

    # A marker left by an earlier agent process must not count.
    mark_control_plane_ready()
    recovered = SimpleNamespace(proxy_id="edge", capture_required=False)
    runtime = _Runtime([_db_down_recovery_error(), recovered])
    monkeypatch.setattr(agent, "get_runtime", lambda: runtime)

    agent.start_agent()
    assert control_plane_ready() is False

    _interval, sync_cycle, *_rest = _loop_args("proxy-sync-loop")
    sync_cycle()
    assert control_plane_ready() is True
