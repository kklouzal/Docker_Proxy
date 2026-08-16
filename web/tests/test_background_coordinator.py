from __future__ import annotations

import sys
import threading
from pathlib import Path

web_dir = Path(__file__).resolve().parents[1]
if str(web_dir) not in sys.path:
    sys.path.insert(0, str(web_dir))

from services import background_guard  # type: ignore  # noqa: E402


def test_coordinator_retries_contention_and_partial_start(monkeypatch) -> None:
    calls: list[str] = []
    lock_results = iter([False, True, True])
    second_attempts = iter([RuntimeError("not ready"), None])

    def second() -> None:
        calls.append("second")
        failure = next(second_attempts)
        if failure:
            raise failure

    monkeypatch.setattr(
        background_guard, "acquire_background_lock", lambda: next(lock_results)
    )
    coordinator = background_guard.BackgroundServiceCoordinator(
        (lambda: calls.append("first"), second, lambda: calls.append("third"))
    )

    assert coordinator.ensure_started() is False
    assert calls == []
    assert coordinator.ensure_started() is False
    assert calls == ["first", "second", "third"]
    assert coordinator.ensure_started() is True
    assert calls == ["first", "second", "third", "second"]


def test_coordinator_resets_service_state_after_fork(monkeypatch) -> None:
    calls: list[int] = []
    current_pid = {"value": 100}
    monkeypatch.setattr(background_guard.os, "getpid", lambda: current_pid["value"])
    monkeypatch.setattr(background_guard, "acquire_background_lock", lambda: True)
    coordinator = background_guard.BackgroundServiceCoordinator(
        (lambda: calls.append(current_pid["value"]),)
    )

    assert coordinator.ensure_started() is True
    assert coordinator.ensure_started() is True
    current_pid["value"] = 200
    assert coordinator.ensure_started() is True
    assert calls == [100, 200]


def test_coordinator_stops_only_successfully_started_services_in_reverse_order(
    monkeypatch,
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(background_guard, "acquire_background_lock", lambda: True)
    monkeypatch.setattr(background_guard, "release_background_lock", lambda: True)

    def failed_start() -> None:
        msg = "not started"
        raise RuntimeError(msg)

    coordinator = background_guard.BackgroundServiceCoordinator(
        (
            lambda: calls.append("start-1"),
            failed_start,
            lambda: calls.append("start-3"),
        ),
        (
            lambda: calls.append("stop-1"),
            lambda: calls.append("stop-2"),
            lambda: calls.append("stop-3"),
        ),
    )

    assert coordinator.ensure_started() is False
    assert coordinator.stop() is True
    assert coordinator.stop() is True
    assert calls == ["start-1", "start-3", "stop-3", "stop-1"]


def test_coordinator_retains_service_and_lock_when_bounded_stop_times_out(
    monkeypatch,
) -> None:
    releases: list[bool] = []
    stop_results = iter([False, True])
    monkeypatch.setattr(background_guard, "acquire_background_lock", lambda: True)
    monkeypatch.setattr(
        background_guard,
        "release_background_lock",
        lambda: releases.append(True) or True,
    )
    coordinator = background_guard.BackgroundServiceCoordinator(
        (lambda: None,), (lambda: next(stop_results),)
    )

    assert coordinator.ensure_started() is True
    assert coordinator.stop() is False
    assert releases == []
    assert coordinator.stop() is True
    assert releases == [True]


def test_coordinator_serializes_start_and_stop(monkeypatch) -> None:
    entered = threading.Event()
    proceed = threading.Event()
    calls: list[str] = []
    monkeypatch.setattr(background_guard, "acquire_background_lock", lambda: True)
    monkeypatch.setattr(background_guard, "release_background_lock", lambda: True)

    def start() -> None:
        entered.set()
        assert proceed.wait(1)
        calls.append("start")

    coordinator = background_guard.BackgroundServiceCoordinator(
        (start,), (lambda: calls.append("stop"),)
    )
    starter = threading.Thread(target=coordinator.ensure_started)
    stopper = threading.Thread(target=coordinator.stop)
    starter.start()
    assert entered.wait(1)
    stopper.start()
    assert stopper.is_alive()
    proceed.set()
    starter.join(1)
    stopper.join(1)

    assert calls == ["start", "stop"]


def test_coordinator_child_stop_does_not_stop_parent_owned_services(
    monkeypatch,
) -> None:
    current_pid = {"value": 100}
    calls: list[str] = []
    monkeypatch.setattr(background_guard.os, "getpid", lambda: current_pid["value"])
    monkeypatch.setattr(background_guard, "acquire_background_lock", lambda: True)
    coordinator = background_guard.BackgroundServiceCoordinator(
        (lambda: calls.append("start"),), (lambda: calls.append("stop"),)
    )

    assert coordinator.ensure_started() is True
    current_pid["value"] = 200
    assert coordinator.stop() is True
    assert calls == ["start"]
