from __future__ import annotations

import sys
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
