from __future__ import annotations

import logging
import threading


class FakeThread:
    def __init__(self, name: str, *, alive_after_join: bool) -> None:
        self.name = name
        self._alive = alive_after_join
        self.join_timeouts: list[float] = []

    def join(self, timeout: float | None = None) -> None:
        assert timeout is not None
        self.join_timeouts.append(timeout)

    def is_alive(self) -> bool:
        return self._alive


def test_shutdown_does_not_race_background_stop_with_active_loop(
    monkeypatch, caplog
) -> None:
    from proxy import agent  # type: ignore

    callback_entered = threading.Event()
    release_callback = threading.Event()
    stop_event = threading.Event()

    def blocking_callback() -> None:
        callback_entered.set()
        release_callback.wait()

    active = threading.Thread(
        target=agent._loop,
        args=(1.0, blocking_callback, stop_event),
        name="proxy-sync-loop",
        daemon=True,
    )

    class Runtime:
        def stop_background_tasks(self, *, timeout: float) -> None:
            message = "must not stop background tasks under an active loop"
            raise AssertionError(message)

    active.start()
    assert callback_entered.wait(timeout=0.5)
    stop_event.set()
    monkeypatch.setattr(agent, "_loop_threads", [active])

    try:
        with caplog.at_level(logging.WARNING):
            assert agent._shutdown(Runtime(), timeout=0.01) is False

        assert active.is_alive()
        assert "active loops: proxy-sync-loop" in caplog.text
        assert "background services were not stopped" in caplog.text
    finally:
        release_callback.set()
        active.join(timeout=0.5)

    assert not active.is_alive()


def test_shutdown_gracefully_stops_background_tasks_with_remaining_budget(
    monkeypatch,
) -> None:
    from proxy import agent  # type: ignore

    stopped = FakeThread("proxy-heartbeat", alive_after_join=False)
    stop_timeouts: list[float] = []

    class Runtime:
        def stop_background_tasks(self, *, timeout: float) -> bool:
            stop_timeouts.append(timeout)
            return True

    monotonic_values = iter((200.0, 201.0, 202.0))
    monkeypatch.setattr(agent, "_loop_threads", [stopped])
    monkeypatch.setattr(agent.time, "monotonic", lambda: next(monotonic_values))

    assert agent._shutdown(Runtime(), timeout=10.0) is True

    assert stopped.join_timeouts == [9.0]
    assert stop_timeouts == [8.0]
