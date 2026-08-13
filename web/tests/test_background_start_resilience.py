from __future__ import annotations

import threading

from services import (  # type: ignore
    adblock_artifacts,
    safe_browsing_v5,
    webfilter_store,
)


def _noop_init_schema(_conn) -> None:
    return None


def test_adblock_artifact_background_start_defers_database_init(monkeypatch) -> None:
    store = adblock_artifacts.AdblockArtifactStore()
    started: list[bool] = []
    targets: list[object] = []

    def fail_if_called() -> None:  # pragma: no cover - should never run here
        msg = (
            "start_background should defer database initialization to the worker thread"
        )
        raise AssertionError(msg)

    class FakeThread:
        def __init__(self, *, target, name, daemon) -> None:
            targets.append(target)
            assert name == "adblock-artifact-builder"
            assert daemon is True

        def start(self) -> None:
            started.append(True)

    monkeypatch.setattr(store, "init_db", fail_if_called)
    monkeypatch.setattr(adblock_artifacts.threading, "Thread", FakeThread)

    store.start_background()

    assert store._started is True
    assert started == [True]
    assert len(targets) == 1


def test_webfilter_background_start_defers_database_init(monkeypatch) -> None:
    store = webfilter_store.WebFilterStore()
    started: list[bool] = []
    targets: list[object] = []
    safe_browsing_started: list[bool] = []

    def fail_if_called() -> None:  # pragma: no cover - should never run here
        msg = (
            "start_background should defer database initialization to the worker thread"
        )
        raise AssertionError(msg)

    class FakeThread:
        def __init__(self, *, target, name, daemon) -> None:
            targets.append(target)
            assert name == "webfilter-updater"
            assert daemon is True

        def start(self) -> None:
            started.append(True)

    monkeypatch.setattr(store, "init_db", fail_if_called)
    monkeypatch.setattr(webfilter_store.threading, "Thread", FakeThread)
    monkeypatch.setattr(
        safe_browsing_v5.SafeBrowsingStore,
        "start_background",
        lambda self, *_args: safe_browsing_started.append(True),
    )

    store.start_background()

    assert store._started is True
    assert started == [True]
    assert safe_browsing_started == [True]
    assert len(targets) == 1


def test_webfilter_background_retries_only_failed_safe_browsing_start(
    monkeypatch,
) -> None:
    store = webfilter_store.WebFilterStore()
    webfilter_starts: list[bool] = []
    safe_browsing_attempts: list[bool] = []

    def fail_if_called() -> None:  # pragma: no cover - should never run here
        msg = "database initialization must remain in the worker thread"
        raise AssertionError(msg)

    class FakeThread:
        def __init__(self, *, target, name, daemon) -> None:
            assert target == store._loop
            assert name == "webfilter-updater"
            assert daemon is True

        def start(self) -> None:
            webfilter_starts.append(True)

    def start_safe_browsing(self, *_args) -> None:
        if self._started:
            return
        safe_browsing_attempts.append(True)
        if len(safe_browsing_attempts) == 1:
            msg = "simulated Safe Browsing thread start failure"
            raise RuntimeError(msg)
        self._started = True

    monkeypatch.setattr(store, "init_db", fail_if_called)
    monkeypatch.setattr(webfilter_store.threading, "Thread", FakeThread)
    monkeypatch.setattr(
        safe_browsing_v5.SafeBrowsingStore,
        "start_background",
        start_safe_browsing,
    )

    try:
        store.start_background()
    except RuntimeError as exc:
        assert str(exc) == "simulated Safe Browsing thread start failure"
    else:  # pragma: no cover - regression guard
        msg = "Safe Browsing startup failure should escape"
        raise AssertionError(msg)

    store.start_background()
    store.start_background()

    assert store._started is True
    assert store._safe_browsing_store._started is True
    assert webfilter_starts == [True]
    assert safe_browsing_attempts == [True, True]


def test_webfilter_background_retries_failed_webfilter_thread_start(
    monkeypatch,
) -> None:
    store = webfilter_store.WebFilterStore()
    webfilter_attempts: list[bool] = []
    safe_browsing_starts: list[bool] = []

    class FakeThread:
        def __init__(self, *, target, name, daemon) -> None:
            assert target == store._loop
            assert name == "webfilter-updater"
            assert daemon is True

        def start(self) -> None:
            webfilter_attempts.append(True)
            if len(webfilter_attempts) == 1:
                msg = "simulated webfilter thread start failure"
                raise RuntimeError(msg)

    monkeypatch.setattr(webfilter_store.threading, "Thread", FakeThread)

    def start_safe_browsing(self, *_args) -> None:
        if self._started:
            return
        safe_browsing_starts.append(True)
        self._started = True

    monkeypatch.setattr(
        safe_browsing_v5.SafeBrowsingStore,
        "start_background",
        start_safe_browsing,
    )

    try:
        store.start_background()
    except RuntimeError as exc:
        assert str(exc) == "simulated webfilter thread start failure"
    else:  # pragma: no cover - regression guard
        msg = "webfilter thread startup failure should escape"
        raise AssertionError(msg)

    assert store._started is False
    assert safe_browsing_starts == []

    store.start_background()
    store.start_background()

    assert store._started is True
    assert webfilter_attempts == [True, True]
    assert safe_browsing_starts == [True]


def test_webfilter_background_stop_is_bounded_idempotent_and_restartable(
    monkeypatch,
) -> None:
    store = webfilter_store.WebFilterStore()
    iterations = 0
    iteration_seen = threading.Event()
    safe_browsing_stops: list[float] = []

    def run_until_stopped() -> None:
        nonlocal iterations
        iterations += 1
        iteration_seen.set()
        store._stop_event.wait(60.0)

    monkeypatch.setattr(store, "_loop", run_until_stopped)
    monkeypatch.setattr(
        store._safe_browsing_store,
        "start_background",
        lambda *_args: None,
    )
    monkeypatch.setattr(
        store._safe_browsing_store,
        "stop_background",
        lambda *, timeout: safe_browsing_stops.append(timeout) or True,
    )
    monkeypatch.setattr(webfilter_store.atexit, "register", lambda _func: None)

    store.start_background()
    assert iteration_seen.wait(1.0)
    assert store.stop_background(timeout=1.0) is True
    assert store.stop_background(timeout=1.0) is True

    iteration_seen.clear()
    store.start_background()
    assert iteration_seen.wait(1.0)
    assert store.stop_background(timeout=1.0) is True

    assert iterations == 2
    assert len(safe_browsing_stops) == 3
    assert store._started is False
    assert store._thread is None


def test_safe_browsing_background_stop_interrupts_poll_and_allows_restart(
    monkeypatch,
) -> None:
    store = safe_browsing_v5.SafeBrowsingStore()
    iterations = 0
    iteration_seen = threading.Event()

    def run_once(_get_settings, _set_status) -> None:
        nonlocal iterations
        iterations += 1
        iteration_seen.set()

    monkeypatch.setenv("SAFE_BROWSING_POLL_SECONDS", "3600")
    monkeypatch.setattr(store, "_run_updater_once", run_once)

    store.start_background(lambda: None, lambda *_args: None)
    assert iteration_seen.wait(1.0)
    assert store.stop_background(timeout=1.0) is True

    iteration_seen.clear()
    store.start_background(lambda: None, lambda *_args: None)
    assert iteration_seen.wait(1.0)
    assert store.stop_background(timeout=1.0) is True

    assert iterations == 2
    assert store._started is False
    assert store._thread is None


def test_safe_browsing_stop_cannot_pass_start_before_thread_is_owned(
    monkeypatch,
) -> None:
    store = safe_browsing_v5.SafeBrowsingStore()
    real_thread = threading.Thread
    start_entered = threading.Event()
    release_start = threading.Event()
    stop_finished = threading.Event()

    class BlockingStartThread:
        def __init__(self, **_kwargs) -> None:
            pass

        def start(self) -> None:
            start_entered.set()
            assert release_start.wait(1.0)

        def join(self, _timeout: float) -> None:
            pass

        def is_alive(self) -> bool:
            return False

    monkeypatch.setattr(safe_browsing_v5.threading, "Thread", BlockingStartThread)

    starter = real_thread(
        target=store.start_background, args=(lambda: None, lambda *_args: None)
    )
    starter.start()
    assert start_entered.wait(1.0)
    stopper = real_thread(
        target=lambda: (store.stop_background(timeout=1.0), stop_finished.set())
    )
    stopper.start()
    assert not stop_finished.wait(0.05)
    release_start.set()
    starter.join(1.0)
    stopper.join(1.0)

    assert stop_finished.is_set()
    assert store._started is False
    assert store._thread is None


def test_webfilter_stop_cannot_pass_start_before_thread_is_owned(monkeypatch) -> None:
    store = webfilter_store.WebFilterStore()
    real_thread = threading.Thread
    start_entered = threading.Event()
    release_start = threading.Event()
    stop_finished = threading.Event()

    class BlockingStartThread:
        def __init__(self, **_kwargs) -> None:
            pass

        def start(self) -> None:
            start_entered.set()
            assert release_start.wait(1.0)

        def join(self, _timeout: float) -> None:
            pass

        def is_alive(self) -> bool:
            return False

    monkeypatch.setattr(webfilter_store.threading, "Thread", BlockingStartThread)
    monkeypatch.setattr(
        store._safe_browsing_store, "start_background", lambda *_args: None
    )
    monkeypatch.setattr(
        store._safe_browsing_store, "stop_background", lambda *, timeout: True
    )
    monkeypatch.setattr(webfilter_store.atexit, "register", lambda _func: None)

    starter = real_thread(target=store.start_background)
    starter.start()
    assert start_entered.wait(1.0)
    stopper = real_thread(
        target=lambda: (store.stop_background(timeout=1.0), stop_finished.set())
    )
    stopper.start()
    assert not stop_finished.wait(0.05)
    release_start.set()
    starter.join(1.0)
    stopper.join(1.0)

    assert stop_finished.is_set()
    assert store._started is False
    assert store._thread is None


def test_safe_browsing_background_start_defers_database_init(monkeypatch) -> None:
    store = safe_browsing_v5.SafeBrowsingStore()
    started: list[bool] = []
    targets: list[object] = []

    def fail_if_called() -> None:  # pragma: no cover - should never run here
        msg = (
            "start_background should defer database initialization to the worker thread"
        )
        raise AssertionError(msg)

    class FakeThread:
        def __init__(self, *, target, args, name, daemon) -> None:
            targets.append((target, args))
            assert name == "safe-browsing-updater"
            assert daemon is True

        def start(self) -> None:
            started.append(True)

    monkeypatch.setattr(store, "init_db", fail_if_called)
    monkeypatch.setattr(safe_browsing_v5.threading, "Thread", FakeThread)

    store.start_background(lambda: None, lambda *_args: None)

    assert store._started is True
    assert started == [True]
    assert len(targets) == 1


def test_safe_browsing_local_checker_close_releases_cached_connection(
    monkeypatch,
) -> None:
    closed: list[bool] = []

    class FakeConn:
        def close(self) -> None:
            closed.append(True)

    monkeypatch.setattr(safe_browsing_v5, "connect", FakeConn)
    monkeypatch.setattr(
        safe_browsing_v5.SafeBrowsingStore,
        "init_schema",
        staticmethod(_noop_init_schema),
    )

    checker = safe_browsing_v5.SafeBrowsingLocalChecker(api_key="test")
    conn = checker._connect()

    conn.close()
    checker.close()

    assert closed == [True]
    assert checker._conn is None


def test_safe_browsing_local_checker_context_manager_closes(monkeypatch) -> None:
    closed: list[bool] = []

    class FakeConn:
        def close(self) -> None:
            closed.append(True)

    monkeypatch.setattr(safe_browsing_v5, "connect", FakeConn)
    monkeypatch.setattr(
        safe_browsing_v5.SafeBrowsingStore,
        "init_schema",
        staticmethod(_noop_init_schema),
    )

    with safe_browsing_v5.SafeBrowsingLocalChecker(api_key="test") as checker:
        conn = checker._connect()
        conn.close()

    assert closed == [True]
    assert checker._conn is None


def test_safe_browsing_local_checker_discards_cached_connection_on_db_error(
    monkeypatch,
) -> None:
    closed: list[bool] = []

    class FakeConn:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            self.close()
            return False

        def execute(self, *_args, **_kwargs):
            msg = "stale connection"
            raise RuntimeError(msg)

        def close(self) -> None:
            closed.append(True)

    monkeypatch.setattr(safe_browsing_v5, "connect", FakeConn)
    monkeypatch.setattr(
        safe_browsing_v5.SafeBrowsingStore,
        "init_schema",
        staticmethod(_noop_init_schema),
    )

    checker = safe_browsing_v5.SafeBrowsingLocalChecker(api_key="test")

    assert checker._local_lists_for_prefix(b"abcd") == ()
    assert closed == [True, True]
    assert checker._conn is None
