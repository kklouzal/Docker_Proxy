from __future__ import annotations

import sys
from pathlib import Path


def _add_repo_paths() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    web_root = repo_root / "web"
    for path in (repo_root, web_root):
        path_str = str(path)
        if path_str not in sys.path:
            sys.path.insert(0, path_str)


def _noop_init_schema(_conn) -> None:
    return None


def test_adblock_artifact_background_start_defers_database_init(monkeypatch) -> None:
    _add_repo_paths()
    from services import adblock_artifacts  # type: ignore

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
    _add_repo_paths()
    from services import safe_browsing_v5, webfilter_store  # type: ignore

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


def test_safe_browsing_background_start_defers_database_init(monkeypatch) -> None:
    _add_repo_paths()
    from services import safe_browsing_v5  # type: ignore

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
    _add_repo_paths()
    from services import safe_browsing_v5  # type: ignore

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
    _add_repo_paths()
    from services import safe_browsing_v5  # type: ignore

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
    _add_repo_paths()
    from services import safe_browsing_v5  # type: ignore

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
