from __future__ import annotations

import sys
from pathlib import Path

import pytest


def _add_repo_paths() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    web_root = repo_root / "web"
    for path in (repo_root, web_root):
        path_str = str(path)
        if path_str not in sys.path:
            sys.path.insert(0, path_str)


def test_context_manager_preserves_original_error_when_rollback_connection_is_lost() -> None:
    _add_repo_paths()
    import pymysql  # type: ignore
    from services.db import CompatConnection  # type: ignore

    closed: list[bool] = []

    class NativeConnection:
        def rollback(self):
            raise pymysql.err.InterfaceError(0, "")

        def close(self):
            closed.append(True)

    with pytest.raises(RuntimeError, match="body failed"):
        with CompatConnection(NativeConnection(), cfg=None):
            raise RuntimeError("body failed")

    assert closed == [True]


def test_ssl_errors_store_getter_tolerates_transient_database_init_failure(monkeypatch) -> None:
    _add_repo_paths()
    import pymysql  # type: ignore
    import services.ssl_errors_store as ssl_errors_store  # type: ignore

    ssl_errors_store._store = None

    def fail_init(self):
        raise pymysql.err.OperationalError(2013, "Lost connection to MySQL server during query (timed out)")

    monkeypatch.setattr(ssl_errors_store.SslErrorsStore, "init_db", fail_init)

    try:
        store = ssl_errors_store.get_ssl_errors_store()

        assert isinstance(store, ssl_errors_store.SslErrorsStore)
        assert store._db_initialized is False
        assert ssl_errors_store.get_ssl_errors_store() is store
    finally:
        ssl_errors_store._store = None


def test_ssl_errors_background_start_does_not_block_on_database_init(monkeypatch, tmp_path) -> None:
    _add_repo_paths()
    import services.ssl_errors_store as ssl_errors_store  # type: ignore

    started: list[bool] = []
    targets: list[object] = []
    store = ssl_errors_store.SslErrorsStore(cache_log_path=str(tmp_path / "cache.log"))

    def fail_if_called():  # pragma: no cover - should never run in this test
        raise AssertionError("start_background should defer database initialization to the tailer thread")

    class FakeThread:
        def __init__(self, *, target, name, daemon):
            targets.append(target)
            assert name == "ssl-errors-tailer"
            assert daemon is True

        def start(self):
            started.append(True)

    monkeypatch.setattr(store, "init_db", fail_if_called)
    monkeypatch.setattr(ssl_errors_store.threading, "Thread", FakeThread)

    store.start_background()

    assert store._started is True
    assert started == [True]
    assert len(targets) == 1


def test_ssl_errors_tail_loop_retries_after_database_init_timeout(monkeypatch, tmp_path) -> None:
    _add_repo_paths()
    import pymysql  # type: ignore
    import services.ssl_errors_store as ssl_errors_store  # type: ignore

    class StopLoop(BaseException):
        pass

    calls = {"init_db": 0}
    store = ssl_errors_store.SslErrorsStore(cache_log_path=str(tmp_path / "missing-cache.log"))

    def flaky_init_db():
        calls["init_db"] += 1
        if calls["init_db"] == 1:
            raise pymysql.err.OperationalError(2013, "Lost connection to MySQL server during query (timed out)")
        store._db_initialized = True

    def fake_sleep(_seconds: float) -> None:
        if calls["init_db"] >= 2:
            raise StopLoop()

    monkeypatch.setattr(store, "init_db", flaky_init_db)
    monkeypatch.setattr(ssl_errors_store.os.path, "exists", lambda _path: False)
    monkeypatch.setattr(ssl_errors_store.time, "sleep", fake_sleep)

    with pytest.raises(StopLoop):
        store._tail_loop()

    assert calls["init_db"] >= 2
