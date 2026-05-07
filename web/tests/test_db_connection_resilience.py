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


def test_returning_connection_to_pool_rolls_back_any_open_transaction(monkeypatch) -> None:
    _add_repo_paths()
    import services.db as db  # type: ignore

    db.reset_mysql_ready_for_tests()
    monkeypatch.setenv("DB_POOL_SIZE", "1")
    calls: list[str] = []

    class NativeConnection:
        def rollback(self):
            calls.append("rollback")

        def close(self):
            calls.append("close")

    cfg = db.DatabaseConfig(host="db", user="u", password="p", database="d")
    native = NativeConnection()

    db._return_connection(cfg, native)

    assert calls == ["rollback"]
    assert any(bucket and bucket[-1][1] is native for bucket in db._pooled_connections.values())
    db.reset_mysql_ready_for_tests()


def test_failed_pool_rollback_discards_connection(monkeypatch) -> None:
    _add_repo_paths()
    import services.db as db  # type: ignore

    db.reset_mysql_ready_for_tests()
    monkeypatch.setenv("DB_POOL_SIZE", "1")
    calls: list[str] = []

    class NativeConnection:
        def rollback(self):
            calls.append("rollback")
            raise RuntimeError("connection is broken")

        def close(self):
            calls.append("close")

    cfg = db.DatabaseConfig(host="db", user="u", password="p", database="d")

    db._return_connection(cfg, NativeConnection())

    assert calls == ["rollback", "close"]
    assert not db._pooled_connections


def test_new_native_connections_receive_session_guardrails(monkeypatch) -> None:
    _add_repo_paths()
    import services.db as db  # type: ignore

    db.reset_mysql_ready_for_tests()
    statements: list[tuple[str, tuple[object, ...]]] = []
    calls: list[str] = []

    class Cursor:
        def execute(self, sql, params=()):
            statements.append((str(sql), tuple(params or ())))

    class NativeConnection:
        def cursor(self):
            return Cursor()

        def rollback(self):
            calls.append("rollback")

        def close(self):
            calls.append("close")

    cfg = db.DatabaseConfig(host="db", user="u", password="p", database="d")
    monkeypatch.setenv("MYSQL_LOCK_WAIT_TIMEOUT", "7")
    monkeypatch.setenv("MYSQL_INNODB_LOCK_WAIT_TIMEOUT", "6")
    monkeypatch.setenv("MYSQL_SESSION_WAIT_TIMEOUT", "123")
    monkeypatch.setenv("MYSQL_TRANSACTION_ISOLATION", "READ COMMITTED")
    monkeypatch.setattr(db, "_open_native_connection", lambda _cfg: NativeConnection())

    native = db._checkout_connection(cfg)

    assert isinstance(native, NativeConnection)
    assert ("SET SESSION innodb_lock_wait_timeout=%s", (6,)) in statements
    assert ("SET SESSION lock_wait_timeout=%s", (7,)) in statements
    assert ("SET SESSION wait_timeout=%s", (123,)) in statements
    assert any(sql == "SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED" for sql, _params in statements)
    assert calls == ["rollback"]


def test_ssl_errors_store_getter_tolerates_transient_database_init_failure(monkeypatch) -> None:
    _add_repo_paths()
    import services.ssl_errors_store as ssl_errors_store  # type: ignore

    ssl_errors_store._store = None
    init_calls = {"count": 0}

    def fail_init(self):
        init_calls["count"] += 1
        raise AssertionError("store factory must not perform database I/O")

    monkeypatch.setattr(ssl_errors_store.SslErrorsStore, "init_db", fail_init)

    try:
        store = ssl_errors_store.get_ssl_errors_store()

        assert isinstance(store, ssl_errors_store.SslErrorsStore)
        assert store._db_initialized is False
        assert ssl_errors_store.get_ssl_errors_store() is store
        assert init_calls["count"] == 0
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


def test_ssl_errors_cleanup_uses_bounded_delete_chunks(monkeypatch, tmp_path) -> None:
    _add_repo_paths()
    import services.ssl_errors_store as ssl_errors_store  # type: ignore

    executed: list[tuple[str, tuple[object, ...]]] = []
    rowcounts = [2, 2, 1]
    store = ssl_errors_store.SslErrorsStore(cache_log_path=str(tmp_path / "cache.log"))
    monkeypatch.setenv("SSL_ERRORS_CLEANUP_CHUNK_SIZE", "2")
    monkeypatch.setenv("SSL_ERRORS_CLEANUP_MAX_ROWS", "10")

    class Result:
        def __init__(self, rowcount: int):
            self.rowcount = rowcount

    class Conn:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def execute(self, sql, params=()):
            executed.append((str(sql), tuple(params or ())))
            return Result(rowcounts.pop(0))

    monkeypatch.setattr(store, "_connect", lambda: Conn())

    deleted = store._delete_in_chunks("last_seen < %s", (123,), log_key="test.cleanup")

    assert deleted == 5
    assert len(executed) == 3
    assert all(" LIMIT %s" in sql for sql, _params in executed)
    assert [params[-1] for _sql, params in executed] == [2, 2, 2]


def test_ssl_errors_init_db_survives_cleanup_lock_timeout(monkeypatch, tmp_path) -> None:
    _add_repo_paths()
    import pymysql  # type: ignore
    import services.ssl_errors_store as ssl_errors_store  # type: ignore

    store = ssl_errors_store.SslErrorsStore(cache_log_path=str(tmp_path / "cache.log"))
    created_tables: list[str] = []

    class Conn:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def execute(self, sql, params=()):
            created_tables.append(str(sql))

    monkeypatch.setattr(store, "_connect", lambda: Conn())
    monkeypatch.setattr(
        store,
        "_cleanup_known_false_positives",
        lambda: (_ for _ in ()).throw(pymysql.err.OperationalError(1205, "Lock wait timeout exceeded")),
    )
    monkeypatch.setattr(
        store,
        "_delete_in_chunks",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(pymysql.err.OperationalError(1205, "Lock wait timeout exceeded")),
    )
    monkeypatch.setattr(ssl_errors_store, "should_log", lambda *_args, **_kwargs: False)

    store.init_db()

    assert store._db_initialized is True
    assert any("CREATE TABLE IF NOT EXISTS ssl_errors" in sql for sql in created_tables)
