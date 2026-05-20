from __future__ import annotations

import sys
from pathlib import Path
from typing import NoReturn

import pytest


def _add_repo_paths() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    web_root = repo_root / "web"
    for path in (repo_root, web_root):
        path_str = str(path)
        if path_str not in sys.path:
            sys.path.insert(0, path_str)


def test_context_manager_preserves_original_error_when_rollback_connection_is_lost() -> (
    None
):
    _add_repo_paths()
    import pymysql  # type: ignore
    from services.db import CompatConnection  # type: ignore

    closed: list[bool] = []

    class NativeConnection:
        def rollback(self) -> NoReturn:
            raise pymysql.err.InterfaceError(0, "")

        def close(self) -> None:
            closed.append(True)

    with pytest.raises(RuntimeError, match="body failed"):
        with CompatConnection(NativeConnection(), cfg=None):
            msg = "body failed"
            raise RuntimeError(msg)

    assert closed == [True]


def test_returning_connection_to_pool_rolls_back_any_open_transaction(
    monkeypatch,
) -> None:
    _add_repo_paths()
    from services import db  # type: ignore

    db.reset_mysql_ready_for_tests()
    monkeypatch.setenv("DB_POOL_SIZE", "1")
    calls: list[str] = []

    class NativeConnection:
        def rollback(self) -> None:
            calls.append("rollback")

        def close(self) -> None:
            calls.append("close")

    cfg = db.DatabaseConfig(host="db", user="u", password="p", database="d")
    native = NativeConnection()

    db._return_connection(cfg, native)

    assert calls == ["rollback"]
    assert any(
        state.idle and state.idle[-1][1] is native
        for state in db._pooled_connections.values()
    )
    db.reset_mysql_ready_for_tests()


def test_failed_pool_rollback_discards_connection(monkeypatch) -> None:
    _add_repo_paths()
    from services import db  # type: ignore

    db.reset_mysql_ready_for_tests()
    monkeypatch.setenv("DB_POOL_SIZE", "1")
    calls: list[str] = []

    class NativeConnection:
        def rollback(self) -> NoReturn:
            calls.append("rollback")
            msg = "connection is broken"
            raise RuntimeError(msg)

        def close(self) -> None:
            calls.append("close")

    cfg = db.DatabaseConfig(host="db", user="u", password="p", database="d")

    db._return_connection(cfg, NativeConnection())

    assert calls == ["rollback", "close"]
    assert not db._pooled_connections


def test_new_native_connections_receive_session_guardrails(monkeypatch) -> None:
    _add_repo_paths()
    from services import db  # type: ignore

    db.reset_mysql_ready_for_tests()
    statements: list[tuple[str, tuple[object, ...]]] = []
    calls: list[str] = []

    class Cursor:
        def execute(self, sql, params=()) -> None:
            statements.append((str(sql), tuple(params or ())))

    class NativeConnection:
        def cursor(self):
            return Cursor()

        def rollback(self) -> None:
            calls.append("rollback")

        def close(self) -> None:
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
    assert any(
        sql == "SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED"
        for sql, _params in statements
    )
    assert calls == ["rollback"]


def test_open_native_connection_retries_transient_mysql_errors(monkeypatch) -> None:
    _add_repo_paths()
    import pymysql  # type: ignore
    from services import db  # type: ignore

    db.reset_mysql_ready_for_tests()
    attempts = {"count": 0}

    class NativeConnection:
        def cursor(self):
            class Cursor:
                def execute(self, sql, params=()) -> None:
                    return None

            return Cursor()

        def rollback(self) -> None:
            return None

        def close(self) -> None:
            return None

        def ping(self, reconnect=False) -> None:
            return None

    def flaky_open(_cfg):
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise pymysql.err.OperationalError(1040, "Too many connections")
        return NativeConnection()

    monkeypatch.setenv("MYSQL_CONNECT_RETRIES", "2")
    monkeypatch.setenv("MYSQL_CONNECT_RETRY_DELAY_SECONDS", "0")
    monkeypatch.setattr(db, "_open_native_connection", flaky_open)

    native = db._retry_mysql_operation(
        lambda: db._open_native_connection(db.DatabaseConfig(host="db"))
    )

    assert attempts["count"] == 2
    assert native is not None


def test_ssl_errors_store_getter_tolerates_transient_database_init_failure(
    monkeypatch,
) -> None:
    _add_repo_paths()
    from services import ssl_errors_store  # type: ignore

    ssl_errors_store._store = None
    init_calls = {"count": 0}

    def fail_init(self) -> NoReturn:
        init_calls["count"] += 1
        msg = "store factory must not perform database I/O"
        raise AssertionError(msg)

    monkeypatch.setattr(ssl_errors_store.SslErrorsStore, "init_db", fail_init)

    try:
        store = ssl_errors_store.get_ssl_errors_store()

        assert isinstance(store, ssl_errors_store.SslErrorsStore)
        assert store._db_initialized is False
        assert ssl_errors_store.get_ssl_errors_store() is store
        assert init_calls["count"] == 0
    finally:
        ssl_errors_store._store = None


def test_ssl_errors_background_start_does_not_block_on_database_init(
    monkeypatch, tmp_path
) -> None:
    _add_repo_paths()
    from services import ssl_errors_store  # type: ignore

    started: list[bool] = []
    targets: list[object] = []
    store = ssl_errors_store.SslErrorsStore(cache_log_path=str(tmp_path / "cache.log"))

    def fail_if_called() -> (
        NoReturn
    ):  # pragma: no cover - should never run in this test
        msg = (
            "start_background should defer database initialization to the tailer thread"
        )
        raise AssertionError(msg)

    class FakeThread:
        def __init__(self, *, target, name, daemon) -> None:
            targets.append(target)
            assert name == "ssl-errors-tailer"
            assert daemon is True

        def start(self) -> None:
            started.append(True)

    monkeypatch.setattr(store, "init_db", fail_if_called)
    monkeypatch.setattr(ssl_errors_store.threading, "Thread", FakeThread)

    store.start_background()

    assert store._started is True
    assert started == [True]
    assert len(targets) == 1


def test_ssl_errors_tail_loop_retries_after_database_init_timeout(
    monkeypatch, tmp_path
) -> None:
    _add_repo_paths()
    import pymysql  # type: ignore
    from services import ssl_errors_store  # type: ignore

    class StopLoop(BaseException):
        pass

    calls = {"init_db": 0}
    store = ssl_errors_store.SslErrorsStore(
        cache_log_path=str(tmp_path / "missing-cache.log")
    )

    def flaky_init_db() -> None:
        calls["init_db"] += 1
        if calls["init_db"] == 1:
            raise pymysql.err.OperationalError(
                2013, "Lost connection to MySQL server during query (timed out)"
            )
        store._db_initialized = True

    def fake_sleep(_seconds: float) -> None:
        if calls["init_db"] >= 2:
            raise StopLoop

    monkeypatch.setattr(store, "init_db", flaky_init_db)
    monkeypatch.setattr(ssl_errors_store.os.path, "exists", lambda _path: False)
    monkeypatch.setattr(ssl_errors_store.time, "sleep", fake_sleep)

    with pytest.raises(StopLoop):
        store._tail_loop()

    assert calls["init_db"] >= 2


def test_ssl_errors_cleanup_uses_bounded_delete_chunks(monkeypatch, tmp_path) -> None:
    _add_repo_paths()
    from services import ssl_errors_store  # type: ignore

    executed: list[tuple[str, tuple[object, ...]]] = []
    rowcounts = [2, 2, 1]
    store = ssl_errors_store.SslErrorsStore(cache_log_path=str(tmp_path / "cache.log"))
    monkeypatch.setenv("SSL_ERRORS_CLEANUP_CHUNK_SIZE", "2")
    monkeypatch.setenv("SSL_ERRORS_CLEANUP_MAX_ROWS", "10")

    class Result:
        def __init__(self, rowcount: int) -> None:
            self.rowcount = rowcount

    class Conn:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def execute(self, sql, params=()):
            executed.append((str(sql), tuple(params or ())))
            return Result(rowcounts.pop(0))

    monkeypatch.setattr(store, "_connect", Conn)

    deleted = store._delete_in_chunks("last_seen < %s", (123,), log_key="test.cleanup")

    assert deleted == 5
    assert len(executed) == 3
    assert all(" LIMIT %s" in sql for sql, _params in executed)
    assert [params[-1] for _sql, params in executed] == [2, 2, 2]


def test_ssl_errors_init_db_survives_cleanup_lock_timeout(
    monkeypatch, tmp_path
) -> None:
    _add_repo_paths()
    import pymysql  # type: ignore
    from services import ssl_errors_store  # type: ignore

    store = ssl_errors_store.SslErrorsStore(cache_log_path=str(tmp_path / "cache.log"))
    created_tables: list[str] = []

    class Conn:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def execute(self, sql, params=()) -> None:
            created_tables.append(str(sql))

    monkeypatch.setattr(store, "_connect", Conn)
    monkeypatch.setattr(
        store,
        "_cleanup_known_false_positives",
        lambda: (_ for _ in ()).throw(
            pymysql.err.OperationalError(1205, "Lock wait timeout exceeded")
        ),
    )
    monkeypatch.setattr(
        store,
        "_delete_in_chunks",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            pymysql.err.OperationalError(1205, "Lock wait timeout exceeded")
        ),
    )
    monkeypatch.setattr(ssl_errors_store, "should_log", lambda *_args, **_kwargs: False)

    store.init_db()

    assert store._db_initialized is True
    assert any("CREATE TABLE IF NOT EXISTS ssl_errors" in sql for sql in created_tables)


def test_blank_db_pool_size_derives_from_web_threads(monkeypatch) -> None:
    _add_repo_paths()
    from services import db  # type: ignore

    monkeypatch.delenv("DB_POOL_SIZE", raising=False)
    monkeypatch.setenv("WEB_THREADS", "2")

    assert db._pool_maxsize() == 4


def test_explicit_db_pool_size_still_allows_single_connection(monkeypatch) -> None:
    _add_repo_paths()
    from services import db  # type: ignore

    monkeypatch.setenv("DB_POOL_SIZE", "1")
    monkeypatch.setenv("WEB_THREADS", "8")

    assert db._pool_maxsize() == 1


def test_mysql_advisory_lock_acquires_and_releases() -> None:
    _add_repo_paths()
    from services import db  # type: ignore

    statements: list[tuple[str, tuple[object, ...]]] = []

    class Result:
        def __init__(self, acquired: int | None = None) -> None:
            self.acquired = acquired

        def fetchone(self):
            if self.acquired is None:
                return None
            return {"acquired": self.acquired}

    class Conn:
        def execute(self, sql, params=()):
            statements.append((str(sql), tuple(params or ())))
            if "GET_LOCK" in str(sql):
                return Result(1)
            return Result()

    with db.mysql_advisory_lock(Conn(), "docker_proxy:test", 7):
        statements.append(("body", ()))

    assert statements[0] == (
        "SELECT GET_LOCK(%s, %s) AS acquired",
        ("docker_proxy:test", 7),
    )
    assert statements[-1] == ("DO RELEASE_LOCK(%s)", ("docker_proxy:test",))


def test_mysql_advisory_lock_times_out() -> None:
    _add_repo_paths()
    import pytest
    from services import db  # type: ignore

    class Result:
        def fetchone(self):
            return {"acquired": 0}

    class Conn:
        def execute(self, _sql, _params=()):
            return Result()

    with pytest.raises(TimeoutError):
        with db.mysql_advisory_lock(Conn(), "docker_proxy:test", 1):
            pass
