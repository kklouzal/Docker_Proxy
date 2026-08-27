from __future__ import annotations

from typing import NoReturn

import pytest


def test_parse_database_url_resolves_valid_mysql_url(monkeypatch) -> None:
    from services import db  # type: ignore

    monkeypatch.setenv("MYSQL_CHARSET", "utf8")
    cfg = db._parse_database_url("mysql+pymysql://user:pass@db.example:3307/proxy")

    assert cfg == db.DatabaseConfig(
        host="db.example",
        port=3307,
        user="user",
        password="pass",
        database="proxy",
        charset="utf8",
    )


@pytest.mark.parametrize(
    "database_url",
    [
        "mysql://[bad/db",
        "mysql://db.example:not-a-port/proxy",
    ],
)
def test_parse_database_url_reports_malformed_url_as_mysql_config_error(
    database_url,
) -> None:
    from services import db  # type: ignore

    with pytest.raises(
        ValueError,
        match="Invalid DATABASE_URL for MySQL configuration",
    ) as exc_info:
        db._parse_database_url(database_url)

    assert "Invalid IPv6 URL" not in str(exc_info.value)
    assert "Port could not be cast" not in str(exc_info.value)


@pytest.mark.parametrize(
    ("env", "expected_message"),
    [
        ({"MYSQL_HOST": "db", "MYSQL_PORT": "not-a-port"}, "Invalid MYSQL_PORT"),
        (
            {"MYSQL_HOST": "db", "MYSQL_PORT": "0"},
            "MYSQL_PORT for MySQL configuration: 0 < 1",
        ),
        (
            {"MYSQL_HOST": "db", "MYSQL_CONNECT_TIMEOUT": "soon"},
            "Invalid MYSQL_CONNECT_TIMEOUT",
        ),
        (
            {"MYSQL_HOST": "db", "MYSQL_READ_TIMEOUT": "0"},
            "MYSQL_READ_TIMEOUT for MySQL configuration: 0 < 1",
        ),
        (
            {"MYSQL_HOST": "db", "MYSQL_WRITE_TIMEOUT": "later"},
            "Invalid MYSQL_WRITE_TIMEOUT",
        ),
    ],
)
def test_resolve_database_config_reports_invalid_numeric_mysql_env(
    monkeypatch,
    env,
    expected_message,
) -> None:
    from services import db  # type: ignore

    monkeypatch.delenv("DATABASE_URL", raising=False)
    for name in (
        "MYSQL_HOST",
        "MYSQL_DATABASE",
        "MYSQL_USER",
        "MYSQL_PORT",
        "MYSQL_CONNECT_TIMEOUT",
        "MYSQL_READ_TIMEOUT",
        "MYSQL_WRITE_TIMEOUT",
    ):
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)

    with pytest.raises(ValueError, match=expected_message):
        db.resolve_database_config()


@pytest.mark.parametrize(
    ("env_name", "env_value", "expected_message"),
    [
        ("MYSQL_PORT", "bad", "Invalid MYSQL_PORT"),
        ("MYSQL_CONNECT_TIMEOUT", "bad", "Invalid MYSQL_CONNECT_TIMEOUT"),
        ("MYSQL_READ_TIMEOUT", "bad", "Invalid MYSQL_READ_TIMEOUT"),
        ("MYSQL_WRITE_TIMEOUT", "bad", "Invalid MYSQL_WRITE_TIMEOUT"),
    ],
)
def test_parse_database_url_reports_invalid_numeric_mysql_fallback_env(
    monkeypatch,
    env_name: str,
    env_value: str,
    expected_message: str,
) -> None:
    from services import db  # type: ignore

    for name in (
        "MYSQL_PORT",
        "MYSQL_CONNECT_TIMEOUT",
        "MYSQL_READ_TIMEOUT",
        "MYSQL_WRITE_TIMEOUT",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(env_name, env_value)

    with pytest.raises(ValueError, match=expected_message):
        db._parse_database_url("mysql://user:pass@db.example/proxy")


def test_parse_database_url_explicit_port_does_not_read_mysql_port_fallback(
    monkeypatch,
) -> None:
    from services import db  # type: ignore

    monkeypatch.setenv("MYSQL_PORT", "bad")

    cfg = db._parse_database_url("mysql://user:pass@db.example:3307/proxy")

    assert cfg.port == 3307


@pytest.mark.parametrize(
    ("exc", "expected"),
    [
        (Exception(1060, "Duplicate column"), 1060),
        (Exception("1062", "Duplicate key"), 1062),
        (Exception("not-a-code"), None),
        (Exception(), None),
    ],
)
def test_mysql_error_code_extracts_first_numeric_arg(exc, expected) -> None:
    from services import db  # type: ignore

    assert db.mysql_error_code(exc) == expected


def test_context_manager_preserves_original_error_when_rollback_connection_is_lost() -> (
    None
):
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


@pytest.mark.parametrize("method_name", ["execute", "executemany"])
def test_failed_cursor_connection_error_discards_pooled_connection(
    monkeypatch,
    method_name: str,
) -> None:
    import pymysql  # type: ignore
    from services import db  # type: ignore

    db.reset_mysql_ready_for_tests()
    monkeypatch.setenv("DB_POOL_SIZE", "1")
    calls: list[str] = []

    class Cursor:
        def execute(self, *_args, **_kwargs) -> NoReturn:
            calls.append("execute")
            raise pymysql.err.InterfaceError(0, "")

        def executemany(self, *_args, **_kwargs) -> NoReturn:
            calls.append("executemany")
            raise pymysql.err.InterfaceError(0, "")

        def close(self) -> None:
            calls.append("cursor.close")

    class NativeConnection:
        def cursor(self):
            return Cursor()

        def rollback(self) -> None:
            calls.append("rollback")

        def close(self) -> None:
            calls.append("native.close")

    cfg = db.DatabaseConfig(host="db", user="u", password="p", database="d")
    key = db._pool_key(cfg)
    with db._pool_condition:
        db._pooled_connections[key] = db._PoolState(idle=[], active=1)

    conn = db.CompatConnection(NativeConnection(), cfg=cfg)
    with pytest.raises(pymysql.err.InterfaceError):
        if method_name == "execute":
            conn.execute("SELECT 1")
        else:
            conn.executemany("INSERT INTO t VALUES (%s)", [(1,)])
    conn.close()

    assert calls == [method_name, "cursor.close", "native.close"]
    assert key not in db._pooled_connections
    db.reset_mysql_ready_for_tests()


@pytest.mark.parametrize("method_name", ["execute", "executemany"])
def test_cursor_acquisition_connection_error_discards_pooled_connection(
    monkeypatch,
    method_name: str,
) -> None:
    import pymysql  # type: ignore
    from services import db  # type: ignore

    db.reset_mysql_ready_for_tests()
    monkeypatch.setenv("DB_POOL_SIZE", "1")
    calls: list[str] = []

    class NativeConnection:
        def cursor(self) -> NoReturn:
            calls.append("cursor")
            raise pymysql.err.InterfaceError(0, "")

        def rollback(self) -> None:
            calls.append("rollback")

        def close(self) -> None:
            calls.append("native.close")

    cfg = db.DatabaseConfig(host="db", user="u", password="p", database="d")
    key = db._pool_key(cfg)
    with db._pool_condition:
        db._pooled_connections[key] = db._PoolState(idle=[], active=1)

    conn = db.CompatConnection(NativeConnection(), cfg=cfg)
    with pytest.raises(pymysql.err.InterfaceError):
        if method_name == "execute":
            conn.execute("SELECT 1")
        else:
            conn.executemany("INSERT INTO t VALUES (%s)", [(1,)])
    conn.close()

    assert calls == ["cursor", "native.close"]
    assert key not in db._pooled_connections
    db.reset_mysql_ready_for_tests()


def test_compat_result_closes_cursor_after_fetchall_and_preserves_rows() -> None:
    from services.db import CompatConnection  # type: ignore

    class Cursor:
        description = (("id",), ("name",))
        rowcount = 2
        lastrowid = None
        closed = False

        def execute(self, *_args) -> None:
            pass

        def fetchall(self):
            return [(1, "one"), (2, "two")]

        def close(self) -> None:
            self.closed = True

    cursor = Cursor()
    native = type("Native", (), {"cursor": lambda self: cursor})()
    result = CompatConnection(native).execute("SELECT id, name FROM t")

    rows = result.fetchall()

    assert cursor.closed is True
    assert rows[0][0] == 1
    assert rows[0]["name"] == "one"
    assert result.rowcount == 2


def test_compat_result_fetchone_defers_close_until_exhausted() -> None:
    from services.db import CompatConnection  # type: ignore

    class Cursor:
        description = (("id",),)
        rowcount = 2
        lastrowid = None
        rownumber = 0
        closed = False

        def execute(self, *_args) -> None:
            pass

        def fetchone(self):
            rows = [(1,), (2,)]
            row = rows[self.rownumber]
            self.rownumber += 1
            return row

        def close(self) -> None:
            self.closed = True

    cursor = Cursor()
    native = type("Native", (), {"cursor": lambda self: cursor})()
    result = CompatConnection(native).execute("SELECT id FROM t")

    assert result.fetchone()[0] == 1
    assert cursor.closed is False
    assert result.fetchone()[0] == 2
    assert cursor.closed is True


def test_compat_result_iterates_rows_without_materializing_and_closes_cursor() -> None:
    from services.db import CompatConnection  # type: ignore

    class Cursor:
        description = (("id",),)
        rowcount = 2
        lastrowid = None
        rownumber = 0
        closed = False
        fetchall_called = False

        def execute(self, *_args) -> None:
            pass

        def fetchone(self):
            rows = [(1,), (2,)]
            row = rows[self.rownumber]
            self.rownumber += 1
            return row

        def fetchall(self):
            self.fetchall_called = True
            pytest.fail("streaming iteration must not materialize the result set")

        def close(self) -> None:
            self.closed = True

    cursor = Cursor()
    native = type("Native", (), {"cursor": lambda self: cursor})()
    result = CompatConnection(native).execute("SELECT id FROM t")

    rows = list(result)

    assert [row["id"] for row in rows] == [1, 2]
    assert cursor.fetchall_called is False
    assert cursor.closed is True


def test_compat_connection_closes_partial_result_and_write_cursor() -> None:
    from services.db import CompatConnection  # type: ignore

    class Cursor:
        def __init__(self, *, description, rowcount) -> None:
            self.description = description
            self.rowcount = rowcount
            self.lastrowid = 17
            self.closed = False

        def execute(self, *_args) -> None:
            pass

        def fetchone(self):
            return (1,)

        def close(self) -> None:
            self.closed = True

    read_cursor = Cursor(description=(("id",),), rowcount=2)
    write_cursor = Cursor(description=None, rowcount=1)
    cursors = iter((read_cursor, write_cursor))
    native = type(
        "Native",
        (),
        {"cursor": lambda self: next(cursors), "close": lambda self: None},
    )()
    conn = CompatConnection(native)

    result = conn.execute("SELECT id FROM t")
    assert result.fetchone()[0] == 1
    assert read_cursor.closed is False
    write_result = conn.execute("UPDATE t SET id = 2")
    assert write_cursor.closed is True
    assert write_result.rowcount == 1
    assert write_result.lastrowid == 17

    conn.close()

    assert read_cursor.closed is True


def test_partial_result_cursor_close_failure_discards_pooled_connection(
    monkeypatch,
) -> None:
    from services import db  # type: ignore

    db.reset_mysql_ready_for_tests()
    monkeypatch.setenv("DB_POOL_SIZE", "1")
    calls: list[str] = []

    class Cursor:
        description = (("id",),)
        rowcount = 2
        lastrowid = None
        rownumber = 0

        def execute(self, *_args) -> None:
            calls.append("execute")

        def fetchone(self):
            self.rownumber += 1
            return (1,)

        def close(self) -> NoReturn:
            calls.append("cursor.close")
            message = "unread result could not be drained"
            raise RuntimeError(message)

    class NativeConnection:
        def cursor(self):
            return Cursor()

        def rollback(self) -> None:
            calls.append("rollback")

        def close(self) -> None:
            calls.append("native.close")

    cfg = db.DatabaseConfig(host="db", user="u", password="***", database="d")
    key = db._pool_key(cfg)
    with db._pool_condition:
        db._pooled_connections[key] = db._PoolState(idle=[], active=1)

    conn = db.CompatConnection(NativeConnection(), cfg=cfg)
    result = conn.execute("SELECT id FROM t")
    assert result.fetchone()[0] == 1
    conn.close()

    assert calls == ["execute", "cursor.close", "native.close"]
    assert key not in db._pooled_connections
    db.reset_mysql_ready_for_tests()


@pytest.mark.parametrize("fetch_method", ["fetchone", "fetchall"])
def test_fetch_connection_error_discards_pooled_connection(
    monkeypatch,
    fetch_method: str,
) -> None:
    import pymysql  # type: ignore
    from services import db  # type: ignore

    db.reset_mysql_ready_for_tests()
    monkeypatch.setenv("DB_POOL_SIZE", "1")
    calls: list[str] = []

    class Cursor:
        description = (("id",),)
        rowcount = 1
        lastrowid = None

        def execute(self, *_args) -> None:
            calls.append("execute")

        def fetchone(self) -> NoReturn:
            calls.append("fetchone")
            raise pymysql.err.OperationalError(2013, "Lost connection during query")

        def fetchall(self) -> NoReturn:
            calls.append("fetchall")
            raise pymysql.err.OperationalError(2013, "Lost connection during query")

        def close(self) -> None:
            calls.append("cursor.close")

    class NativeConnection:
        def cursor(self):
            return Cursor()

        def rollback(self) -> None:
            calls.append("rollback")

        def close(self) -> None:
            calls.append("native.close")

    cfg = db.DatabaseConfig(host="db", user="u", password="***", database="d")
    key = db._pool_key(cfg)
    with db._pool_condition:
        db._pooled_connections[key] = db._PoolState(idle=[], active=1)

    conn = db.CompatConnection(NativeConnection(), cfg=cfg)
    result = conn.execute("SELECT id FROM t")
    with pytest.raises(pymysql.err.OperationalError, match="Lost connection"):
        getattr(result, fetch_method)()
    conn.close()

    assert calls == ["execute", fetch_method, "cursor.close", "native.close"]
    assert key not in db._pooled_connections
    db.reset_mysql_ready_for_tests()


def test_compat_result_closes_cursor_when_fetch_raises() -> None:
    from services.db import CompatConnection  # type: ignore

    class Cursor:
        description = (("id",),)
        rowcount = 1
        lastrowid = None
        closed = False

        def execute(self, *_args) -> None:
            pass

        def fetchall(self):
            message = "fetch failed"
            raise RuntimeError(message)

        def close(self) -> None:
            self.closed = True

    cursor = Cursor()
    native = type("Native", (), {"cursor": lambda self: cursor})()
    result = CompatConnection(native).execute("SELECT id FROM t")

    with pytest.raises(RuntimeError, match="fetch failed"):
        result.fetchall()

    assert cursor.closed is True


def test_interface_error_zero_is_retryable_mysql_error() -> None:
    import pymysql  # type: ignore
    from services import db  # type: ignore

    assert db._is_retryable_mysql_error(pymysql.err.InterfaceError(0, "")) is True


def test_returning_connection_to_pool_rolls_back_any_open_transaction(
    monkeypatch,
) -> None:
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


def test_discarded_compat_connection_releases_pool_slot(monkeypatch) -> None:
    from services import db  # type: ignore

    db.reset_mysql_ready_for_tests()
    monkeypatch.setenv("DB_POOL_SIZE", "1")
    calls: list[str] = []

    class NativeConnection:
        def commit(self) -> NoReturn:
            calls.append("commit")
            msg = "commit failed"
            raise RuntimeError(msg)

        def rollback(self) -> None:
            calls.append("rollback")

        def close(self) -> None:
            calls.append("close")

    cfg = db.DatabaseConfig(host="db", user="u", password="p", database="d")
    key = db._pool_key(cfg)
    with db._pool_condition:
        db._pooled_connections[key] = db._PoolState(idle=[], active=1)

    with pytest.raises(RuntimeError, match="commit failed"):
        with db.CompatConnection(NativeConnection(), cfg=cfg):
            pass

    assert calls == ["commit", "close"]
    assert key not in db._pooled_connections
    db.reset_mysql_ready_for_tests()


def test_failed_context_rollback_releases_pool_slot(monkeypatch) -> None:
    from services import db  # type: ignore

    db.reset_mysql_ready_for_tests()
    monkeypatch.setenv("DB_POOL_SIZE", "1")
    calls: list[str] = []

    class NativeConnection:
        def rollback(self) -> NoReturn:
            calls.append("rollback")
            msg = "rollback failed"
            raise RuntimeError(msg)

        def close(self) -> None:
            calls.append("close")

    cfg = db.DatabaseConfig(host="db", user="u", password="p", database="d")
    key = db._pool_key(cfg)
    with db._pool_condition:
        db._pooled_connections[key] = db._PoolState(idle=[], active=1)

    with pytest.raises(RuntimeError, match="body failed"):
        with db.CompatConnection(NativeConnection(), cfg=cfg):
            msg = "body failed"
            raise RuntimeError(msg)

    assert calls == ["rollback", "close"]
    assert key not in db._pooled_connections
    db.reset_mysql_ready_for_tests()


def test_pool_reaper_preserves_active_only_bucket(monkeypatch) -> None:
    from services import db  # type: ignore

    db.reset_mysql_ready_for_tests()
    monkeypatch.setenv("DB_POOL_SIZE", "1")
    cfg = db.DatabaseConfig(host="db", user="u", password="p", database="d")
    key = db._pool_key(cfg)

    with db._pool_condition:
        db._pooled_connections[key] = db._PoolState(idle=[], active=1)
        db._reap_pool_locked(now=123.0)

    assert key in db._pooled_connections
    assert db._pooled_connections[key].active == 1
    db.reset_mysql_ready_for_tests()


def test_new_native_connections_receive_session_guardrails(monkeypatch) -> None:
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


def test_pool_disabled_checkout_closes_connection_when_configuration_fails(
    monkeypatch,
) -> None:
    from services import db  # type: ignore

    db.reset_mysql_ready_for_tests()
    monkeypatch.setenv("DB_POOL_SIZE", "0")
    calls: list[str] = []

    class NativeConnection:
        def close(self) -> None:
            calls.append("native.close")

    native = NativeConnection()
    cfg = db.DatabaseConfig(host="db", user="u", password="***", database="d")
    monkeypatch.setattr(db, "_open_native_connection", lambda _cfg: native)

    def fail_configuration(_native, _cfg) -> NoReturn:
        calls.append("configure")
        message = "configuration failed"
        raise RuntimeError(message)

    monkeypatch.setattr(db, "_configure_native_connection", fail_configuration)

    with pytest.raises(RuntimeError, match="configuration failed"):
        db._checkout_connection(cfg)

    assert calls == ["configure", "native.close"]
    assert not db._pooled_connections


def test_checkout_discards_new_connection_when_session_reset_fails(monkeypatch) -> None:
    from services import db  # type: ignore

    db.reset_mysql_ready_for_tests()
    monkeypatch.setenv("DB_POOL_SIZE", "1")
    calls: list[str] = []

    class Cursor:
        def execute(self, *_args) -> None:
            pass

        def close(self) -> None:
            calls.append("cursor.close")

    class NativeConnection:
        def cursor(self):
            return Cursor()

        def rollback(self) -> NoReturn:
            calls.append("rollback")
            message = "session reset failed"
            raise RuntimeError(message)

        def close(self) -> None:
            calls.append("native.close")

    cfg = db.DatabaseConfig(host="db", user="u", password="***", database="d")
    monkeypatch.setattr(db, "_open_native_connection", lambda _cfg: NativeConnection())

    with pytest.raises(RuntimeError, match="session reset failed"):
        db._checkout_connection(cfg)

    assert calls == ["cursor.close", "rollback", "native.close"]
    assert not db._pooled_connections


def test_failed_advisory_lock_release_discards_pooled_connection(monkeypatch) -> None:
    from services import db  # type: ignore

    db.reset_mysql_ready_for_tests()
    monkeypatch.setenv("DB_POOL_SIZE", "1")
    calls: list[str] = []

    class Result:
        def fetchone(self):
            return {"acquired": 1}

    class NativeConnection:
        def commit(self) -> None:
            calls.append("commit")

        def rollback(self) -> None:
            calls.append("rollback")

        def close(self) -> None:
            calls.append("close")

    cfg = db.DatabaseConfig(host="db", user="u", password="***", database="d")
    key = db._pool_key(cfg)
    with db._pool_condition:
        db._pooled_connections[key] = db._PoolState(idle=[], active=1)
    conn = db.CompatConnection(NativeConnection(), cfg=cfg)

    def execute(sql, _params):
        if "GET_LOCK" in sql:
            return Result()
        calls.append("release")
        message = "release uncertain"
        raise RuntimeError(message)

    monkeypatch.setattr(conn, "execute", execute)
    with conn:
        with db.mysql_advisory_lock(conn, "schema"):
            pass

    assert calls == ["release", "commit", "close"]
    assert key not in db._pooled_connections


def test_failed_advisory_lock_release_does_not_mask_body_exception() -> None:
    from services import db  # type: ignore

    class Result:
        def fetchone(self):
            return {"acquired": 1}

    class Conn:
        _discard_on_close = False

        def execute(self, sql, _params):
            if "GET_LOCK" in sql:
                return Result()
            message = "release uncertain"
            raise RuntimeError(message)

    conn = Conn()
    with pytest.raises(ValueError, match="body failed"):
        with db.mysql_advisory_lock(conn, "schema"):
            message = "body failed"
            raise ValueError(message)

    assert conn._discard_on_close is True


def test_open_native_connection_retries_transient_mysql_errors(monkeypatch) -> None:
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


def test_ssl_errors_ingest_retries_after_database_init_timeout(
    monkeypatch, tmp_path
) -> None:
    import pymysql  # type: ignore
    from services import ssl_errors_store  # type: ignore

    calls = {"init_db": 0}
    line = "2026/05/20 12:00:00 kid1| error detail: SQUID_TLS_ERR_ACCEPT+TLS_LIB_ERR=A000119+TLS_IO_ERR=1"
    store = ssl_errors_store.SslErrorsStore(cache_log_path=str(tmp_path / "cache.log"))

    def flaky_init_db() -> None:
        calls["init_db"] += 1
        if calls["init_db"] == 1:
            raise pymysql.err.OperationalError(
                2013, "Lost connection to MySQL server during query (timed out)"
            )
        store._db_initialized = True

    class Result:
        rowcount = 1

        def fetchone(self):
            return None

    class Conn:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def execute(self, *_args, **_kwargs):
            return Result()

    monkeypatch.setattr(store, "init_db", flaky_init_db)
    monkeypatch.setattr(store, "_connect", Conn)

    store.ingest_line(line)
    store.ingest_line(line)

    assert calls["init_db"] == 2


def test_ssl_errors_tailer_uses_unpooled_connections(monkeypatch, tmp_path) -> None:
    from services import ssl_errors_store  # type: ignore

    calls: list[str] = []
    store = ssl_errors_store.SslErrorsStore(cache_log_path=str(tmp_path / "cache.log"))

    class Conn:
        pass

    monkeypatch.setattr(
        ssl_errors_store,
        "connect",
        lambda: (_ for _ in ()).throw(
            AssertionError("tailer should not use the shared DB pool")
        ),
    )
    monkeypatch.setattr(
        ssl_errors_store,
        "connect_unpooled",
        lambda: calls.append("unpooled") or Conn(),
    )

    assert isinstance(store._tailer_connect(), Conn)
    assert calls == ["unpooled"]


def test_ssl_errors_cleanup_uses_bounded_delete_chunks(monkeypatch, tmp_path) -> None:
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
    from services import db  # type: ignore

    monkeypatch.delenv("DB_POOL_SIZE", raising=False)
    monkeypatch.setenv("WEB_THREADS", "2")

    assert db._pool_maxsize() == 6


def test_explicit_db_pool_size_still_allows_single_connection(monkeypatch) -> None:
    from services import db  # type: ignore

    monkeypatch.setenv("DB_POOL_SIZE", "1")
    monkeypatch.setenv("WEB_THREADS", "8")

    assert db._pool_maxsize() == 1


def test_explicit_db_pool_size_caps_at_larger_admin_budget(monkeypatch) -> None:
    from services import db  # type: ignore

    monkeypatch.setenv("DB_POOL_SIZE", "64")

    assert db._pool_maxsize() == 32


def test_mysql_advisory_lock_acquires_and_releases() -> None:
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


def test_ssl_errors_ingest_logs_database_outage_without_traceback(
    monkeypatch, tmp_path
) -> None:
    import pymysql  # type: ignore
    from services import ssl_errors_store  # type: ignore

    line = "2026/05/20 12:00:00 kid1| error detail: SQUID_TLS_ERR_ACCEPT+TLS_LIB_ERR=A000119+TLS_IO_ERR=1"
    store = ssl_errors_store.SslErrorsStore(cache_log_path=str(tmp_path / "cache.log"))
    monkeypatch.setattr(
        store,
        "init_db",
        lambda: (_ for _ in ()).throw(
            pymysql.err.OperationalError(2003, "connect timed out")
        ),
    )
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(
        ssl_errors_store,
        "log_database_unavailable",
        lambda _logger, key, message, _exc: calls.append((key, message)),
    )
    monkeypatch.setattr(
        ssl_errors_store,
        "log_exception_throttled",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("database outages should not log tracebacks")
        ),
    )

    store.ingest_line(line)

    assert calls == [
        (
            "ssl_errors_store.ingest_direct.db",
            "SSL errors ingest skipped database work because the database is unavailable",
        )
    ]


def test_connect_unpooled_does_not_register_pool_slot(monkeypatch) -> None:
    from services import db  # type: ignore

    db.reset_mysql_ready_for_tests()
    monkeypatch.setenv("DB_POOL_SIZE", "1")

    class NativeConnection:
        def cursor(self):
            class Cursor:
                def execute(self, *_args, **_kwargs):
                    return None

                def close(self):
                    return None

            return Cursor()

        def rollback(self):
            return None

        def close(self):
            return None

    cfg = db.DatabaseConfig(
        host="db", user="u", password="p", database="d", create_database=False
    )
    monkeypatch.setattr(db, "_open_native_connection", lambda _cfg: NativeConnection())

    conn = db.connect_unpooled(cfg)

    assert conn._cfg is None
    assert db._pooled_connections == {}
    conn.close()
    db.reset_mysql_ready_for_tests()


def test_transaction_retry_does_not_replay_lost_connection_commit_ambiguity(
    monkeypatch,
) -> None:
    import pymysql  # type: ignore
    from services import db  # type: ignore

    attempts = {"count": 0}

    def operation() -> None:
        attempts["count"] += 1
        raise pymysql.err.OperationalError(
            2013,
            "Lost connection to MySQL server during query",
        )

    monkeypatch.setenv("MYSQL_CONNECT_RETRIES", "3")
    monkeypatch.setenv("MYSQL_CONNECT_RETRY_DELAY_SECONDS", "0")

    with pytest.raises(pymysql.err.OperationalError):
        db.run_mysql_operation_with_retry(operation)

    assert attempts["count"] == 1


def test_transaction_retry_does_not_replay_connection_acquisition_failure(
    monkeypatch,
) -> None:
    import pymysql  # type: ignore
    from services import db  # type: ignore

    attempts = {"count": 0}

    def operation() -> None:
        attempts["count"] += 1
        raise pymysql.err.OperationalError(
            2003,
            "Can't connect to MySQL server",
        )

    monkeypatch.setenv("MYSQL_CONNECT_RETRIES", "3")
    monkeypatch.setenv("MYSQL_CONNECT_RETRY_DELAY_SECONDS", "0")

    with pytest.raises(pymysql.err.OperationalError):
        db.run_mysql_operation_with_retry(operation)

    assert attempts["count"] == 1


def test_transaction_retry_replays_lock_wait_timeout(monkeypatch) -> None:
    import pymysql  # type: ignore
    from services import db  # type: ignore

    attempts = {"count": 0}

    def operation() -> str:
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise pymysql.err.OperationalError(
                1205,
                "Lock wait timeout exceeded; try restarting transaction",
            )
        return "ok"

    monkeypatch.setenv("MYSQL_CONNECT_RETRIES", "2")
    monkeypatch.setenv("MYSQL_CONNECT_RETRY_DELAY_SECONDS", "0")
    monkeypatch.setenv("MYSQL_RETRY_JITTER_SECONDS", "0")
    monkeypatch.setattr(db.time, "sleep", lambda _seconds: None)

    assert db.run_mysql_operation_with_retry(operation) == "ok"
    assert attempts["count"] == 2


def test_lock_contention_retry_uses_numeric_code_not_message(monkeypatch) -> None:
    import pymysql  # type: ignore
    from services import db  # type: ignore

    attempts = {"count": 0}
    sleeps: list[float] = []

    def operation() -> str:
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise pymysql.err.OperationalError(1205, "localized server message")
        return "ok"

    assert (
        db.run_mysql_lock_contention_with_retry(
            operation,
            attempts=2,
            base_delay_seconds=0.25,
            max_delay_seconds=1.0,
            sleep_fn=sleeps.append,
        )
        == "ok"
    )
    assert attempts["count"] == 2
    assert sleeps == [0.25]


@pytest.mark.parametrize("code", [2003, 2006, 2013])
def test_lock_contention_retry_does_not_replay_connection_errors(code) -> None:
    import pymysql  # type: ignore
    from services import db  # type: ignore

    attempts = {"count": 0}

    def operation() -> None:
        attempts["count"] += 1
        raise pymysql.err.OperationalError(code, "ambiguous connection failure")

    with pytest.raises(pymysql.err.OperationalError):
        db.run_mysql_lock_contention_with_retry(
            operation,
            attempts=4,
            base_delay_seconds=0,
            max_delay_seconds=1,
        )
    assert attempts["count"] == 1


def test_transaction_retry_replays_deadlock_with_bounded_jitter(monkeypatch) -> None:
    import pymysql  # type: ignore
    from services import db  # type: ignore

    attempts = {"count": 0}
    sleeps: list[float] = []

    def operation() -> str:
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise pymysql.err.OperationalError(
                1213,
                "Deadlock found when trying to get lock; try restarting transaction",
            )
        return "ok"

    monkeypatch.setenv("MYSQL_CONNECT_RETRIES", "2")
    monkeypatch.setenv("MYSQL_CONNECT_RETRY_DELAY_SECONDS", "0.1")
    monkeypatch.setenv("MYSQL_RETRY_JITTER_SECONDS", "0.05")
    monkeypatch.setattr(db.time, "sleep", sleeps.append)
    monkeypatch.setattr(db.random, "uniform", lambda _low, high: high)

    assert db.run_mysql_operation_with_retry(operation) == "ok"
    assert attempts["count"] == 2
    assert sleeps == [0.15000000000000002]


def test_mysql_error_classification_names_operator_relevant_failures() -> None:
    import pymysql  # type: ignore
    from services import db  # type: ignore

    assert (
        db.mysql_error_classification(
            pymysql.err.OperationalError(1205, "Lock wait timeout exceeded"),
        )
        == "lock_wait_timeout"
    )
    assert (
        db.mysql_error_classification(
            pymysql.err.OperationalError(1213, "Deadlock found"),
        )
        == "deadlock"
    )
    assert (
        db.mysql_error_classification(
            pymysql.err.OperationalError(2013, "Lost connection"),
        )
        == "connection_lost"
    )


def test_ensure_mysql_database_validates_database_identifier_and_charset(
    monkeypatch,
) -> None:
    from services import db  # type: ignore

    db.reset_mysql_ready_for_tests()
    calls: list[str] = []

    class Cursor:
        def execute(self, sql, params=()) -> None:
            calls.append(str(sql))

        def close(self) -> None:
            return None

    class NativeConnection:
        def cursor(self):
            return Cursor()

        def close(self) -> None:
            return None

    monkeypatch.setattr(db.pymysql, "connect", lambda **_kwargs: NativeConnection())
    db._ensure_mysql_database(
        db.DatabaseConfig(
            host="db",
            user="u",
            password="p",
            database="safe_db",
            charset="utf8mb4",
        )
    )

    assert calls == [
        "CREATE DATABASE IF NOT EXISTS `safe_db` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
    ]

    db.reset_mysql_ready_for_tests()
    with pytest.raises(ValueError, match="Unsafe MySQL identifier"):
        db._ensure_mysql_database(
            db.DatabaseConfig(host="db", user="u", password="p", database="bad`db")
        )

    db.reset_mysql_ready_for_tests()
    with pytest.raises(ValueError, match="Unsafe MySQL charset"):
        db._ensure_mysql_database(
            db.DatabaseConfig(
                host="db",
                user="u",
                password="p",
                database="safe_db",
                charset="utf8mb4;DROP",
            )
        )


def test_mysql_database_creation_ready_cache_is_scoped_per_database(
    monkeypatch,
) -> None:
    from services import db  # type: ignore

    created: list[str] = []

    class Cursor:
        def execute(self, sql, params=()):
            created.append(str(sql))

        def close(self) -> None:
            pass

    class NativeConnection:
        def cursor(self):
            return Cursor()

        def close(self) -> None:
            pass

    monkeypatch.setattr(db.pymysql, "connect", lambda **_kwargs: NativeConnection())
    monkeypatch.setattr(
        db, "_retry_mysql_operation", lambda operation, **_kwargs: operation()
    )
    db.reset_mysql_ready_for_tests()

    cfg_a = db.DatabaseConfig(host="db", user="user", database="proxy_a")
    cfg_b = db.DatabaseConfig(host="db", user="user", database="proxy_b")

    db._ensure_mysql_database(cfg_a)
    db._ensure_mysql_database(cfg_a)
    db._ensure_mysql_database(cfg_b)

    assert sum("CREATE DATABASE IF NOT EXISTS `proxy_a`" in sql for sql in created) == 1
    assert sum("CREATE DATABASE IF NOT EXISTS `proxy_b`" in sql for sql in created) == 1
