from __future__ import annotations

import threading
import time

import pymysql
import pytest
from services import db  # type: ignore


class _Native:
    def __init__(self) -> None:
        self.closed = False

    def cursor(self):
        class _Cursor:
            def execute(self, *_args, **_kwargs):
                return 0

            def close(self):
                return None

        return _Cursor()

    def rollback(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True


def _cfg(**overrides) -> db.DatabaseConfig:
    values = {
        "host": "mysql.invalid",
        "port": 3306,
        "database": "circuit_test",
        "create_database": False,
    }
    values.update(overrides)
    return db.DatabaseConfig(**values)


@pytest.fixture(autouse=True)
def _fast_circuit(monkeypatch):
    monkeypatch.setenv("MYSQL_CONNECT_RETRIES", "1")
    monkeypatch.setenv("MYSQL_CONNECT_CIRCUIT_BACKOFF_INITIAL_SECONDS", "0.1")
    monkeypatch.setenv("MYSQL_CONNECT_CIRCUIT_BACKOFF_MAX_SECONDS", "0.2")
    monkeypatch.setenv("DB_POOL_SIZE", "0")
    db._reset_connect_circuits()
    listeners = list(db._mysql_recovery_listeners)
    yield
    db._reset_connect_circuits()
    db._mysql_recovery_listeners[:] = listeners


def test_connectivity_failure_opens_circuit_and_later_connects_fail_fast(
    monkeypatch,
) -> None:
    attempts: list[str] = []
    down = threading.Event()
    down.set()

    def open_native(_cfg):
        attempts.append("open")
        if down.is_set():
            raise pymysql.OperationalError(2003, "Can't connect to MySQL server")
        return _Native()

    monkeypatch.setattr(db, "_open_native_connection", open_native)
    cfg = _cfg()

    with pytest.raises(pymysql.OperationalError):
        db.connect_unpooled(cfg)
    calls_after_trip = len(attempts)

    started = time.monotonic()
    with pytest.raises(pymysql.OperationalError) as fast:
        db.connect_unpooled(cfg)
    assert time.monotonic() - started < 0.05
    assert db.mysql_error_code(fast.value) == 2003
    assert db.mysql_error_classification(fast.value) == "connectivity"
    # The fail-fast path performs no network attempt of its own; only the
    # single background prober may have tried in the meantime.
    assert len(attempts) <= calls_after_trip + 1


def test_background_probe_closes_circuit_and_notifies_listeners(monkeypatch) -> None:
    down = threading.Event()
    down.set()
    recovered = threading.Event()

    def open_native(_cfg):
        if down.is_set():
            raise pymysql.OperationalError(2003, "Can't connect to MySQL server")
        return _Native()

    monkeypatch.setattr(db, "_open_native_connection", open_native)
    db.add_mysql_recovery_listener(recovered.set)
    cfg = _cfg()

    with pytest.raises(pymysql.OperationalError):
        db.connect_unpooled(cfg)
    time.sleep(0.3)
    assert not recovered.is_set()
    with pytest.raises(pymysql.OperationalError):
        db.connect_unpooled(cfg)

    down.clear()
    assert recovered.wait(2.0)
    conn = db.connect_unpooled(cfg)
    conn.close()


def test_probe_treats_reachable_server_rejection_as_recovery(monkeypatch) -> None:
    state = {"error": pymysql.OperationalError(2003, "Can't connect")}
    recovered = threading.Event()

    def open_native(_cfg):
        raise state["error"]

    monkeypatch.setattr(db, "_open_native_connection", open_native)
    db.add_mysql_recovery_listener(recovered.set)
    cfg = _cfg()
    with pytest.raises(pymysql.OperationalError):
        db.connect_unpooled(cfg)

    state["error"] = pymysql.OperationalError(1045, "Access denied")
    assert recovered.wait(2.0)
    # The caller now sees the real server-side error instead of the circuit.
    with pytest.raises(pymysql.OperationalError) as exc:
        db.connect_unpooled(cfg)
    assert db.mysql_error_code(exc.value) == 1045


@pytest.mark.parametrize(
    "error",
    [
        pymysql.OperationalError(1040, "Database pool exhausted"),
        pymysql.OperationalError(1045, "Access denied"),
        pymysql.ProgrammingError(1146, "Table doesn't exist"),
    ],
)
def test_non_connectivity_failures_do_not_open_circuit(monkeypatch, error) -> None:
    attempts: list[int] = []

    def open_native(_cfg):
        attempts.append(1)
        raise error

    monkeypatch.setattr(db, "_open_native_connection", open_native)
    cfg = _cfg()
    for _ in range(2):
        with pytest.raises(type(error)):
            db.connect_unpooled(cfg)
    assert len(attempts) == 2


def test_circuit_is_scoped_per_database_target(monkeypatch) -> None:
    def open_native(cfg):
        if cfg.host == "down.invalid":
            raise pymysql.OperationalError(2003, "Can't connect")
        return _Native()

    monkeypatch.setattr(db, "_open_native_connection", open_native)
    with pytest.raises(pymysql.OperationalError):
        db.connect_unpooled(_cfg(host="down.invalid"))
    db.connect_unpooled(_cfg(host="up.invalid")).close()


def test_forked_child_starts_with_closed_circuits(monkeypatch) -> None:
    def open_native(_cfg):
        raise pymysql.OperationalError(2003, "Can't connect")

    monkeypatch.setattr(db, "_open_native_connection", open_native)
    with pytest.raises(pymysql.OperationalError):
        db.connect_unpooled(_cfg())
    parent_circuits = list(db._connect_circuits.values())
    assert parent_circuits

    db._reinitialize_connect_circuits_after_fork()

    assert not db._connect_circuits
    # A real fork has no probe threads in the child; stop this process's one.
    for circuit in parent_circuits:
        circuit.stop.set()


def test_mysql_recovery_releases_pending_observability_write_backoffs() -> None:
    # MySQL integration helpers purge and re-import services.*; use the current
    # module pair rather than this file's import-time db module.
    from services import db as current_db  # type: ignore
    from services.observability_backoff import DatabaseWriteBackoff  # type: ignore

    backoff = DatabaseWriteBackoff(base_seconds=60.0, max_seconds=120.0)
    backoff.record_failure()
    assert not backoff.can_attempt()

    current_db._notify_mysql_recovery_listeners()

    # Telemetry resumes on the next writer tick, but a flapping database still
    # backs off from the accumulated failure count.
    assert backoff.can_attempt()
    assert backoff.failures == 1


def test_timed_out_attempt_opens_circuit_for_others_but_caller_keeps_retries(
    monkeypatch,
) -> None:
    monkeypatch.setenv("MYSQL_CONNECT_RETRIES", "3")
    monkeypatch.setenv("MYSQL_CONNECT_CIRCUIT_BACKOFF_INITIAL_SECONDS", "60")
    monkeypatch.setenv("MYSQL_CONNECT_CIRCUIT_BACKOFF_MAX_SECONDS", "60")
    real_sleep = time.sleep
    monkeypatch.setattr(db.time, "sleep", lambda _seconds: None)
    attempts: list[str] = []
    other_call: dict[str, BaseException] = {}

    cfg = _cfg(connect_timeout=1)

    def stalled_then_up(_cfg):
        attempts.append(threading.current_thread().name)
        if len(attempts) == 1:
            real_sleep(0.95)
            raise pymysql.OperationalError(2003, "Can't connect (timed out)")
        # During the observing caller's retry, any other caller fails fast
        # instead of waiting out the connect timeout again.
        started = time.monotonic()
        try:
            db.connect_unpooled(cfg)
        except db.MySQLUnreachableError as exc:
            other_call["error"] = exc
        other_call["elapsed"] = time.monotonic() - started  # type: ignore[assignment]
        return _Native()

    monkeypatch.setattr(db, "_open_native_connection", stalled_then_up)

    # The observing caller still recovers from a transient stall in-call.
    db.connect_unpooled(cfg).close()

    assert len(attempts) == 2
    assert isinstance(other_call["error"], db.MySQLUnreachableError)
    assert other_call["elapsed"] < 0.05  # type: ignore[operator]
    assert not db._connect_circuit(cfg).open


def test_fast_connect_failures_keep_bounded_in_call_retries(monkeypatch) -> None:
    monkeypatch.setenv("MYSQL_CONNECT_RETRIES", "4")
    monkeypatch.setattr(db.time, "sleep", lambda _seconds: None)
    attempts: list[int] = []

    def refused_then_up(_cfg):
        attempts.append(1)
        if len(attempts) < 3:
            raise pymysql.OperationalError(2003, "Connection refused")
        return _Native()

    monkeypatch.setattr(db, "_open_native_connection", refused_then_up)

    db.connect_unpooled(_cfg(connect_timeout=10)).close()

    assert len(attempts) == 3
    assert not db._connect_circuit(_cfg()).open


def test_hung_pooled_session_ping_opens_circuit(monkeypatch) -> None:
    monkeypatch.setenv("DB_POOL_SIZE", "1")
    db._clear_pooled_connections()
    opened: list[int] = []

    monkeypatch.setenv("MYSQL_CONNECT_CIRCUIT_BACKOFF_INITIAL_SECONDS", "60")
    monkeypatch.setenv("MYSQL_CONNECT_CIRCUIT_BACKOFF_MAX_SECONDS", "60")

    class _PooledNative(_Native):
        def ping(self, reconnect=False):
            assert reconnect is False
            time.sleep(0.95)
            raise pymysql.OperationalError(2013, "Lost connection (timed out)")

    def open_native(_cfg):
        opened.append(1)
        if len(opened) > 1:
            raise pymysql.OperationalError(2003, "Can't connect (refused)")
        return _PooledNative()

    monkeypatch.setattr(db, "_open_native_connection", open_native)
    cfg = _cfg(read_timeout=1)
    db.connect(cfg).close()

    # The caller whose pooled ping hung still tries a fresh connection ...
    with pytest.raises(pymysql.OperationalError):
        db.connect(cfg)
    assert len(opened) == 2
    assert db._connect_circuit(cfg).open

    # ... while later callers fail fast without any attempt.
    with pytest.raises(db.MySQLUnreachableError):
        db.connect(cfg)
    assert len(opened) == 2
    db._clear_pooled_connections()


def test_open_circuit_error_is_not_replayed_by_in_call_retries(monkeypatch) -> None:
    monkeypatch.setenv("MYSQL_CONNECT_RETRIES", "4")
    sleeps: list[float] = []
    monkeypatch.setattr(db.time, "sleep", sleeps.append)

    def refused(_cfg):
        raise pymysql.OperationalError(2003, "Connection refused")

    monkeypatch.setattr(db, "_open_native_connection", refused)
    cfg = _cfg()
    with pytest.raises(pymysql.OperationalError):
        db.connect_unpooled(cfg)
    sleeps.clear()

    with pytest.raises(db.MySQLUnreachableError) as exc:
        db.connect_unpooled(cfg)

    assert sleeps == []
    assert isinstance(exc.value, db.DATABASE_ERRORS)
    assert db.mysql_error_classification(exc.value) == "connectivity"


def test_probe_thread_start_failure_leaves_circuit_closed(monkeypatch) -> None:
    def refused(_cfg):
        raise pymysql.OperationalError(2003, "Connection refused")

    class _UnstartableThread:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def start(self) -> None:
            msg = "can't start new thread"
            raise RuntimeError(msg)

    monkeypatch.setattr(db, "_open_native_connection", refused)
    monkeypatch.setattr(db.threading, "Thread", _UnstartableThread)
    cfg = _cfg()

    with pytest.raises(pymysql.OperationalError):
        db.connect_unpooled(cfg)

    assert not db._connect_circuit(cfg).open
