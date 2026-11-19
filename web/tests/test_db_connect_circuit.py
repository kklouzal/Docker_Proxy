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
    assert db._connect_circuits

    db._reinitialize_connect_circuits_after_fork()

    assert not db._connect_circuits


def test_mysql_recovery_releases_pending_observability_write_backoffs() -> None:
    from services.observability_backoff import DatabaseWriteBackoff  # type: ignore

    backoff = DatabaseWriteBackoff(base_seconds=60.0, max_seconds=120.0)
    backoff.record_failure()
    assert not backoff.can_attempt()

    db._notify_mysql_recovery_listeners()

    # Telemetry resumes on the next writer tick, but a flapping database still
    # backs off from the accumulated failure count.
    assert backoff.can_attempt()
    assert backoff.failures == 1


def test_timed_out_attempt_opens_circuit_without_spending_remaining_retries(
    monkeypatch,
) -> None:
    monkeypatch.setenv("MYSQL_CONNECT_RETRIES", "4")
    real_sleep = time.sleep
    monkeypatch.setattr(db.time, "sleep", lambda _seconds: None)
    attempts: list[str] = []

    def hung_open(_cfg):
        attempts.append(threading.current_thread().name)
        real_sleep(0.95)
        raise pymysql.OperationalError(2013, "Lost connection (timed out)")

    monkeypatch.setattr(db, "_open_native_connection", hung_open)

    started = time.monotonic()
    with pytest.raises(pymysql.OperationalError):
        db.connect_unpooled(_cfg(connect_timeout=1))

    # One hung attempt is enough evidence; the other three fail fast (only the
    # background prober may try again).
    assert attempts.count(threading.main_thread().name) == 1
    assert time.monotonic() - started < 1.5


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

    class _PooledNative(_Native):
        def ping(self, reconnect=False):
            assert reconnect is False
            time.sleep(0.95)
            raise pymysql.OperationalError(2013, "Lost connection (timed out)")

    def open_native(_cfg):
        opened.append(1)
        if len(opened) > 1:
            msg = "circuit must fail fast after a hung ping"
            raise AssertionError(msg)
        return _PooledNative()

    monkeypatch.setattr(db, "_open_native_connection", open_native)
    cfg = _cfg(read_timeout=1)
    db.connect(cfg).close()

    with pytest.raises(pymysql.OperationalError) as exc:
        db.connect(cfg)

    assert db.mysql_error_code(exc.value) in {2003, 2013}
    assert db._connect_circuit(cfg).open
    db._clear_pooled_connections()
