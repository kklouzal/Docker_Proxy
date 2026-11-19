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
