from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from typing import NoReturn

import pymysql


def _add_web_to_path() -> None:
    web_dir = Path(__file__).resolve().parents[1]
    if str(web_dir) not in sys.path:
        sys.path.insert(0, str(web_dir))


_add_web_to_path()
from services.config_revisions import ConfigRevisionStore  # type: ignore  # noqa: E402


class _ConfigRevisionConn:
    def __init__(self, calls: list[str], *, fail_insert_once: bool) -> None:
        self.calls = calls
        self.fail_insert_once = fail_insert_once

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def execute(self, sql, params=None):
        text = str(sql)
        self.calls.append(text)
        if self.fail_insert_once and "INSERT INTO proxy_config_revisions" in text:
            self.fail_insert_once = False
            raise pymysql.OperationalError(
                1213,
                "Deadlock found when trying to get lock; try restarting transaction",
            )
        if "INSERT INTO proxy_config_revisions" in text:
            return SimpleNamespace(lastrowid=42, rowcount=1)
        if "SELECT * FROM proxy_config_revisions WHERE id=" in text:
            return SimpleNamespace(
                fetchone=lambda: {
                    "id": 42,
                    "proxy_id": "edge-a",
                    "config_sha256": "abc",
                    "config_text": "workers 1\n",
                    "source_kind": "bootstrap",
                    "created_by": "system",
                    "created_ts": 123,
                    "is_active": 1,
                },
            )
        return SimpleNamespace(
            fetchone=lambda: None, fetchall=list, lastrowid=0, rowcount=0
        )


def test_config_revision_create_retries_transient_deadlock(monkeypatch) -> None:
    store = ConfigRevisionStore()
    calls: list[str] = []
    first = _ConfigRevisionConn(calls, fail_insert_once=True)
    second = _ConfigRevisionConn(calls, fail_insert_once=False)
    connections = iter([first, second])

    monkeypatch.setattr(store, "init_db", lambda: None)
    monkeypatch.setattr(store, "get_active_revision", lambda _proxy_id: None)
    monkeypatch.setattr(store, "_connect", lambda: next(connections))
    monkeypatch.setattr("services.config_revisions.time.sleep", lambda _seconds: None)

    revision = store.create_revision(
        "edge-a", "workers 1\n", created_by="system", source_kind="bootstrap"
    )

    assert revision.revision_id == 42
    assert sum(1 for call in calls if "INSERT INTO proxy_config_revisions" in call) == 2


def test_config_revision_lock_retry_exhaustion_preserves_exception(monkeypatch) -> None:
    store = ConfigRevisionStore()
    attempts = {"count": 0}
    sleeps: list[float] = []

    def always_deadlock() -> NoReturn:
        attempts["count"] += 1
        raise pymysql.OperationalError(
            1213, "Deadlock found when trying to get lock; try restarting transaction"
        )

    monkeypatch.setattr("services.config_revisions.time.sleep", sleeps.append)

    try:
        store._with_db_lock_retry(always_deadlock, attempts=3)
    except pymysql.OperationalError as exc:
        assert "Deadlock found" in str(exc)
    else:  # pragma: no cover - defensive assertion
        msg = "expected retry exhaustion to raise the original OperationalError"
        raise AssertionError(msg)

    assert attempts["count"] == 3
    assert sleeps == [0.1, 0.2]


def test_config_revision_retry_does_not_retry_non_lock_operational_errors(
    monkeypatch,
) -> None:
    store = ConfigRevisionStore()
    attempts = {"count": 0}

    def connection_error() -> NoReturn:
        attempts["count"] += 1
        raise pymysql.OperationalError(2003, "Can't connect to MySQL server")

    monkeypatch.setattr(
        "services.config_revisions.time.sleep",
        lambda _seconds: (_ for _ in ()).throw(AssertionError("sleep should not run")),
    )

    try:
        store._with_db_lock_retry(connection_error, attempts=4)
    except pymysql.OperationalError as exc:
        assert "Can't connect" in str(exc)
    else:  # pragma: no cover - defensive assertion
        msg = "expected non-lock OperationalError to be raised immediately"
        raise AssertionError(msg)

    assert attempts["count"] == 1


def test_config_revision_lock_retry_backoff_is_capped(monkeypatch) -> None:
    store = ConfigRevisionStore()
    sleeps: list[float] = []
    attempts = {"count": 0}

    def fail_many_then_succeed() -> str:
        attempts["count"] += 1
        if attempts["count"] < 8:
            raise pymysql.OperationalError(
                1205, "Lock wait timeout exceeded; try restarting transaction"
            )
        return "ok"

    monkeypatch.setattr("services.config_revisions.time.sleep", sleeps.append)

    assert store._with_db_lock_retry(fail_many_then_succeed, attempts=8) == "ok"
    assert sleeps == [0.1, 0.2, 0.4, 0.8, 1.0, 1.0, 1.0]


class _ActivationConn:
    def __init__(self, calls: list[str], *, target_exists: bool) -> None:
        self.calls = calls
        self.target_exists = target_exists

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def execute(self, sql, params=None):
        text = str(sql)
        self.calls.append(text)
        if (
            "SELECT * FROM proxy_config_revisions WHERE id=%s AND proxy_id=%s LIMIT 1"
            in text
        ):
            row = None
            if self.target_exists:
                row = {
                    "id": 9,
                    "proxy_id": "edge-a",
                    "config_sha256": "abc",
                    "config_text": "workers 2\n",
                    "source_kind": "manual",
                    "created_by": "operator",
                    "created_ts": 123,
                    "is_active": 1,
                }
            return SimpleNamespace(fetchone=lambda: row)
        return SimpleNamespace(fetchone=lambda: None, rowcount=1)


def test_activate_revision_checks_target_before_deactivating_current(
    monkeypatch,
) -> None:
    store = ConfigRevisionStore()
    calls: list[str] = []

    monkeypatch.setattr(store, "init_db", lambda: None)
    monkeypatch.setattr(
        store, "_connect", lambda: _ActivationConn(calls, target_exists=False)
    )

    try:
        store.activate_revision("edge-a", 404)
    except ValueError as exc:
        assert "Config revision 404 was not found" in str(exc)
    else:  # pragma: no cover - defensive assertion
        msg = "expected missing target activation to fail"
        raise AssertionError(msg)

    assert not any("SET is_active=0" in call for call in calls)


def test_activate_revision_switches_active_revision(monkeypatch) -> None:
    store = ConfigRevisionStore()
    calls: list[str] = []

    monkeypatch.setattr(store, "init_db", lambda: None)
    monkeypatch.setattr(
        store, "_connect", lambda: _ActivationConn(calls, target_exists=True)
    )

    revision = store.activate_revision("edge-a", 9)

    assert revision.revision_id == 9
    assert any("SET is_active=0" in call for call in calls)
    assert any("SET is_active=1" in call for call in calls)
