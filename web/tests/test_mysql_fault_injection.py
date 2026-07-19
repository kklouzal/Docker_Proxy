from __future__ import annotations

import concurrent.futures
import sys
import threading
from pathlib import Path
from unittest import SkipTest

import pytest

from .mysql_test_utils import configure_test_mysql_env

WEB_ROOT = Path(__file__).resolve().parents[1]
if str(WEB_ROOT) not in sys.path:
    sys.path.insert(0, str(WEB_ROOT))


def _mysql_modules(tmp_path: Path):
    try:
        configure_test_mysql_env(tmp_path, secret_path=tmp_path / "flask_secret.key")
    except SkipTest as exc:
        pytest.skip(str(exc))
    from services import db, schema_lifecycle  # type: ignore

    schema_lifecycle.migrate_schema(require_privileges=False)
    return db


@pytest.mark.integration
@pytest.mark.mysql
def test_mysql_deadlock_retry_replays_idempotent_transaction_once_per_worker(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db = _mysql_modules(tmp_path)
    monkeypatch.setenv("MYSQL_CONNECT_RETRIES", "3")
    monkeypatch.setenv("MYSQL_CONNECT_RETRY_DELAY_SECONDS", "0")
    monkeypatch.setenv("MYSQL_RETRY_JITTER_SECONDS", "0")

    with db.connect() as conn:
        conn.execute("CREATE TABLE fault_deadlock(id INT PRIMARY KEY, value INT NOT NULL) ENGINE=InnoDB")
        conn.execute("INSERT INTO fault_deadlock(id, value) VALUES(1, 0), (2, 0)")

    barrier = threading.Barrier(2)
    first_attempt = {"a": True, "b": True}
    first_attempt_lock = threading.Lock()

    def worker(name: str, first_id: int, second_id: int) -> str:
        def attempt() -> None:
            with db.connect() as conn:
                conn.execute(
                    "UPDATE fault_deadlock SET value=value+1 WHERE id=%s",
                    (first_id,),
                )
                with first_attempt_lock:
                    wait_for_peer = first_attempt[name]
                    first_attempt[name] = False
                if wait_for_peer:
                    barrier.wait(timeout=10)
                conn.execute(
                    "UPDATE fault_deadlock SET value=value+1 WHERE id=%s",
                    (second_id,),
                )

        db.run_mysql_operation_with_retry(attempt, operation_name=f"deadlock-{name}")
        return name

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        results = sorted(
            executor.map(
                lambda args: worker(*args),
                (("a", 1, 2), ("b", 2, 1)),
            ),
        )

    assert results == ["a", "b"]
    with db.connect() as conn:
        rows = conn.execute("SELECT id, value FROM fault_deadlock ORDER BY id").fetchall()
    assert [(int(row["id"]), int(row["value"])) for row in rows] == [(1, 2), (2, 2)]


@pytest.mark.integration
@pytest.mark.mysql
def test_mysql_killed_session_during_commit_is_not_blindly_retried(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db = _mysql_modules(tmp_path)
    monkeypatch.setenv("MYSQL_CONNECT_RETRIES", "3")
    monkeypatch.setenv("MYSQL_CONNECT_RETRY_DELAY_SECONDS", "0")
    monkeypatch.setenv("MYSQL_RETRY_JITTER_SECONDS", "0")

    with db.connect() as conn:
        conn.execute("CREATE TABLE fault_commit(id INT PRIMARY KEY, value INT NOT NULL) ENGINE=InnoDB")

    attempts = {"count": 0}

    def ambiguous_commit() -> None:
        attempts["count"] += 1
        with db.connect_unpooled() as victim:
            connection_id = victim.execute("SELECT CONNECTION_ID() AS id").fetchone()["id"]
            victim.execute("INSERT INTO fault_commit(id, value) VALUES(1, 1)")
            with db.connect_unpooled() as killer:
                killer.execute(f"KILL CONNECTION {int(connection_id)}")
            victim.commit()

    with pytest.raises(db.DATABASE_ERRORS):
        db.run_mysql_operation_with_retry(ambiguous_commit, operation_name="ambiguous-commit")

    assert attempts["count"] == 1


@pytest.mark.integration
@pytest.mark.mysql
def test_mysql_advisory_lock_released_when_session_is_killed(tmp_path: Path) -> None:
    db = _mysql_modules(tmp_path)
    lock_name = "docker_proxy:test:advisory_loss"
    with db.connect_unpooled() as holder:
        acquired = holder.execute("SELECT GET_LOCK(%s, 1) AS acquired", (lock_name,)).fetchone()
        assert int(acquired["acquired"] or 0) == 1
        connection_id = int(holder.execute("SELECT CONNECTION_ID() AS id").fetchone()["id"])
        with db.connect_unpooled() as killer:
            killer.execute(f"KILL CONNECTION {connection_id}")
        with db.connect_unpooled() as contender:
            row = contender.execute("SELECT GET_LOCK(%s, 5) AS acquired", (lock_name,)).fetchone()
            assert int(row["acquired"] or 0) == 1
            contender.execute("DO RELEASE_LOCK(%s)", (lock_name,))
