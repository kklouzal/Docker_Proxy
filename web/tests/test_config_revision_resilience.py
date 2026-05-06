from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pymysql


def _add_web_to_path() -> None:
    web_dir = Path(__file__).resolve().parents[1]
    if str(web_dir) not in sys.path:
        sys.path.insert(0, str(web_dir))


class _ConfigRevisionConn:
    def __init__(self, calls: list[str], *, fail_insert_once: bool):
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
            raise pymysql.OperationalError(1213, "Deadlock found when trying to get lock; try restarting transaction")
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
                }
            )
        return SimpleNamespace(fetchone=lambda: None, fetchall=lambda: [], lastrowid=0, rowcount=0)


def test_config_revision_create_retries_transient_deadlock(monkeypatch) -> None:
    _add_web_to_path()
    from services.config_revisions import ConfigRevisionStore  # type: ignore

    store = ConfigRevisionStore()
    calls: list[str] = []
    first = _ConfigRevisionConn(calls, fail_insert_once=True)
    second = _ConfigRevisionConn(calls, fail_insert_once=False)
    connections = iter([first, second])

    monkeypatch.setattr(store, "init_db", lambda: None)
    monkeypatch.setattr(store, "get_active_revision", lambda _proxy_id: None)
    monkeypatch.setattr(store, "_connect", lambda: next(connections))
    monkeypatch.setattr("services.config_revisions.time.sleep", lambda _seconds: None)

    revision = store.create_revision("edge-a", "workers 1\n", created_by="system", source_kind="bootstrap")

    assert revision.revision_id == 42
    assert sum(1 for call in calls if "INSERT INTO proxy_config_revisions" in call) == 2
