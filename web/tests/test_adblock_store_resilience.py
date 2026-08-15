from __future__ import annotations

from types import SimpleNamespace

import pymysql

from .mysql_test_utils import configure_test_mysql_env


def test_adblock_fresh_default_is_disabled_and_init_preserves_explicit_opt_in(
    tmp_path,
) -> None:
    configure_test_mysql_env(tmp_path / "adblock-default-disabled")

    from services.adblock_store import AdblockStore  # type: ignore

    lists_dir = tmp_path / "lists"
    store = AdblockStore(lists_dir=str(lists_dir))
    store.init_db()

    assert store.get_settings()["enabled"] is False

    store.set_settings(enabled=True, cache_ttl=120, cache_max=4096)
    assert store.get_settings()["enabled"] is True

    reinitialized = AdblockStore(lists_dir=str(lists_dir))
    reinitialized.init_db()
    assert reinitialized.get_settings()["enabled"] is True


class _AdblockConn:
    def __init__(self, calls: list[str], *, fail_enabled_update_once: bool) -> None:
        self.calls = calls
        self.fail_enabled_update_once = fail_enabled_update_once

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def execute(self, sql, params=None):
        text = str(sql)
        self.calls.append(text)
        if "SELECT v FROM adblock_meta WHERE k='settings_version'" in text:
            return SimpleNamespace(fetchone=lambda: ("7",))
        return SimpleNamespace(fetchone=lambda: None, fetchall=list, rowcount=1)

    def executemany(self, sql, seq_of_params):
        text = str(sql)
        self.calls.append(text)
        if self.fail_enabled_update_once:
            self.fail_enabled_update_once = False
            raise pymysql.OperationalError(
                1213,
                "Deadlock found when trying to get lock; try restarting transaction",
            )
        return SimpleNamespace(rowcount=len(list(seq_of_params)))


def test_adblock_set_enabled_retries_transient_deadlock(monkeypatch) -> None:
    from services.adblock_store import AdblockStore  # type: ignore

    store = AdblockStore()
    calls: list[str] = []
    first = _AdblockConn(calls, fail_enabled_update_once=True)
    second = _AdblockConn(calls, fail_enabled_update_once=False)
    connections = iter([first, second])
    sleeps: list[float] = []

    monkeypatch.setattr(store, "_connect", lambda: next(connections))
    monkeypatch.setenv("MYSQL_RETRY_JITTER_SECONDS", "0")
    monkeypatch.setattr("services.db.time.sleep", sleeps.append)

    store.set_enabled({"easylist": True, "easyprivacy": False})

    assert sum(1 for call in calls if "UPDATE adblock_lists" in call) == 2
    assert any(
        "settings_version" in call and "INSERT INTO adblock_meta" in call
        for call in calls
    )
    assert sleeps == [0.2]
