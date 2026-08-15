from __future__ import annotations

from types import SimpleNamespace

import pymysql

from .mysql_test_utils import configure_test_mysql_env


def test_adblock_runtime_enablement_is_scoped_per_proxy(tmp_path) -> None:
    configure_test_mysql_env(tmp_path / "adblock-proxy-scoped-enablement")

    from services.adblock_store import AdblockStore  # type: ignore
    from services.proxy_context import reset_proxy_id, set_proxy_id  # type: ignore
    from services.proxy_registry import get_proxy_registry  # type: ignore

    store = AdblockStore(lists_dir=str(tmp_path / "lists"))
    registry = get_proxy_registry()
    registry.init_db()
    registry.ensure_proxy("proxy-a")
    registry.ensure_proxy("proxy-b")
    store.init_db()

    token = set_proxy_id("proxy-a")
    try:
        store.set_settings(enabled=False, cache_ttl=120, cache_max=4096)
        assert store.get_settings()["enabled"] is False
    finally:
        reset_proxy_id(token)

    token = set_proxy_id("proxy-b")
    try:
        store.set_settings(enabled=True, cache_ttl=120, cache_max=4096)
        assert store.get_settings()["enabled"] is True
    finally:
        reset_proxy_id(token)

    token = set_proxy_id("proxy-a")
    try:
        assert store.get_settings()["enabled"] is False
    finally:
        reset_proxy_id(token)


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


def test_runtime_toggle_does_not_change_shared_artifact_state(tmp_path) -> None:
    configure_test_mysql_env(tmp_path / "adblock-runtime-toggle-shared-state")

    from services.adblock_store import AdblockStore  # type: ignore

    store = AdblockStore(lists_dir=str(tmp_path / "lists"))
    store.init_db()
    version = store.get_settings_version()
    refresh_requested = store.get_refresh_requested()

    store.set_runtime_enabled(True)

    assert store.get_settings()["enabled"] is True
    assert store.get_settings_version() == version
    assert store.get_refresh_requested() == refresh_requested


def test_shared_cache_settings_bump_version_only_when_changed(tmp_path) -> None:
    configure_test_mysql_env(tmp_path / "adblock-shared-cache-settings")

    from services.adblock_store import AdblockStore  # type: ignore

    store = AdblockStore(lists_dir=str(tmp_path / "lists"))
    store.init_db()
    version = store.get_settings_version()

    assert store.set_shared_settings(cache_ttl=3600, cache_max=200000) is False
    assert store.get_settings_version() == version
    assert store.set_shared_settings(cache_ttl=120, cache_max=4096) is True
    assert store.get_settings_version() == version + 1


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
