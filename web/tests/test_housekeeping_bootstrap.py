from __future__ import annotations

import sys
import threading
from pathlib import Path


def _add_web_to_path() -> None:
    web_dir = Path(__file__).resolve().parents[1]
    if str(web_dir) not in sys.path:
        sys.path.insert(0, str(web_dir))


class _FakeConn:
    def __init__(self, calls: list[str]):
        self.calls = calls

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def execute(self, sql, params=None):
        self.calls.append(str(sql))
        return []


def _fake_connect(calls: list[str]):
    def connect():
        return _FakeConn(calls)

    return connect


def test_prune_methods_initialize_tables_before_deleting(monkeypatch) -> None:
    _add_web_to_path()
    from services.adblock_store import AdblockStore  # type: ignore
    from services.diagnostic_store import DiagnosticStore  # type: ignore
    from services.live_stats import LiveStatsStore  # type: ignore
    from services.ssl_errors_store import SslErrorsStore  # type: ignore

    stores = []

    adblock = AdblockStore.__new__(AdblockStore)
    adblock.blocklog_retention_days = 30
    stores.append(adblock)

    diagnostic = DiagnosticStore.__new__(DiagnosticStore)
    diagnostic.retention_days = 30
    stores.append(diagnostic)

    live = LiveStatsStore.__new__(LiveStatsStore)
    stores.append(live)

    ssl_errors = SslErrorsStore.__new__(SslErrorsStore)
    stores.append(ssl_errors)

    for store in stores:
        calls: list[str] = []
        monkeypatch.setattr(store, "init_db", lambda calls=calls: calls.append("init_db"))
        monkeypatch.setattr(store, "_connect", _fake_connect(calls))

        store.prune_old_entries(retention_days=1)

        assert calls[0] == "init_db"
        assert any("DELETE FROM" in call for call in calls[1:])


class _TimeseriesConn:
    def __init__(self, calls: list[str], *, fail_insert: bool = False, fail_select: bool = False):
        self.calls = calls
        self.fail_insert = fail_insert
        self.fail_select = fail_select

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def execute(self, sql, params=None):
        text = str(sql)
        self.calls.append(text)
        if self.fail_insert and "INSERT INTO ts_1s" in text:
            raise RuntimeError("(1146, table 'squid_proxy.ts_1s' doesn't exist)")
        if self.fail_select and "FROM ts_" in text:
            raise RuntimeError("(1146, table 'squid_proxy.ts_1s' doesn't exist)")
        return _TimeseriesResult(text)


class _TimeseriesResult:
    def __init__(self, sql: str):
        self.sql = sql

    def fetchone(self):
        return (0, None, None, None)

    def fetchall(self):
        if "SELECT ts, count, cpu, mem, hit_rate" in self.sql:
            return [(123, 1, 2.5, 50.0, 75.0)]
        return []


def test_timeseries_insert_reinitializes_after_external_schema_wipe(monkeypatch) -> None:
    _add_web_to_path()
    from services.timeseries_store import TimeSeriesStore  # type: ignore

    store = TimeSeriesStore.__new__(TimeSeriesStore)
    store._db_initialized = True
    store._db_init_lock = threading.Lock()
    calls: list[str] = []
    connections = iter([
        _TimeseriesConn(calls, fail_insert=True),
        _TimeseriesConn(calls),
        _TimeseriesConn(calls),
    ])
    monkeypatch.setattr(store, "_connect", lambda: next(connections))

    store.insert_snapshot({}, ts=123)

    assert store._db_initialized is True
    assert sum(1 for call in calls if "CREATE TABLE IF NOT EXISTS" in call) == 7
    assert sum(1 for call in calls if "INSERT INTO ts_1s" in call) == 2


def test_timeseries_summary_reinitializes_after_external_schema_wipe(monkeypatch) -> None:
    _add_web_to_path()
    from services.timeseries_store import TimeSeriesStore  # type: ignore

    store = TimeSeriesStore.__new__(TimeSeriesStore)
    store._db_initialized = True
    store._db_init_lock = threading.Lock()
    calls: list[str] = []
    connections = iter([
        _TimeseriesConn(calls, fail_select=True),
        _TimeseriesConn(calls),
        _TimeseriesConn(calls),
    ])
    monkeypatch.setattr(store, "_connect", lambda: next(connections))

    summary = store.summary()

    assert set(summary) == {"60s", "1h", "24h", "7d"}
    assert summary["60s"]["count"] == 0
    assert store._db_initialized is True
    assert sum(1 for call in calls if "CREATE TABLE IF NOT EXISTS" in call) == 7


def test_timeseries_query_reinitializes_after_external_schema_wipe(monkeypatch) -> None:
    _add_web_to_path()
    from services.timeseries_store import TimeSeriesStore  # type: ignore

    store = TimeSeriesStore.__new__(TimeSeriesStore)
    store._db_initialized = True
    store._db_init_lock = threading.Lock()
    calls: list[str] = []
    connections = iter([
        _TimeseriesConn(calls, fail_select=True),
        _TimeseriesConn(calls),
        _TimeseriesConn(calls),
    ])
    monkeypatch.setattr(store, "_connect", lambda: next(connections))

    rows = store.query("1s", since=0, limit=25)

    assert rows == [{"ts": 123, "count": 1, "cpu": 2.5, "mem": 50.0, "hit_rate": 75.0}]
    assert store._db_initialized is True
    assert sum(1 for call in calls if "CREATE TABLE IF NOT EXISTS" in call) == 7
