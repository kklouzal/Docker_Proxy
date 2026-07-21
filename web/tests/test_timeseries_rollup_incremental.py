from __future__ import annotations

import threading

import pytest
from services.timeseries_store import TimeSeriesStore

from .mysql_test_utils import configure_test_mysql_env


class _SummaryConn:
    def __init__(self, calls: list[str]) -> None:
        self.calls = calls

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def execute(self, sql, params=None):
        self.calls.append(str(sql))
        return _SummaryResult()


class _SummaryResult:
    def fetchone(self):
        return (3, 90.0, 40.0, 60.0)


def _insert_hourly(
    conn,
    day_start: int,
    day_index: int,
    *,
    count: int = 1,
    cpu: float | None = None,
) -> None:
    value = float(cpu if cpu is not None else 10 + day_index)
    for hour in (0, 1):
        conn.execute(
            """
            INSERT INTO ts_1h(proxy_id, ts, count, cpu, mem, disk_used, cache_dir_size, hit_rate)
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            (
                "default",
                day_start + day_index * 86400 + hour * 3600,
                count,
                value,
                0.0,
                0.0,
                0.0,
                0.0,
            ),
        )


def test_daily_rollup_processes_bounded_oldest_buckets_and_is_idempotent(tmp_path) -> None:
    configure_test_mysql_env(tmp_path)
    store = TimeSeriesStore()
    store.init_db()
    day0 = (1_777_000_000 // 86400) * 86400
    cutoff = day0 + 5 * 86400

    with store._connect() as conn:
        for day in range(5):
            _insert_hourly(conn, day0, day)

    store._rollup("ts_1h", "ts_1d", 86400, cutoff, "default", max_dst_buckets=2)
    with store._connect() as conn:
        daily_rows = conn.execute("SELECT ts, count FROM ts_1d ORDER BY ts").fetchall()
        remaining = conn.execute("SELECT COUNT(*) FROM ts_1h").fetchone()[0]
    assert [(int(row[0]), int(row[1])) for row in daily_rows] == [
        (day0, 2),
        (day0 + 86400, 2),
    ]
    assert int(remaining) == 6

    store._rollup("ts_1h", "ts_1d", 86400, cutoff, "default", max_dst_buckets=2)
    store._rollup("ts_1h", "ts_1d", 86400, cutoff, "default", max_dst_buckets=2)
    with store._connect() as conn:
        before = [
            (int(row[0]), int(row[1]))
            for row in conn.execute("SELECT ts, count FROM ts_1d ORDER BY ts").fetchall()
        ]
        assert int(conn.execute("SELECT COUNT(*) FROM ts_1h").fetchone()[0]) == 0

    store._rollup("ts_1h", "ts_1d", 86400, cutoff, "default", max_dst_buckets=2)
    with store._connect() as conn:
        after = [
            (int(row[0]), int(row[1]))
            for row in conn.execute("SELECT ts, count FROM ts_1d ORDER BY ts").fetchall()
        ]
    assert after == before


def test_rollup_floors_non_aligned_source_timestamps_to_bucket_start(
    tmp_path,
) -> None:
    configure_test_mysql_env(tmp_path)
    store = TimeSeriesStore()
    store.init_db()
    minute_start = (1_777_000_123 // 60) * 60

    with store._connect() as conn:
        conn.execute(
            """
            INSERT INTO ts_1s(proxy_id, ts, count, cpu, mem, disk_used, cache_dir_size, hit_rate)
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            ("default", minute_start + 1, 1, 10.0, 0.0, 0.0, 0.0, 0.0),
        )
        conn.execute(
            """
            INSERT INTO ts_1s(proxy_id, ts, count, cpu, mem, disk_used, cache_dir_size, hit_rate)
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            ("default", minute_start + 59, 1, 20.0, 0.0, 0.0, 0.0, 0.0),
        )

    store._rollup(
        "ts_1s",
        "ts_1m",
        60,
        minute_start + 120,
        "default",
        max_dst_buckets=1,
    )

    with store._connect() as conn:
        rows = conn.execute("SELECT ts, count, cpu FROM ts_1m ORDER BY ts").fetchall()

    assert [(int(row[0]), int(row[1]), float(row[2])) for row in rows] == [
        (minute_start, 2, pytest.approx(15.0)),
    ]


def test_daily_rollup_late_hour_updates_existing_day_weighted_average(tmp_path) -> None:
    configure_test_mysql_env(tmp_path)
    store = TimeSeriesStore()
    store.init_db()
    day0 = (1_777_000_000 // 86400) * 86400
    cutoff = day0 + 2 * 86400

    with store._connect() as conn:
        _insert_hourly(conn, day0, 0, count=1, cpu=10.0)

    store._rollup("ts_1h", "ts_1d", 86400, cutoff, "default", max_dst_buckets=1)
    with store._connect() as conn:
        conn.execute(
            """
            INSERT INTO ts_1h(proxy_id, ts, count, cpu, mem, disk_used, cache_dir_size, hit_rate)
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            ("default", day0 + 12 * 3600, 2, 30.0, 0.0, 0.0, 0.0, 0.0),
        )

    store._rollup("ts_1h", "ts_1d", 86400, cutoff, "default", max_dst_buckets=1)

    with store._connect() as conn:
        count, cpu = conn.execute("SELECT count, cpu FROM ts_1d WHERE ts=%s", (day0,)).fetchone()
    assert int(count) == 4
    assert float(cpu) == pytest.approx(20.0)


def test_rollup_averages_ignore_null_metric_samples(tmp_path) -> None:
    configure_test_mysql_env(tmp_path)
    store = TimeSeriesStore()
    store.init_db()
    minute_start = (1_777_000_123 // 60) * 60

    with store._connect() as conn:
        conn.execute(
            """
            INSERT INTO ts_1s(proxy_id, ts, count, cpu, mem, disk_used, cache_dir_size, hit_rate)
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            ("default", minute_start + 1, 1, None, 0.0, 0.0, 0.0, 0.0),
        )
        conn.execute(
            """
            INSERT INTO ts_1s(proxy_id, ts, count, cpu, mem, disk_used, cache_dir_size, hit_rate)
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            ("default", minute_start + 2, 1, 20.0, 0.0, 0.0, 0.0, 0.0),
        )

    store._rollup(
        "ts_1s",
        "ts_1m",
        60,
        minute_start + 120,
        "default",
        max_dst_buckets=1,
    )

    with store._connect() as conn:
        count, cpu = conn.execute(
            "SELECT count, cpu FROM ts_1m WHERE proxy_id=%s AND ts=%s",
            ("default", minute_start),
        ).fetchone()

    assert int(count) == 2
    assert float(cpu) == pytest.approx(20.0)


def test_summary_averages_use_metric_non_null_denominators(monkeypatch) -> None:
    store = TimeSeriesStore.__new__(TimeSeriesStore)
    store._db_initialized = True
    store._db_init_lock = threading.Lock()
    calls: list[str] = []
    monkeypatch.setattr(store, "_connect", lambda: _SummaryConn(calls))
    monkeypatch.setattr("services.timeseries_store._now", lambda: 1_777_000_180)

    summary = store.summary()["60s"]
    query = "\n".join(calls)

    assert summary["count"] == 3
    assert summary["cpu_avg"] == pytest.approx(90.0)
    assert summary["mem_avg"] == pytest.approx(40.0)
    assert summary["hit_rate_avg"] == pytest.approx(60.0)
    assert "SUM(CASE WHEN cpu IS NOT NULL THEN count ELSE 0 END)" in query
    assert "SUM(CASE WHEN mem IS NOT NULL THEN count ELSE 0 END)" in query
    assert "SUM(CASE WHEN hit_rate IS NOT NULL THEN count ELSE 0 END)" in query
    assert "SUM(cpu * count)/SUM(count)" not in query


def test_summary_averages_ignore_null_metric_samples_mysql(monkeypatch, tmp_path) -> None:
    configure_test_mysql_env(tmp_path)
    store = TimeSeriesStore()
    store.init_db()
    now = 1_777_000_180
    monkeypatch.setattr("services.timeseries_store._now", lambda: now)

    with store._connect() as conn:
        conn.execute(
            """
            INSERT INTO ts_1s(proxy_id, ts, count, cpu, mem, disk_used, cache_dir_size, hit_rate)
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            ("default", now - 30, 2, None, 40.0, None, None, 50.0),
        )
        conn.execute(
            """
            INSERT INTO ts_1s(proxy_id, ts, count, cpu, mem, disk_used, cache_dir_size, hit_rate)
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            ("default", now - 20, 1, 90.0, None, None, None, 80.0),
        )

    summary = store.summary()["60s"]

    assert summary["count"] == 3
    assert float(summary["cpu_avg"]) == pytest.approx(90.0)
    assert float(summary["mem_avg"]) == pytest.approx(40.0)
    assert float(summary["hit_rate_avg"]) == pytest.approx(60.0)
