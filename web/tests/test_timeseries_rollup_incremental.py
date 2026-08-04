from __future__ import annotations

import threading
from operator import itemgetter

import pytest
from services.timeseries_store import (
    TimeSeriesStore,
    canonicalize_resolution_name,
    resolve_resolution,
)

from .mysql_test_utils import configure_test_mysql_env


class _QueryConn:
    def __init__(self, calls: list[tuple[str, object]]) -> None:
        self.calls = calls

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def execute(self, sql, params=None):
        self.calls.append((str(sql), params))
        return _QueryResult()


class _QueryResult:
    def fetchall(self):
        return [(123, 1, 2.0, 3.0, 5.0, 6.0, 4.0)]


class _FilteringQueryConn:
    def __init__(
        self,
        rows: list[tuple[str, int, int, float, float, float, float, float]],
        calls: list[tuple[str, object]],
    ) -> None:
        self.rows = rows
        self.calls = calls

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def execute(self, sql, params=None):
        text = str(sql)
        self.calls.append((text, params))
        proxy_id, overlap_since, now, limit = params
        matching = sorted(
            (
                row[1:]
                for row in self.rows
                if row[0] == proxy_id and overlap_since <= row[1] <= now
            ),
            key=itemgetter(0),
            reverse="ORDER BY ts DESC" in text,
        )[:limit]
        return _FilteringQueryResult(matching)


class _FilteringQueryResult:
    def __init__(self, rows: list[tuple[int, int, float, float, float, float, float]]) -> None:
        self.rows = rows

    def fetchall(self):
        return self.rows


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


class _SnapshotConn:
    def __init__(self, calls: list[tuple[str, object]]) -> None:
        self.calls = calls

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def execute(self, sql, params=None):
        self.calls.append((str(sql), params))


class _FilteringSummaryConn:
    def __init__(
        self,
        rows_by_table: dict[str, list[tuple]],
        calls: list[tuple[str, object]],
    ) -> None:
        self.rows_by_table = rows_by_table
        self.calls = calls

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def execute(self, sql, params=None):
        text = str(sql)
        self.calls.append((text, params))
        table = next(
            table
            for table in ("ts_1s", "ts_1m", "ts_1h", "ts_1d")
            if f"FROM {table}" in text
        )
        proxy_id, overlap_since, now = params
        matching = [
            row
            for row in self.rows_by_table.get(table, [])
            if row[0] == proxy_id and overlap_since <= row[1] <= now
        ]
        return _FilteringSummaryResult(matching)


class _FilteringSummaryResult:
    def __init__(self, rows: list[tuple]) -> None:
        self.rows = rows

    def fetchone(self):
        def weighted_average(value_index: int, count_index: int) -> float | None:
            denominator = sum(row[count_index] for row in self.rows)
            if not denominator:
                return None
            return (
                sum(row[value_index] * row[count_index] for row in self.rows)
                / denominator
            )

        return (
            sum(row[2] for row in self.rows),
            weighted_average(3, 4),
            weighted_average(5, 6),
            weighted_average(7, 8),
        )


class _RollupSqlResult:
    def __init__(self, row=None) -> None:
        self._row = row

    def fetchone(self):
        return self._row


class _RollupSqlConn:
    def __init__(self, calls: list[str]) -> None:
        self.calls = calls

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def execute(self, sql, params=None):
        text = str(sql)
        self.calls.append(text)
        if "SELECT MIN(ts)" in text:
            return _RollupSqlResult((1_777_000_120,))
        return _RollupSqlResult()


class _Guard:
    def __init__(self, proxy_id: str) -> None:
        self.proxy_id = proxy_id

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


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


@pytest.mark.parametrize(
    ("supplied_ts", "expected_ts", "expected_clock_calls"),
    [(0, 0, 0), (None, 123, 1)],
)
def test_insert_snapshot_timestamp_contract_reaches_sql(
    monkeypatch,
    supplied_ts: int | None,
    expected_ts: int,
    expected_clock_calls: int,
) -> None:
    store = TimeSeriesStore.__new__(TimeSeriesStore)
    store._db_initialized = True
    store._db_init_lock = threading.Lock()
    calls: list[tuple[str, object]] = []
    clock_calls: list[None] = []

    def application_clock() -> int:
        clock_calls.append(None)
        return 123

    monkeypatch.setattr(store, "_connect", lambda: _SnapshotConn(calls))
    monkeypatch.setattr(
        "services.timeseries_store.guarded_proxy_write",
        lambda _conn, proxy_id: _Guard(proxy_id),
    )
    monkeypatch.setattr("services.timeseries_store.get_proxy_id", lambda: "proxy-a")
    monkeypatch.setattr("services.timeseries_store._now", application_clock)

    store.insert_snapshot({}, ts=supplied_ts)

    assert len(clock_calls) == expected_clock_calls
    assert len(calls) == 1
    sql, params = calls[0]
    assert "INSERT INTO ts_1s" in sql
    assert params[0:3] == ("proxy-a", expected_ts, 1)


def test_rollup_and_prune_at_explicit_zero_does_not_mutate_db(monkeypatch) -> None:
    store = TimeSeriesStore.__new__(TimeSeriesStore)
    store._db_initialized = True
    store._db_init_lock = threading.Lock()

    monkeypatch.setattr(
        store,
        "_connect",
        lambda: pytest.fail("an epoch-zero cutoff must not issue retention SQL"),
    )
    monkeypatch.setattr("services.timeseries_store.get_proxy_id", lambda: "proxy-a")
    monkeypatch.setattr(
        "services.timeseries_store._now",
        lambda: pytest.fail("explicit timestamps must not read the application clock"),
    )

    store.rollup_and_prune(ts=0)


def test_query_canonicalizes_resolution_and_returns_persisted_metrics(
    monkeypatch,
) -> None:
    store = TimeSeriesStore.__new__(TimeSeriesStore)
    store._db_initialized = True
    store._db_init_lock = threading.Lock()
    calls: list[tuple[str, object]] = []
    monkeypatch.setattr(store, "_connect", lambda: _QueryConn(calls))
    monkeypatch.setattr("services.timeseries_store._now", lambda: 200)

    valid_points = store.query(resolution="1m", since=100, limit=25)
    unknown_points = store.query(resolution="bogus", since=100, limit=25)

    assert canonicalize_resolution_name("1m") == "1m"
    assert canonicalize_resolution_name("bogus") == "1s"
    assert "FROM ts_1m" in calls[0][0]
    assert "FROM ts_1s" in calls[1][0]
    assert calls[0][1] == ("default", 41, 200, 25)
    assert calls[1][1] == ("default", 100, 200, 25)
    assert "ts >= %s AND ts <= %s" in calls[0][0]
    assert "disk_used" in calls[0][0]
    assert "cache_dir_size" in calls[0][0]
    assert valid_points == unknown_points == [
        {
            "ts": 123,
            "count": 1,
            "cpu": 2.0,
            "mem": 3.0,
            "disk_used": 5.0,
            "cache_dir_size": 6.0,
            "hit_rate": 4.0,
        }
    ]


def test_query_returns_latest_bounded_proxy_points_in_chronological_order(
    monkeypatch,
) -> None:
    store = TimeSeriesStore.__new__(TimeSeriesStore)
    store._db_initialized = True
    store._db_init_lock = threading.Lock()
    metric_row = (1, 2.0, 3.0, 5.0, 6.0, 4.0)
    rows = [("proxy-a", ts, *metric_row) for ts in range(99, 116)] + [
        ("proxy-b", ts, *metric_row) for ts in range(100, 115)
    ]
    calls: list[tuple[str, object]] = []
    monkeypatch.setattr(store, "_connect", lambda: _FilteringQueryConn(rows, calls))
    monkeypatch.setattr("services.timeseries_store._now", lambda: 114)
    monkeypatch.setattr("services.timeseries_store.get_proxy_id", lambda: "proxy-a")

    points = store.query(resolution="1s", since=100, limit=3)

    assert [point["ts"] for point in points] == list(range(105, 115))
    assert calls[0][1] == ("proxy-a", 100, 114, 10)
    assert "ORDER BY ts DESC LIMIT %s" in calls[0][0]


@pytest.mark.parametrize(
    ("resolution", "seconds"),
    [
        ("1s", 1),
        ("1m", 60),
        ("1h", 60 * 60),
        ("1d", 60 * 60 * 24),
        ("1w", 60 * 60 * 24 * 7),
        ("1mo", 60 * 60 * 24 * 30),
        ("1y", 60 * 60 * 24 * 365),
    ],
)
def test_query_includes_only_buckets_overlapping_since_through_now(
    monkeypatch,
    resolution: str,
    seconds: int,
) -> None:
    store = TimeSeriesStore.__new__(TimeSeriesStore)
    store._db_initialized = True
    store._db_init_lock = threading.Lock()
    bucket_start = (1_777_000_000 // seconds) * seconds
    since = bucket_start + seconds // 2
    now = bucket_start + seconds
    metric_row = (1, 2.0, 3.0, 5.0, 6.0, 4.0)
    rows = [
        ("proxy-a", bucket_start - seconds, *metric_row),
        ("proxy-a", bucket_start, *metric_row),
        ("proxy-a", now, *metric_row),
        ("proxy-a", now + seconds, *metric_row),
        ("proxy-b", bucket_start, *metric_row),
    ]
    calls: list[tuple[str, object]] = []
    monkeypatch.setattr(
        store,
        "_connect",
        lambda: _FilteringQueryConn(rows, calls),
    )
    monkeypatch.setattr("services.timeseries_store._now", lambda: now)
    monkeypatch.setattr("services.timeseries_store.get_proxy_id", lambda: "proxy-a")

    points = store.query(resolution=resolution, since=since, limit=25)

    # A rollup bucket beginning exactly at now is current, not future. Only a
    # bucket whose start is later than now must be excluded.
    assert [point["ts"] for point in points] == [bucket_start, now]
    assert f"FROM ts_{resolution}" in calls[0][0]
    assert calls[0][1] == ("proxy-a", since - (seconds - 1), now, 25)
    assert "ts >= %s AND ts <= %s ORDER BY ts DESC LIMIT %s" in calls[0][0]
    if resolution == "1s":
        assert calls[0][1][1] == since


@pytest.mark.parametrize(
    ("label", "resolution_name", "window_seconds"),
    [
        ("60s", "1s", 60),
        ("1h", "1m", 60 * 60),
        ("24h", "1h", 60 * 60 * 24),
        ("7d", "1d", 60 * 60 * 24 * 7),
    ],
)
def test_summary_includes_only_buckets_overlapping_window_through_now(
    monkeypatch,
    label: str,
    resolution_name: str,
    window_seconds: int,
) -> None:
    store = TimeSeriesStore.__new__(TimeSeriesStore)
    store._db_initialized = True
    store._db_init_lock = threading.Lock()
    now = 1_777_000_180
    resolution = resolve_resolution(resolution_name)
    since = now - window_seconds
    bucket_start = (since // resolution.seconds) * resolution.seconds
    current_bucket_start = (now // resolution.seconds) * resolution.seconds
    rows = [
        (
            "proxy-a",
            bucket_start - resolution.seconds,
            100,
            100.0,
            100,
            100.0,
            100,
            100.0,
            100,
        ),
        ("proxy-a", bucket_start, 2, 20.0, 2, 20.0, 2, 20.0, 2),
        (
            "proxy-a",
            bucket_start + resolution.seconds,
            3,
            40.0,
            3,
            40.0,
            3,
            40.0,
            3,
        ),
        (
            "proxy-a",
            current_bucket_start,
            5,
            50.0,
            5,
            50.0,
            5,
            50.0,
            5,
        ),
        (
            "proxy-a",
            current_bucket_start + resolution.seconds,
            100,
            100.0,
            100,
            100.0,
            100,
            100.0,
            100,
        ),
        ("proxy-b", bucket_start, 200, 200.0, 200, 200.0, 200, 200.0, 200),
    ]
    calls: list[tuple[str, object]] = []
    monkeypatch.setattr(
        store,
        "_connect",
        lambda: _FilteringSummaryConn({resolution.table: rows}, calls),
    )
    monkeypatch.setattr("services.timeseries_store._now", lambda: now)
    monkeypatch.setattr("services.timeseries_store.get_proxy_id", lambda: "proxy-a")

    summary = store.summary()[label]

    assert summary == {
        "count": 10,
        "cpu_avg": pytest.approx(41.0),
        "mem_avg": pytest.approx(41.0),
        "hit_rate_avg": pytest.approx(41.0),
    }
    sql, params = next(call for call in calls if f"FROM {resolution.table}" in call[0])
    overlap_since = since - (resolution.seconds - 1)
    assert bucket_start - resolution.seconds < overlap_since <= bucket_start
    assert current_bucket_start <= now < current_bucket_start + resolution.seconds
    assert params == ("proxy-a", overlap_since, now)
    assert "WHERE proxy_id = %s AND ts >= %s AND ts <= %s" in sql
    assert "ts + " not in sql


def test_rollup_sql_combines_late_buckets_with_metric_sample_counts(
    monkeypatch,
) -> None:
    store = TimeSeriesStore.__new__(TimeSeriesStore)
    calls: list[str] = []
    monkeypatch.setattr(store, "_connect", lambda: _RollupSqlConn(calls))
    monkeypatch.setattr(
        "services.timeseries_store.guarded_proxy_write",
        lambda _conn, proxy_id: _Guard(proxy_id),
    )

    store._rollup("ts_1s", "ts_1m", 60, 1_777_000_240, "default")

    query = "\n".join(calls)
    assert "cpu_count" in query
    assert "COALESCE(cpu_count, CASE WHEN cpu IS NOT NULL THEN count ELSE 0 END)" in query
    assert "+ incoming.cpu_count" in query
    assert "ts_1m.cpu * ts_1m.count + incoming.cpu * incoming.count" not in query


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


def test_late_rollup_updates_existing_bucket_with_metric_sample_counts(
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
            ("default", minute_start + 1, 9, None, 0.0, 0.0, 0.0, 0.0),
        )
        conn.execute(
            """
            INSERT INTO ts_1s(proxy_id, ts, count, cpu, mem, disk_used, cache_dir_size, hit_rate)
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            ("default", minute_start + 2, 1, 20.0, 0.0, 0.0, 0.0, 0.0),
        )

    store._rollup("ts_1s", "ts_1m", 60, minute_start + 120, "default", max_dst_buckets=1)

    with store._connect() as conn:
        conn.execute(
            """
            INSERT INTO ts_1s(proxy_id, ts, count, cpu, mem, disk_used, cache_dir_size, hit_rate)
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            ("default", minute_start + 3, 1, 100.0, 0.0, 0.0, 0.0, 0.0),
        )

    store._rollup("ts_1s", "ts_1m", 60, minute_start + 120, "default", max_dst_buckets=1)

    with store._connect() as conn:
        count, cpu = conn.execute(
            "SELECT count, cpu FROM ts_1m WHERE proxy_id=%s AND ts=%s",
            ("default", minute_start),
        ).fetchone()

    assert int(count) == 11
    assert float(cpu) == pytest.approx(60.0)


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
    assert "COALESCE(cpu_count, CASE WHEN cpu IS NOT NULL THEN count ELSE 0 END)" in query
    assert "COALESCE(mem_count, CASE WHEN mem IS NOT NULL THEN count ELSE 0 END)" in query
    assert "COALESCE(hit_rate_count, CASE WHEN hit_rate IS NOT NULL THEN count ELSE 0 END)" in query
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
