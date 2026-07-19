from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from typing import Any

from services.db import DATABASE_ERRORS, connect
from services.logutil import log_database_unavailable, log_exception_throttled
from services.observability_backoff import DatabaseWriteBackoff, stagger_delay_from_env
from services.proxy_context import get_proxy_id
from services.proxy_write_guard import guarded_proxy_write
from services.runtime_helpers import env_float as _env_float
from services.runtime_helpers import now_ts as _now

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Resolution:
    name: str
    table: str
    seconds: int


RESOLUTIONS: list[Resolution] = [
    Resolution("1s", "ts_1s", 1),
    Resolution("1m", "ts_1m", 60),
    Resolution("1h", "ts_1h", 60 * 60),
    Resolution("1d", "ts_1d", 60 * 60 * 24),
    Resolution("1w", "ts_1w", 60 * 60 * 24 * 7),
    Resolution("1mo", "ts_1mo", 60 * 60 * 24 * 30),
    Resolution("1y", "ts_1y", 60 * 60 * 24 * 365),
]
RESOLUTION_BY_NAME = {resolution.name: resolution for resolution in RESOLUTIONS}


def _get_metric(stats: dict[str, Any], path: str) -> float | None:
    # path like "cpu.util_percent"
    cur: Any = stats
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    if cur is None:
        return None
    try:
        return float(cur)
    except (TypeError, ValueError):
        return None


class TimeSeriesStore:
    def __init__(self) -> None:
        self._started = False
        self._start_lock = threading.Lock()
        self._db_initialized = False
        self._db_init_lock = threading.Lock()

    def _connect(self):
        return connect()

    def _mark_db_uninitialized(self) -> None:
        with self._db_init_lock:
            self._db_initialized = False

    def _is_missing_table_error(self, exc: BaseException) -> bool:
        text = str(exc).lower()
        return "doesn't exist" in text or "does not exist" in text or "1146" in text

    def _with_missing_table_retry(self, fn):
        try:
            return fn()
        except Exception as exc:
            if not self._is_missing_table_error(exc):
                raise
            self._mark_db_uninitialized()
            self.init_db()
            return fn()

    def init_db(self) -> None:
        if self._db_initialized:
            return
        with self._db_init_lock:
            if self._db_initialized:
                return
            with self._connect() as conn:
                for r in RESOLUTIONS:
                    conn.execute(
                        f"""
                        CREATE TABLE IF NOT EXISTS {r.table} (
                            proxy_id VARCHAR(64) NOT NULL DEFAULT 'default',
                            ts BIGINT NOT NULL,
                            count BIGINT NOT NULL,
                            cpu DOUBLE,
                            mem DOUBLE,
                            disk_used DOUBLE,
                            cache_dir_size DOUBLE,
                            hit_rate DOUBLE,
                            PRIMARY KEY(proxy_id, ts)
                        )
                        """,
                    )
            self._db_initialized = True

    def insert_snapshot(self, stats: dict[str, Any], ts: int | None = None) -> None:
        self.init_db()
        ts_i = int(ts or _now())

        cpu = _get_metric(stats, "cpu.util_percent")
        mem = _get_metric(stats, "memory.used_percent")
        disk_used = _get_metric(stats, "storage.cache_fs_used_bytes")
        cache_dir_size = _get_metric(stats, "storage.cache_dir_size_bytes")
        hit_rate = _get_metric(stats, "squid.hit_rate.request_hit_ratio")
        proxy_id = get_proxy_id()

        def write_snapshot() -> None:
            with self._connect() as conn:
                with guarded_proxy_write(conn, proxy_id) as guard:
                    conn.execute(
                        """
                        INSERT INTO ts_1s(proxy_id, ts, count, cpu, mem, disk_used, cache_dir_size, hit_rate)
                        VALUES(%s,%s,%s,%s,%s,%s,%s,%s) AS incoming
                        ON DUPLICATE KEY UPDATE
                            count = incoming.count,
                            cpu = incoming.cpu,
                            mem = incoming.mem,
                            disk_used = incoming.disk_used,
                            cache_dir_size = incoming.cache_dir_size,
                            hit_rate = incoming.hit_rate
                        """,
                        (guard.proxy_id, ts_i, 1, cpu, mem, disk_used, cache_dir_size, hit_rate),
                    )

        self._with_missing_table_retry(write_snapshot)

    def _rollup(
        self,
        src_table: str,
        dst_table: str,
        dst_seconds: int,
        cutoff_end_ts: int,
        proxy_id: str,
        *,
        max_dst_buckets: int = 4,
    ) -> None:
        # Roll complete destination buckets with bucket_start < aligned_end.
        aligned_end = (cutoff_end_ts // dst_seconds) * dst_seconds
        if aligned_end <= 0:
            return
        bucket_limit = max(1, int(max_dst_buckets))

        def rollup_bucket() -> None:
            with self._connect() as conn:
                with guarded_proxy_write(conn, proxy_id) as guard:
                    canonical_proxy_id = guard.proxy_id
                    first_row = conn.execute(
                        f"SELECT MIN(ts) FROM {src_table} WHERE proxy_id = %s AND ts < %s",
                        (canonical_proxy_id, aligned_end),
                    ).fetchone()
                    first_ts = int(first_row[0]) if first_row and first_row[0] is not None else None
                    if first_ts is None:
                        return
                    range_start = (first_ts // dst_seconds) * dst_seconds
                    range_end = min(aligned_end, range_start + (dst_seconds * bucket_limit))
                    if range_end <= range_start:
                        return
                    conn.execute(
                        f"""
                        INSERT INTO {dst_table}(proxy_id, ts, count, cpu, mem, disk_used, cache_dir_size, hit_rate)
                        SELECT * FROM (
                            SELECT
                                proxy_id,
                                FLOOR(ts / %s) * %s AS bucket_start,
                                SUM(count) AS count,
                                CASE WHEN SUM(count) > 0 THEN SUM(cpu * count) / SUM(count) ELSE NULL END AS cpu,
                                CASE WHEN SUM(count) > 0 THEN SUM(mem * count) / SUM(count) ELSE NULL END AS mem,
                                CASE WHEN SUM(count) > 0 THEN SUM(disk_used * count) / SUM(count) ELSE NULL END AS disk_used,
                                CASE WHEN SUM(count) > 0 THEN SUM(cache_dir_size * count) / SUM(count) ELSE NULL END AS cache_dir_size,
                                CASE WHEN SUM(count) > 0 THEN SUM(hit_rate * count) / SUM(count) ELSE NULL END AS hit_rate
                            FROM {src_table}
                            WHERE proxy_id = %s AND ts >= %s AND ts < %s
                            GROUP BY proxy_id, bucket_start
                        ) AS incoming
                        ON DUPLICATE KEY UPDATE
                            cpu = CASE WHEN {dst_table}.count + incoming.count > 0 AND NOT ({dst_table}.cpu IS NULL AND incoming.cpu IS NULL) THEN (COALESCE({dst_table}.cpu, 0) * {dst_table}.count + COALESCE(incoming.cpu, 0) * incoming.count) / ({dst_table}.count + incoming.count) ELSE NULL END,
                            mem = CASE WHEN {dst_table}.count + incoming.count > 0 AND NOT ({dst_table}.mem IS NULL AND incoming.mem IS NULL) THEN (COALESCE({dst_table}.mem, 0) * {dst_table}.count + COALESCE(incoming.mem, 0) * incoming.count) / ({dst_table}.count + incoming.count) ELSE NULL END,
                            disk_used = CASE WHEN {dst_table}.count + incoming.count > 0 AND NOT ({dst_table}.disk_used IS NULL AND incoming.disk_used IS NULL) THEN (COALESCE({dst_table}.disk_used, 0) * {dst_table}.count + COALESCE(incoming.disk_used, 0) * incoming.count) / ({dst_table}.count + incoming.count) ELSE NULL END,
                            cache_dir_size = CASE WHEN {dst_table}.count + incoming.count > 0 AND NOT ({dst_table}.cache_dir_size IS NULL AND incoming.cache_dir_size IS NULL) THEN (COALESCE({dst_table}.cache_dir_size, 0) * {dst_table}.count + COALESCE(incoming.cache_dir_size, 0) * incoming.count) / ({dst_table}.count + incoming.count) ELSE NULL END,
                            hit_rate = CASE WHEN {dst_table}.count + incoming.count > 0 AND NOT ({dst_table}.hit_rate IS NULL AND incoming.hit_rate IS NULL) THEN (COALESCE({dst_table}.hit_rate, 0) * {dst_table}.count + COALESCE(incoming.hit_rate, 0) * incoming.count) / ({dst_table}.count + incoming.count) ELSE NULL END,
                            count = {dst_table}.count + incoming.count
                        """,
                        (dst_seconds, dst_seconds, canonical_proxy_id, range_start, range_end),
                    )

                    conn.execute(
                        f"DELETE FROM {src_table} WHERE proxy_id = %s AND ts >= %s AND ts < %s",
                        (canonical_proxy_id, range_start, range_end),
                    )

        self._with_missing_table_retry(rollup_bucket)

    def rollup_and_prune(self, ts: int | None = None) -> None:
        self.init_db()
        now = int(ts or _now())
        proxy_id = get_proxy_id()

        # Retention cutoffs (seconds): keep finer data for these windows.
        keep_1s = 60
        keep_1m = 60 * 60
        keep_1h = 60 * 60 * 24
        keep_1d = 60 * 60 * 24 * 7
        keep_1w = 60 * 60 * 24 * 30
        keep_1mo = 60 * 60 * 24 * 365
        keep_1y = 60 * 60 * 24 * 365 * 10

        # 1s -> 1m
        self._rollup("ts_1s", "ts_1m", 60, now - keep_1s, proxy_id, max_dst_buckets=120)
        # 1m -> 1h
        self._rollup("ts_1m", "ts_1h", 60 * 60, now - keep_1m, proxy_id, max_dst_buckets=48)
        # 1h -> 1d
        self._rollup("ts_1h", "ts_1d", 60 * 60 * 24, now - keep_1h, proxy_id, max_dst_buckets=3)
        # 1d -> 1w
        self._rollup("ts_1d", "ts_1w", 60 * 60 * 24 * 7, now - keep_1d, proxy_id, max_dst_buckets=2)
        # 1w -> 1mo
        self._rollup("ts_1w", "ts_1mo", 60 * 60 * 24 * 30, now - keep_1w, proxy_id, max_dst_buckets=2)
        # 1mo -> 1y
        self._rollup("ts_1mo", "ts_1y", 60 * 60 * 24 * 365, now - keep_1mo, proxy_id, max_dst_buckets=1)

        # Prune oldest year-level data beyond keep_1y.
        cutoff_y = now - keep_1y
        aligned_y = (cutoff_y // (60 * 60 * 24 * 365)) * (60 * 60 * 24 * 365)
        if aligned_y > 0:
            self._with_missing_table_retry(
                lambda: self._delete_old_year_points(
                    proxy_id=proxy_id,
                    aligned_y=aligned_y,
                ),
            )

    def _delete_old_year_points(self, *, proxy_id: str, aligned_y: int) -> None:
        with self._connect() as conn:
            with guarded_proxy_write(conn, proxy_id) as guard:
                conn.execute(
                    "DELETE FROM ts_1y WHERE proxy_id = %s AND ts < %s",
                    (guard.proxy_id, aligned_y),
                )

    def summary(self) -> dict[str, Any]:
        # Returns weighted averages for recent windows.
        now = _now()

        windows = [
            ("60s", "ts_1s", now - 60),
            ("1h", "ts_1m", now - 60 * 60),
            ("24h", "ts_1h", now - 60 * 60 * 24),
            ("7d", "ts_1d", now - 60 * 60 * 24 * 7),
        ]
        proxy_id = get_proxy_id()

        out: dict[str, Any] = {}

        def read_summary() -> None:
            with self._connect() as conn:
                for label, table, since in windows:
                    row = conn.execute(
                        f"""
                        SELECT
                            SUM(count) AS cnt,
                            CASE WHEN SUM(count) > 0 THEN SUM(cpu * count)/SUM(count) ELSE NULL END AS cpu,
                            CASE WHEN SUM(count) > 0 THEN SUM(mem * count)/SUM(count) ELSE NULL END AS mem,
                            CASE WHEN SUM(count) > 0 THEN SUM(hit_rate * count)/SUM(count) ELSE NULL END AS hit
                        FROM {table}
                        WHERE proxy_id = %s AND ts >= %s
                        """,
                        (proxy_id, int(since)),
                    ).fetchone()
                    out[label] = {
                        "count": int(row[0] or 0),
                        "cpu_avg": row[1],
                        "mem_avg": row[2],
                        "hit_rate_avg": row[3],
                    }

        self.init_db()
        self._with_missing_table_retry(read_summary)
        return out

    def query(
        self,
        resolution: str,
        since: int,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        res = RESOLUTION_BY_NAME.get(resolution) or RESOLUTIONS[0]

        lim = max(10, min(2000, int(limit)))
        proxy_id = get_proxy_id()
        self.init_db()

        def read_rows():
            with self._connect() as conn:
                return conn.execute(
                    f"SELECT ts, count, cpu, mem, hit_rate FROM {res.table} WHERE proxy_id = %s AND ts >= %s ORDER BY ts ASC LIMIT %s",
                    (proxy_id, int(since), lim),
                ).fetchall()

        rows = self._with_missing_table_retry(read_rows)

        return [
            {
                "ts": int(r[0]),
                "count": int(r[1]),
                "cpu": r[2],
                "mem": r[3],
                "hit_rate": r[4],
            }
            for r in rows
        ]

    def start_background(self, get_stats_func) -> None:
        with self._start_lock:
            if self._started:
                return

            sample_backoff = DatabaseWriteBackoff.from_env(
                "TIMESERIES_SAMPLE_DB",
                default_base=5.0,
                default_max=120.0,
            )
            rollup_backoff = DatabaseWriteBackoff.from_env(
                "TIMESERIES_ROLLUP_DB",
                default_base=30.0,
                default_max=300.0,
            )
            rollup_interval = _env_float(
                "TIMESERIES_ROLLUP_INTERVAL_SECONDS",
                300.0,
                minimum=30.0,
                maximum=86400.0,
            )
            initial_jitter = stagger_delay_from_env(
                "TIMESERIES_STARTUP_JITTER_SECONDS",
                15.0,
                maximum=300.0,
            )

            def loop() -> None:
                next_rollup_at = time.monotonic() + initial_jitter + rollup_interval
                while True:
                    now_monotonic = time.monotonic()
                    try:
                        if sample_backoff.can_attempt(now_monotonic):
                            stats = get_stats_func()
                            self.insert_snapshot(stats)
                            sample_backoff.record_success()
                    except DATABASE_ERRORS as exc:
                        delay = sample_backoff.record_failure(now_monotonic)
                        log_database_unavailable(
                            logger,
                            "timeseries_store.sampler.db",
                            (
                                "timeseries sampler deferred snapshot write while MySQL "
                                f"is unavailable; retrying in about {delay:.1f}s"
                            ),
                            exc,
                        )
                    except Exception:
                        log_exception_throttled(
                            logger,
                            "timeseries_store.sampler",
                            interval_seconds=30,
                            message="timeseries sampler iteration failed",
                        )

                    now_monotonic = time.monotonic()
                    if now_monotonic >= next_rollup_at and rollup_backoff.can_attempt(
                        now_monotonic
                    ):
                        try:
                            self.rollup_and_prune()
                            rollup_backoff.record_success()
                            next_rollup_at = now_monotonic + rollup_interval
                        except DATABASE_ERRORS as exc:
                            delay = rollup_backoff.record_failure(now_monotonic)
                            next_rollup_at = now_monotonic + delay
                            log_database_unavailable(
                                logger,
                                "timeseries_store.rollup.db",
                                (
                                    "timeseries rollup/prune deferred while MySQL is "
                                    f"unavailable; retrying in about {delay:.1f}s"
                                ),
                                exc,
                            )
                        except Exception:
                            next_rollup_at = now_monotonic + rollup_interval
                            log_exception_throttled(
                                logger,
                                "timeseries_store.rollup",
                                interval_seconds=60,
                                message="timeseries rollup/prune iteration failed",
                            )
                    elif now_monotonic >= next_rollup_at:
                        next_rollup_at = max(
                            next_rollup_at + 1.0,
                            rollup_backoff.next_attempt_at,
                        )

                    time.sleep(1.0)

            t = threading.Thread(target=loop, name="timeseries-sampler", daemon=True)
            t.start()
            self._started = True


_store: TimeSeriesStore | None = None
_store_lock = threading.Lock()


def get_timeseries_store() -> TimeSeriesStore:
    global _store
    if _store is not None:
        return _store
    with _store_lock:
        if _store is None:
            _store = TimeSeriesStore()
        return _store
