from __future__ import annotations

import os
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import logging

from services.logutil import log_exception_throttled


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Resolution:
    name: str
    table: str
    seconds: int


RESOLUTIONS: List[Resolution] = [
    Resolution("1s", "ts_1s", 1),
    Resolution("1m", "ts_1m", 60),
    Resolution("1h", "ts_1h", 60 * 60),
    Resolution("1d", "ts_1d", 60 * 60 * 24),
    Resolution("1w", "ts_1w", 60 * 60 * 24 * 7),
    Resolution("1mo", "ts_1mo", 60 * 60 * 24 * 30),
    Resolution("1y", "ts_1y", 60 * 60 * 24 * 365),
]


def _now() -> int:
    return int(time.time())


def _get_metric(stats: Dict[str, Any], path: str) -> Optional[float]:
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
    def __init__(self, db_path: str = "/var/lib/squid-flask-proxy/timeseries.db"):
        self.db_path = db_path

        self._started = False
        self._start_lock = threading.Lock()

    def _connect(self) -> sqlite3.Connection:
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        conn = sqlite3.connect(self.db_path, timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA busy_timeout=30000;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def init_db(self) -> None:
        with self._connect() as conn:
            for r in RESOLUTIONS:
                conn.execute(
                    f"""
                    CREATE TABLE IF NOT EXISTS {r.table} (
                        ts INTEGER PRIMARY KEY,
                        count INTEGER NOT NULL,
                        cpu REAL,
                        mem REAL,
                        disk_used REAL,
                        cache_dir_size REAL,
                        hit_rate REAL
                    );
                    """
                )
                conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{r.table}_ts ON {r.table}(ts DESC);")

    def insert_snapshot(self, stats: Dict[str, Any], ts: Optional[int] = None) -> None:
        self.init_db()
        ts_i = int(ts or _now())

        cpu = _get_metric(stats, "cpu.util_percent")
        mem = _get_metric(stats, "memory.used_percent")
        disk_used = _get_metric(stats, "storage.cache_fs_used_bytes")
        cache_dir_size = _get_metric(stats, "storage.cache_dir_size_bytes")
        hit_rate = _get_metric(stats, "squid.hit_rate.request_hit_ratio")

        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO ts_1s(ts, count, cpu, mem, disk_used, cache_dir_size, hit_rate)
                VALUES(?,?,?,?,?,?,?)
                """,
                (ts_i, 1, cpu, mem, disk_used, cache_dir_size, hit_rate),
            )

    def _rollup(self, src_table: str, dst_table: str, dst_seconds: int, cutoff_end_ts: int) -> None:
        # Roll complete destination buckets with bucket_start < aligned_end.
        aligned_end = (cutoff_end_ts // dst_seconds) * dst_seconds
        if aligned_end <= 0:
            return

        with self._connect() as conn:
            conn.execute(
                f"""
                INSERT OR REPLACE INTO {dst_table}(ts, count, cpu, mem, disk_used, cache_dir_size, hit_rate)
                SELECT
                    (ts / ?) * ? AS bucket_start,
                    SUM(count) AS cnt,
                    CASE WHEN SUM(count) > 0 THEN SUM(cpu * count) / SUM(count) ELSE NULL END,
                    CASE WHEN SUM(count) > 0 THEN SUM(mem * count) / SUM(count) ELSE NULL END,
                    CASE WHEN SUM(count) > 0 THEN SUM(disk_used * count) / SUM(count) ELSE NULL END,
                    CASE WHEN SUM(count) > 0 THEN SUM(cache_dir_size * count) / SUM(count) ELSE NULL END,
                    CASE WHEN SUM(count) > 0 THEN SUM(hit_rate * count) / SUM(count) ELSE NULL END
                FROM {src_table}
                WHERE ts < ?
                GROUP BY bucket_start
                """,
                (dst_seconds, dst_seconds, aligned_end),
            )

            conn.execute(f"DELETE FROM {src_table} WHERE ts < ?", (aligned_end,))

    def rollup_and_prune(self, ts: Optional[int] = None) -> None:
        self.init_db()
        now = int(ts or _now())

        # Retention cutoffs (seconds): keep finer data for these windows.
        keep_1s = 60
        keep_1m = 60 * 60
        keep_1h = 60 * 60 * 24
        keep_1d = 60 * 60 * 24 * 7
        keep_1w = 60 * 60 * 24 * 30
        keep_1mo = 60 * 60 * 24 * 365
        keep_1y = 60 * 60 * 24 * 365 * 10

        # 1s -> 1m
        self._rollup("ts_1s", "ts_1m", 60, now - keep_1s)
        # 1m -> 1h
        self._rollup("ts_1m", "ts_1h", 60 * 60, now - keep_1m)
        # 1h -> 1d
        self._rollup("ts_1h", "ts_1d", 60 * 60 * 24, now - keep_1h)
        # 1d -> 1w
        self._rollup("ts_1d", "ts_1w", 60 * 60 * 24 * 7, now - keep_1d)
        # 1w -> 1mo
        self._rollup("ts_1w", "ts_1mo", 60 * 60 * 24 * 30, now - keep_1w)
        # 1mo -> 1y
        self._rollup("ts_1mo", "ts_1y", 60 * 60 * 24 * 365, now - keep_1mo)

        # Prune oldest year-level data beyond keep_1y.
        cutoff_y = now - keep_1y
        aligned_y = (cutoff_y // (60 * 60 * 24 * 365)) * (60 * 60 * 24 * 365)
        if aligned_y > 0:
            with self._connect() as conn:
                conn.execute("DELETE FROM ts_1y WHERE ts < ?", (aligned_y,))

    def summary(self) -> Dict[str, Any]:
        # Returns weighted averages for recent windows.
        now = _now()

        windows = [
            ("60s", "ts_1s", now - 60),
            ("1h", "ts_1m", now - 60 * 60),
            ("24h", "ts_1h", now - 60 * 60 * 24),
            ("7d", "ts_1d", now - 60 * 60 * 24 * 7),
        ]

        out: Dict[str, Any] = {}
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
                    WHERE ts >= ?
                    """,
                    (int(since),),
                ).fetchone()
                out[label] = {
                    "count": int(row[0] or 0),
                    "cpu_avg": row[1],
                    "mem_avg": row[2],
                    "hit_rate_avg": row[3],
                }
        return out

    def query(self, resolution: str, since: int, limit: int = 500) -> List[Dict[str, Any]]:
        res = next((r for r in RESOLUTIONS if r.name == resolution), None)
        if not res:
            res = RESOLUTIONS[0]

        lim = max(10, min(2000, int(limit)))
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT ts, count, cpu, mem, hit_rate FROM {res.table} WHERE ts >= ? ORDER BY ts ASC LIMIT ?",
                (int(since), lim),
            ).fetchall()

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
            self._started = True

        self.init_db()

        def loop() -> None:
            tick = 0
            while True:
                try:
                    stats = get_stats_func()
                    self.insert_snapshot(stats)
                    tick += 1
                    if tick % 30 == 0:
                        self.rollup_and_prune()
                except Exception:
                    log_exception_throttled(
                        logger,
                        "timeseries_store.sampler",
                        interval_seconds=30,
                        message="timeseries sampler iteration failed",
                    )
                time.sleep(1.0)

        t = threading.Thread(target=loop, name="timeseries-sampler", daemon=True)
        t.start()


_store: Optional[TimeSeriesStore] = None


def get_timeseries_store() -> TimeSeriesStore:
    global _store
    if _store is None:
        _store = TimeSeriesStore()
    return _store
