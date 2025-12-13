from __future__ import annotations

import os
import sqlite3
import time
from dataclasses import dataclass
from typing import Dict, Optional


def _now() -> int:
    return int(time.time())


@dataclass(frozen=True)
class PreloadSummary:
    # Health-ish
    first_seen: int
    last_seen: int
    last_injected: int
    last_failure: int
    last_failure_msg: str

    # Counters
    respmod_calls: int
    injected_responses: int
    injected_links: int

    skipped_non_html: int
    skipped_no_head_or_imgs: int
    skipped_unsupported_encoding: int
    skipped_incomplete_body: int
    skipped_missing_parts: int

    failures: int


class PreloadStore:
    def __init__(self, db_path: str = "/var/lib/squid-flask-proxy/preload.db") -> None:
        self.db_path = db_path

    def _connect(self) -> sqlite3.Connection:
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        conn = sqlite3.connect(self.db_path, timeout=3, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS preload_meta (
                    k TEXT PRIMARY KEY,
                    v TEXT NOT NULL
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS preload_counts (
                    k TEXT PRIMARY KEY,
                    v INTEGER NOT NULL
                );
                """
            )

            # Ensure keys exist (stable output for UI).
            for k in (
                "first_seen",
                "last_seen",
                "last_injected",
                "last_failure",
                "last_failure_msg",
            ):
                conn.execute("INSERT OR IGNORE INTO preload_meta(k,v) VALUES(?,?)", (k, "0" if k != "last_failure_msg" else ""))

            for k in (
                "respmod_calls",
                "injected_responses",
                "injected_links",
                "skipped_non_html",
                "skipped_no_head_or_imgs",
                "skipped_unsupported_encoding",
                "skipped_incomplete_body",
                "skipped_missing_parts",
                "failures",
            ):
                conn.execute("INSERT OR IGNORE INTO preload_counts(k,v) VALUES(?,0)", (k,))

    def _incr(self, conn: sqlite3.Connection, key: str, delta: int = 1) -> None:
        conn.execute(
            """
            INSERT INTO preload_counts(k,v) VALUES(?,?)
            ON CONFLICT(k) DO UPDATE SET v = v + excluded.v;
            """,
            (key, int(delta)),
        )

    def _set_meta(self, conn: sqlite3.Connection, key: str, value: str) -> None:
        conn.execute(
            """
            INSERT INTO preload_meta(k,v) VALUES(?,?)
            ON CONFLICT(k) DO UPDATE SET v = excluded.v;
            """,
            (key, value),
        )

    def record_seen(self) -> None:
        ts = _now()
        self.init_db()
        with self._connect() as conn:
            self._incr(conn, "respmod_calls", 1)
            cur = conn.execute("SELECT v FROM preload_meta WHERE k='first_seen'").fetchone()
            try:
                first = int(cur[0]) if cur else 0
            except Exception:
                first = 0
            if first <= 0:
                self._set_meta(conn, "first_seen", str(ts))
            self._set_meta(conn, "last_seen", str(ts))

    def record_injected(self, *, links_added: int) -> None:
        ts = _now()
        self.init_db()
        with self._connect() as conn:
            self._incr(conn, "injected_responses", 1)
            if links_added > 0:
                self._incr(conn, "injected_links", int(links_added))
            self._set_meta(conn, "last_injected", str(ts))
            self._set_meta(conn, "last_seen", str(ts))

    def record_skip(self, reason: str) -> None:
        self.init_db()
        key = {
            "non_html": "skipped_non_html",
            "no_head_or_imgs": "skipped_no_head_or_imgs",
            "unsupported_encoding": "skipped_unsupported_encoding",
            "incomplete_body": "skipped_incomplete_body",
            "missing_parts": "skipped_missing_parts",
        }.get((reason or "").strip(), "")
        if not key:
            return
        with self._connect() as conn:
            self._incr(conn, key, 1)

    def record_failure(self, msg: str) -> None:
        ts = _now()
        self.init_db()
        with self._connect() as conn:
            self._incr(conn, "failures", 1)
            self._set_meta(conn, "last_failure", str(ts))
            self._set_meta(conn, "last_failure_msg", (msg or "")[:400])
            self._set_meta(conn, "last_seen", str(ts))

    def summary(self) -> PreloadSummary:
        self.init_db()
        with self._connect() as conn:
            meta_rows = conn.execute("SELECT k, v FROM preload_meta").fetchall()
            cnt_rows = conn.execute("SELECT k, v FROM preload_counts").fetchall()

        meta: Dict[str, str] = {str(r[0]): str(r[1]) for r in meta_rows}
        cnt: Dict[str, int] = {str(r[0]): int(r[1]) for r in cnt_rows}

        def as_int(k: str) -> int:
            try:
                return int((meta.get(k) or "0").strip())
            except Exception:
                return 0

        return PreloadSummary(
            first_seen=as_int("first_seen"),
            last_seen=as_int("last_seen"),
            last_injected=as_int("last_injected"),
            last_failure=as_int("last_failure"),
            last_failure_msg=(meta.get("last_failure_msg") or ""),
            respmod_calls=int(cnt.get("respmod_calls") or 0),
            injected_responses=int(cnt.get("injected_responses") or 0),
            injected_links=int(cnt.get("injected_links") or 0),
            skipped_non_html=int(cnt.get("skipped_non_html") or 0),
            skipped_no_head_or_imgs=int(cnt.get("skipped_no_head_or_imgs") or 0),
            skipped_unsupported_encoding=int(cnt.get("skipped_unsupported_encoding") or 0),
            skipped_incomplete_body=int(cnt.get("skipped_incomplete_body") or 0),
            skipped_missing_parts=int(cnt.get("skipped_missing_parts") or 0),
            failures=int(cnt.get("failures") or 0),
        )


_store: Optional[PreloadStore] = None


def get_preload_store() -> PreloadStore:
    global _store
    if _store is None:
        _store = PreloadStore()
    return _store
