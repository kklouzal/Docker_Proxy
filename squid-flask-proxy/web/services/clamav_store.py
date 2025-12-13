from __future__ import annotations

import os
import sqlite3
import time
from dataclasses import dataclass
from typing import Dict, List, Optional


def _now() -> int:
    return int(time.time())


@dataclass(frozen=True)
class ClamavSummary:
    first_seen: int
    last_seen: int
    last_infected: int
    last_error: int
    last_error_msg: str

    respmod_calls: int
    scanned: int
    clean: int
    infected: int

    skipped_image_video: int
    skipped_too_large: int
    skipped_unsupported_encoding: int
    skipped_incomplete_body: int
    skipped_missing_parts: int

    errors: int


@dataclass(frozen=True)
class ClamavEvent:
    ts: int
    kind: str  # 'infected'|'error'
    url: str
    content_type: str
    content_encoding: str
    size_bytes: int
    detail: str


class ClamavStore:
    def __init__(self, db_path: str = "/var/lib/squid-flask-proxy/clamav.db") -> None:
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
                CREATE TABLE IF NOT EXISTS clamav_meta (
                    k TEXT PRIMARY KEY,
                    v TEXT NOT NULL
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS clamav_counts (
                    k TEXT PRIMARY KEY,
                    v INTEGER NOT NULL
                );
                """
            )

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS clamav_settings (
                    k TEXT PRIMARY KEY,
                    v TEXT NOT NULL
                );
                """
            )

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS clamav_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts INTEGER NOT NULL,
                    kind TEXT NOT NULL,
                    url TEXT NOT NULL,
                    content_type TEXT NOT NULL,
                    content_encoding TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    detail TEXT NOT NULL
                );
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_clamav_events_ts ON clamav_events(ts DESC);"
            )

            for k in ("first_seen", "last_seen", "last_infected", "last_error", "last_error_msg"):
                conn.execute(
                    "INSERT OR IGNORE INTO clamav_meta(k,v) VALUES(?,?)",
                    (k, "0" if k != "last_error_msg" else ""),
                )

            for k in (
                "respmod_calls",
                "scanned",
                "clean",
                "infected",
                "skipped_image_video",
                "skipped_too_large",
                "skipped_unsupported_encoding",
                "skipped_incomplete_body",
                "skipped_missing_parts",
                "errors",
            ):
                conn.execute("INSERT OR IGNORE INTO clamav_counts(k,v) VALUES(?,0)", (k,))

            # Defaults
            conn.execute(
                "INSERT OR IGNORE INTO clamav_settings(k,v) VALUES('max_scan_bytes', '134217728')"
            )

    def record_event(
        self,
        *,
        kind: str,
        url: str = "",
        content_type: str = "",
        content_encoding: str = "",
        size_bytes: int = 0,
        detail: str = "",
    ) -> None:
        # Intentionally used only for non-OK outcomes (infected/errors) to avoid huge write volume.
        k = (kind or "").strip().lower()
        if k not in ("infected", "error"):
            return

        ts = _now()
        self.init_db()
        u = (url or "")[:700]
        ct = (content_type or "")[:120]
        ce = (content_encoding or "")[:60]
        d = (detail or "")[:800]
        try:
            sb = int(size_bytes)
        except Exception:
            sb = 0
        if sb < 0:
            sb = 0

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO clamav_events(ts, kind, url, content_type, content_encoding, size_bytes, detail)
                VALUES(?,?,?,?,?,?,?)
                """,
                (int(ts), k, u, ct, ce, int(sb), d),
            )

    def list_recent_events(self, *, limit: int = 50) -> List[ClamavEvent]:
        self.init_db()
        try:
            lim = int(limit)
        except Exception:
            lim = 50
        lim = max(1, min(500, lim))

        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT ts, kind, url, content_type, content_encoding, size_bytes, detail
                FROM clamav_events
                ORDER BY ts DESC, id DESC
                LIMIT ?
                """,
                (int(lim),),
            ).fetchall()

        out: List[ClamavEvent] = []
        for r in rows:
            try:
                out.append(
                    ClamavEvent(
                        ts=int(r[0] or 0),
                        kind=str(r[1] or ""),
                        url=str(r[2] or ""),
                        content_type=str(r[3] or ""),
                        content_encoding=str(r[4] or ""),
                        size_bytes=int(r[5] or 0),
                        detail=str(r[6] or ""),
                    )
                )
            except Exception:
                continue
        return out

    def get_settings(self) -> Dict[str, int]:
        self.init_db()
        with self._connect() as conn:
            rows = conn.execute("SELECT k, v FROM clamav_settings").fetchall()

        raw: Dict[str, str] = {str(r[0]): str(r[1]) for r in rows}

        def as_int(k: str, default: int) -> int:
            try:
                return int((raw.get(k) or str(default)).strip())
            except Exception:
                return default

        return {
            "max_scan_bytes": as_int("max_scan_bytes", 134217728),
        }

    def set_settings(self, *, max_scan_bytes: int) -> None:
        self.init_db()
        v = int(max_scan_bytes)
        if v < 1:
            v = 134217728
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO clamav_settings(k,v) VALUES('max_scan_bytes', ?)
                ON CONFLICT(k) DO UPDATE SET v = excluded.v;
                """,
                (str(v),),
            )

    def _incr(self, conn: sqlite3.Connection, key: str, delta: int = 1) -> None:
        conn.execute(
            """
            INSERT INTO clamav_counts(k,v) VALUES(?,?)
            ON CONFLICT(k) DO UPDATE SET v = v + excluded.v;
            """,
            (key, int(delta)),
        )

    def _set_meta(self, conn: sqlite3.Connection, key: str, value: str) -> None:
        conn.execute(
            """
            INSERT INTO clamav_meta(k,v) VALUES(?,?)
            ON CONFLICT(k) DO UPDATE SET v = excluded.v;
            """,
            (key, value),
        )

    def record_seen(self) -> None:
        ts = _now()
        self.init_db()
        with self._connect() as conn:
            self._incr(conn, "respmod_calls", 1)
            cur = conn.execute("SELECT v FROM clamav_meta WHERE k='first_seen'").fetchone()
            try:
                first = int(cur[0]) if cur else 0
            except Exception:
                first = 0
            if first <= 0:
                self._set_meta(conn, "first_seen", str(ts))
            self._set_meta(conn, "last_seen", str(ts))

    def record_skip(self, reason: str) -> None:
        self.init_db()
        key = {
            "image_video": "skipped_image_video",
            "too_large": "skipped_too_large",
            "unsupported_encoding": "skipped_unsupported_encoding",
            "incomplete_body": "skipped_incomplete_body",
            "missing_parts": "skipped_missing_parts",
        }.get((reason or "").strip(), "")
        if not key:
            return
        with self._connect() as conn:
            self._incr(conn, key, 1)

    def record_scanned(self, *, clean: bool, infected: bool) -> None:
        ts = _now()
        self.init_db()
        with self._connect() as conn:
            self._incr(conn, "scanned", 1)
            if clean:
                self._incr(conn, "clean", 1)
            if infected:
                self._incr(conn, "infected", 1)
                self._set_meta(conn, "last_infected", str(ts))
            self._set_meta(conn, "last_seen", str(ts))

    def record_error(self, msg: str) -> None:
        ts = _now()
        self.init_db()
        with self._connect() as conn:
            self._incr(conn, "errors", 1)
            self._set_meta(conn, "last_error", str(ts))
            self._set_meta(conn, "last_error_msg", (msg or "")[:400])
            self._set_meta(conn, "last_seen", str(ts))

    def summary(self) -> ClamavSummary:
        self.init_db()
        with self._connect() as conn:
            meta_rows = conn.execute("SELECT k, v FROM clamav_meta").fetchall()
            cnt_rows = conn.execute("SELECT k, v FROM clamav_counts").fetchall()

        meta: Dict[str, str] = {str(r[0]): str(r[1]) for r in meta_rows}
        cnt: Dict[str, int] = {str(r[0]): int(r[1]) for r in cnt_rows}

        def as_int(k: str) -> int:
            try:
                return int((meta.get(k) or "0").strip())
            except Exception:
                return 0

        return ClamavSummary(
            first_seen=as_int("first_seen"),
            last_seen=as_int("last_seen"),
            last_infected=as_int("last_infected"),
            last_error=as_int("last_error"),
            last_error_msg=(meta.get("last_error_msg") or ""),
            respmod_calls=int(cnt.get("respmod_calls") or 0),
            scanned=int(cnt.get("scanned") or 0),
            clean=int(cnt.get("clean") or 0),
            infected=int(cnt.get("infected") or 0),
            skipped_image_video=int(cnt.get("skipped_image_video") or 0),
            skipped_too_large=int(cnt.get("skipped_too_large") or 0),
            skipped_unsupported_encoding=int(cnt.get("skipped_unsupported_encoding") or 0),
            skipped_incomplete_body=int(cnt.get("skipped_incomplete_body") or 0),
            skipped_missing_parts=int(cnt.get("skipped_missing_parts") or 0),
            errors=int(cnt.get("errors") or 0),
        )


_store: Optional[ClamavStore] = None


def get_clamav_store() -> ClamavStore:
    global _store
    if _store is None:
        _store = ClamavStore()
    return _store
