from __future__ import annotations

import hashlib
import os
import sqlite3
import time
from typing import Optional


class AuditStore:
    def __init__(self, db_path: str = "/var/lib/squid-flask-proxy/audit.db"):
        self.db_path = db_path

    def _connect(self) -> sqlite3.Connection:
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        conn = sqlite3.connect(self.db_path, timeout=3)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA busy_timeout=3000;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts INTEGER NOT NULL,
                    kind TEXT NOT NULL,
                    ok INTEGER NOT NULL,
                    remote_addr TEXT,
                    user_agent TEXT,
                    detail TEXT,
                    config_sha256 TEXT,
                    config_text TEXT
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(ts DESC);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_kind ON audit_events(kind);")

    def record(
        self,
        kind: str,
        ok: bool,
        remote_addr: Optional[str] = None,
        user_agent: Optional[str] = None,
        detail: Optional[str] = None,
        config_text: Optional[str] = None,
        keep_config_text: bool = True,
    ) -> None:
        self.init_db()

        sha = None
        stored_text = None
        if config_text is not None:
            sha = hashlib.sha256(config_text.encode("utf-8", errors="replace")).hexdigest()
            if keep_config_text:
                stored_text = config_text

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO audit_events(ts, kind, ok, remote_addr, user_agent, detail, config_sha256, config_text)
                VALUES(?,?,?,?,?,?,?,?)
                """,
                (
                    int(time.time()),
                    kind,
                    1 if ok else 0,
                    remote_addr,
                    user_agent,
                    detail,
                    sha,
                    stored_text,
                ),
            )

            # Keep storage bounded (last 200 events).
            conn.execute(
                "DELETE FROM audit_events WHERE id NOT IN (SELECT id FROM audit_events ORDER BY ts DESC, id DESC LIMIT 200)"
            )

    def latest_config_apply(self) -> Optional[sqlite3.Row]:
        # Returns the most recent config_apply* event (if any).
        self.init_db()
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT ts, kind, ok, remote_addr, user_agent, detail
                FROM audit_events
                WHERE kind LIKE 'config_apply%'
                ORDER BY ts DESC, id DESC
                LIMIT 1
                """
            ).fetchone()
        return row

    def _checkpoint_and_vacuum(self) -> None:
        # Best-effort compaction. VACUUM may fail if the DB is busy.
        try:
            with self._connect() as conn:
                try:
                    conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
                except Exception:
                    pass
                try:
                    conn.execute("VACUUM;")
                except Exception:
                    pass
        except Exception:
            pass

    def prune_old_entries(self, *, retention_days: int = 30, vacuum: bool = True) -> None:
        """Prune old audit/config apply history.

        Note: the store also enforces a max row count on write; this adds
        time-based pruning to ensure stale history doesn't linger.
        """
        self.init_db()
        days = max(1, int(retention_days or 30))
        cutoff = int(time.time()) - (days * 24 * 60 * 60)
        with self._connect() as conn:
            conn.execute("DELETE FROM audit_events WHERE ts < ?", (int(cutoff),))
        if vacuum:
            self._checkpoint_and_vacuum()


_store: Optional[AuditStore] = None


def get_audit_store() -> AuditStore:
    global _store
    if _store is None:
        _store = AuditStore()
    return _store
