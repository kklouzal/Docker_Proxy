from __future__ import annotations

import hashlib
import logging
import threading
import time
from typing import Optional

from services.db import connect
from services.proxy_context import get_proxy_id


logger = logging.getLogger(__name__)


class AuditStore:
    def _connect(self):
        return connect()

    def init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    id BIGINT PRIMARY KEY AUTO_INCREMENT,
                    proxy_id VARCHAR(64) NOT NULL DEFAULT 'default',
                    ts BIGINT NOT NULL,
                    kind VARCHAR(80) NOT NULL,
                    ok TINYINT(1) NOT NULL,
                    remote_addr VARCHAR(64),
                    user_agent VARCHAR(256),
                    detail TEXT,
                    config_sha256 CHAR(64),
                    config_text LONGTEXT,
                    KEY idx_audit_ts (ts),
                    KEY idx_audit_kind (kind),
                    KEY idx_audit_proxy_ts (proxy_id, ts)
                )
                """
            )

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

        def _clip(val: Optional[str], max_len: int) -> Optional[str]:
            if val is None:
                return None
            s = str(val)
            if max_len > 0 and len(s) > max_len:
                return s[: max_len - 1] + "…"
            return s

        kind_s = _clip((kind or "").strip(), 80) or ""
        remote_s = _clip((remote_addr or "").strip(), 64)
        ua_s = _clip((user_agent or "").strip(), 256)
        detail_s = _clip((detail or "").strip(), 1000)

        sha = None
        stored_text = None
        if config_text is not None:
            sha = hashlib.sha256(config_text.encode("utf-8", errors="replace")).hexdigest()
            if keep_config_text:
                # Bound stored config text to avoid unbounded DB growth.
                stored_text = _clip(config_text, 200_000)

        proxy_id = get_proxy_id()

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO audit_events(proxy_id, ts, kind, ok, remote_addr, user_agent, detail, config_sha256, config_text)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """,
                (
                    proxy_id,
                    int(time.time()),
                    kind_s,
                    1 if ok else 0,
                    remote_s,
                    ua_s,
                    detail_s,
                    sha,
                    stored_text,
                ),
            )

            # Keep storage bounded (last 200 events).
            conn.execute(
                "DELETE FROM audit_events WHERE id NOT IN (SELECT id FROM (SELECT id FROM audit_events ORDER BY ts DESC, id DESC LIMIT 200) AS keepers)"
            )

    def latest_config_apply(self) -> Optional[object]:
        # Returns the most recent config_apply* event (if any).
        self.init_db()
        proxy_id = get_proxy_id()
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT ts, kind, ok, remote_addr, user_agent, detail
                FROM audit_events
                WHERE proxy_id=%s AND kind LIKE 'config_apply%'
                ORDER BY ts DESC, id DESC
                LIMIT 1
                """
                ,
                (proxy_id,),
            ).fetchone()
        return row

    def prune_old_entries(self, *, retention_days: int = 30) -> None:
        """Prune old audit/config apply history.

        Note: the store also enforces a max row count on write; this adds
        time-based pruning to ensure stale history doesn't linger.
        """
        self.init_db()
        days = max(1, int(retention_days or 30))
        cutoff = int(time.time()) - (days * 24 * 60 * 60)
        with self._connect() as conn:
            conn.execute("DELETE FROM audit_events WHERE ts < %s", (int(cutoff),))


_store: Optional[AuditStore] = None
_store_lock = threading.Lock()


def get_audit_store() -> AuditStore:
    global _store
    if _store is not None:
        return _store
    with _store_lock:
        if _store is None:
            _store = AuditStore()
        return _store
