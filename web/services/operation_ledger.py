from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any, Optional

from services.db import connect
from services.proxy_context import normalize_proxy_id

OPERATION_STATUSES = ("pending", "applying", "applied", "failed")
TERMINAL_STATUSES = {"applied", "failed"}


@dataclass(frozen=True)
class ProxyOperation:
    operation_id: int
    proxy_id: str
    status: str
    operation_type: str
    subject: str
    summary: str
    target_kind: str
    target_ref: str
    rollback_kind: str
    rollback_ref: str
    request_hash: str
    detail: str
    created_by: str
    created_ts: int
    started_ts: int
    completed_ts: int
    updated_ts: int

    @property
    def can_revert(self) -> bool:
        return bool(self.rollback_kind and self.rollback_ref)

    def to_dict(self) -> dict[str, Any]:
        return {
            "operation_id": self.operation_id,
            "proxy_id": self.proxy_id,
            "status": self.status,
            "operation_type": self.operation_type,
            "subject": self.subject,
            "summary": self.summary,
            "target_kind": self.target_kind,
            "target_ref": self.target_ref,
            "rollback_kind": self.rollback_kind,
            "rollback_ref": self.rollback_ref,
            "request_hash": self.request_hash,
            "detail": self.detail,
            "created_by": self.created_by,
            "created_ts": self.created_ts,
            "started_ts": self.started_ts,
            "completed_ts": self.completed_ts,
            "updated_ts": self.updated_ts,
            "can_revert": self.can_revert,
        }


class OperationLedger:
    _SELECT_COLUMNS = "id, proxy_id, status, operation_type, subject, summary, target_kind, target_ref, rollback_kind, rollback_ref, request_hash, detail, created_by, created_ts, started_ts, completed_ts, updated_ts"

    def __init__(self) -> None:
        self._schema_ready = False
        self._schema_lock = threading.Lock()

    def _connect(self):
        return connect()

    def init_db(self) -> None:
        if self._schema_ready:
            return
        with self._schema_lock:
            if self._schema_ready:
                return
            with self._connect() as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS proxy_operations (
                    id BIGINT PRIMARY KEY AUTO_INCREMENT,
                    proxy_id VARCHAR(64) NOT NULL,
                    status VARCHAR(32) NOT NULL DEFAULT 'pending',
                    operation_type VARCHAR(64) NOT NULL DEFAULT 'sync',
                    subject VARCHAR(255) NOT NULL DEFAULT '',
                    summary VARCHAR(512) NOT NULL DEFAULT '',
                    target_kind VARCHAR(64) NOT NULL DEFAULT '',
                    target_ref VARCHAR(255) NOT NULL DEFAULT '',
                    rollback_kind VARCHAR(64) NOT NULL DEFAULT '',
                    rollback_ref VARCHAR(255) NOT NULL DEFAULT '',
                    request_hash CHAR(64) NOT NULL DEFAULT '',
                    detail TEXT,
                    created_by VARCHAR(255) NOT NULL DEFAULT '',
                    created_ts BIGINT NOT NULL,
                    started_ts BIGINT NOT NULL DEFAULT 0,
                    completed_ts BIGINT NOT NULL DEFAULT 0,
                    updated_ts BIGINT NOT NULL,
                    KEY idx_proxy_operations_proxy_status (proxy_id, status, created_ts),
                    KEY idx_proxy_operations_proxy_updated (proxy_id, updated_ts),
                    KEY idx_proxy_operations_status_updated (status, updated_ts)
                    )
                    """
                )
            self._schema_ready = True

    def _row_to_operation(self, row: object | None) -> Optional[ProxyOperation]:
        if not row:
            return None
        return ProxyOperation(
            operation_id=int(row["id"] or 0),
            proxy_id=str(row["proxy_id"] or ""),
            status=str(row["status"] or "pending"),
            operation_type=str(row["operation_type"] or "sync"),
            subject=str(row["subject"] or ""),
            summary=str(row["summary"] or ""),
            target_kind=str(row["target_kind"] or ""),
            target_ref=str(row["target_ref"] or ""),
            rollback_kind=str(row["rollback_kind"] or ""),
            rollback_ref=str(row["rollback_ref"] or ""),
            request_hash=str(row["request_hash"] or ""),
            detail=str(row["detail"] or ""),
            created_by=str(row["created_by"] or ""),
            created_ts=int(row["created_ts"] or 0),
            started_ts=int(row["started_ts"] or 0),
            completed_ts=int(row["completed_ts"] or 0),
            updated_ts=int(row["updated_ts"] or 0),
        )

    def create_operation(self, proxy_id: object | None, *, operation_type: str, subject: str, summary: str, target_kind: str = "", target_ref: object | None = None, rollback_kind: str = "", rollback_ref: object | None = None, request_hash: str = "", detail: str = "", created_by: str = "") -> ProxyOperation:
        self.init_db()
        proxy_key = normalize_proxy_id(proxy_id)
        now = int(time.time())
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO proxy_operations(proxy_id,status,operation_type,subject,summary,target_kind,target_ref,rollback_kind,rollback_ref,request_hash,detail,created_by,created_ts,updated_ts)
                VALUES(%s,'pending',%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """,
                (proxy_key, (operation_type or "sync")[:64], (subject or "")[:255], (summary or "")[:512], (target_kind or "")[:64], str(target_ref or "")[:255], (rollback_kind or "")[:64], str(rollback_ref or "")[:255], (request_hash or "")[:64], (detail or "")[:4000], (created_by or "")[:255], now, now),
            )
        op = ProxyOperation(
            operation_id=int(cur.lastrowid or 0),
            proxy_id=proxy_key,
            status="pending",
            operation_type=(operation_type or "sync")[:64],
            subject=(subject or "")[:255],
            summary=(summary or "")[:512],
            target_kind=(target_kind or "")[:64],
            target_ref=str(target_ref or "")[:255],
            rollback_kind=(rollback_kind or "")[:64],
            rollback_ref=str(rollback_ref or "")[:255],
            request_hash=(request_hash or "")[:64],
            detail=(detail or "")[:4000],
            created_by=(created_by or "")[:255],
            created_ts=now,
            started_ts=0,
            completed_ts=0,
            updated_ts=now,
        )
        return op

    def list_operations(self, proxy_id: object | None, *, limit: int = 100, statuses: list[str] | None = None) -> list[ProxyOperation]:
        self.init_db()
        proxy_key = normalize_proxy_id(proxy_id)
        limit = max(1, min(500, int(limit)))
        params: list[Any] = [proxy_key]
        where = "proxy_id=%s"
        if statuses:
            filtered = [s for s in statuses if s in OPERATION_STATUSES]
            if filtered:
                where += " AND status IN (" + ",".join(["%s"] * len(filtered)) + ")"
                params.extend(filtered)
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(f"SELECT {self._SELECT_COLUMNS} FROM proxy_operations WHERE {where} ORDER BY updated_ts DESC, id DESC LIMIT %s", tuple(params)).fetchall()
        return [op for op in (self._row_to_operation(row) for row in rows) if op is not None]

    def list_recent_since(self, proxy_id: object | None, *, after_updated_ts: int = 0, after_id: int = 0, limit: int = 100) -> list[ProxyOperation]:
        self.init_db()
        proxy_key = normalize_proxy_id(proxy_id)
        limit = max(1, min(500, int(limit)))
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, proxy_id, status, operation_type, subject, summary, target_kind, target_ref, rollback_kind, rollback_ref, request_hash, detail, created_by, created_ts, started_ts, completed_ts, updated_ts FROM proxy_operations
                WHERE proxy_id=%s AND (updated_ts>%s OR (updated_ts=%s AND id>%s))
                ORDER BY updated_ts ASC, id ASC LIMIT %s
                """,
                (proxy_key, int(after_updated_ts or 0), int(after_updated_ts or 0), int(after_id or 0), limit),
            ).fetchall()
        return [op for op in (self._row_to_operation(row) for row in rows) if op is not None]

    def get_operation(self, operation_id: object) -> Optional[ProxyOperation]:
        self.init_db()
        with self._connect() as conn:
            row = conn.execute(f"SELECT {self._SELECT_COLUMNS} FROM proxy_operations WHERE id=%s LIMIT 1", (int(operation_id or 0),)).fetchone()
        return self._row_to_operation(row)

    def counts_by_status(self, proxy_id: object | None) -> dict[str, int]:
        self.init_db()
        proxy_key = normalize_proxy_id(proxy_id)
        counts = {status: 0 for status in OPERATION_STATUSES}
        with self._connect() as conn:
            rows = conn.execute("SELECT status, COUNT(*) AS c FROM proxy_operations WHERE proxy_id=%s GROUP BY status", (proxy_key,)).fetchall()
        for row in rows:
            status = str(row["status"] or "")
            if status in counts:
                counts[status] = int(row["c"] or 0)
        return counts

    def requeue_stale_applying(self, proxy_id: object | None, *, older_than_seconds: int = 600) -> int:
        self.init_db()
        proxy_key = normalize_proxy_id(proxy_id)
        now = int(time.time())
        cutoff = now - max(60, int(older_than_seconds or 600))
        with self._connect() as conn:
            cur = conn.execute(
                """
                UPDATE proxy_operations
                SET status='pending', detail='Requeued after stale applying state.', updated_ts=%s, started_ts=0
                WHERE proxy_id=%s AND status='applying' AND started_ts>0 AND started_ts<%s
                """,
                (now, proxy_key, cutoff),
            )
        return int(getattr(cur, "rowcount", 0) or 0)

    def claim_pending(self, proxy_id: object | None, *, limit: int = 50, operation_id: object | None = None) -> list[ProxyOperation]:
        self.init_db()
        proxy_key = normalize_proxy_id(proxy_id)
        now = int(time.time())
        limit = max(1, min(200, int(limit)))
        target_operation_id = int(operation_id or 0)
        params: list[Any] = [proxy_key]
        where = "proxy_id=%s AND status='pending'"
        if target_operation_id > 0:
            where += " AND id=%s"
            params.append(target_operation_id)
            limit = 1
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT id FROM proxy_operations
                WHERE {where}
                ORDER BY created_ts ASC, id ASC LIMIT %s
                FOR UPDATE SKIP LOCKED
                """,
                tuple(params),
            ).fetchall()
            ids = [int(row["id"] or 0) for row in rows]
            if not ids:
                return []
            placeholders = ",".join(["%s"] * len(ids))
            conn.execute(
                f"UPDATE proxy_operations SET status='applying', started_ts=%s, updated_ts=%s WHERE proxy_id=%s AND status='pending' AND id IN ({placeholders})",
                tuple([now, now, proxy_key] + ids),
            )
            claimed_rows = conn.execute(
                f"SELECT {self._SELECT_COLUMNS} FROM proxy_operations WHERE proxy_id=%s AND status='applying' AND id IN ({placeholders}) ORDER BY created_ts ASC, id ASC",
                tuple([proxy_key] + ids),
            ).fetchall()
        return [op for op in (self._row_to_operation(row) for row in claimed_rows) if op is not None]

    def mark_status(self, operation_id: object, *, status: str, detail: str = "") -> Optional[ProxyOperation]:
        if status not in OPERATION_STATUSES:
            raise ValueError(f"Unsupported operation status: {status}")
        self.init_db()
        now = int(time.time())
        completed = now if status in TERMINAL_STATUSES else 0
        with self._connect() as conn:
            conn.execute("UPDATE proxy_operations SET status=%s, detail=%s, completed_ts=%s, updated_ts=%s WHERE id=%s", (status, (detail or "")[:4000], completed, now, int(operation_id or 0)))
            row = conn.execute(f"SELECT {self._SELECT_COLUMNS} FROM proxy_operations WHERE id=%s LIMIT 1", (int(operation_id or 0),)).fetchone()
        return self._row_to_operation(row)

    def mark_many(self, operations: list[ProxyOperation], *, status: str, detail: str = "") -> None:
        for op in operations:
            self.mark_status(op.operation_id, status=status, detail=detail)


_store: Optional[OperationLedger] = None
_store_lock = threading.Lock()


def get_operation_ledger() -> OperationLedger:
    global _store
    if _store is not None:
        return _store
    with _store_lock:
        if _store is None:
            _store = OperationLedger()
        return _store
