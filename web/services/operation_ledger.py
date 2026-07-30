from __future__ import annotations

import hashlib
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any

from services.db import (
    DATABASE_ERRORS,
    connect,
    mysql_advisory_lock,
    mysql_error_code,
    mysql_schema_lock_timeout_seconds,
    run_mysql_operation_with_retry,
)
from services.errors import redact_sensitive_text
from services.proxy_context import normalize_proxy_id
from services.proxy_write_guard import guarded_proxy_write

OPERATION_STATUSES = ("pending", "applying", "applied", "superseded", "failed")
TERMINAL_STATUSES = {"applied", "superseded", "failed"}
_REQUIRED_COLUMNS = (
    "request_key",
    "claim_token",
    "stale_requeue_count",
    "force_sync",
)
_REQUIRED_INDEXES = (
    "idx_proxy_operations_proxy_status_created_id",
    "idx_proxy_operations_proxy_started_id",
    "idx_proxy_operations_proxy_updated_id",
    "uniq_proxy_operations_active_request",
)


def _text_or_default(value: object | None, *, default: str = "") -> str:
    if value is None:
        return default
    text = str(value)
    return text or default


def _limited_text(
    value: object | None,
    limit: int,
    *,
    default: str = "",
    redact: bool = False,
) -> str:
    text = _text_or_default(value, default=default)
    if redact:
        text = redact_sensitive_text(text)
    return text[:limit]


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
    stale_requeue_count: int = 0
    force: bool = False
    claim_token: str = ""

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
            "stale_requeue_count": self.stale_requeue_count,
            "force": self.force,
            "can_revert": self.can_revert,
        }


class OperationLedger:
    _SELECT_COLUMNS = "id, proxy_id, status, operation_type, subject, summary, target_kind, target_ref, rollback_kind, rollback_ref, request_hash, detail, created_by, created_ts, started_ts, completed_ts, updated_ts, stale_requeue_count, force_sync, claim_token"

    def __init__(self) -> None:
        self._schema_ready = False
        self._schema_lock = threading.Lock()

    def _connect(self):
        return connect()

    def _column_exists(self, conn, table_name: str, column_name: str) -> bool:
        row = conn.execute(
            """
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = DATABASE() AND table_name = %s AND column_name = %s
            LIMIT 1
            """,
            (table_name, column_name),
        ).fetchone()
        return row is not None

    def _index_exists(self, conn, table_name: str, index_name: str) -> bool:
        row = conn.execute(
            """
            SELECT 1 FROM information_schema.statistics
            WHERE table_schema = DATABASE() AND table_name = %s AND index_name = %s
            LIMIT 1
            """,
            (table_name, index_name),
        ).fetchone()
        return row is not None

    def _ensure_index(self, conn, table_name: str, index_name: str, ddl: str) -> None:
        if self._index_exists(conn, table_name, index_name):
            return
        try:
            conn.execute(ddl)
        except DATABASE_ERRORS as exc:
            if mysql_error_code(exc) != 1061:
                raise

    def _request_key(
        self,
        *,
        operation_type: str,
        subject: str,
        target_kind: str,
        target_ref: object | None,
        request_hash: str,
    ) -> str:
        payload = "\0".join(
            (
                _limited_text(operation_type, 64, default="sync"),
                _limited_text(subject, 255),
                _limited_text(target_kind, 64),
                _limited_text(target_ref, 255),
                _limited_text(request_hash, 64),
            ),
        )
        return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()

    @staticmethod
    def _request_key_sql(alias: str = "") -> str:
        prefix = f"{alias}." if alias else ""
        return (
            "SHA2(CONCAT("
            f"LEFT(COALESCE(NULLIF({prefix}operation_type,''),'sync'),64),CHAR(0),"
            f"LEFT(COALESCE({prefix}subject,''),255),CHAR(0),"
            f"LEFT(COALESCE({prefix}target_kind,''),64),CHAR(0),"
            f"LEFT(COALESCE({prefix}target_ref,''),255),CHAR(0),"
            f"LEFT(COALESCE({prefix}request_hash,''),64)"
            "),256)"
        )

    @staticmethod
    def _stale_recovery_priority_sql(alias: str) -> str:
        prefix = f"{alias}." if alias else ""
        return (
            "CASE "
            f"WHEN {prefix}status='applying' AND {prefix}started_ts>=%s THEN 0 "
            f"WHEN {prefix}status='applying' THEN 1 "
            "ELSE 2 "
            "END"
        )

    def _backfill_active_request_keys(self, conn) -> None:
        now = int(time.time())
        request_key_expr = self._request_key_sql()
        conn.execute(
            """
            UPDATE proxy_operations
            SET request_key=NULL,
                claim_token=NULL
            WHERE status NOT IN ('pending','applying')
              AND (request_key IS NOT NULL OR claim_token IS NOT NULL)
            """,
        )
        active_request_key_expr = self._request_key_sql("active")
        keeper_request_key_expr = self._request_key_sql("keeper")
        conn.execute(
            f"""
            UPDATE proxy_operations active
            JOIN proxy_operations keeper
              ON keeper.proxy_id=active.proxy_id
             AND keeper.status IN ('pending','applying')
             AND {keeper_request_key_expr}={active_request_key_expr}
             AND (
                 CASE WHEN keeper.status='applying' THEN 0 ELSE 1 END
                 < CASE WHEN active.status='applying' THEN 0 ELSE 1 END
                 OR (
                     CASE WHEN keeper.status='applying' THEN 0 ELSE 1 END
                     = CASE WHEN active.status='applying' THEN 0 ELSE 1 END
                     AND (
                         keeper.created_ts < active.created_ts
                         OR (keeper.created_ts = active.created_ts AND keeper.id < active.id)
                     )
                 )
             )
            SET active.status='superseded',
                active.detail='Superseded by a matching active operation during request-key backfill.',
                active.completed_ts=%s,
                active.updated_ts=%s,
                active.started_ts=0,
                active.request_key=NULL,
                active.claim_token=NULL
            WHERE active.status IN ('pending','applying')
            """,
            (now, now),
        )
        conn.execute(
            f"""
            UPDATE proxy_operations
            SET request_key=NULL
            WHERE status IN ('pending','applying')
              AND (request_key IS NULL OR request_key='' OR request_key<>{request_key_expr})
            """,
        )
        conn.execute(
            f"""
            UPDATE proxy_operations
            SET request_key={request_key_expr}
            WHERE status IN ('pending','applying')
              AND (request_key IS NULL OR request_key='' OR request_key<>{request_key_expr})
            """,
        )

    def _init_db_on_connection(self, conn) -> None:
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
            request_key CHAR(64) NULL DEFAULT NULL,
            claim_token CHAR(32) NULL DEFAULT NULL,
            detail TEXT,
            created_by VARCHAR(255) NOT NULL DEFAULT '',
            created_ts BIGINT NOT NULL,
            started_ts BIGINT NOT NULL DEFAULT 0,
            completed_ts BIGINT NOT NULL DEFAULT 0,
            updated_ts BIGINT NOT NULL,
            stale_requeue_count INT NOT NULL DEFAULT 0,
            force_sync TINYINT(1) NOT NULL DEFAULT 0,
            KEY idx_proxy_operations_proxy_status (proxy_id, status, created_ts),
            KEY idx_proxy_operations_proxy_updated (proxy_id, updated_ts),
            KEY idx_proxy_operations_status_updated (status, updated_ts)
            )
            """,
        )
        if not self._column_exists(conn, "proxy_operations", "request_key"):
            conn.execute(
                "ALTER TABLE proxy_operations ADD COLUMN request_key CHAR(64) NULL DEFAULT NULL AFTER request_hash",
            )
        if not self._column_exists(conn, "proxy_operations", "claim_token"):
            conn.execute(
                "ALTER TABLE proxy_operations ADD COLUMN claim_token CHAR(32) NULL DEFAULT NULL AFTER request_key",
            )
        if not self._column_exists(
            conn,
            "proxy_operations",
            "stale_requeue_count",
        ):
            conn.execute(
                "ALTER TABLE proxy_operations ADD COLUMN stale_requeue_count INT NOT NULL DEFAULT 0 AFTER updated_ts",
            )
        if not self._column_exists(conn, "proxy_operations", "force_sync"):
            conn.execute(
                "ALTER TABLE proxy_operations ADD COLUMN force_sync TINYINT(1) NOT NULL DEFAULT 0 AFTER stale_requeue_count",
            )
        self._backfill_active_request_keys(conn)
        for index_name, ddl in (
            (
                "idx_proxy_operations_proxy_status_created_id",
                "ALTER TABLE proxy_operations ADD INDEX idx_proxy_operations_proxy_status_created_id (proxy_id, status, created_ts, id)",
            ),
            (
                "idx_proxy_operations_proxy_started_id",
                "ALTER TABLE proxy_operations ADD INDEX idx_proxy_operations_proxy_started_id (proxy_id, started_ts, id)",
            ),
            (
                "idx_proxy_operations_proxy_updated_id",
                "ALTER TABLE proxy_operations ADD INDEX idx_proxy_operations_proxy_updated_id (proxy_id, updated_ts, id)",
            ),
        ):
            self._ensure_index(conn, "proxy_operations", index_name, ddl)
        if not self._index_exists(
            conn,
            "proxy_operations",
            "uniq_proxy_operations_active_request",
        ):
            conn.execute(
                "ALTER TABLE proxy_operations ADD UNIQUE KEY uniq_proxy_operations_active_request (proxy_id, request_key)",
            )

    def _schema_missing_requirements(self, conn) -> list[str]:
        missing = [
            f"column:{column_name}"
            for column_name in _REQUIRED_COLUMNS
            if not self._column_exists(conn, "proxy_operations", column_name)
        ]
        missing.extend(
            f"index:{index_name}"
            for index_name in _REQUIRED_INDEXES
            if not self._index_exists(conn, "proxy_operations", index_name)
        )
        return missing

    def _schema_current_on_connection(self, conn) -> bool:
        if not hasattr(conn, "native"):
            return False
        try:
            from services.schema_lifecycle import runtime_schema_ready_for_lazy_store

            return runtime_schema_ready_for_lazy_store(
                conn,
            ) and not self._schema_missing_requirements(conn)
        except Exception:
            return False

    def init_db(self) -> None:
        if self._schema_ready:
            return
        with self._schema_lock:
            if self._schema_ready:
                return

            def _ensure_schema() -> None:
                with self._connect() as conn:
                    if self._schema_current_on_connection(conn):
                        self._schema_ready = True
                        return
                    if not hasattr(conn, "native"):
                        self._init_db_on_connection(conn)
                        return
                    with mysql_advisory_lock(
                        conn,
                        "docker_proxy:operation_ledger:schema",
                        mysql_schema_lock_timeout_seconds(),
                    ):
                        self._init_db_on_connection(conn)

            run_mysql_operation_with_retry(_ensure_schema)
            self._schema_ready = True

    def _row_to_operation(self, row: object | None) -> ProxyOperation | None:
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
            stale_requeue_count=int(row.get("stale_requeue_count") or 0),
            force=bool(int(row["force_sync"] or 0)),
            claim_token=str(row.get("claim_token") or ""),
        )

    def create_operation(
        self,
        proxy_id: object | None,
        *,
        operation_type: str,
        subject: str,
        summary: str,
        target_kind: str = "",
        target_ref: object | None = None,
        rollback_kind: str = "",
        rollback_ref: object | None = None,
        request_hash: str = "",
        detail: str = "",
        created_by: str = "",
        force: bool = False,
    ) -> ProxyOperation:
        self.init_db()
        proxy_key = normalize_proxy_id(proxy_id)
        now = int(time.time())
        op_type = _limited_text(operation_type, 64, default="sync")
        subject_text = _limited_text(subject, 255)
        summary_text = _limited_text(summary, 512, redact=True)
        target_kind_text = _limited_text(target_kind, 64)
        target_ref_text = _limited_text(target_ref, 255)
        rollback_kind_text = _limited_text(rollback_kind, 64)
        rollback_ref_text = _limited_text(rollback_ref, 255)
        request_hash_text = _limited_text(request_hash, 64)
        detail_text = _limited_text(detail, 4000, redact=True)
        created_by_text = _limited_text(created_by, 255)
        force_requested = bool(force)
        request_key = self._request_key(
            operation_type=op_type,
            subject=subject_text,
            target_kind=target_kind_text,
            target_ref=target_ref_text,
            request_hash=request_hash_text,
        )

        def _create() -> object | None:
            nonlocal proxy_key
            with self._connect() as conn:
                with guarded_proxy_write(conn, proxy_key) as guard:
                    proxy_key = guard.proxy_id
                    cur = conn.execute(
                        """
                        INSERT INTO proxy_operations(proxy_id,status,operation_type,subject,summary,target_kind,target_ref,rollback_kind,rollback_ref,request_hash,request_key,detail,created_by,created_ts,updated_ts,force_sync)
                        VALUES(%s,'pending',%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        ON DUPLICATE KEY UPDATE id=LAST_INSERT_ID(id), summary=VALUES(summary), detail=VALUES(detail), created_by=VALUES(created_by), updated_ts=VALUES(updated_ts), force_sync=GREATEST(force_sync, VALUES(force_sync))
                        """,
                        (
                            proxy_key,
                            op_type,
                            subject_text,
                            summary_text,
                            target_kind_text,
                            target_ref_text,
                            rollback_kind_text,
                            rollback_ref_text,
                            request_hash_text,
                            request_key,
                            detail_text,
                            created_by_text,
                            now,
                            now,
                            1 if force_requested else 0,
                        ),
                    )
                    if rollback_kind_text and rollback_ref_text:
                        conn.execute(
                            """
                            UPDATE proxy_operations
                            SET rollback_kind=%s, rollback_ref=%s
                            WHERE id=%s AND (rollback_kind='' OR rollback_ref='')
                            """,
                            (
                                rollback_kind_text,
                                rollback_ref_text,
                                int(cur.lastrowid or 0),
                            ),
                        )
                    return conn.execute(
                        f"SELECT {self._SELECT_COLUMNS} FROM proxy_operations WHERE id=%s LIMIT 1",
                        (int(cur.lastrowid or 0),),
                    ).fetchone()

        row = run_mysql_operation_with_retry(
            _create,
            operation_name="operation ledger create",
        )
        operation = self._row_to_operation(row)
        if operation is None:
            msg = "Operation ledger insert did not return a row."
            raise RuntimeError(msg)
        return operation

    def list_operations(
        self,
        proxy_id: object | None,
        *,
        limit: int = 100,
        statuses: list[str] | None = None,
    ) -> list[ProxyOperation]:
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
            rows = conn.execute(
                f"SELECT {self._SELECT_COLUMNS} FROM proxy_operations WHERE {where} ORDER BY updated_ts DESC, id DESC LIMIT %s",
                tuple(params),
            ).fetchall()
        return [
            op for op in (self._row_to_operation(row) for row in rows) if op is not None
        ]

    def list_recent_since(
        self,
        proxy_id: object | None,
        *,
        after_updated_ts: int = 0,
        after_id: int = 0,
        limit: int = 100,
    ) -> list[ProxyOperation]:
        self.init_db()
        proxy_key = normalize_proxy_id(proxy_id)
        limit = max(1, min(500, int(limit)))
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT {self._SELECT_COLUMNS} FROM proxy_operations
                WHERE proxy_id=%s AND (updated_ts>%s OR (updated_ts=%s AND id>%s))
                ORDER BY updated_ts ASC, id ASC LIMIT %s
                """,
                (
                    proxy_key,
                    int(after_updated_ts or 0),
                    int(after_updated_ts or 0),
                    int(after_id or 0),
                    limit,
                ),
            ).fetchall()
        return [
            op for op in (self._row_to_operation(row) for row in rows) if op is not None
        ]

    def get_operation(self, operation_id: object) -> ProxyOperation | None:
        self.init_db()
        with self._connect() as conn:
            row = conn.execute(
                f"SELECT {self._SELECT_COLUMNS} FROM proxy_operations WHERE id=%s LIMIT 1",
                (int(operation_id or 0),),
            ).fetchone()
        return self._row_to_operation(row)

    def counts_by_status(self, proxy_id: object | None) -> dict[str, int]:
        self.init_db()
        proxy_key = normalize_proxy_id(proxy_id)
        counts = dict.fromkeys(OPERATION_STATUSES, 0)
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT status, COUNT(*) AS c FROM proxy_operations WHERE proxy_id=%s GROUP BY status",
                (proxy_key,),
            ).fetchall()
        for row in rows:
            status = str(row["status"] or "")
            if status in counts:
                counts[status] = int(row["c"] or 0)
        return counts

    def requeue_stale_applying(
        self,
        proxy_id: object | None,
        *,
        older_than_seconds: int = 600,
        max_requeues: int = 3,
    ) -> int:
        self.init_db()
        proxy_key = normalize_proxy_id(proxy_id)
        now = int(time.time())
        cutoff = now - max(60, int(older_than_seconds or 600))
        max_requeues = max(1, min(20, int(max_requeues or 3)))
        stale_request_key_expr = self._request_key_sql("stale")
        active_request_key_expr = self._request_key_sql("active")

        def _recover_stale() -> int:
            with self._connect() as conn:
                keeper_request_key_expr = self._request_key_sql("keeper")
                keeper_priority_expr = self._stale_recovery_priority_sql("keeper")
                active_priority_expr = self._stale_recovery_priority_sql("active")
                conn.execute(
                    f"""
                    UPDATE proxy_operations active
                    JOIN (
                        SELECT proxy_id, request_key
                        FROM (
                            SELECT stale_source.proxy_id,
                                   {stale_request_key_expr.replace("stale.", "stale_source.")} AS request_key
                            FROM proxy_operations stale_source
                            WHERE stale_source.proxy_id=%s
                              AND stale_source.status='applying'
                              AND stale_source.started_ts>0
                              AND stale_source.started_ts<%s
                        ) stale_source_keys
                        GROUP BY proxy_id, request_key
                    ) stale_keys
                      ON stale_keys.proxy_id=active.proxy_id
                     AND stale_keys.request_key={active_request_key_expr}
                    JOIN proxy_operations keeper
                      ON keeper.proxy_id=active.proxy_id
                     AND keeper.status IN ('pending','applying')
                     AND {keeper_request_key_expr}={active_request_key_expr}
                     AND (
                         {keeper_priority_expr}
                         < {active_priority_expr}
                         OR (
                             {keeper_priority_expr}
                             = {active_priority_expr}
                             AND (
                                 keeper.created_ts < active.created_ts
                                 OR (keeper.created_ts = active.created_ts AND keeper.id < active.id)
                             )
                         )
                     )
                    SET active.status='superseded',
                        active.detail='Superseded by a matching active operation before stale applying recovery.',
                        active.completed_ts=%s,
                        active.updated_ts=%s,
                        active.started_ts=0,
                        active.request_key=NULL,
                        active.claim_token=NULL
                    WHERE active.proxy_id=%s
                      AND active.status IN ('pending','applying')
                    """,
                    (
                        proxy_key,
                        cutoff,
                        cutoff,
                        cutoff,
                        cutoff,
                        cutoff,
                        now,
                        now,
                        proxy_key,
                    ),
                )
                conn.execute(
                    f"""
                    UPDATE proxy_operations stale
                    LEFT JOIN proxy_operations active
                      ON active.proxy_id=stale.proxy_id
                     AND active.status IN ('pending','applying')
                     AND active.id<>stale.id
                     AND {active_request_key_expr}={stale_request_key_expr}
                    SET stale.status='failed',
                        stale.detail='Failed after repeated stale applying recoveries; operation needs operator review before retry.',
                        stale.completed_ts=%s,
                        stale.updated_ts=%s,
                        stale.started_ts=0,
                        stale.request_key=NULL,
                        stale.claim_token=NULL
                    WHERE stale.proxy_id=%s
                      AND stale.status='applying'
                      AND stale.started_ts>0
                      AND stale.started_ts<%s
                      AND stale.stale_requeue_count >= %s
                      AND active.id IS NULL
                    """,
                    (now, now, proxy_key, cutoff, max_requeues),
                )
                cur = conn.execute(
                    f"""
                    UPDATE proxy_operations stale
                    LEFT JOIN proxy_operations active
                      ON active.proxy_id=stale.proxy_id
                     AND active.status IN ('pending','applying')
                     AND active.id<>stale.id
                     AND {active_request_key_expr}={stale_request_key_expr}
                    SET stale.status='pending',
                        stale.detail='Requeued after stale applying state.',
                        stale.updated_ts=%s,
                        stale.started_ts=0,
                        stale.completed_ts=0,
                        stale.stale_requeue_count=stale.stale_requeue_count+1,
                        stale.request_key={stale_request_key_expr},
                        stale.claim_token=NULL
                    WHERE stale.proxy_id=%s
                      AND stale.status='applying'
                      AND stale.started_ts>0
                      AND stale.started_ts<%s
                      AND stale.stale_requeue_count < %s
                      AND active.id IS NULL
                    """,
                    (now, proxy_key, cutoff, max_requeues),
                )
                return int(getattr(cur, "rowcount", 0) or 0)

        return int(
            run_mysql_operation_with_retry(
                _recover_stale,
                operation_name="operation ledger stale recovery",
            )
            or 0,
        )

    def claim_pending(
        self,
        proxy_id: object | None,
        *,
        limit: int = 50,
        operation_id: object | None = None,
    ) -> list[ProxyOperation]:
        self.init_db()
        proxy_key = normalize_proxy_id(proxy_id)
        now = int(time.time())
        claim_token = secrets.token_hex(16)
        limit = max(1, min(200, int(limit)))
        target_operation_id = int(operation_id or 0)
        params: list[Any] = [proxy_key]
        where = "proxy_id=%s AND status='pending'"
        if target_operation_id > 0:
            where += " AND id=%s"
            params.append(target_operation_id)
            limit = 1
        params.append(limit)

        def _claim() -> list[Any]:
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
                    f"UPDATE proxy_operations SET status='applying', started_ts=%s, updated_ts=%s, claim_token=%s WHERE proxy_id=%s AND status='pending' AND id IN ({placeholders})",
                    (now, now, claim_token, proxy_key, *ids),
                )
                return conn.execute(
                    f"SELECT {self._SELECT_COLUMNS} FROM proxy_operations WHERE proxy_id=%s AND status='applying' AND claim_token=%s AND id IN ({placeholders}) ORDER BY created_ts ASC, id ASC",
                    (proxy_key, claim_token, *ids),
                ).fetchall()

        claimed_rows = run_mysql_operation_with_retry(
            _claim,
            operation_name="operation ledger claim",
        )
        return [
            op
            for op in (self._row_to_operation(row) for row in claimed_rows)
            if op is not None
        ]

    def mark_status(
        self,
        operation_id: object,
        *,
        status: str,
        detail: str = "",
        expected_status: str | None = None,
        expected_claim_token: str | None = None,
    ) -> ProxyOperation | None:
        if status not in OPERATION_STATUSES:
            msg = f"Unsupported operation status: {status}"
            raise ValueError(msg)
        self.init_db()
        now = int(time.time())
        completed = now if status in TERMINAL_STATUSES else 0
        where = "id=%s"
        where_params: list[Any] = [int(operation_id or 0)]
        where += " AND status NOT IN ('applied','superseded','failed')"
        if expected_status:
            expected_status_text = str(expected_status or "")
            if expected_status_text not in OPERATION_STATUSES:
                msg = f"Unsupported expected operation status: {expected_status_text}"
                raise ValueError(msg)
            where += " AND status=%s"
            where_params.append(expected_status_text)
        if expected_claim_token is not None:
            where += " AND claim_token=%s"
            where_params.append(str(expected_claim_token))
        detail_text = _limited_text(detail, 4000, redact=True)

        def _mark() -> object | None:
            with self._connect() as conn:
                conn.execute(
                    f"UPDATE proxy_operations SET status=%s, detail=%s, completed_ts=%s, updated_ts=%s, request_key=IF(%s, NULL, request_key), claim_token=IF(%s, NULL, claim_token) WHERE {where}",
                    (
                        status,
                        detail_text,
                        completed,
                        now,
                        status in TERMINAL_STATUSES,
                        status in TERMINAL_STATUSES,
                        *where_params,
                    ),
                )
                return conn.execute(
                    f"SELECT {self._SELECT_COLUMNS} FROM proxy_operations WHERE id=%s LIMIT 1",
                    (int(operation_id or 0),),
                ).fetchone()

        row = run_mysql_operation_with_retry(
            _mark,
            operation_name="operation ledger mark status",
        )
        return self._row_to_operation(row)

    def mark_many(
        self,
        operations: list[ProxyOperation],
        *,
        status: str,
        detail: str = "",
    ) -> None:
        for op in operations:
            self.mark_status(
                op.operation_id,
                status=status,
                detail=detail,
                expected_status="applying",
                expected_claim_token=getattr(op, "claim_token", ""),
            )


_store: OperationLedger | None = None
_store_lock = threading.Lock()


def get_operation_ledger() -> OperationLedger:
    global _store
    if _store is not None:
        return _store
    with _store_lock:
        if _store is None:
            _store = OperationLedger()
        return _store
