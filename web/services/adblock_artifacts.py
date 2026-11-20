from __future__ import annotations

import contextlib
import hashlib
import io
import json
import logging
import os
import shutil
import sqlite3
import tempfile
import threading
import time
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

from services.adblock_lookup import LOOKUP_SCHEMA_VERSION
from services.application_ledgers import (
    normalize_application_actor,
    normalize_application_detail,
    normalize_sha256_evidence,
)
from services.db import (
    DATABASE_ERRORS,
    connect,
    staged_blob_parameter,
)
from services.errors import public_error_message
from services.logutil import log_database_unavailable, log_exception_throttled
from services.proxy_sync import nudge_registered_proxies
from services.proxy_write_guard import guarded_proxy_write, resolve_proxy_read_id_cached
from services.revision_lifecycle import (
    ensure_generated_column,
    ensure_index,
    mysql_advisory_lock,
    repair_duplicate_active_rows,
    run_revision_store_transaction,
)
from services.runtime_helpers import env_int as _env_int
from services.runtime_helpers import fsync_dir
from services.runtime_helpers import now_ts as _now

logger = logging.getLogger(__name__)

_ARTIFACT_SHA_FILENAME = ".artifact-sha256"
_DEFAULT_COMPILED_DIR = "/var/lib/squid-flask-proxy/adblock/compiled"
_DEFAULT_SETTINGS_FILENAME = "settings.json"
_BUILDER_SOURCE_KINDS = {"background", "compile"}

# Proxies consume only the request lookup database; the report and settings
# describe it for the Admin UI and runtime alignment checks. Archives built
# before 2026-11 also carry the compiler's diagnostic JSONL buckets (and an
# alias manifest for them); nothing reads those, so materialization skips them.
_RUNTIME_ARTIFACT_MEMBERS = (
    _DEFAULT_SETTINGS_FILENAME,
    "report.json",
    "request_lookup.sqlite",
)


_BUILDER_MYSQL_RETRY_ATTEMPTS = 4
_BUILDER_MYSQL_RETRY_BASE_DELAY_SECONDS = 0.2
_ARTIFACT_PRUNE_BATCH_SIZE = 5
_ARTIFACT_PRUNE_MAX_BATCHES = 4
_ARTIFACT_PRUNE_LOCK_NAME = "docker_proxy:adblock_artifact_prune"
_ARTIFACT_PRUNE_LOCK_TIMEOUT_SECONDS = 0

# Compiled artifacts contain both line-oriented indexes and a SQLite lookup
# database, so legitimate production payloads can exceed 256 MiB. Keep this
# bounded well below the hard ceiling while leaving enough room for those
# generated artifacts. The same resolver is used by build, recovery validation,
# and runtime materialization.
_ARTIFACT_EXTRACT_MAX_BYTES = 1024 * 1024 * 1024
_ARTIFACT_EXTRACT_MAX_MEMBERS = 256


class AdblockArtifactArchiveError(ValueError):
    """Raised when an adblock artifact archive is unsafe or invalid."""


class AdblockArtifactRollbackError(RuntimeError):
    """Raised when publication fails and the previous artifact cannot be restored."""


_ADBLOCK_ARCHIVE_READ_ERRORS = (
    OSError,
    RuntimeError,
    ValueError,
    EOFError,
    NotImplementedError,
    zipfile.BadZipFile,
    zlib.error,
)


@dataclass
class _AdblockArchiveBudget:
    max_bytes: int
    max_members: int
    member_count: int = 0
    total_declared_bytes: int = 0
    total_read_bytes: int = 0

    def add_member(self, info: zipfile.ZipInfo) -> None:
        self.member_count += 1
        if self.member_count > self.max_members:
            msg = (
                f"Adblock artifact archive exceeded member limit ({self.max_members})."
            )
            raise AdblockArtifactArchiveError(msg)

        declared_size = int(getattr(info, "file_size", 0) or 0)
        if declared_size < 0:
            msg = "Adblock artifact archive contains an invalid member size."
            raise AdblockArtifactArchiveError(msg)
        self.total_declared_bytes += declared_size
        if self.total_declared_bytes > self.max_bytes:
            msg = (
                "Adblock artifact archive exceeded extract limit "
                f"({self.max_bytes} bytes)."
            )
            raise AdblockArtifactArchiveError(msg)

    def add_chunk(self, chunk: bytes) -> None:
        self.total_read_bytes += len(chunk)
        if self.total_read_bytes > self.max_bytes:
            msg = (
                "Adblock artifact archive exceeded extract limit "
                f"({self.max_bytes} bytes)."
            )
            raise AdblockArtifactArchiveError(msg)


def _run_builder_mysql_operation(operation):
    return run_revision_store_transaction(
        operation,
        attempts=_BUILDER_MYSQL_RETRY_ATTEMPTS,
        base_delay_seconds=_BUILDER_MYSQL_RETRY_BASE_DELAY_SECONDS,
        max_delay_seconds=5.0,
        operation_name="adblock artifact transaction",
        sleep_fn=time.sleep,
    )


def _adblock_artifact_prune_batch_size() -> int:
    return _env_int(
        "ADBLOCK_ARTIFACT_PRUNE_BATCH_SIZE",
        _ARTIFACT_PRUNE_BATCH_SIZE,
        minimum=1,
        maximum=1000,
    )


def _adblock_artifact_prune_max_batches() -> int:
    return _env_int(
        "ADBLOCK_ARTIFACT_PRUNE_MAX_BATCHES",
        _ARTIFACT_PRUNE_MAX_BATCHES,
        minimum=1,
        maximum=1000,
    )


def _parse_enabled_lists_json(enabled_lists_json: str) -> list[str]:
    try:
        raw = json.loads(enabled_lists_json or "[]")
    except Exception:
        return []
    if not isinstance(raw, list):
        return []
    return [str(item).strip() for item in raw if str(item).strip()]


def _parse_report_json(report_json: str) -> dict[str, Any]:
    try:
        raw = json.loads(report_json or "{}")
    except Exception:
        return {}
    return raw if isinstance(raw, dict) else {}


def _list_file_has_rule_content(path: str | os.PathLike[str]) -> bool:
    try:
        with Path(path).open(encoding="utf-8", errors="replace") as handle:
            for line in handle:
                text = (line or "").strip()
                if not text or text.startswith("!"):
                    continue
                if text.startswith("[") and text.endswith("]"):
                    continue
                return True
    except OSError:
        return False
    return False


@dataclass(frozen=True)
class AdblockArtifactRevision:
    revision_id: int
    artifact_sha256: str
    archive_blob: bytes
    report_json: str
    settings_version: int
    source_kind: str
    enabled_lists_json: str
    created_by: str
    created_ts: int
    is_active: bool

    @property
    def enabled_lists(self) -> list[str]:
        return _parse_enabled_lists_json(self.enabled_lists_json)

    @property
    def report(self) -> dict[str, Any]:
        return _parse_report_json(self.report_json)


@dataclass(frozen=True)
class AdblockArtifactApplication:
    application_id: int
    proxy_id: str
    revision_id: int
    ok: bool
    detail: str
    applied_by: str
    applied_ts: int
    artifact_sha256: str


@dataclass(frozen=True)
class AdblockArtifactSummary:
    revision_id: int
    artifact_sha256: str
    report_json: str
    settings_version: int
    source_kind: str
    enabled_lists_json: str
    created_by: str
    created_ts: int
    is_active: bool

    @property
    def enabled_lists(self) -> list[str]:
        return _parse_enabled_lists_json(self.enabled_lists_json)

    @property
    def report(self) -> dict[str, Any]:
        return _parse_report_json(self.report_json)


@dataclass(frozen=True)
class AdblockArtifactMetadata:
    revision_id: int
    artifact_sha256: str
    settings_version: int
    source_kind: str
    enabled_lists_json: str
    created_by: str
    created_ts: int
    is_active: bool

    @property
    def enabled_lists(self) -> list[str]:
        return _parse_enabled_lists_json(self.enabled_lists_json)


@dataclass(frozen=True)
class AdblockArtifactPruneResult:
    """Outcome of one bounded adblock revision retention pass.

    ``deleted_rows`` counts deleted unreferenced inactive revisions (plus stale
    duplicate-active demotions); ``stripped_archives`` counts inactive revisions
    whose archive blob was released while their metadata row is kept because
    proxy application evidence still references it. ``truncated`` means the
    pass stopped at its bound with work possibly remaining.
    """

    deleted_rows: int = 0
    stripped_archives: int = 0
    truncated: bool = False


class AdblockArtifactStore:
    def __init__(self, *, compiled_dir: str | None = None) -> None:
        self.compiled_dir = (
            compiled_dir
            or os.environ.get("ADBLOCK_COMPILED_DIR")
            or _DEFAULT_COMPILED_DIR
        ).strip() or _DEFAULT_COMPILED_DIR
        self._started = False
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._schema_ready = False
        self._schema_lock = threading.Lock()
        # Builder thread only: the active revision last rebuilt for a lookup
        # schema change.
        self._schema_rebuild_revision_id: int | None = None

    def _connect(self):
        return connect()

    def init_db(self) -> None:
        if self._schema_ready:
            return
        with self._schema_lock:
            if self._schema_ready:
                return
            with self._connect() as conn:
                from services.schema_lifecycle import (
                    runtime_schema_ready_for_lazy_store,
                )

                if runtime_schema_ready_for_lazy_store(conn):
                    self._schema_ready = True
                    return
            with self._connect() as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS adblock_artifact_revisions (
                        id BIGINT PRIMARY KEY AUTO_INCREMENT,
                        artifact_sha256 CHAR(64) NOT NULL,
                        archive_blob LONGBLOB NOT NULL,
                        report_json LONGTEXT NOT NULL,
                        settings_version BIGINT NOT NULL DEFAULT 0,
                        source_kind VARCHAR(64) NOT NULL DEFAULT 'compile',
                        enabled_lists_json LONGTEXT NOT NULL,
                        created_by VARCHAR(255) NOT NULL DEFAULT '',
                        created_ts BIGINT NOT NULL,
                        is_active TINYINT(1) NOT NULL DEFAULT 1,
                        active_global_slot TINYINT GENERATED ALWAYS AS (CASE WHEN is_active=1 THEN 1 ELSE NULL END) STORED,
                        UNIQUE KEY uniq_adblock_artifact_revisions_active (active_global_slot),
                        KEY idx_adblock_artifact_revisions_active (is_active, created_ts, id),
                        KEY idx_adblock_artifact_revisions_sha (artifact_sha256, created_ts, id)
                    )
                    """,
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS proxy_adblock_artifact_applications (
                        id BIGINT PRIMARY KEY AUTO_INCREMENT,
                        proxy_id VARCHAR(64) NOT NULL,
                        revision_id BIGINT NOT NULL,
                        ok TINYINT(1) NOT NULL,
                        detail TEXT,
                        applied_by VARCHAR(255) NOT NULL DEFAULT '',
                        applied_ts BIGINT NOT NULL,
                        artifact_sha256 CHAR(64) NOT NULL DEFAULT '',
                        KEY idx_proxy_adblock_artifact_apply_proxy_ts (proxy_id, applied_ts),
                        KEY idx_proxy_adblock_artifact_apply_proxy_revision_ts (proxy_id, revision_id, applied_ts, id)
                    )
                    """,
                )
                ensure_generated_column(
                    conn,
                    table_name="proxy_adblock_artifact_applications",
                    column_name="artifact_sha256",
                    ddl=(
                        "ALTER TABLE proxy_adblock_artifact_applications "
                        "ADD COLUMN artifact_sha256 CHAR(64) NOT NULL DEFAULT '' AFTER applied_ts"
                    ),
                )
                repair_duplicate_active_rows(
                    conn,
                    table_name="adblock_artifact_revisions",
                )
                ensure_generated_column(
                    conn,
                    table_name="adblock_artifact_revisions",
                    column_name="active_global_slot",
                    ddl=(
                        "ALTER TABLE adblock_artifact_revisions "
                        "ADD COLUMN active_global_slot TINYINT "
                        "GENERATED ALWAYS AS (CASE WHEN is_active=1 THEN 1 ELSE NULL END) STORED"
                    ),
                )
                ensure_index(
                    conn,
                    table_name="adblock_artifact_revisions",
                    index_name="uniq_adblock_artifact_revisions_active",
                    ddl=(
                        "ALTER TABLE adblock_artifact_revisions "
                        "ADD UNIQUE KEY uniq_adblock_artifact_revisions_active (active_global_slot)"
                    ),
                )
                for table, index_name, ddl in (
                    (
                        "adblock_artifact_revisions",
                        "idx_adblock_artifact_revisions_active",
                        "ALTER TABLE adblock_artifact_revisions ADD INDEX idx_adblock_artifact_revisions_active (is_active, created_ts, id)",
                    ),
                    (
                        "adblock_artifact_revisions",
                        "idx_adblock_artifact_revisions_sha",
                        "ALTER TABLE adblock_artifact_revisions ADD INDEX idx_adblock_artifact_revisions_sha (artifact_sha256, created_ts, id)",
                    ),
                    (
                        "proxy_adblock_artifact_applications",
                        "idx_proxy_adblock_artifact_apply_proxy_ts",
                        "ALTER TABLE proxy_adblock_artifact_applications ADD INDEX idx_proxy_adblock_artifact_apply_proxy_ts (proxy_id, applied_ts)",
                    ),
                    (
                        "proxy_adblock_artifact_applications",
                        "idx_proxy_adblock_artifact_apply_proxy_revision_ts",
                        "ALTER TABLE proxy_adblock_artifact_applications ADD INDEX idx_proxy_adblock_artifact_apply_proxy_revision_ts (proxy_id, revision_id, applied_ts, id)",
                    ),
                ):
                    ensure_index(conn, table_name=table, index_name=index_name, ddl=ddl)

            self._schema_ready = True

    def _row_to_revision(self, row: object | None) -> AdblockArtifactRevision | None:
        if not row:
            return None
        return AdblockArtifactRevision(
            revision_id=int(row["id"] or 0),
            artifact_sha256=str(row["artifact_sha256"] or ""),
            archive_blob=bytes(row["archive_blob"] or b""),
            report_json=str(row["report_json"] or "{}"),
            settings_version=int(row["settings_version"] or 0),
            source_kind=str(row["source_kind"] or "compile"),
            enabled_lists_json=str(row["enabled_lists_json"] or "[]"),
            created_by=str(row["created_by"] or ""),
            created_ts=int(row["created_ts"] or 0),
            is_active=bool(int(row["is_active"] or 0)),
        )

    def _row_to_application(
        self,
        row: object | None,
    ) -> AdblockArtifactApplication | None:
        if not row:
            return None
        return AdblockArtifactApplication(
            application_id=int(row["id"] or 0),
            proxy_id=str(row["proxy_id"] or "default"),
            revision_id=int(row["revision_id"] or 0),
            ok=bool(int(row["ok"] or 0)),
            detail=str(row["detail"] or ""),
            applied_by=str(row["applied_by"] or ""),
            applied_ts=int(row["applied_ts"] or 0),
            artifact_sha256=str(row["artifact_sha256"] or ""),
        )

    def _row_to_metadata(self, row: object | None) -> AdblockArtifactMetadata | None:
        if not row:
            return None
        return AdblockArtifactMetadata(
            revision_id=int(row["id"] or 0),
            artifact_sha256=str(row["artifact_sha256"] or ""),
            settings_version=int(row["settings_version"] or 0),
            source_kind=str(row["source_kind"] or "compile"),
            enabled_lists_json=str(row["enabled_lists_json"] or "[]"),
            created_by=str(row["created_by"] or ""),
            created_ts=int(row["created_ts"] or 0),
            is_active=bool(int(row["is_active"] or 0)),
        )

    def _row_to_summary(self, row: object | None) -> AdblockArtifactSummary | None:
        if not row:
            return None
        return AdblockArtifactSummary(
            revision_id=int(row["id"] or 0),
            artifact_sha256=str(row["artifact_sha256"] or ""),
            report_json=str(row["report_json"] or "{}"),
            settings_version=int(row["settings_version"] or 0),
            source_kind=str(row["source_kind"] or "compile"),
            enabled_lists_json=str(row["enabled_lists_json"] or "[]"),
            created_by=str(row["created_by"] or ""),
            created_ts=int(row["created_ts"] or 0),
            is_active=bool(int(row["is_active"] or 0)),
        )

    def get_active_artifact(self) -> AdblockArtifactRevision | None:
        self.init_db()
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM adblock_artifact_revisions
                WHERE is_active=1
                ORDER BY created_ts DESC, id DESC
                LIMIT 1
                """,
            ).fetchone()
        return self._row_to_revision(row)

    def get_active_artifact_metadata(self) -> AdblockArtifactMetadata | None:
        self.init_db()
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT id, artifact_sha256, settings_version, source_kind, enabled_lists_json, created_by, created_ts, is_active
                FROM adblock_artifact_revisions
                WHERE is_active=1
                ORDER BY created_ts DESC, id DESC
                LIMIT 1
                """,
            ).fetchone()
        return self._row_to_metadata(row)

    def get_active_artifact_summary(self) -> AdblockArtifactSummary | None:
        self.init_db()
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT id, artifact_sha256, report_json, settings_version, source_kind, enabled_lists_json, created_by, created_ts, is_active
                FROM adblock_artifact_revisions
                WHERE is_active=1
                ORDER BY created_ts DESC, id DESC
                LIMIT 1
                """,
            ).fetchone()
        return self._row_to_summary(row)

    def create_revision(
        self,
        *,
        archive_blob: bytes,
        artifact_sha256: str,
        report_json: str,
        settings_version: int,
        enabled_lists: list[str],
        created_by: str = "",
        source_kind: str = "compile",
        activate: bool = True,
    ) -> AdblockArtifactRevision:
        self.init_db()
        enabled_lists_json = json.dumps(
            sorted({str(item).strip() for item in enabled_lists if str(item).strip()}),
        )

        def _create() -> object | None:
            now = _now()
            with self._connect() as conn:
                lock_scope = "global" if activate else "inactive"
                with mysql_advisory_lock(
                    conn,
                    namespace="adblock_artifact_revisions.active",
                    scope=lock_scope,
                ):
                    if activate:
                        current_metadata = self._row_to_metadata(
                            conn.execute(
                                """
                                SELECT id, artifact_sha256, settings_version, source_kind, enabled_lists_json, created_by, created_ts, is_active
                                FROM adblock_artifact_revisions
                                WHERE is_active=1
                                ORDER BY created_ts DESC, id DESC
                                LIMIT 1
                                FOR UPDATE
                                """,
                            ).fetchone(),
                        )
                        if (
                            current_metadata is not None
                            and current_metadata.artifact_sha256 == artifact_sha256
                            and current_metadata.settings_version
                            == int(settings_version)
                            and current_metadata.source_kind
                            == (source_kind or "compile")[:64]
                            and current_metadata.enabled_lists_json
                            == enabled_lists_json
                        ):
                            return conn.execute(
                                "SELECT * FROM adblock_artifact_revisions WHERE id=%s LIMIT 1",
                                (current_metadata.revision_id,),
                            ).fetchone()
                        conn.execute(
                            "UPDATE adblock_artifact_revisions SET is_active=0 WHERE is_active=1",
                        )
                    with staged_blob_parameter(conn, archive_blob) as archive_sql:
                        cur = conn.execute(
                            f"""
                            INSERT INTO adblock_artifact_revisions(
                                artifact_sha256, archive_blob, report_json, settings_version,
                                source_kind, enabled_lists_json, created_by, created_ts, is_active
                            )
                            VALUES(%s,{archive_sql},%s,%s,%s,%s,%s,%s,%s)
                            """,
                            (
                                (artifact_sha256 or "")[:64],
                                report_json or "{}",
                                int(settings_version),
                                (source_kind or "compile")[:64],
                                enabled_lists_json,
                                (created_by or "")[:255],
                                now,
                                1 if activate else 0,
                            ),
                        )
                    return conn.execute(
                        "SELECT * FROM adblock_artifact_revisions WHERE id=%s LIMIT 1",
                        (int(cur.lastrowid or 0),),
                    ).fetchone()

        row = _run_builder_mysql_operation(_create)
        self._prune_revisions_best_effort(max_batches=1)
        revision = self._row_to_revision(row)
        assert revision is not None
        return revision

    def prune_revisions(
        self,
        *,
        max_batches: int | None = None,
        batch_size: int | None = None,
    ) -> AdblockArtifactPruneResult:
        """Bound adblock revision storage to the active and previous archives.

        Only the active revision's archive is ever read (proxy apply and
        recovery export); the newest inactive revision is kept intact as the
        previous artifact. Older inactive revisions are deleted when no proxy
        application evidence references them. Referenced ones keep their
        metadata row (application/state-validation integrity) but their archive
        blob is replaced by an empty value, which releases the multi-MB payload.
        Each statement commits separately and the pass is bounded by
        ``max_batches * batch_size`` deletions plus the same number of strips.
        """
        self.init_db()
        batches_remaining = (
            _adblock_artifact_prune_max_batches()
            if max_batches is None
            else max(1, int(max_batches))
        )
        delete_batch_size = (
            _adblock_artifact_prune_batch_size()
            if batch_size is None
            else max(1, int(batch_size))
        )
        strip_limit = batches_remaining * delete_batch_size
        deleted = 0
        stripped = 0
        truncated = False
        with self._connect() as conn:
            if not self._try_acquire_prune_lock(conn):
                return AdblockArtifactPruneResult()
            try:
                while batches_remaining > 0:
                    batch_deleted = self._prune_revisions_with_conn(
                        conn,
                        batch_size=delete_batch_size,
                    )
                    if batch_deleted <= 0:
                        break
                    deleted += batch_deleted
                    batches_remaining -= 1
                    conn.commit()
                else:
                    truncated = True
                # Strip only once unreferenced rows are gone, so a row about to
                # be deleted is never rewritten first; the rest are referenced.
                if not truncated:
                    stripped, truncated = self._strip_inactive_archives_with_conn(
                        conn,
                        limit=strip_limit,
                    )
            finally:
                with contextlib.suppress(Exception):
                    conn.execute("DO RELEASE_LOCK(%s)", (_ARTIFACT_PRUNE_LOCK_NAME,))
        return AdblockArtifactPruneResult(
            deleted_rows=deleted,
            stripped_archives=stripped,
            truncated=truncated,
        )

    def _try_acquire_prune_lock(self, conn) -> bool:
        row = conn.execute(
            "SELECT GET_LOCK(%s, %s) AS acquired",
            (
                _ARTIFACT_PRUNE_LOCK_NAME,
                _ARTIFACT_PRUNE_LOCK_TIMEOUT_SECONDS,
            ),
        ).fetchone()
        if row is None:
            return False
        try:
            return int(row["acquired"] or 0) == 1
        except IndexError, KeyError, TypeError, ValueError:
            with contextlib.suppress(IndexError, TypeError, ValueError):
                return int(row[0] or 0) == 1
            return False

    def _prune_revisions_best_effort(self, *, max_batches: int) -> None:
        try:
            self.prune_revisions(max_batches=max_batches)
        except DATABASE_ERRORS:
            log_exception_throttled(
                logger,
                "adblock-artifact-prune",
                interval_seconds=300.0,
                message="Adblock artifact retention cleanup failed.",
            )

    def _retained_revision_ids(self, conn) -> set[int]:
        """Return the revisions whose archives retention must keep intact."""
        active = conn.execute(
            "SELECT id FROM adblock_artifact_revisions WHERE is_active=1 ORDER BY created_ts DESC, id DESC LIMIT 1"
        ).fetchone()
        if active is None:
            newest_rows = conn.execute(
                "SELECT id FROM adblock_artifact_revisions ORDER BY created_ts DESC, id DESC LIMIT 2"
            ).fetchall()
            return {int(row[0]) for row in newest_rows}
        keep_ids = {int(active[0])}
        previous = conn.execute(
            "SELECT id FROM adblock_artifact_revisions WHERE is_active=0 ORDER BY created_ts DESC, id DESC LIMIT 1"
        ).fetchone()
        if previous:
            keep_ids.add(int(previous[0]))
        return keep_ids

    def _prune_revisions_with_conn(self, conn, *, batch_size: int) -> int:
        active_rows = conn.execute(
            "SELECT id FROM adblock_artifact_revisions WHERE is_active=1 ORDER BY created_ts DESC, id DESC LIMIT %s",
            (int(batch_size) + 1,),
        ).fetchall()
        active_ids = [int(row[0]) for row in active_rows]
        if len(active_ids) > 1:
            stale_active_ids = active_ids[1 : int(batch_size) + 1]
            placeholders = ", ".join(["%s"] * len(stale_active_ids))
            result = conn.execute(
                f"UPDATE adblock_artifact_revisions SET is_active=0 WHERE id IN ({placeholders})",
                tuple(stale_active_ids),
            )
            return max(0, int(getattr(result, "rowcount", 0) or 0))
        keep_ids = self._retained_revision_ids(conn)
        candidate_ids = self._select_prune_candidate_ids(
            conn,
            keep_ids=keep_ids,
            batch_size=batch_size,
        )
        if not candidate_ids:
            return 0
        placeholders = ", ".join(["%s"] * len(candidate_ids))
        result = conn.execute(
            f"DELETE FROM adblock_artifact_revisions WHERE id IN ({placeholders})",
            tuple(candidate_ids),
        )
        return max(0, int(getattr(result, "rowcount", 0) or 0))

    def _strip_inactive_archives_with_conn(
        self,
        conn,
        *,
        limit: int,
    ) -> tuple[int, bool]:
        """Release up to ``limit`` non-retained inactive archives.

        Returns ``(stripped, truncated)``. Candidate ids are read without the
        blob column, and each row is updated by primary key in its own commit,
        so a pass reads only the archives it releases (stripped rows hold an
        empty value) and each transaction/binlog event covers one archive.
        Revisions never become active again and the retained set only moves to
        newer rows, so ids selected up front stay safe to strip.
        """
        keep_ids = sorted(self._retained_revision_ids(conn))
        keep_sql = ""
        if keep_ids:
            keep_sql = f" AND id NOT IN ({', '.join(['%s'] * len(keep_ids))})"
        candidate_rows = conn.execute(
            "SELECT id AS revision_id FROM adblock_artifact_revisions "
            f"WHERE is_active=0{keep_sql} ORDER BY id ASC",
            tuple(keep_ids),
        ).fetchall()
        stripped = 0
        for row in candidate_rows:
            if stripped >= limit:
                return stripped, True
            result = conn.execute(
                "UPDATE adblock_artifact_revisions SET archive_blob=%s "
                "WHERE id=%s AND is_active=0 AND archive_blob <> %s",
                (b"", int(row[0]), b""),
            )
            if max(0, int(getattr(result, "rowcount", 0) or 0)) > 0:
                stripped += 1
                conn.commit()
        return stripped, False

    def _select_prune_candidate_ids(
        self,
        conn,
        *,
        keep_ids: set[int],
        batch_size: int,
    ) -> list[int]:
        if keep_ids:
            placeholders = ", ".join(["%s"] * len(keep_ids))
            sql = (
                "SELECT id FROM adblock_artifact_revisions "
                f"WHERE is_active=0 AND id NOT IN ({placeholders}) "
                "AND NOT EXISTS ("
                "SELECT 1 FROM proxy_adblock_artifact_applications app "
                "WHERE app.revision_id=adblock_artifact_revisions.id"
                ") "
                "ORDER BY created_ts ASC, id ASC LIMIT %s"
            )
            rows = conn.execute(
                sql, (*tuple(sorted(keep_ids)), int(batch_size))
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT id FROM adblock_artifact_revisions
                WHERE is_active=0
                  AND NOT EXISTS (
                    SELECT 1 FROM proxy_adblock_artifact_applications app
                    WHERE app.revision_id=adblock_artifact_revisions.id
                  )
                ORDER BY created_ts ASC, id ASC
                LIMIT %s
                """,
                (int(batch_size),),
            ).fetchall()
        return [int(row[0]) for row in rows]

    def create_revision_from_directory(
        self,
        directory: str | os.PathLike[str],
        *,
        settings_version: int,
        enabled_lists: list[str],
        created_by: str = "",
        source_kind: str = "compile",
        activate: bool = True,
    ) -> AdblockArtifactRevision:
        file_map = _load_directory_files(directory)
        archive_blob = _build_deterministic_archive(file_map)
        artifact_sha256 = _calculate_artifact_sha(file_map)
        report_json = _load_report_json(file_map)
        return self.create_revision(
            archive_blob=archive_blob,
            artifact_sha256=artifact_sha256,
            report_json=report_json,
            settings_version=settings_version,
            enabled_lists=enabled_lists,
            created_by=created_by,
            source_kind=source_kind,
            activate=activate,
        )

    def record_apply_result(
        self,
        proxy_id: object | None,
        revision_id: int,
        *,
        ok: bool,
        detail: str = "",
        applied_by: str = "proxy",
        artifact_sha256: str = "",
    ) -> AdblockArtifactApplication:
        self.init_db()
        from services.proxy_context import normalize_proxy_id

        proxy_key = normalize_proxy_id(proxy_id)
        now = _now()
        target_revision_id = int(revision_id)
        with self._connect() as conn:
            with guarded_proxy_write(conn, proxy_key) as guard:
                proxy_key = guard.proxy_id
                revision = conn.execute(
                    "SELECT id, artifact_sha256 FROM adblock_artifact_revisions WHERE id=%s LIMIT 1 FOR SHARE",
                    (target_revision_id,),
                ).fetchone()
                if revision is None:
                    msg = (
                        f"Adblock artifact revision {target_revision_id} was not found."
                    )
                    raise ValueError(msg)
                evidence_sha = normalize_sha256_evidence(
                    artifact_sha256,
                    fallback=str(revision["artifact_sha256"] or ""),
                    ok=bool(ok),
                    label="Adblock artifact application SHA-256",
                )
                cur = conn.execute(
                    """
                    INSERT INTO proxy_adblock_artifact_applications(
                        proxy_id, revision_id, ok, detail, applied_by, applied_ts, artifact_sha256
                    )
                    VALUES(%s,%s,%s,%s,%s,%s,%s)
                    """,
                    (
                        proxy_key,
                        target_revision_id,
                        1 if ok else 0,
                        normalize_application_detail(detail),
                        normalize_application_actor(applied_by),
                        now,
                        evidence_sha,
                    ),
                )
                row = conn.execute(
                    "SELECT * FROM proxy_adblock_artifact_applications WHERE id=%s LIMIT 1",
                    (int(cur.lastrowid or 0),),
                ).fetchone()
        application = self._row_to_application(row)
        assert application is not None
        return application

    def latest_apply(
        self,
        proxy_id: object | None,
        *,
        revision_id: int | None = None,
    ) -> AdblockArtifactApplication | None:
        self.init_db()
        from services.proxy_context import normalize_proxy_id

        proxy_key = normalize_proxy_id(proxy_id)
        with self._connect() as conn:
            proxy_key = resolve_proxy_read_id_cached(conn, proxy_key).proxy_id
            if revision_id is None:
                row = conn.execute(
                    """
                    SELECT * FROM proxy_adblock_artifact_applications
                    WHERE proxy_id=%s
                    ORDER BY applied_ts DESC, id DESC
                    LIMIT 1
                    """,
                    (proxy_key,),
                ).fetchone()
            else:
                row = conn.execute(
                    """
                    SELECT * FROM proxy_adblock_artifact_applications
                    WHERE proxy_id=%s AND revision_id=%s
                    ORDER BY applied_ts DESC, id DESC
                    LIMIT 1
                    """,
                    (proxy_key, int(revision_id)),
                ).fetchone()
        return self._row_to_application(row)

    def build_active_artifact(
        self,
        *,
        refresh_lists: bool = False,
        created_by: str = "system",
        source_kind: str = "background",
    ) -> dict[str, Any]:
        def load_state() -> tuple[Any, dict[str, Any], bool, int, list[Any], Any]:
            self.init_db()
            from services.adblock_store import get_adblock_store

            loaded_store = get_adblock_store()
            loaded_store.init_db()
            loaded_settings = loaded_store.get_settings()
            loaded_settings_version = loaded_store.get_settings_version()
            loaded_statuses = loaded_store.list_statuses()
            loaded_enabled_statuses = [
                status for status in loaded_statuses if status.enabled
            ]
            loaded_previous = self.get_active_artifact()
            return (
                loaded_store,
                loaded_settings,
                True,
                loaded_settings_version,
                loaded_enabled_statuses,
                loaded_previous,
            )

        (
            store,
            settings,
            settings_enabled,
            settings_version,
            enabled_statuses,
            previous,
        ) = _run_builder_mysql_operation(load_state)
        any_downloaded = False
        download_pending = False

        if enabled_statuses and (settings_enabled or refresh_lists):
            now_ts = _now()
            for status in enabled_statuses:
                list_path = store.list_path(status.key)
                has_local_rules = _list_file_has_rule_content(list_path)
                needs_download = (
                    refresh_lists
                    or (
                        not has_local_rules
                        and not store.download_retry_backoff(status, now_ts)
                    )
                    or store.should_update(status, now_ts, False)
                )
                if not needs_download:
                    continue
                force_download = bool(refresh_lists or not has_local_rules)
                downloaded_now = bool(
                    _run_builder_mysql_operation(
                        lambda status=status, force_download=force_download: (
                            store.update_one(
                                status.key,
                                force=force_download,
                            )
                        ),
                    ),
                )
                any_downloaded = downloaded_now or any_downloaded
                if not downloaded_now:
                    download_pending = True

        available_enabled_statuses = [
            status
            for status in enabled_statuses
            if settings_enabled
            and _list_file_has_rule_content(store.list_path(status.key))
        ]
        effective_enabled_lists = [status.key for status in available_enabled_statuses]
        if settings_enabled and len(available_enabled_statuses) < len(enabled_statuses):
            download_pending = True
        if settings_enabled and enabled_statuses and not available_enabled_statuses:
            detail = "No enabled adblock subscription lists with rule content are available locally."
            if download_pending:
                detail = (
                    "Enabled adblock subscription lists could not be downloaded and "
                    "no cached lists with rule content are available."
                )
            with contextlib.suppress(Exception):
                store.record_artifact_build_result(
                    ok=False,
                    detail=detail,
                    revision_id=getattr(previous, "revision_id", 0),
                    artifact_sha256=getattr(previous, "artifact_sha256", ""),
                    download_pending=download_pending,
                )
            return {
                "ok": False,
                "detail": detail,
                "revision": previous,
                "changed": False,
                "downloaded": any_downloaded,
                "download_pending": download_pending,
            }

        try:
            with tempfile.TemporaryDirectory(prefix="adblock-build-") as out_dir:
                if settings_enabled and available_enabled_statuses:
                    _compile_current_lists(
                        lists_dir=store.lists_dir,
                        out_dir=out_dir,
                        enabled_lists=effective_enabled_lists,
                    )
                    if _compiled_request_rule_count(out_dir) <= 0:
                        detail = (
                            "Enabled adblock subscription lists compiled without any "
                            "request-time rules; preserving the previous artifact."
                        )
                        with contextlib.suppress(Exception):
                            store.record_artifact_build_result(
                                ok=False,
                                detail=detail,
                                revision_id=getattr(previous, "revision_id", 0),
                                artifact_sha256=getattr(
                                    previous,
                                    "artifact_sha256",
                                    "",
                                ),
                                download_pending=download_pending,
                            )
                        return {
                            "ok": False,
                            "detail": detail,
                            "revision": previous,
                            "changed": False,
                            "downloaded": any_downloaded,
                            "download_pending": download_pending,
                        }
                else:
                    _write_empty_output(out_dir)
                _write_settings_file(
                    out_dir,
                    settings=settings,
                    settings_version=settings_version,
                    enabled_lists=effective_enabled_lists,
                )
                revision = self.create_revision_from_directory(
                    out_dir,
                    settings_version=settings_version,
                    enabled_lists=effective_enabled_lists,
                    created_by=created_by,
                    source_kind=source_kind,
                    activate=True,
                )
                archive_bytes = len(revision.archive_blob or b"")
        except Exception as exc:
            logger.exception("adblock artifact build failed")
            detail = public_error_message(
                exc,
                default="Adblock artifact build failed.",
            )
            with contextlib.suppress(Exception):
                store.record_artifact_build_result(
                    ok=False,
                    detail=detail,
                    revision_id=getattr(previous, "revision_id", 0),
                    artifact_sha256=getattr(previous, "artifact_sha256", ""),
                    download_pending=download_pending,
                )
            return {
                "ok": False,
                "detail": detail,
                "revision": previous,
                "changed": False,
                "downloaded": any_downloaded,
                "download_pending": download_pending,
            }

        changed = (
            previous is None
            or previous.revision_id != revision.revision_id
            or previous.artifact_sha256 != revision.artifact_sha256
        )
        detail = "Adblock artifact is already current."
        if changed:
            detail = f"Activated adblock artifact revision {revision.revision_id}."
        if download_pending:
            detail = (
                f"{detail} One or more enabled subscription downloads are still "
                "pending; the active artifact was built from locally cached lists."
            )
        with contextlib.suppress(Exception):
            store.record_artifact_build_result(
                ok=True,
                detail=detail,
                revision_id=revision.revision_id,
                artifact_sha256=revision.artifact_sha256,
                archive_bytes=archive_bytes,
                download_pending=download_pending,
            )
        return {
            "ok": True,
            "detail": detail,
            "revision": revision,
            "changed": changed,
            "downloaded": any_downloaded,
            "download_pending": download_pending,
        }

    def start_background(self) -> None:
        with self._lock:
            if self._started:
                return
            self._stop_event.clear()
            thread = threading.Thread(
                target=self._loop,
                name="adblock-artifact-builder",
                daemon=True,
            )
            self._thread = thread
            self._started = True
            try:
                thread.start()
            except Exception:
                self._thread = None
                self._started = False
                raise

    def stop_background(self, *, timeout: float = 5.0) -> bool:
        with self._lock:
            self._stop_event.set()
            thread = self._thread
        if thread is not None:
            thread.join(max(0.0, timeout))
        stopped = thread is None or not thread.is_alive()
        if stopped:
            with self._lock:
                if self._thread is thread:
                    self._thread = None
                    self._started = False
        return stopped

    def _loop(self) -> None:
        poll_seconds = float(
            _env_int("ADBLOCK_BUILDER_POLL_SECONDS", 30, minimum=5, maximum=3600),
        )
        error_seconds = float(
            _env_int(
                "ADBLOCK_BUILDER_ERROR_BACKOFF_SECONDS",
                30,
                minimum=5,
                maximum=300,
            ),
        )
        from services.adblock_store import get_adblock_store

        store = get_adblock_store()
        while not self._stop_event.is_set():
            sleep_seconds = poll_seconds
            try:
                self.init_db()
                store.init_db()
                # Poll the summary only: the decision never needs the archive
                # blob, which is tens of MB per read.
                active = self.get_active_artifact_summary()
                statuses = store.list_statuses()
                enabled_statuses = [status for status in statuses if status.enabled]
                refresh_requested = bool(store.get_refresh_requested())
                settings_version = store.get_settings_version()
                # Subscription artifacts are shared; proxy enablement controls
                # Squid routing and must not empty another proxy's artifact.
                settings_enabled = True
                now_ts = _now()
                locally_available = {
                    status.key
                    for status in enabled_statuses
                    if _list_file_has_rule_content(store.list_path(status.key))
                }
                # Compare against the lists a build could include right now; a
                # list without local rules is handled by its download schedule,
                # otherwise it would force an identical rebuild on every poll.
                active_lists_drift = _active_enabled_lists_drift(
                    active,
                    settings_enabled=settings_enabled,
                    enabled_statuses=[
                        status
                        for status in enabled_statuses
                        if status.key in locally_available
                    ],
                )
                due_download = settings_enabled and any(
                    (
                        (
                            status.key not in locally_available
                            and not store.download_retry_backoff(status, now_ts)
                        )
                        or store.should_update(status, now_ts, False)
                    )
                    for status in enabled_statuses
                )
                # An artifact whose report names another lookup schema (older
                # compiler, restored recovery bundle) is rebuilt in the current
                # format, once per revision so a build that preserves it (no
                # request rules) is not retried on every poll.
                schema_rebuild = (
                    active is not None
                    and active.report.get("lookup_schema_version")
                    != LOOKUP_SCHEMA_VERSION
                    and active.revision_id != self._schema_rebuild_revision_id
                )
                if schema_rebuild:
                    self._schema_rebuild_revision_id = active.revision_id
                needs_build = (
                    refresh_requested
                    or schema_rebuild
                    or active is None
                    or (
                        active is not None
                        and active.settings_version != settings_version
                    )
                    or active_lists_drift
                    or due_download
                )
                if needs_build:
                    result = self.build_active_artifact(
                        refresh_lists=refresh_requested,
                        created_by="system",
                        source_kind="background",
                    )
                    if bool(result.get("changed")):
                        nudge_registered_proxies(force=False)
                    if bool(result.get("ok")):
                        # A completed build consumed the refresh request; lists
                        # whose download failed are retried after the
                        # per-list download backoff, not on every poll.
                        with contextlib.suppress(Exception):
                            store.clear_refresh_requested()
                    if not bool(result.get("ok")) or bool(
                        result.get("download_pending"),
                    ):
                        sleep_seconds = error_seconds
                    else:
                        sleep_seconds = poll_seconds
            except DATABASE_ERRORS as exc:
                log_database_unavailable(
                    logger,
                    "adblock_artifacts.loop.db_unavailable",
                    "Adblock artifact builder deferred database work while MySQL is unavailable",
                    exc,
                )
            except Exception:
                log_exception_throttled(
                    logger,
                    "adblock_artifacts.loop",
                    interval_seconds=30.0,
                    message="Adblock artifact builder loop failed",
                )
                sleep_seconds = error_seconds
            self._stop_event.wait(sleep_seconds)


def _compile_current_lists(
    *,
    lists_dir: str,
    out_dir: str,
    enabled_lists: list[str],
) -> None:
    from tools import adblock_compile  # type: ignore

    args = ["--lists-dir", str(lists_dir), "--out-dir", str(out_dir)]
    for key in enabled_lists:
        cleaned = str(key).strip()
        if cleaned:
            args.extend(["--enabled-list", cleaned])

    rc = int(
        adblock_compile.main(args),
    )
    if rc != 0:
        msg = f"adblock_compile failed with exit code {rc}"
        raise RuntimeError(msg)


def _compiled_request_rule_count(out_dir: str | os.PathLike[str]) -> int:
    try:
        report = json.loads(Path(out_dir, "report.json").read_text(encoding="utf-8"))
        breakdowns = report.get("breakdowns") if isinstance(report, dict) else {}
        lookup_counts = (
            breakdowns.get("lookup_index_counts")
            if isinstance(breakdowns, dict)
            else {}
        )
        if not isinstance(lookup_counts, dict):
            return 0
        return int(lookup_counts.get("rules") or 0)
    except Exception:
        return 0


def _active_enabled_lists_drift(
    active: AdblockArtifactMetadata | AdblockArtifactRevision | None,
    *,
    settings_enabled: bool,
    enabled_statuses: list[Any],
) -> bool:
    if active is None:
        return False
    source_kind = str(getattr(active, "source_kind", "") or "compile").strip()
    if source_kind not in _BUILDER_SOURCE_KINDS:
        return False
    expected = (
        sorted(
            str(getattr(status, "key", "") or "").strip()
            for status in enabled_statuses
            if str(getattr(status, "key", "") or "").strip()
        )
        if settings_enabled
        else []
    )
    current = sorted(
        str(item).strip() for item in active.enabled_lists if str(item).strip()
    )
    return current != expected


def _write_empty_output(out_dir: str) -> None:
    from tools import adblock_compile  # type: ignore

    root = Path(out_dir)
    root.mkdir(parents=True, exist_ok=True)
    _write_empty_request_lookup_db(root / "request_lookup.sqlite")
    report = {
        "lookup_schema_version": LOOKUP_SCHEMA_VERSION,
        "enabled_lists": [],
        "counts": {
            "network_rules_total": 0,
            "network_rules_with_options": 0,
            "network_rules_with_domain_opt": 0,
            "cosmetic_rules_total": 0,
        },
        "breakdowns": {
            "network_by_pattern_kind": {},
            "cosmetic_by_marker": {},
            "option_key_counts": {},
            "option_group_counts": {},
            "lookup_index_counts": dict.fromkeys(
                adblock_compile.LOOKUP_INDEX_COUNT_TABLES,
                0,
            ),
        },
        "per_list": {},
        "notes": {
            "empty": "No enabled adblock lists are active, so the materialized artifact contains an empty request lookup.",
        },
    }
    (root / "report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _write_empty_request_lookup_db(path: Path) -> None:
    from tools import adblock_compile  # type: ignore

    path.parent.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(FileNotFoundError):
        path.unlink()
    conn = sqlite3.connect(str(path))
    try:
        adblock_compile._create_lookup_schema(conn)
        adblock_compile._create_lookup_indexes(conn)
        metadata = {
            "schema_version": LOOKUP_SCHEMA_VERSION,
            "lookup_strategy": adblock_compile.LOOKUP_STRATEGY,
            **{
                f"count_{table}": "0"
                for table in adblock_compile.LOOKUP_INDEX_COUNT_TABLES
            },
        }
        conn.executemany(
            "INSERT INTO metadata(key, value) VALUES(?, ?)",
            sorted(metadata.items()),
        )
        conn.commit()
    finally:
        conn.close()


def _write_settings_file(
    out_dir: str,
    *,
    settings: dict[str, Any],
    settings_version: int,
    enabled_lists: list[str],
) -> None:
    payload = {
        # Kept for artifact format compatibility; runtime enablement is per proxy.
        "enabled": True,
        "cache_ttl": int(settings.get("cache_ttl") or 0),
        "cache_max": int(settings.get("cache_max") or 0),
        "settings_version": int(settings_version),
        "enabled_lists": sorted(
            {str(item).strip() for item in enabled_lists if str(item).strip()},
        ),
    }
    Path(out_dir, _DEFAULT_SETTINGS_FILENAME).write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _load_directory_files(directory: str | os.PathLike[str]) -> dict[str, bytes]:
    root = Path(directory)
    file_map: dict[str, bytes] = {}
    for name in _RUNTIME_ARTIFACT_MEMBERS:
        path = root / name
        if path.is_file():
            file_map[name] = path.read_bytes()
    return file_map


def _validate_generated_artifact_budget(file_map: dict[str, bytes]) -> None:
    max_bytes = _adblock_artifact_extract_max_bytes()
    max_members = _adblock_artifact_extract_max_members()
    member_count = len(file_map)
    if member_count > max_members:
        msg = f"Generated adblock artifact exceeded member limit ({max_members})."
        raise AdblockArtifactArchiveError(msg)
    payload_bytes = sum(len(content) for content in file_map.values())
    if payload_bytes > max_bytes:
        msg = f"Generated adblock artifact exceeded extract limit ({max_bytes} bytes)."
        raise AdblockArtifactArchiveError(msg)


def _calculate_artifact_sha(file_map: dict[str, bytes]) -> str:
    digest = hashlib.sha256()
    for rel_path in sorted(file_map):
        digest.update(rel_path.encode("utf-8", errors="replace"))
        digest.update(b"\0")
        digest.update(file_map[rel_path])
        digest.update(b"\0")
    return digest.hexdigest()


def _build_deterministic_archive(file_map: dict[str, bytes]) -> bytes:
    # Reject an artifact before it can become authoritative if the proxy or
    # recovery validator would later be unable to consume its materialized
    # payload.
    _validate_generated_artifact_budget(file_map)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for rel_path in sorted(file_map):
            info = zipfile.ZipInfo(rel_path)
            info.date_time = (2020, 1, 1, 0, 0, 0)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            zf.writestr(info, file_map[rel_path])
    return buffer.getvalue()


def _load_report_json(file_map: dict[str, bytes]) -> str:
    report = file_map.get("report.json")
    if report is None:
        return "{}"
    try:
        return report.decode("utf-8", errors="replace")
    except Exception:
        return "{}"


def read_materialized_artifact_sha(
    compiled_dir: str | os.PathLike[str] | None = None,
) -> str:
    root = Path(
        compiled_dir or os.environ.get("ADBLOCK_COMPILED_DIR") or _DEFAULT_COMPILED_DIR,
    )
    marker = root / _ARTIFACT_SHA_FILENAME
    try:
        return marker.read_text(encoding="utf-8", errors="replace").strip()
    except Exception:
        return ""


def _adblock_artifact_extract_max_bytes() -> int:
    return _env_int(
        "ADBLOCK_ARTIFACT_EXTRACT_MAX_BYTES",
        _ARTIFACT_EXTRACT_MAX_BYTES,
        minimum=1,
        maximum=4 * 1024 * 1024 * 1024,
    )


def _adblock_artifact_extract_max_members() -> int:
    return _env_int(
        "ADBLOCK_ARTIFACT_EXTRACT_MAX_MEMBERS",
        _ARTIFACT_EXTRACT_MAX_MEMBERS,
        minimum=1,
        maximum=100_000,
    )


def _safe_adblock_archive_member_name(name: str) -> str | None:
    normalized = (name or "").replace("\\", "/")
    if not normalized or normalized.endswith("/"):
        return None
    norm = os.path.normpath(normalized).replace("\\", "/")
    if norm.startswith(("../", "/")) or norm == "..":
        msg = f"Refusing to extract unsafe archive member: {normalized}"
        raise AdblockArtifactArchiveError(msg)
    return norm


def _open_adblock_artifact_archive(archive_blob: bytes) -> zipfile.ZipFile:
    try:
        return zipfile.ZipFile(io.BytesIO(bytes(archive_blob or b"")))
    except _ADBLOCK_ARCHIVE_READ_ERRORS as exc:
        msg = "Adblock artifact archive is invalid."
        raise AdblockArtifactArchiveError(msg) from exc


def _validated_adblock_archive_members(
    archive: zipfile.ZipFile,
    budget: _AdblockArchiveBudget,
) -> tuple[tuple[zipfile.ZipInfo, str], ...]:
    members: list[tuple[zipfile.ZipInfo, str]] = []
    member_names: set[str] = set()
    for info in archive.infolist():
        normalized = _safe_adblock_archive_member_name(info.filename or "")
        if normalized is None:
            continue
        if info.filename in member_names:
            msg = "Adblock artifact archive contains a duplicate member."
            raise AdblockArtifactArchiveError(msg)
        member_names.add(info.filename)
        budget.add_member(info)
        members.append((info, normalized))
    return tuple(members)


def _read_adblock_archive_member(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    budget: _AdblockArchiveBudget,
    consume: Callable[[bytes], object],
) -> None:
    member_bytes = 0
    try:
        source = archive.open(info, "r")
    except _ADBLOCK_ARCHIVE_READ_ERRORS as exc:
        msg = "Adblock artifact archive is invalid."
        raise AdblockArtifactArchiveError(msg) from exc
    with source:
        while True:
            try:
                chunk = source.read(512 * 1024)
            except _ADBLOCK_ARCHIVE_READ_ERRORS as exc:
                msg = "Adblock artifact archive is invalid."
                raise AdblockArtifactArchiveError(msg) from exc
            if not chunk:
                break
            member_bytes += len(chunk)
            budget.add_chunk(chunk)
            consume(chunk)
    if member_bytes != int(getattr(info, "file_size", 0) or 0):
        msg = "Adblock artifact archive contains a truncated member."
        raise AdblockArtifactArchiveError(msg)


def _adblock_archive_budget() -> _AdblockArchiveBudget:
    return _AdblockArchiveBudget(
        max_bytes=_adblock_artifact_extract_max_bytes(),
        max_members=_adblock_artifact_extract_max_members(),
    )


def adblock_archive_artifact_sha256(archive_blob: bytes) -> str:
    """Validate an artifact archive and hash its deterministic file payload."""
    digest = hashlib.sha256()
    with _open_adblock_artifact_archive(archive_blob) as archive:
        budget = _adblock_archive_budget()
        members = _validated_adblock_archive_members(archive, budget)
        for info, _normalized in sorted(
            members,
            key=lambda member: member[0].filename,
        ):
            digest.update(info.filename.encode("utf-8", errors="replace"))
            digest.update(b"\0")
            _read_adblock_archive_member(archive, info, budget, digest.update)
            digest.update(b"\0")
    return digest.hexdigest()


def _fsync_tree(root: Path) -> None:
    for current_root, directories, filenames in os.walk(root, topdown=False):
        current = Path(current_root)
        for filename in filenames:
            with (current / filename).open("rb") as handle:
                os.fsync(handle.fileno())
        for directory in directories:
            fsync_dir(current / directory)
        fsync_dir(current)


def materialize_archive_to_directory(
    target_dir: str | os.PathLike[str],
    *,
    archive_blob: bytes,
    artifact_sha256: str = "",
) -> None:
    target = Path(target_dir)
    parent = target.parent
    parent.mkdir(parents=True, exist_ok=True)

    stage_root = Path(tempfile.mkdtemp(prefix=".adblock-stage-", dir=str(parent)))
    payload_dir = stage_root / "payload"
    payload_dir.mkdir(parents=True, exist_ok=True)
    backup_dir: Path | None = None

    try:
        with _open_adblock_artifact_archive(archive_blob) as zf:
            budget = _adblock_archive_budget()
            members = _validated_adblock_archive_members(zf, budget)
            for info, norm in members:
                if norm not in _RUNTIME_ARTIFACT_MEMBERS:
                    continue
                dest = payload_dir / norm
                dest.parent.mkdir(parents=True, exist_ok=True)
                with Path(dest).open("wb") as dst:
                    _read_adblock_archive_member(zf, info, budget, dst.write)

        if artifact_sha256:
            (payload_dir / _ARTIFACT_SHA_FILENAME).write_text(
                (artifact_sha256 or "").strip() + "\n",
                encoding="utf-8",
            )

        _fsync_tree(payload_dir)

        try:
            if target.exists():
                backup_dir = Path(
                    tempfile.mkdtemp(prefix=".adblock-backup-", dir=str(parent))
                )
                backup_dir.rmdir()
                target.replace(backup_dir)
                fsync_dir(parent)

            payload_dir.replace(target)
            fsync_dir(parent)
        except Exception:
            if backup_dir is not None and backup_dir.exists():
                try:
                    if target.exists():
                        target.replace(payload_dir)
                    backup_dir.replace(target)
                    fsync_dir(parent)
                except Exception as restore_exc:
                    msg = (
                        "Failed to publish adblock artifact and failed to restore "
                        f"the previous artifact; recovery backup remains at {backup_dir}."
                    )
                    raise AdblockArtifactRollbackError(msg) from restore_exc
            raise

        if backup_dir is not None:
            try:
                shutil.rmtree(backup_dir)
                fsync_dir(parent)
            except OSError:
                logger.warning(
                    "Published adblock artifact but could not remove recovery backup %s",
                    backup_dir,
                    exc_info=True,
                )
    finally:
        shutil.rmtree(stage_root, ignore_errors=True)


_store: AdblockArtifactStore | None = None
_store_lock = threading.Lock()


def get_adblock_artifacts() -> AdblockArtifactStore:
    global _store
    if _store is not None:
        return _store
    with _store_lock:
        if _store is None:
            _store = AdblockArtifactStore()
        return _store
