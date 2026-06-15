from __future__ import annotations

import contextlib
import hashlib
import io
import json
import logging
import os
import shutil
import sqlite3
import subprocess
import tempfile
import threading
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from services.db import DATABASE_ERRORS, connect
from services.errors import public_error_message
from services.logutil import log_database_unavailable, log_exception_throttled
from services.proxy_sync import nudge_registered_proxies
from services.runtime_helpers import env_int as _env_int
from services.runtime_helpers import now_ts as _now

logger = logging.getLogger(__name__)

_ARTIFACT_SHA_FILENAME = ".artifact-sha256"
_DEFAULT_COMPILED_DIR = "/var/lib/squid-flask-proxy/adblock/compiled"
_DEFAULT_SETTINGS_FILENAME = "settings.json"
_BUILDER_SOURCE_KINDS = {"background", "compile"}


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


def _mysql_error_code(exc: BaseException) -> int | None:
    args = getattr(exc, "args", ())
    if args:
        try:
            return int(args[0])
        except (TypeError, ValueError):
            return None
    return None


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


class AdblockArtifactStore:
    def __init__(self, *, compiled_dir: str | None = None) -> None:
        self.compiled_dir = (
            compiled_dir
            or os.environ.get("ADBLOCK_COMPILED_DIR")
            or _DEFAULT_COMPILED_DIR
        ).strip() or _DEFAULT_COMPILED_DIR
        self._started = False
        self._lock = threading.Lock()

    def _connect(self):
        return connect()

    def init_db(self) -> None:
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
                    KEY idx_adblock_artifact_revisions_active (is_active, created_ts),
                    KEY idx_adblock_artifact_revisions_sha (artifact_sha256, created_ts)
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
                    KEY idx_proxy_adblock_artifact_apply_proxy_ts (proxy_id, applied_ts)
                )
                """,
            )
            artifact_column = conn.execute(
                """
                SELECT 1
                FROM information_schema.columns
                WHERE table_schema = DATABASE()
                  AND table_name = 'proxy_adblock_artifact_applications'
                  AND column_name = 'artifact_sha256'
                LIMIT 1
                """,
            ).fetchone()
            if not artifact_column:
                try:
                    conn.execute(
                        "ALTER TABLE proxy_adblock_artifact_applications ADD COLUMN artifact_sha256 CHAR(64) NOT NULL DEFAULT '' AFTER applied_ts",
                    )
                except DATABASE_ERRORS as exc:
                    if _mysql_error_code(exc) != 1060:
                        raise

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
        current = self.get_active_artifact()
        enabled_lists_json = json.dumps(
            sorted({str(item).strip() for item in enabled_lists if str(item).strip()}),
        )
        if (
            activate
            and current is not None
            and current.artifact_sha256 == artifact_sha256
            and current.settings_version == int(settings_version)
            and current.enabled_lists_json == enabled_lists_json
        ):
            return current

        now = _now()
        with self._connect() as conn:
            if activate:
                conn.execute(
                    "UPDATE adblock_artifact_revisions SET is_active=0 WHERE is_active=1",
                )
            cur = conn.execute(
                """
                INSERT INTO adblock_artifact_revisions(
                    artifact_sha256, archive_blob, report_json, settings_version,
                    source_kind, enabled_lists_json, created_by, created_ts, is_active
                )
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """,
                (
                    (artifact_sha256 or "")[:64],
                    bytes(archive_blob or b""),
                    report_json or "{}",
                    int(settings_version),
                    (source_kind or "compile")[:64],
                    enabled_lists_json,
                    (created_by or "")[:255],
                    now,
                    1 if activate else 0,
                ),
            )
            row = conn.execute(
                "SELECT * FROM adblock_artifact_revisions WHERE id=%s LIMIT 1",
                (int(cur.lastrowid or 0),),
            ).fetchone()
        revision = self._row_to_revision(row)
        assert revision is not None
        return revision

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

    def estimate_archive_size(self, directory: str | os.PathLike[str]) -> int:
        file_map = _load_directory_files(directory)
        return len(_build_deterministic_archive(file_map))

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
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO proxy_adblock_artifact_applications(
                    proxy_id, revision_id, ok, detail, applied_by, applied_ts, artifact_sha256
                )
                VALUES(%s,%s,%s,%s,%s,%s,%s)
                """,
                (
                    proxy_key,
                    int(revision_id),
                    1 if ok else 0,
                    (detail or "")[:4000],
                    (applied_by or "proxy")[:255],
                    now,
                    (artifact_sha256 or "")[:64],
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
        self.init_db()
        from services.adblock_store import get_adblock_store

        store = get_adblock_store()
        store.init_db()
        settings = store.get_settings()
        settings_enabled = bool(settings.get("enabled"))
        settings_version = store.get_settings_version()
        statuses = store.list_statuses()
        enabled_statuses = [status for status in statuses if status.enabled]
        previous = self.get_active_artifact()
        any_downloaded = False
        download_pending = False

        if enabled_statuses and (settings_enabled or refresh_lists):
            now_ts = _now()
            for status in enabled_statuses:
                list_path = store.list_path(status.key)
                has_local_rules = _list_file_has_rule_content(list_path)
                needs_download = (
                    refresh_lists
                    or not has_local_rules
                    or store.should_update(status, now_ts, False)
                )
                if not needs_download:
                    continue
                force_download = bool(refresh_lists or not has_local_rules)
                downloaded_now = bool(
                    store.update_one(status.key, force=force_download),
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
                archive_bytes = self.estimate_archive_size(out_dir)
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
            thread = threading.Thread(
                target=self._loop,
                name="adblock-artifact-builder",
                daemon=True,
            )
            thread.start()
            self._started = True

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
        while True:
            sleep_seconds = poll_seconds
            try:
                self.init_db()
                store.init_db()
                active = self.get_active_artifact()
                settings = store.get_settings()
                statuses = store.list_statuses()
                enabled_statuses = [status for status in statuses if status.enabled]
                refresh_requested = bool(store.get_refresh_requested())
                settings_version = store.get_settings_version()
                settings_enabled = bool(settings.get("enabled"))
                active_lists_drift = _active_enabled_lists_drift(
                    active,
                    settings_enabled=settings_enabled,
                    enabled_statuses=enabled_statuses,
                )
                due_download = settings_enabled and any(
                    (
                        not _list_file_has_rule_content(store.list_path(status.key))
                        or store.should_update(status, _now(), False)
                    )
                    for status in enabled_statuses
                )
                needs_build = (
                    refresh_requested
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
                    if not bool(result.get("ok")) or bool(
                        result.get("download_pending"),
                    ):
                        sleep_seconds = error_seconds
                    else:
                        with contextlib.suppress(Exception):
                            store.clear_refresh_requested()
                        sleep_seconds = 5.0
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
            time.sleep(sleep_seconds)


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
    active: AdblockArtifactRevision | None,
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
    root = Path(out_dir)
    root.mkdir(parents=True, exist_ok=True)
    for filename in (
        "network_rules.jsonl",
        "cosmetic_rules.jsonl",
        "network_no_options.jsonl",
        "network_with_options.jsonl",
        "network_option_domain.jsonl",
        "network_option_third_party.jsonl",
        "network_option_type.jsonl",
        "network_option_misc.jsonl",
        "network_kind_domain_only.jsonl",
        "network_kind_host_anchored.jsonl",
        "network_kind_left_anchored.jsonl",
        "network_kind_substring.jsonl",
        "network_kind_wildcard.jsonl",
        "network_kind_regex.jsonl",
        "network_block.jsonl",
        "network_exception.jsonl",
        "request_index_domain.jsonl",
        "request_index_host.jsonl",
        "request_index_regex.jsonl",
        "request_index_generic.jsonl",
        "cosmetic_elemhide.jsonl",
        "cosmetic_elemhide_exception.jsonl",
        "cosmetic_extended_css.jsonl",
        "cosmetic_extended_css_exception.jsonl",
        "cosmetic_html_filter.jsonl",
        "cosmetic_html_filter_exception.jsonl",
        "cosmetic_scriptlet.jsonl",
        "cosmetic_scriptlet_exception.jsonl",
        "cosmetic_scoped.jsonl",
        "cosmetic_global.jsonl",
        "cosmetic_exception.jsonl",
        "cosmetic_non_exception.jsonl",
    ):
        (root / filename).write_text("", encoding="utf-8")
    for resource_type in (
        "document",
        "font",
        "image",
        "media",
        "object",
        "other",
        "ping",
        "popup",
        "script",
        "stylesheet",
        "subdocument",
        "websocket",
        "xmlhttprequest",
    ):
        (root / f"network_type_{resource_type}.jsonl").write_text(
            "",
            encoding="utf-8",
        )
        (root / f"network_type_not_{resource_type}.jsonl").write_text(
            "",
            encoding="utf-8",
        )
    _write_empty_request_lookup_db(root / "request_lookup.sqlite")
    report = {
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
            "lookup_index_counts": {
                "domain_index": 0,
                "domain_scope_index": 0,
                "generic_index": 0,
                "host_index": 0,
                "host_pattern_index": 0,
                "host_pattern_token_index": 0,
                "option_index": 0,
                "regex_index": 0,
                "regex_token_index": 0,
                "resource_type_index": 0,
                "rules": 0,
            },
        },
        "per_list": {},
        "notes": {
            "empty": "No enabled adblock lists are active, so the materialized artifact contains an empty request lookup.",
            "request_indexes": "request_index_*.jsonl files are empty because no adblock lists are enabled.",
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
        conn.executescript(
            """
            PRAGMA journal_mode=OFF;
            PRAGMA synchronous=OFF;

            CREATE TABLE metadata(
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            ) WITHOUT ROWID;

            CREATE TABLE rules(
                rule_id TEXT PRIMARY KEY,
                list_key TEXT NOT NULL,
                action TEXT NOT NULL,
                exception INTEGER NOT NULL,
                pattern_kind TEXT NOT NULL,
                raw TEXT NOT NULL,
                pattern TEXT NOT NULL,
                options_json TEXT NOT NULL,
                resource_types_json TEXT NOT NULL,
                excluded_resource_types_json TEXT NOT NULL,
                third_party TEXT NOT NULL,
                behavior_options_json TEXT NOT NULL,
                value_options_json TEXT NOT NULL,
                payload_json TEXT NOT NULL
            ) WITHOUT ROWID;

            CREATE TABLE domain_index(
                host TEXT NOT NULL,
                action TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                PRIMARY KEY(host, action, rule_id)
            ) WITHOUT ROWID;

            CREATE TABLE host_index(
                host TEXT NOT NULL,
                action TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                pattern_kind TEXT NOT NULL,
                url_scheme_pattern TEXT NOT NULL,
                path_pattern TEXT NOT NULL,
                query_pattern TEXT NOT NULL,
                suffix_separator_prefix INTEGER NOT NULL,
                suffix_separator_suffix INTEGER NOT NULL,
                PRIMARY KEY(host, action, rule_id)
            ) WITHOUT ROWID;

            CREATE TABLE host_pattern_index(
                host_pattern TEXT NOT NULL,
                action TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                pattern_kind TEXT NOT NULL,
                url_scheme_pattern TEXT NOT NULL,
                path_pattern TEXT NOT NULL,
                query_pattern TEXT NOT NULL,
                PRIMARY KEY(host_pattern, action, rule_id)
            ) WITHOUT ROWID;

            CREATE TABLE host_pattern_token_index(
                literal_key TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                PRIMARY KEY(literal_key, rule_id)
            ) WITHOUT ROWID;

            CREATE TABLE regex_index(
                action TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                regex TEXT NOT NULL,
                PRIMARY KEY(action, rule_id)
            ) WITHOUT ROWID;

            CREATE TABLE regex_token_index(
                literal_key TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                PRIMARY KEY(literal_key, rule_id)
            ) WITHOUT ROWID;

            CREATE TABLE generic_index(
                literal_key TEXT NOT NULL,
                pattern_kind TEXT NOT NULL,
                action TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                PRIMARY KEY(literal_key, pattern_kind, action, rule_id)
            ) WITHOUT ROWID;

            CREATE TABLE option_index(
                option_key TEXT NOT NULL,
                option_value TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                PRIMARY KEY(option_key, option_value, rule_id)
            ) WITHOUT ROWID;

            CREATE TABLE resource_type_index(
                resource_type TEXT NOT NULL,
                negated INTEGER NOT NULL,
                rule_id TEXT NOT NULL,
                PRIMARY KEY(resource_type, negated, rule_id)
            ) WITHOUT ROWID;

            CREATE TABLE domain_scope_index(
                domain TEXT NOT NULL,
                excluded INTEGER NOT NULL,
                pattern INTEGER NOT NULL,
                rule_id TEXT NOT NULL,
                PRIMARY KEY(domain, excluded, pattern, rule_id)
            ) WITHOUT ROWID;

            CREATE INDEX idx_rules_kind_action ON rules(pattern_kind, action);
            CREATE INDEX idx_domain_action ON domain_index(action, host);
            CREATE INDEX idx_host_action ON host_index(action, host);
            CREATE INDEX idx_host_pattern_action ON host_pattern_index(action, host_pattern);
            CREATE INDEX idx_host_pattern_token_rule ON host_pattern_token_index(rule_id);
            CREATE INDEX idx_regex_action ON regex_index(action);
            CREATE INDEX idx_regex_token_rule ON regex_token_index(rule_id);
            CREATE INDEX idx_generic_kind_key ON generic_index(pattern_kind, literal_key);
            CREATE INDEX idx_option_key ON option_index(option_key, option_value);
            CREATE INDEX idx_resource_type ON resource_type_index(resource_type, negated);
            CREATE INDEX idx_domain_scope ON domain_scope_index(domain, excluded, pattern);
            """
        )
        metadata = {
            "schema_version": "4",
            "count_domain_index": "0",
            "count_domain_scope_index": "0",
            "count_generic_index": "0",
            "count_host_index": "0",
            "count_host_pattern_index": "0",
            "count_host_pattern_token_index": "0",
            "count_option_index": "0",
            "count_regex_index": "0",
            "count_regex_token_index": "0",
            "count_resource_type_index": "0",
            "count_rules": "0",
            "lookup_strategy": adblock_compile.LOOKUP_STRATEGY,
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
        "enabled": bool(settings.get("enabled")),
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
    if not root.exists():
        return file_map
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        file_map[rel] = path.read_bytes()
    return file_map


def _calculate_artifact_sha(file_map: dict[str, bytes]) -> str:
    digest = hashlib.sha256()
    for rel_path in sorted(file_map):
        digest.update(rel_path.encode("utf-8", errors="replace"))
        digest.update(b"\0")
        digest.update(file_map[rel_path])
        digest.update(b"\0")
    return digest.hexdigest()


def _build_deterministic_archive(file_map: dict[str, bytes]) -> bytes:
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
        with zipfile.ZipFile(io.BytesIO(bytes(archive_blob or b""))) as zf:
            for info in zf.infolist():
                name = (info.filename or "").replace("\\", "/")
                if not name or name.endswith("/"):
                    continue
                norm = os.path.normpath(name).replace("\\", "/")
                if norm.startswith(("../", "/")) or norm == "..":
                    msg = f"Refusing to extract unsafe archive member: {name}"
                    raise ValueError(msg)
                dest = payload_dir / norm
                dest.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info, "r") as src, Path(dest).open("wb") as dst:
                    shutil.copyfileobj(src, dst)

        if artifact_sha256:
            (payload_dir / _ARTIFACT_SHA_FILENAME).write_text(
                (artifact_sha256 or "").strip() + "\n",
                encoding="utf-8",
            )

        if target.exists():
            backup_dir = (
                parent / f".adblock-backup-{os.getpid()}-{int(time.time() * 1000)}"
            )
            if backup_dir.exists():
                shutil.rmtree(backup_dir, ignore_errors=True)
            Path(str(target)).replace(str(backup_dir))

        Path(str(payload_dir)).replace(str(target))
        if backup_dir is not None:
            shutil.rmtree(backup_dir, ignore_errors=True)
    except Exception:
        if backup_dir is not None and backup_dir.exists() and not target.exists():
            with contextlib.suppress(Exception):
                Path(str(backup_dir)).replace(str(target))
        raise
    finally:
        shutil.rmtree(stage_root, ignore_errors=True)


def _restart_local_adblock_service() -> tuple[bool, str]:
    try:
        proc = subprocess.run(
            [
                "supervisorctl",
                "-c",
                "/etc/supervisord.conf",
                "restart",
                "cicap_adblock",
            ],
            capture_output=True,
            timeout=30,
        )
    except Exception as exc:
        return False, public_error_message(
            exc,
            default="Failed to restart the adblock ICAP helper.",
        )

    stdout = (proc.stdout or b"").decode("utf-8", errors="replace").strip()
    stderr = (proc.stderr or b"").decode("utf-8", errors="replace").strip()
    detail = (
        "\n".join(part for part in (stdout, stderr) if part).strip()
        or "Adblock ICAP helper restarted."
    )
    return proc.returncode == 0, detail


def apply_active_artifact_locally(
    *,
    force: bool = False,
    clear_cache: bool = False,
    compiled_dir: str | os.PathLike[str] | None = None,
) -> tuple[bool, str]:
    from services.adblock_store import get_adblock_store

    store = get_adblock_store()
    artifacts = get_adblock_artifacts()
    revision = artifacts.get_active_artifact()
    target_dir = str(compiled_dir or artifacts.compiled_dir)
    flush_requested = bool(clear_cache or store.get_cache_flush_requested())
    current_sha = read_materialized_artifact_sha(target_dir)
    changed = False

    if revision is not None and current_sha != revision.artifact_sha256:
        materialize_archive_to_directory(
            target_dir,
            archive_blob=revision.archive_blob,
            artifact_sha256=revision.artifact_sha256,
        )
        changed = True

    if revision is None and not flush_requested and not changed:
        return True, "No active adblock artifact is available."
    if not changed and not flush_requested:
        return True, "Adblock runtime is already current."

    ok, detail = _restart_local_adblock_service()
    if ok and flush_requested:
        try:
            store.mark_cache_flushed(size=0)
        except Exception as exc:
            clear_detail = public_error_message(
                exc,
                default="Failed to clear adblock cache flush request.",
            )
            detail = "\n".join(
                part for part in (detail.strip(), clear_detail) if part
            ).strip()
            return False, detail
    return ok, detail


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
