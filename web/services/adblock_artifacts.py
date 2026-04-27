from __future__ import annotations

import hashlib
import io
import json
import logging
import os
import shutil
import subprocess
import tempfile
import threading
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from services.db import connect
from services.errors import public_error_message
from services.logutil import log_exception_throttled
from services.proxy_sync import nudge_registered_proxies
from services.runtime_helpers import env_int as _env_int, now_ts as _now


logger = logging.getLogger(__name__)

_ARTIFACT_SHA_FILENAME = ".artifact-sha256"
_DEFAULT_COMPILED_DIR = "/var/lib/squid-flask-proxy/adblock/compiled"
_DEFAULT_SETTINGS_FILENAME = "settings.json"


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
        try:
            raw = json.loads(self.enabled_lists_json or "[]")
        except Exception:
            return []
        if not isinstance(raw, list):
            return []
        return [str(item).strip() for item in raw if str(item).strip()]

    @property
    def report(self) -> dict[str, Any]:
        try:
            raw = json.loads(self.report_json or "{}")
        except Exception:
            return {}
        return raw if isinstance(raw, dict) else {}


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
    def __init__(self, *, compiled_dir: str | None = None):
        self.compiled_dir = (compiled_dir or os.environ.get("ADBLOCK_COMPILED_DIR") or _DEFAULT_COMPILED_DIR).strip() or _DEFAULT_COMPILED_DIR
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
                """
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
                """
            )

    def _row_to_revision(self, row: object | None) -> Optional[AdblockArtifactRevision]:
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

    def _row_to_application(self, row: object | None) -> Optional[AdblockArtifactApplication]:
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

    def _row_to_metadata(self, row: object | None) -> Optional[AdblockArtifactMetadata]:
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

    def get_active_artifact(self) -> Optional[AdblockArtifactRevision]:
        self.init_db()
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM adblock_artifact_revisions
                WHERE is_active=1
                ORDER BY created_ts DESC, id DESC
                LIMIT 1
                """
            ).fetchone()
        return self._row_to_revision(row)

    def get_active_artifact_metadata(self) -> Optional[AdblockArtifactMetadata]:
        self.init_db()
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT id, artifact_sha256, settings_version, source_kind, enabled_lists_json, created_by, created_ts, is_active
                FROM adblock_artifact_revisions
                WHERE is_active=1
                ORDER BY created_ts DESC, id DESC
                LIMIT 1
                """
            ).fetchone()
        return self._row_to_metadata(row)

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
        enabled_lists_json = json.dumps(sorted(set(str(item).strip() for item in enabled_lists if str(item).strip())))
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
                conn.execute("UPDATE adblock_artifact_revisions SET is_active=0 WHERE is_active=1")
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

    def latest_apply(self, proxy_id: object | None) -> Optional[AdblockArtifactApplication]:
        self.init_db()
        from services.proxy_context import normalize_proxy_id

        proxy_key = normalize_proxy_id(proxy_id)
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM proxy_adblock_artifact_applications
                WHERE proxy_id=%s
                ORDER BY applied_ts DESC, id DESC
                LIMIT 1
                """,
                (proxy_key,),
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
        settings_version = store.get_settings_version()
        statuses = store.list_statuses()
        enabled_statuses = [status for status in statuses if status.enabled]
        previous = self.get_active_artifact()
        any_downloaded = False

        if bool(settings.get("enabled")) and enabled_statuses:
            now_ts = _now()
            for status in enabled_statuses:
                list_path = store.list_path(status.key)
                needs_download = refresh_lists or not os.path.exists(list_path) or store.should_update(status, now_ts, False)
                if not needs_download:
                    continue
                force_download = bool(refresh_lists or not os.path.exists(list_path))
                any_downloaded = bool(store.update_one(status.key, force=force_download)) or any_downloaded

        try:
            with tempfile.TemporaryDirectory(prefix="adblock-build-") as out_dir:
                if bool(settings.get("enabled")) and enabled_statuses:
                    _compile_current_lists(lists_dir=store.lists_dir, out_dir=out_dir)
                else:
                    _write_empty_output(out_dir)
                _write_settings_file(
                    out_dir,
                    settings=settings,
                    settings_version=settings_version,
                    enabled_lists=[status.key for status in enabled_statuses],
                )
                revision = self.create_revision_from_directory(
                    out_dir,
                    settings_version=settings_version,
                    enabled_lists=[status.key for status in enabled_statuses],
                    created_by=created_by,
                    source_kind=source_kind,
                    activate=True,
                )
        except Exception as exc:
            logger.exception("adblock artifact build failed")
            return {
                "ok": False,
                "detail": public_error_message(exc, default="Adblock artifact build failed."),
                "revision": None,
                "changed": False,
                "downloaded": any_downloaded,
            }

        changed = previous is None or previous.revision_id != revision.revision_id or previous.artifact_sha256 != revision.artifact_sha256
        detail = "Adblock artifact is already current."
        if changed:
            detail = f"Activated adblock artifact revision {revision.revision_id}."
        return {
            "ok": True,
            "detail": detail,
            "revision": revision,
            "changed": changed,
            "downloaded": any_downloaded,
        }

    def start_background(self) -> None:
        with self._lock:
            if self._started:
                return
            self._started = True
            self.init_db()
            thread = threading.Thread(target=self._loop, name="adblock-artifact-builder", daemon=True)
            thread.start()

    def _loop(self) -> None:
        poll_seconds = float(_env_int("ADBLOCK_BUILDER_POLL_SECONDS", 30, minimum=5, maximum=3600))
        error_seconds = float(_env_int("ADBLOCK_BUILDER_ERROR_BACKOFF_SECONDS", 30, minimum=5, maximum=300))
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
                due_download = bool(settings.get("enabled")) and any(
                    (not os.path.exists(store.list_path(status.key)) or store.should_update(status, _now(), False))
                    for status in enabled_statuses
                )
                needs_build = refresh_requested or active is None or (active is not None and active.settings_version != settings_version) or due_download
                if needs_build:
                    result = self.build_active_artifact(refresh_lists=refresh_requested, created_by="system", source_kind="background")
                    if not bool(result.get("ok")):
                        sleep_seconds = error_seconds
                    else:
                        try:
                            store.clear_refresh_requested()
                        except Exception:
                            pass
                        if bool(result.get("changed")):
                            nudge_registered_proxies(force=False)
                        sleep_seconds = 5.0
            except Exception:
                log_exception_throttled(
                    logger,
                    "adblock_artifacts.loop",
                    interval_seconds=30.0,
                    message="Adblock artifact builder loop failed",
                )
                sleep_seconds = error_seconds
            time.sleep(sleep_seconds)
def _compile_current_lists(*, lists_dir: str, out_dir: str) -> None:
    from tools import adblock_compile  # type: ignore

    rc = int(adblock_compile.main(["--lists-dir", str(lists_dir), "--out-dir", str(out_dir)]))
    if rc != 0:
        raise RuntimeError(f"adblock_compile failed with exit code {rc}")


def _write_empty_output(out_dir: str) -> None:
    root = Path(out_dir)
    root.mkdir(parents=True, exist_ok=True)
    for filename in ("domains_allow.txt", "domains_block.txt", "regex_allow.txt", "regex_block.txt"):
        (root / filename).write_text("", encoding="utf-8")
    report = {
        "enabled_lists": [],
        "counts": {
            "domains_allow": 0,
            "domains_block": 0,
            "regex_allow": 0,
            "regex_block": 0,
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
        },
        "per_list": {},
        "notes": {
            "empty": "No enabled adblock lists are active, so the materialized artifact contains empty allow/block tables."
        },
    }
    (root / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


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
        "enabled_lists": sorted(set(str(item).strip() for item in enabled_lists if str(item).strip())),
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


def read_materialized_artifact_sha(compiled_dir: str | os.PathLike[str] | None = None) -> str:
    root = Path(compiled_dir or os.environ.get("ADBLOCK_COMPILED_DIR") or _DEFAULT_COMPILED_DIR)
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
                if norm.startswith("../") or norm.startswith("/") or norm == "..":
                    raise ValueError(f"Refusing to extract unsafe archive member: {name}")
                dest = payload_dir / norm
                dest.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info, "r") as src, open(dest, "wb") as dst:
                    shutil.copyfileobj(src, dst)

        if artifact_sha256:
            (payload_dir / _ARTIFACT_SHA_FILENAME).write_text(
                (artifact_sha256 or "").strip() + "\n",
                encoding="utf-8",
            )

        if target.exists():
            backup_dir = parent / f".adblock-backup-{os.getpid()}-{int(time.time() * 1000)}"
            if backup_dir.exists():
                shutil.rmtree(backup_dir, ignore_errors=True)
            os.replace(str(target), str(backup_dir))

        os.replace(str(payload_dir), str(target))
        if backup_dir is not None:
            shutil.rmtree(backup_dir, ignore_errors=True)
    except Exception:
        if backup_dir is not None and backup_dir.exists() and not target.exists():
            try:
                os.replace(str(backup_dir), str(target))
            except Exception:
                pass
        raise
    finally:
        shutil.rmtree(stage_root, ignore_errors=True)


def _restart_local_adblock_service() -> tuple[bool, str]:
    try:
        proc = subprocess.run(
            ["supervisorctl", "-c", "/etc/supervisord.conf", "restart", "cicap_adblock"],
            capture_output=True,
            timeout=30,
        )
    except Exception as exc:
        return False, public_error_message(exc, default="Failed to restart cicap_adblock.")

    stdout = (proc.stdout or b"").decode("utf-8", errors="replace").strip()
    stderr = (proc.stderr or b"").decode("utf-8", errors="replace").strip()
    detail = "\n".join(part for part in (stdout, stderr) if part).strip() or "cicap_adblock restarted."
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

    if revision is not None and (force or current_sha != revision.artifact_sha256):
        materialize_archive_to_directory(target_dir, archive_blob=revision.archive_blob, artifact_sha256=revision.artifact_sha256)
        changed = True

    if revision is None and not flush_requested and not changed:
        return True, "No active adblock artifact is available."
    if not changed and not flush_requested:
        return True, "Adblock runtime is already current."

    ok, detail = _restart_local_adblock_service()
    if ok and flush_requested:
        try:
            store.mark_cache_flushed(size=0)
        except Exception:
            pass
    return ok, detail


_store: Optional[AdblockArtifactStore] = None
_store_lock = threading.Lock()


def get_adblock_artifacts() -> AdblockArtifactStore:
    global _store
    if _store is not None:
        return _store
    with _store_lock:
        if _store is None:
            _store = AdblockArtifactStore()
            _store.init_db()
        return _store
