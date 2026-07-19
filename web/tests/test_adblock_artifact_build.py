from __future__ import annotations

import importlib
import io
import json
import os
import sqlite3
import sys
import zipfile
from email.message import Message
from pathlib import Path
from types import SimpleNamespace

import pymysql
import pytest

from .mysql_test_utils import configure_test_mysql_env


def _import_artifact_modules(tmp_path: Path):
    repo_root = Path(__file__).resolve().parents[2]
    web_root = repo_root / "web"
    for path in (str(repo_root), str(web_root)):
        if path not in sys.path:
            sys.path.insert(0, path)

    os.environ["DISABLE_BACKGROUND"] = "1"
    configure_test_mysql_env(tmp_path, secret_path=tmp_path / "flask_secret.key")

    import services.adblock_artifacts as artifacts_module  # type: ignore
    import services.adblock_store as store_module  # type: ignore

    importlib.reload(store_module)
    importlib.reload(artifacts_module)
    return store_module, artifacts_module


def _import_adblock_artifacts_module():
    repo_root = Path(__file__).resolve().parents[2]
    web_root = repo_root / "web"
    for path in (str(repo_root), str(web_root)):
        if path not in sys.path:
            sys.path.insert(0, path)

    os.environ["DISABLE_BACKGROUND"] = "1"
    import services.adblock_artifacts as artifacts_module  # type: ignore

    return importlib.reload(artifacts_module)


class _FakeSqlResult:
    def __init__(self, rows=None, *, rowcount: int = 0, lastrowid: int | None = None) -> None:
        self._rows = list(rows or [])
        self.rowcount = rowcount
        self.lastrowid = lastrowid

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return list(self._rows)


class _FakeAdblockRevisionConn:
    def __init__(self, rows: list[dict[str, int]]) -> None:
        self.rows = rows
        self.deleted_batches: list[list[int]] = []
        self.updated_batches: list[list[int]] = []
        self.commits = 0

    def commit(self) -> None:
        self.commits += 1

    def execute(self, sql: str, params=()):
        text = " ".join(sql.split())
        params = tuple(params or ())
        if text.startswith(
            "SELECT id FROM adblock_artifact_revisions WHERE is_active=1",
        ):
            limit = int(params[0]) if params else 1
            rows = sorted(
                (row for row in self.rows if int(row["is_active"]) == 1),
                key=lambda row: (int(row["created_ts"]), int(row["id"])),
                reverse=True,
            )[:limit]
            return _FakeSqlResult([(row["id"],) for row in rows])
        if text.startswith(
            "SELECT id FROM adblock_artifact_revisions WHERE is_active=0 AND id NOT IN",
        ):
            limit = int(params[-1])
            keep_ids = {int(value) for value in params[:-1]}
            rows = sorted(
                (
                    row
                    for row in self.rows
                    if int(row["is_active"]) == 0 and int(row["id"]) not in keep_ids
                ),
                key=lambda row: (int(row["created_ts"]), int(row["id"])),
            )[:limit]
            return _FakeSqlResult([(row["id"],) for row in rows])
        if text.startswith(
            "SELECT id FROM adblock_artifact_revisions WHERE is_active=0",
        ):
            limit = int(params[0]) if params else 1
            reverse = "DESC" in text
            rows = sorted(
                (row for row in self.rows if int(row["is_active"]) == 0),
                key=lambda row: (int(row["created_ts"]), int(row["id"])),
                reverse=reverse,
            )[:limit]
            return _FakeSqlResult([(row["id"],) for row in rows])
        if text.startswith("SELECT id FROM adblock_artifact_revisions ORDER BY"):
            limit = int(params[0]) if params else 2
            rows = sorted(
                self.rows,
                key=lambda row: (int(row["created_ts"]), int(row["id"])),
                reverse=True,
            )[:limit]
            return _FakeSqlResult([(row["id"],) for row in rows])
        if text.startswith("UPDATE adblock_artifact_revisions SET is_active=0 WHERE id IN"):
            ids = {int(value) for value in params}
            changed = 0
            for row in self.rows:
                if int(row["id"]) in ids and int(row["is_active"]) == 1:
                    row["is_active"] = 0
                    changed += 1
            self.updated_batches.append(sorted(ids))
            return _FakeSqlResult(rowcount=changed)
        if text.startswith("DELETE FROM adblock_artifact_revisions WHERE id IN"):
            ids = {int(value) for value in params}
            self.rows[:] = [row for row in self.rows if int(row["id"]) not in ids]
            self.deleted_batches.append(sorted(ids))
            return _FakeSqlResult(rowcount=len(ids))
        msg = f"Unexpected SQL: {text}"
        raise AssertionError(msg)


def _read_zipped_sqlite(
    zf: zipfile.ZipFile, name: str, tmp_path: Path
) -> sqlite3.Connection:
    db_path = tmp_path / name
    db_path.write_bytes(zf.read(name))
    return sqlite3.connect(str(db_path))


def _enable_first_default_list(store, tmp_path: Path, *, enabled: bool = True) -> str:
    store.lists_dir = str(tmp_path / "lists")
    Path(store.lists_dir).mkdir(parents=True, exist_ok=True)
    store.init_db()

    statuses = store.list_statuses()
    assert statuses, "expected default adblock lists to be present"
    selected = statuses[0].key

    store.set_enabled({status.key: status.key == selected for status in statuses})
    store.set_settings(enabled=enabled, cache_ttl=120, cache_max=4096)
    return selected


def test_artifact_revision_and_summary_share_json_property_parsing(
    tmp_path: Path,
) -> None:
    _store_module, artifacts_module = _import_artifact_modules(tmp_path)

    common = {
        "artifact_sha256": "a" * 64,
        "report_json": '{"ok": true}',
        "settings_version": 3,
        "source_kind": "compile",
        "enabled_lists_json": '[" easylist ", "", "easyprivacy"]',
        "created_by": "tester",
        "created_ts": 123,
        "is_active": True,
    }
    revision = artifacts_module.AdblockArtifactRevision(
        revision_id=1,
        archive_blob=b"archive",
        **common,
    )
    summary = artifacts_module.AdblockArtifactSummary(revision_id=1, **common)

    assert revision.enabled_lists == ["easylist", "easyprivacy"]
    assert summary.enabled_lists == revision.enabled_lists
    assert revision.report == {"ok": True}
    assert summary.report == revision.report

    malformed = {
        **common,
        "report_json": "[1, 2]",
        "enabled_lists_json": "{",
    }
    revision = artifacts_module.AdblockArtifactRevision(
        revision_id=2,
        archive_blob=b"archive",
        **malformed,
    )
    summary = artifacts_module.AdblockArtifactSummary(revision_id=2, **malformed)

    assert revision.enabled_lists == summary.enabled_lists == []
    assert revision.report == summary.report == {}


def test_build_active_artifact_packages_compiled_lists_and_settings(
    tmp_path, monkeypatch
) -> None:
    env_backup = {key: os.environ.get(key) for key in ("DISABLE_BACKGROUND",)}
    try:
        store_module, artifacts_module = _import_artifact_modules(tmp_path)

        store = store_module.get_adblock_store()
        selected = _enable_first_default_list(store, tmp_path)

        Path(store.list_path(selected)).write_text(
            "! comment\n||ads.example^\n@@||allow.example^\n/tracker[.]example/\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(store, "update_one", lambda *_args, **_kwargs: False)

        result = artifacts_module.get_adblock_artifacts().build_active_artifact(
            refresh_lists=False,
            created_by="tester",
            source_kind="test",
        )

        assert result["ok"] is True
        assert result["changed"] is True
        revision = result["revision"]
        assert revision is not None
        assert revision.created_by == "tester"
        assert revision.source_kind == "test"
        assert revision.enabled_lists == [selected]

        with zipfile.ZipFile(io.BytesIO(revision.archive_blob), mode="r") as zf:
            names = set(zf.namelist())
            assert {
                "request_index_domain.jsonl",
                "request_index_host.jsonl",
                "request_index_regex.jsonl",
                "request_index_generic.jsonl",
                "request_lookup.sqlite",
                "settings.json",
                "report.json",
            } <= names
            assert "domains_allow.txt" not in names
            assert "domains_block.txt" not in names
            assert "regex_allow.txt" not in names
            assert "regex_block.txt" not in names
            settings = json.loads(
                zf.read("settings.json").decode("utf-8", errors="replace")
            )
            report = json.loads(
                zf.read("report.json").decode("utf-8", errors="replace")
            )
            request_index_domain = zf.read("request_index_domain.jsonl").decode(
                "utf-8", errors="replace"
            )
            request_index_regex = zf.read("request_index_regex.jsonl").decode(
                "utf-8", errors="replace"
            )
            lookup_conn = _read_zipped_sqlite(zf, "request_lookup.sqlite", tmp_path)
            try:
                lookup_counts = {
                    "rules": lookup_conn.execute(
                        "SELECT COUNT(*) FROM rules"
                    ).fetchone()[0],
                    "domain_index": lookup_conn.execute(
                        "SELECT COUNT(*) FROM domain_index"
                    ).fetchone()[0],
                    "regex_index": lookup_conn.execute(
                        "SELECT COUNT(*) FROM regex_index"
                    ).fetchone()[0],
                }
                indexed_host = lookup_conn.execute(
                    "SELECT action FROM domain_index WHERE host=?",
                    ("ads.example",),
                ).fetchone()
            finally:
                lookup_conn.close()

        assert '"host": "ads.example"' in request_index_domain
        assert '"pattern_kind": "regex"' in request_index_regex
        assert settings == {
            "cache_max": 4096,
            "cache_ttl": 120,
            "enabled": True,
            "enabled_lists": [selected],
            "settings_version": store.get_settings_version(),
        }
        assert report["enabled_lists"] == [selected]
        assert int(report["counts"]["network_rules_total"]) == 3
        assert report["breakdowns"]["lookup_index_counts"]["rules"] == 3
        assert lookup_counts == {
            "rules": 3,
            "domain_index": 2,
            "regex_index": 1,
        }
        assert indexed_host == ("block",)
    finally:
        for key, value in env_backup.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def test_build_active_artifact_reports_download_pending_when_due_download_fails_but_cached_lists_compile(
    tmp_path, monkeypatch
) -> None:
    env_backup = {key: os.environ.get(key) for key in ("DISABLE_BACKGROUND",)}
    try:
        store_module, artifacts_module = _import_artifact_modules(tmp_path)

        store = store_module.get_adblock_store()
        selected = _enable_first_default_list(store, tmp_path)

        Path(store.list_path(selected)).write_text(
            "||ads.example^\n",
            encoding="utf-8",
        )

        monkeypatch.setattr(store, "should_update", lambda *_args, **_kwargs: True)
        monkeypatch.setattr(store, "update_one", lambda *_args, **_kwargs: False)

        result = artifacts_module.get_adblock_artifacts().build_active_artifact(
            refresh_lists=False,
            created_by="tester",
            source_kind="test",
        )

        assert result["ok"] is True
        assert result["downloaded"] is False
        assert result["download_pending"] is True
        status = store.get_artifact_build_status()
        assert status["ok"] is True
        assert status["download_pending"] is True
        assert "locally cached lists" in status["detail"]
    finally:
        for key, value in env_backup.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def test_build_active_artifact_persists_download_pending_when_no_cached_lists(
    tmp_path, monkeypatch
) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    web_root = repo_root / "web"
    for path in (str(repo_root), str(web_root)):
        if path not in sys.path:
            sys.path.insert(0, path)

    import services.adblock_artifacts as artifacts_module  # type: ignore
    import services.adblock_store as store_module  # type: ignore

    importlib.reload(artifacts_module)

    lists_dir = tmp_path / "lists"
    lists_dir.mkdir(parents=True, exist_ok=True)
    selected = "easylist"
    recorded: dict[str, object] = {}

    class FakeStore:
        def __init__(self) -> None:
            self.lists_dir = str(lists_dir)

        def init_db(self) -> None:
            return None

        def get_settings(self) -> dict[str, object]:
            return {"enabled": True, "cache_ttl": 120, "cache_max": 4096}

        def get_settings_version(self) -> int:
            return 7

        def list_statuses(self) -> list[SimpleNamespace]:
            return [SimpleNamespace(key=selected, enabled=True)]

        def list_path(self, key: str) -> str:
            assert key == selected
            return str(lists_dir / f"{key}.txt")

        def update_one(self, key: str, *, force: bool = False) -> bool:
            assert key == selected
            assert force is True
            return False

        def record_artifact_build_result(self, **kwargs: object) -> None:
            recorded.update(kwargs)

    monkeypatch.setattr(store_module, "get_adblock_store", FakeStore)

    artifact_store = artifacts_module.AdblockArtifactStore(
        compiled_dir=str(tmp_path / "compiled"),
    )
    monkeypatch.setattr(artifact_store, "init_db", lambda: None)
    monkeypatch.setattr(artifact_store, "get_active_artifact", lambda: None)

    result = artifact_store.build_active_artifact(
        refresh_lists=False,
        created_by="tester",
        source_kind="test",
    )

    assert result["ok"] is False
    assert result["download_pending"] is True
    assert recorded["ok"] is False
    assert recorded["download_pending"] is True
    assert "could not be downloaded" in str(recorded["detail"])


def test_build_active_artifact_reports_no_effective_lists_when_adblock_disabled(
    tmp_path, monkeypatch
) -> None:
    env_backup = {key: os.environ.get(key) for key in ("DISABLE_BACKGROUND",)}
    try:
        store_module, artifacts_module = _import_artifact_modules(tmp_path)

        store = store_module.get_adblock_store()
        _enable_first_default_list(store, tmp_path, enabled=False)
        monkeypatch.setattr(store, "update_one", lambda *_args, **_kwargs: False)

        result = artifacts_module.get_adblock_artifacts().build_active_artifact(
            refresh_lists=False,
            created_by="tester",
            source_kind="test",
        )

        assert result["ok"] is True
        revision = result["revision"]
        assert revision is not None
        assert revision.enabled_lists == []

        with zipfile.ZipFile(io.BytesIO(revision.archive_blob), mode="r") as zf:
            names = set(zf.namelist())
            settings = json.loads(
                zf.read("settings.json").decode("utf-8", errors="replace")
            )
            report = json.loads(
                zf.read("report.json").decode("utf-8", errors="replace")
            )
            lookup_conn = _read_zipped_sqlite(zf, "request_lookup.sqlite", tmp_path)
            try:
                empty_rule_count = lookup_conn.execute(
                    "SELECT COUNT(*) FROM rules"
                ).fetchone()[0]
                schema_version = lookup_conn.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()[0]
                lookup_strategy = lookup_conn.execute(
                    "SELECT value FROM metadata WHERE key='lookup_strategy'"
                ).fetchone()[0]
                idx_resource_type_rule_present = lookup_conn.execute(
                    """
                    SELECT 1 FROM sqlite_master
                    WHERE type='index' AND name='idx_resource_type_rule'
                    """
                ).fetchone()
            finally:
                lookup_conn.close()

        assert {
            "network_rules.jsonl",
            "network_option_misc.jsonl",
            "request_index_domain.jsonl",
            "request_index_host.jsonl",
            "request_index_regex.jsonl",
            "request_index_generic.jsonl",
            "request_lookup.sqlite",
            "cosmetic_scriptlet.jsonl",
            "cosmetic_html_filter.jsonl",
            "network_type_popup.jsonl",
            "network_type_not_popup.jsonl",
        } <= names
        assert settings["enabled"] is False
        assert settings["enabled_lists"] == []
        assert report["enabled_lists"] == []
        assert report["breakdowns"]["lookup_index_counts"]["rules"] == 0
        assert empty_rule_count == 0
        assert schema_version == "4"
        assert idx_resource_type_rule_present == (1,)
        assert "host-pattern/regex token prefilters" in lookup_strategy
        assert "generic literal-key prefilter" in lookup_strategy
    finally:
        for key, value in env_backup.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def test_apply_active_artifact_locally_reports_cache_flush_marker_failure(
    tmp_path,
    monkeypatch,
) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    web_root = repo_root / "web"
    for path in (str(repo_root), str(web_root)):
        if path not in sys.path:
            sys.path.insert(0, path)

    os.environ["DISABLE_BACKGROUND"] = "1"

    import services.adblock_artifacts as artifacts_module  # type: ignore
    import services.adblock_store as store_module  # type: ignore

    importlib.reload(store_module)
    importlib.reload(artifacts_module)

    class Store:
        def get_cache_flush_requested(self) -> bool:
            return True

        def mark_cache_flushed(self, *, size=0) -> None:
            msg = "db unavailable"
            raise RuntimeError(msg)

    class Artifacts:
        compiled_dir = str(tmp_path / "compiled")

        def get_active_artifact(self):
            return None

    monkeypatch.setattr(artifacts_module, "get_adblock_artifacts", Artifacts)
    monkeypatch.setattr(store_module, "get_adblock_store", Store)
    monkeypatch.setattr(
        artifacts_module,
        "_restart_local_adblock_service",
        lambda: (True, "restarted"),
    )

    ok, detail = artifacts_module.apply_active_artifact_locally()

    assert ok is False
    assert "restarted" in detail
    assert "Failed to clear adblock cache flush request" in detail


def test_background_build_detects_enabled_list_drift_without_version_change(
    tmp_path,
) -> None:
    _store_module, artifacts_module = _import_artifact_modules(tmp_path)

    active = SimpleNamespace(enabled_lists=["easylist"], source_kind="background")

    assert (
        artifacts_module._active_enabled_lists_drift(
            active,
            settings_enabled=True,
            enabled_statuses=[
                SimpleNamespace(key="easylist", enabled=True),
                SimpleNamespace(key="easyprivacy", enabled=True),
            ],
        )
        is True
    )
    assert (
        artifacts_module._active_enabled_lists_drift(
            SimpleNamespace(
                enabled_lists=["easyprivacy", "easylist"],
                source_kind="background",
            ),
            settings_enabled=True,
            enabled_statuses=[
                SimpleNamespace(key="easylist", enabled=True),
                SimpleNamespace(key="easyprivacy", enabled=True),
            ],
        )
        is False
    )
    assert (
        artifacts_module._active_enabled_lists_drift(
            active,
            settings_enabled=False,
            enabled_statuses=[SimpleNamespace(key="easylist", enabled=True)],
        )
        is True
    )
    assert (
        artifacts_module._active_enabled_lists_drift(
            SimpleNamespace(enabled_lists=[], source_kind="background"),
            settings_enabled=False,
            enabled_statuses=[SimpleNamespace(key="easylist", enabled=True)],
        )
        is False
    )
    assert (
        artifacts_module._active_enabled_lists_drift(
            SimpleNamespace(enabled_lists=["live-fixture"], source_kind="live_fixture"),
            settings_enabled=True,
            enabled_statuses=[SimpleNamespace(key="easylist", enabled=True)],
        )
        is False
    )


def test_background_loop_nudges_changed_artifact_even_when_download_pending(
    tmp_path, monkeypatch
) -> None:
    store_module, artifacts_module = _import_artifact_modules(tmp_path)

    lists_dir = tmp_path / "lists"
    lists_dir.mkdir(parents=True, exist_ok=True)
    list_path = lists_dir / "easylist.txt"
    list_path.write_text("||cached.example^\n", encoding="utf-8")
    cleared: list[bool] = []
    nudges: list[bool] = []
    sleeps: list[float] = []

    class StopLoopError(Exception):
        pass

    class FakeStore:
        def init_db(self) -> None:
            return None

        def get_settings(self) -> dict[str, object]:
            return {"enabled": True}

        def list_statuses(self) -> list[SimpleNamespace]:
            return [SimpleNamespace(key="easylist", enabled=True)]

        def get_refresh_requested(self) -> int:
            return 1

        def get_settings_version(self) -> int:
            return 7

        def list_path(self, key: str) -> str:
            assert key == "easylist"
            return str(list_path)

        def should_update(self, *_args, **_kwargs) -> bool:
            return False

        def clear_refresh_requested(self) -> None:
            cleared.append(True)

    monkeypatch.setattr(store_module, "get_adblock_store", FakeStore)
    monkeypatch.setattr(
        artifacts_module,
        "nudge_registered_proxies",
        lambda *, force=False: nudges.append(bool(force)) or (1, 1),
    )

    def sleep_once(seconds: float) -> None:
        sleeps.append(seconds)
        raise StopLoopError

    monkeypatch.setattr(artifacts_module.time, "sleep", sleep_once)

    artifact_store = artifacts_module.AdblockArtifactStore(
        compiled_dir=str(tmp_path / "compiled"),
    )
    monkeypatch.setattr(artifact_store, "init_db", lambda: None)
    monkeypatch.setattr(
        artifact_store,
        "get_active_artifact",
        lambda: SimpleNamespace(
            revision_id=4,
            settings_version=7,
            enabled_lists=["easylist"],
            source_kind="background",
        ),
    )
    monkeypatch.setattr(
        artifact_store,
        "build_active_artifact",
        lambda **_kwargs: {"ok": True, "changed": True, "download_pending": True},
    )

    try:
        artifact_store._loop()
    except StopLoopError:
        pass
    else:
        msg = "background loop did not reach its sleep boundary"
        raise AssertionError(msg)

    assert nudges == [False]
    assert cleared == []
    assert sleeps == [30.0]


def test_manual_refresh_downloads_enabled_lists_even_when_adblock_disabled(
    tmp_path, monkeypatch
) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    web_root = repo_root / "web"
    for path in (str(repo_root), str(web_root)):
        if path not in sys.path:
            sys.path.insert(0, path)

    import services.adblock_artifacts as artifacts_module  # type: ignore
    import services.adblock_store as store_module  # type: ignore

    importlib.reload(artifacts_module)

    lists_dir = tmp_path / "lists"
    lists_dir.mkdir(parents=True, exist_ok=True)
    selected = "easylist"
    downloaded: list[str] = []

    class FakeStore:
        def __init__(self) -> None:
            self.lists_dir = str(lists_dir)

        def init_db(self) -> None:
            return None

        def get_settings(self) -> dict[str, object]:
            return {"enabled": False, "cache_ttl": 120, "cache_max": 4096}

        def get_settings_version(self) -> int:
            return 7

        def list_statuses(self) -> list[SimpleNamespace]:
            return [SimpleNamespace(key=selected, enabled=True)]

        def list_path(self, key: str) -> str:
            return str(lists_dir / f"{key}.txt")

        def should_update(self, *_args, **_kwargs) -> bool:
            return False

        def update_one(self, key: str, *, force: bool = False) -> bool:
            assert key == selected
            assert force is True
            downloaded.append(key)
            Path(store.list_path(key)).write_text("||ads.example^\n", encoding="utf-8")
            return True

        def record_artifact_build_result(self, **_kwargs) -> None:
            return None

    store = FakeStore()
    monkeypatch.setattr(store_module, "get_adblock_store", lambda: store)

    artifact_store = artifacts_module.AdblockArtifactStore(
        compiled_dir=str(tmp_path / "compiled"),
    )
    monkeypatch.setattr(artifact_store, "init_db", lambda: None)
    monkeypatch.setattr(artifact_store, "get_active_artifact", lambda: None)

    created: dict[str, object] = {}

    def create_revision_from_directory(
        out_dir: str,
        *,
        settings_version: int,
        enabled_lists: list[str],
        created_by: str,
        source_kind: str,
        activate: bool,
    ) -> SimpleNamespace:
        created["settings"] = json.loads(
            Path(out_dir, "settings.json").read_text(encoding="utf-8")
        )
        created["report"] = json.loads(
            Path(out_dir, "report.json").read_text(encoding="utf-8")
        )
        return SimpleNamespace(
            revision_id=1,
            artifact_sha256="abc123",
            settings_version=settings_version,
            enabled_lists=enabled_lists,
            created_by=created_by,
            source_kind=source_kind,
            archive_blob=b"",
        )

    monkeypatch.setattr(
        artifact_store,
        "create_revision_from_directory",
        create_revision_from_directory,
    )
    monkeypatch.setattr(artifact_store, "estimate_archive_size", lambda _out_dir: 123)

    result = artifact_store.build_active_artifact(
        refresh_lists=True,
        created_by="tester",
        source_kind="test",
    )

    assert result["ok"] is True
    assert result["downloaded"] is True
    assert downloaded == [selected]
    revision = result["revision"]
    assert revision is not None
    assert revision.enabled_lists == []
    assert created["settings"]["enabled"] is False
    assert created["settings"]["enabled_lists"] == []
    assert created["report"]["enabled_lists"] == []
    assert created["report"]["breakdowns"]["lookup_index_counts"]["rules"] == 0


def test_build_active_artifact_preserves_previous_when_enabled_list_missing(
    tmp_path, monkeypatch
) -> None:
    env_backup = {key: os.environ.get(key) for key in ("DISABLE_BACKGROUND",)}
    try:
        store_module, artifacts_module = _import_artifact_modules(tmp_path)

        store = store_module.get_adblock_store()
        selected = _enable_first_default_list(store, tmp_path)
        list_path = Path(store.list_path(selected))
        list_path.write_text("||cached.example^\n", encoding="utf-8")
        monkeypatch.setattr(store, "update_one", lambda *_args, **_kwargs: False)

        artifacts = artifacts_module.get_adblock_artifacts()
        initial = artifacts.build_active_artifact(
            refresh_lists=False,
            created_by="tester",
            source_kind="test",
        )
        assert initial["ok"] is True
        previous_revision = initial["revision"]
        assert previous_revision is not None

        list_path.unlink()
        monkeypatch.setattr(store, "should_update", lambda *_args, **_kwargs: True)

        result = artifacts.build_active_artifact(
            refresh_lists=False,
            created_by="tester",
            source_kind="test",
        )

        assert result["ok"] is False
        assert result["changed"] is False
        assert result["download_pending"] is True
        assert result["revision"].revision_id == previous_revision.revision_id
        assert (
            artifacts.get_active_artifact().revision_id == previous_revision.revision_id
        )
    finally:
        for key, value in env_backup.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def test_build_active_artifact_preserves_previous_when_enabled_list_empty(
    tmp_path, monkeypatch
) -> None:
    env_backup = {key: os.environ.get(key) for key in ("DISABLE_BACKGROUND",)}
    try:
        store_module, artifacts_module = _import_artifact_modules(tmp_path)

        store = store_module.get_adblock_store()
        selected = _enable_first_default_list(store, tmp_path)
        list_path = Path(store.list_path(selected))
        list_path.write_text("||cached.example^\n", encoding="utf-8")
        monkeypatch.setattr(store, "update_one", lambda *_args, **_kwargs: False)

        artifacts = artifacts_module.get_adblock_artifacts()
        initial = artifacts.build_active_artifact(
            refresh_lists=False,
            created_by="tester",
            source_kind="test",
        )
        assert initial["ok"] is True
        previous_revision = initial["revision"]
        assert previous_revision is not None

        list_path.write_text("! header only\n[Adblock Plus 2.0]\n\n", encoding="utf-8")
        monkeypatch.setattr(store, "should_update", lambda *_args, **_kwargs: False)

        result = artifacts.build_active_artifact(
            refresh_lists=False,
            created_by="tester",
            source_kind="test",
        )

        assert result["ok"] is False
        assert result["changed"] is False
        assert result["download_pending"] is True
        assert result["revision"].revision_id == previous_revision.revision_id
        assert "no cached lists with rule content" in result["detail"]
        assert (
            artifacts.get_active_artifact().revision_id == previous_revision.revision_id
        )
    finally:
        for key, value in env_backup.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def test_build_active_artifact_preserves_previous_when_enabled_list_has_no_request_rules(
    tmp_path, monkeypatch
) -> None:
    env_backup = {key: os.environ.get(key) for key in ("DISABLE_BACKGROUND",)}
    try:
        store_module, artifacts_module = _import_artifact_modules(tmp_path)

        store = store_module.get_adblock_store()
        selected = _enable_first_default_list(store, tmp_path)
        list_path = Path(store.list_path(selected))
        list_path.write_text("||cached.example^\n", encoding="utf-8")
        monkeypatch.setattr(store, "update_one", lambda *_args, **_kwargs: False)

        artifacts = artifacts_module.get_adblock_artifacts()
        initial = artifacts.build_active_artifact(
            refresh_lists=False,
            created_by="tester",
            source_kind="test",
        )
        assert initial["ok"] is True
        previous_revision = initial["revision"]
        assert previous_revision is not None

        list_path.write_text("example.com##.advert\n", encoding="utf-8")

        result = artifacts.build_active_artifact(
            refresh_lists=False,
            created_by="tester",
            source_kind="test",
        )

        assert result["ok"] is False
        assert result["changed"] is False
        assert result["download_pending"] is False
        assert result["revision"].revision_id == previous_revision.revision_id
        assert "without any request-time rules" in result["detail"]
        assert (
            artifacts.get_active_artifact().revision_id == previous_revision.revision_id
        )
        status = store.get_artifact_build_status()
        assert status["ok"] is False
        assert status["revision_id"] == previous_revision.revision_id
    finally:
        for key, value in env_backup.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def test_build_active_artifact_preserves_previous_and_pending_on_compile_failure(
    tmp_path, monkeypatch
) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    web_root = repo_root / "web"
    for path in (str(repo_root), str(web_root)):
        if path not in sys.path:
            sys.path.insert(0, path)

    import services.adblock_artifacts as artifacts_module  # type: ignore
    import services.adblock_store as store_module  # type: ignore

    importlib.reload(artifacts_module)

    lists_dir = tmp_path / "lists"
    lists_dir.mkdir(parents=True, exist_ok=True)
    selected = "easylist"
    (lists_dir / f"{selected}.txt").write_text("||cached.example^\n", encoding="utf-8")
    recorded: dict[str, object] = {}
    previous_revision = SimpleNamespace(
        revision_id=42,
        artifact_sha256="previous-sha",
    )

    class FakeStore:
        def __init__(self) -> None:
            self.lists_dir = str(lists_dir)

        def init_db(self) -> None:
            return None

        def get_settings(self) -> dict[str, object]:
            return {"enabled": True, "cache_ttl": 120, "cache_max": 4096}

        def get_settings_version(self) -> int:
            return 7

        def list_statuses(self) -> list[SimpleNamespace]:
            return [SimpleNamespace(key=selected, enabled=True)]

        def list_path(self, key: str) -> str:
            assert key == selected
            return str(lists_dir / f"{key}.txt")

        def should_update(self, *_args, **_kwargs) -> bool:
            return True

        def update_one(self, key: str, *, force: bool = False) -> bool:
            assert key == selected
            assert force is False
            return False

        def record_artifact_build_result(self, **kwargs: object) -> None:
            recorded.update(kwargs)

    def fail_compile(**_kwargs) -> None:
        msg = "adblock_compile failed with exit code 2"
        raise RuntimeError(msg)

    monkeypatch.setattr(store_module, "get_adblock_store", FakeStore)
    monkeypatch.setattr(artifacts_module, "_compile_current_lists", fail_compile)

    artifact_store = artifacts_module.AdblockArtifactStore(
        compiled_dir=str(tmp_path / "compiled"),
    )
    monkeypatch.setattr(artifact_store, "init_db", lambda: None)
    monkeypatch.setattr(
        artifact_store, "get_active_artifact", lambda: previous_revision
    )

    result = artifact_store.build_active_artifact(
        refresh_lists=False,
        created_by="tester",
        source_kind="test",
    )

    assert result["ok"] is False
    assert result["changed"] is False
    assert result["downloaded"] is False
    assert result["download_pending"] is True
    assert result["revision"].revision_id == previous_revision.revision_id
    assert recorded["ok"] is False
    assert recorded["download_pending"] is True
    assert recorded["revision_id"] == previous_revision.revision_id
    assert recorded["artifact_sha256"] == previous_revision.artifact_sha256


def test_adblock_download_rejects_hostname_resolving_private(
    tmp_path, monkeypatch
) -> None:
    store_module, _artifacts_module = _import_artifact_modules(tmp_path)
    download_safety = store_module.download_safety

    def fake_getaddrinfo(host: str, *_args, **_kwargs):
        assert host == "public.example"
        return [
            (
                download_safety.socket.AF_INET,
                download_safety.socket.SOCK_STREAM,
                0,
                "",
                ("127.0.0.1", 0),
            ),
        ]

    monkeypatch.setattr(download_safety.socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(
        download_safety.urllib.request,
        "build_opener",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("download should not open internal resolved host")
        ),
    )

    store = store_module.AdblockStore(lists_dir=str(tmp_path / "lists"))
    ok, err, bytes_read, rules = store.download_list(
        "easylist",
        "https://public.example/easylist.txt",
    )

    assert ok is False
    assert "internal/localhost" in err
    assert bytes_read == 0
    assert rules == 0


def test_adblock_download_rejects_hostname_when_dns_cannot_be_verified(
    tmp_path, monkeypatch
) -> None:
    store_module, _artifacts_module = _import_artifact_modules(tmp_path)
    download_safety = store_module.download_safety

    def fake_getaddrinfo(host: str, *_args, **_kwargs):
        assert host == "public.example"
        msg = "resolver unavailable"
        raise download_safety.socket.gaierror(msg)

    monkeypatch.setattr(download_safety.socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(
        download_safety.urllib.request,
        "build_opener",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("download should not open when DNS cannot be verified")
        ),
    )

    store = store_module.AdblockStore(lists_dir=str(tmp_path / "lists"))
    ok, err, bytes_read, rules = store.download_list(
        "easylist",
        "https://public.example/easylist.txt",
    )

    assert ok is False
    assert "internal/localhost" in err
    assert bytes_read == 0
    assert rules == 0


def test_adblock_download_rejects_ambiguous_backslash_url_before_dns(
    tmp_path, monkeypatch
) -> None:
    store_module, _artifacts_module = _import_artifact_modules(tmp_path)
    download_safety = store_module.download_safety

    monkeypatch.setattr(
        download_safety.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("backslash-bearing URLs should not reach DNS")
        ),
    )
    monkeypatch.setattr(
        download_safety.urllib.request,
        "build_opener",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("download should not open backslash-bearing URL")
        ),
    )

    store = store_module.AdblockStore(lists_dir=str(tmp_path / "lists"))
    ok, err, bytes_read, rules = store.download_list(
        "easylist",
        r"https://public.example\@127.0.0.1/easylist.txt",
    )

    assert ok is False
    assert "valid absolute HTTP/HTTPS" in err
    assert bytes_read == 0
    assert rules == 0


def test_adblock_download_rejects_embedded_url_credentials(
    tmp_path, monkeypatch
) -> None:
    store_module, _artifacts_module = _import_artifact_modules(tmp_path)
    download_safety = store_module.download_safety

    monkeypatch.setattr(
        download_safety.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("credential-bearing URLs should not reach DNS")
        ),
    )
    monkeypatch.setattr(
        download_safety.urllib.request,
        "build_opener",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("download should not open credential-bearing URL")
        ),
    )

    store = store_module.AdblockStore(lists_dir=str(tmp_path / "lists"))
    ok, err, bytes_read, rules = store.download_list(
        "easylist",
        "https://feed-user:feed-pass@public.example/easylist.txt",
    )

    assert ok is False
    assert "embedded credentials" in err
    assert bytes_read == 0
    assert rules == 0


def test_adblock_download_rejects_redirect_to_internal_host(
    tmp_path, monkeypatch
) -> None:
    store_module, _artifacts_module = _import_artifact_modules(tmp_path)
    download_safety = store_module.download_safety

    def fake_getaddrinfo(host: str, *_args, **_kwargs):
        assert host == "public.example"
        return [
            (
                download_safety.socket.AF_INET,
                download_safety.socket.SOCK_STREAM,
                0,
                "",
                ("93.184.216.34", 0),
            ),
        ]

    headers = Message()
    headers["Location"] = "http://127.0.0.1/easylist.txt"

    class _Opener:
        def open(self, req, **_kwargs):
            raise download_safety.urllib.error.HTTPError(
                req.full_url,
                302,
                "Found",
                headers,
                None,
            )

    monkeypatch.setattr(download_safety.socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(
        download_safety.urllib.request,
        "build_opener",
        lambda *_args, **_kwargs: _Opener(),
    )

    store = store_module.AdblockStore(lists_dir=str(tmp_path / "lists"))
    ok, err, bytes_read, rules = store.download_list(
        "easylist",
        "https://public.example/easylist.txt",
    )

    assert ok is False
    assert "internal/localhost" in err
    assert bytes_read == 0
    assert rules == 0


def test_adblock_cicap_access_parser_requires_http_403_status(tmp_path) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    web_root = repo_root / "web"
    for path in (str(repo_root), str(web_root)):
        if path not in sys.path:
            sys.path.insert(0, path)

    import services.adblock_store as store_module  # type: ignore

    importlib.reload(store_module)
    store = store_module.AdblockStore(lists_dir=str(tmp_path / "lists"))
    line = (
        "1700000000\t192.0.2.10\t198.51.100.20\tREQMOD\t/adblockreq\t200\t"
        "GET http://ads.example/ HTTP/1.1\thttp://ads.example/\t"
        "HTTP/1.1 403 Forbidden\t-"
    )

    blocked = store._parse_cicap_access_line(line)

    assert blocked is not None
    assert blocked["ts"] == 1700000000
    assert blocked["src_ip"] == "192.0.2.10"
    assert blocked["method"] == "GET"
    assert blocked["url"] == "http://ads.example/"
    assert blocked["http_status"] == 403
    assert blocked["icap_status"] == 200

    for response_line in (
        "HTTP/1.1 200 upstream note 403",
        "HTTP/1.1 not-a-code 403",
    ):
        assert (
            store._parse_cicap_access_line(
                line.replace("HTTP/1.1 403 Forbidden", response_line),
            )
            is None
        )


def test_adblock_cicap_access_parser_accepts_quoted_tabs_and_scaled_service_path(
    tmp_path,
) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    web_root = repo_root / "web"
    for path in (str(repo_root), str(web_root)):
        if path not in sys.path:
            sys.path.insert(0, path)

    import services.adblock_store as store_module  # type: ignore

    importlib.reload(store_module)
    store = store_module.AdblockStore(lists_dir=str(tmp_path / "lists"))
    line = (
        "1700000000\t192.0.2.10\t198.51.100.20\tREQMOD\t/adblockreq\t200\t"
        '"GET http://ads.example/path?note=a\tb HTTP/1.1"\thttp://ads.example/\t'
        "HTTP/1.1 403 Forbidden\t-"
    )

    blocked = store._parse_cicap_access_line(line)

    assert blocked is not None
    assert blocked["method"] == "GET"
    assert blocked["url"] == "http://ads.example/"
    assert blocked["icap_status"] == 200


def test_create_revision_reuses_unchanged_active_artifact_without_new_blob(
    tmp_path: Path,
) -> None:
    _store_module, artifacts_module = _import_artifact_modules(tmp_path)
    revision_store = artifacts_module.AdblockArtifactStore()
    revision_store.init_db()

    first = revision_store.create_revision(
        artifact_sha256="1" * 64,
        archive_blob=b"large-archive-v1",
        report_json="{}",
        settings_version=1,
        source_kind="compile",
        enabled_lists=["easylist"],
        created_by="pytest",
    )
    duplicate = revision_store.create_revision(
        artifact_sha256="1" * 64,
        archive_blob=b"large-archive-v1-should-not-be-written",
        report_json="{}",
        settings_version=1,
        source_kind="compile",
        enabled_lists=["easylist"],
        created_by="pytest",
    )

    assert duplicate.revision_id == first.revision_id
    with revision_store._connect() as conn:
        count, blob = conn.execute(
            "SELECT COUNT(*), MAX(archive_blob) FROM adblock_artifact_revisions"
        ).fetchone()
    assert int(count) == 1
    assert bytes(blob) == b"large-archive-v1"


def test_create_revision_prunes_to_current_and_previous_artifacts(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _store_module, artifacts_module = _import_artifact_modules(tmp_path)
    revision_store = artifacts_module.AdblockArtifactStore()
    revision_store.init_db()

    for index, digest in enumerate(("1" * 64, "2" * 64, "3" * 64), start=1):
        monkeypatch.setattr(artifacts_module, "_now", lambda index=index: 1000 + index)
        revision_store.create_revision(
            artifact_sha256=digest,
            archive_blob=f"archive-{index}".encode(),
            report_json="{}",
            settings_version=index,
            source_kind="compile",
            enabled_lists=["easylist"],
            created_by="pytest",
        )

    with revision_store._connect() as conn:
        rows = conn.execute(
            "SELECT artifact_sha256, is_active, archive_blob FROM adblock_artifact_revisions ORDER BY created_ts, id"
        ).fetchall()

    assert [(str(row[0]), int(row[1]), bytes(row[2])) for row in rows] == [
        ("2" * 64, 0, b"archive-2"),
        ("3" * 64, 1, b"archive-3"),
    ]


def test_prune_revisions_converges_in_small_committed_batches(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _store_module, artifacts_module = _import_artifact_modules(tmp_path)
    revision_store = artifacts_module.AdblockArtifactStore()
    revision_store.init_db()
    monkeypatch.setattr(
        revision_store,
        "_prune_revisions_best_effort",
        lambda *, max_batches: None,
    )

    for index in range(1, 9):
        monkeypatch.setattr(artifacts_module, "_now", lambda index=index: 2000 + index)
        revision_store.create_revision(
            artifact_sha256=f"{index:064x}"[-64:],
            archive_blob=(b"large-artifact-blob" * 8) + bytes([index]),
            report_json="{}",
            settings_version=index,
            source_kind="compile",
            enabled_lists=["easylist"],
            created_by="pytest",
        )

    deleted = revision_store.prune_revisions(max_batches=2, batch_size=2)

    assert deleted == 4
    with revision_store._connect() as conn:
        rows = conn.execute(
            "SELECT id, settings_version, is_active FROM adblock_artifact_revisions ORDER BY id"
        ).fetchall()
    assert [int(row[1]) for row in rows] == [5, 6, 7, 8]

    deleted = revision_store.prune_revisions(max_batches=10, batch_size=2)

    assert deleted == 2
    with revision_store._connect() as conn:
        rows = conn.execute(
            "SELECT settings_version, is_active, archive_blob FROM adblock_artifact_revisions ORDER BY created_ts, id"
        ).fetchall()
    assert [(int(row[0]), int(row[1])) for row in rows] == [(7, 0), (8, 1)]
    assert all(bytes(row[2]).startswith(b"large-artifact-blob") for row in rows)


def test_activation_commits_before_bounded_prune_cleanup(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _store_module, artifacts_module = _import_artifact_modules(tmp_path)
    revision_store = artifacts_module.AdblockArtifactStore()
    revision_store.init_db()

    revision_store.create_revision(
        artifact_sha256="1" * 64,
        archive_blob=b"archive-1",
        report_json="{}",
        settings_version=1,
        source_kind="compile",
        enabled_lists=["easylist"],
        created_by="pytest",
    )
    monkeypatch.setattr(artifacts_module, "_now", lambda: 3000)
    monkeypatch.setattr(revision_store, "init_db", lambda: None)

    commits: list[str] = []
    original_connect = revision_store._connect

    class TrackingConn:
        def __init__(self, inner, label: str) -> None:
            self.inner = inner
            self.label = label

        def __enter__(self):
            self.inner.__enter__()
            return self

        def __exit__(self, exc_type, exc, tb) -> bool:
            commits.append(f"{self.label}:exit")
            return self.inner.__exit__(exc_type, exc, tb)

        def execute(self, *args, **kwargs):
            return self.inner.execute(*args, **kwargs)

        def commit(self) -> None:
            commits.append(f"{self.label}:commit")
            self.inner.commit()

        def rollback(self) -> None:
            self.inner.rollback()

    connect_count = 0

    def tracking_connect():
        nonlocal connect_count
        connect_count += 1
        label = "metadata" if connect_count == 1 else "activation" if connect_count == 2 else "cleanup"
        return TrackingConn(original_connect(), label)

    monkeypatch.setattr(revision_store, "_connect", tracking_connect)

    revision = revision_store.create_revision(
        artifact_sha256="2" * 64,
        archive_blob=b"archive-2",
        report_json="{}",
        settings_version=2,
        source_kind="compile",
        enabled_lists=["easylist"],
        created_by="pytest",
    )

    assert revision.artifact_sha256 == "2" * 64
    assert commits.index("activation:exit") < commits.index("cleanup:exit")


def test_prune_revisions_skips_when_another_cleanup_holds_lock(
    tmp_path: Path,
) -> None:
    _store_module, artifacts_module = _import_artifact_modules(tmp_path)
    revision_store = artifacts_module.AdblockArtifactStore()
    revision_store.init_db()

    for index in range(1, 5):
        revision_store.create_revision(
            artifact_sha256=f"{index:064x}"[-64:],
            archive_blob=f"archive-{index}".encode(),
            report_json="{}",
            settings_version=index,
            source_kind="compile",
            enabled_lists=["easylist"],
            created_by="pytest",
        )

    with revision_store._connect() as held_conn:
        acquired = held_conn.execute(
            "SELECT GET_LOCK(%s, 1) AS acquired",
            (artifacts_module._ARTIFACT_PRUNE_LOCK_NAME,),
        ).fetchone()
        assert int(acquired["acquired"] or 0) == 1
        try:
            assert revision_store.prune_revisions(max_batches=10, batch_size=1) == 0
        finally:
            held_conn.execute(
                "DO RELEASE_LOCK(%s)",
                (artifacts_module._ARTIFACT_PRUNE_LOCK_NAME,),
            )


def test_post_activation_prune_best_effort_does_not_retry_transient_contention(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _store_module, artifacts_module = _import_artifact_modules(tmp_path)
    revision_store = artifacts_module.AdblockArtifactStore()
    attempts: list[int] = []

    def lock_wait(*, max_batches: int) -> int:
        attempts.append(max_batches)
        raise pymysql.OperationalError(
            1205,
            "Lock wait timeout exceeded; try restarting transaction",
        )

    monkeypatch.setattr(revision_store, "prune_revisions", lock_wait)

    revision_store._prune_revisions_best_effort(max_batches=1)

    assert attempts == [1]


def test_prune_revision_batch_keeps_active_and_previous_with_large_backlog() -> None:
    artifacts_module = _import_adblock_artifacts_module()
    revision_store = artifacts_module.AdblockArtifactStore()
    conn = _FakeAdblockRevisionConn(
        [
            {"id": index, "created_ts": 10_000 + index, "is_active": 1 if index == 10 else 0}
            for index in range(1, 11)
        ],
    )

    first_deleted = revision_store._prune_revisions_with_conn(conn, batch_size=3)
    second_deleted = revision_store._prune_revisions_with_conn(conn, batch_size=3)
    final_deleted = revision_store._prune_revisions_with_conn(conn, batch_size=3)

    assert first_deleted == 3
    assert second_deleted == 3
    assert final_deleted == 2
    assert conn.deleted_batches == [[1, 2, 3], [4, 5, 6], [7, 8]]
    assert [(row["id"], row["is_active"]) for row in conn.rows] == [(9, 0), (10, 1)]


def test_prune_revision_batch_demotes_stale_active_before_deleting_blobs() -> None:
    artifacts_module = _import_adblock_artifacts_module()
    revision_store = artifacts_module.AdblockArtifactStore()
    conn = _FakeAdblockRevisionConn(
        [
            {"id": 1, "created_ts": 101, "is_active": 0},
            {"id": 2, "created_ts": 102, "is_active": 1},
            {"id": 3, "created_ts": 103, "is_active": 1},
            {"id": 4, "created_ts": 104, "is_active": 1},
        ],
    )

    updated = revision_store._prune_revisions_with_conn(conn, batch_size=2)
    deleted = revision_store._prune_revisions_with_conn(conn, batch_size=2)

    assert updated == 2
    assert deleted == 2
    assert conn.updated_batches == [[2, 3]]
    assert conn.deleted_batches == [[1, 2]]
    assert [(row["id"], row["is_active"]) for row in conn.rows] == [
        (3, 0),
        (4, 1),
    ]


def test_prune_revisions_commits_each_bounded_batch(monkeypatch) -> None:
    artifacts_module = _import_adblock_artifacts_module()
    revision_store = artifacts_module.AdblockArtifactStore()

    class FakeContextConn(_FakeAdblockRevisionConn):
        def __init__(self) -> None:
            super().__init__(
                [
                    {
                        "id": index,
                        "created_ts": 20_000 + index,
                        "is_active": 1 if index == 6 else 0,
                    }
                    for index in range(1, 7)
                ],
            )
            self.released = False

        def __enter__(self):
            return self

        def __exit__(self, *_exc) -> bool:
            return False

        def execute(self, sql: str, params=()):
            text = " ".join(sql.split())
            if text.startswith("SELECT GET_LOCK"):
                return _FakeSqlResult([{"acquired": 1}])
            if text.startswith("DO RELEASE_LOCK"):
                self.released = True
                return _FakeSqlResult()
            return super().execute(sql, params)

    conn = FakeContextConn()
    monkeypatch.setattr(revision_store, "init_db", lambda: None)
    monkeypatch.setattr(revision_store, "_connect", lambda: conn)

    deleted = revision_store.prune_revisions(max_batches=2, batch_size=2)

    assert deleted == 4
    assert conn.deleted_batches == [[1, 2], [3, 4]]
    assert conn.commits == 2
    assert conn.released is True
    assert [(row["id"], row["is_active"]) for row in conn.rows] == [(5, 0), (6, 1)]


def test_create_revision_retries_transient_mysql_lock_wait(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    web_root = repo_root / "web"
    for path in (str(repo_root), str(web_root)):
        if path not in sys.path:
            sys.path.insert(0, path)

    os.environ["DISABLE_BACKGROUND"] = "1"
    import services.adblock_artifacts as artifacts_module  # type: ignore

    importlib.reload(artifacts_module)
    revision_store = artifacts_module.AdblockArtifactStore()
    monkeypatch.setattr(revision_store, "init_db", lambda: None)
    monkeypatch.setattr(revision_store, "get_active_artifact", lambda: None)
    monkeypatch.setattr(revision_store, "get_active_artifact_metadata", lambda: None)

    attempts = 0
    operations: list[str] = []

    def retry_once(operation):
        nonlocal attempts
        for _attempt in range(2):
            attempts += 1
            try:
                return operation()
            except pymysql.OperationalError as exc:
                if int(exc.args[0]) != 1205:
                    raise
        return operation()

    class FakeResult:
        lastrowid = 7

        def __init__(self, row=None) -> None:
            self._row = row

        def fetchone(self):
            return self._row

    class FakeConn:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> bool:
            operations.append("ROLLBACK" if exc_type is not None else "COMMIT")
            return False

        def execute(self, sql: str, params=()):
            nonlocal operations
            text = " ".join(sql.split())
            operations.append(text)
            if text.startswith("UPDATE") and operations.count(text) == 1:
                raise pymysql.OperationalError(
                    1205,
                    "Lock wait timeout exceeded; try restarting transaction",
                )
            if text.startswith("INSERT"):
                return FakeResult()
            if text.startswith("SELECT * FROM adblock_artifact_revisions"):
                return FakeResult(
                    {
                        "id": 7,
                        "artifact_sha256": "a" * 64,
                        "archive_blob": b"archive",
                        "report_json": "{}",
                        "settings_version": 3,
                        "source_kind": "background",
                        "enabled_lists_json": '["easylist"]',
                        "created_by": "pytest",
                        "created_ts": 123,
                        "is_active": 1,
                    }
                )
            return FakeResult([])

    def fake_connect():
        return FakeConn()

    monkeypatch.setattr(artifacts_module, "_run_builder_mysql_operation", retry_once)
    monkeypatch.setattr(revision_store, "_connect", fake_connect)
    monkeypatch.setattr(
        revision_store,
        "_prune_revisions_with_conn",
        lambda _conn, *, batch_size: 0,
    )
    monkeypatch.setattr(
        revision_store,
        "_prune_revisions_best_effort",
        lambda *, max_batches: None,
    )

    revision = revision_store.create_revision(
        artifact_sha256="a" * 64,
        archive_blob=b"archive",
        report_json="{}",
        settings_version=3,
        source_kind="background",
        enabled_lists=["easylist"],
        created_by="pytest",
    )

    assert attempts == 2
    assert revision.revision_id == 7
    assert revision.artifact_sha256 == "a" * 64
    assert operations.count("ROLLBACK") == 1
    assert operations.count("COMMIT") == 1


def test_builder_mysql_operation_retries_only_lock_and_deadlock_errors(
    monkeypatch,
) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    web_root = repo_root / "web"
    for path in (str(repo_root), str(web_root)):
        if path not in sys.path:
            sys.path.insert(0, path)

    import services.adblock_artifacts as artifacts_module  # type: ignore

    sleeps: list[float] = []
    monkeypatch.setattr(artifacts_module.time, "sleep", sleeps.append)

    attempts = 0

    def lock_wait_once() -> str:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise pymysql.OperationalError(
                1205,
                "Lock wait timeout exceeded; try restarting transaction",
            )
        return "ok"

    assert artifacts_module._run_builder_mysql_operation(lock_wait_once) == "ok"
    assert attempts == 2
    assert sleeps == [0.2]

    attempts = 0
    sleeps.clear()

    def deadlock_once() -> str:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise pymysql.OperationalError(
                1213,
                "Deadlock found when trying to get lock; try restarting transaction",
            )
        return "ok"

    assert artifacts_module._run_builder_mysql_operation(deadlock_once) == "ok"
    assert attempts == 2
    assert sleeps == [0.2]

    def connection_refused() -> None:
        raise pymysql.OperationalError(2003, "Can't connect to MySQL server")

    with pytest.raises(pymysql.OperationalError):
        artifacts_module._run_builder_mysql_operation(connection_refused)
    assert sleeps == [0.2]

    attempts = 0
    sleeps.clear()

    def duplicate_key() -> None:
        nonlocal attempts
        attempts += 1
        raise pymysql.IntegrityError(1062, "Duplicate entry")

    with pytest.raises(pymysql.IntegrityError):
        artifacts_module._run_builder_mysql_operation(duplicate_key)
    assert attempts == 1
    assert sleeps == []


def test_builder_mysql_operation_propagates_non_database_errors(monkeypatch) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    web_root = repo_root / "web"
    for path in (str(repo_root), str(web_root)):
        if path not in sys.path:
            sys.path.insert(0, path)

    import services.adblock_artifacts as artifacts_module  # type: ignore

    sleeps: list[float] = []
    monkeypatch.setattr(artifacts_module.time, "sleep", sleeps.append)

    def fail() -> None:
        msg = "not transient mysql"
        raise ValueError(msg)

    with pytest.raises(ValueError, match="not transient mysql"):
        artifacts_module._run_builder_mysql_operation(fail)
    assert sleeps == []
