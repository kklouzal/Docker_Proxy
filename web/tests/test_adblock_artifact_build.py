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


def _read_zipped_sqlite(
    zf: zipfile.ZipFile, name: str, tmp_path: Path
) -> sqlite3.Connection:
    db_path = tmp_path / name
    db_path.write_bytes(zf.read(name))
    return sqlite3.connect(str(db_path))


def test_build_active_artifact_packages_compiled_lists_and_settings(
    tmp_path, monkeypatch
) -> None:
    env_backup = {key: os.environ.get(key) for key in ("DISABLE_BACKGROUND",)}
    try:
        store_module, artifacts_module = _import_artifact_modules(tmp_path)

        store = store_module.get_adblock_store()
        store.lists_dir = str(tmp_path / "lists")
        Path(store.lists_dir).mkdir(parents=True, exist_ok=True)
        store.init_db()

        statuses = store.list_statuses()
        assert statuses, "expected default adblock lists to be present"
        selected = statuses[0].key

        store.set_enabled({status.key: status.key == selected for status in statuses})
        store.set_settings(enabled=True, cache_ttl=120, cache_max=4096)

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
        store.lists_dir = str(tmp_path / "lists")
        Path(store.lists_dir).mkdir(parents=True, exist_ok=True)
        store.init_db()

        statuses = store.list_statuses()
        assert statuses, "expected default adblock lists to be present"
        selected = statuses[0].key

        store.set_enabled({status.key: status.key == selected for status in statuses})
        store.set_settings(enabled=True, cache_ttl=120, cache_max=4096)

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
        store.lists_dir = str(tmp_path / "lists")
        Path(store.lists_dir).mkdir(parents=True, exist_ok=True)
        store.init_db()

        statuses = store.list_statuses()
        assert statuses, "expected default adblock lists to be present"
        selected = statuses[0].key

        store.set_enabled({status.key: status.key == selected for status in statuses})
        store.set_settings(enabled=False, cache_ttl=120, cache_max=4096)
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
        store.lists_dir = str(tmp_path / "lists")
        Path(store.lists_dir).mkdir(parents=True, exist_ok=True)
        store.init_db()

        statuses = store.list_statuses()
        assert statuses, "expected default adblock lists to be present"
        selected = statuses[0].key

        store.set_enabled({status.key: status.key == selected for status in statuses})
        store.set_settings(enabled=True, cache_ttl=120, cache_max=4096)
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
        store.lists_dir = str(tmp_path / "lists")
        Path(store.lists_dir).mkdir(parents=True, exist_ok=True)
        store.init_db()

        statuses = store.list_statuses()
        assert statuses, "expected default adblock lists to be present"
        selected = statuses[0].key

        store.set_enabled({status.key: status.key == selected for status in statuses})
        store.set_settings(enabled=True, cache_ttl=120, cache_max=4096)
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
        store.lists_dir = str(tmp_path / "lists")
        Path(store.lists_dir).mkdir(parents=True, exist_ok=True)
        store.init_db()

        statuses = store.list_statuses()
        assert statuses, "expected default adblock lists to be present"
        selected = statuses[0].key

        store.set_enabled({status.key: status.key == selected for status in statuses})
        store.set_settings(enabled=True, cache_ttl=120, cache_max=4096)
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
