from __future__ import annotations

import importlib
import io
import json
import os
import sys
import zipfile
from pathlib import Path

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


def test_build_active_artifact_packages_compiled_lists_and_settings(tmp_path, monkeypatch):
    env_backup = {
        key: os.environ.get(key)
        for key in ("DISABLE_BACKGROUND",)
    }
    try:
        store_module, artifacts_module = _import_artifact_modules(tmp_path)

        store = store_module.get_adblock_store()
        store.lists_dir = str(tmp_path / "lists")
        Path(store.lists_dir).mkdir(parents=True, exist_ok=True)

        statuses = store.list_statuses()
        assert statuses, "expected default adblock lists to be present"
        selected = statuses[0].key

        store.set_enabled({status.key: status.key == selected for status in statuses})
        store.set_settings(enabled=True, cache_ttl=120, cache_max=4096)

        Path(store.list_path(selected)).write_text(
            "! comment\n"
            "||ads.example^\n"
            "@@||allow.example^\n"
            "/tracker[.]example/\n",
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
            assert {"domains_allow.txt", "domains_block.txt", "regex_block.txt", "settings.json", "report.json"} <= names

            domains_block = zf.read("domains_block.txt").decode("utf-8", errors="replace")
            domains_allow = zf.read("domains_allow.txt").decode("utf-8", errors="replace")
            regex_block = zf.read("regex_block.txt").decode("utf-8", errors="replace")
            settings = json.loads(zf.read("settings.json").decode("utf-8", errors="replace"))
            report = json.loads(zf.read("report.json").decode("utf-8", errors="replace"))

        assert domains_block == "ads.example\n"
        assert domains_allow == "allow.example\n"
        assert regex_block == "/tracker[.]example/\n"
        assert settings == {
            "cache_max": 4096,
            "cache_ttl": 120,
            "enabled": True,
            "enabled_lists": [selected],
            "settings_version": store.get_settings_version(),
        }
        assert report["enabled_lists"] == [selected]
        assert int(report["counts"]["domains_block"]) == 1
        assert int(report["counts"]["domains_allow"]) == 1
        assert int(report["counts"]["regex_block"]) == 1
    finally:
        for key, value in env_backup.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
