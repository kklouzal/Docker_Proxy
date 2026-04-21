from __future__ import annotations

import importlib
import json
import os
import sys
from pathlib import Path

from .mysql_test_utils import configure_test_mysql_env


def _import_proxy_runtime(tmp_path: Path):
    repo_root = Path(__file__).resolve().parents[2]
    web_root = repo_root / "web"
    for path in (str(repo_root), str(web_root)):
        if path not in sys.path:
            sys.path.insert(0, path)

    os.environ["PROXY_INSTANCE_ID"] = "edge-1"
    os.environ["DEFAULT_PROXY_ID"] = "edge-1"
    os.environ["DISABLE_BACKGROUND"] = "1"
    os.environ["ADBLOCK_COMPILED_DIR"] = str(tmp_path / "compiled")
    os.environ["PAC_RENDER_DIR"] = str(tmp_path / "pac")

    configure_test_mysql_env(tmp_path, secret_path=tmp_path / "flask_secret.key")

    import proxy.runtime as runtime_module  # type: ignore

    importlib.reload(runtime_module)
    return runtime_module


def test_proxy_sync_adblock_artifact_materializes_and_records_apply(tmp_path, monkeypatch):
    env_backup = {
        key: os.environ.get(key)
        for key in ("PROXY_INSTANCE_ID", "DEFAULT_PROXY_ID", "DISABLE_BACKGROUND", "ADBLOCK_COMPILED_DIR", "PAC_RENDER_DIR")
    }
    try:
        runtime_module = _import_proxy_runtime(tmp_path)
        from services.adblock_artifacts import get_adblock_artifacts, read_materialized_artifact_sha  # type: ignore
        from services.adblock_store import get_adblock_store  # type: ignore

        artifact_dir = tmp_path / "artifact"
        artifact_dir.mkdir(parents=True, exist_ok=True)
        (artifact_dir / "domains_allow.txt").write_text("allow.example\n", encoding="utf-8")
        (artifact_dir / "domains_block.txt").write_text("ads.example\n", encoding="utf-8")
        (artifact_dir / "regex_allow.txt").write_text("", encoding="utf-8")
        (artifact_dir / "regex_block.txt").write_text("/tracker[.]example/\n", encoding="utf-8")
        (artifact_dir / "settings.json").write_text(
            json.dumps({"enabled": True, "cache_ttl": 120, "cache_max": 1000, "settings_version": 2, "enabled_lists": ["easylist"]}, indent=2)
            + "\n",
            encoding="utf-8",
        )
        (artifact_dir / "report.json").write_text(
            json.dumps({"enabled_lists": ["easylist"], "counts": {"domains_block": 1, "domains_allow": 1, "regex_block": 1, "regex_allow": 0}}, indent=2)
            + "\n",
            encoding="utf-8",
        )

        revision = get_adblock_artifacts().create_revision_from_directory(
            artifact_dir,
            settings_version=2,
            enabled_lists=["easylist"],
            created_by="tester",
            source_kind="test",
        )
        store = get_adblock_store()
        store.request_cache_flush()

        runtime = runtime_module.ProxyRuntime()
        monkeypatch.setattr(runtime, "_restart_adblock_service", lambda: (True, "cicap_adblock restarted"))

        result = runtime.sync_adblock_state(force=False)

        assert result["ok"] is True
        assert result["changed"] is True
        assert result["artifact_changed"] is True
        assert result["cache_flushed"] is True
        assert result["revision_id"] == revision.revision_id

        compiled_dir = tmp_path / "compiled"
        assert (compiled_dir / "domains_block.txt").read_text(encoding="utf-8") == "ads.example\n"
        assert (compiled_dir / "settings.json").exists()
        assert read_materialized_artifact_sha(compiled_dir) == revision.artifact_sha256

        latest_apply = get_adblock_artifacts().latest_apply("edge-1")
        assert latest_apply is not None
        assert latest_apply.ok is True
        assert latest_apply.revision_id == revision.revision_id
        assert store.get_cache_flush_requested() == 0
    finally:
        for key, value in env_backup.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def test_proxy_sync_pac_state_materializes_pre_rendered_files(tmp_path):
    env_backup = {
        key: os.environ.get(key)
        for key in ("PROXY_INSTANCE_ID", "DEFAULT_PROXY_ID", "DISABLE_BACKGROUND", "ADBLOCK_COMPILED_DIR", "PAC_RENDER_DIR")
    }
    try:
        runtime_module = _import_proxy_runtime(tmp_path)
        from services.exclusions_store import get_exclusions_store  # type: ignore
        from services.pac_profiles_store import get_pac_profiles_store  # type: ignore
        from services.pac_renderer import read_materialized_pac_state_sha  # type: ignore

        pac_store = get_pac_profiles_store()
        ok, err, _ = pac_store.upsert_profile(
            profile_id=None,
            name="Office LAN",
            client_cidr="192.168.50.0/24",
            socks_enabled=True,
            socks_host="",
            socks_port="1080",
            direct_domains_text="example.com\n",
            direct_dst_nets_text="10.0.0.0/8\n",
        )
        assert ok, err

        exclusions = get_exclusions_store()
        exclusions.add_domain("internal.example")
        exclusions.set_exclude_private_nets(True)

        runtime = runtime_module.ProxyRuntime()
        result = runtime.sync_pac_state(force=True)

        assert result["ok"] is True
        assert result["changed"] is True

        pac_dir = tmp_path / "pac"
        manifest = json.loads((pac_dir / "manifest.json").read_text(encoding="utf-8"))
        assert manifest["profiles"]

        profile_path = pac_dir / str(manifest["profiles"][0]["file"])
        profile_text = profile_path.read_text(encoding="utf-8")
        fallback_text = (pac_dir / "fallback.pac").read_text(encoding="utf-8")

        assert "SOCKS5 __PAC_PROXY_HOST__:1080; PROXY __PAC_PROXY_HOST__:3128; DIRECT" in profile_text
        assert "dnsDomainIs(host, 'example.com')" in profile_text
        assert "internal.example" in fallback_text
        assert read_materialized_pac_state_sha(pac_dir) == result["state_sha256"]
    finally:
        for key, value in env_backup.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def test_pac_http_server_prefers_local_pre_rendered_state(tmp_path):
    env_backup = {
        key: os.environ.get(key)
        for key in ("PROXY_INSTANCE_ID", "DEFAULT_PROXY_ID", "DISABLE_BACKGROUND", "ADBLOCK_COMPILED_DIR", "PAC_RENDER_DIR", "PAC_UPSTREAM")
    }
    try:
        runtime_module = _import_proxy_runtime(tmp_path)
        from services.pac_profiles_store import get_pac_profiles_store  # type: ignore

        pac_store = get_pac_profiles_store()
        ok, err, _ = pac_store.upsert_profile(
            profile_id=None,
            name="Office LAN",
            client_cidr="192.168.50.0/24",
            socks_enabled=True,
            socks_host="",
            socks_port="1080",
            direct_domains_text="example.com\n",
            direct_dst_nets_text="",
        )
        assert ok, err

        runtime = runtime_module.ProxyRuntime()
        result = runtime.sync_pac_state(force=True)
        assert result["ok"] is True

        os.environ["PAC_UPSTREAM"] = ""
        import tools.pac_http_server as pac_http_server  # type: ignore

        importlib.reload(pac_http_server)
        body = pac_http_server._LOCAL_CACHE.resolve(client_ip="192.168.50.10", request_host="proxy.example:80")
        assert body is not None
        text = body.decode("utf-8", errors="replace")
        assert "SOCKS5 proxy.example:1080; PROXY proxy.example:3128; DIRECT" in text
        assert "FindProxyForURL" in text
    finally:
        for key, value in env_backup.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
