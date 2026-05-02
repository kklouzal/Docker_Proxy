from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

from .proxy_runtime_test_helpers import import_proxy_runtime


CERT_PEM = "-----BEGIN CERTIFICATE-----\nMIIFPROXY\n-----END CERTIFICATE-----\n"
KEY_PEM = "-----BEGIN PRIVATE KEY-----\nMIIEPROXY\n-----END PRIVATE KEY-----\n"

def test_proxy_sync_certificate_bundle_materializes_and_records_apply(tmp_path):
    env_backup = {
        key: os.environ.get(key)
        for key in ("PROXY_INSTANCE_ID", "DEFAULT_PROXY_ID", "DISABLE_BACKGROUND", "CERTS_DIR", "SSL_DB_DIR")
    }
    try:
        runtime_module = import_proxy_runtime(
            tmp_path,
            extra_env={
                "CERTS_DIR": tmp_path / "certs",
                "SSL_DB_DIR": tmp_path / "ssl_db" / "store",
            },
        )
        from services.certificate_bundles import get_certificate_bundles  # type: ignore
        from services.cert_manager import build_certificate_bundle  # type: ignore

        revision = get_certificate_bundles().create_revision(
            build_certificate_bundle(CERT_PEM, KEY_PEM, source_kind="self_signed"),
            created_by="tester",
        )

        runtime = runtime_module.ProxyRuntime(
            services=runtime_module.build_runtime_services(
                ssl_db_reinitializer=lambda: (True, "ssl db refreshed"),
            )
        )

        result = runtime.sync_certificate_bundle(force=True)

        assert result["ok"] is True
        assert result["changed"] is True
        assert result["revision_id"] == revision.revision_id

        cert_path = tmp_path / "certs" / "ca.crt"
        key_path = tmp_path / "certs" / "ca.key"
        assert cert_path.exists()
        assert key_path.exists()
        assert "MIIFPROXY" in cert_path.read_text(encoding="utf-8")
        assert "MIIEPROXY" in key_path.read_text(encoding="utf-8")

        latest_apply = get_certificate_bundles().latest_apply("edge-1")
        assert latest_apply is not None
        assert latest_apply.ok is True
        assert latest_apply.revision_id == revision.revision_id
    finally:
        for key, value in env_backup.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def test_proxy_reinitialize_ssl_db_uses_init_script(tmp_path, monkeypatch):
    env_backup = {
        key: os.environ.get(key)
        for key in ("PROXY_INSTANCE_ID", "DEFAULT_PROXY_ID", "DISABLE_BACKGROUND", "CERTS_DIR", "SSL_DB_DIR")
    }
    try:
        runtime_module = import_proxy_runtime(
            tmp_path,
            extra_env={
                "CERTS_DIR": tmp_path / "certs",
            },
        )

        ssl_db_dir = "/tmp/proxy-runtime-ssl-db/store"
        calls: list[tuple[list[str], dict[str, str] | None]] = []
        orig_exists = runtime_module.os.path.exists

        def fake_exists(path: str) -> bool:
            if path == "/scripts/init_ssl_db.sh":
                return True
            return orig_exists(path)

        def fake_run(args, capture_output=True, timeout=None, env=None):
            argv = list(args)
            calls.append((argv, dict(env) if env is not None else None))
            if argv[:4] == ["supervisorctl", "-c", "/etc/supervisord.conf", "stop"]:
                return SimpleNamespace(returncode=0, stdout=b"squid: stopped\n", stderr=b"")
            if argv[:2] == ["sh", "/scripts/init_ssl_db.sh"]:
                target = Path((env or {}).get("SSL_DB_DIR") or ssl_db_dir)
                (target / "certs").mkdir(parents=True, exist_ok=True)
                (target / "index.txt").write_text("", encoding="utf-8")
                (target / "size").write_text("1", encoding="utf-8")
                return SimpleNamespace(returncode=0, stdout=b"Initializing sslcrtd DB\n", stderr=b"")
            raise AssertionError(f"unexpected subprocess.run call: {argv!r}")

        monkeypatch.setattr(runtime_module.os.path, "exists", fake_exists)
        monkeypatch.setattr(runtime_module.subprocess, "run", fake_run)

        runtime = runtime_module.ProxyRuntime()
        runtime.ssl_db_dir = ssl_db_dir
        runtime.controller.restart_squid = lambda: (True, "squid restarted")

        ok, detail = runtime._reinitialize_ssl_db_and_restart()

        assert ok is True
        assert "Initializing sslcrtd DB" in detail
        assert "squid restarted" in detail
        assert any(
            argv[:2] == ["sh", "/scripts/init_ssl_db.sh"] and env is not None and env.get("SSL_DB_DIR") == ssl_db_dir
            for argv, env in calls
        )
        assert Path(ssl_db_dir, "index.txt").exists()
        assert Path(ssl_db_dir, "size").exists()
        assert Path(ssl_db_dir, "certs").is_dir()
    finally:
        for key, value in env_backup.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
