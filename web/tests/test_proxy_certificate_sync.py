from __future__ import annotations

import importlib
import os

from .proxy_runtime_test_helpers import import_proxy_runtime


CERT_PEM = "-----BEGIN CERTIFICATE-----\nMIIFPROXY\n-----END CERTIFICATE-----\n"
KEY_PEM = "-----BEGIN PRIVATE KEY-----\nMIIEPROXY\n-----END PRIVATE KEY-----\n"

def test_proxy_sync_certificate_bundle_materializes_and_records_apply(tmp_path, monkeypatch):
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

        runtime = runtime_module.ProxyRuntime()
        monkeypatch.setattr(runtime, "_reinitialize_ssl_db_and_restart", lambda: (True, "ssl db refreshed"))

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
