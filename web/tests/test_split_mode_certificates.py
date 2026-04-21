from __future__ import annotations

import io
import os
import sys
import tempfile
import unittest
from urllib.parse import parse_qs, urlsplit

from .mysql_test_utils import configure_test_mysql_env


CERT_PEM = "-----BEGIN CERTIFICATE-----\nMIIFREMOTE\n-----END CERTIFICATE-----\n"
KEY_PEM = "-----BEGIN PRIVATE KEY-----\nMIIEREMOTE\n-----END PRIVATE KEY-----\n"


class _FakeProxyClient:
    def __init__(self):
        self.sync_calls: list[tuple[str, bool]] = []

    def sync_proxy(self, proxy_id, *, force=False, timeout_seconds=15.0):
        self.sync_calls.append((str(proxy_id), bool(force)))
        return {"ok": True, "detail": "sync requested"}


def _import_remote_app_module():
    web_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if web_dir not in sys.path:
        sys.path.insert(0, web_dir)

    os.environ["PROXY_CONTROL_MODE"] = "remote"
    os.environ["DISABLE_BACKGROUND"] = "1"
    os.environ["PROXY_MANAGEMENT_TOKEN"] = "test-token"
    os.environ["DEFAULT_PROXY_ID"] = "edge-1"

    secret_path = os.path.join(tempfile.mkdtemp(prefix="sfp_secret_remote_certs_"), "flask_secret.key")
    configure_test_mysql_env(tempfile.mkdtemp(prefix="sfp_mysql_remote_certs_"), secret_path=secret_path)

    import app as app_module  # type: ignore

    app_module.app.testing = True
    return app_module


class TestSplitModeCertificates(unittest.TestCase):
    def setUp(self):
        self._env_backup = {
            key: os.environ.get(key)
            for key in ("PROXY_CONTROL_MODE", "DISABLE_BACKGROUND", "PROXY_MANAGEMENT_TOKEN", "DEFAULT_PROXY_ID")
        }
        self.addCleanup(self._restore_env)
        self.app_module = _import_remote_app_module()
        self.client = self.app_module.app.test_client()

        self.client.get("/login")
        with self.client.session_transaction() as sess:
            self.csrf_token = sess.get("_csrf_token", "")

        self.client.post(
            "/login",
            data={"username": "admin", "password": "admin", "next": "", "csrf_token": self.csrf_token},
            follow_redirects=True,
        )

    def _restore_env(self):
        for key, value in self._env_backup.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def _qs(self, response) -> dict[str, list[str]]:
        return parse_qs(urlsplit(response.headers.get("Location", "") or "").query)

    def test_generate_certificate_remote_creates_revision_and_nudges_fleet(self):
        from services.certificate_bundles import get_certificate_bundles  # type: ignore
        from services.cert_manager import build_certificate_bundle  # type: ignore
        from services.proxy_registry import get_proxy_registry  # type: ignore

        registry = get_proxy_registry()
        registry.ensure_proxy("edge-1", display_name="Edge 1", management_url="http://edge-1:5000")
        registry.ensure_proxy("edge-2", display_name="Edge 2", management_url="http://edge-2:5000")

        fake_client = _FakeProxyClient()
        original_client = self.app_module.get_proxy_client
        original_generate = self.app_module.generate_self_signed_ca_bundle
        self.app_module.get_proxy_client = lambda: fake_client
        self.app_module.generate_self_signed_ca_bundle = lambda: build_certificate_bundle(
            CERT_PEM,
            KEY_PEM,
            source_kind="self_signed",
        )
        try:
            response = self.client.post(
                "/certs/generate",
                data={"csrf_token": self.csrf_token},
                follow_redirects=False,
            )
        finally:
            self.app_module.get_proxy_client = original_client
            self.app_module.generate_self_signed_ca_bundle = original_generate

        self.assertIn(response.status_code, (301, 302, 303, 307, 308))
        self.assertEqual(self._qs(response).get("ok"), ["1"])

        revision = get_certificate_bundles().get_active_bundle()
        self.assertIsNotNone(revision)
        assert revision is not None
        self.assertEqual(revision.source_kind, "self_signed")
        self.assertEqual(set(fake_client.sync_calls), {("edge-1", True), ("edge-2", True)})

    def test_upload_certificate_remote_stores_bundle_and_downloads_public_cert(self):
        from services.certificate_bundles import get_certificate_bundles  # type: ignore
        from services.cert_manager import PfxInstallResult, build_certificate_bundle  # type: ignore
        from services.proxy_registry import get_proxy_registry  # type: ignore

        registry = get_proxy_registry()
        registry.ensure_proxy("edge-1", display_name="Edge 1", management_url="http://edge-1:5000")

        bundle = build_certificate_bundle(
            CERT_PEM,
            KEY_PEM,
            source_kind="uploaded_pfx",
            original_pfx_bytes=b"pfx-bytes",
        )
        fake_client = _FakeProxyClient()
        original_client = self.app_module.get_proxy_client
        original_parse = self.app_module.parse_pfx_bundle
        self.app_module.get_proxy_client = lambda: fake_client
        self.app_module.parse_pfx_bundle = lambda _pfx_bytes, password="": PfxInstallResult(
            ok=True,
            message="parsed",
            bundle=bundle,
        )
        try:
            response = self.client.post(
                "/certs/upload",
                data={
                    "pfx": (io.BytesIO(b"fake-pfx"), "ca.pfx"),
                    "pfx_password": "secret",
                    "csrf_token": self.csrf_token,
                },
                content_type="multipart/form-data",
                follow_redirects=False,
            )
        finally:
            self.app_module.get_proxy_client = original_client
            self.app_module.parse_pfx_bundle = original_parse

        self.assertIn(response.status_code, (301, 302, 303, 307, 308))
        self.assertEqual(self._qs(response).get("ok"), ["1"])
        self.assertEqual(fake_client.sync_calls, [("edge-1", True)])

        revision = get_certificate_bundles().get_active_bundle()
        self.assertIsNotNone(revision)
        assert revision is not None
        self.assertEqual(revision.source_kind, "uploaded_pfx")
        self.assertEqual(revision.original_filename, "ca.pfx")

        download = self.client.get("/certs/download/ca.crt")
        self.assertEqual(download.status_code, 200)
        self.assertIn("attachment", download.headers.get("Content-Disposition", ""))
        self.assertIn("MIIFREMOTE", download.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
