from __future__ import annotations

import os
import unittest

from .flask_test_helpers import login
from .split_mode_test_helpers import FakeProxyClient, import_remote_app_module


class TestSplitModeControlPlane(unittest.TestCase):
    def setUp(self):
        self._env_backup = {
            key: os.environ.get(key)
            for key in (
                'DISABLE_BACKGROUND',
                'PROXY_MANAGEMENT_TOKEN',
                'DEFAULT_PROXY_ID',
                'PROXY_INSTANCE_ID',
                'PROXY_DISPLAY_NAME',
                'PROXY_MANAGEMENT_URL',
                'PROXY_PUBLIC_HOST',
                'PROXY_PUBLIC_HTTP_PROXY_PORT',
                'PROXY_PUBLIC_SOCKS_PROXY_PORT',
                'PROXY_PUBLIC_SOCKS_ENABLED',
            )
        }
        self.addCleanup(self._restore_env)
        self.app_module = import_remote_app_module(
            secret_prefix='sfp_secret_remote_',
            mysql_prefix='sfp_mysql_remote_',
        )
        self.app = self.app_module.app.test_client()
        self.csrf_token = login(self.app)

    def _restore_env(self):
        for key, value in self._env_backup.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def test_api_squid_config_reads_selected_proxy_revision(self):
        from services.config_revisions import get_config_revisions  # type: ignore
        from services.proxy_registry import get_proxy_registry  # type: ignore

        registry = get_proxy_registry()
        registry.ensure_proxy('edge-1', display_name='Edge 1', management_url='http://edge-1:5000')
        registry.ensure_proxy('edge-2', display_name='Edge 2', management_url='http://edge-2:5000')

        revisions = get_config_revisions()
        revisions.create_revision('edge-1', 'workers 1\n', created_by='tester', source_kind='test')
        revisions.create_revision('edge-2', 'workers 2\n', created_by='tester', source_kind='test')

        fake_client = FakeProxyClient()
        original = self.app_module.get_proxy_client
        self.app_module.get_proxy_client = lambda: fake_client
        try:
            response = self.app.get('/api/squid-config?proxy_id=edge-2')
        finally:
            self.app_module.get_proxy_client = original

        self.assertEqual(response.status_code, 200)
        self.assertIn('workers 2', response.get_data(as_text=True))

    def test_reload_route_targets_selected_proxy(self):
        from services.proxy_registry import get_proxy_registry  # type: ignore

        registry = get_proxy_registry()
        registry.ensure_proxy('edge-1', display_name='Edge 1', management_url='http://edge-1:5000')

        fake_client = FakeProxyClient()
        original = self.app_module.get_proxy_client
        self.app_module.get_proxy_client = lambda: fake_client
        try:
            response = self.app.post(
                '/reload',
                data={'proxy_id': 'edge-1', 'csrf_token': self.csrf_token},
                follow_redirects=False,
            )
        finally:
            self.app_module.get_proxy_client = original

        self.assertIn(response.status_code, (301, 302, 308))
        self.assertEqual(fake_client.sync_calls, [('edge-1', True)])

    def test_proxies_page_renders_registered_proxy(self):
        from services.proxy_registry import get_proxy_registry  # type: ignore

        registry = get_proxy_registry()
        registry.ensure_proxy('edge-1', display_name='Edge 1', management_url='http://edge-1:5000')

        fake_client = FakeProxyClient()
        original = self.app_module.get_proxy_client
        self.app_module.get_proxy_client = lambda: fake_client
        try:
            response = self.app.get('/proxies')
        finally:
            self.app_module.get_proxy_client = original

        self.assertEqual(response.status_code, 200)
        self.assertIn('Edge 1', response.get_data(as_text=True))
        self.assertIn('Observability (24h)', response.get_data(as_text=True))

    def test_registry_refresh_does_not_reset_existing_proxy_status(self):
        from services.proxy_registry import get_proxy_registry  # type: ignore

        registry = get_proxy_registry()
        registry.ensure_proxy('edge-1', display_name='Edge 1', management_url='http://edge-1:5000', status='healthy')

        os.environ['PROXY_INSTANCE_ID'] = 'edge-1'
        os.environ['PROXY_DISPLAY_NAME'] = 'Edge 1'
        os.environ['PROXY_MANAGEMENT_URL'] = 'http://edge-1:5000'
        os.environ['PROXY_PUBLIC_HOST'] = 'edge-1'
        os.environ['PROXY_PUBLIC_HTTP_PROXY_PORT'] = '3128'
        os.environ['PROXY_PUBLIC_SOCKS_PROXY_PORT'] = '1080'
        os.environ['PROXY_PUBLIC_SOCKS_ENABLED'] = '1'

        refreshed = registry.register_local_proxy()

        self.assertEqual(refreshed.status, 'healthy')
        self.assertEqual(refreshed.public_host, 'edge-1')
        self.assertEqual(refreshed.public_http_proxy_port, 3128)
        self.assertEqual(refreshed.public_socks_proxy_port, 1080)
        self.assertTrue(refreshed.public_socks_enabled)


if __name__ == '__main__':
    unittest.main()
