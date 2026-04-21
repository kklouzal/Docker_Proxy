from __future__ import annotations

import os
import sys
import tempfile
import unittest

from .mysql_test_utils import REPO_ROOT, configure_test_mysql_env


def _import_proxy_app():
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))

    os.environ.setdefault('DISABLE_PROXY_AGENT', '1')
    os.environ.setdefault('DISABLE_BACKGROUND', '1')
    os.environ['PROXY_MANAGEMENT_TOKEN'] = 'test-token'
    os.environ['PROXY_INSTANCE_ID'] = 'edge-1'
    configure_test_mysql_env(tempfile.mkdtemp(prefix='proxy_api_mysql_'))

    from proxy.app import app as proxy_flask_app  # type: ignore

    proxy_flask_app.testing = True
    return proxy_flask_app


class TestProxyManagementApi(unittest.TestCase):
    def setUp(self):
        self._env_backup = {
            key: os.environ.get(key)
            for key in ('DISABLE_PROXY_AGENT', 'DISABLE_BACKGROUND', 'PROXY_MANAGEMENT_TOKEN', 'PROXY_INSTANCE_ID')
        }
        self.addCleanup(self._restore_env)
        flask_app = _import_proxy_app()
        self.app = flask_app.test_client()

    def _restore_env(self):
        for key, value in self._env_backup.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def test_health_requires_auth(self):
        response = self.app.get('/api/manage/health')
        self.assertEqual(response.status_code, 403)

    def test_health_returns_payload_with_auth(self):
        response = self.app.get('/api/manage/health', headers={'Authorization': 'Bearer test-token'})
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertIn('proxy_id', payload)
        self.assertIn('services', payload)
        self.assertIn('stats', payload)

    def test_sync_endpoint_delegates_to_runtime(self):
        import proxy.app as proxy_module  # type: ignore

        original = proxy_module.runtime.sync_from_db
        proxy_module.runtime.sync_from_db = lambda force=False: {'ok': True, 'forced': bool(force), 'detail': 'synced'}
        try:
            response = self.app.post(
                '/api/manage/sync',
                json={'force': True},
                headers={'Authorization': 'Bearer test-token'},
            )
        finally:
            proxy_module.runtime.sync_from_db = original

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload['ok'])
        self.assertTrue(payload['forced'])

    def test_cache_clear_endpoint_delegates_to_runtime(self):
        import proxy.app as proxy_module  # type: ignore

        original = proxy_module.runtime.clear_cache
        proxy_module.runtime.clear_cache = lambda: {'ok': True, 'detail': 'cache cleared'}
        try:
            response = self.app.post(
                '/api/manage/cache/clear',
                json={},
                headers={'Authorization': 'Bearer test-token'},
            )
        finally:
            proxy_module.runtime.clear_cache = original

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload['ok'])
        self.assertIn('cache', payload['detail'])


if __name__ == '__main__':
    unittest.main()
