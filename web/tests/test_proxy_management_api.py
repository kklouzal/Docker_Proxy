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

    def test_health_returns_degraded_payload_when_runtime_raises(self):
        import proxy.app as proxy_module  # type: ignore

        original = proxy_module.runtime.collect_health
        proxy_module.runtime.collect_health = lambda: (_ for _ in ()).throw(RuntimeError('boom'))
        try:
            response = self.app.get('/api/manage/health', headers={'Authorization': 'Bearer test-token'})
        finally:
            proxy_module.runtime.collect_health = original

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertFalse(payload['ok'])
        self.assertEqual(payload['status'], 'degraded')
        self.assertIn('state_errors', payload)

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

    def test_clamav_test_endpoints_delegate_to_runtime(self):
        import proxy.app as proxy_module  # type: ignore

        original_eicar = proxy_module.runtime.test_clamav_eicar
        original_icap = proxy_module.runtime.test_clamav_icap
        proxy_module.runtime.test_clamav_eicar = lambda: {'ok': True, 'detail': 'Eicar FOUND'}
        proxy_module.runtime.test_clamav_icap = lambda: {'ok': False, 'detail': 'ICAP/1.0 500'}
        try:
            eicar_response = self.app.post(
                '/api/manage/clamav/test-eicar',
                json={},
                headers={'Authorization': 'Bearer test-token'},
            )
            icap_response = self.app.post(
                '/api/manage/clamav/test-icap',
                json={},
                headers={'Authorization': 'Bearer test-token'},
            )
        finally:
            proxy_module.runtime.test_clamav_eicar = original_eicar
            proxy_module.runtime.test_clamav_icap = original_icap

        self.assertEqual(eicar_response.status_code, 200)
        self.assertEqual(icap_response.status_code, 503)
        self.assertTrue(eicar_response.get_json()['ok'])
        self.assertFalse(icap_response.get_json()['ok'])


if __name__ == '__main__':
    unittest.main()
