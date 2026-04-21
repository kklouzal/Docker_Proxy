from __future__ import annotations

import os
import sys
import tempfile
import unittest

from .mysql_test_utils import configure_test_mysql_env


def _import_remote_app():
    web_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    if web_dir not in sys.path:
        sys.path.insert(0, web_dir)

    os.environ['PROXY_CONTROL_MODE'] = 'remote'
    os.environ['DISABLE_BACKGROUND'] = '1'
    os.environ['PROXY_MANAGEMENT_TOKEN'] = 'test-token'
    os.environ['DEFAULT_PROXY_ID'] = 'edge-1'

    secret_path = os.path.join(tempfile.mkdtemp(prefix='sfp_secret_remote_'), 'flask_secret.key')
    configure_test_mysql_env(tempfile.mkdtemp(prefix='sfp_mysql_remote_'), secret_path=secret_path)

    from app import app as flask_app  # type: ignore

    flask_app.testing = True
    return flask_app


class _FakeProxyClient:
    def __init__(self):
        self.health_calls: list[str] = []
        self.sync_calls: list[tuple[str, bool]] = []
        self.clear_calls: list[str] = []

    def get_health(self, proxy_id, *, timeout_seconds=2.0):
        self.health_calls.append(str(proxy_id))
        return {
            'ok': True,
            'proxy_id': str(proxy_id),
            'proxy_status': 'healthy',
            'stats': {},
            'services': {
                'icap': {'ok': True, 'detail': 'ok'},
                'clamav': {'ok': True, 'detail': 'ok'},
                'dante': {'ok': True, 'detail': 'ok'},
            },
        }

    def sync_proxy(self, proxy_id, *, force=False, timeout_seconds=15.0):
        self.sync_calls.append((str(proxy_id), bool(force)))
        return {'ok': True, 'detail': 'sync requested'}

    def clear_proxy_cache(self, proxy_id, *, timeout_seconds=60.0):
        self.clear_calls.append(str(proxy_id))
        return {'ok': True, 'detail': 'cache clear requested'}


class TestSplitModeControlPlane(unittest.TestCase):
    def setUp(self):
        self._env_backup = {
            key: os.environ.get(key)
            for key in ('PROXY_CONTROL_MODE', 'DISABLE_BACKGROUND', 'PROXY_MANAGEMENT_TOKEN', 'DEFAULT_PROXY_ID')
        }
        self.addCleanup(self._restore_env)
        flask_app = _import_remote_app()
        self.app = flask_app.test_client()

        self.app.get('/login')
        with self.app.session_transaction() as sess:
            self.csrf_token = sess.get('_csrf_token', '')

        self.app.post(
            '/login',
            data={'username': 'admin', 'password': 'admin', 'next': '', 'csrf_token': self.csrf_token},
            follow_redirects=True,
        )

    def _restore_env(self):
        for key, value in self._env_backup.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def test_api_squid_config_reads_selected_proxy_revision(self):
        import app as app_module  # type: ignore
        from services.config_revisions import get_config_revisions  # type: ignore
        from services.proxy_registry import get_proxy_registry  # type: ignore

        registry = get_proxy_registry()
        registry.ensure_proxy('edge-1', display_name='Edge 1', management_url='http://edge-1:5000')
        registry.ensure_proxy('edge-2', display_name='Edge 2', management_url='http://edge-2:5000')

        revisions = get_config_revisions()
        revisions.create_revision('edge-1', 'workers 1\n', created_by='tester', source_kind='test')
        revisions.create_revision('edge-2', 'workers 2\n', created_by='tester', source_kind='test')

        fake_client = _FakeProxyClient()
        original = app_module.get_proxy_client
        app_module.get_proxy_client = lambda: fake_client
        try:
            response = self.app.get('/api/squid-config?proxy_id=edge-2')
        finally:
            app_module.get_proxy_client = original

        self.assertEqual(response.status_code, 200)
        self.assertIn('workers 2', response.get_data(as_text=True))

    def test_reload_route_targets_selected_proxy(self):
        import app as app_module  # type: ignore
        from services.proxy_registry import get_proxy_registry  # type: ignore

        registry = get_proxy_registry()
        registry.ensure_proxy('edge-1', display_name='Edge 1', management_url='http://edge-1:5000')

        fake_client = _FakeProxyClient()
        original = app_module.get_proxy_client
        app_module.get_proxy_client = lambda: fake_client
        try:
            response = self.app.post(
                '/reload',
                data={'proxy_id': 'edge-1', 'csrf_token': self.csrf_token},
                follow_redirects=False,
            )
        finally:
            app_module.get_proxy_client = original

        self.assertIn(response.status_code, (301, 302, 308))
        self.assertEqual(fake_client.sync_calls, [('edge-1', True)])

    def test_fleet_page_renders_registered_proxy(self):
        import app as app_module  # type: ignore
        from services.proxy_registry import get_proxy_registry  # type: ignore

        registry = get_proxy_registry()
        registry.ensure_proxy('edge-1', display_name='Edge 1', management_url='http://edge-1:5000')

        fake_client = _FakeProxyClient()
        original = app_module.get_proxy_client
        app_module.get_proxy_client = lambda: fake_client
        try:
            response = self.app.get('/fleet')
        finally:
            app_module.get_proxy_client = original

        self.assertEqual(response.status_code, 200)
        self.assertIn('Edge 1', response.get_data(as_text=True))


if __name__ == '__main__':
    unittest.main()
