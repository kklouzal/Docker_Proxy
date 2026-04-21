from __future__ import annotations

import os
import sys
import tempfile
import unittest
from types import SimpleNamespace

from .mysql_test_utils import configure_test_mysql_env


def _import_remote_app():
    web_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    if web_dir not in sys.path:
        sys.path.insert(0, web_dir)

    os.environ['PROXY_CONTROL_MODE'] = 'remote'
    os.environ['DISABLE_BACKGROUND'] = '1'
    os.environ['PROXY_MANAGEMENT_TOKEN'] = 'test-token'
    os.environ['DEFAULT_PROXY_ID'] = 'edge-1'

    secret_path = os.path.join(tempfile.mkdtemp(prefix='sfp_secret_remote_policy_'), 'flask_secret.key')
    configure_test_mysql_env(tempfile.mkdtemp(prefix='sfp_mysql_remote_policy_'), secret_path=secret_path)

    from app import app as flask_app  # type: ignore

    flask_app.testing = True
    return flask_app


class _FakeProxyClient:
    def __init__(self):
        self.sync_calls: list[tuple[str, bool]] = []

    def sync_proxy(self, proxy_id, *, force=False, timeout_seconds=15.0):
        self.sync_calls.append((str(proxy_id), bool(force)))
        return {'ok': True, 'detail': 'sync requested'}

    def get_health(self, proxy_id, *, timeout_seconds=2.0):
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


class TestSplitModePolicyRoutes(unittest.TestCase):
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

    def test_webfilter_save_nudges_selected_proxy_without_local_apply(self):
        import app as app_module  # type: ignore
        from services.proxy_registry import get_proxy_registry  # type: ignore

        registry = get_proxy_registry()
        registry.ensure_proxy('edge-1', display_name='Edge 1', management_url='http://edge-1:5000')

        fake_client = _FakeProxyClient()

        class FakeWebFilterStore:
            def __init__(self):
                self.saved = None

            def init_db(self):
                return None

            def set_settings(self, *, enabled: bool, source_url: str, blocked_categories: list[str]):
                self.saved = {
                    'enabled': enabled,
                    'source_url': source_url,
                    'blocked_categories': blocked_categories,
                }

            def apply_squid_include(self):
                raise AssertionError('remote mode should not apply local webfilter includes')

            def get_settings(self):
                return SimpleNamespace(enabled=False, source_url='', blocked_categories=[])

            def list_available_categories(self):
                return []

            def list_whitelist(self):
                return []

            def list_blocked_log(self, limit: int = 200):
                return []

        fake_store = FakeWebFilterStore()
        original_client = app_module.get_proxy_client
        original_store = app_module.get_webfilter_store
        app_module.get_proxy_client = lambda: fake_client
        app_module.get_webfilter_store = lambda: fake_store
        try:
            response = self.app.post(
                '/webfilter',
                data={
                    'action': 'save',
                    'tab': 'categories',
                    'proxy_id': 'edge-1',
                    'enabled': 'on',
                    'source_url': 'https://example.invalid/webcat.tar.gz',
                    'categories': ['adult', 'malware'],
                    'csrf_token': self.csrf_token,
                },
                follow_redirects=False,
            )
        finally:
            app_module.get_proxy_client = original_client
            app_module.get_webfilter_store = original_store

        self.assertIn(response.status_code, (301, 302, 303, 307, 308))
        self.assertEqual(fake_client.sync_calls, [('edge-1', True)])
        self.assertEqual(
            fake_store.saved,
            {
                'enabled': True,
                'source_url': 'https://example.invalid/webcat.tar.gz',
                'blocked_categories': ['adult', 'malware'],
            },
        )

    def test_sslfilter_add_nudges_selected_proxy_without_local_apply(self):
        import app as app_module  # type: ignore
        from services.proxy_registry import get_proxy_registry  # type: ignore

        registry = get_proxy_registry()
        registry.ensure_proxy('edge-1', display_name='Edge 1', management_url='http://edge-1:5000')

        fake_client = _FakeProxyClient()

        class FakeSSLFilterStore:
            def init_db(self):
                return None

            def add_nobump(self, entry: str):
                return True, '', entry

            def apply_squid_include(self):
                raise AssertionError('remote mode should not apply local sslfilter includes')

            def list_nobump(self):
                return []

        fake_store = FakeSSLFilterStore()
        original_client = app_module.get_proxy_client
        original_store = app_module.get_sslfilter_store
        app_module.get_proxy_client = lambda: fake_client
        app_module.get_sslfilter_store = lambda: fake_store
        try:
            response = self.app.post(
                '/sslfilter',
                data={
                    'action': 'add',
                    'proxy_id': 'edge-1',
                    'cidr': '10.0.0.0/8',
                    'csrf_token': self.csrf_token,
                },
                follow_redirects=False,
            )
        finally:
            app_module.get_proxy_client = original_client
            app_module.get_sslfilter_store = original_store

        self.assertIn(response.status_code, (301, 302, 303, 307, 308))
        self.assertEqual(fake_client.sync_calls, [('edge-1', True)])

    def test_clamav_toggle_publishes_revision_and_nudges_selected_proxy(self):
        import app as app_module  # type: ignore
        from services.config_revisions import get_config_revisions  # type: ignore
        from services.proxy_registry import get_proxy_registry  # type: ignore

        registry = get_proxy_registry()
        registry.ensure_proxy('edge-1', display_name='Edge 1', management_url='http://edge-1:5000')

        fake_client = _FakeProxyClient()
        original_client = app_module.get_proxy_client
        original_get_current_config = app_module.squid_controller.get_current_config
        app_module.get_proxy_client = lambda: fake_client
        app_module.squid_controller.get_current_config = lambda: 'adaptation_access av_resp_set deny all\n'
        try:
            response = self.app.post(
                '/clamav/toggle',
                data={'action': 'enable', 'proxy_id': 'edge-1', 'csrf_token': self.csrf_token},
                follow_redirects=False,
            )
        finally:
            app_module.get_proxy_client = original_client
            app_module.squid_controller.get_current_config = original_get_current_config

        self.assertIn(response.status_code, (301, 302, 303, 307, 308))
        self.assertEqual(fake_client.sync_calls, [('edge-1', True)])

        active = get_config_revisions().get_active_revision('edge-1')
        self.assertIsNotNone(active)
        self.assertIn('adaptation_access av_resp_set allow icap_adblockable', active.config_text)

    def test_adblock_flush_cache_nudges_selected_proxy(self):
        import app as app_module  # type: ignore
        from services.proxy_registry import get_proxy_registry  # type: ignore

        registry = get_proxy_registry()
        registry.ensure_proxy('edge-1', display_name='Edge 1', management_url='http://edge-1:5000')

        fake_client = _FakeProxyClient()

        class FakeAdblockStore:
            def __init__(self):
                self.flush_requested = False

            def init_db(self):
                return None

            def request_cache_flush(self):
                self.flush_requested = True

        fake_store = FakeAdblockStore()
        original_client = app_module.get_proxy_client
        original_store = app_module.get_adblock_store
        app_module.get_proxy_client = lambda: fake_client
        app_module.get_adblock_store = lambda: fake_store
        try:
            response = self.app.post(
                '/adblock',
                data={
                    'action': 'flush_cache',
                    'proxy_id': 'edge-1',
                    'csrf_token': self.csrf_token,
                },
                follow_redirects=False,
            )
        finally:
            app_module.get_proxy_client = original_client
            app_module.get_adblock_store = original_store

        self.assertIn(response.status_code, (301, 302, 303, 307, 308))
        self.assertTrue(fake_store.flush_requested)
        self.assertEqual(fake_client.sync_calls, [('edge-1', False)])

    def test_pac_profile_create_nudges_selected_proxy(self):
        import app as app_module  # type: ignore
        from services.proxy_registry import get_proxy_registry  # type: ignore

        registry = get_proxy_registry()
        registry.ensure_proxy('edge-1', display_name='Edge 1', management_url='http://edge-1:5000')

        fake_client = _FakeProxyClient()

        class FakePacProfilesStore:
            def upsert_profile(self, **kwargs):
                return True, '', 101

            def list_profiles(self):
                return []

        fake_store = FakePacProfilesStore()
        original_client = app_module.get_proxy_client
        original_store = app_module.get_pac_profiles_store
        app_module.get_proxy_client = lambda: fake_client
        app_module.get_pac_profiles_store = lambda: fake_store
        try:
            response = self.app.post(
                '/pac',
                data={
                    'action': 'create',
                    'proxy_id': 'edge-1',
                    'name': 'Office',
                    'client_cidr': '192.168.50.0/24',
                    'socks_enabled': 'on',
                    'socks_host': '',
                    'socks_port': '1080',
                    'direct_domains': 'example.com\n',
                    'direct_dst_nets': '',
                    'csrf_token': self.csrf_token,
                },
                follow_redirects=False,
            )
        finally:
            app_module.get_proxy_client = original_client
            app_module.get_pac_profiles_store = original_store

        self.assertIn(response.status_code, (301, 302, 303, 307, 308))
        self.assertEqual(fake_client.sync_calls, [('edge-1', False)])

    def test_exclusions_add_domain_nudges_selected_proxy_for_pac(self):
        import app as app_module  # type: ignore
        from services.proxy_registry import get_proxy_registry  # type: ignore

        registry = get_proxy_registry()
        registry.ensure_proxy('edge-1', display_name='Edge 1', management_url='http://edge-1:5000')

        fake_client = _FakeProxyClient()

        class FakeExclusionsStore:
            def __init__(self):
                self.domains: list[str] = []

            def add_domain(self, domain: str):
                self.domains.append(domain)

            def list_all(self):
                return SimpleNamespace(domains=list(self.domains), src_nets=[], dst_nets=[], exclude_private_nets=False)

        fake_store = FakeExclusionsStore()
        original_client = app_module.get_proxy_client
        original_store = app_module.get_exclusions_store
        app_module.get_proxy_client = lambda: fake_client
        app_module.get_exclusions_store = lambda: fake_store
        try:
            response = self.app.post(
                '/exclusions',
                data={
                    'action': 'add_domain',
                    'proxy_id': 'edge-1',
                    'domain': 'internal.example',
                    'csrf_token': self.csrf_token,
                },
                follow_redirects=False,
            )
        finally:
            app_module.get_proxy_client = original_client
            app_module.get_exclusions_store = original_store

        self.assertIn(response.status_code, (301, 302, 303, 307, 308))
        self.assertEqual(fake_store.domains, ['internal.example'])
        self.assertEqual(fake_client.sync_calls, [('edge-1', False)])


if __name__ == '__main__':
    unittest.main()
