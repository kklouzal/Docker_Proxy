from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

from .mysql_test_utils import REPO_ROOT, configure_test_mysql_env


def _import_runtime():
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    web_root = REPO_ROOT / 'web'
    if str(web_root) not in sys.path:
        sys.path.insert(0, str(web_root))

    os.environ['DISABLE_PROXY_AGENT'] = '1'
    os.environ['DISABLE_BACKGROUND'] = '1'
    os.environ['PROXY_INSTANCE_ID'] = 'edge-1'
    os.environ['DEFAULT_PROXY_ID'] = 'edge-1'
    configure_test_mysql_env(tempfile.mkdtemp(prefix='proxy_policy_mysql_'))

    from proxy.runtime import ProxyRuntime  # type: ignore
    from services.webfilter_store import get_webfilter_store  # type: ignore
    from services.sslfilter_store import get_sslfilter_store  # type: ignore
    from services.proxy_context import reset_proxy_id, set_proxy_id  # type: ignore

    return ProxyRuntime, get_webfilter_store, get_sslfilter_store, set_proxy_id, reset_proxy_id


class TestProxyPolicyMaterialization(unittest.TestCase):
    def setUp(self):
        self._env_backup = {
            key: os.environ.get(key)
            for key in ('DISABLE_PROXY_AGENT', 'DISABLE_BACKGROUND', 'PROXY_INSTANCE_ID', 'DEFAULT_PROXY_ID')
        }
        self.addCleanup(self._restore_env)

    def _restore_env(self):
        for key, value in self._env_backup.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def test_proxy_sync_materializes_policy_files_and_reloads(self):
        ProxyRuntime, get_webfilter_store, get_sslfilter_store, _set_proxy_id, _reset_proxy_id = _import_runtime()

        runtime = ProxyRuntime()
        webfilter_store = get_webfilter_store()
        sslfilter_store = get_sslfilter_store()

        temp_root = Path(tempfile.mkdtemp(prefix='proxy_policy_files_'))
        webfilter_store.squid_include_path = str(temp_root / '30-webfilter.conf')
        webfilter_store.whitelist_path = str(temp_root / 'webfilter_whitelist.txt')
        sslfilter_store.squid_include_path = str(temp_root / '10-sslfilter.conf')
        sslfilter_store.nobump_list_path = str(temp_root / 'sslfilter_nobump.txt')

        token = _set_proxy_id('edge-1')
        try:
            webfilter_store.set_settings(
                enabled=True,
                source_url='https://example.invalid/all.tar.gz',
                blocked_categories=['adult', 'malware'],
            )
            ok, err, _ = webfilter_store.add_whitelist('example.com')
            self.assertTrue(ok, err)
            ok, err, _ = sslfilter_store.add_nobump('10.0.0.0/8')
            self.assertTrue(ok, err)
        finally:
            _reset_proxy_id(token)

        runtime.controller.get_current_config = lambda: ''  # type: ignore[method-assign]
        runtime.controller.reload_squid = lambda: (b'policy reload ok', b'')  # type: ignore[method-assign]

        result = runtime.sync_from_db(force=True)

        self.assertTrue(result['ok'])
        self.assertTrue(result['policy_changed'])
        self.assertFalse(result['config_changed'])
        self.assertIn('policy reload ok', result['detail'])

        webfilter_include = Path(webfilter_store.squid_include_path).read_text(encoding='utf-8')
        whitelist = Path(webfilter_store.whitelist_path).read_text(encoding='utf-8')
        sslfilter_include = Path(sslfilter_store.squid_include_path).read_text(encoding='utf-8')
        nobump = Path(sslfilter_store.nobump_list_path).read_text(encoding='utf-8')

        self.assertIn('acl webfilter_block_adult external webcat adult', webfilter_include)
        self.assertIn('http_access allow webfilter_whitelist', webfilter_include)
        self.assertIn('example.com', whitelist)
        self.assertIn('ssl_bump splice sslfilter_nobump', sslfilter_include)
        self.assertIn('10.0.0.0/8', nobump)

    def test_webfilter_settings_are_scoped_per_proxy(self):
        _ProxyRuntime, get_webfilter_store, _get_sslfilter_store, _set_proxy_id, _reset_proxy_id = _import_runtime()
        webfilter_store = get_webfilter_store()

        token = _set_proxy_id('edge-1')
        try:
            webfilter_store.set_settings(
                enabled=True,
                source_url='https://example.invalid/all.tar.gz',
                blocked_categories=['adult'],
            )
        finally:
            _reset_proxy_id(token)

        token = _set_proxy_id('edge-2')
        try:
            webfilter_store.set_settings(
                enabled=False,
                source_url='https://example.invalid/all.tar.gz',
                blocked_categories=['malware'],
            )
            settings_edge_2 = webfilter_store.get_settings()
        finally:
            _reset_proxy_id(token)

        token = _set_proxy_id('edge-1')
        try:
            settings_edge_1 = webfilter_store.get_settings()
        finally:
            _reset_proxy_id(token)

        self.assertTrue(settings_edge_1.enabled)
        self.assertEqual(settings_edge_1.blocked_categories, ['adult'])
        self.assertFalse(settings_edge_2.enabled)
        self.assertEqual(settings_edge_2.blocked_categories, ['malware'])


if __name__ == '__main__':
    unittest.main()
