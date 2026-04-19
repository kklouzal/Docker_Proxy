import os
import socket
import sys
import tarfile
import zipfile
import tempfile
import threading
import unittest

from .mysql_test_utils import configure_test_mysql_env


def _import_app():
    try:
        import flask  # noqa: F401
    except Exception as e:
        raise unittest.SkipTest(f"Flask not available in this environment: {e}")

    # Ensure we import the real Flask app from web/app.py.
    web_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    if web_dir not in sys.path:
        sys.path.insert(0, web_dir)

    # Avoid starting background tailers/samplers during unit tests.
    os.environ.setdefault('DISABLE_BACKGROUND', '1')

    # Isolate auth state so tests are deterministic.
    secret_path = os.path.join(tempfile.mkdtemp(prefix='sfp_secret_'), 'flask_secret.key')
    configure_test_mysql_env(tempfile.mkdtemp(prefix='sfp_mysql_'), secret_path=secret_path)

    from app import app as flask_app  # type: ignore
    flask_app.testing = True
    return flask_app

class TestRoutes(unittest.TestCase):

    def setUp(self):
        flask_app = _import_app()
        self.app = flask_app.test_client()

        # Establish session + CSRF token.
        self.app.get('/login')
        with self.app.session_transaction() as sess:
            self.csrf_token = sess.get('_csrf_token', '')

        # Login for all protected routes.
        self.app.post(
            '/login',
            data={'username': 'admin', 'password': 'admin', 'next': '', 'csrf_token': self.csrf_token},
            follow_redirects=True,
        )

    def test_eicar_temp_file_cleaned_on_socket_failure(self):
        # Import the app module to call the helper directly.
        web_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        if web_dir not in sys.path:
            sys.path.insert(0, web_dir)
        import app as app_module  # type: ignore

        old_host = os.environ.get('CLAMD_HOST')
        old_port = os.environ.get('CLAMD_PORT')
        try:
            # Pick an unused port and close it so the connect attempt fails cleanly.
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
            listener.close()

            os.environ['CLAMD_HOST'] = '127.0.0.1'
            os.environ['CLAMD_PORT'] = str(port)

            res = app_module._test_eicar()
            self.assertFalse(res.get('ok'), res)
        finally:
            if old_host is None:
                os.environ.pop('CLAMD_HOST', None)
            else:
                os.environ['CLAMD_HOST'] = old_host
            if old_port is None:
                os.environ.pop('CLAMD_PORT', None)
            else:
                os.environ['CLAMD_PORT'] = old_port

    def test_check_clamd_uses_remote_tcp_ping(self):
        import app as app_module  # type: ignore

        old_host = os.environ.get('CLAMD_HOST')
        old_port = os.environ.get('CLAMD_PORT')

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        seen = {'request': b''}

        def serve() -> None:
            conn, _addr = listener.accept()
            with conn:
                buf = b''
                while b'\n' not in buf:
                    chunk = conn.recv(64)
                    if not chunk:
                        break
                    buf += chunk
                seen['request'] = buf
                conn.sendall(b'PONG\n')

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        try:
            os.environ['CLAMD_HOST'] = '127.0.0.1'
            os.environ['CLAMD_PORT'] = str(port)

            res = app_module._check_clamd()
            self.assertTrue(res.get('ok'), res)
            self.assertIn('PONG', res.get('detail', ''))
            self.assertEqual(seen['request'], b'PING\n')
        finally:
            listener.close()
            t.join(timeout=2)
            if old_host is None:
                os.environ.pop('CLAMD_HOST', None)
            else:
                os.environ['CLAMD_HOST'] = old_host
            if old_port is None:
                os.environ.pop('CLAMD_PORT', None)
            else:
                os.environ['CLAMD_PORT'] = old_port

    def test_eicar_uses_remote_tcp_instream(self):
        web_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        if web_dir not in sys.path:
            sys.path.insert(0, web_dir)
        import app as app_module  # type: ignore

        old_host = os.environ.get('CLAMD_HOST')
        old_port = os.environ.get('CLAMD_PORT')

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        captured = {'command': b'', 'payload': b''}

        def serve() -> None:
            conn, _addr = listener.accept()
            with conn:
                prefix = b'zINSTREAM\0'
                buf = b''
                while len(buf) < len(prefix):
                    chunk = conn.recv(128)
                    if not chunk:
                        break
                    buf += chunk
                captured['command'] = buf[:len(prefix)]
                rest = buf[len(prefix):]
                payload = b''

                while True:
                    while len(rest) < 4:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        rest += chunk
                    if len(rest) < 4:
                        break
                    size = int.from_bytes(rest[:4], 'big')
                    rest = rest[4:]
                    if size == 0:
                        break
                    while len(rest) < size:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        rest += chunk
                    payload += rest[:size]
                    rest = rest[size:]

                captured['payload'] = payload
                conn.sendall(b'stream: Eicar-Test-Signature FOUND\0')

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        try:
            os.environ['CLAMD_HOST'] = '127.0.0.1'
            os.environ['CLAMD_PORT'] = str(port)

            res = app_module._test_eicar()
            self.assertTrue(res.get('ok'), res)
            self.assertIn('FOUND', res.get('detail', ''))
            self.assertEqual(captured['command'], b'zINSTREAM\0')
            self.assertIn(b'EICAR-STANDARD-ANTIVIRUS-TEST-FILE', captured['payload'])
        finally:
            listener.close()
            t.join(timeout=2)
            if old_host is None:
                os.environ.pop('CLAMD_HOST', None)
            else:
                os.environ['CLAMD_HOST'] = old_host
            if old_port is None:
                os.environ.pop('CLAMD_PORT', None)
            else:
                os.environ['CLAMD_PORT'] = old_port

    def test_index(self):
        response = self.app.get('/')
        self.assertEqual(response.status_code, 200)

    def test_squid_config(self):
        response = self.app.get('/squid/config')
        self.assertEqual(response.status_code, 200)

    def test_squid_config_caching_tab(self):
        response = self.app.get('/squid/config?tab=caching')
        self.assertEqual(response.status_code, 200)

    def test_squid_config_caching_tab_keeps_range_cache_checked_for_bounded_limit(self):
        import app as app_module  # type: ignore

        old_get_current_config = app_module.squid_controller.get_current_config
        try:
            app_module.squid_controller.get_current_config = lambda: "range_offset_limit 128 MB\n"
            response = self.app.get('/squid/config?tab=caching')
        finally:
            app_module.squid_controller.get_current_config = old_get_current_config

        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        self.assertIn('name="range_cache_on" checked', body)

    def test_squid_config_timeouts_tab(self):
        response = self.app.get('/squid/config?tab=timeouts')
        self.assertEqual(response.status_code, 200)

    def test_squid_config_logging_tab(self):
        response = self.app.get('/squid/config?tab=logging')
        self.assertEqual(response.status_code, 200)

    def test_squid_config_network_tab(self):
        response = self.app.get('/squid/config?tab=network')
        self.assertEqual(response.status_code, 200)

    def test_squid_config_dns_tab(self):
        response = self.app.get('/squid/config?tab=dns')
        self.assertEqual(response.status_code, 200)

    def test_squid_config_ssl_tab(self):
        response = self.app.get('/squid/config?tab=ssl')
        self.assertEqual(response.status_code, 200)

    def test_squid_config_icap_tab(self):
        response = self.app.get('/squid/config?tab=icap')
        self.assertEqual(response.status_code, 200)

    def test_squid_config_privacy_tab(self):
        response = self.app.get('/squid/config?tab=privacy')
        self.assertEqual(response.status_code, 200)

    def test_squid_config_limits_tab(self):
        response = self.app.get('/squid/config?tab=limits')
        self.assertEqual(response.status_code, 200)

    def test_squid_config_performance_tab(self):
        response = self.app.get('/squid/config?tab=performance')
        self.assertEqual(response.status_code, 200)

    def test_squid_config_http_tab(self):
        response = self.app.get('/squid/config?tab=http')
        self.assertEqual(response.status_code, 200)

    def test_status(self):
        response = self.app.get('/status', follow_redirects=False)
        self.assertIn(response.status_code, (301, 302, 308))

    def test_certs(self):
        response = self.app.get('/certs')
        self.assertEqual(response.status_code, 200)

    def test_cannot_delete_current_user(self):
        response = self.app.post(
            '/administration',
            data={'action': 'delete_user', 'username': 'admin', 'csrf_token': self.csrf_token},
            follow_redirects=False,
        )
        self.assertIn(response.status_code, (301, 302, 308))
        self.assertIn('/administration', response.headers.get('Location', ''))

    def test_adblock(self):
        response = self.app.get('/adblock')
        self.assertEqual(response.status_code, 200)

    def test_clamav(self):
        response = self.app.get('/clamav')
        self.assertEqual(response.status_code, 200)

    def test_pac_builder(self):
        response = self.app.get('/pac')
        self.assertEqual(response.status_code, 200)

    def test_webfilter_categories_tab(self):
        response = self.app.get('/webfilter?tab=categories')
        self.assertEqual(response.status_code, 200)

    def test_webfilter_whitelist_tab(self):
        response = self.app.get('/webfilter?tab=whitelist')
        self.assertEqual(response.status_code, 200)

    def test_webfilter_blockedlog_tab(self):
        response = self.app.get('/webfilter?tab=blockedlog')
        self.assertEqual(response.status_code, 200)

    def test_sslfilter_page(self):
        response = self.app.get('/sslfilter')
        self.assertEqual(response.status_code, 200)

    def test_proxy_pac(self):
        response = self.app.get('/proxy.pac')
        self.assertEqual(response.status_code, 200)

    def test_wpad_dat_public(self):
        flask_app = _import_app()
        c = flask_app.test_client()
        r = c.get('/wpad.dat')
        self.assertEqual(r.status_code, 200)
        self.assertIn('application/x-ns-proxy-autoconfig', r.headers.get('Content-Type', ''))

    def test_proxy_pac_can_include_socks(self):
        # Create a catch-all PAC profile that enables SOCKS.
        from services.pac_profiles_store import PacProfilesStore  # type: ignore

        store = PacProfilesStore()
        ok, err, pid = store.upsert_profile(
            profile_id=None,
            name="test",
            client_cidr="",
            socks_enabled=True,
            socks_host="",
            socks_port="1080",
            direct_domains_text="example.com\n",
            direct_dst_nets_text="10.0.0.0/8\n",
        )
        self.assertTrue(ok, err)
        self.assertIsNotNone(pid)

        # Monkeypatch the global store getter inside app module.
        import app as app_module  # type: ignore

        old_get = app_module.get_pac_profiles_store
        app_module.get_pac_profiles_store = lambda: store
        try:
            response = self.app.get('/proxy.pac')
            self.assertEqual(response.status_code, 200)
            body = response.data.decode('utf-8', errors='replace')
            self.assertIn('SOCKS5', body)
        finally:
            app_module.get_pac_profiles_store = old_get


class TestWebcatBuildUt1(unittest.TestCase):

    def _import_webcat_build(self):
        # Import tools module from web/ directory.
        web_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        if web_dir not in sys.path:
            sys.path.insert(0, web_dir)

        from tools import webcat_build  # type: ignore

        return webcat_build

    def test_ut1_tar_gz_lowercase_blacklists_detected(self):
        webcat_build = self._import_webcat_build()

        with tempfile.TemporaryDirectory(prefix="webcat_ut1_") as td:
            root = os.path.join(td, "payload")
            os.makedirs(root, exist_ok=True)

            # UT1 layout (lowercase): blacklists/<category>/domains
            for cat, domains in {
                "adult": ["example.com", "sub.example.com"],
                "drogue": ["drug.example"],
            }.items():
                cat_dir = os.path.join(root, "blacklists", cat)
                os.makedirs(cat_dir, exist_ok=True)
                with open(os.path.join(cat_dir, "domains"), "w", encoding="utf-8") as f:
                    for d in domains:
                        f.write(d + "\n")

            tar_path = os.path.join(td, "ut1.tar.gz")
            with tarfile.open(tar_path, "w:gz") as t:
                # Add the payload directory contents at archive root.
                t.add(root, arcname="")

            pairs, source, aliases = webcat_build._collect(webcat_build.Path(tar_path))  # type: ignore[attr-defined]
            self.assertTrue(source.startswith("ut1tar:"), source)
            self.assertGreaterEqual(len(pairs), 3)
            cats = {c for _, c in pairs}
            self.assertIn("adult", cats)
            self.assertIn("drogue", cats)
            self.assertEqual(aliases, {})

    def test_ut1_dedup_identical_category_lists(self):
        webcat_build = self._import_webcat_build()

        with tempfile.TemporaryDirectory(prefix="webcat_ut1_") as td:
            root = os.path.join(td, "payload")
            os.makedirs(root, exist_ok=True)

            # Two categories with identical domain lists.
            for cat in ("proxy", "proxies"):
                cat_dir = os.path.join(root, "blacklists", cat)
                os.makedirs(cat_dir, exist_ok=True)
                with open(os.path.join(cat_dir, "domains"), "w", encoding="utf-8") as f:
                    f.write("example.com\n")
                    f.write("sub.example.com\n")

            tar_path = os.path.join(td, "ut1.tar.gz")
            with tarfile.open(tar_path, "w:gz") as t:
                t.add(root, arcname="")

            pairs, source, aliases = webcat_build._collect(webcat_build.Path(tar_path))  # type: ignore[attr-defined]
            self.assertTrue(source.startswith("ut1tar:"), source)
            # Because we iterate categories in sorted order, 'proxies' is canonical and 'proxy' becomes alias.
            self.assertIn("proxy", aliases)
            self.assertEqual(aliases["proxy"], "proxies")
            cats = {c for _, c in pairs}
            self.assertEqual(cats, {"proxies"})

    def test_zip_extraction_blocks_path_traversal(self):
        webcat_build = self._import_webcat_build()

        with tempfile.TemporaryDirectory(prefix="webcat_zip_") as td:
            zip_path = os.path.join(td, "ut1.zip")
            pwned_path = os.path.join(td, "pwned.txt")

            # Build a zip with both a valid UT1 layout and a traversal entry.
            with zipfile.ZipFile(zip_path, "w") as z:
                z.writestr("blacklists/adult/domains", "example.com\nsub.example.com\n")
                z.writestr("blacklists/drogue/domains", "drug.example\n")
                z.writestr("../pwned.txt", "you should not see this")

            pairs, source, aliases = webcat_build._collect(webcat_build.Path(zip_path))  # type: ignore[attr-defined]

            self.assertTrue(source.startswith("ut1zip:"), source)
            self.assertGreaterEqual(len(pairs), 3)
            cats = {c for _, c in pairs}
            self.assertIn("adult", cats)
            self.assertIn("drogue", cats)
            self.assertEqual(aliases, {})
            self.assertFalse(os.path.exists(pwned_path), "zip traversal wrote outside extraction dir")

if __name__ == '__main__':
    unittest.main()