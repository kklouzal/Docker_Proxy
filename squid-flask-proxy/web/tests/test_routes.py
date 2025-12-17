import os
import sys
import tarfile
import tempfile
import unittest


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
    os.environ.setdefault('AUTH_DB', os.path.join(tempfile.mkdtemp(prefix='sfp_auth_'), 'auth.db'))
    os.environ.setdefault('FLASK_SECRET_PATH', os.path.join(tempfile.mkdtemp(prefix='sfp_secret_'), 'flask_secret.key'))

    from app import app as flask_app  # type: ignore
    flask_app.testing = True
    return flask_app

class TestRoutes(unittest.TestCase):

    def setUp(self):
        flask_app = _import_app()
        self.app = flask_app.test_client()

        # Login for all protected routes.
        self.app.post(
            '/login',
            data={'username': 'admin', 'password': 'admin', 'next': ''},
            follow_redirects=True,
        )

    def test_index(self):
        response = self.app.get('/')
        self.assertEqual(response.status_code, 200)

    def test_squid_config(self):
        response = self.app.get('/squid/config')
        self.assertEqual(response.status_code, 200)

    def test_squid_config_caching_tab(self):
        response = self.app.get('/squid/config?tab=caching')
        self.assertEqual(response.status_code, 200)

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
            data={'action': 'delete_user', 'username': 'admin'},
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
        flask_app = _import_app()
        from services.pac_profiles_store import PacProfilesStore  # type: ignore

        # Use a temp DB file to avoid interacting with real volumes.
        import tempfile
        db = tempfile.NamedTemporaryFile(prefix="pac_profiles_", suffix=".db", delete=False)
        db.close()

        store = PacProfilesStore(db_path=db.name)
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

if __name__ == '__main__':
    unittest.main()