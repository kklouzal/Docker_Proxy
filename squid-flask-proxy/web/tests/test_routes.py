import os
import sys
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

    from app import app as flask_app  # type: ignore
    flask_app.testing = True
    return flask_app

class TestRoutes(unittest.TestCase):

    def setUp(self):
        flask_app = _import_app()
        self.app = flask_app.test_client()

    def test_index(self):
        response = self.app.get('/')
        self.assertEqual(response.status_code, 200)

    def test_squid_config(self):
        response = self.app.get('/squid/config')
        self.assertEqual(response.status_code, 200)

    def test_status(self):
        response = self.app.get('/status', follow_redirects=False)
        self.assertIn(response.status_code, (301, 302, 308))

    def test_certs(self):
        response = self.app.get('/certs')
        self.assertEqual(response.status_code, 200)

    def test_adblock(self):
        response = self.app.get('/adblock')
        self.assertEqual(response.status_code, 200)

    def test_clamav(self):
        response = self.app.get('/clamav')
        self.assertEqual(response.status_code, 200)

if __name__ == '__main__':
    unittest.main()