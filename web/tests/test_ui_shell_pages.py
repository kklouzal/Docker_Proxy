import pytest

from .flask_test_helpers import login


pytestmark = pytest.mark.legacy_simulated


@pytest.mark.parametrize(
    "path, expected",
    [
        ("/", "Status"),
        ("/observability", "Observability"),
        ("/squid/config", "Squid"),
        ("/exclusions", "Exclusions"),
        ("/certs", "Certificates"),
        ("/adblock", "Ad"),
        ("/webfilter", "Web"),
        ("/clamav", "Clam"),
        ("/sslfilter", "SSL"),
        ("/pac", "PAC"),
        ("/administration", "Administration"),
    ],
)
def test_ui_pages_render_and_include_csrf_meta(app_module, path: str, expected: str):
    c = app_module.app.test_client()
    login(c)

    r = c.get(path)
    assert r.status_code == 200
    body = r.data.decode("utf-8", errors="replace")
    assert "<meta name=\"csrf-token\"" in body
    assert expected.lower() in body.lower()


def test_logged_in_layout_renders_shell_accessibility_hooks(app_module):
    c = app_module.app.test_client()
    login(c)

    r = c.get("/")
    assert r.status_code == 200
    body = r.data.decode("utf-8", errors="replace")
    assert 'class="skip-link"' in body
    assert 'id="site-header"' in body
    assert 'id="context-strip-slot"' in body
    assert 'id="primary-nav"' in body
    assert 'id="nav-toggle"' in body
    assert 'class="nav-user"' not in body


def test_login_page_uses_updated_auth_shell(app_module):
    c = app_module.app.test_client()

    r = c.get("/login")
    assert r.status_code == 200
    body = r.data.decode("utf-8", errors="replace")
    assert "Secure access" in body
    assert 'class="auth-shell"' in body
    assert "Default credentials for first-run local setups" in body
