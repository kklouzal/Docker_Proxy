import os
import sys
import tempfile

import pytest


def _import_app():
    try:
        import flask  # noqa: F401
    except Exception as e:
        pytest.skip(f"Flask not available in this environment: {e}")

    # Ensure we import the real Flask app from web/app.py.
    web_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if web_dir not in sys.path:
        sys.path.insert(0, web_dir)

    # Avoid starting background tailers/samplers during unit tests.
    os.environ.setdefault("DISABLE_BACKGROUND", "1")

    # Isolate auth state so tests are deterministic.
    os.environ.setdefault("AUTH_DB", os.path.join(tempfile.mkdtemp(prefix="sfp_auth_"), "auth.db"))
    os.environ.setdefault(
        "FLASK_SECRET_PATH",
        os.path.join(tempfile.mkdtemp(prefix="sfp_secret_"), "flask_secret.key"),
    )

    from app import app as flask_app  # type: ignore

    flask_app.testing = True
    return flask_app


def _get_csrf_token(client) -> str:
    client.get("/login")
    with client.session_transaction() as sess:
        return sess.get("_csrf_token", "") or ""


def test_security_headers_present_on_html():
    app = _import_app()
    c = app.test_client()

    csrf = _get_csrf_token(c)
    c.post("/login", data={"username": "admin", "password": "admin", "next": "", "csrf_token": csrf})

    r = c.get("/")
    assert r.status_code == 200

    # Baseline hardening headers.
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("X-Frame-Options") == "SAMEORIGIN"
    assert r.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "Permissions-Policy" in r.headers

    # CSP is only set for HTML.
    csp = r.headers.get("Content-Security-Policy", "")
    assert "default-src" in csp


def test_health_is_public_without_login():
    app = _import_app()
    c = app.test_client()

    r = c.get("/health")
    assert r.status_code == 200
    assert r.is_json
    assert r.get_json() == {"ok": True}


def test_login_blocks_open_redirect_external_url():
    app = _import_app()
    c = app.test_client()

    csrf = _get_csrf_token(c)
    r = c.post(
        "/login",
        data={
            "username": "admin",
            "password": "admin",
            "next": "https://evil.example/phish",
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )

    assert r.status_code in (301, 302, 303, 307, 308)
    loc = r.headers.get("Location", "")
    assert "evil.example" not in loc
    # Invalid next should fall back to app index.
    assert loc.endswith("/")


def test_login_blocks_open_redirect_scheme_relative_url():
    app = _import_app()
    c = app.test_client()

    csrf = _get_csrf_token(c)
    r = c.post(
        "/login",
        data={"username": "admin", "password": "admin", "next": "//evil.example/phish", "csrf_token": csrf},
        follow_redirects=False,
    )

    assert r.status_code in (301, 302, 303, 307, 308)
    loc = r.headers.get("Location", "")
    assert "evil.example" not in loc
    assert loc.endswith("/")


def test_login_blocks_open_redirect_non_absolute_path():
    app = _import_app()
    c = app.test_client()

    csrf = _get_csrf_token(c)
    r = c.post(
        "/login",
        data={"username": "admin", "password": "admin", "next": "squid/config", "csrf_token": csrf},
        follow_redirects=False,
    )

    assert r.status_code in (301, 302, 303, 307, 308)
    assert r.headers.get("Location", "").endswith("/")


def test_login_allows_local_relative_next_path():
    app = _import_app()
    c = app.test_client()

    csrf = _get_csrf_token(c)
    r = c.post(
        "/login",
        data={
            "username": "admin",
            "password": "admin",
            "next": "/squid/config",
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)
    assert r.headers.get("Location", "").endswith("/squid/config")


def test_login_sets_session_cookie_flags():
    app = _import_app()
    c = app.test_client()

    csrf = _get_csrf_token(c)
    r = c.post(
        "/login",
        data={"username": "admin", "password": "admin", "next": "", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)

    # Flask should set a session cookie with hardening flags.
    set_cookie = r.headers.get("Set-Cookie", "")
    assert set_cookie
    assert "HttpOnly" in set_cookie
    # Default configured in app.py.
    assert "SameSite=Lax" in set_cookie


def test_protected_get_redirects_to_login_when_unauthenticated():
    app = _import_app()
    c = app.test_client()

    r = c.get("/", follow_redirects=False)
    assert r.status_code in (301, 302, 303, 307, 308)
    assert (r.headers.get("Location", "") or "").startswith("/login")


def test_pac_endpoints_are_public_without_login():
    app = _import_app()
    c = app.test_client()

    r = c.get("/proxy.pac")
    assert r.status_code == 200
    # PAC should not be treated as HTML and should not receive an HTML CSP.
    assert "Content-Security-Policy" not in r.headers


def test_csrf_required_for_protected_post_even_when_logged_in(monkeypatch):
    monkeypatch.delenv("DISABLE_CSRF", raising=False)

    app = _import_app()
    c = app.test_client()

    csrf = _get_csrf_token(c)
    c.post("/login", data={"username": "admin", "password": "admin", "next": "", "csrf_token": csrf})

    # Missing csrf_token should be rejected by the global CSRF guard.
    r = c.post("/administration", data={"action": "add_user", "username": "u2", "password": "1234"})
    assert r.status_code == 403


def test_csrf_header_is_accepted(monkeypatch):
    monkeypatch.delenv("DISABLE_CSRF", raising=False)

    app = _import_app()
    c = app.test_client()

    csrf = _get_csrf_token(c)
    r = c.post("/logout", headers={"X-CSRF-Token": csrf}, data={}, follow_redirects=False)
    assert r.status_code in (301, 302, 303, 307, 308)


def test_all_post_routes_require_csrf_by_default(monkeypatch):
    """Regression test: any new POST route must be CSRF-protected.

    This intentionally does NOT log in and sends no CSRF token, so the global CSRF
    guard should short-circuit with 403 before handlers run (avoids side effects).
    """

    monkeypatch.delenv("DISABLE_CSRF", raising=False)

    app = _import_app()
    c = app.test_client()

    post_rules = []
    for rule in app.url_map.iter_rules():
        if "POST" not in (rule.methods or set()):
            continue
        if rule.endpoint == "static":
            continue
        # Skip variable routes (e.g. /foo/<id>) because posting to the literal string
        # won't match the route and would produce 404 instead of exercising CSRF.
        if "<" in rule.rule:
            continue
        post_rules.append(rule.rule)

    assert post_rules, "Expected at least one POST route to exist"

    for path in sorted(set(post_rules)):
        r = c.post(path, data={}, follow_redirects=False)
        assert r.status_code == 403, f"POST {path} did not enforce CSRF (got {r.status_code})"


def test_all_get_routes_require_login_except_public():
    """Regression test: any new GET route should be behind login unless intended public."""

    app = _import_app()
    c = app.test_client()

    public_paths = {"/health", "/proxy.pac", "/wpad.dat", "/login"}

    get_rules = []
    for rule in app.url_map.iter_rules():
        if "GET" not in (rule.methods or set()):
            continue
        if rule.endpoint == "static":
            continue
        # Skip variable routes (e.g. /certs/download/<path:filename>)
        if "<" in rule.rule:
            continue
        get_rules.append(rule.rule)

    assert get_rules, "Expected at least one GET route to exist"

    for path in sorted(set(get_rules)):
        r = c.get(path, follow_redirects=False)

        if path in public_paths:
            assert r.status_code == 200, f"GET {path} expected public 200 (got {r.status_code})"
            continue

        # Protected routes should redirect to login.
        assert r.status_code in (301, 302, 303, 307, 308), f"GET {path} expected redirect (got {r.status_code})"
        loc = r.headers.get("Location", "") or ""
        assert loc.startswith("/login"), f"GET {path} redirected somewhere else: {loc!r}"


def test_csrf_required_for_post_when_enabled(monkeypatch):
    monkeypatch.delenv("DISABLE_CSRF", raising=False)

    app = _import_app()
    c = app.test_client()

    # Establish a session but do not send any CSRF token.
    c.get("/login")

    r = c.post("/logout", data={}, follow_redirects=False)
    assert r.status_code == 403


def test_csrf_required_for_login_post(monkeypatch):
    monkeypatch.delenv("DISABLE_CSRF", raising=False)

    app = _import_app()
    c = app.test_client()
    # No prior GET to establish a CSRF token, and no csrf_token provided.
    r = c.post("/login", data={"username": "admin", "password": "admin", "next": ""}, follow_redirects=False)
    assert r.status_code == 403


def test_csrf_can_be_disabled_for_debug(monkeypatch):
    monkeypatch.setenv("DISABLE_CSRF", "1")

    app = _import_app()
    c = app.test_client()

    c.get("/login")

    r = c.post("/logout", data={}, follow_redirects=False)
    # With CSRF disabled, logout should be allowed and redirect to login.
    assert r.status_code in (301, 302, 303, 307, 308)
    assert "/login" in (r.headers.get("Location", "") or "")


def test_auth_store_connect_uses_safe_sqlite_options(tmp_path, monkeypatch):
    # Import module from web/ directory.
    web_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if web_dir not in sys.path:
        sys.path.insert(0, web_dir)

    from services import auth_store  # type: ignore

    captured = {"args": None, "kwargs": None, "pragmas": []}

    class FakeConn:
        def execute(self, sql: str, *params):
            captured["pragmas"].append(sql.strip())
            return None

    def fake_connect(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return FakeConn()

    monkeypatch.setattr(auth_store.sqlite3, "connect", fake_connect)

    store = auth_store.AuthStore(db_path=str(tmp_path / "auth.db"), secret_path=str(tmp_path / "secret.key"))
    _ = store._connect()

    assert captured["kwargs"] is not None
    assert captured["kwargs"].get("timeout") == 30
    assert captured["kwargs"].get("check_same_thread") is False

    # Ensure we set WAL + busy timeout to reduce lock errors.
    pragmas = "\n".join(captured["pragmas"])
    assert "journal_mode=WAL" in pragmas
    assert "busy_timeout=30000" in pragmas


def test_auth_store_username_and_password_validation(tmp_path):
    web_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if web_dir not in sys.path:
        sys.path.insert(0, web_dir)

    from services.auth_store import AuthStore  # type: ignore

    store = AuthStore(db_path=str(tmp_path / "auth.db"), secret_path=str(tmp_path / "secret.key"))

    with pytest.raises(ValueError):
        store.add_user("", "pass")

    with pytest.raises(ValueError):
        store.add_user("has space", "pass")

    with pytest.raises(ValueError):
        store.add_user("bad@name", "pass")

    with pytest.raises(ValueError):
        store.add_user("x" * 65, "pass")

    with pytest.raises(ValueError):
        store.add_user("ok", "")

    with pytest.raises(ValueError):
        store.add_user("ok", "123")

    # Accepts reasonable usernames.
    store.add_user("user_1", "1234")
    assert store.verify_user("user_1", "1234") is True
    assert store.verify_user("user_1", "nope") is False
