import importlib
import os
import sys
from urllib.parse import parse_qs, urlsplit

import pytest


def _import_app_isolated(tmp_path):
    try:
        import flask  # noqa: F401
    except Exception as e:
        pytest.skip(f"Flask not available in this environment: {e}")

    web_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if web_dir not in sys.path:
        sys.path.insert(0, web_dir)

    os.environ["DISABLE_BACKGROUND"] = "1"
    os.environ["AUTH_DB"] = str(tmp_path / "auth.db")
    os.environ["FLASK_SECRET_PATH"] = str(tmp_path / "flask_secret.key")

    if "app" in sys.modules:
        del sys.modules["app"]

    import app as app_module  # type: ignore

    importlib.reload(app_module)
    app_module.app.testing = True
    return app_module


def _get_csrf_token(client) -> str:
    client.get("/login")
    with client.session_transaction() as sess:
        return sess.get("_csrf_token", "") or ""


def _login(client, username: str, password: str) -> str:
    csrf = _get_csrf_token(client)
    r = client.post(
        "/login",
        data={"username": username, "password": password, "next": "", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)
    return csrf


def _qs(resp) -> dict[str, list[str]]:
    loc = resp.headers.get("Location", "") or ""
    return parse_qs(urlsplit(loc).query)


def test_add_user_then_login_as_new_user(tmp_path):
    app_module = _import_app_isolated(tmp_path)

    c = app_module.app.test_client()
    csrf = _login(c, "admin", "admin")

    r = c.post(
        "/administration",
        data={"action": "add_user", "username": "alice", "password": "pw12", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)
    assert _qs(r).get("ok") == ["1"]

    # New session -> login as alice should work.
    c2 = app_module.app.test_client()
    _ = _login(c2, "alice", "pw12")
    r2 = c2.get("/administration")
    assert r2.status_code == 200


def test_set_password_changes_login_behavior(tmp_path):
    app_module = _import_app_isolated(tmp_path)

    c = app_module.app.test_client()
    csrf = _login(c, "admin", "admin")

    # Create a user first.
    c.post(
        "/administration",
        data={"action": "add_user", "username": "bob", "password": "old1", "csrf_token": csrf},
        follow_redirects=False,
    )

    # Change password.
    r = c.post(
        "/administration",
        data={"action": "set_password", "username": "bob", "new_password": "new1", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)
    assert _qs(r).get("ok") == ["1"]

    # Old password should fail (renders login page 200 with error).
    c_old = app_module.app.test_client()
    csrf_old = _get_csrf_token(c_old)
    r_old = c_old.post(
        "/login",
        data={"username": "bob", "password": "old1", "next": "", "csrf_token": csrf_old},
        follow_redirects=False,
    )
    assert r_old.status_code == 200

    # New password should succeed (redirect).
    c_new = app_module.app.test_client()
    _ = _login(c_new, "bob", "new1")


def test_cannot_delete_last_user(tmp_path):
    app_module = _import_app_isolated(tmp_path)

    c = app_module.app.test_client()
    csrf = _login(c, "admin", "admin")

    # In a fresh auth DB there should be exactly one user (admin).
    r = c.post(
        "/administration",
        data={"action": "delete_user", "username": "admin", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)

    # Should not allow removing current user; and should also avoid removing last user.
    qs = _qs(r)
    assert qs.get("ok") == ["0"]
