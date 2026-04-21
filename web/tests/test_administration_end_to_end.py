from .flask_test_helpers import get_csrf_token, import_isolated_app_module, login, redirect_query_params


def test_add_user_then_login_as_new_user(tmp_path):
    app_module = import_isolated_app_module(tmp_path)

    c = app_module.app.test_client()
    csrf = login(c, "admin", "admin")

    r = c.post(
        "/administration",
        data={"action": "add_user", "username": "alice", "password": "pw12", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)
    assert redirect_query_params(r).get("ok") == ["1"]

    # New session -> login as alice should work.
    c2 = app_module.app.test_client()
    _ = login(c2, "alice", "pw12")
    r2 = c2.get("/administration")
    assert r2.status_code == 200


def test_set_password_changes_login_behavior(tmp_path):
    app_module = import_isolated_app_module(tmp_path)

    c = app_module.app.test_client()
    csrf = login(c, "admin", "admin")

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
    assert redirect_query_params(r).get("ok") == ["1"]

    # Old password should fail (renders login page 200 with error).
    c_old = app_module.app.test_client()
    csrf_old = get_csrf_token(c_old)
    r_old = c_old.post(
        "/login",
        data={"username": "bob", "password": "old1", "next": "", "csrf_token": csrf_old},
        follow_redirects=False,
    )
    assert r_old.status_code == 200

    # New password should succeed (redirect).
    c_new = app_module.app.test_client()
    _ = login(c_new, "bob", "new1")


def test_cannot_delete_last_user(tmp_path):
    app_module = import_isolated_app_module(tmp_path)

    c = app_module.app.test_client()
    csrf = login(c, "admin", "admin")

    # In a fresh auth DB there should be exactly one user (admin).
    r = c.post(
        "/administration",
        data={"action": "delete_user", "username": "admin", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)

    # Should not allow removing current user; and should also avoid removing last user.
    qs = redirect_query_params(r)
    assert qs.get("ok") == ["0"]
