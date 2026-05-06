from __future__ import annotations

from datetime import timedelta

import pytest

from .admin_route_test_utils import FakeAuditStore, csrf_token, load_admin_app, login_client


def test_login_requires_csrf_and_accepts_form_or_header_token(monkeypatch, tmp_path) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()

    missing = client.post("/login", data={"username": "admin", "password": "admin"})
    assert missing.status_code == 403

    token = csrf_token(client, "/login")
    form_response = client.post(
        "/login",
        data={"username": "admin", "password": "admin", "csrf_token": token},
        follow_redirects=False,
    )
    assert form_response.status_code in {302, 303}

    header_client = loaded.module.app.test_client()
    header_token = csrf_token(header_client, "/login")
    header_response = header_client.post(
        "/login",
        data={"username": "admin", "password": "admin"},
        headers={"X-CSRF-Token": header_token},
        follow_redirects=False,
    )
    assert header_response.status_code in {302, 303}


def test_login_clears_session_fixation_data_but_preserves_csrf(monkeypatch, tmp_path) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    token = csrf_token(client, "/login")

    with client.session_transaction() as sess:
        sess["pre_auth_marker"] = "attacker-controlled"
        sess["_csrf_token"] = token

    response = client.post(
        "/login",
        data={"username": "admin", "password": "admin", "csrf_token": token},
        follow_redirects=False,
    )
    assert response.status_code in {302, 303}
    with client.session_transaction() as sess:
        assert sess.get("user") == "admin"
        assert sess.get("_csrf_token") == token
        assert "pre_auth_marker" not in sess
        assert sess.permanent is True


def test_login_records_success_and_failure_audit_events(monkeypatch, tmp_path) -> None:
    audit = FakeAuditStore()
    loaded = load_admin_app(monkeypatch, tmp_path, audit_store=audit)

    failed_client = loaded.module.app.test_client()
    failed_token = csrf_token(failed_client, "/login")
    failed = failed_client.post(
        "/login",
        data={"username": "admin", "password": "wrong", "csrf_token": failed_token},
    )
    assert failed.status_code == 200
    assert "Invalid username or password" in failed.get_data(as_text=True)

    success_client = loaded.module.app.test_client()
    login_client(success_client)

    assert [record["kind"] for record in audit.records] == ["login_failed", "login_success"]
    assert audit.records[0]["ok"] is False
    assert audit.records[1]["ok"] is True


def test_audit_store_failure_does_not_break_login(monkeypatch, tmp_path) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path, audit_store=FakeAuditStore(fail=True))
    client = loaded.module.app.test_client()
    response = login_client(client)
    assert response.status_code in {302, 303}


def test_logout_requires_csrf_and_clears_session(monkeypatch, tmp_path) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    login_client(client)

    missing = client.post("/logout", follow_redirects=False)
    assert missing.status_code == 403

    token = csrf_token(client, "/")
    ok = client.post("/logout", data={"csrf_token": token}, follow_redirects=False)
    assert ok.status_code in {302, 303}
    with client.session_transaction() as sess:
        assert "user" not in sess


@pytest.mark.parametrize(
    ("candidate", "expected"),
    [
        ("", ""),
        ("   ", ""),
        ("/", "/"),
        ("/squid/config?tab=ssl", "/squid/config?tab=ssl"),
        ("squid/config", ""),
        ("./squid/config", ""),
        ("#fragment", ""),
        ("//evil.example/path", ""),
        ("https://evil.example/path", ""),
        ("http://evil.example/path", ""),
        ("/\\evil", "/\\evil"),
    ],
)
def test_safe_next_url_edge_cases(monkeypatch, tmp_path, candidate: str, expected: str) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    assert loaded.module._safe_next_url(candidate) == expected


def test_session_timeout_configuration_is_bounded_to_at_least_one_hour(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("SESSION_TIMEOUT_HOURS", "0")
    loaded = load_admin_app(monkeypatch, tmp_path)
    assert loaded.module.app.config["PERMANENT_SESSION_LIFETIME"] == timedelta(hours=1)


def test_csrf_wrong_header_with_correct_form_field_is_rejected(monkeypatch, tmp_path) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/")

    response = client.post(
        "/reload",
        data={"csrf_token": token},
        headers={"X-CSRF-Token": "wrong-token"},
        follow_redirects=False,
    )

    assert response.status_code == 403


def test_csrf_can_be_disabled_explicitly_for_test_mode(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("DISABLE_CSRF", "1")
    loaded = load_admin_app(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    with client.session_transaction() as sess:
        sess["user"] = "admin"

    response = client.post("/reload", follow_redirects=False)
    assert response.status_code in {302, 303}
