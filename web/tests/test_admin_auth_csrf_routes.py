from __future__ import annotations

from datetime import timedelta

import pytest

from .admin_route_test_utils import (
    FakeAuditStore,
    csrf_token,
    load_admin_app,
    login_client,
)


class UnavailableSamlAuthStore:
    def get_profile(self):
        msg = "saml profile database password=secret"
        raise RuntimeError(msg)

    def default_profile(self):
        from services.saml_auth import SamlAuthStore

        return SamlAuthStore().default_profile()


@pytest.mark.parametrize(
    ("base_url", "effective_https", "expect_secure"),
    [
        ("http://admin.example.test", None, False),
        ("https://admin.example.test", None, True),
        ("http://admin.example.test", "1", True),
        ("http://admin.example.test", "0", False),
    ],
)
def test_session_cookie_secure_matches_effective_admin_ui_scheme(
    monkeypatch,
    tmp_path,
    base_url: str,
    effective_https: str | None,
    expect_secure: bool,
) -> None:
    monkeypatch.delenv("SESSION_COOKIE_SECURE", raising=False)
    if effective_https is None:
        monkeypatch.delenv("ADMIN_UI_EFFECTIVE_HTTPS_ENABLED", raising=False)
    else:
        monkeypatch.setenv("ADMIN_UI_EFFECTIVE_HTTPS_ENABLED", effective_https)

    loaded = load_admin_app(monkeypatch, tmp_path)
    response = loaded.module.app.test_client().get("/login", base_url=base_url)
    cookie = response.headers.get("Set-Cookie", "")

    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie
    assert ("; Secure" in cookie) is expect_secure


def test_session_cookie_secure_env_remains_explicit_http_override(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "1")
    monkeypatch.setenv("ADMIN_UI_EFFECTIVE_HTTPS_ENABLED", "0")

    loaded = load_admin_app(monkeypatch, tmp_path)
    response = loaded.module.app.test_client().get(
        "/login", base_url="http://admin.example.test"
    )

    assert "; Secure" in response.headers.get("Set-Cookie", "")


def test_login_requires_csrf_and_accepts_form_or_header_token(
    monkeypatch, tmp_path
) -> None:
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


def test_login_clears_session_fixation_data_but_preserves_csrf(
    monkeypatch, tmp_path
) -> None:
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


def test_login_degrades_to_local_auth_when_saml_profile_store_is_unavailable(
    monkeypatch, tmp_path
) -> None:
    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        saml_auth_store=UnavailableSamlAuthStore(),
    )
    client = loaded.module.app.test_client()

    page = client.get("/login")
    body = page.get_data(as_text=True)

    assert page.status_code == 200
    assert "Sign in with SAML" not in body
    assert "secret" not in body

    token = csrf_token(client, "/login")
    login_response = client.post(
        "/login",
        data={"username": "admin", "password": "admin", "csrf_token": token},
        follow_redirects=False,
    )

    assert login_response.status_code in {302, 303}
    with client.session_transaction() as sess:
        assert sess.get("user") == "admin"


def test_saml_routes_degrade_when_profile_store_is_unavailable(
    monkeypatch, tmp_path
) -> None:
    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        saml_auth_store=UnavailableSamlAuthStore(),
    )
    client = loaded.module.app.test_client()

    metadata = client.get("/auth/saml/metadata", base_url="https://admin.example.test")
    metadata_body = metadata.get_data(as_text=True)
    assert metadata.status_code == 200
    assert metadata.mimetype == "application/samlmetadata+xml"
    assert "secret" not in metadata_body
    assert 'entityID="https://admin.example.test/auth/saml/metadata"' in metadata_body

    login = client.get("/auth/saml/login?next=/administration", follow_redirects=False)
    assert login.status_code in {302, 303}
    assert login.headers["Location"].startswith(
        "/login?next=/administration&error=saml_unavailable"
    )

    acs = client.post(
        "/auth/saml/acs",
        data={"RelayState": "/administration"},
        follow_redirects=False,
    )
    assert acs.status_code in {302, 303}
    assert acs.headers["Location"].startswith("/login?next=/administration")


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

    assert [record["kind"] for record in audit.records] == [
        "login_failed",
        "login_success",
    ]
    assert audit.records[0]["ok"] is False
    assert audit.records[1]["ok"] is True


def test_login_audit_details_are_single_line_and_redacted(
    monkeypatch, tmp_path
) -> None:
    audit = FakeAuditStore()
    loaded = load_admin_app(monkeypatch, tmp_path, audit_store=audit)
    client = loaded.module.app.test_client()
    token = csrf_token(client, "/login")

    response = client.post(
        "/login",
        data={
            "username": "attacker\npassword=supersecret",
            "password": "wrong",
            "csrf_token": token,
        },
    )

    assert response.status_code == 200
    detail = audit.records[-1]["detail"]
    assert "\n" not in detail
    assert "supersecret" not in detail
    assert "password=[redacted]" in detail


def test_audit_store_failure_does_not_break_login(monkeypatch, tmp_path) -> None:
    loaded = load_admin_app(
        monkeypatch, tmp_path, audit_store=FakeAuditStore(fail=True)
    )
    client = loaded.module.app.test_client()
    response = login_client(client)
    assert response.status_code in {302, 303}


def test_recover_route_is_available_before_login_and_clears_proxy_selection(
    monkeypatch, tmp_path
) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    with client.session_transaction() as sess:
        sess["active_proxy_id"] = "stale-proxy"

    response = client.get("/recover", follow_redirects=False)

    assert response.status_code in {302, 303}
    assert response.headers["Location"].startswith("/?recovered=1")
    with client.session_transaction() as sess:
        assert "active_proxy_id" not in sess
        assert "user" not in sess


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
        ("/\\evil", ""),
        ("/safe\\..\\login", ""),
        ("/%2fevil.example/path", ""),
        ("/%2F%2Fevil.example/path", ""),
        ("/%5cevil.example/path", ""),
        ("/safe%5c..%5clogin", ""),
        ("/squid%2fconfig", ""),
        ("/squid/config%0d%0aLocation:%20//evil.example", ""),
        ("/squid/config%00", ""),
        ("/%252fevil.example/path", ""),
        ("/%2525252fevil.example/path", ""),
    ],
)
def test_safe_next_url_edge_cases(
    monkeypatch, tmp_path, candidate: str, expected: str
) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    assert loaded.module._safe_next_url(candidate) == expected


def test_safe_next_url_delegates_to_shared_local_return_sanitizer(
    monkeypatch, tmp_path
) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    calls: list[str | None] = []

    def fake_safe_local_return_url(value: str | None) -> str | None:
        calls.append(value)
        return "/shared?ok=1" if value == "/admin" else None

    monkeypatch.setattr(
        loaded.module,
        "_safe_local_return_url",
        fake_safe_local_return_url,
    )

    assert loaded.module._safe_next_url("/admin") == "/shared?ok=1"
    assert loaded.module._safe_next_url("https://evil.example/phish") == ""
    assert calls == ["/admin", "https://evil.example/phish"]


@pytest.mark.parametrize("value", ["0", "-1"])
def test_max_content_length_configuration_defaults_on_nonpositive_values(
    monkeypatch, tmp_path, value: str
) -> None:
    monkeypatch.setenv("MAX_CONTENT_LENGTH", value)
    loaded = load_admin_app(monkeypatch, tmp_path)
    assert loaded.module.app.config["MAX_CONTENT_LENGTH"] == 16 * 1024 * 1024


@pytest.mark.parametrize("value", ["", "not-an-int"])
def test_max_content_length_configuration_defaults_on_blank_or_malformed_values(
    monkeypatch, tmp_path, value: str
) -> None:
    monkeypatch.setenv("MAX_CONTENT_LENGTH", value)
    loaded = load_admin_app(monkeypatch, tmp_path)
    assert loaded.module.app.config["MAX_CONTENT_LENGTH"] == 16 * 1024 * 1024


def test_max_content_length_configuration_accepts_positive_values(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setenv("MAX_CONTENT_LENGTH", "1024")
    loaded = load_admin_app(monkeypatch, tmp_path)
    assert loaded.module.app.config["MAX_CONTENT_LENGTH"] == 1024


@pytest.mark.parametrize("value", ["TRUE", "Yes", "ON", "1"])
def test_session_cookie_secure_configuration_accepts_case_insensitive_truthy_values(
    monkeypatch, tmp_path, value: str
) -> None:
    monkeypatch.setenv("SESSION_COOKIE_SECURE", value)
    loaded = load_admin_app(monkeypatch, tmp_path)
    assert loaded.module.app.config["SESSION_COOKIE_SECURE"] is True


def test_session_timeout_configuration_is_bounded_to_at_least_one_hour(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setenv("SESSION_TIMEOUT_HOURS", "0")
    loaded = load_admin_app(monkeypatch, tmp_path)
    assert loaded.module.app.config["PERMANENT_SESSION_LIFETIME"] == timedelta(hours=1)


@pytest.mark.parametrize("value", ["", "not-an-int"])
def test_session_timeout_configuration_defaults_on_blank_or_malformed_values(
    monkeypatch, tmp_path, value: str
) -> None:
    monkeypatch.setenv("SESSION_TIMEOUT_HOURS", value)
    loaded = load_admin_app(monkeypatch, tmp_path)
    assert loaded.module.app.config["PERMANENT_SESSION_LIFETIME"] == timedelta(hours=8)


def test_session_timeout_configuration_caps_oversized_values(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setenv("SESSION_TIMEOUT_HOURS", "100000000000000000000000000000000")
    loaded = load_admin_app(monkeypatch, tmp_path)
    assert loaded.module.app.config["PERMANENT_SESSION_LIFETIME"] == timedelta(days=30)


def test_csrf_wrong_header_with_correct_form_field_is_rejected(
    monkeypatch, tmp_path
) -> None:
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
