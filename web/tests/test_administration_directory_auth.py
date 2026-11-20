from __future__ import annotations

import io
from dataclasses import replace
from types import SimpleNamespace

import pytest
from werkzeug.datastructures import MultiDict

from .admin_route_test_utils import (
    FakeAuditStore,
    csrf_token,
    load_admin_app,
    login_client,
)


class FakeDirectoryAuthStore:
    def __init__(self) -> None:
        self.saved = []
        self.disabled = []
        self.tested = []
        self.login_ok = False
        self.login_provider = "local"
        self.login_detail = "No active directory provider."
        self.profile_enabled = {"ldap": False, "active_directory": False}
        self.profile_last_test_ok = {"ldap": False, "active_directory": False}

    def ensure_default_profiles(self) -> None:
        return None

    def authenticate_admin(self, username: str, password: str):
        if self.login_ok and username == "ldap-user" and password == "ldap-pass":
            return SimpleNamespace(
                ok=True,
                provider="ldap",
                username=username,
                detail="Directory authentication succeeded.",
                groups=("cn=admins,dc=example,dc=org",),
            )
        return SimpleNamespace(
            ok=False,
            provider=self.login_provider,
            username=username,
            detail=self.login_detail,
        )

    def get_status(self):
        ldap_enabled = self.profile_enabled["ldap"] or self.login_ok
        ldap = SimpleNamespace(
            provider="ldap",
            label="LDAP",
            enabled=ldap_enabled,
            server_urls="ldaps://ldap.example.org:636",
            use_starttls=False,
            verify_tls=True,
            ca_bundle="",
            bind_dn="cn=bind,dc=example,dc=org",
            has_bind_password=True,
            base_dn="dc=example,dc=org",
            user_search_base="ou=people",
            user_filter="(uid={username})",
            user_attribute="uid",
            group_search_base="ou=groups",
            group_filter="(member={user_dn})",
            required_admin_group="cn=admins,dc=example,dc=org",
            timeout_seconds=5,
            last_test_ok=self.profile_last_test_ok["ldap"],
            last_test_ts=0,
            last_test_detail=(
                "Configuration changed since the last successful test."
                if self.login_ok
                else ""
            ),
        )
        ad = SimpleNamespace(
            provider="active_directory",
            label="Active Directory",
            enabled=self.profile_enabled["active_directory"],
            server_urls="ldaps://dc.example.local:636",
            use_starttls=False,
            verify_tls=True,
            ca_bundle="",
            bind_dn="svc@example.local",
            has_bind_password=False,
            base_dn="DC=example,DC=local",
            user_search_base="",
            user_filter="(sAMAccountName={username})",
            user_attribute="sAMAccountName",
            group_search_base="",
            group_filter="(member={user_dn})",
            required_admin_group="CN=Admins,DC=example,DC=local",
            timeout_seconds=5,
            last_test_ok=self.profile_last_test_ok["active_directory"],
            last_test_ts=0,
            last_test_detail="",
        )
        return {
            "active_provider": "ldap" if ldap_enabled else "local",
            "active_label": "LDAP" if ldap_enabled else "Local accounts",
            "profiles": {"ldap": ldap, "active_directory": ad},
            "providers": ("ldap", "active_directory"),
            "provider_labels": {"ldap": "LDAP", "active_directory": "Active Directory"},
            "presets": {
                "ldap": {
                    "user_attribute": (("uid", "OpenLDAP uid"),),
                    "user_filter": (("(uid={username})", "OpenLDAP uid"),),
                    "group_filter": (("(member={user_dn})", "groupOfNames"),),
                },
                "active_directory": {
                    "user_attribute": (("sAMAccountName", "Windows logon name"),),
                    "user_filter": (
                        ("(sAMAccountName={username})", "Windows logon name"),
                    ),
                    "group_filter": (("(member={user_dn})", "Direct AD group member"),),
                },
            },
        }

    def get_profile(self, provider):
        return self.get_status()["profiles"][provider]

    def save_profile(self, provider, payload):
        self.saved.append((provider, dict(payload)))
        self.profile_enabled[provider] = str(payload.get("enabled") or "") in {
            "1",
            "true",
            "yes",
            "on",
        }
        return self.get_status()["profiles"][provider]

    def test_connection(self, provider):
        self.tested.append(provider)
        self.profile_last_test_ok[provider] = True
        return SimpleNamespace(
            ok=True,
            provider=provider,
            detail="Directory bind and base search succeeded.",
        )

    def disable_provider(self, provider):
        self.disabled.append(provider)

    def restore_profile(self, profile):
        self.profile_enabled[profile.provider] = profile.enabled
        self.profile_last_test_ok[profile.provider] = profile.last_test_ok

    def scan_directory(self, provider):
        return SimpleNamespace(
            provider=provider,
            base_dns=("dc=example,dc=org",),
            user_search_bases=("ou=people",),
            group_search_bases=("ou=groups",),
            admin_groups=("cn=admins,ou=groups,dc=example,dc=org",),
            detail="Directory scan found 1 OU/container choices and 1 group choices.",
        )


def test_administration_exposes_directory_tabs(monkeypatch, tmp_path) -> None:
    directory_store = FakeDirectoryAuthStore()
    loaded = load_admin_app(monkeypatch, tmp_path, directory_auth_store=directory_store)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/administration?tab=ldap")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "Authentication status" not in body
    assert "LDAP provider" in body
    assert "fresh successful connection test" in body
    assert "CA certificate upload" in body
    assert "Login matching" in body
    assert "Active Directory" in client.get("/administration?tab=status").get_data(
        as_text=True
    )


def test_administration_query_message_is_redacted(monkeypatch, tmp_path) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    login_client(client)

    body = client.get(
        "/administration?ok=0&msg=password=supersecret",
        follow_redirects=True,
    ).get_data(as_text=True)

    assert "password=[redacted]" in body
    assert "supersecret" not in body


def test_administration_user_post_is_audited_without_password(
    monkeypatch, tmp_path
) -> None:
    audit = FakeAuditStore()
    loaded = load_admin_app(monkeypatch, tmp_path, audit_store=audit)
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/administration")

    response = client.post(
        "/administration",
        data={
            "csrf_token": token,
            "action": "add_user",
            "username": "operator",
            "password": "secret-password",
        },
    )

    assert response.status_code in {302, 303}
    record = audit.records[-1]
    assert record["kind"] == "administration_user_action"
    assert record["ok"] is True
    assert "username=operator" in record["detail"]
    assert "secret-password" not in record["detail"]


def test_administration_local_password_policy_is_operator_clear(
    monkeypatch, tmp_path
) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    login_client(client)

    body = client.get("/administration?tab=status").get_data(as_text=True)
    assert "Local passwords must be 12-1024 characters." in body
    assert 'name="password" type="password" minlength="12" maxlength="1024"' in body
    assert 'name="new_password" type="password" minlength="12" maxlength="1024"' in body

    token = csrf_token(client, "/administration")
    response = client.post(
        "/administration",
        data={
            "csrf_token": token,
            "action": "add_user",
            "username": "operator",
            "password": "short",
        },
        follow_redirects=True,
    )
    assert "Password must be between 12 and 1024 characters." in response.get_data(
        as_text=True
    )


def test_directory_secret_provider_prefers_flask_secret_key(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setenv("FLASK_SECRET_KEY", "configured-flask-secret")
    loaded = load_admin_app(monkeypatch, tmp_path)

    assert loaded.module.app.secret_key == "configured-flask-secret"
    assert loaded.module._directory_secret_key() == "configured-flask-secret"


def test_administration_surfaces_retest_required_after_directory_config_change(
    monkeypatch, tmp_path
) -> None:
    directory_store = FakeDirectoryAuthStore()
    directory_store.login_ok = True
    loaded = load_admin_app(monkeypatch, tmp_path, directory_auth_store=directory_store)
    client = loaded.module.app.test_client()
    login_client(client)

    body = client.get("/administration?tab=ldap").get_data(as_text=True)

    assert "Retest required" in body
    assert "Configuration changed since the last successful test." in body


def test_login_accepts_active_directory_provider(monkeypatch, tmp_path) -> None:
    directory_store = FakeDirectoryAuthStore()
    directory_store.login_ok = True
    loaded = load_admin_app(monkeypatch, tmp_path, directory_auth_store=directory_store)
    client = loaded.module.app.test_client()
    token = csrf_token(client, "/login")

    response = client.post(
        "/login",
        data={"username": "ldap-user", "password": "ldap-pass", "csrf_token": token},
    )

    assert response.status_code in {302, 303}
    with client.session_transaction() as sess:
        assert sess["user"] == "ldap-user"
        assert sess["auth_provider"] == "ldap"


def test_login_records_directory_failure_diagnostic_detail(
    monkeypatch, tmp_path
) -> None:
    audit = FakeAuditStore()
    directory_store = FakeDirectoryAuthStore()
    directory_store.login_provider = "ldap"
    directory_store.login_detail = "User is not in the required admin group.\n"
    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        audit_store=audit,
        directory_auth_store=directory_store,
    )
    client = loaded.module.app.test_client()
    token = csrf_token(client, "/login")

    response = client.post(
        "/login",
        data={"username": "ldap-user", "password": "wrong", "csrf_token": token},
    )

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "Invalid username or password" in body
    assert "required admin group" not in body
    assert audit.records[-1]["kind"] == "login_failed"
    assert audit.records[-1]["detail"] == (
        "user=ldap-user provider=ldap "
        "directory_detail=User is not in the required admin group."
    )


def test_auth_provider_save_is_scoped_to_one_provider(monkeypatch, tmp_path) -> None:
    directory_store = FakeDirectoryAuthStore()
    loaded = load_admin_app(monkeypatch, tmp_path, directory_auth_store=directory_store)
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/administration?tab=ldap")

    response = client.post(
        "/administration?tab=ldap",
        data={
            "csrf_token": token,
            "action": "save_auth_provider",
            "provider": "ldap",
            "enabled": "1",
            "server_urls": "ldaps://ldap.example.org:636",
            "bind_dn": "cn=bind,dc=example,dc=org",
            "bind_password": "secret",
            "base_dn": "dc=example,dc=org",
            "user_search_base": "ou=people",
            "user_filter": "(uid={username})",
            "user_attribute": "uid",
            "group_search_base": "ou=groups",
            "group_filter": "(member={user_dn})",
            "required_admin_group": "cn=admins,dc=example,dc=org",
            "timeout_seconds": "5",
            "verify_tls": "1",
        },
    )

    assert response.status_code in {302, 303}
    assert directory_store.saved[0][0] == "ldap"
    assert directory_store.saved[0][1]["enabled"] == "1"


def test_auth_provider_actions_submit_directory_form_payload(
    monkeypatch, tmp_path
) -> None:
    directory_store = FakeDirectoryAuthStore()
    loaded = load_admin_app(monkeypatch, tmp_path, directory_auth_store=directory_store)
    client = loaded.module.app.test_client()
    login_client(client)

    ldap_body = client.get("/administration?tab=ldap").get_data(as_text=True)
    ad_body = client.get("/administration?tab=active_directory").get_data(as_text=True)

    assert 'id="ldap-auth-provider-form"' in ldap_body
    assert (
        'form="ldap-auth-provider-form" name="action" value="test_auth_provider"'
        in ldap_body
    )
    assert (
        'form="ldap-auth-provider-form" name="action" value="scan_auth_provider"'
        in ldap_body
    )
    assert 'id="active_directory-auth-provider-form"' in ad_body
    assert (
        'form="active_directory-auth-provider-form" name="action" '
        'value="test_auth_provider"'
    ) in ad_body
    assert 'type="hidden" name="action" value="save_auth_provider"' not in ldap_body
    assert 'type="hidden" name="action" value="save_auth_provider"' not in ad_body


def test_active_directory_provider_save_passes_server_url_to_store(
    monkeypatch, tmp_path
) -> None:
    directory_store = FakeDirectoryAuthStore()
    loaded = load_admin_app(monkeypatch, tmp_path, directory_auth_store=directory_store)
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/administration?tab=active_directory")

    response = client.post(
        "/administration?tab=active_directory",
        data={
            "csrf_token": token,
            "action": "save_auth_provider",
            "provider": "active_directory",
            "enabled": "0",
            "server_urls": "ldaps://dc.example.local:636",
            "bind_dn": "svc@example.local",
            "bind_password": "secret",
            "base_dn": "DC=example,DC=local",
            "user_filter": "(sAMAccountName={username})",
            "user_attribute": "sAMAccountName",
            "group_filter": "(member={user_dn})",
            "required_admin_group": "CN=Admins,DC=example,DC=local",
            "timeout_seconds": "5",
            "verify_tls": "1",
        },
    )

    assert response.status_code in {302, 303}
    assert directory_store.saved[0][0] == "active_directory"
    assert directory_store.saved[0][1]["server_urls"] == "ldaps://dc.example.local:636"


def test_auth_provider_checked_tls_controls_override_hidden_defaults(
    monkeypatch, tmp_path
) -> None:
    directory_store = FakeDirectoryAuthStore()
    loaded = load_admin_app(monkeypatch, tmp_path, directory_auth_store=directory_store)
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/administration?tab=active_directory")

    response = client.post(
        "/administration?tab=active_directory",
        data=MultiDict(
            [
                ("csrf_token", token),
                ("action", "test_auth_provider"),
                ("provider", "active_directory"),
                ("enabled", "0"),
                ("server_urls", "ldaps://submitted-dc.example.local:636"),
                ("use_starttls", "0"),
                ("use_starttls", "1"),
                ("verify_tls", "0"),
                ("verify_tls", "1"),
                ("bind_dn", "submitted-svc@example.local"),
                ("bind_password", "submitted-secret"),
                ("base_dn", "DC=submitted,DC=local"),
                ("user_search_base", "OU=People"),
                ("user_filter", "(sAMAccountName={username})"),
                ("user_attribute", "sAMAccountName"),
                ("group_search_base", "OU=Groups"),
                ("group_filter", "(member={user_dn})"),
                ("required_admin_group", "CN=Admins,OU=Groups,DC=submitted,DC=local"),
                ("timeout_seconds", "9"),
            ]
        ),
    )

    assert response.status_code in {302, 303}
    saved = directory_store.saved[0][1]
    assert saved["server_urls"] == "ldaps://submitted-dc.example.local:636"
    assert saved["use_starttls"] == "1"
    assert saved["verify_tls"] == "1"
    assert saved["bind_dn"] == "submitted-svc@example.local"
    assert saved["base_dn"] == "DC=submitted,DC=local"
    assert saved["user_search_base"] == "OU=People"
    assert saved["group_search_base"] == "OU=Groups"
    assert directory_store.tested == ["active_directory"]


def test_auth_provider_certificate_upload_is_passed_to_store(
    monkeypatch, tmp_path
) -> None:
    directory_store = FakeDirectoryAuthStore()
    loaded = load_admin_app(monkeypatch, tmp_path, directory_auth_store=directory_store)
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/administration?tab=ldap")

    response = client.post(
        "/administration?tab=ldap",
        data={
            "csrf_token": token,
            "action": "save_auth_provider",
            "provider": "ldap",
            "enabled": "0",
            "server_urls": "ldaps://ldap.example.org:636",
            "bind_dn": "cn=bind,dc=example,dc=org",
            "bind_password": "secret",
            "base_dn": "dc=example,dc=org",
            "user_filter": "(uid={username})",
            "user_attribute": "uid",
            "group_filter": "(member={user_dn})",
            "required_admin_group": "cn=admins,dc=example,dc=org",
            "timeout_seconds": "5",
            "verify_tls": "1",
            "ca_bundle_file": (io.BytesIO(b"cert-bytes"), "ca.crt"),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code in {302, 303}
    assert directory_store.saved[0][1]["ca_bundle_upload"] == b"cert-bytes"


def test_auth_provider_certificate_upload_rejects_oversize_before_store(
    monkeypatch, tmp_path
) -> None:
    directory_store = FakeDirectoryAuthStore()
    loaded = load_admin_app(monkeypatch, tmp_path, directory_auth_store=directory_store)
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/administration?tab=ldap")

    response = client.post(
        "/administration?tab=ldap",
        data={
            "csrf_token": token,
            "action": "save_auth_provider",
            "provider": "ldap",
            "ca_bundle_file": (
                io.BytesIO(b"x" * (64 * 1024 + 1)),
                "oversize.crt",
            ),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "CA certificate material is too large (max 64 KiB)." in response.text
    assert directory_store.saved == []


def test_enabling_directory_provider_disables_saml_provider(
    monkeypatch, tmp_path
) -> None:
    directory_store = FakeDirectoryAuthStore()
    loaded = load_admin_app(monkeypatch, tmp_path, directory_auth_store=directory_store)
    saml_disabled = []

    def disable_saml_provider() -> None:
        saml_disabled.append(True)

    monkeypatch.setattr(
        loaded.module._saml_auth_store,
        "disable_provider",
        disable_saml_provider,
    )
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/administration?tab=ldap")

    response = client.post(
        "/administration?tab=ldap",
        data={
            "csrf_token": token,
            "action": "save_auth_provider",
            "provider": "ldap",
            "enabled": "1",
            "server_urls": "ldaps://ldap.example.org:636",
            "bind_dn": "cn=bind,dc=example,dc=org",
            "bind_password": "secret",
            "base_dn": "dc=example,dc=org",
            "user_filter": "(uid={username})",
            "user_attribute": "uid",
            "group_filter": "(member={user_dn})",
            "required_admin_group": "cn=admins,dc=example,dc=org",
            "timeout_seconds": "5",
            "verify_tls": "1",
        },
    )

    assert response.status_code in {302, 303}
    assert directory_store.profile_enabled["ldap"] is True
    assert saml_disabled == [True]


def test_auth_provider_test_saves_submitted_bind_password_first(
    monkeypatch, tmp_path
) -> None:
    directory_store = FakeDirectoryAuthStore()
    loaded = load_admin_app(monkeypatch, tmp_path, directory_auth_store=directory_store)
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/administration?tab=active_directory")

    response = client.post(
        "/administration?tab=active_directory",
        data={
            "csrf_token": token,
            "action": "test_auth_provider",
            "provider": "active_directory",
            "enabled": "1",
            "server_urls": "ldaps://dc.example.local:636",
            "bind_dn": "svc@example.local",
            "bind_password": "replacement-secret",
            "base_dn": "DC=example,DC=local",
            "user_filter": "(sAMAccountName={username})",
            "user_attribute": "sAMAccountName",
            "group_filter": "(member={user_dn})",
            "required_admin_group": "CN=Admins,DC=example,DC=local",
            "timeout_seconds": "5",
            "verify_tls": "1",
        },
    )

    assert response.status_code in {302, 303}
    assert directory_store.saved[0][0] == "active_directory"
    assert directory_store.saved[0][1]["bind_password"] == "replacement-secret"
    assert directory_store.saved[0][1]["enabled"] == "0"
    assert directory_store.tested == ["active_directory"]
    assert directory_store.profile_enabled["active_directory"] is False


def test_ldap_auth_provider_test_passes_server_url_to_store(
    monkeypatch, tmp_path
) -> None:
    directory_store = FakeDirectoryAuthStore()
    loaded = load_admin_app(monkeypatch, tmp_path, directory_auth_store=directory_store)
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/administration?tab=ldap")

    response = client.post(
        "/administration?tab=ldap",
        data={
            "csrf_token": token,
            "action": "test_auth_provider",
            "provider": "ldap",
            "enabled": "1",
            "server_urls": "ldaps://ldap.example.org:636",
            "bind_dn": "cn=bind,dc=example,dc=org",
            "bind_password": "replacement-secret",
            "base_dn": "dc=example,dc=org",
            "user_filter": "(uid={username})",
            "user_attribute": "uid",
            "group_search_base": "ou=groups",
            "group_filter": "(member={user_dn})",
            "required_admin_group": "cn=admins,dc=example,dc=org",
            "timeout_seconds": "5",
            "verify_tls": "1",
        },
    )

    assert response.status_code in {302, 303}
    assert directory_store.saved[0][0] == "ldap"
    assert directory_store.saved[0][1]["server_urls"] == "ldaps://ldap.example.org:636"
    assert directory_store.saved[0][1]["enabled"] == "0"
    assert directory_store.tested == ["ldap"]


def test_active_auth_provider_test_restores_enabled_state_after_success(
    monkeypatch, tmp_path
) -> None:
    directory_store = FakeDirectoryAuthStore()
    directory_store.profile_enabled["ldap"] = True
    loaded = load_admin_app(monkeypatch, tmp_path, directory_auth_store=directory_store)
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/administration?tab=ldap")

    response = client.post(
        "/administration?tab=ldap",
        data={
            "csrf_token": token,
            "action": "test_auth_provider",
            "provider": "ldap",
            "enabled": "1",
            "server_urls": "ldaps://ldap.example.org:636",
            "bind_dn": "cn=bind,dc=example,dc=org",
            "bind_password": "replacement-secret",
            "base_dn": "dc=example,dc=org",
            "user_filter": "(uid={username})",
            "user_attribute": "uid",
            "group_search_base": "ou=groups",
            "group_filter": "(member={user_dn})",
            "required_admin_group": "cn=admins,dc=example,dc=org",
            "timeout_seconds": "5",
            "verify_tls": "1",
        },
    )

    assert response.status_code in {302, 303}
    assert [saved[1]["enabled"] for saved in directory_store.saved] == ["0", "1"]
    assert directory_store.saved[-1][1]["bind_password"] == ""
    assert directory_store.profile_enabled["ldap"] is True


def test_active_auth_provider_test_restores_previous_profile_after_failure(
    monkeypatch, tmp_path
) -> None:
    class FailingTestStore(FakeDirectoryAuthStore):
        def test_connection(self, provider):
            self.tested.append(provider)
            self.profile_last_test_ok[provider] = False
            return SimpleNamespace(
                ok=False,
                provider=provider,
                detail="Directory connection failed.",
            )

    directory_store = FailingTestStore()
    directory_store.profile_enabled["ldap"] = True
    directory_store.profile_last_test_ok["ldap"] = True
    loaded = load_admin_app(monkeypatch, tmp_path, directory_auth_store=directory_store)
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/administration?tab=ldap")

    response = client.post(
        "/administration?tab=ldap",
        data={
            "csrf_token": token,
            "action": "test_auth_provider",
            "provider": "ldap",
            "server_urls": "ldaps://bad.example.org:636",
            "bind_dn": "cn=bind,dc=example,dc=org",
            "bind_password": "not-for-output",
            "base_dn": "dc=example,dc=org",
            "user_filter": "(uid={username})",
            "user_attribute": "uid",
            "group_filter": "(member={user_dn})",
            "required_admin_group": "cn=admins,dc=example,dc=org",
            "timeout_seconds": "5",
            "verify_tls": "1",
        },
    )

    assert response.status_code in {302, 303}
    assert directory_store.profile_enabled["ldap"] is True
    assert directory_store.profile_last_test_ok["ldap"] is True
    assert "not-for-output" not in response.headers["Location"]


@pytest.mark.parametrize("action", ["test_auth_provider", "scan_auth_provider"])
def test_active_auth_provider_probe_restores_previous_profile_after_exception(
    monkeypatch, tmp_path, action
) -> None:
    class RaisingProbeStore(FakeDirectoryAuthStore):
        def test_connection(self, provider):
            msg = "probe exploded"
            raise RuntimeError(msg)

        def scan_directory(self, provider):
            msg = "probe exploded"
            raise RuntimeError(msg)

    directory_store = RaisingProbeStore()
    directory_store.profile_enabled["ldap"] = True
    directory_store.profile_last_test_ok["ldap"] = True
    loaded = load_admin_app(monkeypatch, tmp_path, directory_auth_store=directory_store)
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/administration?tab=ldap")

    response = client.post(
        "/administration?tab=ldap",
        data={
            "csrf_token": token,
            "action": action,
            "provider": "ldap",
            "server_urls": "ldaps://bad.example.org:636",
            "bind_dn": "cn=bind,dc=example,dc=org",
            "bind_password": "not-for-output",
            "base_dn": "dc=example,dc=org",
            "user_filter": "(uid={username})",
            "user_attribute": "uid",
            "group_filter": "(member={user_dn})",
            "required_admin_group": "cn=admins,dc=example,dc=org",
            "timeout_seconds": "5",
            "verify_tls": "1",
        },
    )

    assert response.status_code in {302, 303}
    assert directory_store.profile_enabled["ldap"] is True
    assert directory_store.profile_last_test_ok["ldap"] is True
    assert "not-for-output" not in response.headers["Location"]


def test_auth_provider_scan_populates_directory_choices(monkeypatch, tmp_path) -> None:
    directory_store = FakeDirectoryAuthStore()
    loaded = load_admin_app(monkeypatch, tmp_path, directory_auth_store=directory_store)
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/administration?tab=ldap")

    response = client.post(
        "/administration?tab=ldap",
        data={
            "csrf_token": token,
            "action": "scan_auth_provider",
            "provider": "ldap",
            "enabled": "1",
            "server_urls": "ldaps://scan-ldap.example.org:636",
            "bind_dn": "cn=scan,dc=example,dc=org",
            "bind_password": "scan-secret",
            "base_dn": "dc=example,dc=org",
            "user_filter": "(uid={username})",
            "user_attribute": "uid",
            "group_search_base": "ou=groups",
            "group_filter": "(member={user_dn})",
            "required_admin_group": "cn=admins,dc=example,dc=org",
            "timeout_seconds": "5",
            "verify_tls": "1",
        },
    )

    assert response.status_code in {302, 303}
    assert directory_store.saved[0][0] == "ldap"
    assert directory_store.saved[0][1]["server_urls"] == (
        "ldaps://scan-ldap.example.org:636"
    )
    assert directory_store.saved[0][1]["bind_password"] == "scan-secret"
    assert directory_store.saved[0][1]["enabled"] == "0"
    assert directory_store.profile_enabled["ldap"] is False
    body = client.get("/administration?tab=ldap").get_data(as_text=True)
    assert "ou=people" in body
    assert "cn=admins,ou=groups,dc=example,dc=org" in body


def test_active_auth_provider_scan_restores_enabled_state_for_tested_config(
    monkeypatch, tmp_path
) -> None:
    directory_store = FakeDirectoryAuthStore()
    directory_store.profile_enabled["ldap"] = True
    directory_store.profile_last_test_ok["ldap"] = True
    loaded = load_admin_app(monkeypatch, tmp_path, directory_auth_store=directory_store)
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/administration?tab=ldap")

    response = client.post(
        "/administration?tab=ldap",
        data={
            "csrf_token": token,
            "action": "scan_auth_provider",
            "provider": "ldap",
            "enabled": "1",
            "server_urls": "ldaps://scan-ldap.example.org:636",
            "bind_dn": "cn=scan,dc=example,dc=org",
            "bind_password": "scan-secret",
            "base_dn": "dc=example,dc=org",
            "user_filter": "(uid={username})",
            "user_attribute": "uid",
            "group_search_base": "ou=groups",
            "group_filter": "(member={user_dn})",
            "required_admin_group": "cn=admins,dc=example,dc=org",
            "timeout_seconds": "5",
            "verify_tls": "1",
        },
    )

    assert response.status_code in {302, 303}
    assert [saved[1]["enabled"] for saved in directory_store.saved] == ["0"]
    assert directory_store.profile_enabled["ldap"] is True


def test_active_directory_provider_scan_saves_submitted_form_first(
    monkeypatch, tmp_path
) -> None:
    directory_store = FakeDirectoryAuthStore()
    loaded = load_admin_app(monkeypatch, tmp_path, directory_auth_store=directory_store)
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/administration?tab=active_directory")

    response = client.post(
        "/administration?tab=active_directory",
        data={
            "csrf_token": token,
            "action": "scan_auth_provider",
            "provider": "active_directory",
            "enabled": "1",
            "server_urls": "ldaps://scan-dc.example.local:636",
            "bind_dn": "scan-svc@example.local",
            "bind_password": "scan-ad-secret",
            "base_dn": "DC=example,DC=local",
            "user_filter": "(sAMAccountName={username})",
            "user_attribute": "sAMAccountName",
            "group_filter": "(member={user_dn})",
            "required_admin_group": "CN=Admins,DC=example,DC=local",
            "timeout_seconds": "5",
            "verify_tls": "1",
        },
    )

    assert response.status_code in {302, 303}
    assert directory_store.saved[0][0] == "active_directory"
    assert directory_store.saved[0][1]["server_urls"] == (
        "ldaps://scan-dc.example.local:636"
    )
    assert directory_store.saved[0][1]["bind_dn"] == "scan-svc@example.local"
    assert directory_store.saved[0][1]["bind_password"] == "scan-ad-secret"
    assert directory_store.saved[0][1]["enabled"] == "0"


class RaisingDirectoryAuthStore(FakeDirectoryAuthStore):
    def authenticate_admin(self, username: str, password: str):
        msg = "directory unavailable"
        raise RuntimeError(msg)


def test_directory_auth_failure_falls_back_to_local_login(
    monkeypatch, tmp_path
) -> None:
    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        directory_auth_store=RaisingDirectoryAuthStore(),
    )
    client = loaded.module.app.test_client()
    token = csrf_token(client, "/login")

    response = client.post(
        "/login",
        data={"username": "admin", "password": "admin", "csrf_token": token},
    )

    assert response.status_code in {302, 303}
    with client.session_transaction() as sess:
        assert sess["user"] == "admin"
        assert sess["auth_provider"] == "local"


class RejectingActiveDirectoryAuthStore(FakeDirectoryAuthStore):
    def __init__(self) -> None:
        super().__init__()
        self.login_ok = True

    def authenticate_admin(self, username: str, password: str):
        return SimpleNamespace(
            ok=False,
            provider="ldap",
            username=username,
            detail="User is not in the required admin group.",
        )


def test_active_directory_rejection_falls_back_to_local_login(
    monkeypatch,
    tmp_path,
) -> None:
    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        directory_auth_store=RejectingActiveDirectoryAuthStore(),
    )
    client = loaded.module.app.test_client()
    token = csrf_token(client, "/login")

    response = client.post(
        "/login",
        data={"username": "admin", "password": "admin", "csrf_token": token},
    )

    assert response.status_code in {302, 303}
    with client.session_transaction() as sess:
        assert sess["user"] == "admin"
        assert sess["auth_provider"] == "local"


class StatusFailingDirectoryAuthStore(FakeDirectoryAuthStore):
    def get_status(self):
        msg = "directory status unavailable"
        raise RuntimeError(msg)


def test_administration_provider_tab_degrades_to_status(monkeypatch, tmp_path) -> None:
    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        directory_auth_store=StatusFailingDirectoryAuthStore(),
    )
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/administration?tab=ldap")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "Authentication status" in body
    assert "LDAP provider" not in body


class RevalidatingDirectoryAuthStore:
    """Directory store fake built on real profiles and policy fingerprints."""

    def __init__(self) -> None:
        from services.directory_auth import DirectoryAuthStore

        base = DirectoryAuthStore(lambda: "test-secret")
        self.profile = replace(base.default_profile("ldap"), enabled=True)
        self.in_admin_group = True
        self.unreachable = False
        self.profile_reads = 0
        self.revalidations: list[tuple[str, str]] = []

    def ensure_default_profiles(self) -> None:
        return None

    def authenticate_admin(self, username: str, password: str):
        from services.directory_auth import (
            DirectoryAuthResult,
            directory_policy_fingerprint,
        )

        if username == "EXAMPLE\\ldap-user" and password == "ldap-pass":
            return DirectoryAuthResult(
                True,
                "ldap",
                "ldap-user",
                "Directory authentication succeeded.",
                lookup_name=username,
                policy_fingerprint=directory_policy_fingerprint(self.profile),
            )
        return DirectoryAuthResult(False, "ldap", username, "bad credentials")

    def get_active_profile_for_session(self):
        self.profile_reads += 1
        return self.profile if self.profile.enabled else None

    def revalidate_admin(self, profile, username, lookup_name):
        from services.directory_auth import (
            DirectoryAuthResult,
            DirectoryUnavailableError,
        )

        self.revalidations.append((username, lookup_name))
        if self.unreachable:
            msg = "All configured LDAP server URLs failed"
            raise DirectoryUnavailableError(msg)
        if not self.in_admin_group:
            return DirectoryAuthResult(
                False,
                profile.provider,
                username,
                "User is not in the required admin group.",
            )
        return DirectoryAuthResult(True, profile.provider, username, "ok")

    def get_status(self):
        return {
            "active_provider": "ldap",
            "active_label": "LDAP",
            "profiles": {},
            "providers": (),
            "provider_labels": {},
        }


def _directory_session(monkeypatch, tmp_path, **env):
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    audit = FakeAuditStore()
    store = RevalidatingDirectoryAuthStore()
    loaded = load_admin_app(
        monkeypatch, tmp_path, audit_store=audit, directory_auth_store=store
    )
    client = loaded.module.app.test_client()
    login_client(client, "EXAMPLE\\ldap-user", "ldap-pass")
    with client.session_transaction() as sess:
        assert sess["user"] == "ldap-user"
        assert sess["auth_provider"] == "ldap"
        assert sess["directory_lookup"] == "EXAMPLE\\ldap-user"
    return loaded, client, store, audit


def _age_directory_check(client, seconds: int) -> None:
    with client.session_transaction() as sess:
        sess["directory_checked_ts"] = int(sess["directory_checked_ts"]) - seconds


def test_directory_session_skips_ldap_within_revalidation_interval(
    monkeypatch, tmp_path
) -> None:
    loaded, client, store, _audit = _directory_session(monkeypatch, tmp_path)

    response = client.get("/", follow_redirects=False)

    assert response.status_code == 200
    assert store.revalidations == []
    # Guards, context processor and link building share one validation.
    assert store.profile_reads == 1

    _age_directory_check(client, loaded.module._directory_revalidate_seconds)
    response = client.get("/", follow_redirects=False)

    assert response.status_code == 200
    assert store.revalidations == [("ldap-user", "EXAMPLE\\ldap-user")]
    response = client.get("/", follow_redirects=False)
    assert store.revalidations == [("ldap-user", "EXAMPLE\\ldap-user")]


def test_directory_revalidation_interval_is_env_configurable_and_clamped(
    monkeypatch, tmp_path
) -> None:
    loaded, *_rest = _directory_session(
        monkeypatch, tmp_path, DIRECTORY_SESSION_REVALIDATE_SECONDS="5"
    )
    assert loaded.module._directory_revalidate_seconds == 60
    monkeypatch.setenv("DIRECTORY_SESSION_REVALIDATE_SECONDS", "999999")
    loaded = load_admin_app(monkeypatch, tmp_path)
    assert loaded.module._directory_revalidate_seconds == 3600


def test_directory_session_ends_when_user_leaves_admin_group(
    monkeypatch, tmp_path
) -> None:
    loaded, client, store, audit = _directory_session(monkeypatch, tmp_path)
    store.in_admin_group = False
    _age_directory_check(client, loaded.module._directory_revalidate_seconds)

    response = client.get("/", follow_redirects=False)

    assert response.status_code in {302, 303}
    assert response.headers["Location"].startswith("/login?")
    with client.session_transaction() as sess:
        assert "user" not in sess
    assert audit.records[-1]["kind"] == "session_revoked"
    assert "required admin group" in audit.records[-1]["detail"]


def test_directory_policy_change_revalidates_at_once(monkeypatch, tmp_path) -> None:
    _loaded, client, store, _audit = _directory_session(monkeypatch, tmp_path)
    store.profile = replace(store.profile, required_admin_group="cn=new,dc=x")

    response = client.get("/", follow_redirects=False)

    assert response.status_code == 200
    assert len(store.revalidations) == 1

    store.in_admin_group = False
    store.profile = replace(store.profile, required_admin_group="cn=newer,dc=x")
    response = client.get("/", follow_redirects=False)

    assert response.status_code in {302, 303}
    with client.session_transaction() as sess:
        assert "user" not in sess


def test_directory_session_ends_when_provider_disabled(monkeypatch, tmp_path) -> None:
    _loaded, client, store, audit = _directory_session(monkeypatch, tmp_path)
    store.profile = replace(store.profile, enabled=False)

    response = client.get("/", follow_redirects=False)

    assert response.status_code in {302, 303}
    assert store.revalidations == []
    with client.session_transaction() as sess:
        assert "user" not in sess
    assert "no longer active" in audit.records[-1]["detail"]


def test_directory_outage_keeps_session_with_backoff(monkeypatch, tmp_path) -> None:
    loaded, client, store, _audit = _directory_session(monkeypatch, tmp_path)
    store.unreachable = True
    _age_directory_check(client, loaded.module._directory_revalidate_seconds)

    response = client.get("/", follow_redirects=False)

    assert response.status_code == 503
    with client.session_transaction() as sess:
        assert sess["user"] == "ldap-user"
    assert len(store.revalidations) == 1

    # Within the backoff the directory is not asked again.
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 503
    assert len(store.revalidations) == 1

    # Logout still works while the session cannot be validated.
    with client.session_transaction() as sess:
        token = sess["_csrf_token"]
    response = client.post(
        "/logout", data={"csrf_token": token}, follow_redirects=False
    )
    assert response.status_code in {302, 303}
    with client.session_transaction() as sess:
        assert "user" not in sess


def test_directory_recovers_after_backoff(monkeypatch, tmp_path) -> None:
    loaded, client, store, _audit = _directory_session(monkeypatch, tmp_path)
    store.unreachable = True
    _age_directory_check(client, loaded.module._directory_revalidate_seconds)
    assert client.get("/", follow_redirects=False).status_code == 503

    store.unreachable = False
    loaded.module._directory_revalidation_backoff.seconds = 0.0
    loaded.module._directory_revalidation_backoff.record_failure("expired")

    response = client.get("/", follow_redirects=False)

    assert response.status_code == 200
    assert len(store.revalidations) == 2


def test_directory_session_profile_db_outage_keeps_session(
    monkeypatch, tmp_path
) -> None:
    import pymysql

    _loaded, client, store, _audit = _directory_session(monkeypatch, tmp_path)

    def unavailable():
        raise pymysql.err.OperationalError(2003, "Can't connect to MySQL server")

    store.get_active_profile_for_session = unavailable

    response = client.get("/", follow_redirects=False)

    assert response.status_code == 503
    with client.session_transaction() as sess:
        assert sess["user"] == "ldap-user"


def _directory_outage_session(monkeypatch, tmp_path):
    loaded, client, store, audit = _directory_session(monkeypatch, tmp_path)
    store.unreachable = True
    _age_directory_check(client, loaded.module._directory_revalidate_seconds)
    return loaded, client, store, audit


def test_directory_outage_keeps_local_break_glass_login_reachable(
    monkeypatch, tmp_path
) -> None:
    _loaded, client, store, _audit = _directory_outage_session(monkeypatch, tmp_path)
    # Protected pages still answer 503 and keep the directory session.
    assert client.get("/", follow_redirects=False).status_code == 503

    page = client.get("/login", follow_redirects=False)
    body = page.get_data(as_text=True)

    assert page.status_code == 200
    assert 'action="/login"' in body
    # Rendered as signed out: no navigation into protected pages.
    assert 'id="primary-nav"' not in body
    with client.session_transaction() as sess:
        assert sess["user"] == "ldap-user"
        token = sess["_csrf_token"]

    response = client.post(
        "/login",
        data={"username": "admin", "password": "admin", "csrf_token": token},
        follow_redirects=False,
    )

    assert response.status_code in {302, 303}
    # The directory session is replaced, nothing of it carries over.
    with client.session_transaction() as sess:
        assert sess["user"] == "admin"
        assert sess["auth_provider"] == "local"
        for key in ("directory_lookup", "directory_checked_ts", "auth_policy"):
            assert key not in sess
    revalidations = len(store.revalidations)
    assert client.get("/", follow_redirects=False).status_code == 200
    assert len(store.revalidations) == revalidations


def test_directory_outage_page_offers_working_logout(monkeypatch, tmp_path) -> None:
    _loaded, client, _store, _audit = _directory_outage_session(monkeypatch, tmp_path)

    response = client.get("/", follow_redirects=False)
    body = response.get_data(as_text=True)

    assert response.status_code == 503
    assert response.mimetype == "text/html"
    assert "script-src 'self'" in response.headers["Content-Security-Policy"]
    assert "<script" not in body
    assert "directory service is temporarily unavailable" in body
    assert '<form method="post" action="/logout">' in body
    assert 'href="/login"' in body
    form_token = body.split('name="csrf_token" value="', 1)[1].split('"', 1)[0]
    with client.session_transaction() as sess:
        assert sess["user"] == "ldap-user"

    response = client.post(
        "/logout", data={"csrf_token": form_token}, follow_redirects=False
    )

    assert response.status_code in {302, 303}
    assert response.headers["Location"].startswith("/login")
    with client.session_transaction() as sess:
        assert "user" not in sess
    assert client.get("/login").status_code == 200
