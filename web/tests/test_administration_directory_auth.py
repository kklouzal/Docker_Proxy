from __future__ import annotations

import io
from types import SimpleNamespace

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
        ldap = SimpleNamespace(
            provider="ldap",
            label="LDAP",
            enabled=self.login_ok,
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
            last_test_ok=False,
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
            enabled=False,
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
            last_test_ok=False,
            last_test_ts=0,
            last_test_detail="",
        )
        return {
            "active_provider": "ldap" if self.login_ok else "local",
            "active_label": "LDAP" if self.login_ok else "Local accounts",
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

    def save_profile(self, provider, payload):
        self.saved.append((provider, dict(payload)))
        return self.get_status()["profiles"][provider]

    def test_connection(self, provider):
        self.tested.append(provider)
        return SimpleNamespace(
            ok=True,
            provider=provider,
            detail="Directory bind and base search succeeded.",
        )

    def disable_provider(self, provider):
        self.disabled.append(provider)

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
    assert 'form="ldap-auth-provider-form" name="action" value="test_auth_provider"' in ldap_body
    assert 'form="ldap-auth-provider-form" name="action" value="scan_auth_provider"' in ldap_body
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
        },
    )

    assert response.status_code in {302, 303}
    body = client.get("/administration?tab=ldap").get_data(as_text=True)
    assert "ou=people" in body
    assert "cn=admins,ou=groups,dc=example,dc=org" in body


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
