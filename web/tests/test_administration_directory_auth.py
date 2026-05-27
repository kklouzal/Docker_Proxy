from __future__ import annotations

from types import SimpleNamespace

from .admin_route_test_utils import csrf_token, load_admin_app, login_client


class FakeDirectoryAuthStore:
    def __init__(self) -> None:
        self.saved = []
        self.disabled = []
        self.tested = []
        self.login_ok = False

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
        return SimpleNamespace(ok=False, provider="ldap", username=username, detail="no")

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
            last_test_detail="",
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
        }

    def save_profile(self, provider, payload):
        self.saved.append((provider, dict(payload)))
        return self.get_status()["profiles"][provider]

    def test_connection(self, provider):
        self.tested.append(provider)
        return SimpleNamespace(ok=True, provider=provider, detail="Directory bind and base search succeeded.")

    def disable_provider(self, provider):
        self.disabled.append(provider)


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
    assert "Active Directory" in client.get("/administration?tab=status").get_data(as_text=True)


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


class RaisingDirectoryAuthStore(FakeDirectoryAuthStore):
    def authenticate_admin(self, username: str, password: str):
        msg = "directory unavailable"
        raise RuntimeError(msg)


def test_directory_auth_failure_falls_back_to_local_login(monkeypatch, tmp_path) -> None:
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
