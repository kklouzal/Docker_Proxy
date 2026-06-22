from __future__ import annotations

import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from services.directory_auth import DirectoryAuthResult, DirectoryAuthStore


class MemoryDirectoryAuthStore(DirectoryAuthStore):
    def __init__(self) -> None:
        super().__init__(lambda: "test-secret")
        self.rows = {}

    def ensure_schema(self) -> None:
        return None

    def ensure_default_profiles(self) -> None:
        for provider in (
            self.default_profile("ldap").provider,
            self.default_profile("active_directory").provider,
        ):
            self.rows.setdefault(provider, self.default_profile(provider))

    def list_profiles(self):
        self.ensure_default_profiles()
        return dict(self.rows)

    def save_profile(self, provider, payload):
        profile = super().save_profile(provider, payload)
        self.rows[provider] = profile
        return profile


def _test_ca_pem() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Docker Proxy Test CA")]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def test_bind_password_encryption_round_trips_without_plaintext() -> None:
    store = DirectoryAuthStore(lambda: "stable-secret")
    encrypted = store._encrypt("super-secret")

    assert encrypted.startswith("enc:v1:")
    assert "super-secret" not in encrypted
    assert store._decrypt(encrypted) == "super-secret"


def test_bind_password_uses_configured_secret_across_store_reinitialization(
    tmp_path,
) -> None:
    from .mysql_test_utils import configure_test_mysql_env, ensure_web_import_path

    configure_test_mysql_env(tmp_path / "directory-auth-configured-secret-test")
    ensure_web_import_path()
    from services.directory_auth import DirectoryAuthStore as RuntimeDirectoryAuthStore

    payload = {
        "server_urls": "ldaps://dc.example.local:636",
        "bind_dn": "svc-docker-proxy@example.local",
        "bind_password": "secret",
        "base_dn": "DC=example,DC=local",
        "user_filter": "(sAMAccountName={username})",
        "user_attribute": "sAMAccountName",
        "group_filter": "(member={user_dn})",
        "required_admin_group": "CN=Admins,DC=example,DC=local",
        "timeout_seconds": "5",
        "verify_tls": "1",
    }
    first = RuntimeDirectoryAuthStore(lambda: "configured-flask-secret")
    first.save_profile("active_directory", payload)

    second = RuntimeDirectoryAuthStore(lambda: "configured-flask-secret")
    profile = second.get_profile("active_directory")

    assert profile.bind_password.startswith("enc:v1:")
    assert second._decrypt(profile.bind_password) == "secret"


def test_save_profile_recovers_stale_bind_password_with_new_plaintext(
    tmp_path,
) -> None:
    from .mysql_test_utils import configure_test_mysql_env, ensure_web_import_path

    configure_test_mysql_env(tmp_path / "directory-auth-stale-password-recovery-test")
    ensure_web_import_path()
    from services.directory_auth import DirectoryAuthStore as RuntimeDirectoryAuthStore

    old_store = RuntimeDirectoryAuthStore(lambda: "old-container-secret")
    old_profile = old_store.save_profile(
        "active_directory",
        {
            "server_urls": "ldaps://dc.example.local:636",
            "bind_dn": "svc-docker-proxy@example.local",
            "bind_password": "old-secret",
            "base_dn": "DC=example,DC=local",
            "user_filter": "(sAMAccountName={username})",
            "user_attribute": "sAMAccountName",
            "group_filter": "(member={user_dn})",
            "required_admin_group": "CN=Admins,DC=example,DC=local",
            "timeout_seconds": "5",
            "verify_tls": "1",
        },
    )

    new_store = RuntimeDirectoryAuthStore(lambda: "new-container-secret")
    assert new_store._decrypt(old_profile.bind_password) == ""

    recovered = new_store.save_profile(
        "active_directory",
        {
            "server_urls": old_profile.server_urls,
            "bind_dn": old_profile.bind_dn,
            "bind_password": "new-secret",
            "base_dn": old_profile.base_dn,
            "user_filter": old_profile.user_filter,
            "user_attribute": old_profile.user_attribute,
            "group_filter": old_profile.group_filter,
            "required_admin_group": old_profile.required_admin_group,
            "timeout_seconds": str(old_profile.timeout_seconds),
            "verify_tls": "1",
        },
    )

    assert new_store._decrypt(recovered.bind_password) == "new-secret"


def test_save_profile_requires_bind_password_when_stale_ciphertext_is_kept(
    tmp_path,
) -> None:
    from .mysql_test_utils import configure_test_mysql_env, ensure_web_import_path

    configure_test_mysql_env(tmp_path / "directory-auth-stale-password-empty-test")
    ensure_web_import_path()
    from services.directory_auth import DirectoryAuthStore as RuntimeDirectoryAuthStore

    old_store = RuntimeDirectoryAuthStore(lambda: "old-container-secret")
    old_profile = old_store.save_profile(
        "active_directory",
        {
            "server_urls": "ldaps://dc.example.local:636",
            "bind_dn": "svc-docker-proxy@example.local",
            "bind_password": "old-secret",
            "base_dn": "DC=example,DC=local",
            "user_filter": "(sAMAccountName={username})",
            "user_attribute": "sAMAccountName",
            "group_filter": "(member={user_dn})",
            "required_admin_group": "CN=Admins,DC=example,DC=local",
            "timeout_seconds": "5",
            "verify_tls": "1",
        },
    )

    new_store = RuntimeDirectoryAuthStore(lambda: "new-container-secret")
    assert new_store._decrypt(old_profile.bind_password) == ""

    with pytest.raises(ValueError, match="Bind password is required"):
        new_store.save_profile(
            "active_directory",
            {
                "enabled": "1",
                "server_urls": old_profile.server_urls,
                "bind_dn": old_profile.bind_dn,
                "bind_password": "",
                "base_dn": old_profile.base_dn,
                "user_filter": old_profile.user_filter,
                "user_attribute": old_profile.user_attribute,
                "group_filter": old_profile.group_filter,
                "required_admin_group": old_profile.required_admin_group,
                "timeout_seconds": str(old_profile.timeout_seconds),
                "verify_tls": "1",
            },
        )


def test_profile_save_clears_stale_connection_test_status_when_settings_change(
    tmp_path,
) -> None:
    from .mysql_test_utils import configure_test_mysql_env, ensure_web_import_path

    configure_test_mysql_env(tmp_path / "directory-auth-stale-test")
    ensure_web_import_path()
    from services.directory_auth import DirectoryAuthStore as RuntimeDirectoryAuthStore

    store = RuntimeDirectoryAuthStore(lambda: "stable-secret")
    store.ensure_default_profiles()
    profile = store.save_profile(
        "ldap",
        {
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
    store.record_test(
        "ldap", ok=True, detail="Directory bind and base search succeeded."
    )

    updated = store.save_profile(
        "ldap",
        {
            "server_urls": "ldaps://new.example.org:636",
            "bind_dn": profile.bind_dn,
            "base_dn": profile.base_dn,
            "user_filter": profile.user_filter,
            "user_attribute": profile.user_attribute,
            "group_filter": profile.group_filter,
            "required_admin_group": profile.required_admin_group,
            "timeout_seconds": str(profile.timeout_seconds),
            "verify_tls": "1",
        },
    )

    assert updated.last_test_ok is False
    assert updated.last_test_ts == 0
    assert "Configuration changed" in updated.last_test_detail


def test_profile_save_normalizes_multiline_server_urls(tmp_path) -> None:
    from .mysql_test_utils import configure_test_mysql_env, ensure_web_import_path

    configure_test_mysql_env(tmp_path / "directory-auth-url-normalize-test")
    ensure_web_import_path()
    from services.directory_auth import DirectoryAuthStore as RuntimeDirectoryAuthStore

    store = RuntimeDirectoryAuthStore(lambda: "stable-secret")
    profile = store.save_profile(
        "ldap",
        {
            "server_urls": "\n LDAPS://LDAP.EXAMPLE.ORG:636 \nldap://dc.example.org\n",
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

    assert profile.server_urls == "ldaps://ldap.example.org:636\nldap://dc.example.org"


def test_profile_save_preserves_bracketed_ipv6_server_urls(tmp_path) -> None:
    from .mysql_test_utils import configure_test_mysql_env, ensure_web_import_path

    configure_test_mysql_env(tmp_path / "directory-auth-ipv6-url-normalize-test")
    ensure_web_import_path()
    from services.directory_auth import DirectoryAuthStore as RuntimeDirectoryAuthStore

    store = RuntimeDirectoryAuthStore(lambda: "stable-secret")
    profile = store.save_profile(
        "ldap",
        {
            "server_urls": "LDAP://[2001:DB8::1]:389\nldaps://[2001:db8::2]",
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

    assert profile.server_urls == "ldap://[2001:db8::1]:389\nldaps://[2001:db8::2]"


def test_join_dn_requires_base_dn_boundary() -> None:
    store = DirectoryAuthStore(lambda: "stable-secret")

    assert (
        store._join_dn("ou=people,dc=example,dc=org", "dc=example,dc=org")
        == "ou=people,dc=example,dc=org"
    )
    assert store._join_dn("dc=example,dc=org", "dc=example,dc=org") == (
        "dc=example,dc=org"
    )
    assert store._join_dn("notdc=example,dc=org", "dc=example,dc=org") == (
        "notdc=example,dc=org,dc=example,dc=org"
    )


@pytest.mark.parametrize(
    ("server_urls", "message"),
    [
        ("http://ldap.example.org:389", "Only ldap:// or ldaps://"),
        ("ldap://", "valid ldap:// or ldaps:// URLs"),
        ("ldap://ldap.example.org/path", "valid ldap:// or ldaps:// URLs"),
        ("ldap://ldap.example.org?x=1", "valid ldap:// or ldaps:// URLs"),
        ("ldap://ldap.example.org#frag", "valid ldap:// or ldaps:// URLs"),
        ("ldap://user@ldap.example.org", "valid ldap:// or ldaps:// URLs"),
        ("ldap://ldap.example.org:not-a-port", "valid ldap:// or ldaps:// URLs"),
        ("ldap://2001:db8::1", "valid ldap:// or ldaps:// URLs"),
    ],
)
def test_profile_save_rejects_invalid_server_urls(
    tmp_path, server_urls: str, message: str
) -> None:
    from .mysql_test_utils import configure_test_mysql_env, ensure_web_import_path

    configure_test_mysql_env(tmp_path / "directory-auth-url-invalid-test")
    ensure_web_import_path()
    from services.directory_auth import DirectoryAuthStore as RuntimeDirectoryAuthStore

    store = RuntimeDirectoryAuthStore(lambda: "stable-secret")
    payload = {
        "server_urls": server_urls,
        "bind_dn": "cn=bind,dc=example,dc=org",
        "bind_password": "secret",
        "base_dn": "dc=example,dc=org",
        "user_filter": "(uid={username})",
        "user_attribute": "uid",
        "group_filter": "(member={user_dn})",
        "required_admin_group": "cn=admins,dc=example,dc=org",
        "timeout_seconds": "5",
        "verify_tls": "1",
    }

    with pytest.raises(ValueError, match=message):
        store.save_profile("ldap", payload)


def test_profile_requires_successful_connection_test_before_enable(tmp_path) -> None:
    from .mysql_test_utils import configure_test_mysql_env, ensure_web_import_path

    configure_test_mysql_env(tmp_path / "directory-auth-enable-test")
    ensure_web_import_path()
    from services.directory_auth import DirectoryAuthStore as RuntimeDirectoryAuthStore

    store = RuntimeDirectoryAuthStore(lambda: "stable-secret")
    store.ensure_default_profiles()

    payload = {
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
    }
    with pytest.raises(ValueError, match="successfully before enabling"):
        store.save_profile("ldap", payload)

    disabled = dict(payload)
    disabled["enabled"] = "0"
    store.save_profile("ldap", disabled)
    store.record_test(
        "ldap", ok=True, detail="Directory bind and base search succeeded."
    )
    tested = store.get_profile("ldap")
    store.save_profile("ldap", {**payload, "bind_password": ""})

    active = store.get_profile("ldap")
    assert active.enabled is True
    assert active.last_test_ok is True
    assert active.bind_password == tested.bind_password


def test_active_directory_auth_without_bind_password_fails_before_ldap(
    monkeypatch,
) -> None:
    store = DirectoryAuthStore(lambda: "stable-secret")
    profile = replace(
        store.default_profile("active_directory"),
        enabled=True,
        bind_password="",
    )
    monkeypatch.setattr(store, "get_active_profile", lambda: profile)
    monkeypatch.setattr(
        store,
        "_service_connection",
        lambda _profile: (_ for _ in ()).throw(
            AssertionError("LDAP connection should not be attempted")
        ),
    )

    result = store.authenticate_admin("kklouzal", "secret")

    assert result.ok is False
    assert result.provider == "active_directory"
    assert "Bind password is required" in result.detail
    assert "configuration is incomplete" in result.detail


def test_connection_without_decryptable_bind_password_records_clear_failure(
    monkeypatch,
) -> None:
    calls = []

    class FakeConnection:
        def __init__(self, *_args, **_kwargs) -> None:
            calls.append("connection")
            msg = "LDAP connection should not be constructed"
            raise AssertionError(msg)

    fake_ldap3 = SimpleNamespace(
        NONE=0,
        Server=lambda *_args, **_kwargs: SimpleNamespace(),
        Connection=FakeConnection,
        Tls=lambda **_kwargs: SimpleNamespace(),
    )
    monkeypatch.setitem(sys.modules, "ldap3", fake_ldap3)

    store = DirectoryAuthStore(lambda: "stable-secret")
    profile = replace(
        store.default_profile("ldap"),
        enabled=True,
        bind_password="enc:v1:not-decryptable",
    )
    recorded = []
    monkeypatch.setattr(store, "get_profile", lambda _provider: profile)
    monkeypatch.setattr(
        store,
        "record_test",
        lambda provider, *, ok, detail: recorded.append((provider, ok, detail)),
    )

    result = store.test_connection("ldap")

    assert result.ok is False
    assert result.provider == "ldap"
    assert "Bind password is required" in result.detail
    assert "configuration is incomplete" in result.detail
    assert recorded == [("ldap", False, result.detail)]
    assert calls == []


def test_directory_auth_result_keeps_provider_and_groups() -> None:
    result = DirectoryAuthResult(
        True,
        "ldap",
        "alice",
        "ok",
        ("cn=admins,dc=example,dc=org",),
    )

    assert result.ok is True
    assert result.provider == "ldap"
    assert result.groups == ("cn=admins,dc=example,dc=org",)


def test_profile_checkbox_false_value_overrides_default_true() -> None:
    store = DirectoryAuthStore(lambda: "stable-secret")

    assert store._truthy("0", default=True) is False


def test_normalize_ca_bundle_validates_uploaded_certificate() -> None:
    pem = _test_ca_pem()

    normalized = DirectoryAuthStore.normalize_ca_bundle(pem.encode())

    assert normalized.startswith("-----BEGIN CERTIFICATE-----")
    assert normalized.endswith("-----END CERTIFICATE-----\n")


def test_filter_presets_replace_raw_filter_fields() -> None:
    store = DirectoryAuthStore(lambda: "stable-secret")

    assert (
        store._preset_or_required(
            "active_directory",
            "group_filter",
            "(member:1.2.840.113556.1.4.1941:={user_dn})",
            "",
            "Group filter",
        )
        == "(member:1.2.840.113556.1.4.1941:={user_dn})"
    )


def test_scan_directory_returns_ou_and_group_choices(monkeypatch) -> None:
    store = DirectoryAuthStore(lambda: "stable-secret")
    profile = replace(
        store.default_profile("ldap"),
        base_dn="dc=example,dc=org",
    )

    class FakeConn:
        def __init__(self) -> None:
            self.entries = []

        def search(self, _base, search_filter, **_kwargs):
            if "organizationalUnit" in search_filter:
                self.entries = [
                    SimpleNamespace(entry_dn="ou=people,dc=example,dc=org"),
                    SimpleNamespace(entry_dn="ou=groups,dc=example,dc=org"),
                ]
            elif "objectClass=container" in search_filter:
                self.entries = [SimpleNamespace(entry_dn="cn=Users,dc=example,dc=org")]
            elif "objectClass=group" in search_filter:
                self.entries = [
                    SimpleNamespace(entry_dn="cn=admins,ou=groups,dc=example,dc=org")
                ]
            else:
                self.entries = []
            return bool(self.entries)

        def unbind(self):
            return None

    monkeypatch.setattr(store, "get_profile", lambda _provider: profile)
    monkeypatch.setattr(
        store, "_service_connection", lambda _profile: (FakeConn(), None)
    )

    result = store.scan_directory("ldap")

    assert result.base_dns == ("dc=example,dc=org",)
    assert "ou=people" in result.user_search_bases
    assert "cn=Users" in result.group_search_bases
    assert result.admin_groups == ("cn=admins,ou=groups,dc=example,dc=org",)


@pytest.mark.parametrize(
    ("login_username", "lookup_username"),
    [
        ("AD\\kklouzal", "kklouzal"),
        ("AD/kklouzal", "kklouzal"),
        ("kklouzal@ad.kklouzal.com", "kklouzal@ad.kklouzal.com"),
        ("kklouzal", "kklouzal"),
    ],
)
def test_active_directory_auth_uses_normalized_lookup_username(
    monkeypatch, login_username: str, lookup_username: str
) -> None:
    store = DirectoryAuthStore(lambda: "stable-secret")
    profile = replace(
        store.default_profile("active_directory"),
        base_dn="dc=ad,dc=kklouzal,dc=com",
        bind_password=store._encrypt("bind-secret"),
        user_filter="(|(sAMAccountName={username})(userPrincipalName={username}))",
        group_filter="(memberUid={username})",
        required_admin_group="cn=admins,dc=ad,dc=kklouzal,dc=com",
    )
    searches = []

    class FakeConn:
        def __init__(self) -> None:
            self.entries = []

        def search(self, base, search_filter, **_kwargs):
            searches.append((base, search_filter))
            if search_filter.startswith("(|(sAMAccountName="):
                self.entries = [
                    SimpleNamespace(
                        entry_dn="cn=kklouzal,cn=users,dc=ad,dc=kklouzal,dc=com"
                    )
                ]
            elif search_filter.startswith("(memberUid="):
                self.entries = [
                    SimpleNamespace(entry_dn="cn=admins,dc=ad,dc=kklouzal,dc=com")
                ]
            else:
                self.entries = []
            return bool(self.entries)

        def unbind(self):
            return None

    fake_ldap3 = SimpleNamespace(
        utils=SimpleNamespace(
            conv=SimpleNamespace(escape_filter_chars=lambda value: value)
        )
    )
    monkeypatch.setattr(
        store,
        "_service_connection",
        lambda _profile: (FakeConn(), fake_ldap3),
    )
    monkeypatch.setattr(store, "_user_bind", lambda *_args: True)

    result = store.authenticate(profile, login_username, "secret")

    assert result.ok is True
    assert result.username == login_username
    assert searches[0][1] == (
        f"(|(sAMAccountName={lookup_username})"
        f"(userPrincipalName={lookup_username}))"
    )
    assert searches[1][1] == f"(memberUid={lookup_username})"


def test_ldap_auth_preserves_domain_qualified_username_lookup(monkeypatch) -> None:
    store = DirectoryAuthStore(lambda: "stable-secret")
    profile = replace(
        store.default_profile("ldap"),
        bind_password=store._encrypt("bind-secret"),
        user_filter="(uid={username})",
        group_filter="(memberUid={username})",
        required_admin_group="cn=admins,dc=example,dc=org",
    )
    searches = []

    class FakeConn:
        def __init__(self) -> None:
            self.entries = []

        def search(self, _base, search_filter, **_kwargs):
            searches.append(search_filter)
            if search_filter == "(uid=AD\\kklouzal)":
                self.entries = [SimpleNamespace(entry_dn="uid=AD\\kklouzal,ou=people")]
            elif search_filter == "(memberUid=AD\\kklouzal)":
                self.entries = [
                    SimpleNamespace(entry_dn="cn=admins,dc=example,dc=org")
                ]
            else:
                self.entries = []
            return bool(self.entries)

        def unbind(self):
            return None

    fake_ldap3 = SimpleNamespace(
        utils=SimpleNamespace(
            conv=SimpleNamespace(escape_filter_chars=lambda value: value)
        )
    )
    monkeypatch.setattr(
        store,
        "_service_connection",
        lambda _profile: (FakeConn(), fake_ldap3),
    )
    monkeypatch.setattr(store, "_user_bind", lambda *_args: True)

    result = store.authenticate(profile, "AD\\kklouzal", "secret")

    assert result.ok is True
    assert searches == ["(uid=AD\\kklouzal)", "(memberUid=AD\\kklouzal)"]


def test_plain_ldap_user_bind_does_not_require_tls(monkeypatch) -> None:
    calls = []

    class FakeConnection:
        def __init__(self, *args, **kwargs) -> None:
            calls.append(("connect", kwargs))

        def open(self) -> None:
            calls.append(("open", None))

        def start_tls(self) -> None:
            calls.append(("start_tls", None))

        def bind(self) -> None:
            calls.append(("bind", None))

        def unbind(self) -> None:
            calls.append(("unbind", None))

    fake_ldap3 = SimpleNamespace(
        NONE=0,
        Server=lambda *args, **kwargs: SimpleNamespace(args=args, kwargs=kwargs),
        Connection=FakeConnection,
        Tls=lambda **kwargs: (_ for _ in ()).throw(
            AssertionError("TLS should not be configured")
        ),
    )
    monkeypatch.setitem(sys.modules, "ldap3", fake_ldap3)
    store = DirectoryAuthStore(lambda: "stable-secret")
    profile = replace(
        store.default_profile("ldap"), server_urls="ldap://ldap.example.org:389"
    )

    assert store._user_bind(profile, "uid=alice,dc=example,dc=org", "secret") is True
    assert ("start_tls", None) not in calls
    assert calls[-1] == ("unbind", None)


def _install_failing_first_ldap(monkeypatch):
    calls = []

    class FakeServer:
        def __init__(self, url, **kwargs) -> None:
            self.url = url
            self.kwargs = kwargs

    class FakeConnection:
        def __init__(self, server, **kwargs) -> None:
            self.server = server
            self.kwargs = kwargs
            calls.append(("connect", server.url, kwargs["user"]))

        def open(self) -> None:
            calls.append(("open", self.server.url))
            if "bad" in self.server.url:
                msg = "connection failed"
                raise RuntimeError(msg)

        def start_tls(self) -> None:
            calls.append(("start_tls", self.server.url))

        def bind(self) -> None:
            calls.append(("bind", self.server.url))

        def search(self, *args, **kwargs) -> bool:
            calls.append(("search", self.server.url))
            return True

        def unbind(self) -> None:
            calls.append(("unbind", self.server.url))

    def fake_tls(**kwargs):
        return SimpleNamespace(kwargs=kwargs)

    fake_ldap3 = SimpleNamespace(
        NONE=0,
        Server=FakeServer,
        Connection=FakeConnection,
        Tls=fake_tls,
    )
    monkeypatch.setitem(sys.modules, "ldap3", fake_ldap3)
    return calls


def test_service_connection_falls_back_to_next_server_url(monkeypatch) -> None:
    calls = _install_failing_first_ldap(monkeypatch)
    store = DirectoryAuthStore(lambda: "stable-secret")
    profile = replace(
        store.default_profile("ldap"),
        server_urls="ldaps://bad.example.org:636\nldaps://good.example.org:636",
        bind_password=store._encrypt("bind-secret"),
    )

    conn, _ldap3 = store._service_connection(profile)

    assert conn.server.url == "ldaps://good.example.org:636"
    assert ("open", "ldaps://bad.example.org:636") in calls
    assert ("unbind", "ldaps://bad.example.org:636") in calls
    assert ("bind", "ldaps://good.example.org:636") in calls
    store._safe_unbind(conn)


def test_user_bind_falls_back_to_next_server_url(monkeypatch) -> None:
    calls = _install_failing_first_ldap(monkeypatch)
    store = DirectoryAuthStore(lambda: "stable-secret")
    profile = replace(
        store.default_profile("ldap"),
        server_urls="ldaps://bad.example.org:636\nldaps://good.example.org:636",
    )

    assert store._user_bind(profile, "uid=alice,dc=example,dc=org", "secret") is True
    assert ("open", "ldaps://bad.example.org:636") in calls
    assert ("bind", "ldaps://good.example.org:636") in calls
    assert ("unbind", "ldaps://good.example.org:636") in calls
