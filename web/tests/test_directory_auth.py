from __future__ import annotations

import sys
from dataclasses import replace
from types import SimpleNamespace

from services.directory_auth import DirectoryAuthResult, DirectoryAuthStore


class MemoryDirectoryAuthStore(DirectoryAuthStore):
    def __init__(self) -> None:
        super().__init__(lambda: "test-secret")
        self.rows = {}

    def ensure_schema(self) -> None:
        return None

    def ensure_default_profiles(self) -> None:
        for provider in self.default_profile("ldap").provider, self.default_profile("active_directory").provider:
            self.rows.setdefault(provider, self.default_profile(provider))

    def list_profiles(self):
        self.ensure_default_profiles()
        return dict(self.rows)

    def save_profile(self, provider, payload):
        profile = super().save_profile(provider, payload)
        self.rows[provider] = profile
        return profile


def test_bind_password_encryption_round_trips_without_plaintext() -> None:
    store = DirectoryAuthStore(lambda: "stable-secret")
    encrypted = store._encrypt("super-secret")

    assert encrypted.startswith("enc:v1:")
    assert "super-secret" not in encrypted
    assert store._decrypt(encrypted) == "super-secret"


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
        Tls=lambda **kwargs: (_ for _ in ()).throw(AssertionError("TLS should not be configured")),
    )
    monkeypatch.setitem(sys.modules, "ldap3", fake_ldap3)
    store = DirectoryAuthStore(lambda: "stable-secret")
    profile = replace(store.default_profile("ldap"), server_urls="ldap://ldap.example.org:389")

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
                raise RuntimeError("connection failed")

        def start_tls(self) -> None:
            calls.append(("start_tls", self.server.url))

        def bind(self) -> None:
            calls.append(("bind", self.server.url))

        def search(self, *args, **kwargs) -> bool:
            calls.append(("search", self.server.url))
            return True

        def unbind(self) -> None:
            calls.append(("unbind", self.server.url))

    fake_ldap3 = SimpleNamespace(
        NONE=0,
        Server=FakeServer,
        Connection=FakeConnection,
        Tls=lambda **kwargs: SimpleNamespace(kwargs=kwargs),
    )
    monkeypatch.setitem(sys.modules, "ldap3", fake_ldap3)
    return calls


def test_service_connection_falls_back_to_next_server_url(monkeypatch) -> None:
    calls = _install_failing_first_ldap(monkeypatch)
    store = DirectoryAuthStore(lambda: "stable-secret")
    profile = replace(
        store.default_profile("ldap"),
        server_urls="ldaps://bad.example.org:636\nldaps://good.example.org:636",
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

