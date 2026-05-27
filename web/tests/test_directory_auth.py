from __future__ import annotations

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
