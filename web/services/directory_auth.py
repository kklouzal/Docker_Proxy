from __future__ import annotations

import base64
import contextlib
import hashlib
import logging
import re
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from collections.abc import Callable

from cryptography import x509
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import serialization

from services.db import connect
from services.logutil import log_exception_throttled

logger = logging.getLogger(__name__)

PROVIDER_LDAP = "ldap"
PROVIDER_ACTIVE_DIRECTORY = "active_directory"
DIRECTORY_PROVIDERS = (PROVIDER_LDAP, PROVIDER_ACTIVE_DIRECTORY)
PROVIDER_LABELS = {
    PROVIDER_LDAP: "LDAP",
    PROVIDER_ACTIVE_DIRECTORY: "Active Directory",
}
DIRECTORY_PRESETS = {
    PROVIDER_LDAP: {
        "user_attribute": (
            ("uid", "OpenLDAP uid"),
            ("mail", "Email address"),
            ("cn", "Common name"),
        ),
        "user_filter": (
            ("(uid={username})", "OpenLDAP uid"),
            ("(mail={username})", "Email address"),
            ("(|(uid={username})(mail={username}))", "UID or email"),
        ),
        "group_filter": (
            (
                "(|(member={user_dn})(uniqueMember={user_dn})(memberUid={username}))",
                "OpenLDAP groups",
            ),
            ("(member={user_dn})", "groupOfNames"),
            ("(uniqueMember={user_dn})", "groupOfUniqueNames"),
            ("(memberUid={username})", "posixGroup"),
        ),
    },
    PROVIDER_ACTIVE_DIRECTORY: {
        "user_attribute": (
            ("sAMAccountName", "Windows logon name"),
            ("userPrincipalName", "User principal name"),
            ("mail", "Email address"),
        ),
        "user_filter": (
            (
                "(|(sAMAccountName={username})(userPrincipalName={username}))",
                "Logon name or UPN",
            ),
            ("(sAMAccountName={username})", "Windows logon name"),
            ("(userPrincipalName={username})", "User principal name"),
        ),
        "group_filter": (
            (
                "(member:1.2.840.113556.1.4.1941:={user_dn})",
                "Nested AD groups",
            ),
            ("(member={user_dn})", "Direct AD group member"),
        ),
    },
}


@dataclass(frozen=True)
class DirectoryProfile:
    provider: str
    enabled: bool
    server_urls: str
    use_starttls: bool
    verify_tls: bool
    ca_bundle: str
    bind_dn: str
    bind_password: str
    base_dn: str
    user_search_base: str
    user_filter: str
    user_attribute: str
    group_search_base: str
    group_filter: str
    required_admin_group: str
    timeout_seconds: int
    last_test_ok: bool
    last_test_ts: int
    last_test_detail: str
    updated_ts: int

    @property
    def label(self) -> str:
        return PROVIDER_LABELS.get(self.provider, self.provider)

    @property
    def has_bind_password(self) -> bool:
        return bool(self.bind_password)


@dataclass(frozen=True)
class DirectoryAuthResult:
    ok: bool
    provider: str
    username: str
    detail: str = ""
    groups: tuple[str, ...] = ()


@dataclass(frozen=True)
class DirectoryScanResult:
    provider: str
    base_dns: tuple[str, ...]
    user_search_bases: tuple[str, ...]
    group_search_bases: tuple[str, ...]
    admin_groups: tuple[str, ...]
    detail: str


class DirectoryAuthStore:
    def __init__(self, secret_provider: Callable[[], str] | None = None) -> None:
        self._secret_provider = secret_provider or (lambda: "")

    def _connect(self):
        return connect()

    def ensure_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS directory_auth_profiles (
                    provider VARCHAR(32) PRIMARY KEY,
                    enabled TINYINT(1) NOT NULL DEFAULT 0,
                    server_urls TEXT NOT NULL,
                    use_starttls TINYINT(1) NOT NULL DEFAULT 0,
                    verify_tls TINYINT(1) NOT NULL DEFAULT 1,
                    ca_bundle TEXT NOT NULL,
                    bind_dn TEXT NOT NULL,
                    bind_password TEXT NOT NULL,
                    base_dn TEXT NOT NULL,
                    user_search_base TEXT NOT NULL,
                    user_filter TEXT NOT NULL,
                    user_attribute VARCHAR(64) NOT NULL,
                    group_search_base TEXT NOT NULL,
                    group_filter TEXT NOT NULL,
                    required_admin_group TEXT NOT NULL,
                    timeout_seconds INT NOT NULL DEFAULT 5,
                    last_test_ok TINYINT(1) NOT NULL DEFAULT 0,
                    last_test_ts BIGINT NOT NULL DEFAULT 0,
                    last_test_detail TEXT NOT NULL,
                    updated_ts BIGINT NOT NULL
                )
                """,
            )

    def ensure_default_profiles(self) -> None:
        self.ensure_schema()
        now = int(time.time())
        for provider in DIRECTORY_PROVIDERS:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT provider FROM directory_auth_profiles WHERE provider = %s",
                    (provider,),
                ).fetchone()
                if row:
                    continue
                defaults = self.default_profile(provider)
                conn.execute(
                    """
                    INSERT INTO directory_auth_profiles(
                        provider, enabled, server_urls, use_starttls, verify_tls,
                        ca_bundle, bind_dn, bind_password, base_dn,
                        user_search_base, user_filter, user_attribute,
                        group_search_base, group_filter, required_admin_group,
                        timeout_seconds, last_test_ok, last_test_ts,
                        last_test_detail, updated_ts
                    ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """,
                    (
                        provider,
                        0,
                        defaults.server_urls,
                        int(defaults.use_starttls),
                        int(defaults.verify_tls),
                        defaults.ca_bundle,
                        defaults.bind_dn,
                        "",
                        defaults.base_dn,
                        defaults.user_search_base,
                        defaults.user_filter,
                        defaults.user_attribute,
                        defaults.group_search_base,
                        defaults.group_filter,
                        defaults.required_admin_group,
                        defaults.timeout_seconds,
                        0,
                        0,
                        "",
                        now,
                    ),
                )

    def default_profile(self, provider: str) -> DirectoryProfile:
        if provider == PROVIDER_ACTIVE_DIRECTORY:
            return DirectoryProfile(
                provider=provider,
                enabled=False,
                server_urls="ldaps://dc.example.local:636",
                use_starttls=False,
                verify_tls=True,
                ca_bundle="",
                bind_dn="svc-docker-proxy@example.local",
                bind_password="",
                base_dn="DC=example,DC=local",
                user_search_base="",
                user_filter="(|(sAMAccountName={username})(userPrincipalName={username}))",
                user_attribute="sAMAccountName",
                group_search_base="",
                group_filter="(member:1.2.840.113556.1.4.1941:={user_dn})",
                required_admin_group="CN=Docker Proxy Admins,OU=Groups,DC=example,DC=local",
                timeout_seconds=5,
                last_test_ok=False,
                last_test_ts=0,
                last_test_detail="",
                updated_ts=0,
            )
        return DirectoryProfile(
            provider=PROVIDER_LDAP,
            enabled=False,
            server_urls="ldaps://ldap.example.org:636",
            use_starttls=False,
            verify_tls=True,
            ca_bundle="",
            bind_dn="cn=proxy-bind,ou=service,dc=example,dc=org",
            bind_password="",
            base_dn="dc=example,dc=org",
            user_search_base="ou=people",
            user_filter="(uid={username})",
            user_attribute="uid",
            group_search_base="ou=groups",
            group_filter="(|(member={user_dn})(uniqueMember={user_dn})(memberUid={username}))",
            required_admin_group="cn=docker-proxy-admins,ou=groups,dc=example,dc=org",
            timeout_seconds=5,
            last_test_ok=False,
            last_test_ts=0,
            last_test_detail="",
            updated_ts=0,
        )

    def list_profiles(self) -> dict[str, DirectoryProfile]:
        self.ensure_default_profiles()
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT provider, enabled, server_urls, use_starttls, verify_tls,
                       ca_bundle, bind_dn, bind_password, base_dn,
                       user_search_base, user_filter, user_attribute,
                       group_search_base, group_filter, required_admin_group,
                       timeout_seconds, last_test_ok, last_test_ts,
                       last_test_detail, updated_ts
                FROM directory_auth_profiles
                ORDER BY provider ASC
                """,
            ).fetchall()
        return {str(row[0]): self._row_to_profile(row) for row in rows}

    def get_profile(self, provider: str) -> DirectoryProfile:
        provider = self._validate_provider(provider)
        profiles = self.list_profiles()
        return profiles.get(provider) or self.default_profile(provider)

    def get_active_profile(self) -> DirectoryProfile | None:
        profiles = self.list_profiles()
        enabled = [profile for profile in profiles.values() if profile.enabled]
        if len(enabled) != 1:
            return None
        return enabled[0]

    def get_status(self) -> dict[str, Any]:
        profiles = self.list_profiles()
        active = self.get_active_profile()
        return {
            "active_provider": active.provider if active else "local",
            "active_label": active.label if active else "Local accounts",
            "profiles": profiles,
            "providers": DIRECTORY_PROVIDERS,
            "provider_labels": PROVIDER_LABELS,
            "presets": DIRECTORY_PRESETS,
        }

    def save_profile(self, provider: str, payload: dict[str, Any]) -> DirectoryProfile:
        provider = self._validate_provider(provider)
        current = self.get_profile(provider)
        enabled = self._truthy(payload.get("enabled"))
        bind_password = str(payload.get("bind_password") or "")
        current_bind_password = self._decrypt(current.bind_password)
        stored_password = (
            current.bind_password
            if bind_password and bind_password == current_bind_password
            else self._encrypt(bind_password)
            if bind_password
            else current.bind_password
            if current.provider == provider
            else ""
        )
        timeout_seconds = self._bounded_int(payload.get("timeout_seconds"), 1, 30, 5)
        server_urls = self._normalize_server_urls(payload.get("server_urls"))
        use_starttls = self._truthy(payload.get("use_starttls"))
        verify_tls = self._truthy(payload.get("verify_tls"), default=current.verify_tls)
        ca_bundle = self._ca_bundle_from_payload(payload, current.ca_bundle)
        bind_dn = self._clean_required(payload.get("bind_dn"), "Bind DN/user")
        base_dn = self._clean_required(payload.get("base_dn"), "Base DN")
        user_search_base = str(payload.get("user_search_base") or "").strip()
        user_filter = self._preset_or_required(
            provider,
            "user_filter",
            payload.get("user_filter_preset"),
            payload.get("user_filter"),
            "User filter",
        )
        user_attribute = self._preset_or_required(
            provider,
            "user_attribute",
            payload.get("user_attribute_preset"),
            payload.get("user_attribute"),
            "User attribute",
        )
        group_search_base = str(payload.get("group_search_base") or "").strip()
        group_filter = self._preset_or_required(
            provider,
            "group_filter",
            payload.get("group_filter_preset"),
            payload.get("group_filter"),
            "Group filter",
        )
        required_admin_group = self._clean_required(
            payload.get("required_admin_group"),
            "Required admin group",
        )
        connection_changed = self._connection_settings_changed(
            current,
            server_urls=server_urls,
            use_starttls=use_starttls,
            verify_tls=verify_tls,
            ca_bundle=ca_bundle,
            bind_dn=bind_dn,
            bind_password=stored_password,
            base_dn=base_dn,
            user_search_base=user_search_base,
            user_filter=user_filter,
            user_attribute=user_attribute,
            group_search_base=group_search_base,
            group_filter=group_filter,
            required_admin_group=required_admin_group,
            timeout_seconds=timeout_seconds,
        )
        last_test_ok = current.last_test_ok and not connection_changed
        last_test_ts = current.last_test_ts if not connection_changed else 0
        last_test_detail = (
            current.last_test_detail
            if not connection_changed
            else "Configuration changed since the last successful test."
        )
        profile = DirectoryProfile(
            provider=provider,
            enabled=enabled,
            server_urls=server_urls,
            use_starttls=use_starttls,
            verify_tls=verify_tls,
            ca_bundle=ca_bundle,
            bind_dn=bind_dn,
            bind_password=stored_password,
            base_dn=base_dn,
            user_search_base=user_search_base,
            user_filter=user_filter,
            user_attribute=user_attribute,
            group_search_base=group_search_base,
            group_filter=group_filter,
            required_admin_group=required_admin_group,
            timeout_seconds=timeout_seconds,
            last_test_ok=last_test_ok,
            last_test_ts=last_test_ts,
            last_test_detail=last_test_detail,
            updated_ts=int(time.time()),
        )
        if profile.enabled:
            if not self._decrypt(profile.bind_password):
                msg = "Bind password is required before enabling a directory provider."
                raise ValueError(msg)
            if not profile.last_test_ok:
                msg = "Test the directory provider successfully before enabling it."
                raise ValueError(msg)
        self.ensure_default_profiles()
        with self._connect() as conn:
            if profile.enabled:
                conn.execute(
                    "UPDATE directory_auth_profiles SET enabled = 0 WHERE provider <> %s",
                    (profile.provider,),
                )
            conn.execute(
                """
                UPDATE directory_auth_profiles
                   SET enabled = %s, server_urls = %s, use_starttls = %s,
                       verify_tls = %s, ca_bundle = %s, bind_dn = %s,
                       bind_password = %s, base_dn = %s, user_search_base = %s,
                       user_filter = %s, user_attribute = %s,
                       group_search_base = %s, group_filter = %s,
                       required_admin_group = %s, timeout_seconds = %s,
                       last_test_ok = %s, last_test_ts = %s,
                       last_test_detail = %s, updated_ts = %s
                 WHERE provider = %s
                """,
                (
                    int(profile.enabled),
                    profile.server_urls,
                    int(profile.use_starttls),
                    int(profile.verify_tls),
                    profile.ca_bundle,
                    profile.bind_dn,
                    profile.bind_password,
                    profile.base_dn,
                    profile.user_search_base,
                    profile.user_filter,
                    profile.user_attribute,
                    profile.group_search_base,
                    profile.group_filter,
                    profile.required_admin_group,
                    profile.timeout_seconds,
                    int(profile.last_test_ok),
                    profile.last_test_ts,
                    profile.last_test_detail,
                    profile.updated_ts,
                    profile.provider,
                ),
            )
        return self.get_profile(provider)

    def disable_provider(self, provider: str) -> None:
        provider = self._validate_provider(provider)
        self.ensure_default_profiles()
        with self._connect() as conn:
            conn.execute(
                "UPDATE directory_auth_profiles SET enabled = 0, updated_ts = %s WHERE provider = %s",
                (int(time.time()), provider),
            )

    def record_test(self, provider: str, *, ok: bool, detail: str) -> None:
        provider = self._validate_provider(provider)
        self.ensure_default_profiles()
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE directory_auth_profiles
                   SET last_test_ok = %s, last_test_ts = %s, last_test_detail = %s
                 WHERE provider = %s
                """,
                (int(ok), int(time.time()), str(detail or "")[:2000], provider),
            )

    def test_connection(self, provider: str) -> DirectoryAuthResult:
        profile = self.get_profile(provider)
        conn = None
        try:
            conn, _ldap3 = self._service_connection(profile)
        except Exception as exc:
            detail = self._public_error(exc)
            self.record_test(provider, ok=False, detail=detail)
            return DirectoryAuthResult(False, profile.provider, "", detail=detail)
        finally:
            self._safe_unbind(conn)
        detail = "Directory bind and base search succeeded."
        self.record_test(provider, ok=True, detail=detail)
        return DirectoryAuthResult(True, profile.provider, "", detail=detail)

    def scan_directory(self, provider: str) -> DirectoryScanResult:
        profile = self.get_profile(provider)
        conn = None
        try:
            conn, _ldap3 = self._service_connection(profile)
            base_dn = self._join_dn("", profile.base_dn)
            ous = self._scan_dns(
                conn,
                base_dn,
                "(objectClass=organizationalUnit)",
                ("ou", "distinguishedName"),
                200,
            )
            containers = self._scan_dns(
                conn,
                base_dn,
                "(objectClass=container)",
                ("cn", "distinguishedName"),
                100,
            )
            groups = self._scan_dns(
                conn,
                base_dn,
                "(|(objectClass=group)(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup))",
                ("cn", "distinguishedName"),
                300,
            )
        finally:
            self._safe_unbind(conn)
        search_bases = tuple(self._relative_dn(item, base_dn) for item in ous)
        group_bases = tuple(
            self._relative_dn(item, base_dn) for item in (*ous, *containers)
        )
        detail = (
            f"Directory scan found {len(search_bases)} OU/container choices and "
            f"{len(groups)} group choices under {base_dn}."
        )
        return DirectoryScanResult(
            provider=profile.provider,
            base_dns=(base_dn,),
            user_search_bases=tuple(dict.fromkeys(filter(None, search_bases))),
            group_search_bases=tuple(dict.fromkeys(filter(None, group_bases))),
            admin_groups=groups,
            detail=detail,
        )

    def authenticate_admin(self, username: str, password: str) -> DirectoryAuthResult:
        profile = self.get_active_profile()
        if profile is None:
            return DirectoryAuthResult(
                False, "local", username, "No active directory provider."
            )
        return self.authenticate(profile, username, password)

    def authenticate(
        self,
        profile: DirectoryProfile,
        username: str,
        password: str,
    ) -> DirectoryAuthResult:
        username = (username or "").strip()
        if not username or not password:
            return DirectoryAuthResult(
                False, profile.provider, username, "Username and password are required."
            )
        conn = None
        try:
            conn, ldap3 = self._service_connection(profile)
            escape_filter_chars = ldap3.utils.conv.escape_filter_chars
            user_filter = profile.user_filter.format(
                username=escape_filter_chars(username),
            )
            user_base = self._join_dn(profile.user_search_base, profile.base_dn)
            if not conn.search(
                user_base,
                user_filter,
                attributes=[profile.user_attribute, "dn"],
                size_limit=2,
            ):
                return DirectoryAuthResult(
                    False, profile.provider, username, "Directory user was not found."
                )
            entries = list(conn.entries)
            if len(entries) != 1:
                return DirectoryAuthResult(
                    False,
                    profile.provider,
                    username,
                    "Directory user lookup was ambiguous.",
                )
            user_dn = str(entries[0].entry_dn)
            if not self._user_bind(profile, user_dn, password):
                return DirectoryAuthResult(
                    False,
                    profile.provider,
                    username,
                    "Directory password check failed.",
                )
            groups = self._groups_for_user(profile, conn, user_dn, username, ldap3)
            if not self._required_group_matches(profile.required_admin_group, groups):
                return DirectoryAuthResult(
                    False,
                    profile.provider,
                    username,
                    "User is not in the required admin group.",
                )
            return DirectoryAuthResult(
                True,
                profile.provider,
                username,
                "Directory authentication succeeded.",
                tuple(groups),
            )
        except Exception as exc:
            log_exception_throttled(
                logger,
                f"directory_auth.authenticate.{profile.provider}",
                interval_seconds=300.0,
                message="Directory authentication failed",
            )
            return DirectoryAuthResult(
                False, profile.provider, username, self._public_error(exc)
            )
        finally:
            self._safe_unbind(conn)

    def _groups_for_user(
        self,
        profile: DirectoryProfile,
        conn: Any,
        user_dn: str,
        username: str,
        ldap3: Any,
    ) -> list[str]:
        escape_filter_chars = ldap3.utils.conv.escape_filter_chars
        group_filter = profile.group_filter.format(
            user_dn=escape_filter_chars(user_dn),
            username=escape_filter_chars(username),
        )
        group_base = self._join_dn(profile.group_search_base, profile.base_dn)
        if not conn.search(
            group_base,
            group_filter,
            attributes=["cn", "distinguishedName", "member"],
            size_limit=200,
        ):
            return []
        groups: list[str] = []
        for entry in conn.entries:
            groups.append(str(entry.entry_dn))
            cn = getattr(entry, "cn", None)
            if cn:
                groups.append(str(cn))
        return sorted({item for item in groups if item})

    def _service_connection(self, profile: DirectoryProfile) -> tuple[Any, Any]:
        try:
            import ldap3
        except Exception as exc:
            msg = "ldap3 package is not installed in the admin-ui container."
            raise RuntimeError(msg) from exc
        last_exc: Exception | None = None
        for server_url in self._server_urls(profile.server_urls):
            conn = None
            try:
                tls = self._tls_config(profile, server_url, ldap3)
                server = ldap3.Server(
                    server_url,
                    connect_timeout=profile.timeout_seconds,
                    get_info=ldap3.NONE,
                    tls=tls,
                )
                conn = ldap3.Connection(
                    server,
                    user=profile.bind_dn,
                    password=self._decrypt(profile.bind_password),
                    auto_bind=False,
                    receive_timeout=profile.timeout_seconds,
                    raise_exceptions=True,
                )
                conn.open()
                if self._should_start_tls(profile, server_url):
                    conn.start_tls()
                conn.bind()
                base_dn = self._join_dn("", profile.base_dn)
                conn.search(base_dn, "(objectClass=*)", attributes=["dn"], size_limit=1)
                return conn, ldap3
            except Exception as exc:
                last_exc = exc
                self._safe_unbind(conn)
        if last_exc is not None:
            msg = f"All configured LDAP server URLs failed; last error: {self._public_error(last_exc)}"
            raise RuntimeError(msg) from last_exc
        msg = "At least one LDAP server URL is required."
        raise ValueError(msg)

    def _user_bind(
        self, profile: DirectoryProfile, user_dn: str, password: str
    ) -> bool:
        try:
            import ldap3

            server_urls = self._server_urls(profile.server_urls)
        except Exception:
            return False
        for server_url in server_urls:
            conn = None
            try:
                tls = self._tls_config(profile, server_url, ldap3)
                server = ldap3.Server(
                    server_url,
                    connect_timeout=profile.timeout_seconds,
                    get_info=ldap3.NONE,
                    tls=tls,
                )
                conn = ldap3.Connection(
                    server,
                    user=user_dn,
                    password=password,
                    auto_bind=False,
                    receive_timeout=profile.timeout_seconds,
                    raise_exceptions=True,
                )
                conn.open()
                if self._should_start_tls(profile, server_url):
                    conn.start_tls()
                conn.bind()
                return True
            except Exception:
                continue
            finally:
                self._safe_unbind(conn)
        return False

    def _tls_config(
        self, profile: DirectoryProfile, server_url: str, ldap3: Any
    ) -> Any:
        if not (server_url.lower().startswith("ldaps://") or profile.use_starttls):
            return None
        import ssl

        tls_kwargs = {
            "validate": ssl.CERT_REQUIRED if profile.verify_tls else ssl.CERT_NONE
        }
        if profile.ca_bundle.strip():
            tls_kwargs["ca_certs_data"] = profile.ca_bundle
        return ldap3.Tls(**tls_kwargs)

    def _should_start_tls(self, profile: DirectoryProfile, server_url: str) -> bool:
        return profile.use_starttls and not server_url.lower().startswith("ldaps://")

    def _safe_unbind(self, conn: Any) -> None:
        if conn is None:
            return
        with contextlib.suppress(Exception):
            conn.unbind()

    def _row_to_profile(self, row: Any) -> DirectoryProfile:
        return DirectoryProfile(
            provider=str(row[0]),
            enabled=bool(row[1]),
            server_urls=str(row[2] or ""),
            use_starttls=bool(row[3]),
            verify_tls=bool(row[4]),
            ca_bundle=str(row[5] or ""),
            bind_dn=str(row[6] or ""),
            bind_password=str(row[7] or ""),
            base_dn=str(row[8] or ""),
            user_search_base=str(row[9] or ""),
            user_filter=str(row[10] or ""),
            user_attribute=str(row[11] or ""),
            group_search_base=str(row[12] or ""),
            group_filter=str(row[13] or ""),
            required_admin_group=str(row[14] or ""),
            timeout_seconds=int(row[15] or 5),
            last_test_ok=bool(row[16]),
            last_test_ts=int(row[17] or 0),
            last_test_detail=str(row[18] or ""),
            updated_ts=int(row[19] or 0),
        )

    def _fernet(self) -> Fernet:
        secret = (self._secret_provider() or "").encode()
        key = base64.urlsafe_b64encode(hashlib.sha256(secret).digest())
        return Fernet(key)

    def _encrypt(self, value: str) -> str:
        return "enc:v1:" + self._fernet().encrypt(value.encode()).decode()

    def _decrypt(self, value: str) -> str:
        if not value:
            return ""
        if not value.startswith("enc:v1:"):
            return value
        try:
            return (
                self._fernet().decrypt(value.removeprefix("enc:v1:").encode()).decode()
            )
        except InvalidToken:
            return ""

    def _connection_settings_changed(
        self, current: DirectoryProfile, **values: Any
    ) -> bool:
        return any(getattr(current, key) != value for key, value in values.items())

    def _validate_provider(self, provider: str) -> str:
        provider = (provider or "").strip()
        if provider not in DIRECTORY_PROVIDERS:
            msg = "Unknown directory provider."
            raise ValueError(msg)
        return provider

    def _clean_required(self, value: Any, label: str) -> str:
        cleaned = str(value or "").strip()
        if not cleaned:
            msg = f"{label} is required."
            raise ValueError(msg)
        return cleaned

    def _normalize_server_urls(self, value: Any) -> str:
        invalid_url_msg = (
            "LDAP server URLs must be valid ldap:// or ldaps:// URLs with a host "
            "and optional numeric port."
        )
        urls = []
        for raw_line in str(value or "").splitlines():
            source = raw_line.strip()
            if not source:
                continue
            if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in source):
                raise ValueError(invalid_url_msg)
            try:
                parsed = urlsplit(source)
                hostname = parsed.hostname or ""
                port = parsed.port
            except ValueError as exc:
                raise ValueError(invalid_url_msg) from exc
            if parsed.scheme not in {"ldap", "ldaps"}:
                msg = "Only ldap:// or ldaps:// directory server URLs are supported."
                raise ValueError(msg)
            if (
                not parsed.netloc
                or not hostname
                or parsed.username
                or parsed.password
                or parsed.path
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError(invalid_url_msg)
            url = f"{parsed.scheme}://{hostname}"
            if port is not None:
                url = f"{url}:{port}"
            urls.append(url)
        if not urls:
            msg = "At least one LDAP server URL is required."
            raise ValueError(msg)
        return "\n".join(urls)

    def _ca_bundle_from_payload(
        self, payload: dict[str, Any], current_ca_bundle: str
    ) -> str:
        uploaded = payload.get("ca_bundle_upload")
        if isinstance(uploaded, bytes) and uploaded:
            return self.normalize_ca_bundle(uploaded)
        text = str(payload.get("ca_bundle") or "").strip()
        if text:
            return self.normalize_ca_bundle(text.encode())
        if self._truthy(payload.get("clear_ca_bundle")):
            return ""
        return current_ca_bundle

    def _preset_or_required(
        self,
        provider: str,
        preset_group: str,
        selected: Any,
        fallback: Any,
        label: str,
    ) -> str:
        selected_value = str(selected or "").strip()
        allowed = {
            value
            for value, _label in DIRECTORY_PRESETS.get(provider, {}).get(
                preset_group, ()
            )
        }
        if selected_value and selected_value != "custom":
            if selected_value not in allowed:
                msg = f"Unknown {label.lower()} preset."
                raise ValueError(msg)
            return selected_value
        return self._clean_required(fallback, label)

    def _scan_dns(
        self,
        conn: Any,
        base_dn: str,
        search_filter: str,
        attributes: tuple[str, ...],
        size_limit: int,
    ) -> tuple[str, ...]:
        try:
            found = conn.search(
                base_dn,
                search_filter,
                attributes=list(attributes),
                size_limit=size_limit,
            )
        except Exception:
            return ()
        if not found:
            return ()
        dns = []
        for entry in getattr(conn, "entries", ()):
            dn = str(getattr(entry, "entry_dn", "") or "").strip()
            if dn:
                dns.append(dn)
        return tuple(sorted(dict.fromkeys(dns), key=str.casefold))

    def _relative_dn(self, dn: str, base_dn: str) -> str:
        dn = (dn or "").strip().strip(",")
        base_dn = (base_dn or "").strip().strip(",")
        if not dn or not base_dn:
            return dn
        suffix = "," + base_dn
        if dn.casefold().endswith(suffix.casefold()):
            return dn[: -len(suffix)]
        if dn.casefold() == base_dn.casefold():
            return ""
        return dn

    def _bounded_int(self, value: Any, low: int, high: int, default: int) -> int:
        try:
            parsed = int(str(value or "").strip())
        except Exception:
            parsed = default
        return max(low, min(high, parsed))

    def _truthy(self, value: Any, *, default: bool = False) -> bool:
        if value is None:
            return default
        return str(value).strip().lower() in {"1", "true", "yes", "on"}

    def _server_urls(self, value: str) -> list[str]:
        urls = [line.strip() for line in (value or "").splitlines() if line.strip()]
        if not urls:
            msg = "At least one LDAP server URL is required."
            raise ValueError(msg)
        return urls

    def _first_server_url(self, value: str) -> str:
        return self._server_urls(value)[0]

    def _join_dn(self, child: str, base: str) -> str:
        child = (child or "").strip().strip(",")
        base = (base or "").strip().strip(",")
        if not child:
            return base
        if child.lower().endswith(base.lower()):
            return child
        return f"{child},{base}" if base else child

    def _required_group_matches(self, required_group: str, groups: list[str]) -> bool:
        required = (required_group or "").strip().casefold()
        if not required:
            return False
        return any(group.casefold() == required for group in groups)

    def _public_error(self, exc: Exception) -> str:
        detail = re.sub(
            r"password=[^,\\s]+", "password=<redacted>", str(exc), flags=re.IGNORECASE
        )
        return detail[:500] or exc.__class__.__name__

    @staticmethod
    def normalize_ca_bundle(raw_bytes: bytes) -> str:
        if not raw_bytes:
            msg = "Uploaded CA certificate file was empty."
            raise ValueError(msg)
        blocks = []
        text = raw_bytes.decode("utf-8", errors="ignore")
        for match in re.finditer(
            r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----",
            text,
            flags=re.DOTALL,
        ):
            block = match.group(0).strip().encode()
            cert = x509.load_pem_x509_certificate(block)
            blocks.append(
                cert.public_bytes(serialization.Encoding.PEM).decode().strip()
            )
        if not blocks:
            try:
                cert = x509.load_der_x509_certificate(raw_bytes)
            except Exception as exc:
                msg = "Uploaded CA certificate must be PEM or DER X.509 material."
                raise ValueError(msg) from exc
            blocks.append(
                cert.public_bytes(serialization.Encoding.PEM).decode().strip()
            )
        return "\n".join(blocks) + "\n"


_directory_auth_store: DirectoryAuthStore | None = None


def get_directory_auth_store(
    secret_provider: Callable[[], str] | None = None,
) -> DirectoryAuthStore:
    global _directory_auth_store
    if _directory_auth_store is None:
        _directory_auth_store = DirectoryAuthStore(secret_provider)
    return _directory_auth_store
