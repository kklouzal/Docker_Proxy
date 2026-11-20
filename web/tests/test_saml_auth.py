from __future__ import annotations

import json
import sys
import time
from dataclasses import replace
from types import SimpleNamespace

import pymysql
import pytest
from services import saml_auth
from services.saml_auth import (
    SamlAuthStore,
    build_saml_settings,
    build_sp_info,
    parse_saml_metadata,
    prepare_flask_request,
    resolve_saml_login,
)

from .clock_patching import patch_module_clock

SIGNING_CERT = "MIICsigningCERTvalue"
ENCRYPTION_CERT = "MIICencryptionCERTvalue"
ENTITY_METADATA = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE EntityDescriptor [
  <!ENTITY injected "https://evil.example/idp">
]>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="&injected;">
</EntityDescriptor>
"""


SAMPLE_METADATA = f"""<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
    entityID="https://adfs.example.local/adfs/services/trust"
    validUntil="2030-01-02T03:04:05Z"
    cacheDuration="PT6H">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>
            {SIGNING_CERT}
          </ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </KeyDescriptor>
    <KeyDescriptor use="encryption">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>{ENCRYPTION_CERT}</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </KeyDescriptor>
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
    <SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="https://adfs.example.local/adfs/ls/" />
    <SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="https://adfs.example.local/adfs/ls/post" />
    <SingleLogoutService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="https://adfs.example.local/adfs/ls/?wa=wsignout1.0" />
  </IDPSSODescriptor>
</EntityDescriptor>
"""


def _metadata_with_service_locations(
    *,
    sso_location: str = "https://adfs.example.local/adfs/ls/",
    slo_location: str = "https://adfs.example.local/adfs/ls/?wa=wsignout1.0",
) -> str:
    return SAMPLE_METADATA.replace(
        'Location="https://adfs.example.local/adfs/ls/"',
        f'Location="{sso_location}"',
        1,
    ).replace(
        'Location="https://adfs.example.local/adfs/ls/?wa=wsignout1.0"',
        f'Location="{slo_location}"',
        1,
    )


class MemorySamlAuthStore(SamlAuthStore):
    def __init__(self) -> None:
        self.profile = self.default_profile()

    def ensure_schema(self) -> None:
        return None

    def ensure_default_profile(self) -> None:
        return None

    def get_profile(self):
        return self.profile

    def _persist(self, profile):
        self.profile = profile

    def record_metadata_refresh(self, profile, *, raw_xml, parsed) -> None:
        now = int(time.time())
        self.profile = type(profile)(
            provider=profile.provider,
            enabled=profile.enabled,
            metadata_url=profile.metadata_url,
            require_https=profile.require_https,
            verify_tls=profile.verify_tls,
            ca_bundle=profile.ca_bundle,
            timeout_seconds=profile.timeout_seconds,
            max_metadata_bytes=profile.max_metadata_bytes,
            raw_metadata_xml=raw_xml,
            parsed_metadata_json=json.dumps(parsed, sort_keys=True),
            entity_id=parsed["entity_id"],
            fetched_ts=now,
            cache_expires_ts=now + parsed["cache_duration_seconds"],
            valid_until_ts=parsed["valid_until_ts"],
            last_refresh_ok=True,
            last_refresh_ts=now,
            last_refresh_detail="SAML IdP metadata refreshed successfully.",
            public_base_url=profile.public_base_url,
            username_attribute=profile.username_attribute,
            groups_attribute=profile.groups_attribute,
            required_group=profile.required_group,
            updated_ts=now,
            refresh_failures=0,
            next_refresh_ts=saml_auth._next_scheduled_refresh_ts(
                fetched_ts=now,
                cache_expires_ts=now + parsed["cache_duration_seconds"],
                valid_until_ts=parsed["valid_until_ts"],
            ),
        )
        return True

    def record_refresh_status(
        self, *, ok: bool, detail: str, refresh_failures: int, next_refresh_ts: int
    ) -> None:
        self.profile = replace(
            self.profile,
            last_refresh_ok=ok,
            last_refresh_ts=int(time.time()),
            last_refresh_detail=detail,
            refresh_failures=refresh_failures,
            next_refresh_ts=next_refresh_ts,
        )


def _saml_request(url: str, *, scheme: str = "https", server_port: str = ""):
    root = url.split("://", 1)[1].split("/", 1)[0]
    host = root
    return SimpleNamespace(
        url=url,
        url_root=f"{scheme}://{root}/",
        scheme=scheme,
        host=host,
        path="/auth/saml/login",
        args={},
        form={},
        query_string=b"",
        environ={"SERVER_PORT": server_port} if server_port else {},
    )


def test_ensure_schema_propagates_lifecycle_probe_failure_without_runtime_ddl(
    monkeypatch,
) -> None:
    class SchemaReadinessProbeError(RuntimeError):
        pass

    probe_error = SchemaReadinessProbeError("schema readiness query failed")

    class FailingProbeConnection:
        def __init__(self) -> None:
            self.ops: list[str] = []

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def execute(self, sql, params=()):
            text = " ".join(str(sql).split())
            self.ops.append(text)
            if text.startswith(
                "SELECT version, name, checksum, status, error FROM schema_migrations"
            ):
                raise probe_error
            msg = f"fallback DDL must not follow a failed readiness probe: {text}"
            raise AssertionError(msg)

    conn = FailingProbeConnection()
    store = SamlAuthStore()
    monkeypatch.setattr(store, "_connect", lambda: conn)

    with pytest.raises(SchemaReadinessProbeError) as caught:
        store.ensure_schema()

    assert caught.value is probe_error
    assert store._schema_ready is False
    assert len(conn.ops) == 1
    assert not any(op.startswith(("CREATE TABLE", "ALTER TABLE")) for op in conn.ops)


class _FallbackSchemaConnection:
    def __init__(self) -> None:
        self.ops: list[str] = []

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def execute(self, sql, params=()):
        text = " ".join(str(sql).split())
        self.ops.append(text)
        if text.startswith(
            "SELECT version, name, checksum, status, error FROM schema_migrations"
        ):
            return SimpleNamespace(fetchall=list)
        if text.startswith(
            (
                "CREATE TABLE IF NOT EXISTS saml_auth_profiles",
                "CREATE TABLE IF NOT EXISTS saml_assertion_replay",
            )
        ):
            return SimpleNamespace(fetchone=lambda: None)
        if "FROM information_schema.columns" in text:
            return SimpleNamespace(fetchone=lambda: {"exists": 1})
        msg = f"unexpected fallback schema SQL: {text}"
        raise AssertionError(msg)


def test_ensure_schema_preserves_fallback_when_lifecycle_is_not_current(
    monkeypatch,
) -> None:
    conn = _FallbackSchemaConnection()
    store = SamlAuthStore()
    monkeypatch.setattr(store, "_connect", lambda: conn)

    store.ensure_schema()

    assert store._schema_ready is True
    assert any(
        op.startswith("CREATE TABLE IF NOT EXISTS saml_auth_profiles")
        for op in conn.ops
    )
    assert any(
        op.startswith("CREATE TABLE IF NOT EXISTS saml_assertion_replay")
        for op in conn.ops
    )
    assert not any(op.startswith("ALTER TABLE") for op in conn.ops)


def test_ensure_schema_fails_closed_when_lifecycle_module_is_unavailable(
    monkeypatch,
) -> None:
    conn = _FallbackSchemaConnection()
    store = SamlAuthStore()
    monkeypatch.setattr(store, "_connect", lambda: conn)
    monkeypatch.setitem(sys.modules, "services.schema_lifecycle", None)

    with pytest.raises(ModuleNotFoundError):
        store.ensure_schema()

    assert store._schema_ready is False
    assert conn.ops == []


class FakeSamlToolkit:
    def __init__(
        self,
        *,
        ok: bool = True,
        groups: list[str] | None = None,
        username: str = "saml-user@example.test",
    ) -> None:
        self.ok = ok
        self.groups = groups or ["AdminGroup"]
        self.username = username

    def get_errors(self):
        return [] if self.ok else ["invalid_response"]

    def get_last_error_reason(self):
        return "signature validation failed" if not self.ok else ""

    def is_authenticated(self) -> bool:
        return self.ok

    def get_attributes(self):
        return {"email": [self.username], "groups": self.groups}

    def get_nameid(self):
        return "nameid@example.test"

    def get_session_index(self):
        return "SESSION-1"


def test_build_sp_info_requires_explicit_public_base_url() -> None:
    profile = replace(
        MemorySamlAuthStore().default_profile(),
        public_base_url="",
    )

    with pytest.raises(ValueError, match="public admin base URL must be configured"):
        build_sp_info(
            profile,
        )


def test_build_sp_info_ignores_host_when_public_base_url_configured() -> None:
    profile = replace(
        MemorySamlAuthStore().default_profile(),
        public_base_url="https://admin.example.test/base",
    )

    sp = build_sp_info(
        profile,
    )

    assert sp == {
        "entity_id": "https://admin.example.test/base/auth/saml/metadata",
        "acs_url": "https://admin.example.test/base/auth/saml/acs",
        "sls_url": "https://admin.example.test/base/auth/saml/sls",
    }


def test_build_saml_settings_rejects_host_derived_service_provider_urls() -> None:
    profile = replace(
        MemorySamlAuthStore().default_profile(),
        public_base_url="",
        raw_metadata_xml=SAMPLE_METADATA,
        parsed_metadata_json=json.dumps(parse_saml_metadata(SAMPLE_METADATA)),
        last_refresh_ok=True,
    )

    with pytest.raises(ValueError, match="public admin base URL must be configured"):
        build_saml_settings(
            profile,
        )


def test_prepare_flask_request_uses_default_https_port_when_url_omits_port() -> None:
    request_data = prepare_flask_request(
        _saml_request("https://admin.example.test/auth/saml/login")
    )

    assert request_data["server_port"] == "443"


def test_prepare_flask_request_preserves_explicit_url_port() -> None:
    request_data = prepare_flask_request(
        _saml_request("https://admin.example.test:8443/auth/saml/login")
    )

    assert request_data["server_port"] == "8443"


def test_parse_saml_metadata_extracts_adfs_metadata() -> None:
    parsed = parse_saml_metadata(SAMPLE_METADATA)

    assert parsed["entity_id"] == "https://adfs.example.local/adfs/services/trust"
    assert parsed["cache_duration_seconds"] == 21600
    assert parsed["valid_until_ts"] > 0
    assert (
        parsed["sso_services"][0]["location"] == "https://adfs.example.local/adfs/ls/"
    )
    assert parsed["slo_services"][0]["binding"].endswith(":HTTP-Redirect")
    assert parsed["signing_certs"] == [SIGNING_CERT]
    assert parsed["encryption_certs"] == [ENCRYPTION_CERT]
    assert parsed["name_id_formats"] == [
        "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    ]
    assert parsed["settings"]["idp"]["x509certMulti"] == {
        "signing": [SIGNING_CERT],
        "encryption": [ENCRYPTION_CERT],
    }


def test_parse_saml_metadata_finds_nested_idp_entity_descriptor() -> None:
    nested_metadata = f"""<?xml version="1.0" encoding="UTF-8"?>
<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <EntitiesDescriptor Name="federation">
    <EntityDescriptor entityID="https://sp.example.test/metadata">
      <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/>
    </EntityDescriptor>
    <EntityDescriptor entityID="https://idp.example.test/metadata">
      <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <KeyDescriptor use="signing">
          <ds:KeyInfo>
            <ds:X509Data>
              <ds:X509Certificate>{SIGNING_CERT}</ds:X509Certificate>
            </ds:X509Data>
          </ds:KeyInfo>
        </KeyDescriptor>
        <SingleSignOnService
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            Location="https://idp.example.test/sso" />
      </IDPSSODescriptor>
    </EntityDescriptor>
  </EntitiesDescriptor>
</EntitiesDescriptor>
"""

    parsed = parse_saml_metadata(nested_metadata)

    assert parsed["entity_id"] == "https://idp.example.test/metadata"
    assert parsed["sso_services"] == [
        {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            "location": "https://idp.example.test/sso",
        }
    ]


def test_parse_saml_metadata_requires_idp_sso_descriptor() -> None:
    metadata = """<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
        entityID="https://idp.example"></EntityDescriptor>"""

    with pytest.raises(ValueError, match="IDPSSODescriptor"):
        parse_saml_metadata(metadata)


def test_parse_saml_metadata_rejects_dtd_entities_safely() -> None:
    with pytest.raises(ValueError) as exc_info:
        parse_saml_metadata(ENTITY_METADATA)

    message = str(exc_info.value)
    assert (
        message == "SAML metadata XML contains disallowed DTD or entity declarations."
    )
    assert "injected" not in message
    assert "evil.example" not in message
    assert "EntityDescriptor [" not in message


@pytest.mark.parametrize(
    "group_claim",
    [
        "Domain Admins",
        "EXAMPLE\\Domain Admins",
        "Domain Admins@example.local",
        "CN=Domain Admins,CN=Users,DC=example,DC=local",
        "cn=Domain Admins,ou=Groups,dc=example,dc=local",
        r"CN=Domain\20Admins,CN=Users,DC=example,DC=local",
    ],
)
def test_resolve_saml_login_allows_safe_adfs_and_ldap_group_forms(
    group_claim: str,
) -> None:
    profile = replace(
        MemorySamlAuthStore().default_profile(),
        username_attribute="email",
        groups_attribute="groups",
        required_group="Domain Admins",
    )

    result = resolve_saml_login(FakeSamlToolkit(groups=[group_claim]), profile)

    assert result.ok is True
    assert result.username == "saml-user@example.test"


@pytest.mark.parametrize(
    "group_claim",
    [
        "Not Domain Admins",
        "EXAMPLE\\Not Domain Admins",
        "Not Domain Admins@example.local",
        "CN=Not Domain Admins,CN=Users,DC=example,DC=local",
        "CN=Domain Admins Backup,CN=Users,DC=example,DC=local",
        "prefix-Domain Admins-suffix",
    ],
)
def test_resolve_saml_login_rejects_confusing_required_group_near_matches(
    group_claim: str,
) -> None:
    profile = replace(
        MemorySamlAuthStore().default_profile(),
        username_attribute="email",
        groups_attribute="groups",
        required_group="Domain Admins",
    )

    result = resolve_saml_login(FakeSamlToolkit(groups=[group_claim]), profile)

    assert result.ok is False
    assert result.detail == "SAML user is missing the required admin group."


def test_saml_profile_requires_successful_metadata_refresh_before_enable() -> None:
    store = MemorySamlAuthStore()

    with pytest.raises(ValueError, match="Refresh SAML metadata successfully"):
        store.save_profile(
            {
                "enabled": "1",
                "metadata_url": "https://adfs.example.local/FederationMetadata/2007-06/FederationMetadata.xml",
                "public_base_url": "https://admin.example.test",
            }
        )

    saved = store.save_profile(
        {
            "metadata_url": "https://adfs.example.local/FederationMetadata/2007-06/FederationMetadata.xml",
        }
    )
    parsed = parse_saml_metadata(SAMPLE_METADATA)
    store.record_metadata_refresh(saved, raw_xml=SAMPLE_METADATA, parsed=parsed)
    enabled = store.save_profile(
        {
            "enabled": "1",
            "metadata_url": "https://adfs.example.local/FederationMetadata/2007-06/FederationMetadata.xml",
            "public_base_url": "https://admin.example.test",
        }
    )

    assert enabled.enabled is True
    assert enabled.last_refresh_ok is True
    assert enabled.entity_id == "https://adfs.example.local/adfs/services/trust"


def test_saml_profile_requires_current_metadata_cache_before_enable() -> None:
    store = MemorySamlAuthStore()
    saved = store.save_profile(
        {
            "metadata_url": "https://adfs.example.local/FederationMetadata/2007-06/FederationMetadata.xml",
        }
    )
    parsed = parse_saml_metadata(SAMPLE_METADATA)
    store.record_metadata_refresh(saved, raw_xml=SAMPLE_METADATA, parsed=parsed)
    store.profile = replace(store.profile, cache_expires_ts=int(time.time()) - 1)

    with pytest.raises(ValueError, match="Refresh SAML metadata successfully"):
        store.save_profile(
            {
                "enabled": "1",
                "metadata_url": "https://adfs.example.local/FederationMetadata/2007-06/FederationMetadata.xml",
                "public_base_url": "https://admin.example.test",
            }
        )

    saved_disabled = store.save_profile(
        {
            "enabled": "0",
            "metadata_url": "https://adfs.example.local/FederationMetadata/2007-06/FederationMetadata.xml",
        }
    )
    assert saved_disabled.enabled is False
    assert saved_disabled.last_refresh_ok is True


def test_saml_profile_requires_unexpired_metadata_valid_until_before_enable() -> None:
    store = MemorySamlAuthStore()
    saved = store.save_profile(
        {
            "metadata_url": "https://adfs.example.local/FederationMetadata/2007-06/FederationMetadata.xml",
        }
    )
    parsed = parse_saml_metadata(SAMPLE_METADATA)
    store.record_metadata_refresh(saved, raw_xml=SAMPLE_METADATA, parsed=parsed)
    store.profile = replace(store.profile, valid_until_ts=int(time.time()) - 1)

    with pytest.raises(ValueError, match="Refresh SAML metadata successfully"):
        store.save_profile(
            {
                "enabled": "1",
                "metadata_url": "https://adfs.example.local/FederationMetadata/2007-06/FederationMetadata.xml",
                "public_base_url": "https://admin.example.test",
            }
        )


def test_saml_profile_https_is_required_by_default() -> None:
    store = MemorySamlAuthStore()

    with pytest.raises(ValueError, match="https://"):
        store.save_profile({"metadata_url": "http://adfs.example.local/metadata.xml"})


@pytest.mark.parametrize(
    "metadata_url",
    [
        "https://adfs.example.local/adfs/%255cls",
        "https://adfs.example.local/adfs/ls?Relay=%250aInjected",
        "https://adfs.example.local%252f.evil/adfs/ls",
    ],
)
def test_saml_profile_rejects_double_encoded_unsafe_metadata_urls(
    metadata_url: str,
) -> None:
    store = MemorySamlAuthStore()

    with pytest.raises(
        ValueError,
        match="encoded whitespace, control characters, or backslashes",
    ):
        store.save_profile({"metadata_url": metadata_url})


@pytest.mark.parametrize(
    "metadata_url",
    [
        "https://adfs.example.local\\@evil.example/metadata.xml",
        "https://adfs.example.local%2fevil.example/metadata.xml",
        "https://adfs.example.local/%5cmetadata.xml",
        "https://adfs.example.local/metadata.xml?next=%0d%0aHost:evil.example",
        "https://adfs.example.local/metadata xml",
    ],
)
def test_saml_profile_rejects_parser_ambiguous_metadata_urls(
    metadata_url: str,
) -> None:
    store = MemorySamlAuthStore()

    with pytest.raises(
        ValueError,
        match="whitespace, control characters, or backslashes",
    ):
        store.save_profile({"metadata_url": metadata_url})


@pytest.mark.parametrize(
    "url",
    [
        "https://idp.example%/metadata.xml",
        "https://idp.example%2/metadata.xml",
        "https://idp.example%GG/metadata.xml",
    ],
)
def test_saml_url_normalizers_reject_malformed_authority_percent_encoding(
    url: str,
) -> None:
    store = MemorySamlAuthStore()

    with pytest.raises(ValueError, match="malformed percent-encoding"):
        saml_auth._normalize_saml_url(url, label="metadata")
    with pytest.raises(ValueError, match="malformed percent-encoding"):
        store._normalize_public_base_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "http://idp.example.test:8080/saml",
        "https://93.184.216.34:8443/saml",
        "https://[2001:4860:4860::8888]:8443/saml",
    ],
)
def test_saml_url_normalizers_preserve_valid_dns_ipv4_and_ipv6_authorities(
    url: str,
) -> None:
    store = MemorySamlAuthStore()

    assert saml_auth._normalize_saml_url(url, label="metadata") == url
    assert store._normalize_public_base_url(url) == url


@pytest.mark.parametrize(
    "metadata_url",
    [
        "https://adfs.example.local:0/metadata.xml",
        "https://adfs.example.local:/metadata.xml",
        "https://adfs.example.local:/FederationMetadata/2007-06/FederationMetadata.xml",
    ],
)
def test_saml_profile_rejects_invalid_metadata_url_ports(metadata_url: str) -> None:
    store = MemorySamlAuthStore()

    with pytest.raises(ValueError, match="metadata URL includes an invalid port"):
        store.save_profile({"metadata_url": metadata_url})


@pytest.mark.parametrize(
    "public_base_url",
    [
        "https://localhost/auth",
        "https://admin.internal/auth",
        "https://10.0.0.1/auth",
        "https://127.0.0.1/auth",
        "https://[fe80::1%25eth0]/auth",
        "https://0177.0.0.1/auth",
        "https://admin/auth",
    ],
)
def test_saml_profile_rejects_non_public_base_url_authorities(
    public_base_url: str,
) -> None:
    store = MemorySamlAuthStore()

    with pytest.raises(ValueError, match="public DNS name or global IP address"):
        store.save_profile(
            {
                "metadata_url": "https://adfs.example.local/FederationMetadata/2007-06/FederationMetadata.xml",
                "public_base_url": public_base_url,
            }
        )


def test_saml_profile_canonicalizes_public_base_url_authority() -> None:
    store = MemorySamlAuthStore()

    profile = store.save_profile(
        {
            "metadata_url": "https://adfs.example.local/FederationMetadata/2007-06/FederationMetadata.xml",
            "public_base_url": "HTTPS://BÜCHER.example.:8443/saml/",
        }
    )

    assert profile.public_base_url == "https://xn--bcher-kva.example:8443/saml"


def test_saml_profile_accepts_valid_public_base_url_port() -> None:
    store = MemorySamlAuthStore()

    profile = store.save_profile(
        {
            "metadata_url": "https://adfs.example.local/FederationMetadata/2007-06/FederationMetadata.xml",
            "public_base_url": "https://admin.example.test:8443/",
        }
    )

    assert profile.public_base_url == "https://admin.example.test:8443"


def test_saml_profile_rejects_double_encoded_unsafe_public_base_url_path() -> None:
    store = MemorySamlAuthStore()

    with pytest.raises(
        ValueError,
        match="encoded whitespace, control characters, or backslashes",
    ):
        store.save_profile(
            {
                "metadata_url": "https://adfs.example.local/FederationMetadata/2007-06/FederationMetadata.xml",
                "public_base_url": "https://admin.example.test/app/%255cadmin",
            }
        )


@pytest.mark.parametrize(
    "public_base_url",
    [
        "https://admin.example.test\\@evil.example/",
        "https://admin.example.test%2fevil.example/",
        "https://admin.example.test/%5cmetadata",
        "https://admin.example.test/base path",
    ],
)
def test_saml_profile_rejects_parser_ambiguous_public_base_urls(
    public_base_url: str,
) -> None:
    store = MemorySamlAuthStore()

    with pytest.raises(
        ValueError,
        match="whitespace, control characters, or backslashes",
    ):
        store.save_profile(
            {
                "metadata_url": "https://adfs.example.local/FederationMetadata/2007-06/FederationMetadata.xml",
                "public_base_url": public_base_url,
            }
        )


@pytest.mark.parametrize(
    "public_base_url",
    [
        "https://admin.example.test:99999",
        "https://admin.example.test:notaport",
        "https://admin.example.test:0",
        "https://admin.example.test:",
        "https://admin.example.test:/saml",
    ],
)
def test_saml_profile_rejects_invalid_public_base_url_ports(
    public_base_url: str,
) -> None:
    store = MemorySamlAuthStore()

    with pytest.raises(ValueError, match="public base URL includes an invalid port"):
        store.save_profile(
            {
                "metadata_url": "https://adfs.example.local/FederationMetadata/2007-06/FederationMetadata.xml",
                "public_base_url": public_base_url,
            }
        )


class _FakeMetadataResponse:
    def __init__(self, body: bytes, final_url: str) -> None:
        self._body = body
        self._final_url = final_url
        self._read = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False

    def geturl(self) -> str:
        return self._final_url

    def read(self, _size: int = -1) -> bytes:
        if self._read:
            return b""
        self._read = True
        return self._body


def _use_fake_metadata_opener(monkeypatch, response: _FakeMetadataResponse):
    opened_requests = []

    class FakeOpener:
        def open(self, request, *, timeout):
            opened_requests.append((request, timeout))
            return response

    monkeypatch.setattr(saml_auth, "build_opener", lambda *_handlers: FakeOpener())
    return opened_requests


def test_saml_fetch_enforces_one_deadline_across_open_and_body_reads(
    monkeypatch,
) -> None:
    store = MemorySamlAuthStore()
    profile = store.save_profile(
        {
            "metadata_url": "https://adfs.example.local/metadata.xml",
            "timeout_seconds": "10",
        }
    )
    monotonic_values = iter((100.0, 103.0, 104.0, 110.0))
    socket_timeouts = []

    class FakeSocket:
        def settimeout(self, timeout):
            socket_timeouts.append(timeout)

    class SlowTrickleResponse(_FakeMetadataResponse):
        fp = SimpleNamespace(raw=SimpleNamespace(_sock=FakeSocket()))

        def __init__(self) -> None:
            super().__init__(b"", profile.metadata_url)
            self.read_count = 0

        def read(self, _size: int = -1) -> bytes:
            self.read_count += 1
            return b"<EntityDescriptor>"

    response = SlowTrickleResponse()
    opened_requests = _use_fake_metadata_opener(monkeypatch, response)
    patch_module_clock(monkeypatch, saml_auth, monotonic=lambda: next(monotonic_values))

    with pytest.raises(
        TimeoutError,
        match=r"SAML metadata fetch timed out after 10 seconds\.",
    ):
        store.fetch_metadata(profile)

    assert opened_requests[0][1] == pytest.approx(7.0)
    assert socket_timeouts == pytest.approx([6.0])
    assert response.read_count == 1


def test_saml_fetch_does_not_open_when_setup_exhausts_total_deadline(
    monkeypatch,
) -> None:
    store = MemorySamlAuthStore()
    profile = store.save_profile(
        {
            "metadata_url": "https://adfs.example.local/metadata.xml",
            "timeout_seconds": "10",
        }
    )
    opened_requests = _use_fake_metadata_opener(
        monkeypatch,
        _FakeMetadataResponse(SAMPLE_METADATA.encode(), profile.metadata_url),
    )
    monotonic_values = iter((100.0, 110.0))
    patch_module_clock(monkeypatch, saml_auth, monotonic=lambda: next(monotonic_values))

    with pytest.raises(
        TimeoutError,
        match=r"SAML metadata fetch timed out after 10 seconds\.",
    ):
        store.fetch_metadata(profile)

    assert opened_requests == []


def test_saml_fetch_disables_ambient_proxy_and_preserves_tls_redirect_handlers(
    monkeypatch,
) -> None:
    store = MemorySamlAuthStore()
    profile = store.save_profile(
        {
            "metadata_url": "https://adfs.example.local/metadata.xml",
            "ca_bundle": "test custom CA",
            "require_https": "1",
        }
    )
    monkeypatch.setenv("HTTPS_PROXY", "http://ambient-proxy.example.test:8080")
    monkeypatch.setenv("NO_PROXY", "adfs.example.local")
    context = saml_auth.ssl.SSLContext(saml_auth.ssl.PROTOCOL_TLS_CLIENT)
    context_calls = []
    captured_handlers = []

    def fake_create_default_context(*, cadata=None):
        context_calls.append(cadata)
        return context

    class FakeOpener:
        def open(self, request, *, timeout):
            assert request.full_url == profile.metadata_url
            assert 0 < timeout <= profile.timeout_seconds
            return _FakeMetadataResponse(SAMPLE_METADATA.encode(), profile.metadata_url)

    def fake_build_opener(*handlers):
        captured_handlers.extend(handlers)
        return FakeOpener()

    monkeypatch.setattr(
        saml_auth.ssl, "create_default_context", fake_create_default_context
    )
    monkeypatch.setattr(saml_auth, "build_opener", fake_build_opener)

    assert store.fetch_metadata(profile) == SAMPLE_METADATA
    assert context_calls == ["test custom CA"]
    assert len(captured_handlers) == 3
    proxy_handler, https_handler, redirect_handler = captured_handlers
    assert isinstance(proxy_handler, saml_auth.ProxyHandler)
    assert proxy_handler.proxies == {}
    assert isinstance(https_handler, saml_auth.HTTPSHandler)
    assert https_handler._context is context
    assert isinstance(redirect_handler, saml_auth._SamlMetadataRedirectHandler)
    assert redirect_handler._require_https is True


def test_saml_fetch_rejects_https_metadata_redirect_before_unsafe_fetch(
    monkeypatch,
) -> None:
    store = MemorySamlAuthStore()
    profile = store.save_profile(
        {
            "metadata_url": "https://adfs.example.local/FederationMetadata/2007-06/FederationMetadata.xml",
            "require_https": "1",
        }
    )
    opened_urls = []

    def fake_urlopen(request, *, timeout, context):
        opened_urls.append(request.full_url)
        opened_urls.append("http://evil.example/FederationMetadata.xml")
        return _FakeMetadataResponse(
            SAMPLE_METADATA.encode(),
            "http://evil.example/FederationMetadata.xml",
        )

    monkeypatch.setattr(saml_auth, "urlopen", fake_urlopen, raising=False)

    def fake_build_opener(*handlers):
        redirect_handler = next(
            handler
            for handler in handlers
            if handler.__class__.__name__ == "_SamlMetadataRedirectHandler"
        )

        class FakeOpener:
            def open(self, request, *, timeout):
                opened_urls.append(request.full_url)
                assert request.get_header("Accept") == (
                    "application/samlmetadata+xml, application/xml, text/xml"
                )
                assert 0 < timeout <= profile.timeout_seconds
                redirect_handler.redirect_request(
                    request,
                    None,
                    302,
                    "Found",
                    {},
                    "http://evil.example/FederationMetadata.xml",
                )
                opened_urls.append("http://evil.example/FederationMetadata.xml")
                return _FakeMetadataResponse(
                    SAMPLE_METADATA.encode(), profile.metadata_url
                )

        return FakeOpener()

    monkeypatch.setattr(saml_auth, "build_opener", fake_build_opener)

    with pytest.raises(ValueError, match="metadata redirect URL must use https://"):
        store.fetch_metadata(profile)

    assert opened_urls == [profile.metadata_url]


def test_saml_fetch_redirect_uses_remaining_total_deadline(monkeypatch) -> None:
    request = saml_auth.Request("https://adfs.example.local/metadata.xml")
    request.timeout = 10.0
    socket_timeouts = []
    redirect_response = SimpleNamespace(
        fp=SimpleNamespace(
            raw=SimpleNamespace(
                _sock=SimpleNamespace(settimeout=socket_timeouts.append),
            )
        )
    )
    patch_module_clock(monkeypatch, saml_auth, monotonic=lambda: 104.0)

    redirected = saml_auth._SamlMetadataRedirectHandler(
        require_https=True,
        deadline=110.0,
        timeout_seconds=10.0,
    ).redirect_request(
        request,
        redirect_response,
        302,
        "Found",
        {},
        "https://login.example.local/metadata.xml",
    )

    assert redirected is not None
    assert request.timeout == pytest.approx(6.0)
    assert socket_timeouts == pytest.approx([6.0])


def test_saml_fetch_preserves_accept_header_on_https_redirect() -> None:
    request = saml_auth.Request(
        "https://adfs.example.local/FederationMetadata.xml",
        headers={"Accept": "application/samlmetadata+xml, application/xml, text/xml"},
    )

    redirected = saml_auth._SamlMetadataRedirectHandler(
        require_https=True,
    ).redirect_request(
        request,
        None,
        302,
        "Found",
        {},
        "https://login.example.local/FederationMetadata.xml",
    )

    assert redirected is not None
    assert redirected.full_url == "https://login.example.local/FederationMetadata.xml"
    assert redirected.get_header("Accept") == (
        "application/samlmetadata+xml, application/xml, text/xml"
    )


def test_saml_fetch_rejects_https_metadata_redirect_to_http(monkeypatch) -> None:
    store = MemorySamlAuthStore()
    profile = store.save_profile(
        {
            "metadata_url": "https://adfs.example.local/FederationMetadata/2007-06/FederationMetadata.xml",
            "require_https": "1",
        }
    )

    _use_fake_metadata_opener(
        monkeypatch,
        _FakeMetadataResponse(
            SAMPLE_METADATA.encode(),
            "http://adfs.example.local/FederationMetadata/2007-06/FederationMetadata.xml",
        ),
    )

    with pytest.raises(ValueError, match="must use https://"):
        store.fetch_metadata(profile)


@pytest.mark.parametrize(
    "final_url",
    [
        "https://login.example.local/FederationMetadata.xml?next=%0d%0aHost:evil.example",
        "https://login.example.local/%5cFederationMetadata.xml",
        "https://login.example.local%40evil.example/FederationMetadata.xml",
    ],
)
def test_saml_fetch_rejects_parser_ambiguous_https_metadata_redirects(
    monkeypatch,
    final_url: str,
) -> None:
    store = MemorySamlAuthStore()
    profile = store.save_profile(
        {
            "metadata_url": "https://adfs.example.local/FederationMetadata/2007-06/FederationMetadata.xml",
            "require_https": "1",
        }
    )

    _use_fake_metadata_opener(
        monkeypatch,
        _FakeMetadataResponse(SAMPLE_METADATA.encode(), final_url),
    )

    with pytest.raises(
        ValueError,
        match="metadata final response URL must not include encoded whitespace",
    ):
        store.fetch_metadata(profile)


def test_saml_fetch_rejects_zero_port_https_metadata_redirect(monkeypatch) -> None:
    store = MemorySamlAuthStore()
    profile = store.save_profile(
        {
            "metadata_url": "https://adfs.example.local/FederationMetadata/2007-06/FederationMetadata.xml",
            "require_https": "1",
        }
    )

    _use_fake_metadata_opener(
        monkeypatch,
        _FakeMetadataResponse(
            SAMPLE_METADATA.encode(),
            "https://login.example.local:0/FederationMetadata.xml",
        ),
    )

    with pytest.raises(
        ValueError,
        match="metadata final response URL includes an invalid port",
    ):
        store.fetch_metadata(profile)


def test_saml_fetch_accepts_https_metadata_redirect_to_https(monkeypatch) -> None:
    store = MemorySamlAuthStore()
    profile = store.save_profile(
        {
            "metadata_url": "https://adfs.example.local/FederationMetadata/2007-06/FederationMetadata.xml",
            "require_https": "1",
        }
    )

    _use_fake_metadata_opener(
        monkeypatch,
        _FakeMetadataResponse(
            SAMPLE_METADATA.encode(),
            "https://login.example.local/FederationMetadata/2007-06/FederationMetadata.xml",
        ),
    )

    assert store.fetch_metadata(profile) == SAMPLE_METADATA


@pytest.mark.parametrize(
    ("metadata", "blocked_service"),
    [
        (
            _metadata_with_service_locations(
                sso_location="http://adfs.example.local/adfs/ls/"
            ),
            "SingleSignOnService",
        ),
        (
            _metadata_with_service_locations(
                slo_location="http://adfs.example.local/adfs/slo"
            ),
            "SingleLogoutService",
        ),
    ],
)
def test_saml_refresh_rejects_http_idp_endpoint_locations_when_https_required(
    monkeypatch,
    metadata: str,
    blocked_service: str,
) -> None:
    store = MemorySamlAuthStore()
    store.save_profile(
        {
            "metadata_url": "https://adfs.example.local/FederationMetadata/2007-06/FederationMetadata.xml",
            "require_https": "1",
        }
    )
    monkeypatch.setattr(store, "fetch_metadata", lambda _profile: metadata)

    result = store.refresh_metadata()

    assert result.ok is False
    assert blocked_service in result.detail
    assert "must use https://" in result.detail
    assert store.profile.last_refresh_ok is False
    assert store.profile.parsed_metadata_json == ""


def test_build_saml_settings_revalidates_cached_idp_endpoint_locations() -> None:
    parsed = parse_saml_metadata(
        _metadata_with_service_locations(
            sso_location="http://adfs.example.local/adfs/ls/"
        )
    )
    profile = replace(
        MemorySamlAuthStore().default_profile(),
        require_https=True,
        raw_metadata_xml="cached",
        parsed_metadata_json=json.dumps(parsed, sort_keys=True),
    )

    with pytest.raises(ValueError, match=r"SingleSignOnService.*must use https://"):
        build_saml_settings(
            profile,
        )


def test_build_saml_settings_prefers_redirect_idp_endpoints_over_post_order() -> None:
    metadata = f"""<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
    entityID="https://idp.example.test/metadata">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>{SIGNING_CERT}</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="https://idp.example.test/sso/post" />
    <SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="https://idp.example.test/sso/redirect" />
    <SingleLogoutService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="https://idp.example.test/slo/post" />
    <SingleLogoutService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="https://idp.example.test/slo/redirect" />
  </IDPSSODescriptor>
</EntityDescriptor>
"""
    parsed = parse_saml_metadata(metadata)
    profile = replace(
        MemorySamlAuthStore().default_profile(),
        raw_metadata_xml="cached",
        parsed_metadata_json=json.dumps(parsed, sort_keys=True),
        public_base_url="https://admin.example.test",
    )

    settings = build_saml_settings(
        profile,
    )

    assert parsed["sso_services"][0]["binding"].endswith(":HTTP-POST")
    assert parsed["slo_services"][0]["binding"].endswith(":HTTP-POST")
    assert settings["idp"]["singleSignOnService"] == {
        "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
        "url": "https://idp.example.test/sso/redirect",
    }
    assert settings["idp"]["singleLogoutService"] == {
        "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
        "url": "https://idp.example.test/slo/redirect",
    }


def test_build_saml_settings_rejects_double_encoded_cached_idp_endpoint_locations() -> (
    None
):
    parsed = parse_saml_metadata(
        _metadata_with_service_locations(
            sso_location="https://adfs.example.local/adfs/%255cls"
        )
    )
    profile = replace(
        MemorySamlAuthStore().default_profile(),
        require_https=True,
        raw_metadata_xml="cached",
        parsed_metadata_json=json.dumps(parsed, sort_keys=True),
    )

    with pytest.raises(
        ValueError,
        match="encoded whitespace, control characters, or backslashes",
    ):
        build_saml_settings(
            profile,
        )


def test_saml_refresh_accepts_http_idp_endpoint_locations_when_https_disabled(
    monkeypatch,
) -> None:
    store = MemorySamlAuthStore()
    store.save_profile(
        {
            "metadata_url": "http://adfs.example.local/FederationMetadata/2007-06/FederationMetadata.xml",
            "require_https": "0",
        }
    )
    metadata = _metadata_with_service_locations(
        sso_location="http://adfs.example.local/adfs/ls/",
        slo_location="http://adfs.example.local/adfs/slo",
    )
    monkeypatch.setattr(store, "fetch_metadata", lambda _profile: metadata)

    result = store.refresh_metadata()

    assert result.ok is True
    assert store.profile.parsed_metadata["sso_services"][0]["location"] == (
        "http://adfs.example.local/adfs/ls/"
    )
    assert store.profile.parsed_metadata["slo_services"][0]["location"] == (
        "http://adfs.example.local/adfs/slo"
    )


def test_saml_refresh_fetches_and_caches_static_metadata(monkeypatch) -> None:
    store = MemorySamlAuthStore()
    store.save_profile(
        {
            "metadata_url": "https://adfs.example.local/FederationMetadata/2007-06/FederationMetadata.xml",
        }
    )
    monkeypatch.setattr(store, "fetch_metadata", lambda _profile: SAMPLE_METADATA)

    result = store.refresh_metadata()

    assert result.ok is True
    assert store.profile.raw_metadata_xml == SAMPLE_METADATA
    assert store.profile.parsed_metadata["entity_id"] == (
        "https://adfs.example.local/adfs/services/trust"
    )
    assert store.profile.cache_expires_ts > store.profile.fetched_ts


def test_saml_refresh_records_safe_detail_for_rejected_metadata(monkeypatch) -> None:
    store = MemorySamlAuthStore()
    store.save_profile(
        {
            "metadata_url": "https://adfs.example.local/FederationMetadata/2007-06/FederationMetadata.xml",
        }
    )
    monkeypatch.setattr(store, "fetch_metadata", lambda _profile: ENTITY_METADATA)

    result = store.refresh_metadata()

    assert result.ok is False
    assert (
        result.detail
        == "SAML metadata XML contains disallowed DTD or entity declarations."
    )
    assert store.profile.last_refresh_ok is False
    assert store.profile.last_refresh_detail == result.detail
    assert "evil.example" not in result.detail
    assert "EntityDescriptor [" not in result.detail


def test_saml_public_error_redacts_assertions_and_secret_parameters() -> None:
    store = MemorySamlAuthStore()

    detail = store._public_error(
        RuntimeError(
            "failed URL ?SAMLResponse=base64assertion&RelayState=/admin "
            "password=secret token=abc signature=deadbeef"
        )
    )

    assert "base64assertion" not in detail
    assert "secret" not in detail
    assert "abc" not in detail
    assert "deadbeef" not in detail
    assert "SAMLResponse=[redacted]" in detail
    assert "RelayState=[redacted]" in detail
    assert "password=[redacted]" in detail


class _GuardedUpdateConnection:
    def __init__(self, *, rowcount: int, current_row) -> None:
        self.rowcount = rowcount
        self.current_row = current_row
        self.statements: list[tuple[str, tuple]] = []

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def execute(self, sql, params=()):
        self.statements.append((sql, tuple(params)))
        if sql.lstrip().startswith("SELECT"):
            return SimpleNamespace(fetchone=lambda: self.current_row)
        return SimpleNamespace(rowcount=self.rowcount)


@pytest.mark.parametrize(
    ("rowcount", "current_row", "expected_ok"),
    [(1, None, True), (0, (1,), True), (0, None, False)],
)
def test_metadata_refresh_is_only_cached_for_the_current_fetch_settings(
    monkeypatch, rowcount, current_row, expected_ok
) -> None:
    store = SamlAuthStore()
    profile = replace(
        store.default_profile(),
        metadata_url="https://idp.example.test/metadata.xml",
    )
    conn = _GuardedUpdateConnection(rowcount=rowcount, current_row=current_row)
    monkeypatch.setattr(store, "get_profile", lambda: profile)
    monkeypatch.setattr(store, "fetch_metadata", lambda _profile: SAMPLE_METADATA)
    monkeypatch.setattr(store, "_connect", lambda: conn)
    monkeypatch.setattr(
        store,
        "record_refresh_status",
        lambda **_kwargs: pytest.fail("success path must not record a failure"),
    )

    result = store.refresh_metadata()

    assert result.ok is expected_ok
    update_sql, update_params = conn.statements[0]
    assert "metadata_url = %s" in update_sql
    assert "max_metadata_bytes = %s" in update_sql
    assert "https://idp.example.test/metadata.xml" in update_params
    if not expected_ok:
        assert "changed while metadata was being refreshed" in result.detail


class _ReplayToolkit:
    def __init__(
        self,
        *,
        assertion_id: str | None = "_assertion-1",
        not_on_or_after: int | None = None,
        in_response_to: str | None = "REQ-1",
    ) -> None:
        self.assertion_id = assertion_id
        self.not_on_or_after = not_on_or_after
        self.in_response_to = in_response_to

    def get_last_assertion_id(self):
        return self.assertion_id

    def get_last_assertion_not_on_or_after(self):
        return self.not_on_or_after

    def get_last_response_in_response_to(self):
        return self.in_response_to


def _replay_profile(entity_id: str = "https://idp.example.test/entity"):
    return replace(SamlAuthStore().default_profile(), entity_id=entity_id)


def test_replay_clock_drift_matches_python3_saml_constant() -> None:
    from onelogin.saml2.constants import OneLogin_Saml2_Constants

    assert (
        OneLogin_Saml2_Constants.ALLOWED_CLOCK_DRIFT
        == saml_auth.SAML_CLOCK_DRIFT_SECONDS
    )


@pytest.mark.parametrize(
    ("not_on_or_after", "expected_offset"),
    [
        # No SubjectConfirmationData NotOnOrAfter: the pending window bounds it.
        (None, 660 + 300),
        # Long-lived assertion: still capped by the pending-request window.
        (1_000_000 + 86_400, 660 + 300),
        # Short-lived assertion: its NotOnOrAfter is the tighter bound.
        (1_000_000 + 120, 120 + 300),
    ],
)
def test_assertion_replay_expiry_outlives_every_acceptance_window(
    not_on_or_after, expected_offset
) -> None:
    use = saml_auth.saml_assertion_use(
        _ReplayToolkit(not_on_or_after=not_on_or_after),
        _replay_profile(),
        request_id="REQ-1",
        acceptance_window_seconds=660,
        now=1_000_000,
    )

    assert use.expires_ts == 1_000_000 + expected_offset
    assert len(use.replay_key) == 64


def test_assertion_replay_key_is_scoped_to_idp_entity() -> None:
    def key(entity_id: str, assertion_id: str) -> str:
        return saml_auth.saml_assertion_use(
            _ReplayToolkit(assertion_id=assertion_id),
            _replay_profile(entity_id),
            request_id="REQ-1",
            acceptance_window_seconds=660,
            now=1_000_000,
        ).replay_key

    assert key("https://a.example", "_x") == key("https://a.example", "_x")
    assert key("https://a.example", "_x") != key("https://b.example", "_x")
    assert key("https://a.example", "_x") != key("https://a.example", "_y")


@pytest.mark.parametrize(
    ("toolkit", "profile", "message"),
    [
        (_ReplayToolkit(assertion_id=None), _replay_profile(), "did not include an ID"),
        (_ReplayToolkit(assertion_id="  "), _replay_profile(), "did not include an ID"),
        (_ReplayToolkit(in_response_to=None), _replay_profile(), "pending login"),
        (_ReplayToolkit(in_response_to="REQ-2"), _replay_profile(), "pending login"),
        (_ReplayToolkit(), _replay_profile(entity_id=""), "entity ID is unknown"),
    ],
)
def test_assertion_replay_claim_rejects_unbindable_assertions(
    toolkit, profile, message
) -> None:
    with pytest.raises(ValueError, match=message):
        saml_auth.saml_assertion_use(
            toolkit,
            profile,
            request_id="REQ-1",
            acceptance_window_seconds=660,
            now=1_000_000,
        )


class _ReplayInsertConnection:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.statements: list[tuple[str, tuple]] = []

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def execute(self, sql, params=()):
        self.statements.append((" ".join(str(sql).split()), tuple(params)))
        if self.error is not None:
            raise self.error
        return SimpleNamespace(rowcount=1)


@pytest.mark.parametrize(
    ("error", "expected"),
    [(None, True), (pymysql.err.IntegrityError(1062, "dup"), False)],
)
def test_record_assertion_use_claims_once(monkeypatch, error, expected) -> None:
    store = SamlAuthStore()
    conn = _ReplayInsertConnection(error)
    monkeypatch.setattr(store, "ensure_schema", lambda: None)
    monkeypatch.setattr(store, "_connect", lambda: conn)
    use = saml_auth.SamlAssertionUse(replay_key="a" * 64, expires_ts=1_000_960)

    assert store.record_assertion_use(use, now=1_000_000) is expected
    sql, params = conn.statements[0]
    assert sql.startswith("INSERT INTO saml_assertion_replay(")
    assert params == ("a" * 64, 1_000_960, 1_000_000)


def test_record_assertion_use_propagates_other_database_errors(monkeypatch) -> None:
    store = SamlAuthStore()
    conn = _ReplayInsertConnection(pymysql.err.OperationalError(2013, "lost"))
    monkeypatch.setattr(store, "ensure_schema", lambda: None)
    monkeypatch.setattr(store, "_connect", lambda: conn)

    with pytest.raises(pymysql.err.OperationalError):
        store.record_assertion_use(
            saml_auth.SamlAssertionUse(replay_key="b" * 64, expires_ts=1),
            now=0,
        )


def _ready_saml_profile(now: int):
    parsed = parse_saml_metadata(SAMPLE_METADATA)
    return replace(
        SamlAuthStore().default_profile(),
        enabled=True,
        metadata_url="https://idp.example.test/metadata.xml",
        raw_metadata_xml=SAMPLE_METADATA,
        parsed_metadata_json=json.dumps(parsed, sort_keys=True),
        entity_id=parsed["entity_id"],
        fetched_ts=now,
        cache_expires_ts=now + 3600,
        last_refresh_ok=True,
        last_refresh_ts=now,
        public_base_url="https://admin.example.test",
        required_group="Admins",
        updated_ts=now,
    )


def test_saml_policy_fingerprint_ignores_refresh_bookkeeping_only() -> None:
    now = int(time.time())
    profile = _ready_saml_profile(now)
    fingerprint = saml_auth.saml_policy_fingerprint(profile)

    refreshed = replace(
        profile,
        fetched_ts=now + 60,
        cache_expires_ts=now + 7200,
        last_refresh_ts=now + 60,
        last_refresh_detail="refreshed",
        updated_ts=now + 60,
        raw_metadata_xml=SAMPLE_METADATA + "\n",
    )
    assert saml_auth.saml_policy_fingerprint(refreshed) == fingerprint
    for changed in (
        replace(profile, required_group="Other"),
        replace(profile, groups_attribute="roles"),
        replace(profile, username_attribute="upn"),
        replace(profile, entity_id="https://other.example/idp"),
        replace(profile, metadata_url="https://other.example/metadata.xml"),
        replace(profile, public_base_url="https://other.example.test"),
    ):
        assert saml_auth.saml_policy_fingerprint(changed) != fingerprint


class _SessionPolicyConnection:
    def __init__(self, row) -> None:
        self.row = row
        self.sql = ""

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def execute(self, sql, _params=()):
        self.sql = " ".join(str(sql).split())
        return SimpleNamespace(fetchone=lambda: self.row)


@pytest.mark.parametrize(
    "variant",
    [
        "ready",
        "disabled",
        "no_metadata",
        "refresh_failed",
        "within_stale_grace",
        "past_stale_grace",
        "past_valid_until",
    ],
)
def test_session_policy_query_matches_full_profile_readiness(
    monkeypatch, variant
) -> None:
    now = int(time.time())
    profile = _ready_saml_profile(now)
    window = 2 * 3600
    stale = replace(profile, fetched_ts=now - window - 60, cache_expires_ts=now - 60)
    profile = {
        "ready": profile,
        "disabled": replace(profile, enabled=False),
        "no_metadata": replace(profile, raw_metadata_xml=""),
        # A failed refresh keeps the last good metadata in use.
        "refresh_failed": replace(profile, last_refresh_ok=False),
        "within_stale_grace": stale,
        "past_stale_grace": replace(
            stale, fetched_ts=now - 2 * window - 1, cache_expires_ts=now - window - 1
        ),
        "past_valid_until": replace(stale, valid_until_ts=now - 1),
    }[variant]
    row = (
        int(profile.enabled),
        int(profile.raw_metadata_xml != ""),
        int(profile.parsed_metadata_json != ""),
        profile.fetched_ts,
        profile.cache_expires_ts,
        profile.valid_until_ts,
        profile.entity_id,
        profile.metadata_url,
        profile.public_base_url,
        profile.username_attribute,
        profile.groups_attribute,
        profile.required_group,
    )
    store = SamlAuthStore()
    conn = _SessionPolicyConnection(row)
    monkeypatch.setattr(store, "ensure_schema", lambda: None)
    monkeypatch.setattr(store, "_connect", lambda: conn)

    policy = store.get_session_policy(now=now)

    assert policy == saml_auth.saml_session_policy(profile, now=now)
    assert policy.ready is (
        variant in {"ready", "refresh_failed", "within_stale_grace"}
    )
    # The per-request read never transfers the cached metadata documents.
    selected = conn.sql.split(" FROM ", 1)[0]
    assert "raw_metadata_xml <> ''" in selected
    assert "raw_metadata_xml," not in selected


@pytest.mark.mysql
def test_saml_replay_cache_claims_once_and_is_pruned_on_mysql(tmp_path) -> None:
    import importlib

    from .mysql_test_utils import configure_test_mysql_env

    configure_test_mysql_env(tmp_path / "saml-replay-cache")
    schema_lifecycle = importlib.import_module("services.schema_lifecycle")
    schema_lifecycle.migrate_schema(require_privileges=False)
    live_saml = importlib.import_module("services.saml_auth")
    maintenance = importlib.import_module("services.control_plane_maintenance")
    store = live_saml.SamlAuthStore()
    now = int(time.time())
    fresh = live_saml.SamlAssertionUse(replay_key="c" * 64, expires_ts=now + 900)
    stale = live_saml.SamlAssertionUse(replay_key="d" * 64, expires_ts=now - 1)

    assert store.record_assertion_use(fresh, now=now) is True
    assert store.record_assertion_use(fresh, now=now) is False
    assert store.record_assertion_use(stale, now=now - 1000) is True
    assert store.get_session_policy(now=now) == live_saml.saml_session_policy(
        store.get_profile(), now=now
    )

    result = maintenance.prune_control_plane_tables(retention_days=1)

    replay_result = next(
        row for row in result["tables"] if row["table"] == "saml_assertion_replay"
    )
    assert replay_result["status"] == "pruned"
    assert replay_result["deleted_rows"] == 1
    with live_saml.connect() as conn:
        keys = {
            str(row["replay_key"])
            for row in conn.execute(
                "SELECT replay_key FROM saml_assertion_replay"
            ).fetchall()
        }
    assert keys == {"c" * 64}


def test_metadata_stale_grace_is_bounded_by_window_and_valid_until() -> None:
    day = 24 * 3600
    grace = saml_auth.SAML_METADATA_STALE_GRACE_SECONDS
    assert (
        saml_auth.metadata_usable_until(
            fetched_ts=1000, cache_expires_ts=1000 + day, valid_until_ts=0
        )
        == 1000 + day + grace
    )
    # A short cache window never gets more grace than its own length.
    assert (
        saml_auth.metadata_usable_until(
            fetched_ts=1000, cache_expires_ts=1600, valid_until_ts=0
        )
        == 2200
    )
    # validUntil is a hard limit the grace never passes.
    assert (
        saml_auth.metadata_usable_until(
            fetched_ts=1000, cache_expires_ts=1000 + day, valid_until_ts=1000 + day + 5
        )
        == 1000 + day + 5
    )
    assert (
        saml_auth.metadata_usable_until(
            fetched_ts=0, cache_expires_ts=0, valid_until_ts=0
        )
        == 0
    )


def _enabled_store_with_metadata() -> MemorySamlAuthStore:
    store = MemorySamlAuthStore()
    saved = store.save_profile(
        {
            "metadata_url": "https://adfs.example.local/FederationMetadata/2007-06/FederationMetadata.xml",
        }
    )
    store.record_metadata_refresh(
        saved, raw_xml=SAMPLE_METADATA, parsed=parse_saml_metadata(SAMPLE_METADATA)
    )
    store.save_profile(
        {
            "enabled": "1",
            "metadata_url": "https://adfs.example.local/FederationMetadata/2007-06/FederationMetadata.xml",
            "public_base_url": "https://admin.example.test",
        }
    )
    return store


def test_failed_refresh_keeps_last_good_metadata_and_backs_off(monkeypatch) -> None:
    store = _enabled_store_with_metadata()
    good_xml = store.profile.raw_metadata_xml

    def unreachable(_profile):
        msg = "IdP unreachable"
        raise OSError(msg)

    monkeypatch.setattr(store, "fetch_metadata", unreachable)
    now = int(time.time())
    delays = []
    for _attempt in range(10):
        before = int(time.time())
        assert store.refresh_metadata().ok is False
        delays.append(store.profile.next_refresh_ts - before)

    profile = store.profile
    assert profile.refresh_failures == 10
    assert profile.raw_metadata_xml == good_xml
    assert profile.last_refresh_ok is False
    # Logins and sessions keep working on the cached metadata within its window.
    assert saml_auth.profile_metadata_ready(profile, now=now) is True
    # Equal jitter around a doubling delay, capped at one hour.
    assert 30 <= delays[0] <= 61
    assert 60 <= delays[1] <= 121
    assert all(1800 <= delay <= 3601 for delay in delays[6:])


def test_successful_refresh_resets_backoff_and_schedules_mid_window() -> None:
    now = int(time.time())
    parsed = parse_saml_metadata(SAMPLE_METADATA)
    for _ in range(20):
        next_ts = saml_auth._next_scheduled_refresh_ts(
            fetched_ts=now, cache_expires_ts=now + 24 * 3600, valid_until_ts=0
        )
        assert now + int(0.45 * 24 * 3600) <= next_ts <= now + 12 * 3600
    # A validUntil earlier than the cache expiry shortens the schedule.
    assert (
        saml_auth._next_scheduled_refresh_ts(
            fetched_ts=now, cache_expires_ts=now + 24 * 3600, valid_until_ts=now + 600
        )
        <= now + 300
    )
    # The real store writes the schedule and clears failures with the metadata.
    store = SamlAuthStore()
    profile = replace(
        store.default_profile(),
        metadata_url="https://idp.example.test/metadata.xml",
        refresh_failures=4,
    )
    conn = _GuardedUpdateConnection(rowcount=1, current_row=None)
    store._connect = lambda: conn  # type: ignore[method-assign]
    assert store.record_metadata_refresh(
        profile, raw_xml=SAMPLE_METADATA, parsed=parsed
    )
    update_sql, update_params = conn.statements[0]
    assert "refresh_failures = 0, next_refresh_ts = %s" in " ".join(update_sql.split())
    scheduled = update_params[8]
    assert now + 60 <= scheduled <= now + 12 * 3600 + 5


class _NamedLockConnection:
    def __init__(self, *, acquired: int) -> None:
        self.acquired = acquired
        self.statements: list[str] = []

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def execute(self, sql, params=()):
        self.statements.append(" ".join(str(sql).split()))
        if "GET_LOCK" in sql:
            return SimpleNamespace(fetchone=lambda: {"acquired": self.acquired})
        return SimpleNamespace(fetchone=lambda: {"released": 1})


@pytest.mark.parametrize(
    ("variant", "expect_fetch"),
    [
        ("not_due", False),
        ("disabled", False),
        ("lock_held_elsewhere", False),
        ("refreshed_by_other_holder", False),
        ("due", True),
    ],
)
def test_background_refresh_is_due_gated_and_single_flight(
    monkeypatch, variant, expect_fetch
) -> None:
    now = int(time.time())
    store = _enabled_store_with_metadata()
    due = replace(store.profile, next_refresh_ts=now - 1)
    store.profile = {
        "not_due": replace(due, next_refresh_ts=now + 600),
        "disabled": replace(due, enabled=False),
    }.get(variant, due)
    conn = _NamedLockConnection(acquired=0 if variant == "lock_held_elsewhere" else 1)
    monkeypatch.setattr(store, "_connect_lock_session", lambda: conn)
    if variant == "refreshed_by_other_holder":
        reads = iter([due, replace(due, next_refresh_ts=now + 900)])
        monkeypatch.setattr(store, "get_profile", lambda: next(reads))
    fetches = []
    monkeypatch.setattr(
        store, "fetch_metadata", lambda _profile: fetches.append(1) or SAMPLE_METADATA
    )

    next_due = store.refresh_metadata_if_due(now=now)

    assert bool(fetches) is expect_fetch
    if variant == "disabled":
        assert next_due == 0
    elif variant == "not_due":
        assert next_due == now + 600
        assert conn.statements == []
    elif variant == "due":
        assert next_due > now
        assert store.profile.refresh_failures == 0
    if variant in {"due", "refreshed_by_other_holder"}:
        assert any("RELEASE_LOCK" in sql for sql in conn.statements)


def test_background_refresh_loop_poll_bounds(monkeypatch) -> None:
    from services import saml_metadata_refresh

    assert saml_metadata_refresh.next_poll_delay(0, 100) == 300
    assert saml_metadata_refresh.next_poll_delay(50, 100) == 30
    assert saml_metadata_refresh.next_poll_delay(160, 100) == 60
    assert saml_metadata_refresh.next_poll_delay(10_000, 100) == 300

    class _BrokenStore:
        def refresh_metadata_if_due(self):
            msg = "mysql down"
            raise RuntimeError(msg)

    assert saml_metadata_refresh.run_once(_BrokenStore()) == 30


@pytest.mark.mysql
def test_saml_background_refresh_schedule_round_trips_on_mysql(
    tmp_path, monkeypatch
) -> None:
    import importlib

    from .mysql_test_utils import configure_test_mysql_env

    configure_test_mysql_env(tmp_path / "saml-refresh-schedule")
    schema_lifecycle = importlib.import_module("services.schema_lifecycle")
    schema_lifecycle.migrate_schema(require_privileges=False)
    live_saml = importlib.import_module("services.saml_auth")
    store = live_saml.SamlAuthStore()
    url = "https://adfs.example.local/FederationMetadata/2007-06/FederationMetadata.xml"
    store.save_profile({"metadata_url": url})
    monkeypatch.setattr(store, "fetch_metadata", lambda _profile: SAMPLE_METADATA)
    assert store.refresh_metadata().ok is True
    store.save_profile(
        {
            "enabled": "1",
            "metadata_url": url,
            "public_base_url": "https://admin.example.test",
        }
    )
    scheduled = store.get_profile().next_refresh_ts
    now = int(time.time())
    assert scheduled > now

    # Not due: no fetch, schedule unchanged.
    monkeypatch.setattr(
        store, "fetch_metadata", lambda _profile: pytest.fail("refresh not due")
    )
    assert store.refresh_metadata_if_due(now=now) == scheduled

    # Due and failing: metadata kept, backoff recorded, still ready.
    with live_saml.connect() as conn:
        conn.execute("UPDATE saml_auth_profiles SET next_refresh_ts = 1")

    def unreachable(_profile):
        msg = "IdP unreachable"
        raise OSError(msg)

    monkeypatch.setattr(store, "fetch_metadata", unreachable)
    retry_at = store.refresh_metadata_if_due()
    profile = store.get_profile()
    assert profile.refresh_failures == 1
    assert retry_at == profile.next_refresh_ts
    assert now + 29 <= retry_at <= int(time.time()) + 61
    assert profile.raw_metadata_xml == SAMPLE_METADATA
    assert store.get_session_policy().ready is True

    # Another holder of the refresh lock makes this process skip the fetch.
    with live_saml.connect() as conn:
        conn.execute("UPDATE saml_auth_profiles SET next_refresh_ts = 1")
        lock_name = live_saml.scoped_lock_name(live_saml._REFRESH_LOCK_NAMESPACE)
        assert live_saml.acquire_mysql_named_lock(conn, lock_name, 0)
        try:
            assert store.refresh_metadata_if_due() > int(time.time())
            assert store.get_profile().refresh_failures == 1
        finally:
            live_saml.release_mysql_named_lock(conn, lock_name)
