from __future__ import annotations

import json
import time
from dataclasses import replace
from types import SimpleNamespace

import pytest
from services.saml_auth import SamlAuthStore, parse_saml_metadata, prepare_flask_request

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
        )

    def record_refresh_status(self, *, ok: bool, detail: str) -> None:
        now = int(time.time())
        self.profile = type(self.profile)(
            provider=self.profile.provider,
            enabled=self.profile.enabled,
            metadata_url=self.profile.metadata_url,
            require_https=self.profile.require_https,
            verify_tls=self.profile.verify_tls,
            ca_bundle=self.profile.ca_bundle,
            timeout_seconds=self.profile.timeout_seconds,
            max_metadata_bytes=self.profile.max_metadata_bytes,
            raw_metadata_xml=self.profile.raw_metadata_xml,
            parsed_metadata_json=self.profile.parsed_metadata_json,
            entity_id=self.profile.entity_id,
            fetched_ts=self.profile.fetched_ts,
            cache_expires_ts=self.profile.cache_expires_ts,
            valid_until_ts=self.profile.valid_until_ts,
            last_refresh_ok=ok,
            last_refresh_ts=now,
            last_refresh_detail=detail,
            public_base_url=self.profile.public_base_url,
            username_attribute=self.profile.username_attribute,
            groups_attribute=self.profile.groups_attribute,
            required_group=self.profile.required_group,
            updated_ts=self.profile.updated_ts,
        )


def _saml_request(url: str, *, scheme: str = "https", server_port: str = ""):
    host = url.split("://", 1)[1].split("/", 1)[0]
    return SimpleNamespace(
        url=url,
        scheme=scheme,
        host=host,
        path="/auth/saml/login",
        args={},
        form={},
        query_string=b"",
        environ={"SERVER_PORT": server_port} if server_port else {},
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
    assert parsed["sso_services"][0]["location"] == "https://adfs.example.local/adfs/ls/"
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
    assert message == "SAML metadata XML contains disallowed DTD or entity declarations."
    assert "injected" not in message
    assert "evil.example" not in message
    assert "EntityDescriptor [" not in message


def test_saml_profile_requires_successful_metadata_refresh_before_enable() -> None:
    store = MemorySamlAuthStore()

    with pytest.raises(ValueError, match="Refresh SAML metadata successfully"):
        store.save_profile(
            {
                "enabled": "1",
                "metadata_url": "https://adfs.example.local/FederationMetadata/2007-06/FederationMetadata.xml",
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
            }
        )


def test_saml_profile_https_is_required_by_default() -> None:
    store = MemorySamlAuthStore()

    with pytest.raises(ValueError, match="https://"):
        store.save_profile({"metadata_url": "http://adfs.example.local/metadata.xml"})


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
    assert result.detail == "SAML metadata XML contains disallowed DTD or entity declarations."
    assert store.profile.last_refresh_ok is False
    assert store.profile.last_refresh_detail == result.detail
    assert "evil.example" not in result.detail
    assert "EntityDescriptor [" not in result.detail
