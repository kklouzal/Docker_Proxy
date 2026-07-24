from __future__ import annotations

import json
import time
from dataclasses import replace
from types import SimpleNamespace

import pytest
from services import saml_auth
from services.saml_auth import (
    SamlAuthStore,
    build_saml_settings,
    parse_saml_metadata,
    prepare_flask_request,
)

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


def test_saml_profile_rejects_zero_metadata_url_port() -> None:
    store = MemorySamlAuthStore()

    with pytest.raises(ValueError, match="metadata URL includes an invalid port"):
        store.save_profile({"metadata_url": "https://adfs.example.local:0/metadata.xml"})


def test_saml_profile_accepts_valid_public_base_url_port() -> None:
    store = MemorySamlAuthStore()

    profile = store.save_profile(
        {
            "metadata_url": "https://adfs.example.local/FederationMetadata/2007-06/FederationMetadata.xml",
            "public_base_url": "https://admin.example.test:8443/",
        }
    )

    assert profile.public_base_url == "https://admin.example.test:8443"


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
                assert timeout == profile.timeout_seconds
                redirect_handler.redirect_request(
                    request,
                    None,
                    302,
                    "Found",
                    {},
                    "http://evil.example/FederationMetadata.xml",
                )
                opened_urls.append("http://evil.example/FederationMetadata.xml")
                return _FakeMetadataResponse(SAMPLE_METADATA.encode(), profile.metadata_url)

        return FakeOpener()

    monkeypatch.setattr(saml_auth, "build_opener", fake_build_opener)

    with pytest.raises(ValueError, match="metadata redirect URL must use https://"):
        store.fetch_metadata(profile)

    assert opened_urls == [profile.metadata_url]


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
            _saml_request("https://admin.example.test/auth/saml/login"),
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
    assert result.detail == "SAML metadata XML contains disallowed DTD or entity declarations."
    assert store.profile.last_refresh_ok is False
    assert store.profile.last_refresh_detail == result.detail
    assert "evil.example" not in result.detail
    assert "EntityDescriptor [" not in result.detail
