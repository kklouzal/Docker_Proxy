from __future__ import annotations

import json
import time
from types import SimpleNamespace

from services.saml_auth import SamlAuthStore, parse_saml_metadata

from .admin_route_test_utils import (
    FakeAuditStore,
    csrf_token,
    load_admin_app,
    login_client,
)
from .test_saml_auth import SAMPLE_METADATA


class FakeSamlStore(SamlAuthStore):
    def __init__(self) -> None:
        self.profile = self.default_profile()
        self.saved: list[dict[str, str]] = []
        self.refreshed = 0
        self.disabled = 0

    def ensure_schema(self) -> None:
        return None

    def ensure_default_profile(self) -> None:
        return None

    def get_profile(self):
        return self.profile

    def _persist(self, profile):
        self.profile = profile

    def refresh_metadata(self):
        self.refreshed += 1
        parsed = parse_saml_metadata(SAMPLE_METADATA)
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
            raw_metadata_xml=SAMPLE_METADATA,
            parsed_metadata_json=json.dumps(parsed, sort_keys=True),
            entity_id=parsed["entity_id"],
            fetched_ts=now,
            cache_expires_ts=now + 3600,
            valid_until_ts=parsed["valid_until_ts"],
            last_refresh_ok=True,
            last_refresh_ts=now,
            last_refresh_detail="SAML IdP metadata refreshed successfully.",
            public_base_url=self.profile.public_base_url,
            username_attribute=self.profile.username_attribute,
            groups_attribute=self.profile.groups_attribute,
            required_group=self.profile.required_group,
            updated_ts=now,
        )
        return SimpleNamespace(
            ok=True,
            provider="saml",
            detail="SAML IdP metadata refreshed successfully.",
            parsed_metadata=parsed,
        )

    def save_profile(self, payload):
        self.saved.append(dict(payload))
        return super().save_profile(payload)

    def disable_provider(self) -> None:
        self.disabled += 1
        self.profile = type(self.profile)(
            provider=self.profile.provider,
            enabled=False,
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
            last_refresh_ok=self.profile.last_refresh_ok,
            last_refresh_ts=self.profile.last_refresh_ts,
            last_refresh_detail=self.profile.last_refresh_detail,
            public_base_url=self.profile.public_base_url,
            username_attribute=self.profile.username_attribute,
            groups_attribute=self.profile.groups_attribute,
            required_group=self.profile.required_group,
            updated_ts=self.profile.updated_ts,
        )

    def enable_with_metadata(self, *, required_group: str = "AdminGroup") -> None:
        self.refresh_metadata()
        self.profile = self.save_profile(
            {
                "enabled": "1",
                "metadata_url": self.profile.metadata_url,
                "require_https": "1",
                "verify_tls": "1",
                "username_attribute": "email",
                "groups_attribute": "groups",
                "required_group": required_group,
                "public_base_url": "https://admin.example.test",
            }
        )


class FakeSamlToolkit:
    def __init__(self, *, ok: bool = True, groups: list[str] | None = None) -> None:
        self.ok = ok
        self.groups = groups or ["AdminGroup"]
        self.processed_request_id = None

    def login(self, return_to: str = "") -> str:
        return f"https://idp.example.test/sso?RelayState={return_to}"

    def get_last_request_id(self) -> str:
        return "REQ-123"

    def process_response(self, request_id: str | None = None) -> None:
        self.processed_request_id = request_id

    def get_errors(self):
        return [] if self.ok else ["invalid_response"]

    def get_last_error_reason(self):
        return "signature validation failed" if not self.ok else ""

    def is_authenticated(self) -> bool:
        return self.ok

    def get_attributes(self):
        return {"email": ["saml-user@example.test"], "groups": self.groups}

    def get_nameid(self):
        return "nameid@example.test"

    def get_session_index(self):
        return "SESSION-1"


def _load_with_saml(monkeypatch, tmp_path, store=None, **overrides):
    loaded = load_admin_app(monkeypatch, tmp_path, **overrides)
    store = store or FakeSamlStore()
    monkeypatch.setattr(loaded.module, "_saml_auth_store", store)
    return loaded, store


def test_administration_exposes_saml_tab_and_sp_endpoints(monkeypatch, tmp_path):
    loaded, store = _load_with_saml(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/administration?tab=saml")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "SAML provider" in body
    assert "Metadata URL" in body
    assert "Entity ID" in body
    assert "/auth/saml/metadata" in body
    assert store.profile.metadata_url in body


def test_saml_sp_metadata_is_available_before_idp_metadata_refresh(
    monkeypatch, tmp_path
):
    loaded, _store = _load_with_saml(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()

    response = client.get("/auth/saml/metadata", base_url="https://admin.example.test")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert response.mimetype == "application/samlmetadata+xml"
    assert 'entityID="https://admin.example.test/auth/saml/metadata"' in body
    assert 'Location="https://admin.example.test/auth/saml/acs"' in body


def test_saml_admin_refresh_save_and_disable_actions(monkeypatch, tmp_path):
    loaded, store = _load_with_saml(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/administration?tab=saml")

    refreshed = client.post(
        "/administration?tab=saml",
        data={"csrf_token": token, "provider": "saml", "action": "refresh_saml_metadata"},
    )
    assert refreshed.status_code in {302, 303}
    assert store.refreshed == 1

    token = csrf_token(client, "/administration?tab=saml")
    saved = client.post(
        "/administration?tab=saml",
        data={
            "csrf_token": token,
            "provider": "saml",
            "action": "save_saml_provider",
            "enabled": "1",
            "metadata_url": store.profile.metadata_url,
            "require_https": "1",
            "verify_tls": "1",
            "username_attribute": "email",
            "groups_attribute": "groups",
            "required_group": "AdminGroup",
            "public_base_url": "https://admin.example.test",
        },
    )
    assert saved.status_code in {302, 303}
    assert store.profile.enabled is True
    assert store.profile.required_group == "AdminGroup"

    token = csrf_token(client, "/administration?tab=saml")
    disabled = client.post(
        "/administration?tab=saml",
        data={"csrf_token": token, "provider": "saml", "action": "disable_saml_provider"},
    )
    assert disabled.status_code in {302, 303}
    assert store.disabled == 1


def test_login_page_shows_saml_button_only_when_ready(monkeypatch, tmp_path):
    loaded, store = _load_with_saml(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    assert "Sign in with SAML" not in client.get("/login").get_data(as_text=True)

    store.enable_with_metadata()

    assert "Sign in with SAML" in client.get("/login").get_data(as_text=True)


def test_saml_login_and_acs_create_standard_session(monkeypatch, tmp_path):
    audit = FakeAuditStore()
    loaded, store = _load_with_saml(monkeypatch, tmp_path, audit_store=audit)
    store.enable_with_metadata()
    toolkit = FakeSamlToolkit()
    monkeypatch.setattr(loaded.module, "build_saml_auth", lambda _profile, _request: toolkit)
    client = loaded.module.app.test_client()

    login_response = client.get("/auth/saml/login?next=/administration")
    assert login_response.status_code in {302, 303}
    with client.session_transaction() as sess:
        assert sess["saml_request_id"] == "REQ-123"

    acs_response = client.post("/auth/saml/acs", data={"RelayState": "/administration"})

    assert acs_response.status_code in {302, 303}
    assert toolkit.processed_request_id == "REQ-123"
    with client.session_transaction() as sess:
        assert sess["user"] == "saml-user@example.test"
        assert sess["auth_provider"] == "saml"
        assert "saml_request_id" not in sess
    assert audit.records[-1]["kind"] == "login_success"
    assert audit.records[-1]["detail"] == "user=saml-user@example.test provider=saml"


def test_saml_login_clears_stale_request_id_when_provider_unavailable(
    monkeypatch, tmp_path
):
    loaded, store = _load_with_saml(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    with client.session_transaction() as sess:
        sess["saml_request_id"] = "STALE-REQ"

    response = client.get("/auth/saml/login?next=/administration")

    assert response.status_code in {302, 303}
    assert "error=saml_unavailable" in response.headers["Location"]
    with client.session_transaction() as sess:
        assert "saml_request_id" not in sess
    assert not store.profile.enabled


def test_saml_login_replaces_stale_request_id_after_initiation_failure(
    monkeypatch, tmp_path
):
    loaded, store = _load_with_saml(monkeypatch, tmp_path)
    store.enable_with_metadata()
    calls = 0

    def build_auth(_profile, _request):
        nonlocal calls
        calls += 1
        if calls == 1:
            msg = "idp initiation failed"
            raise RuntimeError(msg)
        return FakeSamlToolkit()

    monkeypatch.setattr(loaded.module, "build_saml_auth", build_auth)
    client = loaded.module.app.test_client()
    with client.session_transaction() as sess:
        sess["saml_request_id"] = "STALE-REQ"

    failed = client.get("/auth/saml/login?next=/administration")

    assert failed.status_code in {302, 303}
    with client.session_transaction() as sess:
        assert "saml_request_id" not in sess

    started = client.get("/auth/saml/login?next=/administration")

    assert started.status_code in {302, 303}
    with client.session_transaction() as sess:
        assert sess["saml_request_id"] == "REQ-123"


def test_saml_acs_clears_stale_request_id_when_provider_unavailable(
    monkeypatch, tmp_path
):
    loaded, _store = _load_with_saml(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    with client.session_transaction() as sess:
        sess["saml_request_id"] = "STALE-REQ"

    response = client.post("/auth/saml/acs", data={"RelayState": "/administration"})

    assert response.status_code in {302, 303}
    with client.session_transaction() as sess:
        assert "saml_request_id" not in sess


def test_saml_acs_drops_external_relay_state(monkeypatch, tmp_path):
    loaded, store = _load_with_saml(monkeypatch, tmp_path)
    store.enable_with_metadata(required_group="")
    toolkit = FakeSamlToolkit()
    monkeypatch.setattr(loaded.module, "build_saml_auth", lambda _profile, _request: toolkit)
    client = loaded.module.app.test_client()

    response = client.post(
        "/auth/saml/acs",
        data={"RelayState": "https://evil.example/phish"},
    )

    assert response.status_code in {302, 303}
    assert response.headers["Location"] == "/"
    with client.session_transaction() as sess:
        assert sess["user"] == "saml-user@example.test"


def test_saml_acs_rejects_missing_required_group_without_raw_response_audit(
    monkeypatch, tmp_path
):
    audit = FakeAuditStore()
    loaded, store = _load_with_saml(monkeypatch, tmp_path, audit_store=audit)
    store.enable_with_metadata(required_group="AdminGroup")
    toolkit = FakeSamlToolkit(groups=["OtherGroup"])
    monkeypatch.setattr(loaded.module, "build_saml_auth", lambda _profile, _request: toolkit)
    client = loaded.module.app.test_client()

    response = client.post(
        "/auth/saml/acs",
        data={"RelayState": "/administration", "SAMLResponse": "<raw xml>"},
    )

    assert response.status_code in {302, 303}
    with client.session_transaction() as sess:
        assert "user" not in sess
    assert audit.records[-1]["kind"] == "saml_login_failed"
    assert "required admin group" in audit.records[-1]["detail"]
    assert "<raw xml>" not in audit.records[-1]["detail"]
