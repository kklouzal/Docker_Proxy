from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from .live_test_helpers import (
    LIVE_CONFIG,
    LiveStackClient,
    active_certificate_bundle,
    admin_client,
    latest_certificate_apply,
    query_params,
    wait_for_certificate_apply,
    wait_for_proxy_inventory,
)


pytestmark = pytest.mark.live


def _apply_ts(application: object | None) -> int:
    return int(getattr(application, "applied_ts", 0) or 0)


def _build_test_pfx(password: bytes) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Live Tests"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Live Uploaded Proxy CA"),
        ]
    )
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=True,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return pkcs12.serialize_key_and_certificates(
        name=b"live-uploaded-ca",
        key=key,
        cert=cert,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(password),
    )


@pytest.fixture
def multi_proxy_admin(admin_client: LiveStackClient) -> LiveStackClient:
    wait_for_proxy_inventory(
        admin_client,
        [LIVE_CONFIG.primary_proxy_id, LIVE_CONFIG.remote_proxy_id],
        timeout_seconds=120.0,
    )
    return admin_client


def test_live_generate_certificate_creates_shared_bundle_and_nudges_all_registered_proxies(
    multi_proxy_admin: LiveStackClient,
) -> None:
    primary_before = latest_certificate_apply(LIVE_CONFIG.primary_proxy_id)
    remote_before = latest_certificate_apply(LIVE_CONFIG.remote_proxy_id)

    response = multi_proxy_admin.admin_post_form(
        "/certs/generate",
        {},
        csrf_path="/certs",
        timeout_seconds=120.0,
    )
    assert response.status == 200
    assert query_params(response.url).get("ok") == ["1"]

    bundle = active_certificate_bundle()
    assert bundle is not None
    assert bundle.source_kind == "self_signed"

    primary_apply = wait_for_certificate_apply(
        LIVE_CONFIG.primary_proxy_id,
        revision_id=bundle.revision_id,
        after_ts=_apply_ts(primary_before) or None,
        timeout_seconds=120.0,
    )
    remote_apply = wait_for_certificate_apply(
        LIVE_CONFIG.remote_proxy_id,
        revision_id=bundle.revision_id,
        after_ts=_apply_ts(remote_before) or None,
        timeout_seconds=120.0,
    )
    assert primary_apply is not None
    assert remote_apply is not None

    certs_page = multi_proxy_admin.admin_request("/certs")
    assert certs_page.status == 200
    assert "Edge 2" in certs_page.text
    assert "Applied" in certs_page.text or "Pending" in certs_page.text

    download = multi_proxy_admin.admin_request("/certs/download/ca.crt")
    assert download.status == 200
    assert "attachment" in download.headers.get("Content-Disposition", "")
    assert "BEGIN CERTIFICATE" in download.text

    for bad_name in ("nope.crt", "ca.key", "../ca.crt", "..%2Fca.crt"):
        rejected = multi_proxy_admin.admin_request(f"/certs/download/{bad_name}")
        assert rejected.status == 404, f"Expected certificate download name {bad_name!r} to be rejected."


def test_live_certificate_upload_rejects_invalid_requests(multi_proxy_admin: LiveStackClient) -> None:
    missing = multi_proxy_admin.admin_post_form(
        "/certs/upload",
        {"pfx_password": ""},
        csrf_path="/certs",
    )
    assert missing.status == 200
    assert query_params(missing.url).get("ok") == ["0"]
    assert query_params(missing.url).get("msg") == ["No PFX file selected."]

    wrong_ext = multi_proxy_admin.admin_post_multipart(
        "/certs/upload",
        {"pfx_password": ""},
        {"pfx": ("ca.crt", b"not-a-pfx", "application/x-pem-file")},
        csrf_path="/certs",
    )
    assert wrong_ext.status == 200
    assert query_params(wrong_ext.url).get("ok") == ["0"]
    assert query_params(wrong_ext.url).get("msg") == ["Unsupported file type. Please upload a .pfx or .p12."]

    too_large = multi_proxy_admin.admin_post_multipart(
        "/certs/upload",
        {"pfx_password": ""},
        {"pfx": ("too-large.pfx", b"x" * (10 * 1024 * 1024 + 1), "application/x-pkcs12")},
        csrf_path="/certs",
        timeout_seconds=90.0,
    )
    assert too_large.status == 200
    assert query_params(too_large.url).get("ok") == ["0"]
    assert query_params(too_large.url).get("msg") == ["Upload too large (max 10MB)."]


def test_live_upload_certificate_pfx_creates_shared_bundle_and_nudges_all_registered_proxies(
    multi_proxy_admin: LiveStackClient,
) -> None:
    primary_before = latest_certificate_apply(LIVE_CONFIG.primary_proxy_id)
    remote_before = latest_certificate_apply(LIVE_CONFIG.remote_proxy_id)
    password = b"live-secret"

    response = multi_proxy_admin.admin_post_multipart(
        "/certs/upload",
        {"pfx_password": password.decode("ascii")},
        {"pfx": ("live-upload-ca.pfx", _build_test_pfx(password), "application/x-pkcs12")},
        csrf_path="/certs",
        timeout_seconds=120.0,
    )
    assert response.status == 200
    assert query_params(response.url).get("ok") == ["1"]

    bundle = active_certificate_bundle()
    assert bundle is not None
    assert bundle.source_kind == "uploaded_pfx"
    assert bundle.original_filename == "live-upload-ca.pfx"
    assert bundle.original_pfx_blob

    wait_for_certificate_apply(
        LIVE_CONFIG.primary_proxy_id,
        revision_id=bundle.revision_id,
        after_ts=_apply_ts(primary_before) or None,
        timeout_seconds=120.0,
    )
    wait_for_certificate_apply(
        LIVE_CONFIG.remote_proxy_id,
        revision_id=bundle.revision_id,
        after_ts=_apply_ts(remote_before) or None,
        timeout_seconds=120.0,
    )