from __future__ import annotations

import hashlib

from services import certificate_core
from services.certificate_digest import certificate_bundle_sha256


def _legacy_digest(cert_pem: str, key_pem: str, chain_pem: str) -> str:
    payload = f"{cert_pem}\0{chain_pem}\0{key_pem}"
    return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()


def test_certificate_bundle_digest_preserves_component_order_and_framing() -> None:
    cert_pem = "leaf"
    chain_pem = "issuer"
    key_pem = "private"

    digest = certificate_bundle_sha256(cert_pem, key_pem, chain_pem)

    assert digest == _legacy_digest(cert_pem, key_pem, chain_pem)
    assert digest != _legacy_digest(cert_pem, chain_pem, key_pem)
    assert (
        digest
        != hashlib.sha256(
            f"{cert_pem}{chain_pem}{key_pem}".encode(),
        ).hexdigest()
    )


def test_certificate_bundle_digest_frames_empty_chain() -> None:
    assert (
        certificate_bundle_sha256("leaf", "private")
        == hashlib.sha256(
            b"leaf\0\0private",
        ).hexdigest()
    )


def test_certificate_bundle_creation_uses_shared_digest(monkeypatch) -> None:
    monkeypatch.setattr(
        certificate_core,
        "_extract_certificate_metadata",
        lambda _cert: ("", "", ""),
    )

    bundle = certificate_core.build_certificate_bundle(
        " leaf\r\n",
        " private\r",
        chain_pem=" issuer\r\n",
    )

    assert bundle.bundle_sha256 == certificate_bundle_sha256(
        bundle.cert_pem,
        bundle.key_pem,
        bundle.chain_pem,
    )
