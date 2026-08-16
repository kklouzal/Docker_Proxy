from __future__ import annotations

import hashlib


def certificate_bundle_sha256(
    cert_pem: str,
    key_pem: str,
    chain_pem: str = "",
) -> str:
    """Return the persisted certificate-bundle digest.

    Compatibility contract: UTF-8 encode (with replacement) the certificate,
    chain, and private key in that order, separated by single NUL bytes. Empty
    chain material still occupies its framed position. Changing this framing or
    ordering would invalidate persisted certificate revision digests.
    """
    payload = "\0".join((cert_pem or "", chain_pem or "", key_pem or ""))
    return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()
