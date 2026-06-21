from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _add_web_to_path() -> None:
    web_dir = Path(__file__).resolve().parents[1]
    if str(web_dir) not in sys.path:
        sys.path.insert(0, str(web_dir))


_add_web_to_path()
from services import certificate_core  # type: ignore  # noqa: E402

CERT_A = "-----BEGIN CERTIFICATE-----\nCERTA\n-----END CERTIFICATE-----\n"
CERT_B = "-----BEGIN CERTIFICATE-----\nCERTB\n-----END CERTIFICATE-----\n"
KEY_A = "-----BEGIN PRIVATE KEY-----\nKEYA\n-----END PRIVATE KEY-----\n"


def _valid_ca_bundle() -> certificate_core.CertificateBundle:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Docker Proxy Test CA")]
    )
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return certificate_core.build_certificate_bundle(
        cert.public_bytes(serialization.Encoding.PEM).decode(),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode(),
    )


def test_pem_helpers_normalize_extract_and_split_certificate_chains() -> None:
    messy = "\r\n  " + CERT_A.replace("\n", "\r\n") + CERT_B + "  "

    assert certificate_core._normalize_pem_text("  abc\r\n") == "abc\n"
    assert certificate_core._first_pem_block(messy, "CERTIFICATE") == CERT_A
    assert certificate_core._all_pem_blocks(messy, "CERTIFICATE") == [CERT_A, CERT_B]
    assert certificate_core._split_cert_chain(messy) == (CERT_A, CERT_B)
    assert certificate_core._split_cert_chain("not pem") == ("", "")


def test_build_certificate_bundle_hashes_content_and_metadata(monkeypatch) -> None:
    monkeypatch.setattr(
        certificate_core,
        "_extract_certificate_metadata",
        lambda _cert: (
            "CN=Proxy",
            "May 1 00:00:00 2026 GMT",
            "May 1 00:00:00 2036 GMT",
        ),
    )

    bundle = certificate_core.build_certificate_bundle(
        CERT_A,
        KEY_A,
        chain_pem=CERT_B,
        source_kind=" uploaded_pfx ",
        original_pfx_bytes=b"pfx",
    )

    assert bundle.cert_pem == CERT_A
    assert bundle.key_pem == KEY_A
    assert bundle.chain_pem == CERT_B
    assert bundle.fullchain_pem == CERT_A + CERT_B
    assert bundle.source_kind == "uploaded_pfx"
    assert bundle.subject_dn == "CN=Proxy"
    assert len(bundle.bundle_sha256) == 64
    assert len(bundle.cert_sha256) == 64
    assert bundle.original_pfx_bytes == b"pfx"

    with pytest.raises(ValueError):
        certificate_core.build_certificate_bundle(CERT_A, "")


def test_materialize_and_load_certificate_bundle_round_trip_and_manage_pfx_file(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(
        certificate_core, "_extract_certificate_metadata", lambda _cert: ("", "", "")
    )

    bundle_with_pfx = certificate_core.build_certificate_bundle(
        CERT_A,
        KEY_A,
        chain_pem=CERT_B,
        source_kind="uploaded_pfx",
        original_pfx_bytes=b"pfx-bytes",
    )

    certificate_core.materialize_certificate_bundle(tmp_path, bundle_with_pfx)
    assert (tmp_path / "ca.crt").read_text(encoding="utf-8") == CERT_A + CERT_B
    assert (tmp_path / "ca.key").read_text(encoding="utf-8") == KEY_A
    assert (tmp_path / "uploaded_ca.pfx").read_bytes() == b"pfx-bytes"

    loaded = certificate_core.load_local_certificate_bundle(tmp_path)
    assert loaded is not None
    assert loaded.cert_pem == CERT_A
    assert loaded.chain_pem == CERT_B
    assert loaded.key_pem == KEY_A
    assert loaded.original_pfx_bytes == b"pfx-bytes"

    bundle_without_pfx = certificate_core.build_certificate_bundle(CERT_A, KEY_A)
    certificate_core.materialize_certificate_bundle(tmp_path, bundle_without_pfx)
    assert not (tmp_path / "uploaded_ca.pfx").exists()


def test_load_local_certificate_bundle_returns_none_for_missing_or_incomplete_material(
    tmp_path,
) -> None:
    assert certificate_core.load_local_certificate_bundle(tmp_path) is None
    (tmp_path / "ca.crt").write_text(CERT_A, encoding="utf-8")
    (tmp_path / "ca.key").write_text("not a private key", encoding="utf-8")
    assert certificate_core.load_local_certificate_bundle(tmp_path) is None


def test_admin_ui_leaf_generation_uses_separate_server_cert_with_sans(tmp_path) -> None:
    bundle = _valid_ca_bundle()
    certificate_core.materialize_certificate_bundle(tmp_path, bundle)
    ca_cert_before = (tmp_path / "ca.crt").read_text(encoding="utf-8")
    ca_key_before = (tmp_path / "ca.key").read_text(encoding="utf-8")

    material = certificate_core.materialize_admin_ui_server_certificate(
        tmp_path,
        bundle,
        san_tokens=[
            "admin.example.test:8443",
            "https://proxy.example.test",
            "192.0.2.10",
            "../bad",
        ],
    )

    assert material.certfile == str(tmp_path / "admin-ui.crt")
    assert material.keyfile == str(tmp_path / "admin-ui.key")
    assert "admin.example.test" in material.sans
    assert "proxy.example.test" in material.sans
    assert "192.0.2.10" in material.sans
    assert "../bad" not in material.sans
    assert (tmp_path / "ca.crt").read_text(encoding="utf-8") == ca_cert_before
    assert (tmp_path / "ca.key").read_text(encoding="utf-8") == ca_key_before

    validation = certificate_core.validate_tls_material_paths(
        material.certfile,
        material.keyfile,
    )
    assert validation.ready is True

    leaf = x509.load_pem_x509_certificate((tmp_path / "admin-ui.crt").read_bytes())
    assert (
        leaf.extensions.get_extension_for_class(
            x509.BasicConstraints,
        ).value.ca
        is False
    )
    assert (
        ExtendedKeyUsageOID.SERVER_AUTH
        in leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    )
    key_usage = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
    assert key_usage.digital_signature is True
    assert key_usage.key_encipherment is True
    sans = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "admin.example.test" in sans.get_values_for_type(x509.DNSName)
    assert "proxy.example.test" in sans.get_values_for_type(x509.DNSName)
    assert "192.0.2.10" in [str(ip) for ip in sans.get_values_for_type(x509.IPAddress)]


def test_admin_ui_san_normalization_handles_forwarded_hosts_and_ipv6() -> None:
    sans = certificate_core.normalize_admin_ui_certificate_sans(
        [
            "edge.example.test:8443, proxy.example.test",
            "[2001:db8::10]:5000",
            "bad/host",
            "user@example.test",
            "https://proxy.example.test/certs",
            "*.example.test",
        ],
    )

    assert "edge.example.test" in sans
    assert "2001:db8::10" in sans
    assert "proxy.example.test" not in sans
    assert "bad/host" not in sans
    assert "example.test" not in sans
    assert "*.example.test" not in sans
