import os
import pathlib
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from typing import NoReturn

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def _import_cert_manager_module():
    web_dir = pathlib.Path(os.path.join(pathlib.Path(__file__).parent, "..")).resolve()
    if web_dir not in sys.path:
        sys.path.insert(0, web_dir)

    from services import cert_manager  # type: ignore

    return cert_manager


def _pem_ca_material(
    *,
    ca: bool = True,
    key_cert_sign: bool = True,
    not_before_delta: timedelta = timedelta(minutes=-5),
    not_after_delta: timedelta = timedelta(days=30),
) -> tuple[str, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Docker Proxy Uploaded CA Test")]
    )
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + not_before_delta)
        .not_valid_after(now + not_after_delta)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=key_cert_sign,
                crl_sign=key_cert_sign,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM).decode(),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode(),
    )


def _new_ca_material(
    *,
    common_name: str,
    issuer_cert: x509.Certificate | None = None,
    issuer_key: rsa.RSAPrivateKey | None = None,
    not_before_delta: timedelta = timedelta(minutes=-5),
    not_after_delta: timedelta = timedelta(days=30),
) -> tuple[str, str, x509.Certificate, rsa.RSAPrivateKey]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    issuer_name = issuer_cert.subject if issuer_cert is not None else subject
    signing_key = issuer_key if issuer_key is not None else key
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + not_before_delta)
        .not_valid_after(now + not_after_delta)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(signing_key, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM).decode(),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode(),
        cert,
        key,
    )


def _pem_leaf_material(*, common_name: str) -> tuple[str, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM).decode(),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode(),
    )


def _fake_pfx_runner(cert_pem: str, key_pem: str, chain_pem: str = ""):
    class FakeCP:
        def __init__(self, stdout: str = "") -> None:
            self.stdout = stdout
            self.stderr = ""

    def fake_run_checked(args, *, timeout: int = 30):
        if "pkcs12" in args and "-out" in args:
            out_path = args[args.index("-out") + 1]
            if "-clcerts" in args:
                pathlib.Path(out_path).write_text(cert_pem, encoding="utf-8")
            elif "-cacerts" in args:
                pathlib.Path(out_path).write_text(chain_pem, encoding="utf-8")
            else:
                pathlib.Path(out_path).write_text(key_pem, encoding="utf-8")
            return FakeCP("")
        if args[:2] == ["openssl", "x509"]:
            return FakeCP("PUBKEY_SAME")
        if args[:2] == ["openssl", "pkey"]:
            return FakeCP("PUBKEY_SAME")
        return FakeCP("")

    return fake_run_checked


def test_install_pfx_empty_bytes(tmp_path) -> None:
    m = _import_cert_manager_module()
    r = m.install_pfx_as_ca(str(tmp_path), b"", password="")
    assert r.ok is False
    assert "Empty PFX" in r.message


def test_install_pfx_openssl_missing(tmp_path) -> None:
    m = _import_cert_manager_module()

    def fake_run_checked(_args, *, timeout: int = 30) -> NoReturn:
        msg = "openssl"
        raise FileNotFoundError(msg)

    r = m.install_pfx_as_ca(
        str(tmp_path), b"abc", password="", run_checked=fake_run_checked
    )
    assert r.ok is False
    assert "openssl not found" in r.message


def test_install_pfx_openssl_parse_error_is_sanitized(tmp_path) -> None:
    m = _import_cert_manager_module()

    def fake_run_checked(_args, *, timeout: int = 30) -> NoReturn:
        raise subprocess.CalledProcessError(
            returncode=1, cmd=_args, stderr="bad\ninput"
        )

    r = m.install_pfx_as_ca(
        str(tmp_path), b"abc", password="", run_checked=fake_run_checked
    )
    assert r.ok is False
    assert "OpenSSL failed" in r.message


def test_install_pfx_cert_key_mismatch(tmp_path) -> None:
    m = _import_cert_manager_module()

    class FakeCP:
        def __init__(self, stdout: str = "") -> None:
            self.stdout = stdout
            self.stderr = ""

    def fake_run_checked(args, *, timeout: int = 30):
        # The installer uses pkcs12 to write to -out paths, then compares pubkeys.
        if "pkcs12" in args:
            if "-out" in args:
                out_path = args[args.index("-out") + 1]
                if "-nokeys" in args:
                    # leaf cert / chain certs
                    pathlib.Path(out_path).write_text(
                        "-----BEGIN CERTIFICATE-----\nMIIF...\n-----END CERTIFICATE-----\n",
                        encoding="utf-8",
                    )
                else:
                    # private key
                    pathlib.Path(out_path).write_text(
                        "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----\n",
                        encoding="utf-8",
                    )
            return FakeCP("")

        if args[:2] == ["openssl", "x509"]:
            return FakeCP("PUBKEY_A")
        if args[:2] == ["openssl", "pkey"]:
            return FakeCP("PUBKEY_B")

        return FakeCP("")

    r = m.install_pfx_as_ca(
        str(tmp_path), b"abc", password="", run_checked=fake_run_checked
    )
    assert r.ok is False
    assert "do not match" in r.message


def test_install_pfx_happy_path_writes_files(tmp_path) -> None:
    m = _import_cert_manager_module()
    cert_pem, key_pem = _pem_ca_material()

    r = m.install_pfx_as_ca(
        str(tmp_path),
        b"abc",
        password="secret",
        run_checked=_fake_pfx_runner(cert_pem, key_pem),
    )
    assert r.ok is True

    # Ensure expected outputs are present.
    assert (tmp_path / "ca.crt").exists()
    assert (tmp_path / "ca.key").exists()
    assert (tmp_path / "uploaded_ca.pfx").exists()


def test_parse_pfx_reports_missing_certificate(tmp_path) -> None:
    m = _import_cert_manager_module()

    class FakeCP:
        def __init__(self, stdout: str = "") -> None:
            self.stdout = stdout
            self.stderr = ""

    def fake_run_checked(args, *, timeout: int = 30):
        if "pkcs12" in args and "-out" in args:
            out_path = args[args.index("-out") + 1]
            if "-nokeys" in args:
                pathlib.Path(out_path).write_text("", encoding="utf-8")
            else:
                pathlib.Path(out_path).write_text(
                    "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----\n",
                    encoding="utf-8",
                )
        return FakeCP("PUBKEY")

    r = m.parse_pfx_bundle(b"abc", password="", run_checked=fake_run_checked)
    assert r.ok is False
    assert "does not contain a certificate" in r.message


def test_parse_pfx_reports_missing_private_key(tmp_path) -> None:
    m = _import_cert_manager_module()

    class FakeCP:
        def __init__(self, stdout: str = "") -> None:
            self.stdout = stdout
            self.stderr = ""

    def fake_run_checked(args, *, timeout: int = 30):
        if "pkcs12" in args and "-out" in args:
            out_path = args[args.index("-out") + 1]
            if "-nokeys" in args:
                pathlib.Path(out_path).write_text(
                    "-----BEGIN CERTIFICATE-----\nMIIF...\n-----END CERTIFICATE-----\n",
                    encoding="utf-8",
                )
            else:
                pathlib.Path(out_path).write_text("", encoding="utf-8")
        return FakeCP("PUBKEY")

    r = m.parse_pfx_bundle(b"abc", password="", run_checked=fake_run_checked)
    assert r.ok is False
    assert "does not contain a private key" in r.message


def test_parse_pfx_reports_encrypted_private_key(tmp_path) -> None:
    m = _import_cert_manager_module()

    class FakeCP:
        def __init__(self, stdout: str = "") -> None:
            self.stdout = stdout
            self.stderr = ""

    def fake_run_checked(args, *, timeout: int = 30):
        if "pkcs12" in args and "-out" in args:
            out_path = args[args.index("-out") + 1]
            if "-nokeys" in args:
                pathlib.Path(out_path).write_text(
                    "-----BEGIN CERTIFICATE-----\nMIIF...\n-----END CERTIFICATE-----\n",
                    encoding="utf-8",
                )
            else:
                pathlib.Path(out_path).write_text(
                    "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIE...\n-----END ENCRYPTED PRIVATE KEY-----\n",
                    encoding="utf-8",
                )
        return FakeCP("PUBKEY")

    r = m.parse_pfx_bundle(b"abc", password="", run_checked=fake_run_checked)
    assert r.ok is False
    assert "encrypted" in r.message


def test_parse_pfx_orders_verified_issuer_chain_and_original_bytes(tmp_path) -> None:
    m = _import_cert_manager_module()
    root_pem, _root_key_pem, root_cert, root_key = _new_ca_material(
        common_name="Docker Proxy Test Root",
    )
    intermediate_pem, _intermediate_key_pem, intermediate_cert, intermediate_key = (
        _new_ca_material(
            common_name="Docker Proxy Test Intermediate",
            issuer_cert=root_cert,
            issuer_key=root_key,
        )
    )
    cert_pem, key_pem, _selected_cert, _selected_key = _new_ca_material(
        common_name="Docker Proxy Uploaded SSL Bump CA",
        issuer_cert=intermediate_cert,
        issuer_key=intermediate_key,
    )

    r = m.parse_pfx_bundle(
        b"pfx-bytes",
        password="secret",
        run_checked=_fake_pfx_runner(
            cert_pem,
            key_pem,
            chain_pem=root_pem + cert_pem + intermediate_pem + root_pem,
        ),
    )
    assert r.ok is True
    assert r.bundle is not None
    assert r.bundle.chain_pem == intermediate_pem + root_pem
    assert r.bundle.original_pfx_bytes == b"pfx-bytes"


def test_parse_pfx_accepts_verified_partial_issuer_chain() -> None:
    m = _import_cert_manager_module()
    root_pem, _root_key_pem, root_cert, root_key = _new_ca_material(
        common_name="Docker Proxy Test Root",
    )
    intermediate_pem, _intermediate_key_pem, intermediate_cert, intermediate_key = (
        _new_ca_material(
            common_name="Docker Proxy Test Intermediate",
            issuer_cert=root_cert,
            issuer_key=root_key,
        )
    )
    cert_pem, key_pem, _selected_cert, _selected_key = _new_ca_material(
        common_name="Docker Proxy Uploaded SSL Bump CA",
        issuer_cert=intermediate_cert,
        issuer_key=intermediate_key,
    )

    r = m.parse_pfx_bundle(
        b"pfx-bytes",
        password="secret",
        run_checked=_fake_pfx_runner(
            cert_pem,
            key_pem,
            chain_pem=intermediate_pem,
        ),
    )

    assert r.ok is True
    assert r.bundle is not None
    assert root_pem not in r.bundle.chain_pem
    assert r.bundle.chain_pem == intermediate_pem


def test_parse_pfx_rejects_unrelated_chain_certificate() -> None:
    m = _import_cert_manager_module()
    cert_pem, key_pem = _pem_ca_material()
    unrelated_pem, _unrelated_key_pem, _unrelated_cert, _unrelated_key = (
        _new_ca_material(common_name="Unrelated Extra CA")
    )

    r = m.parse_pfx_bundle(
        b"pfx-bytes",
        password="secret",
        run_checked=_fake_pfx_runner(
            cert_pem,
            key_pem,
            chain_pem=unrelated_pem,
        ),
    )

    assert r.ok is False
    assert "do not form a verified issuer chain" in r.message


def test_parse_pfx_rejects_issuer_chain_signature_mismatch() -> None:
    m = _import_cert_manager_module()
    issuer_pem, _issuer_key_pem, issuer_cert, issuer_key = _new_ca_material(
        common_name="Docker Proxy Test Intermediate",
    )
    cert_pem, key_pem, _selected_cert, _selected_key = _new_ca_material(
        common_name="Docker Proxy Uploaded SSL Bump CA",
        issuer_cert=issuer_cert,
        issuer_key=issuer_key,
    )
    _rogue_pem, _rogue_key_pem, rogue_cert, rogue_key = _new_ca_material(
        common_name="Rogue Intermediate",
    )
    rogue_same_name_pem, _rogue_same_name_key_pem, _rogue_same_name, _key = (
        _new_ca_material(
            common_name="Docker Proxy Test Intermediate",
            issuer_cert=rogue_cert,
            issuer_key=rogue_key,
        )
    )

    r = m.parse_pfx_bundle(
        b"pfx-bytes",
        password="secret",
        run_checked=_fake_pfx_runner(
            cert_pem,
            key_pem,
            chain_pem=rogue_same_name_pem,
        ),
    )

    assert issuer_pem != rogue_same_name_pem
    assert r.ok is False
    assert "does not verify" in r.message


def test_parse_pfx_rejects_expired_issuer_chain_certificate() -> None:
    m = _import_cert_manager_module()
    expired_issuer_pem, _issuer_key_pem, expired_issuer_cert, expired_issuer_key = (
        _new_ca_material(
            common_name="Expired Docker Proxy Intermediate",
            not_before_delta=timedelta(days=-30),
            not_after_delta=timedelta(days=-1),
        )
    )
    cert_pem, key_pem, _selected_cert, _selected_key = _new_ca_material(
        common_name="Docker Proxy Uploaded SSL Bump CA",
        issuer_cert=expired_issuer_cert,
        issuer_key=expired_issuer_key,
    )

    r = m.parse_pfx_bundle(
        b"pfx-bytes",
        password="secret",
        run_checked=_fake_pfx_runner(
            cert_pem,
            key_pem,
            chain_pem=expired_issuer_pem,
        ),
    )

    assert r.ok is False
    assert "expired" in r.message


def test_parse_pfx_removes_leaf_duplicate_from_ca_chain() -> None:
    m = _import_cert_manager_module()
    cert_pem, key_pem = _pem_ca_material()

    r = m.parse_pfx_bundle(
        b"pfx-bytes",
        password="secret",
        run_checked=_fake_pfx_runner(cert_pem, key_pem, chain_pem=cert_pem),
    )

    assert r.ok is True
    assert r.bundle is not None
    assert r.bundle.cert_pem == cert_pem
    assert r.bundle.chain_pem == ""
    assert r.bundle.fullchain_pem.count("BEGIN CERTIFICATE") == 1


def test_parse_pfx_rejects_non_ca_leaf_certificate() -> None:
    m = _import_cert_manager_module()
    cert_pem, key_pem = _pem_ca_material(ca=False, key_cert_sign=False)

    r = m.parse_pfx_bundle(
        b"pfx-bytes",
        password="secret",
        run_checked=_fake_pfx_runner(cert_pem, key_pem),
    )

    assert r.ok is False
    assert "not a CA certificate" in r.message


def test_parse_pfx_rejects_ca_without_certificate_signing_usage() -> None:
    m = _import_cert_manager_module()
    cert_pem, key_pem = _pem_ca_material(ca=True, key_cert_sign=False)

    r = m.parse_pfx_bundle(
        b"pfx-bytes",
        password="secret",
        run_checked=_fake_pfx_runner(cert_pem, key_pem),
    )

    assert r.ok is False
    assert "must allow certificate signing" in r.message


def test_parse_pfx_rejects_ca_certificate_outside_validity_window() -> None:
    m = _import_cert_manager_module()
    future_cert_pem, future_key_pem = _pem_ca_material(
        not_before_delta=timedelta(days=1),
        not_after_delta=timedelta(days=30),
    )
    expired_cert_pem, expired_key_pem = _pem_ca_material(
        not_before_delta=timedelta(days=-30),
        not_after_delta=timedelta(days=-1),
    )

    future = m.parse_pfx_bundle(
        b"pfx-bytes",
        password="secret",
        run_checked=_fake_pfx_runner(future_cert_pem, future_key_pem),
    )
    expired = m.parse_pfx_bundle(
        b"pfx-bytes",
        password="secret",
        run_checked=_fake_pfx_runner(expired_cert_pem, expired_key_pem),
    )

    assert future.ok is False
    assert "not valid yet" in future.message
    assert expired.ok is False
    assert "expired" in expired.message


def test_parse_pfx_accepts_valid_ca_certificate() -> None:
    m = _import_cert_manager_module()
    cert_pem, key_pem = _pem_ca_material()

    r = m.parse_pfx_bundle(
        b"pfx-bytes",
        password="secret",
        run_checked=_fake_pfx_runner(cert_pem, key_pem),
    )

    assert r.ok is True
    assert r.bundle is not None
    assert r.bundle.cert_pem == cert_pem
    assert r.bundle.original_pfx_bytes == b"pfx-bytes"


def test_parse_pfx_selects_matching_ca_when_first_cert_and_key_are_decoys() -> None:
    m = _import_cert_manager_module()
    decoy_cert_pem, decoy_key_pem = _pem_leaf_material(common_name="Decoy Client Cert")
    ca_cert_pem, ca_key_pem = _pem_ca_material()

    r = m.parse_pfx_bundle(
        b"pfx-bytes",
        password="secret",
        run_checked=_fake_pfx_runner(
            decoy_cert_pem + ca_cert_pem,
            decoy_key_pem + ca_key_pem,
        ),
    )

    assert r.ok is True
    assert r.bundle is not None
    assert r.bundle.cert_pem == ca_cert_pem
    assert r.bundle.key_pem == ca_key_pem
    assert decoy_cert_pem not in r.bundle.chain_pem
    assert r.bundle.fullchain_pem.count("BEGIN CERTIFICATE") == 1


def test_parse_pfx_can_select_ca_private_key_from_cacerts_output() -> None:
    m = _import_cert_manager_module()
    decoy_cert_pem, decoy_key_pem = _pem_leaf_material(common_name="Decoy Client Cert")
    ca_cert_pem, ca_key_pem = _pem_ca_material()

    r = m.parse_pfx_bundle(
        b"pfx-bytes",
        password="secret",
        run_checked=_fake_pfx_runner(
            decoy_cert_pem,
            decoy_key_pem + ca_key_pem,
            chain_pem=ca_cert_pem,
        ),
    )

    assert r.ok is True
    assert r.bundle is not None
    assert r.bundle.cert_pem == ca_cert_pem
    assert r.bundle.key_pem == ca_key_pem
    assert decoy_cert_pem not in r.bundle.chain_pem
