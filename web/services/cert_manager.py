from __future__ import annotations

import logging
import os
import pathlib
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

from services.certificate_core import (
    CertificateBundle,
    _all_pem_blocks,
    build_certificate_bundle,
    load_local_certificate_bundle,
    materialize_certificate_bundle,
)
from services.certificate_core import CertManager as _CoreCertManager
from services.certificate_core import _run_checked as _core_run_checked
from services.errors import clean_text, public_error_message

logger = logging.getLogger(__name__)

DEFAULT_CA_SUBJECT = "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=Squid Proxy CA"
DEFAULT_CA_DAYS_VALID = 3650
_run_checked = _core_run_checked


class CertManager(_CoreCertManager):
    def ensure_ca(self) -> str:
        if self.ca_exists():
            return self.ca_cert_path
        bundle = generate_self_signed_ca_bundle()
        materialize_certificate_bundle(self.ca_dir, bundle)
        return self.ca_cert_path


@dataclass(frozen=True)
class PfxInstallResult:
    ok: bool
    message: str
    bundle: CertificateBundle | None = None


class PfxInstallError(Exception):
    pass


def _normalize_pubkey(text: str) -> str:
    return "".join([line.strip() for line in text.splitlines() if line.strip()])


def _public_key_bytes(key: object) -> bytes:
    return key.public_key().public_bytes(  # type: ignore[attr-defined]
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _certificate_and_key_match(cert_pem: str, key_pem: str) -> bool:
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
        key = serialization.load_pem_private_key(
            key_pem.encode("utf-8"),
            password=None,
        )
        return _public_key_bytes(cert) == _public_key_bytes(key)
    except Exception:
        return False


def _unique_pem_blocks(blocks: list[str]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for block in blocks:
        normalized = _normalize_pubkey(block)
        if normalized in seen:
            continue
        seen.add(normalized)
        unique.append(block)
    return unique


def _private_key_blocks(key_text: str) -> list[str]:
    return _unique_pem_blocks(
        _all_pem_blocks(key_text, "PRIVATE KEY")
        + _all_pem_blocks(key_text, "RSA PRIVATE KEY")
        + _all_pem_blocks(key_text, "EC PRIVATE KEY"),
    )


def _select_ssl_bump_ca_material(
    cert_candidates: list[str],
    private_keys: list[str],
) -> tuple[str, str]:
    first_ca_error = ""
    for cert_pem in cert_candidates:
        for key_pem in private_keys:
            if not _certificate_and_key_match(cert_pem, key_pem):
                continue
            try:
                _validate_ssl_bump_ca_certificate(cert_pem)
            except PfxInstallError as exc:
                if not first_ca_error:
                    first_ca_error = str(exc)
                continue
            return cert_pem, key_pem
    if first_ca_error:
        raise PfxInstallError(first_ca_error)
    msg = "Certificate and private key do not match."
    raise PfxInstallError(msg)


def _validate_ssl_bump_ca_certificate(cert_pem: str) -> None:
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
    except Exception as exc:
        msg = "PFX certificate is not valid PEM material."
        raise PfxInstallError(msg) from exc

    now = datetime.now(UTC)
    if now < cert.not_valid_before_utc:
        msg = "PFX certificate is not valid yet."
        raise PfxInstallError(msg)
    if now >= cert.not_valid_after_utc:
        msg = "PFX certificate is expired."
        raise PfxInstallError(msg)

    try:
        basic_constraints = cert.extensions.get_extension_for_class(
            x509.BasicConstraints,
        ).value
    except x509.ExtensionNotFound as exc:
        msg = "PFX certificate must include a CA basic constraints extension."
        raise PfxInstallError(msg) from exc
    if not basic_constraints.ca:
        msg = "PFX certificate is not a CA certificate."
        raise PfxInstallError(msg)

    try:
        key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        return
    if not key_usage.key_cert_sign:
        msg = "PFX CA certificate key usage must allow certificate signing."
        raise PfxInstallError(msg)


def _certificate_identity(cert_pem: str) -> str:
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
        return f"sha256:{cert.fingerprint(hashes.SHA256()).hex()}"
    except Exception:
        return f"pem:{_normalize_pubkey(cert_pem)}"


def _certificate_identity_from_cert(cert: x509.Certificate) -> str:
    return f"sha256:{cert.fingerprint(hashes.SHA256()).hex()}"


def _verify_certificate_signature(
    child: x509.Certificate,
    issuer: x509.Certificate,
) -> bool:
    if child.issuer != issuer.subject:
        return False
    public_key = issuer.public_key()
    try:
        if isinstance(public_key, rsa.RSAPublicKey | ec.EllipticCurvePublicKey):
            parameters = child.signature_algorithm_parameters
            if parameters is None:
                return False
            public_key.verify(
                child.signature,
                child.tbs_certificate_bytes,
                parameters,
                child.signature_hash_algorithm,
            )
        elif isinstance(public_key, dsa.DSAPublicKey):
            hash_algorithm = child.signature_hash_algorithm
            if hash_algorithm is None:
                return False
            public_key.verify(
                child.signature,
                child.tbs_certificate_bytes,
                hash_algorithm,
            )
        elif isinstance(
            public_key,
            ed25519.Ed25519PublicKey | ed448.Ed448PublicKey,
        ):
            public_key.verify(child.signature, child.tbs_certificate_bytes)
        else:
            return False
    except (InvalidSignature, TypeError, ValueError, UnsupportedAlgorithm):
        return False
    return True


def _validate_issuer_ca_certificate(cert: x509.Certificate) -> None:
    now = datetime.now(UTC)
    if now < cert.not_valid_before_utc:
        msg = "PFX issuer chain certificate is not valid yet."
        raise PfxInstallError(msg)
    if now >= cert.not_valid_after_utc:
        msg = "PFX issuer chain certificate is expired."
        raise PfxInstallError(msg)

    try:
        basic_constraints = cert.extensions.get_extension_for_class(
            x509.BasicConstraints,
        ).value
    except x509.ExtensionNotFound as exc:
        msg = "PFX issuer chain certificate must include a CA basic constraints extension."
        raise PfxInstallError(msg) from exc
    if not basic_constraints.ca:
        msg = "PFX issuer chain certificate is not a CA certificate."
        raise PfxInstallError(msg)

    try:
        key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        return
    if not key_usage.key_cert_sign:
        msg = "PFX issuer chain certificate key usage must allow certificate signing."
        raise PfxInstallError(msg)


def _chain_certificates_from_pem_blocks(
    selected_cert_pem: str,
    chain_certs: list[str],
) -> list[tuple[str, x509.Certificate, str]]:
    try:
        selected_cert = x509.load_pem_x509_certificate(
            selected_cert_pem.encode("utf-8"),
        )
    except Exception as exc:
        msg = "PFX certificate is not valid PEM material."
        raise PfxInstallError(msg) from exc

    selected_identity = _certificate_identity_from_cert(selected_cert)
    seen = {selected_identity}
    parsed: list[tuple[str, x509.Certificate, str]] = []
    for chain_cert_pem in chain_certs:
        try:
            chain_cert = x509.load_pem_x509_certificate(
                chain_cert_pem.encode("utf-8"),
            )
        except Exception as exc:
            msg = "PFX issuer chain includes invalid certificate PEM material."
            raise PfxInstallError(msg) from exc
        identity = _certificate_identity_from_cert(chain_cert)
        if identity in seen:
            continue
        seen.add(identity)
        parsed.append((chain_cert_pem, chain_cert, identity))
    return parsed


def _orders_as_alternate_issuer(
    candidate: x509.Certificate,
    ordered_children: list[x509.Certificate],
) -> bool:
    try:
        _validate_issuer_ca_certificate(candidate)
    except PfxInstallError:
        return False
    return any(
        child.issuer == candidate.subject
        and _verify_certificate_signature(child, candidate)
        for child in ordered_children
    )


def _validated_ordered_chain_certificates(
    selected_cert_pem: str,
    chain_certs: list[str],
) -> list[str]:
    try:
        selected_cert = x509.load_pem_x509_certificate(
            selected_cert_pem.encode("utf-8"),
        )
    except Exception as exc:
        msg = "PFX certificate is not valid PEM material."
        raise PfxInstallError(msg) from exc

    available = _chain_certificates_from_pem_blocks(selected_cert_pem, chain_certs)
    ordered: list[tuple[str, x509.Certificate, str]] = []
    ordered_children = [selected_cert]
    used = {_certificate_identity_from_cert(selected_cert)}
    current = selected_cert

    while not _verify_certificate_signature(current, current):
        subject_matches = [
            candidate
            for candidate in available
            if candidate[2] not in used and candidate[1].subject == current.issuer
        ]
        verified_matches = [
            candidate
            for candidate in subject_matches
            if _verify_certificate_signature(current, candidate[1])
        ]
        if not verified_matches:
            if subject_matches:
                msg = "PFX issuer chain certificate does not verify the selected CA signature."
                raise PfxInstallError(msg)
            unused = [candidate for candidate in available if candidate[2] not in used]
            if unused:
                msg = (
                    "PFX issuer chain includes certificate(s) that do not form a "
                    "verified issuer chain for the selected CA."
                )
                raise PfxInstallError(msg)
            break

        chosen: tuple[str, x509.Certificate, str] | None = None
        first_error = ""
        for candidate in verified_matches:
            try:
                _validate_issuer_ca_certificate(candidate[1])
            except PfxInstallError as exc:
                if not first_error:
                    first_error = str(exc)
                continue
            chosen = candidate
            break
        if chosen is None:
            raise PfxInstallError(first_error or "PFX issuer chain certificate is invalid.")

        ordered.append(chosen)
        ordered_children.append(chosen[1])
        used.add(chosen[2])
        current = chosen[1]

    unused = [candidate for candidate in available if candidate[2] not in used]
    unexpected = [
        candidate
        for candidate in unused
        if not _orders_as_alternate_issuer(candidate[1], ordered_children)
    ]
    if unexpected:
        msg = (
            "PFX issuer chain includes certificate(s) that do not form a verified "
            "issuer chain for the selected CA."
        )
        raise PfxInstallError(msg)

    return [chain_cert_pem for chain_cert_pem, _cert, _identity in ordered]


def _passin_arg(password: str) -> str:
    return f"pass:{password or ''}"


def generate_self_signed_ca_bundle(
    *,
    subject: str = DEFAULT_CA_SUBJECT,
    days_valid: int = DEFAULT_CA_DAYS_VALID,
    run_checked=None,
) -> CertificateBundle:
    runner = run_checked or _run_checked
    with tempfile.TemporaryDirectory(prefix="generated_ca_") as tmpdir:
        key_path = os.path.join(tmpdir, "ca.key")
        cert_path = os.path.join(tmpdir, "ca.crt")
        runner(["openssl", "genrsa", "-out", key_path, "2048"], timeout=60)
        runner(
            [
                "openssl",
                "req",
                "-x509",
                "-new",
                "-nodes",
                "-key",
                key_path,
                "-sha256",
                "-days",
                str(int(days_valid)),
                "-out",
                cert_path,
                "-subj",
                subject,
            ],
            timeout=60,
        )
        cert_text = pathlib.Path(cert_path).read_text(encoding="utf-8", errors="ignore")
        key_text = pathlib.Path(key_path).read_text(encoding="utf-8", errors="ignore")
    return build_certificate_bundle(cert_text, key_text, source_kind="self_signed")


def parse_pfx_bundle(
    pfx_bytes: bytes,
    password: str = "",
    *,
    run_checked=None,
) -> PfxInstallResult:
    if not pfx_bytes:
        return PfxInstallResult(ok=False, message="Empty PFX upload.")
    runner = run_checked or _run_checked

    try:
        with tempfile.TemporaryDirectory(prefix="pfx_install_") as tmpdir:
            pfx_path = os.path.join(tmpdir, "upload.pfx")
            leaf_path = os.path.join(tmpdir, "leaf.pem")
            chain_path = os.path.join(tmpdir, "chain.pem")
            key_path = os.path.join(tmpdir, "key.pem")

            pathlib.Path(pfx_path).write_bytes(pfx_bytes)

            passin = _passin_arg(password)

            runner(
                [
                    "openssl",
                    "pkcs12",
                    "-in",
                    pfx_path,
                    "-clcerts",
                    "-nokeys",
                    "-out",
                    leaf_path,
                    "-passin",
                    passin,
                ],
            )

            try:
                runner(
                    [
                        "openssl",
                        "pkcs12",
                        "-in",
                        pfx_path,
                        "-cacerts",
                        "-nokeys",
                        "-out",
                        chain_path,
                        "-passin",
                        passin,
                    ],
                )
            except subprocess.CalledProcessError:
                pathlib.Path(chain_path).write_text("", encoding="utf-8")

            runner(
                [
                    "openssl",
                    "pkcs12",
                    "-in",
                    pfx_path,
                    "-nocerts",
                    "-nodes",
                    "-out",
                    key_path,
                    "-passin",
                    passin,
                ],
            )

            leaf_text = pathlib.Path(leaf_path).read_text(
                encoding="utf-8",
                errors="ignore",
            )
            chain_text = pathlib.Path(chain_path).read_text(
                encoding="utf-8",
                errors="ignore",
            )
            key_text = pathlib.Path(key_path).read_text(
                encoding="utf-8",
                errors="ignore",
            )

            cert_candidates = _unique_pem_blocks(
                _all_pem_blocks(leaf_text, "CERTIFICATE")
                + _all_pem_blocks(chain_text, "CERTIFICATE"),
            )
            if not cert_candidates:
                msg = "PFX does not contain a certificate."
                raise PfxInstallError(msg)

            private_keys = _private_key_blocks(key_text)
            if not private_keys and "BEGIN ENCRYPTED PRIVATE KEY" in key_text:
                msg = "Private key is encrypted; Squid needs an unencrypted key."
                raise PfxInstallError(msg)
            if not private_keys:
                msg = "PFX does not contain a private key."
                raise PfxInstallError(msg)
            if any("ENCRYPTED PRIVATE KEY" in private_key for private_key in private_keys):
                msg = "Private key is encrypted; Squid needs an unencrypted key."
                raise PfxInstallError(msg)

            leaf_cert, private_key = _select_ssl_bump_ca_material(
                cert_candidates,
                private_keys,
            )

            chain_certs = _validated_ordered_chain_certificates(
                leaf_cert,
                _all_pem_blocks(chain_text, "CERTIFICATE"),
            )
            bundle = build_certificate_bundle(
                leaf_cert,
                private_key,
                chain_pem="".join(chain_certs),
                source_kind="uploaded_pfx",
                original_pfx_bytes=bytes(pfx_bytes),
            )
            return PfxInstallResult(
                ok=True,
                message="PFX parsed successfully.",
                bundle=bundle,
            )
    except FileNotFoundError:
        return PfxInstallResult(
            ok=False,
            message="openssl not found in container; cannot import PFX.",
        )
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or "").strip()
        if stderr:
            return PfxInstallResult(
                ok=False,
                message=f"OpenSSL failed: {clean_text(stderr, max_len=300)}",
            )
        return PfxInstallResult(ok=False, message="OpenSSL failed to parse PFX.")
    except PfxInstallError as exc:
        return PfxInstallResult(ok=False, message=str(exc))
    except Exception as exc:
        logger.exception("Unexpected PFX import failure")
        return PfxInstallResult(
            ok=False,
            message=public_error_message(
                exc,
                default="PFX import failed. Check server logs for details.",
            ),
        )


def install_pfx_as_ca(
    ca_dir: str,
    pfx_bytes: bytes,
    password: str = "",
    *,
    run_checked=None,
) -> PfxInstallResult:
    pathlib.Path(ca_dir).mkdir(exist_ok=True, parents=True)
    result = parse_pfx_bundle(pfx_bytes, password=password, run_checked=run_checked)
    if not result.ok or result.bundle is None:
        return result

    try:
        materialize_certificate_bundle(
            ca_dir,
            result.bundle,
            original_pfx_bytes=result.bundle.original_pfx_bytes,
        )
        return PfxInstallResult(
            ok=True,
            message="PFX installed; Squid will use it for SSL-bump.",
            bundle=result.bundle,
        )
    except Exception as exc:
        logger.exception("Unexpected PFX materialization failure")
        return PfxInstallResult(
            ok=False,
            message=public_error_message(
                exc,
                default="PFX import failed. Check server logs for details.",
            ),
        )


__all__ = [
    "DEFAULT_CA_DAYS_VALID",
    "DEFAULT_CA_SUBJECT",
    "CertManager",
    "CertificateBundle",
    "PfxInstallError",
    "PfxInstallResult",
    "build_certificate_bundle",
    "generate_self_signed_ca_bundle",
    "install_pfx_as_ca",
    "load_local_certificate_bundle",
    "materialize_certificate_bundle",
    "parse_pfx_bundle",
]
