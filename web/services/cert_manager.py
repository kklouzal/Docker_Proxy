from __future__ import annotations

import contextlib
import logging
import os
import pathlib
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime

from cryptography import x509

from services.certificate_core import (
    CertificateBundle,
    _all_pem_blocks,
    _first_pem_block,
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

            leaf_cert = _first_pem_block(leaf_text, "CERTIFICATE")
            if not leaf_cert:
                msg = "PFX does not contain a certificate."
                raise PfxInstallError(msg)

            private_key = (
                _first_pem_block(key_text, "PRIVATE KEY")
                or _first_pem_block(key_text, "RSA PRIVATE KEY")
                or _first_pem_block(key_text, "EC PRIVATE KEY")
            )
            if not private_key and "BEGIN ENCRYPTED PRIVATE KEY" in key_text:
                msg = "Private key is encrypted; Squid needs an unencrypted key."
                raise PfxInstallError(msg)
            if not private_key:
                msg = "PFX does not contain a private key."
                raise PfxInstallError(msg)
            if "ENCRYPTED PRIVATE KEY" in private_key:
                msg = "Private key is encrypted; Squid needs an unencrypted key."
                raise PfxInstallError(msg)

            with tempfile.NamedTemporaryFile(
                "w",
                delete=False,
                encoding="utf-8",
            ) as tmp_leaf:
                tmp_leaf.write(leaf_cert)
                tmp_leaf_path = tmp_leaf.name
            with tempfile.NamedTemporaryFile(
                "w",
                delete=False,
                encoding="utf-8",
            ) as tmp_key:
                tmp_key.write(private_key)
                tmp_key_path = tmp_key.name

            try:
                cert_pub = runner(
                    ["openssl", "x509", "-in", tmp_leaf_path, "-noout", "-pubkey"],
                ).stdout
                key_pub = runner(
                    ["openssl", "pkey", "-in", tmp_key_path, "-pubout"],
                ).stdout
            finally:
                with contextlib.suppress(OSError):
                    pathlib.Path(tmp_leaf_path).unlink()
                with contextlib.suppress(OSError):
                    pathlib.Path(tmp_key_path).unlink()

            if _normalize_pubkey(cert_pub) != _normalize_pubkey(key_pub):
                msg = "Certificate and private key do not match."
                raise PfxInstallError(msg)

            _validate_ssl_bump_ca_certificate(leaf_cert)

            chain_certs = _all_pem_blocks(chain_text, "CERTIFICATE")
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
