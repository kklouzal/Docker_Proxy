from __future__ import annotations

import os
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Optional

import logging

from services.certificate_core import CertificateBundle, CertManager as _CoreCertManager, _all_pem_blocks, _first_pem_block, _run_checked as _core_run_checked, build_certificate_bundle, load_local_certificate_bundle, materialize_certificate_bundle
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
    bundle: Optional[CertificateBundle] = None


class PfxInstallError(Exception):
    pass


def _normalize_pubkey(text: str) -> str:
    return "".join([line.strip() for line in text.splitlines() if line.strip()])


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
        with open(cert_path, "r", encoding="utf-8", errors="ignore") as cert_file:
            cert_text = cert_file.read()
        with open(key_path, "r", encoding="utf-8", errors="ignore") as key_file:
            key_text = key_file.read()
    return build_certificate_bundle(cert_text, key_text, source_kind="self_signed")


def parse_pfx_bundle(pfx_bytes: bytes, password: str = "", *, run_checked=None) -> PfxInstallResult:
    if not pfx_bytes:
        return PfxInstallResult(ok=False, message="Empty PFX upload.")
    runner = run_checked or _run_checked

    try:
        with tempfile.TemporaryDirectory(prefix="pfx_install_") as tmpdir:
            pfx_path = os.path.join(tmpdir, "upload.pfx")
            leaf_path = os.path.join(tmpdir, "leaf.pem")
            chain_path = os.path.join(tmpdir, "chain.pem")
            key_path = os.path.join(tmpdir, "key.pem")

            with open(pfx_path, "wb") as handle:
                handle.write(pfx_bytes)

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
                ]
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
                    ]
                )
            except subprocess.CalledProcessError:
                with open(chain_path, "w", encoding="utf-8") as handle:
                    handle.write("")

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
                ]
            )

            with open(leaf_path, "r", encoding="utf-8", errors="ignore") as leaf_file:
                leaf_text = leaf_file.read()
            with open(chain_path, "r", encoding="utf-8", errors="ignore") as chain_file:
                chain_text = chain_file.read()
            with open(key_path, "r", encoding="utf-8", errors="ignore") as key_file:
                key_text = key_file.read()

            leaf_cert = _first_pem_block(leaf_text, "CERTIFICATE")
            if not leaf_cert:
                raise PfxInstallError("PFX does not contain a certificate.")

            private_key = (
                _first_pem_block(key_text, "PRIVATE KEY")
                or _first_pem_block(key_text, "RSA PRIVATE KEY")
                or _first_pem_block(key_text, "EC PRIVATE KEY")
            )
            if not private_key:
                raise PfxInstallError("PFX does not contain a private key.")
            if "ENCRYPTED PRIVATE KEY" in private_key:
                raise PfxInstallError("Private key is encrypted; Squid needs an unencrypted key.")

            with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as tmp_leaf:
                tmp_leaf.write(leaf_cert)
                tmp_leaf_path = tmp_leaf.name
            with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as tmp_key:
                tmp_key.write(private_key)
                tmp_key_path = tmp_key.name

            try:
                cert_pub = runner(["openssl", "x509", "-in", tmp_leaf_path, "-noout", "-pubkey"]).stdout
                key_pub = runner(["openssl", "pkey", "-in", tmp_key_path, "-pubout"]).stdout
            finally:
                try:
                    os.unlink(tmp_leaf_path)
                except OSError:
                    pass
                try:
                    os.unlink(tmp_key_path)
                except OSError:
                    pass

            if _normalize_pubkey(cert_pub) != _normalize_pubkey(key_pub):
                raise PfxInstallError("Certificate and private key do not match.")

            chain_certs = _all_pem_blocks(chain_text, "CERTIFICATE")
            bundle = build_certificate_bundle(
                leaf_cert,
                private_key,
                chain_pem="".join(chain_certs),
                source_kind="uploaded_pfx",
                original_pfx_bytes=bytes(pfx_bytes),
            )
            return PfxInstallResult(ok=True, message="PFX parsed successfully.", bundle=bundle)
    except FileNotFoundError:
        return PfxInstallResult(ok=False, message="openssl not found in container; cannot import PFX.")
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or "").strip()
        if stderr:
            return PfxInstallResult(ok=False, message=f"OpenSSL failed: {clean_text(stderr, max_len=300)}")
        return PfxInstallResult(ok=False, message="OpenSSL failed to parse PFX.")
    except PfxInstallError as exc:
        return PfxInstallResult(ok=False, message=str(exc))
    except Exception as exc:
        logger.exception("Unexpected PFX import failure")
        return PfxInstallResult(ok=False, message=public_error_message(exc, default="PFX import failed. Check server logs for details."))


def install_pfx_as_ca(ca_dir: str, pfx_bytes: bytes, password: str = "", *, run_checked=None) -> PfxInstallResult:
    os.makedirs(ca_dir, exist_ok=True)
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
            message=public_error_message(exc, default="PFX import failed. Check server logs for details."),
        )


__all__ = [
    "CertificateBundle",
    "CertManager",
    "DEFAULT_CA_DAYS_VALID",
    "DEFAULT_CA_SUBJECT",
    "PfxInstallError",
    "PfxInstallResult",
    "build_certificate_bundle",
    "generate_self_signed_ca_bundle",
    "install_pfx_as_ca",
    "load_local_certificate_bundle",
    "materialize_certificate_bundle",
    "parse_pfx_bundle",
]
