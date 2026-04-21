import hashlib
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Optional

import logging

from services.errors import clean_text, public_error_message
from services.logutil import log_exception_throttled


logger = logging.getLogger(__name__)

DEFAULT_CA_SUBJECT = "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=Squid Proxy CA"
DEFAULT_CA_DAYS_VALID = 3650


@dataclass(frozen=True)
class CertificateBundle:
    cert_pem: str
    key_pem: str
    chain_pem: str = ""
    source_kind: str = "manual"
    bundle_sha256: str = ""
    cert_sha256: str = ""
    subject_dn: str = ""
    not_before: str = ""
    not_after: str = ""
    original_pfx_bytes: Optional[bytes] = None

    @property
    def fullchain_pem(self) -> str:
        return (self.cert_pem or "") + (self.chain_pem or "")


class CertManager:
    def __init__(self, ca_dir: str = "/etc/squid/ssl/certs"):
        self.ca_dir = ca_dir

    @property
    def uploaded_pfx_path(self) -> str:
        return os.path.join(self.ca_dir, "uploaded_ca.pfx")

    @property
    def ca_cert_path(self) -> str:
        return os.path.join(self.ca_dir, "ca.crt")

    @property
    def ca_key_path(self) -> str:
        return os.path.join(self.ca_dir, "ca.key")

    def ensure_ca(self) -> str:
        if self.ca_exists():
            return self.ca_cert_path
        bundle = generate_self_signed_ca_bundle()
        materialize_certificate_bundle(self.ca_dir, bundle)
        return self.ca_cert_path

    def ca_exists(self) -> bool:
        return os.path.exists(self.ca_cert_path) and os.path.exists(self.ca_key_path)

    def load_bundle(self) -> Optional[CertificateBundle]:
        return load_local_certificate_bundle(self.ca_dir)


@dataclass(frozen=True)
class PfxInstallResult:
    ok: bool
    message: str
    bundle: Optional[CertificateBundle] = None


class PfxInstallError(Exception):
    pass


def _normalize_pem_text(text: str) -> str:
    normalized = (text or "").replace("\r\n", "\n").replace("\r", "\n").strip()
    return normalized + "\n" if normalized else ""


def _first_pem_block(pem_text: str, block_type: str) -> Optional[str]:
    pattern = re.compile(
        rf"-----BEGIN {re.escape(block_type)}-----.*?-----END {re.escape(block_type)}-----",
        re.DOTALL,
    )
    match = pattern.search(pem_text)
    return _normalize_pem_text(match.group(0)) if match else None


def _all_pem_blocks(pem_text: str, block_type: str) -> list[str]:
    pattern = re.compile(
        rf"-----BEGIN {re.escape(block_type)}-----.*?-----END {re.escape(block_type)}-----",
        re.DOTALL,
    )
    return [_normalize_pem_text(m.group(0)) for m in pattern.finditer(pem_text)]


def _split_cert_chain(cert_text: str) -> tuple[str, str]:
    certs = _all_pem_blocks(cert_text, "CERTIFICATE")
    if not certs:
        return "", ""
    leaf = certs[0]
    chain = _normalize_pem_text("".join(certs[1:])) if len(certs) > 1 else ""
    return leaf, chain


def _normalize_pubkey(text: str) -> str:
    # Avoid differences in line wrapping/newlines.
    return "".join([line.strip() for line in text.splitlines() if line.strip()])


def _passin_arg(password: str) -> str:
    # For openssl, passin requires a source. Empty password uses 'pass:'
    return f"pass:{password or ''}"


def _run_checked(args: list[str], *, timeout: int = 30) -> subprocess.CompletedProcess:
    # OpenSSL should be fast; a timeout prevents pathological hangs.
    return subprocess.run(args, capture_output=True, text=True, check=True, timeout=timeout)


def _sha256_text(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8", errors="replace")).hexdigest()


def _bundle_sha256(cert_pem: str, key_pem: str, chain_pem: str) -> str:
    payload = "\0".join([cert_pem or "", chain_pem or "", key_pem or ""])
    return _sha256_text(payload)


def _extract_certificate_metadata(cert_pem: str) -> tuple[str, str]:
    subject_dn = ""
    not_before = ""
    not_after = ""
    tmp_cert_path = ""
    try:
        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as tmp_cert:
            tmp_cert.write(_normalize_pem_text(cert_pem))
            tmp_cert_path = tmp_cert.name
        p = _run_checked(["openssl", "x509", "-in", tmp_cert_path, "-noout", "-subject", "-dates"], timeout=15)
        for line in (p.stdout or "").splitlines():
            if line.startswith("subject="):
                subject_dn = line.split("=", 1)[1].strip()
            elif line.startswith("notBefore="):
                not_before = line.split("=", 1)[1].strip()
            elif line.startswith("notAfter="):
                not_after = line.split("=", 1)[1].strip()
    except Exception:
        pass
    finally:
        if tmp_cert_path:
            try:
                os.unlink(tmp_cert_path)
            except OSError:
                pass
    return subject_dn, not_before, not_after


def build_certificate_bundle(
    cert_pem: str,
    key_pem: str,
    *,
    chain_pem: str = "",
    source_kind: str = "manual",
    original_pfx_bytes: Optional[bytes] = None,
) -> CertificateBundle:
    cert_norm = _normalize_pem_text(cert_pem)
    key_norm = _normalize_pem_text(key_pem)
    chain_norm = _normalize_pem_text(chain_pem)
    if not cert_norm or not key_norm:
        raise ValueError("Certificate bundle requires both a certificate and a private key.")
    subject_dn, not_before, not_after = _extract_certificate_metadata(cert_norm)
    return CertificateBundle(
        cert_pem=cert_norm,
        key_pem=key_norm,
        chain_pem=chain_norm,
        source_kind=(source_kind or "manual").strip() or "manual",
        bundle_sha256=_bundle_sha256(cert_norm, key_norm, chain_norm),
        cert_sha256=_sha256_text(cert_norm),
        subject_dn=subject_dn,
        not_before=not_before,
        not_after=not_after,
        original_pfx_bytes=original_pfx_bytes,
    )


def _set_best_effort_permissions(cert_path: str, key_path: str):
    try:
        os.chmod(cert_path, 0o644)
    except Exception:
        log_exception_throttled(
            logger,
            "cert_manager.chmod.cert",
            interval_seconds=300.0,
            message="Failed to chmod CA cert path",
        )
    try:
        os.chmod(key_path, 0o640)
    except Exception:
        log_exception_throttled(
            logger,
            "cert_manager.chmod.key",
            interval_seconds=300.0,
            message="Failed to chmod CA key path",
        )

    # Try to hand ownership to squid if present.
    try:
        import pwd  # type: ignore

        squid = pwd.getpwnam("squid")
        os.chown(cert_path, squid.pw_uid, squid.pw_gid)
        os.chown(key_path, squid.pw_uid, squid.pw_gid)
    except Exception:
        log_exception_throttled(
            logger,
            "cert_manager.chown.squid",
            interval_seconds=300.0,
            message="Failed to chown CA cert/key to squid user",
        )


def materialize_certificate_bundle(
    ca_dir: str,
    bundle: CertificateBundle,
    *,
    original_pfx_bytes: Optional[bytes] = None,
) -> None:
    os.makedirs(ca_dir, exist_ok=True)
    dest_cert = os.path.join(ca_dir, "ca.crt")
    dest_key = os.path.join(ca_dir, "ca.key")
    dest_pfx = os.path.join(ca_dir, "uploaded_ca.pfx")

    tmp_cert_path = ""
    tmp_key_path = ""
    tmp_pfx_path = ""
    try:
        with tempfile.NamedTemporaryFile("w", delete=False, dir=ca_dir, encoding="utf-8") as f_cert:
            f_cert.write(bundle.fullchain_pem or bundle.cert_pem)
            tmp_cert_path = f_cert.name
        with tempfile.NamedTemporaryFile("w", delete=False, dir=ca_dir, encoding="utf-8") as f_key:
            f_key.write(bundle.key_pem)
            tmp_key_path = f_key.name

        pfx_bytes = bundle.original_pfx_bytes if original_pfx_bytes is None else original_pfx_bytes
        if pfx_bytes is not None:
            with tempfile.NamedTemporaryFile("wb", delete=False, dir=ca_dir) as f_pfx:
                f_pfx.write(pfx_bytes)
                tmp_pfx_path = f_pfx.name

        os.replace(tmp_cert_path, dest_cert)
        tmp_cert_path = ""
        os.replace(tmp_key_path, dest_key)
        tmp_key_path = ""
        if tmp_pfx_path:
            os.replace(tmp_pfx_path, dest_pfx)
            tmp_pfx_path = ""
        elif os.path.exists(dest_pfx):
            os.unlink(dest_pfx)

        _set_best_effort_permissions(dest_cert, dest_key)
    finally:
        for path in (tmp_cert_path, tmp_key_path, tmp_pfx_path):
            if path:
                try:
                    os.unlink(path)
                except OSError:
                    pass


def load_local_certificate_bundle(ca_dir: str) -> Optional[CertificateBundle]:
    cert_path = os.path.join(ca_dir, "ca.crt")
    key_path = os.path.join(ca_dir, "ca.key")
    if not (os.path.exists(cert_path) and os.path.exists(key_path)):
        return None
    try:
        with open(cert_path, "r", encoding="utf-8", errors="ignore") as f_cert:
            cert_text = f_cert.read()
        with open(key_path, "r", encoding="utf-8", errors="ignore") as f_key:
            key_text = f_key.read()
        leaf_cert, chain_pem = _split_cert_chain(cert_text)
        if not leaf_cert:
            return None
        private_key = (
            _first_pem_block(key_text, "PRIVATE KEY")
            or _first_pem_block(key_text, "RSA PRIVATE KEY")
            or _first_pem_block(key_text, "EC PRIVATE KEY")
        )
        if not private_key:
            return None
        original_pfx_bytes = None
        uploaded_pfx_path = os.path.join(ca_dir, "uploaded_ca.pfx")
        if os.path.exists(uploaded_pfx_path):
            try:
                with open(uploaded_pfx_path, "rb") as f_pfx:
                    original_pfx_bytes = f_pfx.read()
            except Exception:
                original_pfx_bytes = None
        return build_certificate_bundle(
            leaf_cert,
            private_key,
            chain_pem=chain_pem,
            source_kind="local",
            original_pfx_bytes=original_pfx_bytes,
        )
    except Exception:
        return None


def generate_self_signed_ca_bundle(
    *,
    subject: str = DEFAULT_CA_SUBJECT,
    days_valid: int = DEFAULT_CA_DAYS_VALID,
) -> CertificateBundle:
    with tempfile.TemporaryDirectory(prefix="generated_ca_") as tmpdir:
        key_path = os.path.join(tmpdir, "ca.key")
        cert_path = os.path.join(tmpdir, "ca.crt")
        _run_checked(["openssl", "genrsa", "-out", key_path, "2048"], timeout=60)
        _run_checked(
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
        with open(cert_path, "r", encoding="utf-8", errors="ignore") as f_cert:
            cert_text = f_cert.read()
        with open(key_path, "r", encoding="utf-8", errors="ignore") as f_key:
            key_text = f_key.read()
    return build_certificate_bundle(cert_text, key_text, source_kind="self_signed")


def parse_pfx_bundle(pfx_bytes: bytes, password: str = "") -> PfxInstallResult:
    if not pfx_bytes:
        return PfxInstallResult(ok=False, message="Empty PFX upload.")

    try:
        with tempfile.TemporaryDirectory(prefix="pfx_install_") as tmpdir:
            pfx_path = os.path.join(tmpdir, "upload.pfx")
            leaf_path = os.path.join(tmpdir, "leaf.pem")
            chain_path = os.path.join(tmpdir, "chain.pem")
            key_path = os.path.join(tmpdir, "key.pem")

            with open(pfx_path, "wb") as f:
                f.write(pfx_bytes)

            passin = _passin_arg(password)

            _run_checked(
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
                _run_checked(
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
                with open(chain_path, "w", encoding="utf-8") as f:
                    f.write("")

            _run_checked(
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

            with open(leaf_path, "r", encoding="utf-8", errors="ignore") as f:
                leaf_text = f.read()
            with open(chain_path, "r", encoding="utf-8", errors="ignore") as f:
                chain_text = f.read()
            with open(key_path, "r", encoding="utf-8", errors="ignore") as f:
                key_text = f.read()

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
                cert_pub = _run_checked(["openssl", "x509", "-in", tmp_leaf_path, "-noout", "-pubkey"]).stdout
                key_pub = _run_checked(["openssl", "pkey", "-in", tmp_key_path, "-pubout"]).stdout
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
    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or "").strip()
        if stderr:
            return PfxInstallResult(ok=False, message=f"OpenSSL failed: {clean_text(stderr, max_len=300)}")
        return PfxInstallResult(ok=False, message="OpenSSL failed to parse PFX.")
    except PfxInstallError as e:
        return PfxInstallResult(ok=False, message=str(e))
    except Exception as e:
        logger.exception("Unexpected PFX import failure")
        return PfxInstallResult(ok=False, message=public_error_message(e, default="PFX import failed. Check server logs for details."))


def install_pfx_as_ca(ca_dir: str, pfx_bytes: bytes, password: str = "") -> PfxInstallResult:
    """Install a user-provided PKCS#12 (.pfx/.p12) as Squid's ssl-bump CA.

    This extracts a leaf certificate + private key from the PFX, validates that
    they match, writes them as PEM to ca.crt / ca.key, and persists the original
    PFX as uploaded_ca.pfx.
    """
    os.makedirs(ca_dir, exist_ok=True)
    result = parse_pfx_bundle(pfx_bytes, password=password)
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
    except Exception as e:
        logger.exception("Unexpected PFX materialization failure")
        return PfxInstallResult(
            ok=False,
            message=public_error_message(e, default="PFX import failed. Check server logs for details."),
        )