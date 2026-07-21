from __future__ import annotations

import contextlib
import fcntl
import hashlib
import ipaddress
import logging
import os
import pathlib
import re
import socket
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from services.logutil import log_exception_throttled

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

logger = logging.getLogger(__name__)


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
    original_pfx_bytes: bytes | None = None

    @property
    def fullchain_pem(self) -> str:
        return (self.cert_pem or "") + (self.chain_pem or "")


@dataclass(frozen=True)
class TlsMaterialPathStatus:
    path: str
    configured: bool
    readable: bool
    non_empty: bool
    valid: bool
    detail: str
    size: int = 0


@dataclass(frozen=True)
class TlsMaterialValidation:
    cert_status: TlsMaterialPathStatus
    key_status: TlsMaterialPathStatus
    ready: bool
    detail: str


@dataclass(frozen=True)
class AdminUiCertificateMaterial:
    certfile: str
    keyfile: str
    sans: tuple[str, ...]


ADMIN_UI_CERT_FILENAME = "admin-ui.crt"
ADMIN_UI_KEY_FILENAME = "admin-ui.key"
_DEFAULT_ADMIN_UI_DNS_SANS = ("localhost", "admin-ui", "docker-proxy-admin-ui")
_DEFAULT_ADMIN_UI_IP_SANS = ("127.0.0.1", "::1")


class CertManager:
    def __init__(self, ca_dir: str = "/etc/squid/ssl/certs") -> None:
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

    def ca_exists(self) -> bool:
        return (
            pathlib.Path(self.ca_cert_path).exists()
            and pathlib.Path(self.ca_key_path).exists()
        )

    def load_bundle(self) -> CertificateBundle | None:
        return load_local_certificate_bundle(self.ca_dir)


def _normalize_pem_text(text: str) -> str:
    normalized = (text or "").replace("\r\n", "\n").replace("\r", "\n").strip()
    return normalized + "\n" if normalized else ""


def _first_pem_block(pem_text: str, block_type: str) -> str | None:
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
    return [_normalize_pem_text(match.group(0)) for match in pattern.finditer(pem_text)]


def _split_cert_chain(cert_text: str) -> tuple[str, str]:
    certs = _all_pem_blocks(cert_text, "CERTIFICATE")
    if not certs:
        return "", ""
    leaf = certs[0]
    chain = _normalize_pem_text("".join(certs[1:])) if len(certs) > 1 else ""
    return leaf, chain


def _run_checked(args: list[str], *, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        check=True,
        timeout=timeout,
    )


def _sha256_text(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8", errors="replace")).hexdigest()


@contextlib.contextmanager
def _certificate_material_install_lock(ca_dir: str):
    lock_path = pathlib.Path(ca_dir) / ".certificate-materialize.lock"
    with lock_path.open("a+b") as lock_file:
        with contextlib.suppress(OSError):
            lock_path.chmod(0o600)
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _path_status(
    path: str,
    *,
    parser: Callable[[bytes], object],
    material_name: str,
) -> tuple[TlsMaterialPathStatus, object | None]:
    clean_path = (path or "").strip()
    if not clean_path:
        return (
            TlsMaterialPathStatus(
                path="",
                configured=False,
                readable=False,
                non_empty=False,
                valid=False,
                detail=f"{material_name} path is not configured.",
            ),
            None,
        )
    path_obj = pathlib.Path(clean_path)
    if not path_obj.is_file():
        return (
            TlsMaterialPathStatus(
                path=clean_path,
                configured=True,
                readable=False,
                non_empty=False,
                valid=False,
                detail=f"{material_name} file does not exist.",
            ),
            None,
        )
    if not os.access(clean_path, os.R_OK):
        return (
            TlsMaterialPathStatus(
                path=clean_path,
                configured=True,
                readable=False,
                non_empty=False,
                valid=False,
                detail=f"{material_name} file is not readable.",
            ),
            None,
        )
    try:
        data = path_obj.read_bytes()
    except OSError:
        return (
            TlsMaterialPathStatus(
                path=clean_path,
                configured=True,
                readable=False,
                non_empty=False,
                valid=False,
                detail=f"{material_name} file is not readable.",
            ),
            None,
        )
    size = len(data)
    if size <= 0:
        return (
            TlsMaterialPathStatus(
                path=clean_path,
                configured=True,
                readable=True,
                non_empty=False,
                valid=False,
                detail=f"{material_name} file is empty.",
                size=size,
            ),
            None,
        )
    try:
        parsed = parser(data)
    except Exception:
        return (
            TlsMaterialPathStatus(
                path=clean_path,
                configured=True,
                readable=True,
                non_empty=True,
                valid=False,
                detail=f"{material_name} file is not valid PEM material.",
                size=size,
            ),
            None,
        )
    return (
        TlsMaterialPathStatus(
            path=clean_path,
            configured=True,
            readable=True,
            non_empty=True,
            valid=True,
            detail=f"{material_name} file is valid.",
            size=size,
        ),
        parsed,
    )


def _load_pem_certificate(data: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(data)


def _load_pem_private_key(data: bytes) -> object:
    return serialization.load_pem_private_key(data, password=None)


def _public_key_bytes(key: object) -> bytes:
    return key.public_key().public_bytes(  # type: ignore[attr-defined]
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _certificate_validity_detail(cert: x509.Certificate) -> str:
    now = datetime.now(UTC)
    if now < cert.not_valid_before_utc:
        return "certificate is not valid yet."
    if now >= cert.not_valid_after_utc:
        return "certificate is expired."
    return ""


def validate_tls_material_paths(certfile: str, keyfile: str) -> TlsMaterialValidation:
    cert_status, cert = _path_status(
        certfile,
        parser=_load_pem_certificate,
        material_name="certificate",
    )
    key_status, key = _path_status(
        keyfile,
        parser=_load_pem_private_key,
        material_name="private key",
    )
    if not cert_status.valid or not key_status.valid:
        detail = "; ".join(
            status.detail for status in (cert_status, key_status) if not status.valid
        )
        return TlsMaterialValidation(
            cert_status=cert_status,
            key_status=key_status,
            ready=False,
            detail=detail,
        )
    validity_detail = _certificate_validity_detail(cert)
    if validity_detail:
        return TlsMaterialValidation(
            cert_status=cert_status,
            key_status=key_status,
            ready=False,
            detail=validity_detail,
        )
    try:
        if _public_key_bytes(cert) != _public_key_bytes(key):
            return TlsMaterialValidation(
                cert_status=cert_status,
                key_status=key_status,
                ready=False,
                detail="certificate and private key do not match.",
            )
    except Exception:
        return TlsMaterialValidation(
            cert_status=cert_status,
            key_status=key_status,
            ready=False,
            detail="certificate and private key could not be compared.",
        )
    return TlsMaterialValidation(
        cert_status=cert_status,
        key_status=key_status,
        ready=True,
        detail="certificate and private key are valid.",
    )


def _dns_san_valid(hostname: str) -> bool:
    if not hostname or len(hostname) > 253:
        return False
    hostname = hostname.removesuffix(".")
    labels = hostname.split(".")
    label_re = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
    return all(label_re.fullmatch(label or "") for label in labels)


def sanitize_admin_ui_certificate_san_token(token: object) -> str:
    value = str(token or "").split(",", 1)[0].strip().rstrip(".")
    if not value:
        return ""
    if "://" in value:
        from urllib.parse import urlsplit

        parsed = urlsplit(value)
        if parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
            return ""
        value = (parsed.hostname or "").strip().strip("[]").rstrip(".")
    elif value.startswith("["):
        from urllib.parse import urlsplit

        try:
            parsed = urlsplit(f"//{value}")
            value = (parsed.hostname or "").strip().strip("[]").rstrip(".")
        except ValueError:
            return ""
    elif "/" in value or "@" in value or "\\" in value or "*" in value:
        return ""
    elif value.count(":") == 1 and not value.startswith("["):
        host, port = value.rsplit(":", 1)
        if port.isdigit():
            value = host.strip().strip("[]").rstrip(".")
    else:
        value = value.strip().strip("[]").rstrip(".")
    return value


def normalize_admin_ui_certificate_sans(
    tokens: Iterable[object] = (),
) -> tuple[str, ...]:
    sans: list[str] = []
    seen: set[str] = set()

    def add(value: object) -> None:
        clean = sanitize_admin_ui_certificate_san_token(value)
        if not clean:
            return
        try:
            ip = ipaddress.ip_address(clean)
        except ValueError:
            dns = clean.lower()
            if not _dns_san_valid(dns):
                return
            key = f"dns:{dns}"
            display = dns
        else:
            key = f"ip:{ip.compressed}"
            display = ip.compressed
        if key not in seen:
            seen.add(key)
            sans.append(display)

    for token in tokens:
        add(token)
    for token in _DEFAULT_ADMIN_UI_DNS_SANS:
        add(token)
    for token in _DEFAULT_ADMIN_UI_IP_SANS:
        add(token)
    for token in (socket.gethostname(), socket.getfqdn()):
        add(token)
    return tuple(sans)


def _general_names_for_sans(sans: Iterable[str]) -> list[x509.GeneralName]:
    names: list[x509.GeneralName] = []
    for san in sans:
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(san)))
        except ValueError:
            names.append(x509.DNSName(san))
    return names


def _load_bundle_ca_material(
    bundle: CertificateBundle | object,
) -> tuple[x509.Certificate, object]:
    cert_pem = str(getattr(bundle, "cert_pem", "") or "")
    key_pem = str(getattr(bundle, "key_pem", "") or "")
    fullchain_pem = str(getattr(bundle, "fullchain_pem", "") or "")
    if not cert_pem and fullchain_pem:
        cert_pem, _chain = _split_cert_chain(fullchain_pem)
    if not cert_pem or not key_pem:
        msg = "Admin UI HTTPS leaf generation requires active CA certificate and private key material."
        raise ValueError(msg)
    ca_cert = _load_pem_certificate(cert_pem.encode("utf-8"))
    ca_key = _load_pem_private_key(key_pem.encode("utf-8"))
    return ca_cert, ca_key


def materialize_admin_ui_server_certificate(
    ca_dir: str,
    bundle: CertificateBundle | object,
    *,
    san_tokens: Iterable[object] = (),
) -> AdminUiCertificateMaterial:
    pathlib.Path(ca_dir).mkdir(exist_ok=True, parents=True)
    ca_cert, ca_key = _load_bundle_ca_material(bundle)
    sans = normalize_admin_ui_certificate_sans(san_tokens)
    general_names = _general_names_for_sans(sans)
    if not general_names:
        msg = "Admin UI HTTPS leaf generation requires at least one valid SAN."
        raise ValueError(msg)

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(UTC)
    not_after = min(ca_cert.not_valid_after_utc, now + timedelta(days=825))
    if not_after <= now + timedelta(days=1):
        not_after = ca_cert.not_valid_after_utc
    cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name(
                [x509.NameAttribute(NameOID.COMMON_NAME, "Docker Proxy Admin UI")]
            ),
        )
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(x509.SubjectAlternativeName(general_names), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    certfile = os.path.join(ca_dir, ADMIN_UI_CERT_FILENAME)
    keyfile = os.path.join(ca_dir, ADMIN_UI_KEY_FILENAME)
    tmp_cert_path = ""
    tmp_key_path = ""
    try:
        with tempfile.NamedTemporaryFile(
            "wb",
            delete=False,
            dir=ca_dir,
        ) as cert_tmp:
            cert_tmp.write(cert.public_bytes(serialization.Encoding.PEM))
            tmp_cert_path = cert_tmp.name
        with tempfile.NamedTemporaryFile(
            "wb",
            delete=False,
            dir=ca_dir,
        ) as key_tmp:
            key_tmp.write(
                leaf_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                ),
            )
            tmp_key_path = key_tmp.name
        with _certificate_material_install_lock(ca_dir):
            pathlib.Path(tmp_cert_path).replace(certfile)
            tmp_cert_path = ""
            pathlib.Path(tmp_key_path).replace(keyfile)
            tmp_key_path = ""
            _set_best_effort_permissions(certfile, keyfile)
    finally:
        for path in (tmp_cert_path, tmp_key_path):
            if path:
                with contextlib.suppress(OSError):
                    pathlib.Path(path).unlink()
    return AdminUiCertificateMaterial(certfile=certfile, keyfile=keyfile, sans=sans)


def _bundle_sha256(cert_pem: str, key_pem: str, chain_pem: str) -> str:
    payload = "\0".join([cert_pem or "", chain_pem or "", key_pem or ""])
    return _sha256_text(payload)


def _extract_certificate_metadata(cert_pem: str) -> tuple[str, str, str]:
    subject_dn = ""
    not_before = ""
    not_after = ""
    tmp_cert_path = ""
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            delete=False,
            encoding="utf-8",
        ) as tmp_cert:
            tmp_cert.write(_normalize_pem_text(cert_pem))
            tmp_cert_path = tmp_cert.name
        proc = _run_checked(
            ["openssl", "x509", "-in", tmp_cert_path, "-noout", "-subject", "-dates"],
            timeout=15,
        )
        for line in (proc.stdout or "").splitlines():
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
            with contextlib.suppress(OSError):
                pathlib.Path(tmp_cert_path).unlink()
    return subject_dn, not_before, not_after


def build_certificate_bundle(
    cert_pem: str,
    key_pem: str,
    *,
    chain_pem: str = "",
    source_kind: str = "manual",
    original_pfx_bytes: bytes | None = None,
) -> CertificateBundle:
    cert_norm = _normalize_pem_text(cert_pem)
    key_norm = _normalize_pem_text(key_pem)
    chain_norm = _normalize_pem_text(chain_pem)
    if not cert_norm or not key_norm:
        msg = "Certificate bundle requires both a certificate and a private key."
        raise ValueError(msg)
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


def _set_best_effort_permissions(cert_path: str, key_path: str) -> None:
    try:
        pathlib.Path(cert_path).chmod(0o644)
    except Exception:
        log_exception_throttled(
            logger,
            "certificate_core.chmod.cert",
            interval_seconds=300.0,
            message="Failed to chmod CA cert path",
        )
    try:
        pathlib.Path(key_path).chmod(0o640)
    except Exception:
        log_exception_throttled(
            logger,
            "certificate_core.chmod.key",
            interval_seconds=300.0,
            message="Failed to chmod CA key path",
        )

    try:
        import pwd  # type: ignore

        squid = pwd.getpwnam("squid")
        os.chown(cert_path, squid.pw_uid, squid.pw_gid)
        os.chown(key_path, squid.pw_uid, squid.pw_gid)
    except Exception:
        log_exception_throttled(
            logger,
            "certificate_core.chown.squid",
            interval_seconds=300.0,
            message="Failed to chown CA cert/key to squid user",
        )


def materialize_certificate_bundle(
    ca_dir: str,
    bundle: CertificateBundle,
    *,
    original_pfx_bytes: bytes | None = None,
) -> None:
    pathlib.Path(ca_dir).mkdir(exist_ok=True, parents=True)
    dest_cert = os.path.join(ca_dir, "ca.crt")
    dest_key = os.path.join(ca_dir, "ca.key")
    dest_pfx = os.path.join(ca_dir, "uploaded_ca.pfx")

    tmp_cert_path = ""
    tmp_key_path = ""
    tmp_pfx_path = ""
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            delete=False,
            dir=ca_dir,
            encoding="utf-8",
        ) as cert_file:
            cert_file.write(bundle.fullchain_pem or bundle.cert_pem)
            tmp_cert_path = cert_file.name
        with tempfile.NamedTemporaryFile(
            "w",
            delete=False,
            dir=ca_dir,
            encoding="utf-8",
        ) as key_file:
            key_file.write(bundle.key_pem)
            tmp_key_path = key_file.name

        pfx_bytes = (
            bundle.original_pfx_bytes
            if original_pfx_bytes is None
            else original_pfx_bytes
        )
        if pfx_bytes is not None:
            with tempfile.NamedTemporaryFile(
                "wb",
                delete=False,
                dir=ca_dir,
            ) as pfx_file:
                pfx_file.write(pfx_bytes)
                tmp_pfx_path = pfx_file.name

        with _certificate_material_install_lock(ca_dir):
            pathlib.Path(tmp_cert_path).replace(dest_cert)
            tmp_cert_path = ""
            pathlib.Path(tmp_key_path).replace(dest_key)
            tmp_key_path = ""
            if tmp_pfx_path:
                pathlib.Path(tmp_pfx_path).replace(dest_pfx)
                tmp_pfx_path = ""
            elif pathlib.Path(dest_pfx).exists():
                pathlib.Path(dest_pfx).unlink()

            _set_best_effort_permissions(dest_cert, dest_key)
    finally:
        for path in (tmp_cert_path, tmp_key_path, tmp_pfx_path):
            if path:
                with contextlib.suppress(OSError):
                    pathlib.Path(path).unlink()


def load_local_certificate_bundle(ca_dir: str) -> CertificateBundle | None:
    cert_path = os.path.join(ca_dir, "ca.crt")
    key_path = os.path.join(ca_dir, "ca.key")
    if not (pathlib.Path(cert_path).exists() and pathlib.Path(key_path).exists()):
        return None
    try:
        cert_text = pathlib.Path(cert_path).read_text(encoding="utf-8", errors="ignore")
        key_text = pathlib.Path(key_path).read_text(encoding="utf-8", errors="ignore")
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
        if pathlib.Path(uploaded_pfx_path).exists():
            try:
                original_pfx_bytes = pathlib.Path(uploaded_pfx_path).read_bytes()
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
