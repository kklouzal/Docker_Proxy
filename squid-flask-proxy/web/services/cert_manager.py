import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Optional


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
        os.makedirs(self.ca_dir, exist_ok=True)
        subprocess.check_call(["/scripts/generate_ca.sh"])
        return self.ca_cert_path

    def ca_exists(self) -> bool:
        return os.path.exists(self.ca_cert_path)


@dataclass(frozen=True)
class PfxInstallResult:
    ok: bool
    message: str


class PfxInstallError(Exception):
    pass


def _first_pem_block(pem_text: str, block_type: str) -> Optional[str]:
    pattern = re.compile(
        rf"-----BEGIN {re.escape(block_type)}-----.*?-----END {re.escape(block_type)}-----",
        re.DOTALL,
    )
    match = pattern.search(pem_text)
    return match.group(0).strip() if match else None


def _all_pem_blocks(pem_text: str, block_type: str) -> list[str]:
    pattern = re.compile(
        rf"-----BEGIN {re.escape(block_type)}-----.*?-----END {re.escape(block_type)}-----",
        re.DOTALL,
    )
    return [m.group(0).strip() for m in pattern.finditer(pem_text)]


def _normalize_pubkey(text: str) -> str:
    # Avoid differences in line wrapping/newlines.
    return "".join([line.strip() for line in text.splitlines() if line.strip()])


def _passin_arg(password: str) -> str:
    # For openssl, passin requires a source. Empty password uses 'pass:'
    return f"pass:{password or ''}"


def _run_checked(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, check=True)


def _set_best_effort_permissions(cert_path: str, key_path: str):
    try:
        os.chmod(cert_path, 0o644)
    except Exception:
        pass
    try:
        os.chmod(key_path, 0o640)
    except Exception:
        pass

    # Try to hand ownership to squid if present.
    try:
        import pwd  # type: ignore

        squid = pwd.getpwnam("squid")
        os.chown(cert_path, squid.pw_uid, squid.pw_gid)
        os.chown(key_path, squid.pw_uid, squid.pw_gid)
    except Exception:
        pass


def install_pfx_as_ca(ca_dir: str, pfx_bytes: bytes, password: str = "") -> PfxInstallResult:
    """Install a user-provided PKCS#12 (.pfx/.p12) as Squid's ssl-bump CA.

    This extracts a leaf certificate + private key from the PFX, validates that
    they match, writes them as PEM to ca.crt / ca.key, and persists the original
    PFX as uploaded_ca.pfx.
    """
    os.makedirs(ca_dir, exist_ok=True)

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

            # Extract leaf cert (usually the one matching the private key)
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

            # Extract CA chain (optional, kept for completeness)
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
                # Some PFX files don't include any CA certs.
                with open(chain_path, "w", encoding="utf-8") as f:
                    f.write("")

            # Extract unencrypted private key
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

            leaf_text = ""
            with open(leaf_path, "r", encoding="utf-8", errors="ignore") as f:
                leaf_text = f.read()
            chain_text = ""
            with open(chain_path, "r", encoding="utf-8", errors="ignore") as f:
                chain_text = f.read()
            key_text = ""
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

            # Validate key matches cert using public key comparison.
            with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as tmp_leaf:
                tmp_leaf.write(leaf_cert + "\n")
                tmp_leaf_path = tmp_leaf.name
            with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as tmp_key:
                tmp_key.write(private_key + "\n")
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

            # Compose ca.crt: leaf + any additional certs from chain.
            chain_certs = _all_pem_blocks(chain_text, "CERTIFICATE")
            out_cert = "\n".join([leaf_cert] + chain_certs).strip() + "\n"
            out_key = private_key.strip() + "\n"

            dest_cert = os.path.join(ca_dir, "ca.crt")
            dest_key = os.path.join(ca_dir, "ca.key")
            dest_pfx = os.path.join(ca_dir, "uploaded_ca.pfx")

            # Write atomically.
            with tempfile.NamedTemporaryFile("w", delete=False, dir=ca_dir, encoding="utf-8") as f_cert:
                f_cert.write(out_cert)
                tmp_cert_path = f_cert.name
            with tempfile.NamedTemporaryFile("w", delete=False, dir=ca_dir, encoding="utf-8") as f_key:
                f_key.write(out_key)
                tmp_key_out_path = f_key.name
            with tempfile.NamedTemporaryFile("wb", delete=False, dir=ca_dir) as f_pfx:
                f_pfx.write(pfx_bytes)
                tmp_pfx_path = f_pfx.name

            os.replace(tmp_cert_path, dest_cert)
            os.replace(tmp_key_out_path, dest_key)
            os.replace(tmp_pfx_path, dest_pfx)

            _set_best_effort_permissions(dest_cert, dest_key)
            return PfxInstallResult(ok=True, message="PFX installed; Squid will use it for SSL-bump.")
    except FileNotFoundError:
        return PfxInstallResult(ok=False, message="openssl not found in container; cannot import PFX.")
    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or "").strip()
        if stderr:
            return PfxInstallResult(ok=False, message=f"OpenSSL failed: {stderr}")
        return PfxInstallResult(ok=False, message="OpenSSL failed to parse PFX.")
    except PfxInstallError as e:
        return PfxInstallResult(ok=False, message=str(e))
    except Exception as e:
        return PfxInstallResult(ok=False, message=str(e))