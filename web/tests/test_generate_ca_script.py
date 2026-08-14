from __future__ import annotations

import hashlib
from pathlib import Path

from .subprocess_test_utils import run_test_process

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "generate_ca.sh"


def _script_for_ca_dir(ca_dir: Path) -> str:
    script = SCRIPT_PATH.read_text(encoding="utf-8")
    return script.replace('CA_DIR="/etc/squid/ssl/certs"', f'CA_DIR="{ca_dir}"')


def _run_openssl(*args: str) -> bytes:
    result = run_test_process(
        ["openssl", *args],
        check=True,
        capture_output=True,
    )
    return result.stdout


def _public_key_fingerprint(ca_dir: Path, source: str) -> str:
    if source == "key":
        public_key = _run_openssl("pkey", "-in", str(ca_dir / "ca.key"), "-pubout", "-outform", "DER")
    else:
        pem = _run_openssl("x509", "-in", str(ca_dir / "ca.crt"), "-pubkey", "-noout")
        public_key = run_test_process(
            ["openssl", "pkey", "-pubin", "-outform", "DER"],
            input=pem,
            check=True,
            capture_output=True,
        ).stdout
    return hashlib.sha256(public_key).hexdigest()


def _create_self_signed_pair(ca_dir: Path, name: str) -> tuple[Path, Path]:
    key_path = ca_dir / f"{name}.key"
    cert_path = ca_dir / f"{name}.crt"
    _run_openssl("genrsa", "-out", str(key_path), "2048")
    _run_openssl(
        "req",
        "-x509",
        "-new",
        "-nodes",
        "-key",
        str(key_path),
        "-sha256",
        "-days",
        "30",
        "-out",
        str(cert_path),
        "-subj",
        f"/CN={name}",
    )
    return key_path, cert_path


def test_generate_ca_replaces_valid_but_mismatched_key_and_certificate(
    tmp_path: Path,
) -> None:
    ca_dir = tmp_path / "certs"
    ca_dir.mkdir()
    first_key, _first_cert = _create_self_signed_pair(ca_dir, "first")
    _second_key, second_cert = _create_self_signed_pair(ca_dir, "second")
    (ca_dir / "ca.key").write_bytes(first_key.read_bytes())
    (ca_dir / "ca.crt").write_bytes(second_cert.read_bytes())

    before_key_fp = _public_key_fingerprint(ca_dir, "key")
    before_cert_fp = _public_key_fingerprint(ca_dir, "cert")
    assert before_key_fp != before_cert_fp

    run_test_process(
        ["/bin/sh", "-c", _script_for_ca_dir(ca_dir)],
        check=True,
        capture_output=True,
        text=True,
    )

    assert _public_key_fingerprint(ca_dir, "key") == _public_key_fingerprint(
        ca_dir,
        "cert",
    )
    assert (ca_dir / "ca.key").stat().st_mode & 0o777 == 0o600
    assert (ca_dir / "ca.crt").stat().st_mode & 0o777 == 0o644
