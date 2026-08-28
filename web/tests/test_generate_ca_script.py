from __future__ import annotations

import hashlib
import os
import shutil
from pathlib import Path

import pytest

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
        public_key = _run_openssl(
            "pkey", "-in", str(ca_dir / "ca.key"), "-pubout", "-outform", "DER"
        )
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


def _install_command_shims(bin_dir: Path) -> dict[str, str]:
    bin_dir.mkdir()
    real_commands = {
        command: shutil.which(command) for command in ("chmod", "chown", "getent")
    }
    assert all(real_commands.values())
    (bin_dir / "chmod").write_text(
        f"""#!/bin/sh
if [ "${{FAIL_CHMOD_MODE:-}}" = "$1" ]; then
    exit 71
fi
exec {real_commands["chmod"]} "$@"
""",
        encoding="utf-8",
    )
    (bin_dir / "chown").write_text(
        f"""#!/bin/sh
if [ "${{FAIL_CHOWN:-0}}" = "1" ]; then
    exit 72
fi
if [ "${{SQUID_ACCOUNT_EXISTS:-0}}" = "1" ]; then
    exit 0
fi
exec {real_commands["chown"]} "$@"
""",
        encoding="utf-8",
    )
    (bin_dir / "getent").write_text(
        f"""#!/bin/sh
if [ "$1" = "passwd" ] && [ "$2" = "squid" ]; then
    [ "${{SQUID_ACCOUNT_EXISTS:-0}}" = "1" ]
    exit $?
fi
exec {real_commands["getent"]} "$@"
""",
        encoding="utf-8",
    )
    for path in bin_dir.iterdir():
        path.chmod(0o755)
    return {"PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}"}


def _run_ca_script(ca_dir: Path, env: dict[str, str]):
    return run_test_process(
        ["/bin/sh", "-c", _script_for_ca_dir(ca_dir)],
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, **env},
    )


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

    result = _run_ca_script(ca_dir, _install_command_shims(tmp_path / "bin"))

    assert result.returncode == 0
    assert "CA files available" in result.stdout
    assert _public_key_fingerprint(ca_dir, "key") == _public_key_fingerprint(
        ca_dir,
        "cert",
    )
    assert (ca_dir / "ca.key").stat().st_mode & 0o777 == 0o600
    assert (ca_dir / "ca.crt").stat().st_mode & 0o777 == 0o644


@pytest.mark.parametrize(
    ("failure_env", "expected_error"),
    [
        ({"FAIL_CHMOD_MODE": "600"}, "Failed to set CA private key mode 0600"),
        ({"FAIL_CHMOD_MODE": "644"}, "Failed to set CA certificate mode 0644"),
        ({"FAIL_CHOWN": "1"}, "Failed to set squid:squid ownership"),
        (
            {"FAIL_CHMOD_MODE": "640"},
            "Failed to set Squid-readable CA private key mode 0640",
        ),
    ],
)
def test_generate_ca_fails_closed_on_permission_installation_error(
    tmp_path: Path,
    failure_env: dict[str, str],
    expected_error: str,
) -> None:
    ca_dir = tmp_path / "certs"
    ca_dir.mkdir()
    key, cert = _create_self_signed_pair(ca_dir, "existing")
    (ca_dir / "ca.key").write_bytes(key.read_bytes())
    (ca_dir / "ca.crt").write_bytes(cert.read_bytes())
    env = _install_command_shims(tmp_path / "bin")
    env.update({"SQUID_ACCOUNT_EXISTS": "1", **failure_env})

    result = _run_ca_script(ca_dir, env)

    assert result.returncode != 0
    assert expected_error in result.stderr
    assert "CA files available" not in result.stdout


def test_generate_ca_installs_squid_readable_permissions_when_account_exists(
    tmp_path: Path,
) -> None:
    ca_dir = tmp_path / "certs"
    env = _install_command_shims(tmp_path / "bin")
    env["SQUID_ACCOUNT_EXISTS"] = "1"

    result = _run_ca_script(ca_dir, env)

    assert result.returncode == 0
    assert "CA files available" in result.stdout
    assert (ca_dir / "ca.key").stat().st_mode & 0o777 == 0o640
    assert (ca_dir / "ca.crt").stat().st_mode & 0o777 == 0o644
