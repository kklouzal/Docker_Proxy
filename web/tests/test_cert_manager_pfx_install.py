import os
import pathlib
import subprocess
import sys
from typing import NoReturn


def _import_cert_manager_module():
    web_dir = pathlib.Path(os.path.join(pathlib.Path(__file__).parent, "..")).resolve()
    if web_dir not in sys.path:
        sys.path.insert(0, web_dir)

    from services import cert_manager  # type: ignore

    return cert_manager


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

    class FakeCP:
        def __init__(self, stdout: str = "") -> None:
            self.stdout = stdout
            self.stderr = ""

    def fake_run_checked(args, *, timeout: int = 30):
        if "pkcs12" in args:
            if "-out" in args:
                out_path = args[args.index("-out") + 1]
                if "-nokeys" in args:
                    pathlib.Path(out_path).write_text(
                        "-----BEGIN CERTIFICATE-----\nMIIF...\n-----END CERTIFICATE-----\n",
                        encoding="utf-8",
                    )
                else:
                    pathlib.Path(out_path).write_text(
                        "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----\n",
                        encoding="utf-8",
                    )
            return FakeCP("")

        if args[:2] == ["openssl", "x509"]:
            return FakeCP("PUBKEY_SAME")
        if args[:2] == ["openssl", "pkey"]:
            return FakeCP("PUBKEY_SAME")

        return FakeCP("")

    r = m.install_pfx_as_ca(
        str(tmp_path), b"abc", password="secret", run_checked=fake_run_checked
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


def test_parse_pfx_preserves_chain_and_original_bytes(tmp_path) -> None:
    m = _import_cert_manager_module()

    class FakeCP:
        def __init__(self, stdout: str = "") -> None:
            self.stdout = stdout
            self.stderr = ""

    def fake_run_checked(args, *, timeout: int = 30):
        if "pkcs12" in args and "-out" in args:
            out_path = args[args.index("-out") + 1]
            if "-clcerts" in args:
                pathlib.Path(out_path).write_text(
                    "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n",
                    encoding="utf-8",
                )
            elif "-cacerts" in args:
                pathlib.Path(out_path).write_text(
                    "-----BEGIN CERTIFICATE-----\nCHAIN1\n-----END CERTIFICATE-----\n"
                    "-----BEGIN CERTIFICATE-----\nCHAIN2\n-----END CERTIFICATE-----\n",
                    encoding="utf-8",
                )
            else:
                pathlib.Path(out_path).write_text(
                    "-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----\n",
                    encoding="utf-8",
                )
            return FakeCP("")
        if args[:2] == ["openssl", "x509"]:
            return FakeCP("PUBKEY_SAME")
        if args[:2] == ["openssl", "pkey"]:
            return FakeCP("PUBKEY_SAME")
        return FakeCP("")

    r = m.parse_pfx_bundle(
        b"pfx-bytes", password="secret", run_checked=fake_run_checked
    )
    assert r.ok is True
    assert r.bundle is not None
    assert "CHAIN1" in r.bundle.chain_pem
    assert "CHAIN2" in r.bundle.chain_pem
    assert r.bundle.original_pfx_bytes == b"pfx-bytes"
