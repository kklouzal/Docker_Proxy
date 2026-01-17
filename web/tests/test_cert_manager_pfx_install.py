import os
import sys
import subprocess

import pytest


def _import_cert_manager_module():
    web_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if web_dir not in sys.path:
        sys.path.insert(0, web_dir)

    from services import cert_manager  # type: ignore

    return cert_manager


def test_install_pfx_empty_bytes(tmp_path):
    m = _import_cert_manager_module()
    r = m.install_pfx_as_ca(str(tmp_path), b"", password="")
    assert r.ok is False
    assert "Empty PFX" in r.message


def test_install_pfx_openssl_missing(tmp_path, monkeypatch):
    m = _import_cert_manager_module()

    def fake_run_checked(_args, *, timeout: int = 30):
        raise FileNotFoundError("openssl")

    monkeypatch.setattr(m, "_run_checked", fake_run_checked)

    r = m.install_pfx_as_ca(str(tmp_path), b"abc", password="")
    assert r.ok is False
    assert "openssl not found" in r.message


def test_install_pfx_openssl_parse_error_is_sanitized(tmp_path, monkeypatch):
    m = _import_cert_manager_module()

    def fake_run_checked(_args, *, timeout: int = 30):
        raise subprocess.CalledProcessError(returncode=1, cmd=_args, stderr="bad\ninput")

    monkeypatch.setattr(m, "_run_checked", fake_run_checked)

    r = m.install_pfx_as_ca(str(tmp_path), b"abc", password="")
    assert r.ok is False
    assert "OpenSSL failed" in r.message


def test_install_pfx_cert_key_mismatch(tmp_path, monkeypatch):
    m = _import_cert_manager_module()

    class FakeCP:
        def __init__(self, stdout: str = ""):
            self.stdout = stdout
            self.stderr = ""

    def fake_run_checked(args, *, timeout: int = 30):
        # The installer uses pkcs12 to write to -out paths, then compares pubkeys.
        if "pkcs12" in args:
            if "-out" in args:
                out_path = args[args.index("-out") + 1]
                if "-nokeys" in args:
                    # leaf cert / chain certs
                    with open(out_path, "w", encoding="utf-8") as f:
                        f.write("-----BEGIN CERTIFICATE-----\nMIIF...\n-----END CERTIFICATE-----\n")
                else:
                    # private key
                    with open(out_path, "w", encoding="utf-8") as f:
                        f.write("-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----\n")
            return FakeCP("")

        if args[:2] == ["openssl", "x509"]:
            return FakeCP("PUBKEY_A")
        if args[:2] == ["openssl", "pkey"]:
            return FakeCP("PUBKEY_B")

        return FakeCP("")

    monkeypatch.setattr(m, "_run_checked", fake_run_checked)

    r = m.install_pfx_as_ca(str(tmp_path), b"abc", password="")
    assert r.ok is False
    assert "do not match" in r.message


def test_install_pfx_happy_path_writes_files(tmp_path, monkeypatch):
    m = _import_cert_manager_module()

    class FakeCP:
        def __init__(self, stdout: str = ""):
            self.stdout = stdout
            self.stderr = ""

    def fake_run_checked(args, *, timeout: int = 30):
        if "pkcs12" in args:
            if "-out" in args:
                out_path = args[args.index("-out") + 1]
                if "-nokeys" in args:
                    with open(out_path, "w", encoding="utf-8") as f:
                        f.write("-----BEGIN CERTIFICATE-----\nMIIF...\n-----END CERTIFICATE-----\n")
                else:
                    with open(out_path, "w", encoding="utf-8") as f:
                        f.write("-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----\n")
            return FakeCP("")

        if args[:2] == ["openssl", "x509"]:
            return FakeCP("PUBKEY_SAME")
        if args[:2] == ["openssl", "pkey"]:
            return FakeCP("PUBKEY_SAME")

        return FakeCP("")

    monkeypatch.setattr(m, "_run_checked", fake_run_checked)

    r = m.install_pfx_as_ca(str(tmp_path), b"abc", password="secret")
    assert r.ok is True

    # Ensure expected outputs are present.
    assert (tmp_path / "ca.crt").exists()
    assert (tmp_path / "ca.key").exists()
    assert (tmp_path / "uploaded_ca.pfx").exists()
