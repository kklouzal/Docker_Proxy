from __future__ import annotations

import sys
from pathlib import Path

import pytest


def _add_web_to_path() -> None:
    web_dir = Path(__file__).resolve().parents[1]
    if str(web_dir) not in sys.path:
        sys.path.insert(0, str(web_dir))


CERT_A = "-----BEGIN CERTIFICATE-----\nCERTA\n-----END CERTIFICATE-----\n"
CERT_B = "-----BEGIN CERTIFICATE-----\nCERTB\n-----END CERTIFICATE-----\n"
KEY_A = "-----BEGIN PRIVATE KEY-----\nKEYA\n-----END PRIVATE KEY-----\n"


def test_pem_helpers_normalize_extract_and_split_certificate_chains() -> None:
    _add_web_to_path()
    import services.certificate_core as certificate_core  # type: ignore

    messy = "\r\n  " + CERT_A.replace("\n", "\r\n") + CERT_B + "  "

    assert certificate_core._normalize_pem_text("  abc\r\n") == "abc\n"
    assert certificate_core._first_pem_block(messy, "CERTIFICATE") == CERT_A
    assert certificate_core._all_pem_blocks(messy, "CERTIFICATE") == [CERT_A, CERT_B]
    assert certificate_core._split_cert_chain(messy) == (CERT_A, CERT_B)
    assert certificate_core._split_cert_chain("not pem") == ("", "")


def test_build_certificate_bundle_hashes_content_and_metadata(monkeypatch) -> None:
    _add_web_to_path()
    import services.certificate_core as certificate_core  # type: ignore

    monkeypatch.setattr(
        certificate_core,
        "_extract_certificate_metadata",
        lambda _cert: ("CN=Proxy", "May 1 00:00:00 2026 GMT", "May 1 00:00:00 2036 GMT"),
    )

    bundle = certificate_core.build_certificate_bundle(
        CERT_A,
        KEY_A,
        chain_pem=CERT_B,
        source_kind=" uploaded_pfx ",
        original_pfx_bytes=b"pfx",
    )

    assert bundle.cert_pem == CERT_A
    assert bundle.key_pem == KEY_A
    assert bundle.chain_pem == CERT_B
    assert bundle.fullchain_pem == CERT_A + CERT_B
    assert bundle.source_kind == "uploaded_pfx"
    assert bundle.subject_dn == "CN=Proxy"
    assert len(bundle.bundle_sha256) == 64
    assert len(bundle.cert_sha256) == 64
    assert bundle.original_pfx_bytes == b"pfx"

    with pytest.raises(ValueError):
        certificate_core.build_certificate_bundle(CERT_A, "")


def test_materialize_and_load_certificate_bundle_round_trip_and_manage_pfx_file(tmp_path, monkeypatch) -> None:
    _add_web_to_path()
    import services.certificate_core as certificate_core  # type: ignore

    monkeypatch.setattr(certificate_core, "_extract_certificate_metadata", lambda _cert: ("", "", ""))

    bundle_with_pfx = certificate_core.build_certificate_bundle(
        CERT_A,
        KEY_A,
        chain_pem=CERT_B,
        source_kind="uploaded_pfx",
        original_pfx_bytes=b"pfx-bytes",
    )

    certificate_core.materialize_certificate_bundle(tmp_path, bundle_with_pfx)
    assert (tmp_path / "ca.crt").read_text(encoding="utf-8") == CERT_A + CERT_B
    assert (tmp_path / "ca.key").read_text(encoding="utf-8") == KEY_A
    assert (tmp_path / "uploaded_ca.pfx").read_bytes() == b"pfx-bytes"

    loaded = certificate_core.load_local_certificate_bundle(tmp_path)
    assert loaded is not None
    assert loaded.cert_pem == CERT_A
    assert loaded.chain_pem == CERT_B
    assert loaded.key_pem == KEY_A
    assert loaded.original_pfx_bytes == b"pfx-bytes"

    bundle_without_pfx = certificate_core.build_certificate_bundle(CERT_A, KEY_A)
    certificate_core.materialize_certificate_bundle(tmp_path, bundle_without_pfx)
    assert not (tmp_path / "uploaded_ca.pfx").exists()


def test_load_local_certificate_bundle_returns_none_for_missing_or_incomplete_material(tmp_path) -> None:
    _add_web_to_path()
    import services.certificate_core as certificate_core  # type: ignore

    assert certificate_core.load_local_certificate_bundle(tmp_path) is None
    (tmp_path / "ca.crt").write_text(CERT_A, encoding="utf-8")
    (tmp_path / "ca.key").write_text("not a private key", encoding="utf-8")
    assert certificate_core.load_local_certificate_bundle(tmp_path) is None
