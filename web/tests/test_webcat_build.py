from __future__ import annotations

import os
import sys
import tarfile
import io
import tempfile
import zipfile
import pytest
from pathlib import Path


def _import_webcat_build():
    web_dir = Path(__file__).resolve().parents[1]
    if str(web_dir) not in sys.path:
        sys.path.insert(0, str(web_dir))
    from tools import webcat_build  # type: ignore

    return webcat_build


def test_ut1_tar_gz_lowercase_blacklists_detected() -> None:
    webcat_build = _import_webcat_build()

    with tempfile.TemporaryDirectory(prefix="webcat_ut1_") as td:
        root = os.path.join(td, "payload")
        os.makedirs(root, exist_ok=True)

        for cat, domains in {
            "adult": ["example.com", "sub.example.com"],
            "drogue": ["drug.example"],
        }.items():
            cat_dir = os.path.join(root, "blacklists", cat)
            os.makedirs(cat_dir, exist_ok=True)
            with open(os.path.join(cat_dir, "domains"), "w", encoding="utf-8") as handle:
                for domain in domains:
                    handle.write(domain + "\n")

        tar_path = os.path.join(td, "ut1.tar.gz")
        with tarfile.open(tar_path, "w:gz") as archive:
            archive.add(root, arcname="")

        pairs, source, aliases = webcat_build._collect(webcat_build.Path(tar_path))  # type: ignore[attr-defined]
        assert source.startswith("ut1tar:")
        assert len(pairs) >= 3
        assert {category for _domain, category in pairs} >= {"adult", "drogue"}
        assert aliases == {}


def test_ut1_dedup_identical_category_lists() -> None:
    webcat_build = _import_webcat_build()

    with tempfile.TemporaryDirectory(prefix="webcat_ut1_") as td:
        root = os.path.join(td, "payload")
        os.makedirs(root, exist_ok=True)

        for cat in ("proxy", "proxies"):
            cat_dir = os.path.join(root, "blacklists", cat)
            os.makedirs(cat_dir, exist_ok=True)
            with open(os.path.join(cat_dir, "domains"), "w", encoding="utf-8") as handle:
                handle.write("example.com\n")
                handle.write("sub.example.com\n")

        tar_path = os.path.join(td, "ut1.tar.gz")
        with tarfile.open(tar_path, "w:gz") as archive:
            archive.add(root, arcname="")

        pairs, source, aliases = webcat_build._collect(webcat_build.Path(tar_path))  # type: ignore[attr-defined]
        assert source.startswith("ut1tar:")
        assert aliases["proxy"] == "proxies"
        assert {category for _domain, category in pairs} == {"proxies"}


def test_zip_extraction_blocks_path_traversal() -> None:
    webcat_build = _import_webcat_build()

    with tempfile.TemporaryDirectory(prefix="webcat_zip_") as td:
        zip_path = os.path.join(td, "ut1.zip")
        pwned_path = os.path.join(td, "pwned.txt")

        with zipfile.ZipFile(zip_path, "w") as archive:
            archive.writestr("blacklists/adult/domains", "example.com\nsub.example.com\n")
            archive.writestr("blacklists/drogue/domains", "drug.example\n")
            archive.writestr("../pwned.txt", "you should not see this")

        pairs, source, aliases = webcat_build._collect(webcat_build.Path(zip_path))  # type: ignore[attr-defined]
        assert source.startswith("ut1zip:")
        assert len(pairs) >= 3
        assert {category for _domain, category in pairs} >= {"adult", "drogue"}
        assert aliases == {}
        assert not os.path.exists(pwned_path)


def test_download_rejects_oversized_content_length(monkeypatch: pytest.MonkeyPatch) -> None:
    webcat_build = _import_webcat_build()

    class _Headers:
        def get(self, name: str) -> str | None:
            return "11" if name == "Content-Length" else None

    class _Response:
        headers = _Headers()

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def read(self, _size: int) -> bytes:
            raise AssertionError("body should not be read after oversized Content-Length")

    monkeypatch.setenv("WEBCAT_MAX_DOWNLOAD_BYTES", "10")
    monkeypatch.setattr(webcat_build.urllib.request, "urlopen", lambda *_args, **_kwargs: _Response())

    with tempfile.TemporaryDirectory(prefix="webcat_download_") as td:
        with pytest.raises(ValueError, match="Content-Length=11"):
            webcat_build._download("https://example.com/feed.csv", Path(td) / "feed.csv")


def test_tar_extraction_blocks_traversal_and_enforces_size_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    webcat_build = _import_webcat_build()

    with tempfile.TemporaryDirectory(prefix="webcat_tar_duplicated_") as td:
        tar_path = Path(td) / "payload.tar"
        pwned_path = Path(td) / "pwned.txt"
        with tarfile.open(tar_path, "w") as archive:
            traversal = tarfile.TarInfo("../pwned.txt")
            traversal_data = b"you should not see this"
            traversal.size = len(traversal_data)
            archive.addfile(traversal, io.BytesIO(traversal_data))

            safe = tarfile.TarInfo("blacklists/adult/domains")
            safe_data = b"example.com\n"
            safe.size = len(safe_data)
            archive.addfile(safe, io.BytesIO(safe_data))

        monkeypatch.setenv("WEBCAT_MAX_EXTRACT_BYTES", "5")
        with pytest.raises(ValueError, match="Extracted data exceeded limit"):
            webcat_build._extract_tar(tar_path, Path(td) / "out")
        assert not pwned_path.exists()


def test_download_rejects_hostname_resolving_private(monkeypatch: pytest.MonkeyPatch) -> None:
    webcat_build = _import_webcat_build()

    def fake_getaddrinfo(host: str, *_args, **_kwargs):
        assert host == "public.example"
        return [(webcat_build.socket.AF_INET, webcat_build.socket.SOCK_STREAM, 0, "", ("127.0.0.1", 0))]

    monkeypatch.setattr(webcat_build.socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(
        webcat_build.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("urlopen should not be called")),
    )

    with tempfile.TemporaryDirectory(prefix="webcat_ssrf_") as td:
        with pytest.raises(ValueError, match="internal/localhost"):
            webcat_build._download("https://public.example/feed.csv", Path(td) / "feed.csv")
