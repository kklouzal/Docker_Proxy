from __future__ import annotations

import os
import sys
import tarfile
import tempfile
import zipfile
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