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
    class _Opener:
        def open(self, *_args, **_kwargs):
            return _Response()

    monkeypatch.setattr(webcat_build.urllib.request, "build_opener", lambda *_args, **_kwargs: _Opener())

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


def test_provider_ut1_rejects_non_ut1_archive() -> None:
    webcat_build = _import_webcat_build()

    with tempfile.TemporaryDirectory(prefix="webcat_provider_") as td:
        root = Path(td) / "payload"
        root.mkdir()
        (root / "adult.txt").write_text("example.com\n", encoding="utf-8")
        tar_path = Path(td) / "category-dir.tar.gz"
        with tarfile.open(tar_path, "w:gz") as archive:
            archive.add(root, arcname="")

        with pytest.raises(ValueError, match="UT1 provider selected"):
            webcat_build._collect(tar_path, provider="ut1")


def test_provider_category_dir_can_parse_non_ut1_archive() -> None:
    webcat_build = _import_webcat_build()

    with tempfile.TemporaryDirectory(prefix="webcat_provider_") as td:
        root = Path(td) / "payload"
        root.mkdir()
        (root / "adult.txt").write_text("example.com\n", encoding="utf-8")
        tar_path = Path(td) / "category-dir.tar.gz"
        with tarfile.open(tar_path, "w:gz") as archive:
            archive.add(root, arcname="")

        pairs, source, aliases = webcat_build._collect(tar_path, provider="category-dir")

        assert pairs == [("example.com", "adult")]
        assert source.startswith("tar:")
        assert aliases == {}



def test_download_rejects_redirect_to_internal_host(monkeypatch: pytest.MonkeyPatch) -> None:
    webcat_build = _import_webcat_build()
    from email.message import Message

    headers = Message()
    headers["Location"] = "http://127.0.0.1/feed.csv"

    class _Opener:
        def open(self, req, **_kwargs):
            raise webcat_build.urllib.error.HTTPError(req.full_url, 302, "Found", headers, None)

    monkeypatch.setattr(webcat_build.urllib.request, "build_opener", lambda *_args, **_kwargs: _Opener())

    with pytest.raises(ValueError, match="internal/localhost"):
        webcat_build._open_download_url("https://public.example/feed.csv", timeout=1)

def test_download_if_changed_uses_conditional_headers_and_skips_on_304(monkeypatch: pytest.MonkeyPatch) -> None:
    webcat_build = _import_webcat_build()

    seen_headers = []

    class _Opener:
        def open(self, req, **_kwargs):
            seen_headers.append(dict(req.header_items()))
            raise webcat_build.urllib.error.HTTPError(req.full_url, 304, "Not Modified", {}, None)

    monkeypatch.setattr(webcat_build.urllib.request, "build_opener", lambda *_args, **_kwargs: _Opener())
    monkeypatch.setattr(webcat_build, "_now", lambda: 456)

    with tempfile.TemporaryDirectory(prefix="webcat_conditional_") as td:
        dest = Path(td) / "feed.tar.gz"
        dest.write_bytes(b"cached")
        webcat_build._save_download_metadata(dest, {
            "url": "https://public.example/feed.tar.gz",
            "etag": "etag-1",
            "last_modified": "Mon, 01 Jan 2024 00:00:00 GMT",
        })

        downloaded, source_path = webcat_build._download_if_changed("https://public.example/feed.tar.gz", dest)

        assert downloaded is False
        assert source_path == dest
        assert dest.read_bytes() == b"cached"
        assert seen_headers
        sent = {k.lower(): v for k, v in seen_headers[0].items()}
        assert sent["if-none-match"] == "etag-1"
        assert sent["if-modified-since"] == "Mon, 01 Jan 2024 00:00:00 GMT"
        metadata = webcat_build._load_download_metadata(dest)
        assert metadata["url"] == "https://public.example/feed.tar.gz"
        assert metadata["checked_ts"] == "456"


def test_main_skips_rebuild_when_upstream_not_modified(monkeypatch: pytest.MonkeyPatch) -> None:
    webcat_build = _import_webcat_build()

    with tempfile.TemporaryDirectory(prefix="webcat_main_") as td:
        cached = Path(td) / "webcat_feed.tar.gz"
        cached.write_bytes(b"cached")

        monkeypatch.setattr(webcat_build, "_download_if_changed", lambda *_args, **_kwargs: (False, cached))
        monkeypatch.setattr(webcat_build, "_collect", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("_collect should not run")))
        monkeypatch.setattr(webcat_build, "_build_db", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("_build_db should not run")))

        rc = webcat_build.main([
            "--source-url", "https://public.example/feed.tar.gz",
            "--download-to", td,
        ])

        assert rc == 0


def test_webcat_domain_normalization_is_shared_and_idna() -> None:
    webcat_build = _import_webcat_build()
    _add_web_to_path = None
    web_dir = Path(__file__).resolve().parents[1]
    if str(web_dir) not in sys.path:
        sys.path.insert(0, str(web_dir))
    from tools import webcat_acl  # type: ignore

    assert webcat_build._norm_domain("http://Bücher.Example:8080/path") == "xn--bcher-kva.example"
    assert webcat_acl._norm_domain("http://Bücher.Example:8080/path") == "xn--bcher-kva.example"
    assert webcat_build._norm_domain("user@Example.COM:443") == "example.com"


def test_build_db_stages_then_renames_without_deleting_live_tables(monkeypatch: pytest.MonkeyPatch) -> None:
    webcat_build = _import_webcat_build()

    class _Conn:
        def __init__(self):
            self.sql: list[str] = []
            self.commits = 0

        def execute(self, sql: str, params=()):
            self.sql.append(sql)

            class _Result:
                def __init__(self, statement: str):
                    self.statement = statement

                def fetchone(self):
                    return (0,)

                def fetchall(self):
                    return []

            return _Result(sql)

        def executemany(self, sql: str, seq):
            self.sql.append(sql)
            return None

        def commit(self):
            self.commits += 1

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

    conn = _Conn()
    monkeypatch.setattr(webcat_build, "_connect", lambda: conn)
    monkeypatch.setattr(webcat_build, "_now", lambda: 12345)
    monkeypatch.setattr(webcat_build.os, "getpid", lambda: 678)

    domains, pairs = webcat_build._build_db(
        [("HTTP://Bücher.Example:443/path", "adult"), ("xn--bcher-kva.example", "gambling")],
        source="unit-test",
    )

    assert domains == 1
    assert pairs == 2
    joined = "\n".join(conn.sql)
    assert "DELETE FROM webcat_domains" not in joined
    assert "CREATE TABLE `webcat_domains_stage_678_12345` LIKE `webcat_domains`" in joined
    assert "RENAME TABLE" in joined
    assert "webcat_pairs_stage_678_12345" not in joined
    assert "INSERT INTO `webcat_domains_stage_678_12345`(domain, categories) VALUES(%s,%s)" in joined
    assert "INSERT INTO `webcat_categories_stage_678_12345`(category, domains) VALUES(%s,%s)" in joined
    assert "`webcat_domains_stage_678_12345` TO `webcat_domains`" in joined
    assert conn.commits >= 1


def test_build_db_drops_stale_stage_tables(monkeypatch: pytest.MonkeyPatch) -> None:
    webcat_build = _import_webcat_build()

    class _Conn:
        def __init__(self):
            self.sql: list[str] = []

        def execute(self, sql: str, params=()):
            self.sql.append(sql)

            class _Result:
                def fetchone(self):
                    return (1,)

                def fetchall(self):
                    if "information_schema.TABLES" in sql:
                        return [
                            ("webcat_domains_stage_111_1000",),
                            ("webcat_pairs_stage_111_1000",),
                            ("webcat_domains_stage_222_999999",),
                            ("webcat_domains",),
                        ]
                    return []

            return _Result()

        def executemany(self, sql: str, seq):
            self.sql.append(sql)
            return None

        def commit(self):
            return None

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

    conn = _Conn()
    monkeypatch.setattr(webcat_build, "_connect", lambda: conn)
    monkeypatch.setattr(webcat_build, "_now", lambda: 2000)
    monkeypatch.setattr(webcat_build.os, "getpid", lambda: 333)
    monkeypatch.setenv("WEBCAT_STALE_STAGE_TTL_SECONDS", "500")

    webcat_build._build_db([("example.com", "adult")], source="unit-test")

    joined = "\n".join(conn.sql)
    assert "DROP TABLE IF EXISTS `webcat_domains_stage_111_1000`" in joined
    assert "DROP TABLE IF EXISTS `webcat_pairs_stage_111_1000`" in joined
    assert "webcat_domains_stage_222_999999" not in joined
