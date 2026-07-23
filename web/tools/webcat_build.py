#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import shutil
import sys
import tarfile
import tempfile
import urllib.error
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent
APP_ROOT = HERE.parent
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

from dataclasses import replace  # noqa: E402

from services import webcat_hygiene  # noqa: E402
from services.db import connect, resolve_database_config  # noqa: E402
from services.domain_normalization import (  # noqa: E402
    looks_like_domain as _looks_like_host,
)
from services.domain_normalization import normalize_domain as _norm_domain  # noqa: E402
from services.download_safety import (  # noqa: E402
    is_internal_host,
    open_download_url,
    validate_download_url,
)
from services.runtime_helpers import now_ts as _now  # noqa: E402

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence


def _norm_category(s: str) -> str:
    c = (s or "").strip().lower()
    c = c.replace(" ", "_")
    c = re.sub(r"[^a-z0-9_\-]+", "", c)
    return c.strip("_-")


def _read_lines(path: Path) -> Iterable[str]:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            yield from f
    except Exception:
        return


def _collect_from_category_dir(root: Path) -> list[tuple[str, str]]:
    """Accepts a directory of per-category text files.

    Each file name (stem) is treated as the category. Each file contains domains,
    one per line, with optional comments.

    This matches how many categorized blacklists are distributed.
    """
    pairs: list[tuple[str, str]] = []
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        if p.name.startswith("."):
            continue
        if p.suffix.lower() not in {".txt", ".domains", ".list", ""}:
            # Keep conservative; many feeds use .txt.
            continue
        cat = _norm_category(p.stem or p.name)
        if not cat:
            continue
        for ln in _read_lines(p):
            t = (ln or "").strip()
            if not t or t.startswith(("#", "//", "!")):
                continue
            # Remove inline comments
            t = t.split("#", 1)[0].strip()
            t = t.split(";", 1)[0].strip()
            if not t:
                continue
            if not _looks_like_host(t):
                continue
            pairs.append((_norm_domain(t), cat))
    return pairs


def _collect_from_csv(path: Path) -> list[tuple[str, str]]:
    """Accept CSV/TSV-ish files with at least domain + category columns."""
    pairs: list[tuple[str, str]] = []

    # Attempt to sniff delimiter
    raw = path.read_text(encoding="utf-8", errors="replace")
    sample = raw[:32_768]
    dialect = None
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",\t;")
    except Exception:
        dialect = csv.excel

    reader = csv.reader(raw.splitlines(), dialect)

    header: list[str] | None = None
    for row in reader:
        if not row:
            continue
        if header is None:
            # header if it looks like one
            lower = [c.strip().lower() for c in row]
            if any(c in {"domain", "host", "hostname"} for c in lower) and any(
                c in {"category", "categories", "cat"} for c in lower
            ):
                header = lower
                continue
            # else treat as data
        if header is not None:
            idx_domain = (
                header.index("domain")
                if "domain" in header
                else (
                    header.index("host")
                    if "host" in header
                    else header.index("hostname")
                )
            )
            idx_cat = (
                header.index("category")
                if "category" in header
                else (
                    header.index("categories")
                    if "categories" in header
                    else header.index("cat")
                )
            )
            if idx_domain >= len(row) or idx_cat >= len(row):
                continue
            domain = row[idx_domain]
            cats = row[idx_cat]
        else:
            # Assume first 2 columns are domain/category
            if len(row) < 2:
                continue
            domain, cats = row[0], row[1]

        d = _norm_domain(domain)
        if not _looks_like_host(d):
            continue

        # categories can be comma/pipe/space separated
        cat_tokens = re.split(r"[|,\s]+", str(cats))
        for ct in cat_tokens:
            c = _norm_category(ct)
            if c:
                pairs.append((d, c))

    return pairs


def _is_internal_host(hostname: str) -> bool:
    return is_internal_host(hostname)


def _validate_download_url(url: str):
    return validate_download_url(
        url,
        scheme_error="Only http/https URLs are supported for downloads.",
    )


def _open_download_url(
    url: str,
    *,
    timeout: int,
    max_redirects: int = 5,
    headers: dict[str, str] | None = None,
):
    return open_download_url(
        url,
        timeout=timeout,
        user_agent="squid-flask-proxy-webcat/1.0",
        max_redirects=max_redirects,
        headers=headers,
        scheme_error="Only http/https URLs are supported for downloads.",
    )


def _metadata_path(dest: Path) -> Path:
    return dest.with_name(dest.name + ".metadata.json")


def _load_download_metadata(dest: Path) -> dict[str, str]:
    try:
        raw = json.loads(_metadata_path(dest).read_text(encoding="utf-8"))
    except Exception:
        return {}
    if not isinstance(raw, dict):
        return {}
    return {str(key): str(value) for key, value in raw.items() if value is not None}


def _save_download_metadata(dest: Path, metadata: dict[str, str]) -> None:
    meta_path = _metadata_path(dest)
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    meta_path.write_text(json.dumps(metadata, sort_keys=True) + "\n", encoding="utf-8")


def _download_origin(url: str) -> tuple[str, str, int | None]:
    parsed = urlparse(url)
    scheme = str(parsed.scheme or "").lower()
    port = parsed.port
    if port is None:
        if scheme == "http":
            port = 80
        elif scheme == "https":
            port = 443
    return (scheme, str(parsed.hostname or "").lower().rstrip("."), port)


_DEFAULT_MAX_DOWNLOAD_BYTES = 512 * 1024 * 1024


def _download_max_bytes() -> int:
    try:
        max_bytes = int(
            (
                os.environ.get(
                    "WEBCAT_MAX_DOWNLOAD_BYTES",
                    str(_DEFAULT_MAX_DOWNLOAD_BYTES),
                )
                or str(_DEFAULT_MAX_DOWNLOAD_BYTES)
            ).strip()
            or str(_DEFAULT_MAX_DOWNLOAD_BYTES),
        )
    except Exception:
        return _DEFAULT_MAX_DOWNLOAD_BYTES
    if max_bytes <= 0:
        return _DEFAULT_MAX_DOWNLOAD_BYTES
    return max_bytes


def _download(url: str, dest: Path, *, timeout: int = 60) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    _validate_download_url(url)

    max_bytes = _download_max_bytes()

    tmp = dest.with_suffix(dest.suffix + ".tmp")

    completed = False
    try:
        total = 0
        with _open_download_url(url, timeout=timeout) as r:
            cl = r.headers.get("Content-Length")
            if cl is not None:
                try:
                    content_length = int(cl)
                except (TypeError, ValueError):
                    content_length = None
                if content_length is not None and content_length > max_bytes:
                    msg = f"Download too large (Content-Length={cl})."
                    raise ValueError(msg)

            with Path(tmp).open("wb") as f:
                while True:
                    chunk = r.read(512 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        msg = f"Download exceeded limit ({max_bytes} bytes)."
                        raise ValueError(msg)
                    f.write(chunk)

        tmp.replace(dest)
        completed = True
    finally:
        if not completed:
            try:
                if tmp.exists():
                    tmp.unlink()
            except Exception:
                pass


def _download_if_changed(
    url: str,
    dest: Path,
    *,
    timeout: int = 60,
) -> tuple[bool, Path]:
    dest.parent.mkdir(parents=True, exist_ok=True)
    _validate_download_url(url)

    metadata = _load_download_metadata(dest)
    headers: dict[str, str] = {}
    if metadata.get("url") == url:
        etag = (metadata.get("etag") or "").strip()
        last_modified = (metadata.get("last_modified") or "").strip()
        if etag:
            headers["If-None-Match"] = etag
        if last_modified:
            headers["If-Modified-Since"] = last_modified

    tmp = dest.with_suffix(dest.suffix + ".tmp")
    max_bytes = _download_max_bytes()

    try:
        total = 0
        with _open_download_url(url, timeout=timeout, headers=headers) as r:
            cl = r.headers.get("Content-Length")
            if cl is not None:
                try:
                    content_length = int(cl)
                except (TypeError, ValueError):
                    content_length = None
                if content_length is not None and content_length > max_bytes:
                    msg = f"Download too large (Content-Length={cl})."
                    raise ValueError(msg)

            with Path(tmp).open("wb") as f:
                while True:
                    chunk = r.read(512 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        msg = f"Download exceeded limit ({max_bytes} bytes)."
                        raise ValueError(msg)
                    f.write(chunk)

            response_url = ""
            try:
                response_url = str(r.geturl() or "")
            except Exception:
                response_url = ""

            new_metadata = {
                "url": url,
                "final_url": response_url or url,
                "downloaded_ts": str(_now()),
                "checked_ts": str(_now()),
            }
            if _download_origin(response_url or url) == _download_origin(url):
                new_metadata["etag"] = str(r.headers.get("ETag") or "").strip()
                new_metadata["last_modified"] = str(
                    r.headers.get("Last-Modified") or "",
                ).strip()

        tmp.replace(dest)
        _save_download_metadata(dest, new_metadata)
        return True, dest
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            if not dest.exists():
                msg = "Upstream reported not modified, but no cached feed is available."
                raise ValueError(msg) from exc
            metadata["url"] = url
            metadata["checked_ts"] = str(_now())
            _save_download_metadata(dest, metadata)
            return False, dest
        raise
    finally:
        try:
            if tmp.exists():
                tmp.unlink()
        except Exception:
            pass


_WINDOWS_DRIVE_ARCHIVE_NAME_RE = re.compile(r"^[A-Za-z]:")


def _safe_archive_member_name(name: str) -> str | None:
    """Return a normalized safe relative archive path, or None to skip it."""
    name = (name or "").replace("\\", "/")
    if (
        not name
        or name.startswith(("//", "/"))
        or _WINDOWS_DRIVE_ARCHIVE_NAME_RE.match(name)
    ):
        return None

    parts = [part for part in name.split("/") if part not in {"", "."}]
    if not parts or any(part == ".." for part in parts):
        return None
    return "/".join(parts)


_DEFAULT_MAX_EXTRACT_BYTES = 2 * 1024 * 1024 * 1024


def _extract_max_bytes() -> int:
    try:
        max_bytes = int(
            (
                os.environ.get(
                    "WEBCAT_MAX_EXTRACT_BYTES",
                    str(_DEFAULT_MAX_EXTRACT_BYTES),
                )
                or str(_DEFAULT_MAX_EXTRACT_BYTES)
            ).strip()
            or str(_DEFAULT_MAX_EXTRACT_BYTES),
        )
    except Exception:
        return _DEFAULT_MAX_EXTRACT_BYTES
    if max_bytes <= 0:
        return _DEFAULT_MAX_EXTRACT_BYTES
    return max_bytes


def _extract_zip(zip_path: Path, out_dir: Path) -> None:
    out_dir.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=f".{out_dir.name}.tmp-",
        dir=str(out_dir.parent),
    ) as staging_dir:
        staging = Path(staging_dir)
        _extract_zip_into(zip_path, staging)
        if out_dir.exists():
            shutil.rmtree(out_dir)
        staging.replace(out_dir)


def _extract_zip_into(zip_path: Path, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    out_root = out_dir.resolve()
    max_bytes = _extract_max_bytes()

    total = 0
    with zipfile.ZipFile(zip_path, "r") as z:
        for info in z.infolist():
            name = _safe_archive_member_name(info.filename or "")
            if name is None:
                continue

            target = (out_dir / name).resolve()
            try:
                ok = (
                    str(target).startswith(str(out_root) + os.sep) or target == out_root
                )
            except Exception:
                ok = False
            if not ok:
                continue

            # Prevent zip bombs / runaway extraction.
            file_size = int(getattr(info, "file_size", 0) or 0)
            total += file_size
            if total > max_bytes:
                msg = f"Extracted data exceeded limit ({max_bytes} bytes)."
                raise ValueError(msg)

            if getattr(info, "is_dir", None) and info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue

            target.parent.mkdir(parents=True, exist_ok=True)
            with z.open(info, "r") as src, Path(target).open("wb") as dst:
                shutil.copyfileobj(src, dst, length=512 * 1024)


def _extract_tar(tar_path: Path, out_dir: Path) -> None:
    out_dir.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=f".{out_dir.name}.tmp-",
        dir=str(out_dir.parent),
    ) as staging_dir:
        staging = Path(staging_dir)
        _extract_tar_into(tar_path, staging)
        if out_dir.exists():
            shutil.rmtree(out_dir)
        staging.replace(out_dir)


def _extract_tar_into(tar_path: Path, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    out_root = out_dir.resolve()
    # Supports .tar, .tar.gz, .tgz
    max_bytes = _extract_max_bytes()
    total = 0
    with tarfile.open(tar_path, "r:*") as t:
        for m in t.getmembers():
            # Preserve data-filter behavior: only directories and regular files are extracted.
            if not (m.isdir() or m.isfile()):
                continue

            # Prevent path traversal / absolute paths, including Windows drive paths.
            name = _safe_archive_member_name(m.name or "")
            if name is None:
                continue

            target = (out_dir / name).resolve()
            try:
                ok = (
                    str(target).startswith(str(out_root) + os.sep) or target == out_root
                )
            except Exception:
                ok = False
            if not ok:
                continue

            if m.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue

            size = int(getattr(m, "size", 0) or 0)
            total += size
            if total > max_bytes:
                msg = f"Extracted data exceeded limit ({max_bytes} bytes)."
                raise ValueError(msg)

            src = t.extractfile(m)
            if src is None:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with src, Path(target).open("wb") as dst:
                while True:
                    chunk = src.read(512 * 1024)
                    if not chunk:
                        break
                    total += max(0, len(chunk) - size)
                    if total > max_bytes:
                        msg = f"Extracted data exceeded limit ({max_bytes} bytes)."
                        raise ValueError(msg)
                    dst.write(chunk)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _webcat_db_is_current(*, source_sha256: str) -> bool:
    if not source_sha256:
        return False
    try:
        with _connect() as conn:
            row = conn.execute(
                "SELECT v FROM webcat_meta WHERE k=%s",
                ("source_sha256",),
            ).fetchone()
            if not row or str(row[0] or "") != source_sha256:
                return False
            built_row = conn.execute(
                "SELECT v FROM webcat_meta WHERE k=%s",
                ("built_ts",),
            ).fetchone()
            if not built_row or int((built_row[0] if built_row else 0) or 0) <= 0:
                return False
            conn.execute("SELECT COUNT(*) FROM webcat_domains").fetchone()
            conn.execute("SELECT COUNT(*) FROM webcat_categories").fetchone()
            return True
    except Exception:
        return False


def _env_int(name: str, default: int) -> int:
    try:
        value = int((os.environ.get(name) or str(default)).strip() or str(default))
    except Exception:
        value = int(default)
    return max(1, value)


def _connect():
    cfg = resolve_database_config()
    cfg = replace(
        cfg,
        connect_timeout=max(
            cfg.connect_timeout,
            _env_int("WEBCAT_MYSQL_CONNECT_TIMEOUT", 30),
        ),
        read_timeout=max(cfg.read_timeout, _env_int("WEBCAT_MYSQL_READ_TIMEOUT", 300)),
        write_timeout=max(
            cfg.write_timeout,
            _env_int("WEBCAT_MYSQL_WRITE_TIMEOUT", 300),
        ),
    )
    return connect(config=cfg)


def _init_db(conn) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS webcat_domains (
            domain VARCHAR(255) PRIMARY KEY,
            categories TEXT NOT NULL
        )
        """,
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS webcat_categories (
            category VARCHAR(128) PRIMARY KEY,
            domains BIGINT NOT NULL
        )
        """,
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS webcat_meta (
            k VARCHAR(64) PRIMARY KEY,
            v LONGTEXT NOT NULL
        )
        """,
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS webcat_aliases (
            alias VARCHAR(128) PRIMARY KEY,
            canonical VARCHAR(128) NOT NULL
        )
        """,
    )


def _upsert_meta(conn, k: str, v: str) -> None:
    conn.execute(
        "INSERT INTO webcat_meta(k,v) VALUES(%s,%s) AS incoming ON DUPLICATE KEY UPDATE v=incoming.v",
        (k, v),
    )


def _quote_table_name(name: str) -> str:
    if not name.replace("_", "").isalnum():
        msg = f"Unsafe table name: {name}"
        raise ValueError(msg)
    return f"`{name}`"


def _upsert_meta_table(conn, table: str, k: str, v: str) -> None:
    conn.execute(
        f"INSERT INTO {_quote_table_name(table)}(k,v) VALUES(%s,%s) AS incoming ON DUPLICATE KEY UPDATE v=incoming.v",
        (k, v),
    )


def _cleanup_stale_build_tables(conn, *, current_suffix: str) -> None:
    try:
        webcat_hygiene.cleanup_stale_webcat_build_tables(
            conn,
            current_suffix=current_suffix,
            now_ts=_now(),
        )
    except Exception:
        return


def _build_db(
    pairs: Sequence[tuple[str, str]],
    *,
    source: str,
    aliases: dict[str, str] | None = None,
    source_sha256: str = "",
) -> tuple[int, int]:
    suffix = f"{os.getpid()}_{_now()}"
    stages = {
        "webcat_domains": f"webcat_domains_stage_{suffix}",
        "webcat_categories": f"webcat_categories_stage_{suffix}",
        "webcat_aliases": f"webcat_aliases_stage_{suffix}",
        "webcat_meta": f"webcat_meta_stage_{suffix}",
    }
    old_tables = {
        name: f"{name}_old_{suffix}"
        for name in (
            "webcat_domains",
            "webcat_categories",
            "webcat_aliases",
            "webcat_meta",
        )
    }

    try:
        batch_size = int(
            (os.environ.get("WEBCAT_DB_BATCH_SIZE") or "10000").strip() or "10000",
        )
    except Exception:
        batch_size = 10000
    batch_size = max(500, min(20000, batch_size))

    domain_insert_sql = f"INSERT INTO {_quote_table_name(stages['webcat_domains'])}(domain, categories) VALUES(%s,%s)"
    category_insert_sql = f"INSERT INTO {_quote_table_name(stages['webcat_categories'])}(category, domains) VALUES(%s,%s)"
    alias_insert_sql = f"INSERT INTO {_quote_table_name(stages['webcat_aliases'])}(alias,canonical) VALUES(%s,%s) AS incoming ON DUPLICATE KEY UPDATE canonical=incoming.canonical"

    domain_categories: dict[str, set[str]] = {}
    for d, c in pairs:
        domain = _norm_domain(d)
        category = _norm_category(c)
        if not domain or not category:
            continue
        cats = domain_categories.setdefault(domain, set())
        cats.add(category)

    category_counts: dict[str, int] = {}
    domain_rows: list[tuple[str, str]] = []
    unique_pairs = 0
    for domain in sorted(domain_categories):
        categories = sorted(domain_categories[domain])
        if not categories:
            continue
        domain_rows.append((domain, "|".join(categories)))
        for category in categories:
            category_counts[category] = category_counts.get(category, 0) + 1
            unique_pairs += 1
    category_rows = [
        (category, count) for category, count in sorted(category_counts.items())
    ]

    domains_built = len(domain_rows)
    with _connect() as conn:
        try:
            _init_db(conn)
            _cleanup_stale_build_tables(conn, current_suffix=suffix)
            webcat_hygiene.drop_tables(
                conn, list(stages.values()) + list(old_tables.values())
            )
            for live, stage in stages.items():
                conn.execute(
                    f"CREATE TABLE {_quote_table_name(stage)} LIKE {_quote_table_name(live)}",
                )
            webcat_hygiene.commit_if_supported(conn)

            if domain_rows:
                for start_idx in range(0, len(domain_rows), batch_size):
                    conn.executemany(
                        domain_insert_sql,
                        domain_rows[start_idx : start_idx + batch_size],
                    )
                webcat_hygiene.commit_if_supported(conn)

            if category_rows:
                for start_idx in range(0, len(category_rows), batch_size):
                    conn.executemany(
                        category_insert_sql,
                        category_rows[start_idx : start_idx + batch_size],
                    )
                webcat_hygiene.commit_if_supported(conn)

            alias_rows: list[tuple[str, str]] = []
            if aliases:
                for alias, canonical in sorted(aliases.items()):
                    if alias and canonical and alias != canonical:
                        alias_rows.append((alias, canonical))
                if alias_rows:
                    conn.executemany(alias_insert_sql, alias_rows)
                    webcat_hygiene.commit_if_supported(conn)

            _upsert_meta_table(conn, stages["webcat_meta"], "built_ts", str(_now()))
            _upsert_meta_table(conn, stages["webcat_meta"], "source", source)
            _upsert_meta_table(
                conn,
                stages["webcat_meta"],
                "source_sha256",
                source_sha256,
            )
            _upsert_meta_table(
                conn,
                stages["webcat_meta"],
                "domains",
                str(domains_built),
            )
            _upsert_meta_table(conn, stages["webcat_meta"], "pairs", str(unique_pairs))
            _upsert_meta_table(
                conn,
                stages["webcat_meta"],
                "source_pairs",
                str(len(pairs)),
            )
            _upsert_meta_table(
                conn,
                stages["webcat_meta"],
                "aliases",
                str(len(alias_rows)),
            )
            rename_parts: list[str] = []
            for live, stage in stages.items():
                rename_parts.extend(
                    (
                        f"{_quote_table_name(live)} TO {_quote_table_name(old_tables[live])}",
                        f"{_quote_table_name(stage)} TO {_quote_table_name(live)}",
                    ),
                )
            conn.execute("RENAME TABLE " + ", ".join(rename_parts))
            webcat_hygiene.drop_tables(conn, list(old_tables.values()))
        except Exception:
            webcat_hygiene.drop_tables(
                conn, list(stages.values()) + list(old_tables.values())
            )
            raise
    return domains_built, unique_pairs


def _collect(
    source_path: Path,
    *,
    provider: str = "auto",
) -> tuple[list[tuple[str, str]], str, dict[str, str]]:
    provider = (provider or "auto").strip().lower()
    if provider not in {"auto", "ut1", "category-dir", "csv"}:
        msg = f"Unsupported webcat provider: {provider}"
        raise ValueError(msg)
    if source_path.is_dir():
        if provider in {"auto", "ut1"}:
            # UT1 canonical layout: blacklists/<category>/domains
            ut1_root = _find_ut1_blacklists_dir(source_path)
            if ut1_root is not None:
                pairs, aliases = _collect_from_ut1_blacklists_dedup(ut1_root)
                return pairs, f"ut1:{ut1_root}", aliases
            if provider == "ut1":
                msg = f"UT1 provider selected but no blacklists/ directory was found under {source_path}"
                raise ValueError(msg)

        if provider in {"auto", "category-dir"}:
            pairs = _collect_from_category_dir(source_path)
            return pairs, f"dir:{source_path}", {}
        msg = (
            f"Provider {provider} expects a file source, not a directory: {source_path}"
        )
        raise ValueError(msg)

    # Files: treat archives specially, else attempt CSV/TSV
    if source_path.is_file() and source_path.suffix.lower() == ".zip":
        extracted = source_path.parent / (source_path.stem + "_extracted")
        # Always re-extract to avoid stale partial extraction
        if extracted.exists():
            # Best-effort clean
            for p in sorted(extracted.rglob("*"), reverse=True):
                try:
                    if p.is_file():
                        p.unlink()
                    else:
                        p.rmdir()
                except Exception:
                    pass
        _extract_zip(source_path, extracted)
        # Prefer UT1 layout if present.
        if provider in {"auto", "ut1"}:
            ut1_root = _find_ut1_blacklists_dir(extracted)
            if ut1_root is not None:
                pairs, aliases = _collect_from_ut1_blacklists_dedup(ut1_root)
                return pairs, f"ut1zip:{source_path}", aliases
            if provider == "ut1":
                msg = f"UT1 provider selected but archive {source_path} did not contain blacklists/<category>/domains"
                raise ValueError(msg)
        pairs = _collect_from_category_dir(extracted)
        return pairs, f"zip:{source_path}", {}

    # tar.* archives (UT1 uses all.tar.gz)
    if source_path.is_file() and (
        source_path.name.lower().endswith(".tar.gz")
        or source_path.name.lower().endswith(".tgz")
        or source_path.suffix.lower() == ".tar"
    ):
        base = source_path.name
        if base.lower().endswith(".tar.gz"):
            stem = base[:-7]
        elif base.lower().endswith(".tgz"):
            stem = base[:-4]
        else:
            stem = source_path.stem
        extracted = source_path.parent / (stem + "_extracted")
        if extracted.exists():
            for p in sorted(extracted.rglob("*"), reverse=True):
                try:
                    if p.is_file():
                        p.unlink()
                    else:
                        p.rmdir()
                except Exception:
                    pass
        _extract_tar(source_path, extracted)

        # UT1 layout may be nested; detect case-insensitively.
        if provider in {"auto", "ut1"}:
            ut1_root = _find_ut1_blacklists_dir(extracted)
            if ut1_root is not None:
                pairs, aliases = _collect_from_ut1_blacklists_dedup(ut1_root)
                return pairs, f"ut1tar:{source_path}", aliases
            if provider == "ut1":
                msg = f"UT1 provider selected but archive {source_path} did not contain blacklists/<category>/domains"
                raise ValueError(msg)

        pairs = _collect_from_category_dir(extracted)
        return pairs, f"tar:{source_path}", {}

    if provider == "ut1":
        msg = f"UT1 provider expects a directory or archive source: {source_path}"
        raise ValueError(msg)
    pairs = _collect_from_csv(source_path)
    return pairs, f"file:{source_path}", {}


def _collect_from_ut1_blacklists_dedup(
    blacklists_dir: Path,
) -> tuple[list[tuple[str, str]], dict[str, str]]:
    """Parse UT1 blacklists/<category>/domains, collapsing duplicate lists.

    Some UT1 categories ship multiple directories with different names but identical
    domain lists. We dedupe these at build time to avoid duplicate buttons in the UI.

    Returns (pairs, aliases) where aliases maps alias_category -> canonical_category.
    """
    pairs: list[tuple[str, str]] = []
    aliases: dict[str, str] = {}
    if not blacklists_dir.is_dir():
        return pairs, aliases

    # Signature -> canonical category. Signature is an order-independent fingerprint.
    sig_to_cat: dict[tuple[int, int, int, int, int], str] = {}

    def _sig_for_domains(domains: set[str]) -> tuple[int, int, int, int, int]:
        # Order-independent fingerprint using two 64-bit XORs + two 64-bit sums + count.
        xor1 = 0
        xor2 = 0
        sum1 = 0
        sum2 = 0
        for d in domains:
            h = hashlib.blake2b(
                d.encode("utf-8", errors="ignore"),
                digest_size=16,
            ).digest()
            a = int.from_bytes(h[0:8], "little", signed=False)
            b = int.from_bytes(h[8:16], "little", signed=False)
            xor1 ^= a
            xor2 ^= b
            sum1 = (sum1 + a) & 0xFFFFFFFFFFFFFFFF
            sum2 = (sum2 + b) & 0xFFFFFFFFFFFFFFFF
        return (len(domains), xor1, xor2, sum1, sum2)

    for category_dir in sorted(blacklists_dir.iterdir()):
        if not category_dir.is_dir():
            continue
        if category_dir.name.startswith("."):
            continue

        cat = _norm_category(category_dir.name)
        if not cat:
            continue

        domains_file = category_dir / "domains"
        if not domains_file.is_file():
            continue

        # Build a unique set for fingerprinting and for emitting pairs.
        doms: set[str] = set()
        for ln in _read_lines(domains_file):
            t = (ln or "").strip()
            if not t or t.startswith("#"):
                continue
            t = t.split("#", 1)[0].strip()
            if not t:
                continue
            if not _looks_like_host(t):
                continue
            doms.add(_norm_domain(t))

        if not doms:
            continue

        sig = _sig_for_domains(doms)
        canonical = sig_to_cat.get(sig)
        if canonical is None:
            sig_to_cat[sig] = cat
            canonical = cat
        elif cat != canonical:
            aliases[cat] = canonical

        pairs.extend((d, canonical) for d in doms)

    return pairs, aliases


def _find_ut1_blacklists_dir(root: Path) -> Path | None:
    """Find UT1 'blacklists' directory (case-insensitive), possibly nested."""
    if not root.exists():
        return None
    # Common: root/blacklists or root/Blacklists
    for name in ("blacklists", "Blacklists"):
        cand = root / name
        if cand.is_dir():
            return cand

    # Nested: scan a limited depth first (cheap), then full rglob.
    try:
        for p in root.glob("*"):
            if p.is_dir() and p.name.lower() == "blacklists":
                return p
    except Exception:
        pass

    try:
        for cand in root.rglob("*"):
            if cand.is_dir() and cand.name.lower() == "blacklists":
                return cand
    except Exception:
        return None
    return None


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Download/compile a domain->category DB for Squid (UT1/OWC-style sources).",
    )
    ap.add_argument(
        "--source-url",
        default="",
        help="Optional URL to download (zip or csv)",
    )
    ap.add_argument(
        "--source-path",
        default="",
        help="Optional local path (dir, zip, csv)",
    )
    ap.add_argument(
        "--download-to",
        default="/var/lib/squid-flask-proxy/webcat/source",
        help="Where to save downloaded artifact",
    )
    ap.add_argument(
        "--provider",
        default=os.environ.get("WEBCAT_PROVIDER", "auto"),
        choices=("auto", "ut1", "category-dir", "csv"),
        help="Feed parser/provider contract. auto keeps legacy layout detection; ut1 requires blacklists/<category>/domains.",
    )
    args = ap.parse_args(list(argv) if argv is not None else None)

    source_path_s = (args.source_path or "").strip()
    source_url = (args.source_url or "").strip()

    if not source_path_s and not source_url:
        return 0

    downloaded = False
    if source_url:
        dl_dir = Path(args.download_to)
        dl_dir.mkdir(parents=True, exist_ok=True)
        # Guess filename
        name = "webcat_feed"
        # Prefer exact matches for common archive types.
        try:
            parsed_name = urlparse(source_url).path.lower()
        except ValueError:
            sys.stderr.write(
                "Download URLs must be valid absolute HTTP/HTTPS URLs.\n",
            )
            return 2
        lower_url = parsed_name or source_url.lower()
        if lower_url.endswith(".tar.gz"):
            name += ".tar.gz"
        elif lower_url.endswith(".tgz"):
            name += ".tgz"
        else:
            for ext in (".zip", ".csv", ".txt", ".tar"):
                if lower_url.endswith(ext):
                    name += ext
                    break
        dest = dl_dir / name
        downloaded, source_path = _download_if_changed(source_url, dest)
    else:
        source_path = Path(source_path_s)

    if not source_path.exists():
        return 2

    source_sha256 = ""
    if source_path.is_file():
        source_sha256 = _file_sha256(source_path)

    if (
        source_url
        and not downloaded
        and _webcat_db_is_current(source_sha256=source_sha256)
    ):
        return 0
    try:
        pairs, source_label, aliases = _collect(source_path, provider=args.provider)
    except ValueError:
        return 3
    if not pairs:
        return 3

    _domains, _total_pairs = _build_db(
        pairs,
        source=source_label,
        aliases=aliases,
        source_sha256=source_sha256,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
