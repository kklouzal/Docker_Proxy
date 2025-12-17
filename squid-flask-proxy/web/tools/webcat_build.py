#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import os
import re
import sqlite3
import sys
import time
import tarfile
import urllib.request
import zipfile
from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple


_HOST_RE = re.compile(
    r"^(?=.{1,255}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$",
    re.IGNORECASE,
)


def _now() -> int:
    return int(time.time())


def _norm_domain(s: str) -> str:
    d = (s or "").strip().lower().rstrip(".")
    if d.startswith("."):
        d = d[1:]
    # Strip obvious scheme/path if present
    if "://" in d:
        d = d.split("://", 1)[1]
    d = d.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    # Strip userinfo/port
    if "@" in d:
        d = d.split("@", 1)[1]
    if ":" in d:
        host, port = d.rsplit(":", 1)
        if port.isdigit():
            d = host
    return d


def _looks_like_host(s: str) -> bool:
    d = _norm_domain(s)
    if not d or "." not in d or ".." in d:
        return False
    return _HOST_RE.match(d) is not None


def _norm_category(s: str) -> str:
    c = (s or "").strip().lower()
    c = c.replace(" ", "_")
    c = re.sub(r"[^a-z0-9_\-]+", "", c)
    c = c.strip("_-")
    return c


def _read_lines(path: Path) -> Iterable[str]:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                yield line
    except Exception:
        return


def _collect_from_category_dir(root: Path) -> List[Tuple[str, str]]:
    """Accepts a directory of per-category text files.

    Each file name (stem) is treated as the category. Each file contains domains,
    one per line, with optional comments.

    This matches how many categorized blacklists are distributed.
    """

    pairs: List[Tuple[str, str]] = []
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        if p.name.startswith("."):
            continue
        if p.suffix.lower() not in (".txt", ".domains", ".list", ""):
            # Keep conservative; many feeds use .txt.
            continue
        cat = _norm_category(p.stem or p.name)
        if not cat:
            continue
        for ln in _read_lines(p):
            t = (ln or "").strip()
            if not t or t.startswith("#") or t.startswith("//") or t.startswith("!"):
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


def _collect_from_csv(path: Path) -> List[Tuple[str, str]]:
    """Accept CSV/TSV-ish files with at least domain + category columns."""

    pairs: List[Tuple[str, str]] = []

    # Attempt to sniff delimiter
    raw = path.read_text(encoding="utf-8", errors="replace")
    sample = raw[: 32_768]
    dialect = None
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",\t;")
    except Exception:
        dialect = csv.excel

    reader = csv.reader(raw.splitlines(), dialect)

    header: Optional[List[str]] = None
    for row in reader:
        if not row:
            continue
        if header is None:
            # header if it looks like one
            lower = [c.strip().lower() for c in row]
            if any(c in ("domain", "host", "hostname") for c in lower) and any(
                c in ("category", "categories", "cat") for c in lower
            ):
                header = lower
                continue
            # else treat as data
        if header is not None:
            idx_domain = header.index("domain") if "domain" in header else (header.index("host") if "host" in header else header.index("hostname"))
            idx_cat = header.index("category") if "category" in header else (header.index("categories") if "categories" in header else header.index("cat"))
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
        cat_tokens = re.split(r"[|,]+", str(cats))
        for ct in cat_tokens:
            c = _norm_category(ct)
            if c:
                pairs.append((d, c))

    return pairs


def _download(url: str, dest: Path, *, timeout: int = 60) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": "squid-flask-proxy-webcat/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read()
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    tmp.write_bytes(data)
    tmp.replace(dest)


def _extract_zip(zip_path: Path, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "r") as z:
        z.extractall(out_dir)


def _extract_tar(tar_path: Path, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    # Supports .tar, .tar.gz, .tgz
    with tarfile.open(tar_path, "r:*") as t:
        # Prefer safe extraction mode when supported (avoids future default changes).
        try:
            t.extractall(out_dir, filter="data")
            return
        except TypeError:
            pass

        out_root = out_dir.resolve()
        for m in t.getmembers():
            # Skip special file types
            if m.ischr() or m.isblk() or m.isfifo() or m.isdev():
                continue

            # Prevent path traversal / absolute paths
            target = (out_dir / m.name).resolve()
            try:
                ok = str(target).startswith(str(out_root) + os.sep) or target == out_root
            except Exception:
                ok = False
            if not ok:
                continue

            t.extract(m, out_dir)


def _connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), timeout=10)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def _init_db(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS webcat_domains (
            domain TEXT PRIMARY KEY,
            categories TEXT NOT NULL
        );
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS webcat_categories (
            category TEXT PRIMARY KEY,
            domains INTEGER NOT NULL
        );
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS webcat_meta (
            k TEXT PRIMARY KEY,
            v TEXT NOT NULL
        );
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS webcat_aliases (
            alias TEXT PRIMARY KEY,
            canonical TEXT NOT NULL
        );
        """
    )


def _upsert_meta(conn: sqlite3.Connection, k: str, v: str) -> None:
    conn.execute(
        "INSERT INTO webcat_meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
        (k, v),
    )


def _build_db(
    db_path: Path,
    pairs: Sequence[Tuple[str, str]],
    *,
    source: str,
    aliases: Optional[Dict[str, str]] = None,
) -> Tuple[int, int]:
    # Collapse domain -> set(categories)
    by_domain: Dict[str, Set[str]] = {}
    for d, c in pairs:
        if not d or not c:
            continue
        s = by_domain.setdefault(d, set())
        s.add(c)

    # Category counts for UI
    cat_counts: Dict[str, int] = {}
    for domain, cats in by_domain.items():
        for c in cats:
            cat_counts[c] = cat_counts.get(c, 0) + 1

    with _connect(db_path) as conn:
        _init_db(conn)
        conn.execute("DELETE FROM webcat_domains")
        conn.execute("DELETE FROM webcat_categories")
        conn.execute("DELETE FROM webcat_aliases")
        for domain, cats in by_domain.items():
            conn.execute(
                "INSERT OR REPLACE INTO webcat_domains(domain,categories) VALUES(?,?)",
                (domain, "|".join(sorted(cats))),
            )

        for c, n in sorted(cat_counts.items()):
            conn.execute(
                "INSERT OR REPLACE INTO webcat_categories(category,domains) VALUES(?,?)",
                (c, int(n)),
            )

        if aliases:
            for alias, canonical in sorted(aliases.items()):
                if alias and canonical and alias != canonical:
                    conn.execute(
                        "INSERT OR REPLACE INTO webcat_aliases(alias,canonical) VALUES(?,?)",
                        (alias, canonical),
                    )
        _upsert_meta(conn, "built_ts", str(_now()))
        _upsert_meta(conn, "source", source)
        _upsert_meta(conn, "domains", str(len(by_domain)))
        _upsert_meta(conn, "pairs", str(len(pairs)))
        _upsert_meta(conn, "aliases", str(len(aliases or {})))
    return len(by_domain), len(pairs)


def _collect(source_path: Path) -> Tuple[List[Tuple[str, str]], str, Dict[str, str]]:
    if source_path.is_dir():
        # UT1 canonical layout: blacklists/<category>/domains
        ut1_root = _find_ut1_blacklists_dir(source_path)
        if ut1_root is not None:
            pairs, aliases = _collect_from_ut1_blacklists_dedup(ut1_root)
            return pairs, f"ut1:{ut1_root}", aliases

        pairs = _collect_from_category_dir(source_path)
        return pairs, f"dir:{source_path}", {}

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
        ut1_root = _find_ut1_blacklists_dir(extracted)
        if ut1_root is not None:
            pairs, aliases = _collect_from_ut1_blacklists_dedup(ut1_root)
            return pairs, f"ut1zip:{source_path}", aliases
        pairs = _collect_from_category_dir(extracted)
        return pairs, f"zip:{source_path}", {}

    # tar.* archives (UT1 uses all.tar.gz)
    if source_path.is_file() and (source_path.name.lower().endswith(".tar.gz") or source_path.name.lower().endswith(".tgz") or source_path.suffix.lower() == ".tar"):
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
        ut1_root = _find_ut1_blacklists_dir(extracted)
        if ut1_root is not None:
            pairs, aliases = _collect_from_ut1_blacklists_dedup(ut1_root)
            return pairs, f"ut1tar:{source_path}", aliases

        pairs = _collect_from_category_dir(extracted)
        return pairs, f"tar:{source_path}", {}

    pairs = _collect_from_csv(source_path)
    return pairs, f"file:{source_path}", {}


def _collect_from_ut1_blacklists_dedup(blacklists_dir: Path) -> Tuple[List[Tuple[str, str]], Dict[str, str]]:
    """Parse UT1 blacklists/<category>/domains, collapsing duplicate lists.

    Some UT1 categories ship multiple directories with different names but identical
    domain lists. We dedupe these at build time to avoid duplicate buttons in the UI.

    Returns (pairs, aliases) where aliases maps alias_category -> canonical_category.
    """

    pairs: List[Tuple[str, str]] = []
    aliases: Dict[str, str] = {}
    if not blacklists_dir.is_dir():
        return pairs, aliases

    # Signature -> canonical category. Signature is an order-independent fingerprint.
    sig_to_cat: Dict[Tuple[int, int, int, int, int], str] = {}

    def _sig_for_domains(domains: Set[str]) -> Tuple[int, int, int, int, int]:
        # Order-independent fingerprint using two 64-bit XORs + two 64-bit sums + count.
        xor1 = 0
        xor2 = 0
        sum1 = 0
        sum2 = 0
        for d in domains:
            h = hashlib.blake2b(d.encode("utf-8", errors="ignore"), digest_size=16).digest()
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
        doms: Set[str] = set()
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
        else:
            if cat != canonical:
                aliases[cat] = canonical

        for d in doms:
            pairs.append((d, canonical))

    return pairs, aliases


def _find_ut1_blacklists_dir(root: Path) -> Optional[Path]:
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


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Download/compile a domain->category DB for Squid (UT1/OWC-style sources).")
    ap.add_argument("--db", default="/var/lib/squid-flask-proxy/webcat.db", help="Output SQLite DB path")
    ap.add_argument("--source-url", default="", help="Optional URL to download (zip or csv)")
    ap.add_argument("--source-path", default="", help="Optional local path (dir, zip, csv)")
    ap.add_argument("--download-to", default="/var/lib/squid-flask-proxy/webcat/source", help="Where to save downloaded artifact")
    args = ap.parse_args(list(argv) if argv is not None else None)

    db_path = Path(args.db)

    source_path_s = (args.source_path or "").strip()
    source_url = (args.source_url or "").strip()

    if not source_path_s and not source_url:
        print("[webcat] no source specified (set --source-path or --source-url); skipping", file=sys.stderr)
        return 0

    if source_url:
        dl_dir = Path(args.download_to)
        dl_dir.mkdir(parents=True, exist_ok=True)
        # Guess filename
        name = "webcat_feed"
        # Prefer exact matches for common archive types.
        lower_url = source_url.lower()
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
        print(f"[webcat] downloading {source_url} -> {dest}", file=sys.stderr)
        _download(source_url, dest)
        source_path = dest
    else:
        source_path = Path(source_path_s)

    if not source_path.exists():
        print(f"[webcat] source not found: {source_path}", file=sys.stderr)
        return 2

    print(f"[webcat] collecting categories from {source_path}", file=sys.stderr)
    pairs, source_label, aliases = _collect(source_path)
    if not pairs:
        print("[webcat] no domain/category pairs found (format mismatch?)", file=sys.stderr)
        return 3

    # Build to a temporary DB and atomically replace. This prevents rebuild failures when Squid
    # (or other readers) currently have the DB open.
    tmp_db_path = db_path.with_name(db_path.name + ".buildtmp")
    try:
        if tmp_db_path.exists():
            tmp_db_path.unlink()
    except Exception:
        pass

    domains, total_pairs = _build_db(tmp_db_path, pairs, source=source_label, aliases=aliases)
    os.replace(str(tmp_db_path), str(db_path))
    print(f"[webcat] built {db_path}: {domains} domains, {total_pairs} pairs", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
