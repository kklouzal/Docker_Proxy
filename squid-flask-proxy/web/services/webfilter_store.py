from __future__ import annotations

import os
import re
import sqlite3
import threading
import time
from dataclasses import dataclass
from subprocess import run
from typing import Dict, List, Optional, Set, Tuple


_DEFAULT_SOURCE_URL = "https://dsi.ut-capitole.fr/blacklists/download/all.tar.gz"

# Policy defaults: blocked by default (all other categories allowed by default).
_DEFAULT_BLOCKED_CATEGORIES: List[str] = [
    "adult",
    "cryptojacking",
    "dangerous_material",
    "ddos",
    "fakenews",
    "malware",
    "phishing",
    "proxy",
    "residential-proxies",
    "stalkerware",
]


_HOST_RE = re.compile(
    r"^(?=.{1,255}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$",
    re.IGNORECASE,
)


def _norm_domain(s: str) -> str:
    d = (s or "").strip().lower().rstrip(".")
    if d.startswith("."):
        d = d[1:]
    if "://" in d:
        d = d.split("://", 1)[1]
    d = d.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
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


def _parent_domains(domain: str, *, max_levels: int = 6) -> List[str]:
    d = _norm_domain(domain)
    if not d:
        return []
    parts = [p for p in d.split(".") if p]
    if len(parts) < 2:
        return [d]
    out: List[str] = []
    for i in range(0, min(len(parts) - 1, max_levels)):
        out.append(".".join(parts[i:]))
    return out


def _now() -> int:
    return int(time.time())


def _next_midnight_ts(now: Optional[int] = None) -> int:
    """Next local midnight (seconds since epoch)."""

    n = int(now if now is not None else _now())
    lt = time.localtime(n)
    # midnight at start of current day in local time
    midnight = int(time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, 0, 0, 0, 0, 0, -1)))
    if n < midnight:
        return midnight
    return midnight + 24 * 60 * 60


@dataclass(frozen=True)
class WebFilterSettings:
    enabled: bool
    source_url: str
    blocked_categories: List[str]
    whitelist_domains: List[str]
    last_success: int
    last_attempt: int
    last_error: str
    next_run_ts: int


def _strip_comment(line: str) -> str:
    return (line or "").split("#", 1)[0].strip()


def _parse_whitelist_lines(lines: List[str]) -> List[str]:
    """Parse user-provided whitelist entries.

    Supported forms:
      - domain.com
      - sub.domain.com
      - *.domain.com
      - .domain.com (treated as *.domain.com)

    Returns canonical patterns:
      - exact hosts: domain.com
      - wildcard hosts: *.domain.com
    """

    out: List[str] = []
    seen: Set[str] = set()

    for raw in (lines or []):
        t = _strip_comment(raw)
        if not t:
            continue

        if t.startswith("*."):
            base = _norm_domain(t[2:])
            if not _looks_like_host(base):
                continue
            pat = f"*.{base}"
        elif t.startswith("."):
            base = _norm_domain(t[1:])
            if not _looks_like_host(base):
                continue
            pat = f"*.{base}"
        else:
            host = _norm_domain(t)
            if not _looks_like_host(host):
                continue
            pat = host

        if pat not in seen:
            seen.add(pat)
            out.append(pat)

    return out


def _whitelist_match(domain: str, patterns: List[str]) -> str:
    """Return the matched whitelist pattern, or "" if none."""

    d = _norm_domain(domain)
    if not _looks_like_host(d):
        return ""

    for pat in (patterns or []):
        p = (pat or "").strip().lower()
        if not p:
            continue

        if p.startswith("*."):
            base = p[2:]
            if not base:
                continue
            if d == base or d.endswith("." + base):
                return pat
        else:
            if d == p:
                return pat
    return ""


_DEFAULTS: Dict[str, str] = {
    "enabled": "0",
    "source_url": _DEFAULT_SOURCE_URL,
    "blocked_categories": ",".join(_DEFAULT_BLOCKED_CATEGORIES),
    "whitelist_domains": "",
    "last_success": "0",
    "last_attempt": "0",
    "last_error": "",
    "next_run_ts": "0",
}


class WebFilterStore:
    def __init__(
        self,
        settings_db_path: str = "/var/lib/squid-flask-proxy/webfilter.db",
        webcat_db_path: str = "/var/lib/squid-flask-proxy/webcat.db",
        squid_include_path: str = "/etc/squid/conf.d/30-webfilter.conf",
        whitelist_path: str = "/var/lib/squid-flask-proxy/webfilter_whitelist.txt",
    ):
        self.settings_db_path = settings_db_path
        self.webcat_db_path = webcat_db_path
        self.squid_include_path = squid_include_path
        self.whitelist_path = whitelist_path

        self._started = False
        self._lock = threading.Lock()

    def _connect(self) -> sqlite3.Connection:
        os.makedirs(os.path.dirname(self.settings_db_path), exist_ok=True)
        conn = sqlite3.connect(self.settings_db_path, timeout=3, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA busy_timeout=3000;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def init_db(self) -> None:
        with self._connect() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT NOT NULL);")
            conn.execute("CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT NOT NULL);")
            conn.execute(
                "CREATE TABLE IF NOT EXISTS whitelist(pattern TEXT PRIMARY KEY, added_ts INTEGER NOT NULL);"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS blocked_log("
                "ts INTEGER NOT NULL, "
                "src_ip TEXT NOT NULL, "
                "url TEXT NOT NULL, "
                "category TEXT NOT NULL"
                ");"
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_blocked_log_ts ON blocked_log(ts);")
            for k, v in _DEFAULTS.items():
                conn.execute("INSERT OR IGNORE INTO settings(k,v) VALUES(?,?)", (k, v))
            conn.execute("INSERT OR IGNORE INTO meta(k,v) VALUES('refresh_requested','0')")

            # One-time migration: if an existing DB has empty values, populate the new defaults
            # without overwriting user-provided configuration.
            applied = conn.execute(
                "SELECT v FROM meta WHERE k='defaults_v1_applied'"
            ).fetchone()
            if not applied:
                cur_src = (conn.execute("SELECT v FROM settings WHERE k='source_url'").fetchone() or [""])[0]
                cur_cats = (conn.execute("SELECT v FROM settings WHERE k='blocked_categories'").fetchone() or [""])[0]
                if not str(cur_src or "").strip():
                    self._set(conn, "source_url", _DEFAULT_SOURCE_URL)
                if not str(cur_cats or "").strip():
                    self._set(conn, "blocked_categories", ",".join(_DEFAULT_BLOCKED_CATEGORIES))
                self._set_meta(conn, "defaults_v1_applied", "1")

            # One-time migration: move legacy newline whitelist from settings into whitelist table.
            migrated = conn.execute(
                "SELECT v FROM meta WHERE k='whitelist_v1_migrated'"
            ).fetchone()
            if not migrated:
                raw = self._get(conn, "whitelist_domains", "")
                patterns = _parse_whitelist_lines([ln for ln in str(raw or "").splitlines()])
                now = _now()
                for p in patterns:
                    conn.execute(
                        "INSERT OR IGNORE INTO whitelist(pattern, added_ts) VALUES(?,?)",
                        (p, int(now)),
                    )
                # Clear legacy key so we don't keep dual sources of truth.
                self._set(conn, "whitelist_domains", "")
                self._set_meta(conn, "whitelist_v1_migrated", "1")

    def list_whitelist(self, limit: int = 5000) -> List[Tuple[str, int]]:
        """Return [(pattern, added_ts)] for whitelist entries."""

        self.init_db()
        with self._connect() as conn:
            return self._list_whitelist(conn, limit=int(limit))

    def _list_whitelist(self, conn: sqlite3.Connection, limit: int) -> List[Tuple[str, int]]:
        rows = conn.execute(
            "SELECT pattern, added_ts FROM whitelist ORDER BY added_ts DESC, pattern ASC LIMIT ?",
            (int(limit),),
        ).fetchall()
        out: List[Tuple[str, int]] = []
        for r in rows:
            out.append((str(r[0]), int(r[1]) if r[1] is not None else 0))
        return out

    def list_blocked_log(self, limit: int = 200) -> List[Dict[str, object]]:
        """Return recent blocked events for the UI.

        Each item: {ts, src_ip, url, category}
        """

        try:
            self.init_db()
        except Exception:
            return []

        try:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT ts, src_ip, url, category FROM blocked_log ORDER BY ts DESC LIMIT ?",
                    (int(limit),),
                ).fetchall()
                out: List[Dict[str, object]] = []
                for r in rows:
                    out.append(
                        {
                            "ts": int(r[0]) if r[0] is not None else 0,
                            "src_ip": str(r[1] or ""),
                            "url": str(r[2] or ""),
                            "category": str(r[3] or ""),
                        }
                    )
                return out
        except Exception:
            return []

    def add_whitelist(self, entry: str) -> Tuple[bool, str, str]:
        """Add a single whitelist entry. Returns (ok, err, canonical_pattern)."""

        self.init_db()
        patterns = _parse_whitelist_lines([entry])
        if not patterns:
            return False, "Enter a domain like example.com or *.example.com", ""
        pat = patterns[0]
        with self._connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO whitelist(pattern, added_ts) VALUES(?,?)",
                (pat, int(_now())),
            )
        return True, "", pat

    def remove_whitelist(self, pattern: str) -> None:
        self.init_db()
        pat = (pattern or "").strip().lower()
        if not pat:
            return
        with self._connect() as conn:
            conn.execute("DELETE FROM whitelist WHERE pattern=?", (pat,))

    def get_whitelist_patterns(self) -> List[str]:
        """Return patterns in a stable precedence order.

        - Exact matches first
        - Then wildcards
        - More specific (longer) first within each group
        """

        self.init_db()
        with self._connect() as conn:
            return self._get_whitelist_patterns(conn)

    def _get_whitelist_patterns(self, conn: sqlite3.Connection) -> List[str]:
        rows = self._list_whitelist(conn, limit=10000)
        pats = [p for p, _ts in rows if p]
        exact = [p for p in pats if not p.startswith("*.")]
        wild = [p for p in pats if p.startswith("*.")]
        exact.sort(key=lambda s: (-len(s), s))
        wild.sort(key=lambda s: (-len(s), s))
        return exact + wild

    def _get(self, conn: sqlite3.Connection, key: str, default: str = "") -> str:
        row = conn.execute("SELECT v FROM settings WHERE k=?", (key,)).fetchone()
        return str(row[0]) if row and row[0] is not None else default

    def _set(self, conn: sqlite3.Connection, key: str, value: str) -> None:
        conn.execute(
            "INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
            (key, value),
        )

    def _get_meta(self, conn: sqlite3.Connection, key: str, default: str = "") -> str:
        row = conn.execute("SELECT v FROM meta WHERE k=?", (key,)).fetchone()
        return str(row[0]) if row and row[0] is not None else default

    def _set_meta(self, conn: sqlite3.Connection, key: str, value: str) -> None:
        conn.execute(
            "INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
            (key, value),
        )

    def get_settings(self) -> WebFilterSettings:
        self.init_db()
        with self._connect() as conn:
            return self._get_settings(conn)

    def _get_settings(self, conn: sqlite3.Connection) -> WebFilterSettings:
        enabled = self._get(conn, "enabled", "0") == "1"
        source_url = self._get(conn, "source_url", "")
        blocked_raw = self._get(conn, "blocked_categories", "")
        blocked = [c.strip() for c in blocked_raw.replace("\n", ",").split(",") if c.strip()]
        whitelist = self._get_whitelist_patterns(conn)
        last_success = int(self._get(conn, "last_success", "0") or 0)
        last_attempt = int(self._get(conn, "last_attempt", "0") or 0)
        last_error = self._get(conn, "last_error", "")
        next_run_ts = int(self._get(conn, "next_run_ts", "0") or 0)
        return WebFilterSettings(
            enabled=enabled,
            source_url=source_url,
            blocked_categories=blocked,
            whitelist_domains=whitelist,
            last_success=last_success,
            last_attempt=last_attempt,
            last_error=last_error,
            next_run_ts=next_run_ts,
        )

    def set_settings(
        self,
        *,
        enabled: bool,
        source_url: str,
        blocked_categories: List[str],
    ) -> None:
        self.init_db()
        src = (source_url or "").strip()
        cats = [c.strip() for c in (blocked_categories or []) if (c or "").strip()]
        cats = self._resolve_category_aliases(cats)
        cats_csv = ",".join(sorted(set(cats)))

        with self._connect() as conn:
            prev_enabled = self._get(conn, "enabled", "0") == "1"

            self._set(conn, "enabled", "1" if enabled else "0")
            self._set(conn, "source_url", src)
            self._set(conn, "blocked_categories", cats_csv)

            # Schedule download/build behavior.
            if enabled and not prev_enabled:
                # Enable transition: trigger immediate refresh + schedule next midnight.
                self._set_meta(conn, "refresh_requested", "1")
                self._set(conn, "next_run_ts", str(_next_midnight_ts(_now())))
            elif enabled:
                # If next_run_ts missing, set it.
                cur_next = int(self._get(conn, "next_run_ts", "0") or 0)
                if cur_next <= 0:
                    self._set(conn, "next_run_ts", str(_next_midnight_ts(_now())))

    def request_refresh_now(self) -> None:
        self.init_db()
        with self._connect() as conn:
            self._set_meta(conn, "refresh_requested", "1")

    def list_available_categories(self, limit: int = 5000) -> List[Tuple[str, int]]:
        """Return [(category, domains)] from the compiled webcat DB if available."""

        db_path = self.webcat_db_path
        if not os.path.exists(db_path):
            return []
        try:
            conn = sqlite3.connect(db_path, timeout=2)
            conn.row_factory = sqlite3.Row
            try:
                rows = conn.execute(
                    "SELECT category, domains FROM webcat_categories ORDER BY category ASC LIMIT ?",
                    (int(limit),),
                ).fetchall()
            finally:
                conn.close()
            out: List[Tuple[str, int]] = []
            for r in rows:
                out.append((str(r[0]), int(r[1]) if r[1] is not None else 0))
            return out
        except Exception:
            return []

    def _lookup_domain_categories(self, domain: str) -> Set[str]:
        """Return the set of categories for a domain using the compiled webcat DB."""

        if not _looks_like_host(domain):
            return set()

        db_path = self.webcat_db_path
        if not os.path.exists(db_path):
            return set()

        try:
            conn = sqlite3.connect(db_path, timeout=2)
            try:
                for cand in _parent_domains(domain):
                    row = conn.execute(
                        "SELECT categories FROM webcat_domains WHERE domain=?",
                        (cand,),
                    ).fetchone()
                    if row and row[0]:
                        raw = str(row[0])
                        return {c for c in raw.split("|") if c}
            finally:
                conn.close()
        except Exception:
            return set()
        return set()

    def test_domain(self, domain: str) -> Dict[str, object]:
        """Test whether a given domain would be blocked by current web filtering settings."""

        d = _norm_domain(domain)
        if not _looks_like_host(d):
            return {
                "ok": False,
                "domain": d,
                "verdict": "invalid",
                "reason": "Enter a domain like example.com",
                "whitelisted": False,
                "whitelist_match": "",
                "domain_categories": [],
                "matched_blocked": [],
                "blocked_by": "",
            }

        s = self.get_settings()

        wl_match = _whitelist_match(d, self.get_whitelist_patterns())
        if wl_match:
            return {
                "ok": True,
                "domain": d,
                "verdict": "allowed",
                "reason": "Whitelisted",
                "whitelisted": True,
                "whitelist_match": wl_match,
                "domain_categories": [],
                "matched_blocked": [],
                "blocked_by": "",
            }

        if not s.enabled:
            return {
                "ok": True,
                "domain": d,
                "verdict": "allowed",
                "reason": "Web filtering is disabled",
                "whitelisted": False,
                "whitelist_match": "",
                "domain_categories": [],
                "matched_blocked": [],
                "blocked_by": "",
            }

        blocked = set(self._resolve_category_aliases(list(s.blocked_categories or [])))
        if not blocked:
            return {
                "ok": True,
                "domain": d,
                "verdict": "allowed",
                "reason": "No categories are currently blocked",
                "whitelisted": False,
                "whitelist_match": "",
                "domain_categories": [],
                "matched_blocked": [],
                "blocked_by": "",
            }

        cats = self._lookup_domain_categories(d)
        if not cats:
            return {
                "ok": True,
                "domain": d,
                "verdict": "allowed",
                "reason": "Domain not present in category database",
                "whitelisted": False,
                "whitelist_match": "",
                "domain_categories": [],
                "matched_blocked": [],
                "blocked_by": "",
            }

        matched = sorted(c for c in cats if c in blocked)
        verdict = "blocked" if matched else "allowed"
        reason = "Matched blocked category" if matched else "No blocked categories matched"
        return {
            "ok": True,
            "domain": d,
            "verdict": verdict,
            "reason": reason,
            "whitelisted": False,
            "whitelist_match": "",
            "domain_categories": sorted(cats),
            "matched_blocked": matched,
            "blocked_by": (matched[0] if matched else ""),
        }

    def _resolve_category_aliases(self, categories: List[str]) -> List[str]:
        """Map alias categories to their canonical names using the webcat DB."""

        cats = [c.strip() for c in (categories or []) if (c or "").strip()]
        if not cats:
            return []

        db_path = self.webcat_db_path
        if not os.path.exists(db_path):
            return cats

        try:
            conn = sqlite3.connect(db_path, timeout=2)
            try:
                # Table may not exist if the DB was built by an older version.
                exists = conn.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='webcat_aliases'"
                ).fetchone()
                if not exists:
                    return cats
                placeholders = ",".join(["?"] * len(cats))
                rows = conn.execute(
                    f"SELECT alias, canonical FROM webcat_aliases WHERE alias IN ({placeholders})",
                    tuple(cats),
                ).fetchall()
            finally:
                conn.close()

            mapping = {str(r[0]): str(r[1]) for r in rows if r and r[0] and r[1]}
            mapped = [mapping.get(c, c) for c in cats]
            # De-dupe while preserving original order.
            seen = set()
            out: List[str] = []
            for c in mapped:
                if c not in seen:
                    seen.add(c)
                    out.append(c)
            return out
        except Exception:
            return cats

    def apply_squid_include(self) -> None:
        """(Re)generate the Squid include file from current settings."""

        s = self.get_settings()
        os.makedirs(os.path.dirname(self.squid_include_path), exist_ok=True)

        if not s.enabled or not s.blocked_categories:
            with open(self.squid_include_path, "w", encoding="utf-8") as f:
                f.write("# Autogenerated: web filtering disabled or no categories selected\n")
            return

        # Fixed defaults (not user-configurable via env).
        helpers = 20
        ttl = 3600
        neg_ttl = 300
        fail = "open"

        def _safe_acl_name(cat: str) -> str:
            out = []
            for ch in (cat or "").lower():
                if "a" <= ch <= "z" or "0" <= ch <= "9" or ch == "_":
                    out.append(ch)
                else:
                    out.append("_")
            return "".join(out).strip("_") or "cat"

        lines: List[str] = []
        lines.append("# Autogenerated: web filtering (domain categories)")
        # Pass client IP + destination + full requested URL so the helper can write a blocked log.
        lines.append(
            f"external_acl_type webcat children={helpers} ttl={ttl} negative_ttl={neg_ttl} %SRC %DST %URI "
            f"/usr/bin/python3 /app/tools/webcat_acl.py --db {self.webcat_db_path} --settings-db {self.settings_db_path} --fail {fail}"
        )

        # Whitelist is evaluated first.
        wl_patterns = list(s.whitelist_domains or [])
        os.makedirs(os.path.dirname(self.whitelist_path), exist_ok=True)
        try:
            with open(self.whitelist_path, "w", encoding="utf-8") as f:
                for pat in wl_patterns:
                    p = (pat or "").strip().lower()
                    if not p:
                        continue
                    if p.startswith("*."):
                        base = p[2:]
                        if base:
                            # Squid dstdomain uses a leading dot for wildcard suffix matches.
                            f.write("." + base + "\n")
                    else:
                        f.write(p + "\n")
        except Exception:
            # If we can't write the whitelist file, proceed without whitelist.
            wl_patterns = []

        if wl_patterns:
            lines.append(f"acl webfilter_whitelist dstdomain \"{self.whitelist_path}\"")
            lines.append("http_access allow webfilter_whitelist")

        # Block each selected category
        selected = self._resolve_category_aliases(list(s.blocked_categories or []))
        for cat in selected:
            safe = _safe_acl_name(cat)
            lines.append(f"acl webfilter_block_{safe} external webcat {cat}")
            lines.append(f"deny_info ERR_WEBFILTER_BLOCKED webfilter_block_{safe}")
            lines.append(f"http_access deny webfilter_block_{safe}")

        with open(self.squid_include_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

    def _record_attempt(self, ok: bool, err: str) -> None:
        self.init_db()
        with self._connect() as conn:
            self._record_attempt_conn(conn, ok=ok, err=err)

    def _record_attempt_conn(self, conn: sqlite3.Connection, *, ok: bool, err: str) -> None:
        self._set(conn, "last_attempt", str(_now()))
        if ok:
            self._set(conn, "last_success", str(_now()))
            self._set(conn, "last_error", "")
        else:
            self._set(conn, "last_error", (err or "")[:500])

    def _set_next_run(self, ts: int) -> None:
        self.init_db()
        with self._connect() as conn:
            self._set_next_run_conn(conn, ts=int(ts))

    def _set_next_run_conn(self, conn: sqlite3.Connection, *, ts: int) -> None:
        self._set(conn, "next_run_ts", str(int(ts)))

    def _clear_refresh_requested(self) -> None:
        self.init_db()
        with self._connect() as conn:
            self._clear_refresh_requested_conn(conn)

    def _clear_refresh_requested_conn(self, conn: sqlite3.Connection) -> None:
        self._set_meta(conn, "refresh_requested", "0")

    def _refresh_requested(self) -> bool:
        self.init_db()
        with self._connect() as conn:
            return self._refresh_requested_conn(conn)

    def _refresh_requested_conn(self, conn: sqlite3.Connection) -> bool:
        return self._get_meta(conn, "refresh_requested", "0") == "1"

    def _run_build(self, source_url: str) -> Tuple[bool, str]:
        """Run the builder inside the container (best-effort)."""

        if not source_url:
            return False, "source_url is empty"

        # Use the tool already shipped in /app.
        try:
            p = run(
                [
                    "python3",
                    "/app/tools/webcat_build.py",
                    "--db",
                    self.webcat_db_path,
                    "--source-url",
                    source_url,
                    "--download-to",
                    "/var/lib/squid-flask-proxy/webcat/source",
                ],
                capture_output=True,
                timeout=300,
            )
            if p.returncode != 0:
                out = (p.stdout or b"").decode("utf-8", errors="replace")
                err = (p.stderr or b"").decode("utf-8", errors="replace")
                return False, (err or out or f"builder failed rc={p.returncode}").strip()
            return True, ""
        except Exception as e:
            return False, f"{type(e).__name__}: {e}"

    def start_background(self) -> None:
        with self._lock:
            if self._started:
                return
            self._started = True

        self.init_db()
        t = threading.Thread(target=self._loop, name="webfilter-updater", daemon=True)
        t.start()

    def _loop(self) -> None:
        while True:
            try:
                self.init_db()

                # Read settings + refresh flag in a single connection to avoid extra
                # opens/closes in this tight loop.
                with self._connect() as conn:
                    s = self._get_settings(conn)
                    refresh = self._refresh_requested_conn(conn)

                    if s.enabled:
                        now = _now()
                        # Ensure next_run_ts is initialized when enabled.
                        next_ts = int(s.next_run_ts or 0)
                        if next_ts <= 0:
                            next_ts = _next_midnight_ts(now)
                            self._set_next_run_conn(conn, ts=next_ts)
                    else:
                        next_ts = 0

                if not s.enabled:
                    time.sleep(5.0)
                    continue

                now = _now()
                do_build = False
                if refresh:
                    do_build = True
                    next_after = _next_midnight_ts(now)
                else:
                    do_build = now >= int(next_ts or 0)
                    next_after = _next_midnight_ts(now + 60)

                if do_build:
                    ok, err = self._run_build(s.source_url)
                    with self._connect() as conn:
                        self._record_attempt_conn(conn, ok=ok, err=err)
                        if refresh:
                            self._clear_refresh_requested_conn(conn)
                        self._set_next_run_conn(conn, ts=next_after)
            except Exception:
                pass
            time.sleep(5.0)


_store: Optional[WebFilterStore] = None


def get_webfilter_store() -> WebFilterStore:
    global _store
    if _store is None:
        _store = WebFilterStore()
        _store.init_db()
    return _store
