from __future__ import annotations

import os
import re
import threading
import time
from dataclasses import dataclass
from subprocess import run
from typing import Dict, List, Optional, Set, Tuple

import logging

from services.db import column_exists, connect, create_index_if_not_exists, table_exists
from services.errors import public_error_message
from services.logutil import log_exception_throttled
from services.proxy_context import get_proxy_id


logger = logging.getLogger(__name__)


def _env_int(name: str, default: int, *, minimum: int, maximum: int) -> int:
    try:
        value = int((os.environ.get(name) or str(default)).strip() or str(default))
    except Exception:
        value = int(default)
    return max(minimum, min(maximum, value))


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

_GLOBAL_SCOPE = "__global__"
_GLOBAL_SETTINGS_KEYS = {"source_url", "last_success", "last_attempt", "last_error", "next_run_ts"}


@dataclass(frozen=True)
class WebFilterMaterializedState:
    include_text: str
    whitelist_text: str


class WebFilterStore:
    def __init__(
        self,
        squid_include_path: str = "/etc/squid/conf.d/30-webfilter.conf",
        whitelist_path: str = "/var/lib/squid-flask-proxy/webfilter_whitelist.txt",
    ):
        self.squid_include_path = squid_include_path
        self.whitelist_path = whitelist_path

        self._started = False
        self._lock = threading.Lock()

    def _connect(self):
        return connect()

    def _connect_webcat(self):
        return connect()

    def _settings_scope_for_key(self, key: str) -> str:
        if (key or "").strip() in _GLOBAL_SETTINGS_KEYS:
            return _GLOBAL_SCOPE
        return get_proxy_id()

    def _table(self, conn, logical_name: str) -> str:
        mapping = {
            "settings": "webfilter_settings",
            "meta": "webfilter_meta",
            "whitelist": "webfilter_whitelist",
            "blocked_log": "webfilter_blocked_log",
        }
        return mapping[logical_name]

    def init_db(self) -> None:
        with self._connect() as conn:
            settings_table = self._table(conn, "settings")
            meta_table = self._table(conn, "meta")
            whitelist_table = self._table(conn, "whitelist")
            blocked_log_table = self._table(conn, "blocked_log")
            conn.execute(
                f"CREATE TABLE IF NOT EXISTS {settings_table}(proxy_id VARCHAR(64) NOT NULL DEFAULT 'default', k VARCHAR(64) NOT NULL, v LONGTEXT NOT NULL, PRIMARY KEY(proxy_id, k))"
            )
            conn.execute(f"CREATE TABLE IF NOT EXISTS {meta_table}(k VARCHAR(64) PRIMARY KEY, v LONGTEXT NOT NULL)")
            conn.execute(
                f"CREATE TABLE IF NOT EXISTS {whitelist_table}(proxy_id VARCHAR(64) NOT NULL DEFAULT 'default', pattern VARCHAR(255) NOT NULL, added_ts BIGINT NOT NULL, PRIMARY KEY(proxy_id, pattern))"
            )
            conn.execute(
                f"CREATE TABLE IF NOT EXISTS {blocked_log_table}("
                "id BIGINT PRIMARY KEY AUTO_INCREMENT, "
                "proxy_id VARCHAR(64) NOT NULL DEFAULT 'default', "
                "ts BIGINT NOT NULL, "
                "src_ip VARCHAR(64) NOT NULL, "
                "url TEXT NOT NULL, "
                "category VARCHAR(128) NOT NULL"
                ")"
            )
            if not column_exists(conn, settings_table, "proxy_id"):
                conn.execute(f"ALTER TABLE {settings_table} ADD COLUMN proxy_id VARCHAR(64) NOT NULL DEFAULT 'default' FIRST")
                conn.execute(f"ALTER TABLE {settings_table} DROP PRIMARY KEY, ADD PRIMARY KEY(proxy_id, k)")
            if not column_exists(conn, whitelist_table, "proxy_id"):
                conn.execute(f"ALTER TABLE {whitelist_table} ADD COLUMN proxy_id VARCHAR(64) NOT NULL DEFAULT 'default' FIRST")
                conn.execute(f"ALTER TABLE {whitelist_table} DROP PRIMARY KEY, ADD PRIMARY KEY(proxy_id, pattern)")
            if not column_exists(conn, blocked_log_table, "proxy_id"):
                conn.execute(f"ALTER TABLE {blocked_log_table} ADD COLUMN proxy_id VARCHAR(64) NOT NULL DEFAULT 'default' AFTER id")
            create_index_if_not_exists(conn, table_name=settings_table, index_name=f"idx_{settings_table}_proxy_key", columns_sql="proxy_id, k")
            create_index_if_not_exists(conn, table_name=whitelist_table, index_name=f"idx_{whitelist_table}_proxy_ts", columns_sql="proxy_id, added_ts")
            create_index_if_not_exists(conn, table_name=blocked_log_table, index_name=f"idx_{blocked_log_table}_proxy_ts", columns_sql="proxy_id, ts, id")
            for k, v in _DEFAULTS.items():
                conn.execute(
                    f"INSERT OR IGNORE INTO {settings_table}(proxy_id, k, v) VALUES(?,?,?)",
                    (self._settings_scope_for_key(k), k, v),
                )
            conn.execute(f"INSERT OR IGNORE INTO {meta_table}(k,v) VALUES('refresh_requested','0')")

            for key in _GLOBAL_SETTINGS_KEYS:
                row = conn.execute(
                    f"SELECT 1 FROM {settings_table} WHERE proxy_id=? AND k=? LIMIT 1",
                    (_GLOBAL_SCOPE, key),
                ).fetchone()
                if row is not None:
                    continue
                src = conn.execute(
                    f"SELECT v FROM {settings_table} WHERE k=? ORDER BY CASE WHEN proxy_id='default' THEN 0 ELSE 1 END, proxy_id ASC LIMIT 1",
                    (key,),
                ).fetchone()
                if src and src[0] is not None:
                    conn.execute(
                        f"INSERT OR IGNORE INTO {settings_table}(proxy_id, k, v) VALUES(?,?,?)",
                        (_GLOBAL_SCOPE, key, str(src[0])),
                    )

            # One-time migration: if an existing DB has empty values, populate the new defaults
            # without overwriting user-provided configuration.
            applied = conn.execute(f"SELECT v FROM {meta_table} WHERE k='defaults_v1_applied'").fetchone()
            if not applied:
                cur_src = (conn.execute(f"SELECT v FROM {settings_table} WHERE k='source_url'").fetchone() or [""])[0]
                cur_cats = (conn.execute(f"SELECT v FROM {settings_table} WHERE k='blocked_categories'").fetchone() or [""])[0]
                if not str(cur_src or "").strip():
                    self._set(conn, "source_url", _DEFAULT_SOURCE_URL)
                if not str(cur_cats or "").strip():
                    self._set(conn, "blocked_categories", ",".join(_DEFAULT_BLOCKED_CATEGORIES))
                self._set_meta(conn, "defaults_v1_applied", "1")

            # One-time migration: move newline-based whitelist entries from settings into the whitelist table.
            migrated = conn.execute(f"SELECT v FROM {meta_table} WHERE k='whitelist_v1_migrated'").fetchone()
            if not migrated:
                raw = self._get(conn, "whitelist_domains", "")
                patterns = _parse_whitelist_lines([ln for ln in str(raw or "").splitlines()])
                now = _now()
                for p in patterns:
                    conn.execute(
                        f"INSERT OR IGNORE INTO {whitelist_table}(pattern, added_ts) VALUES(?,?)",
                        (p, int(now)),
                    )
                # Clear the old settings key so we don't keep dual sources of truth.
                self._set(conn, "whitelist_domains", "")
                self._set_meta(conn, "whitelist_v1_migrated", "1")

    def list_whitelist(self, limit: int = 5000) -> List[Tuple[str, int]]:
        """Return [(pattern, added_ts)] for whitelist entries."""

        self.init_db()
        with self._connect() as conn:
            return self._list_whitelist(conn, limit=int(limit))

    def _list_whitelist(self, conn, limit: int) -> List[Tuple[str, int]]:
        proxy_id = get_proxy_id()
        rows = conn.execute(
            f"SELECT pattern, added_ts FROM {self._table(conn, 'whitelist')} WHERE proxy_id=? ORDER BY added_ts DESC, pattern ASC LIMIT ?",
            (proxy_id, int(limit)),
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
                proxy_id = get_proxy_id()
                rows = conn.execute(
                    f"SELECT ts, src_ip, url, category FROM {self._table(conn, 'blocked_log')} WHERE proxy_id=? ORDER BY ts DESC LIMIT ?",
                    (proxy_id, int(limit)),
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
            proxy_id = get_proxy_id()
            conn.execute(
                f"INSERT OR IGNORE INTO {self._table(conn, 'whitelist')}(proxy_id, pattern, added_ts) VALUES(?,?,?)",
                (proxy_id, pat, int(_now())),
            )
        return True, "", pat

    def remove_whitelist(self, pattern: str) -> None:
        self.init_db()
        pat = (pattern or "").strip().lower()
        if not pat:
            return
        with self._connect() as conn:
            conn.execute(f"DELETE FROM {self._table(conn, 'whitelist')} WHERE proxy_id=? AND pattern=?", (get_proxy_id(), pat))

    def get_whitelist_patterns(self) -> List[str]:
        """Return patterns in a stable precedence order.

        - Exact matches first
        - Then wildcards
        - More specific (longer) first within each group
        """

        self.init_db()
        with self._connect() as conn:
            return self._get_whitelist_patterns(conn)

    def _get_whitelist_patterns(self, conn) -> List[str]:
        rows = self._list_whitelist(conn, limit=10000)
        pats = [p for p, _ts in rows if p]
        exact = [p for p in pats if not p.startswith("*.")]
        wild = [p for p in pats if p.startswith("*.")]
        exact.sort(key=lambda s: (-len(s), s))
        wild.sort(key=lambda s: (-len(s), s))
        return exact + wild

    def _get(self, conn, key: str, default: str = "") -> str:
        scope = self._settings_scope_for_key(key)
        row = conn.execute(
            f"SELECT v FROM {self._table(conn, 'settings')} WHERE proxy_id=? AND k=?",
            (scope, key),
        ).fetchone()
        return str(row[0]) if row and row[0] is not None else default

    def _set(self, conn, key: str, value: str) -> None:
        scope = self._settings_scope_for_key(key)
        conn.execute(
            f"INSERT INTO {self._table(conn, 'settings')}(proxy_id, k, v) VALUES(?,?,?) ON CONFLICT(proxy_id, k) DO UPDATE SET v=excluded.v",
            (scope, key, value),
        )

    def _get_global_setting_conn(self, conn, key: str, default: str = "") -> str:
        row = conn.execute(
            f"SELECT v FROM {self._table(conn, 'settings')} WHERE proxy_id=? AND k=?",
            (_GLOBAL_SCOPE, key),
        ).fetchone()
        return str(row[0]) if row and row[0] is not None else default

    def _get_meta(self, conn, key: str, default: str = "") -> str:
        row = conn.execute(f"SELECT v FROM {self._table(conn, 'meta')} WHERE k=?", (key,)).fetchone()
        return str(row[0]) if row and row[0] is not None else default

    def _set_meta(self, conn, key: str, value: str) -> None:
        conn.execute(
            f"INSERT INTO {self._table(conn, 'meta')}(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
            (key, value),
        )

    def get_settings(self) -> WebFilterSettings:
        self.init_db()
        with self._connect() as conn:
            return self._get_settings(conn)

    def _get_settings(self, conn) -> WebFilterSettings:
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
            prev_source = self._get_global_setting_conn(conn, "source_url", "")

            self._set(conn, "enabled", "1" if enabled else "0")
            self._set(conn, "source_url", src)
            self._set(conn, "blocked_categories", cats_csv)

            # Schedule download/build behavior.
            if src and src != prev_source:
                self._set_meta(conn, "refresh_requested", "1")
                self._set(conn, "next_run_ts", str(_next_midnight_ts(_now())))
            elif enabled and not prev_enabled:
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

        try:
            with self._connect_webcat() as conn:
                rows = conn.execute(
                    "SELECT category, domains FROM webcat_categories ORDER BY category ASC LIMIT ?",
                    (int(limit),),
                ).fetchall()
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

        try:
            with self._connect_webcat() as conn:
                for cand in _parent_domains(domain):
                    row = conn.execute(
                        "SELECT categories FROM webcat_domains WHERE domain=?",
                        (cand,),
                    ).fetchone()
                    if row and row[0]:
                        raw = str(row[0])
                        return {c for c in raw.split("|") if c}
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

        try:
            with self._connect_webcat() as conn:
                if not table_exists(conn, "webcat_aliases"):
                    return cats
                placeholders = ",".join(["?"] * len(cats))
                rows = conn.execute(
                    f"SELECT alias, canonical FROM webcat_aliases WHERE alias IN ({placeholders})",
                    tuple(cats),
                ).fetchall()

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

    def render_materialized_state(self) -> WebFilterMaterializedState:
        s = self.get_settings()
        helpers = _env_int("WEBFILTER_HELPERS", 64, minimum=8, maximum=256)
        ttl = _env_int("WEBFILTER_TTL_SECONDS", 3600, minimum=60, maximum=86400)
        neg_ttl = _env_int("WEBFILTER_NEGATIVE_TTL_SECONDS", 300, minimum=0, maximum=3600)
        fail = "open"

        def _safe_acl_name(cat: str) -> str:
            out = []
            for ch in (cat or "").lower():
                if "a" <= ch <= "z" or "0" <= ch <= "9" or ch == "_":
                    out.append(ch)
                else:
                    out.append("_")
            return "".join(out).strip("_") or "cat"

        whitelist_lines: List[str] = []
        for pat in list(s.whitelist_domains or []):
            p = (pat or "").strip().lower()
            if not p:
                continue
            if p.startswith("*."):
                base = p[2:]
                if base:
                    whitelist_lines.append("." + base)
            else:
                whitelist_lines.append(p)
        whitelist_text = ("\n".join(whitelist_lines) + "\n") if whitelist_lines else ""

        if not s.enabled or not s.blocked_categories:
            return WebFilterMaterializedState(
                include_text="# Autogenerated: web filtering disabled or no categories selected\n",
                whitelist_text=whitelist_text,
            )

        lines: List[str] = []
        lines.append("# Autogenerated: web filtering (domain categories)")
        lines.append(
            f"external_acl_type webcat children={helpers} ttl={ttl} negative_ttl={neg_ttl} %SRC %DST %URI "
            f"/usr/bin/python3 /app/tools/webcat_acl.py --fail {fail}"
        )

        if whitelist_lines:
            lines.append(f"acl webfilter_whitelist dstdomain \"{self.whitelist_path}\"")
            lines.append("http_access allow webfilter_whitelist")

        selected = self._resolve_category_aliases(list(s.blocked_categories or []))
        for cat in selected:
            safe = _safe_acl_name(cat)
            lines.append(f"acl webfilter_block_{safe} external webcat {cat}")
            lines.append(f"deny_info ERR_WEBFILTER_BLOCKED webfilter_block_{safe}")
            lines.append(f"http_access deny webfilter_block_{safe}")

        return WebFilterMaterializedState(
            include_text="\n".join(lines) + "\n",
            whitelist_text=whitelist_text,
        )

    def apply_squid_include(self) -> None:
        """(Re)generate the Squid include file from current settings."""
        include_dir = os.path.dirname(self.squid_include_path)
        if include_dir:
            os.makedirs(include_dir, exist_ok=True)
        whitelist_dir = os.path.dirname(self.whitelist_path)
        if whitelist_dir:
            os.makedirs(whitelist_dir, exist_ok=True)
        state = self.render_materialized_state()
        with open(self.whitelist_path, "w", encoding="utf-8") as f:
            f.write(state.whitelist_text)
        with open(self.squid_include_path, "w", encoding="utf-8") as f:
            f.write(state.include_text)

    def _record_attempt(self, ok: bool, err: str) -> None:
        self.init_db()
        with self._connect() as conn:
            self._record_attempt_conn(conn, ok=ok, err=err)

    def _record_attempt_conn(self, conn, *, ok: bool, err: str) -> None:
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

    def _set_next_run_conn(self, conn, *, ts: int) -> None:
        self._set(conn, "next_run_ts", str(int(ts)))

    def _clear_refresh_requested(self) -> None:
        self.init_db()
        with self._connect() as conn:
            self._clear_refresh_requested_conn(conn)

    def _clear_refresh_requested_conn(self, conn) -> None:
        self._set_meta(conn, "refresh_requested", "0")

    def _refresh_requested(self) -> bool:
        self.init_db()
        with self._connect() as conn:
            return self._refresh_requested_conn(conn)

    def _refresh_requested_conn(self, conn) -> bool:
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
            logger.exception("webfilter build failed")
            return False, public_error_message(
                e,
                default="Build failed. Check server logs for details.",
                max_len=400,
            )

    def start_background(self) -> None:
        with self._lock:
            if self._started:
                return
            self._started = True
            self.init_db()
            t = threading.Thread(target=self._loop, name="webfilter-updater", daemon=True)
            t.start()

    def _loop(self) -> None:
        disabled_sleep = float(_env_int("WEBFILTER_DISABLED_POLL_SECONDS", 60, minimum=5, maximum=3600))
        enabled_sleep = float(_env_int("WEBFILTER_ENABLED_POLL_SECONDS", 300, minimum=5, maximum=3600))
        error_sleep = float(_env_int("WEBFILTER_ERROR_BACKOFF_SECONDS", 30, minimum=5, maximum=300))
        while True:
            sleep_seconds = enabled_sleep
            try:
                self.init_db()

                # Read settings + refresh flag in a single connection to avoid extra
                # opens/closes in this tight loop.
                with self._connect() as conn:
                    source_url = self._get_global_setting_conn(conn, "source_url", _DEFAULT_SOURCE_URL)
                    last_success = int(self._get_global_setting_conn(conn, "last_success", "0") or 0)
                    next_ts = int(self._get_global_setting_conn(conn, "next_run_ts", "0") or 0)
                    refresh = self._refresh_requested_conn(conn)
                    if next_ts <= 0:
                        next_ts = _next_midnight_ts(_now())
                        self._set_next_run_conn(conn, ts=next_ts)

                if not source_url:
                    sleep_seconds = disabled_sleep
                    time.sleep(sleep_seconds)
                    continue

                now = _now()
                do_build = False
                if refresh:
                    do_build = True
                    next_after = _next_midnight_ts(now)
                    sleep_seconds = 5.0
                else:
                    do_build = now >= int(next_ts or 0)
                    next_after = _next_midnight_ts(now + 60)
                    if not do_build:
                        remaining = max(5, int(next_ts or 0) - now) if int(next_ts or 0) > 0 else int(enabled_sleep)
                        sleep_seconds = min(enabled_sleep, float(remaining))

                if do_build:
                    ok, err = self._run_build(source_url)
                    with self._connect() as conn:
                        self._record_attempt_conn(conn, ok=ok, err=err)
                        if refresh:
                            self._clear_refresh_requested_conn(conn)
                        self._set_next_run_conn(conn, ts=next_after)
                    sleep_seconds = 5.0
            except Exception:
                log_exception_throttled(
                    logger,
                    "webfilter_store.loop",
                    interval_seconds=30,
                    message="webfilter background loop iteration failed",
                )
                sleep_seconds = error_sleep
            time.sleep(sleep_seconds)


_store: Optional[WebFilterStore] = None
_store_lock = threading.Lock()


def get_webfilter_store() -> WebFilterStore:
    global _store
    if _store is not None:
        return _store
    with _store_lock:
        if _store is None:
            _store = WebFilterStore()
            _store.init_db()
        return _store
