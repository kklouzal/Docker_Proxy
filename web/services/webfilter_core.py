from __future__ import annotations

import os
import re
import threading
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from services.db import connect, table_exists
from services.proxy_context import get_proxy_id
from services.runtime_helpers import env_int as _env_int, now_ts as _now
_DEFAULT_SOURCE_URL = "https://dsi.ut-capitole.fr/blacklists/download/all.tar.gz"
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

_DEFAULTS: dict[str, str] = {
    "enabled": "0",
    "source_url": _DEFAULT_SOURCE_URL,
    "blocked_categories": ",".join(_DEFAULT_BLOCKED_CATEGORIES),
    "last_success": "0",
    "last_attempt": "0",
    "last_error": "",
    "next_run_ts": "0",
}

_GLOBAL_SCOPE = "__global__"
_GLOBAL_SETTINGS_KEYS = {"source_url", "last_success", "last_attempt", "last_error", "next_run_ts"}


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


@dataclass(frozen=True)
class WebFilterMaterializedState:
    include_text: str
    whitelist_text: str
def _next_midnight_ts(now: Optional[int] = None) -> int:
    current = int(now if now is not None else _now())
    local = time.localtime(current)
    midnight = int(time.mktime((local.tm_year, local.tm_mon, local.tm_mday, 0, 0, 0, 0, 0, -1)))
    if current < midnight:
        return midnight
    return midnight + 24 * 60 * 60


def _strip_comment(line: str) -> str:
    return (line or "").split("#", 1)[0].strip()


def _norm_domain(value: str) -> str:
    domain = (value or "").strip().lower().rstrip(".")
    if domain.startswith("."):
        domain = domain[1:]
    if "://" in domain:
        domain = domain.split("://", 1)[1]
    domain = domain.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in domain:
        domain = domain.split("@", 1)[1]
    if ":" in domain:
        host, port = domain.rsplit(":", 1)
        if port.isdigit():
            domain = host
    return domain


def _looks_like_host(value: str) -> bool:
    domain = _norm_domain(value)
    if not domain or "." not in domain or ".." in domain:
        return False
    return _HOST_RE.match(domain) is not None


def _parent_domains(domain: str, *, max_levels: int = 6) -> List[str]:
    normalized = _norm_domain(domain)
    if not normalized:
        return []
    parts = [part for part in normalized.split(".") if part]
    if len(parts) < 2:
        return [normalized]
    out: List[str] = []
    for index in range(0, min(len(parts) - 1, max_levels)):
        out.append(".".join(parts[index:]))
    return out


def _parse_whitelist_lines(lines: List[str]) -> List[str]:
    out: List[str] = []
    seen: Set[str] = set()
    for raw in lines or []:
        text = _strip_comment(raw)
        if not text:
            continue
        if text.startswith("*."):
            base = _norm_domain(text[2:])
            if not _looks_like_host(base):
                continue
            pattern = f"*.{base}"
        elif text.startswith("."):
            base = _norm_domain(text[1:])
            if not _looks_like_host(base):
                continue
            pattern = f"*.{base}"
        else:
            host = _norm_domain(text)
            if not _looks_like_host(host):
                continue
            pattern = host
        if pattern not in seen:
            seen.add(pattern)
            out.append(pattern)
    return out


def _whitelist_match(domain: str, patterns: List[str]) -> str:
    normalized = _norm_domain(domain)
    if not _looks_like_host(normalized):
        return ""
    for pattern in patterns or []:
        candidate = (pattern or "").strip().lower()
        if not candidate:
            continue
        if candidate.startswith("*."):
            base = candidate[2:]
            if base and (normalized == base or normalized.endswith("." + base)):
                return pattern
        elif normalized == candidate:
            return pattern
    return ""


class WebFilterStoreBase:
    TABLE_MAP: dict[str, str] = {
        "settings": "webfilter_settings",
        "meta": "webfilter_meta",
        "whitelist": "webfilter_whitelist",
    }

    def __init__(
        self,
        squid_include_path: str = "/etc/squid/conf.d/30-webfilter.conf",
        whitelist_path: str = "/var/lib/squid-flask-proxy/webfilter_whitelist.txt",
    ):
        self.squid_include_path = squid_include_path
        self.whitelist_path = whitelist_path

    def _connect(self):
        return connect()

    def _connect_webcat(self):
        return connect()

    def _settings_scope_for_key(self, key: str) -> str:
        if (key or "").strip() in _GLOBAL_SETTINGS_KEYS:
            return _GLOBAL_SCOPE
        return get_proxy_id()

    def _table(self, logical_name: str) -> str:
        return self.TABLE_MAP[logical_name]

    def init_db(self) -> None:
        with self._connect() as conn:
            settings_table = self._table("settings")
            meta_table = self._table("meta")
            whitelist_table = self._table("whitelist")
            conn.execute(
                f"CREATE TABLE IF NOT EXISTS {settings_table}(proxy_id VARCHAR(64) NOT NULL DEFAULT 'default', k VARCHAR(64) NOT NULL, v LONGTEXT NOT NULL, PRIMARY KEY(proxy_id, k))"
            )
            conn.execute(f"CREATE TABLE IF NOT EXISTS {meta_table}(k VARCHAR(64) PRIMARY KEY, v LONGTEXT NOT NULL)")
            conn.execute(
                f"CREATE TABLE IF NOT EXISTS {whitelist_table}(proxy_id VARCHAR(64) NOT NULL DEFAULT 'default', pattern VARCHAR(255) NOT NULL, added_ts BIGINT NOT NULL, PRIMARY KEY(proxy_id, pattern), KEY idx_{whitelist_table}_proxy_ts (proxy_id, added_ts))"
            )
            for key, value in _DEFAULTS.items():
                conn.execute(
                    f"INSERT IGNORE INTO {settings_table}(proxy_id, k, v) VALUES(%s,%s,%s)",
                    (self._settings_scope_for_key(key), key, value),
                )
            self._init_extra_schema(conn)

    def _init_extra_schema(self, conn) -> None:
        return None

    def _list_whitelist(self, conn, limit: int) -> List[Tuple[str, int]]:
        rows = conn.execute(
            f"SELECT pattern, added_ts FROM {self._table('whitelist')} WHERE proxy_id=%s ORDER BY added_ts DESC, pattern ASC LIMIT %s",
            (get_proxy_id(), int(limit)),
        ).fetchall()
        return [(str(row[0]), int(row[1]) if row[1] is not None else 0) for row in rows]

    def list_whitelist(self, limit: int = 5000) -> List[Tuple[str, int]]:
        self.init_db()
        with self._connect() as conn:
            return self._list_whitelist(conn, limit=int(limit))

    def add_whitelist(self, entry: str) -> Tuple[bool, str, str]:
        self.init_db()
        patterns = _parse_whitelist_lines([entry])
        if not patterns:
            return False, "Enter a domain like example.com or *.example.com", ""
        pattern = patterns[0]
        with self._connect() as conn:
            conn.execute(
                f"INSERT IGNORE INTO {self._table('whitelist')}(proxy_id, pattern, added_ts) VALUES(%s,%s,%s)",
                (get_proxy_id(), pattern, int(_now())),
            )
        return True, "", pattern

    def remove_whitelist(self, pattern: str) -> None:
        self.init_db()
        candidate = (pattern or "").strip().lower()
        if not candidate:
            return
        with self._connect() as conn:
            conn.execute(f"DELETE FROM {self._table('whitelist')} WHERE proxy_id=%s AND pattern=%s", (get_proxy_id(), candidate))

    def _get_whitelist_patterns(self, conn) -> List[str]:
        rows = self._list_whitelist(conn, limit=10000)
        patterns = [pattern for pattern, _ts in rows if pattern]
        exact = [pattern for pattern in patterns if not pattern.startswith("*.")]
        wild = [pattern for pattern in patterns if pattern.startswith("*.")]
        exact.sort(key=lambda item: (-len(item), item))
        wild.sort(key=lambda item: (-len(item), item))
        return exact + wild

    def get_whitelist_patterns(self) -> List[str]:
        self.init_db()
        with self._connect() as conn:
            return self._get_whitelist_patterns(conn)

    def _get(self, conn, key: str, default: str = "") -> str:
        scope = self._settings_scope_for_key(key)
        row = conn.execute(
            f"SELECT v FROM {self._table('settings')} WHERE proxy_id=%s AND k=%s",
            (scope, key),
        ).fetchone()
        return str(row[0]) if row and row[0] is not None else default

    def _set(self, conn, key: str, value: str) -> None:
        scope = self._settings_scope_for_key(key)
        conn.execute(
            f"INSERT INTO {self._table('settings')}(proxy_id, k, v) VALUES(%s,%s,%s) ON DUPLICATE KEY UPDATE v=VALUES(v)",
            (scope, key, value),
        )

    def _get_global_setting_conn(self, conn, key: str, default: str = "") -> str:
        row = conn.execute(
            f"SELECT v FROM {self._table('settings')} WHERE proxy_id=%s AND k=%s",
            (_GLOBAL_SCOPE, key),
        ).fetchone()
        return str(row[0]) if row and row[0] is not None else default

    def _get_meta(self, conn, key: str, default: str = "") -> str:
        row = conn.execute(f"SELECT v FROM {self._table('meta')} WHERE k=%s", (key,)).fetchone()
        return str(row[0]) if row and row[0] is not None else default

    def _set_meta(self, conn, key: str, value: str) -> None:
        conn.execute(
            f"INSERT INTO {self._table('meta')}(k,v) VALUES(%s,%s) ON DUPLICATE KEY UPDATE v=VALUES(v)",
            (key, value),
        )

    def _get_settings(self, conn) -> WebFilterSettings:
        enabled = self._get(conn, "enabled", "0") == "1"
        source_url = self._get(conn, "source_url", "")
        blocked_raw = self._get(conn, "blocked_categories", "")
        blocked = [item.strip() for item in blocked_raw.replace("\n", ",").split(",") if item.strip()]
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

    def get_settings(self) -> WebFilterSettings:
        self.init_db()
        with self._connect() as conn:
            return self._get_settings(conn)

    def _resolve_category_aliases(self, categories: List[str]) -> List[str]:
        normalized = [item.strip() for item in (categories or []) if (item or "").strip()]
        if not normalized:
            return []
        try:
            with self._connect_webcat() as conn:
                if not table_exists(conn, "webcat_aliases"):
                    return normalized
                placeholders = ",".join(["%s"] * len(normalized))
                rows = conn.execute(
                    f"SELECT alias, canonical FROM webcat_aliases WHERE alias IN ({placeholders})",
                    tuple(normalized),
                ).fetchall()
            mapping = {str(row[0]): str(row[1]) for row in rows if row and row[0] and row[1]}
            seen: Set[str] = set()
            out: List[str] = []
            for category in [mapping.get(item, item) for item in normalized]:
                if category not in seen:
                    seen.add(category)
                    out.append(category)
            return out
        except Exception:
            return normalized

    def render_materialized_state(self) -> WebFilterMaterializedState:
        settings = self.get_settings()
        helpers = _env_int("WEBFILTER_HELPERS", 64, minimum=8, maximum=256)
        ttl = _env_int("WEBFILTER_TTL_SECONDS", 3600, minimum=60, maximum=86400)
        neg_ttl = _env_int("WEBFILTER_NEGATIVE_TTL_SECONDS", 300, minimum=0, maximum=3600)
        fail = "open"

        def _safe_acl_name(category: str) -> str:
            out = []
            for ch in (category or "").lower():
                if "a" <= ch <= "z" or "0" <= ch <= "9" or ch == "_":
                    out.append(ch)
                else:
                    out.append("_")
            return "".join(out).strip("_") or "cat"

        whitelist_lines: List[str] = []
        for pattern in list(settings.whitelist_domains or []):
            normalized = (pattern or "").strip().lower()
            if not normalized:
                continue
            if normalized.startswith("*."):
                base = normalized[2:]
                if base:
                    whitelist_lines.append("." + base)
            else:
                whitelist_lines.append(normalized)
        whitelist_text = ("\n".join(whitelist_lines) + "\n") if whitelist_lines else ""

        if not settings.enabled or not settings.blocked_categories:
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
            lines.append("note webfilter_allow whitelist webfilter_whitelist")
            lines.append("http_access allow webfilter_whitelist")

        selected = self._resolve_category_aliases(list(settings.blocked_categories or []))
        for category in selected:
            safe = _safe_acl_name(category)
            lines.append(f"acl webfilter_block_{safe} external webcat {category}")
            lines.append(f"deny_info ERR_WEBFILTER_BLOCKED webfilter_block_{safe}")
            lines.append(f"http_access deny webfilter_block_{safe}")

        return WebFilterMaterializedState(
            include_text="\n".join(lines) + "\n",
            whitelist_text=whitelist_text,
        )

    def apply_squid_include(self) -> None:
        include_dir = os.path.dirname(self.squid_include_path)
        if include_dir:
            os.makedirs(include_dir, exist_ok=True)
        whitelist_dir = os.path.dirname(self.whitelist_path)
        if whitelist_dir:
            os.makedirs(whitelist_dir, exist_ok=True)
        state = self.render_materialized_state()
        with open(self.whitelist_path, "w", encoding="utf-8") as whitelist_file:
            whitelist_file.write(state.whitelist_text)
        with open(self.squid_include_path, "w", encoding="utf-8") as include_file:
            include_file.write(state.include_text)


class ProxyWebFilterStore(WebFilterStoreBase):
    pass


_store: Optional[ProxyWebFilterStore] = None
_store_lock = threading.Lock()


def get_proxy_webfilter_store() -> ProxyWebFilterStore:
    global _store
    if _store is not None:
        return _store
    with _store_lock:
        if _store is None:
            _store = ProxyWebFilterStore()
            _store.init_db()
        return _store
