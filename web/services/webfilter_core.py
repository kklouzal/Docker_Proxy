from __future__ import annotations

import hashlib
import ipaddress
import os
import socket
import threading
import time
from dataclasses import dataclass
from typing import ClassVar
from urllib.parse import urlparse

from services.db import connect, table_exists
from services.domain_normalization import (
    looks_like_domain as _looks_like_host,
)
from services.domain_normalization import (
    normalize_domain as _norm_domain,
)
from services.errors import public_error_message
from services.materialized_files import write_managed_text_files
from services.proxy_context import get_proxy_id
from services.runtime_helpers import env_int as _env_int
from services.runtime_helpers import now_ts as _now
from services.safe_browsing_v5 import DEFAULT_SAFE_BROWSING_LISTS, SafeBrowsingStore


def get_policy_request_store():
    from services.policy_requests import (
        get_policy_request_store as _get_policy_request_store,
    )

    return _get_policy_request_store()


_DEFAULT_SOURCE_URL = "https://dsi.ut-capitole.fr/blacklists/download/all.tar.gz"
_LEGACY_DEFAULT_BLOCKED_CATEGORIES: list[str] = [
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
_LEGACY_DEFAULT_BLOCKED_CATEGORIES_CSV = ",".join(_LEGACY_DEFAULT_BLOCKED_CATEGORIES)

_DEFAULTS: dict[str, str] = {
    "enabled": "0",
    "source_url": _DEFAULT_SOURCE_URL,
    "source_provider": "auto",
    "blocked_categories": "",
    "last_success": "0",
    "last_attempt": "0",
    "last_error": "",
    "next_run_ts": "0",
    "safe_browsing_enabled": "0",
    "safe_browsing_api_key": "",
    "safe_browsing_lists": ",".join(DEFAULT_SAFE_BROWSING_LISTS),
    "safe_browsing_last_success": "0",
    "safe_browsing_last_attempt": "0",
    "safe_browsing_last_error": "",
    "safe_browsing_next_run_ts": "0",
}

_GLOBAL_SCOPE = "__global__"
_GLOBAL_SETTINGS_KEYS = {
    "source_url",
    "source_provider",
    "last_success",
    "last_attempt",
    "last_error",
    "next_run_ts",
    "safe_browsing_enabled",
    "safe_browsing_api_key",
    "safe_browsing_lists",
    "safe_browsing_last_success",
    "safe_browsing_last_attempt",
    "safe_browsing_last_error",
    "safe_browsing_next_run_ts",
}


@dataclass(frozen=True)
class WebFilterSettings:
    enabled: bool
    source_url: str
    blocked_categories: list[str]
    whitelist_domains: list[str]
    last_success: int
    last_attempt: int
    last_error: str
    next_run_ts: int
    source_provider: str = "auto"
    safe_browsing_enabled: bool = False
    safe_browsing_api_key: str = ""
    safe_browsing_lists: list[str] | None = None
    safe_browsing_last_success: int = 0
    safe_browsing_last_attempt: int = 0
    safe_browsing_last_error: str = ""
    safe_browsing_next_run_ts: int = 0


@dataclass(frozen=True)
class WebFilterMaterializedState:
    include_text: str
    whitelist_text: str


def _next_midnight_ts(now: int | None = None) -> int:
    current = int(now if now is not None else _now())
    local = time.localtime(current)
    midnight = int(
        time.mktime((local.tm_year, local.tm_mon, local.tm_mday, 0, 0, 0, 0, 0, -1)),
    )
    if current < midnight:
        return midnight
    return midnight + 24 * 60 * 60


def _is_forbidden_download_ip(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    return (
        ip.is_loopback
        or ip.is_private
        or ip.is_reserved
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
    )


def _is_internal_source_host(hostname: str) -> bool:
    host = (hostname or "").strip().lower().rstrip(".")
    if not host:
        return True
    if host in {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}:
        return True
    try:
        return _is_forbidden_download_ip(host)
    except ValueError:
        pass
    if host.endswith((".local", ".internal", ".localhost")):
        return True

    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, OSError):
        return True

    resolved = {info[4][0] for info in infos if info and info[4]}
    if not resolved:
        return True
    return any(_is_forbidden_download_ip(address) for address in resolved)


def validate_source_url(source_url: str) -> str:
    invalid_url_msg = "Web filter source URLs must be valid absolute HTTP/HTTPS URLs."
    source = (source_url or "").strip()
    if not source or any(
        ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in source
    ):
        raise ValueError(invalid_url_msg)
    try:
        parsed = urlparse(source)
    except ValueError as exc:
        raise ValueError(invalid_url_msg) from exc
    if parsed.scheme not in {"http", "https"}:
        msg = "Only http/https web filter source URLs are supported."
        raise ValueError(msg)
    try:
        hostname = parsed.hostname or ""
    except ValueError as exc:
        raise ValueError(invalid_url_msg) from exc
    if not parsed.netloc or not hostname:
        raise ValueError(invalid_url_msg)
    if _is_internal_source_host(hostname):
        msg = (
            "Web filter source URLs must not point at internal or localhost addresses."
        )
        raise ValueError(msg)
    return source


def _strip_comment(line: str) -> str:
    return (line or "").split("#", 1)[0].strip()


def _parent_domains(domain: str, *, max_levels: int = 6) -> list[str]:
    normalized = _norm_domain(domain)
    if not normalized:
        return []
    parts = [part for part in normalized.split(".") if part]
    if len(parts) < 2:
        return [normalized]
    out: list[str] = [
        ".".join(parts[index:]) for index in range(min(len(parts) - 1, max_levels))
    ]
    return out


def _default_webfilter_helpers() -> int:
    workers = _env_int("SQUID_WORKERS", 1, minimum=1, maximum=4)
    return max(1, min(256, workers * 2))


def _env_fail_mode(name: str, default: str = "open") -> str:
    value = (os.environ.get(name) or default).strip().lower()
    if value in {"open", "closed"}:
        return value
    return default


def _parse_whitelist_lines(lines: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
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


def _whitelist_match(domain: str, patterns: list[str]) -> str:
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
    TABLE_MAP: ClassVar[dict[str, str]] = {
        "settings": "webfilter_settings",
        "meta": "webfilter_meta",
        "whitelist": "webfilter_whitelist",
    }

    def __init__(
        self,
        squid_include_path: str = "/etc/squid/conf.d/30-webfilter.conf",
        whitelist_path: str = "/var/lib/squid-flask-proxy/webfilter_whitelist.txt",
    ) -> None:
        self.squid_include_path = squid_include_path
        self.whitelist_path = whitelist_path
        self.last_webcat_snapshot_status: tuple[bool, str] = (True, "")
        self._schema_ready = False
        self._schema_lock = threading.Lock()

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
        if self._schema_ready:
            return
        with self._schema_lock:
            if self._schema_ready:
                return
            with self._connect() as conn:
                settings_table = self._table("settings")
                meta_table = self._table("meta")
                whitelist_table = self._table("whitelist")
                conn.execute(
                    f"CREATE TABLE IF NOT EXISTS {settings_table}(proxy_id VARCHAR(64) NOT NULL DEFAULT 'default', k VARCHAR(64) NOT NULL, v LONGTEXT NOT NULL, PRIMARY KEY(proxy_id, k))",
                )
                conn.execute(
                    f"CREATE TABLE IF NOT EXISTS {meta_table}(k VARCHAR(64) PRIMARY KEY, v LONGTEXT NOT NULL)",
                )
                conn.execute(
                    f"CREATE TABLE IF NOT EXISTS {whitelist_table}(proxy_id VARCHAR(64) NOT NULL DEFAULT 'default', pattern VARCHAR(255) NOT NULL, added_ts BIGINT NOT NULL, PRIMARY KEY(proxy_id, pattern), KEY idx_{whitelist_table}_proxy_ts (proxy_id, added_ts))",
                )
                SafeBrowsingStore.init_schema(conn)
                for key, value in _DEFAULTS.items():
                    conn.execute(
                        f"INSERT IGNORE INTO {settings_table}(proxy_id, k, v) VALUES(%s,%s,%s)",
                        (self._settings_scope_for_key(key), key, value),
                    )
                self._init_extra_schema(conn)
                if (
                    self._get(conn, "enabled", "0") != "1"
                    and self._get(conn, "blocked_categories", "")
                    == _LEGACY_DEFAULT_BLOCKED_CATEGORIES_CSV
                ):
                    self._set(conn, "blocked_categories", "")
            self._schema_ready = True

    def _init_extra_schema(self, conn) -> None:
        return None

    def _list_whitelist(self, conn, limit: int) -> list[tuple[str, int]]:
        rows = conn.execute(
            f"SELECT pattern, added_ts FROM {self._table('whitelist')} WHERE proxy_id=%s ORDER BY added_ts DESC, pattern ASC LIMIT %s",
            (get_proxy_id(), int(limit)),
        ).fetchall()
        return [(str(row[0]), int(row[1]) if row[1] is not None else 0) for row in rows]

    def list_whitelist(self, limit: int = 5000) -> list[tuple[str, int]]:
        self.init_db()
        with self._connect() as conn:
            return self._list_whitelist(conn, limit=int(limit))

    def add_whitelist(self, entry: str) -> tuple[bool, str, str]:
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
            conn.execute(
                f"DELETE FROM {self._table('whitelist')} WHERE proxy_id=%s AND pattern=%s",
                (get_proxy_id(), candidate),
            )

    def _get_whitelist_patterns(self, conn) -> list[str]:
        rows = self._list_whitelist(conn, limit=10000)
        patterns = [pattern for pattern, _ts in rows if pattern]
        exact = [pattern for pattern in patterns if not pattern.startswith("*.")]
        wild = [pattern for pattern in patterns if pattern.startswith("*.")]
        exact.sort(key=lambda item: (-len(item), item))
        wild.sort(key=lambda item: (-len(item), item))
        return exact + wild

    def get_whitelist_patterns(self) -> list[str]:
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
            f"INSERT INTO {self._table('settings')}(proxy_id, k, v) VALUES(%s,%s,%s) AS incoming ON DUPLICATE KEY UPDATE v=incoming.v",
            (scope, key, value),
        )

    def _get_global_setting_conn(self, conn, key: str, default: str = "") -> str:
        row = conn.execute(
            f"SELECT v FROM {self._table('settings')} WHERE proxy_id=%s AND k=%s",
            (_GLOBAL_SCOPE, key),
        ).fetchone()
        return str(row[0]) if row and row[0] is not None else default

    def _get_meta(self, conn, key: str, default: str = "") -> str:
        row = conn.execute(
            f"SELECT v FROM {self._table('meta')} WHERE k=%s",
            (key,),
        ).fetchone()
        return str(row[0]) if row and row[0] is not None else default

    def _set_meta(self, conn, key: str, value: str) -> None:
        conn.execute(
            f"INSERT INTO {self._table('meta')}(k,v) VALUES(%s,%s) AS incoming ON DUPLICATE KEY UPDATE v=incoming.v",
            (key, value),
        )

    def _get_settings(self, conn) -> WebFilterSettings:
        settings_table = self._table("settings")
        proxy_scope = get_proxy_id()
        rows = conn.execute(
            f"SELECT proxy_id, k, v FROM {settings_table} WHERE proxy_id IN (%s, %s)",
            (proxy_scope, _GLOBAL_SCOPE),
        ).fetchall()
        scoped_values: dict[str, str] = {}
        global_values: dict[str, str] = {}
        for row in rows:
            key = str(row[1] or "")
            value = str(row[2]) if row[2] is not None else ""
            if str(row[0] or "") == _GLOBAL_SCOPE:
                global_values[key] = value
            else:
                scoped_values[key] = value

        def _value(key: str, default: str = "") -> str:
            if (key or "").strip() in _GLOBAL_SETTINGS_KEYS:
                return global_values.get(key, default)
            return scoped_values.get(key, default)

        enabled = _value("enabled", "0") == "1"
        source_url = _value("source_url", "")
        source_provider = _value("source_provider", "auto") or "auto"
        if source_provider not in {"auto", "ut1", "category-dir", "csv"}:
            source_provider = "auto"
        blocked_raw = _value("blocked_categories", "")
        blocked = [
            item.strip()
            for item in blocked_raw.replace("\n", ",").split(",")
            if item.strip()
        ]
        whitelist = self._get_whitelist_patterns(conn)
        last_success = int(_value("last_success", "0") or 0)
        last_attempt = int(_value("last_attempt", "0") or 0)
        last_error = _value("last_error", "")
        next_run_ts = int(_value("next_run_ts", "0") or 0)
        safe_browsing = SafeBrowsingStore.settings_from_webfilter(
            conn,
            lambda _conn, key, default="": global_values.get(key, default),
        )
        return WebFilterSettings(
            enabled=enabled,
            source_url=source_url,
            source_provider=source_provider,
            blocked_categories=blocked,
            whitelist_domains=whitelist,
            last_success=last_success,
            last_attempt=last_attempt,
            last_error=last_error,
            next_run_ts=next_run_ts,
            safe_browsing_enabled=safe_browsing.enabled,
            safe_browsing_api_key=safe_browsing.api_key,
            safe_browsing_lists=list(safe_browsing.lists),
            safe_browsing_last_success=safe_browsing.last_success,
            safe_browsing_last_attempt=safe_browsing.last_attempt,
            safe_browsing_last_error=safe_browsing.last_error,
            safe_browsing_next_run_ts=safe_browsing.next_run_ts,
        )

    def get_settings(self) -> WebFilterSettings:
        self.init_db()
        with self._connect() as conn:
            return self._get_settings(conn)

    def _resolve_category_aliases(self, categories: list[str]) -> list[str]:
        normalized = [
            item.strip() for item in (categories or []) if (item or "").strip()
        ]
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
            mapping = {
                str(row[0]): str(row[1]) for row in rows if row and row[0] and row[1]
            }
            seen: set[str] = set()
            out: list[str] = []
            for category in [mapping.get(item, item) for item in normalized]:
                if category not in seen:
                    seen.add(category)
                    out.append(category)
            return out
        except Exception:
            return normalized

    def _webcat_built_ts(self) -> int:
        try:
            with self._connect_webcat() as conn:
                if not table_exists(conn, "webcat_meta"):
                    return 0
                row = conn.execute(
                    "SELECT v FROM webcat_meta WHERE k=%s",
                    ("built_ts",),
                ).fetchone()
            return int((row[0] if row else 0) or 0)
        except Exception:
            return 0

    def _webcat_helper_name(
        self,
        *,
        settings: WebFilterSettings,
        categories: list[str],
        exceptions: list[object],
    ) -> str:
        # Squid and the helper both cache category lookups. Version the helper
        # name with the webcat/policy state so a reconfigure starts a fresh helper
        # namespace instead of preserving stale allow decisions after Admin UI
        # category or exception changes.
        digest = hashlib.sha256()
        for value in (
            str(int(bool(settings.enabled))),
            ",".join(categories),
            ",".join(settings.whitelist_domains or []),
            str(self._webcat_built_ts()),
            str(int(bool(settings.safe_browsing_enabled))),
            hashlib.sha256(
                str(settings.safe_browsing_api_key or "").encode(
                    "utf-8",
                    errors="replace",
                ),
            ).hexdigest(),
            ",".join(settings.safe_browsing_lists or []),
            str(settings.safe_browsing_last_success or 0),
        ):
            digest.update(value.encode("utf-8", errors="replace"))
            digest.update(b"\0")
        for ex in sorted(exceptions, key=lambda item: int(getattr(item, "id", 0) or 0)):
            digest.update(
                str(getattr(ex, "id", 0) or 0).encode("ascii", errors="ignore"),
            )
            digest.update(b":")
            digest.update(
                str(getattr(ex, "domain", "") or "")
                .lower()
                .encode("utf-8", errors="replace"),
            )
            digest.update(b":")
            digest.update(
                str(getattr(ex, "client_ip", "") or "").encode(
                    "utf-8",
                    errors="replace",
                ),
            )
            digest.update(b"\0")
        return "webcat_" + digest.hexdigest()[:16]

    def render_materialized_state(self) -> WebFilterMaterializedState:
        settings = self.get_settings()
        helpers = _env_int(
            "WEBFILTER_HELPERS",
            _default_webfilter_helpers(),
            minimum=1,
            maximum=256,
        )
        ttl = _env_int("WEBFILTER_TTL_SECONDS", 0, minimum=0, maximum=86400)
        neg_ttl = _env_int("WEBFILTER_NEGATIVE_TTL_SECONDS", 0, minimum=0, maximum=3600)
        webfilter_fail = _env_fail_mode("WEBFILTER_FAIL")
        safe_browsing_fail = _env_fail_mode("SAFE_BROWSING_FAIL")

        def _safe_acl_name(category: str) -> str:
            out = []
            for ch in (category or "").lower():
                if "a" <= ch <= "z" or "0" <= ch <= "9" or ch == "_":
                    out.append(ch)
                else:
                    out.append("_")
            return "".join(out).strip("_") or "cat"

        whitelist_lines: list[str] = []
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

        selected = self._resolve_category_aliases(
            list(settings.blocked_categories or []),
        )
        safe_browsing_ready = bool(
            settings.safe_browsing_enabled and settings.safe_browsing_api_key,
        )
        if not settings.enabled or (not selected and not safe_browsing_ready):
            return WebFilterMaterializedState(
                include_text="# Autogenerated: web filtering disabled or no categories selected\n",
                whitelist_text=whitelist_text,
            )

        lines: list[str] = []
        exceptions = []
        if get_policy_request_store is not None:
            try:
                exceptions = get_policy_request_store().active_webfilter_exceptions(
                    proxy_id=get_proxy_id(),
                )
            except Exception:
                exceptions = []
        helper_name = self._webcat_helper_name(
            settings=settings,
            categories=selected,
            exceptions=exceptions,
        )

        lines.append(
            "# Autogenerated: web filtering (domain categories + Safe Browsing)",
        )
        if selected:
            lines.append(
                f"external_acl_type {helper_name} children={helpers} ttl={ttl} negative_ttl={neg_ttl} %SRC %DST %URI "
                f"/usr/bin/python3 /app/tools/webcat_acl.py --fail {webfilter_fail}",
            )
        if safe_browsing_ready:
            gsb_helper = helper_name + "_gsb"
            safe_browsing_args = [
                "/usr/bin/python3 /app/tools/safe_browsing_acl.py",
                f"--fail {safe_browsing_fail}",
            ]
            for list_name in settings.safe_browsing_lists or DEFAULT_SAFE_BROWSING_LISTS:
                selected_list = SafeBrowsingStore.selected_lists([str(list_name)])
                if selected_list:
                    safe_browsing_args.append(f"--list {selected_list[0]}")
            lines.append(
                f"external_acl_type {gsb_helper} children={helpers} ttl={ttl} negative_ttl={neg_ttl} %SRC %DST %URI "
                + " ".join(safe_browsing_args),
            )
        if whitelist_lines:
            lines.extend(
                (
                    f'acl webfilter_whitelist dstdomain "{self.whitelist_path}"',
                    "note webfilter_allow whitelist webfilter_whitelist",
                    "http_access allow webfilter_whitelist",
                )
            )

        for ex in exceptions:
            domain = _norm_domain(getattr(ex, "domain", ""))
            client_ip = str(getattr(ex, "client_ip", "") or "").strip()
            if not client_ip or not domain:
                continue
            suffix = f"{getattr(ex, 'id', 0)}"
            lines.append(f"acl webfilter_exception_src_{suffix} src {client_ip}")
            dst_domains = f"{domain} .{domain}" if "." in domain else domain
            lines.extend(
                (
                    f"acl webfilter_exception_dst_{suffix} dstdomain {dst_domains}",
                    f"note webfilter_allow exception_{suffix} webfilter_exception_src_{suffix} webfilter_exception_dst_{suffix}",
                    f"http_access allow webfilter_exception_src_{suffix} webfilter_exception_dst_{suffix}",
                )
            )

        for category in selected:
            safe = _safe_acl_name(category)
            lines.extend(
                (
                    f"acl webfilter_block_{safe} external {helper_name} {category}",
                    f"deny_info ERR_WEBFILTER_BLOCKED webfilter_block_{safe}",
                    f"http_access deny webfilter_block_{safe}",
                )
            )

        if safe_browsing_ready:
            lines.extend(
                (
                    f"acl webfilter_block_google_safe_browsing external {gsb_helper}",
                    "deny_info ERR_WEBFILTER_BLOCKED webfilter_block_google_safe_browsing",
                    "http_access deny webfilter_block_google_safe_browsing",
                )
            )

        return WebFilterMaterializedState(
            include_text="\n".join(lines) + "\n",
            whitelist_text=whitelist_text,
        )

    def _publish_webcat_snapshot_for_helper(self) -> tuple[bool, str]:
        try:
            expected_built_ts = self._webcat_built_ts()
            if expected_built_ts <= 0:
                return True, "No web category snapshot build is available yet."
            from tools.webcat_acl import _Db as WebCatSnapshotDb  # type: ignore

            if WebCatSnapshotDb()._build_snapshot_from_db(
                expected_built_ts=expected_built_ts,
            ):
                return True, "Web category snapshot is current."
            return (
                False,
                "Failed to publish local web category snapshot; helper will use the last usable snapshot if present.",
            )
        except Exception as exc:
            return False, public_error_message(
                exc,
                default="Failed to publish local web category snapshot.",
            )

    def apply_squid_include(self) -> None:
        state = self.render_materialized_state()
        if "webcat_acl.py" in state.include_text:
            snapshot_status = self._publish_webcat_snapshot_for_helper()
        else:
            self.last_webcat_snapshot_status = (
                True,
                "Web category snapshot not needed for current policy.",
            )
            snapshot_status = None
        if snapshot_status is not None:
            self.last_webcat_snapshot_status = snapshot_status
        write_managed_text_files(
            (self.whitelist_path, state.whitelist_text),
            (self.squid_include_path, state.include_text),
        )


class ProxyWebFilterStore(WebFilterStoreBase):
    pass


_store: ProxyWebFilterStore | None = None
_store_lock = threading.Lock()


def get_proxy_webfilter_store() -> ProxyWebFilterStore:
    global _store
    if _store is not None:
        return _store
    with _store_lock:
        if _store is None:
            _store = ProxyWebFilterStore()
        return _store
