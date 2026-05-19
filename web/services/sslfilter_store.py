from __future__ import annotations

import ipaddress
import re
import threading
from dataclasses import dataclass
from typing import Any

from services.db import connect
from services.materialized_files import write_managed_text_files
from services.proxy_context import get_proxy_id
from services.runtime_helpers import now_ts as _now
from services.ssl_compatibility_presets import (
    COMPATIBILITY_PRESETS,
    PRIVATE_NETS_V4,
    CompatibilityPreset,
)

_DOMAIN_LABEL_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")
_DOMAIN_POLICIES = {"nobump", "nocache"}
_SRC_POLICIES = {"nobump", "nocache"}


@dataclass(frozen=True)
class SslFilterRules:
    no_bump_domains: list[str]
    no_cache_domains: list[str]
    no_bump_src_nets: list[str]
    no_cache_src_nets: list[str]
    exclude_private_nets: bool


@dataclass(frozen=True)
class SslFilterSettings:
    # Backward-compatible shape for older callers/tests; new code should use SslFilterRules.
    nobump_cidrs: list[tuple[str, int]]


@dataclass(frozen=True)
class SslFilterMaterializedState:
    include_text: str
    nobump_src_list_text: str
    nocache_src_list_text: str

    @property
    def list_text(self) -> str:
        return self.nobump_src_list_text


def _canonical_policy(policy: str) -> str:
    value = (policy or "").strip().lower().replace("-", "_")
    if value in {"no_bump", "nobump", "splice"}:
        return "nobump"
    if value in {"no_cache", "nocache", "cache"}:
        return "nocache"
    return value


def _normalize_domain_rule(domain: str) -> tuple[bool, str, str]:
    raw = (domain or "").strip().lower()
    if not raw:
        return False, "Domain is required.", ""
    if raw.startswith("http://") or raw.startswith("https://"):
        # Keep this helper deliberately small; app-level callers usually pass extracted domains.
        raw = raw.split("//", 1)[1].split("/", 1)[0].split(":", 1)[0]
    if raw.startswith("*."):
        core = raw[2:]
        is_wildcard = True
    elif raw.startswith("."):
        core = raw[1:]
        is_wildcard = True
    else:
        core = raw
        is_wildcard = False
    if not core or len(core) > 253:
        return False, "Invalid domain length.", ""
    if any(ch in core for ch in (" ", "/", "\n", "\r")):
        return False, "Invalid domain characters.", ""
    labels = core.split(".")
    if not labels or any(not label for label in labels):
        return False, "Invalid domain format.", ""
    for label in labels:
        if not _DOMAIN_LABEL_RE.match(label):
            return False, f"Invalid domain label: {label}", ""
    return True, "", (f"*.{core}" if is_wildcard else core)


def _normalize_domain_for_squid(domain: str) -> str:
    value = (domain or "").strip().lower()
    if value.startswith("*."):
        return "." + value[2:].lstrip(".")
    if value.startswith("."):
        return "." + value.lstrip(".")
    return value.lstrip(".")


def _dedupe_squid_domains(values: list[str]) -> list[str]:
    raw = [
        normalized
        for value in values
        if (normalized := _normalize_domain_for_squid(str(value)))
    ]
    wildcard_domains = {value[1:] for value in raw if value.startswith(".")}
    out: list[str] = []
    seen: set[str] = set()
    for value in raw:
        # Squid dstdomain/ssl::server_name treats .example.com as covering both
        # example.com and subdomains, so avoid warning-producing duplicates.
        if value in wildcard_domains:
            continue
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


class SslFilterStore:
    def __init__(
        self,
        squid_include_path: str = "/etc/squid/conf.d/10-sslfilter.conf",
        nobump_list_path: str = "/var/lib/squid-flask-proxy/sslfilter_nobump.txt",
        nocache_src_list_path: str = "/var/lib/squid-flask-proxy/sslfilter_nocache_src.txt",
    ):
        self.squid_include_path = squid_include_path
        self.nobump_list_path = nobump_list_path
        self.nocache_src_list_path = nocache_src_list_path

    def _connect(self):
        return connect()

    def init_db(self) -> None:
        with self._connect() as conn:
            # New consolidated model. Old pre-consolidation policy tables are intentionally ignored.
            conn.execute(
                "CREATE TABLE IF NOT EXISTS sslfilter_domains("
                "proxy_id VARCHAR(64) NOT NULL DEFAULT 'default', "
                "policy VARCHAR(16) NOT NULL, "
                "domain VARCHAR(255) NOT NULL, "
                "added_ts BIGINT NOT NULL, "
                "PRIMARY KEY(proxy_id, policy, domain), "
                "KEY idx_sslfilter_domains_proxy_policy_ts (proxy_id, policy, added_ts)"
                ")",
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS sslfilter_src_nets("
                "proxy_id VARCHAR(64) NOT NULL DEFAULT 'default', "
                "policy VARCHAR(16) NOT NULL, "
                "cidr VARCHAR(64) NOT NULL, "
                "added_ts BIGINT NOT NULL, "
                "PRIMARY KEY(proxy_id, policy, cidr), "
                "KEY idx_sslfilter_src_nets_proxy_policy_ts (proxy_id, policy, added_ts)"
                ")",
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS sslfilter_settings("
                "proxy_id VARCHAR(64) NOT NULL DEFAULT 'default', "
                "`key` VARCHAR(64) NOT NULL, "
                "value TEXT NOT NULL, "
                "PRIMARY KEY(proxy_id, `key`)"
                ")",
            )

    def _set_setting(self, key: str, value: str) -> None:
        self.init_db()
        proxy_id = get_proxy_id()
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO sslfilter_settings(proxy_id, `key`, value) VALUES(%s,%s,%s) "
                "ON DUPLICATE KEY UPDATE value=VALUES(value)",
                (proxy_id, key, value),
            )

    def _get_setting_conn(self, conn: Any, key: str) -> str | None:
        row = conn.execute(
            "SELECT value FROM sslfilter_settings WHERE proxy_id=%s AND `key`=%s",
            (get_proxy_id(), key),
        ).fetchone()
        return str(row[0]) if row else None

    def set_exclude_private_nets(self, enabled: bool) -> None:
        self._set_setting("exclude_private_nets", "1" if enabled else "0")

    def get_exclude_private_nets(self) -> bool:
        self.init_db()
        with self._connect() as conn:
            v = self._get_setting_conn(conn, "exclude_private_nets")
        return True if v is None else (v == "1")

    def add_domain(
        self, policy: str, domain: str | None = None,
    ) -> tuple[bool, str, str]:
        # Backward-compatible two-arg behavior: add_domain(domain) means no-bump domain.
        if domain is None:
            domain = policy
            policy = "nobump"
        policy_key = _canonical_policy(policy)
        if policy_key not in _DOMAIN_POLICIES:
            return False, "Invalid domain policy.", ""
        ok, err, canonical = _normalize_domain_rule(domain or "")
        if not ok:
            return False, err, canonical
        self.init_db()
        proxy_id = get_proxy_id()
        with self._connect() as conn:
            conn.execute(
                "INSERT IGNORE INTO sslfilter_domains(proxy_id, policy, domain, added_ts) VALUES(%s,%s,%s,%s)",
                (proxy_id, policy_key, canonical, int(_now())),
            )
        return True, "", canonical

    def remove_domain(self, policy: str, domain: str | None = None) -> None:
        if domain is None:
            domain = policy
            policy = "nobump"
        policy_key = _canonical_policy(policy)
        if policy_key not in _DOMAIN_POLICIES:
            return
        raw = (domain or "").strip().lower()
        candidates = {raw, raw.lstrip(".")}
        if raw.startswith("*."):
            candidates.add(raw[2:].lstrip("."))
        elif raw.startswith("."):
            candidates.add(f"*.{raw.lstrip('.')}")
        elif raw:
            candidates.add(f"*.{raw}")
        values = [value for value in candidates if value]
        if not values:
            return
        self.init_db()
        proxy_id = get_proxy_id()
        placeholders = ",".join(["%s"] * len(values))
        with self._connect() as conn:
            conn.execute(
                f"DELETE FROM sslfilter_domains WHERE proxy_id=%s AND policy=%s AND domain IN ({placeholders})",
                (proxy_id, policy_key, *values),
            )

    def add_src_net(self, policy: str, cidr: str) -> tuple[bool, str, str]:
        policy_key = _canonical_policy(policy)
        if policy_key not in _SRC_POLICIES:
            return False, "Invalid CIDR policy.", ""
        raw = (cidr or "").strip()
        if not raw:
            return False, "CIDR is required.", ""
        try:
            if "/" in raw:
                net = ipaddress.ip_network(raw, strict=False)
            else:
                ip = ipaddress.ip_address(raw)
                net = ipaddress.ip_network(
                    f"{ip}/{32 if ip.version == 4 else 128}", strict=False,
                )
        except Exception:
            return False, "Invalid CIDR/IP. Example: 10.0.0.0/8", ""
        canonical = net.with_prefixlen
        self.init_db()
        proxy_id = get_proxy_id()
        with self._connect() as conn:
            conn.execute(
                "INSERT IGNORE INTO sslfilter_src_nets(proxy_id, policy, cidr, added_ts) VALUES(%s,%s,%s,%s)",
                (proxy_id, policy_key, canonical, int(_now())),
            )
        return True, "", canonical

    def remove_src_net(self, policy: str, cidr: str) -> None:
        policy_key = _canonical_policy(policy)
        if policy_key not in _SRC_POLICIES:
            return
        canonical = (cidr or "").strip()
        if not canonical:
            return
        self.init_db()
        proxy_id = get_proxy_id()
        with self._connect() as conn:
            conn.execute(
                "DELETE FROM sslfilter_src_nets WHERE proxy_id=%s AND policy=%s AND cidr=%s",
                (proxy_id, policy_key, canonical),
            )

    # Backward-compatible helpers for older tests/callers.
    def list_nobump(self, limit: int = 5000) -> list[tuple[str, int]]:
        self.init_db()
        proxy_id = get_proxy_id()
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT cidr, added_ts FROM sslfilter_src_nets WHERE proxy_id=%s AND policy='nobump' ORDER BY added_ts DESC, cidr ASC LIMIT %s",
                (proxy_id, int(limit)),
            ).fetchall()
        return [(str(r[0]), int(r[1]) if r[1] is not None else 0) for r in rows]

    def add_nobump(self, entry: str) -> tuple[bool, str, str]:
        return self.add_src_net("nobump", entry)

    def remove_nobump(self, cidr: str) -> None:
        self.remove_src_net("nobump", cidr)

    def add_net(self, table: str, cidr: str) -> tuple[bool, str]:
        policy = (
            "nobump"
            if table in {"src_nets", "nobump_src_nets"}
            else "nocache"
            if table == "nocache_src_nets"
            else ""
        )
        ok, err, _canonical = self.add_src_net(policy, cidr)
        return ok, err

    def remove_net(self, table: str, cidr: str) -> None:
        policy = (
            "nobump"
            if table in {"src_nets", "nobump_src_nets"}
            else "nocache"
            if table == "nocache_src_nets"
            else ""
        )
        self.remove_src_net(policy, cidr)

    def _list_domains_conn(self, conn: Any, policy: str) -> list[str]:
        rows = conn.execute(
            "SELECT domain FROM sslfilter_domains WHERE proxy_id=%s AND policy=%s ORDER BY domain ASC",
            (get_proxy_id(), policy),
        ).fetchall()
        return [str(r[0]) for r in rows]

    def _list_src_conn(self, conn: Any, policy: str) -> list[str]:
        rows = conn.execute(
            "SELECT cidr FROM sslfilter_src_nets WHERE proxy_id=%s AND policy=%s ORDER BY cidr ASC",
            (get_proxy_id(), policy),
        ).fetchall()
        return [str(r[0]) for r in rows]

    def list_all(self) -> SslFilterRules:
        self.init_db()
        with self._connect() as conn:
            v = self._get_setting_conn(conn, "exclude_private_nets")
            return SslFilterRules(
                no_bump_domains=self._list_domains_conn(conn, "nobump"),
                no_cache_domains=self._list_domains_conn(conn, "nocache"),
                no_bump_src_nets=self._list_src_conn(conn, "nobump"),
                no_cache_src_nets=self._list_src_conn(conn, "nocache"),
                exclude_private_nets=True if v is None else (v == "1"),
            )

    @property
    def private_dst_nets(self) -> list[str]:
        return list(PRIVATE_NETS_V4)

    def list_compatibility_presets(self) -> list[dict[str, Any]]:
        current = set(self.list_all().no_bump_domains)
        presets: list[dict[str, Any]] = []
        for preset in COMPATIBILITY_PRESETS:
            installed = [domain for domain in preset.domains if domain in current]
            missing = [domain for domain in preset.domains if domain not in current]
            presets.append(
                {
                    "id": preset.id,
                    "title": preset.title,
                    "description": preset.description,
                    "domains": list(preset.domains),
                    "installed": len(installed),
                    "missing": len(missing),
                    "total": len(preset.domains),
                    "complete": len(missing) == 0,
                },
            )
        return presets

    def install_compatibility_preset(self, preset_id: str) -> tuple[int, int, str]:
        wanted = (preset_id or "").strip().lower()
        presets: list[CompatibilityPreset] = (
            list(COMPATIBILITY_PRESETS)
            if wanted in ("all", "*")
            else [p for p in COMPATIBILITY_PRESETS if p.id == wanted]
        )
        if not presets:
            return 0, 0, "Unknown compatibility preset."
        before = set(self.list_all().no_bump_domains)
        attempted = 0
        errors: list[str] = []
        for preset in presets:
            for domain in preset.domains:
                attempted += 1
                ok, err, _canonical = self.add_domain("nobump", domain)
                if not ok and err:
                    errors.append(f"{domain}: {err}")
        after = set(self.list_all().no_bump_domains)
        return len(after - before), attempted, "; ".join(errors[:3])

    def render_materialized_state(self) -> SslFilterMaterializedState:
        rules = self.list_all()
        nobump_src = [c for c in rules.no_bump_src_nets if c]
        nocache_src = [c for c in rules.no_cache_src_nets if c]
        nobump_src_text = ("\n".join(nobump_src) + "\n") if nobump_src else ""
        nocache_src_text = ("\n".join(nocache_src) + "\n") if nocache_src else ""

        nobump_domains = _dedupe_squid_domains(rules.no_bump_domains)
        nocache_domains = _dedupe_squid_domains(rules.no_cache_domains)

        lines: list[str] = ["# Autogenerated: SSL filtering policy"]
        if nobump_domains:
            lines.append(
                "acl sslfilter_nobump_domains ssl::server_name "
                + " ".join(nobump_domains),
            )
            lines.append(
                "note ssl_exception sslfilter_nobump_domain sslfilter_nobump_domains",
            )
            lines.append("ssl_bump splice sslfilter_nobump_domains")
        if nobump_src:
            lines.append(f'acl sslfilter_nobump_src src "{self.nobump_list_path}"')
            lines.append("note ssl_exception sslfilter_nobump_src sslfilter_nobump_src")
            lines.append("ssl_bump splice sslfilter_nobump_src")
        if nocache_domains:
            lines.append(
                "acl sslfilter_nocache_domains dstdomain " + " ".join(nocache_domains),
            )
            lines.append(
                "note cache_bypass sslfilter_nocache_domain sslfilter_nocache_domains",
            )
            lines.append("cache deny sslfilter_nocache_domains")
        if nocache_src:
            lines.append(
                f'acl sslfilter_nocache_src src "{self.nocache_src_list_path}"',
            )
            lines.append(
                "note cache_bypass sslfilter_nocache_src sslfilter_nocache_src",
            )
            lines.append("cache deny sslfilter_nocache_src")
        if len(lines) == 1:
            lines.append("# none configured")
        include_text = "\n".join(lines) + "\n"
        return SslFilterMaterializedState(
            include_text=include_text,
            nobump_src_list_text=nobump_src_text,
            nocache_src_list_text=nocache_src_text,
        )

    def apply_squid_include(self) -> None:
        state = self.render_materialized_state()
        write_managed_text_files(
            (self.nobump_list_path, state.nobump_src_list_text),
            (self.nocache_src_list_path, state.nocache_src_list_text),
            (self.squid_include_path, state.include_text),
        )


_store: SslFilterStore | None = None
_store_lock = threading.Lock()


def get_sslfilter_store() -> SslFilterStore:
    global _store
    if _store is not None:
        return _store
    with _store_lock:
        if _store is None:
            _store = SslFilterStore()
        return _store
