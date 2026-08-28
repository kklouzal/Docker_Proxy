from __future__ import annotations

import ipaddress
import re
import threading
from dataclasses import dataclass
from typing import Any

from services.db import connect
from services.domain_normalization import normalize_domain as _shared_normalize_domain
from services.materialized_files import write_managed_text_files
from services.pac_private_local import pac_private_local_destination_values
from services.proxy_context import get_proxy_id
from services.proxy_write_guard import guarded_proxy_write
from services.runtime_helpers import now_ts as _now
from services.ssl_compatibility_presets import (
    COMPATIBILITY_PRESETS,
    CompatibilityPreset,
)

_DOMAIN_LABEL_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")
_DOMAIN_POLICIES = {"nobump", "nocache"}
_SRC_POLICIES = {"nobump", "nocache"}
_IP_LITERAL_DOMAIN_RULE_ERROR = (
    "IP literals are not valid domain rules; use CIDR/source policy where appropriate."
)


@dataclass(frozen=True)
class SslFilterRules:
    no_bump_domains: list[str]
    no_cache_domains: list[str]
    no_bump_src_nets: list[str]
    no_cache_src_nets: list[str]
    exclude_private_nets: bool
    inspection_enabled: bool


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


@dataclass(frozen=True)
class _EffectivePresetDomains:
    domains: list[str]
    invalid: list[tuple[str, str]]


def _canonical_policy(policy: str) -> str:
    value = (policy or "").strip().lower().replace("-", "_")
    if value in {"no_bump", "nobump", "splice"}:
        return "nobump"
    if value in {"no_cache", "nocache", "cache"}:
        return "nocache"
    return value


def _normalize_domain_rule(domain: str) -> tuple[bool, str, str]:
    raw = (domain or "").strip()
    if not raw:
        return False, "Domain is required.", ""
    lowered = raw.lower()
    is_url = lowered.startswith(("http://", "https://"))
    if not is_url and any(ch in raw for ch in ("/", "?", "#", "\n", "\r")):
        return False, "Invalid domain characters.", ""
    if lowered.startswith("*."):
        core = raw[2:]
        is_wildcard = True
    elif lowered.startswith("."):
        core = raw[1:]
        is_wildcard = True
    else:
        core = raw
        is_wildcard = False
    core = _shared_normalize_domain(core)
    try:
        ipaddress.ip_address(core)
    except ValueError:
        pass
    else:
        return False, _IP_LITERAL_DOMAIN_RULE_ERROR, ""
    if not core or len(core) > 253:
        return False, "Invalid domain length.", ""
    labels = core.split(".")
    if not labels or any(not label for label in labels):
        return False, "Invalid domain format.", ""
    for label in labels:
        if not _DOMAIN_LABEL_RE.match(label):
            return False, f"Invalid domain label: {label}", ""
    return True, "", (f"*.{core}" if is_wildcard else core)


def validate_domain_rule(domain: str) -> tuple[bool, str, str]:
    return _normalize_domain_rule(domain)


def normalize_src_net_rule(cidr: str) -> tuple[bool, str, str]:
    raw = (cidr or "").strip()
    if not raw:
        return False, "CIDR is required.", ""
    try:
        if "/" in raw:
            net = ipaddress.ip_network(raw, strict=False)
        else:
            ip = ipaddress.ip_address(raw)
            net = ipaddress.ip_network(
                f"{ip}/{32 if ip.version == 4 else 128}",
                strict=False,
            )
    except Exception:
        return False, "Invalid CIDR/IP. Example: 10.0.0.0/8", ""
    return True, "", net.with_prefixlen


def _normalize_domain_for_squid(domain: str) -> str:
    value = (domain or "").strip()
    lowered = value.lower()
    if lowered.startswith("*."):
        normalized = _shared_normalize_domain(value[2:])
        return f".{normalized}" if normalized else ""
    if lowered.startswith("."):
        normalized = _shared_normalize_domain(value[1:])
        return f".{normalized}" if normalized else ""
    return _shared_normalize_domain(value)


def _dedupe_squid_domains(values: list[str]) -> list[str]:
    raw = [
        normalized
        for value in values
        if (normalized := _normalize_domain_for_squid(str(value)))
    ]
    wildcards = [value for value in raw if value.startswith(".")]
    out: list[str] = []
    seen: set[str] = set()
    for value in raw:
        # Squid dstdomain/ssl::server_name treats .example.com as covering both
        # example.com and subdomains, so avoid warning-producing duplicates.
        if _squid_domain_is_covered_by_other_wildcard(value, wildcards):
            continue
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _domain_rule_from_squid_domain(value: str) -> str:
    normalized = (value or "").strip().lower()
    if normalized.startswith("."):
        return f"*.{normalized[1:]}" if normalized[1:] else ""
    return normalized


def _effective_preset_domains(preset: CompatibilityPreset) -> _EffectivePresetDomains:
    canonical_domains: list[str] = []
    invalid: list[tuple[str, str]] = []
    for domain in preset.domains:
        ok, err, canonical = _normalize_domain_rule(domain)
        if ok and canonical:
            canonical_domains.append(canonical)
        else:
            invalid.append((domain, err or "Invalid domain."))
    effective_domains = [
        rule
        for squid_domain in _dedupe_squid_domains(canonical_domains)
        if (rule := _domain_rule_from_squid_domain(squid_domain))
    ]
    if not effective_domains and not invalid:
        invalid.append(("", "Preset has no effective domains."))
    return _EffectivePresetDomains(domains=effective_domains, invalid=invalid)


def _effective_shared_infrastructure_domains(
    preset: CompatibilityPreset,
) -> _EffectivePresetDomains:
    shared = CompatibilityPreset(
        id=preset.id,
        title=preset.title,
        description=preset.description,
        domains=preset.shared_infrastructure_domains,
    )
    effective = _effective_preset_domains(shared)
    if not preset.shared_infrastructure_domains:
        return _EffectivePresetDomains(domains=[], invalid=[])
    catalog_domains = set(_effective_preset_domains(preset).domains)
    invalid = list(effective.invalid)
    invalid.extend(
        (domain, "Shared-infrastructure rule is not an effective preset domain.")
        for domain in effective.domains
        if domain not in catalog_domains
    )
    return _EffectivePresetDomains(
        domains=[domain for domain in effective.domains if domain in catalog_domains],
        invalid=invalid,
    )


def _squid_domain_is_covered_by_wildcard(value: str, wildcard: str) -> bool:
    if not value or not wildcard.startswith("."):
        return False
    core = wildcard[1:]
    target = value.removeprefix(".")
    return target == core or target.endswith(f".{core}")


def _squid_domain_is_covered_by_other_wildcard(
    value: str,
    wildcards: list[str],
) -> bool:
    for wildcard in wildcards:
        if wildcard == value:
            continue
        if _squid_domain_is_covered_by_wildcard(value, wildcard):
            return True
    return False


def _squid_domain_is_effectively_configured(
    domain: str,
    configured: list[str],
) -> bool:
    normalized = _normalize_domain_for_squid(domain)
    if not normalized:
        return False
    for configured_value in configured:
        value = _normalize_domain_for_squid(configured_value)
        if value == normalized:
            return True
        if _squid_domain_is_covered_by_wildcard(normalized, value):
            return True
    return False


def domain_rule_is_effectively_configured(
    domain: str,
    configured: list[str],
) -> bool:
    """Return whether an exact or parent-wildcard rule covers ``domain``."""
    return _squid_domain_is_effectively_configured(domain, configured)


class SslFilterStore:
    def __init__(
        self,
        squid_include_path: str = "/etc/squid/conf.d/10-sslfilter.conf",
        nobump_list_path: str = "/var/lib/squid-flask-proxy/sslfilter_nobump.txt",
        nocache_src_list_path: str = "/var/lib/squid-flask-proxy/sslfilter_nocache_src.txt",
    ) -> None:
        self.squid_include_path = squid_include_path
        self.nobump_list_path = nobump_list_path
        self.nocache_src_list_path = nocache_src_list_path
        self._schema_ready = False
        self._schema_lock = threading.Lock()

    def _connect(self):
        return connect()

    def init_db(self) -> None:
        if self._schema_ready:
            return
        with self._schema_lock:
            if self._schema_ready:
                return
            with self._connect() as conn:
                from services.schema_lifecycle import (
                    runtime_schema_ready_for_lazy_store,
                )

                if runtime_schema_ready_for_lazy_store(conn):
                    self._schema_ready = True
                    return
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
            self._schema_ready = True

    def _set_setting(self, key: str, value: str) -> None:
        self.init_db()
        with self._connect() as conn:
            with guarded_proxy_write(conn, get_proxy_id()) as guard:
                conn.execute(
                    "INSERT INTO sslfilter_settings(proxy_id, `key`, value) VALUES(%s,%s,%s) AS incoming "
                    "ON DUPLICATE KEY UPDATE value=incoming.value",
                    (guard.proxy_id, key, value),
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

    def set_inspection_enabled(self, enabled: bool) -> None:
        self._set_setting("inspection_enabled", "1" if enabled else "0")

    def get_inspection_enabled(self) -> bool:
        self.init_db()
        with self._connect() as conn:
            v = self._get_setting_conn(conn, "inspection_enabled")
        return False if v is None else (v == "1")

    def add_domain(
        self,
        policy: str,
        domain: str | None = None,
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
        with self._connect() as conn:
            with guarded_proxy_write(conn, get_proxy_id()) as guard:
                conn.execute(
                    "INSERT IGNORE INTO sslfilter_domains(proxy_id, policy, domain, added_ts) VALUES(%s,%s,%s,%s)",
                    (guard.proxy_id, policy_key, canonical, int(_now())),
                )
        return True, "", canonical

    def add_domain_if_uncovered(
        self,
        policy: str,
        domain: str,
    ) -> tuple[bool, str, str, bool]:
        """Add a rule only when it changes effective policy coverage."""
        policy_key = _canonical_policy(policy)
        if policy_key not in _DOMAIN_POLICIES:
            return False, "Invalid domain policy.", "", False
        ok, err, canonical = _normalize_domain_rule(domain or "")
        if not ok:
            return False, err, canonical, False
        self.init_db()
        with self._connect() as conn:
            with guarded_proxy_write(conn, get_proxy_id()) as guard:
                configured = self._list_domains_conn(conn, policy_key)
                if domain_rule_is_effectively_configured(canonical, configured):
                    return (
                        True,
                        "Domain is already effectively covered.",
                        canonical,
                        False,
                    )
                cursor = conn.execute(
                    "INSERT IGNORE INTO sslfilter_domains(proxy_id, policy, domain, added_ts) VALUES(%s,%s,%s,%s)",
                    (guard.proxy_id, policy_key, canonical, int(_now())),
                )
                changed = bool(getattr(cursor, "rowcount", 0))
        detail = "" if changed else "Domain is already configured."
        return True, detail, canonical, changed

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
        ok, _err, canonical = _normalize_domain_rule(domain or "")
        if ok and canonical:
            candidates.add(canonical)
            if canonical.startswith("*."):
                candidates.add(canonical[2:].lstrip("."))
            else:
                candidates.add(f"*.{canonical}")
        values = [value for value in candidates if value]
        if not values:
            return
        self.init_db()
        placeholders = ",".join(["%s"] * len(values))
        with self._connect() as conn:
            with guarded_proxy_write(conn, get_proxy_id()) as guard:
                conn.execute(
                    f"DELETE FROM sslfilter_domains WHERE proxy_id=%s AND policy=%s AND domain IN ({placeholders})",
                    (guard.proxy_id, policy_key, *values),
                )

    def add_src_net(self, policy: str, cidr: str) -> tuple[bool, str, str]:
        policy_key = _canonical_policy(policy)
        if policy_key not in _SRC_POLICIES:
            return False, "Invalid CIDR policy.", ""
        ok, err, canonical = normalize_src_net_rule(cidr)
        if not ok:
            return False, err, canonical
        self.init_db()
        with self._connect() as conn:
            with guarded_proxy_write(conn, get_proxy_id()) as guard:
                conn.execute(
                    "INSERT IGNORE INTO sslfilter_src_nets(proxy_id, policy, cidr, added_ts) VALUES(%s,%s,%s,%s)",
                    (guard.proxy_id, policy_key, canonical, int(_now())),
                )
        return True, "", canonical

    def remove_src_net(self, policy: str, cidr: str) -> None:
        policy_key = _canonical_policy(policy)
        if policy_key not in _SRC_POLICIES:
            return
        raw = (cidr or "").strip()
        if not raw:
            return
        candidates = {raw}
        try:
            if "/" in raw:
                net = ipaddress.ip_network(raw, strict=False)
            else:
                ip = ipaddress.ip_address(raw)
                net = ipaddress.ip_network(
                    f"{ip}/{32 if ip.version == 4 else 128}",
                    strict=False,
                )
            candidates.add(net.with_prefixlen)
        except Exception:
            pass
        self.init_db()
        values = [value for value in candidates if value]
        placeholders = ",".join(["%s"] * len(values))
        with self._connect() as conn:
            with guarded_proxy_write(conn, get_proxy_id()) as guard:
                conn.execute(
                    "DELETE FROM sslfilter_src_nets "
                    f"WHERE proxy_id=%s AND policy=%s AND cidr IN ({placeholders})",
                    (guard.proxy_id, policy_key, *values),
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
            exclude_private_nets = self._get_setting_conn(conn, "exclude_private_nets")
            inspection_enabled = self._get_setting_conn(conn, "inspection_enabled")
            return SslFilterRules(
                no_bump_domains=self._list_domains_conn(conn, "nobump"),
                no_cache_domains=self._list_domains_conn(conn, "nocache"),
                no_bump_src_nets=self._list_src_conn(conn, "nobump"),
                no_cache_src_nets=self._list_src_conn(conn, "nocache"),
                exclude_private_nets=(
                    True
                    if exclude_private_nets is None
                    else (exclude_private_nets == "1")
                ),
                inspection_enabled=(
                    False if inspection_enabled is None else (inspection_enabled == "1")
                ),
            )

    @property
    def private_dst_nets(self) -> list[str]:
        return pac_private_local_destination_values()

    def list_compatibility_presets(self) -> list[dict[str, Any]]:
        current = _dedupe_squid_domains(self.list_all().no_bump_domains)
        presets: list[dict[str, Any]] = []
        for preset in COMPATIBILITY_PRESETS:
            effective = _effective_preset_domains(preset)
            shared = _effective_shared_infrastructure_domains(preset)
            installed = [
                domain
                for domain in effective.domains
                if _squid_domain_is_effectively_configured(domain, current)
            ]
            missing = [
                domain
                for domain in effective.domains
                if not _squid_domain_is_effectively_configured(domain, current)
            ]
            presets.append(
                {
                    "id": preset.id,
                    "title": preset.title,
                    "description": preset.description,
                    "domains": list(preset.domains),
                    "effective_domains": list(effective.domains),
                    "catalog_errors": [
                        {"domain": domain, "error": err}
                        for domain, err in effective.invalid
                    ],
                    "shared_infrastructure_domains": list(shared.domains),
                    "shared_infrastructure_total": len(shared.domains),
                    "installed": len(installed),
                    "missing": len(missing),
                    "total": len(effective.domains),
                    "complete": len(missing) == 0 and not effective.invalid,
                },
            )
        return presets

    def install_compatibility_preset(
        self,
        preset_id: str,
        allow_shared_infrastructure: bool = False,
    ) -> tuple[int, int, str]:
        wanted = (preset_id or "").strip().lower()
        presets: list[CompatibilityPreset] = (
            list(COMPATIBILITY_PRESETS)
            if wanted in {"all", "*"}
            else [p for p in COMPATIBILITY_PRESETS if p.id == wanted]
        )
        if not presets:
            return 0, 0, "Unknown compatibility preset."
        evaluated = [(preset, _effective_preset_domains(preset)) for preset in presets]
        shared_evaluated = [
            (preset, _effective_shared_infrastructure_domains(preset))
            for preset in presets
        ]
        catalog_errors = [
            f"{preset.id}: {domain or 'catalog'}: {err}"
            for preset, effective in evaluated
            for domain, err in effective.invalid
        ]
        if catalog_errors:
            return 0, 0, "; ".join(catalog_errors[:3])
        shared_errors = [
            f"{preset.id}: {domain or 'catalog'}: {err}"
            for preset, effective in shared_evaluated
            for domain, err in effective.invalid
        ]
        if shared_errors:
            return 0, 0, "; ".join(shared_errors[:3])
        guarded = [
            domain
            for _preset, effective in shared_evaluated
            for domain in effective.domains
        ]
        if guarded and not allow_shared_infrastructure:
            return (
                0,
                0,
                (
                    "This preset includes shared CDN/cloud namespaces that may exempt "
                    "unrelated tenants; explicitly acknowledge shared infrastructure "
                    "before installing."
                ),
            )

        self.init_db()
        with self._connect() as conn:
            with guarded_proxy_write(conn, get_proxy_id()) as guard:
                rows = conn.execute(
                    "SELECT domain FROM sslfilter_domains WHERE proxy_id=%s AND policy=%s ORDER BY domain ASC",
                    (guard.proxy_id, "nobump"),
                ).fetchall()
                current = _dedupe_squid_domains([str(row[0]) for row in rows])
                missing: list[str] = []
                for _preset, effective in evaluated:
                    for domain in effective.domains:
                        if _squid_domain_is_effectively_configured(domain, current):
                            continue
                        missing.append(domain)
                        squid_domain = _normalize_domain_for_squid(domain)
                        if squid_domain:
                            current = _dedupe_squid_domains([*current, squid_domain])

                added = 0
                for domain in missing:
                    result = conn.execute(
                        "INSERT IGNORE INTO sslfilter_domains(proxy_id, policy, domain, added_ts) VALUES(%s,%s,%s,%s)",
                        (guard.proxy_id, "nobump", domain, int(_now())),
                    )
                    added += max(0, int(result.rowcount))
        return added, len(missing), ""

    def render_materialized_state(self) -> SslFilterMaterializedState:
        rules = self.list_all()
        nobump_src = [c for c in rules.no_bump_src_nets if c]
        nocache_src = [c for c in rules.no_cache_src_nets if c]
        nobump_src_text = ("\n".join(nobump_src) + "\n") if nobump_src else ""
        nocache_src_text = ("\n".join(nocache_src) + "\n") if nocache_src else ""

        nobump_domains = _dedupe_squid_domains(rules.no_bump_domains)
        nocache_domains = _dedupe_squid_domains(rules.no_cache_domains)

        lines: list[str] = ["# Autogenerated: SSL filtering policy"]
        if not rules.inspection_enabled:
            lines.extend(
                (
                    "# SSL inspection disabled from Admin UI; tunnel all TLS traffic.",
                    "ssl_bump splice all",
                )
            )
        elif nobump_domains:
            lines.extend(
                (
                    "acl sslfilter_nobump_domains ssl::server_name "
                    + " ".join(nobump_domains),
                    "note ssl_exception sslfilter_nobump_domain sslfilter_nobump_domains",
                    "ssl_bump splice sslfilter_nobump_domains",
                )
            )
        if rules.inspection_enabled and nobump_src:
            lines.extend(
                (
                    f'acl sslfilter_nobump_src src "{self.nobump_list_path}"',
                    "note ssl_exception sslfilter_nobump_src sslfilter_nobump_src",
                    "ssl_bump splice sslfilter_nobump_src",
                )
            )
        if nocache_domains:
            lines.extend(
                (
                    "acl sslfilter_nocache_domains dstdomain "
                    + " ".join(nocache_domains),
                    "note cache_bypass sslfilter_nocache_domain sslfilter_nocache_domains",
                    "cache deny sslfilter_nocache_domains",
                )
            )
        if nocache_src:
            lines.extend(
                (
                    f'acl sslfilter_nocache_src src "{self.nocache_src_list_path}"',
                    "note cache_bypass sslfilter_nocache_src sslfilter_nocache_src",
                    "cache deny sslfilter_nocache_src",
                )
            )
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
