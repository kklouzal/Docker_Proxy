from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field
from ipaddress import ip_network
from typing import List, Optional, Tuple

from services.db import connect
from services.proxy_context import get_proxy_id
from services.runtime_helpers import now_ts as _now


# Domain validation pattern: allows labels with alphanumeric and hyphens,
# must start/end with alphanumeric, max 63 chars per label, max 253 chars total.
# Also allows wildcard prefix (*.example.com) for subdomain matching.
_DOMAIN_LABEL_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")

PRIVATE_NETS_V4 = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
]


@dataclass(frozen=True)
class Exclusions:
    domains: List[str]
    dst_nets: List[str]
    src_nets: List[str]
    exclude_private_nets: bool
    manual_domains: List[str] = field(default_factory=list)
    auto_domains: List["AutoDomainExclusion"] = field(default_factory=list)


@dataclass(frozen=True)
class AutoDomainExclusion:
    domain: str
    added_ts: int
    expires_ts: int
    last_seen: int
    score: int
    evidence: str


@dataclass(frozen=True)
class DomainExclusionPreset:
    key: str
    name: str
    description: str
    domains: Tuple[str, ...]


_DOMAIN_EXCLUSION_PRESETS: Tuple[DomainExclusionPreset, ...] = (
    DomainExclusionPreset(
        key="microsoft_update_store",
        name="Microsoft Windows Update + Store",
        description=(
            "Curated baseline for Windows Update, Delivery Optimization, and core Microsoft "
            "Store endpoints that commonly need TLS-bypass treatment behind SSL bump. "
            "Review periodically because Microsoft endpoint families evolve over time."
        ),
        domains=(
            "*.prod.do.dsp.mp.microsoft.com",
            "*.update.microsoft.com",
            "*.delivery.mp.microsoft.com",
            "*.dl.delivery.mp.microsoft.com",
            "*.windowsupdate.com",
            "*.api.cdp.microsoft.com",
            "definitionupdates.microsoft.com",
            "tsfe.trafficshaping.dsp.mp.microsoft.com",
            "ctldl.windowsupdate.com",
            "adl.windows.com",
            "displaycatalog.mp.microsoft.com",
            "*.displaycatalog.mp.microsoft.com",
            "storeedgefd.dsx.mp.microsoft.com",
            "livetileedge.dsx.mp.microsoft.com",
            "storecatalogrevocation.storequality.microsoft.com",
            "share.microsoft.com",
            "licensing.mp.microsoft.com",
            "login.live.com",
        ),
    ),
)


def list_domain_exclusion_presets() -> Tuple[DomainExclusionPreset, ...]:
    return _DOMAIN_EXCLUSION_PRESETS


def get_domain_exclusion_preset(key: str) -> Optional[DomainExclusionPreset]:
    needle = (key or "").strip().lower()
    if not needle:
        return None
    for preset in _DOMAIN_EXCLUSION_PRESETS:
        if preset.key == needle:
            return preset
    return None


class ExclusionsStore:
    def _connect(self):
        return connect()

    def _table(self, conn, logical_name: str) -> str:
        mapping = {
            "domains": "exclusions_domains",
            "auto_domains": "exclusions_auto_domains",
            "dst_nets": "exclusions_dst_nets",
            "src_nets": "exclusions_src_nets",
            "settings": "exclusions_settings",
        }
        return mapping[logical_name]

    def init_db(self) -> None:
        with self._connect() as conn:
            domains_table = self._table(conn, "domains")
            auto_domains_table = self._table(conn, "auto_domains")
            dst_table = self._table(conn, "dst_nets")
            src_table = self._table(conn, "src_nets")
            settings_table = self._table(conn, "settings")
            conn.execute(
                f"CREATE TABLE IF NOT EXISTS {domains_table}(proxy_id VARCHAR(64) NOT NULL DEFAULT 'default', domain VARCHAR(255) NOT NULL, PRIMARY KEY(proxy_id, domain))"
            )
            conn.execute(
                f"CREATE TABLE IF NOT EXISTS {auto_domains_table}("
                "proxy_id VARCHAR(64) NOT NULL DEFAULT 'default', "
                "domain VARCHAR(255) NOT NULL, "
                "added_ts BIGINT NOT NULL, "
                "expires_ts BIGINT NOT NULL, "
                "last_seen BIGINT NOT NULL DEFAULT 0, "
                "score INT NOT NULL DEFAULT 0, "
                "evidence TEXT NOT NULL, "
                "PRIMARY KEY(proxy_id, domain), "
                "KEY idx_exclusions_auto_domains_proxy_exp (proxy_id, expires_ts), "
                "KEY idx_exclusions_auto_domains_proxy_last_seen (proxy_id, last_seen)"
                ")"
            )
            conn.execute(
                f"CREATE TABLE IF NOT EXISTS {dst_table}(proxy_id VARCHAR(64) NOT NULL DEFAULT 'default', cidr VARCHAR(64) NOT NULL, PRIMARY KEY(proxy_id, cidr))"
            )
            conn.execute(
                f"CREATE TABLE IF NOT EXISTS {src_table}(proxy_id VARCHAR(64) NOT NULL DEFAULT 'default', cidr VARCHAR(64) NOT NULL, PRIMARY KEY(proxy_id, cidr))"
            )
            conn.execute(
                f"CREATE TABLE IF NOT EXISTS {settings_table}(proxy_id VARCHAR(64) NOT NULL DEFAULT 'default', `key` VARCHAR(64) NOT NULL, value TEXT NOT NULL, PRIMARY KEY(proxy_id, `key`))"
            )

    def _set_setting(self, key: str, value: str) -> None:
        proxy_id = get_proxy_id()
        with self._connect() as conn:
            settings_table = self._table(conn, "settings")
            conn.execute(
                f"INSERT INTO {settings_table}(proxy_id, `key`, value) VALUES(%s,%s,%s) ON DUPLICATE KEY UPDATE value=VALUES(value)",
                (proxy_id, key, value),
            )

    def _get_setting(self, key: str) -> Optional[str]:
        proxy_id = get_proxy_id()
        with self._connect() as conn:
            settings_table = self._table(conn, "settings")
            row = conn.execute(f"SELECT value FROM {settings_table} WHERE proxy_id=%s AND `key`=%s", (proxy_id, key)).fetchone()
            return str(row[0]) if row else None

    def _get_setting_conn(self, conn, key: str) -> Optional[str]:
        settings_table = self._table(conn, "settings")
        row = conn.execute(f"SELECT value FROM {settings_table} WHERE proxy_id=%s AND `key`=%s", (get_proxy_id(), key)).fetchone()
        return str(row[0]) if row else None

    def set_exclude_private_nets(self, enabled: bool) -> None:
        self._set_setting("exclude_private_nets", "1" if enabled else "0")

    def get_exclude_private_nets(self) -> bool:
        v = self._get_setting("exclude_private_nets")
        if v is None:
            return True
        return v == "1"

    def _normalize_domain(self, domain: str) -> Tuple[bool, str, str]:
        d = (domain or "").strip().lower()
        if not d:
            return False, "Domain is required.", ""
        if d.startswith("*."):
            d = d[2:]
            is_wildcard = True
        elif d.startswith("."):
            d = d[1:]
            is_wildcard = False
        else:
            is_wildcard = False
        if not d or len(d) > 253:
            return False, "Invalid domain length.", ""
        if " " in d or "/" in d or "\n" in d or "\r" in d:
            return False, "Invalid domain characters.", ""
        labels = d.split(".")
        if not labels or any(not label for label in labels):
            return False, "Invalid domain format.", ""
        for label in labels:
            if not _DOMAIN_LABEL_RE.match(label):
                return False, f"Invalid domain label: {label}", ""
        return True, "", (f"*.{d}" if is_wildcard else d)

    def add_domain(self, domain: str) -> Tuple[bool, str]:
        ok, err, store_value = self._normalize_domain(domain)
        if not ok:
            return False, err
        proxy_id = get_proxy_id()
        with self._connect() as conn:
            conn.execute(
                f"INSERT IGNORE INTO {self._table(conn, 'domains')}(proxy_id, domain) VALUES(%s,%s)",
                (proxy_id, store_value),
            )
        return True, ""

    def add_auto_domain(
        self,
        domain: str,
        *,
        ttl_seconds: int,
        evidence: str = "",
        last_seen: int = 0,
        score: int = 0,
        added_ts: int | None = None,
    ) -> Tuple[bool, str, str]:
        ok, err, canonical = self._normalize_domain(domain)
        if not ok:
            return False, err, ""
        ttl = max(300, int(ttl_seconds or 0))
        now_i = int(added_ts or _now())
        return self.save_auto_domain_state(
            canonical,
            added_ts=now_i,
            expires_ts=now_i + ttl,
            evidence=evidence,
            last_seen=last_seen,
            score=score,
        )

    def save_auto_domain_state(
        self,
        domain: str,
        *,
        added_ts: int,
        expires_ts: int,
        evidence: str = "",
        last_seen: int = 0,
        score: int = 0,
    ) -> Tuple[bool, str, str]:
        ok, err, canonical = self._normalize_domain(domain)
        if not ok:
            return False, err, ""
        proxy_id = get_proxy_id()
        with self._connect() as conn:
            conn.execute(
                f"""
                INSERT INTO {self._table(conn, 'auto_domains')}(proxy_id, domain, added_ts, expires_ts, last_seen, score, evidence)
                VALUES(%s,%s,%s,%s,%s,%s,%s)
                ON DUPLICATE KEY UPDATE
                    added_ts = LEAST(added_ts, VALUES(added_ts)),
                    expires_ts = VALUES(expires_ts),
                    last_seen = VALUES(last_seen),
                    score = VALUES(score),
                    evidence = VALUES(evidence)
                """,
                (
                    proxy_id,
                    canonical,
                    int(added_ts or _now()),
                    max(int(expires_ts or 0), int(added_ts or _now()) + 300),
                    int(last_seen or 0),
                    int(score or 0),
                    str(evidence or "")[:2000],
                ),
            )
        return True, "", canonical

    def remove_auto_domain(self, domain: str) -> None:
        d = (domain or "").strip().lower().lstrip(".")
        if not d:
            return
        proxy_id = get_proxy_id()
        with self._connect() as conn:
            conn.execute(f"DELETE FROM {self._table(conn, 'auto_domains')} WHERE proxy_id=%s AND domain=%s", (proxy_id, d))

    def list_auto_domains(self, limit: int = 5000, *, now_ts: int | None = None) -> List[AutoDomainExclusion]:
        self.init_db()
        proxy_id = get_proxy_id()
        now_i = int(now_ts or _now())
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT domain, added_ts, expires_ts, last_seen, score, evidence
                FROM {self._table(conn, 'auto_domains')}
                WHERE proxy_id=%s AND expires_ts > %s
                ORDER BY last_seen DESC, score DESC, domain ASC
                LIMIT %s
                """,
                (proxy_id, now_i, int(limit)),
            ).fetchall()
        return [
            AutoDomainExclusion(
                domain=str(row[0] or ""),
                added_ts=int(row[1] or 0),
                expires_ts=int(row[2] or 0),
                last_seen=int(row[3] or 0),
                score=int(row[4] or 0),
                evidence=str(row[5] or ""),
            )
            for row in rows
        ]

    def remove_domain(self, domain: str) -> None:
        d = (domain or "").strip().lower().lstrip(".")
        proxy_id = get_proxy_id()
        with self._connect() as conn:
            conn.execute(f"DELETE FROM {self._table(conn, 'domains')} WHERE proxy_id=%s AND domain=%s", (proxy_id, d))

    def add_net(self, table: str, cidr: str) -> Tuple[bool, str]:
        c = (cidr or "").strip()
        if not c:
            return False, "CIDR is required."
        try:
            n = ip_network(c, strict=False)
        except Exception:
            return False, "Invalid CIDR."
        if table not in ("dst_nets", "src_nets"):
            return False, "Invalid target."
        proxy_id = get_proxy_id()
        with self._connect() as conn:
            conn.execute(
                f"INSERT IGNORE INTO {self._table(conn, table)}(proxy_id, cidr) VALUES(%s,%s)",
                (proxy_id, str(n)),
            )
        return True, ""

    def remove_net(self, table: str, cidr: str) -> None:
        c = (cidr or "").strip()
        if table not in ("dst_nets", "src_nets"):
            return
        proxy_id = get_proxy_id()
        with self._connect() as conn:
            conn.execute(f"DELETE FROM {self._table(conn, table)} WHERE proxy_id=%s AND cidr=%s", (proxy_id, c))

    def list_all(self) -> Exclusions:
        self.init_db()
        proxy_id = get_proxy_id()
        with self._connect() as conn:
            manual_domains = [
                str(r[0])
                for r in conn.execute(
                    f"SELECT domain FROM {self._table(conn, 'domains')} WHERE proxy_id=%s ORDER BY domain ASC",
                    (proxy_id,),
                ).fetchall()
            ]
            src = [
                str(r[0])
                for r in conn.execute(
                    f"SELECT cidr FROM {self._table(conn, 'src_nets')} WHERE proxy_id=%s ORDER BY cidr ASC",
                    (proxy_id,),
                ).fetchall()
            ]
            v = self._get_setting_conn(conn, "exclude_private_nets")
            enabled = True if v is None else (v == "1")
        auto_domains = self.list_auto_domains(limit=5000)
        domains: List[str] = []
        seen: set[str] = set()
        for value in list(manual_domains) + [row.domain for row in auto_domains]:
            if value and value not in seen:
                domains.append(value)
                seen.add(value)
        # Destination-network exclusions are intentionally limited to the built-in private/local ranges.
        # (Custom destination CIDR exclusions are not exposed by the UI.)
        return Exclusions(
            domains=domains,
            dst_nets=[],
            src_nets=src,
            exclude_private_nets=enabled,
            manual_domains=manual_domains,
            auto_domains=auto_domains,
        )

    def prune_expired_entries(self, *, now_ts: int | None = None, retention_days: int = 30) -> None:
        self.init_db()
        now_i = int(now_ts or _now())
        cutoff = now_i - (max(1, int(retention_days or 30)) * 24 * 60 * 60)
        proxy_id = get_proxy_id()
        with self._connect() as conn:
            conn.execute(
                f"DELETE FROM {self._table(conn, 'auto_domains')} WHERE proxy_id=%s AND expires_ts <= %s",
                (proxy_id, now_i),
            )
            conn.execute(
                f"DELETE FROM {self._table(conn, 'auto_domains')} WHERE proxy_id=%s AND expires_ts < %s",
                (proxy_id, cutoff),
            )


_store: Optional[ExclusionsStore] = None
_store_lock = threading.Lock()


def get_exclusions_store() -> ExclusionsStore:
    global _store
    if _store is not None:
        return _store
    with _store_lock:
        if _store is None:
            _store = ExclusionsStore()
            _store.init_db()
        return _store
