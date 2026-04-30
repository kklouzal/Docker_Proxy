from __future__ import annotations

import ipaddress
import threading
from dataclasses import dataclass
from typing import List, Optional, Tuple

from services.db import connect
from services.materialized_files import write_managed_text_files
from services.proxy_context import get_proxy_id
from services.runtime_helpers import now_ts as _now


@dataclass(frozen=True)
class SslFilterSettings:
    nobump_cidrs: List[Tuple[str, int]]


@dataclass(frozen=True)
class AutoNoBumpEntry:
    cidr: str
    added_ts: int
    expires_ts: int
    last_seen: int
    score: int
    evidence: str


@dataclass(frozen=True)
class DynamicMitigationSettings:
    enabled: bool
    auto_domain_enabled: bool
    auto_client_enabled: bool
    review_window_seconds: int
    reconcile_interval_seconds: int
    min_pair_events: int
    min_bump_aborts: int
    min_ssl_events: int
    domain_limit: int
    domain_ttl_seconds: int
    client_pair_events: int
    client_distinct_domains: int
    client_limit: int
    client_ttl_seconds: int
    last_run_ts: int
    last_apply_ts: int
    last_result: str


@dataclass(frozen=True)
class SslFilterMaterializedState:
    include_text: str
    list_text: str


def _default_dynamic_mitigation_settings() -> DynamicMitigationSettings:
    return DynamicMitigationSettings(
        enabled=True,
        auto_domain_enabled=True,
        auto_client_enabled=True,
        review_window_seconds=4 * 60 * 60,
        reconcile_interval_seconds=5 * 60,
        min_pair_events=6,
        min_bump_aborts=8,
        min_ssl_events=10,
        domain_limit=12,
        domain_ttl_seconds=6 * 60 * 60,
        client_pair_events=24,
        client_distinct_domains=4,
        client_limit=4,
        client_ttl_seconds=2 * 60 * 60,
        last_run_ts=0,
        last_apply_ts=0,
        last_result="",
    )


class SslFilterStore:
    def __init__(
        self,
        squid_include_path: str = "/etc/squid/conf.d/10-sslfilter.conf",
        nobump_list_path: str = "/var/lib/squid-flask-proxy/sslfilter_nobump.txt",
    ):
        self.squid_include_path = squid_include_path
        self.nobump_list_path = nobump_list_path

    def _connect(self):
        return connect()

    def init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS nobump_cidrs("
                "proxy_id VARCHAR(64) NOT NULL DEFAULT 'default', "
                "cidr VARCHAR(64) NOT NULL, "
                "added_ts BIGINT NOT NULL, "
                "PRIMARY KEY(proxy_id, cidr), "
                "KEY idx_nobump_cidrs_proxy_ts (proxy_id, added_ts)"
                ")"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS nobump_cidrs_auto("
                "proxy_id VARCHAR(64) NOT NULL DEFAULT 'default', "
                "cidr VARCHAR(64) NOT NULL, "
                "added_ts BIGINT NOT NULL, "
                "expires_ts BIGINT NOT NULL, "
                "last_seen BIGINT NOT NULL DEFAULT 0, "
                "score INT NOT NULL DEFAULT 0, "
                "evidence TEXT NOT NULL, "
                "PRIMARY KEY(proxy_id, cidr), "
                "KEY idx_nobump_cidrs_auto_proxy_exp (proxy_id, expires_ts), "
                "KEY idx_nobump_cidrs_auto_proxy_last_seen (proxy_id, last_seen)"
                ")"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS sslfilter_settings("
                "proxy_id VARCHAR(64) NOT NULL DEFAULT 'default', "
                "`key` VARCHAR(64) NOT NULL, "
                "value TEXT NOT NULL, "
                "PRIMARY KEY(proxy_id, `key`)"
                ")"
            )

    def _set_setting(self, key: str, value: str) -> None:
        proxy_id = get_proxy_id()
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO sslfilter_settings(proxy_id, `key`, value) VALUES(%s,%s,%s) ON DUPLICATE KEY UPDATE value=VALUES(value)",
                (proxy_id, key, value),
            )

    def _get_setting(self, key: str) -> Optional[str]:
        proxy_id = get_proxy_id()
        with self._connect() as conn:
            row = conn.execute("SELECT value FROM sslfilter_settings WHERE proxy_id=%s AND `key`=%s", (proxy_id, key)).fetchone()
            return str(row[0]) if row else None

    @staticmethod
    def _bool_setting(value: Optional[str], default: bool) -> bool:
        if value is None:
            return bool(default)
        return str(value).strip().lower() in {"1", "true", "yes", "on"}

    @staticmethod
    def _int_setting(value: Optional[str], default: int, *, minimum: int, maximum: int) -> int:
        try:
            parsed = int(str(value).strip()) if value is not None else int(default)
        except Exception:
            parsed = int(default)
        return max(int(minimum), min(int(maximum), parsed))

    def get_dynamic_mitigation_settings(self) -> DynamicMitigationSettings:
        self.init_db()
        defaults = _default_dynamic_mitigation_settings()
        return DynamicMitigationSettings(
            enabled=self._bool_setting(self._get_setting("dynamic_enabled"), defaults.enabled),
            auto_domain_enabled=self._bool_setting(self._get_setting("dynamic_auto_domain_enabled"), defaults.auto_domain_enabled),
            auto_client_enabled=self._bool_setting(self._get_setting("dynamic_auto_client_enabled"), defaults.auto_client_enabled),
            review_window_seconds=self._int_setting(self._get_setting("dynamic_review_window_seconds"), defaults.review_window_seconds, minimum=1800, maximum=24 * 60 * 60),
            reconcile_interval_seconds=self._int_setting(self._get_setting("dynamic_reconcile_interval_seconds"), defaults.reconcile_interval_seconds, minimum=60, maximum=60 * 60),
            min_pair_events=self._int_setting(self._get_setting("dynamic_min_pair_events"), defaults.min_pair_events, minimum=3, maximum=100),
            min_bump_aborts=self._int_setting(self._get_setting("dynamic_min_bump_aborts"), defaults.min_bump_aborts, minimum=3, maximum=100),
            min_ssl_events=self._int_setting(self._get_setting("dynamic_min_ssl_events"), defaults.min_ssl_events, minimum=3, maximum=200),
            domain_limit=self._int_setting(self._get_setting("dynamic_domain_limit"), defaults.domain_limit, minimum=1, maximum=100),
            domain_ttl_seconds=self._int_setting(self._get_setting("dynamic_domain_ttl_seconds"), defaults.domain_ttl_seconds, minimum=900, maximum=7 * 24 * 60 * 60),
            client_pair_events=self._int_setting(self._get_setting("dynamic_client_pair_events"), defaults.client_pair_events, minimum=6, maximum=500),
            client_distinct_domains=self._int_setting(self._get_setting("dynamic_client_distinct_domains"), defaults.client_distinct_domains, minimum=2, maximum=20),
            client_limit=self._int_setting(self._get_setting("dynamic_client_limit"), defaults.client_limit, minimum=1, maximum=50),
            client_ttl_seconds=self._int_setting(self._get_setting("dynamic_client_ttl_seconds"), defaults.client_ttl_seconds, minimum=900, maximum=7 * 24 * 60 * 60),
            last_run_ts=self._int_setting(self._get_setting("dynamic_last_run_ts"), defaults.last_run_ts, minimum=0, maximum=2**31 - 1),
            last_apply_ts=self._int_setting(self._get_setting("dynamic_last_apply_ts"), defaults.last_apply_ts, minimum=0, maximum=2**31 - 1),
            last_result=str(self._get_setting("dynamic_last_result") or defaults.last_result),
        )

    def set_dynamic_mitigation_settings(
        self,
        *,
        enabled: bool,
        auto_domain_enabled: bool,
        auto_client_enabled: bool,
        review_window_seconds: int,
        reconcile_interval_seconds: int,
        min_pair_events: int,
        min_bump_aborts: int,
        min_ssl_events: int,
        domain_limit: int,
        domain_ttl_seconds: int,
        client_pair_events: int,
        client_distinct_domains: int,
        client_limit: int,
        client_ttl_seconds: int,
    ) -> None:
        self._set_setting("dynamic_enabled", "1" if enabled else "0")
        self._set_setting("dynamic_auto_domain_enabled", "1" if auto_domain_enabled else "0")
        self._set_setting("dynamic_auto_client_enabled", "1" if auto_client_enabled else "0")
        self._set_setting("dynamic_review_window_seconds", str(max(1800, min(24 * 60 * 60, int(review_window_seconds)))))
        self._set_setting("dynamic_reconcile_interval_seconds", str(max(60, min(60 * 60, int(reconcile_interval_seconds)))))
        self._set_setting("dynamic_min_pair_events", str(max(3, min(100, int(min_pair_events)))))
        self._set_setting("dynamic_min_bump_aborts", str(max(3, min(100, int(min_bump_aborts)))))
        self._set_setting("dynamic_min_ssl_events", str(max(3, min(200, int(min_ssl_events)))))
        self._set_setting("dynamic_domain_limit", str(max(1, min(100, int(domain_limit)))))
        self._set_setting("dynamic_domain_ttl_seconds", str(max(900, min(7 * 24 * 60 * 60, int(domain_ttl_seconds)))))
        self._set_setting("dynamic_client_pair_events", str(max(6, min(500, int(client_pair_events)))))
        self._set_setting("dynamic_client_distinct_domains", str(max(2, min(20, int(client_distinct_domains)))))
        self._set_setting("dynamic_client_limit", str(max(1, min(50, int(client_limit)))))
        self._set_setting("dynamic_client_ttl_seconds", str(max(900, min(7 * 24 * 60 * 60, int(client_ttl_seconds)))))

    def update_dynamic_mitigation_status(self, *, last_run_ts: int | None = None, last_apply_ts: int | None = None, last_result: str | None = None) -> None:
        if last_run_ts is not None:
            self._set_setting("dynamic_last_run_ts", str(max(0, int(last_run_ts))))
        if last_apply_ts is not None:
            self._set_setting("dynamic_last_apply_ts", str(max(0, int(last_apply_ts))))
        if last_result is not None:
            self._set_setting("dynamic_last_result", str(last_result or "")[:4000])

    def _canonicalize_cidr(self, entry: str) -> Tuple[bool, str, str]:
        raw = (entry or "").strip()
        if not raw:
            return False, "Enter a CIDR like 192.168.1.0/24 (or a single IP)", ""
        try:
            if "/" in raw:
                net = ipaddress.ip_network(raw, strict=False)
            else:
                ip = ipaddress.ip_address(raw)
                net = ipaddress.ip_network(f"{ip}/{32 if ip.version == 4 else 128}", strict=False)
        except Exception:
            return False, "Invalid CIDR/IP. Example: 10.0.0.0/8", ""
        return True, "", net.with_prefixlen

    def list_nobump(self, limit: int = 5000) -> List[Tuple[str, int]]:
        self.init_db()
        proxy_id = get_proxy_id()
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT cidr, added_ts FROM nobump_cidrs WHERE proxy_id=%s ORDER BY added_ts DESC, cidr ASC LIMIT %s",
                (proxy_id, int(limit)),
            ).fetchall()
            out: List[Tuple[str, int]] = []
            for r in rows:
                out.append((str(r[0]), int(r[1]) if r[1] is not None else 0))
            return out

    def list_auto_nobump(self, limit: int = 5000, *, now_ts: int | None = None) -> List[AutoNoBumpEntry]:
        self.init_db()
        proxy_id = get_proxy_id()
        now_i = int(now_ts or _now())
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT cidr, added_ts, expires_ts, last_seen, score, evidence
                FROM nobump_cidrs_auto
                WHERE proxy_id=%s AND expires_ts > %s
                ORDER BY last_seen DESC, score DESC, cidr ASC
                LIMIT %s
                """,
                (proxy_id, now_i, int(limit)),
            ).fetchall()
        return [
            AutoNoBumpEntry(
                cidr=str(row[0] or ""),
                added_ts=int(row[1] or 0),
                expires_ts=int(row[2] or 0),
                last_seen=int(row[3] or 0),
                score=int(row[4] or 0),
                evidence=str(row[5] or ""),
            )
            for row in rows
        ]

    def list_effective_nobump(self, limit: int = 5000, *, now_ts: int | None = None) -> List[Tuple[str, int]]:
        manual = self.list_nobump(limit=limit)
        auto = self.list_auto_nobump(limit=limit, now_ts=now_ts)
        out: List[Tuple[str, int]] = []
        seen: set[str] = set()
        for cidr, added_ts in manual:
            if cidr and cidr not in seen:
                out.append((cidr, int(added_ts or 0)))
                seen.add(cidr)
        for row in auto:
            if row.cidr and row.cidr not in seen:
                out.append((row.cidr, row.added_ts))
                seen.add(row.cidr)
        return out[: max(1, int(limit))]

    def add_nobump(self, entry: str) -> Tuple[bool, str, str]:
        """Add a CIDR (or single IP). Returns (ok, err, canonical)."""

        self.init_db()
        ok, err, canonical = self._canonicalize_cidr(entry)
        if not ok:
            return False, err, ""
        proxy_id = get_proxy_id()
        with self._connect() as conn:
            conn.execute(
                "INSERT IGNORE INTO nobump_cidrs(proxy_id, cidr, added_ts) VALUES(%s,%s,%s)",
                (proxy_id, canonical, int(_now())),
            )
        return True, "", canonical

    def add_auto_nobump(
        self,
        entry: str,
        *,
        ttl_seconds: int,
        evidence: str = "",
        last_seen: int = 0,
        score: int = 0,
        added_ts: int | None = None,
    ) -> Tuple[bool, str, str]:
        self.init_db()
        ok, err, canonical = self._canonicalize_cidr(entry)
        if not ok:
            return False, err, ""
        ttl = max(300, int(ttl_seconds or 0))
        now_i = int(added_ts or _now())
        return self.save_auto_nobump_state(
            canonical,
            added_ts=now_i,
            expires_ts=now_i + ttl,
            evidence=evidence,
            last_seen=last_seen,
            score=score,
        )

    def save_auto_nobump_state(
        self,
        entry: str,
        *,
        added_ts: int,
        expires_ts: int,
        evidence: str = "",
        last_seen: int = 0,
        score: int = 0,
    ) -> Tuple[bool, str, str]:
        self.init_db()
        ok, err, canonical = self._canonicalize_cidr(entry)
        if not ok:
            return False, err, ""
        proxy_id = get_proxy_id()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO nobump_cidrs_auto(proxy_id, cidr, added_ts, expires_ts, last_seen, score, evidence)
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

    def remove_nobump(self, cidr: str) -> None:
        self.init_db()
        t = (cidr or "").strip()
        if not t:
            return
        proxy_id = get_proxy_id()
        with self._connect() as conn:
            conn.execute("DELETE FROM nobump_cidrs WHERE proxy_id=%s AND cidr=%s", (proxy_id, t))

    def remove_auto_nobump(self, cidr: str) -> None:
        self.init_db()
        t = (cidr or "").strip()
        if not t:
            return
        proxy_id = get_proxy_id()
        with self._connect() as conn:
            conn.execute("DELETE FROM nobump_cidrs_auto WHERE proxy_id=%s AND cidr=%s", (proxy_id, t))

    def render_materialized_state(self, *, now_ts: int | None = None) -> SslFilterMaterializedState:
        self.init_db()
        rows = self.list_effective_nobump(limit=10000, now_ts=now_ts)
        cidrs = [c for c, _ts in rows if c]
        list_text = ("\n".join(cidrs) + "\n") if cidrs else ""

        if cidrs:
            include_text = "\n".join(
                [
                    "# Autogenerated: SSL filtering (no-bump CIDRs)",
                    f"acl sslfilter_nobump src \"{self.nobump_list_path}\"",
                    "note ssl_exception sslfilter_nobump sslfilter_nobump",
                    "# Splice (tunnel) TLS for unmanaged/untrusted clients.",
                    "ssl_bump splice sslfilter_nobump",
                ]
            ) + "\n"
        else:
            include_text = "# Autogenerated: SSL filtering (no-bump CIDRs) - none configured\n"

        return SslFilterMaterializedState(include_text=include_text, list_text=list_text)

    def apply_squid_include(self) -> None:
        """(Re)generate the Squid include file for ssl_bump splice policy."""
        state = self.render_materialized_state()
        write_managed_text_files(
            (self.nobump_list_path, state.list_text),
            (self.squid_include_path, state.include_text),
        )

    def prune_expired_entries(self, *, now_ts: int | None = None, retention_days: int = 30) -> None:
        self.init_db()
        now_i = int(now_ts or _now())
        cutoff = now_i - (max(1, int(retention_days or 30)) * 24 * 60 * 60)
        proxy_id = get_proxy_id()
        with self._connect() as conn:
            conn.execute("DELETE FROM nobump_cidrs_auto WHERE proxy_id=%s AND expires_ts <= %s", (proxy_id, now_i))
            conn.execute("DELETE FROM nobump_cidrs_auto WHERE proxy_id=%s AND expires_ts < %s", (proxy_id, cutoff))


_store: Optional[SslFilterStore] = None
_store_lock = threading.Lock()


def get_sslfilter_store() -> SslFilterStore:
    global _store
    if _store is not None:
        return _store
    with _store_lock:
        if _store is None:
            _store = SslFilterStore()
            _store.init_db()
        return _store
