from __future__ import annotations

import os
import re
import threading
from dataclasses import dataclass
from ipaddress import ip_network
from typing import List, Optional, Tuple

from services.db import connect
from services.proxy_context import get_proxy_id


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


class ExclusionsStore:
    def _connect(self):
        return connect()

    def _table(self, conn, logical_name: str) -> str:
        mapping = {
            "domains": "exclusions_domains",
            "dst_nets": "exclusions_dst_nets",
            "src_nets": "exclusions_src_nets",
            "settings": "exclusions_settings",
        }
        return mapping[logical_name]

    def init_db(self) -> None:
        with self._connect() as conn:
            domains_table = self._table(conn, "domains")
            dst_table = self._table(conn, "dst_nets")
            src_table = self._table(conn, "src_nets")
            settings_table = self._table(conn, "settings")
            conn.execute(
                f"CREATE TABLE IF NOT EXISTS {domains_table}(proxy_id VARCHAR(64) NOT NULL DEFAULT 'default', domain VARCHAR(255) NOT NULL, PRIMARY KEY(proxy_id, domain))"
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

    def add_domain(self, domain: str) -> Tuple[bool, str]:
        d = (domain or "").strip().lower()
        if not d:
            return False, "Domain is required."
        # allow leading dot or wildcard prefix for subdomain matching
        if d.startswith("*."):
            d = d[2:]  # strip wildcard for validation, will be stored as-is later
            is_wildcard = True
        elif d.startswith("."):
            d = d[1:]
            is_wildcard = False
        else:
            is_wildcard = False
        # Validate domain format
        if not d or len(d) > 253:
            return False, "Invalid domain length."
        if " " in d or "/" in d or "\n" in d or "\r" in d:
            return False, "Invalid domain characters."
        labels = d.split(".")
        if not labels or any(not label for label in labels):
            return False, "Invalid domain format."
        for label in labels:
            if not _DOMAIN_LABEL_RE.match(label):
                return False, f"Invalid domain label: {label}"
        # Store with wildcard prefix if applicable
        store_value = f"*.{d}" if is_wildcard else d
        proxy_id = get_proxy_id()
        with self._connect() as conn:
            conn.execute(
                f"INSERT IGNORE INTO {self._table(conn, 'domains')}(proxy_id, domain) VALUES(%s,%s)",
                (proxy_id, store_value),
            )
        return True, ""

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
            domains = [
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
        # Destination-network exclusions are intentionally limited to the built-in private/local ranges.
        # (Custom destination CIDR exclusions are not exposed by the UI.)
        return Exclusions(domains=domains, dst_nets=[], src_nets=src, exclude_private_nets=enabled)


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
