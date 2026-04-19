from __future__ import annotations

import os
import re
import threading
from dataclasses import dataclass
from ipaddress import ip_network
from typing import List, Optional, Tuple

from services.db import connect


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
            conn.execute(f"CREATE TABLE IF NOT EXISTS {domains_table}(domain VARCHAR(255) PRIMARY KEY)")
            conn.execute(f"CREATE TABLE IF NOT EXISTS {dst_table}(cidr VARCHAR(64) PRIMARY KEY)")
            conn.execute(f"CREATE TABLE IF NOT EXISTS {src_table}(cidr VARCHAR(64) PRIMARY KEY)")
            conn.execute(f"CREATE TABLE IF NOT EXISTS {settings_table}(`key` VARCHAR(64) PRIMARY KEY, value TEXT NOT NULL)")

    def _set_setting(self, key: str, value: str) -> None:
        with self._connect() as conn:
            settings_table = self._table(conn, "settings")
            conn.execute(
                f"INSERT INTO {settings_table}(`key`,value) VALUES(?,?) ON CONFLICT(`key`) DO UPDATE SET value=excluded.value",
                (key, value),
            )

    def _get_setting(self, key: str) -> Optional[str]:
        with self._connect() as conn:
            settings_table = self._table(conn, "settings")
            row = conn.execute(f"SELECT value FROM {settings_table} WHERE `key`=?", (key,)).fetchone()
            return str(row[0]) if row else None

    def _get_setting_conn(self, conn, key: str) -> Optional[str]:
        settings_table = self._table(conn, "settings")
        row = conn.execute(f"SELECT value FROM {settings_table} WHERE `key`=?", (key,)).fetchone()
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
        with self._connect() as conn:
            conn.execute(f"INSERT OR IGNORE INTO {self._table(conn, 'domains')}(domain) VALUES(?)", (store_value,))
        return True, ""

    def remove_domain(self, domain: str) -> None:
        d = (domain or "").strip().lower().lstrip(".")
        with self._connect() as conn:
            conn.execute(f"DELETE FROM {self._table(conn, 'domains')} WHERE domain=?", (d,))

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
        with self._connect() as conn:
            conn.execute(f"INSERT OR IGNORE INTO {self._table(conn, table)}(cidr) VALUES(?)", (str(n),))
        return True, ""

    def remove_net(self, table: str, cidr: str) -> None:
        c = (cidr or "").strip()
        if table not in ("dst_nets", "src_nets"):
            return
        with self._connect() as conn:
            conn.execute(f"DELETE FROM {self._table(conn, table)} WHERE cidr=?", (c,))

    def list_all(self) -> Exclusions:
        self.init_db()
        with self._connect() as conn:
            domains = [str(r[0]) for r in conn.execute(f"SELECT domain FROM {self._table(conn, 'domains')} ORDER BY domain ASC").fetchall()]
            src = [str(r[0]) for r in conn.execute(f"SELECT cidr FROM {self._table(conn, 'src_nets')} ORDER BY cidr ASC").fetchall()]
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
