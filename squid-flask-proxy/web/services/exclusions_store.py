from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass
from ipaddress import ip_network
from typing import List, Optional, Tuple


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
    def __init__(self, db_path: str = "/var/lib/squid-flask-proxy/exclusions.db"):
        self.db_path = db_path

    def _connect(self) -> sqlite3.Connection:
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        conn = sqlite3.connect(self.db_path, timeout=3)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def init_db(self) -> None:
        with self._connect() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS domains(domain TEXT PRIMARY KEY);")
            conn.execute("CREATE TABLE IF NOT EXISTS dst_nets(cidr TEXT PRIMARY KEY);")
            conn.execute("CREATE TABLE IF NOT EXISTS src_nets(cidr TEXT PRIMARY KEY);")
            conn.execute("CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);")

    def _set_setting(self, key: str, value: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )

    def _get_setting(self, key: str) -> Optional[str]:
        with self._connect() as conn:
            row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
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
        if " " in d or "/" in d:
            return False, "Invalid domain."
        # allow leading dot to match subdomains
        if d.startswith("."):
            d = d[1:]
        with self._connect() as conn:
            conn.execute("INSERT OR IGNORE INTO domains(domain) VALUES(?)", (d,))
        return True, ""

    def remove_domain(self, domain: str) -> None:
        d = (domain or "").strip().lower().lstrip(".")
        with self._connect() as conn:
            conn.execute("DELETE FROM domains WHERE domain=?", (d,))

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
            conn.execute(f"INSERT OR IGNORE INTO {table}(cidr) VALUES(?)", (str(n),))
        return True, ""

    def remove_net(self, table: str, cidr: str) -> None:
        c = (cidr or "").strip()
        if table not in ("dst_nets", "src_nets"):
            return
        with self._connect() as conn:
            conn.execute(f"DELETE FROM {table} WHERE cidr=?", (c,))

    def list_all(self) -> Exclusions:
        self.init_db()
        with self._connect() as conn:
            domains = [str(r[0]) for r in conn.execute("SELECT domain FROM domains ORDER BY domain ASC").fetchall()]
            src = [str(r[0]) for r in conn.execute("SELECT cidr FROM src_nets ORDER BY cidr ASC").fetchall()]
        enabled = self.get_exclude_private_nets()
        # Destination-network exclusions are intentionally limited to the built-in private/local ranges.
        # (Custom destination CIDR exclusions are not exposed by the UI.)
        return Exclusions(domains=domains, dst_nets=[], src_nets=src, exclude_private_nets=enabled)


_store: Optional[ExclusionsStore] = None


def get_exclusions_store() -> ExclusionsStore:
    global _store
    if _store is None:
        _store = ExclusionsStore()
        _store.init_db()
    return _store
