from __future__ import annotations

import os
import sqlite3
import time
from dataclasses import dataclass
from ipaddress import ip_address, ip_network
from typing import List, Optional, Tuple


@dataclass(frozen=True)
class PacProfile:
    id: int
    name: str
    client_cidr: str
    socks_enabled: bool
    socks_host: str
    socks_port: int
    direct_domains: List[str]
    direct_dst_nets: List[str]
    created_ts: int


def _now() -> int:
    return int(time.time())


def _normalize_domain(domain: str) -> Tuple[Optional[str], str]:
    d = (domain or "").strip().lower()
    if not d:
        return None, ""
    if " " in d or "/" in d:
        return None, "Invalid domain."
    if d.startswith("."):
        d = d[1:]
    if not d:
        return None, "Invalid domain."
    return d, ""


def _normalize_v4_cidr(cidr: str) -> Tuple[Optional[str], str]:
    c = (cidr or "").strip()
    if not c:
        return "", ""
    try:
        net = ip_network(c, strict=False)
    except Exception:
        return None, "Invalid CIDR."
    if net.version != 4:
        return None, "Only IPv4 CIDR is supported in PAC rules."
    return str(net), ""


class PacProfilesStore:
    def __init__(self, db_path: str = "/var/lib/squid-flask-proxy/pac_profiles.db"):
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
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS pac_profiles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    client_cidr TEXT NOT NULL DEFAULT '',
                    socks_enabled INTEGER NOT NULL DEFAULT 0,
                    socks_host TEXT NOT NULL DEFAULT '',
                    socks_port INTEGER NOT NULL DEFAULT 1080,
                    created_ts INTEGER NOT NULL
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS pac_direct_domains (
                    profile_id INTEGER NOT NULL,
                    domain TEXT NOT NULL,
                    PRIMARY KEY(profile_id, domain)
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS pac_direct_dst_nets (
                    profile_id INTEGER NOT NULL,
                    cidr TEXT NOT NULL,
                    PRIMARY KEY(profile_id, cidr)
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_pac_profiles_created ON pac_profiles(created_ts DESC, id DESC);")

            # Lightweight schema migration for existing DBs.
            cols = [str(r[1]) for r in conn.execute("PRAGMA table_info(pac_profiles)").fetchall()]
            if "socks_enabled" not in cols:
                conn.execute("ALTER TABLE pac_profiles ADD COLUMN socks_enabled INTEGER NOT NULL DEFAULT 0")
            if "socks_host" not in cols:
                conn.execute("ALTER TABLE pac_profiles ADD COLUMN socks_host TEXT NOT NULL DEFAULT ''")
            if "socks_port" not in cols:
                conn.execute("ALTER TABLE pac_profiles ADD COLUMN socks_port INTEGER NOT NULL DEFAULT 1080")

    def list_profiles(self) -> List[PacProfile]:
        self.init_db()
        with self._connect() as conn:
            profiles = conn.execute(
                "SELECT id, name, client_cidr, socks_enabled, socks_host, socks_port, created_ts FROM pac_profiles ORDER BY id ASC"
            ).fetchall()
            res: List[PacProfile] = []
            for p in profiles:
                pid = int(p["id"])
                domains = [
                    str(r[0])
                    for r in conn.execute(
                        "SELECT domain FROM pac_direct_domains WHERE profile_id=? ORDER BY domain ASC", (pid,)
                    ).fetchall()
                ]
                nets = [
                    str(r[0])
                    for r in conn.execute(
                        "SELECT cidr FROM pac_direct_dst_nets WHERE profile_id=? ORDER BY cidr ASC", (pid,)
                    ).fetchall()
                ]
                res.append(
                    PacProfile(
                        id=pid,
                        name=str(p["name"]),
                        client_cidr=str(p["client_cidr"] or ""),
                        socks_enabled=bool(int(p["socks_enabled"] or 0)),
                        socks_host=str(p["socks_host"] or ""),
                        socks_port=int(p["socks_port"] or 1080),
                        direct_domains=domains,
                        direct_dst_nets=nets,
                        created_ts=int(p["created_ts"] or 0),
                    )
                )
            return res

    def upsert_profile(
        self,
        *,
        profile_id: Optional[int],
        name: str,
        client_cidr: str,
        socks_enabled: bool,
        socks_host: str,
        socks_port: str,
        direct_domains_text: str,
        direct_dst_nets_text: str,
    ) -> Tuple[bool, str, Optional[int]]:
        self.init_db()

        nm = (name or "").strip()
        if not nm:
            return False, "Name is required.", None

        cidr_norm, err = _normalize_v4_cidr(client_cidr)
        if cidr_norm is None:
            return False, err, None

        socks_on = bool(socks_enabled)
        shost = (socks_host or "").strip()
        if shost and " " in shost:
            return False, "Invalid SOCKS host.", None
        try:
            sport = int((socks_port or "1080").strip() or "1080")
        except Exception:
            return False, "Invalid SOCKS port.", None
        if sport < 1 or sport > 65535:
            return False, "Invalid SOCKS port.", None

        domains: List[str] = []
        for ln in (direct_domains_text or "").splitlines():
            d, derr = _normalize_domain(ln)
            if d is None:
                if derr:
                    return False, derr, None
                continue
            if d not in domains:
                domains.append(d)

        nets: List[str] = []
        for ln in (direct_dst_nets_text or "").splitlines():
            c, cerr = _normalize_v4_cidr(ln)
            if c is None:
                return False, cerr, None
            if not c:
                continue
            if c not in nets:
                nets.append(c)

        with self._connect() as conn:
            if profile_id is None:
                cur = conn.execute(
                    "INSERT INTO pac_profiles(name, client_cidr, socks_enabled, socks_host, socks_port, created_ts) VALUES(?,?,?,?,?,?)",
                    (nm, cidr_norm or "", 1 if socks_on else 0, shost, int(sport), _now()),
                )
                pid = int(cur.lastrowid)
            else:
                pid = int(profile_id)
                conn.execute(
                    "UPDATE pac_profiles SET name=?, client_cidr=?, socks_enabled=?, socks_host=?, socks_port=? WHERE id=?",
                    (nm, cidr_norm or "", 1 if socks_on else 0, shost, int(sport), pid),
                )

                # Clear old rules.
                conn.execute("DELETE FROM pac_direct_domains WHERE profile_id=?", (pid,))
                conn.execute("DELETE FROM pac_direct_dst_nets WHERE profile_id=?", (pid,))

            for d in domains:
                conn.execute(
                    "INSERT OR IGNORE INTO pac_direct_domains(profile_id, domain) VALUES(?,?)",
                    (pid, d),
                )
            for c in nets:
                conn.execute(
                    "INSERT OR IGNORE INTO pac_direct_dst_nets(profile_id, cidr) VALUES(?,?)",
                    (pid, c),
                )

        return True, "", pid

    def delete_profile(self, profile_id: int) -> None:
        self.init_db()
        pid = int(profile_id)
        with self._connect() as conn:
            conn.execute("DELETE FROM pac_direct_domains WHERE profile_id=?", (pid,))
            conn.execute("DELETE FROM pac_direct_dst_nets WHERE profile_id=?", (pid,))
            conn.execute("DELETE FROM pac_profiles WHERE id=?", (pid,))

    def match_profile_for_client_ip(self, client_ip: str) -> Optional[PacProfile]:
        """Return the first matching profile for client_ip.

        Matching order:
        - profiles with a non-empty client_cidr, in id order
        - then profiles with empty client_cidr (catch-all), in id order
        """
        profiles = self.list_profiles()
        if not profiles:
            return None

        try:
            ip = ip_address((client_ip or "").strip())
        except Exception:
            ip = None

        def sort_key(p: PacProfile) -> Tuple[int, int]:
            return (1 if not p.client_cidr else 0, int(p.id))

        for p in sorted(profiles, key=sort_key):
            if not p.client_cidr:
                if ip is None:
                    continue
                # catch-all handled after CIDR matches
                continue
            if ip is None:
                continue
            try:
                net = ip_network(p.client_cidr, strict=False)
                if ip in net:
                    return p
            except Exception:
                continue

        # fall back to first catch-all (if any)
        for p in sorted(profiles, key=sort_key):
            if not p.client_cidr:
                return p

        return None


_store: Optional[PacProfilesStore] = None


def get_pac_profiles_store() -> PacProfilesStore:
    global _store
    if _store is None:
        _store = PacProfilesStore()
        _store.init_db()
    return _store
