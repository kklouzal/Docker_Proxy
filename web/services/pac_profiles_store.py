from __future__ import annotations

import threading
from dataclasses import dataclass
from ipaddress import ip_address, ip_network
from urllib.parse import urlsplit

from services.db import connect
from services.domain_normalization import normalize_domain as _shared_normalize_domain
from services.proxy_context import get_proxy_id
from services.proxy_write_guard import guarded_proxy_write
from services.runtime_helpers import now_ts as _now


@dataclass(frozen=True)
class PacProfile:
    id: int
    name: str
    client_cidr: str
    direct_domains: list[str]
    direct_dst_nets: list[str]
    created_ts: int


@dataclass(frozen=True)
class PacBackupProxy:
    id: int
    proxy_host: str
    proxy_port: int
    position: int
    created_ts: int


@dataclass(frozen=True)
class PacProxyChainSettings:
    backup_proxies: list[PacBackupProxy]
    direct_enabled: bool


def _normalize_domain(domain: str) -> tuple[str | None, str]:
    raw = (domain or "").strip()
    if not raw:
        return None, ""
    if any(ch.isspace() for ch in raw):
        return None, "Invalid domain."
    wildcard = raw.lower().startswith("*.") and "://" not in raw
    raw = raw[2:] if wildcard else raw.removeprefix(".")
    d = _shared_normalize_domain(raw)
    if not d or ":" in d:
        return None, "Invalid domain."
    labels = d.split(".")
    if any(
        not label
        or len(label) > 63
        or not label.isascii()
        or not label[0].isalnum()
        or not label[-1].isalnum()
        or any(not (ch.isalnum() or ch == "-") for ch in label)
        for label in labels
    ):
        return None, "Invalid domain."
    return (f"*.{d}" if wildcard else d), ""


def _normalize_client_cidr(cidr: str) -> tuple[str | None, str]:
    c = (cidr or "").strip()
    if not c:
        return "", ""
    try:
        net = ip_network(c, strict=False)
    except Exception:
        return None, "Invalid client CIDR."
    return str(net), ""


def _normalize_pac_dst_v4_cidr(cidr: str) -> tuple[str | None, str]:
    c = (cidr or "").strip()
    if not c:
        return "", ""
    try:
        net = ip_network(c, strict=False)
    except Exception:
        return None, "Invalid destination CIDR."
    if net.version != 4:
        return None, "Only IPv4 destination CIDR is supported in PAC DIRECT rules."
    return str(net), ""


def _is_valid_proxy_host(host: str) -> bool:
    if not host or any(ch.isspace() for ch in host) or "/" in host:
        return False
    try:
        parsed_ip = ip_address(host)
        return not bool(getattr(parsed_ip, "scope_id", None))
    except Exception:
        pass

    if len(host) > 253:
        return False
    labels = host.split(".")
    return all(
        label
        and len(label) <= 63
        and label.isascii()
        and label[0].isalnum()
        and label[-1].isalnum()
        and all(ch.isalnum() or ch == "-" for ch in label)
        for label in labels
    )


def _normalize_proxy_host_port(
    proxy_host: str,
    proxy_port: object | None,
) -> tuple[str | None, int | None, str]:
    host = (proxy_host or "").strip()
    raw_port = "" if proxy_port is None else str(proxy_port).strip()
    if not host:
        return None, None, "Proxy host is required."

    parsed_port = raw_port
    if "://" in host:
        try:
            parsed = urlsplit(host)
            if parsed.scheme.lower() not in {"http", "https"}:
                return None, None, "Invalid proxy host."
            if parsed.username is not None or parsed.password is not None:
                return None, None, "Proxy host must not include embedded credentials."
        except Exception:
            return None, None, "Invalid proxy host."
        try:
            inline_port = parsed.port
        except ValueError:
            return None, None, "Invalid proxy port."
        if inline_port is not None:
            if inline_port < 1 or inline_port > 65535:
                return None, None, "Proxy port must be between 1 and 65535."
        if parsed.path or parsed.query or parsed.fragment:
            return None, None, "Invalid proxy host."
        if inline_port is not None:
            if parsed_port and parsed_port != str(inline_port):
                return None, None, "Conflicting proxy ports."
            parsed_port = str(inline_port)
        host = parsed.hostname or ""
    elif host.startswith("[") and "]" in host:
        end = host.find("]")
        suffix = host[end + 1 :].strip()
        host = host[1:end]
        if suffix:
            if not suffix.startswith(":") or not suffix[1:].isdigit():
                return None, None, "Invalid proxy port."
            if parsed_port and parsed_port != suffix[1:]:
                return None, None, "Conflicting proxy ports."
            parsed_port = suffix[1:]
    elif host.count(":") == 1:
        candidate_host, candidate_port = host.rsplit(":", 1)
        if not parsed_port:
            if candidate_port.isdigit():
                host = candidate_host
                parsed_port = candidate_port
            else:
                return None, None, "Invalid proxy port."

    host = host.strip().strip("[]").lower().removesuffix(".")
    if not _is_valid_proxy_host(host):
        return None, None, "Invalid proxy host."

    try:
        port = int(parsed_port or "3128")
    except Exception:
        return None, None, "Invalid proxy port."
    if port < 1 or port > 65535:
        return None, None, "Proxy port must be between 1 and 65535."
    return host, port, ""


class PacProfilesStore:
    def __init__(self) -> None:
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
                try:
                    from services.schema_lifecycle import (
                        runtime_schema_ready_for_lazy_store,
                    )

                    if runtime_schema_ready_for_lazy_store(conn):
                        self._schema_ready = True
                        return
                except Exception:
                    pass
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS pac_profiles (
                        id BIGINT PRIMARY KEY AUTO_INCREMENT,
                        proxy_id VARCHAR(64) NOT NULL DEFAULT 'default',
                        name VARCHAR(255) NOT NULL,
                        client_cidr VARCHAR(64) NOT NULL DEFAULT '',
                        created_ts BIGINT NOT NULL,
                        KEY idx_pac_profiles_created (created_ts, id),
                        KEY idx_pac_profiles_proxy (proxy_id, id)
                    )
                    """,
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS pac_direct_domains (
                        profile_id BIGINT NOT NULL,
                        domain VARCHAR(255) NOT NULL,
                        PRIMARY KEY(profile_id, domain)
                    )
                    """,
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS pac_direct_dst_nets (
                        profile_id BIGINT NOT NULL,
                        cidr VARCHAR(64) NOT NULL,
                        PRIMARY KEY(profile_id, cidr)
                    )
                    """,
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS pac_backup_proxies (
                        id BIGINT PRIMARY KEY AUTO_INCREMENT,
                        proxy_id VARCHAR(64) NOT NULL DEFAULT 'default',
                        proxy_host VARCHAR(255) NOT NULL,
                        proxy_port INT NOT NULL DEFAULT 3128,
                        position INT NOT NULL DEFAULT 0,
                        created_ts BIGINT NOT NULL,
                        KEY idx_pac_backup_proxies_proxy_position (proxy_id, position, id)
                    )
                    """,
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS pac_proxy_chain_settings (
                        proxy_id VARCHAR(64) PRIMARY KEY,
                        direct_enabled TINYINT(1) NOT NULL DEFAULT 1,
                        updated_ts BIGINT NOT NULL
                    )
                    """,
                )
            self._schema_ready = True

    def list_profiles(self) -> list[PacProfile]:
        self.init_db()
        proxy_id = get_proxy_id()
        with self._connect() as conn:
            profiles = conn.execute(
                "SELECT id, name, client_cidr, created_ts FROM pac_profiles WHERE proxy_id=%s ORDER BY id ASC",
                (proxy_id,),
            ).fetchall()
            if not profiles:
                return []

            profile_ids = [int(p["id"]) for p in profiles]
            placeholders = ",".join(["%s"] * len(profile_ids))

            domains_by_profile: dict[int, list[str]] = {pid: [] for pid in profile_ids}
            domain_rows = conn.execute(
                f"SELECT profile_id, domain FROM pac_direct_domains WHERE profile_id IN ({placeholders}) ORDER BY profile_id ASC, domain ASC",
                tuple(profile_ids),
            ).fetchall()
            for row in domain_rows:
                domain, _err = _normalize_domain(str(row["domain"]))
                if not domain:
                    continue
                profile_domains = domains_by_profile.setdefault(
                    int(row["profile_id"]),
                    [],
                )
                if domain not in profile_domains:
                    profile_domains.append(domain)

            nets_by_profile: dict[int, list[str]] = {pid: [] for pid in profile_ids}
            net_rows = conn.execute(
                f"SELECT profile_id, cidr FROM pac_direct_dst_nets WHERE profile_id IN ({placeholders}) ORDER BY profile_id ASC, cidr ASC",
                tuple(profile_ids),
            ).fetchall()
            for row in net_rows:
                cidr, _err = _normalize_pac_dst_v4_cidr(str(row["cidr"]))
                if not cidr:
                    continue
                profile_nets = nets_by_profile.setdefault(
                    int(row["profile_id"]),
                    [],
                )
                if cidr not in profile_nets:
                    profile_nets.append(cidr)

            res: list[PacProfile] = []
            for p in profiles:
                pid = int(p["id"])
                res.append(
                    PacProfile(
                        id=pid,
                        name=str(p["name"]),
                        client_cidr=str(p["client_cidr"] or ""),
                        direct_domains=domains_by_profile.get(pid, []),
                        direct_dst_nets=nets_by_profile.get(pid, []),
                        created_ts=int(p["created_ts"] or 0),
                    ),
                )
            return res

    def list_proxy_chain_settings(self) -> PacProxyChainSettings:
        self.init_db()
        proxy_id = get_proxy_id()
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, proxy_host, proxy_port, position, created_ts
                FROM pac_backup_proxies
                WHERE proxy_id=%s
                ORDER BY position ASC, id ASC
                """,
                (proxy_id,),
            ).fetchall()
            setting = conn.execute(
                "SELECT direct_enabled FROM pac_proxy_chain_settings WHERE proxy_id=%s LIMIT 1",
                (proxy_id,),
            ).fetchone()

        backups: list[PacBackupProxy] = []
        for row in rows:
            host, port, _err = _normalize_proxy_host_port(
                str(row["proxy_host"] or ""),
                row["proxy_port"],
            )
            if host is None or port is None:
                continue
            backups.append(
                PacBackupProxy(
                    id=int(row["id"]),
                    proxy_host=host,
                    proxy_port=port,
                    position=int(row["position"] or 0),
                    created_ts=int(row["created_ts"] or 0),
                ),
            )
        direct_enabled = (
            True if setting is None else bool(int(setting["direct_enabled"] or 0))
        )
        return PacProxyChainSettings(
            backup_proxies=backups,
            direct_enabled=direct_enabled,
        )

    def add_backup_proxy(
        self,
        *,
        proxy_host: str,
        proxy_port: object | None = None,
    ) -> tuple[bool, str, int | None]:
        self.init_db()
        host, port, err = _normalize_proxy_host_port(proxy_host, proxy_port)
        if host is None or port is None:
            return False, err, None

        with self._connect() as conn:
            with guarded_proxy_write(conn, get_proxy_id()) as guard:
                proxy_id = guard.proxy_id
                row = conn.execute(
                    "SELECT COALESCE(MAX(position), 0) AS max_position FROM pac_backup_proxies WHERE proxy_id=%s",
                    (proxy_id,),
                ).fetchone()
                position = int(row["max_position"] or 0) + 1 if row else 1
                cur = conn.execute(
                    """
                    INSERT INTO pac_backup_proxies(proxy_id, proxy_host, proxy_port, position, created_ts)
                    VALUES(%s,%s,%s,%s,%s)
                    """,
                    (proxy_id, host, port, position, _now()),
                )
                return True, "", int(cur.lastrowid)

    def _resequence_backup_proxies(self, conn, proxy_id: str) -> list[int]:
        rows = conn.execute(
            "SELECT id FROM pac_backup_proxies WHERE proxy_id=%s ORDER BY position ASC, id ASC",
            (proxy_id,),
        ).fetchall()
        ordered_ids = [int(row["id"]) for row in rows]
        for idx, proxy_id_value in enumerate(ordered_ids, start=1):
            conn.execute(
                "UPDATE pac_backup_proxies SET position=%s WHERE id=%s",
                (idx, proxy_id_value),
            )
        return ordered_ids

    def delete_backup_proxy(self, backup_proxy_id: int) -> bool:
        self.init_db()
        bid = int(backup_proxy_id)
        with self._connect() as conn:
            with guarded_proxy_write(conn, get_proxy_id()) as guard:
                proxy_id = guard.proxy_id
                existing = conn.execute(
                    "SELECT 1 FROM pac_backup_proxies WHERE id=%s AND proxy_id=%s LIMIT 1",
                    (bid, proxy_id),
                ).fetchone()
                if existing is None:
                    return False
                conn.execute(
                    "DELETE FROM pac_backup_proxies WHERE id=%s AND proxy_id=%s",
                    (bid, proxy_id),
                )
                self._resequence_backup_proxies(conn, proxy_id)
                return True

    def move_backup_proxy(self, backup_proxy_id: int, direction: str) -> bool:
        self.init_db()
        bid = int(backup_proxy_id)
        normalized_direction = (direction or "").strip().lower()
        with self._connect() as conn:
            with guarded_proxy_write(conn, get_proxy_id()) as guard:
                proxy_id = guard.proxy_id
                ordered_ids = self._resequence_backup_proxies(conn, proxy_id)
                if bid not in ordered_ids:
                    return False
                index = ordered_ids.index(bid)
                if normalized_direction == "up" and index > 0:
                    ordered_ids[index - 1], ordered_ids[index] = (
                        ordered_ids[index],
                        ordered_ids[index - 1],
                    )
                elif normalized_direction == "down" and index < len(ordered_ids) - 1:
                    ordered_ids[index + 1], ordered_ids[index] = (
                        ordered_ids[index],
                        ordered_ids[index + 1],
                    )
                else:
                    return False
                for idx, proxy_id_value in enumerate(ordered_ids, start=1):
                    conn.execute(
                        "UPDATE pac_backup_proxies SET position=%s WHERE id=%s",
                        (idx, proxy_id_value),
                    )
                return True

    def set_direct_enabled(self, enabled: bool) -> None:
        self.init_db()
        with self._connect() as conn:
            with guarded_proxy_write(conn, get_proxy_id()) as guard:
                conn.execute(
                    """
                    INSERT INTO pac_proxy_chain_settings(proxy_id, direct_enabled, updated_ts)
                    VALUES(%s,%s,%s) AS incoming
                    ON DUPLICATE KEY UPDATE direct_enabled=incoming.direct_enabled, updated_ts=incoming.updated_ts
                    """,
                    (guard.proxy_id, 1 if enabled else 0, _now()),
                )

    def upsert_profile(
        self,
        *,
        profile_id: int | None,
        name: str,
        client_cidr: str,
        direct_domains_text: str,
        direct_dst_nets_text: str,
        **_ignored: object,
    ) -> tuple[bool, str, int | None]:
        self.init_db()

        nm = (name or "").strip()
        if not nm:
            return False, "Name is required.", None

        cidr_norm, err = _normalize_client_cidr(client_cidr)
        if cidr_norm is None:
            return False, err, None

        domains: list[str] = []
        for ln in (direct_domains_text or "").splitlines():
            d, derr = _normalize_domain(ln)
            if d is None:
                if derr:
                    return False, derr, None
                continue
            if d not in domains:
                domains.append(d)

        nets: list[str] = []
        for ln in (direct_dst_nets_text or "").splitlines():
            c, cerr = _normalize_pac_dst_v4_cidr(ln)
            if c is None:
                return False, cerr, None
            if not c:
                continue
            if c not in nets:
                nets.append(c)

        with self._connect() as conn:
            with guarded_proxy_write(conn, get_proxy_id()) as guard:
                proxy_id = guard.proxy_id
                if profile_id is None:
                    cur = conn.execute(
                        "INSERT INTO pac_profiles(proxy_id, name, client_cidr, created_ts) VALUES(%s,%s,%s,%s)",
                        (proxy_id, nm, cidr_norm or "", _now()),
                    )
                    pid = int(cur.lastrowid)
                else:
                    pid = int(profile_id)
                    existing = conn.execute(
                        "SELECT 1 FROM pac_profiles WHERE id=%s AND proxy_id=%s LIMIT 1",
                        (pid, proxy_id),
                    ).fetchone()
                    if existing is None:
                        return False, "Profile not found.", None
                    conn.execute(
                        "UPDATE pac_profiles SET name=%s, client_cidr=%s WHERE id=%s AND proxy_id=%s",
                        (nm, cidr_norm or "", pid, proxy_id),
                    )

                    # Clear old rules.
                    conn.execute(
                        "DELETE FROM pac_direct_domains WHERE profile_id=%s",
                        (pid,),
                    )
                    conn.execute(
                        "DELETE FROM pac_direct_dst_nets WHERE profile_id=%s",
                        (pid,),
                    )

                for d in domains:
                    conn.execute(
                        "INSERT IGNORE INTO pac_direct_domains(profile_id, domain) VALUES(%s,%s)",
                        (pid, d),
                    )
                for c in nets:
                    conn.execute(
                        "INSERT IGNORE INTO pac_direct_dst_nets(profile_id, cidr) VALUES(%s,%s)",
                        (pid, c),
                    )

        return True, "", pid

    def delete_profile(self, profile_id: int) -> bool:
        self.init_db()
        pid = int(profile_id)
        with self._connect() as conn:
            with guarded_proxy_write(conn, get_proxy_id()) as guard:
                proxy_id = guard.proxy_id
                row = conn.execute(
                    "SELECT 1 FROM pac_profiles WHERE id=%s AND proxy_id=%s LIMIT 1",
                    (pid, proxy_id),
                ).fetchone()
                if row is None:
                    return False
                conn.execute(
                    "DELETE FROM pac_direct_domains WHERE profile_id=%s", (pid,)
                )
                conn.execute(
                    "DELETE FROM pac_direct_dst_nets WHERE profile_id=%s", (pid,)
                )
                conn.execute(
                    "DELETE FROM pac_profiles WHERE id=%s AND proxy_id=%s",
                    (pid, proxy_id),
                )
                return True

    def match_profile_for_client_ip(self, client_ip: str) -> PacProfile | None:
        """Return the effective profile for client_ip.

        Matching order mirrors the materialized PAC manifest selector:
        - the matching client_cidr profile with the longest prefix, then lowest id
        - then the first empty-client_cidr catch-all profile, by id
        """
        profiles = self.list_profiles()
        if not profiles:
            return None

        try:
            ip = ip_address((client_ip or "").strip())
        except Exception:
            ip = None

        def id_key(p: PacProfile) -> int:
            return int(p.id)

        matches: list[tuple[int, int, PacProfile]] = []
        for p in profiles:
            if not p.client_cidr or ip is None:
                continue
            try:
                net = ip_network(p.client_cidr, strict=False)
            except Exception:
                continue
            if ip.version != net.version:
                continue
            if ip in net:
                matches.append((int(net.prefixlen), id_key(p), p))

        if matches:
            return min(matches, key=lambda item: (-item[0], item[1]))[2]

        # Fall back to the first catch-all (if any). Keep this behavior for
        # malformed or unavailable client IPs so diagnostics match PAC serving.
        for p in sorted(profiles, key=id_key):
            if not p.client_cidr:
                return p

        return None


_store: PacProfilesStore | None = None
_store_lock = threading.Lock()


def get_pac_profiles_store() -> PacProfilesStore:
    global _store
    if _store is not None:
        return _store
    with _store_lock:
        if _store is None:
            _store = PacProfilesStore()
        return _store
