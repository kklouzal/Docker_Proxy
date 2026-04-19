#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import os
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence


HERE = Path(__file__).resolve().parent
APP_ROOT = HERE.parent
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

from services.adblock_store import AdblockStore
from services.audit_store import AuditStore
from services.auth_store import AuthStore
from services.db import connect, using_mysql
from services.exclusions_store import ExclusionsStore
from services.live_stats import LiveStatsStore
from services.pac_profiles_store import PacProfilesStore
from services.socks_store import SocksStore
from services.ssl_errors_store import SslErrorsStore
from services.sslfilter_store import SslFilterStore
from services.timeseries_store import RESOLUTIONS, TimeSeriesStore
from services.webfilter_store import WebFilterStore


EXCLUSIONS_DOMAINS_TABLE = "exclusions_domains"
EXCLUSIONS_DST_TABLE = "exclusions_dst_nets"
EXCLUSIONS_SRC_TABLE = "exclusions_src_nets"
EXCLUSIONS_SETTINGS_TABLE = "exclusions_settings"

LIVE_STATS_DOMAINS_TABLE = "live_stats_domains"
LIVE_STATS_CLIENTS_TABLE = "live_stats_clients"
LIVE_STATS_CLIENT_DOMAINS_TABLE = "live_stats_client_domains"
LIVE_STATS_NO_CACHE_TABLE = "live_stats_client_domain_nocache"

WEBFILTER_SETTINGS_TABLE = "webfilter_settings"
WEBFILTER_META_TABLE = "webfilter_meta"
WEBFILTER_WHITELIST_TABLE = "webfilter_whitelist"
WEBFILTER_BLOCKED_LOG_TABLE = "webfilter_blocked_log"


def _now() -> int:
    return int(time.time())


def _sha1(*parts: object) -> str:
    h = hashlib.sha1()
    for part in parts:
        h.update(str(part).encode("utf-8", errors="replace"))
        h.update(b"|")
    return h.hexdigest()


def _sqlite_connect(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path), timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def _sqlite_table_exists(conn: sqlite3.Connection, table_name: str) -> bool:
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    ).fetchone()
    return row is not None


def _rows(conn: sqlite3.Connection, query: str, params: Sequence[Any] = ()) -> list[sqlite3.Row]:
    return list(conn.execute(query, tuple(params)).fetchall())


def _ensure_schema() -> None:
    AuthStore().ensure_schema()
    AuditStore().init_db()
    ExclusionsStore().init_db()
    PacProfilesStore().init_db()
    SslFilterStore().init_db()
    SslErrorsStore().init_db()
    SocksStore().init_db()
    TimeSeriesStore().init_db()
    LiveStatsStore().init_db()
    AdblockStore().init_db()
    WebFilterStore().init_db()

    with connect() as conn:
        if conn.is_mysql:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS webcat_domains (
                    domain VARCHAR(255) PRIMARY KEY,
                    categories TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS webcat_categories (
                    category VARCHAR(128) PRIMARY KEY,
                    domains BIGINT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS webcat_meta (
                    k VARCHAR(64) PRIMARY KEY,
                    v LONGTEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS webcat_aliases (
                    alias VARCHAR(128) PRIMARY KEY,
                    canonical VARCHAR(128) NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS migration_meta (
                    k VARCHAR(128) PRIMARY KEY,
                    v LONGTEXT NOT NULL
                )
                """
            )
        else:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS webcat_domains (
                    domain TEXT PRIMARY KEY,
                    categories TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS webcat_categories (
                    category TEXT PRIMARY KEY,
                    domains INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS webcat_meta (
                    k TEXT PRIMARY KEY,
                    v TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS webcat_aliases (
                    alias TEXT PRIMARY KEY,
                    canonical TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS migration_meta (
                    k TEXT PRIMARY KEY,
                    v TEXT NOT NULL
                )
                """
            )


def _get_marker() -> str:
    with connect() as conn:
        row = conn.execute("SELECT v FROM migration_meta WHERE k='sqlite_import_v1'").fetchone()
        return str(row[0]) if row and row[0] is not None else ""


def _set_marker(value: str) -> None:
    with connect() as conn:
        conn.execute(
            "INSERT INTO migration_meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
            ("sqlite_import_v1", value),
        )


def _batch(seq: list[tuple[Any, ...]], size: int = 500) -> Iterable[list[tuple[Any, ...]]]:
    for i in range(0, len(seq), size):
        yield seq[i : i + size]


def _exec_many(sql: str, rows: list[tuple[Any, ...]]) -> None:
    if not rows:
        return
    with connect() as conn:
        for chunk in _batch(rows):
            conn.executemany(sql, chunk)


def _import_if_exists(data_dir: Path, name: str, fn: Callable[[Path], int]) -> int:
    path = data_dir / name
    if not path.exists():
        return 0
    return fn(path)


def _import_auth(path: Path) -> int:
    with _sqlite_connect(path) as src:
        if not _sqlite_table_exists(src, "users"):
            return 0
        rows = [
            (str(r["username"]), str(r["password_hash"]), int(r["created_ts"] or 0), int(r["updated_ts"] or 0))
            for r in _rows(src, "SELECT username, password_hash, created_ts, updated_ts FROM users")
        ]
    _exec_many(
        """
        INSERT INTO users(username, password_hash, created_ts, updated_ts)
        VALUES(?,?,?,?)
        ON CONFLICT(username) DO UPDATE SET
            password_hash=excluded.password_hash,
            created_ts=excluded.created_ts,
            updated_ts=excluded.updated_ts
        """,
        rows,
    )
    return len(rows)


def _import_audit(path: Path) -> int:
    with _sqlite_connect(path) as src:
        if not _sqlite_table_exists(src, "audit_events"):
            return 0
        rows = [
            (
                int(r["id"] or 0),
                int(r["ts"] or 0),
                str(r["kind"] or ""),
                int(r["ok"] or 0),
                str(r["remote_addr"] or "") or None,
                str(r["user_agent"] or "") or None,
                str(r["detail"] or "") or None,
                str(r["config_sha256"] or "") or None,
                str(r["config_text"] or "") or None,
            )
            for r in _rows(src, "SELECT id, ts, kind, ok, remote_addr, user_agent, detail, config_sha256, config_text FROM audit_events")
        ]
    _exec_many(
        """
        INSERT INTO audit_events(id, ts, kind, ok, remote_addr, user_agent, detail, config_sha256, config_text)
        VALUES(?,?,?,?,?,?,?,?,?)
        ON CONFLICT(id) DO UPDATE SET
            ts=excluded.ts,
            kind=excluded.kind,
            ok=excluded.ok,
            remote_addr=excluded.remote_addr,
            user_agent=excluded.user_agent,
            detail=excluded.detail,
            config_sha256=excluded.config_sha256,
            config_text=excluded.config_text
        """,
        rows,
    )
    return len(rows)


def _import_exclusions(path: Path) -> int:
    count = 0
    with _sqlite_connect(path) as src:
        if _sqlite_table_exists(src, "domains"):
            rows = [(str(r["domain"]),) for r in _rows(src, "SELECT domain FROM domains")]
            _exec_many(f"INSERT OR IGNORE INTO {EXCLUSIONS_DOMAINS_TABLE}(domain) VALUES(?)", rows)
            count += len(rows)
        if _sqlite_table_exists(src, "dst_nets"):
            rows = [(str(r["cidr"]),) for r in _rows(src, "SELECT cidr FROM dst_nets")]
            _exec_many(f"INSERT OR IGNORE INTO {EXCLUSIONS_DST_TABLE}(cidr) VALUES(?)", rows)
            count += len(rows)
        if _sqlite_table_exists(src, "src_nets"):
            rows = [(str(r["cidr"]),) for r in _rows(src, "SELECT cidr FROM src_nets")]
            _exec_many(f"INSERT OR IGNORE INTO {EXCLUSIONS_SRC_TABLE}(cidr) VALUES(?)", rows)
            count += len(rows)
        if _sqlite_table_exists(src, "settings"):
            rows = [(str(r["key"]), str(r["value"])) for r in _rows(src, "SELECT key, value FROM settings")]
            _exec_many(
                f"INSERT INTO {EXCLUSIONS_SETTINGS_TABLE}(`key`, value) VALUES(?,?) ON CONFLICT(`key`) DO UPDATE SET value=excluded.value",
                rows,
            )
            count += len(rows)
    return count


def _import_pac_profiles(path: Path) -> int:
    total = 0
    with _sqlite_connect(path) as src:
        if _sqlite_table_exists(src, "pac_profiles"):
            rows = [
                (
                    int(r["id"] or 0),
                    str(r["name"] or ""),
                    str(r["client_cidr"] or ""),
                    int(r["socks_enabled"] or 0),
                    str(r["socks_host"] or ""),
                    int(r["socks_port"] or 1080),
                    int(r["created_ts"] or 0),
                )
                for r in _rows(src, "SELECT id, name, client_cidr, socks_enabled, socks_host, socks_port, created_ts FROM pac_profiles")
            ]
            _exec_many(
                """
                INSERT INTO pac_profiles(id, name, client_cidr, socks_enabled, socks_host, socks_port, created_ts)
                VALUES(?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET
                    name=excluded.name,
                    client_cidr=excluded.client_cidr,
                    socks_enabled=excluded.socks_enabled,
                    socks_host=excluded.socks_host,
                    socks_port=excluded.socks_port,
                    created_ts=excluded.created_ts
                """,
                rows,
            )
            total += len(rows)
        if _sqlite_table_exists(src, "pac_direct_domains"):
            rows = [(int(r["profile_id"] or 0), str(r["domain"] or "")) for r in _rows(src, "SELECT profile_id, domain FROM pac_direct_domains")]
            _exec_many("INSERT OR IGNORE INTO pac_direct_domains(profile_id, domain) VALUES(?,?)", rows)
            total += len(rows)
        if _sqlite_table_exists(src, "pac_direct_dst_nets"):
            rows = [(int(r["profile_id"] or 0), str(r["cidr"] or "")) for r in _rows(src, "SELECT profile_id, cidr FROM pac_direct_dst_nets")]
            _exec_many("INSERT OR IGNORE INTO pac_direct_dst_nets(profile_id, cidr) VALUES(?,?)", rows)
            total += len(rows)
    return total


def _import_sslfilter(path: Path) -> int:
    with _sqlite_connect(path) as src:
        if not _sqlite_table_exists(src, "nobump_cidrs"):
            return 0
        rows = [(str(r["cidr"]), int(r["added_ts"] or 0)) for r in _rows(src, "SELECT cidr, added_ts FROM nobump_cidrs")]
    _exec_many(
        "INSERT INTO nobump_cidrs(cidr, added_ts) VALUES(?,?) ON CONFLICT(cidr) DO UPDATE SET added_ts=excluded.added_ts",
        rows,
    )
    return len(rows)


def _import_ssl_errors(path: Path) -> int:
    with _sqlite_connect(path) as src:
        if not _sqlite_table_exists(src, "ssl_errors"):
            return 0
        rows = []
        for r in _rows(src, "SELECT domain, category, reason, count, first_seen, last_seen, sample FROM ssl_errors"):
            domain = str(r["domain"] or "")
            category = str(r["category"] or "")
            reason = str(r["reason"] or "")
            rows.append(
                (
                    _sha1(domain, category, reason),
                    domain,
                    category,
                    reason,
                    int(r["count"] or 0),
                    int(r["first_seen"] or 0),
                    int(r["last_seen"] or 0),
                    str(r["sample"] or ""),
                )
            )
    _exec_many(
        """
        INSERT INTO ssl_errors(row_key, domain, category, reason, count, first_seen, last_seen, sample)
        VALUES(?,?,?,?,?,?,?,?)
        ON CONFLICT(row_key) DO UPDATE SET
            domain=excluded.domain,
            category=excluded.category,
            reason=excluded.reason,
            count=excluded.count,
            first_seen=excluded.first_seen,
            last_seen=excluded.last_seen,
            sample=excluded.sample
        """,
        rows,
    )
    return len(rows)


def _import_socks(path: Path) -> int:
    with _sqlite_connect(path) as src:
        if not _sqlite_table_exists(src, "socks_events"):
            return 0
        rows = [
            (
                int(r["id"] or 0),
                int(r["ts"] or 0),
                str(r["action"] or ""),
                str(r["protocol"] or ""),
                str(r["src_ip"] or ""),
                int(r["src_port"] or 0),
                str(r["dst"] or ""),
                int(r["dst_port"] or 0),
                str(r["msg"] or ""),
            )
            for r in _rows(src, "SELECT id, ts, action, protocol, src_ip, src_port, dst, dst_port, msg FROM socks_events")
        ]
    _exec_many(
        """
        INSERT INTO socks_events(id, ts, action, protocol, src_ip, src_port, dst, dst_port, msg)
        VALUES(?,?,?,?,?,?,?,?,?)
        ON CONFLICT(id) DO UPDATE SET
            ts=excluded.ts,
            action=excluded.action,
            protocol=excluded.protocol,
            src_ip=excluded.src_ip,
            src_port=excluded.src_port,
            dst=excluded.dst,
            dst_port=excluded.dst_port,
            msg=excluded.msg
        """,
        rows,
    )
    return len(rows)


def _import_timeseries(path: Path) -> int:
    total = 0
    with _sqlite_connect(path) as src:
        for res in RESOLUTIONS:
            if not _sqlite_table_exists(src, res.table):
                continue
            rows = [
                (
                    int(r["ts"] or 0),
                    int(r["count"] or 0),
                    r["cpu"],
                    r["mem"],
                    r["disk_used"],
                    r["cache_dir_size"],
                    r["hit_rate"],
                )
                for r in _rows(src, f"SELECT ts, count, cpu, mem, disk_used, cache_dir_size, hit_rate FROM {res.table}")
            ]
            _exec_many(
                f"INSERT OR REPLACE INTO {res.table}(ts, count, cpu, mem, disk_used, cache_dir_size, hit_rate) VALUES(?,?,?,?,?,?,?)",
                rows,
            )
            total += len(rows)
    return total


def _import_live_stats(path: Path) -> int:
    total = 0
    with _sqlite_connect(path) as src:
        if _sqlite_table_exists(src, "domains"):
            rows = [
                (
                    str(r["domain"]),
                    int(r["requests"] or 0),
                    int(r["hit_requests"] or 0),
                    int(r["bytes"] or 0),
                    int(r["hit_bytes"] or 0),
                    int(r["first_seen"] or 0),
                    int(r["last_seen"] or 0),
                )
                for r in _rows(src, "SELECT domain, requests, hit_requests, bytes, hit_bytes, first_seen, last_seen FROM domains")
            ]
            _exec_many(
                """
                INSERT INTO live_stats_domains(domain, requests, hit_requests, bytes, hit_bytes, first_seen, last_seen)
                VALUES(?,?,?,?,?,?,?)
                ON CONFLICT(domain) DO UPDATE SET
                    requests=excluded.requests,
                    hit_requests=excluded.hit_requests,
                    bytes=excluded.bytes,
                    hit_bytes=excluded.hit_bytes,
                    first_seen=excluded.first_seen,
                    last_seen=excluded.last_seen
                """,
                rows,
            )
            total += len(rows)
        if _sqlite_table_exists(src, "clients"):
            rows = [
                (
                    str(r["ip"]),
                    int(r["requests"] or 0),
                    int(r["hit_requests"] or 0),
                    int(r["bytes"] or 0),
                    int(r["hit_bytes"] or 0),
                    int(r["first_seen"] or 0),
                    int(r["last_seen"] or 0),
                )
                for r in _rows(src, "SELECT ip, requests, hit_requests, bytes, hit_bytes, first_seen, last_seen FROM clients")
            ]
            _exec_many(
                """
                INSERT INTO live_stats_clients(ip, requests, hit_requests, bytes, hit_bytes, first_seen, last_seen)
                VALUES(?,?,?,?,?,?,?)
                ON CONFLICT(ip) DO UPDATE SET
                    requests=excluded.requests,
                    hit_requests=excluded.hit_requests,
                    bytes=excluded.bytes,
                    hit_bytes=excluded.hit_bytes,
                    first_seen=excluded.first_seen,
                    last_seen=excluded.last_seen
                """,
                rows,
            )
            total += len(rows)
        if _sqlite_table_exists(src, "client_domains"):
            rows = [
                (
                    str(r["ip"]),
                    str(r["domain"]),
                    int(r["requests"] or 0),
                    int(r["hit_requests"] or 0),
                    int(r["bytes"] or 0),
                    int(r["hit_bytes"] or 0),
                    int(r["first_seen"] or 0),
                    int(r["last_seen"] or 0),
                )
                for r in _rows(src, "SELECT ip, domain, requests, hit_requests, bytes, hit_bytes, first_seen, last_seen FROM client_domains")
            ]
            _exec_many(
                """
                INSERT INTO live_stats_client_domains(ip, domain, requests, hit_requests, bytes, hit_bytes, first_seen, last_seen)
                VALUES(?,?,?,?,?,?,?,?)
                ON CONFLICT(ip, domain) DO UPDATE SET
                    requests=excluded.requests,
                    hit_requests=excluded.hit_requests,
                    bytes=excluded.bytes,
                    hit_bytes=excluded.hit_bytes,
                    first_seen=excluded.first_seen,
                    last_seen=excluded.last_seen
                """,
                rows,
            )
            total += len(rows)
        if _sqlite_table_exists(src, "client_domain_nocache"):
            rows = []
            for r in _rows(src, "SELECT ip, domain, reason, requests, first_seen, last_seen FROM client_domain_nocache"):
                ip = str(r["ip"] or "")
                domain = str(r["domain"] or "")
                reason = str(r["reason"] or "")
                rows.append(
                    (
                        _sha1(ip, domain, reason),
                        ip,
                        domain,
                        reason,
                        int(r["requests"] or 0),
                        int(r["first_seen"] or 0),
                        int(r["last_seen"] or 0),
                    )
                )
            _exec_many(
                """
                INSERT INTO live_stats_client_domain_nocache(row_key, ip, domain, reason, requests, first_seen, last_seen)
                VALUES(?,?,?,?,?,?,?)
                ON CONFLICT(row_key) DO UPDATE SET
                    ip=excluded.ip,
                    domain=excluded.domain,
                    reason=excluded.reason,
                    requests=excluded.requests,
                    first_seen=excluded.first_seen,
                    last_seen=excluded.last_seen
                """,
                rows,
            )
            total += len(rows)
    return total


def _import_adblock(path: Path) -> int:
    total = 0
    with _sqlite_connect(path) as src:
        for table, cols, upsert_key in [
            ("adblock_lists", ["key", "url", "enabled", "last_success", "last_attempt", "last_error", "bytes", "rules"], "`key`"),
            ("adblock_meta", ["k", "v"], "k"),
            ("adblock_cache_stats", ["k", "v"], "k"),
            ("adblock_settings", ["k", "v"], "k"),
        ]:
            if not _sqlite_table_exists(src, table):
                continue
            query = f"SELECT {', '.join(cols)} FROM {table}"
            rows = [tuple(r[c] for c in cols) for r in _rows(src, query)]
            updates = ", ".join([f"{c}=excluded.{c}" for c in cols if c != cols[0]])
            insert_cols = ["`key`" if c == "key" else c for c in cols]
            _exec_many(
                f"INSERT INTO {table}({', '.join(insert_cols)}) VALUES({', '.join(['?'] * len(cols))}) ON CONFLICT({upsert_key}) DO UPDATE SET {updates}",
                rows,
            )
            total += len(rows)

        if _sqlite_table_exists(src, "adblock_counts"):
            rows = [
                (int(r["day"] or 0), str(r["list_key"] or ""), int(r["blocked"] or 0))
                for r in _rows(src, "SELECT day, list_key, blocked FROM adblock_counts")
            ]
            _exec_many(
                "INSERT INTO adblock_counts(day, list_key, blocked) VALUES(?,?,?) ON CONFLICT(day, list_key) DO UPDATE SET blocked=excluded.blocked",
                rows,
            )
            total += len(rows)

        if _sqlite_table_exists(src, "adblock_events"):
            rows = []
            for r in _rows(src, "SELECT ts, src_ip, method, url, http_status, http_resp_line, icap_status, raw, created_ts FROM adblock_events"):
                ts = int(r["ts"] or 0)
                src_ip = str(r["src_ip"] or "-")
                url = str(r["url"] or "")
                http_status = int(r["http_status"] or 0)
                rows.append(
                    (
                        _sha1(ts, src_ip, url, http_status),
                        ts,
                        src_ip,
                        str(r["method"] or "-"),
                        url,
                        http_status,
                        str(r["http_resp_line"] or ""),
                        int(r["icap_status"] or 0),
                        str(r["raw"] or ""),
                        int(r["created_ts"] or 0),
                    )
                )
            _exec_many(
                "INSERT OR IGNORE INTO adblock_events(event_key, ts, src_ip, method, url, http_status, http_resp_line, icap_status, raw, created_ts) VALUES(?,?,?,?,?,?,?,?,?,?)",
                rows,
            )
            total += len(rows)
    return total


def _import_webfilter(path: Path) -> int:
    total = 0
    with _sqlite_connect(path) as src:
        for table, cols, keycol in [
            (WEBFILTER_SETTINGS_TABLE, ["k", "v"], "k"),
            (WEBFILTER_META_TABLE, ["k", "v"], "k"),
        ]:
            legacy_table = "settings" if table == WEBFILTER_SETTINGS_TABLE else "meta"
            if not _sqlite_table_exists(src, legacy_table):
                continue
            rows = [tuple(r[c] for c in cols) for r in _rows(src, f"SELECT {', '.join(cols)} FROM {legacy_table}")]
            updates = ", ".join([f"{c}=excluded.{c}" for c in cols if c != keycol])
            _exec_many(
                f"INSERT INTO {table}({', '.join(cols)}) VALUES({', '.join(['?'] * len(cols))}) ON CONFLICT({keycol}) DO UPDATE SET {updates}",
                rows,
            )
            total += len(rows)

        if _sqlite_table_exists(src, "whitelist"):
            rows = [(str(r["pattern"] or ""), int(r["added_ts"] or 0)) for r in _rows(src, "SELECT pattern, added_ts FROM whitelist")]
            _exec_many(
                f"INSERT INTO {WEBFILTER_WHITELIST_TABLE}(pattern, added_ts) VALUES(?,?) ON CONFLICT(pattern) DO UPDATE SET added_ts=excluded.added_ts",
                rows,
            )
            total += len(rows)

        if _sqlite_table_exists(src, "blocked_log"):
            rows = [
                (int(r["ts"] or 0), str(r["src_ip"] or ""), str(r["url"] or ""), str(r["category"] or ""))
                for r in _rows(src, "SELECT ts, src_ip, url, category FROM blocked_log")
            ]
            _exec_many(f"INSERT INTO {WEBFILTER_BLOCKED_LOG_TABLE}(ts, src_ip, url, category) VALUES(?,?,?,?)", rows)
            total += len(rows)
    return total


def _import_webcat(path: Path) -> int:
    total = 0
    with _sqlite_connect(path) as src:
        for table, cols, keycol in [
            ("webcat_domains", ["domain", "categories"], "domain"),
            ("webcat_categories", ["category", "domains"], "category"),
            ("webcat_meta", ["k", "v"], "k"),
            ("webcat_aliases", ["alias", "canonical"], "alias"),
        ]:
            if not _sqlite_table_exists(src, table):
                continue
            rows = [tuple(r[c] for c in cols) for r in _rows(src, f"SELECT {', '.join(cols)} FROM {table}")]
            updates = ", ".join([f"{c}=excluded.{c}" for c in cols if c != keycol])
            _exec_many(
                f"INSERT INTO {table}({', '.join(cols)}) VALUES({', '.join(['?'] * len(cols))}) ON CONFLICT({keycol}) DO UPDATE SET {updates}",
                rows,
            )
            total += len(rows)
    return total


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Import legacy SQLite state into the configured MySQL database.")
    ap.add_argument("--data-dir", default="/var/lib/squid-flask-proxy", help="Directory containing legacy *.db files")
    ap.add_argument("--force", action="store_true", help="Run even if the migration marker is already present")
    args = ap.parse_args(list(argv) if argv is not None else None)

    if not using_mysql(default_sqlite_path=str(Path(args.data_dir) / "auth.db")):
        print("[sqlite_to_mysql] MySQL is not configured; nothing to do", file=sys.stderr)
        return 0

    _ensure_schema()

    if _get_marker() and not args.force:
        print("[sqlite_to_mysql] migration already completed; skipping", file=sys.stderr)
        return 0

    data_dir = Path(args.data_dir)
    imported = {
        "auth": _import_if_exists(data_dir, "auth.db", _import_auth),
        "audit": _import_if_exists(data_dir, "audit.db", _import_audit),
        "exclusions": _import_if_exists(data_dir, "exclusions.db", _import_exclusions),
        "pac_profiles": _import_if_exists(data_dir, "pac_profiles.db", _import_pac_profiles),
        "sslfilter": _import_if_exists(data_dir, "sslfilter.db", _import_sslfilter),
        "ssl_errors": _import_if_exists(data_dir, "ssl_errors.db", _import_ssl_errors),
        "socks": _import_if_exists(data_dir, "socks.db", _import_socks),
        "timeseries": _import_if_exists(data_dir, "timeseries.db", _import_timeseries),
        "live_stats": _import_if_exists(data_dir, "live_stats.db", _import_live_stats),
        "adblock": _import_if_exists(data_dir, "adblock.db", _import_adblock),
        "webfilter": _import_if_exists(data_dir, "webfilter.db", _import_webfilter),
        "webcat": _import_if_exists(data_dir, "webcat.db", _import_webcat),
    }

    stamp = f"done:{_now()}:{sum(imported.values())}"
    _set_marker(stamp)
    print(f"[sqlite_to_mysql] imported rows: {imported}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
