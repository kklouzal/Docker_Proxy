#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import sqlite3
import sys
import time
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple


def _now() -> int:
    return int(time.time())


def _norm_domain(s: str) -> str:
    d = (s or "").strip().lower().rstrip(".")
    if d.startswith("."):
        d = d[1:]
    # Squid passes host:port sometimes
    if ":" in d:
        host, port = d.rsplit(":", 1)
        if port.isdigit():
            d = host
    # Also handle accidental scheme/path
    if "://" in d:
        d = d.split("://", 1)[1]
    d = d.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    return d


def _parent_domains(domain: str, *, max_levels: int = 6) -> Iterable[str]:
    d = _norm_domain(domain)
    if not d:
        return []
    parts = [p for p in d.split(".") if p]
    if len(parts) < 2:
        return [d]
    out = []
    # sub.example.co.uk -> try full, then drop left labels
    for i in range(0, min(len(parts) - 1, max_levels)):
        out.append(".".join(parts[i:]))
    return out


class _Db:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None
        self._last_open_attempt = 0

    def _connect(self) -> Optional[sqlite3.Connection]:
        now = _now()
        # Retry open at most once per second if DB missing during startup.
        if self._conn is not None:
            return self._conn
        if now == self._last_open_attempt:
            return None
        self._last_open_attempt = now
        try:
            conn = sqlite3.connect(self.db_path, timeout=2)
            conn.row_factory = sqlite3.Row
            self._conn = conn
            return conn
        except Exception:
            return None

    def lookup_categories(self, domain: str) -> Set[str]:
        conn = self._connect()
        if conn is None:
            return set()
        for cand in _parent_domains(domain):
            try:
                row = conn.execute(
                    "SELECT categories FROM webcat_domains WHERE domain=?",
                    (cand,),
                ).fetchone()
            except Exception:
                return set()
            if row and row[0]:
                raw = str(row[0])
                return {c for c in raw.split("|") if c}
        return set()


class _BlockedLogDb:
    def __init__(self, db_path: str, *, max_rows: int = 5000):
        self.db_path = db_path
        self.max_rows = int(max_rows) if max_rows else 5000
        self._conn: Optional[sqlite3.Connection] = None
        self._last_open_attempt = 0
        self._inserts = 0

    def _connect(self) -> Optional[sqlite3.Connection]:
        if not self.db_path:
            return None
        now = _now()
        if self._conn is not None:
            return self._conn
        if now == self._last_open_attempt:
            return None
        self._last_open_attempt = now
        try:
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            conn = sqlite3.connect(self.db_path, timeout=1)
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            conn.execute(
                "CREATE TABLE IF NOT EXISTS blocked_log("
                "ts INTEGER NOT NULL, "
                "src_ip TEXT NOT NULL, "
                "url TEXT NOT NULL, "
                "category TEXT NOT NULL"
                ");"
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_blocked_log_ts ON blocked_log(ts);")
            self._conn = conn
            return conn
        except Exception:
            return None

    def insert(self, *, ts: int, src_ip: str, url: str, category: str) -> None:
        conn = self._connect()
        if conn is None:
            return
        try:
            s_ip = (src_ip or "")[:128]
            s_url = (url or "")[:2000]
            s_cat = (category or "")[:128]
            if not s_ip or not s_url or not s_cat:
                return
            conn.execute(
                "INSERT INTO blocked_log(ts, src_ip, url, category) VALUES(?,?,?,?)",
                (int(ts), s_ip, s_url, s_cat),
            )
            conn.commit()
            self._inserts += 1
            # Periodic trimming to keep the DB bounded.
            if self.max_rows > 0 and (self._inserts % 100) == 0:
                conn.execute(
                    "DELETE FROM blocked_log WHERE rowid IN ("
                    "SELECT rowid FROM blocked_log ORDER BY ts DESC LIMIT -1 OFFSET ?"
                    ")",
                    (int(self.max_rows),),
                )
                conn.commit()
        except Exception:
            return


def _parse_line(line: str) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str], Optional[str]]:
    """Return (channel_id, src_ip, domain, url, category).

    Supported helper input formats:
      - "<domain> <category>"
      - "<channel> <domain> <category>"
      - "<src_ip> <domain> <url> <category>"
      - "<channel> <src_ip> <domain> <url> <category>"
    """

    t = (line or "").strip()
    if not t:
        return None, None, None, None, None
    parts = t.split()
    if not parts:
        return None, None, None, None, None

    channel_id: Optional[str] = None
    if parts and parts[0].isdigit():
        channel_id = parts[0]
        parts = parts[1:]

    # New format: src, dst, uri, category
    if len(parts) >= 4:
        return channel_id, parts[0], parts[1], parts[2], parts[3]

    # Old format: dst, category
    if len(parts) >= 2:
        return channel_id, None, parts[0], None, parts[1]

    return channel_id, None, parts[0], None, None


def _write_response(channel_id: Optional[str], ok: bool) -> None:
    if channel_id is not None:
        sys.stdout.write(f"{channel_id} {'OK' if ok else 'ERR'}\n")
    else:
        sys.stdout.write(f"{'OK' if ok else 'ERR'}\n")
    sys.stdout.flush()


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Squid external ACL helper for domain category blocking (local categories DB).")
    ap.add_argument("--db", default=os.environ.get("WEBFILTER_DB", "/var/lib/squid-flask-proxy/webcat.db"))
    ap.add_argument("--settings-db", default=os.environ.get("WEBFILTER_SETTINGS_DB", "/var/lib/squid-flask-proxy/webfilter.db"))
    ap.add_argument("--log-max-rows", type=int, default=int(os.environ.get("WEBFILTER_LOG_MAX_ROWS", "5000")))
    ap.add_argument("--fail", choices=["open", "closed"], default=os.environ.get("WEBFILTER_FAIL", "open"))
    args = ap.parse_args(list(argv) if argv is not None else None)

    db = _Db(args.db)
    log_db = _BlockedLogDb(args.settings_db, max_rows=int(args.log_max_rows))
    fail_open = args.fail == "open"

    for raw in sys.stdin:
        ch, src_ip, domain, url, category = _parse_line(raw)
        if not domain or not category:
            # Fail-open: do not match the ACL (allow). Fail-closed: match (block).
            _write_response(ch, not fail_open)
            continue

        cats = db.lookup_categories(domain)
        if not cats:
            # Unknown domain: do not match the ACL (allow) unless fail-closed.
            _write_response(ch, not fail_open)
            continue

        # External ACL semantics: return OK when the ACL *matches*.
        # For blocking ACLs, we match when the destination is in the named category.
        match = category.lower() in cats
        if match:
            # Best-effort: record the event so the admin UI can show a blocked log.
            # This helper is invoked only for requests that reach the deny ACL chain.
            log_db.insert(ts=_now(), src_ip=(src_ip or ""), url=(url or domain or ""), category=(category or ""))
        _write_response(ch, match)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
