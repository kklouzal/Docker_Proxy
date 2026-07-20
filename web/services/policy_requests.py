from __future__ import annotations

import ipaddress
import re
import threading
from dataclasses import dataclass
from typing import Any

from services.db import connect
from services.domain_normalization import normalize_domain as _shared_normalize_domain
from services.proxy_context import get_proxy_id, normalize_proxy_id
from services.proxy_write_guard import guarded_proxy_write
from services.runtime_helpers import extract_domain, now_ts

PENDING = "pending"
APPROVED = "approved"
REJECTED = "rejected"
CLOSED = "closed"
ACTIVE = "active"
REVOKED = "revoked"
REQ_STATUS = {PENDING, APPROVED, REJECTED, CLOSED}
BLOCK_TYPES = {"webfilter", "adblock", "clamav", "download", "mime"}
POLICY_EXCEPTION_DEFAULT_DURATION_SECONDS = 24 * 60 * 60
POLICY_EXCEPTION_MIN_DURATION_SECONDS = 60
POLICY_EXCEPTION_MAX_DURATION_SECONDS = 30 * 24 * 60 * 60
_SAFE = re.compile(r"[^a-z0-9_.:-]+", re.IGNORECASE)
_HOST_LABEL = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    re.IGNORECASE,
)


def _norm_domain(value: object) -> str:
    raw = str(value or "").strip().lstrip(".")
    raw = raw.removeprefix("*.")
    host = _shared_normalize_domain(raw)
    if not host:
        return ""
    return host[:255]


def _looks_like_host(value: object) -> bool:
    host = str(value or "").strip()
    if not host or len(host) > 255:
        return False
    if any(ch.isspace() for ch in host):
        return False
    parts = host.split(".")
    if not all(_HOST_LABEL.fullmatch(part or "") for part in parts):
        return False
    # Single-label DNS names are valid inside container and private networks
    # (for example Docker Compose service names such as ``traffic-fixture``).
    # Keep obviously non-host tokens out by requiring at least one alphabetic
    # character, which also avoids accepting IPv4-looking numeric strings here.
    return any(re.search(r"[a-z]", part) for part in parts)


@dataclass(frozen=True)
class PolicyRequest:
    id: int
    proxy_id: str
    status: str
    block_type: str
    client_ip: str
    request_url: str
    domain: str
    category: str
    method: str
    squid_error: str
    user_note: str
    admin_note: str
    created_ts: int
    updated_ts: int
    reviewed_ts: int
    reviewer: str
    exception_id: int | None


@dataclass(frozen=True)
class PolicyException:
    id: int
    proxy_id: str
    status: str
    block_type: str
    client_ip: str
    domain: str
    category: str
    created_ts: int
    updated_ts: int
    created_by: str
    admin_note: str
    expires_ts: int
    revoked_ts: int
    revoked_by: str
    source_request_id: int | None


def _text(v: object, max_len: int, multiline: bool = False) -> str:
    s = str(v or "").replace("\x00", "").strip()
    if multiline:
        s = s.replace("\r\n", "\n").replace("\r", "\n")
        s = "\n".join(x.strip() for x in s.split("\n"))
        s = re.sub(r"\n{4,}", "\n\n\n", s).strip()
    else:
        s = re.sub(r"[\r\n\t]+", " ", s)
    return s[:max_len]


def _bounded_duration_seconds(value: object) -> int:
    try:
        seconds = int(str(value).strip())
    except Exception:
        seconds = POLICY_EXCEPTION_DEFAULT_DURATION_SECONDS
    return max(
        POLICY_EXCEPTION_MIN_DURATION_SECONDS,
        min(POLICY_EXCEPTION_MAX_DURATION_SECONDS, seconds),
    )


def normalize_block_type(v: object) -> str:
    s = _SAFE.sub("", str(v or "").strip().lower())[:32]
    return s if s in BLOCK_TYPES else "webfilter"


def normalize_client_ip(v: object) -> str:
    s = _text(v, 64)
    if "," in s:
        s = s.split(",", 1)[0].strip()
    try:
        return str(ipaddress.ip_address(s))
    except Exception:
        return ""


def normalize_domain(v: object, *, request_url: object = "") -> str:
    h = (
        _norm_domain(extract_domain(v))
        or _norm_domain(str(v or ""))
        or _norm_domain(extract_domain(request_url))
    )
    return h if _looks_like_host(h) else ""


def _s(row: Any, k: str, i: int) -> str:
    try:
        v = row[k]
    except Exception:
        v = row[i]
    return str(v or "")


def _i(row: Any, k: str, i: int, d: int = 0) -> int:
    try:
        v = row[k]
    except Exception:
        v = row[i]
    try:
        return int(v) if v is not None else d
    except Exception:
        return d


def _oi(row: Any, k: str, i: int) -> int | None:
    try:
        v = row[k]
    except Exception:
        v = row[i]
    if v is None:
        return None
    try:
        return int(v)
    except Exception:
        return None


def _req(row: Any) -> PolicyRequest:
    return PolicyRequest(
        _i(row, "id", 0),
        _s(row, "proxy_id", 1),
        _s(row, "status", 2),
        _s(row, "block_type", 3),
        _s(row, "client_ip", 4),
        _s(row, "request_url", 5),
        _s(row, "domain", 6),
        _s(row, "category", 7),
        _s(row, "method", 8),
        _s(row, "squid_error", 9),
        _s(row, "user_note", 10),
        _s(row, "admin_note", 11),
        _i(row, "created_ts", 12),
        _i(row, "updated_ts", 13),
        _i(row, "reviewed_ts", 14),
        _s(row, "reviewer", 15),
        _oi(row, "exception_id", 16),
    )


def _exc(row: Any) -> PolicyException:
    return PolicyException(
        _i(row, "id", 0),
        _s(row, "proxy_id", 1),
        _s(row, "status", 2),
        _s(row, "block_type", 3),
        _s(row, "client_ip", 4),
        _s(row, "domain", 5),
        _s(row, "category", 6),
        _i(row, "created_ts", 7),
        _i(row, "updated_ts", 8),
        _s(row, "created_by", 9),
        _s(row, "admin_note", 10),
        _i(row, "expires_ts", 11),
        _i(row, "revoked_ts", 12),
        _s(row, "revoked_by", 13),
        _oi(row, "source_request_id", 14),
    )


class PolicyRequestStore:
    REQUEST_TABLE = "policy_requests"
    EXCEPTION_TABLE = "policy_exceptions"

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
            with self._connect() as c:
                try:
                    from services.schema_lifecycle import (
                        runtime_schema_ready_for_lazy_store,
                    )

                    if runtime_schema_ready_for_lazy_store(c):
                        self._schema_ready = True
                        return
                except Exception:
                    pass
                c.execute(
                    f"CREATE TABLE IF NOT EXISTS {self.REQUEST_TABLE}(id BIGINT PRIMARY KEY AUTO_INCREMENT, proxy_id VARCHAR(64) NOT NULL DEFAULT 'default', status VARCHAR(24) NOT NULL DEFAULT 'pending', block_type VARCHAR(32) NOT NULL DEFAULT 'webfilter', client_ip VARCHAR(64) NOT NULL, request_url TEXT NOT NULL, domain VARCHAR(255) NOT NULL, category VARCHAR(128) NOT NULL DEFAULT '', method VARCHAR(16) NOT NULL DEFAULT '', squid_error VARCHAR(64) NOT NULL DEFAULT '', user_note TEXT NOT NULL, admin_note TEXT NOT NULL, created_ts BIGINT NOT NULL, updated_ts BIGINT NOT NULL, reviewed_ts BIGINT NOT NULL DEFAULT 0, reviewer VARCHAR(128) NOT NULL DEFAULT '', exception_id BIGINT NULL, KEY idx_policy_requests_status_ts (status, created_ts, id), KEY idx_policy_requests_proxy_status_ts (proxy_id,status,created_ts,id), KEY idx_policy_requests_domain (domain), KEY idx_policy_requests_client (client_ip))",
                )
                c.execute(
                    f"CREATE TABLE IF NOT EXISTS {self.EXCEPTION_TABLE}(id BIGINT PRIMARY KEY AUTO_INCREMENT, proxy_id VARCHAR(64) NOT NULL DEFAULT 'default', status VARCHAR(24) NOT NULL DEFAULT 'active', block_type VARCHAR(32) NOT NULL DEFAULT 'webfilter', client_ip VARCHAR(64) NOT NULL, domain VARCHAR(255) NOT NULL, category VARCHAR(128) NOT NULL DEFAULT '', created_ts BIGINT NOT NULL, updated_ts BIGINT NOT NULL, created_by VARCHAR(128) NOT NULL DEFAULT '', admin_note TEXT NOT NULL, expires_ts BIGINT NOT NULL DEFAULT 0, revoked_ts BIGINT NOT NULL DEFAULT 0, revoked_by VARCHAR(128) NOT NULL DEFAULT '', source_request_id BIGINT NULL, KEY idx_policy_exceptions_active (proxy_id,status,block_type,expires_ts), KEY idx_policy_exceptions_request (source_request_id), KEY idx_policy_exceptions_domain_client (proxy_id,domain,client_ip))",
                )
            self._schema_ready = True

    def _rsql(self, w: str = "") -> str:
        return (
            "SELECT id,proxy_id,status,block_type,client_ip,request_url,domain,category,method,squid_error,user_note,admin_note,created_ts,updated_ts,reviewed_ts,reviewer,exception_id FROM "
            + self.REQUEST_TABLE
            + " "
            + w
        )

    def _esql(self, w: str = "") -> str:
        return (
            "SELECT id,proxy_id,status,block_type,client_ip,domain,category,created_ts,updated_ts,created_by,admin_note,expires_ts,revoked_ts,revoked_by,source_request_id FROM "
            + self.EXCEPTION_TABLE
            + " "
            + w
        )

    def create_request(
        self,
        *,
        proxy_id: str | None = None,
        block_type: object = "webfilter",
        client_ip: object = "",
        request_url: object = "",
        domain: object = "",
        category: object = "",
        method: object = "",
        squid_error: object = "",
        user_note: object = "",
    ) -> PolicyRequest:
        self.init_db()
        p = normalize_proxy_id(proxy_id or get_proxy_id()).lower()
        url = _text(request_url, 2048)
        d = normalize_domain(domain, request_url=url)
        ip = normalize_client_ip(client_ip)
        if not d:
            msg = "A valid destination domain is required."
            raise ValueError(msg)
        if not ip:
            msg = "A valid client IP address is required."
            raise ValueError(msg)
        now = now_ts()
        with self._connect() as c:
            with guarded_proxy_write(c, p) as guard:
                p = guard.proxy_id
                r = c.execute(
                    f"INSERT INTO {self.REQUEST_TABLE}(proxy_id,status,block_type,client_ip,request_url,domain,category,method,squid_error,user_note,admin_note,created_ts,updated_ts,reviewed_ts,reviewer,exception_id) VALUES(%s,'pending',%s,%s,%s,%s,%s,%s,%s,%s,'',%s,%s,0,'',NULL)",
                    (
                        p,
                        normalize_block_type(block_type),
                        ip,
                        url,
                        d,
                        _text(category, 128),
                        _text(method, 16).upper(),
                        _text(squid_error, 64),
                        _text(user_note, 2000, True),
                        now,
                        now,
                    ),
                )
                row = c.execute(
                    self._rsql("WHERE id=%s"),
                    (int(r.lastrowid or 0),),
                ).fetchone()
        return _req(row)

    def list_requests(
        self,
        *,
        statuses: list[str] | None = None,
        limit: int = 200,
        proxy_id: str | None = None,
    ) -> list[PolicyRequest]:
        self.init_db()
        limit = max(1, min(int(limit), 1000))
        statuses = [s for s in (statuses or []) if s in REQ_STATUS]
        clauses: list[str] = []
        params: list[object] = []
        if proxy_id is not None:
            clauses.append("proxy_id=%s")
            params.append(normalize_proxy_id(proxy_id).lower())
        if statuses:
            ph = ",".join(["%s"] * len(statuses))
            clauses.append(f"status IN ({ph})")
            params.extend(statuses)
        where = f"WHERE {' AND '.join(clauses)} " if clauses else ""
        with self._connect() as c:
            rows = c.execute(
                self._rsql(f"{where}ORDER BY created_ts DESC,id DESC LIMIT %s"),
                (*params, limit),
            ).fetchall()
        return [_req(x) for x in rows]

    def list_exceptions(
        self,
        *,
        include_inactive: bool = True,
        limit: int = 200,
        proxy_id: str | None = None,
    ) -> list[PolicyException]:
        self.init_db()
        limit = max(1, min(int(limit), 1000))
        clauses: list[str] = []
        params: list[object] = []
        if proxy_id is not None:
            clauses.append("proxy_id=%s")
            params.append(normalize_proxy_id(proxy_id).lower())
        if not include_inactive:
            clauses.append("status='active'")
        where = f"WHERE {' AND '.join(clauses)} " if clauses else ""
        with self._connect() as c:
            rows = c.execute(
                self._esql(f"{where}ORDER BY updated_ts DESC,id DESC LIMIT %s"),
                (*params, limit),
            ).fetchall()
        return [_exc(x) for x in rows]

    def approve_request(
        self,
        request_id: int,
        *,
        reviewer: object = "",
        admin_note: object = "",
        duration_seconds: int | None = None,
        indefinite: bool = False,
        proxy_id: str | None = None,
    ) -> PolicyException:
        self.init_db()
        now = now_ts()
        exp = (
            0
            if indefinite or duration_seconds is None
            else now + _bounded_duration_seconds(duration_seconds)
        )
        reviewer_s = _text(reviewer, 128)
        note = _text(admin_note, 2000, True)
        scoped_proxy_id = (
            normalize_proxy_id(proxy_id).lower() if proxy_id is not None else ""
        )
        with self._connect() as c:
            if scoped_proxy_id:
                row = c.execute(
                    self._rsql("WHERE id=%s AND proxy_id=%s"),
                    (int(request_id), scoped_proxy_id),
                ).fetchone()
            else:
                row = c.execute(
                    self._rsql("WHERE id=%s"), (int(request_id),)
                ).fetchone()
            if not row:
                msg = (
                    "Request not found for selected proxy."
                    if scoped_proxy_id
                    else "Request not found."
                )
                raise ValueError(msg)
            req = _req(row)
            if req.status != PENDING:
                msg = "Only pending requests can be approved."
                raise ValueError(msg)
            with guarded_proxy_write(c, req.proxy_id) as guard:
                canonical_proxy_id = guard.proxy_id
                r = c.execute(
                    f"INSERT INTO {self.EXCEPTION_TABLE}(proxy_id,status,block_type,client_ip,domain,category,created_ts,updated_ts,created_by,admin_note,expires_ts,revoked_ts,revoked_by,source_request_id) VALUES(%s,'active',%s,%s,%s,%s,%s,%s,%s,%s,%s,0,'',%s)",
                    (
                        canonical_proxy_id,
                        req.block_type,
                        req.client_ip,
                        req.domain,
                        req.category,
                        now,
                        now,
                        reviewer_s,
                        note,
                        exp,
                        req.id,
                    ),
                )
                exid = int(r.lastrowid or 0)
                c.execute(
                    f"UPDATE {self.REQUEST_TABLE} SET status='approved',admin_note=%s,updated_ts=%s,reviewed_ts=%s,reviewer=%s,exception_id=%s,proxy_id=%s WHERE id=%s",
                    (note, now, now, reviewer_s, exid, canonical_proxy_id, req.id),
                )
                exrow = c.execute(self._esql("WHERE id=%s"), (exid,)).fetchone()
        return _exc(exrow)

    def close_request(
        self,
        request_id: int,
        *,
        reviewer: object = "",
        admin_note: object = "",
        status: str = REJECTED,
        proxy_id: str | None = None,
    ) -> None:
        self.init_db()
        status = status if status in {REJECTED, CLOSED} else REJECTED
        now = now_ts()
        scoped_proxy_id = (
            normalize_proxy_id(proxy_id).lower() if proxy_id is not None else ""
        )
        note = _text(admin_note, 2000, True)
        reviewer_s = _text(reviewer, 128)
        with self._connect() as c:
            if scoped_proxy_id:
                with guarded_proxy_write(
                    c,
                    scoped_proxy_id,
                    require_registered=False,
                ) as guard:
                    result = c.execute(
                        f"UPDATE {self.REQUEST_TABLE} SET status=%s,admin_note=%s,updated_ts=%s,reviewed_ts=%s,reviewer=%s WHERE id=%s AND status='pending' AND proxy_id=%s",
                        (
                            status,
                            note,
                            now,
                            now,
                            reviewer_s,
                            int(request_id),
                            guard.proxy_id,
                        ),
                    )
            else:
                result = c.execute(
                    f"UPDATE {self.REQUEST_TABLE} SET status=%s,admin_note=%s,updated_ts=%s,reviewed_ts=%s,reviewer=%s WHERE id=%s AND status='pending'",
                    (status, note, now, now, reviewer_s, int(request_id)),
                )
            if (
                scoped_proxy_id
                and max(0, int(getattr(result, "rowcount", 0) or 0)) == 0
            ):
                msg = "Request not found for selected proxy."
                raise ValueError(msg)

    def revoke_exception(
        self,
        exception_id: int,
        *,
        revoked_by: object = "",
        admin_note: object = "",
        proxy_id: str | None = None,
    ) -> None:
        self.init_db()
        now = now_ts()
        note = _text(admin_note, 2000, True)
        scoped_proxy_id = (
            normalize_proxy_id(proxy_id).lower() if proxy_id is not None else ""
        )
        revoked_by_s = _text(revoked_by, 128)
        with self._connect() as c:
            if scoped_proxy_id:
                with guarded_proxy_write(
                    c,
                    scoped_proxy_id,
                    require_registered=False,
                ) as guard:
                    result = c.execute(
                        f"UPDATE {self.EXCEPTION_TABLE} SET status='revoked',updated_ts=%s,revoked_ts=%s,revoked_by=%s,admin_note=CASE WHEN %s='' THEN admin_note ELSE %s END WHERE id=%s AND status='active' AND proxy_id=%s",
                        (
                            now,
                            now,
                            revoked_by_s,
                            note,
                            note,
                            int(exception_id),
                            guard.proxy_id,
                        ),
                    )
            else:
                result = c.execute(
                    f"UPDATE {self.EXCEPTION_TABLE} SET status='revoked',updated_ts=%s,revoked_ts=%s,revoked_by=%s,admin_note=CASE WHEN %s='' THEN admin_note ELSE %s END WHERE id=%s AND status='active'",
                    (now, now, revoked_by_s, note, note, int(exception_id)),
                )
            if (
                scoped_proxy_id
                and max(0, int(getattr(result, "rowcount", 0) or 0)) == 0
            ):
                msg = "Exception not found for selected proxy."
                raise ValueError(msg)

    def active_webfilter_exceptions(
        self,
        *,
        proxy_id: str | None = None,
        at_ts: int | None = None,
        limit: int = 5000,
    ) -> list[PolicyException]:
        self.init_db()
        now = int(at_ts if at_ts is not None else now_ts())
        p = normalize_proxy_id(proxy_id or get_proxy_id()).lower()
        with self._connect() as c:
            rows = c.execute(
                self._esql(
                    "WHERE proxy_id=%s AND status='active' AND block_type='webfilter' AND (expires_ts=0 OR expires_ts>%s) ORDER BY domain ASC,client_ip ASC,id ASC LIMIT %s",
                ),
                (p, now, max(1, min(int(limit), 10000))),
            ).fetchall()
        return [_exc(x) for x in rows]


_store: PolicyRequestStore | None = None


def get_policy_request_store() -> PolicyRequestStore:
    global _store
    if _store is None:
        _store = PolicyRequestStore()
    return _store
