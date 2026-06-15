from __future__ import annotations

import contextlib
import hashlib
import time
from collections import Counter
from typing import Any

from services.adblock_store import get_adblock_store
from services.client_identity_cache import get_client_identity_cache
from services.db import connect
from services.diagnostic_store import get_diagnostic_store
from services.proxy_context import get_proxy_id
from services.runtime_helpers import cache_hit_sql as _cache_hit_sql
from services.runtime_helpers import escape_like as _escape_like
from services.runtime_helpers import extract_domain as _extract_domain
from services.runtime_helpers import not_cached_reason_sql as _not_cached_reason_sql
from services.runtime_helpers import present_value_sql as _present_value_sql
from services.ssl_errors_store import get_ssl_errors_store
from services.ui_support import (
    present_icap_events,
    present_observability_summary,
    present_ssl_error_rows,
    present_ssl_exclusion_candidates,
    present_ssl_top_domains,
    present_top_tag_rows,
    present_top_value_rows,
    present_transaction_rows,
)
from services.webfilter_store import get_webfilter_store


def _pct(part: int, whole: int) -> float:
    if whole <= 0:
        return 0.0
    return round((float(part) / float(whole)) * 100.0, 1)


def _int_or(value: object, default: int) -> int:
    try:
        return int(value or default)
    except Exception:
        return int(default)


def normalize_runtime_health_state_errors(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        text = value.strip()
        return [text] if text else []
    if isinstance(value, (list, tuple, set)):
        errors: list[str] = []
        for item in value:
            text = str(item or "").strip()
            if text:
                errors.append(text)
        return errors
    text = str(value or "").strip()
    return [text] if text else []


def _badge_rows(counter: Counter[str], *, limit: int = 8) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for label, count in counter.most_common(max(1, limit)):
        clean = str(label or "").strip()
        if not clean:
            continue
        rows.append(
            {
                "label": clean,
                "full_label": clean,
                "count": int(count or 0),
            },
        )
    return rows


def _correlate_icap_events_with_requests(
    diagnostic_store: Any,
    rows: list[dict[str, Any]],
    *,
    icap_limit: int = 0,
) -> list[dict[str, Any]]:
    txs = [str(row.get("master_xaction") or "").strip() for row in rows]
    if hasattr(diagnostic_store, "batch_find_requests_by_master_xactions"):
        request_rows = diagnostic_store.batch_find_requests_by_master_xactions(txs)
    else:
        request_rows = {
            tx: diagnostic_store.find_request_by_master_xaction(tx)
            for tx in dict.fromkeys(txs)
            if tx
        }
    for row in rows:
        row["correlated_request"] = None
        tx = str(row.get("master_xaction") or "").strip()
        request_row = request_rows.get(tx) if tx else None
        if request_row is None:
            continue
        event = dict(request_row)
        event["related_icap"] = []
        event["correlation_kind"] = "master_xaction"
        row["correlated_request"] = present_transaction_rows(
            [event],
            icap_limit=icap_limit,
        )[0]
    return rows


def _correlate_policy_events_with_requests(
    diagnostic_store: Any,
    rows: list[dict[str, Any]],
    *,
    window_seconds: int,
    service: str = "",
) -> list[dict[str, Any]]:
    for row in rows:
        row["correlated_candidates"] = []
        try:
            candidates = diagnostic_store.list_request_candidates_for_policy_event(
                around_ts=int(row.get("ts") or 0),
                url=str(row.get("url") or ""),
                client_ip=str(row.get("src_ip") or ""),
                domain=str(row.get("domain") or ""),
                window_seconds=max(120, min(int(window_seconds or 300), 900)),
                limit=3,
                service=service,
            )
            row["correlated_candidates"] = present_transaction_rows(
                candidates,
                icap_limit=3,
            )
        except Exception:
            row["correlated_candidates"] = []
    return rows


def _pseudonymize(value: object, *, namespace: str = "client") -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    digest = hashlib.sha256(
        f"{get_proxy_id()}:{namespace}:{raw}".encode("utf-8", errors="replace"),
    ).hexdigest()
    return f"{namespace}-{digest[:10]}"


def _next_schedule_run_ts(cadence: str, now: int | None = None) -> int:
    base = int(now if now is not None else time.time())
    interval = 7 * 24 * 3600 if str(cadence or "").lower() == "weekly" else 24 * 3600
    return base + interval


class ObservabilityQueries:
    def _connect(self):
        return connect()

    @staticmethod
    def _request_identity_sql(
        id_column: str = "id",
        master_xaction_column: str = "master_xaction",
    ) -> str:
        return (
            "CASE "
            f"WHEN COALESCE(NULLIF(TRIM({master_xaction_column}), ''), '') <> '' "
            f"THEN CONCAT('tx:', {master_xaction_column}) "
            f"ELSE CONCAT('req:', CAST({id_column} AS CHAR)) END"
        )

    @staticmethod
    def _hit_sql(result_column: str = "result_code") -> str:
        return _cache_hit_sql(result_column)

    @staticmethod
    def _present_sql(column: str) -> str:
        return _present_value_sql(column)

    @staticmethod
    def _url_host_sql(url_column: str = "url") -> str:
        return (
            "LOWER(TRIM(BOTH '.' FROM "
            "CASE "
            f"WHEN LOCATE('://', {url_column}) > 0 THEN "
            f"SUBSTRING_INDEX(SUBSTRING_INDEX(SUBSTRING({url_column}, LOCATE('://', {url_column}) + 3), '/', 1), ':', 1) "
            "ELSE "
            f"SUBSTRING_INDEX(SUBSTRING_INDEX({url_column}, '/', 1), ':', 1) "
            "END))"
        )

    @staticmethod
    def _not_cached_reason_sql(
        *,
        method_column: str = "method",
        result_column: str = "result_code",
        status_column: str = "http_status",
    ) -> str:
        return _not_cached_reason_sql(
            method_column=method_column,
            result_column=result_column,
            status_column=status_column,
        )

    def _request_icap_rollup_filters(
        self,
        *,
        since: int,
        request_present_column: str,
        icap_present_column: str,
        search: str,
        request_search_column: str,
        icap_search_column: str,
    ) -> tuple[str, list[Any], str, list[Any]]:
        proxy_id = get_proxy_id()
        request_where = [
            "r.proxy_id = %s",
            "r.ts >= %s",
            self._present_sql(request_present_column),
        ]
        request_params: list[Any] = [proxy_id, int(since)]
        icap_where = [
            "proxy_id = %s",
            "ts >= %s",
            self._present_sql(icap_present_column),
        ]
        icap_params: list[Any] = [proxy_id, int(since)]
        search_value = (search or "").strip().lower()
        if search_value:
            like = f"%{_escape_like(search_value)}%"
            request_where.append(
                f"LOWER({request_search_column}) LIKE %s ESCAPE '\\\\'",
            )
            request_params.append(like)
            icap_where.append(f"LOWER({icap_search_column}) LIKE %s ESCAPE '\\\\'")
            icap_params.append(like)

        return (
            "WHERE " + " AND ".join(request_where),
            request_params,
            "WHERE " + " AND ".join(icap_where),
            icap_params,
        )

    @staticmethod
    def _av_status(summary: str, details: str) -> str:
        haystack = f"{summary} {details}".lower()
        if any(
            token in haystack
            for token in (
                "found",
                "eicar",
                "malware",
                "virus",
                "infect",
                "trojan",
                "blocked",
                "deny",
            )
        ):
            return "finding"
        if any(token in haystack for token in ("clean", "allow", "passed")):
            return "clean"
        return "activity"

    @staticmethod
    def _av_status_meta(status: str) -> dict[str, str]:
        normalized = (status or "activity").strip().lower()
        if normalized == "finding":
            return {"label": "Potential finding", "tone": "danger"}
        if normalized == "clean":
            return {"label": "Clean / allowed", "tone": "ok"}
        return {"label": "General AV activity", "tone": "ghost"}

    @staticmethod
    def _av_finding_sql() -> str:
        haystack = "LOWER(CONCAT(COALESCE(adapt_summary, ''), ' ', COALESCE(adapt_details, '')))"
        return (
            f"({haystack} LIKE '%%found%%' OR {haystack} LIKE '%%eicar%%' OR {haystack} LIKE '%%malware%%' "
            f"OR {haystack} LIKE '%%virus%%' OR {haystack} LIKE '%%infect%%' OR {haystack} LIKE '%%trojan%%' "
            f"OR {haystack} LIKE '%%blocked%%' OR {haystack} LIKE '%%deny%%')"
        )

    def summary(self, *, since: int) -> dict[str, Any]:
        proxy_id = get_proxy_id()
        hit_sql = self._hit_sql("result_code")
        tx_sql = self._request_identity_sql("id", "master_xaction")

        with self._connect() as conn:
            requests_row = conn.execute(
                f"""
                SELECT
                    COUNT(*) AS request_records,
                    COALESCE(SUM(CASE WHEN {hit_sql} THEN 1 ELSE 0 END), 0) AS cache_hits,
                    COUNT(DISTINCT client_ip) AS clients,
                    COUNT(DISTINCT domain) AS destinations,
                    COUNT(DISTINCT {tx_sql}) AS transactions
                FROM diagnostic_requests
                WHERE proxy_id = %s AND ts >= %s AND {self._present_sql("domain")}
                """,
                (proxy_id, int(since)),
            ).fetchone()
            icap_row = conn.execute(
                """
                SELECT
                    COUNT(*) AS icap_events,
                    COALESCE(SUM(CASE WHEN service_family = 'av' THEN 1 ELSE 0 END), 0) AS av_icap_events,
                    COALESCE(SUM(CASE WHEN service_family = 'adblock' THEN 1 ELSE 0 END), 0) AS adblock_icap_events
                FROM diagnostic_icap_events
                WHERE proxy_id = %s AND ts >= %s
                """,
                (proxy_id, int(since)),
            ).fetchone()

        request_records = int(requests_row[0] or 0) if requests_row else 0
        cache_hits = int(requests_row[1] or 0) if requests_row else 0
        return {
            "request_records": request_records,
            "cache_hits": cache_hits,
            "cache_misses": max(0, request_records - cache_hits),
            "cache_hit_pct": _pct(cache_hits, request_records),
            "clients": int(requests_row[2] or 0) if requests_row else 0,
            "destinations": int(requests_row[3] or 0) if requests_row else 0,
            "transactions": int(requests_row[4] or 0) if requests_row else 0,
            "icap_events": int(icap_row[0] or 0) if icap_row else 0,
            "av_icap_events": int(icap_row[1] or 0) if icap_row else 0,
            "adblock_icap_events": int(icap_row[2] or 0) if icap_row else 0,
        }

    def top_destinations(
        self,
        *,
        since: int,
        search: str = "",
        limit: int = 50,
        sort: str = "requests",
        total_requests: int | None = None,
    ) -> list[dict[str, Any]]:
        lim = max(5, min(200, int(limit)))
        hit_sql = self._hit_sql("r.result_code")
        tx_sql = self._request_identity_sql("r.id", "r.master_xaction")
        request_where_sql, request_params, icap_where_sql, icap_params = (
            self._request_icap_rollup_filters(
                since=since,
                request_present_column="r.domain",
                icap_present_column="domain",
                search=search,
                request_search_column="r.domain",
                icap_search_column="domain",
            )
        )

        if sort == "recent":
            order_by = "req.last_seen DESC, req.requests DESC"
        elif sort == "cache":
            order_by = "req.cache_pct DESC, req.requests DESC, req.last_seen DESC"
        elif sort == "clients":
            order_by = "req.clients DESC, req.requests DESC, req.last_seen DESC"
        else:
            order_by = "req.requests DESC, req.last_seen DESC"

        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT
                    req.domain,
                    req.requests,
                    req.hit_requests,
                    req.clients,
                    req.transactions,
                    req.last_seen,
                    req.cache_pct,
                    COALESCE(icap.av_icap_events, 0) AS av_icap_events,
                    COALESCE(icap.adblock_icap_events, 0) AS adblock_icap_events
                FROM (
                    SELECT
                        r.domain AS domain,
                        COUNT(*) AS requests,
                        COALESCE(SUM(CASE WHEN {hit_sql} THEN 1 ELSE 0 END), 0) AS hit_requests,
                        COUNT(DISTINCT r.client_ip) AS clients,
                        COUNT(DISTINCT {tx_sql}) AS transactions,
                        MAX(r.ts) AS last_seen,
                        ROUND(
                            CASE WHEN COUNT(*) > 0
                                THEN (100.0 * COALESCE(SUM(CASE WHEN {hit_sql} THEN 1 ELSE 0 END), 0) / COUNT(*))
                                ELSE 0 END,
                            1
                        ) AS cache_pct
                    FROM diagnostic_requests r
                    {request_where_sql}
                    GROUP BY r.domain
                ) req
                LEFT JOIN (
                    SELECT
                        domain,
                        COALESCE(SUM(CASE WHEN service_family = 'av' THEN 1 ELSE 0 END), 0) AS av_icap_events,
                        COALESCE(SUM(CASE WHEN service_family = 'adblock' THEN 1 ELSE 0 END), 0) AS adblock_icap_events
                    FROM diagnostic_icap_events
                    {icap_where_sql}
                    GROUP BY domain
                ) icap ON icap.domain = req.domain
                ORDER BY {order_by}
                LIMIT %s
                """,
                tuple(request_params + icap_params + [lim]),
            ).fetchall()

        if total_requests is None:
            total_requests = sum(int(row[1] or 0) for row in rows)
        total_requests = int(total_requests or 0)
        return [
            {
                "domain": str(row[0] or ""),
                "requests": int(row[1] or 0),
                "hit_requests": int(row[2] or 0),
                "clients": int(row[3] or 0),
                "transactions": int(row[4] or 0),
                "last_seen": int(row[5] or 0),
                "cache_pct": float(row[6] or 0.0),
                "av_icap_events": int(row[7] or 0),
                "adblock_icap_events": int(row[8] or 0),
                "pct": _pct(int(row[1] or 0), total_requests),
            }
            for row in rows
        ]

    def top_clients(
        self,
        *,
        since: int,
        search: str = "",
        limit: int = 50,
        sort: str = "requests",
        resolve_hostnames: bool = True,
        total_requests: int | None = None,
    ) -> list[dict[str, Any]]:
        lim = max(5, min(200, int(limit)))
        hit_sql = self._hit_sql("r.result_code")
        tx_sql = self._request_identity_sql("r.id", "r.master_xaction")
        request_where_sql, request_params, icap_where_sql, icap_params = (
            self._request_icap_rollup_filters(
                since=since,
                request_present_column="r.domain",
                icap_present_column="client_ip",
                search=search,
                request_search_column="r.client_ip",
                icap_search_column="client_ip",
            )
        )

        if sort == "recent":
            order_by = "req.last_seen DESC, req.requests DESC"
        elif sort == "cache":
            order_by = "req.cache_pct DESC, req.requests DESC, req.last_seen DESC"
        elif sort == "destinations":
            order_by = "req.destinations DESC, req.requests DESC, req.last_seen DESC"
        else:
            order_by = "req.requests DESC, req.last_seen DESC"

        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT
                    req.client_ip,
                    req.requests,
                    req.hit_requests,
                    req.destinations,
                    req.transactions,
                    req.last_seen,
                    req.cache_pct,
                    COALESCE(icap.av_icap_events, 0) AS av_icap_events,
                    COALESCE(icap.adblock_icap_events, 0) AS adblock_icap_events
                FROM (
                    SELECT
                        r.client_ip AS client_ip,
                        COUNT(*) AS requests,
                        COALESCE(SUM(CASE WHEN {hit_sql} THEN 1 ELSE 0 END), 0) AS hit_requests,
                        COUNT(DISTINCT r.domain) AS destinations,
                        COUNT(DISTINCT {tx_sql}) AS transactions,
                        MAX(r.ts) AS last_seen,
                        ROUND(
                            CASE WHEN COUNT(*) > 0
                                THEN (100.0 * COALESCE(SUM(CASE WHEN {hit_sql} THEN 1 ELSE 0 END), 0) / COUNT(*))
                                ELSE 0 END,
                            1
                        ) AS cache_pct
                    FROM diagnostic_requests r
                    {request_where_sql}
                    GROUP BY r.client_ip
                ) req
                LEFT JOIN (
                    SELECT
                        client_ip,
                        COALESCE(SUM(CASE WHEN service_family = 'av' THEN 1 ELSE 0 END), 0) AS av_icap_events,
                        COALESCE(SUM(CASE WHEN service_family = 'adblock' THEN 1 ELSE 0 END), 0) AS adblock_icap_events
                    FROM diagnostic_icap_events
                    {icap_where_sql}
                    GROUP BY client_ip
                ) icap ON icap.client_ip = req.client_ip
                ORDER BY {order_by}
                LIMIT %s
                """,
                tuple(request_params + icap_params + [lim]),
            ).fetchall()

        if total_requests is None:
            total_requests = sum(int(row[1] or 0) for row in rows)
        total_requests = int(total_requests or 0)
        out = [
            {
                "ip": str(row[0] or ""),
                "requests": int(row[1] or 0),
                "hit_requests": int(row[2] or 0),
                "destinations": int(row[3] or 0),
                "transactions": int(row[4] or 0),
                "last_seen": int(row[5] or 0),
                "cache_pct": float(row[6] or 0.0),
                "av_icap_events": int(row[7] or 0),
                "adblock_icap_events": int(row[8] or 0),
                "pct": _pct(int(row[1] or 0), total_requests),
                "hostname": "",
                "hostname_source": "",
                "hostname_status": "disabled",
            }
            for row in rows
        ]
        if resolve_hostnames and out:
            cache = get_client_identity_cache()
            resolved = cache.resolve_many(row["ip"] for row in out)
            for row in out:
                info = resolved.get(
                    row["ip"],
                    {
                        "hostname": "",
                        "hostname_source": "",
                        "hostname_status": "unresolved",
                    },
                )
                row.update(info)
        return out

    def top_cache_reasons(
        self,
        *,
        since: int,
        search: str = "",
        limit: int = 50,
        sort: str = "requests",
    ) -> list[dict[str, Any]]:
        proxy_id = get_proxy_id()
        lim = max(5, min(200, int(limit)))
        search_value = (search or "").strip().lower()
        hit_sql = self._hit_sql("result_code")
        reason_sql = self._not_cached_reason_sql()
        where = [
            "proxy_id = %s",
            "ts >= %s",
            self._present_sql("domain"),
            f"NOT {hit_sql}",
        ]
        params: list[Any] = [proxy_id, int(since)]
        if search_value:
            like = f"%{_escape_like(search_value)}%"
            where.append(
                "("
                "LOWER(domain) LIKE %s ESCAPE '\\\\' OR LOWER(client_ip) LIKE %s ESCAPE '\\\\' OR LOWER(url) LIKE %s ESCAPE '\\\\'"
                ")",
            )
            params.extend([like, like, like])
        where_sql = "WHERE " + " AND ".join(where)

        if sort == "recent":
            order_by = "last_seen DESC, requests DESC"
        elif sort == "domains":
            order_by = "domains DESC, requests DESC, last_seen DESC"
        elif sort == "clients":
            order_by = "clients DESC, requests DESC, last_seen DESC"
        else:
            order_by = "requests DESC, last_seen DESC"

        with self._connect() as conn:
            total_row = conn.execute(
                f"SELECT COUNT(*) FROM diagnostic_requests {where_sql}",
                tuple(params),
            ).fetchone()
            rows = conn.execute(
                f"""
                SELECT
                    {reason_sql} AS reason,
                    COUNT(*) AS requests,
                    COUNT(DISTINCT domain) AS domains,
                    COUNT(DISTINCT client_ip) AS clients,
                    MAX(ts) AS last_seen
                FROM diagnostic_requests
                {where_sql}
                GROUP BY reason
                ORDER BY {order_by}
                LIMIT %s
                """,
                (*params, lim),
            ).fetchall()

        total_requests = int(total_row[0] or 0) if total_row else 0
        return [
            {
                "reason": str(row[0] or ""),
                "requests": int(row[1] or 0),
                "domains": int(row[2] or 0),
                "clients": int(row[3] or 0),
                "last_seen": int(row[4] or 0),
                "pct": _pct(int(row[1] or 0), total_requests),
            }
            for row in rows
        ]

    def ssl_overview(
        self,
        *,
        since: int,
        search: str = "",
        limit: int = 50,
    ) -> dict[str, Any]:
        store = get_ssl_errors_store()
        with contextlib.suppress(Exception):
            store.init_db()
        raw_rows = store.list_recent(
            since=since,
            search=search,
            limit=max(10, min(500, int(limit))),
        )
        presented = present_ssl_error_rows(raw_rows)
        category_counts: Counter[str] = Counter()
        for row in presented["rows"]:
            category_counts[
                str(row.get("category_label") or row.get("category") or "Other")
            ] += int(row.get("count") or 0)
        return {
            "summary": presented["summary"],
            "rows": presented["rows"],
            "top_domains": present_ssl_top_domains(
                store.top_domains(since=since, search=search, limit=10),
                limit=10,
            ),
            "exclusion_candidates": present_ssl_exclusion_candidates(
                store.suggest_exclusion_candidates(
                    since=since, search=search, limit=10
                ),
            ),
            "top_categories": _badge_rows(category_counts, limit=6),
            "hints": presented["hints"],
        }

    @staticmethod
    def _security_event_filters(
        *,
        since: int,
        search: str,
        base_conditions: list[str] | None = None,
        search_columns: tuple[str, ...],
    ) -> tuple[str, list[Any]]:
        where = ["proxy_id = %s", "ts >= %s", *(base_conditions or [])]
        params: list[Any] = [get_proxy_id(), int(since)]
        search_value = (search or "").strip().lower()
        if search_value:
            like = f"%{_escape_like(search_value)}%"
            where.append(
                "("
                + " OR ".join(
                    f"LOWER({column}) LIKE %s ESCAPE '\\\\'"
                    for column in search_columns
                )
                + ")",
            )
            params.extend([like] * len(search_columns))
        return "WHERE " + " AND ".join(where), params

    def security_overview(
        self,
        *,
        since: int,
        search: str = "",
        limit: int = 50,
    ) -> dict[str, Any]:
        lim = max(5, min(100, int(limit)))
        search_value = (search or "").strip().lower()
        diagnostic_store = get_diagnostic_store()
        get_adblock_store().init_db()
        get_webfilter_store().init_db()

        av_where_sql, av_params = self._security_event_filters(
            since=since,
            search=search,
            base_conditions=["service_family = 'av'"],
            search_columns=(
                "domain",
                "url",
                "client_ip",
                "adapt_summary",
                "adapt_details",
            ),
        )
        av_finding_sql = self._av_finding_sql()

        adblock_where_sql, adblock_params = self._security_event_filters(
            since=since,
            search=search,
            search_columns=("url", "src_ip"),
        )

        webfilter_where_sql, webfilter_params = self._security_event_filters(
            since=since,
            search=search,
            search_columns=("url", "src_ip", "category"),
        )

        with self._connect() as conn:
            av_summary_row = conn.execute(
                f"""
                SELECT
                    COUNT(*) AS events,
                    COALESCE(SUM(CASE WHEN {av_finding_sql} THEN 1 ELSE 0 END), 0) AS findings,
                    MAX(ts) AS last_seen
                FROM diagnostic_icap_events
                {av_where_sql}
                """,
                tuple(av_params),
            ).fetchone()
            adblock_summary_row = conn.execute(
                f"""
                SELECT COUNT(*) AS blocks, COUNT(DISTINCT src_ip) AS clients, MAX(ts) AS last_seen
                FROM adblock_events
                {adblock_where_sql}
                """,
                tuple(adblock_params),
            ).fetchone()
            webfilter_summary_row = conn.execute(
                f"""
                SELECT COUNT(*) AS blocks, COUNT(DISTINCT src_ip) AS clients, COUNT(DISTINCT category) AS categories, MAX(ts) AS last_seen
                FROM webfilter_blocked_log
                {webfilter_where_sql}
                """,
                tuple(webfilter_params),
            ).fetchone()
            top_adblock_domains_rows = conn.execute(
                f"""
                SELECT {self._url_host_sql("url")} AS domain, COUNT(*) AS blocks, COUNT(DISTINCT src_ip) AS clients, MAX(ts) AS last_seen
                FROM adblock_events
                {adblock_where_sql}
                GROUP BY domain
                HAVING domain <> ''
                ORDER BY blocks DESC, last_seen DESC
                LIMIT %s
                """,
                (*adblock_params, min(lim, 10)),
            ).fetchall()
            top_webfilter_category_rows = conn.execute(
                f"""
                SELECT category, COUNT(*) AS blocks, MAX(ts) AS last_seen
                FROM webfilter_blocked_log
                {webfilter_where_sql}
                GROUP BY category
                ORDER BY blocks DESC, last_seen DESC
                LIMIT %s
                """,
                (*webfilter_params, min(lim, 10)),
            ).fetchall()
            top_webfilter_domain_rows = conn.execute(
                f"""
                SELECT {self._url_host_sql("url")} AS domain, COUNT(*) AS blocks, COUNT(DISTINCT src_ip) AS clients, MAX(ts) AS last_seen
                FROM webfilter_blocked_log
                {webfilter_where_sql}
                GROUP BY domain
                HAVING domain <> ''
                ORDER BY blocks DESC, last_seen DESC
                LIMIT %s
                """,
                (*webfilter_params, min(lim, 10)),
            ).fetchall()
            adblock_recent_rows = conn.execute(
                f"""
                SELECT ts, src_ip, method, url, http_status
                FROM adblock_events
                {adblock_where_sql}
                ORDER BY ts DESC, id DESC
                LIMIT %s
                """,
                (*adblock_params, min(max(lim * 2, 20), 100)),
            ).fetchall()
            webfilter_recent_rows = conn.execute(
                f"""
                SELECT ts, src_ip, url, category
                FROM webfilter_blocked_log
                {webfilter_where_sql}
                ORDER BY ts DESC, id DESC
                LIMIT %s
                """,
                (*webfilter_params, min(max(lim * 2, 20), 100)),
            ).fetchall()

        av_raw = diagnostic_store.list_recent_icap(
            since=since,
            search=search_value,
            service="av",
            limit=max(lim, 20),
        )
        av_enriched: list[dict[str, Any]] = []
        av_target_counter: Counter[str] = Counter()
        for row in av_raw:
            event = dict(row)
            status = self._av_status(
                str(event.get("adapt_summary") or ""),
                str(event.get("adapt_details") or ""),
            )
            meta = self._av_status_meta(status)
            event["av_status"] = status
            event["av_status_label"] = meta["label"]
            event["av_status_tone"] = meta["tone"]
            if status == "finding":
                av_target_counter[
                    str(event.get("target_display") or event.get("domain") or "-")
                ] += 1
            av_enriched.append(event)
        av_enriched.sort(
            key=lambda row: (
                0
                if row.get("av_status") == "finding"
                else (1 if row.get("av_status") == "activity" else 2),
                -int(row.get("ts") or 0),
            ),
        )
        av_enriched = _correlate_icap_events_with_requests(
            diagnostic_store,
            av_enriched,
            icap_limit=3,
        )

        adblock_rows = [
            {
                "ts": int(row[0] or 0),
                "src_ip": str(row[1] or ""),
                "method": str(row[2] or ""),
                "url": str(row[3] or ""),
                "domain": _extract_domain(row[3]),
                "http_status": int(row[4] or 0),
                "result": "BLOCKED",
            }
            for row in adblock_recent_rows
        ]
        webfilter_rows = [
            {
                "ts": int(row[0] or 0),
                "src_ip": str(row[1] or ""),
                "url": str(row[2] or ""),
                "domain": _extract_domain(row[2]),
                "category": str(row[3] or ""),
                "result": "BLOCKED",
            }
            for row in webfilter_recent_rows
        ]
        correlation_window = int(time.time()) - int(since)
        adblock_rows = _correlate_policy_events_with_requests(
            diagnostic_store,
            adblock_rows,
            window_seconds=correlation_window,
            service="adblock",
        )
        webfilter_rows = _correlate_policy_events_with_requests(
            diagnostic_store,
            webfilter_rows,
            window_seconds=correlation_window,
        )

        return {
            "summary": {
                "av_events": int(av_summary_row[0] or 0) if av_summary_row else 0,
                "potential_findings": int(av_summary_row[1] or 0)
                if av_summary_row
                else 0,
                "av_last_seen": int(av_summary_row[2] or 0) if av_summary_row else 0,
                "adblock_blocks": int(adblock_summary_row[0] or 0)
                if adblock_summary_row
                else 0,
                "adblock_clients": int(adblock_summary_row[1] or 0)
                if adblock_summary_row
                else 0,
                "adblock_last_seen": int(adblock_summary_row[2] or 0)
                if adblock_summary_row
                else 0,
                "webfilter_blocks": int(webfilter_summary_row[0] or 0)
                if webfilter_summary_row
                else 0,
                "webfilter_clients": int(webfilter_summary_row[1] or 0)
                if webfilter_summary_row
                else 0,
                "webfilter_categories": int(webfilter_summary_row[2] or 0)
                if webfilter_summary_row
                else 0,
                "webfilter_last_seen": int(webfilter_summary_row[3] or 0)
                if webfilter_summary_row
                else 0,
                "combined_blocks": (
                    int(adblock_summary_row[0] or 0) if adblock_summary_row else 0
                )
                + (int(webfilter_summary_row[0] or 0) if webfilter_summary_row else 0),
            },
            "av_rows": present_icap_events(av_enriched, limit=lim),
            "av_top_targets": _badge_rows(av_target_counter, limit=6),
            "adblock_rows": adblock_rows[:lim],
            "adblock_top_domains": [
                {
                    "domain": str(row[0] or ""),
                    "blocks": int(row[1] or 0),
                    "clients": int(row[2] or 0),
                    "last_seen": int(row[3] or 0),
                }
                for row in top_adblock_domains_rows
            ],
            "webfilter_rows": webfilter_rows[:lim],
            "webfilter_top_categories": [
                {
                    "category": str(row[0] or ""),
                    "blocks": int(row[1] or 0),
                    "last_seen": int(row[2] or 0),
                }
                for row in top_webfilter_category_rows
            ],
            "webfilter_top_domains": [
                {
                    "domain": str(row[0] or ""),
                    "blocks": int(row[1] or 0),
                    "clients": int(row[2] or 0),
                    "last_seen": int(row[3] or 0),
                }
                for row in top_webfilter_domain_rows
            ],
            "notes": [
                "AV findings are best-effort string matches over the AV ICAP trace stream. If the scanner logs only generic allow/clean messages, suspicious hits may not appear here.",
                "Adblock and web-filter rows come from explicit block logs, so they are stronger evidence of enforcement than ICAP activity counts alone.",
            ],
        }

    def performance_overview(
        self,
        *,
        since: int,
        limit: int = 10,
        summary: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        diagnostic_store = get_diagnostic_store()
        lim = max(3, min(20, int(limit)))
        diagnostic_summary = summary or diagnostic_store.activity_summary(since=since)
        if summary is not None:
            diagnostic_summary = {
                **summary,
                "requests": summary.get("requests", summary.get("request_records")),
                "domains": summary.get("domains", summary.get("destinations")),
            }
        summary_payload = present_observability_summary(
            diagnostic_summary=diagnostic_summary,
            ssl_summary={},
        )
        return {
            "summary": summary_payload,
            "slow_requests": present_transaction_rows(
                diagnostic_store.slowest_requests(since=since, limit=lim),
                icap_limit=0,
            ),
            "slow_icap_events": present_icap_events(
                diagnostic_store.slowest_icap_events(since=since, limit=lim),
                limit=lim,
            ),
            "top_user_agents": present_top_value_rows(
                diagnostic_store.top_request_dimension(
                    "user_agent",
                    since=since,
                    limit=8,
                ),
                max_label=72,
            ),
            "top_bump_modes": present_top_value_rows(
                diagnostic_store.top_request_dimension(
                    "bump_mode",
                    since=since,
                    limit=8,
                ),
                max_label=40,
            ),
            "top_tls_server_versions": present_top_value_rows(
                diagnostic_store.top_request_dimension(
                    "tls_server_version",
                    since=since,
                    limit=8,
                ),
                max_label=40,
            ),
            "top_policy_tags": present_top_tag_rows(
                diagnostic_store.top_policy_tags(since=since, limit=10),
                max_label=64,
            ),
            "av_icap_summary": diagnostic_store.icap_summary(since=since, service="av"),
            "adblock_icap_summary": diagnostic_store.icap_summary(
                since=since,
                service="adblock",
            ),
        }

    def cache_savings(self, *, since: int, search: str = "") -> dict[str, Any]:
        proxy_id = get_proxy_id()
        search_value = (search or "").strip().lower()
        hit_sql = self._hit_sql("result_code")
        where = ["proxy_id = %s", "ts >= %s", self._present_sql("domain")]
        params: list[Any] = [proxy_id, int(since)]
        if search_value:
            like = f"%{_escape_like(search_value)}%"
            where.append(
                "("
                "LOWER(domain) LIKE %s ESCAPE '\\\\' OR LOWER(client_ip) LIKE %s ESCAPE '\\\\' OR LOWER(url) LIKE %s ESCAPE '\\\\'"
                ")",
            )
            params.extend([like, like, like])
        where_sql = "WHERE " + " AND ".join(where)
        with self._connect() as conn:
            row = conn.execute(
                f"""
                SELECT
                    COUNT(*) AS requests,
                    COALESCE(SUM(bytes), 0) AS total_bytes,
                    COALESCE(SUM(CASE WHEN {hit_sql} THEN 1 ELSE 0 END), 0) AS hit_requests,
                    COALESCE(SUM(CASE WHEN {hit_sql} THEN bytes ELSE 0 END), 0) AS hit_bytes,
                    COALESCE(SUM(CASE WHEN NOT {hit_sql} THEN bytes ELSE 0 END), 0) AS miss_bytes
                FROM diagnostic_requests
                {where_sql}
                """,
                tuple(params),
            ).fetchone()
        total_bytes = int(row[1] or 0) if row else 0
        hit_bytes = int(row[3] or 0) if row else 0
        return {
            "requests": int(row[0] or 0) if row else 0,
            "total_bytes": total_bytes,
            "hit_requests": int(row[2] or 0) if row else 0,
            "hit_bytes": hit_bytes,
            "miss_bytes": int(row[4] or 0) if row else 0,
            "estimated_saved_bytes": hit_bytes,
            "byte_hit_pct": _pct(hit_bytes, total_bytes),
        }

    def top_users_by_bandwidth(
        self,
        *,
        since: int,
        search: str = "",
        limit: int = 50,
        resolve_hostnames: bool = True,
        privacy: bool = False,
    ) -> list[dict[str, Any]]:
        proxy_id = get_proxy_id()
        lim = max(5, min(200, int(limit)))
        search_value = (search or "").strip().lower()
        hit_sql = self._hit_sql("result_code")
        tx_sql = self._request_identity_sql("id", "master_xaction")
        where = ["proxy_id = %s", "ts >= %s", self._present_sql("client_ip")]
        params: list[Any] = [proxy_id, int(since)]
        if search_value:
            like = f"%{_escape_like(search_value)}%"
            where.append(
                "(LOWER(client_ip) LIKE %s ESCAPE '\\\\' OR LOWER(domain) LIKE %s ESCAPE '\\\\' OR LOWER(url) LIKE %s ESCAPE '\\\\')",
            )
            params.extend([like, like, like])
        where_sql = "WHERE " + " AND ".join(where)
        with self._connect() as conn:
            total_row = conn.execute(
                f"SELECT COALESCE(SUM(bytes), 0) FROM diagnostic_requests {where_sql}",
                tuple(params),
            ).fetchone()
            rows = conn.execute(
                f"""
                SELECT
                    client_ip,
                    COUNT(*) AS requests,
                    COUNT(DISTINCT domain) AS destinations,
                    COUNT(DISTINCT {tx_sql}) AS transactions,
                    COALESCE(SUM(bytes), 0) AS bytes_total,
                    COALESCE(SUM(CASE WHEN {hit_sql} THEN bytes ELSE 0 END), 0) AS cache_hit_bytes,
                    COALESCE(SUM(CASE WHEN {hit_sql} THEN 1 ELSE 0 END), 0) AS cache_hits,
                    MAX(ts) AS last_seen
                FROM diagnostic_requests
                {where_sql}
                GROUP BY client_ip
                ORDER BY bytes_total DESC, requests DESC, last_seen DESC
                LIMIT %s
                """,
                (*params, lim),
            ).fetchall()
        total_bytes = int(total_row[0] or 0) if total_row else 0
        out: list[dict[str, Any]] = []
        for row in rows:
            ip = str(row[0] or "")
            out.append(
                {
                    "client_ip": "" if privacy else ip,
                    "client_label": _pseudonymize(ip, namespace="user")
                    if privacy
                    else ip,
                    "requests": int(row[1] or 0),
                    "destinations": int(row[2] or 0),
                    "transactions": int(row[3] or 0),
                    "bytes": int(row[4] or 0),
                    "cache_hit_bytes": int(row[5] or 0),
                    "cache_hits": int(row[6] or 0),
                    "last_seen": int(row[7] or 0),
                    "pct_bytes": _pct(int(row[4] or 0), total_bytes),
                    "hostname": "",
                    "hostname_source": "",
                    "hostname_status": "disabled",
                },
            )
        if resolve_hostnames and out and not privacy:
            cache = get_client_identity_cache()
            resolved = cache.resolve_many(row["client_ip"] for row in out)
            for row in out:
                row.update(
                    resolved.get(
                        row["client_ip"],
                        {
                            "hostname": "",
                            "hostname_source": "",
                            "hostname_status": "unresolved",
                        },
                    ),
                )
        return out

    def top_spliced_destinations(
        self,
        *,
        since: int,
        search: str = "",
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        proxy_id = get_proxy_id()
        lim = max(5, min(200, int(limit)))
        search_value = (search or "").strip().lower()
        where = [
            "proxy_id = %s",
            "ts >= %s",
            self._present_sql("domain"),
            "LOWER(COALESCE(bump_mode, '')) LIKE '%%splice%%'",
        ]
        params: list[Any] = [proxy_id, int(since)]
        if search_value:
            like = f"%{_escape_like(search_value)}%"
            where.append(
                "(LOWER(domain) LIKE %s ESCAPE '\\\\' OR LOWER(client_ip) LIKE %s ESCAPE '\\\\' OR LOWER(url) LIKE %s ESCAPE '\\\\')",
            )
            params.extend([like, like, like])
        where_sql = "WHERE " + " AND ".join(where)
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT domain, COUNT(*) AS requests, COUNT(DISTINCT client_ip) AS clients, COALESCE(SUM(bytes), 0) AS bytes_total, MAX(ts) AS last_seen
                FROM diagnostic_requests
                {where_sql}
                GROUP BY domain
                ORDER BY requests DESC, bytes_total DESC, last_seen DESC
                LIMIT %s
                """,
                (*params, lim),
            ).fetchall()
        return [
            {
                "domain": str(row[0] or ""),
                "requests": int(row[1] or 0),
                "clients": int(row[2] or 0),
                "bytes": int(row[3] or 0),
                "last_seen": int(row[4] or 0),
            }
            for row in rows
        ]

    def top_malware_attempts(
        self,
        *,
        since: int,
        search: str = "",
        limit: int = 50,
        privacy: bool = False,
    ) -> list[dict[str, Any]]:
        proxy_id = get_proxy_id()
        lim = max(5, min(200, int(limit)))
        search_value = (search or "").strip().lower()
        where = [
            "proxy_id = %s",
            "ts >= %s",
            "service_family = 'av'",
            self._av_finding_sql(),
        ]
        params: list[Any] = [proxy_id, int(since)]
        if search_value:
            like = f"%{_escape_like(search_value)}%"
            where.append(
                "(LOWER(domain) LIKE %s ESCAPE '\\\\' OR LOWER(url) LIKE %s ESCAPE '\\\\' OR LOWER(client_ip) LIKE %s ESCAPE '\\\\' OR LOWER(adapt_summary) LIKE %s ESCAPE '\\\\')",
            )
            params.extend([like, like, like, like])
        where_sql = "WHERE " + " AND ".join(where)
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT domain, client_ip, COUNT(*) AS attempts, MAX(ts) AS last_seen, MAX(adapt_summary) AS sample
                FROM diagnostic_icap_events
                {where_sql}
                GROUP BY domain, client_ip
                ORDER BY attempts DESC, last_seen DESC
                LIMIT %s
                """,
                (*params, lim),
            ).fetchall()
        return [
            {
                "domain": str(row[0] or ""),
                "client_ip": "" if privacy else str(row[1] or ""),
                "client_label": _pseudonymize(row[1], namespace="user")
                if privacy
                else str(row[1] or ""),
                "attempts": int(row[2] or 0),
                "last_seen": int(row[3] or 0),
                "sample": str(row[4] or ""),
            }
            for row in rows
        ]

    def _ensure_report_schedule_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS observability_report_schedules (
                    id BIGINT PRIMARY KEY AUTO_INCREMENT,
                    proxy_id VARCHAR(64) NOT NULL DEFAULT 'default',
                    enabled TINYINT(1) NOT NULL DEFAULT 1,
                    name VARCHAR(120) NOT NULL,
                    cadence VARCHAR(16) NOT NULL,
                    recipients VARCHAR(512) NOT NULL,
                    pane VARCHAR(32) NOT NULL,
                    report_format VARCHAR(16) NOT NULL,
                    privacy TINYINT(1) NOT NULL DEFAULT 1,
                    window_seconds INT NOT NULL,
                    created_ts BIGINT NOT NULL,
                    updated_ts BIGINT NOT NULL,
                    next_run_ts BIGINT NOT NULL DEFAULT 0,
                    last_run_ts BIGINT NOT NULL DEFAULT 0,
                    last_status VARCHAR(64) NOT NULL DEFAULT '',
                    KEY idx_obs_report_schedules_proxy_next (proxy_id, enabled, next_run_ts),
                    KEY idx_obs_report_schedules_proxy_updated (proxy_id, updated_ts)
                )
                """,
            )

    def report_schedules(self, *, limit: int = 20) -> list[dict[str, Any]]:
        self._ensure_report_schedule_db()
        proxy_id = get_proxy_id()
        lim = max(1, min(100, int(limit or 20)))
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, enabled, name, cadence, recipients, pane, report_format, privacy,
                       window_seconds, next_run_ts, last_run_ts, last_status, updated_ts
                FROM observability_report_schedules
                WHERE proxy_id = %s
                ORDER BY enabled DESC, next_run_ts ASC, updated_ts DESC
                LIMIT %s
                """,
                (proxy_id, lim),
            ).fetchall()
        return [
            {
                "id": int(row[0] or 0),
                "enabled": bool(row[1]),
                "name": str(row[2] or ""),
                "cadence": str(row[3] or "daily"),
                "recipients": str(row[4] or ""),
                "pane": str(row[5] or "reports"),
                "report_format": str(row[6] or "csv"),
                "privacy": bool(row[7]),
                "window_seconds": int(row[8] or 86400),
                "next_run_ts": int(row[9] or 0),
                "last_run_ts": int(row[10] or 0),
                "last_status": str(row[11] or ""),
                "updated_ts": int(row[12] or 0),
            }
            for row in rows
        ]

    def save_report_schedule(
        self,
        *,
        name: str,
        cadence: str,
        recipients: str,
        pane: str = "reports",
        report_format: str = "csv",
        privacy: bool = True,
        window_seconds: int = 86400,
        enabled: bool = True,
    ) -> dict[str, Any]:
        self._ensure_report_schedule_db()
        now = int(time.time())
        cadence_s = str(cadence or "daily").strip().lower()
        if cadence_s not in {"daily", "weekly"}:
            cadence_s = "daily"
        pane_s = str(pane or "reports").strip().lower()
        if pane_s not in {
            "reports",
            "overview",
            "destinations",
            "clients",
            "cache",
            "ssl",
            "security",
            "performance",
        }:
            pane_s = "reports"
        fmt_s = str(report_format or "csv").strip().lower()
        if fmt_s not in {"csv", "json", "jsonl"}:
            fmt_s = "csv"
        window_i = max(300, min(7 * 24 * 3600, int(window_seconds or 86400)))
        name_s = (
            str(name or "").strip()[:120] or f"{cadence_s.title()} observability report"
        )
        recipients_s = str(recipients or "").strip()[:512]
        if not recipients_s:
            msg = "At least one report recipient is required."
            raise ValueError(msg)
        proxy_id = get_proxy_id()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO observability_report_schedules(
                    proxy_id, enabled, name, cadence, recipients, pane, report_format, privacy,
                    window_seconds, created_ts, updated_ts, next_run_ts, last_run_ts, last_status
                )
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,0,'configured')
                """,
                (
                    proxy_id,
                    1 if enabled else 0,
                    name_s,
                    cadence_s,
                    recipients_s,
                    pane_s,
                    fmt_s,
                    1 if privacy else 0,
                    window_i,
                    now,
                    now,
                    _next_schedule_run_ts(cadence_s, now),
                ),
            )
        return self.report_schedules(limit=1)[0]

    def audit_activity(self, *, since: int, limit: int = 20) -> dict[str, Any]:
        proxy_id = get_proxy_id()
        lim = max(5, min(100, int(limit or 20)))
        try:
            with self._connect() as conn:
                summary = conn.execute(
                    """
                    SELECT COUNT(*) AS events,
                           COALESCE(SUM(CASE WHEN ok = 0 THEN 1 ELSE 0 END), 0) AS failed_events,
                           MAX(ts) AS last_seen
                    FROM audit_events
                    WHERE proxy_id = %s AND ts >= %s
                    """,
                    (proxy_id, int(since)),
                ).fetchone()
                kinds = conn.execute(
                    """
                    SELECT kind, COUNT(*) AS events, MAX(ts) AS last_seen
                    FROM audit_events
                    WHERE proxy_id = %s AND ts >= %s
                    GROUP BY kind
                    ORDER BY events DESC, last_seen DESC
                    LIMIT %s
                    """,
                    (proxy_id, int(since), lim),
                ).fetchall()
                recent = conn.execute(
                    """
                    SELECT ts, kind, ok, remote_addr, detail
                    FROM audit_events
                    WHERE proxy_id = %s AND ts >= %s
                    ORDER BY ts DESC, id DESC
                    LIMIT %s
                    """,
                    (proxy_id, int(since), lim),
                ).fetchall()
        except Exception:
            return {
                "summary": {"events": 0, "failed_events": 0, "last_seen": 0},
                "top_kinds": [],
                "recent": [],
            }
        return {
            "summary": {
                "events": int(summary[0] or 0) if summary else 0,
                "failed_events": int(summary[1] or 0) if summary else 0,
                "last_seen": int(summary[2] or 0) if summary else 0,
            },
            "top_kinds": [
                {
                    "kind": str(row[0] or ""),
                    "events": int(row[1] or 0),
                    "last_seen": int(row[2] or 0),
                }
                for row in kinds
            ],
            "recent": [
                {
                    "ts": int(row[0] or 0),
                    "kind": str(row[1] or ""),
                    "ok": bool(row[2]),
                    "remote_addr": str(row[3] or ""),
                    "detail": str(row[4] or ""),
                }
                for row in recent
            ],
        }

    def time_series_health(self) -> dict[str, Any]:
        proxy_id = get_proxy_id()
        out: dict[str, Any] = {"tables": [], "latest_ts": 0, "rollup_points": 0}
        for table in ("ts_1m", "ts_1h", "ts_1d"):
            try:
                with self._connect() as conn:
                    row = conn.execute(
                        f"SELECT COUNT(*) AS points, MAX(ts) AS latest_ts FROM {table} WHERE proxy_id = %s",
                        (proxy_id,),
                    ).fetchone()
            except Exception:
                out["tables"].append(
                    {"table": table, "points": 0, "latest_ts": 0, "status": "missing"},
                )
                continue
            points = int(row[0] or 0) if row else 0
            latest = int(row[1] or 0) if row else 0
            out["tables"].append(
                {
                    "table": table,
                    "points": points,
                    "latest_ts": latest,
                    "status": "ready",
                },
            )
            out["rollup_points"] += points
            out["latest_ts"] = max(int(out["latest_ts"] or 0), latest)
        return out

    def top_client_groups(
        self,
        *,
        since: int,
        search: str = "",
        limit: int = 50,
        privacy: bool = False,
    ) -> list[dict[str, Any]]:
        proxy_id = get_proxy_id()
        lim = max(5, min(200, int(limit)))
        search_value = (search or "").strip().lower()
        hit_sql = self._hit_sql("result_code")
        group_sql = (
            "CASE "
            "WHEN client_ip LIKE '%%.%%.%%.%%' THEN CONCAT(SUBSTRING_INDEX(client_ip, '.', 3), '.0/24') "
            "ELSE client_ip END"
        )
        where = ["proxy_id = %s", "ts >= %s", self._present_sql("client_ip")]
        params: list[Any] = [proxy_id, int(since)]
        if search_value:
            like = f"%{_escape_like(search_value)}%"
            where.append(
                "(LOWER(client_ip) LIKE %s ESCAPE '\\\\' OR LOWER(domain) LIKE %s ESCAPE '\\\\' OR LOWER(url) LIKE %s ESCAPE '\\\\')",
            )
            params.extend([like, like, like])
        where_sql = "WHERE " + " AND ".join(where)
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT
                    {group_sql} AS group_key,
                    COUNT(*) AS requests,
                    COUNT(DISTINCT client_ip) AS clients,
                    COUNT(DISTINCT domain) AS destinations,
                    COALESCE(SUM(bytes), 0) AS bytes_total,
                    COALESCE(SUM(CASE WHEN {hit_sql} THEN bytes ELSE 0 END), 0) AS cache_hit_bytes,
                    MAX(ts) AS last_seen
                FROM diagnostic_requests
                {where_sql}
                GROUP BY group_key
                ORDER BY bytes_total DESC, requests DESC, last_seen DESC
                LIMIT %s
                """,
                (*params, lim),
            ).fetchall()
        return [
            {
                "group": _pseudonymize(row[0], namespace="group")
                if privacy
                else str(row[0] or ""),
                "requests": int(row[1] or 0),
                "clients": int(row[2] or 0),
                "destinations": int(row[3] or 0),
                "bytes": int(row[4] or 0),
                "cache_hit_bytes": int(row[5] or 0),
                "last_seen": int(row[6] or 0),
                "group_source": "client_subnet",
            }
            for row in rows
        ]

    @staticmethod
    def _suggestion_row(
        *,
        kind: str,
        component: str,
        severity: str,
        title: str,
        subject: str,
        subject_type: str = "domain",
        count: int,
        clients: int,
        last_seen: int,
        confidence: str,
        recommended_action: str,
        evidence: str,
    ) -> dict[str, Any]:
        return {
            "kind": kind,
            "component": component,
            "severity": severity,
            "title": title,
            "subject": subject,
            "subject_type": subject_type,
            "count": int(count or 0),
            "clients": int(clients or 0),
            "last_seen": int(last_seen or 0),
            "confidence": confidence,
            "recommended_action": recommended_action,
            "evidence": evidence,
        }

    @staticmethod
    def _suggestion_matches_search(row: dict[str, Any], search_value: str) -> bool:
        needle = (search_value or "").strip().lower()
        if not needle:
            return True
        haystack = " ".join(
            str(row.get(key) or "")
            for key in (
                "kind",
                "component",
                "severity",
                "title",
                "subject",
                "confidence",
                "recommended_action",
                "evidence",
            )
        ).lower()
        return needle in haystack

    @staticmethod
    def _suggestion_visible_during_search(row: dict[str, Any]) -> bool:
        return (row.get("subject_type") or "domain") == "proxy" and row.get(
            "kind",
        ) in {
            "mysql_degraded",
            "proxy_health_unreachable",
            "runtime_state_degraded",
        }

    @staticmethod
    def _runtime_health_suggestions(
        runtime_health: dict[str, Any] | None,
    ) -> list[dict[str, Any]]:
        if not isinstance(runtime_health, dict) or not runtime_health:
            return []

        proxy_id = str(runtime_health.get("proxy_id") or get_proxy_id())
        observed_at = _int_or(runtime_health.get("timestamp"), int(time.time()))
        rows: list[dict[str, Any]] = []

        def add(
            *,
            kind: str,
            component: str,
            severity: str,
            title: str,
            count: int,
            confidence: str,
            recommended_action: str,
            evidence: str,
        ) -> None:
            rows.append(
                ObservabilityQueries._suggestion_row(
                    kind=kind,
                    component=component,
                    severity=severity,
                    title=title,
                    subject=proxy_id,
                    subject_type="proxy",
                    count=count,
                    clients=0,
                    last_seen=observed_at,
                    confidence=confidence,
                    recommended_action=recommended_action,
                    evidence=evidence[:240],
                ),
            )

        detail_text = " ".join(
            str(runtime_health.get(key) or "")
            for key in ("detail", "health_cache_detail", "proxy_status")
        ).strip()
        state_errors = normalize_runtime_health_state_errors(
            runtime_health.get("state_errors")
        )
        services = (
            runtime_health.get("services")
            if isinstance(runtime_health.get("services"), dict)
            else {}
        )
        stats = (
            runtime_health.get("stats")
            if isinstance(runtime_health.get("stats"), dict)
            else {}
        )

        if runtime_health.get("_unavailable_cached") or runtime_health.get(
            "status"
        ) in {"offline", "unavailable"}:
            add(
                kind="proxy_health_unreachable",
                component="Proxy runtime health",
                severity="high",
                title="Selected proxy runtime health is unreachable",
                count=1,
                confidence="medium",
                recommended_action="Verify the proxy management URL, management token, container state, and network path before trusting traffic-level conclusions.",
                evidence=detail_text
                or "Proxy health request returned an unavailable runtime payload.",
            )

        db_tokens = (
            "mysql",
            "database",
            "db pool",
            "pool exhausted",
            "too many connections",
            "lock wait",
            "server has gone away",
            "max_allowed_packet",
            "packet too large",
            "packet bigger than",
        )
        db_state_errors = [
            item
            for item in state_errors
            if any(token in item.lower() for token in db_tokens)
        ]
        db_text = " ".join([detail_text, *state_errors]).lower()
        if any(token in db_text for token in db_tokens):
            db_evidence_parts = [
                item
                for item in [detail_text, *db_state_errors]
                if item and any(token in item.lower() for token in db_tokens)
            ]
            add(
                kind="mysql_degraded",
                component="MySQL / observability ingestion",
                severity="high",
                title="Database or ingestion degradation observed",
                count=1,
                confidence="medium",
                recommended_action="Check MySQL health, credentials, connection limits, DB_POOL_SIZE, tailer pending-row warnings, and ingestion queue pressure before relying on trend data.",
                evidence="; ".join(db_evidence_parts).strip()
                or "Runtime health referenced database degradation.",
            )

        non_db_state_errors = [
            item
            for item in state_errors
            if not any(token in item.lower() for token in db_tokens)
        ]
        if non_db_state_errors:
            add(
                kind="runtime_state_degraded",
                component="Proxy generated state",
                severity="high",
                title="Proxy generated state does not match runtime",
                count=len(non_db_state_errors),
                confidence="high",
                recommended_action="Review the generated config, certificate bundle, adblock artifact, policy, and PAC state; then force a selected-proxy sync after confirming the desired state is correct.",
                evidence="; ".join(non_db_state_errors),
            )

        for service_name, service in services.items():
            if not isinstance(service, dict) or service.get("ok", True):
                continue
            service_detail = str(service.get("detail") or service_name)
            lowered = f"{service_name} {service_detail}".lower()
            if any(token in lowered for token in ("icap", "clamd", "clamav", "c-icap")):
                add(
                    kind="runtime_icap_degraded",
                    component="ICAP / ClamAV health",
                    severity="high",
                    title="ICAP or ClamAV runtime health is degraded",
                    count=1,
                    confidence="high",
                    recommended_action="Check supervisor state, c-icap listeners, clamd reachability, scan timeouts, fail-open/fail-closed policy, and memory pressure.",
                    evidence=f"{service_name}: {service_detail}",
                )

        memory = stats.get("memory") if isinstance(stats.get("memory"), dict) else {}
        used_percent = memory.get("used_percent")
        available_bytes = memory.get("available_bytes")
        try:
            used_value = float(used_percent) if used_percent is not None else None
        except Exception:
            used_value = None
        try:
            available_value = (
                int(available_bytes) if available_bytes is not None else None
            )
        except Exception:
            available_value = None
        if (used_value is not None and used_value >= 85.0) or (
            available_value is not None and available_value < 256 * 1024 * 1024
        ):
            evidence_parts = []
            if used_value is not None:
                evidence_parts.append(f"memory used {used_value:.1f}%")
            if available_value is not None:
                evidence_parts.append(
                    f"available {available_value // (1024 * 1024)} MiB"
                )
            add(
                kind="memory_pressure",
                component="Proxy runtime resources",
                severity="high"
                if used_value is not None and used_value >= 92.0
                else "medium",
                title="Proxy runtime memory pressure observed",
                count=1,
                confidence="medium",
                recommended_action="Increase the container memory cap, reduce Squid/ICAP/cache concurrency, or move side workloads off the constrained host before increasing inspection depth.",
                evidence=", ".join(evidence_parts)
                or "Runtime memory availability is low.",
            )

        return rows

    @staticmethod
    def _remediation_sort_key(row: dict[str, Any], sort: str) -> tuple[Any, ...]:
        severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(
            str(row.get("severity") or "").lower(),
            4,
        )
        confidence_rank = {"high": 0, "medium": 1, "low": 2}.get(
            str(row.get("confidence") or "").lower(),
            3,
        )
        if sort == "count":
            return (-int(row.get("count") or 0), severity_rank, confidence_rank)
        if sort == "recent":
            return (-int(row.get("last_seen") or 0), severity_rank, confidence_rank)
        return (
            confidence_rank,
            severity_rank,
            -int(row.get("count") or 0),
            -int(row.get("last_seen") or 0),
        )

    def remediation_overview(
        self,
        *,
        since: int,
        search: str = "",
        limit: int = 50,
        sort: str = "confidence",
        summary: dict[str, Any] | None = None,
        runtime_health: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        proxy_id = get_proxy_id()
        lim = max(10, min(200, int(limit or 50)))
        search_value = (search or "").strip().lower()
        query_lim = 200 if search_value else lim
        where = ["proxy_id = %s", "ts >= %s", self._present_sql("domain")]
        params: list[Any] = [proxy_id, int(since)]
        icap_where = ["proxy_id = %s", "ts >= %s", "domain <> ''"]
        icap_params: list[Any] = [proxy_id, int(since)]
        where_sql = "WHERE " + " AND ".join(where)
        icap_where_sql = "WHERE " + " AND ".join(icap_where)
        suggestions: list[dict[str, Any]] = self._runtime_health_suggestions(
            runtime_health
        )

        with self._connect() as conn:
            cf_rows = conn.execute(
                f"""
                SELECT domain, COUNT(*) AS observations, COUNT(DISTINCT client_ip) AS clients, MAX(ts) AS last_seen,
                       MAX(COALESCE(response_server, '')) AS sample_server
                FROM diagnostic_requests
                {where_sql}
                  AND (
                    LOWER(COALESCE(response_cf_mitigated, '')) = 'challenge'
                    OR (http_status = 403 AND LOWER(COALESCE(response_server, '')) LIKE '%%cloudflare%%')
                  )
                GROUP BY domain
                ORDER BY observations DESC, last_seen DESC
                LIMIT %s
                """,
                (*params, query_lim),
            ).fetchall()
            h3_rows = conn.execute(
                f"""
                SELECT domain, COUNT(*) AS observations, COUNT(DISTINCT client_ip) AS clients, MAX(ts) AS last_seen,
                       MAX(COALESCE(response_alt_svc, '')) AS sample_alt_svc
                FROM diagnostic_requests
                {where_sql}
                  AND LOWER(COALESCE(response_alt_svc, '')) REGEXP '(^|[^a-z0-9])h3[-=]'
                GROUP BY domain
                ORDER BY observations DESC, last_seen DESC
                LIMIT %s
                """,
                (*params, query_lim),
            ).fetchall()
            aborted_rows = conn.execute(
                f"""
                SELECT domain, COUNT(*) AS observations, COUNT(DISTINCT client_ip) AS clients, MAX(ts) AS last_seen,
                       MAX(COALESCE(response_content_type, '')) AS sample_type
                FROM diagnostic_requests
                {where_sql}
                  AND result_code LIKE 'TCP_MISS_ABORTED/%%'
                  AND (
                    LOWER(COALESCE(response_content_type, '')) REGEXP 'video|audio|mpegurl|dash'
                    OR LOWER(url) REGEXP '\\\\.(m4s|mp4|m3u8|mpd|ts)(\\\\?|$)'
                  )
                GROUP BY domain
                HAVING observations >= 3
                ORDER BY observations DESC, last_seen DESC
                LIMIT %s
                """,
                (*params, query_lim),
            ).fetchall()
            slow_icap_rows = conn.execute(
                f"""
                SELECT domain, service_family, COUNT(*) AS observations, COUNT(DISTINCT client_ip) AS clients,
                       MAX(ts) AS last_seen, MAX(icap_time_ms) AS max_icap_ms
                FROM diagnostic_icap_events
                {icap_where_sql}
                  AND icap_time_ms >= 1000
                GROUP BY domain, service_family
                ORDER BY observations DESC, max_icap_ms DESC, last_seen DESC
                LIMIT %s
                """,
                (*icap_params, query_lim),
            ).fetchall()
            icap_failure_rows = conn.execute(
                f"""
                SELECT domain, service_family, COUNT(*) AS observations, COUNT(DISTINCT client_ip) AS clients,
                       MAX(ts) AS last_seen, MAX(adapt_summary) AS sample_summary
                FROM diagnostic_icap_events
                {icap_where_sql}
                  AND LOWER(CONCAT(COALESCE(adapt_summary, ''), ' ', COALESCE(adapt_details, ''))) REGEXP 'fail|error|timeout|unreachable|bypass'
                GROUP BY domain, service_family
                ORDER BY observations DESC, last_seen DESC
                LIMIT %s
                """,
                (*icap_params, query_lim),
            ).fetchall()

        suggestions.extend(
            self._suggestion_row(
                kind="cloudflare_challenge",
                component="SSL inspection / upstream bot mitigation",
                severity="high",
                title="Cloudflare challenge observed through proxy",
                subject=str(row[0] or ""),
                count=int(row[1] or 0),
                clients=int(row[2] or 0),
                last_seen=int(row[3] or 0),
                confidence="high",
                recommended_action="Add a no-bump/splice rule for the domain and consider PAC DIRECT if the client app still fails.",
                evidence=f"HTTP 403 with Cloudflare mitigation metadata; sample server={row[4] or 'unknown'}",
            )
            for row in cf_rows
        )
        suggestions.extend(
            self._suggestion_row(
                kind="http3_alt_svc",
                component="HTTP/3 / QUIC routing",
                severity="medium",
                title="Origin advertises HTTP/3 over QUIC",
                subject=str(row[0] or ""),
                count=int(row[1] or 0),
                clients=int(row[2] or 0),
                last_seen=int(row[3] or 0),
                confidence="medium",
                recommended_action="Block or steer UDP/443 at the gateway for managed clients, then verify the browser/app is using the PAC/proxy path.",
                evidence=f"Alt-Svc advertises h3; sample={row[4] or 'not captured'}",
            )
            for row in h3_rows
        )
        suggestions.extend(
            self._suggestion_row(
                kind="aborted_media_segments",
                component="SSL inspection / media streaming",
                severity="medium",
                title="Repeated aborted media segment downloads",
                subject=str(row[0] or ""),
                count=int(row[1] or 0),
                clients=int(row[2] or 0),
                last_seen=int(row[3] or 0),
                confidence="medium",
                recommended_action="Consider no-bump/splice and cache-bypass for this media/CDN domain; use PAC DIRECT if the application is sensitive to inspection.",
                evidence=f"Repeated TCP_MISS_ABORTED media responses; sample type={row[4] or 'unknown'}",
            )
            for row in aborted_rows
        )
        for row in slow_icap_rows:
            service = str(row[1] or "icap")
            suggestions.append(
                self._suggestion_row(
                    kind="slow_icap",
                    component=f"ICAP {service}",
                    severity="medium",
                    title="Slow ICAP adaptation observed",
                    subject=str(row[0] or ""),
                    count=int(row[2] or 0),
                    clients=int(row[3] or 0),
                    last_seen=int(row[4] or 0),
                    confidence="medium",
                    recommended_action="Check c-icap/clamd latency, tune scan policy by MIME/size/domain, or add an exclusion for latency-sensitive traffic.",
                    evidence=f"Max ICAP latency {int(row[5] or 0)} ms",
                ),
            )
        for row in icap_failure_rows:
            service = str(row[1] or "icap")
            suggestions.append(
                self._suggestion_row(
                    kind="icap_degraded",
                    component=f"ICAP {service}",
                    severity="high",
                    title="ICAP degradation or bypass signal observed",
                    subject=str(row[0] or ""),
                    count=int(row[2] or 0),
                    clients=int(row[3] or 0),
                    last_seen=int(row[4] or 0),
                    confidence="high",
                    recommended_action="Check c-icap listener health, clamd reachability, fail-open/fail-closed policy, and proxy memory pressure.",
                    evidence=str(
                        row[5] or "ICAP trace contained failure/bypass language"
                    )[:240],
                ),
            )

        try:
            ssl_candidates: list[dict[str, Any]] = []
            seen_ssl_domains: set[str] = set()

            def add_ssl_candidates(payload: dict[str, Any]) -> None:
                for candidate in payload.get("exclusion_candidates", []):
                    domain = str(candidate.get("domain") or "")
                    if not domain or domain in seen_ssl_domains:
                        continue
                    seen_ssl_domains.add(domain)
                    ssl_candidates.append(candidate)

            add_ssl_candidates(self.ssl_overview(since=since, search=search, limit=lim))
            if search_value:
                add_ssl_candidates(
                    self.ssl_overview(since=since, search="", limit=query_lim),
                )

            for row in ssl_candidates[:query_lim]:
                domain = str(row.get("domain") or "")
                if not domain:
                    continue
                event_count = _int_or(row.get("count") or row.get("total"), 0)
                suggestions.append(
                    self._suggestion_row(
                        kind="ssl_exclusion_candidate",
                        component="SSL inspection",
                        severity="high" if event_count >= 5 else "medium",
                        title="Repeated TLS/SSL errors indicate likely inspection incompatibility",
                        subject=domain,
                        count=event_count,
                        clients=0,
                        last_seen=int(row.get("last_seen") or 0),
                        confidence="high",
                        recommended_action="Add a no-bump/splice rule for this domain, then retest the affected client workflow.",
                        evidence=str(
                            row.get("reason")
                            or row.get("category_label")
                            or "SSL error bucket"
                        ),
                    ),
                )
        except Exception:
            pass

        if search_value:
            suggestions = [
                row
                for row in suggestions
                if self._suggestion_matches_search(row, search_value)
                or self._suggestion_visible_during_search(row)
            ]
        suggestions.sort(key=lambda row: self._remediation_sort_key(row, sort))
        rows = suggestions[:lim]
        by_component = Counter(str(row.get("component") or "Other") for row in rows)
        by_kind = Counter(str(row.get("kind") or "other") for row in rows)
        domain_subjects = {
            str(row.get("subject") or "")
            for row in rows
            if row.get("subject") and (row.get("subject_type") or "domain") == "domain"
        }
        runtime_subjects = {
            str(row.get("subject") or "")
            for row in rows
            if row.get("subject") and (row.get("subject_type") or "domain") != "domain"
        }
        return {
            "summary": {
                "suggestions": len(rows),
                "high_confidence": sum(
                    1 for row in rows if row.get("confidence") == "high"
                ),
                "observations": sum(int(row.get("count") or 0) for row in rows),
                "domains": len(domain_subjects),
                "runtime_subjects": len(runtime_subjects),
                "latest": max([int(row.get("last_seen") or 0) for row in rows] or [0]),
                "http3_candidates": sum(
                    1 for row in rows if row.get("kind") == "http3_alt_svc"
                ),
            },
            "rows": rows,
            "top_components": _badge_rows(by_component, limit=6),
            "top_kinds": _badge_rows(by_kind, limit=6),
            "quic_guidance": [
                "PAC files can steer HTTP/HTTPS proxy use, but they cannot force a browser or app to send UDP/443 QUIC traffic through an HTTP proxy.",
                "On MikroTik/RouterOS, enforce managed-client QUIC policy with explicit forward-chain UDP/443 drop or reject rules for client subnets that must traverse the proxy.",
                "Client verification should include browser HTTP/3 disabled/blocked checks, PAC/WPAD assignment checks, and proof that the same domain appears in proxy observability after UDP/443 is blocked.",
                "Observed Alt-Svc h3 response headers are environment-derived candidates only; Docker Proxy does not ship an arbitrary static site list.",
            ],
            "summary_source": summary or self.summary(since=since),
        }

    def reporting_overview(
        self,
        *,
        since: int,
        search: str = "",
        limit: int = 50,
        resolve_hostnames: bool = True,
        privacy: bool = False,
        summary: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        lim = max(5, min(200, int(limit)))
        security = self.security_overview(
            since=since,
            search=search,
            limit=min(lim, 50),
        )
        ssl_payload = self.ssl_overview(since=since, search=search, limit=min(lim, 50))
        schedules = self.report_schedules(limit=10)
        return {
            "summary": summary or self.summary(since=since),
            "cache_savings": self.cache_savings(since=since, search=search),
            "top_users": self.top_users_by_bandwidth(
                since=since,
                search=search,
                limit=lim,
                resolve_hostnames=resolve_hostnames,
                privacy=privacy,
            ),
            "top_blocked_categories": security.get("webfilter_top_categories", []),
            "top_malware_attempts": self.top_malware_attempts(
                since=since,
                search=search,
                limit=lim,
                privacy=privacy,
            ),
            "top_ssl_bump_failures": ssl_payload.get("rows", [])[:lim],
            "top_spliced_destinations": self.top_spliced_destinations(
                since=since,
                search=search,
                limit=lim,
            ),
            "per_group": self.top_client_groups(
                since=since,
                search=search,
                limit=lim,
                privacy=privacy,
            ),
            "security": security,
            "audit": self.audit_activity(since=since, limit=min(lim, 20)),
            "time_series": self.time_series_health(),
            "schedules": schedules,
            "export_contracts": [
                {
                    "name": "CSV",
                    "status": "ready",
                    "endpoint": "/observability/export?pane=reports",
                },
                {
                    "name": "JSON",
                    "status": "ready",
                    "endpoint": "/observability/export?pane=reports&format=json",
                },
                {
                    "name": "Prometheus",
                    "status": "ready",
                    "endpoint": "/performance",
                    "aliases": ["/observability/metrics"],
                },
                {
                    "name": "SIEM/syslog",
                    "status": "ready",
                    "endpoint": "/observability/export?pane=security&format=jsonl",
                },
                {
                    "name": "Scheduled email",
                    "status": "configured" if schedules else "ready",
                    "endpoint": "/observability/report-schedules",
                },
            ],
            "privacy": {
                "enabled": bool(privacy),
                "mode": "pseudonymized" if privacy else "raw",
            },
        }

    def overview_bundle(
        self,
        *,
        since: int,
        search: str = "",
        limit: int = 6,
        resolve_hostnames: bool = False,
        summary: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        lim = max(3, min(10, int(limit)))
        summary_payload = summary or self.summary(since=since)
        total_requests = int(summary_payload.get("request_records") or 0)
        return {
            "summary": summary_payload,
            "destinations": self.top_destinations(
                since=since,
                search=search,
                limit=lim,
                sort="requests",
                total_requests=total_requests,
            ),
            "clients": self.top_clients(
                since=since,
                search=search,
                limit=lim,
                sort="requests",
                resolve_hostnames=resolve_hostnames,
                total_requests=total_requests,
            ),
            "cache_reasons": self.top_cache_reasons(
                since=since,
                search=search,
                limit=lim,
                sort="requests",
            ),
            "ssl": self.ssl_overview(since=since, search=search, limit=lim),
            "security": self.security_overview(since=since, search=search, limit=lim),
            "performance": self.performance_overview(
                since=since,
                limit=lim,
                summary=summary_payload,
            ),
            "remediation": self.remediation_overview(
                since=since,
                search=search,
                limit=lim,
                summary=summary_payload,
            ),
        }


_store: ObservabilityQueries | None = None


def get_observability_queries() -> ObservabilityQueries:
    global _store
    if _store is None:
        _store = ObservabilityQueries()
    return _store
