from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List

from services.adblock_store import get_adblock_store
from services.client_identity_cache import get_client_identity_cache
from services.db import connect
from services.diagnostic_store import get_diagnostic_store
from services.proxy_context import get_proxy_id
from services.runtime_helpers import cache_hit_sql as _cache_hit_sql, escape_like as _escape_like, extract_domain as _extract_domain, not_cached_reason_sql as _not_cached_reason_sql, present_value_sql as _present_value_sql
from services.ssl_errors_store import get_ssl_errors_store
from services.ui_support import (
    present_icap_events,
    present_observability_summary,
    present_ssl_error_rows,
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


def _badge_rows(counter: Counter[str], *, limit: int = 8) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for label, count in counter.most_common(max(1, limit)):
        clean = str(label or "").strip()
        if not clean:
            continue
        rows.append(
            {
                "label": clean,
                "full_label": clean,
                "count": int(count or 0),
            }
        )
    return rows


class ObservabilityQueries:
    def _connect(self):
        return connect()

    @staticmethod
    def _request_identity_sql(id_column: str = "id", master_xaction_column: str = "master_xaction") -> str:
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

    @staticmethod
    def _av_status(summary: str, details: str) -> str:
        haystack = f"{summary} {details}".lower()
        if any(token in haystack for token in ("found", "eicar", "malware", "virus", "infect", "trojan", "blocked", "deny")):
            return "finding"
        if any(token in haystack for token in ("clean", "allow", "passed")):
            return "clean"
        return "activity"

    @staticmethod
    def _av_status_meta(status: str) -> Dict[str, str]:
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

    def summary(self, *, since: int) -> Dict[str, Any]:
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
                WHERE proxy_id = %s AND ts >= %s AND {self._present_sql('domain')}
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
    ) -> List[Dict[str, Any]]:
        proxy_id = get_proxy_id()
        lim = max(5, min(200, int(limit)))
        search_value = (search or "").strip().lower()
        hit_sql = self._hit_sql("r.result_code")
        tx_sql = self._request_identity_sql("r.id", "r.master_xaction")
        request_where = ["r.proxy_id = %s", "r.ts >= %s", self._present_sql("r.domain")]
        request_params: List[Any] = [proxy_id, int(since)]
        icap_where = ["proxy_id = %s", "ts >= %s", self._present_sql("domain")]
        icap_params: List[Any] = [proxy_id, int(since)]
        if search_value:
            like = f"%{_escape_like(search_value)}%"
            request_where.append("LOWER(r.domain) LIKE %s ESCAPE '\\\\'")
            request_params.append(like)
            icap_where.append("LOWER(domain) LIKE %s ESCAPE '\\\\'")
            icap_params.append(like)

        request_where_sql = "WHERE " + " AND ".join(request_where)
        icap_where_sql = "WHERE " + " AND ".join(icap_where)

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

        totals = self.summary(since=since)
        total_requests = int(totals.get("request_records") or 0)
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
    ) -> List[Dict[str, Any]]:
        proxy_id = get_proxy_id()
        lim = max(5, min(200, int(limit)))
        search_value = (search or "").strip().lower()
        hit_sql = self._hit_sql("r.result_code")
        tx_sql = self._request_identity_sql("r.id", "r.master_xaction")
        request_where = ["r.proxy_id = %s", "r.ts >= %s", self._present_sql("r.domain")]
        request_params: List[Any] = [proxy_id, int(since)]
        icap_where = ["proxy_id = %s", "ts >= %s", self._present_sql("client_ip")]
        icap_params: List[Any] = [proxy_id, int(since)]
        if search_value:
            like = f"%{_escape_like(search_value)}%"
            request_where.append("LOWER(r.client_ip) LIKE %s ESCAPE '\\\\'")
            request_params.append(like)
            icap_where.append("LOWER(client_ip) LIKE %s ESCAPE '\\\\'")
            icap_params.append(like)

        request_where_sql = "WHERE " + " AND ".join(request_where)
        icap_where_sql = "WHERE " + " AND ".join(icap_where)

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

        totals = self.summary(since=since)
        total_requests = int(totals.get("request_records") or 0)
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
                info = resolved.get(row["ip"], {"hostname": "", "hostname_source": "", "hostname_status": "unresolved"})
                row.update(info)
        return out

    def top_cache_reasons(
        self,
        *,
        since: int,
        search: str = "",
        limit: int = 50,
        sort: str = "requests",
    ) -> List[Dict[str, Any]]:
        proxy_id = get_proxy_id()
        lim = max(5, min(200, int(limit)))
        search_value = (search or "").strip().lower()
        hit_sql = self._hit_sql("result_code")
        reason_sql = self._not_cached_reason_sql()
        where = ["proxy_id = %s", "ts >= %s", self._present_sql("domain"), f"NOT {hit_sql}"]
        params: List[Any] = [proxy_id, int(since)]
        if search_value:
            like = f"%{_escape_like(search_value)}%"
            where.append(
                "(" + " OR ".join([
                    "LOWER(domain) LIKE %s ESCAPE '\\\\'",
                    "LOWER(client_ip) LIKE %s ESCAPE '\\\\'",
                    "LOWER(url) LIKE %s ESCAPE '\\\\'",
                ]) + ")"
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
                tuple(params + [lim]),
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

    def ssl_overview(self, *, since: int, search: str = "", limit: int = 50) -> Dict[str, Any]:
        store = get_ssl_errors_store()
        try:
            store.init_db()
        except Exception:
            pass
        raw_rows = store.list_recent(since=since, search=search, limit=max(10, min(500, int(limit))))
        presented = present_ssl_error_rows(raw_rows)
        category_counts: Counter[str] = Counter()
        for row in presented["rows"]:
            category_counts[str(row.get("category_label") or row.get("category") or "Other")] += int(row.get("count") or 0)
        return {
            "summary": presented["summary"],
            "rows": presented["rows"],
            "top_domains": present_ssl_top_domains(store.top_domains(since=since, search=search, limit=10), limit=10),
            "top_categories": _badge_rows(category_counts, limit=6),
            "hints": presented["hints"],
        }

    def security_overview(self, *, since: int, search: str = "", limit: int = 50) -> Dict[str, Any]:
        proxy_id = get_proxy_id()
        lim = max(5, min(100, int(limit)))
        search_value = (search or "").strip().lower()
        diagnostic_store = get_diagnostic_store()
        get_adblock_store().init_db()
        get_webfilter_store().init_db()

        av_where = ["proxy_id = %s", "ts >= %s", "service_family = 'av'"]
        av_params: List[Any] = [proxy_id, int(since)]
        if search_value:
            like = f"%{_escape_like(search_value)}%"
            av_where.append(
                "(" + " OR ".join([
                    "LOWER(domain) LIKE %s ESCAPE '\\\\'",
                    "LOWER(url) LIKE %s ESCAPE '\\\\'",
                    "LOWER(client_ip) LIKE %s ESCAPE '\\\\'",
                    "LOWER(adapt_summary) LIKE %s ESCAPE '\\\\'",
                    "LOWER(adapt_details) LIKE %s ESCAPE '\\\\'",
                ]) + ")"
            )
            av_params.extend([like, like, like, like, like])
        av_where_sql = "WHERE " + " AND ".join(av_where)
        av_finding_sql = self._av_finding_sql()

        adblock_where = ["proxy_id = %s", "ts >= %s"]
        adblock_params: List[Any] = [proxy_id, int(since)]
        if search_value:
            like = f"%{_escape_like(search_value)}%"
            adblock_where.append("(LOWER(url) LIKE %s ESCAPE '\\\\' OR LOWER(src_ip) LIKE %s ESCAPE '\\\\')")
            adblock_params.extend([like, like])
        adblock_where_sql = "WHERE " + " AND ".join(adblock_where)

        webfilter_where = ["proxy_id = %s", "ts >= %s"]
        webfilter_params: List[Any] = [proxy_id, int(since)]
        if search_value:
            like = f"%{_escape_like(search_value)}%"
            webfilter_where.append(
                "(" + " OR ".join([
                    "LOWER(url) LIKE %s ESCAPE '\\\\'",
                    "LOWER(src_ip) LIKE %s ESCAPE '\\\\'",
                    "LOWER(category) LIKE %s ESCAPE '\\\\'",
                ]) + ")"
            )
            webfilter_params.extend([like, like, like])
        webfilter_where_sql = "WHERE " + " AND ".join(webfilter_where)

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
                SELECT {self._url_host_sql('url')} AS domain, COUNT(*) AS blocks, COUNT(DISTINCT src_ip) AS clients, MAX(ts) AS last_seen
                FROM adblock_events
                {adblock_where_sql}
                GROUP BY domain
                HAVING domain <> ''
                ORDER BY blocks DESC, last_seen DESC
                LIMIT %s
                """,
                tuple(adblock_params + [min(lim, 10)]),
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
                tuple(webfilter_params + [min(lim, 10)]),
            ).fetchall()
            top_webfilter_domain_rows = conn.execute(
                f"""
                SELECT {self._url_host_sql('url')} AS domain, COUNT(*) AS blocks, COUNT(DISTINCT src_ip) AS clients, MAX(ts) AS last_seen
                FROM webfilter_blocked_log
                {webfilter_where_sql}
                GROUP BY domain
                HAVING domain <> ''
                ORDER BY blocks DESC, last_seen DESC
                LIMIT %s
                """,
                tuple(webfilter_params + [min(lim, 10)]),
            ).fetchall()
            adblock_recent_rows = conn.execute(
                f"""
                SELECT ts, src_ip, method, url, http_status
                FROM adblock_events
                {adblock_where_sql}
                ORDER BY ts DESC, id DESC
                LIMIT %s
                """,
                tuple(adblock_params + [min(max(lim * 2, 20), 100)]),
            ).fetchall()
            webfilter_recent_rows = conn.execute(
                f"""
                SELECT ts, src_ip, url, category
                FROM webfilter_blocked_log
                {webfilter_where_sql}
                ORDER BY ts DESC, id DESC
                LIMIT %s
                """,
                tuple(webfilter_params + [min(max(lim * 2, 20), 100)]),
            ).fetchall()

        av_raw = diagnostic_store.list_recent_icap(
            since=since,
            search=search_value,
            service='av',
            limit=max(lim, 20),
        )
        av_enriched: List[Dict[str, Any]] = []
        av_target_counter: Counter[str] = Counter()
        for row in av_raw:
            event = dict(row)
            status = self._av_status(str(event.get('adapt_summary') or ''), str(event.get('adapt_details') or ''))
            meta = self._av_status_meta(status)
            event['av_status'] = status
            event['av_status_label'] = meta['label']
            event['av_status_tone'] = meta['tone']
            if status == 'finding':
                av_target_counter[str(event.get('target_display') or event.get('domain') or '-')] += 1
            av_enriched.append(event)
        av_enriched.sort(
            key=lambda row: (
                0 if row.get('av_status') == 'finding' else (1 if row.get('av_status') == 'activity' else 2),
                -int(row.get('ts') or 0),
            )
        )

        adblock_rows = [
            {
                'ts': int(row[0] or 0),
                'src_ip': str(row[1] or ''),
                'method': str(row[2] or ''),
                'url': str(row[3] or ''),
                'domain': _extract_domain(row[3]),
                'http_status': int(row[4] or 0),
                'result': 'BLOCKED',
            }
            for row in adblock_recent_rows
        ]
        webfilter_rows = [
            {
                'ts': int(row[0] or 0),
                'src_ip': str(row[1] or ''),
                'url': str(row[2] or ''),
                'domain': _extract_domain(row[2]),
                'category': str(row[3] or ''),
                'result': 'BLOCKED',
            }
            for row in webfilter_recent_rows
        ]

        return {
            'summary': {
                'av_events': int(av_summary_row[0] or 0) if av_summary_row else 0,
                'potential_findings': int(av_summary_row[1] or 0) if av_summary_row else 0,
                'av_last_seen': int(av_summary_row[2] or 0) if av_summary_row else 0,
                'adblock_blocks': int(adblock_summary_row[0] or 0) if adblock_summary_row else 0,
                'adblock_clients': int(adblock_summary_row[1] or 0) if adblock_summary_row else 0,
                'adblock_last_seen': int(adblock_summary_row[2] or 0) if adblock_summary_row else 0,
                'webfilter_blocks': int(webfilter_summary_row[0] or 0) if webfilter_summary_row else 0,
                'webfilter_clients': int(webfilter_summary_row[1] or 0) if webfilter_summary_row else 0,
                'webfilter_categories': int(webfilter_summary_row[2] or 0) if webfilter_summary_row else 0,
                'webfilter_last_seen': int(webfilter_summary_row[3] or 0) if webfilter_summary_row else 0,
                'combined_blocks': (int(adblock_summary_row[0] or 0) if adblock_summary_row else 0) + (int(webfilter_summary_row[0] or 0) if webfilter_summary_row else 0),
            },
            'av_rows': present_icap_events(av_enriched, limit=lim),
            'av_top_targets': _badge_rows(av_target_counter, limit=6),
            'adblock_rows': adblock_rows[:lim],
            'adblock_top_domains': [
                {
                    'domain': str(row[0] or ''),
                    'blocks': int(row[1] or 0),
                    'clients': int(row[2] or 0),
                    'last_seen': int(row[3] or 0),
                }
                for row in top_adblock_domains_rows
            ],
            'webfilter_rows': webfilter_rows[:lim],
            'webfilter_top_categories': [
                {
                    'category': str(row[0] or ''),
                    'blocks': int(row[1] or 0),
                    'last_seen': int(row[2] or 0),
                }
                for row in top_webfilter_category_rows
            ],
            'webfilter_top_domains': [
                {
                    'domain': str(row[0] or ''),
                    'blocks': int(row[1] or 0),
                    'clients': int(row[2] or 0),
                    'last_seen': int(row[3] or 0),
                }
                for row in top_webfilter_domain_rows
            ],
            'notes': [
                'AV findings are best-effort string matches over the AV ICAP trace stream. If the scanner logs only generic allow/clean messages, suspicious hits may not appear here.',
                'Adblock and web-filter rows come from explicit block logs, so they are stronger evidence of enforcement than ICAP activity counts alone.',
            ],
        }

    def performance_overview(self, *, since: int, limit: int = 10) -> Dict[str, Any]:
        diagnostic_store = get_diagnostic_store()
        lim = max(3, min(20, int(limit)))
        return {
            'summary': present_observability_summary(diagnostic_summary=diagnostic_store.activity_summary(since=since), ssl_summary={}),
            'slow_requests': present_transaction_rows(diagnostic_store.slowest_requests(since=since, limit=lim), icap_limit=0),
            'slow_icap_events': present_icap_events(diagnostic_store.slowest_icap_events(since=since, limit=lim), limit=lim),
            'top_user_agents': present_top_value_rows(diagnostic_store.top_request_dimension('user_agent', since=since, limit=8), max_label=72),
            'top_bump_modes': present_top_value_rows(diagnostic_store.top_request_dimension('bump_mode', since=since, limit=8), max_label=40),
            'top_tls_server_versions': present_top_value_rows(diagnostic_store.top_request_dimension('tls_server_version', since=since, limit=8), max_label=40),
            'top_policy_tags': present_top_tag_rows(diagnostic_store.top_policy_tags(since=since, limit=10), max_label=64),
            'av_icap_summary': diagnostic_store.icap_summary(since=since, service='av'),
            'adblock_icap_summary': diagnostic_store.icap_summary(since=since, service='adblock'),
        }

    def overview_bundle(self, *, since: int, search: str = '', limit: int = 6, resolve_hostnames: bool = False) -> Dict[str, Any]:
        lim = max(3, min(10, int(limit)))
        return {
            'summary': self.summary(since=since),
            'destinations': self.top_destinations(since=since, search=search, limit=lim, sort='requests'),
            'clients': self.top_clients(since=since, search=search, limit=lim, sort='requests', resolve_hostnames=resolve_hostnames),
            'cache_reasons': self.top_cache_reasons(since=since, search=search, limit=lim, sort='requests'),
            'ssl': self.ssl_overview(since=since, search=search, limit=lim),
            'security': self.security_overview(since=since, search=search, limit=lim),
            'performance': self.performance_overview(since=since, limit=lim),
        }


_store: ObservabilityQueries | None = None


def get_observability_queries() -> ObservabilityQueries:
    global _store
    if _store is None:
        _store = ObservabilityQueries()
    return _store
