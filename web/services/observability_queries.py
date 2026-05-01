from __future__ import annotations

from collections import Counter
import ipaddress
from typing import Any, Dict, List

from services.adblock_store import get_adblock_store
from services.client_identity_cache import get_client_identity_cache
from services.db import connect
from services.diagnostic_store import get_diagnostic_store
from services.exclusions_store import get_exclusions_store, list_domain_exclusion_presets
from services.proxy_context import get_proxy_id
from services.runtime_helpers import cache_hit_sql as _cache_hit_sql, escape_like as _escape_like, extract_domain as _extract_domain, not_cached_reason_sql as _not_cached_reason_sql, present_value_sql as _present_value_sql
from services.socks_store import get_socks_store
from services.ssl_errors_store import get_ssl_errors_store
from services.sslfilter_store import get_sslfilter_store
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


def _is_private_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address((value or "").strip()).is_private
    except Exception:
        return False


def _looks_like_docker_bridge(value: str) -> bool:
    ip = (value or "").strip()
    return ip.startswith("172.17.") or ip.startswith("172.18.") or ip.startswith("172.19.") or ip.startswith("172.20.")


_SSL_ACTIONABLE_SSL_CATEGORIES = frozenset(
    {
        "TLS_CLIENT_ACCEPT",
        "SSL_BUMP",
        "TLS_HANDSHAKE",
        "TLS_PROTOCOL",
        "TLS_CIPHER",
        "TLS_OTHER",
    }
)

_DYNAMIC_SCORE_MAX = 100
_DYNAMIC_DOMAIN_HOLD_FLOOR = 35
_DYNAMIC_CLIENT_HOLD_FLOOR = 45
_DYNAMIC_SOFT_COOLDOWN_STEP = 2
_DYNAMIC_HARD_COOLDOWN_STEP = 14
_DYNAMIC_REMOVE_SCORE = 10
_DYNAMIC_TTL_MIN_SECONDS = 15 * 60


def _clamp_dynamic_score(value: Any) -> int:
    try:
        score = int(value or 0)
    except Exception:
        score = 0
    return max(0, min(_DYNAMIC_SCORE_MAX, score))


def _dynamic_ttl_seconds(base_ttl_seconds: int, score: Any) -> int:
    base_ttl = max(_DYNAMIC_TTL_MIN_SECONDS, int(base_ttl_seconds or _DYNAMIC_TTL_MIN_SECONDS))
    scale = 0.35 + ((float(_clamp_dynamic_score(score)) / float(_DYNAMIC_SCORE_MAX)) * 0.65)
    return max(_DYNAMIC_TTL_MIN_SECONDS, int(base_ttl * scale))


def _dynamic_state(score: Any, evidence: str) -> tuple[str, str]:
    text = str(evidence or "").strip().lower()
    if text.startswith("renewed:"):
        return "Renewed", "ok"
    if text.startswith("observed traffic while protected:"):
        return "Holding", "warn"
    if text.startswith("cooling down:"):
        return "Cooling", "ghost"
    bounded = _clamp_dynamic_score(score)
    if bounded >= 75:
        return "Active", "ok"
    if bounded >= 40:
        return "Watching", "warn"
    return "Cooling", "ghost"


def _dynamic_summary_row(*, key: str, value: str, expires_ts: int, last_seen: int, score: int, evidence: str) -> Dict[str, Any]:
    state_label, state_tone = _dynamic_state(score, evidence)
    return {
        key: value,
        "expires_ts": int(expires_ts or 0),
        "last_seen": int(last_seen or 0),
        "score": int(score or 0),
        "score_pct": _clamp_dynamic_score(score),
        "evidence": str(evidence or ""),
        "state_label": state_label,
        "state_tone": state_tone,
    }


def _single_ip_from_cidr(value: str) -> str:
    try:
        network = ipaddress.ip_network((value or "").strip(), strict=False)
    except Exception:
        return ""
    if network.prefixlen != network.max_prefixlen:
        return ""
    return str(network.network_address)


def _domain_covered_by_exclusions(domain: str, patterns: List[str]) -> bool:
    needle = (domain or "").strip().lower().lstrip(".")
    if not needle:
        return False
    for raw in patterns:
        pattern = str(raw or "").strip().lower()
        if not pattern:
            continue
        if pattern == needle or pattern.lstrip(".") == needle:
            return True
        if pattern.startswith("*."):
            suffix = pattern[2:]
            if needle == suffix or needle.endswith("." + suffix):
                return True
        elif pattern.startswith("."):
            suffix = pattern[1:]
            if needle == suffix or needle.endswith("." + suffix):
                return True
    return False


def _sensitive_tls_domain_patterns() -> List[str]:
    patterns: List[str] = []
    seen: set[str] = set()
    for preset in list_domain_exclusion_presets():
        for raw in getattr(preset, "domains", ()) or ():
            pattern = str(raw or "").strip().lower()
            if not pattern or pattern in seen:
                continue
            seen.add(pattern)
            patterns.append(pattern)
    return patterns


def _single_ip_cidr(value: str) -> str:
    try:
        ip = ipaddress.ip_address((value or "").strip())
    except Exception:
        return ""
    return f"{ip}/{32 if ip.version == 4 else 128}"


def _setting_bool(source: Any, name: str, default: bool = False) -> bool:
    try:
        value = getattr(source, name)
    except Exception:
        return bool(default)
    return bool(value)


def _setting_int(source: Any, name: str, default: int = 0) -> int:
    try:
        return int(getattr(source, name) or default)
    except Exception:
        return int(default)


def _setting_str(source: Any, name: str, default: str = "") -> str:
    try:
        value = getattr(source, name)
    except Exception:
        return str(default)
    return str(value or default)


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

    def _recent_activity_by_domain(self, *, since: int, domains: List[str]) -> Dict[str, Dict[str, int]]:
        proxy_id = get_proxy_id()
        requested = sorted({str(domain or "").strip().lower() for domain in domains if str(domain or "").strip()})
        if not requested:
            return {}
        placeholders = ", ".join(["%s"] * len(requested))
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT domain, COUNT(*) AS requests, COUNT(DISTINCT client_ip) AS clients, MAX(ts) AS last_seen
                FROM diagnostic_requests
                WHERE proxy_id = %s
                  AND ts >= %s
                  AND domain IN ({placeholders})
                GROUP BY domain
                """,
                tuple([proxy_id, int(since)] + requested),
            ).fetchall()
        return {
            str(row[0] or "").strip().lower(): {
                "requests": int(row[1] or 0),
                "clients": int(row[2] or 0),
                "last_seen": int(row[3] or 0),
            }
            for row in rows
            if str(row[0] or "").strip()
        }

    def _recent_activity_by_client_ip(self, *, since: int, client_ips: List[str]) -> Dict[str, Dict[str, int]]:
        proxy_id = get_proxy_id()
        requested = sorted({str(ip or "").strip() for ip in client_ips if str(ip or "").strip()})
        if not requested:
            return {}
        placeholders = ", ".join(["%s"] * len(requested))
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT client_ip, COUNT(*) AS requests, COUNT(DISTINCT domain) AS domains, MAX(ts) AS last_seen
                FROM diagnostic_requests
                WHERE proxy_id = %s
                  AND ts >= %s
                  AND client_ip IN ({placeholders})
                GROUP BY client_ip
                """,
                tuple([proxy_id, int(since)] + requested),
            ).fetchall()
        return {
            str(row[0] or "").strip(): {
                "requests": int(row[1] or 0),
                "domains": int(row[2] or 0),
                "last_seen": int(row[3] or 0),
            }
            for row in rows
            if str(row[0] or "").strip()
        }

    def _ssl_domain_candidates(
        self,
        *,
        since: int,
        search: str = "",
        limit: int = 10,
        min_pair_events: int = 3,
        min_bump_aborts: int = 5,
        min_ssl_events: int = 5,
        skip_existing_exclusions: bool = True,
    ) -> List[Dict[str, Any]]:
        proxy_id = get_proxy_id()
        lim = max(3, min(20, int(limit)))
        query_lim = max(30, min(200, lim * 6))
        search_value = (search or "").strip().lower()
        exclusion_patterns = list(getattr(get_exclusions_store().list_all(), "domains", []) or [])
        sensitive_patterns = _sensitive_tls_domain_patterns()
        merged: Dict[str, Dict[str, Any]] = {}

        with self._connect() as conn:
            pair_rows = conn.execute(
                f"""
                SELECT
                    conn.domain,
                    COUNT(DISTINCT conn.id) AS pair_events,
                    COUNT(DISTINCT conn.client_ip) AS clients,
                    MAX(CASE WHEN bad.ts > conn.ts THEN bad.ts ELSE conn.ts END) AS last_seen
                FROM diagnostic_requests conn
                JOIN diagnostic_requests bad
                  ON bad.proxy_id = conn.proxy_id
                 AND bad.client_ip = conn.client_ip
                 AND bad.ts BETWEEN conn.ts - 1 AND conn.ts + 1
                 AND bad.domain = 'error:invalid-request'
                 AND bad.result_code = 'NONE_NONE/400'
                WHERE conn.proxy_id = %s
                  AND conn.ts >= %s
                  AND bad.ts >= %s
                  AND conn.method = 'CONNECT'
                  AND conn.result_code = 'NONE_NONE/200'
                  AND {self._present_sql('conn.domain')}
                GROUP BY conn.domain
                ORDER BY pair_events DESC, last_seen DESC
                LIMIT %s
                """,
                (proxy_id, int(since), int(since), int(query_lim)),
            ).fetchall()
            abort_rows = conn.execute(
                f"""
                SELECT
                    domain,
                    COUNT(*) AS bump_aborts,
                    COUNT(DISTINCT client_ip) AS clients,
                    MAX(ts) AS last_seen
                FROM diagnostic_requests
                WHERE proxy_id = %s
                  AND ts >= %s
                  AND {self._present_sql('domain')}
                  AND COALESCE(LOWER(bump_mode), '') = 'bump'
                  AND UPPER(result_code) LIKE '%%ABORTED%%'
                GROUP BY domain
                ORDER BY bump_aborts DESC, last_seen DESC
                LIMIT %s
                """,
                (proxy_id, int(since), int(query_lim)),
            ).fetchall()
            transport_rows = conn.execute(
                f"""
                SELECT
                    domain,
                    SUM(CASE WHEN method = 'CONNECT' AND COALESCE(LOWER(bump_mode), '') = 'bump' AND result_code = 'NONE_NONE/200' THEN 1 ELSE 0 END) AS bumped_connects,
                    SUM(CASE WHEN method <> 'CONNECT' THEN 1 ELSE 0 END) AS non_connect_rows,
                    SUM(CASE WHEN method <> 'CONNECT' AND http_status >= 500 THEN 1 ELSE 0 END) AS service_failures,
                    COUNT(DISTINCT client_ip) AS clients,
                    MAX(ts) AS last_seen
                FROM diagnostic_requests
                WHERE proxy_id = %s
                  AND ts >= %s
                  AND {self._present_sql('domain')}
                GROUP BY domain
                HAVING bumped_connects > 0 OR service_failures > 0
                ORDER BY service_failures DESC, bumped_connects DESC, last_seen DESC
                LIMIT %s
                """,
                (proxy_id, int(since), int(query_lim)),
            ).fetchall()

        for row in pair_rows:
            domain = str(row[0] or "").strip().lower()
            if not domain:
                continue
            entry = merged.setdefault(
                domain,
                {
                    "domain": domain,
                    "paired_invalid_requests": 0,
                    "bump_aborts": 0,
                    "service_failures": 0,
                    "opaque_tls_connects": 0,
                    "ssl_events": 0,
                    "clients": 0,
                    "last_seen": 0,
                    "sensitive_domain": False,
                },
            )
            entry["paired_invalid_requests"] = int(row[1] or 0)
            entry["clients"] = max(int(entry.get("clients") or 0), int(row[2] or 0))
            entry["last_seen"] = max(int(entry.get("last_seen") or 0), int(row[3] or 0))

        for row in abort_rows:
            domain = str(row[0] or "").strip().lower()
            if not domain:
                continue
            entry = merged.setdefault(
                domain,
                {
                    "domain": domain,
                    "paired_invalid_requests": 0,
                    "bump_aborts": 0,
                    "service_failures": 0,
                    "opaque_tls_connects": 0,
                    "ssl_events": 0,
                    "clients": 0,
                    "last_seen": 0,
                    "sensitive_domain": False,
                },
            )
            entry["bump_aborts"] = int(row[1] or 0)
            entry["clients"] = max(int(entry.get("clients") or 0), int(row[2] or 0))
            entry["last_seen"] = max(int(entry.get("last_seen") or 0), int(row[3] or 0))

        for row in transport_rows:
            domain = str(row[0] or "").strip().lower()
            if not domain:
                continue
            entry = merged.setdefault(
                domain,
                {
                    "domain": domain,
                    "paired_invalid_requests": 0,
                    "bump_aborts": 0,
                    "service_failures": 0,
                    "opaque_tls_connects": 0,
                    "ssl_events": 0,
                    "clients": 0,
                    "last_seen": 0,
                    "sensitive_domain": False,
                },
            )
            bumped_connects = int(row[1] or 0)
            non_connect_rows = int(row[2] or 0)
            entry["service_failures"] = int(row[3] or 0)
            entry["opaque_tls_connects"] = bumped_connects if bumped_connects > 0 and non_connect_rows == 0 else 0
            entry["clients"] = max(int(entry.get("clients") or 0), int(row[4] or 0))
            entry["last_seen"] = max(int(entry.get("last_seen") or 0), int(row[5] or 0))
            entry["sensitive_domain"] = bool(entry.get("sensitive_domain")) or _domain_covered_by_exclusions(domain, sensitive_patterns)

        ssl_rows = get_ssl_errors_store().list_recent(
            since=since,
            search=search_value,
            limit=max(100, min(500, lim * 20)),
        )
        for row in ssl_rows:
            category = str(getattr(row, "category", "") or "").strip().upper()
            if category not in _SSL_ACTIONABLE_SSL_CATEGORIES:
                continue
            domain = str(getattr(row, "domain", "") or "").strip().lower()
            if not domain:
                continue
            entry = merged.setdefault(
                domain,
                {
                    "domain": domain,
                    "paired_invalid_requests": 0,
                    "bump_aborts": 0,
                    "service_failures": 0,
                    "opaque_tls_connects": 0,
                    "ssl_events": 0,
                    "clients": 0,
                    "last_seen": 0,
                    "sensitive_domain": False,
                },
            )
            entry["ssl_events"] += int(getattr(row, "count", 0) or 0)
            entry["last_seen"] = max(int(entry.get("last_seen") or 0), int(getattr(row, "last_seen", 0) or 0))

        candidates: List[Dict[str, Any]] = []
        for domain, entry in merged.items():
            if domain == "error:invalid-request":
                continue
            if search_value and search_value not in domain:
                continue
            if skip_existing_exclusions and _domain_covered_by_exclusions(domain, exclusion_patterns):
                continue
            pair_events = int(entry.get("paired_invalid_requests") or 0)
            bump_aborts = int(entry.get("bump_aborts") or 0)
            service_failures = int(entry.get("service_failures") or 0)
            opaque_tls_connects = int(entry.get("opaque_tls_connects") or 0)
            ssl_events = int(entry.get("ssl_events") or 0)
            sensitive_domain = bool(entry.get("sensitive_domain"))
            combined_failures = bump_aborts + service_failures
            opaque_sensitive_trigger = sensitive_domain and opaque_tls_connects >= max(4, int(min_pair_events))
            if (
                pair_events < int(min_pair_events)
                and combined_failures < int(min_bump_aborts)
                and ssl_events < int(min_ssl_events)
                and not opaque_sensitive_trigger
            ):
                continue
            score = _clamp_dynamic_score(
                (pair_events * 8)
                + (bump_aborts * 3)
                + (service_failures * 6)
                + ssl_events
                + ((opaque_tls_connects * 3) if sensitive_domain else 0)
                + (10 if sensitive_domain and (service_failures or opaque_tls_connects) else 0)
            )
            high_confidence = (
                pair_events >= 10
                or combined_failures >= max(int(min_bump_aborts), 4)
                or (pair_events >= 5 and bump_aborts >= 5)
                or opaque_sensitive_trigger
                or score >= 35
            )
            evidence_bits: List[str] = []
            if pair_events:
                evidence_bits.append(f"{pair_events} CONNECT→invalid-request pairs")
            if bump_aborts:
                evidence_bits.append(f"{bump_aborts} bumped aborts")
            if service_failures:
                evidence_bits.append(f"{service_failures} outer 5xx requests")
            if opaque_tls_connects:
                evidence_bits.append(f"{opaque_tls_connects} bumped CONNECT-only sessions")
            if ssl_events:
                evidence_bits.append(f"{ssl_events} SSL bucket events")
            if sensitive_domain:
                evidence_bits.append("matches a sensitive service family")
            candidates.append(
                {
                    "domain": domain,
                    "paired_invalid_requests": pair_events,
                    "bump_aborts": bump_aborts,
                    "service_failures": service_failures,
                    "combined_failures": combined_failures,
                    "opaque_tls_connects": opaque_tls_connects,
                    "ssl_events": ssl_events,
                    "clients": int(entry.get("clients") or 0),
                    "last_seen": int(entry.get("last_seen") or 0),
                    "sensitive_domain": sensitive_domain,
                    "score": score,
                    "stage_label": "Stage 2 · domain splice candidate",
                    "stage_tone": "danger" if high_confidence else "warn",
                    "confidence_label": "High confidence" if high_confidence else "Moderate confidence",
                    "summary": "; ".join(evidence_bits),
                }
            )

        candidates.sort(key=lambda row: (int(row.get("score") or 0), int(row.get("last_seen") or 0)), reverse=True)
        return candidates[:lim]

    def _ssl_client_candidates(
        self,
        *,
        since: int,
        search: str = "",
        limit: int = 6,
        min_pair_events: int = 12,
        min_distinct_domains: int = 2,
        skip_existing_nobump: bool = True,
    ) -> List[Dict[str, Any]]:
        proxy_id = get_proxy_id()
        lim = max(2, min(12, int(limit)))
        query_lim = max(20, min(100, lim * 6))
        search_value = (search or "").strip().lower()
        sslfilter_store = get_sslfilter_store()
        effective_nobump_loader = getattr(sslfilter_store, "list_effective_nobump", None)
        if callable(effective_nobump_loader):
            effective_rows = effective_nobump_loader(limit=5000)
        else:
            effective_rows = sslfilter_store.list_nobump(limit=5000)
        existing_nobump = {str(cidr or "").strip() for cidr, _ts in effective_rows}
        merged: Dict[str, Dict[str, Any]] = {}

        with self._connect() as conn:
            pair_rows = conn.execute(
                f"""
                SELECT
                    conn.client_ip,
                    COUNT(DISTINCT conn.id) AS pair_events,
                    COUNT(DISTINCT conn.domain) AS distinct_domains,
                    MAX(CASE WHEN bad.ts > conn.ts THEN bad.ts ELSE conn.ts END) AS last_seen,
                    GROUP_CONCAT(DISTINCT conn.domain ORDER BY conn.domain SEPARATOR ',') AS sample_domains
                FROM diagnostic_requests conn
                JOIN diagnostic_requests bad
                  ON bad.proxy_id = conn.proxy_id
                 AND bad.client_ip = conn.client_ip
                 AND bad.ts BETWEEN conn.ts - 1 AND conn.ts + 1
                 AND bad.domain = 'error:invalid-request'
                 AND bad.result_code = 'NONE_NONE/400'
                WHERE conn.proxy_id = %s
                  AND conn.ts >= %s
                  AND bad.ts >= %s
                  AND conn.method = 'CONNECT'
                  AND conn.result_code = 'NONE_NONE/200'
                  AND {self._present_sql('conn.domain')}
                GROUP BY conn.client_ip
                ORDER BY pair_events DESC, distinct_domains DESC, last_seen DESC
                LIMIT %s
                """,
                (proxy_id, int(since), int(since), int(query_lim)),
            ).fetchall()
            failure_rows = conn.execute(
                f"""
                SELECT
                    client_ip,
                    COUNT(*) AS failure_events,
                    COUNT(DISTINCT domain) AS distinct_domains,
                    MAX(ts) AS last_seen,
                    GROUP_CONCAT(DISTINCT domain ORDER BY domain SEPARATOR ',') AS sample_domains
                FROM diagnostic_requests
                WHERE proxy_id = %s
                  AND ts >= %s
                  AND {self._present_sql('domain')}
                  AND (
                    (method = 'CONNECT' AND COALESCE(LOWER(bump_mode), '') = 'bump' AND UPPER(result_code) LIKE '%%ABORTED%%')
                    OR (method <> 'CONNECT' AND http_status >= 500)
                  )
                GROUP BY client_ip
                ORDER BY failure_events DESC, distinct_domains DESC, last_seen DESC
                LIMIT %s
                """,
                (proxy_id, int(since), int(query_lim)),
            ).fetchall()

        for row in pair_rows:
            client_ip = str(row[0] or "").strip()
            if not client_ip:
                continue
            entry = merged.setdefault(
                client_ip,
                {
                    "client_ip": client_ip,
                    "paired_invalid_requests": 0,
                    "failure_events": 0,
                    "sample_domains": set(),
                    "last_seen": 0,
                },
            )
            entry["paired_invalid_requests"] = int(row[1] or 0)
            entry["last_seen"] = max(int(entry.get("last_seen") or 0), int(row[3] or 0))
            entry["sample_domains"].update([domain for domain in str(row[4] or "").split(",") if domain])

        for row in failure_rows:
            client_ip = str(row[0] or "").strip()
            if not client_ip:
                continue
            entry = merged.setdefault(
                client_ip,
                {
                    "client_ip": client_ip,
                    "paired_invalid_requests": 0,
                    "failure_events": 0,
                    "sample_domains": set(),
                    "last_seen": 0,
                },
            )
            entry["failure_events"] = int(row[1] or 0)
            entry["last_seen"] = max(int(entry.get("last_seen") or 0), int(row[3] or 0))
            entry["sample_domains"].update([domain for domain in str(row[4] or "").split(",") if domain])

        candidates: List[Dict[str, Any]] = []
        for client_ip, entry in merged.items():
            cidr = _single_ip_cidr(client_ip)
            if not cidr or (skip_existing_nobump and cidr in existing_nobump):
                continue
            pair_events = int(entry.get("paired_invalid_requests") or 0)
            failure_events = int(entry.get("failure_events") or 0)
            pain_events = pair_events + failure_events
            sample_domains = sorted({str(domain or "").strip() for domain in (entry.get("sample_domains") or set()) if str(domain or "").strip()})[:4]
            distinct_domains = len(sample_domains)
            if pain_events < int(min_pair_events) or distinct_domains < int(min_distinct_domains):
                continue
            if search_value and search_value not in client_ip.lower() and not any(search_value in domain.lower() for domain in sample_domains):
                continue
            high_confidence = pain_events >= max(int(min_pair_events) * 2, 20) or distinct_domains >= max(int(min_distinct_domains) + 2, 4)
            score = _clamp_dynamic_score((pair_events * 4) + (failure_events * 5) + (distinct_domains * 10))
            summary_bits: List[str] = []
            if pair_events:
                summary_bits.append(f"{pair_events} CONNECT→invalid-request pairs")
            if failure_events:
                summary_bits.append(f"{failure_events} bumped abort / 5xx failures")
            candidates.append(
                {
                    "client_ip": client_ip,
                    "cidr": cidr,
                    "paired_invalid_requests": pair_events,
                    "failure_events": failure_events,
                    "pain_events": pain_events,
                    "distinct_domains": distinct_domains,
                    "sample_domains": sample_domains,
                    "last_seen": int(entry.get("last_seen") or 0),
                    "score": score,
                    "stage_label": "Stage 3 · client /32 no-bump",
                    "stage_tone": "danger" if high_confidence else "warn",
                    "confidence_label": "High confidence" if high_confidence else "Moderate confidence",
                    "summary": (
                        f"{pain_events} client distress events across {distinct_domains} domains ({'; '.join(summary_bits)}). "
                        "If domain splice candidates do not stabilize this client, escalate to a /32 no-bump."
                    ),
                }
            )

        candidates.sort(
            key=lambda row: (
                int(row.get("pain_events") or 0),
                int(row.get("distinct_domains") or 0),
                int(row.get("last_seen") or 0),
            ),
            reverse=True,
        )
        return candidates[:lim]

    def _dynamic_ssl_policy_summary(self) -> Dict[str, Any]:
        sslfilter_store = get_sslfilter_store()
        exclusions_store = get_exclusions_store()
        settings_loader = getattr(sslfilter_store, "get_dynamic_mitigation_settings", None)
        settings = settings_loader() if callable(settings_loader) else None
        auto_domain_loader = getattr(exclusions_store, "list_auto_domains", None)
        auto_client_loader = getattr(sslfilter_store, "list_auto_nobump", None)
        auto_domains = auto_domain_loader(limit=5000) if callable(auto_domain_loader) else []
        auto_clients = auto_client_loader(limit=5000) if callable(auto_client_loader) else []
        return {
            "enabled": _setting_bool(settings, "enabled", False),
            "auto_domain_enabled": _setting_bool(settings, "auto_domain_enabled", False),
            "auto_client_enabled": _setting_bool(settings, "auto_client_enabled", False),
            "review_window_seconds": _setting_int(settings, "review_window_seconds", 0),
            "reconcile_interval_seconds": _setting_int(settings, "reconcile_interval_seconds", 0),
            "last_run_ts": _setting_int(settings, "last_run_ts", 0),
            "last_apply_ts": _setting_int(settings, "last_apply_ts", 0),
            "last_result": _setting_str(settings, "last_result", ""),
            "active_domain_count": len(auto_domains),
            "active_client_count": len(auto_clients),
            "domains": [
                _dynamic_summary_row(
                    key="domain",
                    value=str(getattr(row, "domain", "") or ""),
                    expires_ts=int(getattr(row, "expires_ts", 0) or 0),
                    last_seen=int(getattr(row, "last_seen", 0) or 0),
                    score=int(getattr(row, "score", 0) or 0),
                    evidence=str(getattr(row, "evidence", "") or ""),
                )
                for row in auto_domains[:6]
            ],
            "clients": [
                _dynamic_summary_row(
                    key="cidr",
                    value=str(getattr(row, "cidr", "") or ""),
                    expires_ts=int(getattr(row, "expires_ts", 0) or 0),
                    last_seen=int(getattr(row, "last_seen", 0) or 0),
                    score=int(getattr(row, "score", 0) or 0),
                    evidence=str(getattr(row, "evidence", "") or ""),
                )
                for row in auto_clients[:6]
            ],
        }

    def reconcile_dynamic_ssl_mitigations(self, *, force: bool = False, now_ts: int | None = None) -> Dict[str, Any]:
        now_i = int(now_ts or 0) or int(__import__("time").time())
        sslfilter_store = get_sslfilter_store()
        exclusions_store = get_exclusions_store()
        settings_loader = getattr(sslfilter_store, "get_dynamic_mitigation_settings", None)
        update_status = getattr(sslfilter_store, "update_dynamic_mitigation_status", None)
        prune_clients = getattr(sslfilter_store, "prune_expired_entries", None)
        prune_domains = getattr(exclusions_store, "prune_expired_entries", None)
        list_auto_domains = getattr(exclusions_store, "list_auto_domains", None)
        add_auto_domain = getattr(exclusions_store, "add_auto_domain", None)
        save_auto_domain_state = getattr(exclusions_store, "save_auto_domain_state", None)
        remove_auto_domain = getattr(exclusions_store, "remove_auto_domain", None)
        list_auto_clients = getattr(sslfilter_store, "list_auto_nobump", None)
        add_auto_client = getattr(sslfilter_store, "add_auto_nobump", None)
        save_auto_client_state = getattr(sslfilter_store, "save_auto_nobump_state", None)
        remove_auto_client = getattr(sslfilter_store, "remove_auto_nobump", None)

        settings = settings_loader() if callable(settings_loader) else None
        enabled = _setting_bool(settings, "enabled", False)
        if not force and not enabled:
            return {"ran": False, "changed": False, "message": "Dynamic client-experience protection is disabled."}

        interval_seconds = _setting_int(settings, "reconcile_interval_seconds", 300)
        last_run_ts = _setting_int(settings, "last_run_ts", 0)
        if not force and last_run_ts > 0 and (now_i - last_run_ts) < interval_seconds:
            return {"ran": False, "changed": False, "message": "Dynamic client-experience protection is cooling down between passes."}

        if callable(prune_clients):
            prune_clients(now_ts=now_i)
        if callable(prune_domains):
            prune_domains(now_ts=now_i)

        domain_added: List[str] = []
        domain_refreshed: List[str] = []
        domain_cooled: List[str] = []
        domain_removed: List[str] = []
        client_added: List[str] = []
        client_refreshed: List[str] = []
        client_cooled: List[str] = []
        client_removed: List[str] = []

        review_window = _setting_int(settings, "review_window_seconds", 4 * 60 * 60)
        since = max(0, now_i - review_window)

        exclusions_state = exclusions_store.list_all()
        manual_exclusions = list(getattr(exclusions_state, "manual_domains", []) or [])
        active_auto_domains = {row.domain: row for row in (list_auto_domains(limit=5000, now_ts=now_i) if callable(list_auto_domains) else [])}
        effective_exclusions = list(manual_exclusions)
        for domain in active_auto_domains:
            if domain and domain not in effective_exclusions:
                effective_exclusions.append(domain)

        domain_limit = _setting_int(settings, "domain_limit", 12)
        domain_ttl_seconds = _setting_int(settings, "domain_ttl_seconds", 6 * 60 * 60)
        domain_candidates = self._ssl_domain_candidates(
            since=since,
            search="",
            limit=max(domain_limit * 4, 20),
            min_pair_events=1,
            min_bump_aborts=1,
            min_ssl_events=1,
            skip_existing_exclusions=False,
        )
        domain_candidates_by_domain = {str(row.get("domain") or "").strip().lower(): row for row in domain_candidates if str(row.get("domain") or "").strip()}
        domain_activity = self._recent_activity_by_domain(since=since, domains=list(active_auto_domains.keys()))

        for domain, current in list(active_auto_domains.items()):
            fresh = domain_candidates_by_domain.get(domain)
            activity = domain_activity.get(domain)
            current_score = _clamp_dynamic_score(getattr(current, "score", 0))
            if _setting_bool(settings, "auto_domain_enabled", True) and fresh:
                next_score = max(current_score, _clamp_dynamic_score(fresh.get("score") or 0))
                evidence = f"Renewed: {str(fresh.get('summary') or '').strip()}"[:2000]
                last_seen = max(int(getattr(current, "last_seen", 0) or 0), int(fresh.get("last_seen") or 0), int((activity or {}).get("last_seen") or 0))
                ttl = _dynamic_ttl_seconds(domain_ttl_seconds, next_score)
                writer = save_auto_domain_state if callable(save_auto_domain_state) else add_auto_domain
                if callable(writer):
                    if writer is save_auto_domain_state:
                        writer(
                            domain,
                            added_ts=int(getattr(current, "added_ts", now_i) or now_i),
                            expires_ts=now_i + ttl,
                            evidence=evidence,
                            last_seen=last_seen,
                            score=next_score,
                        )
                    else:
                        writer(
                            domain,
                            ttl_seconds=ttl,
                            evidence=evidence,
                            last_seen=last_seen,
                            score=next_score,
                            added_ts=int(getattr(current, "added_ts", now_i) or now_i),
                        )
                domain_refreshed.append(domain)
                active_auto_domains[domain] = type(current)(
                    domain=domain,
                    added_ts=int(getattr(current, "added_ts", now_i) or now_i),
                    expires_ts=now_i + ttl,
                    last_seen=last_seen,
                    score=next_score,
                    evidence=evidence,
                ) if hasattr(type(current), "__call__") else current
                continue
            if activity and int(activity.get("requests") or 0) > 0:
                next_score = max(_DYNAMIC_DOMAIN_HOLD_FLOOR, current_score - _DYNAMIC_SOFT_COOLDOWN_STEP)
                evidence = (
                    f"Observed traffic while protected: {int(activity.get('requests') or 0)} recent requests from "
                    f"{int(activity.get('clients') or 0)} client(s) with no fresh SSL failures. Holding splice and cooling slowly."
                )[:2000]
                ttl = _dynamic_ttl_seconds(domain_ttl_seconds, next_score)
                last_seen = max(int(getattr(current, "last_seen", 0) or 0), int(activity.get("last_seen") or 0))
                writer = save_auto_domain_state if callable(save_auto_domain_state) else add_auto_domain
                if callable(writer):
                    if writer is save_auto_domain_state:
                        writer(
                            domain,
                            added_ts=int(getattr(current, "added_ts", now_i) or now_i),
                            expires_ts=now_i + ttl,
                            evidence=evidence,
                            last_seen=last_seen,
                            score=next_score,
                        )
                    else:
                        writer(
                            domain,
                            ttl_seconds=ttl,
                            evidence=evidence,
                            last_seen=last_seen,
                            score=next_score,
                            added_ts=int(getattr(current, "added_ts", now_i) or now_i),
                        )
                domain_cooled.append(domain)
                continue
            next_score = current_score - _DYNAMIC_HARD_COOLDOWN_STEP
            if next_score < _DYNAMIC_REMOVE_SCORE and callable(remove_auto_domain):
                remove_auto_domain(domain)
                domain_removed.append(domain)
                active_auto_domains.pop(domain, None)
                if domain in effective_exclusions and domain not in manual_exclusions:
                    effective_exclusions = [value for value in effective_exclusions if value != domain]
                continue
            ttl = _dynamic_ttl_seconds(domain_ttl_seconds, next_score)
            evidence = "Cooling down: no fresh failures or recent traffic hit this protected domain, so this temporary splice will expire soon unless the pattern returns."[:2000]
            writer = save_auto_domain_state if callable(save_auto_domain_state) else add_auto_domain
            if callable(writer):
                if writer is save_auto_domain_state:
                    writer(
                        domain,
                        added_ts=int(getattr(current, "added_ts", now_i) or now_i),
                        expires_ts=now_i + ttl,
                        evidence=evidence,
                        last_seen=int(getattr(current, "last_seen", 0) or 0),
                        score=next_score,
                    )
                else:
                    writer(
                        domain,
                        ttl_seconds=ttl,
                        evidence=evidence,
                        last_seen=int(getattr(current, "last_seen", 0) or 0),
                        score=next_score,
                        added_ts=int(getattr(current, "added_ts", now_i) or now_i),
                    )
            domain_cooled.append(domain)

        if _setting_bool(settings, "auto_domain_enabled", True) and callable(add_auto_domain):
            domain_candidates = self._ssl_domain_candidates(
                since=since,
                search="",
                limit=max(domain_limit * 4, 20),
                min_pair_events=1,
                min_bump_aborts=1,
                min_ssl_events=1,
                skip_existing_exclusions=False,
            )
            for row in domain_candidates:
                pair_events = int(row.get("paired_invalid_requests") or 0)
                combined_failures = int(row.get("combined_failures") or 0)
                opaque_tls_connects = int(row.get("opaque_tls_connects") or 0)
                ssl_events = int(row.get("ssl_events") or 0)
                sensitive_domain = bool(row.get("sensitive_domain"))
                domain = str(row.get("domain") or "").strip().lower()
                if not domain:
                    continue
                if domain in active_auto_domains:
                    continue
                if (
                    pair_events < _setting_int(settings, "min_pair_events", 6)
                    and combined_failures < _setting_int(settings, "min_bump_aborts", 8)
                    and ssl_events < _setting_int(settings, "min_ssl_events", 10)
                    and not (sensitive_domain and opaque_tls_connects >= max(4, _setting_int(settings, "min_pair_events", 6)))
                ):
                    continue
                already_covered = _domain_covered_by_exclusions(domain, effective_exclusions)
                if already_covered:
                    continue
                if not already_covered and domain not in active_auto_domains and len(active_auto_domains) >= domain_limit:
                    continue
                ok, _err, canonical = add_auto_domain(
                    domain,
                    ttl_seconds=_dynamic_ttl_seconds(domain_ttl_seconds, row.get("score") or 0),
                    evidence=str(row.get("summary") or "")[:2000],
                    last_seen=int(row.get("last_seen") or 0),
                    score=_clamp_dynamic_score(row.get("score") or 0),
                    added_ts=now_i,
                )
                if not ok or not canonical:
                    continue
                if canonical in active_auto_domains:
                    domain_refreshed.append(canonical)
                elif not already_covered:
                    domain_added.append(canonical)
                active_auto_domains[canonical] = active_auto_domains.get(canonical) or object()
                if canonical not in effective_exclusions:
                    effective_exclusions.append(canonical)

        active_auto_clients = {row.cidr: row for row in (list_auto_clients(limit=5000, now_ts=now_i) if callable(list_auto_clients) else [])}
        effective_nobump_loader = getattr(sslfilter_store, "list_effective_nobump", None)
        if callable(effective_nobump_loader):
            effective_nobumps = {cidr for cidr, _ts in effective_nobump_loader(limit=5000, now_ts=now_i)}
        else:
            effective_nobumps = {cidr for cidr, _ts in sslfilter_store.list_nobump(limit=5000)}

        client_limit = _setting_int(settings, "client_limit", 4)
        client_ttl_seconds = _setting_int(settings, "client_ttl_seconds", 2 * 60 * 60)
        client_candidates = self._ssl_client_candidates(
            since=since,
            search="",
            limit=max(client_limit * 4, 12),
            min_pair_events=1,
            min_distinct_domains=1,
            skip_existing_nobump=False,
        )
        client_candidates_by_cidr = {str(row.get("cidr") or "").strip(): row for row in client_candidates if str(row.get("cidr") or "").strip()}
        client_activity = self._recent_activity_by_client_ip(
            since=since,
            client_ips=[_single_ip_from_cidr(cidr) for cidr in active_auto_clients.keys()],
        )

        for cidr, current in list(active_auto_clients.items()):
            fresh = client_candidates_by_cidr.get(cidr)
            client_ip = _single_ip_from_cidr(cidr)
            activity = client_activity.get(client_ip) if client_ip else None
            current_score = _clamp_dynamic_score(getattr(current, "score", 0))
            if _setting_bool(settings, "auto_client_enabled", True) and fresh:
                next_score = max(current_score, _clamp_dynamic_score(fresh.get("score") or 0))
                evidence = f"Renewed: {str(fresh.get('summary') or '').strip()}"[:2000]
                last_seen = max(int(getattr(current, "last_seen", 0) or 0), int(fresh.get("last_seen") or 0), int((activity or {}).get("last_seen") or 0))
                ttl = _dynamic_ttl_seconds(client_ttl_seconds, next_score)
                writer = save_auto_client_state if callable(save_auto_client_state) else add_auto_client
                if callable(writer):
                    if writer is save_auto_client_state:
                        writer(
                            cidr,
                            added_ts=int(getattr(current, "added_ts", now_i) or now_i),
                            expires_ts=now_i + ttl,
                            evidence=evidence,
                            last_seen=last_seen,
                            score=next_score,
                        )
                    else:
                        writer(
                            cidr,
                            ttl_seconds=ttl,
                            evidence=evidence,
                            last_seen=last_seen,
                            score=next_score,
                            added_ts=int(getattr(current, "added_ts", now_i) or now_i),
                        )
                client_refreshed.append(cidr)
                continue
            if activity and int(activity.get("requests") or 0) > 0:
                next_score = max(_DYNAMIC_CLIENT_HOLD_FLOOR, current_score - _DYNAMIC_SOFT_COOLDOWN_STEP)
                evidence = (
                    f"Observed traffic while protected: {int(activity.get('requests') or 0)} recent requests across "
                    f"{int(activity.get('domains') or 0)} domain(s) with no fresh SSL failures. Holding client no-bump and cooling slowly."
                )[:2000]
                ttl = _dynamic_ttl_seconds(client_ttl_seconds, next_score)
                last_seen = max(int(getattr(current, "last_seen", 0) or 0), int(activity.get("last_seen") or 0))
                writer = save_auto_client_state if callable(save_auto_client_state) else add_auto_client
                if callable(writer):
                    if writer is save_auto_client_state:
                        writer(
                            cidr,
                            added_ts=int(getattr(current, "added_ts", now_i) or now_i),
                            expires_ts=now_i + ttl,
                            evidence=evidence,
                            last_seen=last_seen,
                            score=next_score,
                        )
                    else:
                        writer(
                            cidr,
                            ttl_seconds=ttl,
                            evidence=evidence,
                            last_seen=last_seen,
                            score=next_score,
                            added_ts=int(getattr(current, "added_ts", now_i) or now_i),
                        )
                client_cooled.append(cidr)
                continue
            next_score = current_score - _DYNAMIC_HARD_COOLDOWN_STEP
            if next_score < _DYNAMIC_REMOVE_SCORE and callable(remove_auto_client):
                remove_auto_client(cidr)
                client_removed.append(cidr)
                active_auto_clients.pop(cidr, None)
                effective_nobumps.discard(cidr)
                continue
            ttl = _dynamic_ttl_seconds(client_ttl_seconds, next_score)
            evidence = "Cooling down: no fresh failures or recent traffic hit this protected client, so this temporary /32 no-bump will expire soon unless the pattern returns."[:2000]
            writer = save_auto_client_state if callable(save_auto_client_state) else add_auto_client
            if callable(writer):
                if writer is save_auto_client_state:
                    writer(
                        cidr,
                        added_ts=int(getattr(current, "added_ts", now_i) or now_i),
                        expires_ts=now_i + ttl,
                        evidence=evidence,
                        last_seen=int(getattr(current, "last_seen", 0) or 0),
                        score=next_score,
                    )
                else:
                    writer(
                        cidr,
                        ttl_seconds=ttl,
                        evidence=evidence,
                        last_seen=int(getattr(current, "last_seen", 0) or 0),
                        score=next_score,
                        added_ts=int(getattr(current, "added_ts", now_i) or now_i),
                    )
            client_cooled.append(cidr)

        if _setting_bool(settings, "auto_client_enabled", True) and callable(add_auto_client):
            client_candidates = self._ssl_client_candidates(
                since=since,
                search="",
                limit=max(client_limit * 4, 12),
                min_pair_events=1,
                min_distinct_domains=1,
                skip_existing_nobump=False,
            )
            for row in client_candidates:
                cidr = str(row.get("cidr") or "").strip()
                if not cidr:
                    continue
                if cidr in active_auto_clients:
                    continue
                pain_events = int(row.get("pain_events") or 0)
                distinct_domains = int(row.get("distinct_domains") or 0)
                sample_domains = list(row.get("sample_domains") or [])
                protected_matches = sum(1 for domain in sample_domains if _domain_covered_by_exclusions(str(domain), effective_exclusions))
                if pain_events < _setting_int(settings, "client_pair_events", 24) or distinct_domains < _setting_int(settings, "client_distinct_domains", 4) or protected_matches < 1:
                    continue
                if cidr not in effective_nobumps and cidr not in active_auto_clients and len(active_auto_clients) >= client_limit:
                    continue
                evidence = f"{row.get('summary') or ''} Protected sample domains: {protected_matches}.".strip()
                ok, _err, canonical = add_auto_client(
                    cidr,
                    ttl_seconds=_dynamic_ttl_seconds(client_ttl_seconds, row.get("score") or 0),
                    evidence=evidence[:2000],
                    last_seen=int(row.get("last_seen") or 0),
                    score=_clamp_dynamic_score(row.get("score") or 0),
                    added_ts=now_i,
                )
                if not ok or not canonical:
                    continue
                if canonical in active_auto_clients:
                    client_refreshed.append(canonical)
                elif canonical not in effective_nobumps:
                    client_added.append(canonical)
                active_auto_clients[canonical] = active_auto_clients.get(canonical) or object()
                effective_nobumps.add(canonical)

        changed = bool(
            domain_added or domain_refreshed or domain_cooled or domain_removed
            or client_added or client_refreshed or client_cooled or client_removed
        )
        message_bits: List[str] = []
        if domain_added:
            message_bits.append(f"added {len(domain_added)} temporary domain protection{'s' if len(domain_added) != 1 else ''}")
        if domain_refreshed:
            message_bits.append(f"renewed {len(domain_refreshed)} domain protection{'s' if len(domain_refreshed) != 1 else ''}")
        if domain_cooled:
            message_bits.append(f"cooled {len(domain_cooled)} domain protection{'s' if len(domain_cooled) != 1 else ''}")
        if domain_removed:
            message_bits.append(f"retired {len(domain_removed)} domain protection{'s' if len(domain_removed) != 1 else ''}")
        if client_added:
            message_bits.append(f"added {len(client_added)} temporary client no-bump{'s' if len(client_added) != 1 else ''}")
        if client_refreshed:
            message_bits.append(f"renewed {len(client_refreshed)} client protection{'s' if len(client_refreshed) != 1 else ''}")
        if client_cooled:
            message_bits.append(f"cooled {len(client_cooled)} client protection{'s' if len(client_cooled) != 1 else ''}")
        if client_removed:
            message_bits.append(f"retired {len(client_removed)} client protection{'s' if len(client_removed) != 1 else ''}")
        message = (
            ("Dynamic client-experience protection " + ", ".join(message_bits) + ".")
            if message_bits
            else "Dynamic client-experience protection reviewed current evidence; no new temporary mitigations were needed."
        )
        if callable(update_status):
            update_status(
                last_run_ts=now_i,
                last_apply_ts=(now_i if changed else _setting_int(settings, "last_apply_ts", 0)),
                last_result=message,
            )
        return {
            "ran": True,
            "changed": changed,
            "message": message,
            "domain_added": domain_added,
            "domain_refreshed": domain_refreshed,
            "domain_cooled": domain_cooled,
            "domain_removed": domain_removed,
            "client_added": client_added,
            "client_refreshed": client_refreshed,
            "client_cooled": client_cooled,
            "client_removed": client_removed,
        }

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
        domain_candidates = self._ssl_domain_candidates(since=since, search=search, limit=min(max(int(limit // 2), 6), 12))
        client_candidates = self._ssl_client_candidates(since=since, search=search, limit=min(max(int(limit // 4), 3), 8))
        hints = list(presented["hints"])
        if domain_candidates or client_candidates:
            hints.append(
                {
                    "kind": "warning",
                    "title": "Dynamic mitigation candidates available",
                    "body": (
                        "Use staged mitigation: splice a noisy domain first when repeated CONNECT→invalid-request, bumped-abort, outer 5xx, or opaque CONNECT-only evidence points at one destination, "
                        "then escalate to a client /32 no-bump only when one client keeps failing across multiple domains."
                    ),
                }
            )
        return {
            "summary": presented["summary"],
            "rows": presented["rows"],
            "top_domains": present_ssl_top_domains(store.top_domains(since=since, search=search, limit=10), limit=10),
            "top_categories": _badge_rows(category_counts, limit=6),
            "hints": hints,
            "domain_candidates": domain_candidates,
            "client_candidates": client_candidates,
            "dynamic_policy": self._dynamic_ssl_policy_summary(),
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

    def transport_overview(self, *, since: int, search: str = '', limit: int = 20) -> Dict[str, Any]:
        store = get_socks_store()
        lim = max(5, min(50, int(limit)))
        recent = store.recent(limit=min(max(lim * 2, 20), 100), since=since, search=search)
        unique_ips = sorted({str(event.src_ip or '').strip() for event in recent if getattr(event, 'src_ip', '')})
        nat_warning = False
        nat_warning_text = ''
        if len(unique_ips) == 1 and _is_private_ip(unique_ips[0]):
            nat_warning = True
            if _looks_like_docker_bridge(unique_ips[0]):
                nat_warning_text = (
                    f'All recent SOCKS events appear to come from {unique_ips[0]}. This often means Docker bridge/NAT is masking the real clients.'
                )
            else:
                nat_warning_text = (
                    f'All recent SOCKS events appear to come from {unique_ips[0]}. This may be upstream NAT masking the real clients.'
                )
        return {
            'summary': store.summary(since=since),
            'top_clients': store.top_clients(since=since, limit=lim, search=search),
            'top_destinations': store.top_destinations(since=since, limit=lim, search=search),
            'recent': recent[:lim],
            'nat_warning': nat_warning,
            'nat_warning_text': nat_warning_text,
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
            'transport': self.transport_overview(since=since, search=search, limit=lim),
        }


_store: ObservabilityQueries | None = None


def get_observability_queries() -> ObservabilityQueries:
    global _store
    if _store is None:
        _store = ObservabilityQueries()
    return _store
