from __future__ import annotations

from typing import Any, Dict, Iterable, Sequence
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


SSL_ERROR_CATEGORY_META: Dict[str, Dict[str, str]] = {
    'CERT_VERIFY': {
        'label': 'Trust / chain failure',
        'tone': 'danger',
        'note': 'Certificate validation failed. Confirm the upstream issuer chain and only bypass inspection if the destination is intentionally exempt.',
    },
    'CERT_EXPIRED': {
        'label': 'Expired certificate',
        'tone': 'danger',
        'note': 'The remote certificate appears expired. Verify with the service owner before using an exclusion as a workaround.',
    },
    'CERT_NAME': {
        'label': 'Hostname mismatch',
        'tone': 'danger',
        'note': 'The certificate subject does not match the requested hostname. Double-check the destination and whether interception is appropriate.',
    },
    'CERT': {
        'label': 'Certificate issue',
        'tone': 'warn',
        'note': 'A certificate-related failure was detected. Inspect the latest sample for the specific OpenSSL or Squid message.',
    },
    'TLS_HANDSHAKE': {
        'label': 'Handshake failed',
        'tone': 'warn',
        'note': 'TLS negotiation failed before a session was established. Compare client expectations, upstream TLS support, and bump policy.',
    },
    'TLS_CIPHER': {
        'label': 'Cipher mismatch',
        'tone': 'warn',
        'note': 'Client and server could not agree on a cipher. Review allowed cipher suites and legacy TLS compatibility requirements.',
    },
    'TLS_PROTOCOL': {
        'label': 'Protocol mismatch',
        'tone': 'warn',
        'note': 'The requested TLS version was unsupported or mismatched. Check whether the app or upstream requires a legacy or newer protocol.',
    },
    'SSL_BUMP': {
        'label': 'Inspection policy conflict',
        'tone': 'warn',
        'note': 'The failure occurred while Squid was applying SSL bump logic. Review bump/splice rules before adding exclusions.',
    },
    'TLS_OTHER': {
        'label': 'Other TLS failure',
        'tone': 'warn',
        'note': 'A generic TLS error was captured. Use the latest sample and timestamps to correlate with Live traffic or application logs.',
    },
}


def _normalized_domain(value: str | None) -> str:
    return (value or '').strip().lower().lstrip('.')


def ssl_error_category_meta(category: str | None) -> Dict[str, str]:
    key = (category or 'TLS_OTHER').strip().upper() or 'TLS_OTHER'
    meta = SSL_ERROR_CATEGORY_META.get(key, SSL_ERROR_CATEGORY_META['TLS_OTHER'])
    return {
        'key': key,
        'label': meta['label'],
        'tone': meta['tone'],
        'note': meta['note'],
    }


def window_label(seconds: int) -> str:
    value = max(60, int(seconds or 0))
    if value % (24 * 3600) == 0:
        return f"{value // (24 * 3600)}d"
    if value % 3600 == 0:
        return f"{value // 3600}h"
    if value % 60 == 0:
        return f"{value // 60}m"
    return f"{value}s"


def present_ssl_error_rows(rows: Sequence[Any]) -> Dict[str, Any]:
    presented: list[Dict[str, Any]] = []
    total_events = 0
    unknown_target_buckets = 0
    unknown_target_events = 0
    known_domains: set[str] = set()
    latest_seen = 0
    category_totals: Dict[str, int] = {}

    for row in rows:
        domain = _normalized_domain(getattr(row, 'domain', ''))
        category = str(getattr(row, 'category', '') or 'TLS_OTHER').strip().upper() or 'TLS_OTHER'
        count = int(getattr(row, 'count', 0) or 0)
        first_seen = int(getattr(row, 'first_seen', 0) or 0)
        last_seen = int(getattr(row, 'last_seen', 0) or 0)
        sample = str(getattr(row, 'sample', '') or '').strip()
        meta = ssl_error_category_meta(category)

        total_events += count
        latest_seen = max(latest_seen, last_seen)
        category_totals[category] = category_totals.get(category, 0) + count

        if domain:
            known_domains.add(domain)
        else:
            unknown_target_buckets += 1
            unknown_target_events += count

        presented.append(
            {
                'domain': domain,
                'target_display': domain or 'Hostname not captured',
                'has_domain': bool(domain),
                'category': category,
                'category_label': meta['label'],
                'badge_tone': meta['tone'],
                'operator_note': meta['note'],
                'reason': str(getattr(row, 'reason', '') or ''),
                'count': count,
                'first_seen': first_seen,
                'last_seen': last_seen,
                'sample': sample,
            }
        )

    top_category = ''
    top_category_total = 0
    for category, total in category_totals.items():
        if total > top_category_total:
            top_category = category
            top_category_total = total

    top_meta = ssl_error_category_meta(top_category) if top_category else {
        'label': 'No active errors',
        'tone': 'ok',
        'note': 'No SSL/TLS error buckets were recorded in the selected window.',
    }

    hints: list[Dict[str, str]] = []
    if presented:
        hints.append(
            {
                'kind': 'info',
                'title': 'Treat exclusions as a last-mile workaround',
                'body': 'Prefer fixing certificate trust, expiry, hostname mismatches, or bump rules before bypassing SSL inspection for a destination.',
            }
        )
        if unknown_target_buckets:
            hints.append(
                {
                    'kind': 'warning',
                    'title': 'Some events do not include a hostname',
                    'body': 'Use the latest sample text and last-seen timestamp to correlate with Live traffic, access logs, or the affected application before creating exclusions.',
                }
            )
    else:
        hints.append(
            {
                'kind': 'success',
                'title': 'No current SSL/TLS buckets in this window',
                'body': 'This view stays empty until Squid records a matching TLS error in cache.log for the selected time range.',
            }
        )

    return {
        'rows': presented,
        'summary': {
            'bucket_count': len(presented),
            'total_events': total_events,
            'known_domains': len(known_domains),
            'unknown_target_buckets': unknown_target_buckets,
            'unknown_target_events': unknown_target_events,
            'latest_seen': latest_seen,
            'top_category_label': top_meta['label'],
            'top_category_tone': top_meta['tone'],
            'top_category_total': top_category_total,
        },
        'hints': hints,
    }


def present_ssl_top_domains(rows: Sequence[Dict[str, Any]], *, limit: int = 15) -> list[Dict[str, Any]]:
    presented: list[Dict[str, Any]] = []
    for row in rows:
        domain = _normalized_domain(str(row.get('domain') or ''))
        if not domain:
            continue
        presented.append(
            {
                'domain': domain,
                'total': int(row.get('total') or 0),
                'buckets': int(row.get('buckets') or 0),
                'last_seen': int(row.get('last_seen') or 0),
            }
        )
        if len(presented) >= limit:
            break
    return presented


def csv_safe(value: object) -> str:
    s = '' if value is None else str(value)
    probe = s.lstrip()
    if probe and probe[0] in ('=', '+', '-', '@'):
        return "'" + s
    return s


def bulk_lines(value: str | None) -> list[str]:
    lines: list[str] = []
    for raw in (value or '').splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        lines.append(line)
    return lines


def safe_local_return_url(value: str | None) -> str | None:
    raw = (value or '').strip()
    if not raw:
        return None
    parsed = urlsplit(raw)
    if parsed.scheme or parsed.netloc:
        return None
    if not parsed.path.startswith('/') or parsed.path.startswith('//'):
        return None
    return urlunsplit(('', '', parsed.path, parsed.query, parsed.fragment))


def append_query_to_local_return(return_to: str | None, **params: Any) -> str | None:
    safe = safe_local_return_url(return_to)
    if not safe:
        return None
    parsed = urlsplit(safe)
    replace_keys = {k for k, v in params.items() if v is not None}
    items = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True) if k not in replace_keys]
    for key, value in params.items():
        if value is not None:
            items.append((key, str(value)))
    return urlunsplit(('', '', parsed.path, urlencode(items, doseq=True), parsed.fragment))