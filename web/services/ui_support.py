from __future__ import annotations

import re

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
    'TLS_CLIENT_ACCEPT': {
        'label': 'Client-side TLS accept failure',
        'tone': 'warn',
        'note': 'Squid failed while accepting the bumped TLS session from the client. Start by checking proxy CA trust, certificate pinning, client proxy configuration, or whether the client closed the connection mid-handshake.',
    },
    'TLS_OTHER': {
        'label': 'Other TLS failure',
        'tone': 'warn',
        'note': 'A generic TLS error was captured. Use the latest sample and timestamps to correlate with Live traffic or application logs.',
    },
}

_TLS_LIB_ERR_PATTERN = re.compile(r"\bTLS_LIB_ERR=([0-9A-F]+)\b", re.I)
_TLS_IO_ERR_PATTERN = re.compile(r"\bTLS_IO_ERR=(\d+)\b", re.I)
_TLS_ERROR_SIGNATURE_PATTERN = re.compile(r"\b(SQUID_TLS_ERR_[A-Z_]+(?:\+TLS_LIB_ERR=[0-9A-F]+)?(?:\+TLS_IO_ERR=\d+)?)\b", re.I)
_CONNECTION_CONTEXT_PATTERN = re.compile(
    r"\bconnection:\s*(?P<conn>\S+)(?:.*?\blocal=(?P<local>\S+))?(?:.*?\bremote=(?P<remote>\S+))?",
    re.I,
)
_INLINE_ENDPOINT_PATTERN = re.compile(r"\blocal=(?P<local>\S+).*?\bremote=(?P<remote>\S+)", re.I)
_MASTER_TRANSACTION_PATTERN = re.compile(r"\bcurrent master transaction:\s*(?P<tx>\S+)", re.I)

_OPENSSL_TLS_LIB_ERR_TEXT: Dict[str, str] = {
    'A000119': 'OpenSSL says "decryption failed or bad record MAC" — the client-facing TLS stream did not decrypt cleanly.',
}

_TLS_IO_ERR_TEXT: Dict[str, str] = {
    '1': 'The TLS stack also reported an I/O failure or connection close after the TLS error.',
}

_TLS_ACCEPT_HEADER_TEXT = 'Cannot accept a TLS connection'


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


def extract_ssl_master_transaction(sample: str | None) -> str:
    match = _MASTER_TRANSACTION_PATTERN.search(sample or '')
    if not match:
        return ''
    return str(match.group('tx') or '').strip()


def _infer_ssl_category(category: str, *, reason: str, sample: str) -> str:
    key = (category or 'TLS_OTHER').strip().upper() or 'TLS_OTHER'
    combined = "\n".join(part for part in (reason, sample) if part).lower()
    if 'cannot accept a tls connection' in combined or 'failure while accepting a tls connection' in combined:
        return 'TLS_CLIENT_ACCEPT'
    if 'squid_tls_err_accept' in combined and ('tls_lib_err=a000119' in combined or 'decryption failed or bad record mac' in combined):
        return 'TLS_CLIENT_ACCEPT'
    return key


def _display_reason(*, category: str, reason: str, sample: str) -> str:
    combined = "\n".join(part for part in (reason, sample) if part)
    signature = _TLS_ERROR_SIGNATURE_PATTERN.search(combined)
    if category == 'TLS_CLIENT_ACCEPT' and signature:
        return signature.group(1).upper()
    lowered = combined.lower()
    if category == 'TLS_CLIENT_ACCEPT' and ('cannot accept a tls connection' in lowered or 'failure while accepting a tls connection' in lowered):
        return _TLS_ACCEPT_HEADER_TEXT
    return reason


def _build_ssl_diagnostics(*, category: str, reason: str, sample: str) -> list[str]:
    diagnostics: list[str] = []
    combined = "\n".join(part for part in (reason, sample) if part)

    if category == 'TLS_CLIENT_ACCEPT':
        diagnostics.append('This happened on the client -> proxy TLS leg, not the upstream site TLS session.')

    lib_match = _TLS_LIB_ERR_PATTERN.search(combined)
    if lib_match:
        lib_code = lib_match.group(1).upper()
        decoded = _OPENSSL_TLS_LIB_ERR_TEXT.get(lib_code)
        if decoded:
            diagnostics.append(f'Decoded TLS library code {lib_code}: {decoded}')
        else:
            diagnostics.append(f'Decoded TLS library code {lib_code}.')

    io_match = _TLS_IO_ERR_PATTERN.search(combined)
    if io_match:
        io_code = io_match.group(1)
        decoded_io = _TLS_IO_ERR_TEXT.get(io_code)
        if decoded_io:
            diagnostics.append(f'TLS I/O code {io_code}: {decoded_io}')
    elif category == 'TLS_CLIENT_ACCEPT' and 'cannot accept a tls connection' in combined.lower():
        diagnostics.append('Squid only logged the generic TLS accept failure line; there was no OpenSSL detail code in the latest sample.')

    conn_match = _CONNECTION_CONTEXT_PATTERN.search(sample or '')
    local = ''
    remote = ''
    conn_id = ''
    if conn_match:
        conn_id = str(conn_match.group('conn') or '').strip()
        local = str(conn_match.group('local') or '').strip()
        remote = str(conn_match.group('remote') or '').strip()
    else:
        inline_match = _INLINE_ENDPOINT_PATTERN.search(sample or '')
        if inline_match:
            local = str(inline_match.group('local') or '').strip()
            remote = str(inline_match.group('remote') or '').strip()

    if remote or local:
        path_bits: list[str] = []
        if remote:
            path_bits.append(f'client {remote}')
        if local:
            path_bits.append(f'proxy {local}')
        path_summary = ' -> '.join(path_bits)
        if conn_id:
            diagnostics.append(f'Latest connection context: {path_summary} ({conn_id}).')
        else:
            diagnostics.append(f'Latest connection context: {path_summary}.')

    tx_match = _MASTER_TRANSACTION_PATTERN.search(sample or '')
    if tx_match:
        tx = str(tx_match.group('tx') or '').strip()
        if tx:
            diagnostics.append(f'Latest master transaction: {tx}.')

    if category == 'TLS_CLIENT_ACCEPT' and not (remote or local) and not tx_match:
        diagnostics.append('Squid did not emit any follow-up connection or master-transaction context for the latest sample, so cache.log alone cannot identify the client or app.')

    return diagnostics


def window_label(seconds: int) -> str:
    value = max(60, int(seconds or 0))
    if value % (24 * 3600) == 0:
        return f"{value // (24 * 3600)}d"
    if value % 3600 == 0:
        return f"{value // 3600}h"
    if value % 60 == 0:
        return f"{value // 60}m"
    return f"{value}s"


def _truncate_text(value: object, *, max_len: int = 140) -> str:
    text = str(value or '').strip()
    if max_len <= 0 or len(text) <= max_len:
        return text
    return text[: max(1, max_len - 1)].rstrip() + '…'


def _bytes_human(value: object) -> str:
    try:
        size = int(value or 0)
    except Exception:
        size = 0
    if size <= 0:
        return '0 B'
    units = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
    scaled = float(size)
    unit = units[0]
    for unit in units:
        if scaled < 1024.0 or unit == units[-1]:
            break
        scaled /= 1024.0
    if unit == 'B':
        return f'{int(scaled)} {unit}'
    return f'{scaled:.1f} {unit}'


def _request_result_tone(result_code: str, http_status: object) -> str:
    rc = (result_code or '').upper()
    try:
        status = int(http_status or 0)
    except Exception:
        status = 0
    if rc.startswith('TCP_DENIED') or status >= 500:
        return 'danger'
    if status >= 400 or 'ABORTED' in rc or 'FAIL' in rc:
        return 'warn'
    if 'HIT' in rc or rc.startswith('TCP_TUNNEL'):
        return 'ok'
    return 'ghost'


def _build_tls_details(row: Dict[str, Any]) -> list[str]:
    details: list[str] = []
    bump_mode = str(row.get('bump_mode') or '').strip()
    if bump_mode:
        details.append(f'bump={bump_mode}')
    sni = str(row.get('sni') or '').strip()
    if sni:
        details.append(f'sni={sni}')
    host = str(row.get('host') or '').strip()
    if host and host != sni:
        details.append(f'host={host}')

    server_version = str(row.get('tls_server_version') or '').strip()
    server_cipher = str(row.get('tls_server_cipher') or '').strip()
    if server_version or server_cipher:
        suffix = f' / {server_cipher}' if server_cipher else ''
        details.append(f'server {server_version}{suffix}'.strip())

    client_version = str(row.get('tls_client_version') or '').strip()
    client_cipher = str(row.get('tls_client_cipher') or '').strip()
    if client_version or client_cipher:
        suffix = f' / {client_cipher}' if client_cipher else ''
        details.append(f'client {client_version}{suffix}'.strip())
    return details


def _build_header_details(row: Dict[str, Any]) -> list[Dict[str, str]]:
    details: list[Dict[str, str]] = []
    user_agent = _truncate_text(row.get('user_agent'), max_len=180)
    if user_agent and user_agent != '-':
        details.append({'label': 'UA', 'value': user_agent})
    referer = _truncate_text(row.get('referer'), max_len=180)
    if referer and referer != '-':
        details.append({'label': 'Referer', 'value': referer})
    return details


def _correlation_meta(kind: str, *, time_delta_seconds: object = 0) -> Dict[str, str]:
    normalized = (kind or '').strip().lower()
    try:
        delta = int(time_delta_seconds or 0)
    except Exception:
        delta = 0
    if normalized == 'domain_time':
        extra = f' · ±{delta}s' if delta > 0 else ''
        return {
            'label': f'Possible match (domain + time){extra}',
            'tone': 'warn',
        }
    return {
        'label': 'Exact master transaction match',
        'tone': 'ok',
    }


def present_icap_events(rows: Sequence[Dict[str, Any]], *, limit: int = 10) -> list[Dict[str, Any]]:
    presented: list[Dict[str, Any]] = []
    for row in rows[: max(1, limit)]:
        event = dict(row)
        event['adapt_summary_short'] = _truncate_text(event.get('adapt_summary'), max_len=160)
        event['adapt_details_short'] = _truncate_text(event.get('adapt_details'), max_len=200)
        event['header_details'] = _build_header_details(event)
        event['tls_details'] = _build_tls_details(event)
        event['target_secondary'] = str(event.get('host') or event.get('sni') or '').strip()
        event['correlation'] = _correlation_meta(
            str(event.get('correlation_kind') or 'master_xaction'),
            time_delta_seconds=event.get('time_delta_seconds'),
        )
        presented.append(event)
    return presented


def present_transaction_rows(rows: Sequence[Dict[str, Any]], *, icap_limit: int = 5) -> list[Dict[str, Any]]:
    presented: list[Dict[str, Any]] = []
    for row in rows:
        event = dict(row)
        event['result_tone'] = _request_result_tone(
            str(event.get('result_code') or ''),
            event.get('http_status'),
        )
        event['tls_details'] = _build_tls_details(event)
        event['header_details'] = _build_header_details(event)
        event['bytes_human'] = _bytes_human(event.get('bytes'))
        event['result_summary'] = str(event.get('result_code') or '')
        try:
            http_status = int(event.get('http_status') or 0)
        except Exception:
            http_status = 0
        if http_status > 0:
            event['result_summary'] = f"{event['result_summary']} · HTTP {http_status}"
        hierarchy = str(event.get('hierarchy_status') or '').strip()
        if hierarchy:
            event['result_summary'] = f"{event['result_summary']} · {hierarchy}"
        related_icap = present_icap_events(list(event.get('related_icap') or []), limit=icap_limit)
        event['related_icap'] = related_icap
        event['correlation'] = _correlation_meta(
            str(event.get('correlation_kind') or 'master_xaction'),
            time_delta_seconds=event.get('time_delta_seconds'),
        )
        presented.append(event)
    return presented


def present_observability_summary(*, diagnostic_summary: Dict[str, Any] | None = None, ssl_summary: Dict[str, Any] | None = None) -> Dict[str, int]:
    diag = diagnostic_summary or {}
    ssl = ssl_summary or {}
    return {
        'requests': int(diag.get('requests') or 0),
        'transactions': int(diag.get('transactions') or 0),
        'clients': int(diag.get('clients') or 0),
        'domains': int(diag.get('domains') or 0),
        'icap_events': int(diag.get('icap_events') or 0),
        'av_icap_events': int(diag.get('av_icap_events') or 0),
        'adblock_icap_events': int(diag.get('adblock_icap_events') or 0),
        'ssl_events': int(ssl.get('total_events') or 0),
        'ssl_buckets': int(ssl.get('bucket_count') or 0),
    }


def present_top_value_rows(rows: Sequence[Dict[str, Any]], *, key: str = 'value', max_label: int = 64) -> list[Dict[str, Any]]:
    presented: list[Dict[str, Any]] = []
    for row in rows:
        value = str(row.get(key) or '').strip()
        if not value:
            continue
        presented.append(
            {
                'label': _truncate_text(value, max_len=max_label),
                'full_label': value,
                'count': int(row.get('count') or 0),
                'last_seen': int(row.get('last_seen') or 0),
            }
        )
    return presented


def present_top_tag_rows(rows: Sequence[Dict[str, Any]], *, max_label: int = 72) -> list[Dict[str, Any]]:
    presented: list[Dict[str, Any]] = []
    for row in rows:
        tag = str(row.get('tag') or '').strip()
        if not tag:
            continue
        presented.append(
            {
                'label': _truncate_text(tag, max_len=max_label),
                'full_label': tag,
                'count': int(row.get('count') or 0),
                'last_seen': int(row.get('last_seen') or 0),
            }
        )
    return presented


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
        raw_reason = str(getattr(row, 'reason', '') or '')
        sample = str(getattr(row, 'sample', '') or '').strip()
        category = _infer_ssl_category(
            str(getattr(row, 'category', '') or 'TLS_OTHER'),
            reason=raw_reason,
            sample=sample,
        )
        count = int(getattr(row, 'count', 0) or 0)
        first_seen = int(getattr(row, 'first_seen', 0) or 0)
        last_seen = int(getattr(row, 'last_seen', 0) or 0)
        meta = ssl_error_category_meta(category)
        display_reason = _display_reason(category=category, reason=raw_reason, sample=sample)

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
                'reason': display_reason,
                'count': count,
                'first_seen': first_seen,
                'last_seen': last_seen,
                'sample': sample,
                'diagnostics': _build_ssl_diagnostics(category=category, reason=display_reason, sample=sample),
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
        if category_totals.get('TLS_CLIENT_ACCEPT'):
            hints.append(
                {
                    'kind': 'info',
                    'title': 'Start with client trust and bump compatibility',
                    'body': 'Repeated SQUID_TLS_ERR_ACCEPT bad-record-MAC errors usually mean the client rejected or mangled the intercepted TLS session. Confirm clients trust the proxy CA, splice pinned apps or no-bump CIDRs, and verify clients are configured to use the proxy as an HTTP proxy rather than an HTTPS proxy.',
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