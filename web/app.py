from dataclasses import dataclass
from flask import Flask, g, render_template, request, redirect, url_for, jsonify, abort, session
from services.squidctl import SquidController
from services.cert_manager import generate_self_signed_ca_bundle, install_pfx_as_ca, materialize_certificate_bundle, parse_pfx_bundle
from services.certificate_bundles import get_certificate_bundles as _default_get_certificate_bundles
from services.auth_store import get_auth_store
from services.config_revisions import get_config_revisions as _default_get_config_revisions
from services.diagnostic_store import get_diagnostic_store as _default_get_diagnostic_store
from datetime import UTC, datetime, timedelta
import time
import os
import shutil
from services.exclusions_store import get_exclusions_store as _default_get_exclusions_store
from services.audit_store import get_audit_store as _default_get_audit_store
from services.timeseries_store import get_timeseries_store as _default_get_timeseries_store
from services.ssl_errors_store import get_ssl_errors_store as _default_get_ssl_errors_store
from services.adblock_store import get_adblock_store as _default_get_adblock_store
from services.adblock_artifacts import get_adblock_artifacts
from services.webfilter_store import get_webfilter_store as _default_get_webfilter_store
from services.sslfilter_store import get_sslfilter_store as _default_get_sslfilter_store
from services.pac_profiles_store import get_pac_profiles_store as _default_get_pac_profiles_store
from services.pac_renderer import resolve_proxy_pac_target
from services.proxy_client import ProxyClientError, get_proxy_client as _default_get_proxy_client
from services.proxy_context import get_default_proxy_id, get_proxy_id, normalize_proxy_id, reset_proxy_id, set_proxy_id
from services.proxy_health import build_remote_clamav_view, build_unavailable_runtime_health, check_adblock_icap_health, check_av_icap_health, check_clamd_health, send_sample_av_icap as _shared_send_sample_av_icap, test_eicar as _shared_test_eicar
from services.proxy_registry import get_proxy_registry as _default_get_proxy_registry
from services.housekeeping import start_housekeeping
from services.background_guard import acquire_background_lock
from services.observability_queries import get_observability_queries as _default_get_observability_queries
from services.errors import public_error_message
from services.logutil import log_exception_throttled
from services.runtime_helpers import decode_bytes as _decode_bytes, extract_domain as _extract_domain
from services.squid_config_forms import (
    build_template_options,
    build_template_options_from_form,
    get_config_ui_field_map,
    get_config_ui_sections,
    normalize_safe_form_kind,
    parse_cache_override_form,
)
from services.ui_support import (
    append_query_to_local_return as _append_query_to_local_return,
    bulk_lines as _bulk_lines,
    csv_safe as _csv_safe,
    present_observability_summary as _present_observability_summary,
    present_ssl_error_rows as _present_ssl_error_rows,
    present_transaction_rows as _present_transaction_rows,
    window_label as _window_label,
)

import re
import secrets
import csv
import io
from urllib.parse import urlparse
from typing import Any, Dict, Iterable, List, Sequence
from markupsafe import Markup

app = Flask(__name__)
_asset_version = str(int(time.time()))
OBSERVABILITY_DEFAULT_WINDOW = 24 * 60 * 60
_OBSERVABILITY_PANES = (
    'overview',
    'destinations',
    'clients',
    'cache',
    'ssl',
    'security',
    'performance',
)
_OBSERVABILITY_SORT_DEFAULTS = {
    'overview': 'requests',
    'destinations': 'requests',
    'clients': 'requests',
    'cache': 'requests',
    'ssl': 'recent',
    'security': 'recent',
    'performance': 'recent',
}
_OBSERVABILITY_SORT_OPTIONS = {
    'overview': ('requests',),
    'destinations': ('requests', 'recent', 'cache', 'clients'),
    'clients': ('requests', 'recent', 'cache', 'destinations'),
    'cache': ('requests', 'recent', 'domains', 'clients'),
    'ssl': ('recent',),
    'security': ('recent',),
    'performance': ('recent',),
}
_OBSERVABILITY_OVERVIEW_EXPORT_METRICS = (
    'request_records',
    'cache_hits',
    'cache_misses',
    'cache_hit_pct',
    'clients',
    'destinations',
    'transactions',
    'icap_events',
    'av_icap_events',
    'adblock_icap_events',
)
_OBSERVABILITY_EMPTY_EXPORT_HEADERS = {
    'overview': ['metric', 'value'],
    'destinations': [
        'domain',
        'requests',
        'percent_of_total',
        'clients',
        'transactions',
        'cache_hit_pct',
        'av_icap_events',
        'adblock_icap_events',
        'last_seen',
    ],
    'clients': [
        'client_ip',
        'hostname',
        'requests',
        'percent_of_total',
        'destinations',
        'transactions',
        'cache_hit_pct',
        'av_icap_events',
        'adblock_icap_events',
        'last_seen',
    ],
    'cache': ['reason', 'requests', 'percent_of_misses', 'domains', 'clients', 'last_seen'],
    'ssl': ['domain', 'category', 'category_label', 'reason', 'count', 'first_seen', 'last_seen'],
    'security': ['source', 'timestamp', 'client', 'target', 'detail', 'status'],
    'performance': ['type', 'timestamp', 'subject', 'metric', 'detail'],
}


def _default_check_icap_adblock() -> Dict[str, Any]:
    return check_adblock_icap_health(timeout=0.8, error_formatter=public_error_message)


def _default_check_icap_av() -> Dict[str, Any]:
    return check_av_icap_health(timeout=0.8, error_formatter=public_error_message)


def _default_check_clamd() -> Dict[str, Any]:
    return check_clamd_health(timeout=0.8, error_formatter=public_error_message)


def _default_send_sample_av_icap() -> Dict[str, Any]:
    return _shared_send_sample_av_icap(error_formatter=public_error_message)


def _default_test_eicar() -> Dict[str, Any]:
    return _shared_test_eicar(error_formatter=public_error_message)


@dataclass(frozen=True)
class AppRuntimeServices:
    controller: Any
    get_certificate_bundles: Any
    get_config_revisions: Any
    get_diagnostic_store: Any
    get_exclusions_store: Any
    get_audit_store: Any
    get_timeseries_store: Any
    get_ssl_errors_store: Any
    get_adblock_store: Any
    get_webfilter_store: Any
    get_sslfilter_store: Any
    get_pac_profiles_store: Any
    get_proxy_client: Any
    get_proxy_registry: Any
    get_observability_queries: Any
    check_icap_adblock: Any
    check_icap_av: Any
    check_clamd: Any
    send_sample_av_icap: Any
    test_eicar: Any


_default_app_runtime_services = AppRuntimeServices(
    controller=SquidController(),
    get_certificate_bundles=_default_get_certificate_bundles,
    get_config_revisions=_default_get_config_revisions,
    get_diagnostic_store=_default_get_diagnostic_store,
    get_exclusions_store=_default_get_exclusions_store,
    get_audit_store=_default_get_audit_store,
    get_timeseries_store=_default_get_timeseries_store,
    get_ssl_errors_store=_default_get_ssl_errors_store,
    get_adblock_store=_default_get_adblock_store,
    get_webfilter_store=_default_get_webfilter_store,
    get_sslfilter_store=_default_get_sslfilter_store,
    get_pac_profiles_store=_default_get_pac_profiles_store,
    get_proxy_client=_default_get_proxy_client,
    get_proxy_registry=_default_get_proxy_registry,
    get_observability_queries=_default_get_observability_queries,
    check_icap_adblock=_default_check_icap_adblock,
    check_icap_av=_default_check_icap_av,
    check_clamd=_default_check_clamd,
    send_sample_av_icap=_default_send_sample_av_icap,
    test_eicar=_default_test_eicar,
)


def _app_runtime_services() -> AppRuntimeServices:
    return _default_app_runtime_services


class _ControllerProxy:
    def __getattr__(self, name: str) -> Any:
        return getattr(_app_runtime_services().controller, name)


squid_controller = _ControllerProxy()


def get_certificate_bundles():
    return _app_runtime_services().get_certificate_bundles()


def get_config_revisions():
    return _app_runtime_services().get_config_revisions()


def get_diagnostic_store():
    return _app_runtime_services().get_diagnostic_store()


def get_exclusions_store():
    return _app_runtime_services().get_exclusions_store()


def get_audit_store():
    return _app_runtime_services().get_audit_store()


def get_timeseries_store():
    return _app_runtime_services().get_timeseries_store()


def get_ssl_errors_store():
    return _app_runtime_services().get_ssl_errors_store()


def get_adblock_store():
    return _app_runtime_services().get_adblock_store()


def get_webfilter_store():
    return _app_runtime_services().get_webfilter_store()


def get_sslfilter_store():
    return _app_runtime_services().get_sslfilter_store()


def get_pac_profiles_store():
    return _app_runtime_services().get_pac_profiles_store()


def get_proxy_client():
    return _app_runtime_services().get_proxy_client()


def get_proxy_registry():
    return _app_runtime_services().get_proxy_registry()


def get_observability_queries():
    return _app_runtime_services().get_observability_queries()


def _max_workers() -> int:
    """Upper bound for Squid workers.

    Must match the backend Squid controller clamp to avoid the UI silently
    downscaling an existing config.
    """
    try:
        v = int((os.environ.get('MAX_WORKERS') or '4').strip())
    except Exception:
        v = 4
    # Hard-cap worker count to keep SMP sizing sane for this container profile.
    return min(4, max(1, v))

# Global request body limit (bytes). Keep reasonably above common form posts.
try:
    app.config.setdefault(
        'MAX_CONTENT_LENGTH',
        int((os.environ.get('MAX_CONTENT_LENGTH') or str(16 * 1024 * 1024)).strip()),
    )
except Exception:
    app.config.setdefault('MAX_CONTENT_LENGTH', 16 * 1024 * 1024)

# Session security: persist a secret key so login survives container restarts.
_auth_store = get_auth_store()
_env_secret = (os.environ.get('FLASK_SECRET_KEY') or '').strip()
if _env_secret:
    app.secret_key = _env_secret
else:
    try:
        app.secret_key = _auth_store.get_or_create_secret_key()
    except Exception:
        # Fallback: sessions will reset on restart.
        app.secret_key = secrets.token_urlsafe(48)

# Cookie hardening. Defaults chosen to avoid breaking common HTTP deployments.
# Note: use explicit assignment (not setdefault) so the Set-Cookie attributes are
# reliably emitted across Flask/Werkzeug versions.
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
if (os.environ.get('SESSION_COOKIE_SECURE') or '').strip() in ('1', 'true', 'True', 'yes', 'on'):
    app.config['SESSION_COOKIE_SECURE'] = True

# Session timeout: auto-logout after 8 hours of inactivity (configurable via env).
try:
    _session_hours = int(os.environ.get('SESSION_TIMEOUT_HOURS', '8').strip())
except Exception:
    _session_hours = 8
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=max(1, _session_hours))

# Ensure there is at least one login.
try:
    _auth_store.ensure_default_admin()
except Exception:
    pass


def _is_logged_in() -> bool:
    u = session.get('user')
    return bool(u and isinstance(u, str))


def _query_flag(value: bool) -> str | None:
    return '1' if value else None


_NON_PROXY_ENDPOINTS = frozenset({'static', 'login', 'logout', 'health'})


def _filter_none_params(params: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in params.items() if v is not None}


def _should_preserve_proxy(endpoint: str, params: Dict[str, Any] | None = None) -> bool:
    if endpoint in _NON_PROXY_ENDPOINTS:
        return False
    if params and params.get('proxy_id') is not None:
        return False
    return True


def _endpoint_url(endpoint: str, **params: Any) -> str:
    values = _filter_none_params(params)
    if _should_preserve_proxy(endpoint, values):
        values['proxy_id'] = get_proxy_id()
    return url_for(endpoint, **values)


def _redirect_to(endpoint: str, **params):
    return redirect(_endpoint_url(endpoint, **params))


def _redirect_with_message(endpoint: str, *, ok: bool, msg: str, **params):
    return _redirect_to(endpoint, ok=('1' if ok else '0'), msg=msg, **params)


def _redirect_config(tab: str, *, ok: bool = False, error: bool = False, subtab: str | None = None):
    return _redirect_to('squid_config', tab=tab, subtab=subtab, ok=_query_flag(ok), error=_query_flag(error))


def _record_audit_event(
    kind: str,
    *,
    ok: bool,
    detail: str = '',
    config_text: str | None = None,
) -> None:
    payload: dict[str, Any] = {
        'kind': kind,
        'ok': ok,
        'remote_addr': request.remote_addr,
        'user_agent': request.headers.get('User-Agent'),
        'detail': str(detail or '')[:4000],
    }
    if config_text is not None:
        payload['config_text'] = config_text
    try:
        get_audit_store().record(**payload)
    except Exception:
        pass


def _normalize_choice(value: str | None, allowed: tuple[str, ...] | list[str] | set[str], default: str) -> str:
    candidate = (value or '').strip().lower()
    return candidate if candidate in allowed else default


def _form_action(*, default: str = '', lower: bool = False) -> str:
    action = (request.form.get('action') or default).strip()
    return action.lower() if lower else action


def _posted_int(name: str, default: int) -> int:
    value = (request.form.get(name) or '').strip()
    try:
        return int(value)
    except ValueError:
        return default


def _bounded_int(value: object, *, default: int, minimum: int | None = None, maximum: int | None = None) -> int:
    try:
        parsed = int(str(value).strip())
    except Exception:
        parsed = int(default)
    if minimum is not None:
        parsed = max(minimum, parsed)
    if maximum is not None:
        parsed = min(maximum, parsed)
    return parsed


def _query_int_arg(name: str, *, default: int, minimum: int | None = None, maximum: int | None = None) -> int:
    return _bounded_int(request.args.get(name), default=default, minimum=minimum, maximum=maximum)


def _csv_response(headers: Sequence[str], rows: Iterable[Sequence[object]]):
    buf = io.StringIO()
    writer = csv.writer(buf, delimiter=';', lineterminator='\n')
    writer.writerow(list(headers))
    for row in rows:
        writer.writerow([_csv_safe(value) for value in row])
    return app.response_class(buf.getvalue(), mimetype='text/csv; charset=utf-8')


def _observability_pane_from_request() -> str:
    return _normalize_choice(request.args.get('pane') or 'overview', _OBSERVABILITY_PANES, 'overview')


def _observability_sort_from_request(pane: str) -> str:
    default = _OBSERVABILITY_SORT_DEFAULTS[pane]
    return _normalize_choice(request.args.get('sort') or default, _OBSERVABILITY_SORT_OPTIONS[pane], default)


def _observability_resolve_hostnames_from_request() -> bool:
    resolve_values = request.args.getlist('resolve_hostnames')
    return True if not resolve_values else any((value or '').strip() == '1' for value in resolve_values)


def _empty_observability_summary() -> Dict[str, Any]:
    return {
        'request_records': 0,
        'cache_hits': 0,
        'cache_misses': 0,
        'cache_hit_pct': 0.0,
        'clients': 0,
        'destinations': 0,
        'transactions': 0,
        'icap_events': 0,
        'av_icap_events': 0,
        'adblock_icap_events': 0,
    }


def _empty_observability_payload(pane: str, *, summary: Dict[str, Any] | None = None) -> Dict[str, Any]:
    base_summary = dict(summary or _empty_observability_summary())
    ssl_payload = {
        'summary': {
            'bucket_count': 0,
            'total_events': 0,
            'known_domains': 0,
            'unknown_target_buckets': 0,
        },
        'top_categories': [],
        'hints': [],
        'top_domains': [],
        'rows': [],
    }
    security_payload = {
        'summary': {
            'av_events': 0,
            'potential_findings': 0,
            'adblock_blocks': 0,
            'webfilter_blocks': 0,
            'webfilter_categories': 0,
            'combined_blocks': 0,
        },
        'notes': [],
        'av_rows': [],
        'av_top_targets': [],
        'adblock_rows': [],
        'adblock_top_domains': [],
        'webfilter_rows': [],
        'webfilter_top_categories': [],
    }
    performance_payload = {
        'summary': {
            'requests': 0,
            'transactions': 0,
            'icap_events': 0,
        },
        'av_icap_summary': {'events': 0},
        'adblock_icap_summary': {'events': 0},
        'slow_requests': [],
        'slow_icap_events': [],
        'top_user_agents': [],
        'top_bump_modes': [],
        'top_tls_server_versions': [],
        'top_policy_tags': [],
    }

    if pane == 'overview':
        return {
            'summary': base_summary,
            'destinations': [],
            'clients': [],
            'cache_reasons': [],
            'ssl': ssl_payload,
            'security': security_payload,
            'performance': performance_payload,
        }
    if pane in ('destinations', 'clients', 'cache'):
        return {'rows': []}
    if pane == 'ssl':
        return ssl_payload
    if pane == 'security':
        return security_payload
    if pane == 'performance':
        return performance_payload
    return {'rows': []}


def _empty_observability_export_response(pane: str):
    headers = _OBSERVABILITY_EMPTY_EXPORT_HEADERS.get(
        pane,
        _OBSERVABILITY_EMPTY_EXPORT_HEADERS['destinations'],
    )
    if pane == 'overview':
        rows = ([metric, 0] for metric in _OBSERVABILITY_OVERVIEW_EXPORT_METRICS)
        return _csv_response(headers, rows)
    return _csv_response(headers, [])


def _redirect_after_policy_refresh(endpoint: str, store: Any, *, force: bool = True, **params):
    _best_effort_refresh_managed_policy(store, force=force)
    return _redirect_to(endpoint, **params)


def _redirect_after_pac_refresh(endpoint: str, **params):
    _best_effort_refresh_pac_runtime()
    return _redirect_to(endpoint, **params)


def _redirect_after_pac_refresh_to_return(return_to: str | None, fallback_endpoint: str, **params: Any):
    _best_effort_refresh_pac_runtime()
    target = _append_query_to_local_return(return_to, **params)
    if target:
        return redirect(target)
    return _redirect_to(fallback_endpoint, **params)


def _coerce_store_result(result: Any, *, success_default: bool = True, error_default: str = '') -> tuple[bool, str]:
    if isinstance(result, tuple):
        ok = bool(result[0])
        err = str(result[1] or '') if len(result) > 1 else ''
        return ok, err
    if result is None:
        return success_default, error_default
    if isinstance(result, bool):
        return bool(result), ('' if result else (error_default or 'Operation failed.'))
    return success_default, error_default


def _add_exclusion_domain(store: Any, value: str) -> tuple[bool, str, str]:
    domain = _extract_domain(value)
    if not domain:
        return False, 'Domain is required.', ''
    try:
        ok, err = _coerce_store_result(store.add_domain(value), success_default=True)
        return ok, err, domain
    except Exception as exc:
        return False, public_error_message(exc), domain


def _add_exclusion_cidr(store: Any, value: str) -> tuple[bool, str, str]:
    cidr = (value or '').strip()
    if not cidr:
        return False, 'CIDR is required.', ''
    try:
        ok, err = _coerce_store_result(store.add_net('src_nets', cidr), success_default=True)
        return ok, err, cidr
    except Exception as exc:
        return False, public_error_message(exc), cidr


def _render_template_config_text(
    options: Dict[str, Any],
    *,
    overrides: Dict[str, bool] | None = None,
    exclusions: Any | None = None,
) -> str:
    current = _current_managed_config()
    effective_overrides = overrides if overrides is not None else squid_controller.get_cache_override_options(current)
    effective_exclusions = exclusions if exclusions is not None else get_exclusions_store().list_all()
    config_text = squid_controller.generate_config_from_template_with_exclusions(options, effective_exclusions)
    return squid_controller.apply_cache_overrides(config_text, effective_overrides)


def _publish_template_config(
    options: Dict[str, Any],
    *,
    source_kind: str,
    audit_kind: str,
    overrides: Dict[str, bool] | None = None,
    exclusions: Any | None = None,
) -> tuple[bool, str]:
    config_text = _render_template_config_text(options, overrides=overrides, exclusions=exclusions)
    ok, detail = _publish_config_for_current_mode(config_text, source_kind=source_kind)
    _record_audit_event(audit_kind, ok=ok, detail=detail, config_text=config_text)
    return ok, str(detail or '')


def _active_proxy_management_url() -> str:
    proxy = get_proxy_registry().get_proxy(get_proxy_id())
    if proxy is None:
        return ''
    return str(proxy.management_url or '').strip()


def _uses_remote_proxy_runtime() -> bool:
    return bool(_active_proxy_management_url())


def _best_effort_apply_adblock_flush() -> None:
    try:
        _trigger_proxy_sync()
    except Exception:
        pass


def _pac_profile_form_data(*, profile_id: int | None) -> Dict[str, Any]:
    return {
        'profile_id': profile_id,
        'name': request.form.get('name') or '',
        'client_cidr': request.form.get('client_cidr') or '',
        'direct_domains_text': request.form.get('direct_domains') or '',
        'direct_dst_nets_text': request.form.get('direct_dst_nets') or '',
    }


def _selected_proxy_pac_context() -> tuple[Any, str, str]:
    target = resolve_proxy_pac_target(get_proxy_id())
    pac_url = target.pac_url
    warning = ''
    if not pac_url:
        warning = (
            'This proxy does not advertise an authoritative public PAC hostname yet. '
            'Set PROXY_PUBLIC_HOST or PROXY_PUBLIC_PAC_URL on the selected proxy container so the Admin UI can publish a direct PAC URL.'
        )
    return target, pac_url, warning


def _safe_next_url(next_url: str) -> str:
    """Allow only local relative redirects to avoid open-redirect issues."""
    candidate = (next_url or '').strip()
    if not candidate:
        return ''
    # Disallow scheme-relative (//evil.com) and absolute URLs.
    if candidate.startswith('//'):
        return ''
    parsed = urlparse(candidate)
    if parsed.scheme or parsed.netloc:
        return ''
    # Only allow app-local paths.
    if not candidate.startswith('/'):
        return ''
    return candidate


def _csrf_disabled() -> bool:
    return (os.environ.get('DISABLE_CSRF') or '').strip().lower() in ('1', 'true', 'yes', 'on')




def _ensure_csrf_token() -> str:
    tok = session.get('_csrf_token')
    if not tok or not isinstance(tok, str):
        tok = secrets.token_urlsafe(32)
        session['_csrf_token'] = tok
    return tok


@app.before_request
def _csrf_guard():
    if _csrf_disabled():
        return None
    if request.method not in ('POST', 'PUT', 'PATCH', 'DELETE'):
        return None

    sent = (request.headers.get('X-CSRF-Token') or '').strip()
    if not sent:
        sent = (request.form.get('csrf_token') or '').strip()

    expected = _ensure_csrf_token()
    if not sent or not secrets.compare_digest(sent, expected):
        abort(403)
    return None


@app.after_request
def _security_headers(resp):
    # Conservative baseline. Avoid breaking existing inline scripts/styles.
    resp.headers.setdefault('X-Content-Type-Options', 'nosniff')
    resp.headers.setdefault('X-Frame-Options', 'SAMEORIGIN')
    resp.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
    resp.headers.setdefault('Permissions-Policy', 'geolocation=(), microphone=(), camera=()')
    try:
        if (resp.mimetype or '').lower().startswith('text/html'):
            resp.headers.setdefault(
                'Content-Security-Policy',
                "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
            )
    except Exception:
        pass
    return resp


@app.context_processor
def _inject_csrf():
    token = _ensure_csrf_token()

    def csrf_field() -> Markup:
        return Markup(f'<input type="hidden" name="csrf_token" value="{token}">')

    return {
        'csrf_token': token,
        'csrf_field': csrf_field,
    }


@app.context_processor
def _inject_route_helpers():
    def scoped_url_for(endpoint: str, **values: Any) -> str:
        return _endpoint_url(endpoint, **values)

    return {
        'proxy_url': scoped_url_for,
        'url_for': scoped_url_for,
    }


@app.before_request
def _require_login_guard():
    # Allow liveness and static assets unauthenticated.
    if request.endpoint in (None, 'static', 'health'):
        return None

    # Allow auth routes.
    if request.endpoint in ('login', 'logout'):
        return None

    if _is_logged_in():
        return None

    # Redirect everything else to login.
    return _redirect_to('login', next=request.full_path)


def _resolve_selected_proxy_id() -> str:
    requested_proxy = request.form.get('proxy_id') or request.args.get('proxy_id')
    if requested_proxy is not None:
        session['active_proxy_id'] = normalize_proxy_id(requested_proxy)

    preferred = session.get('active_proxy_id') or get_default_proxy_id()
    registry = get_proxy_registry()
    active = registry.resolve_proxy_id(preferred)
    session['active_proxy_id'] = active
    return active


@app.before_request
def _bind_proxy_context():
    token = set_proxy_id(_resolve_selected_proxy_id())
    g._proxy_context_token = token
    return None


@app.teardown_request
def _reset_proxy_context(_exc):
    token = getattr(g, '_proxy_context_token', None)
    if token is not None:
        reset_proxy_id(token)


@app.context_processor
def _inject_proxy_context():
    active_proxy_id = get_proxy_id()
    registry = get_proxy_registry()
    proxies = registry.list_proxies()
    if not proxies:
        proxies = [registry.ensure_default_proxy()]
    active_proxy = registry.get_proxy(active_proxy_id) or proxies[0]
    return {
        'active_proxy_id': active_proxy.proxy_id,
        'active_proxy': active_proxy,
        'proxy_inventory': proxies,
    }


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        next_url = _safe_next_url(request.form.get('next') or '')
        if _auth_store.verify_user(username, password):
            # Prevent session fixation by clearing any existing session data.
            prev_csrf = session.get('_csrf_token')
            session.clear()
            # Keep a CSRF token available immediately after login so that the
            # next POST (often triggered by UI actions) can succeed even if the
            # client does not perform an intermediate template-rendering GET.
            if prev_csrf and isinstance(prev_csrf, str):
                session['_csrf_token'] = prev_csrf
            else:
                session['_csrf_token'] = secrets.token_urlsafe(32)
            session['user'] = username
            session.permanent = True  # Apply PERMANENT_SESSION_LIFETIME
            _record_audit_event('login_success', ok=True, detail=f'user={username}')
            return redirect(next_url or url_for('index'))
        # Log failed login attempt for security auditing
        _record_audit_event('login_failed', ok=False, detail=f'user={username}')
        return render_template('login.html', error='Invalid username or password.', next=next_url)

    if _is_logged_in():
        return _redirect_to('index')
    next_url = _safe_next_url(request.args.get('next') or '')
    return render_template('login.html', error=None, next=next_url)


@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return _redirect_to('login')


def _options_from_tunables(tunables: Dict[str, Any]) -> Dict[str, Any]:
    return build_template_options(tunables, max_workers=_max_workers())

_disable_background = (os.environ.get('DISABLE_BACKGROUND') or '').strip() == '1'

# In multi-worker servers, ensure only one process runs background workers.
if not _disable_background:
    try:
        if not acquire_background_lock():
            _disable_background = True
    except Exception:
        pass


@app.template_filter('datetimeformat')
def _datetimeformat(ts: object) -> str:
    try:
        i = int(ts)  # type: ignore[arg-type]
        if i <= 0:
            return ''
        return datetime.fromtimestamp(i).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return ''

if not _disable_background:
    # Build and activate adblock artifacts from MySQL-backed admin state.
    try:
        get_adblock_artifacts().start_background()
    except Exception:
        pass

    # Start web filtering background updater (downloads/compiles categories daily at midnight).
    try:
        get_webfilter_store().start_background()
    except Exception:
        pass

    # Daily housekeeping: prune old benign DB entries (best-effort).
    try:
        start_housekeeping(retention_days=30, interval_seconds=24 * 60 * 60)
    except Exception:
        pass


@app.context_processor
def inject_now():
    def fmt_ts(ts: int) -> str:
        try:
            return datetime.fromtimestamp(int(ts)).strftime('%Y-%m-%d %H:%M:%S')
        except Exception:
            return ''

    return {
        # Use timezone-aware UTC to avoid deprecation warnings.
        "current_year": datetime.now(UTC).year,
        "asset_version": _asset_version,
        "fmt_ts": fmt_ts,
        "observability_default_window": OBSERVABILITY_DEFAULT_WINDOW,
    }


def _build_observability_snapshot(window_i: int = OBSERVABILITY_DEFAULT_WINDOW) -> tuple[Dict[str, int], str]:
    since_ts = int(time.time()) - max(300, int(window_i or OBSERVABILITY_DEFAULT_WINDOW))
    diagnostic_summary: Dict[str, Any] = {}
    ssl_summary: Dict[str, Any] = {}
    try:
        diagnostic_summary = get_diagnostic_store().activity_summary(since=since_ts)
    except Exception:
        diagnostic_summary = {}
    try:
        ssl_rows = get_ssl_errors_store().list_recent(since=since_ts, search='', limit=100)
        ssl_summary = _present_ssl_error_rows(ssl_rows).get('summary', {})
    except Exception:
        ssl_summary = {}
    return _present_observability_summary(diagnostic_summary=diagnostic_summary, ssl_summary=ssl_summary), _window_label(window_i)


def _correlate_request_for_icap_events(diagnostic_store: Any, icap_events: List[Dict[str, Any]], *, icap_limit: int = 0) -> List[Dict[str, Any]]:
    for event in icap_events:
        event['correlated_request'] = None
        tx = str(event.get('master_xaction') or '').strip()
        if not tx:
            continue
        request_row = diagnostic_store.find_request_by_master_xaction(tx)
        if request_row is None:
            continue
        request_event = dict(request_row)
        request_event['related_icap'] = []
        request_event['correlation_kind'] = 'master_xaction'
        event['correlated_request'] = _present_transaction_rows([request_event], icap_limit=icap_limit)[0]
    return icap_events


def _correlate_policy_events(diagnostic_store: Any, rows: List[Dict[str, Any]], *, window_i: int, service: str = '') -> List[Dict[str, Any]]:
    for row in rows:
        row['correlated_candidates'] = []
        try:
            candidates = diagnostic_store.list_request_candidates_for_policy_event(
                around_ts=int(row.get('ts') or 0),
                url=str(row.get('url') or ''),
                client_ip=str(row.get('src_ip') or ''),
                domain=str(row.get('domain') or ''),
                window_seconds=max(120, min(window_i, 900)),
                limit=3,
                service=service,
            )
            row['correlated_candidates'] = _present_transaction_rows(candidates, icap_limit=3)
        except Exception:
            row['correlated_candidates'] = []
    return rows


def _current_managed_config() -> str:
    """Return the effective config for the active proxy.

    Config revisions are the source of truth. The live Squid config is used only
    as a bootstrap fallback for a proxy that has not yet stored its first revision.
    """
    revisions = get_config_revisions()
    current = revisions.get_active_config_text(get_proxy_id())
    if current:
        return current
    fallback = squid_controller.get_current_config() or ""
    if fallback.strip():
        revisions.ensure_active_revision(get_proxy_id(), fallback, created_by='system', source_kind='bootstrap')
    return fallback


def _validate_config_for_current_mode(config_text: str) -> tuple[bool, str]:
    """Validate with the selected proxy runtime when available.

    The admin UI image is intentionally standalone-capable and does not require
    a local Squid process. Real validation belongs on the selected proxy because
    that container owns the Squid binary, generated includes, ssl_db paths, and
    cache runtime layout.
    """
    proxy_id = get_proxy_id()
    if _active_proxy_management_url():
        try:
            result = get_proxy_client().validate_config(proxy_id, config_text)
            return bool(result.get('ok', False)), str(result.get('detail') or '')
        except ProxyClientError as exc:
            return False, f'Proxy validation failed: {exc}'

    if shutil.which('squid') is not None:
        return squid_controller.validate_config_text(config_text)

    return False, (
        f"Proxy '{proxy_id}' is not registered with a management URL, and this admin UI container "
        "does not include a local Squid runtime for validation. Start/select a proxy container before applying config changes."
    )


def _publish_config_for_current_mode(config_text: str, *, source_kind: str) -> tuple[bool, str]:
    config_text = squid_controller.normalize_config_text(config_text)
    proxy_id = get_proxy_id()
    created_by = str(session.get('user') or '')
    revisions = get_config_revisions()
    valid, validation_detail = _validate_config_for_current_mode(config_text)
    if not valid:
        detail = (validation_detail or 'Squid config validation failed.').strip()
        return False, f'Config validation failed; revision was not activated.\n{detail}'.strip()
    revision = revisions.create_revision(
        proxy_id,
        config_text,
        created_by=created_by,
        source_kind=source_kind,
        activate=True,
    )
    if not _uses_remote_proxy_runtime():
        if shutil.which('squid') is None:
            return False, (
                f"Revision {revision.revision_id} saved, but no proxy management URL is registered for proxy '{proxy_id}' "
                "and the admin UI container cannot apply Squid configs locally."
            )
        ok, detail = squid_controller.apply_config_text(config_text)
        revisions.record_apply_result(
            proxy_id,
            revision.revision_id,
            ok=ok,
            detail=str(detail or ''),
            applied_by='admin-ui',
        )
        return ok, str(detail or f'Revision {revision.revision_id} applied locally.')
    try:
        result = get_proxy_client().sync_proxy(proxy_id, force=True)
        ok = bool(result.get('ok', False))
        detail = str(result.get('detail') or f'Revision {revision.revision_id} queued for sync.')
        return ok, detail
    except ProxyClientError as exc:
        return False, f'Revision {revision.revision_id} saved, but immediate sync failed: {exc}'


def _trigger_proxy_sync(*, force: bool = False) -> tuple[bool, str]:
    """Request an immediate config sync for the selected proxy."""
    try:
        result = get_proxy_client().sync_proxy(get_proxy_id(), force=force)
        return bool(result.get('ok', False)), str(result.get('detail') or 'Sync requested.')
    except ProxyClientError as exc:
        return False, str(exc)


def _trigger_proxy_cache_clear() -> tuple[bool, str]:
    """Clear cache for the selected proxy."""
    try:
        result = get_proxy_client().clear_proxy_cache(get_proxy_id())
        return bool(result.get('ok', False)), str(result.get('detail') or 'Cache clear requested.')
    except ProxyClientError as exc:
        return False, str(exc)


def _record_local_certificate_apply(bundle, *, original_filename: str = '', already_materialized: bool = False) -> tuple[bool, str]:
    bundle_store = get_certificate_bundles()
    revision = bundle_store.create_revision(
        bundle,
        created_by=str(session.get('user') or ''),
        original_filename=(original_filename or '')[:255],
        activate=True,
    )
    detail_parts: list[str] = []
    ok = True
    if not already_materialized:
        try:
            materialize_certificate_bundle(
                (os.environ.get('CERTS_DIR') or '/etc/squid/ssl/certs').strip() or '/etc/squid/ssl/certs',
                bundle,
                original_pfx_bytes=bundle.original_pfx_bytes,
            )
        except Exception as exc:
            ok = False
            detail_parts.append(public_error_message(exc, default='Failed to install certificate bundle locally.'))
    if ok:
        reload_result = squid_controller.reload_squid()
        if isinstance(reload_result, tuple) and len(reload_result) == 2:
            stdout, stderr = reload_result
            reload_detail = ((_decode_bytes(stdout) + '\n' + _decode_bytes(stderr)).strip())
            ok = not bool(stderr)
            if reload_detail:
                detail_parts.append(reload_detail)
        else:
            detail_parts.append('Certificate bundle installed locally.')
    detail = '\n'.join(part for part in detail_parts if part).strip() or (
        f'Certificate revision {revision.revision_id} applied locally.' if ok else 'Failed to apply certificate bundle locally.'
    )
    bundle_store.record_apply_result(
        get_proxy_id(),
        revision.revision_id,
        ok=ok,
        detail=detail,
        applied_by='admin-ui',
        bundle_sha256=revision.bundle_sha256,
    )
    return ok, detail


def _publish_certificate_bundle_remote(bundle, *, original_filename: str = '') -> tuple[bool, str]:
    if not _uses_remote_proxy_runtime():
        return _record_local_certificate_apply(bundle, original_filename=original_filename)

    bundle_store = get_certificate_bundles()
    revision = bundle_store.create_revision(
        bundle,
        created_by=str(session.get('user') or ''),
        original_filename=(original_filename or '')[:255],
        activate=True,
    )
    proxies = get_proxy_registry().list_proxies()
    attempted = len(proxies)
    ok_count = 0
    if attempted:
        try:
            client = get_proxy_client()
        except Exception:
            client = None
        if client is not None:
            for proxy in proxies:
                try:
                    result = client.sync_proxy(proxy.proxy_id, force=True)
                except ProxyClientError:
                    continue
                if bool(result.get('ok', False)):
                    ok_count += 1
    if attempted == 0:
        detail = (
            f'Certificate revision {revision.revision_id} saved. '
            'No registered proxies were available to nudge; proxies will apply it on their next poll.'
        )
    elif ok_count == attempted:
        plural = 'proxy' if ok_count == 1 else 'proxies'
        detail = f'Certificate revision {revision.revision_id} saved. Nudged {ok_count} {plural} immediately.'
    else:
        detail = (
            f'Certificate revision {revision.revision_id} saved. '
            f'Nudged {ok_count}/{attempted} proxies immediately; remaining proxies will apply it on their next poll.'
        )
    return True, detail


def _best_effort_init_store(store: Any, *, key: str, description: str) -> None:
    try:
        store.init_db()
    except Exception:
        log_exception_throttled(
            app.logger,
            f'web.app.{key}.init_db',
            interval_seconds=30.0,
            message=f'Failed to initialize {description} store',
        )


def _best_effort_refresh_managed_policy(store: Any, *, force: bool = True) -> None:
    try:
        _trigger_proxy_sync(force=force)
    except Exception:
        log_exception_throttled(
            app.logger,
            'web.app.refresh_managed_policy',
            interval_seconds=30.0,
            message='Failed to refresh managed policy state',
        )


def _best_effort_refresh_pac_runtime() -> None:
    try:
        _trigger_proxy_sync()
    except Exception:
        log_exception_throttled(
            app.logger,
            'web.app.refresh_pac_runtime',
            interval_seconds=30.0,
            message='Failed to refresh PAC runtime state',
        )


def _handle_adblock_post(store: Any):
    action = _form_action()
    if action == 'save_lists':
        enabled_map = {}
        for st in store.list_statuses():
            enabled_map[st.key] = request.form.get(f'enabled_{st.key}') == 'on'
        store.set_enabled(enabled_map)
        store.request_refresh_now()
    elif action == 'save_settings':
        enabled = request.form.get('adblock_enabled') == 'on'
        cur = store.get_settings()
        cache_ttl = _posted_int('cache_ttl', int(cur.get('cache_ttl') or 0))
        cache_max = _posted_int('cache_max', int(cur.get('cache_max') or 0))
        store.set_settings(enabled=enabled, cache_ttl=cache_ttl, cache_max=cache_max)
        store.request_refresh_now()
    elif action == 'refresh':
        any_enabled = False
        try:
            any_enabled = any(st.enabled for st in store.list_statuses())
        except Exception:
            any_enabled = False
        if not any_enabled:
            return _redirect_to('adblock', refresh_no_lists='1')
        store.request_refresh_now()
        return _redirect_to('adblock', refresh_requested='1')
    elif action == 'flush_cache':
        store.request_cache_flush()
        _best_effort_apply_adblock_flush()
        return _redirect_to('adblock', cache_flushed='1')
    return _redirect_to('adblock')


def _handle_webfilter_post(store: Any, tab: str):
    action = _form_action()
    if action == 'save':
        enabled = request.form.get('enabled') == 'on'
        source_url = (request.form.get('source_url') or '').strip()
        categories = [c.strip() for c in request.form.getlist('categories') if (c or '').strip()]

        if enabled and not source_url:
            return _redirect_to('webfilter', tab='categories', err_source='1')

        if source_url:
            parsed = urlparse(source_url)
            if parsed.scheme not in ('http', 'https'):
                return _redirect_to('webfilter', tab='categories', err_source='1')

        store.set_settings(enabled=enabled, source_url=source_url, blocked_categories=categories)
        return _redirect_after_policy_refresh('webfilter', store, force=True, tab='categories')

    if action == 'whitelist_add':
        entry = (request.form.get('whitelist_domain') or '').strip()
        ok, err, _pat = store.add_whitelist(entry)
        if not ok:
            return _redirect_after_policy_refresh('webfilter', store, force=True, tab='whitelist', wl_err=(err or '1'))
        return _redirect_after_policy_refresh('webfilter', store, force=True, tab='whitelist', wl_ok='1')

    if action == 'whitelist_remove':
        pat = (request.form.get('pattern') or '').strip()
        try:
            store.remove_whitelist(pat)
        except Exception:
            pass
        return _redirect_after_policy_refresh('webfilter', store, force=True, tab='whitelist')

    return _redirect_to('webfilter', tab=tab)


def _handle_sslfilter_post(store: Any):
    action = _form_action(lower=True)
    if action == 'add':
        entry = (request.form.get('cidr') or '').strip()
        ok, err, _canonical = store.add_nobump(entry)
        if not ok:
            return _redirect_after_policy_refresh('sslfilter', store, force=True, err=(err or '1'))
        return _redirect_after_policy_refresh('sslfilter', store, force=True, ok='1')

    if action == 'remove':
        cidr = (request.form.get('cidr') or '').strip()
        try:
            store.remove_nobump(cidr)
        except Exception:
            pass
        return _redirect_after_policy_refresh('sslfilter', store, force=True)

    return _redirect_to('sslfilter')


def _handle_exclusions_post(store: Any):
    action = _form_action()
    return_to = request.form.get('return_to')
    if action == 'add_domain':
        ok, err, domain = _add_exclusion_domain(store, request.form.get('domain') or '')
        if ok:
            return _redirect_after_pac_refresh_to_return(return_to, 'exclusions', exclude_added=domain, added_domain=domain)
        return _redirect_after_pac_refresh_to_return(return_to, 'exclusions', exclude_error=(err or 'Unable to add domain.'))
    if action == 'add_domain_bulk':
        lines = _bulk_lines(request.form.get('domains_bulk'))
        added = 0
        errors: list[str] = []
        for line in lines:
            ok, err, _domain = _add_exclusion_domain(store, line)
            if ok:
                added += 1
            elif err:
                errors.append(f"{line}: {err}")
        return _redirect_after_pac_refresh_to_return(
            return_to,
            'exclusions',
            bulk_added=added,
            bulk_failed=len(errors),
            exclude_error=(' | '.join(errors[:3]) if errors else None),
        )
    if action == 'remove_domain':
        store.remove_domain(request.form.get('domain') or '')
        return _redirect_after_pac_refresh_to_return(return_to, 'exclusions', exclude_removed='1')
    if action == 'add_src':
        ok, err, cidr = _add_exclusion_cidr(store, request.form.get('cidr') or '')
        if ok:
            return _redirect_after_pac_refresh_to_return(return_to, 'exclusions', cidr_added=cidr)
        return _redirect_after_pac_refresh_to_return(return_to, 'exclusions', exclude_error=(err or 'Unable to add CIDR.'))
    if action == 'add_src_bulk':
        lines = _bulk_lines(request.form.get('src_bulk'))
        added = 0
        errors: list[str] = []
        for line in lines:
            ok, err, _cidr = _add_exclusion_cidr(store, line)
            if ok:
                added += 1
            elif err:
                errors.append(f"{line}: {err}")
        return _redirect_after_pac_refresh_to_return(
            return_to,
            'exclusions',
            bulk_cidrs_added=added,
            bulk_cidrs_failed=len(errors),
            exclude_error=(' | '.join(errors[:3]) if errors else None),
        )
    elif action == 'remove_src':
        store.remove_net('src_nets', request.form.get('cidr') or '')
        return _redirect_after_pac_refresh_to_return(return_to, 'exclusions', exclude_removed='1')
    elif action == 'toggle_private':
        store.set_exclude_private_nets(request.form.get('exclude_private_nets') == 'on')
        return _redirect_after_pac_refresh_to_return(return_to, 'exclusions', private_saved='1')
    elif action == 'apply':
        current = _current_managed_config()
        tunables = squid_controller.get_tunable_options(current)
        options = _options_from_tunables(tunables)
        ok, _details = _publish_template_config(
            options,
            source_kind='exclusions',
            audit_kind='config_apply_exclusions',
            exclusions=store.list_all(),
        )
        return _redirect_to('exclusions', ok=_query_flag(ok), error=_query_flag(not ok))
    return _redirect_to('exclusions')


def _handle_pac_builder_post(store: Any):
    action = _form_action()
    try:
        if action == 'create':
            ok, err, _ = store.upsert_profile(**_pac_profile_form_data(profile_id=None))
            if not ok:
                return _redirect_to('pac_builder', error='1', msg=err)
            return _redirect_after_pac_refresh('pac_builder', ok='1')

        if action == 'update':
            pid = int(request.form.get('profile_id') or '0')
            ok, err, _ = store.upsert_profile(**_pac_profile_form_data(profile_id=pid))
            if not ok:
                return _redirect_to('pac_builder', error='1', msg=err)
            return _redirect_after_pac_refresh('pac_builder', ok='1')

        if action == 'delete':
            pid = int(request.form.get('profile_id') or '0')
            store.delete_profile(pid)
            return _redirect_after_pac_refresh('pac_builder', ok='1')
    except Exception as e:
        return _redirect_to('pac_builder', error='1', msg=public_error_message(e))

    return _redirect_to('pac_builder')


def _handle_administration_post(store: Any, current_user: str):
    action = _form_action()
    try:
        if action == 'add_user':
            username = (request.form.get('username') or '').strip()
            password = request.form.get('password') or ''
            store.add_user(username, password)
            return _redirect_with_message('administration', ok=True, msg='User added.')

        if action == 'set_password':
            username = (request.form.get('username') or '').strip()
            new_password = request.form.get('new_password') or ''
            store.set_password(username, new_password)
            return _redirect_with_message('administration', ok=True, msg='Password updated.')

        if action == 'delete_user':
            username = (request.form.get('username') or '').strip()
            if username == current_user or username.casefold() == current_user.casefold():
                return _redirect_with_message('administration', ok=False, msg='Cannot remove the currently signed-in user.')
            users = store.list_users()
            if len(users) <= 1:
                return _redirect_with_message('administration', ok=False, msg='Cannot remove the last user.')
            store.delete_user(username)
            return _redirect_with_message('administration', ok=True, msg='User removed.')

        return _redirect_with_message('administration', ok=False, msg='Unknown action.')
    except Exception as e:
        app.logger.exception('Administration action failed')
        return _redirect_with_message('administration', ok=False, msg=public_error_message(e))


@app.route('/')
def index():
    observability, observability_window_label = _build_observability_snapshot(OBSERVABILITY_DEFAULT_WINDOW)
    proxy_id = get_proxy_id()
    try:
        health = get_proxy_client().get_health(proxy_id)
    except ProxyClientError as exc:
        proxy = get_proxy_registry().get_proxy(proxy_id)
        health = {
            'ok': False,
            'status': proxy.status if proxy else 'offline',
            'proxy_status': str(exc),
            'stats': {},
            'services': {
                'icap': {'ok': False, 'detail': 'unavailable'},
                'clamav': {'ok': False, 'detail': 'unavailable'},
            },
        }

    proxy_detail = str(health.get('proxy_status') or health.get('detail') or '')
    proxy_ok = bool(health.get('ok'))
    stats = health.get('stats') or {}
    try:
        trends = get_timeseries_store().summary()
    except Exception:
        trends = {}

    services = health.get('services') or {}
    icap_health = services.get('icap') or {'ok': False, 'detail': 'n/a'}
    clamav_health = services.get('clamav') or {'ok': False, 'detail': 'n/a'}

    last_config = None
    latest_apply = get_config_revisions().latest_apply(proxy_id)
    if latest_apply is not None:
        last_config = {
            'ts': latest_apply.applied_ts,
            'kind': 'config_apply_remote',
            'ok': latest_apply.ok,
            'remote_addr': proxy_id,
            'user_agent': latest_apply.applied_by,
            'detail': latest_apply.detail,
        }
    else:
        try:
            row = get_audit_store().latest_config_apply()
            if row:
                last_config = {
                    'ts': int(row[0]),
                    'kind': row[1],
                    'ok': bool(row[2]),
                    'remote_addr': row[3],
                    'user_agent': row[4],
                    'detail': row[5],
                }
        except Exception:
            pass

    return render_template(
        'index.html',
        proxy_status=proxy_detail,
        proxy_ok=proxy_ok,
        flask_status="OK",
        stats=stats,
        trends=trends,
        icap_health=icap_health,
        clamav_health=clamav_health,
        last_config=last_config,
        observability=observability,
        observability_window_label=observability_window_label,
    )


@app.route('/health', methods=['GET'])
def health():
    return jsonify({"ok": True}), 200


@app.route('/api/squid-config', methods=['GET'])
def api_squid_config():
    cfg = _current_managed_config()
    return app.response_class(cfg, mimetype='text/plain; charset=utf-8')


@app.route('/proxies', methods=['GET'])
def proxies():

    registry = get_proxy_registry()
    proxies = registry.list_proxies()
    live_health = {}
    observability_by_proxy: Dict[str, Dict[str, Any]] = {}
    client = get_proxy_client()
    for proxy in proxies:
        try:
            live_health[proxy.proxy_id] = client.get_health(proxy.proxy_id, timeout_seconds=1.5)
        except ProxyClientError as exc:
            live_health[proxy.proxy_id] = {
                'ok': False,
                'status': proxy.status,
                'detail': str(exc),
            }
        token = set_proxy_id(proxy.proxy_id)
        try:
            diagnostic_summary = get_diagnostic_store().activity_summary(since=int(time.time()) - OBSERVABILITY_DEFAULT_WINDOW)
            ssl_summary = _present_ssl_error_rows(
                get_ssl_errors_store().list_recent(since=int(time.time()) - 3600, search='', limit=100)
            ).get('summary', {})
            observability_by_proxy[proxy.proxy_id] = _present_observability_summary(
                diagnostic_summary=diagnostic_summary,
                ssl_summary=ssl_summary,
            )
        except Exception:
            observability_by_proxy[proxy.proxy_id] = _present_observability_summary()
        finally:
            reset_proxy_id(token)
    return render_template('fleet.html', proxies=proxies, live_health=live_health, observability_by_proxy=observability_by_proxy)


@app.route('/observability', methods=['GET'])
def observability():
    queries = get_observability_queries()
    pane = _observability_pane_from_request()
    sort = _observability_sort_from_request(pane)
    limit = _query_int_arg('limit', default=50, minimum=10, maximum=200)
    window_i = _query_int_arg('window', default=OBSERVABILITY_DEFAULT_WINDOW, minimum=300, maximum=7 * 24 * 3600)
    since_ts = int(time.time()) - window_i
    search = (request.args.get('q') or '').strip().lower()
    resolve_hostnames = _observability_resolve_hostnames_from_request()

    try:
        summary = queries.summary(since=since_ts)
    except Exception:
        log_exception_throttled(
            app.logger,
            'web.app.observability.summary',
            interval_seconds=30.0,
            message='Failed to load observability summary; rendering empty state',
        )
        summary = _empty_observability_summary()

    try:
        pane_payload: Dict[str, Any]
        if pane == 'overview':
            pane_payload = queries.overview_bundle(
                since=since_ts,
                search=search,
                limit=min(limit, 10),
                resolve_hostnames=resolve_hostnames,
            )
        elif pane == 'clients':
            pane_payload = {
                'rows': queries.top_clients(
                    since=since_ts,
                    search=search,
                    limit=limit,
                    sort=sort,
                    resolve_hostnames=resolve_hostnames,
                )
            }
        elif pane == 'cache':
            pane_payload = {
                'rows': queries.top_cache_reasons(
                    since=since_ts,
                    search=search,
                    limit=limit,
                    sort=sort,
                )
            }
        elif pane == 'ssl':
            pane_payload = queries.ssl_overview(
                since=since_ts,
                search=search,
                limit=limit,
            )
        elif pane == 'security':
            pane_payload = queries.security_overview(
                since=since_ts,
                search=search,
                limit=limit,
            )
        elif pane == 'performance':
            pane_payload = queries.performance_overview(since=since_ts, limit=limit)
        else:
            pane_payload = {
                'rows': queries.top_destinations(
                    since=since_ts,
                    search=search,
                    limit=limit,
                    sort=sort,
                )
            }
    except Exception:
        log_exception_throttled(
            app.logger,
            f'web.app.observability.pane.{pane}',
            interval_seconds=30.0,
            message='Failed to load observability pane; rendering empty state',
        )
        pane_payload = _empty_observability_payload(pane, summary=summary)

    return render_template(
        'observability.html',
        pane=pane,
        sort=sort,
        limit=limit,
        window=window_i,
        window_label=_window_label(window_i),
        search=search,
        resolve_hostnames=resolve_hostnames,
        summary=summary,
        pane_payload=pane_payload,
    )


@app.route('/observability/export', methods=['GET'])
def observability_export():
    queries = get_observability_queries()
    pane = _observability_pane_from_request()
    sort = _observability_sort_from_request(pane)
    limit = _query_int_arg('limit', default=200, minimum=10, maximum=1000)
    window_i = _query_int_arg('window', default=OBSERVABILITY_DEFAULT_WINDOW, minimum=300, maximum=7 * 24 * 3600)
    since_ts = int(time.time()) - window_i
    search = (request.args.get('q') or '').strip().lower()
    resolve_hostnames = _observability_resolve_hostnames_from_request()
    try:
        if pane == 'overview':
            overview = queries.overview_bundle(
                since=since_ts,
                search=search,
                limit=min(limit, 10),
                resolve_hostnames=resolve_hostnames,
            )
            summary = overview['summary']
            headers = ['metric', 'value']
            data_rows = (
                [metric, summary.get(metric, 0)]
                for metric in (
                    'request_records',
                    'cache_hits',
                    'cache_misses',
                    'cache_hit_pct',
                    'clients',
                    'destinations',
                    'transactions',
                    'icap_events',
                    'av_icap_events',
                    'adblock_icap_events',
                )
            )
            return _csv_response(headers, data_rows)

        if pane == 'clients':
            rows = queries.top_clients(
                since=since_ts,
                search=search,
                limit=limit,
                sort=sort,
                resolve_hostnames=resolve_hostnames,
            )
            headers = ['client_ip', 'hostname', 'requests', 'percent_of_total', 'destinations', 'transactions', 'cache_hit_pct', 'av_icap_events', 'adblock_icap_events', 'last_seen']
            data_rows = (
                [
                    row.get('ip', ''),
                    row.get('hostname', ''),
                    row.get('requests', 0),
                    row.get('pct', 0.0),
                    row.get('destinations', 0),
                    row.get('transactions', 0),
                    row.get('cache_pct', 0.0),
                    row.get('av_icap_events', 0),
                    row.get('adblock_icap_events', 0),
                    row.get('last_seen', 0),
                ]
                for row in rows
            )
            return _csv_response(headers, data_rows)

        if pane == 'cache':
            rows = queries.top_cache_reasons(
                since=since_ts,
                search=search,
                limit=limit,
                sort=sort,
            )
            headers = ['reason', 'requests', 'percent_of_misses', 'domains', 'clients', 'last_seen']
            data_rows = (
                [
                    row.get('reason', ''),
                    row.get('requests', 0),
                    row.get('pct', 0.0),
                    row.get('domains', 0),
                    row.get('clients', 0),
                    row.get('last_seen', 0),
                ]
                for row in rows
            )
            return _csv_response(headers, data_rows)

        if pane == 'ssl':
            payload = queries.ssl_overview(since=since_ts, search=search, limit=limit)
            rows = payload['rows']
            headers = ['domain', 'category', 'category_label', 'reason', 'count', 'first_seen', 'last_seen']
            data_rows = (
                [
                    row.get('domain', ''),
                    row.get('category', ''),
                    row.get('category_label', ''),
                    row.get('reason', ''),
                    row.get('count', 0),
                    row.get('first_seen', 0),
                    row.get('last_seen', 0),
                ]
                for row in rows
            )
            return _csv_response(headers, data_rows)

        if pane == 'security':
            payload = queries.security_overview(since=since_ts, search=search, limit=limit)
            headers = ['source', 'timestamp', 'client', 'target', 'detail', 'status']
            rows = []
            for row in payload.get('av_rows', []):
                rows.append([
                    'av',
                    row.get('ts', 0),
                    row.get('client_ip', ''),
                    row.get('target_display', ''),
                    row.get('adapt_summary', ''),
                    row.get('av_status_label', ''),
                ])
            for row in payload.get('adblock_rows', []):
                rows.append([
                    'adblock',
                    row.get('ts', 0),
                    row.get('src_ip', ''),
                    row.get('url', ''),
                    f"HTTP {row.get('http_status', 0)}",
                    row.get('result', ''),
                ])
            for row in payload.get('webfilter_rows', []):
                rows.append([
                    'webfilter',
                    row.get('ts', 0),
                    row.get('src_ip', ''),
                    row.get('url', ''),
                    row.get('category', ''),
                    row.get('result', ''),
                ])
            return _csv_response(headers, rows)

        if pane == 'performance':
            payload = queries.performance_overview(since=since_ts, limit=limit)
            headers = ['type', 'timestamp', 'subject', 'metric', 'detail']
            rows = []
            for row in payload.get('slow_requests', []):
                rows.append([
                    'request',
                    row.get('ts', 0),
                    row.get('target_display', ''),
                    row.get('duration_ms', 0),
                    row.get('result_summary', ''),
                ])
            for row in payload.get('slow_icap_events', []):
                rows.append([
                    'icap',
                    row.get('ts', 0),
                    row.get('target_display', ''),
                    row.get('icap_time_ms', 0),
                    row.get('adapt_summary', ''),
                ])
            return _csv_response(headers, rows)

        rows = queries.top_destinations(
            since=since_ts,
            search=search,
            limit=limit,
            sort=sort,
        )
        headers = ['domain', 'requests', 'percent_of_total', 'clients', 'transactions', 'cache_hit_pct', 'av_icap_events', 'adblock_icap_events', 'last_seen']
        data_rows = (
            [
                row.get('domain', ''),
                row.get('requests', 0),
                row.get('pct', 0.0),
                row.get('clients', 0),
                row.get('transactions', 0),
                row.get('cache_pct', 0.0),
                row.get('av_icap_events', 0),
                row.get('adblock_icap_events', 0),
                row.get('last_seen', 0),
            ]
            for row in rows
        )
        return _csv_response(headers, data_rows)
    except Exception:
        log_exception_throttled(
            app.logger,
            f'web.app.observability.export.{pane}',
            interval_seconds=30.0,
            message='Failed to export observability pane; returning empty CSV',
        )
        return _empty_observability_export_response(pane)


@app.route('/ssl-errors', methods=['GET'])
def ssl_errors():
    return _redirect_to(
        'observability',
        pane='ssl',
        window=_query_int_arg('window', default=OBSERVABILITY_DEFAULT_WINDOW, minimum=300, maximum=90 * 24 * 3600),
        limit=_query_int_arg('limit', default=50, minimum=10, maximum=200),
        q=((request.args.get('q') or '').strip().lower() or None),
    )


@app.route('/ssl-errors/exclude', methods=['POST'])
def ssl_errors_exclude():
    domain = _extract_domain(request.form.get('domain'))
    if domain:
        try:
            get_exclusions_store().add_domain(domain)
        except Exception:
            pass
        return _redirect_after_pac_refresh('observability', pane='ssl', q=domain)
    return _redirect_to('observability', pane='ssl', q=domain)


@app.route('/ssl-errors/export', methods=['GET'])
def ssl_errors_export():
    return _redirect_to(
        'observability_export',
        pane='ssl',
        window=_query_int_arg('window', default=OBSERVABILITY_DEFAULT_WINDOW, minimum=300, maximum=90 * 24 * 3600),
        limit=_query_int_arg('limit', default=1000, minimum=10, maximum=1000),
        q=((request.args.get('q') or '').strip().lower() or None),
    )


@app.route('/adblock', methods=['GET', 'POST'])
def adblock():
    store = get_adblock_store()
    _best_effort_init_store(store, key='adblock', description='adblock')

    if request.method == 'POST':
        return _handle_adblock_post(store)

    statuses = store.list_statuses()
    try:
        settings = store.get_settings()
    except Exception:
        settings = {"enabled": True, "cache_ttl": 3600, "cache_max": 200000}
    try:
        stats = store.stats()
    except Exception:
        stats = {"total": 0, "last_24h": 0, "by_list": {}, "by_list_24h": {}}
    try:
        cache_stats = store.cache_stats()
    except Exception:
        cache_stats = {"hits": 0, "misses": 0, "evictions": 0, "current_size": 0, "last_flush": 0, "last_flush_req": 0}

    interval = store.get_update_interval_seconds()
    window_i = _query_int_arg('window', default=3600, minimum=300, maximum=7 * 24 * 3600)
    since_ts = int(time.time()) - window_i
    now_ts = int(time.time())
    status_rows = []
    for st in statuses:
        next_refresh = now_ts if not st.enabled else (st.last_success + interval if st.last_success > 0 else now_ts)
        last_failure_ts = st.last_attempt if st.last_error else 0
        status_rows.append(
            {
                "key": st.key,
                "url": st.url,
                "enabled": st.enabled,
                "rules": st.rules,
                "bytes": st.bytes,
                "last_success": st.last_success,
                "last_attempt": st.last_attempt,
                "last_error": st.last_error,
                "last_failure_ts": last_failure_ts,
                "next_refresh": next_refresh,
            }
        )

    try:
        adblock_icap_summary = get_diagnostic_store().icap_summary(since=since_ts, service='adblock')
    except Exception:
        adblock_icap_summary = {'events': 0, 'avg_icap_time_ms': 0, 'max_icap_time_ms': 0}

    return render_template(
        'adblock.html',
        statuses=status_rows,
        stats=stats,
        settings=settings,
        cache_stats=cache_stats,
        cache_max=settings.get('cache_max'),
        cache_ttl=settings.get('cache_ttl'),
        update_interval_seconds=interval,
        cache_flushed=(request.args.get('cache_flushed') == '1'),
        refresh_requested=(request.args.get('refresh_requested') == '1'),
        refresh_no_lists=(request.args.get('refresh_no_lists') == '1'),
        window=window_i,
        window_label=_window_label(window_i),
        adblock_icap_summary=adblock_icap_summary,
    )


@app.route('/webfilter', methods=['GET', 'POST'])
def webfilter():
    store = get_webfilter_store()
    _best_effort_init_store(store, key='webfilter', description='web filter')

    tab = _normalize_choice(request.args.get('tab') or request.form.get('tab') or 'categories', ('categories', 'whitelist'), 'categories')

    if request.method == 'POST':
        return _handle_webfilter_post(store, tab)

    settings = store.get_settings()
    available = store.list_available_categories()
    selected = set(settings.blocked_categories)
    whitelist_rows = store.list_whitelist()
    window_i = _query_int_arg('window', default=3600, minimum=300, maximum=7 * 24 * 3600)
    return render_template(
        'webfilter.html',
        tab=tab,
        settings=settings,
        available_categories=available,
        selected=selected,
        whitelist_rows=whitelist_rows,
        window=window_i,
        window_label=_window_label(window_i),
        err_source=(request.args.get('err_source') == '1'),
        wl_ok=(request.args.get('wl_ok') == '1'),
        wl_err=(request.args.get('wl_err') or ''),
    )


@app.route('/webfilter/test', methods=['POST'])
def webfilter_test_domain():
    store = get_webfilter_store()
    _best_effort_init_store(store, key='webfilter_test', description='web filter')

    payload = request.get_json(silent=True) or {}
    domain = (payload.get('domain') or request.form.get('domain') or '').strip()
    try:
        res = store.test_domain(domain)
        return jsonify(res), 200
    except Exception as e:
        return jsonify({"ok": False, "verdict": "error", "reason": public_error_message(e)}), 200


@app.route('/sslfilter', methods=['GET', 'POST'])
def sslfilter():
    store = get_sslfilter_store()
    _best_effort_init_store(store, key='sslfilter', description='SSL filter')

    if request.method == 'POST':
        return _handle_sslfilter_post(store)

    rows = store.list_nobump()
    return render_template(
        'sslfilter.html',
        rows=rows,
        ok=(request.args.get('ok') == '1'),
        err=(request.args.get('err') or ''),
    )


def _check_icap_adblock() -> Dict[str, Any]:
    return _app_runtime_services().check_icap_adblock()


def _check_icap_av() -> Dict[str, Any]:
    return _app_runtime_services().check_icap_av()


def _clamav_remote_health(proxy_id: str) -> Dict[str, Any]:
    try:
        return get_proxy_client().get_health(proxy_id, timeout_seconds=10.0)
    except ProxyClientError as exc:
        proxy = get_proxy_registry().get_proxy(proxy_id)
        return build_unavailable_runtime_health(str(exc), proxy_status=proxy.status if proxy else 'offline')


def _send_sample_av_icap() -> Dict[str, Any]:
    return _app_runtime_services().send_sample_av_icap()


def _check_clamd() -> Dict[str, Any]:
    return _app_runtime_services().check_clamd()


def _test_eicar() -> Dict[str, Any]:
    return _app_runtime_services().test_eicar()


@app.route('/clamav', methods=['GET'])
def clamav():
    cfg = _current_managed_config()
    clamav_enabled = _is_clamav_enabled(cfg)
    window_i = _query_int_arg('window', default=3600, minimum=300, maximum=7 * 24 * 3600)
    since_ts = int(time.time()) - window_i
    proxy_id = get_proxy_id()
    health_payload = _clamav_remote_health(proxy_id)
    clamav_view = build_remote_clamav_view(health_payload)
    health = clamav_view['health']
    clamd_health = clamav_view['clamd_health']
    av_icap_health = clamav_view['av_icap_health']
    health_source = clamav_view['health_source']

    try:
        clamav_icap_summary = get_diagnostic_store().icap_summary(since=since_ts, service='av')
    except Exception:
        clamav_icap_summary = {'events': 0, 'avg_icap_time_ms': 0, 'max_icap_time_ms': 0}

    return render_template(
        'clamav.html',
        health=health,
        clamd_health=clamd_health,
        av_icap_health=av_icap_health,
        health_source=health_source,
        clamav_enabled=clamav_enabled,
        clamav_icap_summary=clamav_icap_summary,
        window=window_i,
        window_label=_window_label(window_i),
        eicar_result=request.args.get('eicar'),
        eicar_detail=request.args.get('eicar_detail'),
        icap_result=request.args.get('icap_sample'),
        icap_detail=request.args.get('icap_detail'),
    )


@app.route('/clamav/test-eicar', methods=['POST'])
def clamav_test_eicar():
    try:
        res = get_proxy_client().test_clamav_eicar(get_proxy_id())
    except ProxyClientError as exc:
        res = {'ok': False, 'detail': str(exc)}
    return _redirect_to(
        'clamav',
        eicar='ok' if res.get('ok') else 'fail',
        eicar_detail=(res.get('detail') or '')[:300],
    )


@app.route('/clamav/test-icap', methods=['POST'])
def clamav_test_icap():
    try:
        res = get_proxy_client().test_clamav_icap(get_proxy_id())
    except ProxyClientError as exc:
        res = {'ok': False, 'detail': str(exc)}
    return _redirect_to(
        'clamav',
        icap_sample='ok' if res.get('ok') else 'fail',
        icap_detail=(res.get('detail') or '')[:300],
    )


_CLAMAV_ALLOW_RE = re.compile(r"^(\s*)(#\s*)?(adaptation_access\s+av_resp_set\s+allow\b.*)$", re.I | re.M)
_CLAMAV_DENY_RE = re.compile(r"^\s*(#\s*)?adaptation_access\s+av_resp_set\s+deny\s+all\s*$", re.I | re.M)


def _is_clamav_enabled(cfg_text: str) -> bool:
    m = _CLAMAV_ALLOW_RE.search(cfg_text or "")
    if not m:
        return False
    comment_prefix = (m.group(2) or "").strip()
    return comment_prefix == ""


def _set_clamav_enabled(cfg_text: str, enabled: bool) -> str:
    text = cfg_text or ""

    def repl(m: re.Match) -> str:
        indent = m.group(1) or ""
        rule = m.group(3) or ""
        if enabled:
            return indent + rule
        return indent + "# " + rule

    if _CLAMAV_ALLOW_RE.search(text):
        return _CLAMAV_ALLOW_RE.sub(repl, text, count=1)

    if enabled:
        allow_line = "adaptation_access av_resp_set allow icap_av_scanable"
        deny_match = _CLAMAV_DENY_RE.search(text)
        if deny_match:
            insert_at = deny_match.start()
            return text[:insert_at] + allow_line + "\n" + text[insert_at:]
        return text.rstrip() + "\n" + allow_line + "\n"

    return text


@app.route('/clamav/toggle', methods=['POST'])
def clamav_toggle():
    action = _form_action(lower=True)
    cfg = _current_managed_config()
    currently_enabled = _is_clamav_enabled(cfg)

    if action == 'enable':
        desired = True
    elif action == 'disable':
        desired = False
    else:
        desired = (not currently_enabled)

    new_cfg = _set_clamav_enabled(cfg, desired)
    ok, _details = _publish_config_for_current_mode(new_cfg, source_kind='clamav')
    if ok:
        return _redirect_to('clamav')
    return _redirect_to('clamav', error='1')



@app.route('/squid/config', methods=['GET', 'POST'])
def squid_config():
    config_sections = get_config_ui_sections()
    safe_tabs = tuple(section.key for section in config_sections)
    tab = _normalize_choice(
        request.args.get('tab') or request.form.get('tab') or 'config',
        ('config',) + safe_tabs,
        'config',
    )

    validation = None
    posted_config = None
    if request.method == 'POST':
        action = _form_action(default='apply', lower=True)
        config_text = request.form.get('config_text', '')
        posted_config = config_text
        if action == 'validate':
            ok, details = _validate_config_for_current_mode(config_text)
            validation = {'ok': ok, 'detail': (details or '').strip()}
            _record_audit_event('config_validate_manual', ok=ok, detail=(details or ''), config_text=config_text)
        else:
            ok, details = _publish_config_for_current_mode(config_text, source_kind='manual')
            _record_audit_event('config_apply_manual', ok=ok, detail=(details or ''), config_text=config_text)
            if ok:
                return _redirect_config(tab, ok=True)
            return _redirect_config(tab, error=True)
    current_config = _current_managed_config()
    tunables = squid_controller.get_tunable_options(current_config)
    managed_options = build_template_options(tunables, max_workers=_max_workers())
    overrides = squid_controller.get_cache_override_options(current_config)
    caching_lines = squid_controller.get_caching_lines(current_config)
    timeout_lines = squid_controller.get_timeout_lines(current_config)
    logging_lines = squid_controller.get_logging_lines(current_config)
    network_lines = squid_controller.get_network_lines(current_config)
    dns_lines = squid_controller.get_dns_lines(current_config)
    ssl_lines = squid_controller.get_ssl_lines(current_config)
    icap_lines = squid_controller.get_icap_lines(current_config)
    privacy_lines = squid_controller.get_privacy_lines(current_config)
    limits_lines = squid_controller.get_limits_lines(current_config)
    performance_lines = squid_controller.get_performance_lines(current_config)
    http_lines = squid_controller.get_http_lines(current_config)
    line_map = {
        'caching': caching_lines,
        'timeouts': timeout_lines,
        'logging': logging_lines,
        'network': network_lines,
        'dns': dns_lines,
        'ssl': ssl_lines,
        'icap': icap_lines,
        'privacy': privacy_lines,
        'limits': limits_lines,
        'performance': performance_lines,
        'http': http_lines,
    }
    section_map = {section.key: section for section in config_sections}
    active_section = section_map.get(tab)
    exclusions = get_exclusions_store().list_all()
    exclusions_count = (
        len(getattr(exclusions, 'domains', []) or [])
        + len(getattr(exclusions, 'src_nets', []) or [])
        + (1 if bool(getattr(exclusions, 'exclude_private_nets', False)) else 0)
    )
    summary = {
        'workers': tunables.get('workers') if tunables else None,
        'cache_dir_size_mb': tunables.get('cache_dir_size_mb') if tunables else None,
        'cache_mem_mb': tunables.get('cache_mem_mb') if tunables else None,
        'overrides': overrides or {},
        'overrides_on': any(overrides.values()) if overrides else False,
        'exclusions_count': exclusions_count,
    }
    config_text = posted_config if posted_config is not None else current_config
    subtab = _normalize_choice(request.args.get('subtab') or 'safe', ('safe', 'overrides'), 'safe')
    return render_template(
        'squid_config.html',
        tab=tab,
        config_text=config_text,
        tunables=tunables,
        managed_options=managed_options,
        overrides=overrides,
        subtab=subtab,
        summary=summary,
        validation=validation,
        exclusions=exclusions,
        config_sections=config_sections,
        config_field_map=get_config_ui_field_map(),
        active_section=active_section,
        line_map=line_map,
        caching_lines=caching_lines,
        timeout_lines=timeout_lines,
        logging_lines=logging_lines,
        network_lines=network_lines,
        dns_lines=dns_lines,
        ssl_lines=ssl_lines,
        icap_lines=icap_lines,
        privacy_lines=privacy_lines,
        limits_lines=limits_lines,
        performance_lines=performance_lines,
        http_lines=http_lines,
    )


@app.route('/squid/config/apply-safe', methods=['POST'])
def apply_safe_caching():
    form_kind = normalize_safe_form_kind(request.form.get('form_kind'))
    try:
        current = _current_managed_config()
        tunables = squid_controller.get_tunable_options(current)
    except Exception:
        tunables = {}

    options = build_template_options_from_form(
        tunables,
        request.form,
        form_kind=form_kind,
        max_workers=_max_workers(),
    )

    try:
        ok, _details = _publish_template_config(
            options,
            source_kind='template',
            audit_kind='config_apply_template',
        )
    except Exception:
        return _redirect_config('caching', error=True)

    return _redirect_config(form_kind, ok=ok, error=not ok)


@app.route('/squid/config/apply-overrides', methods=['POST'])
def apply_cache_overrides():
    # Apply cache override toggles on top of the current tunables/exclusions.
    try:
        current = _current_managed_config()
        tunables = squid_controller.get_tunable_options(current)

        options = _options_from_tunables(tunables)
        overrides = parse_cache_override_form(request.form)
        ok, _details = _publish_template_config(
            options,
            source_kind='overrides',
            audit_kind='config_apply_overrides',
            overrides=overrides,
        )
    except Exception:
        return _redirect_config('caching', subtab='overrides', error=True)

    return _redirect_config('caching', subtab='overrides', ok=ok, error=not ok)


@app.route('/exclusions', methods=['GET', 'POST'])
def exclusions():
    store = get_exclusions_store()

    if request.method == 'POST':
        return _handle_exclusions_post(store)

    ex = store.list_all()
    pac_target, pac_url, pac_warning = _selected_proxy_pac_context()
    return render_template('exclusions.html', ex=ex, pac_target=pac_target, pac_url=pac_url, pac_warning=pac_warning)


@app.route('/pac', methods=['GET', 'POST'])
def pac_builder():
    store = get_pac_profiles_store()

    if request.method == 'POST':
        return _handle_pac_builder_post(store)

    profiles = []
    try:
        profiles = store.list_profiles()
    except Exception:
        profiles = []

    pac_target, pac_url, pac_warning = _selected_proxy_pac_context()
    return render_template('pac.html', profiles=profiles, pac_url=pac_url, pac_warning=pac_warning, pac_target=pac_target)

@app.route('/api/timeseries', methods=['GET'])
def api_timeseries():
    res = (request.args.get('resolution') or '1s').strip()
    window_i = _query_int_arg('window', default=60, minimum=10, maximum=365 * 24 * 3600)
    limit_i = _query_int_arg('limit', default=500)

    since = int(time.time()) - window_i
    points = get_timeseries_store().query(resolution=res, since=since, limit=limit_i)
    return jsonify({"resolution": res, "since": since, "points": points})


@app.route('/reload', methods=['POST'])
def reload_squid():
    ok, detail = _trigger_proxy_sync(force=True)
    _record_audit_event('proxy_sync', ok=ok, detail=detail)
    return redirect(_endpoint_url('index') + '#status')


@app.route('/cache/clear', methods=['POST'])
def clear_caches():
    # Clear Squid disk cache (best-effort) and restart Squid.
    ok, detail = _trigger_proxy_cache_clear()
    _record_audit_event('cache_clear', ok=ok, detail=detail)
    return redirect(_endpoint_url('index') + '#status')

@app.route('/certs', methods=['GET'])
def certs():
    bundle_store = get_certificate_bundles()
    bundle = bundle_store.get_active_bundle()
    certificate = 'ca.crt' if bundle is not None else None
    proxy_cert_statuses = []
    for proxy in get_proxy_registry().list_proxies():
        latest_apply = bundle_store.latest_apply(proxy.proxy_id)
        proxy_cert_statuses.append(
            {
                'proxy_id': proxy.proxy_id,
                'display_name': proxy.display_name or proxy.proxy_id,
                'ok': latest_apply.ok if latest_apply is not None else None,
                'detail': latest_apply.detail if latest_apply is not None else '',
                'applied_ts': latest_apply.applied_ts if latest_apply is not None else 0,
            }
        )
    message = request.args.get('msg')
    message_ok = request.args.get('ok') == '1'
    return render_template(
        'certs.html',
        certificate=certificate,
        bundle=bundle,
        proxy_cert_statuses=proxy_cert_statuses,
        message=message,
        message_ok=message_ok,
    )


@app.route('/certs/generate', methods=['POST'])
def generate_certificate():
    try:
        bundle = generate_self_signed_ca_bundle()
        ok, detail = _publish_certificate_bundle_remote(bundle)
        _record_audit_event('ca_ensure', ok=ok, detail=detail)
        return _redirect_with_message('certs', ok=ok, msg=detail)
    except Exception as e:
        app.logger.exception("CA generation failed")
        message = public_error_message(e)
        _record_audit_event('ca_ensure', ok=False, detail=message)
        return _redirect_with_message('certs', ok=False, msg=message)


@app.route('/certs/upload', methods=['POST'])
def upload_certificate_pfx():
    # Upload a PKCS#12 bundle containing cert + private key and install it as Squid's CA.
    pfx_file = request.files.get('pfx')
    password = request.form.get('pfx_password', '')

    if not pfx_file or not getattr(pfx_file, 'filename', ''):
        return _redirect_with_message('certs', ok=False, msg='No PFX file selected.')

    filename = (pfx_file.filename or '').lower()
    _, ext = os.path.splitext(filename)
    if ext not in ['.pfx', '.p12']:
        return _redirect_with_message('certs', ok=False, msg='Unsupported file type. Please upload a .pfx or .p12.')

    # Basic guard against accidental huge uploads.
    if request.content_length is not None and request.content_length > (10 * 1024 * 1024):
        return _redirect_with_message('certs', ok=False, msg='Upload too large (max 10MB).')

    # Read with a hard cap even if Content-Length is missing or incorrect.
    max_pfx_bytes = 10 * 1024 * 1024
    buf = bytearray()
    try:
        stream = getattr(pfx_file, 'stream', None) or pfx_file
        while True:
            chunk = stream.read(512 * 1024)
            if not chunk:
                break
            buf.extend(chunk)
            if len(buf) > max_pfx_bytes:
                return _redirect_with_message('certs', ok=False, msg='Upload too large (max 10MB).')
    except Exception:
        return _redirect_with_message('certs', ok=False, msg='Failed to read upload.')

    pfx_bytes = bytes(buf)
    try:
        if not _uses_remote_proxy_runtime():
            installed = install_pfx_as_ca(
                (os.environ.get('CERTS_DIR') or '/etc/squid/ssl/certs').strip() or '/etc/squid/ssl/certs',
                pfx_bytes,
                password=password,
            )
            installed_bundle = getattr(installed, 'bundle', None)
            ok = bool(getattr(installed, 'ok', False))
            detail = str(getattr(installed, 'message', '') or '')
            if ok and installed_bundle is not None:
                ok, detail = _record_local_certificate_apply(
                    installed_bundle,
                    original_filename=(pfx_file.filename or '').strip(),
                    already_materialized=True,
                )
            elif ok:
                reload_result = squid_controller.reload_squid()
                if isinstance(reload_result, tuple) and len(reload_result) == 2:
                    stdout, stderr = reload_result
                    reload_detail = ((_decode_bytes(stdout) + '\n' + _decode_bytes(stderr)).strip())
                    ok = not bool(stderr)
                    detail = reload_detail or detail
        else:
            parsed = parse_pfx_bundle(pfx_bytes, password=password)
            ok = bool(parsed.ok and parsed.bundle is not None)
            detail = parsed.message
            if ok and parsed.bundle is not None:
                ok, detail = _publish_certificate_bundle_remote(
                    parsed.bundle,
                    original_filename=(pfx_file.filename or '').strip(),
                )
    except Exception as exc:
        app.logger.exception('PFX upload failed')
        ok = False
        detail = public_error_message(exc, default='Failed to process uploaded PFX bundle.')

    _record_audit_event('ca_upload_pfx', ok=ok, detail=detail)

    return _redirect_with_message('certs', ok=ok, msg=detail)


@app.route('/certs/download/<path:filename>', methods=['GET'])
def download_certificate(filename: str):
    # Only allow downloading the public CA cert
    if filename != 'ca.crt':
        abort(404)
    bundle = get_certificate_bundles().get_active_bundle()
    if bundle is None:
        abort(404)
    response = app.response_class(bundle.fullchain_pem, mimetype='application/x-pem-file')
    response.headers['Content-Disposition'] = 'attachment; filename=squid-proxy-ca.crt'
    return response


@app.route('/administration', methods=['GET', 'POST'])
def administration():
    store = _auth_store
    current_user = (session.get('user') or '').strip()

    if request.method == 'POST':
        return _handle_administration_post(store, current_user)

    users = []
    try:
        users = store.list_users()
    except Exception:
        users = []

    message = request.args.get('msg')
    message_ok = request.args.get('ok') == '1'
    return render_template(
        'administration.html',
        users=users,
        current_user=current_user,
        message=message,
        message_ok=message_ok,
    )

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)