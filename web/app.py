from flask import Flask, g, render_template, request, redirect, url_for, jsonify, send_file, abort, session
from services.squidctl import SquidController
from services.cert_manager import CertManager, generate_self_signed_ca_bundle, install_pfx_as_ca, parse_pfx_bundle
from services.certificate_bundles import get_certificate_bundles
from services.auth_store import get_auth_store
from services.config_revisions import get_config_revisions
from datetime import UTC, datetime, timedelta
import time
import os
import ipaddress
import subprocess
import shutil
from services.stats import get_stats
from services.live_stats import get_store
from services.exclusions_store import get_exclusions_store
from services.audit_store import get_audit_store
from services.timeseries_store import get_timeseries_store
from services.ssl_errors_store import get_ssl_errors_store
from services.socks_store import get_socks_store
from services.adblock_store import get_adblock_store
from services.adblock_artifacts import apply_active_artifact_locally, get_adblock_artifacts
from services.webfilter_store import get_webfilter_store
from services.sslfilter_store import get_sslfilter_store
from services.pac_profiles_store import get_pac_profiles_store
from services.pac_renderer import build_public_pac_url, build_proxy_pac_state, materialize_proxy_pac_state, render_proxy_pac_for_request
from services.proxy_client import ProxyClientError, get_proxy_client
from services.proxy_context import get_default_proxy_id, get_proxy_id, normalize_proxy_id, reset_proxy_id, set_proxy_id
from services.proxy_health import build_remote_clamav_view, build_unavailable_runtime_health, check_adblock_icap_health, check_av_icap_health, check_clamd_health, check_dante_health, send_sample_av_icap as _shared_send_sample_av_icap, test_eicar as _shared_test_eicar
from services.proxy_registry import get_proxy_registry
from services.housekeeping import start_housekeeping
from services.background_guard import acquire_background_lock
from services.errors import public_error_message
from services.health_checks import build_clamav_health as _shared_build_clamav_health
from services.logutil import log_exception_throttled
from services.squid_config_forms import build_template_options, build_template_options_from_form, normalize_safe_form_kind, parse_cache_override_form
from services.ui_support import append_query_to_local_return as _append_query_to_local_return, bulk_lines as _bulk_lines, csv_safe as _csv_safe, present_ssl_error_rows as _present_ssl_error_rows, present_ssl_top_domains as _present_ssl_top_domains, safe_local_return_url as _safe_local_return_url, window_label as _window_label

import re
import secrets
import csv
import io
from urllib.parse import urlparse, urlsplit
from typing import Any, Dict, Iterable, Sequence
from markupsafe import Markup

app = Flask(__name__)
squid_controller = SquidController()
cert_manager = CertManager()


def _control_mode() -> str:
    return (os.environ.get('PROXY_CONTROL_MODE') or 'local').strip().lower()


def _is_remote_control_mode() -> bool:
    return _control_mode() == 'remote'


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
    if not _is_remote_control_mode():
        return False
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


def _redirect_index_status():
    return redirect(_endpoint_url('index') + '#status')


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
    domain = _normalized_domain(value)
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


def _best_effort_apply_adblock_flush() -> None:
    try:
        if _is_remote_control_mode():
            _trigger_proxy_sync()
        else:
            _apply_local_adblock_runtime(force=True, clear_cache=True)
    except Exception:
        pass


def _pac_profile_form_data(*, profile_id: int | None) -> Dict[str, Any]:
    return {
        'profile_id': profile_id,
        'name': request.form.get('name') or '',
        'client_cidr': request.form.get('client_cidr') or '',
        'socks_enabled': (request.form.get('socks_enabled') == 'on'),
        'socks_host': request.form.get('socks_host') or '',
        'socks_port': request.form.get('socks_port') or '',
        'direct_domains_text': request.form.get('direct_domains') or '',
        'direct_dst_nets_text': request.form.get('direct_dst_nets') or '',
    }


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

    # Allow PAC file retrieval by clients without requiring UI login.
    if request.path in ('/proxy.pac', '/wpad.dat'):
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
    if not _is_remote_control_mode():
        active = normalize_proxy_id(preferred)
        session['active_proxy_id'] = active
        return active

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
    if not _is_remote_control_mode():
        return {
            'remote_control_mode': False,
            'active_proxy_id': active_proxy_id,
            'active_proxy': None,
            'fleet_proxies': [],
        }

    registry = get_proxy_registry()
    proxies = registry.list_proxies()
    if not proxies:
        proxies = [registry.ensure_default_proxy()]
    active_proxy = registry.get_proxy(active_proxy_id) or proxies[0]
    return {
        'remote_control_mode': True,
        'active_proxy_id': active_proxy.proxy_id,
        'active_proxy': active_proxy,
        'fleet_proxies': proxies,
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
            return redirect(next_url or _endpoint_url('index'))
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
    if not _is_remote_control_mode():
        # Start background ingestion of Squid access.log into the database (best-effort).
        try:
            get_store().start_background()
        except Exception:
            pass

        # Start 1s time-series sampler + rollups (best-effort).
        try:
            get_timeseries_store().start_background(get_stats)
        except Exception:
            pass

        # Start background ingestion of Squid cache.log SSL/TLS errors (best-effort).
        try:
            get_ssl_errors_store().start_background()
        except Exception:
            pass

        # Start background ingestion of Dante (sockd) logs (best-effort).
        try:
            get_socks_store().start_background()
        except Exception:
            pass

        # Start background ingestion of c-icap adblock (REQMOD) blocks (best-effort).
        try:
            get_adblock_store().start_blocklog_background()
        except Exception:
            pass

        # Pre-render PAC assets for the local PAC listener.
        try:
            state = build_proxy_pac_state(get_proxy_id())
            target_dir = (os.environ.get('PAC_RENDER_DIR') or '/var/lib/squid-flask-proxy/pac').strip() or '/var/lib/squid-flask-proxy/pac'
            materialize_proxy_pac_state(target_dir, state=state)
        except Exception:
            pass

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
        "fmt_ts": fmt_ts,
    }


def _check_dante() -> Dict[str, Any]:
    return check_dante_health(timeout=0.6, error_formatter=public_error_message)


def _current_managed_config() -> str:
    """Return the effective config for the active proxy.

    Remote mode treats config revisions as the source of truth. Local mode keeps a
    live Squid fallback for dev/test scenarios where the admin UI still manages a
    colocated proxy process directly.
    """
    if _is_remote_control_mode():
        revisions = get_config_revisions()
        current = revisions.get_active_config_text(get_proxy_id())
        if current:
            return current
        fallback = squid_controller.get_current_config() or ""
        if fallback.strip():
            revisions.ensure_active_revision(get_proxy_id(), fallback, created_by='system', source_kind='bootstrap')
        return fallback
    return squid_controller.get_current_config() or ""


def _validate_config_for_current_mode(config_text: str) -> tuple[bool, str]:
    """Validate locally when possible, or defer to proxy sync in split mode."""
    if not _is_remote_control_mode():
        return squid_controller.validate_config_text(config_text)
    if shutil.which('squid') is None:
        return True, 'Validation is deferred to the selected proxy during sync in split mode.'
    return squid_controller.validate_config_text(config_text)


def _publish_config_for_current_mode(config_text: str, *, source_kind: str) -> tuple[bool, str]:
    if not _is_remote_control_mode():
        return squid_controller.apply_config_text(config_text)

    proxy_id = get_proxy_id()
    created_by = str(session.get('user') or '')
    revision = get_config_revisions().create_revision(
        proxy_id,
        config_text,
        created_by=created_by,
        source_kind=source_kind,
        activate=True,
    )
    try:
        result = get_proxy_client().sync_proxy(proxy_id, force=True)
        ok = bool(result.get('ok', False))
        detail = str(result.get('detail') or f'Revision {revision.revision_id} queued for sync.')
        return ok, detail
    except ProxyClientError as exc:
        return False, f'Revision {revision.revision_id} saved, but immediate sync failed: {exc}'


def _trigger_proxy_sync(*, force: bool = False) -> tuple[bool, str]:
    """Apply or request config sync for the active proxy in local or remote mode."""
    if not _is_remote_control_mode():
        result = squid_controller.reload_squid()
        if isinstance(result, tuple) and len(result) == 2:
            stdout, stderr = result
        else:
            stdout, stderr = b'', b''
        detail = (stdout or b'').decode('utf-8', errors='replace') + (stderr or b'').decode('utf-8', errors='replace')
        return (not bool(stderr)), detail.strip() or 'Squid reloaded.'

    try:
        result = get_proxy_client().sync_proxy(get_proxy_id(), force=force)
        return bool(result.get('ok', False)), str(result.get('detail') or 'Sync requested.')
    except ProxyClientError as exc:
        return False, str(exc)


def _trigger_proxy_cache_clear() -> tuple[bool, str]:
    """Clear cache for the active proxy in local or remote mode."""
    if not _is_remote_control_mode():
        result = squid_controller.clear_disk_cache()
        if isinstance(result, tuple) and len(result) == 2:
            return bool(result[0]), str(result[1] or '')
        return True, 'Cache clear requested.'

    try:
        result = get_proxy_client().clear_proxy_cache(get_proxy_id())
        return bool(result.get('ok', False)), str(result.get('detail') or 'Cache clear requested.')
    except ProxyClientError as exc:
        return False, str(exc)


def _nudge_registered_proxies(*, force: bool = False) -> tuple[int, int]:
    """Best-effort sync request across all registered proxies."""
    if not _is_remote_control_mode():
        ok, _detail = _trigger_proxy_sync(force=force)
        return (1 if ok else 0), (1 if ok else 0)

    proxies = get_proxy_registry().list_proxies()
    if not proxies:
        return 0, 0

    client = get_proxy_client()
    ok_count = 0
    for proxy in proxies:
        try:
            result = client.sync_proxy(proxy.proxy_id, force=force)
        except ProxyClientError:
            continue
        if bool(result.get('ok', False)):
            ok_count += 1
    return len(proxies), ok_count


def _publish_certificate_bundle_remote(bundle, *, original_filename: str = '') -> tuple[bool, str]:
    revision = get_certificate_bundles().create_revision(
        bundle,
        created_by=str(session.get('user') or ''),
        original_filename=(original_filename or '')[:255],
        activate=True,
    )
    attempted, ok_count = _nudge_registered_proxies(force=True)
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


def _materialize_local_pac_state() -> tuple[bool, str]:
    if app.testing:
        return True, 'PAC materialization skipped while testing.'
    try:
        state = build_proxy_pac_state(get_proxy_id())
        target_dir = (os.environ.get('PAC_RENDER_DIR') or '/var/lib/squid-flask-proxy/pac').strip() or '/var/lib/squid-flask-proxy/pac'
        materialize_proxy_pac_state(target_dir, state=state)
        return True, 'PAC state materialized locally.'
    except Exception as exc:
        return False, public_error_message(exc, default='Failed to materialize PAC state locally.')


def _apply_local_adblock_runtime(*, force: bool = False, clear_cache: bool = False) -> tuple[bool, str]:
    if app.testing:
        return True, 'Adblock runtime apply skipped while testing.'
    try:
        return apply_active_artifact_locally(force=force, clear_cache=clear_cache)
    except Exception as exc:
        return False, public_error_message(exc, default='Failed to apply adblock runtime locally.')


def _apply_local_policy_include(store: Any) -> None:
    store.apply_squid_include()
    subprocess.run(['squid', '-k', 'reconfigure'], capture_output=True, timeout=6)


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
        if _is_remote_control_mode():
            _trigger_proxy_sync(force=force)
        else:
            _apply_local_policy_include(store)
    except Exception:
        log_exception_throttled(
            app.logger,
            'web.app.refresh_managed_policy',
            interval_seconds=30.0,
            message='Failed to refresh managed policy state',
        )


def _best_effort_refresh_pac_runtime() -> None:
    try:
        if _is_remote_control_mode():
            _trigger_proxy_sync()
        else:
            _materialize_local_pac_state()
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
    if _is_remote_control_mode():
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
                    'dante': {'ok': False, 'detail': 'unavailable'},
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
        dante_health = services.get('dante') or {'ok': False, 'detail': 'n/a'}

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
            flask_status='OK',
            stats=stats,
            trends=trends,
            icap_health=icap_health,
            clamav_health=clamav_health,
            dante_health=dante_health,
            last_config=last_config,
        )

    stdout, stderr = squid_controller.get_status()
    proxy_detail = (stdout or b'').decode('utf-8', errors='replace') + (stderr or b'').decode('utf-8', errors='replace')
    proxy_ok = not stderr

    stats = get_stats()
    try:
        trends = get_timeseries_store().summary()
    except Exception:
        trends = {}

    icap_health = _check_icap_adblock()
    clamav_health = _check_clamd()
    dante_health = _check_dante()

    last_config = None
    try:
        row = get_audit_store().latest_config_apply()
        if row:
            last_config = {
                "ts": int(row[0]),
                "kind": row[1],
                "ok": bool(row[2]),
                "remote_addr": row[3],
                "user_agent": row[4],
                "detail": row[5],
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
        dante_health=dante_health,
        last_config=last_config,
    )


@app.route('/health', methods=['GET'])
def health():
    return jsonify({"ok": True}), 200


@app.route('/api/squid-config', methods=['GET'])
def api_squid_config():
    cfg = _current_managed_config()
    return app.response_class(cfg, mimetype='text/plain; charset=utf-8')


@app.route('/fleet', methods=['GET'])
def fleet():
    if not _is_remote_control_mode():
        return _redirect_to('index')

    registry = get_proxy_registry()
    proxies = registry.list_proxies()
    live_health = {}
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
    return render_template('fleet.html', proxies=proxies, live_health=live_health)


@app.route('/ssl-errors', methods=['GET'])
def ssl_errors():
    store = get_ssl_errors_store()
    limit = _query_int_arg('limit', default=200)
    q = (request.args.get('q') or '').strip().lower()
    window_i = _query_int_arg('window', default=86400, minimum=300, maximum=90 * 24 * 3600)
    since_ts = int(time.time()) - window_i

    try:
        raw_rows = store.list_recent(since=since_ts, search=q, limit=limit)
        raw_top_domains = store.top_domains(since=since_ts, search=q, limit=30)
    except Exception:
        raw_rows = []
        raw_top_domains = []

    presented = _present_ssl_error_rows(raw_rows)
    rows = presented['rows']
    summary = presented['summary']
    hints = presented['hints']
    top_domains = _present_ssl_top_domains(raw_top_domains, limit=15)

    return render_template(
        'ssl_errors.html',
        rows=rows,
        top_domains=top_domains,
        summary=summary,
        hints=hints,
        window=window_i,
        window_label=_window_label(window_i),
        search=q,
    )


@app.route('/ssl-errors/exclude', methods=['POST'])
def ssl_errors_exclude():
    domain = _normalized_domain(request.form.get('domain'))
    if domain:
        try:
            get_exclusions_store().add_domain(domain)
        except Exception:
            pass
        return _redirect_after_pac_refresh('ssl_errors', q=domain)
    return _redirect_to('ssl_errors', q=domain)


@app.route('/ssl-errors/export', methods=['GET'])
def ssl_errors_export():
    store = get_ssl_errors_store()
    q = (request.args.get('q') or '').strip().lower()
    window_i = _query_int_arg('window', default=86400, minimum=300, maximum=90 * 24 * 3600)
    since_ts = int(time.time()) - window_i
    rows = store.list_recent(since=since_ts, search=q, limit=1000)

    return _csv_response(
        ["domain", "category", "reason", "count", "last_seen", "sample"],
        (
            [
                getattr(r, 'domain', ''),
                getattr(r, 'category', ''),
                getattr(r, 'reason', ''),
                getattr(r, 'count', 0),
                getattr(r, 'last_seen', 0),
                getattr(r, 'sample', ''),
            ]
            for r in rows
        ),
    )


@app.route('/socks', methods=['GET'])
def socks():
    store = get_socks_store()
    window = _query_int_arg('window', default=3600, minimum=60, maximum=7 * 24 * 3600)
    q = (request.args.get('q') or '').strip()
    since = int(time.time()) - window

    def window_label() -> str:
        if window < 3600:
            return f"{window // 60}m"
        if window < 24 * 3600:
            return f"{window // 3600}h"
        return f"{window // (24 * 3600)}d"

    summary = store.summary(since=since)
    top_clients = store.top_clients(since=since, limit=20, search=q)
    top_dests = store.top_destinations(since=since, limit=20, search=q)
    recent_all = store.recent(limit=200, since=since)
    recent = store.recent(limit=200, since=since, search=q)

    # Heuristic: if all activity appears from a single private IP, it's often Docker NAT
    # masking real LAN client IPs (common on Docker Desktop).
    def is_private_ip(s: str) -> bool:
        try:
            return ipaddress.ip_address((s or '').strip()).is_private
        except Exception:
            return False

    def looks_like_docker_bridge(s: str) -> bool:
        s = (s or '').strip()
        return s.startswith('172.17.') or s.startswith('172.18.') or s.startswith('172.19.') or s.startswith('172.20.')

    seen_ips = []
    for e in recent_all:
        if e.src_ip:
            seen_ips.append(e.src_ip)
    uniq_ips = sorted({ip for ip in seen_ips if ip})
    nat_warning = False
    nat_warning_text = ''
    if len(uniq_ips) == 1 and is_private_ip(uniq_ips[0]):
        nat_warning = True
        if looks_like_docker_bridge(uniq_ips[0]):
            nat_warning_text = (
                f"All SOCKS events appear to come from {uniq_ips[0]}. "
                "This often means Docker NAT/bridge is masking the true client IPs."
            )
        else:
            nat_warning_text = (
                f"All SOCKS events appear to come from {uniq_ips[0]}. "
                "This may be NAT masking the true client IPs."
            )
    return render_template(
        'socks.html',
        window_label=window_label(),
        window=window,
        search=q,
        summary=summary,
        top_clients=top_clients,
        top_dests=top_dests,
        recent=recent,
        nat_warning=nat_warning,
        nat_warning_text=nat_warning_text,
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
        recent_blocks = store.list_recent_block_events(limit=100)
    except Exception:
        recent_blocks = []

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
        recent_blocks=recent_blocks,
    )


@app.route('/webfilter', methods=['GET', 'POST'])
def webfilter():
    store = get_webfilter_store()
    _best_effort_init_store(store, key='webfilter', description='web filter')

    tab = _normalize_choice(request.args.get('tab') or request.form.get('tab') or 'categories', ('categories', 'whitelist', 'blockedlog'), 'categories')

    if request.method == 'POST':
        return _handle_webfilter_post(store, tab)

    settings = store.get_settings()
    available = store.list_available_categories()
    selected = set(settings.blocked_categories)
    whitelist_rows = store.list_whitelist()
    blocked_log_rows = store.list_blocked_log(limit=200) if tab == 'blockedlog' else []
    return render_template(
        'webfilter.html',
        tab=tab,
        settings=settings,
        available_categories=available,
        selected=selected,
        whitelist_rows=whitelist_rows,
        blocked_log_rows=blocked_log_rows,
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
    return check_adblock_icap_health(timeout=0.8, error_formatter=public_error_message)


def _check_icap_av() -> Dict[str, Any]:
    return check_av_icap_health(timeout=0.8, error_formatter=public_error_message)


def _clamav_remote_health(proxy_id: str) -> Dict[str, Any]:
    try:
        return get_proxy_client().get_health(proxy_id)
    except ProxyClientError as exc:
        proxy = get_proxy_registry().get_proxy(proxy_id)
        return build_unavailable_runtime_health(str(exc), proxy_status=proxy.status if proxy else 'offline')


def _send_sample_av_icap() -> Dict[str, Any]:
    return _shared_send_sample_av_icap(error_formatter=public_error_message)


def _check_clamd() -> Dict[str, Any]:
    return check_clamd_health(timeout=0.8, error_formatter=public_error_message)


def _test_eicar() -> Dict[str, Any]:
    return _shared_test_eicar(error_formatter=public_error_message)


@app.route('/clamav', methods=['GET'])
def clamav():
    cfg = _current_managed_config()
    clamav_enabled = _is_clamav_enabled(cfg)
    if _is_remote_control_mode():
        proxy_id = get_proxy_id()
        health_payload = _clamav_remote_health(proxy_id)
        clamav_view = build_remote_clamav_view(health_payload)
        health = clamav_view['health']
        clamd_health = clamav_view['clamd_health']
        av_icap_health = clamav_view['av_icap_health']
        health_source = clamav_view['health_source']
    else:
        clamd_health = _check_clamd()
        av_icap_health = _check_icap_av()
        health = _shared_build_clamav_health(clamd_health, av_icap_health)
        health_source = ''

    return render_template(
        'clamav.html',
        health=health,
        clamd_health=clamd_health,
        av_icap_health=av_icap_health,
        health_source=health_source,
        clamav_enabled=clamav_enabled,
        eicar_result=request.args.get('eicar'),
        eicar_detail=request.args.get('eicar_detail'),
        icap_result=request.args.get('icap_sample'),
        icap_detail=request.args.get('icap_detail'),
    )


@app.route('/clamav/test-eicar', methods=['POST'])
def clamav_test_eicar():
    if _is_remote_control_mode():
        try:
            res = get_proxy_client().test_clamav_eicar(get_proxy_id())
        except ProxyClientError as exc:
            res = {'ok': False, 'detail': str(exc)}
    else:
        res = _test_eicar()
    return _redirect_to(
        'clamav',
        eicar='ok' if res.get('ok') else 'fail',
        eicar_detail=(res.get('detail') or '')[:300],
    )


@app.route('/clamav/test-icap', methods=['POST'])
def clamav_test_icap():
    if _is_remote_control_mode():
        try:
            res = get_proxy_client().test_clamav_icap(get_proxy_id())
        except ProxyClientError as exc:
            res = {'ok': False, 'detail': str(exc)}
    else:
        res = _send_sample_av_icap()
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
        allow_line = "adaptation_access av_resp_set allow icap_adblockable"
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
    tab = _normalize_choice(
        request.args.get('tab') or request.form.get('tab') or 'config',
        ('config', 'caching', 'timeouts', 'logging', 'network', 'dns', 'ssl', 'icap', 'privacy', 'limits', 'performance', 'http'),
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
        overrides=overrides,
        subtab=subtab,
        summary=summary,
        validation=validation,
        exclusions=exclusions,
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
    return render_template('exclusions.html', ex=ex)


@app.route('/proxy.pac', methods=['GET'])
def proxy_pac():
    def _requester_ip() -> str:
        # Best-effort: if a reverse-proxy is in front, it may set X-Forwarded-For.
        xff = (request.headers.get('X-Forwarded-For') or '').strip()
        if xff:
            # First IP in the list is the original client.
            cand = (xff.split(',')[0] or '').strip()
            if cand:
                return cand
        xri = (request.headers.get('X-Real-IP') or '').strip()
        if xri:
            return xri
        return (request.remote_addr or '').strip()

    def _request_host() -> str:
        return (request.host or '').strip() or '127.0.0.1'

    pac = render_proxy_pac_for_request(
        proxy_id=get_proxy_id(),
        requester_ip=_requester_ip(),
        request_host=_request_host(),
    )
    return app.response_class(pac, mimetype='application/x-ns-proxy-autoconfig')


@app.route('/wpad.dat', methods=['GET'])
def wpad_dat():
    # WPAD convention: clients request http://wpad.<domain>/wpad.dat
    resp = proxy_pac()
    try:
        resp.headers['Content-Disposition'] = 'inline; filename="wpad.dat"'
    except Exception:
        pass
    return resp


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

    pac_url = build_public_pac_url(
        request.host or '',
        proxy_id=(get_proxy_id() if _is_remote_control_mode() else None),
    )
    return render_template('pac.html', profiles=profiles, pac_url=pac_url)

@app.route('/status')
def status():
    return _redirect_index_status()


@app.route('/api/timeseries', methods=['GET'])
def api_timeseries():
    res = (request.args.get('resolution') or '1s').strip()
    window_i = _query_int_arg('window', default=60, minimum=10, maximum=365 * 24 * 3600)
    limit_i = _query_int_arg('limit', default=500)

    since = int(time.time()) - window_i
    points = get_timeseries_store().query(resolution=res, since=since, limit=limit_i)
    return jsonify({"resolution": res, "since": since, "points": points})


@app.route('/live', methods=['GET'])
def live():
    store = get_store()
    subtab = (request.args.get('subtab') or 'activity').strip().lower()
    mode = (request.args.get('mode') or 'domains').strip().lower()
    sort = (request.args.get('sort') or ('recent' if mode in ('domains', 'clients') else 'top')).strip().lower()
    order = (request.args.get('order') or 'desc').strip().lower()
    limit = request.args.get('limit') or '100'
    ip = (request.args.get('ip') or '').strip()
    detail = (request.args.get('detail') or 'top').strip().lower()
    domain = (request.args.get('domain') or '').strip().lower().lstrip('.')
    search = (request.args.get('q') or '').strip().lower()
    window_i = _query_int_arg('window', default=3600, minimum=300, maximum=7 * 24 * 3600)
    since_ts = int(time.time()) - window_i
    window_label = _window_label(window_i)

    limit_i = _bounded_int(limit, default=100, minimum=10, maximum=500)

    # Sub-tab: global view of why content was not served from cache.
    if subtab == 'reasons':
        totals = store.get_totals(since=since_ts)
        global_nocache_total, global_reasons = store.list_global_not_cached_reasons(limit=min(limit_i, 200))
        return render_template(
            'live.html',
            subtab=subtab,
            mode='domains',
            sort=sort,
            order=order,
            limit=limit_i,
            ip='',
            detail='top',
            domain='',
            rows=[],
            client_domains=[],
            client_not_cached=[],
            domain_reasons=[],
            global_nocache_total=global_nocache_total,
            global_reasons=global_reasons,
            totals=totals,
            search=search,
            window=window_i,
            window_label=window_label,
        )

    subtab = 'activity'

    if mode == 'clients':
        rows = store.list_clients(sort=sort, order=order, limit=limit_i, since=since_ts, search=search)
        client_domains = store.list_client_domains(ip=ip, sort=request.args.get('ip_sort') or 'top') if ip else []
        client_not_cached = store.list_client_not_cached(ip=ip, limit=min(limit_i, 200)) if ip else []

        # If a domain is explicitly excluded by configured rules, that is a stronger
        # explanation than a generic MISS reason.
        try:
            exclusions = get_exclusions_store().list_all()
            excluded_domains = [d.lower().lstrip('.') for d in exclusions.domains]

            def is_excluded(domain: str) -> bool:
                d = (domain or '').lower()
                for ex in excluded_domains:
                    if d == ex or d.endswith('.' + ex):
                        return True
                return False

            for r in client_not_cached:
                if is_excluded(r.get('domain', '')):
                    r['reason'] = 'Excluded by configured domain rule'
        except Exception:
            pass
    else:
        mode = 'domains'
        rows = store.list_domains(sort=sort, order=order, limit=limit_i, since=since_ts, search=search)
        client_domains = []
        client_not_cached = []
        domain_reasons = store.list_domain_not_cached_reasons(domain=domain, limit=10) if domain and detail == 'nocache' else []

    totals = store.get_totals(since=since_ts)
    return render_template(
        'live.html',
        subtab=subtab,
        mode=mode,
        sort=sort,
        order=order,
        limit=limit_i,
        ip=ip,
        detail=detail,
        domain=domain,
        rows=rows,
        client_domains=client_domains,
        client_not_cached=client_not_cached,
        domain_reasons=domain_reasons,
        global_nocache_total=0,
        global_reasons=[],
        totals=totals,
        search=search,
        window=window_i,
        window_label=window_label,
    )


@app.route('/live/export', methods=['GET'])
def live_export():
    store = get_store()
    mode = (request.args.get('mode') or 'domains').strip().lower()
    search = (request.args.get('q') or '').strip().lower()
    window_i = _query_int_arg('window', default=3600, minimum=300, maximum=7 * 24 * 3600)
    since_ts = int(time.time()) - window_i
    rows = store.export_rows(mode, since=since_ts, search=search, limit=1000)
    headers = list(rows[0].keys()) if rows else []
    return _csv_response(headers, ([row.get(header, '') for header in headers] for row in rows))


@app.route('/reload', methods=['POST'])
def reload_squid():
    ok, detail = _trigger_proxy_sync(force=True)
    _record_audit_event('proxy_sync', ok=ok, detail=detail)
    return _redirect_index_status()


@app.route('/cache/clear', methods=['POST'])
def clear_caches():
    # Clear Squid disk cache (best-effort) and restart Squid.
    ok, detail = _trigger_proxy_cache_clear()
    _record_audit_event('cache_clear', ok=ok, detail=detail)
    return _redirect_index_status()

@app.route('/certs', methods=['GET'])
def certs():
    bundle = None
    proxy_cert_statuses = []
    if _is_remote_control_mode():
        bundle_store = get_certificate_bundles()
        bundle = bundle_store.get_active_bundle()
        certificate = 'ca.crt' if bundle is not None else None
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
    else:
        bundle = cert_manager.load_bundle()
        certificate = "ca.crt" if cert_manager.ca_exists() else None
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
        if _is_remote_control_mode():
            bundle = generate_self_signed_ca_bundle()
            ok, detail = _publish_certificate_bundle_remote(bundle)
        else:
            cert_manager.ensure_ca()
            ok, detail = True, 'CA generated.'
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
    if _is_remote_control_mode():
        parsed = parse_pfx_bundle(pfx_bytes, password=password)
        ok = bool(parsed.ok and parsed.bundle is not None)
        detail = parsed.message
        if ok and parsed.bundle is not None:
            ok, detail = _publish_certificate_bundle_remote(
                parsed.bundle,
                original_filename=(pfx_file.filename or '').strip(),
            )
    else:
        result = install_pfx_as_ca(cert_manager.ca_dir, pfx_bytes, password=password)
        ok = result.ok
        detail = result.message

        if ok:
            try:
                squid_controller.reload_squid()
            except Exception:
                pass

    _record_audit_event('ca_upload_pfx', ok=ok, detail=detail)

    return _redirect_with_message('certs', ok=ok, msg=detail)


@app.route('/certs/download/<path:filename>', methods=['GET'])
def download_certificate(filename: str):
    # Only allow downloading the public CA cert
    if filename != 'ca.crt':
        abort(404)
    if _is_remote_control_mode():
        bundle = get_certificate_bundles().get_active_bundle()
        if bundle is None:
            abort(404)
        response = app.response_class(bundle.fullchain_pem, mimetype='application/x-pem-file')
        response.headers['Content-Disposition'] = 'attachment; filename=squid-proxy-ca.crt'
        return response
    try:
        cert_manager.ensure_ca()
    except Exception:
        abort(500)
    return send_file(cert_manager.ca_cert_path, as_attachment=True, download_name='squid-proxy-ca.crt')


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