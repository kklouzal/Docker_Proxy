from flask import Flask, render_template, request, redirect, url_for, jsonify, send_file, abort, session
from services.squidctl import SquidController
from services.cert_manager import CertManager, install_pfx_as_ca
from services.auth_store import get_auth_store
import datetime
import time
import os
import ipaddress
import uuid
from services.stats import get_stats
from services.live_stats import get_store
from services.exclusions_store import get_exclusions_store
from services.audit_store import get_audit_store
from services.timeseries_store import get_timeseries_store
from services.ssl_errors_store import get_ssl_errors_store
from services.socks_store import get_socks_store
from services.adblock_store import get_adblock_store
from services.webfilter_store import get_webfilter_store
from services.sslfilter_store import get_sslfilter_store
from services.pac_profiles_store import get_pac_profiles_store
from services.housekeeping import start_housekeeping
from services.background_guard import acquire_background_lock
from services.errors import public_error_message

import socket
import re
import secrets
import csv
import io
from urllib.parse import urlparse
from typing import Any, Dict
from markupsafe import Markup

app = Flask(__name__)
squid_controller = SquidController()
cert_manager = CertManager()

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
_env_secret = (os.environ.get('FLASK_SECRET_KEY') or os.environ.get('SECRET_KEY') or '').strip()
if _env_secret:
    app.secret_key = _env_secret
else:
    try:
        app.secret_key = _auth_store.get_or_create_secret_key()
    except Exception:
        # Fallback: sessions will reset on restart.
        app.secret_key = secrets.token_urlsafe(48)

# Cookie hardening. Defaults chosen to avoid breaking common HTTP deployments.
app.config.setdefault('SESSION_COOKIE_HTTPONLY', True)
app.config.setdefault('SESSION_COOKIE_SAMESITE', 'Lax')
if (os.environ.get('SESSION_COOKIE_SECURE') or '').strip() in ('1', 'true', 'True', 'yes', 'on'):
    app.config['SESSION_COOKIE_SECURE'] = True

# Ensure there is at least one login.
try:
    _auth_store.ensure_default_admin()
except Exception:
    pass


def _is_logged_in() -> bool:
    u = session.get('user')
    return bool(u and isinstance(u, str))


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
    return redirect(url_for('login', next=request.full_path))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        next_url = _safe_next_url(request.form.get('next') or '')
        if _auth_store.verify_user(username, password):
            session['user'] = username
            return redirect(next_url or url_for('index'))
        return render_template('login.html', error='Invalid username or password.', next=next_url)

    if _is_logged_in():
        return redirect(url_for('index'))
    next_url = _safe_next_url(request.args.get('next') or '')
    return render_template('login.html', error=None, next=next_url)


@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))


def _options_from_tunables(tunables: Dict[str, Any]) -> Dict[str, Any]:
    # Centralize the Squid template option defaults derived from an existing config.
    # Keep behavior identical to the prior inline dicts.
    return {
        'cache_dir_size_mb': tunables.get('cache_dir_size_mb') or 10000,
        'cache_mem_mb': tunables.get('cache_mem_mb') or 256,
        'maximum_object_size_mb': tunables.get('maximum_object_size_mb') or 64,
        'maximum_object_size_in_memory_kb': tunables.get('maximum_object_size_in_memory_kb') or 1024,
        'minimum_object_size_kb': tunables.get('minimum_object_size_kb') if tunables.get('minimum_object_size_kb') is not None else 0,
        'cache_swap_low': tunables.get('cache_swap_low') or 90,
        'cache_swap_high': tunables.get('cache_swap_high') or 95,
        'collapsed_forwarding_on': bool(tunables.get('collapsed_forwarding') if tunables.get('collapsed_forwarding') is not None else True),
        'range_cache_on': (tunables.get('range_offset_limit') == -1) if tunables.get('range_offset_limit') is not None else True,
        'workers': min(4, max(1, int(tunables.get('workers') or 2))),
        'cache_replacement_policy': tunables.get('cache_replacement_policy') or 'heap GDSF',
        'memory_replacement_policy': tunables.get('memory_replacement_policy') or 'heap GDSF',
        'pipeline_prefetch_on': bool(tunables.get('pipeline_prefetch') if tunables.get('pipeline_prefetch') is not None else True),
        'client_persistent_connections_on': bool(tunables.get('client_persistent_connections') if tunables.get('client_persistent_connections') is not None else True),
        'server_persistent_connections_on': bool(tunables.get('server_persistent_connections') if tunables.get('server_persistent_connections') is not None else True),
        'negative_ttl_seconds': tunables.get('negative_ttl_seconds'),
        'positive_dns_ttl_seconds': tunables.get('positive_dns_ttl_seconds'),
        'negative_dns_ttl_seconds': tunables.get('negative_dns_ttl_seconds'),
        'read_ahead_gap_kb': tunables.get('read_ahead_gap_kb'),
        'quick_abort_min_kb': tunables.get('quick_abort_min_kb') if tunables.get('quick_abort_min_kb') is not None else 0,
        'quick_abort_max_kb': tunables.get('quick_abort_max_kb') if tunables.get('quick_abort_max_kb') is not None else 0,
        'quick_abort_pct': tunables.get('quick_abort_pct') if tunables.get('quick_abort_pct') is not None else 100,

        # Timeouts (seconds)
        'connect_timeout_seconds': tunables.get('connect_timeout_seconds') if tunables.get('connect_timeout_seconds') is not None else 90,
        'request_timeout_seconds': tunables.get('request_timeout_seconds') if tunables.get('request_timeout_seconds') is not None else 1800,
        'read_timeout_seconds': tunables.get('read_timeout_seconds') if tunables.get('read_timeout_seconds') is not None else 1800,
        'forward_timeout_seconds': tunables.get('forward_timeout_seconds') if tunables.get('forward_timeout_seconds') is not None else 1800,
        'shutdown_lifetime_seconds': tunables.get('shutdown_lifetime_seconds') if tunables.get('shutdown_lifetime_seconds') is not None else 30,
        'half_closed_clients_on': bool(tunables.get('half_closed_clients') if tunables.get('half_closed_clients') is not None else True),

        # Logging
        'logfile_rotate': tunables.get('logfile_rotate') if tunables.get('logfile_rotate') is not None else 10,

        # Network
        'pconn_timeout_seconds': tunables.get('pconn_timeout_seconds') if tunables.get('pconn_timeout_seconds') is not None else 120,
        'idle_pconn_timeout_seconds': tunables.get('idle_pconn_timeout_seconds') if tunables.get('idle_pconn_timeout_seconds') is not None else 60,
        'client_lifetime_seconds': tunables.get('client_lifetime_seconds') if tunables.get('client_lifetime_seconds') is not None else 3600,
        'max_filedescriptors': tunables.get('max_filedescriptors') if tunables.get('max_filedescriptors') is not None else 8192,

        # DNS
        'dns_v4_first_on': bool(tunables.get('dns_v4_first') if tunables.get('dns_v4_first') is not None else True),
        'dns_timeout_seconds': tunables.get('dns_timeout_seconds') if tunables.get('dns_timeout_seconds') is not None else 5,
        'dns_retransmit_seconds': tunables.get('dns_retransmit_seconds') if tunables.get('dns_retransmit_seconds') is not None else 2,
        'dns_nameservers': (tunables.get('dns_nameservers') or ''),
        'hosts_file': (tunables.get('hosts_file') or ''),
        'ipcache_size': tunables.get('ipcache_size') if tunables.get('ipcache_size') is not None else 8192,
        'fqdncache_size': tunables.get('fqdncache_size') if tunables.get('fqdncache_size') is not None else 8192,

        # SSL
        'dynamic_cert_mem_cache_size_mb': tunables.get('dynamic_cert_mem_cache_size_mb') if tunables.get('dynamic_cert_mem_cache_size_mb') is not None else 128,
        'sslcrtd_children': tunables.get('sslcrtd_children') if tunables.get('sslcrtd_children') is not None else 5,

        # ICAP
        'icap_enable_on': bool(tunables.get('icap_enable') if tunables.get('icap_enable') is not None else True),
        'icap_send_client_ip_on': bool(tunables.get('icap_send_client_ip') if tunables.get('icap_send_client_ip') is not None else True),
        'icap_send_client_port_on': bool(tunables.get('icap_send_client_port') if tunables.get('icap_send_client_port') is not None else False),
        'icap_send_client_username_on': bool(tunables.get('icap_send_client_username') if tunables.get('icap_send_client_username') is not None else False),
        'icap_preview_enable_on': bool(tunables.get('icap_preview_enable') if tunables.get('icap_preview_enable') is not None else False),
        'icap_preview_size_kb': tunables.get('icap_preview_size_kb'),
        'icap_connect_timeout_seconds': tunables.get('icap_connect_timeout_seconds') if tunables.get('icap_connect_timeout_seconds') is not None else 60,
        'icap_io_timeout_seconds': tunables.get('icap_io_timeout_seconds') if tunables.get('icap_io_timeout_seconds') is not None else 600,

        # Privacy (optional: only applied when present/posted)
        'forwarded_for_value': (tunables.get('forwarded_for_value') or ''),
        'via_on': (tunables.get('via') if tunables.get('via') is not None else None),
        'follow_x_forwarded_for_value': (tunables.get('follow_x_forwarded_for_value') or ''),

        # Limits (optional)
        'request_header_max_size_kb': tunables.get('request_header_max_size_kb'),
        'reply_header_max_size_kb': tunables.get('reply_header_max_size_kb'),
        'request_body_max_size_mb': tunables.get('request_body_max_size_mb'),
        'client_request_buffer_max_size_kb': tunables.get('client_request_buffer_max_size_kb'),

        # Performance (optional)
        'memory_pools_on': (tunables.get('memory_pools') if tunables.get('memory_pools') is not None else None),
        'memory_pools_limit_mb': tunables.get('memory_pools_limit_mb'),
        'store_avg_object_size_kb': tunables.get('store_avg_object_size_kb'),
        'store_objects_per_bucket': tunables.get('store_objects_per_bucket'),

        # HTTP (optional)
        'visible_hostname': (tunables.get('visible_hostname') or ''),
        'httpd_suppress_version_string_on': (tunables.get('httpd_suppress_version_string') if tunables.get('httpd_suppress_version_string') is not None else None),
    }

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
        return datetime.datetime.fromtimestamp(i).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return ''

if not _disable_background:
    # Start background ingestion of Squid access.log into SQLite (best-effort).
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
            return datetime.datetime.fromtimestamp(int(ts)).strftime('%Y-%m-%d %H:%M:%S')
        except Exception:
            return ''

    return {
        # Use timezone-aware UTC to avoid deprecation warnings.
        "current_year": datetime.datetime.now(datetime.UTC).year,
        "fmt_ts": fmt_ts,
    }


def _check_tcp(host: str, port: int, timeout: float = 0.6) -> Dict[str, Any]:
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return {"ok": True, "detail": "tcp connect ok"}
    except Exception as e:
        return {"ok": False, "detail": f"{type(e).__name__}: {e}"}


@app.route('/')
def index():
    stdout, stderr = squid_controller.get_status()
    proxy_detail = (stdout or b'').decode('utf-8', errors='replace') + (stderr or b'').decode('utf-8', errors='replace')
    proxy_ok = not stderr

    stats = get_stats()
    try:
        trends = get_timeseries_store().summary()
    except Exception:
        trends = {}

    # ICAP health check: verify the adblock REQMOD c-icap instance is reachable.
    icap_health = _check_icap_adblock()
    clamav_health = _check_clamd()
    dante_port = int(os.environ.get('DANTE_PORT', 1080))
    dante_health = _check_tcp(os.environ.get('DANTE_HOST', '127.0.0.1'), dante_port)

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
    cfg = squid_controller.get_current_config() or ""
    return app.response_class(cfg, mimetype='text/plain; charset=utf-8')


@app.route('/ssl-errors', methods=['GET'])
def ssl_errors():
    store = get_ssl_errors_store()
    limit_s = (request.args.get('limit') or '200').strip()
    q = (request.args.get('q') or '').strip().lower()
    window_s = (request.args.get('window') or '86400').strip()
    try:
        limit = int(limit_s)
    except ValueError:
        limit = 200
    try:
        window_i = max(300, min(90 * 24 * 3600, int(window_s)))
    except ValueError:
        window_i = 86400
    since_ts = int(time.time()) - window_i

    try:
        rows = store.list_recent(since=since_ts, search=q, limit=limit)
        top_domains = store.top_domains(since=since_ts, search=q, limit=15)
    except Exception:
        rows = []
        top_domains = []

    return render_template('ssl_errors.html', rows=rows, top_domains=top_domains, window=window_i, search=q)


@app.route('/ssl-errors/exclude', methods=['POST'])
def ssl_errors_exclude():
    domain = (request.form.get('domain') or '').strip().lower().lstrip('.')
    if domain:
        try:
            get_exclusions_store().add_domain(domain)
        except Exception:
            pass
    return redirect(url_for('ssl_errors', q=domain))


@app.route('/ssl-errors/export', methods=['GET'])
def ssl_errors_export():
    store = get_ssl_errors_store()
    q = (request.args.get('q') or '').strip().lower()
    window_s = (request.args.get('window') or '86400').strip()
    try:
        window_i = max(300, min(90 * 24 * 3600, int(window_s)))
    except ValueError:
        window_i = 86400
    since_ts = int(time.time()) - window_i
    rows = store.list_recent(since=since_ts, search=q, limit=1000)

    headers = ["domain", "category", "reason", "count", "last_seen", "sample"]
    out = [";".join(headers)]
    for r in rows:
        out.append(";".join([str(getattr(r, 'domain', '')), getattr(r, 'category', ''), getattr(r, 'reason', ''), str(getattr(r, 'count', 0)), str(getattr(r, 'last_seen', 0)), getattr(r, 'sample', '')]))
    body = "\n".join(out)
    return app.response_class(body, mimetype='text/csv; charset=utf-8')


@app.route('/socks', methods=['GET'])
def socks():
    store = get_socks_store()
    window_s = (request.args.get('window') or '3600').strip()
    q = (request.args.get('q') or '').strip()
    try:
        window = int(window_s)
    except ValueError:
        window = 3600
    window = max(60, min(7 * 24 * 3600, window))
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
    try:
        store.init_db()
    except Exception:
        pass

    if request.method == 'POST':
        action = (request.form.get('action') or '').strip()
        if action == 'save_lists':
            enabled_map = {}
            for st in store.list_statuses():
                enabled_map[st.key] = request.form.get(f'enabled_{st.key}') == 'on'
            store.set_enabled(enabled_map)
        elif action == 'save_settings':
            enabled = request.form.get('adblock_enabled') == 'on'

            def as_int(name: str, default: int) -> int:
                v = (request.form.get(name) or '').strip()
                try:
                    return int(v)
                except ValueError:
                    return default

            cur = store.get_settings()
            cache_ttl = as_int('cache_ttl', int(cur.get('cache_ttl') or 0))
            cache_max = as_int('cache_max', int(cur.get('cache_max') or 0))
            store.set_settings(enabled=enabled, cache_ttl=cache_ttl, cache_max=cache_max)
        elif action == 'refresh':
            # Refresh is handled asynchronously by background workers.
            # If no lists are enabled, a refresh won't download anything.
            any_enabled = False
            try:
                any_enabled = any(st.enabled for st in store.list_statuses())
            except Exception:
                any_enabled = False
            if not any_enabled:
                return redirect(url_for('adblock', refresh_no_lists='1'))
            store.request_refresh_now()
            return redirect(url_for('adblock', refresh_requested='1'))
        elif action == 'flush_cache':
            store.request_cache_flush()
            return redirect(url_for('adblock', cache_flushed='1'))
        return redirect(url_for('adblock'))

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
    try:
        store.init_db()
    except Exception:
        pass

    tab = (request.args.get('tab') or request.form.get('tab') or 'categories').strip().lower()
    if tab not in ('categories', 'whitelist', 'blockedlog'):
        tab = 'categories'

    if request.method == 'POST':
        action = (request.form.get('action') or '').strip()

        if action == 'save':
            enabled = request.form.get('enabled') == 'on'
            source_url = (request.form.get('source_url') or '').strip()
            categories = [c.strip() for c in request.form.getlist('categories') if (c or '').strip()]

            # Enabling requires a source URL so auto-download works.
            if enabled and not source_url:
                return redirect(url_for('webfilter', tab='categories', err_source='1'))

            store.set_settings(enabled=enabled, source_url=source_url, blocked_categories=categories)

            # Apply include + reconfigure squid so changes take effect immediately.
            try:
                store.apply_squid_include()
                from subprocess import run as _run

                _run(['squid', '-k', 'reconfigure'], capture_output=True, timeout=6)
            except Exception:
                pass

            return redirect(url_for('webfilter', tab='categories'))

        if action == 'whitelist_add':
            entry = (request.form.get('whitelist_domain') or '').strip()
            ok, err, _pat = store.add_whitelist(entry)
            try:
                store.apply_squid_include()
                from subprocess import run as _run

                _run(['squid', '-k', 'reconfigure'], capture_output=True, timeout=6)
            except Exception:
                pass

            if not ok:
                return redirect(url_for('webfilter', tab='whitelist', wl_err=(err or '1')))
            return redirect(url_for('webfilter', tab='whitelist', wl_ok='1'))

        if action == 'whitelist_remove':
            pat = (request.form.get('pattern') or '').strip()
            try:
                store.remove_whitelist(pat)
            except Exception:
                pass
            try:
                store.apply_squid_include()
                from subprocess import run as _run

                _run(['squid', '-k', 'reconfigure'], capture_output=True, timeout=6)
            except Exception:
                pass
            return redirect(url_for('webfilter', tab='whitelist'))

        return redirect(url_for('webfilter', tab=tab))

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
    try:
        store.init_db()
    except Exception:
        pass

    payload = request.get_json(silent=True) or {}
    domain = (payload.get('domain') or request.form.get('domain') or '').strip()
    try:
        res = store.test_domain(domain)
        return jsonify(res), 200
    except Exception as e:
        return jsonify({"ok": False, "verdict": "error", "reason": f"{type(e).__name__}: {e}"}), 200


@app.route('/sslfilter', methods=['GET', 'POST'])
def sslfilter():
    store = get_sslfilter_store()
    try:
        store.init_db()
    except Exception:
        pass

    if request.method == 'POST':
        action = (request.form.get('action') or '').strip().lower()
        if action == 'add':
            entry = (request.form.get('cidr') or '').strip()
            ok, err, _canonical = store.add_nobump(entry)
            try:
                store.apply_squid_include()
                from subprocess import run as _run

                _run(['squid', '-k', 'reconfigure'], capture_output=True, timeout=6)
            except Exception:
                pass
            if not ok:
                return redirect(url_for('sslfilter', err=(err or '1')))
            return redirect(url_for('sslfilter', ok='1'))

        if action == 'remove':
            cidr = (request.form.get('cidr') or '').strip()
            try:
                store.remove_nobump(cidr)
            except Exception:
                pass
            try:
                store.apply_squid_include()
                from subprocess import run as _run

                _run(['squid', '-k', 'reconfigure'], capture_output=True, timeout=6)
            except Exception:
                pass
            return redirect(url_for('sslfilter'))

        return redirect(url_for('sslfilter'))

    rows = store.list_nobump()
    return render_template(
        'sslfilter.html',
        rows=rows,
        ok=(request.args.get('ok') == '1'),
        err=(request.args.get('err') or ''),
    )


def _check_icap_service(host: str, port: int, service: str):
    # Best-effort local health check: connect and issue ICAP OPTIONS.
    # Keep timeouts tight so the UI can't hang.
    path = (service or "/")
    if not path.startswith("/"):
        path = "/" + path
    req = (
        f"OPTIONS icap://{host}:{port}{path} ICAP/1.0\r\n"
        f"Host: {host}\r\n"
        "User-Agent: squid-flask-proxy-ui\r\n"
        "Encapsulated: null-body=0\r\n"
        "\r\n"
    ).encode("ascii", errors="replace")

    try:
        with socket.create_connection((host, int(port)), timeout=0.8) as s:
            s.settimeout(0.8)
            s.sendall(req)
            data = s.recv(512)
        ok = data.startswith(b"ICAP/1.0 200")
        if ok:
            return {"ok": True, "detail": "OPTIONS 200"}
        first = data.split(b"\r\n", 1)[0].decode("ascii", errors="replace") if data else "no data"
        return {"ok": False, "detail": first}
    except Exception as e:
        return {"ok": False, "detail": f"{type(e).__name__}: {e}"}


def _check_icap_adblock() -> Dict[str, Any]:
    host = os.environ.get('CICAP_HOST', '127.0.0.1')
    try:
        port = int(os.environ.get('CICAP_PORT', 14000))
    except Exception:
        port = 14000
    return _check_icap_service(host=host, port=port, service='/adblockreq')


def _send_sample_respmod_to(host: str, port: int, service: str = "/avrespmod") -> Dict[str, Any]:
    path = service or '/avrespmod'
    if not path.startswith('/'):
        path = '/' + path

    http_body = b"Hello from ICAP sample"
    http_hdr = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/plain\r\n\r\n"
    chunk = f"{len(http_body):X}\r\n".encode('ascii') + http_body + b"\r\n0\r\n\r\n"
    res_body_off = len(http_hdr)
    icap_req = (
        f"RESPMOD icap://{host}:{port}{path} ICAP/1.0\r\n"
        f"Host: {host}\r\n"
        "Allow: 204\r\n"
        f"Encapsulated: res-hdr=0, res-body={res_body_off}\r\n"
        "\r\n"
    ).encode('ascii') + http_hdr + chunk

    try:
        with socket.create_connection((host, port), timeout=1.2) as s:
            s.settimeout(1.2)
            s.sendall(icap_req)
            resp = s.recv(512)
        line = resp.split(b"\r\n", 1)[0].decode('ascii', errors='replace') if resp else "no data"
        ok = line.startswith("ICAP/1.0 20")
        return {"ok": ok, "detail": line or "no data"}
    except Exception as e:
        return {"ok": False, "detail": f"{type(e).__name__}: {e}"}


def _send_sample_av_icap() -> Dict[str, Any]:
    # Send a tiny RESPMOD sample to the c-icap AV service (avrespmod).
    host = os.environ.get('CICAP_HOST', '127.0.0.1')
    try:
        port = int(os.environ.get('CICAP_AV_PORT', 14001))
    except Exception:
        port = 14001
    return _send_sample_respmod_to(host=host, port=port, service='/avrespmod')


def _check_clamd() -> Dict[str, Any]:
    # Best-effort health check: PING the clamd unix socket.
    sock_path = (os.environ.get('CLAMAV_SOCKET_PATH') or '/var/lib/squid-flask-proxy/clamav/clamd.sock').strip()
    if not sock_path:
        sock_path = '/var/lib/squid-flask-proxy/clamav/clamd.sock'
    # During clamd startup (loading signature DB), the socket file often appears
    # ~30-60s after the process starts. Avoid showing a scary FileNotFoundError.
    try:
        if not os.path.exists(sock_path):
            return {"ok": False, "detail": "starting (clamd socket not ready yet)"}
    except Exception:
        pass
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(0.6)
            s.connect(sock_path)
            s.sendall(b"PING\n")
            data = s.recv(64)
        ok = data.startswith(b"PONG")
        return {"ok": bool(ok), "detail": (data.decode('ascii', errors='replace').strip() or 'no data')}
    except Exception as e:
        return {"ok": False, "detail": f"{type(e).__name__}: {e}"}


def _test_eicar() -> Dict[str, Any]:
    # Send EICAR string via clamd SCAN (temp file) to verify detection.
    sock_path = (os.environ.get('CLAMAV_SOCKET_PATH') or '/var/lib/squid-flask-proxy/clamav/clamd.sock').strip()
    if not sock_path:
        sock_path = '/var/lib/squid-flask-proxy/clamav/clamd.sock'
    data = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    tmp_path = ""
    try:
        if not os.path.exists(sock_path):
            return {"ok": False, "detail": "starting (clamd socket not ready yet)"}

        # Some clamd builds/configs disable INSTREAM and STATS but still allow SCAN.
        # Use SCAN against a temp file as a reliable, local sanity check.
        tmp_dir = os.environ.get('TMPDIR') or '/tmp'
        tmp_name = f"eicar_{uuid.uuid4().hex}.txt"
        tmp_path = os.path.join(tmp_dir, tmp_name)
        with open(tmp_path, 'wb') as f:
            f.write(data)

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(1.5)
            s.connect(sock_path)
            s.sendall((f"SCAN {tmp_path}\n").encode('utf-8'))

            buf = b""
            while b"\n" not in buf and len(buf) < 4096:
                chunk = s.recv(512)
                if not chunk:
                    break
                buf += chunk

        text = buf.decode('ascii', errors='replace') if buf else ''
        ok = ('Eicar' in text) or ('FOUND' in text)
        return {"ok": ok, "detail": text or 'no data'}
    except Exception as e:
        return {"ok": False, "detail": f"{type(e).__name__}: {e}"}
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass


@app.route('/clamav', methods=['GET'])
def clamav():
    clamd_health = _check_clamd()
    cicap_health = _check_icap_service(
        host=os.environ.get('CICAP_HOST', '127.0.0.1'),
        port=int(os.environ.get('CICAP_AV_PORT', 14001)),
        service='/avrespmod',
    )

    ok = bool(clamd_health.get('ok')) and bool(cicap_health.get('ok'))
    detail = f"clamd={clamd_health.get('detail')} | cicap={cicap_health.get('detail')}"

    cfg = squid_controller.get_current_config() or ""
    clamav_enabled = _is_clamav_enabled(cfg)
    return render_template(
        'clamav.html',
        health={"ok": ok, "detail": detail},
        clamav_enabled=clamav_enabled,
        eicar_result=request.args.get('eicar'),
        eicar_detail=request.args.get('eicar_detail'),
        icap_result=request.args.get('icap_sample'),
        icap_detail=request.args.get('icap_detail'),
    )


@app.route('/clamav/test-eicar', methods=['POST'])
def clamav_test_eicar():
    res = _test_eicar()
    return redirect(
        url_for(
            'clamav',
            eicar='ok' if res.get('ok') else 'fail',
            eicar_detail=(res.get('detail') or '')[:300],
        )
    )


@app.route('/clamav/test-icap', methods=['POST'])
def clamav_test_icap():
    res = _send_sample_av_icap()
    return redirect(
        url_for(
            'clamav',
            icap_sample='ok' if res.get('ok') else 'fail',
            icap_detail=(res.get('detail') or '')[:300],
        )
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
    action = (request.form.get('action') or '').strip().lower()
    cfg = squid_controller.get_current_config() or ""
    currently_enabled = _is_clamav_enabled(cfg)

    if action == 'enable':
        desired = True
    elif action == 'disable':
        desired = False
    else:
        desired = (not currently_enabled)

    new_cfg = _set_clamav_enabled(cfg, desired)
    ok, _details = squid_controller.apply_config_text(new_cfg)
    if ok:
        return redirect(url_for('clamav'))
    return redirect(url_for('clamav', error='1'))



@app.route('/squid/config', methods=['GET', 'POST'])
def squid_config():
    tab = (request.args.get('tab') or request.form.get('tab') or 'config').strip().lower()
    if tab not in ('config', 'caching', 'timeouts', 'logging', 'network', 'dns', 'ssl', 'icap', 'privacy', 'limits', 'performance', 'http'):
        tab = 'config'

    validation = None
    posted_config = None
    if request.method == 'POST':
        action = (request.form.get('action') or 'apply').strip().lower()
        config_text = request.form.get('config_text', '')
        posted_config = config_text
        if action == 'validate':
            ok, details = squid_controller.validate_config_text(config_text)
            validation = {'ok': ok, 'detail': (details or '').strip()}
            try:
                get_audit_store().record(
                    kind='config_validate_manual',
                    ok=ok,
                    remote_addr=request.remote_addr,
                    user_agent=request.headers.get('User-Agent'),
                    detail=(details or '')[:4000],
                    config_text=config_text,
                )
            except Exception:
                pass
        else:
            ok, details = squid_controller.apply_config_text(config_text)
            try:
                get_audit_store().record(
                    kind='config_apply_manual',
                    ok=ok,
                    remote_addr=request.remote_addr,
                    user_agent=request.headers.get('User-Agent'),
                    detail=(details or '')[:4000],
                    config_text=config_text,
                )
            except Exception:
                pass
            if ok:
                return redirect(url_for('squid_config', tab=tab, ok='1'))
            return redirect(url_for('squid_config', tab=tab, error='1'))
    current_config = squid_controller.get_current_config()
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
    subtab = (request.args.get('subtab') or 'safe').strip().lower()
    if subtab not in ('safe', 'overrides'):
        subtab = 'safe'
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
    def as_int(name: str, default: int) -> int:
        v = (request.form.get(name) or '').strip()
        try:
            return int(v)
        except ValueError:
            return default

    def as_optional_int(name: str) -> int | None:
        v = (request.form.get(name) or '').strip()
        if v == '':
            return None
        try:
            return int(v)
        except ValueError:
            return None

    def as_optional_str(name: str) -> str | None:
        v = (request.form.get(name) or '').strip()
        return v if v != '' else None

    # Start from current tunables so partial forms (different tabs) don't reset unrelated settings.
    try:
        current = squid_controller.get_current_config()
        tunables = squid_controller.get_tunable_options(current)
        options = _options_from_tunables(tunables)
    except Exception:
        options = _options_from_tunables({})

    form_kind = (request.form.get('form_kind') or 'caching').strip().lower()

    # Numeric caching options (always override when present)
    if request.form.get('cache_dir_size_mb') is not None:
        options['cache_dir_size_mb'] = as_int('cache_dir_size_mb', int(options.get('cache_dir_size_mb') or 10000))
    if request.form.get('cache_mem_mb') is not None:
        options['cache_mem_mb'] = as_int('cache_mem_mb', int(options.get('cache_mem_mb') or 256))
    if request.form.get('maximum_object_size_mb') is not None:
        options['maximum_object_size_mb'] = as_int('maximum_object_size_mb', int(options.get('maximum_object_size_mb') or 64))
    if request.form.get('maximum_object_size_in_memory_kb') is not None:
        options['maximum_object_size_in_memory_kb'] = as_int('maximum_object_size_in_memory_kb', int(options.get('maximum_object_size_in_memory_kb') or 1024))
    if request.form.get('minimum_object_size_kb') is not None:
        options['minimum_object_size_kb'] = as_int('minimum_object_size_kb', int(options.get('minimum_object_size_kb') if options.get('minimum_object_size_kb') is not None else 0))
    if request.form.get('cache_swap_low') is not None:
        options['cache_swap_low'] = as_int('cache_swap_low', int(options.get('cache_swap_low') or 90))
    if request.form.get('cache_swap_high') is not None:
        options['cache_swap_high'] = as_int('cache_swap_high', int(options.get('cache_swap_high') or 95))

    # Checkbox semantics: if the tab posts them, treat presence as True, absence as False.
    if form_kind in ('caching', 'timeouts'):
        if 'collapsed_forwarding_on' in request.form or form_kind == 'caching':
            options['collapsed_forwarding_on'] = ('collapsed_forwarding_on' in request.form)
        if 'range_cache_on' in request.form or form_kind == 'caching':
            options['range_cache_on'] = ('range_cache_on' in request.form)
        if 'pipeline_prefetch_on' in request.form or form_kind == 'caching':
            options['pipeline_prefetch_on'] = ('pipeline_prefetch_on' in request.form)
        if 'client_persistent_connections_on' in request.form or form_kind == 'caching':
            options['client_persistent_connections_on'] = ('client_persistent_connections_on' in request.form)
        if 'server_persistent_connections_on' in request.form or form_kind == 'caching':
            options['server_persistent_connections_on'] = ('server_persistent_connections_on' in request.form)
        if 'half_closed_clients_on' in request.form or form_kind == 'timeouts':
            options['half_closed_clients_on'] = ('half_closed_clients_on' in request.form)

    # Selects/strings
    if request.form.get('cache_replacement_policy') is not None:
        options['cache_replacement_policy'] = (request.form.get('cache_replacement_policy') or (options.get('cache_replacement_policy') or 'heap GDSF')).strip()
    if request.form.get('memory_replacement_policy') is not None:
        options['memory_replacement_policy'] = (request.form.get('memory_replacement_policy') or (options.get('memory_replacement_policy') or 'heap GDSF')).strip()

    # Optional ints: only override if not blank
    v = as_optional_int('negative_ttl_seconds')
    if v is not None:
        options['negative_ttl_seconds'] = v
    v = as_optional_int('positive_dns_ttl_seconds')
    if v is not None:
        options['positive_dns_ttl_seconds'] = v
    v = as_optional_int('negative_dns_ttl_seconds')
    if v is not None:
        options['negative_dns_ttl_seconds'] = v
    v = as_optional_int('read_ahead_gap_kb')
    if v is not None:
        options['read_ahead_gap_kb'] = v

    # Quick abort (numbers always present on caching form)
    if request.form.get('quick_abort_min_kb') is not None:
        options['quick_abort_min_kb'] = as_int('quick_abort_min_kb', int(options.get('quick_abort_min_kb') if options.get('quick_abort_min_kb') is not None else 0))
    if request.form.get('quick_abort_max_kb') is not None:
        options['quick_abort_max_kb'] = as_int('quick_abort_max_kb', int(options.get('quick_abort_max_kb') if options.get('quick_abort_max_kb') is not None else 0))
    if request.form.get('quick_abort_pct') is not None:
        options['quick_abort_pct'] = as_int('quick_abort_pct', int(options.get('quick_abort_pct') if options.get('quick_abort_pct') is not None else 100))

    # Workers (numbers always present on caching form)
    if request.form.get('workers') is not None:
        workers_i = as_int('workers', int(options.get('workers') or 2))
        if workers_i < 1:
            workers_i = 1
        if workers_i > 4:
            workers_i = 4
        options['workers'] = workers_i

    # Timeouts (seconds)
    if request.form.get('connect_timeout_seconds') is not None:
        options['connect_timeout_seconds'] = as_int('connect_timeout_seconds', int(options.get('connect_timeout_seconds') or 90))
    if request.form.get('request_timeout_seconds') is not None:
        options['request_timeout_seconds'] = as_int('request_timeout_seconds', int(options.get('request_timeout_seconds') or 1800))
    if request.form.get('read_timeout_seconds') is not None:
        options['read_timeout_seconds'] = as_int('read_timeout_seconds', int(options.get('read_timeout_seconds') or 1800))
    if request.form.get('forward_timeout_seconds') is not None:
        options['forward_timeout_seconds'] = as_int('forward_timeout_seconds', int(options.get('forward_timeout_seconds') or 1800))
    if request.form.get('shutdown_lifetime_seconds') is not None:
        options['shutdown_lifetime_seconds'] = as_int('shutdown_lifetime_seconds', int(options.get('shutdown_lifetime_seconds') or 30))

    # Logging
    if request.form.get('logfile_rotate') is not None:
        options['logfile_rotate'] = as_int('logfile_rotate', int(options.get('logfile_rotate') or 10))

    # Network
    if request.form.get('pconn_timeout_seconds') is not None:
        options['pconn_timeout_seconds'] = as_int('pconn_timeout_seconds', int(options.get('pconn_timeout_seconds') or 120))
    if request.form.get('idle_pconn_timeout_seconds') is not None:
        options['idle_pconn_timeout_seconds'] = as_int('idle_pconn_timeout_seconds', int(options.get('idle_pconn_timeout_seconds') or 60))
    if request.form.get('client_lifetime_seconds') is not None:
        options['client_lifetime_seconds'] = as_int('client_lifetime_seconds', int(options.get('client_lifetime_seconds') or 3600))
    if request.form.get('max_filedescriptors') is not None:
        options['max_filedescriptors'] = as_int('max_filedescriptors', int(options.get('max_filedescriptors') or 8192))

    # DNS
    if form_kind == 'dns':
        options['dns_v4_first_on'] = ('dns_v4_first_on' in request.form)
        v = as_optional_str('dns_nameservers')
        if v is not None:
            options['dns_nameservers'] = v
        v = as_optional_str('hosts_file')
        if v is not None:
            options['hosts_file'] = v
    if request.form.get('dns_timeout_seconds') is not None:
        options['dns_timeout_seconds'] = as_int('dns_timeout_seconds', int(options.get('dns_timeout_seconds') or 5))
    if request.form.get('dns_retransmit_seconds') is not None:
        options['dns_retransmit_seconds'] = as_int('dns_retransmit_seconds', int(options.get('dns_retransmit_seconds') or 2))
    if request.form.get('ipcache_size') is not None:
        options['ipcache_size'] = as_int('ipcache_size', int(options.get('ipcache_size') or 8192))
    if request.form.get('fqdncache_size') is not None:
        options['fqdncache_size'] = as_int('fqdncache_size', int(options.get('fqdncache_size') or 8192))

    # SSL
    if request.form.get('dynamic_cert_mem_cache_size_mb') is not None:
        options['dynamic_cert_mem_cache_size_mb'] = as_int('dynamic_cert_mem_cache_size_mb', int(options.get('dynamic_cert_mem_cache_size_mb') or 128))
    if request.form.get('sslcrtd_children') is not None:
        options['sslcrtd_children'] = as_int('sslcrtd_children', int(options.get('sslcrtd_children') or 5))

    # ICAP
    if form_kind == 'icap':
        options['icap_enable_on'] = ('icap_enable_on' in request.form)
        options['icap_send_client_ip_on'] = ('icap_send_client_ip_on' in request.form)
        options['icap_send_client_port_on'] = ('icap_send_client_port_on' in request.form)
        options['icap_send_client_username_on'] = ('icap_send_client_username_on' in request.form)
        options['icap_preview_enable_on'] = ('icap_preview_enable_on' in request.form)
        v = as_optional_int('icap_preview_size_kb')
        if v is not None:
            options['icap_preview_size_kb'] = v
    if request.form.get('icap_connect_timeout_seconds') is not None:
        options['icap_connect_timeout_seconds'] = as_int('icap_connect_timeout_seconds', int(options.get('icap_connect_timeout_seconds') or 60))
    if request.form.get('icap_io_timeout_seconds') is not None:
        options['icap_io_timeout_seconds'] = as_int('icap_io_timeout_seconds', int(options.get('icap_io_timeout_seconds') or 600))

    # Privacy
    if form_kind == 'privacy':
        options['via_on'] = ('via_on' in request.form)
        v = as_optional_str('forwarded_for_value')
        if v is not None:
            options['forwarded_for_value'] = v
        v = as_optional_str('follow_x_forwarded_for_value')
        if v is not None:
            options['follow_x_forwarded_for_value'] = v

    # Limits
    if form_kind == 'limits':
        v = as_optional_int('request_header_max_size_kb')
        if v is not None:
            options['request_header_max_size_kb'] = v
        v = as_optional_int('reply_header_max_size_kb')
        if v is not None:
            options['reply_header_max_size_kb'] = v
        v = as_optional_int('request_body_max_size_mb')
        if v is not None:
            options['request_body_max_size_mb'] = v
        v = as_optional_int('client_request_buffer_max_size_kb')
        if v is not None:
            options['client_request_buffer_max_size_kb'] = v

    # Performance
    if form_kind == 'performance':
        options['memory_pools_on'] = ('memory_pools_on' in request.form)
        v = as_optional_int('memory_pools_limit_mb')
        if v is not None:
            options['memory_pools_limit_mb'] = v
        v = as_optional_int('store_avg_object_size_kb')
        if v is not None:
            options['store_avg_object_size_kb'] = v
        v = as_optional_int('store_objects_per_bucket')
        if v is not None:
            options['store_objects_per_bucket'] = v

    # HTTP
    if form_kind == 'http':
        options['httpd_suppress_version_string_on'] = ('httpd_suppress_version_string_on' in request.form)
        v = as_optional_str('visible_hostname')
        if v is not None:
            options['visible_hostname'] = v

    try:
        # Preserve any previously-applied cache override toggles.
        cur = squid_controller.get_current_config()
        overrides = squid_controller.get_cache_override_options(cur)
        exclusions = get_exclusions_store().list_all()
        config_text = squid_controller.generate_config_from_template_with_exclusions(options, exclusions)
        config_text = squid_controller.apply_cache_overrides(config_text, overrides)
    except Exception:
        return redirect(url_for('squid_config', tab='caching', error='1'))

    ok, _details = squid_controller.apply_config_text(config_text)
    try:
        get_audit_store().record(
            kind='config_apply_template',
            ok=ok,
            remote_addr=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            detail=(_details or '')[:4000],
            config_text=config_text,
        )
    except Exception:
        pass
    target_tab = form_kind if form_kind in ('timeouts', 'logging', 'network', 'dns', 'ssl', 'icap', 'privacy', 'limits', 'performance', 'http') else 'caching'
    if ok:
        return redirect(url_for('squid_config', tab=target_tab, ok='1'))
    return redirect(url_for('squid_config', tab=target_tab, error='1'))


@app.route('/squid/config/apply-overrides', methods=['POST'])
def apply_cache_overrides():
    # Apply cache override toggles on top of the current tunables/exclusions.
    try:
        current = squid_controller.get_current_config()
        tunables = squid_controller.get_tunable_options(current)

        options = _options_from_tunables(tunables)

        exclusions = get_exclusions_store().list_all()
        config_text = squid_controller.generate_config_from_template_with_exclusions(options, exclusions)

        overrides = {
            'client_no_cache': request.form.get('override_client_no_cache') == 'on',
            'origin_private': request.form.get('override_origin_private') == 'on',
            'client_no_store': request.form.get('override_client_no_store') == 'on',
            'origin_no_store': request.form.get('override_origin_no_store') == 'on',
            'origin_no_cache': request.form.get('override_origin_no_cache') == 'on',
            'ignore_auth': request.form.get('override_ignore_auth') == 'on',
        }
        config_text = squid_controller.apply_cache_overrides(config_text, overrides)
    except Exception:
        return redirect(url_for('squid_config', tab='caching', subtab='overrides', error='1'))

    ok, _details = squid_controller.apply_config_text(config_text)
    try:
        get_audit_store().record(
            kind='config_apply_overrides',
            ok=ok,
            remote_addr=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            detail=(_details or '')[:4000],
            config_text=config_text,
        )
    except Exception:
        pass
    if ok:
        return redirect(url_for('squid_config', tab='caching', subtab='overrides', ok='1'))
    return redirect(url_for('squid_config', tab='caching', subtab='overrides', error='1'))


@app.route('/exclusions', methods=['GET', 'POST'])
def exclusions():
    store = get_exclusions_store()

    if request.method == 'POST':
        action = (request.form.get('action') or '').strip()

        if action == 'add_domain':
            store.add_domain(request.form.get('domain') or '')
        elif action == 'remove_domain':
            store.remove_domain(request.form.get('domain') or '')
        elif action == 'add_src':
            store.add_net('src_nets', request.form.get('cidr') or '')
        elif action == 'remove_src':
            store.remove_net('src_nets', request.form.get('cidr') or '')
        elif action == 'toggle_private':
            store.set_exclude_private_nets(request.form.get('exclude_private_nets') == 'on')
        elif action == 'apply':
            # Apply current tunables + exclusions as a regenerated config.
            current = squid_controller.get_current_config()
            tunables = squid_controller.get_tunable_options(current)
            overrides = squid_controller.get_cache_override_options(current)
            options = _options_from_tunables(tunables)
            ex = store.list_all()
            cfg = squid_controller.generate_config_from_template_with_exclusions(options, ex)
            cfg = squid_controller.apply_cache_overrides(cfg, overrides)
            ok, _ = squid_controller.apply_config_text(cfg)
            try:
                get_audit_store().record(
                    kind='config_apply_exclusions',
                    ok=ok,
                    remote_addr=request.remote_addr,
                    user_agent=request.headers.get('User-Agent'),
                    config_text=cfg,
                )
            except Exception:
                pass
            return redirect(url_for('exclusions', ok='1' if ok else None, error='1' if not ok else None))

        return redirect(url_for('exclusions'))

    ex = store.list_all()
    return render_template('exclusions.html', ex=ex)


@app.route('/proxy.pac', methods=['GET'])
def proxy_pac():
    # NOTE: Squid cannot force a client to "bypass the proxy" for some destinations when the client is
    # explicitly configured to use the proxy. A PAC file is the usual way to implement bypass behavior.
    #
    # This endpoint dynamically selects which PAC to return based on the *requester's* source IP (server-side).
    # The PAC logic itself remains destination-based (runs on the client).

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

    def _build_pac(proxy_str: str, *, direct_domains: list[str], direct_dst_nets: list[str], include_private: bool) -> str:
        lines: list[str] = []
        lines.append("function FindProxyForURL(url, host) {")
        lines.append("  host = host.toLowerCase();")

        # Always bypass local/loopback. The Windows "bypass proxy for local addresses" checkbox does not
        # reliably apply when a PAC script is used, and many apps use WinHTTP which ignores that checkbox.
        lines.append("  if (host === 'localhost' || host === '127.0.0.1' || host === '::1') return 'DIRECT';")
        lines.append("  if (isPlainHostName(host)) return 'DIRECT';")

        lines.append("  var ip = dnsResolve(host);")
        lines.append("  if (ip && isInNet(ip, '127.0.0.0', '255.0.0.0')) return 'DIRECT';")

        for d in direct_domains:
            # Match domain and subdomains
            lines.append(f"  if (dnsDomainIs(host, '{d}') || shExpMatch(host, '*.{d}')) return 'DIRECT';")

        for cidr in direct_dst_nets:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                if getattr(net, 'version', 4) != 4:
                    continue
                net_addr = str(net.network_address)
                mask = _cidr_to_mask(cidr)
                lines.append(f"  if (ip && isInNet(ip, '{net_addr}', '{mask}')) return 'DIRECT';")
            except Exception:
                continue

        if include_private:
            # Optional: bypass RFC1918 + link-local destinations.
            lines.append("  if (ip && isInNet(ip, '10.0.0.0', '255.0.0.0')) return 'DIRECT';")
            lines.append("  if (ip && isInNet(ip, '172.16.0.0', '255.240.0.0')) return 'DIRECT';")
            lines.append("  if (ip && isInNet(ip, '192.168.0.0', '255.255.0.0')) return 'DIRECT';")
            lines.append("  if (ip && isInNet(ip, '169.254.0.0', '255.255.0.0')) return 'DIRECT';")

        lines.append(f"  return '{proxy_str}';")
        lines.append("}")
        return "\n".join(lines) + "\n"

    host = (request.host.split(':')[0] or '127.0.0.1').strip()
    http_proxy = f"PROXY {host}:3128"
    http_chain = f"{http_proxy}; DIRECT"

    # Try dynamic PAC profiles first.
    prof = None
    try:
        prof = get_pac_profiles_store().match_profile_for_client_ip(_requester_ip())
    except Exception:
        prof = None

    if prof is not None:
        # Optional SOCKS5 in the return chain.
        proxy_chain = http_chain
        try:
            if bool(getattr(prof, 'socks_enabled', False)):
                socks_host = (getattr(prof, 'socks_host', '') or '').strip() or host
                socks_port = int(getattr(prof, 'socks_port', 1080) or 1080)
                proxy_chain = f"SOCKS5 {socks_host}:{socks_port}; {http_proxy}; DIRECT"
        except Exception:
            proxy_chain = http_chain

        pac = _build_pac(
            proxy_chain,
            direct_domains=list(getattr(prof, 'direct_domains', []) or []),
            direct_dst_nets=list(getattr(prof, 'direct_dst_nets', []) or []),
            include_private=False,
        )
        return app.response_class(pac, mimetype='application/x-ns-proxy-autoconfig')

    # Legacy fallback: build PAC from Exclusions.
    ex = get_exclusions_store().list_all()
    pac = _build_pac(
        http_chain,
        direct_domains=[d for d in ex.domains],
        direct_dst_nets=[],
        include_private=bool(getattr(ex, 'exclude_private_nets', False)),
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
        action = (request.form.get('action') or '').strip()
        try:
            if action == 'create':
                ok, err, _ = store.upsert_profile(
                    profile_id=None,
                    name=request.form.get('name') or '',
                    client_cidr=request.form.get('client_cidr') or '',
                    socks_enabled=(request.form.get('socks_enabled') == 'on'),
                    socks_host=request.form.get('socks_host') or '',
                    socks_port=request.form.get('socks_port') or '',
                    direct_domains_text=request.form.get('direct_domains') or '',
                    direct_dst_nets_text=request.form.get('direct_dst_nets') or '',
                )
                if not ok:
                    return redirect(url_for('pac_builder', error='1', msg=err))
                return redirect(url_for('pac_builder', ok='1'))

            if action == 'update':
                pid = int(request.form.get('profile_id') or '0')
                ok, err, _ = store.upsert_profile(
                    profile_id=pid,
                    name=request.form.get('name') or '',
                    client_cidr=request.form.get('client_cidr') or '',
                    socks_enabled=(request.form.get('socks_enabled') == 'on'),
                    socks_host=request.form.get('socks_host') or '',
                    socks_port=request.form.get('socks_port') or '',
                    direct_domains_text=request.form.get('direct_domains') or '',
                    direct_dst_nets_text=request.form.get('direct_dst_nets') or '',
                )
                if not ok:
                    return redirect(url_for('pac_builder', error='1', msg=err))
                return redirect(url_for('pac_builder', ok='1'))

            if action == 'delete':
                pid = int(request.form.get('profile_id') or '0')
                store.delete_profile(pid)
                return redirect(url_for('pac_builder', ok='1'))
        except Exception as e:
            return redirect(url_for('pac_builder', error='1', msg=f"{type(e).__name__}: {e}"))

        return redirect(url_for('pac_builder'))

    profiles = []
    try:
        profiles = store.list_profiles()
    except Exception:
        profiles = []

    pac_url = (request.url_root.rstrip('/') + url_for('proxy_pac'))
    return render_template('pac.html', profiles=profiles, pac_url=pac_url)


def _cidr_to_mask(cidr: str) -> str:
    # Convert v4 CIDR to dotted mask for PAC's isInNet().
    try:
        import ipaddress

        net = ipaddress.ip_network(cidr, strict=False)
        if net.version != 4:
            return '255.255.255.255'
        return str(net.netmask)
    except Exception:
        return '255.255.255.255'

@app.route('/status')
def status():
    return redirect(url_for('index') + '#status')


@app.route('/api/timeseries', methods=['GET'])
def api_timeseries():
    res = (request.args.get('resolution') or '1s').strip()
    window = request.args.get('window') or '60'
    limit = request.args.get('limit') or '500'
    try:
        window_i = max(10, min(365 * 24 * 3600, int(window)))
    except ValueError:
        window_i = 60
    try:
        limit_i = int(limit)
    except ValueError:
        limit_i = 500

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
    window_s = (request.args.get('window') or '3600').strip()

    try:
        window_i = max(300, min(7 * 24 * 3600, int(window_s)))
    except ValueError:
        window_i = 3600
    since_ts = int(time.time()) - window_i

    try:
        limit_i = max(10, min(500, int(limit)))
    except ValueError:
        limit_i = 100

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
    )


@app.route('/live/export', methods=['GET'])
def live_export():
    store = get_store()
    mode = (request.args.get('mode') or 'domains').strip().lower()
    search = (request.args.get('q') or '').strip().lower()
    window_s = (request.args.get('window') or '3600').strip()
    try:
        window_i = max(300, min(7 * 24 * 3600, int(window_s)))
    except ValueError:
        window_i = 3600
    since_ts = int(time.time()) - window_i
    rows = store.export_rows(mode, since=since_ts, search=search, limit=1000)

    def to_csv(data: list[dict]) -> str:
        headers = list(data[0].keys()) if data else []
        buf = io.StringIO()
        w = csv.writer(buf, delimiter=";", lineterminator="\n")
        w.writerow(headers)
        for r in data:
            w.writerow([r.get(h, "") for h in headers])
        return buf.getvalue()

    body = to_csv(rows)
    return app.response_class(body, mimetype='text/csv; charset=utf-8')


@app.route('/reload', methods=['POST'])
def reload_squid():
    squid_controller.reload_squid()
    return redirect(url_for('index') + '#status')


@app.route('/cache/clear', methods=['POST'])
def clear_caches():
    # Clear Squid disk cache (best-effort) and restart Squid.
    try:
        squid_controller.clear_disk_cache()
    except Exception:
        pass
    return redirect(url_for('index') + '#status')

@app.route('/certs', methods=['GET'])
def certs():
    certificate = "ca.crt" if cert_manager.ca_exists() else None
    message = request.args.get('msg')
    message_ok = request.args.get('ok') == '1'
    return render_template('certs.html', certificate=certificate, message=message, message_ok=message_ok)


@app.route('/certs/generate', methods=['POST'])
def generate_certificate():
    cert_manager.ensure_ca()
    try:
        get_audit_store().record(
            kind='ca_ensure',
            ok=True,
            remote_addr=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
        )
    except Exception:
        pass
    return redirect(url_for('certs'))


@app.route('/certs/upload', methods=['POST'])
def upload_certificate_pfx():
    # Upload a PKCS#12 bundle containing cert + private key and install it as Squid's CA.
    pfx_file = request.files.get('pfx')
    password = request.form.get('pfx_password', '')

    if not pfx_file or not getattr(pfx_file, 'filename', ''):
        return redirect(url_for('certs', ok='0', msg='No PFX file selected.'))

    filename = (pfx_file.filename or '').lower()
    _, ext = os.path.splitext(filename)
    if ext not in ['.pfx', '.p12']:
        return redirect(url_for('certs', ok='0', msg='Unsupported file type. Please upload a .pfx or .p12.'))

    # Basic guard against accidental huge uploads.
    if request.content_length is not None and request.content_length > (10 * 1024 * 1024):
        return redirect(url_for('certs', ok='0', msg='Upload too large (max 10MB).'))

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
                return redirect(url_for('certs', ok='0', msg='Upload too large (max 10MB).'))
    except Exception:
        return redirect(url_for('certs', ok='0', msg='Failed to read upload.'))

    pfx_bytes = bytes(buf)
    result = install_pfx_as_ca(cert_manager.ca_dir, pfx_bytes, password=password)

    if result.ok:
        try:
            squid_controller.reload_squid()
        except Exception:
            pass

    try:
        get_audit_store().record(
            kind='ca_upload_pfx',
            ok=result.ok,
            remote_addr=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            details={'message': result.message},
        )
    except Exception:
        pass

    return redirect(url_for('certs', ok='1' if result.ok else '0', msg=result.message))


@app.route('/certs/download/<path:filename>', methods=['GET'])
def download_certificate(filename: str):
    # Only allow downloading the public CA cert
    if filename != 'ca.crt':
        abort(404)
    cert_manager.ensure_ca()
    return send_file(cert_manager.ca_cert_path, as_attachment=True, download_name='squid-proxy-ca.crt')


@app.route('/administration', methods=['GET', 'POST'])
def administration():
    store = _auth_store
    current_user = (session.get('user') or '').strip()

    if request.method == 'POST':
        action = (request.form.get('action') or '').strip()
        try:
            if action == 'add_user':
                username = (request.form.get('username') or '').strip()
                password = request.form.get('password') or ''
                store.add_user(username, password)
                return redirect(url_for('administration', ok='1', msg='User added.'))

            if action == 'set_password':
                username = (request.form.get('username') or '').strip()
                new_password = request.form.get('new_password') or ''
                store.set_password(username, new_password)
                return redirect(url_for('administration', ok='1', msg='Password updated.'))

            if action == 'delete_user':
                username = (request.form.get('username') or '').strip()
                if username == current_user or username.casefold() == current_user.casefold():
                    return redirect(url_for('administration', ok='0', msg='Cannot remove the currently signed-in user.'))
                users = store.list_users()
                if len(users) <= 1:
                    return redirect(url_for('administration', ok='0', msg='Cannot remove the last user.'))
                store.delete_user(username)
                return redirect(url_for('administration', ok='1', msg='User removed.'))

            return redirect(url_for('administration', ok='0', msg='Unknown action.'))
        except Exception as e:
            app.logger.exception("Administration action failed")
            return redirect(url_for('administration', ok='0', msg=public_error_message(e)))

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