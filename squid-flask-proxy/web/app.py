from flask import Flask, render_template, request, redirect, url_for, jsonify, send_file, abort
from services.squidctl import SquidController
from services.cert_manager import CertManager
import datetime
import time
import os
import ipaddress
import struct
from services.stats import get_stats
from services.live_stats import get_store
from services.exclusions_store import get_exclusions_store
from services.audit_store import get_audit_store
from services.timeseries_store import get_timeseries_store
from services.ssl_errors_store import get_ssl_errors_store
from services.socks_store import get_socks_store
from services.adblock_store import get_adblock_store
from services.preload_store import get_preload_store
from services.clamav_store import get_clamav_store

import socket
import re
from typing import Any, Dict

app = Flask(__name__)
squid_controller = SquidController()
cert_manager = CertManager()


def _options_from_tunables(tunables: Dict[str, Any]) -> Dict[str, Any]:
    # Centralize the Squid template option defaults derived from an existing config.
    # Keep behavior identical to the prior inline dicts.
    return {
        'cache_dir_size_mb': tunables.get('cache_dir_size_mb') or 10000,
        'cache_mem_mb': tunables.get('cache_mem_mb') or 256,
        'maximum_object_size_mb': tunables.get('maximum_object_size_mb') or 64,
        'maximum_object_size_in_memory_kb': tunables.get('maximum_object_size_in_memory_kb') or 1024,
        'cache_swap_low': tunables.get('cache_swap_low') or 90,
        'cache_swap_high': tunables.get('cache_swap_high') or 95,
        'collapsed_forwarding_on': bool(tunables.get('collapsed_forwarding') if tunables.get('collapsed_forwarding') is not None else True),
        'range_cache_on': (tunables.get('range_offset_limit') == -1) if tunables.get('range_offset_limit') is not None else True,
        'workers': min(4, max(1, int(tunables.get('workers') or 2))),
        'cache_replacement_policy': tunables.get('cache_replacement_policy') or 'heap GDSF',
        'memory_replacement_policy': tunables.get('memory_replacement_policy') or 'heap GDSF',
        'pipeline_prefetch_on': bool(tunables.get('pipeline_prefetch') if tunables.get('pipeline_prefetch') is not None else True),
        'quick_abort_min_kb': tunables.get('quick_abort_min_kb') if tunables.get('quick_abort_min_kb') is not None else 0,
        'quick_abort_max_kb': tunables.get('quick_abort_max_kb') if tunables.get('quick_abort_max_kb') is not None else 0,
        'quick_abort_pct': tunables.get('quick_abort_pct') if tunables.get('quick_abort_pct') is not None else 100,
    }

_disable_background = (os.environ.get('DISABLE_BACKGROUND') or '').strip() == '1'

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

    icap_health = _check_icap_respmod()
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
            store.request_refresh_now()
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
    )


def _check_icap_service(host: str = "127.0.0.1", port: int = 1344, service: str = "/respmod"):
    # Best-effort local health check: connect and issue ICAP OPTIONS.
    # Keep timeouts tight so the UI can't hang.
    path = (service or "/respmod")
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


def _check_icap_respmod(host: str = "127.0.0.1", port: int = 1344, service: str = "/respmod"):
    return _check_icap_service(host=host, port=port, service=service)


def _send_sample_respmod(service: str = "/respmod") -> Dict[str, Any]:
    host = os.environ.get('ICAP_HOST', '127.0.0.1')
    port = int(os.environ.get('ICAP_PORT', 1344))
    path = service or '/respmod'
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


def _check_clamd() -> Dict[str, Any]:
    # Best-effort health check: PING the clamd unix socket.
    sock_path = '/var/lib/squid-flask-proxy/clamav/clamd.sock'
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(0.6)
        s.connect(sock_path)
        s.sendall(b"PING\n")
        data = s.recv(64)
        s.close()
        ok = data.startswith(b"PONG")
        return {"ok": bool(ok), "detail": (data.decode('ascii', errors='replace').strip() or 'no data')}
    except Exception as e:
        return {"ok": False, "detail": f"{type(e).__name__}: {e}"}


def _test_eicar() -> Dict[str, Any]:
    # Send EICAR string via clamd INSTREAM to verify detection.
    sock_path = '/var/lib/squid-flask-proxy/clamav/clamd.sock'
    data = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(1.5)
        s.connect(sock_path)
        s.sendall(b"zINSTREAM\0")
        s.sendall(struct.pack("!I", len(data)))
        s.sendall(data)
        s.sendall(struct.pack("!I", 0))
        resp = s.recv(512)
        s.close()
        text = resp.decode('ascii', errors='replace') if resp else ''
        ok = ('Eicar' in text) or ('FOUND' in text)
        return {"ok": ok, "detail": text or 'no data'}
    except Exception as e:
        return {"ok": False, "detail": f"{type(e).__name__}: {e}"}


@app.route('/clamav', methods=['GET'])
def clamav():
    try:
        stats = get_clamav_store().summary()
    except Exception:
        stats = None

    store = get_clamav_store()
    try:
        settings = store.get_settings()
    except Exception:
        settings = {"max_scan_bytes": 134217728}

    clamd_health = _check_clamd()
    icap_health = _check_icap_service(
        host=os.environ.get('ICAP_HOST', '127.0.0.1'),
        port=int(os.environ.get('ICAP_PORT', 1344)),
        service='/avrespmod',
    )

    ok = bool(clamd_health.get('ok')) and bool(icap_health.get('ok'))
    detail = f"clamd={clamd_health.get('detail')} | icap={icap_health.get('detail')}"

    cfg = squid_controller.get_current_config() or ""
    clamav_enabled = _is_clamav_enabled(cfg)
    return render_template(
        'clamav.html',
        stats=stats,
        health={"ok": ok, "detail": detail},
        clamav_enabled=clamav_enabled,
        settings=settings,
        eicar_result=request.args.get('eicar'),
        eicar_detail=request.args.get('eicar_detail'),
        icap_result=request.args.get('icap_sample'),
        icap_detail=request.args.get('icap_detail'),
    )


@app.route('/clamav/settings', methods=['POST'])
def clamav_settings():
    # Web-configurable setting (no env vars): max scan size in MiB.
    v = (request.form.get('max_scan_mib') or '').strip()
    try:
        mib = int(v)
    except Exception:
        mib = 128
    if mib < 1:
        mib = 1
    if mib > 2048:
        mib = 2048
    get_clamav_store().set_settings(max_scan_bytes=mib * 1024 * 1024)
    return redirect(url_for('clamav'))


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
    res = _send_sample_respmod(service='/avrespmod')
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


@app.route('/icap/preload', methods=['GET'])
def icap_preload():
    try:
        stats = get_preload_store().summary()
    except Exception:
        stats = None
    health = _check_icap_respmod()
    cfg = squid_controller.get_current_config() or ""
    preload_enabled = _is_preload_enabled(cfg)
    return render_template(
        'icap_preload.html',
        stats=stats,
        health=health,
        preload_enabled=preload_enabled,
        sample_result=request.args.get('sample'),
        sample_detail=request.args.get('sample_detail'),
    )


@app.route('/icap/preload/test', methods=['POST'])
def icap_preload_test():
    res = _send_sample_respmod(service=os.environ.get('ICAP_PRELOAD_PATH', '/respmod'))
    return redirect(
        url_for(
            'icap_preload',
            sample='ok' if res.get('ok') else 'fail',
            sample_detail=(res.get('detail') or '')[:300],
        )
    )


_PRELOAD_ALLOW_RE = re.compile(r"^(\s*)(#\s*)?(adaptation_access\s+html_preload_set\s+allow\b.*)$", re.I | re.M)
_PRELOAD_DENY_RE = re.compile(r"^\s*(#\s*)?adaptation_access\s+html_preload_set\s+deny\s+all\s*$", re.I | re.M)


def _is_preload_enabled(cfg_text: str) -> bool:
    # Enabled if there's an uncommented allow rule for html_preload_set.
    m = _PRELOAD_ALLOW_RE.search(cfg_text or "")
    if not m:
        return False
    comment_prefix = (m.group(2) or "").strip()
    return comment_prefix == ""


def _set_preload_enabled(cfg_text: str, enabled: bool) -> str:
    text = cfg_text or ""

    def repl(m: re.Match) -> str:
        indent = m.group(1) or ""
        rule = m.group(3) or ""
        if enabled:
            return indent + rule
        return indent + "# " + rule

    if _PRELOAD_ALLOW_RE.search(text):
        return _PRELOAD_ALLOW_RE.sub(repl, text, count=1)

    # If the allow rule is missing and we're enabling, insert a default allow rule.
    if enabled:
        allow_line = "adaptation_access html_preload_set allow icap_adblockable icap_resp_html"
        deny_match = _PRELOAD_DENY_RE.search(text)
        if deny_match:
            insert_at = deny_match.start()
            return text[:insert_at] + allow_line + "\n" + text[insert_at:]
        return text.rstrip() + "\n" + allow_line + "\n"

    return text


@app.route('/icap/preload/toggle', methods=['POST'])
def icap_preload_toggle():
    action = (request.form.get('action') or '').strip().lower()
    cfg = squid_controller.get_current_config() or ""
    currently_enabled = _is_preload_enabled(cfg)

    if action == 'enable':
        desired = True
    elif action == 'disable':
        desired = False
    else:
        desired = (not currently_enabled)

    new_cfg = _set_preload_enabled(cfg, desired)
    ok, _details = squid_controller.apply_config_text(new_cfg)
    if ok:
        return redirect(url_for('icap_preload'))
    # Keep it minimal: just redirect back; status will show unchanged.
    return redirect(url_for('icap_preload', error='1'))

@app.route('/squid/config', methods=['GET', 'POST'])
def squid_config():
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
                return redirect(url_for('squid_config', ok='1'))
            return redirect(url_for('squid_config', error='1'))
    current_config = squid_controller.get_current_config()
    tunables = squid_controller.get_tunable_options(current_config)
    overrides = squid_controller.get_cache_override_options(current_config)
    exclusions = get_exclusions_store().list_all()
    exclusions_count = len(getattr(exclusions, 'domains', []) or []) + len(getattr(exclusions, 'dst_nets', []) or []) + len(getattr(exclusions, 'src_nets', []) or [])
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
    return render_template('squid_config.html', config_text=config_text, tunables=tunables, overrides=overrides, subtab=subtab, summary=summary, validation=validation, exclusions=exclusions)


@app.route('/squid/config/apply-safe', methods=['POST'])
def apply_safe_caching():
    def as_int(name: str, default: int) -> int:
        v = (request.form.get(name) or '').strip()
        try:
            return int(v)
        except ValueError:
            return default

    workers_i = as_int('workers', 2)
    if workers_i < 1:
        workers_i = 1
    if workers_i > 4:
        workers_i = 4

    options = {
        'cache_dir_size_mb': as_int('cache_dir_size_mb', 10000),
        'cache_mem_mb': as_int('cache_mem_mb', 256),
        'maximum_object_size_mb': as_int('maximum_object_size_mb', 64),
        'maximum_object_size_in_memory_kb': as_int('maximum_object_size_in_memory_kb', 1024),
        'cache_swap_low': as_int('cache_swap_low', 90),
        'cache_swap_high': as_int('cache_swap_high', 95),
        'collapsed_forwarding_on': request.form.get('collapsed_forwarding_on') == 'on',
        'range_cache_on': request.form.get('range_cache_on') == 'on',
        'workers': workers_i,
        'cache_replacement_policy': (request.form.get('cache_replacement_policy') or 'heap GDSF').strip(),
        'memory_replacement_policy': (request.form.get('memory_replacement_policy') or 'heap GDSF').strip(),
        'pipeline_prefetch_on': request.form.get('pipeline_prefetch_on') == 'on',
        'quick_abort_min_kb': as_int('quick_abort_min_kb', 0),
        'quick_abort_max_kb': as_int('quick_abort_max_kb', 0),
        'quick_abort_pct': as_int('quick_abort_pct', 100),
    }

    try:
        # Preserve any previously-applied cache override toggles.
        cur = squid_controller.get_current_config()
        overrides = squid_controller.get_cache_override_options(cur)
        exclusions = get_exclusions_store().list_all()
        config_text = squid_controller.generate_config_from_template_with_exclusions(options, exclusions)
        config_text = squid_controller.apply_cache_overrides(config_text, overrides)
    except Exception:
        return redirect(url_for('squid_config', error='1'))

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
    if ok:
        return redirect(url_for('squid_config', ok='1'))
    return redirect(url_for('squid_config', error='1'))


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
        }
        config_text = squid_controller.apply_cache_overrides(config_text, overrides)
    except Exception:
        return redirect(url_for('squid_config', subtab='overrides', error='1'))

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
        return redirect(url_for('squid_config', subtab='overrides', ok='1'))
    return redirect(url_for('squid_config', subtab='overrides', error='1'))


@app.route('/exclusions', methods=['GET', 'POST'])
def exclusions():
    store = get_exclusions_store()

    if request.method == 'POST':
        action = (request.form.get('action') or '').strip()

        if action == 'add_domain':
            store.add_domain(request.form.get('domain') or '')
        elif action == 'remove_domain':
            store.remove_domain(request.form.get('domain') or '')
        elif action == 'add_dst':
            store.add_net('dst_nets', request.form.get('cidr') or '')
        elif action == 'remove_dst':
            store.remove_net('dst_nets', request.form.get('cidr') or '')
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
    host = (request.host.split(':')[0] or '127.0.0.1').strip()
    proxy = f"PROXY {host}:3128; DIRECT"
    store = get_exclusions_store()
    ex = store.list_all()

    # For PAC, we only use destination-based checks (domain + dst nets). Client-src based bypass is not
    # possible in PAC (it runs on the client without reliable client IP).
    domains = [d for d in ex.domains]
    dst_nets = [c for c in ex.dst_nets]

    lines = []
    lines.append("function FindProxyForURL(url, host) {")
    lines.append("  host = host.toLowerCase();")

    # Always bypass local/loopback. The Windows "bypass proxy for local addresses" checkbox does not
    # reliably apply when a PAC script is used, and many apps use WinHTTP which ignores that checkbox.
    lines.append("  if (host === 'localhost' || host === '127.0.0.1' || host === '::1') return 'DIRECT';")
    lines.append("  if (isPlainHostName(host)) return 'DIRECT';")

    lines.append("  var ip = dnsResolve(host);")
    lines.append("  if (ip && isInNet(ip, '127.0.0.0', '255.0.0.0')) return 'DIRECT';")
    for d in domains:
        # Match domain and subdomains
        lines.append(f"  if (dnsDomainIs(host, '{d}') || shExpMatch(host, '*.{d}')) return 'DIRECT';")
    for c in dst_nets:
        # ip subnet checks require dnsResolve(host)
        lines.append(f"  if (ip && isInNet(ip, '{c.split('/')[0]}', '{_cidr_to_mask(c)}')) return 'DIRECT';")

    # Optional: bypass RFC1918 + link-local destinations when enabled in Exclusions.
    if getattr(ex, 'exclude_private_nets', False):
        lines.append("  if (ip && isInNet(ip, '10.0.0.0', '255.0.0.0')) return 'DIRECT';")
        lines.append("  if (ip && isInNet(ip, '172.16.0.0', '255.240.0.0')) return 'DIRECT';")
        lines.append("  if (ip && isInNet(ip, '192.168.0.0', '255.255.0.0')) return 'DIRECT';")
        lines.append("  if (ip && isInNet(ip, '169.254.0.0', '255.255.0.0')) return 'DIRECT';")
    lines.append(f"  return '{proxy}';")
    lines.append("}")

    pac = "\n".join(lines) + "\n"
    return app.response_class(pac, mimetype='application/x-ns-proxy-autoconfig')


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
        out = [";".join(headers)]
        for r in data:
            out.append(";".join([str(r.get(h, '')) for h in headers]))
        return "\n".join(out)

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
    return render_template('certs.html', certificate=certificate)


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


@app.route('/certs/download/<path:filename>', methods=['GET'])
def download_certificate(filename: str):
    # Only allow downloading the public CA cert
    if filename != 'ca.crt':
        abort(404)
    cert_manager.ensure_ca()
    return send_file(cert_manager.ca_cert_path, as_attachment=True, download_name='squid-proxy-ca.crt')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)