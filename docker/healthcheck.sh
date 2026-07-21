#!/bin/sh

# Healthcheck script for the Squid and Flask services

set -eu

has_listen_socket() {
    PORT="$1" python3 - <<'PY'
import os

port = int(os.environ['PORT'])

def has_listen_socket(path: str, port: int) -> bool:
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            next(f, None)
            for line in f:
                parts = line.split()
                if len(parts) < 4:
                    continue
                local_addr = parts[1]
                state = parts[3]
                if state != '0A':
                    continue
                _addr, port_hex = local_addr.rsplit(':', 1)
                if int(port_hex, 16) == port:
                    return True
    except FileNotFoundError:
        return False
    return False

assert has_listen_socket('/proc/net/tcp', port) or has_listen_socket('/proc/net/tcp6', port)
PY
}

check_squid_http_listeners() {
    SQUID_CONFIG_PATH="${SQUID_CONFIG_PATH:-/etc/squid/squid.conf}" python3 - <<'PY'
import os


def has_listen_socket(path: str, port: int) -> bool:
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            next(f, None)
            for line in f:
                parts = line.split()
                if len(parts) < 4:
                    continue
                local_addr = parts[1]
                state = parts[3]
                if state != '0A':
                    continue
                _addr, port_hex = local_addr.rsplit(':', 1)
                if int(port_hex, 16) == int(port):
                    return True
    except FileNotFoundError:
        return False
    return False


def logical_lines(text: str):
    pending = []
    for raw in text.splitlines():
        pending.append(raw)
        if raw.rstrip().endswith('\\'):
            continue
        yield ' '.join(line.rstrip().rstrip('\\').strip() for line in pending).strip()
        pending = []
    if pending:
        yield ' '.join(line.rstrip().rstrip('\\').strip() for line in pending).strip()


def parse_port(token: str):
    token = (token or '').strip()
    if token.isdigit():
        return int(token)
    if token.startswith('[') and ']:' in token:
        candidate = token.rsplit(':', 1)[1]
    elif ':' in token:
        candidate = token.rsplit(':', 1)[1]
    else:
        return None
    return int(candidate) if candidate.isdigit() else None


def coerce_port(value, default):
    try:
        parsed = int(str(value or '').strip() or str(default))
    except Exception:
        parsed = int(default)
    return min(65535, max(1, parsed))


def env_enabled(value):
    return str(value or '').strip().lower() in {'1', 'true', 'yes', 'on'}


config_path = os.environ.get('SQUID_CONFIG_PATH') or '/etc/squid/squid.conf'
try:
    with open(config_path, 'r', encoding='utf-8', errors='replace') as handle:
        text = handle.read()
except FileNotFoundError:
    text = ''

ports = []
for logical in logical_lines(text):
    stripped = logical.strip()
    if not stripped or stripped.startswith('#'):
        continue
    lower = stripped.lower()
    if not lower.startswith(('http_port ', 'https_port ')):
        continue
    parts = stripped.split()
    if len(parts) < 2:
        continue
    port = parse_port(parts[1])
    if port and 1 <= port <= 65535 and port not in ports:
        ports.append(port)

if not ports:
    explicit_port = coerce_port(os.environ.get('SQUID_HTTP_PORT'), 3128)
    ports = [explicit_port]
    if env_enabled(os.environ.get('SQUID_INTERCEPT_ENABLED')):
        intercept_port = coerce_port(os.environ.get('SQUID_INTERCEPT_PORT'), explicit_port + 1 if explicit_port < 65535 else 3129)
        if intercept_port not in ports:
            ports.append(intercept_port)

missing = [port for port in ports if not (has_listen_socket('/proc/net/tcp', port) or has_listen_socket('/proc/net/tcp6', port))]
if missing:
    raise SystemExit(f"Squid listener(s) not accepting connections on port(s): {', '.join(map(str, missing))}")
PY
}

check_icap_readiness() {
    if [ ! -x /usr/local/bin/icap_readiness.py ]; then
        return 0
    fi
    /usr/local/bin/icap_readiness.py check \
        --config "${SQUID_ICAP_INCLUDE_PATH:-/etc/squid/conf.d/20-icap.conf}" \
        --probe-timeout "${SQUID_ICAP_READY_HEALTH_PROBE_TIMEOUT_SECONDS:-0.35}"
}

check_squid_forwarding_path() {
    SQUID_CONFIG_PATH="${SQUID_CONFIG_PATH:-/etc/squid/squid.conf}" python3 - <<'PY'
import os
import json
import socket


def logical_lines(text: str):
    pending = []
    for raw in text.splitlines():
        pending.append(raw)
        if raw.rstrip().endswith('\\'):
            continue
        yield ' '.join(line.rstrip().rstrip('\\').strip() for line in pending).strip()
        pending = []
    if pending:
        yield ' '.join(line.rstrip().rstrip('\\').strip() for line in pending).strip()


def parse_port(token: str):
    token = (token or '').strip()
    if token.isdigit():
        return int(token)
    if token.startswith('[') and ']:' in token:
        candidate = token.rsplit(':', 1)[1]
    elif ':' in token:
        candidate = token.rsplit(':', 1)[1]
    else:
        return None
    return int(candidate) if candidate.isdigit() else None


def response_ports(config_path: str):
    try:
        with open(config_path, 'r', encoding='utf-8', errors='replace') as handle:
            text = handle.read()
    except FileNotFoundError:
        text = ''
    ports = []
    for logical in logical_lines(text):
        stripped = logical.strip()
        if not stripped or stripped.startswith('#'):
            continue
        lower = stripped.lower()
        if not lower.startswith('http_port '):
            continue
        parts = stripped.split()
        if len(parts) < 2:
            continue
        modes = {part.strip().lower() for part in parts[2:]}
        if {'intercept', 'tproxy'} & modes:
            continue
        port = parse_port(parts[1])
        if port and 1 <= port <= 65535 and port not in ports:
            ports.append(port)
    try:
        fallback = int((os.environ.get('SQUID_HTTP_PORT') or '3128').strip() or '3128')
    except Exception:
        fallback = 3128
    if fallback < 1 or fallback > 65535:
        fallback = 3128
    return ports or [fallback]


def forwarding_canary_url() -> str:
    host = (os.environ.get('FORWARDING_CANARY_HOST') or '127.0.0.1').strip() or '127.0.0.1'
    if host in {'0.0.0.0', '::', '[::]', '::1', '[::1]'}:
        host = '127.0.0.1'
    display_host = f'[{host}]' if ':' in host and not host.startswith('[') else host
    try:
        port = int((os.environ.get('FORWARDING_CANARY_PORT') or '18080').strip() or '18080')
    except Exception:
        port = 18080
    if port < 1 or port > 65535:
        port = 18080
    path = (os.environ.get('FORWARDING_CANARY_PATH') or '/__docker_proxy_forwarding_canary').strip()
    if not path.startswith('/') or '?' in path or '#' in path or '\\' in path:
        path = '/__docker_proxy_forwarding_canary'
    return f'http://{display_host}:{port}{path}?probe=squid-respmod'


target_url = forwarding_canary_url()
last_error = ''
for port in response_ports(os.environ.get('SQUID_CONFIG_PATH') or '/etc/squid/squid.conf'):
    try:
        with socket.create_connection(('127.0.0.1', int(port)), timeout=2.0) as sock:
            sock.settimeout(2.0)
            sock.sendall(
                (
                    f'GET {target_url} HTTP/1.1\r\n'
                    'Host: 127.0.0.1:18080\r\n'
                    'User-Agent: squid-flask-proxy-forwarding-health\r\n'
                    'Accept: application/json, */*;q=0.1\r\n'
                    'Cache-Control: no-cache\r\n'
                    'Pragma: no-cache\r\n'
                    'Connection: close\r\n\r\n'
                ).encode('ascii', errors='replace')
            )
            data = b''
            while len(data) < 4096:
                chunk = sock.recv(min(512, 4096 - len(data)))
                if not chunk:
                    break
                data += chunk
        status = data.split(b'\r\n', 1)[0].split(b'\n', 1)[0].decode('ascii', errors='replace')
        parts = status.split()
        code = int(parts[1]) if len(parts) > 1 else 0
        if status.startswith('HTTP/') and 200 <= code < 400:
            body = data.split(b'\r\n\r\n', 1)[1] if b'\r\n\r\n' in data else b''
            payload = json.loads(body.decode('utf-8'))
            if payload.get('ok') is True and payload.get('service') == 'docker-proxy-forwarding-canary' and payload.get('probe') == 'squid-respmod':
                raise SystemExit(0)
            last_error = f'port {port}: canary body did not confirm ok'
            continue
        last_error = f'port {port}: {status or "no HTTP status"}'
    except Exception as exc:
        last_error = f'port {port}: {exc}'
raise SystemExit(f'Squid explicit forwarding path failed for local canary target {target_url}: {last_error}')
PY
}

supervisor_program_running() {
    program="$1"
    supervisorctl -c /etc/supervisord.conf status "$program" 2>/dev/null | grep -q "RUNNING"
}

env_enabled() {
    case "$(printf '%s' "${1:-0}" | tr '[:upper:]' '[:lower:]')" in
        1|true|yes|on|required|strict) return 0 ;;
        *) return 1 ;;
    esac
}

clamav_required() {
    env_enabled "${CLAMAV_REQUIRED:-}" || env_enabled "${FILE_SECURITY_AV_REQUIRED:-}"
}

adblock_icap_required() {
    env_enabled "${ADBLOCK_ICAP_REQUIRED:-}"
}

clamd_host_is_remote() {
    normalized="$(printf '%s' "${CLAMD_HOST:-127.0.0.1}" | tr '[:upper:]' '[:lower:]')"
    case "$normalized" in
        ''|localhost|127.*|::1|\[::1\]) return 1 ;;
        *) return 0 ;;
    esac
}

remote_clamd_responding() {
    python3 - <<'PY'
import os
import socket


def recv_clamd_reply(sock: socket.socket, max_bytes: int = 64) -> bytes:
    data = bytearray()
    while len(data) < max_bytes:
        chunk = sock.recv(max_bytes - len(data))
        if not chunk:
            break
        data.extend(chunk)
        if b"\n" in chunk or b"\0" in chunk:
            break
    return bytes(data)


def clamd_ping_reply_is_pong(data: bytes) -> bool:
    if data.endswith(b"\r\n"):
        payload = data[:-2]
    elif data.endswith((b"\n", b"\0")):
        payload = data[:-1]
    else:
        return False
    return payload == b"PONG"


host = (os.environ.get("CLAMD_HOST") or "127.0.0.1").strip() or "127.0.0.1"
port = int((os.environ.get("CLAMD_PORT") or "3310").strip())
with socket.create_connection((host, port), 1.5) as sock:
    sock.settimeout(1.5)
    sock.sendall(b"PING\n")
    reply = recv_clamd_reply(sock)
if not clamd_ping_reply_is_pong(reply):
    raise SystemExit(1)
PY
}

clamp_workers() {
    raw="${1:-1}"
    case "$raw" in
        ''|*[!0-9]*) raw=1 ;;
    esac
    if [ "$raw" -lt 1 ]; then
        raw=1
    elif [ "$raw" -gt 4 ]; then
        raw=4
    fi
    printf '%s' "$raw"
}

extract_squid_workers_from_file() {
    file_path="${1:-}"
    if [ ! -f "$file_path" ]; then
        return 0
    fi
    awk 'tolower($1)=="workers" && $2 ~ /^[0-9]+$/ {print $2; exit}' "$file_path" 2>/dev/null || true
}

icap_base_port() {
    raw="${1:-}"
    default="${2:-}"
    case "$raw" in
        ''|*[!0-9]*) raw="$default" ;;
    esac
    if [ "$raw" -lt 1 ]; then
        raw="$default"
    elif [ "$raw" -gt 65535 ]; then
        raw="$default"
    fi
    printf '%s' "$raw"
}

icap_av_base_port() {
    adblock_base="$1"
    av_base="$2"
    workers="$3"
    if [ "$av_base" -lt $((adblock_base + workers)) ] && [ "$adblock_base" -lt $((av_base + workers)) ]; then
        av_base=$((adblock_base + workers))
    fi
    printf '%s' "$av_base"
}

icap_av_resp_base_port() {
    adblock_base="$1"
    av_base="$2"
    resp_base="$3"
    workers="$4"
    if [ "$resp_base" -lt $((adblock_base + workers)) ] && [ "$adblock_base" -lt $((resp_base + workers)) ]; then
        resp_base=$((av_base + workers))
    fi
    if [ "$resp_base" -lt $((av_base + workers)) ] && [ "$av_base" -lt $((resp_base + workers)) ]; then
        resp_base=$((av_base + workers))
    fi
    printf '%s' "$resp_base"
}

# Check Squid liveness (internal check)
if ! supervisor_program_running squid; then
    echo "supervisor reports squid is not RUNNING"
    exit 1
fi

if ! squid -k check >/dev/null 2>&1; then
    if ! icap_ready_detail="$(check_icap_readiness 2>&1)"; then
        echo "Squid startup is waiting for ICAP readiness: ${icap_ready_detail}"
        exit 1
    fi
    echo "Squid check failed"
    exit 1
fi

if ! icap_ready_detail="$(check_icap_readiness 2>&1)"; then
    echo "Configured ICAP services are not OPTIONS-ready: ${icap_ready_detail}"
    exit 1
fi

if ! listener_detail="$(check_squid_http_listeners 2>&1)"; then
    echo "${listener_detail:-Squid HTTP listener is not accepting connections}"
    exit 1
fi

# Check Flask liveness (avoid curl to keep image smaller)
if ! supervisor_program_running proxy_api; then
    echo "supervisor reports proxy_api is not RUNNING"
    exit 1
fi

if ! supervisor_program_running proxy_agent; then
    echo "supervisor reports proxy_agent is not RUNNING"
    exit 1
fi

if ! supervisor_program_running forwarding_canary; then
    echo "supervisor reports forwarding_canary is not RUNNING"
    exit 1
fi

if ! has_listen_socket "${FORWARDING_CANARY_PORT:-18080}" >/dev/null 2>&1; then
    echo "forwarding_canary is not accepting loopback connections"
    exit 1
fi

if ! python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/health', timeout=2).read()" >/dev/null 2>&1; then
    echo "Flask management health endpoint failed"
    exit 1
fi

if ! has_listen_socket "${PAC_HTTP_PORT:-80}" >/dev/null 2>&1; then
    echo "Flask public PAC/WPAD listener is not accepting connections"
    exit 1
fi

if ! python3 -c "import os, urllib.request; host=(os.environ.get('PAC_HTTP_HOST') or '127.0.0.1').strip() or '127.0.0.1'; host='127.0.0.1' if host in {'0.0.0.0','::','[::]'} else host; host=f'[{host}]' if ':' in host and not host.startswith('[') else host; port=(os.environ.get('PAC_HTTP_PORT') or '80').strip() or '80'; urllib.request.urlopen(f'http://{host}:{port}/health', timeout=2).read()" >/dev/null 2>&1; then
    echo "Flask public proxy health endpoint failed"
    exit 1
fi

if clamav_required || env_enabled "${PROXY_HEALTHCHECK_FORWARDING_REQUIRED:-}"; then
    if ! forwarding_detail="$(check_squid_forwarding_path 2>&1)"; then
        echo "${forwarding_detail:-Squid explicit forwarding path failed}"
        exit 1
    fi
fi

# Check ICAP liveness without generating synthetic OPTIONS traffic. Squid renders
# adblock ICAP with bypass=on, so the container healthcheck must not turn an
# adblock helper outage into data-plane downtime unless explicitly required.
ICAP_WORKERS_RAW="$(extract_squid_workers_from_file /etc/squid/squid.conf)"
ICAP_WORKERS="$(clamp_workers "${ICAP_WORKERS_RAW:-${SQUID_WORKERS:-${WORKERS:-1}}}")"
ICAP_ADBLOCK_BASE="$(icap_base_port "${CICAP_PORT:-}" 14000)"
ICAP_AV_BASE="$(icap_av_base_port "$ICAP_ADBLOCK_BASE" "$(icap_base_port "${CICAP_AV_PORT:-}" 14001)" "$ICAP_WORKERS")"
ICAP_AV_RESP_BASE="$(icap_av_resp_base_port "$ICAP_ADBLOCK_BASE" "$ICAP_AV_BASE" "$(icap_base_port "${CICAP_AV_RESP_PORT:-}" $((ICAP_AV_BASE + ICAP_WORKERS)))" "$ICAP_WORKERS")"

i=0
while [ "$i" -lt "$ICAP_WORKERS" ]; do
    instance=$((i + 1))
    adblock_program="cicap_adblock_${instance}"
    adblock_port=$((ICAP_ADBLOCK_BASE + i))
    if ! supervisor_program_running "$adblock_program"; then
        if adblock_icap_required; then
            echo "ADBLOCK_ICAP_REQUIRED is set but supervisor reports ${adblock_program} is not RUNNING"
            exit 1
        fi
        echo "supervisor reports ${adblock_program} is not RUNNING; Squid adblock ICAP is fail-open"
    elif ! has_listen_socket "$adblock_port" >/dev/null 2>&1; then
        if adblock_icap_required; then
            echo "ADBLOCK_ICAP_REQUIRED is set but ${adblock_program} is not listening on port ${adblock_port}"
            exit 1
        fi
        echo "${adblock_program} is not listening on port ${adblock_port}; Squid adblock ICAP is fail-open"
    fi
    i=$((i + 1))
done

if clamav_required; then
    i=0
    while [ "$i" -lt "$ICAP_WORKERS" ]; do
        instance=$((i + 1))
        av_program="cicap_av_${instance}"
        av_port=$((ICAP_AV_BASE + i))
        if ! supervisor_program_running "$av_program"; then
            echo "CLAMAV_REQUIRED is set but supervisor reports ${av_program} is not RUNNING"
            exit 1
        fi

        if ! has_listen_socket "$av_port" >/dev/null 2>&1; then
            echo "CLAMAV_REQUIRED is set but ${av_program} is not listening on port ${av_port}"
            exit 1
        fi

        if clamd_host_is_remote; then
            resp_program="clamav_respmod_${instance}"
            resp_port=$((ICAP_AV_RESP_BASE + i))
            if ! supervisor_program_running "$resp_program"; then
                echo "CLAMAV_REQUIRED is set but supervisor reports ${resp_program} is not RUNNING"
                exit 1
            fi
            if ! has_listen_socket "$resp_port" >/dev/null 2>&1; then
                echo "CLAMAV_REQUIRED is set but ${resp_program} is not listening on port ${resp_port}"
                exit 1
            fi
        fi
        i=$((i + 1))
    done

    # Check the remote clamd backend used by the local AV ICAP services.
    if ! remote_clamd_responding >/dev/null 2>&1; then
        echo "CLAMAV_REQUIRED is set but remote clamd is not responding"
        exit 1
    fi
fi

echo "OK"
exit 0
