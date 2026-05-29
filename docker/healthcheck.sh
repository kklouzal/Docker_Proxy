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
    if not stripped or stripped.startswith('#') or not stripped.lower().startswith('http_port '):
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

# Check Squid liveness (internal check)
if ! supervisor_program_running squid; then
    echo "supervisor reports squid is not RUNNING"
    exit 1
fi

if ! squid -k check >/dev/null 2>&1; then
    echo "Squid check failed"
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

if ! python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/health', timeout=2).read()" >/dev/null 2>&1; then
    echo "Flask management health endpoint failed"
    exit 1
fi

if ! has_listen_socket "${PAC_HTTP_PORT:-80}" >/dev/null 2>&1; then
    echo "Flask public PAC/WPAD listener is not accepting connections"
    exit 1
fi

if ! python3 -c "import os, urllib.request; port=(os.environ.get('PAC_HTTP_PORT') or '80').strip() or '80'; urllib.request.urlopen(f'http://127.0.0.1:{port}/health', timeout=2).read()" >/dev/null 2>&1; then
    echo "Flask public proxy health endpoint failed"
    exit 1
fi

# Check required c-icap liveness without generating synthetic OPTIONS traffic.
# Adblock is part of the normal proxy path. AV is optional by default because
# Squid ICAP uses bypass=on and should degrade cleanly when clamd is absent.
if ! supervisor_program_running cicap_adblock; then
    echo "supervisor reports cicap_adblock is not RUNNING"
    exit 1
fi

if ! has_listen_socket "${CICAP_PORT:-14000}" >/dev/null 2>&1; then
    echo "cicap_adblock is not listening on its configured port"
    exit 1
fi

if clamav_required; then
    if ! supervisor_program_running cicap_av; then
        echo "CLAMAV_REQUIRED is set but supervisor reports cicap_av is not RUNNING"
        exit 1
    fi

    if ! has_listen_socket "${CICAP_AV_PORT:-14001}" >/dev/null 2>&1; then
        echo "CLAMAV_REQUIRED is set but cicap_av is not listening on its configured port"
        exit 1
    fi

    # Check the remote clamd backend used by the local AV c-icap service.
    if ! python3 -c "import os,socket; host=(os.environ.get('CLAMD_HOST') or '127.0.0.1').strip() or '127.0.0.1'; port=int((os.environ.get('CLAMD_PORT') or '3310').strip()); s=socket.create_connection((host, port), 1.5); s.settimeout(1.5); s.sendall(b'PING\n'); d=s.recv(64); s.close(); assert d.startswith(b'PONG')" >/dev/null 2>&1; then
        echo "CLAMAV_REQUIRED is set but remote clamd is not responding"
        exit 1
    fi
fi

echo "OK"
exit 0
