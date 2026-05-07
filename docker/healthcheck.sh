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

supervisor_program_running() {
    program="$1"
    supervisorctl -c /etc/supervisord.conf status "$program" 2>/dev/null | grep -q "RUNNING"
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

if ! has_listen_socket "${SQUID_HTTP_PORT:-3128}" >/dev/null 2>&1; then
    echo "Squid HTTP listener is not accepting connections"
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

# Check c-icap liveness without generating synthetic OPTIONS traffic.
# Confirm both ICAP ports are listening instead of probing the services over
# the protocol, which would otherwise pollute c-icap access logs
# every 15 seconds.
if ! supervisor_program_running cicap_adblock || ! supervisor_program_running cicap_av; then
    echo "one or more c-icap supervisor programs are not RUNNING"
    exit 1
fi

if ! has_listen_socket "${CICAP_PORT:-14000}" >/dev/null 2>&1 || ! has_listen_socket "${CICAP_AV_PORT:-14001}" >/dev/null 2>&1; then
    echo "One or more c-icap services are not listening on their configured ports"
    exit 1
fi

# Check the remote clamd backend used by the local AV c-icap service.
if ! python3 -c "import os,socket; host=(os.environ.get('CLAMD_HOST') or '127.0.0.1').strip() or '127.0.0.1'; port=int((os.environ.get('CLAMD_PORT') or '3310').strip()); s=socket.create_connection((host, port), 1.5); s.settimeout(1.5); s.sendall(b'PING\n'); d=s.recv(64); s.close(); assert d.startswith(b'PONG')" >/dev/null 2>&1; then
    echo "remote clamd is not responding"
    exit 1
fi

echo "OK"
exit 0