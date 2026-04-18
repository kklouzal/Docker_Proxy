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

# Check Squid liveness (internal check)
if ! squid -k check >/dev/null 2>&1; then
    echo "Squid check failed"
    exit 1
fi

# Check Flask liveness (avoid curl to keep image smaller)
if ! python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/health', timeout=2).read()" >/dev/null 2>&1; then
    echo "Flask health endpoint failed"
    exit 1
fi

# Check Dante liveness (process exists)
if ! ps 2>/dev/null | grep -q '[s]ockd'; then
    echo "Dante (sockd) is not running"
    exit 1
fi

# Check Dante liveness without creating synthetic traffic/log rows.
# Parse /proc/net/tcp{,6} to confirm the port is listening rather than opening
# a probe connection that Dante would record in sockd.log every 15 seconds.
if ! has_listen_socket "${DANTE_PORT:-1080}" >/dev/null 2>&1; then
    echo "Dante (sockd) is not listening on its configured port"
    exit 1
fi

# Check c-icap liveness without generating synthetic OPTIONS traffic.
# As with Dante, confirm both ICAP ports are listening instead of probing the
# services over the protocol, which would otherwise pollute c-icap access logs
# every 15 seconds.
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