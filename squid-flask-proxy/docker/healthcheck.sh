#!/bin/sh

# Healthcheck script for the Squid and Flask services

set -eu

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

# Check ICAP liveness (TCP connect)
if ! python3 -c "import socket; s=socket.create_connection(('127.0.0.1', 1344), 2); s.close()" >/dev/null 2>&1; then
    echo "ICAP server is not reachable"
    exit 1
fi

# Check ClamAV liveness
if ! python3 -c "import socket; p='/var/lib/squid-flask-proxy/clamav/clamd.sock'; s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.settimeout(1.0); s.connect(p); s.sendall(b'PING\n'); d=s.recv(16); s.close(); assert d.startswith(b'PONG')" >/dev/null 2>&1; then
    echo "clamd is not responding"
    exit 1
fi

echo "OK"
exit 0