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

# Check c-icap adblock ICAP service liveness (OPTIONS /adblockreq)
if ! python3 -c "import os,socket; host='127.0.0.1'; port=int(os.environ.get('CICAP_PORT','14000')); path='/adblockreq'; req=(f'OPTIONS icap://{host}:{port}{path} ICAP/1.0\r\nHost: {host}\r\nEncapsulated: null-body=0\r\n\r\n').encode('ascii'); s=socket.create_connection((host,port),2); s.settimeout(2); s.sendall(req); resp=s.recv(512); s.close(); assert resp.startswith(b'ICAP/1.0 200')" >/dev/null 2>&1; then
    echo "c-icap adblock ICAP service is not responding"
    exit 1
fi

# Check c-icap AV ICAP service liveness (OPTIONS /avrespmod)
if ! python3 -c "import os,socket; host='127.0.0.1'; port=int(os.environ.get('CICAP_AV_PORT','14001')); path='/avrespmod'; req=(f'OPTIONS icap://{host}:{port}{path} ICAP/1.0\r\nHost: {host}\r\nEncapsulated: null-body=0\r\n\r\n').encode('ascii'); s=socket.create_connection((host,port),2); s.settimeout(2); s.sendall(req); resp=s.recv(512); s.close(); assert resp.startswith(b'ICAP/1.0 200')" >/dev/null 2>&1; then
    echo "c-icap AV ICAP service is not responding"
    exit 1
fi

# Check ClamAV liveness
if ! python3 -c "import socket; p='/var/lib/squid-flask-proxy/clamav/clamd.sock'; s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.settimeout(1.0); s.connect(p); s.sendall(b'PING\n'); d=s.recv(16); s.close(); assert d.startswith(b'PONG')" >/dev/null 2>&1; then
    echo "clamd is not responding"
    exit 1
fi

echo "OK"
exit 0