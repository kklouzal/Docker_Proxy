#!/bin/sh

set -eu

# shellcheck disable=SC2009
if ! ps | grep -E '[g]unicorn.*wsgi:app' >/dev/null 2>&1; then
    exit 1
fi

# A raw TCP connect works whether gunicorn is currently speaking HTTP or HTTPS.
python3 - <<'PY'
import os
import socket
import sys


def _port_from_bind(bind):
    bind = (bind or "").strip()
    if not bind:
        return None
    if bind.isdigit():
        return int(bind)
    if bind.startswith("["):
        _host, sep, rest = bind.partition("]")
        if sep and rest.startswith(":") and rest[1:].isdigit():
            return int(rest[1:])
        return None
    if bind.startswith(":") and bind[1:].isdigit():
        return int(bind[1:])
    if ":" in bind:
        port = bind.rsplit(":", 1)[1]
        if port.isdigit():
            return int(port)
    return None


def _health_port():
    port = _port_from_bind(os.environ.get("ADMIN_UI_BIND"))
    if port is not None:
        return port
    return _port_from_bind(os.environ.get("ADMIN_UI_PORT")) or 5000


try:
    with socket.create_connection(("127.0.0.1", _health_port()), timeout=2):
        pass
except OSError:
    sys.exit(1)
PY
