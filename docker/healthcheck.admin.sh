#!/bin/sh

set -eu

if ! ps | grep -E '[g]unicorn.*wsgi:app' >/dev/null 2>&1; then
    exit 1
fi

python3 - <<'PY'
import socket

with socket.create_connection(("127.0.0.1", 5000), timeout=2):
    pass
PY
