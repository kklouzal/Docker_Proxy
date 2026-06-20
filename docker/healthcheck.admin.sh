#!/bin/sh

set -eu

# shellcheck disable=SC2009
if ! ps | grep -E '[g]unicorn.*wsgi:app' >/dev/null 2>&1; then
    exit 1
fi

# A raw TCP connect works whether gunicorn is currently speaking HTTP or HTTPS.
python3 - <<'PY'
import socket

with socket.create_connection(("127.0.0.1", 5000), timeout=2):
    pass
PY
