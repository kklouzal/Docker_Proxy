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

from tools.start_admin_ui import resolve_admin_ui_bind

try:
    bind = resolve_admin_ui_bind(os.environ)
    with socket.create_connection((bind.health_host, bind.port), timeout=2):
        pass
except (OSError, ValueError):
    sys.exit(1)
PY
