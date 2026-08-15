#!/bin/sh

set -eu

# Do not issue an HTTP request here: a request can queue behind saturated WSGI
# workers and turn load into a false container failure. Instead, require both a
# Gunicorn worker descended from the app master and the launcher's listener
# contract. This closes the master-only bind window without consuming a worker.
python3 - <<'PY'
import os
from pathlib import Path
import socket
import sys

from tools.start_admin_ui import resolve_admin_ui_bind


def gunicorn_app_processes():
    processes = {}
    for proc_dir in Path("/proc").glob("[0-9]*"):
        try:
            cmdline = proc_dir.joinpath("cmdline").read_bytes().replace(b"\0", b" ")
            if b"gunicorn" not in cmdline or b"wsgi:app" not in cmdline:
                continue
            fields = proc_dir.joinpath("stat").read_text().rsplit(") ", 1)[1].split()
            processes[int(proc_dir.name)] = int(fields[1])
        except (FileNotFoundError, PermissionError, ValueError, IndexError):
            continue
    return processes


try:
    processes = gunicorn_app_processes()
    if not any(parent_pid in processes for parent_pid in processes.values()):
        raise RuntimeError("Gunicorn has no WSGI worker")
    bind = resolve_admin_ui_bind(os.environ)
    with socket.create_connection((bind.health_host, bind.port), timeout=2):
        pass
except (OSError, RuntimeError, ValueError):
    sys.exit(1)
PY
