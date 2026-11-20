#!/bin/sh

# Healthcheck script for the Squid and Flask services.
#
# Docker runs this with the container's configured environment, not the
# entrypoint's: values loaded from /config/app.env and the entrypoint's
# sanitized/derived settings (worker count, ICAP port allocation, AV/adblock
# requirement, PAC and canary binds) would otherwise be invisible here. The
# entrypoint records the values it handed to supervisord in
# HEALTHCHECK_ENV_FILE, so this script checks the services that were actually
# started instead of re-deriving them.
#
# Cost: one supervisorctl call (its start-up costs more CPU than all other
# probes combined), one /proc/net listener snapshot and a few small Python
# probes.

set -eu

HEALTHCHECK_ENV_FILE="${HEALTHCHECK_ENV_FILE:-/run/squid-flask-proxy/healthcheck.env}"
SUPERVISORD_CONF=/etc/supervisord.conf

if [ ! -r "$HEALTHCHECK_ENV_FILE" ]; then
    echo "proxy entrypoint has not finished startup (${HEALTHCHECK_ENV_FILE} missing)"
    exit 1
fi
# shellcheck source=/dev/null
. "$HEALTHCHECK_ENV_FILE"

SUPERVISOR_STATUS=""
LISTEN_PORTS=""

refresh_supervisor_status() {
    # supervisorctl exits non-zero whenever any program is not RUNNING; the
    # per-program lines are still complete, so evaluate them individually.
    SUPERVISOR_STATUS="$(supervisorctl -c "$SUPERVISORD_CONF" status 2>/dev/null || true)"
}

supervisor_program_running() {
    printf '%s\n' "$SUPERVISOR_STATUS" | awk -v program="$1" '
        $1 == program && $2 == "RUNNING" { found = 1 }
        END { exit found ? 0 : 1 }
    '
}

refresh_listen_ports() {
    # Uppercase hex local ports of LISTEN (0A) TCP sockets, IPv4 and IPv6.
    LISTEN_PORTS="$(awk 'FNR > 1 && $4 == "0A" { n = split($2, part, ":"); print part[n] }' /proc/net/tcp /proc/net/tcp6 2>/dev/null || true)"
}

has_listen_socket() {
    port_hex="$(printf '%04X' "$1")"
    printf '%s\n' "$LISTEN_PORTS" | grep -qx "$port_hex"
}

check_squid_http_listeners() {
    python3 - <<'PYHEALTH'
import os

from services.squid_listeners import (
    listener_is_present,
    listening_endpoints,
    parse_squid_listeners,
)

try:
    with open("/etc/squid/squid.conf", encoding="utf-8", errors="replace") as handle:
        text = handle.read()
except FileNotFoundError:
    text = ""
listeners = parse_squid_listeners(text, fallback_port=int(os.environ["SQUID_HTTP_PORT"]))
endpoints = listening_endpoints()
missing = [item for item in listeners if not listener_is_present(item, endpoints)]
if missing:
    rendered = ", ".join(f"{item.get('host') or '*'}:{item['port']} ({item['mode']})" for item in missing)
    raise SystemExit(f"Squid listener(s) not accepting connections: {rendered}")
PYHEALTH
}

check_icap_readiness() {
    if [ ! -x /usr/local/bin/icap_readiness.py ]; then
        return 0
    fi
    /usr/local/bin/icap_readiness.py check \
        --config "${SQUID_ICAP_INCLUDE_PATH:-/etc/squid/conf.d/20-icap.conf}" \
        --probe-timeout "${SQUID_ICAP_READY_HEALTH_PROBE_TIMEOUT_SECONDS:-0.35}"
}

check_http_health_endpoints() {
    # One interpreter for both listeners, with raw sockets: importing urllib
    # costs more CPU than the probes themselves.
    python3 - <<'PY'
import os
import socket

pac_host = os.environ["PAC_HTTP_HOST"]
if pac_host in {"0.0.0.0", "::"}:
    pac_host = "127.0.0.1"
targets = (
    ("Flask management health endpoint", "127.0.0.1", 5000),
    ("Flask public proxy health endpoint", pac_host, int(os.environ["PAC_HTTP_PORT"])),
)
for label, host, port in targets:
    try:
        with socket.create_connection((host, port), timeout=2.0) as sock:
            sock.settimeout(2.0)
            sock.sendall(
                b"GET /health HTTP/1.1\r\nHost: localhost\r\n"
                b"User-Agent: squid-flask-proxy-healthcheck\r\nConnection: close\r\n\r\n"
            )
            status_line = sock.recv(64).split(b"\r\n", 1)[0]
    except OSError as exc:
        raise SystemExit(f"{label} failed: {exc}") from None
    parts = status_line.split()
    if len(parts) < 2 or not parts[0].startswith(b"HTTP/") or parts[1] != b"200":
        rendered = status_line.decode("ascii", "replace") or "no HTTP status"
        raise SystemExit(f"{label} failed: {rendered}")
PY
}

check_squid_forwarding_path() {
    python3 - <<'PY'
import json
import os
import socket

from services.forwarding_canary_config import (
    forwarding_canary_listener_host,
    forwarding_canary_port,
    forwarding_canary_target_url,
)
from services.squid_listeners import parse_squid_listeners

try:
    with open("/etc/squid/squid.conf", encoding="utf-8", errors="replace") as handle:
        text = handle.read()
except FileNotFoundError:
    text = ""
ports = []
for listener in parse_squid_listeners(text, fallback_port=int(os.environ["SQUID_HTTP_PORT"])):
    if listener["mode"] == "explicit" and listener["port"] not in ports:
        ports.append(listener["port"])

target_url = f"{forwarding_canary_target_url()}?probe=squid-respmod"
host_header = f"{forwarding_canary_listener_host()}:{forwarding_canary_port()}"
last_error = "no explicit http_port listener"
for port in ports:
    try:
        with socket.create_connection(("127.0.0.1", int(port)), timeout=2.0) as sock:
            sock.settimeout(2.0)
            sock.sendall(
                (
                    f"GET {target_url} HTTP/1.1\r\n"
                    f"Host: {host_header}\r\n"
                    "User-Agent: squid-flask-proxy-forwarding-health\r\n"
                    "Accept: application/json, */*;q=0.1\r\n"
                    "Cache-Control: no-cache\r\n"
                    "Pragma: no-cache\r\n"
                    "Connection: close\r\n\r\n"
                ).encode("ascii", errors="replace")
            )
            data = b""
            while len(data) < 4096:
                chunk = sock.recv(min(512, 4096 - len(data)))
                if not chunk:
                    break
                data += chunk
        status = data.split(b"\r\n", 1)[0].split(b"\n", 1)[0].decode("ascii", errors="replace")
        parts = status.split()
        code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        if status.startswith("HTTP/") and 200 <= code < 400:
            body = data.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in data else b""
            payload = json.loads(body.decode("utf-8"))
            if payload.get("ok") is True and payload.get("service") == "docker-proxy-forwarding-canary" and payload.get("probe") == "squid-respmod":
                raise SystemExit(0)
            last_error = f"port {port}: canary body did not confirm ok"
            continue
        last_error = f"port {port}: {status or 'no HTTP status'}"
    except Exception as exc:
        last_error = f"port {port}: {exc}"
raise SystemExit(f"Squid explicit forwarding path failed for local canary target {target_url}: {last_error}")
PY
}

remote_clamd_responding() {
    python3 - <<'PY'
import os
import socket

from services.clamd_protocol import (
    CLAMD_PING_MAX_REPLY_BYTES,
    CLAMD_PING_REQUEST,
    ping_reply_is_pong,
    recv_terminated_reply,
)

address = (os.environ["CLAMD_HOST"], int(os.environ["CLAMD_PORT"]))
with socket.create_connection(address, 1.5) as sock:
    sock.settimeout(1.5)
    sock.sendall(CLAMD_PING_REQUEST)
    reply = recv_terminated_reply(sock, max_bytes=CLAMD_PING_MAX_REPLY_BYTES)
if not ping_reply_is_pong(reply):
    raise SystemExit(1)
PY
}

refresh_supervisor_status

# Check Squid liveness (internal check)
if ! supervisor_program_running squid; then
    echo "supervisor reports squid is not RUNNING"
    exit 1
fi

if ! squid -k check >/dev/null 2>&1; then
    if ! icap_ready_detail="$(check_icap_readiness 2>&1)"; then
        echo "Squid startup is waiting for ICAP readiness: ${icap_ready_detail}"
        exit 1
    fi
    echo "Squid check failed"
    exit 1
fi

if ! icap_ready_detail="$(check_icap_readiness 2>&1)"; then
    echo "Configured ICAP services are not OPTIONS-ready: ${icap_ready_detail}"
    exit 1
fi

if ! listener_detail="$(check_squid_http_listeners 2>&1)"; then
    echo "${listener_detail:-Squid HTTP listener is not accepting connections}"
    exit 1
fi

for program in proxy_api proxy_public proxy_agent forwarding_canary; do
    if ! supervisor_program_running "$program"; then
        echo "supervisor reports ${program} is not RUNNING"
        exit 1
    fi
done

refresh_listen_ports

if ! has_listen_socket "$FORWARDING_CANARY_PORT"; then
    echo "forwarding_canary is not accepting loopback connections"
    exit 1
fi

if ! has_listen_socket "$PAC_HTTP_PORT"; then
    echo "Flask public PAC/WPAD listener is not accepting connections"
    exit 1
fi

if ! http_detail="$(check_http_health_endpoints 2>&1)"; then
    echo "${http_detail:-Flask health endpoint failed}"
    exit 1
fi

if [ "$CLAMAV_REQUIRED" = "1" ] || [ "$PROXY_HEALTHCHECK_FORWARDING_REQUIRED" = "1" ]; then
    if ! forwarding_detail="$(check_squid_forwarding_path 2>&1)"; then
        echo "${forwarding_detail:-Squid explicit forwarding path failed}"
        exit 1
    fi
fi

# Check ICAP liveness without generating synthetic OPTIONS traffic. Squid renders
# adblock ICAP with bypass=on, so the container healthcheck must not turn an
# adblock helper outage into data-plane downtime unless explicitly required.
i=0
while [ "$i" -lt "$SQUID_WORKERS" ]; do
    instance=$((i + 1))
    adblock_program="cicap_adblock_${instance}"
    adblock_port=$((CICAP_PORT + i))
    if ! supervisor_program_running "$adblock_program"; then
        if [ "$ADBLOCK_ICAP_REQUIRED" = "1" ]; then
            echo "ADBLOCK_ICAP_REQUIRED is set but supervisor reports ${adblock_program} is not RUNNING"
            exit 1
        fi
        echo "supervisor reports ${adblock_program} is not RUNNING; Squid adblock ICAP is fail-open"
    elif ! has_listen_socket "$adblock_port"; then
        if [ "$ADBLOCK_ICAP_REQUIRED" = "1" ]; then
            echo "ADBLOCK_ICAP_REQUIRED is set but ${adblock_program} is not listening on port ${adblock_port}"
            exit 1
        fi
        echo "${adblock_program} is not listening on port ${adblock_port}; Squid adblock ICAP is fail-open"
    fi
    i=$((i + 1))
done

if [ "$CLAMAV_REQUIRED" = "1" ]; then
    i=0
    while [ "$i" -lt "$SQUID_WORKERS" ]; do
        instance=$((i + 1))
        av_program="cicap_av_${instance}"
        av_port=$((CICAP_AV_PORT + i))
        if ! supervisor_program_running "$av_program"; then
            echo "CLAMAV_REQUIRED is set but supervisor reports ${av_program} is not RUNNING"
            exit 1
        fi

        if ! has_listen_socket "$av_port"; then
            echo "CLAMAV_REQUIRED is set but ${av_program} is not listening on port ${av_port}"
            exit 1
        fi

        if [ "$CLAMD_HOST_IS_REMOTE" = "1" ]; then
            resp_program="clamav_respmod_${instance}"
            resp_port=$((CICAP_AV_RESP_PORT + i))
            if ! supervisor_program_running "$resp_program"; then
                echo "CLAMAV_REQUIRED is set but supervisor reports ${resp_program} is not RUNNING"
                exit 1
            fi
            if ! has_listen_socket "$resp_port"; then
                echo "CLAMAV_REQUIRED is set but ${resp_program} is not listening on port ${resp_port}"
                exit 1
            fi
        fi
        i=$((i + 1))
    done

    # Check the remote clamd backend used by the local AV ICAP services.
    if ! remote_clamd_responding >/dev/null 2>&1; then
        echo "CLAMAV_REQUIRED is set but remote clamd is not responding"
        exit 1
    fi
fi

echo "OK"
exit 0
