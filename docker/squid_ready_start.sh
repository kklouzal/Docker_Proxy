#!/bin/sh
# Start Squid only after every generated ICAP endpoint is OPTIONS-ready.

set -eu

CONFIG_PATH="${SQUID_ICAP_INCLUDE_PATH:-/etc/squid/conf.d/20-icap.conf}"
TIMEOUT="${SQUID_ICAP_READY_TIMEOUT_SECONDS:-75}"
PROBE_TIMEOUT="${SQUID_ICAP_READY_PROBE_TIMEOUT_SECONDS:-1.0}"
INTERVAL="${SQUID_ICAP_READY_INTERVAL_SECONDS:-0.25}"
STATUS_FILE="${SQUID_ICAP_READY_STATUS_FILE:-/var/lib/squid-flask-proxy/icap-readiness.json}"

printf '[squid-ready-start] waiting for ICAP readiness config=%s timeout=%s\n' "$CONFIG_PATH" "$TIMEOUT"
/usr/local/bin/icap_readiness.py wait \
    --config "$CONFIG_PATH" \
    --timeout "$TIMEOUT" \
    --probe-timeout "$PROBE_TIMEOUT" \
    --interval "$INTERVAL" \
    --status-file "$STATUS_FILE"
printf '[squid-ready-start] ICAP ready; starting Squid\n'
exec /usr/sbin/squid --foreground -f /etc/squid/squid.conf
