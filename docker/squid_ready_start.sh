#!/bin/sh
# Start Squid after every required (bypass=off) ICAP endpoint is OPTIONS-ready.
# Optional fail-open endpoint failures remain visible in the readiness status JSON.

set -eu

CONFIG_PATH="${SQUID_ICAP_INCLUDE_PATH:-/etc/squid/conf.d/20-icap.conf}"
STATUS_FILE="${SQUID_ICAP_READY_STATUS_FILE:-/var/lib/squid-flask-proxy/icap-readiness.json}"

printf '[squid-ready-start] waiting for ICAP readiness config=%s timeout=%s\n' "$CONFIG_PATH" "${SQUID_ICAP_READY_TIMEOUT_SECONDS:-75}"
/usr/local/bin/icap_readiness.py wait \
    --config "$CONFIG_PATH" \
    --status-file "$STATUS_FILE"
printf '[squid-ready-start] required ICAP services ready; starting Squid (optional failures, if any, are fail-open)\n'
exec /usr/sbin/squid --foreground -f /etc/squid/squid.conf
