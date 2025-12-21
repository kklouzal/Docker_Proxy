#!/bin/sh

set -eu

INTERVAL_SECONDS="${SQUID_LOG_ROTATE_INTERVAL_SECONDS:-86400}"

# Supervisor-managed loop: rotate Squid logs every INTERVAL_SECONDS.
# Rotation requires `logfile_rotate N` in squid.conf to cap retained files.
while :; do
  ts="$(date -Iseconds 2>/dev/null || date)"
  echo "[squid-logrotate] ${ts} rotating logs"

  # Ask the running Squid to rotate/reopen its logs.
  # Do not crash the loop if Squid is temporarily restarting.
  if ! squid -k rotate >/dev/null 2>&1; then
    echo "[squid-logrotate] ${ts} squid -k rotate failed (will retry next interval)" >&2
  fi

  sleep "${INTERVAL_SECONDS}"
done
