#!/bin/sh

set -eu

INTERVAL_SECONDS="${SQUID_LOG_ROTATE_INTERVAL_SECONDS:-86400}"
INITIAL_DELAY_SECONDS="${SQUID_LOG_ROTATE_INITIAL_DELAY_SECONDS:-15}"

# Give Squid a moment to finish initialization on container start.
sleep "${INITIAL_DELAY_SECONDS}"

# Supervisor-managed loop: rotate Squid logs every INTERVAL_SECONDS.
# Rotation requires `logfile_rotate N` in squid.conf to cap retained files.
while :; do
  ts="$(date -Iseconds 2>/dev/null || date)"
  echo "[squid-logrotate] ${ts} rotating logs"

  # Rotate logs with copytruncate instead of `squid -k rotate`.
  # Squid stdio logs can keep appending to access-observe.log.0/icap.log.0
  # after a runtime rotate, which makes the Admin UI tailers miss explicit and
  # intercept listener traffic.  Copytruncate keeps the active path stable; the
  # tailers detect the truncation (file size < position) and seek to the start.
  for logfile in /var/log/squid/access-observe.log /var/log/squid/icap.log /var/log/cicap-access.log /var/log/cicap-access-av.log; do
    if [ -f "$logfile" ]; then
      cp -- "$logfile" "${logfile}.1" 2>/dev/null || true
      : > "$logfile" 2>/dev/null || true
      echo "[squid-logrotate] ${ts} truncated ${logfile}"
    fi
  done

  sleep "${INTERVAL_SECONDS}"
done
