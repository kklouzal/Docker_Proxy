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

  # Ask the running Squid to rotate/reopen its logs.
  # Do not crash the loop if Squid is temporarily restarting.
  if ! squid -k rotate >/dev/null 2>&1; then
    echo "[squid-logrotate] ${ts} squid -k rotate failed (will retry next interval)" >&2
  fi

  # Rotate unbounded c-icap and Dante (sockd) logs.
  # These services don't support signal-based rotation, so we copytruncate:
  # copy the current file to a .1 backup, then truncate the original in-place.
  # The log tailers in the web app detect the truncation (file size < position)
  # and automatically seek back to the start.
  for logfile in /var/log/cicap-access.log /var/log/cicap-access-av.log /var/log/sockd.log; do
    if [ -f "$logfile" ]; then
      cp -- "$logfile" "${logfile}.1" 2>/dev/null || true
      : > "$logfile" 2>/dev/null || true
      echo "[squid-logrotate] ${ts} truncated ${logfile}"
    fi
  done

  sleep "${INTERVAL_SECONDS}"
done
