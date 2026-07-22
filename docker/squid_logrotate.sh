#!/bin/sh

set -eu

INTERVAL_SECONDS="${SQUID_LOG_ROTATE_INTERVAL_SECONDS:-86400}"
INITIAL_DELAY_SECONDS="${SQUID_LOG_ROTATE_INITIAL_DELAY_SECONDS:-15}"
SQUID_CONF_PATH="${SQUID_CONF_PATH:-/etc/squid/squid.conf}"
DEFAULT_LOGFILE_ROTATE_COUNT=10
LOGFILES="${SQUID_LOG_ROTATE_LOGFILES:-/var/log/squid/access-observe.log /var/log/squid/icap.log /var/log/cicap-access.log}"

is_nonnegative_integer() {
  case "$1" in
    ""|*[!0-9]*) return 1 ;;
    *) return 0 ;;
  esac
}

get_logfile_rotate_count() {
  if is_nonnegative_integer "${SQUID_LOGFILE_ROTATE_COUNT:-}"; then
    printf '%s\n' "${SQUID_LOGFILE_ROTATE_COUNT}"
    return
  fi

  configured_count=""
  if [ -f "$SQUID_CONF_PATH" ]; then
    configured_count="$(sed -n 's/^[[:space:]]*logfile_rotate[[:space:]][[:space:]]*\([0-9][0-9]*\).*$/\1/p' "$SQUID_CONF_PATH" 2>/dev/null | tail -n 1 || true)"
  fi

  if is_nonnegative_integer "$configured_count"; then
    printf '%s\n' "$configured_count"
  else
    printf '%s\n' "$DEFAULT_LOGFILE_ROTATE_COUNT"
  fi
}

copytruncate_logfile() {
  logfile="$1"
  rotate_count="$2"

  if [ ! -f "$logfile" ]; then
    return
  fi

  if [ "$rotate_count" -gt 0 ]; then
    rm -f "${logfile}.${rotate_count}" 2>/dev/null || true

    i=$((rotate_count - 1))
    while [ "$i" -ge 1 ]; do
      if [ -e "${logfile}.${i}" ]; then
        mv "${logfile}.${i}" "${logfile}.$((i + 1))" 2>/dev/null || true
      fi
      i=$((i - 1))
    done

    cp "$logfile" "${logfile}.1" 2>/dev/null || true
  fi

  : > "$logfile" 2>/dev/null || true
}

rotate_logs() {
  ts="$(date -Iseconds 2>/dev/null || date)"
  rotate_count="$(get_logfile_rotate_count)"
  echo "[squid-logrotate] ${ts} rotating logs; retention=${rotate_count}"

  # Rotate logs with copytruncate instead of `squid -k rotate`.
  # Squid stdio logs can keep appending to access-observe.log.0/icap.log.0
  # after a runtime rotate, which makes the Admin UI tailers miss explicit and
  # intercept listener traffic.  Copytruncate keeps the active path stable; the
  # tailers detect the truncation (file size < position) and seek to the start.
  # Since runtime rotate is intentionally not invoked, advance and cap numbered
  # history here using logfile_rotate from squid.conf, with an env/default
  # fallback for testability and older configs.
  for logfile in $LOGFILES; do
    if [ -f "$logfile" ]; then
      copytruncate_logfile "$logfile" "$rotate_count"
      echo "[squid-logrotate] ${ts} truncated ${logfile}"
    fi
  done
}

if [ "${SQUID_LOG_ROTATE_RUN_ONCE:-0}" != "1" ]; then
  # Give Squid a moment to finish initialization on container start.
  sleep "${INITIAL_DELAY_SECONDS}"
fi

# Supervisor-managed loop: rotate Squid logs every INTERVAL_SECONDS.
# Rotation uses `logfile_rotate N` in squid.conf to cap retained files.
while :; do
  rotate_logs

  if [ "${SQUID_LOG_ROTATE_RUN_ONCE:-0}" = "1" ]; then
    exit 0
  fi

  sleep "${INTERVAL_SECONDS}"
done
