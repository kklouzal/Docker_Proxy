#!/bin/sh

set -eu

# shellcheck source=/dev/null
. /usr/local/bin/load-env.sh

export DISABLE_BACKGROUND="${DISABLE_BACKGROUND:-0}"

# Keep DB sizing and the eventual Gunicorn argv on the launcher's single
# sanitization contract. Its output is always five decimal integer tokens.
set -- $(python3 /app/tools/start_admin_ui.py --print-effective-gunicorn-env)
export WEB_WORKERS="$1"
export WEB_THREADS="$2"
export WEB_TIMEOUT="$3"
export WEB_GRACEFUL_TIMEOUT="$4"
export WEB_KEEPALIVE="$5"

if [ -z "${DB_POOL_SIZE:-}" ]; then
    web_threads="$WEB_THREADS"
    derived_pool=$((web_threads + 12))
    if [ "$derived_pool" -lt 16 ]; then
        derived_pool=16
    fi
    if [ "$derived_pool" -gt 32 ]; then
        derived_pool=32
    fi
    export DB_POOL_SIZE="$derived_pool"
fi
exec /usr/bin/supervisord -c /etc/supervisord.conf
