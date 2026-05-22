#!/bin/sh

set -eu

. /usr/local/bin/load-env.sh

export DISABLE_BACKGROUND="${DISABLE_BACKGROUND:-0}"

if [ -z "${DB_POOL_SIZE:-}" ]; then
    web_threads="${WEB_THREADS:-2}"
    case "$web_threads" in
        ''|*[!0-9]*) web_threads=2 ;;
    esac
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
