#!/bin/sh

set -eu

. /usr/local/bin/load-env.sh

export DISABLE_BACKGROUND="${DISABLE_BACKGROUND:-0}"

if [ -z "${DB_POOL_SIZE:-}" ]; then
    web_threads="${WEB_THREADS:-2}"
    case "$web_threads" in
        ''|*[!0-9]*) web_threads=2 ;;
    esac
    derived_pool=$((web_threads + 1))
    if [ "$derived_pool" -lt 2 ]; then
        derived_pool=2
    fi
    if [ "$derived_pool" -gt 8 ]; then
        derived_pool=8
    fi
    export DB_POOL_SIZE="$derived_pool"
fi
exec /usr/bin/supervisord -c /etc/supervisord.conf
