#!/bin/sh

set -eu

bind="${ADMIN_UI_BIND:-0.0.0.0:${ADMIN_UI_PORT:-5000}}"
workers="${WEB_WORKERS:-1}"
threads="${WEB_THREADS:-2}"
timeout="${WEB_TIMEOUT:-120}"
graceful_timeout="${WEB_GRACEFUL_TIMEOUT:-30}"
keepalive="${WEB_KEEPALIVE:-5}"
https_enabled="${ADMIN_UI_HTTPS_ENABLED:-0}"
certfile="${ADMIN_UI_SSL_CERTFILE:-}"
keyfile="${ADMIN_UI_SSL_KEYFILE:-}"

case "$(printf '%s' "$https_enabled" | tr '[:upper:]' '[:lower:]')" in
    1|true|yes|on|enabled)
        https_enabled=1
        ;;
    *)
        https_enabled=0
        ;;
esac

if [ "$https_enabled" = "1" ]; then
    certfile="${certfile:-/etc/squid/ssl/certs/ca.crt}"
    keyfile="${keyfile:-/etc/squid/ssl/certs/ca.key}"
    if [ ! -r "$certfile" ]; then
        echo "ERROR: ADMIN_UI_HTTPS_ENABLED is set but cert file is not readable: $certfile" >&2
        exit 1
    fi
    if [ ! -r "$keyfile" ]; then
        echo "ERROR: ADMIN_UI_HTTPS_ENABLED is set but key file is not readable: $keyfile" >&2
        exit 1
    fi
fi

set -- python3 -m gunicorn \
    -b "$bind" \
    wsgi:app \
    --workers "$workers" \
    --threads "$threads" \
    --timeout "$timeout" \
    --graceful-timeout "$graceful_timeout" \
    --keep-alive "$keepalive" \
    --worker-tmp-dir /dev/shm \
    --error-logfile -

if [ "$https_enabled" = "1" ]; then
    set -- "$@" --certfile "$certfile" --keyfile "$keyfile"
fi

exec "$@"
