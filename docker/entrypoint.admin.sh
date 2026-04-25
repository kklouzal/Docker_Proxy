#!/bin/sh

set -eu

. /usr/local/bin/load-env.sh

export DISABLE_BACKGROUND="${DISABLE_BACKGROUND:-0}"

exec /usr/bin/supervisord -c /etc/supervisord.conf
