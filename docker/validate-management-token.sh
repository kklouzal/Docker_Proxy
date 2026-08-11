#!/bin/sh

set -eu

token=$(printf '%s' "${PROXY_MANAGEMENT_TOKEN:-}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
case "$token" in
    ''|change-me|replace-with-a-long-random-token|replace_with_a_long_random_shared_token)
        echo >&2 "ERROR: PROXY_MANAGEMENT_TOKEN must be set to a private shared token; configure the same value for the Admin UI and proxy runtime."
        exit 1
        ;;
esac
