#!/bin/sh
set -eu

if [ "$#" -eq 0 ]; then
    echo "usage: apk-install <package> [<package> ...]" >&2
    exit 64
fi

retries="${APK_INSTALL_RETRIES:-4}"
delay_seconds="${APK_INSTALL_RETRY_DELAY_SECONDS:-5}"
attempt=1

while :; do
    if apk add --no-cache "$@"; then
        exit 0
    fi

    if [ "$attempt" -ge "$retries" ]; then
        echo "apk-install: apk add failed after ${attempt} attempt(s)" >&2
        exit 1
    fi

    attempt=$((attempt + 1))
    echo "apk-install: apk add failed; retrying attempt ${attempt}/${retries} after ${delay_seconds}s" >&2
    sleep "$delay_seconds"
done
