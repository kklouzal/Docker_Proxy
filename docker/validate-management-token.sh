#!/bin/sh

set -eu

# Keep startup admission identical to the Python request-time/client normalization.
# POSIX sed character classes do not consistently recognize non-ASCII whitespace,
# which could otherwise disguise a public placeholder that Python str.strip()
# later turns into the effective management secret.
python3 - <<'PY'
import os
import sys

_PUBLIC_PLACEHOLDERS = {
    "",
    "change-me",
    "replace-with-a-long-random-token",
    "replace_with_a_long_random_shared_token",
}

token = (os.environ.get("PROXY_MANAGEMENT_TOKEN") or "").strip()
if token in _PUBLIC_PLACEHOLDERS:
    print(
        "ERROR: PROXY_MANAGEMENT_TOKEN must be set to a private shared token; "
        "configure the same value for the Admin UI and proxy runtime.",
        file=sys.stderr,
    )
    raise SystemExit(1)
PY
