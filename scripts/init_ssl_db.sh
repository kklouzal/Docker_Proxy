#!/bin/sh

set -eu

# Initialize CA + SSL certificate database for Squid ssl-bump.
# - CA key/cert: /etc/squid/ssl/certs/ca.key + ca.crt
# - sslcrtd DB:  /var/lib/ssl_db (bind-mount this for persistence)

SSL_DB_DIR="${SSL_DB_DIR:-/var/lib/ssl_db/store}"

# Keep this lexical path contract aligned with ProxyRuntime's reinitializer.  The
# database may live on a deployment-specific absolute mount, but paths whose
# normalized value is a broad system directory must never reach mkdir/rm/chown.
normalize_ssl_db_dir() {
    python3 - "$1" <<'PY'
import os
import sys

path = os.path.normpath(sys.argv[1])
unsafe_ownership_roots = {"/", "/etc", "/usr", "/var", "/var/lib"}
ownership_parent = os.path.dirname(path)
if (
    not path.startswith("/")
    or path in unsafe_ownership_roots
    or ownership_parent in unsafe_ownership_roots
):
    raise SystemExit(1)
print(path)
PY
}

if ! NORMALIZED_SSL_DB_DIR="$(normalize_ssl_db_dir "$SSL_DB_DIR")"; then
    echo "ERROR: Refusing to initialize ssl_db at unsafe path: $SSL_DB_DIR" >&2
    exit 1
fi
SSL_DB_DIR="$NORMALIZED_SSL_DB_DIR"
unset NORMALIZED_SSL_DB_DIR

mkdir -p "$(dirname "$SSL_DB_DIR")"

repair_ssl_db_permissions() {
    if ! chmod 700 "$SSL_DB_DIR"; then
        echo "ERROR: Failed to set ssl_db mode 0700 on $SSL_DB_DIR" >&2
        return 1
    fi
    if [ -d "$SSL_DB_DIR/certs" ] && ! chmod 750 "$SSL_DB_DIR/certs"; then
        echo "ERROR: Failed to set ssl_db certs mode 0750 on $SSL_DB_DIR/certs" >&2
        return 1
    fi

    if getent passwd squid >/dev/null 2>&1; then
        if ! chown -R squid:squid "$(dirname "$SSL_DB_DIR")"; then
            echo "ERROR: Failed to recursively set squid:squid ownership on $(dirname "$SSL_DB_DIR")" >&2
            return 1
        fi
    fi
}

# Ensure a CA exists (used for on-the-fly cert generation)
sh /scripts/generate_ca.sh

# Find Squid's certificate generator helper (varies by distro/build)
SSLCRTD_BIN=""

if command -v ssl_crtd >/dev/null 2>&1; then
    SSLCRTD_BIN="$(command -v ssl_crtd)"
elif [ -x /usr/lib/squid/ssl_crtd ]; then
    SSLCRTD_BIN="/usr/lib/squid/ssl_crtd"
elif [ -x /usr/libexec/squid/ssl_crtd ]; then
    SSLCRTD_BIN="/usr/libexec/squid/ssl_crtd"
elif [ -x /usr/lib/squid/security_file_certgen ]; then
    SSLCRTD_BIN="/usr/lib/squid/security_file_certgen"
elif [ -x /usr/libexec/squid/security_file_certgen ]; then
    SSLCRTD_BIN="/usr/libexec/squid/security_file_certgen"
fi

if [ -z "$SSLCRTD_BIN" ]; then
    echo "ERROR: Could not find ssl_crtd/security_file_certgen helper. HTTPS ssl-bump will not work." >&2
    exit 1
fi

# Make squid.conf stable by ensuring /usr/lib/squid/ssl_crtd exists
if [ "$SSLCRTD_BIN" != "/usr/lib/squid/ssl_crtd" ]; then
    mkdir -p /usr/lib/squid
    if [ ! -x /usr/lib/squid/ssl_crtd ]; then
        ln -s "$SSLCRTD_BIN" /usr/lib/squid/ssl_crtd || true
    fi
fi

# Initialize or repair the sslcrtd DB if it is missing any expected files.
# A partially created or root-owned DB can make ssl_crtd report the directory
# as "uninitialized" when Squid later reloads after policy updates.
if [ ! -f "$SSL_DB_DIR/index.txt" ] || [ ! -f "$SSL_DB_DIR/size" ] || [ ! -d "$SSL_DB_DIR/certs" ]; then
    rm -rf "$SSL_DB_DIR"
    echo "Initializing sslcrtd DB in $SSL_DB_DIR using $SSLCRTD_BIN"
    "$SSLCRTD_BIN" -c -s "$SSL_DB_DIR" -M 16MB
else
    echo "sslcrtd DB already initialized in $SSL_DB_DIR"
fi

repair_ssl_db_permissions
