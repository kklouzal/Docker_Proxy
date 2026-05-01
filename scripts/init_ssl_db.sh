#!/bin/sh

set -eu

# Initialize CA + SSL certificate database for Squid ssl-bump.
# - CA key/cert: /etc/squid/ssl/certs/ca.key + ca.crt
# - sslcrtd DB:  /var/lib/ssl_db (bind-mount this for persistence)

SSL_DB_DIR="${SSL_DB_DIR:-/var/lib/ssl_db/store}"

mkdir -p "$(dirname "$SSL_DB_DIR")"

repair_ssl_db_permissions() {
    chmod 700 "$SSL_DB_DIR" 2>/dev/null || true
    if [ -d "$SSL_DB_DIR/certs" ]; then
        chmod 750 "$SSL_DB_DIR/certs" 2>/dev/null || true
    fi

    if getent passwd squid >/dev/null 2>&1; then
        chown -R squid:squid "$(dirname "$SSL_DB_DIR")" || true
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