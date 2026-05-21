#!/bin/sh

# Generate a self-signed certificate authority (CA) for Squid ssl-bump.
set -eu

CA_DIR="/etc/squid/ssl/certs"
CA_KEY="$CA_DIR/ca.key"
CA_CERT="$CA_DIR/ca.crt"
DAYS_VALID=3650
LOCK_DIR="$CA_DIR/.ca-generate.lock"

mkdir -p "$CA_DIR"

wait_for_lock() {
    i=0
    while ! mkdir "$LOCK_DIR" 2>/dev/null; do
        if [ $i -ge 120 ]; then
            echo "ERROR: Timed out waiting for CA generation lock: $LOCK_DIR" >&2
            exit 1
        fi
        i=$((i + 1))
        sleep 1
    done
    trap 'rm -rf "$LOCK_DIR"' EXIT INT TERM
}

ca_pair_is_valid() {
    [ -s "$CA_KEY" ] && [ -s "$CA_CERT" ] || return 1
    openssl pkey -in "$CA_KEY" -noout >/dev/null 2>&1 || return 1
    openssl x509 -in "$CA_CERT" -noout >/dev/null 2>&1 || return 1
}

install_ca_permissions() {
    chmod 600 "$CA_KEY" || true
    chmod 644 "$CA_CERT" || true

    # Allow Squid (typically runs as user 'squid') to read the CA key.
    if getent passwd squid >/dev/null 2>&1; then
        chown squid:squid "$CA_KEY" "$CA_CERT" || true
        chmod 640 "$CA_KEY" || true
    fi
}

wait_for_lock

if ca_pair_is_valid; then
    echo "CA already exists. Skipping generation."
else
    rm -f "$CA_KEY.tmp" "$CA_CERT.tmp"
    openssl genrsa -out "$CA_KEY.tmp" 2048
    openssl req -x509 -new -nodes -key "$CA_KEY.tmp" -sha256 -days "$DAYS_VALID" -out "$CA_CERT.tmp" -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=Squid Proxy CA"
    mv -f "$CA_KEY.tmp" "$CA_KEY"
    mv -f "$CA_CERT.tmp" "$CA_CERT"
    echo "Self-signed CA certificate generated: $CA_CERT"
fi

install_ca_permissions

echo "CA files available in $CA_DIR"
