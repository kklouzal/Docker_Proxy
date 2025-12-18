#!/bin/sh

# Generate a self-signed certificate authority (CA) for Squid ssl-bump
set -eu

CA_DIR="/etc/squid/ssl/certs"
CA_KEY="$CA_DIR/ca.key"
CA_CERT="$CA_DIR/ca.crt"
DAYS_VALID=3650

mkdir -p "$CA_DIR"

if [ ! -f "$CA_KEY" ] || [ ! -f "$CA_CERT" ]; then
    openssl genrsa -out "$CA_KEY" 2048
    openssl req -x509 -new -nodes -key "$CA_KEY" -sha256 -days "$DAYS_VALID" -out "$CA_CERT" -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=Squid Proxy CA"
    echo "Self-signed CA certificate generated: $CA_CERT"
else
    echo "CA already exists. Skipping generation."
fi

chmod 600 "$CA_KEY" || true
chmod 644 "$CA_CERT" || true

# Allow Squid (typically runs as user 'squid') to read the CA key
if getent passwd squid >/dev/null 2>&1; then
    chown squid:squid "$CA_KEY" "$CA_CERT" || true
    chmod 640 "$CA_KEY" || true
fi

echo "CA files available in $CA_DIR"