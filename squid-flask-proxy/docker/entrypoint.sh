#!/bin/sh

set -eu

# Initialize environment variables
if [ -f /config/app.env ]; then
    export $(cat /config/app.env | xargs)
fi

# Ensure squid.conf is based on our template (needed for caching + ssl-bump).
# If the file already looks like our managed config, keep it.
TEMPLATE=""
if [ -f /etc/squid/squid.conf.template ]; then
    TEMPLATE="/etc/squid/squid.conf.template"
elif [ -f /squid/squid.conf.template ]; then
    TEMPLATE="/squid/squid.conf.template"
fi

if [ -n "$TEMPLATE" ]; then
    if [ ! -f /etc/squid/squid.conf ] || ! grep -q "ssl_bump" /etc/squid/squid.conf 2>/dev/null; then
        cp "$TEMPLATE" /etc/squid/squid.conf
    fi
fi

# Upgrade path: ensure ClamAV adaptation policy exists if ICAP is enabled.
# Insert av_resp_set rules before html_preload_set if missing.
if [ -f /etc/squid/squid.conf ]; then
    if grep -qi "^\s*icap_enable\s\+on\b" /etc/squid/squid.conf 2>/dev/null \
        && grep -qi "^\s*adaptation_access\s\+html_preload_set\b" /etc/squid/squid.conf 2>/dev/null \
        && ! grep -qi "^\s*adaptation_access\s\+av_resp_set\b" /etc/squid/squid.conf 2>/dev/null; then
        awk '
            BEGIN{done=0}
            {line=$0}
            tolower($0) ~ /^\s*adaptation_access\s+html_preload_set\b/ && done==0 {
                print "# Antivirus scanning (RESPMOD): c-icap + ClamAV";
                print "# Runs before HTML response rewriting.";
                print "adaptation_access av_resp_set allow icap_adblockable";
                print "adaptation_access av_resp_set deny all";
                print "";
                done=1
            }
            {print line}
        ' /etc/squid/squid.conf > /tmp/squid.conf.tmp && mv /tmp/squid.conf.tmp /etc/squid/squid.conf
    fi
fi

# Generate Squid include snippets for ICAP scaling.
# We derive the worker count from squid.conf so UI edits like "workers 4" validate.
mkdir -p /etc/squid/conf.d

WORKERS=""
if [ -f /etc/squid/squid.conf ]; then
    # Extract the first "workers N" directive.
    WORKERS=$(awk 'tolower($1)=="workers" && $2 ~ /^[0-9]+$/ {print $2; exit}' /etc/squid/squid.conf 2>/dev/null || true)
fi

if [ -z "$WORKERS" ]; then
    WORKERS_RAW="${SQUID_WORKERS:-2}"
    case "$WORKERS_RAW" in
        ''|*[!0-9]*) WORKERS=2 ;;
        *) WORKERS="$WORKERS_RAW" ;;
    esac
fi

if [ "$WORKERS" -lt 1 ]; then
    WORKERS=1
fi

# Ensure supervisord sees a valid value even if compose didn't set it.
export SQUID_WORKERS="$WORKERS"

# Generate supervisord program config for ICAP based on current workers.
mkdir -p /etc/supervisor.d
{
    echo "[program:icap]"
    echo "directory=/app"
    echo "process_name=icap_%(process_num)s"
    echo "numprocs=$WORKERS"
    echo "environment=PROC_NUM=%(process_num)s"
    echo "command=/bin/sh -c 'BASE=\${ICAP_BASE_PORT:-1344}; PORT=\$((BASE + \${PROC_NUM:-0})); ICAP_BIND=127.0.0.1 ICAP_PORT=\$PORT exec python3 /app/icap_server.py'"
    echo "autostart=true"
    echo "autorestart=true"
    echo "stderr_logfile=/dev/stderr"
    echo "stdout_logfile=/dev/stdout"
    echo "stderr_logfile_maxbytes=0"
    echo "stdout_logfile_maxbytes=0"
} > /etc/supervisor.d/icap.conf

# Run c-icap for AV (ClamAV) ICAP service.
# Squid's av_resp_set always points to c-icap; the Python ICAP server no longer implements /avrespmod.
CICAP_PORT_RAW="${CICAP_PORT:-14000}"
case "$CICAP_PORT_RAW" in
    ''|*[!0-9]*) CICAP_PORT=14000 ;;
    *) CICAP_PORT="$CICAP_PORT_RAW" ;;
esac

mkdir -p /var/run/c-icap
cat > /etc/supervisor.d/cicap.conf <<'EOF'
[program:cicap]
command=/bin/sh -c 'p=/var/lib/squid-flask-proxy/clamav/clamd.sock; i=0; while [ "$i" -lt 60 ]; do [ -S "$p" ] && break; i=$((i + 1)); sleep 1; done; exec /usr/bin/c-icap -N -D -d 1 -f /etc/c-icap/c-icap.conf'
autostart=true
autorestart=true
stderr_logfile=/dev/stderr
stdout_logfile=/dev/stdout
stderr_logfile_maxbytes=0
stdout_logfile_maxbytes=0
EOF

# Keep c-icap config port in sync with env.
if [ -f /etc/c-icap/c-icap.conf ]; then
    # Replace any existing Port directive; otherwise append.
    if grep -qi "^\s*Port\s\+" /etc/c-icap/c-icap.conf 2>/dev/null; then
        sed -i "s/^\s*Port\s\+.*/Port ${CICAP_PORT}/I" /etc/c-icap/c-icap.conf
    else
        echo "Port ${CICAP_PORT}" >> /etc/c-icap/c-icap.conf
    fi
fi

BASE_RAW="${ICAP_BASE_PORT:-1344}"
case "$BASE_RAW" in
    ''|*[!0-9]*) ICAP_BASE_PORT=1344 ;;
    *) ICAP_BASE_PORT="$BASE_RAW" ;;
esac

REQ_NAMES=""
AV_NAMES=""
RESP_NAMES=""

{
    i=0
    while [ "$i" -lt "$WORKERS" ]; do
        port=$((ICAP_BASE_PORT + i))
        echo "icap_service adblock_req_${i} reqmod_precache icap://127.0.0.1:${port}/reqmod bypass=on"
        echo "icap_service av_resp_${i} respmod_precache icap://127.0.0.1:${CICAP_PORT}/avrespmod bypass=on"
        echo "icap_service html_preload_${i} respmod_precache icap://127.0.0.1:${port}/respmod bypass=on"
        REQ_NAMES="$REQ_NAMES adblock_req_${i}"
        AV_NAMES="$AV_NAMES av_resp_${i}"
        RESP_NAMES="$RESP_NAMES html_preload_${i}"
        i=$((i + 1))
    done

    # Squid will select a service from the set (round-robin/availability) for each transaction.
    echo "adaptation_service_set adblock_req_set$REQ_NAMES"
    echo "adaptation_service_set av_resp_set$AV_NAMES"
    echo "adaptation_service_set html_preload_set$RESP_NAMES"
} > /etc/squid/conf.d/20-icap.conf

# Normalize known distro path differences without overwriting user config
if [ -f /etc/squid/squid.conf ] && grep -q "/usr/share/squid/errors/English" /etc/squid/squid.conf 2>/dev/null; then
    sed -i 's#/usr/share/squid/errors/English#/usr/share/squid/errors/en#g' /etc/squid/squid.conf
fi

# Initialize CA + SSL DB for ssl-bump
sh /scripts/init_ssl_db.sh

# Initialize cache dirs (safe to re-run)
mkdir -p /var/spool/squid /var/log/squid
mkdir -p /var/lib/squid-flask-proxy

# ClamAV bootstrap: first startup needs a signature DB download.
# Persist DB + socket under /var/lib/squid-flask-proxy so restarts are fast.
# Note: scanning enable/disable is controlled by Squid policy (web UI), not env vars.
# ClamAV on Alpine can be picky about config file line endings.
sed -i 's/\r$//' /etc/clamav/clamd.conf /etc/clamav/freshclam.conf 2>/dev/null || true

CLAMAV_ROOT="/var/lib/squid-flask-proxy/clamav"
CLAMAV_DB="${CLAMAV_ROOT}/db"
mkdir -p "${CLAMAV_DB}"
rm -f "${CLAMAV_ROOT}/clamd.sock" || true
if getent passwd clamav >/dev/null 2>&1; then
    chown -R clamav:clamav "${CLAMAV_ROOT}" || true
fi

if [ ! -f "${CLAMAV_DB}/main.cld" ] && [ ! -f "${CLAMAV_DB}/main.cvd" ]; then
    echo "[clamav] signature DB missing; running initial freshclam (blocking)..." >&2
    # Use our config so it writes into the persisted DatabaseDirectory.
    freshclam --foreground --stdout --config-file=/etc/clamav/freshclam.conf
    echo "[clamav] initial signature DB ready." >&2
fi

# Generate Dante (sockd) config used by supervisord.
# Default policy: no-auth SOCKS5, LAN-restricted, allow TCP + UDP.
if [ "${ENABLE_DANTE:-1}" = "1" ]; then
    # Ensure log file exists and is writable by the unprivileged user.
    mkdir -p /var/log
    touch /var/log/sockd.log || true
    if getent passwd sockd >/dev/null 2>&1; then
        chown sockd:sockd /var/log/sockd.log || true
    fi

    DANTE_INTERNAL="${DANTE_INTERNAL:-0.0.0.0}"
    DANTE_PORT="${DANTE_PORT:-1080}"
    DANTE_EXTERNAL="${DANTE_EXTERNAL:-eth0}"
    DANTE_ALLOW_FROM="${DANTE_ALLOW_FROM:-10.0.0.0/8 172.16.0.0/12 192.168.0.0/16}"
    DANTE_BLOCK_PRIVATE_DESTS="${DANTE_BLOCK_PRIVATE_DESTS:-1}"

    {
        echo "logoutput: stderr /var/log/sockd.log"
        echo "internal: ${DANTE_INTERNAL} port = ${DANTE_PORT}"
        echo "external: ${DANTE_EXTERNAL}"
        echo "socksmethod: none"
        echo "clientmethod: none"
        echo "user.privileged: sockd"
        echo "user.unprivileged: sockd"
        echo

        # Client allow-list (who may connect to the SOCKS server).
        for cidr in ${DANTE_ALLOW_FROM}; do
            echo "client pass {"
            echo "        from: ${cidr} port 1-65535 to: 0.0.0.0/0"
            echo "        log: connect disconnect error"
            echo "}"
            echo
        done
        echo "client block {"
        echo "        from: 0.0.0.0/0 to: 0.0.0.0/0"
        echo "        log: connect error"
        echo "}"
        echo

        # Prevent the SOCKS proxy from being used to pivot into local/private networks.
        # This blocks requests to loopback + RFC1918 destination ranges.
        if [ "${DANTE_BLOCK_PRIVATE_DESTS}" = "1" ]; then
            echo "socks block {"
            echo "        from: 0.0.0.0/0 to: 127.0.0.0/8"
            echo "        log: connect error"
            echo "}"
            echo
            echo "socks block {"
            echo "        from: 0.0.0.0/0 to: 10.0.0.0/8"
            echo "        log: connect error"
            echo "}"
            echo
            echo "socks block {"
            echo "        from: 0.0.0.0/0 to: 172.16.0.0/12"
            echo "        log: connect error"
            echo "}"
            echo
            echo "socks block {"
            echo "        from: 0.0.0.0/0 to: 192.168.0.0/16"
            echo "        log: connect error"
            echo "}"
            echo
        fi
        echo

        # SOCKS request allow-list (what those clients may do).
        for cidr in ${DANTE_ALLOW_FROM}; do
            echo "socks pass {"
            echo "        from: ${cidr} to: 0.0.0.0/0"
            echo "        protocol: tcp udp"
            echo "        log: connect disconnect error"
            echo "}"
            echo
            # Allow replies back to clients for BIND/UDP flows.
            echo "socks pass {"
            echo "        from: 0.0.0.0/0 to: ${cidr}"
            echo "        command: bindreply udpreply"
            echo "        log: connect disconnect error"
            echo "}"
            echo
        done
        echo "socks block {"
        echo "        from: 0.0.0.0/0 to: 0.0.0.0/0"
        echo "        log: connect error"
        echo "}"
    } > /etc/sockd.generated.conf
else
    # Still create a valid config file to avoid supervisord crash loops if enabled later.
    echo "logoutput: stderr" > /etc/sockd.generated.conf
fi

# Squid typically drops privileges to user 'squid'; ensure it can write cache/logs.
if getent passwd squid >/dev/null 2>&1; then
    chown -R squid:squid /var/spool/squid /var/log/squid || true
fi
# Build cache dirs without daemonizing (avoid leaving a running squid instance)
squid -N -z || true
rm -f /var/run/squid.pid || true

# Start Supervisor to manage Squid and Flask
exec /usr/bin/supervisord -c /etc/supervisord.conf