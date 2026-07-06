#!/bin/sh

set -eu

# shellcheck source=/dev/null
. /usr/local/bin/load-env.sh

IPV6_DISABLED=0
case "$(printf '%s' "${DISABLE_IPV6:-0}" | tr '[:upper:]' '[:lower:]')" in
    1|true|yes|on)
        IPV6_DISABLED=1
        ;;
esac

TEST_MODE_ENABLED=0
case "$(printf '%s' "${ENABLE_TEST_MODE:-0}" | tr '[:upper:]' '[:lower:]')" in
    1|true|yes|on)
        TEST_MODE_ENABLED=1
        ;;
esac

env_enabled() {
    case "$(printf '%s' "${1:-0}" | tr '[:upper:]' '[:lower:]')" in
        1|true|yes|on|required|strict) return 0 ;;
        *) return 1 ;;
    esac
}

LOCALHOST_SRC_ACL="127.0.0.1/32 ::1"
if [ "$IPV6_DISABLED" = "1" ]; then
    LOCALHOST_SRC_ACL="127.0.0.1/32"
fi

clamp_int() {
    val="$1"
    min="$2"
    max="$3"
    if [ "$val" -lt "$min" ]; then
        val="$min"
    fi
    if [ "$val" -gt "$max" ]; then
        val="$max"
    fi
    printf '%s\n' "$val"
}

recommend_sslcrtd_children() {
    workers="$1"
    children=$((workers * 2))
    clamp_int "$children" 2 8
}

recommend_dynamic_cert_cache_mb() {
    workers="$1"
    cache_mb=$((workers * 128))
    cache_mb="$(clamp_int "$cache_mb" 128 512)"
    cache_mb=$(( ((cache_mb + 63) / 64) * 64 ))
    printf '%s\n' "$cache_mb"
}

recommend_nofile() {
    workers="$1"
    nofile=$((workers * 32768))
    clamp_int "$nofile" 65536 131072
}

recommend_webfilter_helpers() {
    workers="$1"
    helpers=$((workers * 2))
    clamp_int "$helpers" 2 8
}

recommend_db_pool_size() {
    workers="$1"
    pool=$((workers + 3))
    clamp_int "$pool" 4 8
}

extract_squid_workers_from_file() {
    file_path="$1"
    if [ ! -f "$file_path" ]; then
        return 0
    fi
    awk 'tolower($1)=="workers" && $2 ~ /^[0-9]+$/ {print $2; exit}' "$file_path" 2>/dev/null || true
}

sanitize_positive_int() {
    raw="$1"
    case "$raw" in
        ''|*[!0-9]*) printf '' ;;
        *)
            if [ "$raw" -lt 1 ]; then
                printf ''
            else
                printf '%s' "$raw"
            fi
            ;;
    esac
}

sanitize_nonnegative_int() {
    raw="$1"
    case "$raw" in
        ''|*[!0-9]*) printf '' ;;
        *) printf '%s' "$raw" ;;
    esac
}

sanitize_bind_host() {
    raw="$1"
    case "$raw" in
        ''|*[!A-Za-z0-9_.:-]*) printf '' ;;
        *) printf '%s' "$raw" ;;
    esac
}

config_has_directive() {
    file_path="$1"
    key="$2"
    grep -qiE "^[[:space:]]*${key}[[:space:]]+" "$file_path" 2>/dev/null
}

if [ -z "${DB_POOL_MAX_IDLE_SECONDS:-}" ]; then
    export DB_POOL_MAX_IDLE_SECONDS=30
fi
if [ -z "${LIVE_STATS_COMMIT_BATCH:-}" ]; then
    export LIVE_STATS_COMMIT_BATCH=500
fi
if [ -z "${LIVE_STATS_COMMIT_INTERVAL_SECONDS:-}" ]; then
    export LIVE_STATS_COMMIT_INTERVAL_SECONDS=3.0
fi
if [ -z "${LIVE_STATS_POLL_INTERVAL_SECONDS:-}" ]; then
    export LIVE_STATS_POLL_INTERVAL_SECONDS=2.0
fi
if [ -z "${LIVE_STATS_MAX_PENDING_ROWS:-}" ]; then
    export LIVE_STATS_MAX_PENDING_ROWS=5000
fi
if [ -z "${LIVE_STATS_DB_WRITE_BACKOFF_INITIAL_SECONDS:-}" ]; then
    export LIVE_STATS_DB_WRITE_BACKOFF_INITIAL_SECONDS=5.0
fi
if [ -z "${LIVE_STATS_DB_WRITE_BACKOFF_MAX_SECONDS:-}" ]; then
    export LIVE_STATS_DB_WRITE_BACKOFF_MAX_SECONDS=120.0
fi
if [ -z "${LIVE_STATS_DB_WRITE_BACKOFF_JITTER_RATIO:-}" ]; then
    export LIVE_STATS_DB_WRITE_BACKOFF_JITTER_RATIO=0.2
fi
if [ -z "${DIAGNOSTIC_COMMIT_BATCH:-}" ]; then
    export DIAGNOSTIC_COMMIT_BATCH=400
fi
if [ -z "${DIAGNOSTIC_COMMIT_INTERVAL_SECONDS:-}" ]; then
    export DIAGNOSTIC_COMMIT_INTERVAL_SECONDS=3.0
fi
if [ -z "${DIAGNOSTIC_POLL_INTERVAL_SECONDS:-}" ]; then
    export DIAGNOSTIC_POLL_INTERVAL_SECONDS=2.0
fi
if [ -z "${DIAGNOSTIC_PENDING_MAX_ROWS:-}" ]; then
    export DIAGNOSTIC_PENDING_MAX_ROWS=5000
fi
if [ -z "${DIAGNOSTIC_DB_WRITE_BACKOFF_INITIAL_SECONDS:-}" ]; then
    export DIAGNOSTIC_DB_WRITE_BACKOFF_INITIAL_SECONDS=5.0
fi
if [ -z "${DIAGNOSTIC_DB_WRITE_BACKOFF_MAX_SECONDS:-}" ]; then
    export DIAGNOSTIC_DB_WRITE_BACKOFF_MAX_SECONDS=120.0
fi
if [ -z "${DIAGNOSTIC_DB_WRITE_BACKOFF_JITTER_RATIO:-}" ]; then
    export DIAGNOSTIC_DB_WRITE_BACKOFF_JITTER_RATIO=0.2
fi
if [ -z "${SSL_ERRORS_COMMIT_BATCH:-}" ]; then
    export SSL_ERRORS_COMMIT_BATCH=300
fi
if [ -z "${SSL_ERRORS_COMMIT_INTERVAL_SECONDS:-}" ]; then
    export SSL_ERRORS_COMMIT_INTERVAL_SECONDS=3.0
fi
if [ -z "${SSL_ERRORS_POLL_INTERVAL_SECONDS:-}" ]; then
    export SSL_ERRORS_POLL_INTERVAL_SECONDS=2.0
fi
if [ -z "${STATS_CACHE_DIR_SIZE_TTL_SECONDS:-}" ]; then
    export STATS_CACHE_DIR_SIZE_TTL_SECONDS=300
fi
if [ -z "${TIMESERIES_ROLLUP_INTERVAL_SECONDS:-}" ]; then
    export TIMESERIES_ROLLUP_INTERVAL_SECONDS=300.0
fi
if [ -z "${TIMESERIES_STARTUP_JITTER_SECONDS:-}" ]; then
    export TIMESERIES_STARTUP_JITTER_SECONDS=15.0
fi
if [ -z "${TIMESERIES_SAMPLE_DB_BACKOFF_INITIAL_SECONDS:-}" ]; then
    export TIMESERIES_SAMPLE_DB_BACKOFF_INITIAL_SECONDS=5.0
fi
if [ -z "${TIMESERIES_SAMPLE_DB_BACKOFF_MAX_SECONDS:-}" ]; then
    export TIMESERIES_SAMPLE_DB_BACKOFF_MAX_SECONDS=120.0
fi
if [ -z "${TIMESERIES_SAMPLE_DB_BACKOFF_JITTER_RATIO:-}" ]; then
    export TIMESERIES_SAMPLE_DB_BACKOFF_JITTER_RATIO=0.2
fi
if [ -z "${TIMESERIES_ROLLUP_DB_BACKOFF_INITIAL_SECONDS:-}" ]; then
    export TIMESERIES_ROLLUP_DB_BACKOFF_INITIAL_SECONDS=30.0
fi
if [ -z "${TIMESERIES_ROLLUP_DB_BACKOFF_MAX_SECONDS:-}" ]; then
    export TIMESERIES_ROLLUP_DB_BACKOFF_MAX_SECONDS=300.0
fi
if [ -z "${TIMESERIES_ROLLUP_DB_BACKOFF_JITTER_RATIO:-}" ]; then
    export TIMESERIES_ROLLUP_DB_BACKOFF_JITTER_RATIO=0.2
fi
PAC_HTTP_PORT="$(sanitize_positive_int "${PAC_HTTP_PORT:-80}")"
export PAC_HTTP_PORT="${PAC_HTTP_PORT:-80}"
PAC_HTTP_HOST="$(sanitize_bind_host "${PAC_HTTP_HOST:-0.0.0.0}")"
export PAC_HTTP_HOST="${PAC_HTTP_HOST:-0.0.0.0}"
WEB_WORKERS="$(sanitize_positive_int "${WEB_WORKERS:-1}")"
export WEB_WORKERS="${WEB_WORKERS:-1}"
WEB_THREADS="$(sanitize_positive_int "${WEB_THREADS:-2}")"
export WEB_THREADS="${WEB_THREADS:-2}"
WEB_TIMEOUT="$(sanitize_positive_int "${WEB_TIMEOUT:-120}")"
export WEB_TIMEOUT="${WEB_TIMEOUT:-120}"
WEB_GRACEFUL_TIMEOUT="$(sanitize_positive_int "${WEB_GRACEFUL_TIMEOUT:-30}")"
export WEB_GRACEFUL_TIMEOUT="${WEB_GRACEFUL_TIMEOUT:-30}"
WEB_KEEPALIVE="$(sanitize_nonnegative_int "${WEB_KEEPALIVE:-5}")"
export WEB_KEEPALIVE="${WEB_KEEPALIVE:-5}"
if [ "$TEST_MODE_ENABLED" = "1" ]; then
    if [ -z "${PROXY_HEARTBEAT_INTERVAL_SECONDS:-}" ]; then
        export PROXY_HEARTBEAT_INTERVAL_SECONDS=5
    fi
    if [ -z "${PROXY_SYNC_INTERVAL_SECONDS:-}" ]; then
        export PROXY_SYNC_INTERVAL_SECONDS=5
    fi
fi

replace_or_append_config_line() {
    file_path="$1"
    key="$2"
    value="$3"
    if grep -qiE "^[[:space:]]*${key}[[:space:]]+" "$file_path" 2>/dev/null; then
        sed -i -E "s#^([[:space:]]*${key}[[:space:]]+).*\$#\\1${value}#I" "$file_path" 2>/dev/null || \
            sed -i -E "s#^([[:space:]]*${key}[[:space:]]+).*\$#\\1${value}#" "$file_path" || true
    else
        printf '\n%s %s\n' "$key" "$value" >> "$file_path"
    fi
}

extract_sslcrtd_child_option() {
    file_path="$1"
    option_name="$2"
    if [ ! -f "$file_path" ]; then
        printf ''
        return 0
    fi
    awk -v opt="$option_name" '
        /^[[:space:]]*#/ { next }
        tolower($1)=="sslcrtd_children" {
            for (i = 3; i <= NF; i++) {
                if (index($i, "=") == 0) {
                    continue
                }
                split($i, parts, "=")
                if (tolower(parts[1]) == opt && parts[2] ~ /^[0-9]+$/) {
                    print parts[2]
                    exit
                }
            }
            exit
        }
    ' "$file_path" 2>/dev/null || true
}

build_sslcrtd_children_value() {
    file_path="$1"
    children="$2"
    startup="$(extract_sslcrtd_child_option "$file_path" "startup")"
    idle="$(extract_sslcrtd_child_option "$file_path" "idle")"
    queue_size="$(extract_sslcrtd_child_option "$file_path" "queue-size")"

    if [ -z "$startup" ]; then
        startup=2
    fi
    if [ -z "$idle" ]; then
        idle=1
    fi
    if [ -z "$queue_size" ]; then
        queue_size=32
    fi

    printf '%s startup=%s idle=%s queue-size=%s\n' "$children" "$startup" "$idle" "$queue_size"
}

normalize_http_port_listeners() {
    file_path="$1"
    if [ ! -f "$file_path" ]; then
        return 0
    fi

    SQUID_CFG_PATH="$file_path" python3 - <<'PY' || true
from pathlib import Path
import os
import re


def coerce_port(value, default):
    try:
        parsed = int(str(value or '').strip() or str(default))
    except Exception:
        parsed = int(default)
    return min(65535, max(1, parsed))


def default_intercept_port(explicit_port):
    return explicit_port + 1 if explicit_port < 65535 else 3129


def first_available_port(preferred, used_ports):
    candidate = coerce_port(preferred, 3130)
    for _ in range(65535):
        if candidate not in used_ports:
            return candidate
        candidate = 1 if candidate >= 65535 else candidate + 1
    raise ValueError('No available TCP listener ports remain.')


def enabled(value):
    return str(value or '').strip().lower() in {'1', 'true', 'yes', 'on'}


def logical_lines(text):
    out = []
    pending = []
    for raw in text.splitlines():
        pending.append(raw)
        if raw.rstrip().endswith('\\'):
            continue
        logical = ' '.join(line.rstrip().rstrip('\\').strip() for line in pending).strip()
        out.append((pending, logical))
        pending = []
    if pending:
        logical = ' '.join(line.rstrip().rstrip('\\').strip() for line in pending).strip()
        out.append((pending, logical))
    return out


def extract_dynamic_cache_mb(text):
    match = re.search(r'dynamic_cert_mem_cache_size\s*=\s*(\d+)\s*MB', text or '', re.I)
    if match:
        try:
            return max(0, int(match.group(1)))
        except Exception:
            pass
    try:
        return max(0, int(str(os.environ.get('SQUID_DYNAMIC_CERT_MEM_CACHE_MB') or '').strip() or '128'))
    except Exception:
        return 128


def extract_port(token):
    token = str(token or '').strip()
    if token.isdigit():
        return coerce_port(token, 3128)
    if token.startswith('[') and ']:' in token:
        candidate = token.rsplit(':', 1)[1]
    elif ':' in token:
        candidate = token.rsplit(':', 1)[1]
    else:
        return None
    if not candidate.isdigit():
        return None
    return coerce_port(candidate, 3128)


def explicit_lines(port, dynamic_cache_mb):
    return [
        f'http_port 0.0.0.0:{port} ssl-bump \\',
        '\tcert=/etc/squid/ssl/certs/ca.crt \\',
        '\tkey=/etc/squid/ssl/certs/ca.key \\',
        '\tgenerate-host-certificates=on \\',
        f'\tdynamic_cert_mem_cache_size={max(0, int(dynamic_cache_mb))}MB',
    ]


def intercept_block(port):
    return [
        '# BEGIN SQUID-UI INTERCEPT LISTENER',
        '# HTTP NAT intercept listener. Requires external REDIRECT/DNAT rules; do not expose directly.',
        f'http_port 0.0.0.0:{port} intercept',
        '# END SQUID-UI INTERCEPT LISTENER',
    ]


def https_intercept_block(port, dynamic_cache_mb):
    return [
        '# BEGIN SQUID-UI HTTPS INTERCEPT LISTENER',
        '# HTTPS NAT intercept listener. Requires TCP/443 REDIRECT/DNAT and explicit operator consent.',
        f'https_port 0.0.0.0:{port} intercept ssl-bump \\',
        '\tname=https_intercept \\',
        '\tcert=/etc/squid/ssl/certs/ca.crt \\',
        '\tkey=/etc/squid/ssl/certs/ca.key \\',
        '\tgenerate-host-certificates=on \\',
        f'	dynamic_cert_mem_cache_size={max(0, int(dynamic_cache_mb))}MB',
        '# END SQUID-UI HTTPS INTERCEPT LISTENER',
    ]


def https_intercept_splice_block():
    return [
        '# BEGIN SQUID-UI HTTPS INTERCEPT SPLICE',
        '# Splice all traffic arriving on the dedicated HTTPS NAT intercept listener.',
        'acl https_intercept_listener myportname https_intercept',
        'ssl_bump splice https_intercept_listener',
        '# END SQUID-UI HTTPS INTERCEPT SPLICE',
    ]


def strip_managed_https_splice(lines):
    stripped = []
    skipping = False
    managed_exact = {
        'acl https_intercept_listener myportname https_intercept',
        'ssl_bump splice https_intercept_listener',
    }
    for line in lines:
        if '# BEGIN SQUID-UI HTTPS INTERCEPT SPLICE' in line:
            skipping = True
            continue
        if skipping:
            if '# END SQUID-UI HTTPS INTERCEPT SPLICE' in line:
                skipping = False
            continue
        if line.strip() in managed_exact:
            continue
        stripped.append(line)
    return stripped


def insert_https_splice_block(lines):
    block = https_intercept_splice_block()
    for index, line in enumerate(lines):
        if line.strip().lower() == 'ssl_bump peek step1':
            return lines[: index + 1] + block + lines[index + 1 :]
    for index, line in enumerate(lines):
        if line.strip().lower().startswith('include /etc/squid/conf.d/10-sslfilter.conf'):
            return lines[:index] + block + lines[index:]
    return lines + [''] + block


def config_has_https_intercept(text):
    for _physical, logical in logical_lines(text):
        stripped = logical.strip()
        if not stripped or stripped.startswith('#') or not stripped.lower().startswith('https_port '):
            continue
        parts = stripped.split()
        modes = {part.strip().lower() for part in parts[2:]}
        if 'intercept' in modes:
            return True
    return False


def first_explicit_port(text):
    for _physical, logical in logical_lines(text):
        stripped = logical.strip()
        if not stripped or stripped.startswith('#') or not stripped.lower().startswith('http_port '):
            continue
        parts = stripped.split()
        if len(parts) < 2:
            continue
        modes = {part.strip().lower() for part in parts[2:]}
        if 'intercept' in modes or 'tproxy' in modes:
            continue
        port = extract_port(parts[1])
        if port:
            return port
    return None


path = Path(os.environ['SQUID_CFG_PATH'])
text = path.read_text(encoding='utf-8')
explicit_env = str(os.environ.get('SQUID_HTTP_PORT') or '').strip()
intercept_env = str(os.environ.get('SQUID_INTERCEPT_ENABLED') or '').strip()
intercept_port_env = str(os.environ.get('SQUID_INTERCEPT_PORT') or '').strip()
https_intercept_env = str(os.environ.get('SQUID_HTTPS_INTERCEPT_ENABLED') or '').strip()
https_intercept_port_env = str(os.environ.get('SQUID_HTTPS_INTERCEPT_PORT') or '').strip()
https_intercept_splice_env = str(os.environ.get('SQUID_HTTPS_INTERCEPT_SPLICE_ONLY') or '').strip()
if not any((explicit_env, intercept_env, intercept_port_env, https_intercept_env, https_intercept_port_env, https_intercept_splice_env)):
    raise SystemExit(0)

explicit_env_set = bool(explicit_env)
intercept_env_set = bool(intercept_env)
https_intercept_env_set = bool(https_intercept_env)
https_intercept_splice_env_set = bool(https_intercept_splice_env)
intercept_on = enabled(intercept_env) if intercept_env_set else None
https_intercept_on = enabled(https_intercept_env) if https_intercept_env_set else None
https_intercept_splice_on = enabled(https_intercept_splice_env) if https_intercept_splice_env_set else None
explicit_port = coerce_port(explicit_env, first_explicit_port(text) or 3128)
intercept_port = coerce_port(intercept_port_env, default_intercept_port(explicit_port))
https_intercept_port = coerce_port(https_intercept_port_env, 3130 if explicit_port != 3130 else 3131)
dynamic_cache_mb = extract_dynamic_cache_mb(text)
existing_https_intercept = config_has_https_intercept(text)
https_intercept_effective = https_intercept_on is True or (https_intercept_on is None and (https_intercept_port_env or existing_https_intercept))

rendered = []
replaced_explicit = False
skipping_intercept = False
for physical, logical in logical_lines(text):
    if any('# BEGIN SQUID-UI INTERCEPT LISTENER' in line for line in physical):
        if intercept_env_set or intercept_port_env:
            skipping_intercept = True
        else:
            rendered.extend(physical)
            continue
    if any('# BEGIN SQUID-UI HTTPS INTERCEPT LISTENER' in line for line in physical):
        if https_intercept_env_set or https_intercept_port_env:
            skipping_intercept = True
        else:
            rendered.extend(physical)
            continue
    if skipping_intercept:
        if any('# END SQUID-UI INTERCEPT LISTENER' in line for line in physical) or any('# END SQUID-UI HTTPS INTERCEPT LISTENER' in line for line in physical):
            skipping_intercept = False
        continue

    stripped = logical.strip()
    if stripped and not stripped.startswith('#') and stripped.lower().startswith('http_port '):
        parts = stripped.split()
        modes = {part.strip().lower() for part in parts[2:]}
        if 'intercept' not in modes and 'tproxy' not in modes and not replaced_explicit:
            current_explicit_port = extract_port(parts[1]) or explicit_port
            if explicit_env_set:
                rendered.extend(explicit_lines(explicit_port, dynamic_cache_mb))
                current_explicit_port = explicit_port
            else:
                rendered.extend(physical)
            if intercept_port == current_explicit_port:
                intercept_port = default_intercept_port(current_explicit_port)
                if intercept_port == current_explicit_port:
                    intercept_port = 3129 if current_explicit_port != 3129 else 3130
            used_ports = {current_explicit_port}
            if intercept_on is True or (intercept_on is None and intercept_port_env):
                rendered.extend(intercept_block(intercept_port))
                used_ports.add(intercept_port)
            https_intercept_port = first_available_port(https_intercept_port, used_ports)
            if https_intercept_on is True or (https_intercept_on is None and https_intercept_port_env):
                rendered.extend(https_intercept_block(https_intercept_port, dynamic_cache_mb))
            replaced_explicit = True
            continue

    rendered.extend(physical)

if not replaced_explicit:
    prefix = explicit_lines(explicit_port, dynamic_cache_mb)
    used_ports = {explicit_port}
    if intercept_on is True or (intercept_on is None and intercept_port_env):
        prefix.extend(intercept_block(intercept_port))
        used_ports.add(intercept_port)
    https_intercept_port = first_available_port(https_intercept_port, used_ports)
    if https_intercept_on is True or (https_intercept_on is None and https_intercept_port_env):
        prefix.extend(https_intercept_block(https_intercept_port, dynamic_cache_mb))
    rendered = prefix + [''] + rendered

if https_intercept_splice_env_set or https_intercept_on is False:
    rendered = strip_managed_https_splice(rendered)
    if https_intercept_splice_on is True and https_intercept_effective:
        rendered = insert_https_splice_block(rendered)

path.write_text('\n'.join(rendered) + ('\n' if text.endswith('\n') else ''), encoding='utf-8')
PY
}

apply_squid_perf_tuning() {
    file_path="$1"
    if [ ! -f "$file_path" ]; then
        return 0
    fi

    replace_or_append_config_line "$file_path" "workers" "$SQUID_WORKERS"

    if [ -n "${EXPLICIT_SQUID_CACHE_MEM_MB:-}" ] || ! config_has_directive "$file_path" "cache_mem"; then
        replace_or_append_config_line "$file_path" "cache_mem" "$SQUID_CACHE_MEM_MB MB"
    fi

    if [ -n "${EXPLICIT_SQUID_SSLCRTD_CHILDREN:-}" ] || ! config_has_directive "$file_path" "sslcrtd_children"; then
        replace_or_append_config_line "$file_path" "sslcrtd_children" "$(build_sslcrtd_children_value "$file_path" "$SQUID_SSLCRTD_CHILDREN")"
    fi

    if [ -n "${EXPLICIT_SQUID_MAX_FILEDESCRIPTORS:-}" ] || ! config_has_directive "$file_path" "max_filedescriptors"; then
        replace_or_append_config_line "$file_path" "max_filedescriptors" "$SQUID_MAX_FILEDESCRIPTORS"
    fi

    if [ -n "${EXPLICIT_SQUID_DYNAMIC_CERT_MEM_CACHE_MB:-}" ] || ! grep -qi "dynamic_cert_mem_cache_size=" "$file_path" 2>/dev/null; then
        sed -i -E "s#(dynamic_cert_mem_cache_size=)[0-9]+MB#\1${SQUID_DYNAMIC_CERT_MEM_CACHE_MB}MB#I" "$file_path" || true
    fi
}

python3 /app/tools/adblock_compile.py \
    --lists-dir /var/lib/squid-flask-proxy/adblock/lists \
    --out-dir /var/lib/squid-flask-proxy/adblock/compiled \
    || true
mkdir -p /var/lib/squid-flask-proxy/adblock/compiled
if [ ! -f /var/lib/squid-flask-proxy/adblock/compiled/request_lookup.sqlite ]; then
    python3 - <<'PY' || true
from pathlib import Path

from services.adblock_artifacts import _write_empty_request_lookup_db

_write_empty_request_lookup_db(
    Path("/var/lib/squid-flask-proxy/adblock/compiled/request_lookup.sqlite")
)
PY
fi

# Ensure squid.conf is based on our template (needed for caching + ssl-bump).
# If the file already looks like our managed config, keep it.
PERSISTED_SQUID_CONF_PATH="${PERSISTED_SQUID_CONF_PATH:-/var/lib/squid-flask-proxy/squid.conf}"
if [ -f "$PERSISTED_SQUID_CONF_PATH" ]; then
    mkdir -p /etc/squid
    cp "$PERSISTED_SQUID_CONF_PATH" /etc/squid/squid.conf

    # Squid 6+ deprecates "pipeline_prefetch on" in favor of numeric values.
    # Migrate the persisted config in-memory for this container run.
    if grep -qiE "^\s*pipeline_prefetch\s+on\b" /etc/squid/squid.conf 2>/dev/null; then
        sed -i -E "s/^([[:space:]]*pipeline_prefetch[[:space:]]+)on\b/\11/I" /etc/squid/squid.conf
    fi
    if grep -qiE "^\s*pipeline_prefetch\s+off\b" /etc/squid/squid.conf 2>/dev/null; then
        sed -i -E "s/^([[:space:]]*pipeline_prefetch[[:space:]]+)off\b/\10/I" /etc/squid/squid.conf
    fi
fi

TEMPLATE=""
if [ -f /etc/squid/squid.conf.template ]; then
    TEMPLATE="/etc/squid/squid.conf.template"
elif [ -f /squid/squid.conf.template ]; then
    TEMPLATE="/squid/squid.conf.template"
fi

if [ -n "$TEMPLATE" ] && [ ! -f "$PERSISTED_SQUID_CONF_PATH" ]; then
    if [ ! -f /etc/squid/squid.conf ] || ! grep -q "ssl_bump" /etc/squid/squid.conf 2>/dev/null; then
        cp "$TEMPLATE" /etc/squid/squid.conf
    fi
fi

# Resolve the authoritative Squid worker count.
# Precedence:
#   1) explicit SQUID_WORKERS env override (deployment/bootstrap override)
#   2) persisted squid.conf workers line (web UI / config file authority)
#   3) current config/template value
#   4) safe fallback of 1
EXPLICIT_SQUID_WORKERS="$(sanitize_positive_int "${SQUID_WORKERS:-}")"
EXPLICIT_SQUID_CACHE_MEM_MB="$(sanitize_positive_int "${SQUID_CACHE_MEM_MB:-}")"
EXPLICIT_SQUID_SSLCRTD_CHILDREN="$(sanitize_positive_int "${SQUID_SSLCRTD_CHILDREN:-}")"
EXPLICIT_SQUID_DYNAMIC_CERT_MEM_CACHE_MB="$(sanitize_nonnegative_int "${SQUID_DYNAMIC_CERT_MEM_CACHE_MB:-}")"
EXPLICIT_SQUID_MAX_FILEDESCRIPTORS="$(sanitize_positive_int "${SQUID_MAX_FILEDESCRIPTORS:-}")"
PERSISTED_SQUID_WORKERS="$(extract_squid_workers_from_file "$PERSISTED_SQUID_CONF_PATH")"
CONFIG_SQUID_WORKERS="$(extract_squid_workers_from_file /etc/squid/squid.conf)"

if [ -n "$EXPLICIT_SQUID_WORKERS" ]; then
    WORKERS="$EXPLICIT_SQUID_WORKERS"
elif [ -n "$PERSISTED_SQUID_WORKERS" ]; then
    WORKERS="$PERSISTED_SQUID_WORKERS"
elif [ -n "$CONFIG_SQUID_WORKERS" ]; then
    WORKERS="$CONFIG_SQUID_WORKERS"
else
    WORKERS=1
fi
WORKERS="$(clamp_int "$WORKERS" 1 4)"
export SQUID_WORKERS="$WORKERS"

# Derive the rest of the process/helper counts from the resolved Squid worker count
# unless the user explicitly overrides them.
if [ -n "$EXPLICIT_SQUID_CACHE_MEM_MB" ]; then
    export SQUID_CACHE_MEM_MB="$EXPLICIT_SQUID_CACHE_MEM_MB"
elif [ -z "${SQUID_CACHE_MEM_MB:-}" ]; then
    export SQUID_CACHE_MEM_MB=256
fi
if [ -n "$EXPLICIT_SQUID_SSLCRTD_CHILDREN" ]; then
    export SQUID_SSLCRTD_CHILDREN="$EXPLICIT_SQUID_SSLCRTD_CHILDREN"
elif [ -z "${SQUID_SSLCRTD_CHILDREN:-}" ]; then
    SQUID_SSLCRTD_CHILDREN="$(recommend_sslcrtd_children "$WORKERS")"
    export SQUID_SSLCRTD_CHILDREN
fi
if [ -n "$EXPLICIT_SQUID_DYNAMIC_CERT_MEM_CACHE_MB" ]; then
    export SQUID_DYNAMIC_CERT_MEM_CACHE_MB="$EXPLICIT_SQUID_DYNAMIC_CERT_MEM_CACHE_MB"
elif [ -z "${SQUID_DYNAMIC_CERT_MEM_CACHE_MB:-}" ]; then
    SQUID_DYNAMIC_CERT_MEM_CACHE_MB="$(recommend_dynamic_cert_cache_mb "$WORKERS")"
    export SQUID_DYNAMIC_CERT_MEM_CACHE_MB
fi
if [ -n "$EXPLICIT_SQUID_MAX_FILEDESCRIPTORS" ]; then
    export SQUID_MAX_FILEDESCRIPTORS="$EXPLICIT_SQUID_MAX_FILEDESCRIPTORS"
elif [ -z "${SQUID_MAX_FILEDESCRIPTORS:-}" ]; then
    SQUID_MAX_FILEDESCRIPTORS="$(recommend_nofile "$WORKERS")"
    export SQUID_MAX_FILEDESCRIPTORS
fi
if [ -z "${ULIMIT_NOFILE:-}" ]; then
    export ULIMIT_NOFILE="$SQUID_MAX_FILEDESCRIPTORS"
fi
if [ -z "${WEB_WORKERS:-}" ]; then
    export WEB_WORKERS=1
fi
if [ -z "${WEB_THREADS:-}" ]; then
    # One extra thread keeps /health and the UI responsive even while a
    # blocking admin action (for example squid -k reconfigure) is in flight.
    export WEB_THREADS=2
fi
if [ -z "${WEBFILTER_HELPERS:-}" ]; then
    WEBFILTER_HELPERS="$(recommend_webfilter_helpers "$WORKERS")"
    export WEBFILTER_HELPERS
fi
if [ -z "${DB_POOL_SIZE:-}" ]; then
    DB_POOL_SIZE="$(recommend_db_pool_size "$WORKERS")"
    export DB_POOL_SIZE
fi

# Squid 6/7 expects logfile paths to be prefixed with a module name.
# Normalize the logs we keep, collapse the duplicate live-only access log into the
# richer structured access log, and disable store.log, which is pure per-object
# overhead for this stack and is not consumed anywhere in-product.
for SQUID_CFG in /etc/squid/squid.conf "$PERSISTED_SQUID_CONF_PATH"; do
    if [ ! -f "$SQUID_CFG" ]; then
        continue
    fi
    sed -i -E '/^[[:space:]]*access_log[[:space:]]+(stdio:)?\/var\/log\/squid\/access\.log\b/d' "$SQUID_CFG" || true
    sed -i -E 's#^([[:space:]]*cache_log[[:space:]]+)(stdio:)?/var/log/squid/cache\.log([[:space:]]*|$)#\1stdio:/var/log/squid/cache.log\3#' "$SQUID_CFG" || true
    sed -i -E 's#^[[:space:]]*cache_store_log[[:space:]]+.*$#cache_store_log none#I' "$SQUID_CFG" || true
done

# Keep log noise down: exclude local cachemgr polling from the structured access log.
# We apply this even if squid.conf already exists (e.g., user edited via UI),
# but only inject once.
if [ -f /etc/squid/squid.conf ]; then
    if grep -qiE '^\s*acl\s+src_localhost\s+src\s+' /etc/squid/squid.conf 2>/dev/null; then
        LOCALHOST_SRC_ACL="$LOCALHOST_SRC_ACL" python3 - <<'PY' || true
from pathlib import Path
import os, re

path = Path('/etc/squid/squid.conf')
text = path.read_text(encoding='utf-8')
acl = os.environ.get('LOCALHOST_SRC_ACL', '127.0.0.1/32 ::1')
text = re.sub(
    r'^(\s*acl\s+src_localhost\s+src\s+).*$',
    lambda m: m.group(1) + acl,
    text,
    count=1,
    flags=re.M,
)
path.write_text(text, encoding='utf-8')
PY
    fi

    if ! grep -q "acl squid_internal_mgr" /etc/squid/squid.conf 2>/dev/null; then
        if grep -q "^access_log \(stdio:\)\?/var/log/squid/access\\.log liveui" /etc/squid/squid.conf 2>/dev/null; then
            sed -i "/^access_log \(stdio:\)\?\/var\/log\/squid\/access\.log liveui/i\\
\\
# Filter noisy internal cache manager polling (e.g. /squid-internal-mgr/info, /squid-internal-mgr/5min)\\
# from localhost. These are generated by the local admin/UI and are not end-user proxy traffic.\\
acl src_localhost src ${LOCALHOST_SRC_ACL}\\
acl squid_internal_mgr urlpath_regex -i ^\/squid-internal-mgr\/\\
access_log none src_localhost squid_internal_mgr\\
" /etc/squid/squid.conf
        else
            cat >> /etc/squid/squid.conf <<EOF

# Filter noisy internal cache manager polling (e.g. /squid-internal-mgr/info, /squid-internal-mgr/5min)
# from localhost. These are generated by the local admin/UI and are not end-user proxy traffic.
acl src_localhost src ${LOCALHOST_SRC_ACL}
acl squid_internal_mgr urlpath_regex -i ^/squid-internal-mgr/
access_log none src_localhost squid_internal_mgr
EOF
        fi
    fi
fi

# When IPv6 is disabled, normalize the default Squid bind to IPv4-only.
if [ "$IPV6_DISABLED" = "1" ] && [ -f /etc/squid/squid.conf ]; then
    sed -i -E 's#^([[:space:]]*http_port[[:space:]]+)3128([[:space:]]+ssl-bump.*)$#\10.0.0.0:3128\2#' /etc/squid/squid.conf || true
    if [ -f "$PERSISTED_SQUID_CONF_PATH" ]; then
        sed -i -E 's#^([[:space:]]*http_port[[:space:]]+)3128([[:space:]]+ssl-bump.*)$#\10.0.0.0:3128\2#' "$PERSISTED_SQUID_CONF_PATH" || true
    fi
fi

# Optional listener shaping: explicit proxy traffic stays on SQUID_HTTP_PORT,
# while NAT-redirected plain HTTP can be accepted on a separate intercept port.
# Firewall/router REDIRECT or DNAT rules are intentionally deployment-owned.
normalize_http_port_listeners /etc/squid/squid.conf
if [ -f "$PERSISTED_SQUID_CONF_PATH" ]; then
    normalize_http_port_listeners "$PERSISTED_SQUID_CONF_PATH"
fi

# Performance + privacy: keep the live UI logformat lean and credential-free.
# Diagnostic logging includes only bounded response metadata that drives
# remediation inference. It intentionally avoids cookies, authorization, and
# full request/response header dumps on the proxy hot path.
SAFE_LIVEUI_FMT='logformat liveui %ts\t%tr\t%>a\t%rm\t%ru\t%Ss/%>Hs\t%st'
SAFE_DIAGNOSTIC_FMT='logformat diagnostic %ts\t%tr\t%>a\t%rm\t%ru\t%Ss/%>Hs\t%st\t%master_xaction\t%Sh\t%ssl::bump_mode\t%ssl::>sni\t%ssl::>negotiated_version\t%ssl::>negotiated_cipher\t%ssl::<negotiated_version\t%ssl::<negotiated_cipher\t%{Host}>h\t%{User-Agent}>h\t%{Referer}>h\t%{exclusion_rule}note\t%{ssl_exception}note\t%{webfilter_allow}note\t%{cache_bypass}note\t%{Content-Type}<h\t%{Server}<h\t%{Cf-Mitigated}<h\t%{Alt-Svc}<h'
SAFE_ICAP_OBSERVE_FMT='logformat icapobserve %ts\t%master_xaction\t%>a\t%rm\t%ru\t%icap::tt\t%adapt::sum_trs\t%adapt::all_trs\t%{Host}>h\t%{User-Agent}>h\t%ssl::>sni\t%{exclusion_rule}note\t%{ssl_exception}note\t%{webfilter_allow}note\t%{cache_bypass}note'
for SQUID_CFG in /etc/squid/squid.conf "$PERSISTED_SQUID_CONF_PATH"; do
    if [ -f "$SQUID_CFG" ] && grep -q "^logformat liveui" "$SQUID_CFG" 2>/dev/null; then
        sed -i -E "s#^logformat[[:space:]]+liveui[[:space:]].*#${SAFE_LIVEUI_FMT}#" "$SQUID_CFG"
    fi

    if [ ! -f "$SQUID_CFG" ]; then
        continue
    fi

    SQUID_CFG_PATH="$SQUID_CFG" \
    SAFE_LIVEUI_FMT="$SAFE_LIVEUI_FMT" \
    SAFE_DIAGNOSTIC_FMT="$SAFE_DIAGNOSTIC_FMT" \
    SAFE_ICAP_OBSERVE_FMT="$SAFE_ICAP_OBSERVE_FMT" \
    python3 - <<'PY' || true
from pathlib import Path
import os
import re

path = Path(os.environ['SQUID_CFG_PATH'])
text = path.read_text(encoding='utf-8')


def replace_or_append(pattern: str, line: str) -> str:
    regex = re.compile(pattern, re.M)
    if regex.search(text_buffer[0]):
        text_buffer[0] = regex.sub(line, text_buffer[0], count=1)
    else:
        text_buffer[0] = text_buffer[0].rstrip() + "\n" + line + "\n"
    return text_buffer[0]


text_buffer = [text]
replace_or_append(r'^\s*logformat\s+liveui\s+.*$', os.environ['SAFE_LIVEUI_FMT'])
replace_or_append(r'^\s*logformat\s+diagnostic\s+.*$', os.environ['SAFE_DIAGNOSTIC_FMT'])
replace_or_append(r'^\s*logformat\s+icapobserve\s+.*$', os.environ['SAFE_ICAP_OBSERVE_FMT'])
text_buffer[0] = re.sub(r'^\s*access_log\s+(?:stdio:)?/var/log/squid/access\.log\b.*$\n?', '', text_buffer[0], flags=re.M)
replace_or_append(r'^\s*access_log\s+(?:stdio:)?/var/log/squid/access-observe\.log\b.*$', 'access_log stdio:/var/log/squid/access-observe.log diagnostic')
replace_or_append(r'^\s*cache_log\s+(?:stdio:)?/var/log/squid/cache\.log\b.*$', 'cache_log stdio:/var/log/squid/cache.log')
replace_or_append(r'^\s*icap_log\s+(?:stdio:)?/var/log/squid/icap\.log\b.*$', 'icap_log stdio:/var/log/squid/icap.log icapobserve')

for note_line, acl_name in (
    ('note cache_bypass auth has_auth', 'has_auth'),
    ('note cache_bypass cookie has_cookie', 'has_cookie'),
):
    if acl_name in text_buffer[0] and note_line not in text_buffer[0]:
        text_buffer[0] = text_buffer[0].rstrip() + "\n" + note_line + "\n"

path.write_text(text_buffer[0] if text_buffer[0].endswith('\n') else text_buffer[0] + '\n', encoding='utf-8')
PY
done

# Stability + privacy: never cache requests that carry Authorization/Cookie.
# This reduces Vary-related cache loops and prevents caching of authenticated content.
ensure_auth_cookie_cache_deny() {
    SQUID_CFG="$1"
    if [ ! -f "$SQUID_CFG" ] || grep -q "^acl has_auth req_header Authorization" "$SQUID_CFG" 2>/dev/null; then
        return 0
    fi

    cat >> "$SQUID_CFG" <<'EOF'

# Never cache authenticated or cookie-bearing traffic.
acl has_auth req_header Authorization .
acl has_cookie req_header Cookie .
cache deny has_auth
cache deny has_cookie
EOF
}

ensure_auth_cookie_cache_deny /etc/squid/squid.conf
ensure_auth_cookie_cache_deny "$PERSISTED_SQUID_CONF_PATH"

# Stability: avoid problematic half-closed client connections.
# We have observed Squid aborting with an internal assertion (SIGABRT) under some client
# behaviors when half-closed connections are enabled. Disabling this is generally safer.
# NOTE: this also patches the persisted volume copy so web UI re-applies don't revert.
if [ -f /etc/squid/squid.conf ]; then
    if grep -qiE "^\s*half_closed_clients\s+" /etc/squid/squid.conf 2>/dev/null; then
        sed -i -E 's/^([[:space:]]*half_closed_clients[[:space:]]+).*/\1off/' /etc/squid/squid.conf || true
    else
        cat >> /etc/squid/squid.conf <<'EOF'

# Stability: disable half-closed clients (safer with misbehaving clients).
half_closed_clients off
EOF
    fi
fi
# Mirror the fix into the persisted copy on the data volume so that it
# survives web-UI re-applies and future container restarts.
if [ -f "$PERSISTED_SQUID_CONF_PATH" ]; then
    if grep -qiE "^\s*half_closed_clients\s+" "$PERSISTED_SQUID_CONF_PATH" 2>/dev/null; then
        sed -i -E 's/^([[:space:]]*half_closed_clients[[:space:]]+).*/\1off/' "$PERSISTED_SQUID_CONF_PATH" || true
    fi
fi

# Ensure we keep a bounded number of rotated log files.
# Even if the user persists/edits squid.conf via the UI, add a safe default if missing.
if [ -f /etc/squid/squid.conf ] && ! grep -q "^\s*logfile_rotate\b" /etc/squid/squid.conf 2>/dev/null; then
    {
        echo ""
        echo "# Default log retention for squid -k rotate (daily via supervisor)."
        echo "logfile_rotate 10"
    } >> /etc/squid/squid.conf
fi

# Restore current UI defaults if older persisted configs predate these directives.
# This keeps startup behavior aligned with the managed template without overwriting
# any user-tuned values that already exist.
if [ -f /etc/squid/squid.conf ]; then
    if ! grep -qiE "^\s*pipeline_prefetch\s+" /etc/squid/squid.conf 2>/dev/null; then
        cat >> /etc/squid/squid.conf <<'EOF'

# Default request pipelining behavior (numeric form for Squid 6+).
pipeline_prefetch 0
EOF
    fi

    if ! grep -qiE "^\s*server_idle_pconn_timeout\s+" /etc/squid/squid.conf 2>/dev/null \
        && ! grep -qiE "^\s*pconn_timeout\s+" /etc/squid/squid.conf 2>/dev/null; then
        cat >> /etc/squid/squid.conf <<'EOF'

# Keep idle upstream keepalive connections bounded to the current managed baseline.
server_idle_pconn_timeout 60 seconds
EOF
    fi

    if ! grep -qiE "^\s*client_idle_pconn_timeout\s+" /etc/squid/squid.conf 2>/dev/null; then
        cat >> /etc/squid/squid.conf <<'EOF'

# Keep client-side keepalive connections warm for bursty image/gallery browsing.
client_idle_pconn_timeout 120 seconds
EOF
    fi

    if ! grep -qiE "^\s*client_lifetime\s+" /etc/squid/squid.conf 2>/dev/null; then
        cat >> /etc/squid/squid.conf <<'EOF'

# Use Squid's documented long-lived client connection baseline unless explicitly tuned.
client_lifetime 86400 seconds
EOF
    fi

    if ! grep -qiE "^\s*quick_abort_min\s+" /etc/squid/squid.conf 2>/dev/null; then
        cat >> /etc/squid/squid.conf <<'EOF'

# Squid's documented quick_abort baseline.
quick_abort_min 16 KB
quick_abort_max 16 KB
quick_abort_pct 95
EOF
    fi
fi

apply_squid_perf_tuning /etc/squid/squid.conf
if [ -f "$PERSISTED_SQUID_CONF_PATH" ]; then
    apply_squid_perf_tuning "$PERSISTED_SQUID_CONF_PATH"
fi

# Generate Squid include snippets for ICAP scaling.
# We derive the worker count from squid.conf so UI edits like "workers 4" validate.
mkdir -p /etc/squid/conf.d

# SSL filtering include is driven by the admin UI database state.
# Always generate a safe include so squid.conf can include it.
python3 /app/tools/sslfilter_apply.py || true

# Web filtering include is driven by the admin UI database state.
# Always generate a safe include so squid.conf.template's include succeeds.
python3 /app/tools/webfilter_apply.py || true

# Ensure the SSL filtering include is present in squid.conf even if a user edited/persisted it.
# It should appear after 'ssl_bump peek step1' and before any 'ssl_bump bump' rule.
if [ -f /etc/squid/squid.conf ] && ! grep -q "/etc/squid/conf.d/10-sslfilter.conf" /etc/squid/squid.conf 2>/dev/null; then
    TMP="/tmp/squid.conf.$$"
    if awk '
        BEGIN{inserted=0}
        /^ssl_bump peek step1$/ && !inserted {
            print;
            print "# SSL filtering (no-bump CIDRs). Safe if empty.";
            print "include /etc/squid/conf.d/10-sslfilter.conf";
            inserted=1;
            next
        }
        /^ssl_bump bump/ && !inserted {
            print "# SSL filtering (no-bump CIDRs). Safe if empty.";
            print "include /etc/squid/conf.d/10-sslfilter.conf";
            inserted=1;
            print;
            next
        }
        {print}
        END{
            if(!inserted){
                print "";
                print "# SSL filtering (no-bump CIDRs). Safe if empty.";
                print "include /etc/squid/conf.d/10-sslfilter.conf";
            }
        }
    ' /etc/squid/squid.conf > "$TMP"; then
        mv "$TMP" /etc/squid/squid.conf
    else
        rm -f "$TMP"
    fi
fi

# Ensure web-filter HTTP access policy is evaluated before broad http_access rules.
if [ -f /etc/squid/squid.conf ] && ! grep -q "/etc/squid/conf.d/30-webfilter.conf" /etc/squid/squid.conf 2>/dev/null; then
    TMP="/tmp/squid-webfilter.conf.$$"
    if awk '
        BEGIN{inserted=0}
        /^[[:space:]]*http_access[[:space:]]+/ && !inserted {
            print "# Web filtering (category/domain policy). Safe if empty.";
            print "include /etc/squid/conf.d/30-webfilter.conf";
            inserted=1;
        }
        {print}
        END{
            if(!inserted){
                print "";
                print "# Web filtering (category/domain policy). Safe if empty.";
                print "include /etc/squid/conf.d/30-webfilter.conf";
            }
        }
    ' /etc/squid/squid.conf > "$TMP"; then
        mv "$TMP" /etc/squid/squid.conf
    else
        rm -f "$TMP"
    fi
fi

WORKERS=""
if [ -f /etc/squid/squid.conf ]; then
    # Extract the first "workers N" directive.
    WORKERS=$(awk 'tolower($1)=="workers" && $2 ~ /^[0-9]+$/ {print $2; exit}' /etc/squid/squid.conf 2>/dev/null || true)
fi

if [ -z "$WORKERS" ]; then
    WORKERS_RAW="${SQUID_WORKERS:-1}"
    case "$WORKERS_RAW" in
        ''|*[!0-9]*) WORKERS=1 ;;
        *) WORKERS="$WORKERS_RAW" ;;
    esac
fi

WORKERS="$(clamp_int "$WORKERS" 1 4)"

# Ensure supervisord sees a valid value even if compose didn't set it.
export SQUID_WORKERS="$WORKERS"

mkdir -p /etc/supervisor.d
rm -f /etc/supervisor.d/icap.conf || true

# Run the SQLite-backed adblock ICAP helper immediately so Squid's ICAP
# OPTIONS checks succeed quickly. AV still runs through c-icap and can wait
# for the remote clamd backend without impacting adblock.
CICAP_PORT_RAW="${CICAP_PORT:-14000}"
case "$CICAP_PORT_RAW" in
    ''|*[!0-9]*) CICAP_PORT=14000 ;;
    *) CICAP_PORT="$CICAP_PORT_RAW" ;;
esac

CICAP_AV_PORT_RAW="${CICAP_AV_PORT:-14001}"
case "$CICAP_AV_PORT_RAW" in
    ''|*[!0-9]*) CICAP_AV_PORT=14001 ;;
    *) CICAP_AV_PORT="$CICAP_AV_PORT_RAW" ;;
esac

# Keep ICAP listener ranges non-overlapping.  The historical adblock/AV defaults
# (14000/14001) collide when WORKERS > 1, so align AV to the first safe port
# after the adblock range while preserving already-safe explicit layouts.
if [ "$CICAP_AV_PORT" -lt $((CICAP_PORT + WORKERS)) ] && [ "$CICAP_PORT" -lt $((CICAP_AV_PORT + WORKERS)) ]; then
    CICAP_AV_PORT=$((CICAP_PORT + WORKERS))
fi

CICAP_AV_RESP_PORT_RAW="${CICAP_AV_RESP_PORT:-$((CICAP_AV_PORT + WORKERS))}"
case "$CICAP_AV_RESP_PORT_RAW" in
    ''|*[!0-9]*) CICAP_AV_RESP_PORT=$((CICAP_AV_PORT + WORKERS)) ;;
    *) CICAP_AV_RESP_PORT="$CICAP_AV_RESP_PORT_RAW" ;;
esac
if [ "$CICAP_AV_RESP_PORT" -lt $((CICAP_PORT + WORKERS)) ] && [ "$CICAP_PORT" -lt $((CICAP_AV_RESP_PORT + WORKERS)) ]; then
    CICAP_AV_RESP_PORT=$((CICAP_AV_PORT + WORKERS))
fi
if [ "$CICAP_AV_RESP_PORT" -lt $((CICAP_AV_PORT + WORKERS)) ] && [ "$CICAP_AV_PORT" -lt $((CICAP_AV_RESP_PORT + WORKERS)) ]; then
    CICAP_AV_RESP_PORT=$((CICAP_AV_PORT + WORKERS))
fi

CLAMD_HOST="$(printf '%s' "${CLAMD_HOST:-127.0.0.1}" | tr -d '\r')"
if [ -z "$CLAMD_HOST" ]; then
    CLAMD_HOST="127.0.0.1"
fi
CLAMD_HOST_IS_REMOTE=1
case "$CLAMD_HOST" in
    localhost|127.*|::1|\[::1\]) CLAMD_HOST_IS_REMOTE=0 ;;
esac
if [ "$CLAMD_HOST_IS_REMOTE" = "1" ]; then
    printf '[proxy-entrypoint] remote CLAMD_HOST detected; using INSTREAM RESPMOD helper for download AV scanning\n'
fi

CLAMD_PORT_RAW="${CLAMD_PORT:-3310}"
case "$CLAMD_PORT_RAW" in
    ''|*[!0-9]*) CLAMD_PORT=3310 ;;
    *) CLAMD_PORT="$CLAMD_PORT_RAW" ;;
esac

CLAMAV_REQUIRED_RAW="${CLAMAV_REQUIRED:-}"
CLAMAV_REQUIRED=0
AV_BYPASS=on
if env_enabled "$CLAMAV_REQUIRED_RAW" || env_enabled "${FILE_SECURITY_AV_REQUIRED:-}"; then
    CLAMAV_REQUIRED=1
    AV_BYPASS=off
fi

export CLAMD_HOST CLAMD_PORT CLAMAV_REQUIRED AV_BYPASS CICAP_PORT CICAP_AV_PORT CICAP_AV_RESP_PORT

cat > /etc/clamd_mod.conf <<EOF
# c-icap clamd_mod configuration for squid-flask-proxy
# Generated by /entrypoint.sh to target a remote clamd backend.
Module common clamd_mod.so
clamd_mod.ClamdHost ${CLAMD_HOST}
clamd_mod.ClamdPort ${CLAMD_PORT}
EOF

mkdir -p /var/run/c-icap

# Generate the AV c-icap config from the base image config. Adblock uses the
# Python ICAP helper below and does not consume a c-icap service config.
if [ -f /etc/c-icap/c-icap.conf ]; then
    i=0
    while [ "$i" -lt "$WORKERS" ]; do
        instance=$((i + 1))
        av_port=$((CICAP_AV_PORT + i))
        av_conf="/etc/c-icap/c-icap-av-${instance}.conf"
        cp /etc/c-icap/c-icap.conf "$av_conf"

        if grep -qiE "^[[:space:]]*PidFile[[:space:]]+" "$av_conf" 2>/dev/null; then
            sed -i -E "s#^[[:space:]]*PidFile[[:space:]]+.*#PidFile /var/run/c-icap/c-icap-av-${instance}.pid#I" "$av_conf"
        else
            echo "PidFile /var/run/c-icap/c-icap-av-${instance}.pid" >> "$av_conf"
        fi

        sed -i -E '/^[[:space:]]*AccessLog[[:space:]]+/d' "$av_conf" || true

        if grep -qiE "^[[:space:]]*Port[[:space:]]+" "$av_conf" 2>/dev/null; then
            sed -i -E "s#^[[:space:]]*Port[[:space:]]+.*#Port 127.0.0.1:${av_port}#I" "$av_conf"
        else
            echo "Port 127.0.0.1:${av_port}" >> "$av_conf"
        fi
        i=$((i + 1))
    done
fi

i=0
while [ "$i" -lt "$WORKERS" ]; do
    instance=$((i + 1))
    adblock_port=$((CICAP_PORT + i))
    av_resp_port=$((CICAP_AV_RESP_PORT + i))
    av_conf="/etc/c-icap/c-icap-av-${instance}.conf"
    av_pid="/var/run/c-icap/c-icap-av-${instance}.pid"
    cat > "/etc/supervisor.d/cicap_adblock_${instance}.conf" <<EOF
[program:cicap_adblock_${instance}]
command=/bin/sh -c 'exec python3 /app/tools/adblock_icap_server.py --host 127.0.0.1 --port "${adblock_port}" --db /var/lib/squid-flask-proxy/adblock/compiled/request_lookup.sqlite --access-log /var/log/cicap-access.log'
autostart=true
autorestart=unexpected
exitcodes=0
startsecs=45
startretries=2
priority=10
stderr_logfile=/dev/stderr
stdout_logfile=/dev/stdout
stderr_logfile_maxbytes=0
stdout_logfile_maxbytes=0
EOF
    cat > "/etc/supervisor.d/cicap_av_${instance}.conf" <<EOF
[program:cicap_av_${instance}]
# Required AV waits for clamd before c-icap starts; optional AV degrades immediately so browsing is not delayed.
# Keep the backend probe inside the supervisor child process. RouterOS/supervisord
# otherwise logs the short-lived probe helper as an unknown reaped pid whenever
# clamd is unavailable.
command=/bin/sh -c 'rm -f "${av_pid}"; exec /usr/local/bin/cicap_av_runner.py "${av_conf}"'
autostart=true
autorestart=true
priority=11
stderr_logfile=/dev/stderr
stdout_logfile=/dev/stdout
stderr_logfile_maxbytes=0
stdout_logfile_maxbytes=0
EOF
    if [ "$CLAMD_HOST_IS_REMOTE" = "1" ]; then
        fail_mode_arg="--fail-open"
        if [ "$CLAMAV_REQUIRED" = "1" ]; then fail_mode_arg="--fail-closed"; fi
        cat > "/etc/supervisor.d/clamav_respmod_${instance}.conf" <<EOF
[program:clamav_respmod_${instance}]
command=/bin/sh -c 'exec python3 /app/tools/clamav_respmod_icap_server.py --host 127.0.0.1 --port "${av_resp_port}" --clamd-host "${CLAMD_HOST}" --clamd-port "${CLAMD_PORT}" ${fail_mode_arg}'
autostart=true
autorestart=true
priority=12
stderr_logfile=/dev/stderr
stdout_logfile=/dev/stdout
stderr_logfile_maxbytes=0
stdout_logfile_maxbytes=0
EOF
    fi
    i=$((i + 1))
done

{
    adblock_services=""
    av_req_services=""
    av_resp_services=""
    i=0
    while [ "$i" -lt "$WORKERS" ]; do
        instance=$((i + 1))
        suffix=""
        if [ "$instance" -gt 1 ]; then suffix="_${instance}"; fi
        adblock_name="adblock_req${suffix}"
        av_req_name="av_req${suffix}"
        av_resp_name="av_resp${suffix}"
        adblock_services="${adblock_services}${adblock_services:+ }${adblock_name}"
        av_req_services="${av_req_services}${av_req_services:+ }${av_req_name}"
        av_resp_services="${av_resp_services}${av_resp_services:+ }${av_resp_name}"
        echo "icap_service ${adblock_name} reqmod_precache icap://127.0.0.1:$((CICAP_PORT + i))/adblockreq bypass=on"
        echo "icap_service ${av_req_name} reqmod_precache icap://127.0.0.1:$((CICAP_AV_PORT + i))/avrespmod bypass=${AV_BYPASS}"
        if [ "$CLAMD_HOST_IS_REMOTE" = "1" ]; then
            echo "icap_service ${av_resp_name} respmod_precache icap://127.0.0.1:$((CICAP_AV_RESP_PORT + i))/avrespmod bypass=${AV_BYPASS}"
        else
            echo "icap_service ${av_resp_name} respmod_precache icap://127.0.0.1:$((CICAP_AV_PORT + i))/avrespmod bypass=${AV_BYPASS}"
        fi
        i=$((i + 1))
    done
    echo "adaptation_service_set adblock_req_set ${adblock_services}"
    echo "adaptation_service_set av_req_set ${av_req_services}"
    echo "adaptation_service_set av_resp_set ${av_resp_services}"
    echo "acl icap_adblockable method GET HEAD CONNECT POST OPTIONS PUT PATCH DELETE"
    echo "adaptation_access adblock_req_set allow icap_adblockable"
    echo "adaptation_access adblock_req_set deny all"
    echo "acl file_security_upload_methods method POST PUT PATCH"
    echo "acl file_security_download_methods method GET HEAD"
    echo "acl file_security_range_request req_header Range .+"
    echo "acl file_security_partial_response http_status 206"
    echo "acl file_security_risky_path urlpath_regex -i \\.(exe|dll|msi|bat|cmd|com|scr|ps1|vbs|jar|apk)($|[?#])"
    echo "acl file_security_executable_path urlpath_regex -i \\.(exe|dll|msi|com|scr|jar|apk)($|[?#])"
    echo "acl file_security_executable_mime req_header Content-Type -i (application/x-msdownload|application/x-msdos-program|application/x-ms-installer)"
    echo "adaptation_access av_req_set allow file_security_upload_methods"
    echo "adaptation_access av_req_set deny all"
    echo "adaptation_access av_resp_set deny file_security_range_request"
    echo "adaptation_access av_resp_set deny file_security_partial_response"
    echo "adaptation_access av_resp_set allow file_security_download_methods"
    echo "adaptation_access av_resp_set deny all"
    echo "http_access deny file_security_risky_path"
    echo "http_access deny file_security_executable_path"
    echo "http_access deny file_security_executable_mime file_security_upload_methods"
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

WORKERS_MARKER_PATH=/var/lib/squid-flask-proxy/squid-workers.last
PREV_WORKERS=""
if [ -f "$WORKERS_MARKER_PATH" ]; then
    PREV_WORKERS="$(tr -cd '0-9' < "$WORKERS_MARKER_PATH" | head -c 16 || true)"
fi
if [ "$PREV_WORKERS" != "$WORKERS" ]; then
    rm -f /var/spool/squid/swap.state* 2>/dev/null || true
fi

# SECURITY: structured access logs and the richer diagnostic logs may contain credentials or
# identifying metadata from older configurations.
# Since /var/log/squid is not persisted as a volume, it's safe to purge on startup.
if [ "${SANITIZE_SQUID_ACCESS_LOGS_ON_START:-1}" = "1" ]; then
    rm -f /var/log/squid/access.log /var/log/squid/access.log.* /var/log/squid/access-observe.log /var/log/squid/access-observe.log.* /var/log/squid/icap.log /var/log/squid/icap.log.* 2>/dev/null || true
fi

# Optional: raise process file-descriptor limit for high-connection workloads.
# (Affects all processes started by this entrypoint.)
ULIMIT_NOFILE_RAW="${ULIMIT_NOFILE:-}"
if [ -n "$ULIMIT_NOFILE_RAW" ]; then
    # shellcheck disable=SC3045
    case "$ULIMIT_NOFILE_RAW" in
        ''|*[!0-9]*) : ;;
        *) ulimit -n "$ULIMIT_NOFILE_RAW" 2>/dev/null || true ;;
    esac
fi

# Squid typically drops privileges to user 'squid'; ensure it can write cache/logs.
if getent passwd squid >/dev/null 2>&1; then
    chown -R squid:squid /var/spool/squid /var/log/squid || true
fi
# Build cache dirs using the real SMP-aware startup path.
# Do not use -N here: it turns the master into a single worker and bypasses SMP kids.
printf '[proxy-entrypoint] preparing squid cache dirs workers=%s existing_pidfile=%s squid_pids=%s\n' \
    "$WORKERS" \
    "$(cat /var/run/squid.pid 2>/dev/null || true)" \
    "$(pgrep -x squid 2>/dev/null | paste -sd, - || true)"
squid -z -f /etc/squid/squid.conf || \
    printf '[proxy-entrypoint] squid cache-dir prepare exited nonzero; continuing to supervisord\n'
printf '[proxy-entrypoint] squid cache-dir prepare complete pidfile=%s squid_pids=%s\n' \
    "$(cat /var/run/squid.pid 2>/dev/null || true)" \
    "$(pgrep -x squid 2>/dev/null | paste -sd, - || true)"
rm -f /var/run/squid.pid || true
printf '%s\n' "$WORKERS" > "$WORKERS_MARKER_PATH" 2>/dev/null || true

# Start Supervisor to manage Squid and Flask
printf '[proxy-entrypoint] starting supervisord workers=%s\n' "$WORKERS"
exec /usr/bin/supervisord -c /etc/supervisord.conf
