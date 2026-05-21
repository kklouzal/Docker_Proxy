# Docker Proxy

[![Publish Docker images to GHCR](https://github.com/kklouzal/Docker_Proxy/actions/workflows/publish-ghcr.yml/badge.svg)](https://github.com/kklouzal/Docker_Proxy/actions/workflows/publish-ghcr.yml)
[![Container Registry](https://img.shields.io/badge/GHCR-admin--ui%20%7C%20proxy-blue)](https://github.com/kklouzal/Docker_Proxy/pkgs/container/docker_proxy-admin-ui)
[![License](https://img.shields.io/badge/license-see%20LICENSE-informational)](LICENSE)

Docker Proxy is a production-oriented Squid proxy appliance with a web control plane, policy automation, PAC/WPAD publishing, observability, and optional ICAP-based security services. It packages a modern Squid runtime and a Flask/Gunicorn administration UI into split containers that share an external MySQL 8+ state backend.

The project is designed for home labs, small offices, schools, managed LANs, and advanced operators who want a transparent, auditable proxy stack without hand-editing Squid configuration for every policy change.

## Highlights

- **Split control plane and runtime**: `admin-ui` manages policy and fleet state; `proxy` runs Squid, c-icap, PAC/WPAD, local policy materialization, and a small management API.
- **MySQL-backed source of truth**: configuration revisions, proxy registration, policy state, users, audit events, telemetry, block logs, PAC profiles, and operation status live in MySQL 8+.
- **Validated configuration workflow**: proxy runtimes validate candidate Squid configs with their own Squid binary/includes before activation and keep a last-known-good rollback path.
- **Fleet-aware operation ledger**: admin actions queue proxy-scoped operations for config, certificates, PAC refresh, adblock artifacts, cache clears, and manual sync.
- **PAC/WPAD as a first-class runtime service**: each proxy serves public `/health`, `/proxy.pac`, and `/wpad.dat` without exposing the admin UI on port 80.
- **TLS inspection controls**: CA generation/upload, SSL-bump policy, compatibility presets, no-bump/no-cache rules, client-CIDR splicing, SSL error analysis, and one-click exclusions.
- **Web filtering and threat intelligence**: UT1-style category filtering, whitelists, proxy-local SQLite snapshots for request-path lookups, and optional Google Safe Browsing v5 local-hash-prefix checks.
- **ICAP security services**: EasyList-style ad blocking through c-icap REQMOD and ClamAV response scanning through c-icap RESPMOD with remote `clamd`.
- **Operational visibility**: live traffic, clients, destinations, cache behavior, ICAP activity, SSL/TLS diagnostics, block events, exports, and maintenance actions.
- **Multi-architecture images**: GitHub Actions builds and publishes `linux/amd64` and `linux/arm64` images to GHCR after deterministic and live-stack tests pass.

## Architecture

```text
                 +----------------------------+
                 |          MySQL 8+          |
                 | config, policy, telemetry  |
                 | users, audit, operations   |
                 +-------------+--------------+
                               |
                +--------------+--------------+
                |                             |
       +--------v--------+          +---------v---------+
       |    admin-ui     |          |       proxy       |
       | Flask/Gunicorn  |          | Squid + c-icap    |
       | policy + fleet  |<-------->| sync + PAC/WPAD   |
       | port 5000       | mgmt API | ports 80/3128/3129|
       +-----------------+          +-------------------+
```

The admin UI can run with local or remote proxy runtimes. Each proxy registers its management URL and public PAC/proxy coordinates in MySQL. The admin UI targets the selected proxy for runtime checks and queues durable operations when policy changes need to be materialized.

## Requirements

- Docker Engine with Docker Compose v2.
- A reachable MySQL 8+ database; runtime and admin state are MySQL-backed.
- A remote `clamd` service when ClamAV response scanning is enabled.
- Managed clients must trust the proxy CA before TLS inspection is enabled for them.

## Quick start

Put database and management-token settings in a root `.env` file or your launch environment:

```dotenv
MYSQL_HOST=192.168.1.10
MYSQL_PORT=3306
MYSQL_USER=docker_proxy
MYSQL_PASSWORD=replace_with_the_database_password
MYSQL_DATABASE=squid_proxy
MYSQL_CREATE_DATABASE=0
PROXY_MANAGEMENT_TOKEN=replace_with_a_shared_internal_token
DOCKER_LOG_DRIVER=json-file
DOCKER_LOG_MAX_SIZE=10m
DOCKER_LOG_MAX_FILE=3
```

For production, create the database and runtime user before starting remote proxy
containers. Keep `MYSQL_CREATE_DATABASE=0` on proxy/admin containers unless that
specific container is allowed to create databases during provisioning.

Build and run from source:

```powershell
docker compose up -d --build
```

Or run the prebuilt GHCR images:

```powershell
docker compose -f docker-compose.ghcr.yml up -d
```

Default endpoints:

- Admin UI: `http://localhost:5000`
- Explicit HTTP proxy: `http://localhost:3128`
- HTTP NAT intercept listener: `localhost:3129` when enabled and routed by your network
- Proxy public health: `http://localhost/health`
- PAC file: `http://localhost/proxy.pac`
- WPAD: `http://localhost/wpad.dat`

Default first-run login:

- Username: `admin`
- Password: `admin`

Change the administrator password after first login. The admin UI stores a persistent session secret in MySQL when available; set `FLASK_SECRET_KEY` explicitly when you want host-managed secret rotation.

## Deployment options

### Source build

`docker-compose.yml` builds both containers from the repository and extends the shared service definition in `docker-compose.common.yml`.

```powershell
docker compose up -d --build
```

Source builds use Alpine's `edge` image tag by default so Squid and runtime packages track the newest Alpine packages available at build time. For a pinned base image, pass an explicit build argument:

```powershell
docker compose build --build-arg ALPINE_VERSION=3.23.4
```

### Prebuilt images

`docker-compose.ghcr.yml` runs the published split images:

- `ghcr.io/kklouzal/docker_proxy-admin-ui:main`
- `ghcr.io/kklouzal/docker_proxy-proxy:main`

The publish workflow runs deterministic tests, builds both images, runs the live Compose test stack, and then publishes multi-architecture images with SBOM and provenance metadata.

### Standalone control plane

Run only the admin UI when proxy runtimes are deployed elsewhere:

```powershell
docker compose up -d --build admin-ui
```

The admin UI still requires MySQL. Proxy-specific actions become available after proxy runtimes register management URLs and public PAC/proxy metadata.

### Multi-proxy deployments

When multiple proxy runtimes share one MySQL/admin-ui control plane, every proxy
container must have a stable, unique identity and public coordinates:

```dotenv
PROXY_INSTANCE_ID=site-a-proxy-1
PROXY_DISPLAY_NAME=Site A Proxy 1
PROXY_PUBLIC_HOST=site-a-proxy-1.example.internal
PROXY_PUBLIC_PAC_URL=http://site-a-proxy-1.example.internal/proxy.pac
PROXY_MANAGEMENT_URL=http://site-a-proxy-1.example.internal:5000
```

Set `DEFAULT_PROXY_ID` only on the admin UI host to choose the initial UI
selection. Do not reuse the same `PROXY_INSTANCE_ID` on multiple proxy hosts;
registration, heartbeat, queued operations, PAC metadata, and health status are
keyed by that ID.

Keep each proxy container's shared-memory allocation at or above the Compose
default `PROXY_SHM_SIZE=512m` unless you also lower Squid memory cache settings.
The default Squid template uses shared memory for cache metadata; Docker's bare
`docker run` default `/dev/shm` size is too small for that production profile.

For a six-proxy fleet plus one admin UI, budget MySQL connections explicitly.
The bundled MySQL Compose profile defaults `MYSQL_MAX_CONNECTIONS=160`; external
MySQL deployments should set equivalent headroom. Leave `DB_POOL_SIZE` blank
unless you have measured a need to override it: the application derives a small
per-process idle pool from `WEB_THREADS`, and six default proxy containers plus
one default admin UI stay well inside the 160-connection budget.

## Core capabilities

### Proxy policy and Squid configuration

- Template-backed Squid configuration editor with structured controls and raw config access.
- Tunable caching baseline using Squid `rock` storage, bounded memory/disk cache settings, conservative refresh semantics, explicit timeout/network/DNS knobs, and SMP-aware worker sizing.
- Config revisions stored in MySQL with audit trails.
- Proxy-side validation, apply, reload, and last-known-good rollback.
- Cache clear and manual synchronization actions scoped to the selected proxy.

### PAC, WPAD, and client routing

- Per-proxy PAC profiles selected by client IPv4 CIDR.
- Direct-domain and direct-destination-network rules for fragile applications or local routes.
- Runtime-rendered PAC files served by the selected proxy, not by the admin UI.
- WPAD-compatible `/wpad.dat` and direct `/proxy.pac` endpoints.
- Emergency PAC fallback when rendered state is unavailable.

### TLS inspection and certificates

- Self-signed CA generation and certificate download.
- PKCS#12 and certificate/key upload validation.
- SSL-bump policy management with domain and client-CIDR no-bump/no-cache rules.
- Source-backed compatibility presets for common SaaS, identity, update, collaboration, and device ecosystems that are poor candidates for TLS break-and-inspect.
- SSL/TLS error aggregation, export, and exclusion workflows.

### Web filtering

- UT1-style category feed ingestion and category selection.
- Exact and wildcard whitelist support.
- MySQL-backed category tables with proxy-local lookup snapshots for request-path decisions.
- Squid external ACL integration and a custom `ERR_WEBFILTER_BLOCKED` page.
- Blocked-request logging with client, destination, URL, category, and timestamp.
- Optional Google Safe Browsing v5 integration using local hash-prefix lists and full-hash lookups only after a local prefix match.

### Ad blocking

- EasyList-style subscription download and compilation.
- c-icap REQMOD service at `icap://127.0.0.1:${CICAP_PORT:-14000}/adblockreq`.
- Domain and URL-rule artifacts staged locally in the proxy container.
- Decision cache controls, block counters, recent event logging, and artifact application tracking.

### ClamAV scanning

- c-icap RESPMOD antivirus service at `icap://127.0.0.1:${CICAP_AV_PORT:-14001}/avrespmod`.
- Remote `clamd` backend configured with `CLAMD_HOST` and `CLAMD_PORT`.
- Fail-open/fail-closed policy controls and c-icap `virus_scan` tuning.
- Per-proxy health view that separates Squid policy, AV c-icap listener health, and remote `clamd` reachability.
- EICAR and sample ICAP verification actions executed through the selected proxy runtime.

### Observability and operations

- Fleet page with registered proxies, live health, and per-proxy observability status.
- Live traffic pages for clients, domains, cache behavior, transactions, and ICAP activity.
- Diagnostic ingestion from Squid and c-icap logs into MySQL-backed rollups.
- SSL error store, block logs, CSV-style exports, and log maintenance actions.
- Operations page for queued, applying, applied, and failed proxy operations, including rollback support when a failed operation has a rollback target.
- Policy request workflow for users to submit unblock/review requests from custom block pages.

## Configuration reference

The Compose files expose the common production knobs as environment variables. The most important settings are:

| Area | Variables |
| --- | --- |
| Database | `DATABASE_URL`, `MYSQL_HOST`, `MYSQL_PORT`, `MYSQL_USER`, `MYSQL_PASSWORD`, `MYSQL_DATABASE`, `MYSQL_CREATE_DATABASE`, `MYSQL_CONNECT_TIMEOUT`, `MYSQL_READ_TIMEOUT`, `MYSQL_WRITE_TIMEOUT`, `MYSQL_CONNECT_RETRIES`, `MYSQL_LOCK_WAIT_TIMEOUT`, `MYSQL_INNODB_LOCK_WAIT_TIMEOUT`, `MYSQL_SESSION_WAIT_TIMEOUT`, `MYSQL_TRANSACTION_ISOLATION`, `MYSQL_SCHEMA_LOCK_TIMEOUT_SECONDS`, `MYSQL_MAX_CONNECTIONS`, `DB_POOL_SIZE`, `DB_POOL_ACQUIRE_TIMEOUT_SECONDS` |
| Container logging | `DOCKER_LOG_DRIVER`, `DOCKER_LOG_MAX_SIZE`, `DOCKER_LOG_MAX_FILE` |
| Security | `FLASK_SECRET_KEY`, `SESSION_COOKIE_SECURE`, `SESSION_TIMEOUT_HOURS`, `PROXY_MANAGEMENT_TOKEN`, `DISABLE_CSRF` for controlled test/dev bypasses |
| Runtime health | `PROXY_HEALTH_UI_TIMEOUT_SECONDS`, `PROXY_CLAMAV_HEALTH_UI_TIMEOUT_SECONDS`, `PROXY_HEALTH_UI_CACHE_TTL_SECONDS`, `PROXY_OBSERVABILITY_UI_CACHE_TTL_SECONDS`, `PROXY_HEALTH_CACHE_TTL_SECONDS`, `PROXY_CLAMAV_HEALTH_PROBE_TIMEOUT_SECONDS` |
| Proxy identity | `DEFAULT_PROXY_ID`, `PROXY_INSTANCE_ID`, `PROXY_DISPLAY_NAME`, `PROXY_MANAGEMENT_URL`, `PROXY_PUBLIC_HOST`, `PROXY_PUBLIC_PAC_URL` |
| Public ports | `PROXY_PUBLIC_PAC_SCHEME`, `PROXY_PUBLIC_PAC_PORT`, `PROXY_PUBLIC_HTTP_PROXY_PORT`, `SQUID_HTTP_PORT`, `SQUID_INTERCEPT_ENABLED`, `SQUID_INTERCEPT_PORT`, `PROXY_PUBLIC_INTERCEPT_PORT` |
| Squid sizing | `SQUID_WORKERS`, `SQUID_CACHE_MEM_MB`, `PROXY_SHM_SIZE`, `SQUID_SSLCRTD_CHILDREN`, `SQUID_DYNAMIC_CERT_MEM_CACHE_MB`, `SQUID_MAX_FILEDESCRIPTORS`, `ULIMIT_NOFILE` |
| ICAP and AV | `CICAP_PORT`, `CICAP_AV_PORT`, `CLAMD_HOST`, `CLAMD_PORT` |
| Web filtering | `WEBFILTER_HELPERS`, `SAFE_BROWSING_POLL_SECONDS`, `SAFE_BROWSING_HELPER_CACHE_ENTRIES`, `SAFE_BROWSING_FAIL` |
| Runtime cadence | `PROXY_HEARTBEAT_INTERVAL_SECONDS`, `PROXY_SYNC_INTERVAL_SECONDS`, `LIVE_STATS_POLL_INTERVAL_SECONDS`, `DIAGNOSTIC_POLL_INTERVAL_SECONDS`, `DIAGNOSTIC_PENDING_MAX_ROWS`, `SSL_ERRORS_POLL_INTERVAL_SECONDS` |
| Admin UI | `WEB_WORKERS`, `WEB_THREADS`, `WEB_TIMEOUT`, `WEB_GRACEFUL_TIMEOUT`, `WEB_KEEPALIVE` |

Both containers also load `/config/app.env` at startup when mounted. Use this for host-managed deployments that prefer a mounted environment file over a root `.env`.

### Bounded logging and optional bundled MySQL

The Compose services set Docker `json-file` rotation by default (`10m`, `3` files) so the Admin UI, proxy, and optional bundled MySQL service do not leave unbounded stdout/stderr logs on Docker hosts. These Compose interpolation values must be supplied from the root `.env` or shell environment; mounted `/config/app.env` files are loaded inside containers too late to affect Docker logging.

Docker_Proxy normally targets an external MySQL 8+ server. If you deploy MySQL alongside the stack, include the optional MySQL Compose file:

```powershell
docker compose -f docker-compose.yml -f docker-compose.mysql.yml up -d --build
```

The bundled MySQL service is attached to the Compose `control` network and is
not published to the host by default. That is intentional for single-host
stacks. For physically remote proxy containers, either use an externally managed
MySQL service or add an explicit host-port mapping on the MySQL host, restrict it
with host/network firewalls, and point every admin/proxy container at that
reachable address with `MYSQL_HOST` and `MYSQL_PORT`.

The bundled MySQL service mounts `config/mysql/conf.d/99-docker-proxy-bounded-logs.cnf`, which disables general and slow query logs by default, sets `log_error_verbosity=2`, sets `max_connections=160`, caps `innodb_redo_log_capacity=256M`, and expires binary logs after one day when binlogs are enabled. Operators who need verbose SQL logging, a different connection budget, or longer PITR retention should override these settings with a later-mounted MySQL config file and explicit disk monitoring.

For externally managed MySQL containers, apply equivalent MySQL settings and Docker log rotation on that host. Host-global Docker daemon rotation, if desired for every container on the host, still belongs in `/etc/docker/daemon.json`; this application can provide Compose defaults but cannot safely rewrite the host daemon policy.

Older or disk-constrained hosts can legitimately take longer to answer management health requests. The Admin UI defaults to a 5 second management-health timeout and a 10 second UI cache, while the proxy runtime caches full health for 10 seconds. The ClamAV page uses a lightweight `/api/manage/health/clamav` management endpoint so AV c-icap and clamd status does not depend on the heavier full runtime health snapshot. Tune `PROXY_HEALTH_UI_TIMEOUT_SECONDS`, `PROXY_CLAMAV_HEALTH_UI_TIMEOUT_SECONDS`, `PROXY_HEALTH_CACHE_TTL_SECONDS`, and `PROXY_CLAMAV_HEALTH_PROBE_TIMEOUT_SECONDS` for slower deployments.

## Persistence

Authoritative state lives in MySQL. The proxy container also persists local runtime assets in named volumes:

- `proxy_data` -> `/var/lib/squid-flask-proxy` for policy artifacts, PAC renders, web-filter snapshots, adblock artifacts, and proxy-local state.
- `squid_cache` -> `/var/spool/squid` for Squid cache storage.
- `squid_ssl_db` -> `/var/lib/ssl_db` for Squid sslcrtd state.
- `./squid/ssl/certs` -> `/etc/squid/ssl/certs` for the generated or uploaded CA material in the default Compose setup.

`docker compose down -v` removes named volumes.

## Networking and security model

Published ports in the default Compose configuration:

- `5000/tcp`: admin UI.
- `80/tcp`: public proxy health, PAC, and WPAD only.
- `3128/tcp`: explicit HTTP proxy.
- `3129/tcp`: plain-HTTP NAT intercept listener, useful only when intercept mode is enabled and client traffic is redirected by the surrounding network.

Destination-port policy:

- Non-standard HTTP and HTTPS destination ports are allowed by default.
- The baseline Squid template does not enforce restrictive `Safe_ports` or `SSL_ports` deny ACLs unless an operator adds them.

Operational guidance:

- Do not publish the admin UI to untrusted networks.
- Put the admin UI behind a management VLAN, VPN, reverse proxy, or SSH tunnel for shared environments.
- Use a strong `PROXY_MANAGEMENT_TOKEN`; the admin UI and proxy management API must agree on this token.
- Set `FLASK_SECRET_KEY` when you want host-managed session-secret rotation instead of the MySQL-backed generated secret.
- Use `SESSION_COOKIE_SECURE=1` when the UI is served over HTTPS by a reverse proxy.
- Treat SSL-bump as managed-device infrastructure: clients must trust the proxy CA, and applications with certificate pinning should be spliced.
- HTTP NAT intercept mode requires external router or host firewall rules; the container listens on the intercept port but does not install topology-specific redirect rules.

## Testing and release gates

Local deterministic tests:

```powershell
.venv\Scripts\python.exe -m pytest -m "not live" -p no:cacheprovider --durations=10 -ra web\tests
```

Live Compose test stack:

```powershell
docker compose -f docker-compose.yml -f docker-compose.live-tests.yml up --build --abort-on-container-exit --exit-code-from live-tests live-tests
```

Teardown:

```powershell
docker compose -f docker-compose.yml -f docker-compose.live-tests.yml down -v
```

The live harness starts MySQL, the admin UI, two proxy runtimes, a traffic fixture, and a dedicated pytest runner. It verifies real login, health, PAC, proxy management, sync, config apply, multi-proxy selection, cache clear, selected-proxy ClamAV reporting, and proxied request telemetry paths.

GitHub Actions runs the release gate on `main`: deterministic tests -> image build tests -> live tests -> GHCR publish.

## Project layout

```text
.github/workflows/          CI, live tests, and GHCR publication
docker/                     Dockerfiles, entrypoints, health checks, supervisord, c-icap config
proxy/                      Proxy-runtime Flask management API
scripts/                    Certificate and sslcrtd helpers
squid/                      Squid template, MIME data, and custom error pages
web/app.py                  Admin UI routes and workflows
web/services/               MySQL stores, policy engines, PAC rendering, proxy sync, observability
web/templates/              Admin UI pages
web/tools/                  Squid helper programs and artifact builders
web/tests/                  Deterministic and live pytest coverage
```

## Troubleshooting quick checks

```powershell
# Container state
docker compose ps

# Admin UI and proxy logs
docker compose logs -f admin-ui proxy

# Health endpoints
curl http://localhost:5000/health
curl http://localhost/health

# PAC/WPAD
curl http://localhost/proxy.pac
curl http://localhost/wpad.dat

# Explicit proxy smoke test
curl --proxy http://localhost:3128 http://example.com/
```

Common issues:

- **UI works locally but not from the LAN**: check host firewall rules for inbound `5000`, `80`, `3128`, and any intercept port you publish.
- **Proxy actions are unavailable**: verify the selected proxy is registered and has a reachable management URL.
- **AV health is red**: verify `CLAMD_HOST:CLAMD_PORT`; the proxy container expects a remote `clamd` service.
- **Modern SaaS or meeting apps break under TLS inspection**: splice the vendor domains, use the compatibility presets, and prefer PAC-based routing for clients that need DIRECT fallbacks.
- **Transparent HTTP interception loops**: exempt the proxy host/container source traffic before redirecting client TCP/80 to the intercept listener.

## License

See [LICENSE](LICENSE).
