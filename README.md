# Squid Flask Proxy

A Dockerized Squid HTTP proxy bundled with a Flask admin UI for managing policy and operational settings.

Runtime state now targets an **external MySQL 8+ backend**.

The SQLite migration window has closed: the project now supports **MySQL 8+ only**, and runtime services create/use the current schema directly rather than attempting in-place upgrades from legacy layouts.

## Multi-container architecture (admin-ui + proxy)

The repository now supports a **two-container split**:

- `admin-ui`: Flask/Gunicorn control plane for login, policy editing, proxy visibility, and desired-state management
- `proxy`: Squid/c-icap runtime plus a tiny internal management API used only for:
  - health checks
  - immediate config sync from MySQL
  - cache clear actions
  - on-demand ClamAV verification actions from the admin UI (EICAR and sample ICAP probes)

MySQL remains the source of truth for desired state, audit, stats, and proxy registration. The direct HTTP path is intentionally tiny and internal-only.

This project targets “real” proxy deployments where you want:
- A manageable Squid configuration (template baseline + UI-driven includes)
- Optional SSL-bump (TLS interception) for managed devices
- Domain-based policy controls (exclusions, web filtering + whitelist)
- WPAD/PAC auto-discovery without exposing the admin UI on port 80
- Optional ICAP services for ad-blocking (REQMOD) and antivirus scanning (ClamAV via RESPMOD)

## Quick start (build from source)

The default source-build Compose file now brings up **both** services:

- `admin-ui` on port `5000`
- `proxy` on ports `80` and `3128`

Set the external database connection in the root `.env` file (gitignored) or via your shell/launch environment.

If you still have data in an older SQLite or pre-split schema layout, export it before upgrading; this repository no longer contains compatibility code to auto-migrate legacy databases in place.

Example:

```dotenv
MYSQL_HOST=192.168.1.10
MYSQL_PORT=3306
MYSQL_USER=root
MYSQL_PASSWORD=change_me
MYSQL_DATABASE=squid_proxy
MYSQL_CREATE_DATABASE=1
```

```powershell
docker compose up -d --build
```

Maintenance note:
- `docker-compose.common.yml` is the shared source of truth for service definitions, environment defaults, ports, volumes, and healthchecks.
- Keep `docker-compose.yml` and `docker-compose.ghcr.yml` focused on the source-build vs prebuilt-image differences so the two deployment paths do not drift.

By default, source builds now track Alpine's `edge` image tag so both
containers pick up the newest Alpine-packaged Squid and supporting runtime
packages available at build time. If you want a more reproducible stable
build instead, override the build arg when building:

```powershell
docker compose build --build-arg ALPINE_VERSION=3.23.4
```

## Live stack tests

The repository now includes a compose-based live test harness that keeps the
runtime containers production-like and executes pytest from a separate
`live-tests` container against the real stack.

What it does:
- starts an ephemeral `mysql-test` service
- starts a tiny `traffic-fixture` upstream service used to generate real proxied requests
- runs the normal `admin-ui` plus two real `proxy` containers against that database so split-mode and remote-scope flows exercise actual container-to-container targeting
- enables `ENABLE_TEST_MODE=1` for the runtime containers so background
  heartbeat/sync loops converge faster when you did not explicitly set custom
  cadence values
- pins the live harness to a local loopback ClamAV target and uses a core-stack
  proxy health check so the initial smoke suite stays self-contained even when
  you do not have an external `clamd` backend available
- gives the second proxy distinct ClamAV/c-icap endpoint settings so the admin
  UI can prove it is rendering and targeting the selected remote proxy instead
  of a local stand-in
- runs the live pytest suites from a dedicated test-runner container over the
  real Docker network

Run the live smoke suite:

```powershell
docker compose -f docker-compose.yml -f docker-compose.live-tests.yml up --build --abort-on-container-exit --exit-code-from live-tests live-tests
```

Tear the live stack down afterward:

```powershell
docker compose -f docker-compose.yml -f docker-compose.live-tests.yml down -v
```

The initial smoke suite validates the real admin login flow, health endpoints,
proxy management API, forced sync path, and PAC serving. This is intentionally
implemented as a separate runner container rather than embedding pytest into the
production containers themselves. AV/ClamAV verification remains a follow-up
expansion once the live harness provisions a dedicated scan backend.

The live harness now also covers broader real workflows that previously relied
on in-process fakes, including:
- authenticated admin shell/page rendering
- live Squid config download + validate/apply flows
- PAC profile create/update/delete with rendered PAC verification
- exclusions apply/remove flows with PAC refresh verification
- user-management add/change/delete flows
- live proxy management API auth, sync, cache-clear, and current AV failure reporting
- real proxied request generation through the live HTTP proxy with observability,
  cache-reason, performance, and monitoring-page assertions driven by the
  resulting in-container telemetry

Live-run guardrails:
- the dedicated `live-tests` runner now executes pytest in verbose mode so you
  can see ongoing progress instead of a long silent wait
- each live test is capped by `pytest-timeout` (default `180` seconds, override
  with `LIVE_TEST_PYTEST_TIMEOUT_SECONDS`) so a blocked request cannot hang the
  suite indefinitely
- split-mode proxy inventory, proxy-scoped navigation, remote PAC pinning,
  and selected-proxy page notices backed by two real proxy containers
- selected-proxy control-plane actions such as remote config reads, scoped reload,
  remote ClamAV health rendering, and shared certificate apply propagation

Admin UI:
- http://localhost:5000

Proxy runtime:
- HTTP proxy: `http://localhost:3128`
- PAC/WPAD: `http://localhost/`

Default login (first run only):
- Username: `admin`
- Password: `admin`

Change the password in **Administration** after first login.

## Run the prebuilt image (GHCR)

The GHCR deployment file now uses **two images**:

- `ghcr.io/<owner>/<repo>-admin-ui:<tag>`
- `ghcr.io/<owner>/<repo>-proxy:<tag>`

Use the provided file:

```powershell
docker compose -f docker-compose.ghcr.yml up -d
```

Or copy/paste a minimal Compose:

```yaml
name: squid-flask-proxy

services:
  admin-ui:
    image: ghcr.io/kklouzal/docker_proxy-admin-ui:main
    ports:
      - "0.0.0.0:5000:5000"
    environment:
      PROXY_MANAGEMENT_TOKEN: ${PROXY_MANAGEMENT_TOKEN:-change-me}
      DATABASE_URL: ${DATABASE_URL:-}
      MYSQL_HOST: ${MYSQL_HOST:-}
      MYSQL_PORT: ${MYSQL_PORT:-3306}
      MYSQL_USER: ${MYSQL_USER:-}
      MYSQL_PASSWORD: ${MYSQL_PASSWORD:-}
      MYSQL_DATABASE: ${MYSQL_DATABASE:-}
      MYSQL_CREATE_DATABASE: ${MYSQL_CREATE_DATABASE:-1}
    depends_on:
      proxy:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "/healthcheck.admin.sh"]
      interval: 15s
      timeout: 5s
      retries: 5
      start_period: 20s

  proxy:
    image: ghcr.io/kklouzal/docker_proxy-proxy:main
    shm_size: ${PROXY_SHM_SIZE:-512m}
    sysctls:
      net.ipv6.conf.all.disable_ipv6: ${DISABLE_IPV6:-1}
      net.ipv6.conf.default.disable_ipv6: ${DISABLE_IPV6:-1}
      net.ipv6.conf.lo.disable_ipv6: ${DISABLE_IPV6:-1}
    ports:
      - "0.0.0.0:80:80"           # WPAD / PAC via dedicated listener
      - "0.0.0.0:3128:3128"       # Squid HTTP proxy
    volumes:
      - ./squid/squid.conf.template:/etc/squid/squid.conf.template:ro
      - ./squid/ssl/certs:/etc/squid/ssl/certs
      - squid_ssl_db:/var/lib/ssl_db
      - squid_cache:/var/spool/squid
      - proxy_data:/var/lib/squid-flask-proxy
    environment:
      DISABLE_IPV6: ${DISABLE_IPV6:-1}
      SQUID_WORKERS: ${SQUID_WORKERS:-}
      SQUID_CACHE_MEM_MB: ${SQUID_CACHE_MEM_MB:-}
      SQUID_SSLCRTD_CHILDREN: ${SQUID_SSLCRTD_CHILDREN:-}
      SQUID_DYNAMIC_CERT_MEM_CACHE_MB: ${SQUID_DYNAMIC_CERT_MEM_CACHE_MB:-}
      SQUID_MAX_FILEDESCRIPTORS: ${SQUID_MAX_FILEDESCRIPTORS:-}
      CICAP_PORT: ${CICAP_PORT:-14000}
      CICAP_AV_PORT: ${CICAP_AV_PORT:-14001}
      CLAMD_HOST: ${CLAMD_HOST:-127.0.0.1}
      CLAMD_PORT: ${CLAMD_PORT:-3310}
      WEB_WORKERS: ${WEB_WORKERS:-}
      WEB_THREADS: ${WEB_THREADS:-}
      ULIMIT_NOFILE: ${ULIMIT_NOFILE:-}
      WEBFILTER_HELPERS: ${WEBFILTER_HELPERS:-}
      DB_POOL_SIZE: ${DB_POOL_SIZE:-}
      DATABASE_URL: ${DATABASE_URL:-}
      MYSQL_HOST: ${MYSQL_HOST:-}
      MYSQL_PORT: ${MYSQL_PORT:-3306}
      MYSQL_USER: ${MYSQL_USER:-}
      MYSQL_PASSWORD: ${MYSQL_PASSWORD:-}
      MYSQL_DATABASE: ${MYSQL_DATABASE:-}
      MYSQL_CREATE_DATABASE: ${MYSQL_CREATE_DATABASE:-1}
      PROXY_MANAGEMENT_TOKEN: ${PROXY_MANAGEMENT_TOKEN:-change-me}
    healthcheck:
      test: ["CMD", "/healthcheck.sh"]
      interval: 15s
      timeout: 5s
      retries: 5
      start_period: 90s

volumes:
  squid_cache:
  squid_ssl_db:
  proxy_data:
```

Notes:
- Container images can be inspected by recipients (layers/files), so don’t bake secrets into the image.
- If you publish under a different owner/repo, update the `image:` value.
- The GHCR publish workflow also refreshes on a weekly schedule so the prebuilt `:main` image can pick up newer Alpine/Squid packages even without a code change.
- The split images are now the only supported deployment path; the old monolithic image layout has been removed from the repository.

## Ports and endpoints

Default published ports:
- `3128/tcp`: Squid HTTP proxy
- `5000/tcp`: Admin UI (Flask)
- `80/tcp`: WPAD/PAC dedicated listener (NOT the admin UI)

Destination-port policy note:
- Squid allows non-standard HTTP and HTTPS destination ports by default.
- The baseline template intentionally does **not** enforce restrictive `Safe_ports` / `SSL_ports` deny ACLs unless you add them manually.
- Operators can review this in the **Squid Config → Network** tab and add explicit restrictions later through the raw config editor if their environment requires it.

Admin UI routes (port 5000):
- `/` UI home
- `/pac` PAC Builder UI (management only)
- `/health` health endpoint (used by container healthcheck)

WPAD/PAC listener behavior (port 80):
- `GET /` → serves `wpad.dat`
- `GET /wpad.dat` → serves PAC (`application/x-ns-proxy-autoconfig`)
- `GET /proxy.pac` → serves PAC
- Any other path → `404`

Important: `http://<host>:5000` is the admin UI. Port 80 is intentionally isolated to PAC/WPAD only.

## Access from other computers (LAN)

Docker publishes ports on all interfaces (`0.0.0.0`) by default:
- Admin UI: `http://<host-ip>:5000`
- HTTP proxy: configure clients to `http://<host-ip>:3128`
- PAC: `http://<proxy-host>/proxy.pac` (port 80, served by the selected proxy)
- WPAD: `http://<host-ip>/wpad.dat` (port 80)

On Windows, the most common “works on host but not on LAN” issue is the inbound firewall.

### Windows Firewall (PowerShell)

Run in elevated PowerShell to allow inbound TCP on the Private profile:

```powershell
New-NetFirewallRule -DisplayName "Squid Flask Proxy UI (5000)" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5000 -Profile Private
New-NetFirewallRule -DisplayName "Squid Proxy (3128)" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 3128 -Profile Private
New-NetFirewallRule -DisplayName "Squid WPAD/PAC (80)" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 80 -Profile Private
```

Also confirm:
- You’re using `http://` (not `https://`) for the UI (unless you front it with your own TLS).
- The client is on the same LAN/subnet and not on an isolated/guest Wi‑Fi.

## Persistence (volumes + database)

Authoritative runtime/admin state now lives in the configured external MySQL database.

The container persists operational state under `/var/lib/squid-flask-proxy` (backed by the `proxy_data` named volume in the default Compose setup), including:
- Policy artifacts and caches (compiled adblock/web filter files, cached proxy-runtime assets)
- Adblock compiled lists / caches

Squid cache and SSL database use separate named volumes by default:
- Squid cache: `/var/spool/squid` (`squid_cache`)
- sslcrtd DB: `/var/lib/ssl_db` (`squid_ssl_db`)

Reminder: `docker compose down -v` deletes named volumes.

## Log rotation

Squid logs are rotated automatically every 24 hours inside the container by a supervisor-managed job that runs `squid -k rotate`.

Notes:
- Retention is controlled by the Squid directive `logfile_rotate N` (default `10`).
- You can change the rotation interval by setting `SQUID_LOG_ROTATE_INTERVAL_SECONDS` (default `86400`).

## Authentication and security model

- The admin UI is protected by a login session.
- PAC/WPAD endpoints on port `80` (`/proxy.pac`, `/wpad.dat`) are intentionally public so clients can fetch PAC without UI authentication.

Recommended hardening:
- Don’t publish the UI port (`5000`) to untrusted networks.
- Set a persistent Flask secret key (see “Configuration”), so sessions remain valid across restarts.
- If you terminate TLS in front of the UI (reverse proxy), set secure cookies.

If you want stronger isolation, consider removing the `5000:5000` publish and accessing the UI only via a management VLAN/VPN or an SSH tunnel.

## Configuration (optional `/config/app.env`)

On startup, the container will load environment variables from `/config/app.env` if you mount it.

Example:

```yaml
services:
  proxy:
    volumes:
      - ./config/app.env:/config/app.env:ro
```

Common environment variables:
- `DATABASE_URL`: optional full DSN for the external database (for example `mysql+pymysql://user:pass@host:3306/squid_proxy`). SQLite DSNs are no longer supported.
- `MYSQL_HOST`, `MYSQL_PORT`, `MYSQL_USER`, `MYSQL_PASSWORD`, `MYSQL_DATABASE`: discrete MySQL connection settings.
- `MYSQL_CREATE_DATABASE=1|0`: auto-create the configured MySQL database if the user has permission.
- `MYSQL_CONNECT_TIMEOUT`, `MYSQL_READ_TIMEOUT`, `MYSQL_WRITE_TIMEOUT`: MySQL client connect/read/write timeouts used by the proxy and admin services.
- `DISABLE_IPV6=1|0`: when enabled, the container disables IPv6 via sysctls, normalizes local binds to IPv4, and the Compose examples publish ports on `0.0.0.0` only.
- `FLASK_SECRET_KEY`: recommended; keeps login sessions stable across restarts.
- `SESSION_COOKIE_SECURE=1`: mark cookies Secure (use when UI is served over HTTPS).
- `DISABLE_CSRF=1`: disables CSRF protection (intended for debugging only; not recommended).
- `SQUID_WORKERS`: explicit Squid SMP bootstrap override. If blank, the Squid config's `workers` value is authoritative.
- `MAX_WORKERS`: admin-UI clamp for the template-backed workers form (default `4`).
- `SQUID_CACHE_MEM_MB`: explicit Squid memory-cache override. Leave blank to keep the persisted/template value; the entrypoint no longer overwrites UI-applied values unless you set an explicit env override.
- `PROXY_SHM_SIZE`: Compose `/dev/shm` allocation for Squid shared memory (default `512m`). Keep this comfortably above `SQUID_CACHE_MEM_MB` when `memory_cache_shared on` is active; too small a value can make Squid terminate with SIGBUS under live traffic.
- `SQUID_SSLCRTD_CHILDREN`: explicit ssl_crtd helper-process override. Leave blank to keep the persisted/template value; otherwise the startup default derives from Squid workers.
- `SQUID_DYNAMIC_CERT_MEM_CACHE_MB`: explicit TLS dynamic certificate cache override. Leave blank to keep the persisted/template value; otherwise the startup default derives from Squid workers (`128 × workers`, capped at `512`).
- `SQUID_MAX_FILEDESCRIPTORS`: explicit Squid file-descriptor ceiling. Leave blank to keep the persisted/template value; otherwise the startup default derives from Squid workers (minimum `65536`).
- `CICAP_PORT`, `CICAP_AV_PORT`: ICAP ports for adblock (REQMOD) and AV (RESPMOD) instances.
- `CLAMD_HOST`, `CLAMD_PORT`: remote ClamAV daemon used by the local AV c-icap instance.
- `ULIMIT_NOFILE`: optional file-descriptor limit for high concurrency.
- `WEBFILTER_HELPERS`: explicit Squid external ACL helper count for web filtering. Leave blank to derive from Squid workers (default `2 × workers`).
- `DB_POOL_SIZE`: per-process idle MySQL connection cache size (default now scales with local container concurrency; expect roughly `4-8` in the proxy container unless you override it).
- `ENABLE_TEST_MODE=1|0`: optional test-friendly mode for dedicated live-stack test deployments. When enabled, the proxy shortens default heartbeat/sync intervals if you did not already set explicit cadence variables. It does not run tests automatically inside the runtime containers.
- `PROXY_HEARTBEAT_INTERVAL_SECONDS`: proxy heartbeat cadence (default `90`).
- `PROXY_SYNC_INTERVAL_SECONDS`: proxy sync cadence for pulling active state from MySQL (default `30`).
- `PROXY_PUBLIC_HOST`: authoritative host/IP clients should use for this proxy's PAC URL and proxy chain.
- `PROXY_PUBLIC_PAC_URL`: optional full PAC URL override; when set, the proxy extracts scheme/host/port from it for PAC publishing.
- `PROXY_PUBLIC_PAC_SCHEME`, `PROXY_PUBLIC_PAC_PORT`: scheme/port used when building the direct PAC URL (defaults `http`, `80`).
- `PROXY_PUBLIC_HTTP_PROXY_PORT`: client-facing HTTP proxy port advertised in generated PAC files (default `3128`).
- `LIVE_STATS_POLL_INTERVAL_SECONDS`, `DIAGNOSTIC_POLL_INTERVAL_SECONDS`, `SSL_ERRORS_POLL_INTERVAL_SECONDS`: proxy-side log/telemetry poll cadence. Defaults now settle at `2.0` seconds to reduce idle wakeups while keeping the UI reasonably fresh.
- `PAC_HTTP_PORT`, `PAC_HTTP_HOST`: WPAD/PAC listener bind settings (defaults: `80`, `0.0.0.0`).

Admin UI (Gunicorn) tuning:
- `WEB_WORKERS`: explicit Gunicorn worker override. Default is `1` because the admin UI is rarely used.
- `WEB_THREADS`: explicit Gunicorn thread override. Default is `2` so `/health` and the UI stay responsive during blocking admin actions.
- `WEB_TIMEOUT`: worker timeout seconds (default `120`).
- `WEB_GRACEFUL_TIMEOUT`: graceful shutdown timeout (default `30`).
- `WEB_KEEPALIVE`: keep-alive seconds (default `5`).

## Features (current)

- **Operational visibility** pages for proxy health, live traffic, SSL/TLS error buckets, and proxy inventory.
- **Policy controls** from the web UI:
  - Squid config editor (with safe defaults)
  - Exclusions (domain/CIDR policies for problematic destinations)
  - Certificates (CA management for SSL-bump)
  - Ad Blocking (ICAP REQMOD)
  - Web Filtering (UT1 categories, domain-based)
  - ClamAV scanning (ICAP RESPMOD) with per-proxy health and on-demand verification actions
  - SSL Filtering (client CIDRs that must be spliced)
- **PAC Builder** UI at `/pac` for managing per-proxy PAC profiles.
- **Proxy-hosted PAC/WPAD** via the dedicated port 80 listener (`/proxy.pac`, `/wpad.dat`) on each proxy runtime.

## Host networking mode (optional)

If Docker NAT causes issues in your environment (for example: connectivity quirks, or you need host-level port binding semantics), you can run with host networking.

Notes:
- Host networking is generally available on Linux Docker Engine.
- Docker Desktop host networking support depends on Docker Desktop version/settings.
- With host networking, Compose `ports:` mappings are not used; services bind directly on the host.

Example Compose snippet:

```yaml
services:
  proxy:
    network_mode: host
```

## Data persistence
This container uses an external MySQL database for runtime/admin state, including:
- Live activity aggregation (domains/IPs) used by the Live page
- Exclusions (domains/CIDRs) used to regenerate Squid config
- Admin audit trail of config apply actions (success/failure + request metadata)
- Web filtering settings + whitelist + blocked-request log
- Authentication/user database
- SSL Filtering (no-bump CIDRs)
- Ad blocking state, counters, and recent events
- Time-series rollups and SSL telemetry

## Ad Blocking (ICAP)
This project supports ICAP-based request blocking using EasyList-style subscriptions.

Important performance note: full EasyList URL matching can be CPU-heavy, especially when combined with SSL-bump (HTTPS interception).

### Tuning
Ad blocking behavior is configured in the **Ad Blocking** tab in the web UI:
- Global enable/disable
- Subscription list enable/disable and manual “Update now”
- Decision cache settings (TTL + max entries)

Implementation details:
- Ad blocking is served by c-icap as a **REQMOD** service at `icap://127.0.0.1:${CICAP_PORT:-14000}/adblockreq`.
- The container compiles subscriptions on startup and on “Update now” via `web/tools/adblock_compile.py`.
- The c-icap url_check service configuration lives in `docker/adblock_req.conf`.

## Web Filtering (UT1 categories, domain-based)
This container can block destinations based on a locally downloaded categorized blacklist (UT1-style: `Blacklists/<category>/domains`).

How it works:
- The admin UI controls whether web filtering is enabled and which categories are blocked.
- When web filtering is enabled, the container downloads/compiles domain categories into MySQL-backed `webcat_*` tables automatically.
- Refresh schedule: first download happens immediately on enable, then once per day at local midnight.
- Squid uses an `external_acl_type` helper to check the destination domain against the selected blocked categories.
- The helper now serves lookups from a proxy-local SQLite snapshot that is refreshed from MySQL in the background, so steady-state web-filter decisions do not depend on per-request MySQL round trips.
- When blocked, Squid returns a custom error page (`ERR_WEBFILTER_BLOCKED`).

UI tabs:
- **Categories**: enable/disable + choose blocked categories + test a domain
- **Whitelist**: allowlist (exact or wildcard suffix) evaluated before blocking
- **Blocked Log**: recent blocked requests (client IP, destination URL, category)

Important notes:
- This is **domain-based** filtering (good for “block a site/category”). It does not require URL/path inspection.
- You are responsible for verifying the dataset’s license/terms are compatible with your internal business use.

Configuration:
- Open the UI: **Policy → Web Filtering**
- Set the feed URL
- Enable filtering and select categories to block

Blocked Log notes:
- The blocked log is recorded by the Squid external ACL helper when a category match results in a deny decision.
- The log is stored in the MySQL `webfilter_blocked_log` table.

### c-icap access log (direct REQMOD logging)
The c-icap REQMOD service logs per-transaction decisions to:
- `/var/log/cicap-access.log` (TSV)

To find ad-block events, filter for `REQMOD` entries for the `adblockreq` service. Blocked requests are returned as an HTTP `403` response.

## ClamAV (ICAP)
This project supports ICAP-based antivirus scanning using **ClamAV**, implemented via **c-icap** (`virus_scan` + `clamd_mod`).

Behavior:
- Squid is configured with `bypass=on` for the AV ICAP service (fail-open if AV is unavailable).
- AV scanning applies to inbound origin responses (`RESPMOD`), not to outbound client uploads/requests.

Topology / startup behavior:
- AV scanning is served by c-icap as a **RESPMOD** service at `icap://127.0.0.1:${CICAP_AV_PORT:-14001}/avrespmod`.
- The proxy container runs two c-icap instances: the adblock instance binds immediately, while the AV instance waits for a reachable remote `clamd` backend.
- The local AV c-icap instance talks to a remote ClamAV daemon at `CLAMD_HOST:CLAMD_PORT`.
- The AV instance does not write a per-transaction access log by default; only the adblock REQMOD instance keeps request logging for the UI/event pipeline.
- Squid only routes `GET` response bodies through the AV RESPMOD path by default; `HEAD` responses are no longer adapted because they do not carry a body to scan.
- The bundled `virus_scan` settings start streaming after `32K` and allow up to `99%` of already-received data to flow while the scan continues, which keeps browsing responsive while still reserving a final tail for the scanner to complete before the client receives 100% of the payload.

Remote ClamAV host:
- Run `clamd` (and optional `freshclam`) on a separate trusted host/container.
- Expose TCP `3310` only to the proxy host/subnet if possible.
- The proxy container no longer ships a local ClamAV signature DB or local `clamd` process.

Configuration:
- Enable/disable scanning via the **ClamAV** tab (updates Squid ICAP policy).
- Set `CLAMD_HOST` / `CLAMD_PORT` for the remote backend.
- c-icap module configuration is provided in `docker/clamd_mod.conf` and `docker/virus_scan.conf`.

Operator workflow:
- The **ClamAV** tab is intentionally per-proxy.
- The page separates three concerns so operators can troubleshoot accurately:
  - **Policy**: whether Squid currently routes responses through the AV ICAP service
  - **AV c-icap service**: whether the proxy-local `avrespmod` listener is reachable
  - **Clamd backend**: whether the configured remote `clamd` endpoint is reachable
- The **Enable** button changes Squid AV policy only. It does **not** start or stop the `clamd` daemon or the AV `c-icap` process.
- The **Test EICAR** and **Send sample ICAP** actions are executed against the selected proxy runtime through the internal management API, so the results reflect that proxy rather than the admin container.

## Caching notes (safe baseline)
The default baseline config in [squid/squid.conf.template](squid/squid.conf.template) is tuned to be a **bandwidth saver** while staying conservative:
- It caches HTTP and bumped-HTTPS content only when the origin server permits caching (no aggressive overrides of `private` / `no-store` / `no-cache`).
- It enables heuristic caching via `refresh_pattern` only when explicit expiry headers are absent.
- It now defaults to the SMP-safe `rock` disk store instead of legacy `ufs`, which keeps multi-worker cache deployments within the Squid 7.x guidance.
- It allows larger objects to be cached (`maximum_object_size 128 MB`) and enables bounded caching of Range responses (`range_offset_limit 128 MB`) so browsers still see progressive delivery.
- It now makes the intended replacement-policy baseline explicit (`cache_replacement_policy heap GDSF`, `memory_replacement_policy heap GDSF`) instead of falling back to Squid's default `lru` on fresh template-only starts.
- It keeps `cache_miss_revalidate on` by default for standards-friendlier MISS handling, while the admin UI can now turn that off when operators want faster cache warming on a mostly empty cache.
- It now makes Squid's memory/SMP cache behavior explicit (`memory_cache_mode always`, `memory_cache_shared on`, `shared_transient_entries_limit 16384`) so the hot-object cache and in-flight transaction table do not depend on ambiguous build/runtime defaults.
- It keeps higher-risk latency/caching features explicit and operator-controlled: `pipeline_prefetch` stays off by default, `reload_into_ims` stays off by default, and the quick-abort / read-ahead settings now follow Squid's documented conservative baseline unless a tenant chooses otherwise.
- It now exposes and sets defaults for more of Squid's forward-proxy hot-path knobs: idle persistent-connection lifetimes, connect/forward retry behavior, request-start and write timeouts, EDNS packet sizing, origin TLS session reuse, generated-certificate cache size, ICAP 206 / retry / upload-continuation behavior, and shared-memory / store-bucket sizing.

Additional forward-proxy performance knobs now exposed in **Policy → Squid Config**:
- **Caching**: cache-store type (`rock` vs `ufs`), rock slot size / swap throttling, memory-cache mode/sharing, transient shared-entry sizing, and freshness controls (`minimum_expiry_time`, `max_stale`, `refresh_all_ims`)
- **Timeouts / network**: request-start + write timeouts, idle client/server keepalive lifetimes, persistent-connection lifetime/error handling, connect retries, and forward retry caps
- **DNS**: `dns_packet_max`, `dns_retransmit_interval`, `ipcache_low/high`, and larger explicit IP/FQDN caches
- **SSL**: richer `sslcrtd_children` tuning, `dynamic_cert_mem_cache_size`, `sslproxy_session_ttl`, and `sslproxy_session_cache_size`
- **ICAP / performance**: `icap_206_enable`, `adaptation_send_client_ip`, `adaptation_send_username`, `icap_client_username_header`, `icap_client_username_encode`, `adaptation_service_iteration_limit`, `force_request_body_continuation`, `icap_retry`, `icap_retry_limit`, `icap_persistent_connections`, `icap_default_options_ttl`, `icap_service_failure_limit`, `icap_service_revival_delay`, `hopeless_kid_revival_delay`, `memory_pools_limit`, `shared_memory_locking`, `cpu_affinity_map`, `high_response_time_warning`, `high_page_fault_warning`, `store_avg_object_size`, and `store_objects_per_bucket`

ICAP performance note:
- The managed template now keeps `icap_preview_enable on` explicitly so ICAP services can use preview-based early decisions when their OPTIONS response requests it.

## Mitigating app breakage (Slack / Google Meet / Webex / Teams)
Some modern apps work poorly with HTTPS interception (SSL-bump) and/or rely on non-HTTP traffic paths (especially WebRTC media over UDP). Common symptoms include sign-in loops, “can’t connect”, blank calls, or meetings failing to start.

Recommended mitigations (lowest-risk first):
- Prefer configuring **browser proxy** via a PAC file rather than forcing a global system proxy. Each proxy runtime serves its PAC directly at `http://<proxy-host>/proxy.pac`, and the admin UI includes a PAC Builder page at `/pac`.
- If a site/app breaks under SSL-bump (often due to **certificate pinning** or strict TLS behavior), add its domain(s) to the **Exclusions** page. Excluded domains are configured to **splice** (no bump) and **not cache**.
- If you are using `netsh winhttp set proxy ...`, use a **bypass list** for pinned/real-time apps so they go DIRECT (example categories: Teams/Office endpoints, Slack, Webex, Google Meet). WinHTTP is used by many non-browser components that may not tolerate interception.
- Be aware of protocol limits: Squid is an **HTTP proxy**. It can proxy HTTP/HTTPS (and WebSockets over HTTP), but it does not proxy arbitrary UDP. WebRTC media frequently uses UDP (STUN/TURN), so calls may still require direct UDP egress even when the browser uses an HTTP proxy for signaling.

Troubleshooting tips:
- Check the **SSL Errors** page (`/ssl-errors`) for repeated TLS/certificate/handshake failures.
- Use the **ClamAV** page to verify whether the issue is policy-disabled AV, a missing proxy-local AV c-icap listener, or an unreachable remote `clamd` backend.
- If changing Squid `workers` to improve throughput, note it triggers a full Squid restart.

## SSL Filtering (no-bump client CIDRs)

Some client networks cannot install a custom CA (guest BYOD, IoT, consoles, printers). If those clients are TLS-intercepted (ssl-bumped), they will fail with certificate errors.

The **Policy → SSL Filtering** page lets you define client CIDRs that should be **spliced** (tunneled) instead of bumped.

Behavior:
- Matching client IP → `ssl_bump splice` (no decryption; real website certs)
- Other clients → existing rules apply (default: `ssl_bump bump all`)

Important limitation:
- Certbot/Let’s Encrypt cannot be used as a “replacement bump CA” for general browsing, because public CAs only issue certificates for domains you control.

Impact on other features:
- Spliced HTTPS traffic cannot be inspected/modified/scanned (no ICAP REQMOD/RESPMOD on the decrypted content).
- Domain-based allow/deny can still work (depending on client behavior and protocol), but you lose URL/path visibility.

## Certificates (ssl-bump CA)

The proxy uses a CA certificate + private key for SSL-bump.

Options:
- Generate a self-signed CA (default)
- Upload an existing CA bundle:
  - `.crt/.key` (where applicable)
  - `.pfx/.p12` (PKCS#12), with validation that the cert and private key match

After updating the CA, Squid is reconfigured so the change takes effect.

Where to find the generated CA:
- If you mount `./squid/ssl/certs:/etc/squid/ssl/certs`, the CA certificate will be available on the host as `./squid/ssl/certs/ca.crt`.

Note: clients must trust this CA to avoid certificate warnings when bumping.

## WPAD / PAC

This project supports:
- Proxy-hosted PAC generation at `/proxy.pac`
- WPAD auto-discovery via `/wpad.dat`

Security model:
- Port 80 is served by a dedicated minimal HTTP server that only serves PAC endpoints.
- PAC content is pre-rendered locally by the proxy runtime and served directly from the proxy container; the admin UI no longer serves PAC files on port `5000`.
- Generated PAC files return `PROXY <proxy-host>:<http-port>; DIRECT`.

## Troubleshooting

Basic checks:
- UI is reachable: `http://<host>:5000/`
- Health endpoint: `http://<host>:5000/health`
- Direct PAC endpoint: `http://<proxy-host>/proxy.pac`
- WPAD endpoint: `http://<host>/wpad.dat` (port 80)
- Proxy is reachable: configure a client to use `http://<host>:3128`

Container logs:

```powershell
docker compose logs -f proxy
```

Remote ClamAV note:
- The proxy container expects a reachable `clamd` endpoint at `CLAMD_HOST:CLAMD_PORT`.
- If that remote daemon is down or unreachable, container health will fail and AV scanning will bypass/fail open until connectivity returns.

## Project structure (high level)

- `docker/`: container build + supervisord + startup scripts
  - Includes a dedicated supervisord program for the PAC/WPAD listener
- `squid/`: Squid template config + MIME + error pages
  - UI-driven policy includes live under `/etc/squid/conf.d/*.conf`
- `web/`: Flask admin UI + services + tools
  - `services/`: MySQL-backed stores and Squid integration
  - `tools/`: helper scripts (PAC server, category helper, builders, apply scripts)

## Scaling: Squid workers

This container can run Squid in SMP mode (multiple worker processes).

The runtime now uses a Squid-first sizing model:

- the effective Squid `workers` value is the main driver
- helper/process counts derive from that worker count by default
- the worker count is hard-capped at `4`
- Gunicorn stays intentionally small (`1` worker, `2` threads by default)

Source of truth for worker count:

- explicit `SQUID_WORKERS` env override if you set one
- otherwise the Squid config's `workers N` line (persisted config if present, otherwise the active/template config)
- otherwise the safe fallback of `1`

- Squid `workers N`
  - The entrypoint resolves the effective worker count first, writes it back into the live config, and derives helper/process counts from it.
  - It generates `/etc/squid/conf.d/20-icap.conf` with matching `adaptation_service_set` entries.
  - The supervisor must launch Squid with `--foreground` for SMP kids to exist; `-N` forces the master to run as the only worker and ignores additional kids.
  - Changing the worker count also forces a cache metadata reinitialization to avoid reusing incompatible `swap.state` files.

### Applying template updates
On container start, the entrypoint copies the template into `/etc/squid/squid.conf` when the config doesn’t exist yet.

If you already edited `/etc/squid/squid.conf` (for example via the UI), changing the template alone will not overwrite your live config.
To adopt new baseline changes, paste the updated template into the UI and reload Squid (or recreate the container after removing the existing config).

## License

This project is licensed under the MIT License. See the LICENSE file for details.