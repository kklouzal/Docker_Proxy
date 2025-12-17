# Squid Flask Proxy

This project is a Dockerized Squid proxy bundled with a Flask admin UI.

It’s designed for “real” proxy deployments where you want:
- A manageable Squid configuration (templated + UI-driven includes)
- Optional SSL-bump (TLS interception) for managed devices
- Domain-based policy controls (exclusions, category filtering, whitelist)
- WPAD/PAC auto-discovery without exposing the admin UI on port 80
- Optional ICAP services for ad-blocking and antivirus

## Quick start

Build and run:
```powershell
docker compose up -d --build
```

Open the admin UI:
- `http://localhost:5000`

Default login:
- Username: `admin`
- Password: `admin`

After first login, change the password in **Administration**.

## Ports and endpoints

The default Compose file publishes:
- `3128/tcp`: Squid HTTP proxy
- `5000/tcp`: Admin UI (Flask)
- `80/tcp`: WPAD/PAC *dedicated listener* (NOT the admin UI)
- `1080/tcp`: SOCKS5 proxy (Dante)

WPAD/PAC listener behavior (port 80):
- `GET /` → serves `wpad.dat`
- `GET /wpad.dat` → serves PAC (`application/x-ns-proxy-autoconfig`)
- `GET /proxy.pac` → serves PAC
- Any other path returns `404`

Note: `http://<host>:5000` is the admin UI. Port 80 is intentionally isolated to PAC/WPAD only.

## Access from other computers (LAN)

By default, Docker publishes ports on all interfaces (`0.0.0.0`) via Compose:
- Admin UI: `http://<host-ip>:5000`
- Proxy: configure system/browser proxy to `http://<host-ip>:3128`
- WPAD: `http://<host-ip>/wpad.dat` (port 80)

If it works on the host but not from another machine, on Windows the most common cause is an inbound firewall rule.

### Windows Firewall (PowerShell)
Run these in an elevated PowerShell to allow inbound TCP on the Private profile:
```powershell
New-NetFirewallRule -DisplayName "Squid Flask Proxy UI (5000)" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5000 -Profile Private
New-NetFirewallRule -DisplayName "Squid Proxy (3128)" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 3128 -Profile Private
New-NetFirewallRule -DisplayName "Squid WPAD/PAC (80)" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 80 -Profile Private
New-NetFirewallRule -DisplayName "Squid SOCKS (1080)" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 1080 -Profile Private
```

Also confirm:
- You’re using `http://` (not `https://`) for the UI.
- The client machine is on the same LAN/subnet and not on an isolated/guest Wi‑Fi network.

## Authentication and security

- The admin UI is protected by a login session.
- PAC endpoints (`/proxy.pac`, `/wpad.dat`) are intentionally public so WPAD works without authentication.
- Users are managed in **Administration** (add users, change passwords). The currently logged-in user cannot delete themselves.

If you want stronger isolation, consider removing the `5000:5000` publish and accessing the UI only via:
- a management VLAN
- a VPN
- an SSH tunnel / port-forward

## Features (current)

- **Status/Diagnostics** pages for live proxy activity and health.
- **Policy controls** from the web UI:
  - Squid config editor (with safe defaults)
  - Exclusions (domain/CIDR policies for problematic destinations)
  - Certificates (CA management for ssl-bump)
  - Ad Blocking (ICAP REQMOD)
  - Web Filtering (UT1 categories, domain-based)
  - ClamAV scanning (ICAP RESPMOD)
  - SSL Filtering (client CIDRs that must be spliced)
- **PAC Builder** UI at `/pac` + PAC generation at `/proxy.pac`.
- **WPAD** support via the dedicated port 80 listener, serving `wpad.dat`.

## SOCKS5 support (Dante)
This container also runs a Dante SOCKS proxy on port `1080`.

Default policy:
- No authentication
- Restricted to RFC1918 client ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
- Allows both TCP and UDP (UDP relay support depends on the client)

Configuration (optional):
- Set `DANTE_ALLOW_FROM` (space-separated CIDRs) in `/config/app.env` to restrict allowed client networks.
- `DANTE_BLOCK_PRIVATE_DESTS=1` blocks SOCKS requests to loopback + RFC1918 destinations (prevents using the proxy to reach internal networks).
- Mount your own `/etc/sockd.conf` if you need a custom Dante policy.

### Windows note (inetcpl.cpl)
On Windows, the system proxy configured via **Internet Options (inetcpl.cpl)** is primarily an **HTTP/HTTPS proxy** feature. Many apps (and even some browsers) will not use a SOCKS proxy configured there, and some SOCKS settings only apply to dial-up/VPN profiles.

To verify Dante is reachable from a client, test explicitly:
`curl --socks5-hostname <host-ip>:1080 https://example.com -v`

Also note: depending on Docker Desktop/NAT, Dante may log the source as a gateway/NAT IP rather than the true LAN client IP.

## Host networking mode (optional)
If Docker NAT is causing issues (for example: client IPs being masked, or connectivity quirks), you can run the container using Docker's **host network driver**.

Docker documents host networking support as:
- Docker Engine on Linux
- Docker Desktop 4.34+ (requires enabling the feature in Docker Desktop settings)

### Docker Desktop prerequisites
1. Docker Desktop → **Settings** → **Resources** → **Network**
2. Enable **Host networking**
3. Apply & restart Docker Desktop

Important limitations (Docker Desktop):
- Host networking works at **layer 4** (TCP/UDP). Protocols below TCP/UDP are not supported.
- Only **Linux containers** are supported.
- Published ports (`ports:`) are not used with host networking; services bind directly on the host.

### Run with host networking
Use the provided Compose file:
```powershell
docker compose -f docker-compose.host.yml up -d --build
```

Ports will be bound directly on the host (defaults):
- Squid proxy: `3128`
- Web UI: `5000`
- SOCKS5 (Dante): `1080`

If any of those ports are already in use on the host, the container will fail to start.

## Data persistence (SQLite)
This container uses SQLite (stored under `/var/lib/squid-flask-proxy` via a named Docker volume) for:
- Live activity aggregation (domains/IPs) used by the Live page
- Exclusions (domains/CIDRs) used to regenerate Squid config
- Admin audit trail of config apply actions (success/failure + request metadata)
- Web filtering settings + whitelist + blocked-request log
- Authentication/user database
- SSL Filtering (no-bump CIDRs)

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
- When web filtering is enabled, the container downloads/compiles a local SQLite DB of domain categories automatically.
- Refresh schedule: first download happens immediately on enable, then once per day at local midnight.
- Squid uses an `external_acl_type` helper to check the destination domain against the selected blocked categories.
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
- The log is stored in `webfilter.db` under `/var/lib/squid-flask-proxy`.

### c-icap access log (direct REQMOD logging)
The c-icap REQMOD service logs per-transaction decisions to:
- `/var/log/cicap-access.log` (TSV)

To find ad-block events, filter for `REQMOD` entries for the `adblockreq` service. Blocked requests are returned as an HTTP `403` response.

## ClamAV (ICAP)
This project supports ICAP-based antivirus scanning using **ClamAV**, implemented via **c-icap** (`virus_scan` + `clamd_mod`).

Behavior:
- Squid is configured with `bypass=on` for the AV ICAP service (fail-open if AV is unavailable).

Ports / startup behavior:
- AV scanning is served by c-icap as a **RESPMOD** service at `icap://127.0.0.1:${CICAP_AV_PORT:-14001}/avrespmod`.
- The container runs two c-icap instances: the adblock instance binds immediately, while the AV instance may wait until the `clamd` unix socket is ready.
- The AV instance writes to `/var/log/cicap-access-av.log` (separate from adblock logging).

Startup note (first run):
- If the ClamAV signature DB is missing, the container will run an initial `freshclam` download **blocking startup**.
- Container health will remain failing until `clamd` is up.

Persistence:
- ClamAV signature databases (e.g. `main.cvd`, `daily.cvd`) are stored under `/var/lib/squid-flask-proxy/clamav/db`.
- In the default Compose setup, this directory is backed by a named Docker volume (`clamav_db`), so signature updates persist across container rebuilds/restarts.
- Note: `docker compose down -v` will delete named volumes (including the ClamAV DB).

Configuration:
- Enable/disable scanning via the **ClamAV** tab (updates Squid ICAP policy).
- c-icap module configuration is provided in `docker/clamd_mod.conf` and `docker/virus_scan.conf`.
- clamd socket is `/var/lib/squid-flask-proxy/clamav/clamd.sock`.

## Caching notes (safe baseline)
The default baseline config in [squid/squid.conf.template](squid/squid.conf.template) is tuned to be a **bandwidth saver** while staying conservative:
- It caches HTTP and bumped-HTTPS content only when the origin server permits caching (no aggressive overrides of `private` / `no-store` / `no-cache`).
- It enables heuristic caching via `refresh_pattern` only when explicit expiry headers are absent.
- It allows larger objects to be cached (`maximum_object_size 64 MB`) and enables caching of Range responses (`range_offset_limit -1`).

## Mitigating app breakage (Slack / Google Meet / Webex / Teams)
Some modern apps work poorly with HTTPS interception (SSL-bump) and/or rely on non-HTTP traffic paths (especially WebRTC media over UDP). Common symptoms include sign-in loops, “can’t connect”, blank calls, or meetings failing to start.

Recommended mitigations (lowest-risk first):
- Prefer configuring **browser proxy** via a PAC file rather than forcing a global system proxy. This project serves a PAC at `/proxy.pac` and includes a PAC Builder UI at `/pac`.
- If a site/app breaks under SSL-bump (often due to **certificate pinning** or strict TLS behavior), add its domain(s) to the **Exclusions** page. Excluded domains are configured to **splice** (no bump) and **not cache**.
- If you are using `netsh winhttp set proxy ...`, use a **bypass list** for pinned/real-time apps so they go DIRECT (example categories: Teams/Office endpoints, Slack, Webex, Google Meet). WinHTTP is used by many non-browser components that may not tolerate interception.
- Be aware of protocol limits: Squid is an **HTTP proxy**. It can proxy HTTP/HTTPS (and WebSockets over HTTP), but it does not proxy arbitrary UDP. WebRTC media frequently uses UDP (STUN/TURN), so calls may still require direct UDP egress even when the browser uses an HTTP proxy for signaling.

Troubleshooting tips:
- Check the **SSL Errors** page (`/ssl-errors`) for repeated TLS/certificate/handshake failures.
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

Note: clients must trust this CA to avoid certificate warnings when bumping.

## WPAD / PAC

This project supports:
- Dynamic PAC generation at `/proxy.pac`
- WPAD auto-discovery via `/wpad.dat`

Security model:
- Port 80 is served by a dedicated minimal HTTP server that only serves PAC endpoints.
- The PAC server fetches generated PAC content from the internal Flask endpoint (`127.0.0.1:5000/proxy.pac`).

## Project structure (high level)

- `docker/`: container build + supervisord + startup scripts
  - Includes a dedicated supervisord program for the PAC/WPAD listener
- `squid/`: Squid template config + MIME + error pages
  - UI-driven policy includes live under `/etc/squid/conf.d/*.conf`
- `web/`: Flask admin UI + services + tools
  - `services/`: SQLite-backed stores and Squid integration
  - `tools/`: helper scripts (PAC server, category helper, builders, apply scripts)

## Scaling: Squid workers

This container can run Squid in SMP mode (multiple worker processes).

- Squid `workers N`
  - The entrypoint reads `workers N` from `/etc/squid/squid.conf` and uses that as the authoritative worker count.
  - It generates `/etc/squid/conf.d/20-icap.conf` with matching `adaptation_service_set` entries.

### Applying template updates
On container start, the entrypoint copies the template into `/etc/squid/squid.conf` only when the config doesn’t exist yet (or doesn’t look like an SSL-bump config).

If you already edited `/etc/squid/squid.conf` (for example via the UI), changing the template alone will not overwrite your live config.
To adopt new baseline changes, paste the updated template into the UI and reload Squid (or recreate the container after removing the existing config).

## License

This project is licensed under the MIT License. See the LICENSE file for details.