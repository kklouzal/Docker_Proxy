# Squid Flask Proxy

This project is a Dockerized application that combines a Squid proxy server with a Flask web interface for configuration and management. It allows users to configure Squid at runtime, view its status, and manage SSL certificates for HTTPS caching.

## Project Structure

- **docker/**: Contains Docker-related files.
  - `Dockerfile`: Instructions to build the Docker image.
  - `entrypoint.sh`: Script executed when the container starts.
  - `supervisord.conf`: Configuration for Supervisor to manage processes.
  - `healthcheck.sh`: Script to check the health of services.

- **squid/**: Contains Squid configuration files.
  - `squid.conf.template`: Template for Squid configuration.
  - `mime.conf`: Defines MIME types for Squid.
  - `error_pages/`: Directory for custom error pages.
  - `ssl/`: Directory for SSL certificates and database.

- **web/**: Contains the Flask web application.
  - `app.py`: Main Flask application file.
  - `wsgi.py`: WSGI entry point for serving the Flask app.
  - `requirements.txt`: Python dependencies for the Flask application.
  - `templates/`: HTML templates for the web interface.
  - `static/`: Directory for static files.
  - `services/`: Contains service logic for interacting with Squid and managing configurations.
  - `tests/`: Unit tests for the Flask application.

- **scripts/**: Contains utility scripts for managing SSL and Squid.
  - `generate_ca.sh`: Generates a self-signed certificate authority (CA).
  - `init_ssl_db.sh`: Initializes the SSL database for Squid.
  - `reload_squid.sh`: Reloads the Squid configuration.

- **config/**: Contains example environment configuration files.
  - `app.env.example`: Example environment configuration for the Flask app.
  - `squid.env.example`: Example environment configuration for Squid.

- **docker-compose.yml**: Defines services, networks, and volumes for the Docker application.

- **.dockerignore**: Specifies files to ignore when building the Docker image.

- **.gitignore**: Specifies files to ignore in version control.

## Getting Started

1. **Clone the repository**:
   ```
   git clone <repository-url>
   cd squid-flask-proxy
   ```

2. **Build the Docker image**:
   ```
   docker-compose build
   ```

3. **Run the application**:
   ```
   docker-compose up
   ```

4. **Access the web interface**:
   Open your web browser and navigate to `http://localhost:5000`.

## Access from other computers (LAN)
By default, Docker publishes the ports on all interfaces (`0.0.0.0`) via Compose:
- Web UI: `http://<host-ip>:5000`
- Proxy: set your client/system proxy to `<host-ip>:3128`

If it works on the host but not from another machine, the most common cause on Windows is an inbound firewall rule.

### Windows Firewall (PowerShell)
Run these in an elevated PowerShell to allow inbound TCP on the Private profile:
```powershell
New-NetFirewallRule -DisplayName "Squid Flask Proxy UI (5000)" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5000 -Profile Private
New-NetFirewallRule -DisplayName "Squid Proxy (3128)" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 3128 -Profile Private
```

Also confirm:
- You’re using `http://` (not `https://`) for the UI.
- The client machine is on the same LAN/subnet and not on an isolated/guest Wi‑Fi network.

## Features

- Dynamic Squid configuration through a web interface.
- View the status of the Squid proxy and Flask application.
- Generate and download self-signed SSL certificates for HTTPS caching.

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

## Ad Blocking (ICAP)
This project supports ICAP-based request blocking using EasyList-style subscriptions.

Important performance note: full EasyList URL matching can be CPU-heavy, especially when combined with SSL-bump (HTTPS interception).

### Tuning
Ad blocking behavior is configured in the **Ad Blocking** tab in the web UI:
- Global enable/disable
- Subscription list enable/disable and manual “Update now”
- Decision cache settings (TTL + max entries)

## ClamAV (ICAP)
This project also supports ICAP-based antivirus scanning using **ClamAV**.

Behavior:
- Scans HTTP responses (RESPMOD) **before** the ICAP Preload HTML rewrite stage.
- Decompresses `Content-Encoding` (gzip/deflate/br) before scanning.
- Skips scanning for `image/*` and `video/*` responses.
- Enforces a max scan size of **128 MiB** (larger responses are skipped).
- On detection, the response is replaced with a simple block page.

Startup note (first run):
- If the ClamAV signature DB is missing, the container will run an initial `freshclam` download **blocking startup**.
- Container health will remain failing until `clamd` is up.

Persistence:
- ClamAV signature databases (e.g. `main.cvd`, `daily.cvd`) are stored under `/var/lib/squid-flask-proxy/clamav/db`.
- In the default Compose setup, this directory is backed by a named Docker volume (`clamav_db`), so signature updates persist across container rebuilds/restarts.
- Note: `docker compose down -v` will delete named volumes (including the ClamAV DB).

Configuration:
- Enable/disable scanning via the **ClamAV** tab (updates Squid ICAP policy).
- Max scan size is configurable in the **ClamAV** tab (default: 128 MiB).
- clamd socket is fixed at `/var/lib/squid-flask-proxy/clamav/clamd.sock`.

## Caching notes (safe baseline)
The default baseline config in [squid/squid.conf.template](squid/squid.conf.template) is tuned to be a **bandwidth saver** while staying conservative:
- It caches HTTP and bumped-HTTPS content only when the origin server permits caching (no aggressive overrides of `private` / `no-store` / `no-cache`).
- It enables heuristic caching via `refresh_pattern` only when explicit expiry headers are absent.
- It allows larger objects to be cached (`maximum_object_size 64 MB`) and enables caching of Range responses (`range_offset_limit -1`).

## Mitigating app breakage (Slack / Google Meet / Webex / Teams)
Some modern apps work poorly with HTTPS interception (SSL-bump) and/or rely on non-HTTP traffic paths (especially WebRTC media over UDP). Common symptoms include sign-in loops, “can’t connect”, blank calls, or meetings failing to start.

Recommended mitigations (lowest-risk first):
- Prefer configuring **browser proxy** via a PAC file rather than forcing a global system proxy. This project serves a PAC at `/proxy.pac`.
- If a site/app breaks under SSL-bump (often due to **certificate pinning** or strict TLS behavior), add its domain(s) to the **Exclusions** page. Excluded domains are configured to **splice** (no bump) and **not cache**.
- If you are using `netsh winhttp set proxy ...`, use a **bypass list** for pinned/real-time apps so they go DIRECT (example categories: Teams/Office endpoints, Slack, Webex, Google Meet). WinHTTP is used by many non-browser components that may not tolerate interception.
- Be aware of protocol limits: Squid is an **HTTP proxy**. It can proxy HTTP/HTTPS (and WebSockets over HTTP), but it does not proxy arbitrary UDP. WebRTC media frequently uses UDP (STUN/TURN), so calls may still require direct UDP egress even when the browser uses an HTTP proxy for signaling.

Troubleshooting tips:
- Check the **SSL Errors** page (`/ssl-errors`) for repeated TLS/certificate/handshake failures.
- If changing Squid `workers` to improve throughput, note it triggers a full Squid restart.

## Scaling: Squid workers and ICAP processes

This container can run Squid in SMP mode (multiple worker processes) and will start the **same number of ICAP server processes** for throughput **at container start**.

- `SQUID_WORKERS` (default: `2`)
  - Used as a fallback if `workers N` is not present in the Squid config.
  - Sets the number of ICAP server processes supervised by Supervisor.
  - Squid load-balances across the ICAP instances using `adaptation_service_set`.

- Squid `workers N`
  - The entrypoint reads `workers N` from `/etc/squid/squid.conf` and uses that as the authoritative worker count.
  - If you change `workers`, recreate/restart the container so Supervisor can respawn the correct number of ICAP processes.

- `ICAP_BASE_PORT` (default: `1344`)
  - ICAP instances listen on consecutive ports starting at this base (e.g. `1344`, `1345`, `1346`...).
  - Squid is configured to use all of these instances.

### Applying template updates
On container start, the entrypoint copies the template into `/etc/squid/squid.conf` only when the config doesn’t exist yet (or doesn’t look like an SSL-bump config).

If you already edited `/etc/squid/squid.conf` (for example via the UI), changing the template alone will not overwrite your live config.
To adopt new baseline changes, paste the updated template into the UI and reload Squid (or recreate the container after removing the existing config).

## License

This project is licensed under the MIT License. See the LICENSE file for details.