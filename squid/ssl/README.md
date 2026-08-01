# Docker Proxy Squid SSL material

This directory is the source-tree anchor for Squid SSL inspection certificate material. Runtime certificate files are generated or uploaded through the Admin UI and mounted into containers at `/etc/squid/ssl/certs`.

## Runtime contract

- `squid/ssl/certs/` is intentionally not part of the tracked source inventory. It may exist in a deployment checkout as an ignored bind-mount directory containing generated CA and Admin UI leaf material.
- Squid SSL inspection reads `/etc/squid/ssl/certs/ca.crt` and `/etc/squid/ssl/certs/ca.key`.
- The Admin UI HTTPS toggle uses `/etc/squid/ssl/certs/admin-ui.crt` and `/etc/squid/ssl/certs/admin-ui.key`, signed by the active CA bundle.
- Squid's `ssl_crtd` helper database is runtime state under `/var/lib/ssl_db`.

## Operator notes

Install the generated CA certificate on clients that should trust inspected HTTPS traffic. Do not commit generated private keys, CA bundles, or ssl_crtd database files to this repository. If certificate material appears in a working tree, treat it as deployment-local secret state and keep it out of source changes.
