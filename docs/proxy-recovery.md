# Proxy-local recovery adoption

Each proxy writes a signed recovery bundle plus a private HMAC key under `PROXY_RECOVERY_DIR` (default: `/var/lib/squid-flask-proxy/recovery`). That directory must live on the proxy's durable volume (`/var/lib/squid-flask-proxy` in the compose files), not on Admin UI/MySQL-only storage. For RB5009/RouterOS-adjacent deployments, keep the persisted host/NAS path mapped into the proxy container at this durable path; do not place the bundle/key on ephemeral router flash, Admin UI exports, or shared backup bundles. Do not expose or copy the key through environment variables, UI fields, logs, or shared backup bundles.

Bundle reads and writes are bounded by `PROXY_RECOVERY_MAX_BUNDLE_BYTES`, which accepts decimal bytes only. The default is `134217728` (128 MiB), large enough for current active adblock artifact recovery payloads while preserving bounded deserialization; values below 1 MiB or above `536870912` (512 MiB) are rejected as invalid configuration.

## First connection to a replacement control plane

When an existing proxy container first connects to a fresh replacement MySQL/Admin UI control plane, startup runs schema migrations through the recovery marker schema, minimally registers the proxy identity needed by lifecycle write guards, verifies the local bundle/key, then attempts one adoption before normal defaults/config refresh/apply run.

Startup continues for these outcomes:

- `adopted`: the fresh target imported the bundle and recorded an adoption marker.
- `already_adopted`: this target control plane already recorded the one-time adoption.
- `same_control_plane`: the bundle was produced by the current control plane, so no import is needed.
- Missing bundle/key for a brand-new proxy: normal startup continues and the proxy captures a fresh bundle after the first successful authoritative DB startup.

Startup fails closed for nonfresh/conflicting target DB state, ambiguous adoption markers, invalid/missing control-plane identity after migrations, corrupt/tampered/oversize/private-permission-invalid recovery files, and restore exceptions. Preserve the recovery directory and either retry against a fresh replacement control plane or perform manual MySQL recovery; startup intentionally stops before normal declarative refresh can overwrite retained local settings.

## Ongoing capture policy

After successful startup/sync, and after successful runtime config/materialization reconciliation, the proxy captures the current authoritative DB state back to the local bundle with atomic/private writes. Runtime capture failure is logged as an operator warning and preserves the previous bundle; the first post-startup capture for a new proxy without a bundle is required once DB startup has completed.

The recovery bundle is a convenience for adopting retained proxy-local configuration during Admin UI/MySQL replacement. It is not a substitute for normal MySQL backups, and it may contain policy, certificate, directory/SAML, and other sensitive declarative settings.
