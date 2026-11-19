# Proxy-local recovery adoption

Each proxy writes a signed recovery bundle plus a private HMAC key under `PROXY_RECOVERY_DIR` (default: `/var/lib/squid-flask-proxy/recovery`). That directory must live on the proxy's durable volume (`/var/lib/squid-flask-proxy` in the compose files), not on Admin UI/MySQL-only storage. For RB5009/RouterOS-adjacent deployments, keep the persisted host/NAS path mapped into the proxy container at this durable path; do not place the bundle/key on ephemeral router flash, Admin UI exports, or shared backup bundles. Do not expose or copy the key through environment variables, UI fields, logs, or shared backup bundles.

Bundle reads and writes are bounded by `PROXY_RECOVERY_MAX_BUNDLE_BYTES`, which accepts decimal bytes only. The default is `134217728` (128 MiB), large enough for current active adblock artifact recovery payloads while preserving bounded deserialization; values below 1 MiB or above `536870912` (512 MiB) are rejected as invalid configuration.

The compressed/base64 recovery-bundle bound is separate from the uncompressed
adblock artifact bound. `ADBLOCK_ARTIFACT_EXTRACT_MAX_BYTES` defaults to
`1073741824` (1 GiB; hard cap 4 GiB), and
`ADBLOCK_ARTIFACT_EXTRACT_MAX_MEMBERS` defaults to `256`. Set both identically
on Admin UI and proxy containers: the builder rejects newly generated artifacts
outside that budget before persistence, while startup recovery and runtime
materialization enforce the same limits. Raising these values is an explicit
capacity decision for a verified authoritative artifact; it does not disable
member/path, streamed-byte, truncation, or digest validation.

Newly built adblock archives losslessly deduplicate a small allowlisted set of
byte-identical JSONL compatibility/diagnostic views. A versioned manifest maps
each omitted view to its authoritative member; proxy materialization restores
the historical filenames as hard links (or copies when hard links are
unavailable). Older manifest-free archives remain readable. Recovery keeps the
same signed JSON/base64 envelope for backward compatibility; because the
embedded adblock archive is already compressed, adding another recovery-layer
compression format would add migration and bounded-decompression complexity
without removing base64's roughly one-third transport overhead.

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

## Control-plane outages (MySQL and Admin UI)

Proxy containers serve from local state and never need the Admin UI at runtime;
the Admin UI only writes desired state and operations to MySQL. The public
PAC/WPAD listener (`proxy_public`, `PAC_WEB_THREADS` threads) is a separate
process from the management API (`proxy_api`, port 5000): it serves local
materialized PAC files and loads no database-backed modules, so management or
control-plane database stalls never delay client auto-configuration (only the
emergency PAC served before any PAC state was ever materialized, and block-page
policy request submissions, consult MySQL). When MySQL
is unreachable:

- **Cold start.** The entrypoint probes MySQL once with a single bounded
  connection attempt. When it is unreachable, boot skips the local adblock
  compile and restores the SSL/web filtering includes from the durable
  last-known-good mirror (`PROXY_POLICY_LKG_DIR`, refreshed after every
  successful policy apply); only a proxy that never applied a policy gets the
  safe (filtering-disabled) include. Squid config, PAC files, certificates, the
  adblock artifact and the web-category snapshot already live on the durable
  volume. Squid, PAC/WPAD, the ICAP helpers and health start normally.
- **Agent startup.** Recovery adoption and the startup schema still run before
  any normal registration/default refresh/apply (the fail-closed ordering
  above). A transient database failure keeps them pending; fail-closed recovery
  outcomes keep normal DB mutation blocked. Neither exits the agent: it retries
  with bounded exponential backoff and jitter
  (`PROXY_CONTROL_PLANE_RETRY_BACKOFF_*`, 2-30 s), while the heartbeat runs only
  local Squid/ICAP self-healing and writes nothing to the control plane.
- **Management API.** Until the agent has completed this startup for its current
  process lifetime, `/api/manage/sync`, `/api/manage/config/rollback` and
  `/api/manage/cache/clear` answer `503` with `status=control_plane_starting`,
  `retryable=true` and `Retry-After: 5` instead of writing to the control plane
  (readiness marker `PROXY_CONTROL_PLANE_READY_FILE`, default
  `/run/squid-flask-proxy/control-plane-ready`, removed at every container and
  agent start). Read-only management endpoints keep answering.
- **Mid-run.** Each process keeps a MySQL reachability circuit
  (`services.db`): after a connectivity failure (or a connect, pooled ping or
  statement that hangs for the whole connect/read timeout) further connects
  fail immediately with a
  `connectivity` error instead of each paying `MYSQL_CONNECT_RETRIES x
  MYSQL_CONNECT_TIMEOUT`, and one background probe retries with backoff
  (`MYSQL_CONNECT_CIRCUIT_BACKOFF_INITIAL_SECONDS`/`_MAX_SECONDS`, 1-10 s).
  Telemetry writers keep their bounded pending buffers and back off.
  Named-lock waits (`GET_LOCK`) are issued in slices shorter than the session
  read timeout, so lock contention reports a lock timeout and never looks like
  a hung server; a statement that legitimately runs longer than
  `MYSQL_READ_TIMEOUT` on a default session is reported as a timeout and also
  opens the circuit until the next successful probe (about 1 s), so long
  maintenance work uses sessions with their own longer read timeouts.
- **Restoration.** The first successful probe closes the circuit and wakes the
  agent: pending startup steps (recovery, schema, registration, bootstrap,
  initial capture) finish, the sync loop re-registers and claims pending
  operations, the heartbeat reports immediately, and telemetry writers flush on
  their next tick instead of waiting out their backoff.

A Squid lifecycle mutation that fails mid-transaction leaves the Squid
transaction journal `recovery_required`, which blocks later Squid mutations.
Startup reconciles such a journal from the persisted last-known-good config;
while the container keeps running, the heartbeat self-heal runs the same
designated last-known-good rollback (with 5 min to 1 h backoff after failures).
