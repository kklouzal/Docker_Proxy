# REFACTOR Plan: MySQL Control Plane and Admin/Proxy Split

Date: 2026-04-18  
Status: Planned

## North star

This project will evolve from a **single-container monolith**:

- Squid
- Dante
- c-icap
- PAC/WPAD HTTP listener
- Flask admin UI
- SQLite-backed stores

into a **centralized control-plane architecture**:

- **Proxy container(s)**: Squid data plane + local reconciliation agent + PAC/WPAD + health + local log/telemetry ingestion
- **Admin container**: Flask admin UI/API + policy/config authoring + telemetry views + background control-plane jobs
- **MySQL 8**: source of truth for auth, audit, desired config, node state, telemetry, and certificate metadata

The result should support **multiple Squid proxy containers** that share the same settings and telemetry backend, while still allowing **explicit per-proxy overrides** when needed.

---

## What this plan is optimizing for

1. **Stage 1 stays low-risk**: replace SQLite with MySQL **without splitting containers yet**.
2. **The proxy stays autonomous**: the admin container does **not** shell into or restart remote proxies.
3. **MySQL becomes the control-plane backbone**: settings are written once, proxies reconcile from DB, telemetry flows back into DB.
4. **Uniform by default, overridable by choice**: global defaults first, targeted overrides only where explicitly configured.
5. **The proxy container becomes leaner over time**: admin UI moves out; only true proxy-runtime concerns remain.

---

## Chosen design decisions

These are the key decisions this refactor will follow.

### 1. MySQL becomes the source of truth

Local files remain a **materialized runtime cache**, not the canonical source of configuration.

That means:

- policy/config settings live in MySQL
- desired runtime state lives in MySQL
- telemetry and audit data live in MySQL
- certificates are centrally managed, then materialized locally where Squid needs them

### 2. Stage 1 does **not** split the containers

Stage 1 is intentionally scoped to:

- replace SQLite with MySQL
- keep the current one-container behavior intact
- keep the current web routes/UI intact
- keep local Squid/Dante/c-icap process control intact

This gives us one big architectural win at a time.

### 3. The future split is **DB-driven**, not RPC-driven

The admin container will **not** directly issue `squid -k` commands to proxy containers.

Instead:

- admin writes desired state to MySQL
- each proxy reads its own desired state from MySQL
- each proxy validates/applies locally
- each proxy reports heartbeat/apply status/telemetry back to MySQL

This is the correct model for multiple proxy nodes.

### 4. PAC/WPAD stays with the proxy runtime

The **admin UI** moves out.

The **PAC/WPAD serving path does not**.

Reason:

- PAC/WPAD is part of the proxy data plane, not the admin UI
- clients usually need PAC content from the same proxy endpoint they use for traffic
- PAC generation can still be driven by MySQL-backed policy, but the serving endpoint should stay local to the proxy container

### 5. Override precedence will be explicit and simple

Override resolution order will be:

1. **Global defaults**
2. **Proxy group/profile overrides**
3. **Proxy node overrides**

Only fields explicitly overridden at a narrower scope replace inherited values.

### 6. Admin computes the **effective desired-state snapshot** per proxy node

The proxy should not have to understand the entire layering model.

Instead:

- admin owns the authoring model
- admin resolves global + group + node overrides into a **fully materialized desired snapshot** per proxy node
- each proxy simply consumes its own resolved snapshot

This keeps the proxy agent small and deterministic.

### 7. MySQL will store the **current curated telemetry**, not an infinite raw log lake

The project today already favors **aggregated/curated telemetry** over a full raw access-log archive.

That same philosophy should continue.

For this refactor:

- keep the current analytics surfaces and bounded event logs in MySQL
- key telemetry by `proxy_node_id`
- use batching and retention controls
- do **not** try to turn MySQL into an unlimited raw Squid log warehouse

If full raw traffic archival is ever needed later, that should go to a dedicated log pipeline, not MySQL.

### 8. Certificates are centrally managed, locally materialized

Squid still needs local files on disk.

So the long-term certificate model is:

- admin stores certificate metadata centrally
- active bundle version/assignment lives in MySQL
- proxy pulls the active bundle for its node/scope
- proxy writes local files under `/etc/squid/ssl/certs`
- proxy keeps a last-known-good local copy for rollback

---

## Current-state summary

Today the system is a single image/container that bundles:

- Squid (`docker/supervisord.conf`)
- Dante (`docker/supervisord.conf`)
- c-icap instances (`docker/entrypoint.sh`)
- PAC/WPAD HTTP server (`web/tools/pac_http_server.py`)
- Flask admin UI (`web/app.py`)
- many SQLite-backed stores under `/var/lib/squid-flask-proxy`

### Current SQLite-backed domains

Current stores include:

- `auth.db`
- `audit.db`
- `exclusions.db`
- `live_stats.db`
- `timeseries.db`
- `ssl_errors.db`
- `socks.db`
- `adblock.db`
- `webfilter.db`
- `sslfilter.db`
- `pac_profiles.db`

### Current proxy-runtime-only assumptions

A lot of today’s code assumes it runs in the same container as Squid:

- direct `squid -k parse`
- direct `squid -k reconfigure`
- direct `squid -z`
- direct `supervisorctl`
- direct writes into `/etc/squid/conf.d`
- direct access to `/var/log/squid/*`
- direct access to `/etc/squid/ssl/certs`
- direct access to `/var/lib/ssl_db`

Those assumptions are why the split must happen **after** MySQL migration and after the code is re-layered.

---

## Target architecture

## Application containers and DB service

The end state is effectively **two application containers plus a MySQL service**:

- `proxy`
- `admin`
- `mysql`

## Responsibilities after the split

### Proxy container

Owns only proxy-runtime concerns:

- Squid
- Dante
- c-icap
- PAC/WPAD server
- health endpoint(s)
- local reconciliation agent
- local config materialization
- local certificate materialization
- local log tailing / telemetry shipping
- heartbeat + apply-status reporting

### Admin container

Owns only control-plane concerns:

- Flask admin UI
- login/auth/session handling
- policy/config authoring
- audit views
- telemetry dashboards and exports
- desired-state computation
- group/node override management
- background jobs that do not require local proxy FS/process access
- certificate upload/assignment workflows

### MySQL

Owns centralized state:

- users/auth metadata
- audit trail
- authored policy/config state
- resolved desired-state snapshots per proxy node
- proxy node registry / heartbeat / apply status
- telemetry and bounded event logs
- certificate metadata and bundle references

---

## Configuration model for multiple proxies

This is the model the refactor should implement.

### Proxy identity

Each proxy node must have a stable identity:

- `proxy_node_id` (required)
- `proxy_group_id` (optional but strongly recommended)
- display name / label
- environment / site / tags (optional)

### Authoring scopes

Configuration will be authored at three scopes:

- **Global**: the default shared policy for all proxies
- **Group**: a shared policy for a subset of proxies
- **Node**: sparse overrides for one proxy only

### Effective-state computation

Admin resolves the scopes into a **single effective desired-state snapshot** per proxy node.

The desired-state snapshot should include, at minimum:

- Squid tunables
- exclusions
- SSL-filter no-bump rules
- PAC/WPAD settings and profiles relevant to that node
- ICAP/adblock settings
- webfilter settings and selected categories
- Dante settings
- certificate bundle references
- operational toggles and version metadata

### Versioning

Each resolved desired-state snapshot gets:

- monotonically increasing version
- checksum/hash
- created timestamp
- source metadata (global/group/node inputs)

Each proxy reports back:

- applied version
- applied checksum
- apply result
- last apply time
- last error
- heartbeat time

This gives us deterministic rollouts and safe rollbacks.

---

## Certificate and secret model

### What gets centralized

Centralized certificate management should cover:

- active Squid bump CA bundle metadata
- uploaded PFX metadata
- assignment of bundle to global/group/node scope
- rotation history / versioning

### What remains local on the proxy

The proxy still needs local copies of:

- `ca.crt`
- `ca.key`
- any active uploaded PFX if used
- Squid ssl_crtd DB under `/var/lib/ssl_db`

### Recommended handling

- store metadata and active-version references in MySQL
- keep certificate payloads encrypted at rest
- materialize local files only inside the proxy container
- validate locally before activating
- keep last-known-good files for rollback

---

## Telemetry model

All telemetry tables should become **multi-node aware**.

That means every telemetry/event row should include `proxy_node_id`.

### Telemetry categories to keep in MySQL

- live domain/client aggregates
- timeseries samples/rollups
- SSL error aggregates
- SOCKS events
- adblock block events
- webfilter blocked events
- audit events

### Operational rules

- writes should be batched where practical
- retention windows should be explicit
- indexes should be built around `proxy_node_id`, timestamp, and primary filter keys
- dashboards should be able to filter by node, group, or global view

### Explicit non-goal

Do **not** try to store an unbounded full-fidelity raw access-log archive in MySQL as part of this refactor.

---

## Artifact model for adblock/webfilter

This deserves explicit treatment.

### Short-term

During Stage 1, keep behavior close to today:

- MySQL stores settings, metadata, and state
- the one-container app can still download/compile locally as it does now

### Long-term

After the split:

- admin owns scheduled download/compile orchestration
- MySQL stores desired version/checksum metadata
- proxies consume the version they are assigned

### Important constraint

Large compiled artifacts should **not** become arbitrary forever-blobs in MySQL unless absolutely necessary.

Recommended long-term model:

- MySQL stores metadata, versions, checksums, and assignments
- compiled artifacts are published as versioned bundles
- proxies download/apply the referenced bundle

If needed, there can be a temporary transition period where artifacts still compile locally on the proxy, but the target architecture should centralize the orchestration and versioning.

---

## Target codebase layering

The refactor should move the repo toward three layers.

### 1. `shared/` or equivalent

Reusable code with no container-specific assumptions:

- data models
- DB access layer
- repositories
- schema migrations
- validation helpers
- effective-config compiler
- policy merge logic

### 2. `admin/` or equivalent

Admin-container-only concerns:

- Flask routes
- templates/static assets
- auth/session UI
- telemetry pages
- admin workflows
- desired-state authoring/materialization

### 3. `proxy_runtime/` or equivalent

Proxy-container-only concerns:

- reconciliation agent
- Squid/Dante/c-icap apply logic
- local FS materialization
- cert materialization
- telemetry shippers / log tailers
- PAC/WPAD serving
- health endpoints

---

## Stage plan

## Stage 1 — Replace SQLite with MySQL, keep one container

### Objective

Move all current SQLite-backed state into MySQL while preserving the current runtime shape and current UI behavior.

### Rules for Stage 1

- keep one container
- keep current Flask UI routes/pages
- keep current local Squid control flow
- keep current background worker shape
- no admin/proxy split yet
- no feature redesign yet

### Stage 1 deliverables

#### 1. Add a real DB foundation

Introduce a shared DB layer based on:

- **MySQL 8**
- **SQLAlchemy 2.x**
- **Alembic** for schema migrations

Recommended env surface:

- `DATABASE_URL`
- or equivalent explicit MySQL env vars if needed for ops clarity
- pool size / timeout settings
- optional SSL settings for MySQL connectivity

#### 2. Add MySQL to local/dev deployment

Update local deployment to support:

- app container
- MySQL container

The one-container app should boot against MySQL locally before any split work starts.

#### 3. Keep store/public APIs stable

Current `get_*_store()` usage and high-level service contracts should remain stable during Stage 1.

Implementation should change underneath them, not across the whole Flask app at once.

#### 4. Migrate domains in this order

Recommended order:

##### Phase 1A — low-risk domains

- auth
- audit
- exclusions
- PAC profiles
- SSL-filter rules

##### Phase 1B — moderate domains

- SSL errors
- SOCKS events
- timeseries

##### Phase 1C — high-write / complex domains

- live stats
- adblock
- webfilter

This order reduces blast radius while the DB layer hardens.

#### 5. Add future-proof multi-node fields now

Even though Stage 1 stays single-container, the schema should already include future split fields where they belong:

- `proxy_node_id`
- optional `proxy_group_id`
- desired/applied version metadata where relevant

For Stage 1, the runtime can default to a single node identity such as:

- `proxy-1`
- or another explicit env-driven default

#### 6. Make MySQL the source of truth for desired/applied config metadata

Even in Stage 1, config state should begin moving toward DB ownership.

That means introducing tables for:

- desired config snapshot metadata
- applied config metadata
- version/checksum tracking

The app can still materialize `/etc/squid/squid.conf` locally and apply directly, but MySQL should start holding the authoritative record.

#### 7. Keep the current background-worker lock model in Stage 1

Do **not** redesign scheduler ownership yet.

Keep the current file-based single-writer guard for the one-container runtime to minimize risk.

This can be replaced later when the split is implemented.

#### 8. Build a one-time SQLite → MySQL migration tool

Add a migration/import tool that:

- reads existing SQLite DB files
- imports into MySQL domain by domain
- validates row counts and key invariants
- supports dry-run mode
- emits a human-readable migration report

#### 9. Update tests to run on MySQL

Before Stage 1 is considered done:

- the current test suite must run against MySQL-backed services
- new migration/import tests must exist
- existing route/service behavior must remain intact

### Stage 1 acceptance criteria

Stage 1 is complete only when all of the following are true:

- no runtime store still depends on SQLite for primary persistence
- current UI behavior is unchanged
- current Squid apply flow still works
- telemetry still flows correctly
- one-container deployment is healthy against MySQL
- tests pass against MySQL
- SQLite remains only as a migration source / backup artifact, not as the active datastore

### Stage 1 explicit non-goals

- no container split
- no removal of Flask from the proxy image yet
- no proxy agent yet
- no full rollout/orchestration UI yet

---

## Stage 2 — Split the codebase by responsibility and introduce the proxy agent

### Objective

Turn the monolith into two application runtimes:

- admin runtime
- proxy runtime

while keeping one repo and shared domain code.

### Main changes

#### 1. Introduce a `proxy_agent`

The proxy agent becomes the local control-plane worker inside the proxy container.

It is responsible for:

- node registration and heartbeat
- fetching its desired-state snapshot from MySQL
- fetching current cert/artifact assignments
- materializing local runtime files
- validating/applying Squid/Dante/c-icap config locally
- writing apply status back to MySQL
- shipping telemetry to MySQL

#### 2. Move all admin UI code out of the proxy runtime

Everything under the current web admin panel path should move to the admin container, including:

- Flask templates
- static assets
- login UI
- policy/config pages
- telemetry pages
- admin-only routes

#### 3. Keep proxy-runtime HTTP surface minimal

After the split, the proxy container should retain only minimal HTTP/runtime endpoints as needed:

- PAC/WPAD serving
- health/status endpoint(s)
- anything strictly required by the proxy data plane

#### 4. Stop using admin-side direct process control

Admin must stop assuming it can do any of the following locally:

- `squid -k parse`
- `squid -k reconfigure`
- `supervisorctl`
- local writes to `/etc/squid/conf.d`
- local writes to `/etc/squid/ssl/certs`

Those actions become proxy-agent responsibilities.

### Stage 2 acceptance criteria

- proxy container can boot and reconcile from MySQL without the Flask admin UI present
- admin container can edit desired state without direct shell access to proxies
- proxy applies desired state locally and reports status/version back
- PAC/WPAD still works from the proxy endpoint
- telemetry still appears centrally in admin views

---

## Stage 3 — Multi-proxy support and override management

### Objective

Support N proxy nodes against one admin container and one MySQL backend.

### Deliverables

#### 1. Proxy node registry

Admin must be able to see:

- all registered proxy nodes
- last heartbeat
- current version/applied version
- last apply error
- group membership
- health/status summary

#### 2. Group-level configuration

Add first-class support for:

- proxy groups / profiles
- assigning nodes to groups
- group-scoped shared settings

#### 3. Node-specific sparse overrides

Allow a node to override only selected settings, while inheriting everything else.

This is the mechanism that satisfies the “uniform by default, explicit override when necessary” requirement.

#### 4. Rollout and rollback visibility

At minimum, admin should be able to see:

- desired version
- applied version
- nodes pending apply
- nodes failed apply
- last successful version

### Stage 3 acceptance criteria

- multiple proxies can run against the same MySQL backend
- global defaults apply uniformly by default
- group and node overrides work predictably
- telemetry can be filtered by node/group/global scope
- certificate assignment can be scoped globally/group/node as needed

---

## Recommended MySQL schema domains

The schema should be organized by domain, not by “one table per old SQLite file”.

### 1. Auth and admin

- users
- roles/permissions (if needed later)
- admin/session secret metadata if retained
- audit events

### 2. Proxy inventory and runtime state

- proxy nodes
- proxy groups
- node tags/metadata
- node heartbeat/status
- desired-state snapshots
- applied-state status/results

### 3. Policy and authored configuration

- exclusions
- PAC profiles
- SSL-filter CIDRs
- webfilter settings
- adblock settings and list metadata
- certificate bundle assignments
- any authored Squid tunables/settings domain

### 4. Telemetry and bounded events

- live domain/client aggregates
- timeseries metrics
- SSL errors
- SOCKS events
- adblock events
- webfilter blocked events

Every telemetry/event domain that originates from a proxy must include `proxy_node_id`.

---

## Risks and mitigations

### Risk: MySQL becomes a bottleneck for telemetry writes

Mitigation:

- batch writes from proxy runtime
- add retention windows
- index on node/time/query dimensions
- keep telemetry curated rather than unbounded raw logs

### Risk: Config drift between DB and local materialized files

Mitigation:

- version every desired-state snapshot
- record applied checksum/version
- treat local files as cache only
- proxy reports back actual applied state

### Risk: Certificate rollout breaks a proxy

Mitigation:

- materialize to temp path
- validate before activation
- keep last-known-good local bundle
- rollback on failed apply

### Risk: Stage 1 becomes too large

Mitigation:

- keep route/UI contracts stable
- migrate domains in phases
- do not split containers in Stage 1
- do not redesign scheduling/ownership in Stage 1

### Risk: Split happens before MySQL is stable

Mitigation:

- do not begin Stage 2 until Stage 1 passes all acceptance criteria

---

## Deployment end state

The target deployment model is:

- one **admin** container
- one or more **proxy** containers
- one **MySQL** service/cluster
- optional external services as already needed (for example remote ClamAV)

The admin container is the human-facing control plane.  
The proxy containers are the runtime workers.  
MySQL is the coordination backbone.

---

## Immediate next implementation target

### Stage 1 first

The next implementation work should be:

1. introduce MySQL into local deployment
2. add the shared DB layer and migrations
3. migrate the current SQLite-backed stores to MySQL
4. keep one container and current UX/runtime behavior intact
5. add future-ready node/version fields where appropriate

Only after that is stable should the repo move into the true admin/proxy split.

---

## Done criteria for this planning phase

This plan is considered locked enough to implement if we follow these boundaries:

- **Stage 1 = MySQL migration only, no container split**
- **Stage 2 = admin/proxy split using DB-driven reconciliation**
- **Stage 3 = multi-proxy rollout + override model hardening**

That is the recommended path for this codebase.
