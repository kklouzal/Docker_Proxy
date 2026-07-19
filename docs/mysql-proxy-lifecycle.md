# MySQL proxy lifecycle write-guard inventory

This project treats `proxy_instances.proxy_id` as the registry owner for proxy-scoped application data.  The lifecycle tables (`proxy_lifecycle_tombstones`, `proxy_id_aliases`) are the source of truth while a proxy is being renamed/removed or after an identity has retired.

## Direct proxy_id write inventory and guard lane

Writers that can insert/update/upsert rows under `proxy_id` and must not bypass lifecycle state:

| Area | Tables | Writer entry points | Risk before guard | Current contract |
| --- | --- | --- | --- | --- |
| Registry | `proxy_instances`, `proxy_id_aliases`, `proxy_lifecycle_tombstones` | `ProxyRegistry.ensure_proxy`, `heartbeat`, `mark_apply_result`, `rename_proxy`, `remove_proxy` | stale heartbeats could recreate a retired id unless tombstone checked | registry checks tombstones; lifecycle transitions clear write-guard cache; heartbeat remains stale-id rejecting rather than alias-following |
| Config revisions/apply evidence | `proxy_config_revisions`, `proxy_config_applications` | `ConfigRevisionStore.create_revision`, `ensure_active_revision`, `activate_revision`, `deactivate_revision`, `record_apply_result` | admin/config writers could recreate rows for removed IDs or keep using an obsolete alias | guarded writes hold the per-proxy lifecycle lock, resolve completed aliases to the canonical active id, and reject removing/removed/renaming IDs |
| Operation ledger | `proxy_operations` | `OperationLedger.create_operation` | queued operations could target a removed or old alias id and recreate pending work after cleanup | guarded creation canonicalizes completed aliases and rejects tombstoned/in-progress identities |
| Certificate/adblock apply evidence | `proxy_certificate_applications`, `proxy_adblock_artifact_applications` | `record_apply_result` in certificate/adblock stores | runtime apply evidence could repopulate a removed/renaming proxy scope | guarded writes reject lifecycle-blocked identities and canonicalize completed aliases |
| Observability/time-series/log counters | `ts_*`, `live_stats_*`, `diagnostic_*`, `ssl_errors`, `adblock_events`, `adblock_counts`, `adblock_cache_stats`, `audit_events`, `observability_report_schedules`, `webfilter_blocked_log` | runtime collectors and admin/report writers | high-volume telemetry can recreate rows after lifecycle cleanup if a stale process keeps writing | audit, adblock counter/cache, diagnostic, live-stats, SSL-error, and timeseries write paths now guard at write/batch boundaries; remaining report/webfilter log writers stay application-managed until the next low-volume service pass |
| Policy/PAC/filter config | `pac_*`, `policy_requests`, `policy_exceptions`, `sslfilter_*`, `webfilter_settings`, `webfilter_whitelist`, `adblock_proxy_meta` | admin config stores and public exception request flow | admin requests can persist under a stale selected proxy id | lifecycle cleanup inventory covers rename/remove; next audit lane should finish guard wrapping on these lower-volume stores |

## Shared write-guard semantics

`services.proxy_write_guard` provides the lightweight service-boundary contract:

1. Normalize the requested id with `normalize_proxy_id`.
2. Read tombstones first and fail closed if tombstone metadata is unavailable.
3. Reject `renaming`, `removing`, and `removed` states.
4. Resolve `renamed` tombstones and `proxy_id_aliases` deterministically, bounded to four hops, when `allow_alias=True`.
5. Require an active registry row by default; missing `proxy_instances` or missing target row blocks writes instead of creating orphan scoped rows.
6. Acquire the same per-proxy lifecycle advisory lock used by rename/remove, then re-check lifecycle state immediately before yielding to the writer.
7. Positive cache is opt-in and bounded by `MYSQL_PROXY_WRITE_GUARD_CACHE_SECONDS`; lifecycle transitions invalidate process-local cache entries.

## FK feasibility

No broad proxy-id foreign keys were added in this lane.  The table-by-table decision is intentionally conservative:

| Tables | FK decision | Reason |
| --- | --- | --- |
| `proxy_config_revisions`, `proxy_config_applications`, `proxy_operations`, certificate/adblock application evidence | Application-managed for now | Existing deployments may already contain legacy/orphan rows; rename/remove uses bounded chunked rewrites/deletes and needs resumable partial completion rather than blocking DDL. |
| `ts_*`, `live_stats_*`, `diagnostic_*`, `ssl_errors`, `adblock_events/counts/cache_stats`, `audit_events`, `webfilter_blocked_log` | No FK | High-write-volume telemetry/log tables should not pay FK cost or introduce lock coupling to the registry hot row. Lifecycle cleanup and guarded writers are safer. |
| `pac_profiles` and children | No new FK in this lane | Children are owned indirectly through `pac_profiles.id`; removal already deletes child rows before parent rows. Adding parent/registry FKs would require legacy cleanup and DDL compatibility testing. |
| `proxy_id_aliases` | Deferred | A target FK with `ON DELETE CASCADE` is feasible only after proving no stale aliases in older DBs; current removal deletes aliases explicitly and tombstones preserve retired identity semantics. |
| `policy_requests`, `policy_exceptions`, `sslfilter_*`, `webfilter_settings`, `webfilter_whitelist`, `adblock_proxy_meta` | Deferred/application-managed | Lower volume but potentially legacy-scoped; add FKs only after a migration proves zero orphan rows and desired delete behavior per table. |

A future migration can add narrowly scoped FKs after an online preflight verifies no orphans and after each table has an explicit `ON UPDATE`/`ON DELETE` policy.  This lane avoids stored procedures/functions/views and keeps old deployments restart-safe.
