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
| Observability/time-series/log counters | `ts_*`, `live_stats_*`, `diagnostic_*`, `ssl_errors`, `adblock_events`, `adblock_counts`, `adblock_cache_stats`, `audit_events`, `observability_report_schedules`, `webfilter_blocked_log` | runtime collectors and admin/report writers | high-volume telemetry can recreate rows after lifecycle cleanup if a stale process keeps writing | audit, adblock event/counter/cache, diagnostic, live-stats, SSL-error, timeseries, webfilter blocked-log, and report-schedule write paths now guard at write/batch boundaries and use canonical proxy ids |
| Policy/PAC/filter config | `pac_*`, `policy_requests`, `policy_exceptions`, `sslfilter_*`, `webfilter_settings`, `webfilter_whitelist`, `adblock_proxy_meta` | admin config stores and public exception request flow | admin requests can persist under a stale selected proxy id | PAC/profile writes and backup-proxy mutations, policy request creation/approval, scoped policy close/revoke mutations, sslfilter/webfilter writes, and adblock proxy metadata writes use lifecycle-guarded canonical proxy ids; unscoped policy admin mutations remain intentionally unscoped |

## Shared write-guard semantics

`services.proxy_write_guard` provides the lightweight service-boundary contract:

1. Normalize the requested id with `normalize_proxy_id`.
2. Read tombstones first and fail closed if tombstone metadata is unavailable.
3. Reject `renaming`, `removing`, and `removed` states.
4. Resolve `renamed` tombstones and `proxy_id_aliases` deterministically, bounded to four hops, when `allow_alias=True`.
5. Require an active registry row by default; missing `proxy_instances` or missing target row blocks writes instead of creating orphan scoped rows.
6. Acquire the same per-proxy lifecycle advisory lock used by rename/remove, then re-check lifecycle state immediately before yielding to the writer.
7. Positive cache is opt-in and bounded by `MYSQL_PROXY_WRITE_GUARD_CACHE_SECONDS`; lifecycle transitions invalidate process-local cache entries.

Removal publishes and commits the `removing` tombstone plus registry status before
the first scoped-row delete. Each request then commits at most
`MYSQL_PROXY_LIFECYCLE_MAX_ROWS_PER_TABLE` rows per visited table in bounded
chunks. If a table reaches that bound with scoped rows still remaining, the
registry remains `remove_pending`, the Admin UI reports the retained progress,
and repeating the removal resumes
idempotently. A fleet-wide removal lock prevents a second proxy removal from
invalidating the last-proxy guard while one of these durable passes is pending.
Aliases and the registry row are deleted only after a pass proves that all
scoped tables are empty; the final tombstone remains `removed`.

## FK feasibility

No broad proxy-id foreign keys were added in this lane.  The table-by-table decision is intentionally conservative:

| Tables | FK decision | Reason |
| --- | --- | --- |
| `proxy_config_revisions`, `proxy_config_applications`, `proxy_operations`, certificate/adblock application evidence | Application-managed for now | Existing deployments may already contain legacy/orphan rows; rename/remove uses bounded chunked rewrites/deletes and needs resumable partial completion rather than blocking DDL. |
| `ts_*`, `live_stats_*`, `diagnostic_*`, `ssl_errors`, `adblock_events/counts/cache_stats`, `audit_events`, `webfilter_blocked_log`, `observability_report_schedules` | No FK | Telemetry/log tables should not pay FK cost or introduce lock coupling to the registry hot row; report schedules share the lifecycle cleanup/restore path and remain application-managed. Lifecycle cleanup and guarded writers are safer. |
| `pac_profiles` and children | No new FK in this lane | Children are owned indirectly through `pac_profiles.id`; removal already deletes child rows before parent rows. Adding parent/registry FKs would require legacy cleanup and DDL compatibility testing. |
| `proxy_id_aliases` | Deferred | A target FK with `ON DELETE CASCADE` is feasible only after proving no stale aliases in older DBs; current removal deletes aliases explicitly and tombstones preserve retired identity semantics. |
| `policy_requests`, `policy_exceptions`, `sslfilter_*`, `webfilter_settings`, `webfilter_whitelist`, `adblock_proxy_meta` | Deferred/application-managed | Lower volume but potentially legacy-scoped; add FKs only after a migration proves zero orphan rows and desired delete behavior per table. |

## Observability report schedule lifecycle notes

`observability_report_schedules` currently has one application writer: `ObservabilityQueries.save_report_schedule`, reached from `POST /observability/report-schedules`. Reads are storage-only: `report_schedules` scopes by the currently selected proxy and feeds the reports pane plus export-contract status; no scheduler, email sender, delivery worker, or next-run consumer executes these rows yet. Saved rows are therefore report presets/configuration records, not an active job queue. The presentation query deliberately excludes legacy runtime columns and reports a static `manual_export_only` delivery contract so stale scheduler-looking values cannot imply that automatic delivery is active.

The writer normalizes cadence/format/pane/window/enabled/privacy, validates and deduplicates recipients before persistence, resolves stale aliases through `guarded_proxy_write`, writes the canonical proxy id, re-reads the inserted row under that canonical scope before returning the saved row to the route. Route audit detail records only recipient counts, format, pane, and privacy mode. Invalid recipient errors are generic so addresses are not echoed into redirects or audit events.

Lifecycle coupling stays application-managed rather than FK-managed. Rename/remove includes the table in `proxy_lifecycle`, recovery export/restore includes only declarative schedule fields and resets runtime fields (`next_run_ts=0`, `last_run_ts=0`, `last_status='recovered'`), and state validation now checks no orphan owners, valid cadence/format values, and sane timestamps.

A future migration can add narrowly scoped FKs after an online preflight verifies no orphans and after each table has an explicit `ON UPDATE`/`ON DELETE` policy.  This lane avoids stored procedures/functions/views and keeps old deployments restart-safe.
