# MySQL schema lifecycle hardening

This application now has a startup schema lifecycle table pair, `schema_migrations` and `schema_migration_events`, guarded by the MySQL advisory lock `docker_proxy:schema_lifecycle:migrate`.  The first versioned migration (`1/bootstrap_mysql_schema_lifecycle`) installs and repairs the high-risk control-plane tables before normal request/runtime paths need to touch DDL.

## Inventory and risk grouping

High-risk generated/unique repair paths:

- `proxy_config_revisions`: generated `active_proxy_id`, unique active-per-proxy index, duplicate active repair.
- `certificate_bundle_revisions`: generated `active_global_slot`, unique active bundle index, duplicate active repair.
- `adblock_artifact_revisions`: generated `active_global_slot`, unique active artifact index, duplicate active repair.

Startup/control-plane identity and lifecycle DDL:

- `proxy_instances`, `proxy_id_aliases`, `proxy_lifecycle_tombstones` in `proxy_registry.py` / `proxy_lifecycle.py`.
- `proxy_operations` and active-request uniqueness in `operation_ledger.py`.
- `users`, `directory_auth_profiles`, `saml_auth_profiles`.

Revision/application history and audit DDL:

- `proxy_config_applications`, `proxy_certificate_applications`, `proxy_adblock_artifact_applications`.
- `audit_events`.
- `admin_ui_https_settings`.

Deferred/lazy compatibility areas still supported by their existing stores during the transition:

- Filter/cache stores: `adblock_*`, `webfilter_*`, `sslfilter_*`, `safe_browsing_*`.
- Observability/tailer tables: `diagnostic_*`, `ssl_errors`, `live_stats_*`, `ts_*`, `observability_*`.
- Policy/PAC tables: `policy_requests`, `policy_exceptions`, `pac_*`.
- Offline/local SQLite/adblock/webcat build artifacts are intentionally outside MySQL lifecycle control.

## Lifecycle model

- Startup acquires `docker_proxy:schema_lifecycle:migrate` and writes `schema_migrations`/`schema_migration_events` before applying DDL.
- Each migration row carries a deterministic checksum.  If a deployed database records a different checksum for an already-applied version, startup stops with checksum drift instead of silently applying incompatible DDL.
- Migration status is recorded as `running`, `applied`, or `failed`; failures include the exception text in `schema_migrations.error` and a matching event row.
- MySQL DDL is non-transactional, so restart safety is achieved by committing the `running` checkpoint before DDL and making every DDL/data-repair step idempotent.  A process interrupted after a DDL statement but before the final checkpoint reruns the same migration safely.
- The generated-column unique constraints are only enforced after legacy duplicate active rows are deterministically demoted by `(created_ts DESC, id DESC)`.
- Startup DDL privilege checks exercise `CREATE`, `ALTER`, `INDEX`, and `DROP`; a failure gives a clear least-privilege message.  After migrations are applied, normal runtime can use the existing lazy stores without requiring DDL privileges.

## Rollback/compatibility

The schema migration is additive plus deterministic duplicate-active demotion.  Roll back application code first if needed; keep the migration history tables for observability.  Do not drop generated columns or unique indexes unless rolling back to a known old code version that cannot tolerate them.  Existing lazy stores remain compatible and idempotent while future migrations can move the remaining deferred table families into explicit versions.
