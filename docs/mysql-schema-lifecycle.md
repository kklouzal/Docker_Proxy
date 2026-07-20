# MySQL schema lifecycle hardening

Docker_Proxy owns MySQL DDL through the startup schema lifecycle table pair, `schema_migrations` and `schema_migration_events`, guarded by the advisory lock `docker_proxy:schema_lifecycle:migrate`.  Runtime stores remain idempotent for old deployments, but normal reads/writes must not repeatedly issue `CREATE TABLE`, `ALTER TABLE`, or `information_schema` probes once startup migration version 15 is applied.

## Version ownership

| Version | Migration | Families/tables owned |
| --- | --- | --- |
| 1 | `bootstrap_mysql_schema_lifecycle` | Admin/control-plane bootstrap: `users`, `proxy_instances`, `proxy_id_aliases`, `proxy_config_revisions`, `proxy_config_applications`, `certificate_bundle_revisions`, `proxy_certificate_applications`, `admin_ui_https_settings`, `adblock_artifact_revisions`, `proxy_adblock_artifact_applications`, `proxy_operations`, `audit_events`. Repairs duplicate active revision rows before generated active-slot unique indexes. |
| 2 | `adblock_runtime_tables` | `adblock_lists`, `adblock_meta`, `adblock_cache_stats`, `adblock_settings`, `adblock_counts`, `adblock_events`, `adblock_proxy_meta`; default subscription/settings seeds and block-log/cache indexes. |
| 3 | `webfilter_and_safe_browsing_tables` | `webfilter_settings`, `webfilter_meta`, `webfilter_whitelist`, `webfilter_blocked_log`, `safe_browsing_hash_lists`, `safe_browsing_hash_prefixes`, `safe_browsing_full_hash_cache`, `safe_browsing_negative_cache`; Safe Browsing generation/expiry indexes and legacy webfilter default-category demotion. |
| 4 | `sslfilter_policy_tables` | `sslfilter_domains`, `sslfilter_src_nets`, `sslfilter_settings`. |
| 5 | `diagnostic_request_and_icap_tables` | `diagnostic_requests`, `diagnostic_policy_tags`, `diagnostic_icap_events`; response metadata columns and query/reporting indexes. |
| 6 | `ssl_error_aggregate_tables` | `ssl_errors` aggregate table and proxy/domain/category indexes. |
| 7 | `live_stats_aggregate_tables` | `live_stats_domains`, `live_stats_clients`, `live_stats_client_domains`, `live_stats_client_domain_nocache`; last-seen/proxy aggregate indexes. |
| 8 | `timeseries_resolution_tables` | `ts_1s`, `ts_1m`, `ts_1h`, `ts_1d`, `ts_1w`, `ts_1mo`, `ts_1y`. |
| 9 | `observability_control_tables` | `observability_settings`, `observability_maintenance_runs`, `observability_report_schedules`. |
| 10 | `policy_request_tables` | `policy_requests`, `policy_exceptions`. |
| 11 | `pac_profile_tables` | `pac_profiles`, `pac_direct_domains`, `pac_direct_dst_nets`, `pac_backup_proxies`, `pac_proxy_chain_settings`. |
| 12 | `proxy_lifecycle_indexes` | `proxy_lifecycle_tombstones` plus lifecycle leftmost-key coverage for every known proxy-scoped table and PAC child table. |
| 13 | `control_plane_retention_indexes` | Bounded housekeeping indexes for revision/application/operation/policy/observability retention paths. |
| 14 | `schema_lifecycle_complete_runtime_assertions` | Cutover marker used by lazy stores to replace runtime DDL with a one-time process assertion that startup migrations are current. |
| 15 | `auth_provider_profile_tables` | `directory_auth_profiles` and `saml_auth_profiles`, including default disabled provider rows and SAML compatibility columns, so authentication-provider setup is covered by the startup lifecycle instead of runtime page/login paths. |

## Lifecycle model

- Startup applies versions in order and records each version checksum/status/events. Already-applied matching versions are no-ops; checksum drift on an applied version blocks startup.
- MySQL DDL is non-transactional, so every version records a `running` checkpoint before DDL and uses idempotent table/index/column repairs. A failed or interrupted version is marked `failed` and can be retried safely.
- DDL privilege checks run at startup. Set `MYSQL_CREATE_DATABASE=0` for externally managed databases; migrations still require a DDL-capable account unless a privileged migration job ran first.
- After version 15, lazy store constructors and control-plane stores use cheap process guards/current-schema assertions instead of repeated hot-path `CREATE TABLE`, `ALTER TABLE`, or `information_schema` repair loops.

## Rollback/compatibility notes

The lifecycle remains additive except deterministic duplicate-active demotion before unique active-slot indexes. To roll back application code, keep `schema_migrations` and `schema_migration_events` for observability and avoid dropping generated columns/indexes unless the target old code is proven compatible. DML-only runtime accounts are supported only after all required migrations are applied.

## Remaining audit lane

Dynamic/offline build artifacts such as local SQLite adblock indexes and transient `webcat_%` build tables are intentionally outside persistent MySQL lifecycle ownership; stale webcat build cleanup remains a bounded housekeeping concern.
