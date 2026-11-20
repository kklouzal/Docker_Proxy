# MySQL schema lifecycle hardening

Docker_Proxy owns MySQL DDL through the startup schema lifecycle table pair, `schema_migrations` and `schema_migration_events`, guarded by the advisory lock `docker_proxy:schema_lifecycle:migrate`. Runtime stores remain idempotent for old deployments, but normal reads/writes must not repeatedly issue `CREATE TABLE`, `ALTER TABLE`, or `information_schema` probes once the lifecycle-current cutover and current startup migrations are applied. This inventory currently tracks migrations through version 37.

## Version ownership

| Version | Migration | Families/tables owned |
| --- | --- | --- |
| 1 | `bootstrap_mysql_schema_lifecycle` | Admin/control-plane bootstrap: `users`, `proxy_instances`, `proxy_id_aliases`, `proxy_config_revisions`, `proxy_config_applications`, `certificate_bundle_revisions`, `proxy_certificate_applications`, `admin_ui_https_settings`, `adblock_artifact_revisions`, `proxy_adblock_artifact_applications`, `proxy_operations`, `audit_events`. Repairs duplicate active revision rows before generated active-slot unique indexes. |
| 2 | `adblock_runtime_tables` | `adblock_lists`, `adblock_meta`, `adblock_settings`, `adblock_counts`, `adblock_events`, `adblock_proxy_meta`; default subscription/settings seeds and block-log/cache indexes. It historically also created `adblock_cache_stats`, retired by version 36. |
| 3 | `webfilter_and_safe_browsing_tables` | `webfilter_settings`, `webfilter_meta`, `webfilter_whitelist`, `webfilter_blocked_log`, `safe_browsing_hash_lists`, `safe_browsing_hash_prefixes`, `safe_browsing_full_hash_cache`, `safe_browsing_negative_cache`; Safe Browsing generation/expiry indexes and legacy webfilter default-category demotion. |
| 4 | `sslfilter_policy_tables` | `sslfilter_domains`, `sslfilter_src_nets`, `sslfilter_settings`. |
| 5 | `diagnostic_request_and_icap_tables` | `diagnostic_requests`, `diagnostic_policy_tags`, `diagnostic_icap_events`; response metadata columns and query/reporting indexes. |
| 6 | `ssl_error_aggregate_tables` | `ssl_errors` aggregate table and proxy/domain/category indexes. |
| 7 | `live_stats_aggregate_tables` | Historical: created the `live_stats_*` aggregates retired by version 34. Fresh installs create nothing here; the step name is kept so recorded checksums stay valid. |
| 8 | `timeseries_resolution_tables` | `ts_1s`, `ts_1m`, `ts_1h`, `ts_1d`, `ts_1w`, `ts_1mo`, `ts_1y`. |
| 9 | `observability_control_tables` | `observability_settings`, `observability_maintenance_runs`, `observability_report_schedules`. |
| 10 | `policy_request_tables` | `policy_requests`, `policy_exceptions`. |
| 11 | `pac_profile_tables` | `pac_profiles`, `pac_direct_domains`, `pac_direct_dst_nets`, `pac_backup_proxies`, `pac_proxy_chain_settings`. |
| 12 | `proxy_lifecycle_indexes` | `proxy_lifecycle_tombstones` plus lifecycle leftmost-key coverage for every known proxy-scoped table and PAC child table. |
| 13 | `control_plane_retention_indexes` | Bounded housekeeping indexes for revision/application/operation/policy/observability retention paths. |
| 14 | `schema_lifecycle_complete_runtime_assertions` | Cutover marker used by lazy stores to replace runtime DDL with a one-time process assertion that startup migrations are current. |
| 15 | `auth_provider_profile_tables` | `directory_auth_profiles` and `saml_auth_profiles`, including default disabled provider rows and SAML compatibility columns, so authentication-provider setup is covered by the startup lifecycle instead of runtime page/login paths. |
| 16 | `control_plane_identity` | `control_plane_identity` singleton identity table used to distinguish control-plane ownership during proxy recovery. |
| 17 | `proxy_recovery_adoptions` | `proxy_recovery_adoptions` records accepted cross-control-plane recovery adoptions. |
| 18 | `policy_exception_method_scope` | Adds `policy_exceptions.method` and method-aware lookup coverage so webfilter approvals can preserve HTTP method scope while legacy empty-method exceptions remain broad. |
| 19 | `operation_ledger_stale_requeue_lifecycle` | Adds `proxy_operations.stale_requeue_count`, backfills active operation idempotency keys, and declares the operation-ledger progress/active-request indexes so lazy operation-ledger startup can trust the lifecycle-current marker without hot-path DDL probes. |
| 20 | `webfilter_blocked_log_lifecycle_indexes` | Adds `webfilter_blocked_log.proxy_id` and declares `(ts, id)` plus `(proxy_id, ts, id)` blocked-log retention/query indexes so the webfilter UI and ACL writer can stay on the lazy-store hot path once startup migrations are current. |
| 21 | `application_ledger_evidence_indexes` | Adds `proxy_config_applications.config_sha256`, backfills it from matching config revisions, and declares proxy/revision/timestamp lookup coverage so config apply ledgers retain deterministic revision evidence after restore. |
| 22 | `timeseries_metric_count_columns` | Adds the per-metric count columns to `ts_1s`, `ts_1m`, `ts_1h`, `ts_1d`, `ts_1w`, `ts_1mo`, and `ts_1y` so rollup averages can distinguish zero samples from absent samples without runtime DDL repair. |
| 23 | `application_ledger_evidence_completion` | Forward-repairs application ledger evidence ownership without changing historical checksums: ensures config, certificate, and adblock application evidence columns; backfills them from matching revisions; and declares all proxy/revision/timestamp application-ledger indexes before lazy stores can skip runtime DDL. |
| 24 | `live_stats_seed_checkpoint` | Historical: added `live_stats_seed_state`, retired by version 34. |
| 25 | `diagnostic_icap_extended_metadata` | Adds ICAP service, outcome, status, timing, and byte-count metadata columns to `diagnostic_icap_events` for durable extended diagnostic evidence. |
| 26 | `observability_manual_export_preset_contract` | Canonicalizes `observability_report_schedules` as manual-export presets: `cadence='manual'`, empty recipients, zero next/last runtime timestamps, and `last_status='manual_export_only'`. |
| 27 | `operation_ledger_hard_retention_cap` | Physically prunes pre-existing terminal `proxy_operations` history until each proxy has at most 128 rows, except while its protected active `pending`/`applying` rows alone require overflow; lifecycle writes maintain and converge the same bound afterward. |
| 28 | `policy_request_public_admission_index` | Adds the `(proxy_id, status, client_ip, id)` policy-request index used by bounded public admission to count pending requests per client within a proxy without a table scan. |
| 29 | `diagnostic_file_security_policy_attribution` | Adds the bounded `diagnostic_requests.file_security_policy` Squid note used to attribute strict file-policy denials. |
| 30 | `proxy_scoped_adblock_runtime_enablement` | Seeds each registered proxy's adblock routing state from the legacy global switch; subscriptions and compiled artifacts remain shared. |
| 31 | `adblock_event_policy_attribution` | Adds `adblock_events.list_key`, `rule_id`, `decision_action`, and `decision_reason` so durable adblock events retain the matched policy list/rule and decision outcome/reason; all four columns are non-null with empty-string defaults for existing rows. |
| 32 | `admin_default_proxy_selection` | `proxy_default_selection` singleton holding the Admin UI default proxy chosen on the Proxies page; absent row means the `DEFAULT_PROXY_ID` environment bootstrap still applies. The column is `default_proxy_id` (not `proxy_id`) so proxy lifecycle discovery never treats it as proxy-scoped data. |
| 33 | `diagnostic_requests_drop_duplicate_indexes` | Drops `idx_diagnostic_requests_proxy_tx` and `idx_diagnostic_requests_proxy_domain`, each the same physical B-tree (declared columns plus the implicit `id` suffix) as the kept `idx_diagnostic_requests_proxy_tx_ts_id` / `idx_diagnostic_requests_proxy_domain_ts_id`; a duplicate is dropped only while its twin exists, with `ALGORITHM=INPLACE, LOCK=NONE` (metadata-only, online). |
| 34 | `retire_live_stats_aggregate_tables` | Drops `live_stats_domains`, `live_stats_clients`, `live_stats_client_domains`, `live_stats_client_domain_nocache`, and `live_stats_seed_state` (`DROP TABLE IF EXISTS`). They were written by the proxy but read by nothing since the Observability pages moved to `diagnostic_requests`. A not-yet-upgraded proxy keeps running: its live-stats writes fail with a throttled database warning behind the bounded write backoff until it is upgraded. |
| 35 | `drop_redundant_audit_and_diagnostic_indexes` | Online (`ALGORITHM=INPLACE, LOCK=NONE`) drops of `audit_events.idx_audit_ts` (`(ts)` is stored as `(ts, id)`, the same B-tree as the kept `idx_audit_ts_id`) and `diagnostic_requests.idx_diagnostic_requests_proxy_client` (a column prefix of the kept `(proxy_id, client_ip, ts, bytes)` index; the only client-filtered `ts DESC, id DESC` query is pinned to `idx_diagnostic_requests_proxy_ts`). Each drop runs only while its covering index exists; fresh installs no longer create either index. |
| 36 | `retire_adblock_cache_stats` | Drops `adblock_cache_stats` (`DROP TABLE IF EXISTS`; seeded with zero hits/misses/evictions and never read or updated) and deletes the write-only `adblock_proxy_meta` keys `cache_last_flush` / `cache_current_size`. `cache_flush_requested` stays: it drives the adblock cache-flush request. |
| 37 | `saml_assertion_replay_cache` | `saml_assertion_replay` single-use claims of accepted SAML assertions (primary key: SHA-256 of IdP entity ID plus assertion ID) with the `expires_ts` index used by control-plane housekeeping to prune expired claims. It has no `proxy_id` column, so proxy lifecycle discovery never treats it as proxy-scoped. |

## Lifecycle model

- Startup applies versions in order and records each version checksum/status/events. Already-applied matching versions are no-ops; checksum drift on an applied version blocks startup.
- MySQL DDL is non-transactional, so every version records a `running` checkpoint before DDL and uses idempotent table/index/column repairs. A failed or interrupted version is marked `failed` and can be retried safely.
- The migration advisory lock and ledger rows are held on a dedicated non-pooled session, so store `init_db()` hooks inside a migration can use the pool even with `DB_POOL_SIZE=1`. Waiting for a concurrent migrator polls `GET_LOCK` in slices shorter than `MYSQL_READ_TIMEOUT`, bounded overall by `MYSQL_SCHEMA_LOCK_TIMEOUT_SECONDS` (default 60).
- DDL privilege checks run at startup. Set `MYSQL_CREATE_DATABASE=0` for externally managed databases; migrations still require a DDL-capable account unless a privileged migration job ran first.
- After the lifecycle-current cutover and subsequent startup migrations, lazy store constructors and control-plane stores use cheap process guards/current-schema assertions instead of repeated hot-path `CREATE TABLE`, `ALTER TABLE`, or `information_schema` repair loops.

## Rollback/compatibility notes

The lifecycle remains additive except deterministic duplicate-active demotion before unique active-slot indexes. To roll back application code, keep `schema_migrations` and `schema_migration_events` for observability and avoid dropping generated columns/indexes unless the target old code is proven compatible. DML-only runtime accounts are supported only after all required migrations are applied.

## Remaining audit lane

Dynamic/offline build artifacts such as local SQLite adblock indexes and transient `webcat_%` build tables are intentionally outside persistent MySQL lifecycle ownership; stale webcat build cleanup remains a bounded housekeeping concern.
