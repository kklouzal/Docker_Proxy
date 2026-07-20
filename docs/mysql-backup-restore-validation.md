# MySQL backup, restore, and import validation

Docker_Proxy does not mutate production backup systems from application code. Operators should continue to use their normal MySQL 8 backup tooling (`mysqldump`, physical backups, managed snapshots, or PITR), then run the read-only validation below before taking a restored/imported state as healthy.

## State that must be preserved

A complete MySQL state export/import must include:

- `schema_migrations` and `schema_migration_events` so code can prove the schema lifecycle and checksum history.
- Generated active-slot columns and their unique indexes on `proxy_config_revisions`, `certificate_bundle_revisions`, and `adblock_artifact_revisions`.
- Proxy lifecycle state: `proxy_instances`, `proxy_id_aliases`, and `proxy_lifecycle_tombstones`.
- Operation idempotency/claim state in `proxy_operations`, including `request_key` and `claim_token`.
- Revision/apply evidence for proxy config, certificate bundles, and adblock artifacts.
- Safe Browsing tables, adblock/webfilter logs and caches, SSL errors, diagnostics, live stats, timeseries rollups, audit events, policy/PAC tables, and observability settings/report schedules.
- Application secrets that live outside MySQL, especially `FLASK_SECRET_PATH` and TLS/private-key material, must be backed up by the host secret-management path rather than by MySQL exports.

## Pre-backup / post-restore command

Run from the admin-ui environment, or any shell with the same `DATABASE_URL`/`MYSQL_*` settings and Python dependencies:

```bash
python -m services.mysql_state_validation --phase pre-backup
python -m services.mysql_state_validation --phase post-restore
```

The command is read-only. It fails closed (`exit 1`) when required persistent tables, generated columns/indexes, schema migration version, active revision uniqueness, operation idempotency uniqueness, or proxy alias integrity are not intact. It warns, but does not fail, when a proxy rename/remove lifecycle transition is paused or in progress; resume or complete that lifecycle before relying on an export as quiescent.

## Retry and ambiguity policy

- Safe automatic retry is limited to connection acquisition failures before a transaction starts, or whole-operation retries after MySQL reports deadlock (`1213`) or lock wait timeout (`1205`) and the caller opened a fresh transaction that can be replayed safely.
- Whole-operation transaction retry does **not** replay connection-acquisition failures (`1040`, `2002`, `2003`) or lost connections during statements/commit (`2006`, `2013`, PyMySQL interface disconnects). Those failures invalidate the connection but fail loudly because the transaction boundary or commit outcome can be ambiguous to the caller.
- Idempotency keys (`proxy_operations.request_key`, unique active revision slots, artifact/config hashes, and `INSERT IGNORE` log/event keys) are the recovery boundary for duplicate requests and background replays.

## Restore checklist

1. Restore MySQL into an isolated database first; do not point production/admin runtimes at it yet.
2. Restore host secrets/config files that are intentionally outside MySQL.
3. Run `python -m services.mysql_state_validation --phase post-restore`.
4. Confirm no lifecycle transition warnings remain unless you intentionally restored an in-progress rename/remove and plan to resume it.
5. Start application runtimes only after validation is green and the restored database has the expected migration version.
