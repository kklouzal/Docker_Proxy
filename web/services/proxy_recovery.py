from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final, Literal

# Recovery bundles are private disaster-recovery material: they may contain
# declarative policy, certificates, directory/SAML settings, and future secret
# fields.  This module deliberately keeps all state local to the durable proxy
# volume, signs it with a per-proxy key that is independent of the Admin UI
# token, and avoids SQL/runtime integration so later slices can add DB export and
# import behind this small data-contract boundary.

FORMAT_VERSION: Final = 2
DATA_SCHEMA_VERSION: Final = 1
DEFAULT_MAX_BUNDLE_BYTES: Final = 8 * 1024 * 1024
RECOVERY_DIR_ENV: Final = "PROXY_RECOVERY_DIR"
DEFAULT_RECOVERY_DIR: Final = Path("/var/lib/squid-flask-proxy/recovery")
MAC_ALGORITHM: Final = "HMAC-SHA256"
KEY_BYTES: Final = 32

_PROXY_ID_RE: Final = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_CONTROL_PLANE_ID_RE: Final = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
)
_TABLE_NAME_RE: Final = re.compile(r"^[a-z][a-z0-9_]{0,127}$")
_RESERVED_ENCODING_KEY: Final = "__proxy_recovery_type__"
_BYTES_ENCODING: Final = "bytes/base64"
_UNSIGNED_KEYS: Final = frozenset(
    {
        "format_version",
        "proxy_id",
        "source_control_plane_id",
        "created_ts",
        "schema_version",
        "tables",
    }
)
_ENVELOPE_KEYS: Final = _UNSIGNED_KEYS | frozenset({"integrity"})
_INTEGRITY_KEYS: Final = frozenset({"content_sha256", "mac_alg", "mac"})
_HEX_SHA256_RE: Final = re.compile(r"^[0-9a-f]{64}$")


class ProxyRecoveryError(ValueError):
    """Raised when recovery bundle storage or validation fails."""


def _recovery_error(message: str) -> ProxyRecoveryError:
    return ProxyRecoveryError(message)


@dataclass(frozen=True)
class TableScopeSpec:
    table_name: str
    scope_kind: str
    restore_filter_mode: str
    dependency_order: int
    secrets_expected: bool = False
    blobs_expected: bool = False


@dataclass(frozen=True)
class RecoveryTablePayload:
    name: str
    rows: tuple[Mapping[str, Any], ...]


@dataclass(frozen=True)
class IntegrityMetadata:
    content_sha256: str
    mac_alg: str
    mac: str


@dataclass(frozen=True)
class RecoveryBundle:
    format_version: int
    proxy_id: str
    source_control_plane_id: str
    created_ts: str
    schema_version: int
    tables: tuple[RecoveryTablePayload, ...]
    integrity: IntegrityMetadata


TABLE_SCOPE_REGISTRY: Final = (
    TableScopeSpec(
        "adblock_lists",
        "shared_global_declarative",
        "all_rows",
        10,
        blobs_expected=True,
    ),
    TableScopeSpec("adblock_settings", "shared_global_declarative", "all_rows", 20),
    TableScopeSpec(
        "adblock_artifact_revisions",
        "shared_global_declarative",
        "active_revision_only",
        30,
        blobs_expected=True,
    ),
    TableScopeSpec(
        "certificate_bundle_revisions",
        "shared_global_declarative",
        "active_revision_only",
        40,
        secrets_expected=True,
        blobs_expected=True,
    ),
    TableScopeSpec(
        "admin_ui_https_settings",
        "shared_global_declarative",
        "singleton",
        50,
        secrets_expected=True,
    ),
    TableScopeSpec(
        "observability_settings", "shared_global_declarative", "singleton", 60
    ),
    TableScopeSpec(
        "directory_auth_profiles",
        "shared_global_declarative",
        "all_rows",
        70,
        secrets_expected=True,
    ),
    TableScopeSpec(
        "saml_auth_profiles",
        "shared_global_declarative",
        "all_rows",
        80,
        secrets_expected=True,
        blobs_expected=True,
    ),
    TableScopeSpec(
        "proxy_config_revisions",
        "proxy_scoped_current_declarative",
        "active_revision_for_proxy",
        100,
    ),
    TableScopeSpec("pac_profiles", "proxy_scoped_current_declarative", "by_proxy", 110),
    TableScopeSpec(
        "pac_direct_domains",
        "proxy_scoped_current_declarative",
        "by_proxy",
        120,
    ),
    TableScopeSpec(
        "pac_direct_dst_nets",
        "proxy_scoped_current_declarative",
        "by_proxy",
        130,
    ),
    TableScopeSpec(
        "pac_backup_proxies",
        "proxy_scoped_current_declarative",
        "by_proxy",
        140,
    ),
    TableScopeSpec(
        "pac_proxy_chain_settings",
        "proxy_scoped_current_declarative",
        "by_proxy",
        150,
        secrets_expected=True,
    ),
    TableScopeSpec(
        "policy_exceptions",
        "proxy_scoped_current_declarative",
        "active_unexpired_by_proxy",
        160,
    ),
    TableScopeSpec(
        "sslfilter_domains", "proxy_scoped_current_declarative", "by_proxy", 170
    ),
    TableScopeSpec(
        "sslfilter_src_nets", "proxy_scoped_current_declarative", "by_proxy", 180
    ),
    TableScopeSpec(
        "sslfilter_settings", "proxy_scoped_current_declarative", "by_proxy", 190
    ),
    TableScopeSpec(
        "webfilter_settings", "proxy_scoped_current_declarative", "by_proxy", 200
    ),
    TableScopeSpec(
        "webfilter_whitelist", "proxy_scoped_current_declarative", "by_proxy", 210
    ),
    TableScopeSpec(
        "adblock_proxy_meta", "proxy_scoped_current_declarative", "by_proxy", 220
    ),
    TableScopeSpec(
        "observability_report_schedules",
        "proxy_scoped_current_declarative",
        "by_proxy",
        230,
    ),
)

# Deliberately excluded scopes.  Additions to TABLE_SCOPE_REGISTRY should first
# decide whether the data is declarative appliance state, whether it is safe to
# replay on a replacement proxy, and whether stale history/caches would corrupt
# recovery semantics.
EXCLUDED_RECOVERY_RATIONALE: Final = MappingProxyType(
    {
        "users_password_hashes_sessions": "identity/session material is not proxy appliance declarative state and must not be replayed from a proxy volume",
        "proxy_registry_aliases_tombstones": "the replacement Admin UI owns proxy identity, alias, and tombstone records",
        "schema_migration_bookkeeping": "migrations are controlled by the target application version, not imported data",
        "operations_audit_diagnostics_stats_events": "operational history is evidence/telemetry, not desired replacement configuration",
        "counts_caches_errors": "derived volatile data should be regenerated and may be stale or hostile",
        "apply_evidence": "apply evidence describes past attempts and must not grant trust to a replacement import",
        "policy_request_history": "request workflow history is not active policy and can contain stale decisions",
        "revoked_or_expired_policy_exceptions": "only active unexpired exceptions are declarative current behavior",
        "safe_browsing_webcat_generated_caches": "generated threat/category caches are large volatile artifacts with their own refresh lifecycle",
        "non_active_revision_history": "historic revisions are intentionally excluded to keep recovery to current declarative state",
    }
)

_REGISTRY_BY_TABLE: Final = MappingProxyType(
    {spec.table_name: spec for spec in TABLE_SCOPE_REGISTRY}
)


def validate_recovery_registry() -> None:
    seen_tables: set[str] = set()
    seen_orders: set[int] = set()
    last_order = -1
    for spec in TABLE_SCOPE_REGISTRY:
        if not _TABLE_NAME_RE.fullmatch(spec.table_name):
            msg = f"invalid recovery table name: {spec.table_name!r}"
            raise _recovery_error(msg)
        if spec.table_name in seen_tables:
            msg = f"duplicate recovery table scope: {spec.table_name}"
            raise _recovery_error(msg)
        if spec.dependency_order in seen_orders:
            msg = f"duplicate recovery dependency order: {spec.dependency_order}"
            raise _recovery_error(msg)
        if spec.dependency_order <= last_order:
            msg = "recovery table registry is not dependency ordered"
            raise _recovery_error(msg)
        seen_tables.add(spec.table_name)
        seen_orders.add(spec.dependency_order)
        last_order = spec.dependency_order


def recovery_registry() -> tuple[TableScopeSpec, ...]:
    return TABLE_SCOPE_REGISTRY


RestoreStatus = Literal[
    "adopted",
    "already_adopted",
    "same_control_plane",
    "not_eligible",
]

_RESTORE_STATUS_ADOPTED: Final = "adopted"
_RESTORE_STATUS_ALREADY_ADOPTED: Final = "already_adopted"
_RESTORE_STATUS_SAME_CONTROL_PLANE: Final = "same_control_plane"
_RESTORE_STATUS_NOT_ELIGIBLE: Final = "not_eligible"
_ADOPTION_STATUS_ADOPTED: Final = "adopted"
_MAX_ROWS_PER_TABLE: Final = 10_000
_MAX_TEXT_BYTES: Final = 2 * 1024 * 1024
_MAX_BLOB_BYTES: Final = 8 * 1024 * 1024

_ADBLOCK_DEFAULT_LISTS: Final = MappingProxyType(
    {
        "easylist": "https://easylist.to/easylist/easylist.txt",
        "easyprivacy": "https://easylist.to/easylist/easyprivacy.txt",
        "cookiemonster": "https://secure.fanboy.co.nz/fanboy-cookiemonster.txt",
    },
)
_ADBLOCK_DEFAULT_SETTINGS: Final = MappingProxyType(
    {"enabled": "1", "cache_ttl": "3600", "cache_max": "200000"},
)
_OBSERVABILITY_DEFAULT_RETENTION_DAYS: Final = 30
_WEBFILTER_DEFAULT_SETTINGS: Final = MappingProxyType(
    {"enabled": "0", "blocked_categories": ""},
)
_DIRECTORY_DEFAULT_ROWS: Final = (
    {
        "provider": "active_directory",
        "enabled": 0,
        "server_urls": "ldaps://dc.example.local:636",
        "use_starttls": 0,
        "verify_tls": 1,
        "ca_bundle": "",
        "bind_dn": "svc-docker-proxy@example.local",
        "bind_password": "",
        "base_dn": "DC=example,DC=local",
        "user_search_base": "",
        "user_filter": "(|(sAMAccountName={username})(userPrincipalName={username}))",
        "user_attribute": "sAMAccountName",
        "group_search_base": "",
        "group_filter": "(member:1.2.840.113556.1.4.1941:={user_dn})",
        "required_admin_group": "CN=Docker Proxy Admins,OU=Groups,DC=example,DC=local",
        "timeout_seconds": 5,
    },
    {
        "provider": "ldap",
        "enabled": 0,
        "server_urls": "ldaps://ldap.example.org:636",
        "use_starttls": 0,
        "verify_tls": 1,
        "ca_bundle": "",
        "bind_dn": "cn=proxy-bind,ou=service,dc=example,dc=org",
        "bind_password": "",
        "base_dn": "dc=example,dc=org",
        "user_search_base": "ou=people",
        "user_filter": "(uid={username})",
        "user_attribute": "uid",
        "group_search_base": "ou=groups",
        "group_filter": "(|(member={user_dn})(uniqueMember={user_dn})(memberUid={username}))",
        "required_admin_group": "cn=docker-proxy-admins,ou=groups,dc=example,dc=org",
        "timeout_seconds": 5,
    },
)
_SAML_DEFAULT_ROW: Final = MappingProxyType(
    {
        "provider": "saml",
        "enabled": 0,
        "metadata_url": "https://adfs.example.local/FederationMetadata/2007-06/FederationMetadata.xml",
        "require_https": 1,
        "verify_tls": 1,
        "ca_bundle": "",
        "timeout_seconds": 10,
        "max_metadata_bytes": 2 * 1024 * 1024,
        "raw_metadata_xml": "",
        "public_base_url": "",
        "username_attribute": "NameID",
        "groups_attribute": "groups",
        "required_group": "",
    },
)


@dataclass(frozen=True)
class RestoreTablePlan:
    table_name: str
    columns: tuple[str, ...]
    rows: tuple[Mapping[str, Any], ...]


@dataclass(frozen=True)
class RecoveryRestorePlan:
    proxy_id: str
    target_proxy_id: str
    source_control_plane_id: str
    bundle_content_sha256: str
    now_ts: int
    tables: tuple[RestoreTablePlan, ...]


@dataclass(frozen=True)
class RecoveryRestoreResult:
    status: RestoreStatus
    proxy_id: str
    target_proxy_id: str
    source_control_plane_id: str
    target_control_plane_id: str = ""
    bundle_content_sha256: str = ""
    adopted_ts: int = 0
    reason: str = ""


@dataclass(frozen=True)
class _RestoreSqlPlan:
    table_name: str
    columns: tuple[str, ...]
    natural_key: tuple[str, ...]
    insert_sql: str


RESTORE_SQL_PLANS: Final = (
    _RestoreSqlPlan(
        "adblock_lists",
        ("key", "url", "enabled"),
        ("key",),
        "INSERT INTO adblock_lists(`key`, url, enabled) VALUES(%s,%s,%s)",
    ),
    _RestoreSqlPlan(
        "adblock_settings",
        ("k", "v"),
        ("k",),
        "INSERT INTO adblock_settings(k, v) VALUES(%s,%s)",
    ),
    _RestoreSqlPlan(
        "adblock_artifact_revisions",
        (
            "artifact_sha256",
            "archive_blob",
            "report_json",
            "settings_version",
            "enabled_lists_json",
        ),
        ("artifact_sha256",),
        """
        INSERT INTO adblock_artifact_revisions(
            artifact_sha256, archive_blob, report_json, settings_version,
            enabled_lists_json, source_kind, created_by, created_ts, is_active
        ) VALUES(%s,%s,%s,%s,%s,'proxy_recovery','proxy_recovery',%s,1)
        """,
    ),
    _RestoreSqlPlan(
        "certificate_bundle_revisions",
        ("bundle_sha256", "cert_sha256", "cert_pem", "key_pem", "chain_pem"),
        ("bundle_sha256",),
        """
        INSERT INTO certificate_bundle_revisions(
            bundle_sha256, cert_sha256, cert_pem, key_pem, chain_pem,
            source_kind, created_by, created_ts, is_active
        ) VALUES(%s,%s,%s,%s,%s,'proxy_recovery','proxy_recovery',%s,1)
        """,
    ),
    _RestoreSqlPlan(
        "admin_ui_https_settings",
        ("enabled", "certfile", "keyfile", "san_tokens"),
        ("enabled",),
        """
        INSERT INTO admin_ui_https_settings(id, enabled, certfile, keyfile, san_tokens, updated_by, updated_ts)
        VALUES(1,%s,%s,%s,%s,'proxy_recovery',%s)
        """,
    ),
    _RestoreSqlPlan(
        "observability_settings",
        ("retention_days",),
        ("retention_days",),
        """
        INSERT INTO observability_settings(id, retention_days, updated_ts)
        VALUES(1,%s,%s)
        """,
    ),
    _RestoreSqlPlan(
        "directory_auth_profiles",
        (
            "provider",
            "enabled",
            "server_urls",
            "use_starttls",
            "verify_tls",
            "ca_bundle",
            "bind_dn",
            "bind_password",
            "base_dn",
            "user_search_base",
            "user_filter",
            "user_attribute",
            "group_search_base",
            "group_filter",
            "required_admin_group",
            "timeout_seconds",
        ),
        ("provider",),
        """
        INSERT INTO directory_auth_profiles(
            provider, enabled, server_urls, use_starttls, verify_tls, ca_bundle,
            bind_dn, bind_password, base_dn, user_search_base, user_filter,
            user_attribute, group_search_base, group_filter, required_admin_group,
            timeout_seconds, last_test_ok, last_test_ts, last_test_detail, updated_ts
        ) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,0,0,'',%s)
        """,
    ),
    _RestoreSqlPlan(
        "saml_auth_profiles",
        (
            "provider",
            "enabled",
            "metadata_url",
            "require_https",
            "verify_tls",
            "ca_bundle",
            "timeout_seconds",
            "max_metadata_bytes",
            "raw_metadata_xml",
            "public_base_url",
            "username_attribute",
            "groups_attribute",
            "required_group",
        ),
        ("provider",),
        """
        INSERT INTO saml_auth_profiles(
            provider, enabled, metadata_url, require_https, verify_tls, ca_bundle,
            timeout_seconds, max_metadata_bytes, raw_metadata_xml, parsed_metadata_json,
            entity_id, fetched_ts, cache_expires_ts, valid_until_ts, last_refresh_ok,
            last_refresh_ts, last_refresh_detail, public_base_url, username_attribute,
            groups_attribute, required_group, updated_ts
        ) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,'','',0,0,0,0,0,'',%s,%s,%s,%s,%s)
        """,
    ),
    _RestoreSqlPlan(
        "proxy_config_revisions",
        ("proxy_id", "config_sha256", "config_text"),
        ("proxy_id", "config_sha256"),
        """
        INSERT INTO proxy_config_revisions(
            proxy_id, config_sha256, config_text, source_kind, created_by, created_ts, is_active
        ) VALUES(%s,%s,%s,'proxy_recovery','proxy_recovery',%s,1)
        """,
    ),
    _RestoreSqlPlan(
        "pac_profiles",
        ("source_profile_id", "proxy_id", "name", "client_cidr"),
        ("source_profile_id",),
        "INSERT INTO pac_profiles(proxy_id, name, client_cidr, created_ts) VALUES(%s,%s,%s,%s)",
    ),
    _RestoreSqlPlan(
        "pac_direct_domains",
        ("source_profile_id", "domain"),
        ("source_profile_id", "domain"),
        "INSERT INTO pac_direct_domains(profile_id, domain) VALUES(%s,%s)",
    ),
    _RestoreSqlPlan(
        "pac_direct_dst_nets",
        ("source_profile_id", "cidr"),
        ("source_profile_id", "cidr"),
        "INSERT INTO pac_direct_dst_nets(profile_id, cidr) VALUES(%s,%s)",
    ),
    _RestoreSqlPlan(
        "pac_backup_proxies",
        ("proxy_id", "proxy_host", "proxy_port", "position"),
        ("proxy_id", "position"),
        "INSERT INTO pac_backup_proxies(proxy_id, proxy_host, proxy_port, position, created_ts) VALUES(%s,%s,%s,%s,%s)",
    ),
    _RestoreSqlPlan(
        "pac_proxy_chain_settings",
        ("proxy_id", "direct_enabled"),
        ("proxy_id",),
        "INSERT INTO pac_proxy_chain_settings(proxy_id, direct_enabled, updated_ts) VALUES(%s,%s,%s)",
    ),
    _RestoreSqlPlan(
        "policy_exceptions",
        (
            "proxy_id",
            "block_type",
            "client_ip",
            "domain",
            "category",
            "admin_note",
            "expires_ts",
        ),
        ("proxy_id", "block_type", "client_ip", "domain", "category", "expires_ts"),
        """
        INSERT INTO policy_exceptions(
            proxy_id, status, block_type, client_ip, domain, category,
            created_ts, updated_ts, created_by, admin_note, expires_ts, revoked_ts, revoked_by, source_request_id
        ) VALUES(%s,'active',%s,%s,%s,%s,%s,%s,'proxy_recovery',%s,%s,0,'',NULL)
        """,
    ),
    _RestoreSqlPlan(
        "sslfilter_domains",
        ("proxy_id", "policy", "domain"),
        ("proxy_id", "policy", "domain"),
        "INSERT INTO sslfilter_domains(proxy_id, policy, domain, added_ts) VALUES(%s,%s,%s,%s)",
    ),
    _RestoreSqlPlan(
        "sslfilter_src_nets",
        ("proxy_id", "policy", "cidr"),
        ("proxy_id", "policy", "cidr"),
        "INSERT INTO sslfilter_src_nets(proxy_id, policy, cidr, added_ts) VALUES(%s,%s,%s,%s)",
    ),
    _RestoreSqlPlan(
        "sslfilter_settings",
        ("proxy_id", "key", "value"),
        ("proxy_id", "key"),
        "INSERT INTO sslfilter_settings(proxy_id, `key`, value) VALUES(%s,%s,%s)",
    ),
    _RestoreSqlPlan(
        "webfilter_settings",
        ("proxy_id", "k", "v"),
        ("proxy_id", "k"),
        "INSERT INTO webfilter_settings(proxy_id, k, v) VALUES(%s,%s,%s)",
    ),
    _RestoreSqlPlan(
        "webfilter_whitelist",
        ("proxy_id", "pattern"),
        ("proxy_id", "pattern"),
        "INSERT INTO webfilter_whitelist(proxy_id, pattern, added_ts) VALUES(%s,%s,%s)",
    ),
    _RestoreSqlPlan(
        "adblock_proxy_meta",
        ("proxy_id", "k", "v"),
        ("proxy_id", "k"),
        "INSERT INTO adblock_proxy_meta(proxy_id, k, v) VALUES(%s,%s,%s)",
    ),
    _RestoreSqlPlan(
        "observability_report_schedules",
        (
            "proxy_id",
            "enabled",
            "name",
            "cadence",
            "recipients",
            "pane",
            "report_format",
            "privacy",
            "window_seconds",
        ),
        ("proxy_id", "name", "cadence", "pane"),
        """
        INSERT INTO observability_report_schedules(
            proxy_id, enabled, name, cadence, recipients, pane, report_format,
            privacy, window_seconds, created_ts, updated_ts, next_run_ts, last_run_ts, last_status
        ) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,0,0,'')
        """,
    ),
)
_RESTORE_SQL_BY_TABLE: Final = MappingProxyType(
    {plan.table_name: plan for plan in RESTORE_SQL_PLANS}
)


def restore_sql_plans() -> tuple[_RestoreSqlPlan, ...]:
    return RESTORE_SQL_PLANS


def validate_restore_sql_plan_coverage() -> None:
    registry_tables = tuple(spec.table_name for spec in TABLE_SCOPE_REGISTRY)
    restore_tables = tuple(plan.table_name for plan in RESTORE_SQL_PLANS)
    if restore_tables != registry_tables:
        msg = "recovery DB restore SQL plans do not match recovery registry order"
        raise _recovery_error(msg)
    for plan in RESTORE_SQL_PLANS:
        lowered = " ".join(plan.insert_sql.lower().split())
        if "select *" in lowered:
            msg = f"unsafe recovery restore SQL for {plan.table_name}"
            raise _recovery_error(msg)
        if plan.table_name not in lowered and plan.table_name not in {
            "pac_direct_domains",
            "pac_direct_dst_nets",
        }:
            msg = f"recovery restore SQL does not reference {plan.table_name}"
            raise _recovery_error(msg)
        if len(plan.columns) != len(set(plan.columns)):
            msg = f"duplicate recovery restore columns for {plan.table_name}"
            raise _recovery_error(msg)
        if not set(plan.natural_key).issubset(plan.columns):
            msg = f"restore natural key is not covered by columns for {plan.table_name}"
            raise _recovery_error(msg)


def build_restore_plan(
    bundle: RecoveryBundle,
    target_proxy_id: str,
    now_ts: int | None = None,
) -> RecoveryRestorePlan:
    """Validate immutable bundle contents and produce a mutation-free restore plan."""
    validate_restore_sql_plan_coverage()
    # The exporter is the contract source for column order; import lazily to avoid
    # a module-load cycle because proxy_recovery_db imports this module.
    from services import proxy_recovery_db

    proxy_recovery_db.validate_export_query_plan_coverage()
    exporter_by_table = {
        plan.table_name: plan for plan in proxy_recovery_db.recovery_export_query_plans()
    }
    normalized_target = normalize_proxy_id(target_proxy_id)
    if bundle.proxy_id != normalized_target:
        msg = "recovery bundle proxy id does not match target proxy"
        raise _recovery_error(msg)
    timestamp = int(time.time() if now_ts is None else now_ts)
    tables_by_name = {table.name: table for table in bundle.tables}
    if set(tables_by_name) != {spec.table_name for spec in TABLE_SCOPE_REGISTRY}:
        msg = "recovery bundle table coverage does not exactly match registry"
        raise _recovery_error(msg)
    planned: list[RestoreTablePlan] = []
    for spec in TABLE_SCOPE_REGISTRY:
        table = tables_by_name[spec.table_name]
        restore_plan = _RESTORE_SQL_BY_TABLE[spec.table_name]
        export_plan = exporter_by_table[spec.table_name]
        if restore_plan.columns != export_plan.columns:
            msg = f"restore/export column contract mismatch for {spec.table_name}"
            raise _recovery_error(msg)
        rows = _validate_restore_rows(
            table,
            restore_plan,
            target_proxy_id=normalized_target,
            now_ts=timestamp,
        )
        planned.append(RestoreTablePlan(spec.table_name, restore_plan.columns, rows))
    _validate_pac_restore_graph(planned)
    return RecoveryRestorePlan(
        proxy_id=bundle.proxy_id,
        target_proxy_id=normalized_target,
        source_control_plane_id=bundle.source_control_plane_id,
        bundle_content_sha256=bundle.integrity.content_sha256,
        now_ts=timestamp,
        tables=tuple(planned),
    )


def restore_recovery_bundle(
    conn: Any,
    bundle: RecoveryBundle,
    target_proxy_id: str,
    *,
    now_ts: int | None = None,
    lock_timeout_seconds: int = 10,
) -> RecoveryRestoreResult:
    """Atomically adopt a valid proxy-local recovery bundle exactly once.

    Bundle reading/signature verification must happen before this API is called.
    The target control-plane identity is never modified.
    """
    plan = build_restore_plan(bundle, target_proxy_id, now_ts)
    from services import proxy_write_guard
    from services.schema_lifecycle import read_control_plane_identity

    with proxy_write_guard.guarded_proxy_write(
        conn,
        plan.target_proxy_id,
        allow_alias=False,
        require_registered=True,
        timeout_seconds=lock_timeout_seconds,
    ) as guard:
        if guard.proxy_id != plan.target_proxy_id:
            msg = "recovery target proxy changed during lifecycle lock acquisition"
            raise _recovery_error(msg)
        conn.execute("START TRANSACTION")
        try:
            # Re-read lifecycle, identity, marker, and freshness under the per-proxy
            # lock and inside the one mutation transaction immediately before writes.
            decision = proxy_write_guard.resolve_proxy_write_id(
                conn,
                plan.target_proxy_id,
                allow_alias=False,
                require_registered=True,
                use_cache=False,
            )
            if decision.proxy_id != plan.target_proxy_id:
                msg = "recovery target proxy changed before mutation"
                raise _recovery_error(msg)
            target_control_plane_id = read_control_plane_identity(conn)
            if target_control_plane_id is None:
                msg = "target control plane identity is missing"
                raise _recovery_error(msg)
            if target_control_plane_id == plan.source_control_plane_id:
                conn.rollback()
                return RecoveryRestoreResult(
                    status=_RESTORE_STATUS_SAME_CONTROL_PLANE,
                    proxy_id=plan.proxy_id,
                    target_proxy_id=plan.target_proxy_id,
                    source_control_plane_id=plan.source_control_plane_id,
                    target_control_plane_id=target_control_plane_id,
                    bundle_content_sha256=plan.bundle_content_sha256,
                    reason="bundle source is the current control plane",
                )
            if _adoption_marker_exists(conn, plan.target_proxy_id, target_control_plane_id):
                conn.rollback()
                return RecoveryRestoreResult(
                    status=_RESTORE_STATUS_ALREADY_ADOPTED,
                    proxy_id=plan.proxy_id,
                    target_proxy_id=plan.target_proxy_id,
                    source_control_plane_id=plan.source_control_plane_id,
                    target_control_plane_id=target_control_plane_id,
                    bundle_content_sha256=plan.bundle_content_sha256,
                    reason="target control plane already adopted this proxy bundle once",
                )
            freshness_reason = _freshness_failure_reason(conn, plan.target_proxy_id)
            if freshness_reason:
                conn.rollback()
                return RecoveryRestoreResult(
                    status=_RESTORE_STATUS_NOT_ELIGIBLE,
                    proxy_id=plan.proxy_id,
                    target_proxy_id=plan.target_proxy_id,
                    source_control_plane_id=plan.source_control_plane_id,
                    target_control_plane_id=target_control_plane_id,
                    bundle_content_sha256=plan.bundle_content_sha256,
                    reason=freshness_reason,
                )
            _apply_restore_plan(conn, plan)
            _insert_adoption_marker(conn, plan, target_control_plane_id)
            conn.commit()
            return RecoveryRestoreResult(
                status=_RESTORE_STATUS_ADOPTED,
                proxy_id=plan.proxy_id,
                target_proxy_id=plan.target_proxy_id,
                source_control_plane_id=plan.source_control_plane_id,
                target_control_plane_id=target_control_plane_id,
                bundle_content_sha256=plan.bundle_content_sha256,
                adopted_ts=plan.now_ts,
            )
        except Exception:
            rollback = getattr(conn, "rollback", None)
            if callable(rollback):
                rollback()
            raise


def _validate_restore_rows(
    table: RecoveryTablePayload,
    plan: _RestoreSqlPlan,
    *,
    target_proxy_id: str,
    now_ts: int,
) -> tuple[Mapping[str, Any], ...]:
    if len(table.rows) > _MAX_ROWS_PER_TABLE:
        msg = f"too many recovery rows for {table.name}"
        raise _recovery_error(msg)
    if table.name in {
        "adblock_artifact_revisions",
        "certificate_bundle_revisions",
        "admin_ui_https_settings",
        "observability_settings",
        "proxy_config_revisions",
    } and len(table.rows) > 1:
        msg = f"recovery table has multiple active/singleton rows: {table.name}"
        raise _recovery_error(msg)
    seen_keys: set[tuple[Any, ...]] = set()
    rows: list[Mapping[str, Any]] = []
    for row in table.rows:
        if set(row) != set(plan.columns):
            msg = f"recovery row columns do not match export contract for {table.name}"
            raise _recovery_error(msg)
        normalized = {column: _validate_restore_value(table.name, column, row[column]) for column in plan.columns}
        for proxy_column in ("proxy_id",):
            if proxy_column in normalized and normalized[proxy_column] != target_proxy_id:
                msg = f"recovery row proxy id does not match target for {table.name}"
                raise _recovery_error(msg)
        if table.name == "pac_profiles":
            source_profile_id = normalized.get("source_profile_id")
            if not isinstance(source_profile_id, int) or source_profile_id <= 0:
                msg = "recovery PAC profile source id is invalid"
                raise _recovery_error(msg)
        if table.name in {"pac_direct_domains", "pac_direct_dst_nets"}:
            source_profile_id = normalized.get("source_profile_id")
            if not isinstance(source_profile_id, int) or source_profile_id <= 0:
                msg = "recovery PAC child source profile id is invalid"
                raise _recovery_error(msg)
        if table.name == "policy_exceptions":
            expires_ts = int(normalized["expires_ts"])
            if expires_ts != 0 and expires_ts <= now_ts:
                msg = "recovery policy exception is expired"
                raise _recovery_error(msg)
        key = tuple(normalized[column] for column in plan.natural_key)
        if key in seen_keys:
            msg = f"duplicate recovery natural key for {table.name}"
            raise _recovery_error(msg)
        seen_keys.add(key)
        rows.append(normalized)
    return tuple(rows)


def _validate_restore_value(table_name: str, column: str, value: Any) -> Any:
    if column in {
        "enabled",
        "use_starttls",
        "verify_tls",
        "require_https",
        "direct_enabled",
        "privacy",
    }:
        if not isinstance(value, int) or value not in {0, 1}:
            msg = f"invalid boolean recovery value for {table_name}.{column}"
            raise _recovery_error(msg)
        return int(value)
    if column in {
        "settings_version",
        "timeout_seconds",
        "max_metadata_bytes",
        "source_profile_id",
        "proxy_port",
        "position",
        "expires_ts",
        "retention_days",
        "window_seconds",
    }:
        if not isinstance(value, int) or value < 0:
            msg = f"invalid integer recovery value for {table_name}.{column}"
            raise _recovery_error(msg)
        return int(value)
    if column == "archive_blob":
        if not isinstance(value, bytes) or len(value) > _MAX_BLOB_BYTES:
            msg = f"invalid blob recovery value for {table_name}.{column}"
            raise _recovery_error(msg)
        return value
    if column.endswith("sha256"):
        if not isinstance(value, str) or not _HEX_SHA256_RE.fullmatch(value):
            msg = f"invalid sha256 recovery value for {table_name}.{column}"
            raise _recovery_error(msg)
        return value
    if not isinstance(value, str):
        msg = f"invalid text recovery value for {table_name}.{column}"
        raise _recovery_error(msg)
    if len(value.encode("utf-8", errors="strict")) > _MAX_TEXT_BYTES:
        msg = f"oversized text recovery value for {table_name}.{column}"
        raise _recovery_error(msg)
    return value


def _validate_pac_restore_graph(planned: Sequence[RestoreTablePlan]) -> None:
    by_table = {table.table_name: table for table in planned}
    profile_ids = {
        int(row["source_profile_id"])
        for row in by_table["pac_profiles"].rows
    }
    if len(profile_ids) != len(by_table["pac_profiles"].rows):
        msg = "duplicate recovery PAC source profile id"
        raise _recovery_error(msg)
    for table_name in ("pac_direct_domains", "pac_direct_dst_nets"):
        for row in by_table[table_name].rows:
            if int(row["source_profile_id"]) not in profile_ids:
                msg = f"orphan recovery PAC child row in {table_name}"
                raise _recovery_error(msg)


def _row_value(row: Any, key: str, index: int = 0) -> Any:
    try:
        return row[key]
    except Exception:
        try:
            return row[index]
        except Exception:
            return None


def _count(conn: Any, sql: str, params: Sequence[Any] = ()) -> int:
    row = conn.execute(sql, tuple(params)).fetchone()
    return int(_row_value(row, "n", 0) or 0)


def _rows(conn: Any, sql: str, params: Sequence[Any] = ()) -> tuple[Any, ...]:
    return tuple(conn.execute(sql, tuple(params)).fetchall())


def _adoption_marker_exists(conn: Any, proxy_id: str, target_control_plane_id: str) -> bool:
    row = conn.execute(
        """
        SELECT status
        FROM proxy_recovery_adoptions
        WHERE proxy_id=%s AND target_control_plane_id=%s
        LIMIT 1
        """,
        (proxy_id, target_control_plane_id),
    ).fetchone()
    return row is not None


def _freshness_failure_reason(conn: Any, proxy_id: str) -> str:
    probes = (
        _fresh_adblock_lists,
        _fresh_adblock_settings,
        _fresh_no_active_adblock_artifacts,
        _fresh_no_active_certificate_bundle,
        _fresh_admin_ui_https_settings,
        _fresh_observability_settings,
        _fresh_directory_auth_profiles,
        _fresh_saml_auth_profiles,
        _fresh_no_proxy_config_revision,
        _fresh_no_pac_profiles,
        _fresh_no_pac_backup_proxies,
        _fresh_pac_proxy_chain_settings,
        _fresh_no_policy_exceptions,
        _fresh_no_sslfilter_rows,
        _fresh_webfilter_settings,
        _fresh_no_proxy_table_rows,
    )
    for probe in probes:
        reason = probe(conn, proxy_id)
        if reason:
            return reason
    return ""


def _fresh_adblock_lists(conn: Any, _proxy_id: str) -> str:
    rows = _rows(conn, "SELECT `key`, url, enabled FROM adblock_lists ORDER BY `key` ASC")
    allowed = {
        (key, url, 0)
        for key, url in _ADBLOCK_DEFAULT_LISTS.items()
    }
    actual = {(str(_row_value(row, "key")), str(_row_value(row, "url")), int(_row_value(row, "enabled") or 0)) for row in rows}
    if actual and actual != allowed:
        return "adblock lists are not canonical schema defaults"
    return ""


def _fresh_adblock_settings(conn: Any, _proxy_id: str) -> str:
    rows = _rows(conn, "SELECT k, v FROM adblock_settings ORDER BY k ASC")
    actual = {str(_row_value(row, "k")): str(_row_value(row, "v")) for row in rows}
    if actual and actual != dict(_ADBLOCK_DEFAULT_SETTINGS):
        return "adblock settings are not canonical schema defaults"
    return ""


def _fresh_no_active_adblock_artifacts(conn: Any, _proxy_id: str) -> str:
    if _count(conn, "SELECT COUNT(*) AS n FROM adblock_artifact_revisions"):
        return "adblock artifact revision already exists"
    return ""


def _fresh_no_active_certificate_bundle(conn: Any, _proxy_id: str) -> str:
    if _count(conn, "SELECT COUNT(*) AS n FROM certificate_bundle_revisions"):
        return "certificate bundle revision already exists"
    return ""


def _fresh_admin_ui_https_settings(conn: Any, _proxy_id: str) -> str:
    rows = _rows(conn, "SELECT enabled, certfile, keyfile, san_tokens FROM admin_ui_https_settings WHERE id=1")
    if not rows:
        return ""
    if len(rows) == 1:
        row = rows[0]
        if (
            int(_row_value(row, "enabled") or 0) == 0
            and str(_row_value(row, "certfile") or "") == ""
            and str(_row_value(row, "keyfile") or "") == ""
            and str(_row_value(row, "san_tokens") or "") == ""
        ):
            return ""
    return "admin UI HTTPS settings are not canonical schema defaults"


def _fresh_observability_settings(conn: Any, _proxy_id: str) -> str:
    rows = _rows(conn, "SELECT retention_days FROM observability_settings WHERE id=1")
    if not rows:
        return ""
    if len(rows) == 1 and int(_row_value(rows[0], "retention_days") or 0) == _OBSERVABILITY_DEFAULT_RETENTION_DAYS:
        return ""
    return "observability settings are not canonical schema defaults"


def _fresh_directory_auth_profiles(conn: Any, _proxy_id: str) -> str:
    rows = _rows(
        conn,
        """
        SELECT provider, enabled, server_urls, use_starttls, verify_tls, ca_bundle,
               bind_dn, bind_password, base_dn, user_search_base, user_filter,
               user_attribute, group_search_base, group_filter, required_admin_group,
               timeout_seconds
        FROM directory_auth_profiles
        ORDER BY provider ASC
        """,
    )
    if not rows:
        return ""
    actual = tuple(_project_row(row, _RESTORE_SQL_BY_TABLE["directory_auth_profiles"].columns) for row in rows)
    expected = tuple(dict(row) for row in sorted(_DIRECTORY_DEFAULT_ROWS, key=lambda item: str(item["provider"])))
    if actual == expected:
        return ""
    return "directory auth profiles are not canonical schema defaults"


def _fresh_saml_auth_profiles(conn: Any, _proxy_id: str) -> str:
    rows = _rows(
        conn,
        """
        SELECT provider, enabled, metadata_url, require_https, verify_tls, ca_bundle,
               timeout_seconds, max_metadata_bytes, raw_metadata_xml, public_base_url,
               username_attribute, groups_attribute, required_group
        FROM saml_auth_profiles
        ORDER BY provider ASC
        """,
    )
    if not rows:
        return ""
    actual = tuple(_project_row(row, _RESTORE_SQL_BY_TABLE["saml_auth_profiles"].columns) for row in rows)
    if actual == (dict(_SAML_DEFAULT_ROW),):
        return ""
    return "SAML auth profile is not the canonical schema default"


def _fresh_no_proxy_config_revision(conn: Any, proxy_id: str) -> str:
    if _count(conn, "SELECT COUNT(*) AS n FROM proxy_config_revisions WHERE proxy_id=%s", (proxy_id,)):
        return "proxy config revision already exists for target proxy"
    return ""


def _fresh_no_pac_profiles(conn: Any, proxy_id: str) -> str:
    if _count(conn, "SELECT COUNT(*) AS n FROM pac_profiles WHERE proxy_id=%s", (proxy_id,)):
        return "PAC profiles already exist for target proxy"
    return ""


def _fresh_no_pac_backup_proxies(conn: Any, proxy_id: str) -> str:
    if _count(conn, "SELECT COUNT(*) AS n FROM pac_backup_proxies WHERE proxy_id=%s", (proxy_id,)):
        return "PAC backup proxies already exist for target proxy"
    return ""


def _fresh_pac_proxy_chain_settings(conn: Any, proxy_id: str) -> str:
    rows = _rows(conn, "SELECT direct_enabled FROM pac_proxy_chain_settings WHERE proxy_id=%s", (proxy_id,))
    if not rows:
        return ""
    if len(rows) == 1 and int(_row_value(rows[0], "direct_enabled") or 0) == 1:
        return ""
    return "PAC proxy chain settings are not canonical defaults"


def _fresh_no_policy_exceptions(conn: Any, proxy_id: str) -> str:
    if _count(conn, "SELECT COUNT(*) AS n FROM policy_exceptions WHERE proxy_id=%s", (proxy_id,)):
        return "policy exceptions already exist for target proxy"
    return ""


def _fresh_no_sslfilter_rows(conn: Any, proxy_id: str) -> str:
    if _count(conn, "SELECT COUNT(*) AS n FROM sslfilter_domains WHERE proxy_id=%s", (proxy_id,)):
        return "SSL filter rows already exist for target proxy"
    if _count(conn, "SELECT COUNT(*) AS n FROM sslfilter_src_nets WHERE proxy_id=%s", (proxy_id,)):
        return "SSL filter rows already exist for target proxy"
    if _count(conn, "SELECT COUNT(*) AS n FROM sslfilter_settings WHERE proxy_id=%s", (proxy_id,)):
        return "SSL filter rows already exist for target proxy"
    return ""


def _fresh_webfilter_settings(conn: Any, proxy_id: str) -> str:
    rows = _rows(conn, "SELECT k, v FROM webfilter_settings WHERE proxy_id=%s ORDER BY k ASC", (proxy_id,))
    if not rows:
        return ""
    actual = {str(_row_value(row, "k")): str(_row_value(row, "v")) for row in rows}
    if actual == dict(_WEBFILTER_DEFAULT_SETTINGS):
        return ""
    return "webfilter settings are not canonical target defaults"


def _fresh_no_proxy_table_rows(conn: Any, proxy_id: str) -> str:
    if _count(conn, "SELECT COUNT(*) AS n FROM webfilter_whitelist WHERE proxy_id=%s", (proxy_id,)):
        return "target proxy declarative rows already exist"
    if _count(conn, "SELECT COUNT(*) AS n FROM adblock_proxy_meta WHERE proxy_id=%s", (proxy_id,)):
        return "target proxy declarative rows already exist"
    if _count(conn, "SELECT COUNT(*) AS n FROM observability_report_schedules WHERE proxy_id=%s", (proxy_id,)):
        return "target proxy declarative rows already exist"
    return ""


def _project_row(row: Any, columns: Sequence[str]) -> dict[str, Any]:
    projected: dict[str, Any] = {}
    for index, column in enumerate(columns):
        value = _row_value(row, column, index)
        if column in {"enabled", "use_starttls", "verify_tls", "require_https", "timeout_seconds", "max_metadata_bytes"}:
            value = int(value or 0)
        elif value is None:
            value = ""
        else:
            value = str(value)
        projected[column] = value
    return projected


def _apply_restore_plan(conn: Any, plan: RecoveryRestorePlan) -> None:
    _delete_known_fresh_defaults(conn, plan.target_proxy_id)
    source_profile_to_target: dict[int, int] = {}
    for table in plan.tables:
        sql_plan = _RESTORE_SQL_BY_TABLE[table.table_name]
        for row in table.rows:
            if table.table_name == "pac_profiles":
                cur = conn.execute(
                    sql_plan.insert_sql,
                    (plan.target_proxy_id, row["name"], row["client_cidr"], plan.now_ts),
                )
                new_id = int(getattr(cur, "lastrowid", 0) or 0)
                if new_id <= 0:
                    new_id = int(_row_value(conn.execute("SELECT LAST_INSERT_ID() AS id").fetchone(), "id") or 0)
                if new_id <= 0:
                    msg = "failed to allocate target PAC profile id"
                    raise _recovery_error(msg)
                source_profile_to_target[int(row["source_profile_id"])] = new_id
                continue
            params = _restore_insert_params(table.table_name, row, plan, source_profile_to_target)
            conn.execute(sql_plan.insert_sql, params)


def _restore_insert_params(
    table_name: str,
    row: Mapping[str, Any],
    plan: RecoveryRestorePlan,
    source_profile_to_target: Mapping[int, int],
) -> tuple[Any, ...]:
    now = plan.now_ts
    if table_name in {"adblock_lists", "adblock_settings"}:
        return tuple(row[column] for column in _RESTORE_SQL_BY_TABLE[table_name].columns)
    if table_name == "adblock_artifact_revisions":
        return (
            row["artifact_sha256"],
            row["archive_blob"],
            row["report_json"],
            row["settings_version"],
            row["enabled_lists_json"],
            now,
        )
    if table_name == "certificate_bundle_revisions":
        return (
            row["bundle_sha256"],
            row["cert_sha256"],
            row["cert_pem"],
            row["key_pem"],
            row["chain_pem"],
            now,
        )
    if table_name == "admin_ui_https_settings":
        return (row["enabled"], row["certfile"], row["keyfile"], row["san_tokens"], now)
    if table_name == "observability_settings":
        return (row["retention_days"], now)
    if table_name == "directory_auth_profiles":
        return (*tuple(row[column] for column in _RESTORE_SQL_BY_TABLE[table_name].columns), now)
    if table_name == "saml_auth_profiles":
        return (*tuple(row[column] for column in _RESTORE_SQL_BY_TABLE[table_name].columns), now)
    if table_name == "proxy_config_revisions":
        return (plan.target_proxy_id, row["config_sha256"], row["config_text"], now)
    if table_name in {"pac_direct_domains", "pac_direct_dst_nets"}:
        source_id = int(row["source_profile_id"])
        target_id = int(source_profile_to_target.get(source_id) or 0)
        if target_id <= 0:
            msg = f"missing target PAC profile id for {table_name}"
            raise _recovery_error(msg)
        value_column = "domain" if table_name == "pac_direct_domains" else "cidr"
        return (target_id, row[value_column])
    if table_name == "pac_backup_proxies":
        return (plan.target_proxy_id, row["proxy_host"], row["proxy_port"], row["position"], now)
    if table_name == "pac_proxy_chain_settings":
        return (plan.target_proxy_id, row["direct_enabled"], now)
    if table_name == "policy_exceptions":
        return (
            plan.target_proxy_id,
            row["block_type"],
            row["client_ip"],
            row["domain"],
            row["category"],
            now,
            now,
            row["admin_note"],
            row["expires_ts"],
        )
    if table_name in {"sslfilter_domains", "sslfilter_src_nets"}:
        value_column = "domain" if table_name == "sslfilter_domains" else "cidr"
        return (plan.target_proxy_id, row["policy"], row[value_column], now)
    if table_name == "sslfilter_settings":
        return (plan.target_proxy_id, row["key"], row["value"])
    if table_name == "webfilter_settings":
        return (plan.target_proxy_id, row["k"], row["v"])
    if table_name == "webfilter_whitelist":
        return (plan.target_proxy_id, row["pattern"], now)
    if table_name == "adblock_proxy_meta":
        return (plan.target_proxy_id, row["k"], row["v"])
    if table_name == "observability_report_schedules":
        return (
            plan.target_proxy_id,
            row["enabled"],
            row["name"],
            row["cadence"],
            row["recipients"],
            row["pane"],
            row["report_format"],
            row["privacy"],
            row["window_seconds"],
            now,
            now,
        )
    msg = f"missing restore insert parameter plan for {table_name}"
    raise _recovery_error(msg)


def _delete_known_fresh_defaults(conn: Any, proxy_id: str) -> None:
    conn.execute("DELETE FROM adblock_lists")
    conn.execute("DELETE FROM adblock_settings")
    conn.execute("DELETE FROM admin_ui_https_settings WHERE id=1")
    conn.execute("DELETE FROM observability_settings WHERE id=1")
    conn.execute("DELETE FROM directory_auth_profiles")
    conn.execute("DELETE FROM saml_auth_profiles")
    conn.execute("DELETE FROM pac_proxy_chain_settings WHERE proxy_id=%s", (proxy_id,))
    conn.execute("DELETE FROM webfilter_settings WHERE proxy_id=%s AND k IN ('enabled','blocked_categories')", (proxy_id,))


def _insert_adoption_marker(
    conn: Any,
    plan: RecoveryRestorePlan,
    target_control_plane_id: str,
) -> None:
    conn.execute(
        """
        INSERT INTO proxy_recovery_adoptions(
            proxy_id, target_control_plane_id, source_control_plane_id,
            bundle_content_sha256, status, adopted_ts, detail
        ) VALUES(%s,%s,%s,%s,%s,%s,'')
        """,
        (
            plan.target_proxy_id,
            target_control_plane_id,
            plan.source_control_plane_id,
            plan.bundle_content_sha256,
            _ADOPTION_STATUS_ADOPTED,
            plan.now_ts,
        ),
    )


validate_restore_sql_plan_coverage()


def normalize_proxy_id(proxy_id: str) -> str:
    normalized = proxy_id.strip().lower()
    if not _PROXY_ID_RE.fullmatch(normalized) or ".." in normalized:
        msg = "invalid proxy id for recovery bundle"
        raise _recovery_error(msg)
    return normalized


def normalize_control_plane_identity(source_control_plane_id: str) -> str:
    normalized = str(source_control_plane_id or "").strip().lower()
    if not _CONTROL_PLANE_ID_RE.fullmatch(normalized):
        msg = "invalid recovery source control plane identity"
        raise _recovery_error(msg)
    return normalized


def bundle_path_for_proxy(
    proxy_id: str, recovery_dir: Path | str | None = None
) -> Path:
    root = resolve_recovery_dir(recovery_dir)
    return root / f"{normalize_proxy_id(proxy_id)}.bundle.json"


def key_path_for_proxy(proxy_id: str, recovery_dir: Path | str | None = None) -> Path:
    root = resolve_recovery_dir(recovery_dir)
    return root / f"{normalize_proxy_id(proxy_id)}.hmac.key"


def resolve_recovery_dir(recovery_dir: Path | str | None = None) -> Path:
    if recovery_dir is not None:
        return Path(recovery_dir)
    configured = os.environ.get(RECOVERY_DIR_ENV)
    if configured:
        return Path(configured)
    return DEFAULT_RECOVERY_DIR


def create_recovery_bundle(
    proxy_id: str,
    tables: Mapping[str, Iterable[Mapping[str, Any]]] | Iterable[RecoveryTablePayload],
    *,
    source_control_plane_id: str,
    schema_version: int = DATA_SCHEMA_VERSION,
    created_ts: str | None = None,
    recovery_dir: Path | str | None = None,
    max_bundle_bytes: int = DEFAULT_MAX_BUNDLE_BYTES,
) -> RecoveryBundle:
    unsigned = _unsigned_payload(
        proxy_id,
        tables,
        source_control_plane_id=source_control_plane_id,
        schema_version=schema_version,
        created_ts=created_ts,
    )
    sealed = _seal_unsigned_payload(
        unsigned,
        get_or_create_signing_key(unsigned["proxy_id"], recovery_dir),
        max_bundle_bytes=max_bundle_bytes,
    )
    return _bundle_from_envelope(sealed)


def write_recovery_bundle(
    proxy_id: str,
    tables: Mapping[str, Iterable[Mapping[str, Any]]] | Iterable[RecoveryTablePayload],
    *,
    source_control_plane_id: str,
    schema_version: int = DATA_SCHEMA_VERSION,
    created_ts: str | None = None,
    recovery_dir: Path | str | None = None,
    max_bundle_bytes: int = DEFAULT_MAX_BUNDLE_BYTES,
) -> Path:
    unsigned = _unsigned_payload(
        proxy_id,
        tables,
        source_control_plane_id=source_control_plane_id,
        schema_version=schema_version,
        created_ts=created_ts,
    )
    key = get_or_create_signing_key(unsigned["proxy_id"], recovery_dir)
    sealed = _seal_unsigned_payload(unsigned, key, max_bundle_bytes=max_bundle_bytes)
    path = bundle_path_for_proxy(unsigned["proxy_id"], recovery_dir)
    _atomic_write_private(path, serialize_envelope(sealed), 0o600)
    return path


def read_recovery_bundle(
    proxy_id: str,
    *,
    expected_source_control_plane_id: str | None = None,
    recovery_dir: Path | str | None = None,
    max_bundle_bytes: int = DEFAULT_MAX_BUNDLE_BYTES,
) -> RecoveryBundle:
    normalized = normalize_proxy_id(proxy_id)
    path = bundle_path_for_proxy(normalized, recovery_dir)
    raw = _read_private_regular_file(path, max_bytes=max_bundle_bytes)
    key = read_signing_key(normalized, recovery_dir)
    return parse_recovery_bundle(
        raw,
        expected_proxy_id=normalized,
        expected_source_control_plane_id=expected_source_control_plane_id,
        key=key,
    )


def serialize_recovery_bundle(bundle: RecoveryBundle) -> bytes:
    envelope = {
        "format_version": bundle.format_version,
        "proxy_id": bundle.proxy_id,
        "source_control_plane_id": bundle.source_control_plane_id,
        "created_ts": bundle.created_ts,
        "schema_version": bundle.schema_version,
        "tables": [_table_to_encoded_json(table) for table in bundle.tables],
        "integrity": {
            "content_sha256": bundle.integrity.content_sha256,
            "mac_alg": bundle.integrity.mac_alg,
            "mac": bundle.integrity.mac,
        },
    }
    return serialize_envelope(envelope)


def parse_recovery_bundle(
    raw: bytes,
    *,
    expected_proxy_id: str,
    expected_source_control_plane_id: str | None = None,
    key: bytes,
    max_bundle_bytes: int = DEFAULT_MAX_BUNDLE_BYTES,
) -> RecoveryBundle:
    if len(raw) > max_bundle_bytes:
        msg = "recovery bundle exceeds maximum size"
        raise _recovery_error(msg)
    envelope = _json_loads_no_duplicates(raw)
    _validate_envelope_shape(
        envelope,
        expected_proxy_id=expected_proxy_id,
        expected_source_control_plane_id=expected_source_control_plane_id,
    )
    unsigned = {name: envelope[name] for name in sorted(_UNSIGNED_KEYS)}
    canonical_unsigned = _canonical_json_bytes(unsigned)
    integrity = envelope["integrity"]
    content_sha256 = hashlib.sha256(canonical_unsigned).hexdigest()
    if not hmac.compare_digest(content_sha256, integrity["content_sha256"]):
        msg = "recovery bundle content digest mismatch"
        raise _recovery_error(msg)
    mac = hmac.new(key, canonical_unsigned, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(mac, integrity["mac"]):
        msg = "recovery bundle MAC mismatch"
        raise _recovery_error(msg)
    return _bundle_from_envelope(envelope)


def serialize_envelope(envelope: Mapping[str, Any]) -> bytes:
    return _canonical_json_bytes(envelope) + b"\n"


def get_or_create_signing_key(
    proxy_id: str,
    recovery_dir: Path | str | None = None,
) -> bytes:
    normalized = normalize_proxy_id(proxy_id)
    root = _ensure_private_dir(resolve_recovery_dir(recovery_dir))
    path = key_path_for_proxy(normalized, root)
    if path.exists() or path.is_symlink():
        return read_signing_key(normalized, root)

    key = secrets.token_bytes(KEY_BYTES)
    tmp_path = root / f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=True) as handle:
            handle.write(key)
            handle.flush()
            os.fsync(handle.fileno())
        Path(tmp_path).chmod(0o600)
        try:
            os.link(tmp_path, path)
        except FileExistsError:
            return read_signing_key(normalized, root)
        _fsync_dir(root)
    finally:
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass
    return read_signing_key(normalized, root)


def read_signing_key(proxy_id: str, recovery_dir: Path | str | None = None) -> bytes:
    path = key_path_for_proxy(proxy_id, recovery_dir)
    key = _read_private_regular_file(path, max_bytes=KEY_BYTES)
    if len(key) != KEY_BYTES:
        msg = "invalid recovery signing key length"
        raise _recovery_error(msg)
    return key


def _unsigned_payload(
    proxy_id: str,
    tables: Mapping[str, Iterable[Mapping[str, Any]]] | Iterable[RecoveryTablePayload],
    *,
    source_control_plane_id: str,
    schema_version: int,
    created_ts: str | None,
) -> dict[str, Any]:
    if not isinstance(schema_version, int) or schema_version < 1:
        msg = "invalid recovery schema version"
        raise _recovery_error(msg)
    timestamp = created_ts or datetime.now(UTC).replace(
        microsecond=0
    ).isoformat().replace("+00:00", "Z")
    _validate_created_ts(timestamp)
    return {
        "format_version": FORMAT_VERSION,
        "proxy_id": normalize_proxy_id(proxy_id),
        "source_control_plane_id": normalize_control_plane_identity(
            source_control_plane_id,
        ),
        "created_ts": timestamp,
        "schema_version": schema_version,
        "tables": [
            _table_to_encoded_json(table) for table in _normalize_tables(tables)
        ],
    }


def _seal_unsigned_payload(
    unsigned: Mapping[str, Any],
    key: bytes,
    *,
    max_bundle_bytes: int,
) -> dict[str, Any]:
    canonical_unsigned = _canonical_json_bytes(unsigned)
    envelope = dict(unsigned)
    envelope["integrity"] = {
        "content_sha256": hashlib.sha256(canonical_unsigned).hexdigest(),
        "mac_alg": MAC_ALGORITHM,
        "mac": hmac.new(key, canonical_unsigned, hashlib.sha256).hexdigest(),
    }
    serialized = serialize_envelope(envelope)
    if len(serialized) > max_bundle_bytes:
        msg = "recovery bundle exceeds maximum size"
        raise _recovery_error(msg)
    return envelope


def _normalize_tables(
    tables: Mapping[str, Iterable[Mapping[str, Any]]] | Iterable[RecoveryTablePayload],
) -> tuple[RecoveryTablePayload, ...]:
    payloads: list[RecoveryTablePayload] = []
    if isinstance(tables, Mapping):
        for name, rows in tables.items():
            payloads.append(RecoveryTablePayload(name=name, rows=tuple(rows)))
    else:
        payloads.extend(tables)

    by_name: dict[str, RecoveryTablePayload] = {}
    for table in payloads:
        if not isinstance(table, RecoveryTablePayload):
            msg = "invalid recovery table payload entry"
            raise _recovery_error(msg)
        if table.name not in _REGISTRY_BY_TABLE:
            msg = f"table is not in recovery scope registry: {table.name}"
            raise _recovery_error(msg)
        if table.name in by_name:
            msg = f"duplicate recovery table payload: {table.name}"
            raise _recovery_error(msg)
        rows = _normalize_rows(table.rows)
        by_name[table.name] = RecoveryTablePayload(table.name, rows)

    return tuple(
        by_name[spec.table_name]
        for spec in TABLE_SCOPE_REGISTRY
        if spec.table_name in by_name
    )


def _normalize_rows(rows: Sequence[Mapping[str, Any]]) -> tuple[Mapping[str, Any], ...]:
    normalized_rows: list[Mapping[str, Any]] = []
    for row in rows:
        if not isinstance(row, Mapping):
            msg = "recovery table rows must be mappings"
            raise _recovery_error(msg)
        for key in row:
            if not isinstance(key, str) or not key:
                msg = "recovery row keys must be non-empty strings"
                raise _recovery_error(msg)
        normalized_rows.append(dict(row))
    return tuple(normalized_rows)


def _table_to_encoded_json(table: RecoveryTablePayload) -> dict[str, Any]:
    return {
        "name": table.name,
        "rows": [_encode_json_value(dict(row)) for row in table.rows],
    }


def _table_from_encoded_json(table: Mapping[str, Any]) -> RecoveryTablePayload:
    if set(table) != {"name", "rows"}:
        msg = "invalid recovery table payload shape"
        raise _recovery_error(msg)
    name = table["name"]
    rows = table["rows"]
    if name not in _REGISTRY_BY_TABLE:
        msg = f"table is not in recovery scope registry: {name}"
        raise _recovery_error(msg)
    if not isinstance(rows, list):
        msg = "recovery table rows must be a list"
        raise _recovery_error(msg)
    decoded_rows: list[Mapping[str, Any]] = []
    for row in rows:
        decoded = _decode_json_value(row)
        if not isinstance(decoded, dict):
            msg = "recovery table row must decode to an object"
            raise _recovery_error(msg)
        decoded_rows.append(decoded)
    return RecoveryTablePayload(name=name, rows=tuple(decoded_rows))


def _encode_json_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return {
            _RESERVED_ENCODING_KEY: _BYTES_ENCODING,
            "data": base64.b64encode(value).decode("ascii"),
        }
    if isinstance(value, bytearray):
        return _encode_json_value(bytes(value))
    if isinstance(value, Mapping):
        if _RESERVED_ENCODING_KEY in value:
            msg = "reserved recovery encoding key in JSON object"
            raise _recovery_error(msg)
        encoded: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str) or not key:
                msg = "JSON object keys must be non-empty strings"
                raise _recovery_error(msg)
            encoded[key] = _encode_json_value(item)
        return encoded
    if isinstance(value, list | tuple):
        return [_encode_json_value(item) for item in value]
    if isinstance(value, str | int | float | bool) or value is None:
        return value
    msg = f"unsupported recovery value type: {type(value).__name__}"
    raise _recovery_error(msg)


def _decode_json_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        if _RESERVED_ENCODING_KEY in value:
            if set(value) != {_RESERVED_ENCODING_KEY, "data"}:
                msg = "malformed recovery bytes encoding"
                raise _recovery_error(msg)
            if value[_RESERVED_ENCODING_KEY] != _BYTES_ENCODING:
                msg = "unknown recovery value encoding"
                raise _recovery_error(msg)
            data = value["data"]
            if not isinstance(data, str):
                msg = "recovery bytes data must be base64 text"
                raise _recovery_error(msg)
            try:
                decoded = base64.b64decode(data.encode("ascii"), validate=True)
            except (UnicodeEncodeError, binascii.Error) as exc:
                msg = "malformed recovery bytes base64"
                raise _recovery_error(msg) from exc
            if base64.b64encode(decoded).decode("ascii") != data:
                msg = "non-canonical recovery bytes base64"
                raise _recovery_error(msg)
            return decoded
        return {key: _decode_json_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_decode_json_value(item) for item in value]
    if isinstance(value, str | int | float | bool) or value is None:
        return value
    msg = "unsupported JSON value in recovery bundle"
    raise _recovery_error(msg)


def _validate_envelope_shape(
    envelope: Any,
    *,
    expected_proxy_id: str,
    expected_source_control_plane_id: str | None = None,
) -> None:
    if not isinstance(envelope, dict) or set(envelope) != _ENVELOPE_KEYS:
        msg = "invalid recovery bundle envelope"
        raise _recovery_error(msg)
    format_version = envelope["format_version"]
    if not isinstance(format_version, int):
        msg = "invalid recovery bundle format version"
        raise _recovery_error(msg)
    if format_version > FORMAT_VERSION:
        msg = "unsupported future recovery bundle format version"
        raise _recovery_error(msg)
    if format_version != FORMAT_VERSION:
        msg = "unsupported recovery bundle format version"
        raise _recovery_error(msg)
    proxy_id = envelope["proxy_id"]
    if normalize_proxy_id(proxy_id) != normalize_proxy_id(expected_proxy_id):
        msg = "recovery bundle proxy id does not match target proxy"
        raise _recovery_error(msg)
    source_control_plane_id = normalize_control_plane_identity(
        envelope["source_control_plane_id"],
    )
    expected_identity = (
        normalize_control_plane_identity(expected_source_control_plane_id)
        if expected_source_control_plane_id is not None
        else None
    )
    if expected_identity is not None and source_control_plane_id != expected_identity:
        msg = "recovery bundle source control plane identity does not match"
        raise _recovery_error(msg)
    schema_version = envelope["schema_version"]
    if not isinstance(schema_version, int) or schema_version < 1:
        msg = "invalid recovery bundle schema version"
        raise _recovery_error(msg)
    _validate_created_ts(envelope["created_ts"])
    tables = envelope["tables"]
    if not isinstance(tables, list):
        msg = "recovery bundle tables must be a list"
        raise _recovery_error(msg)
    seen: set[str] = set()
    last_order = -1
    for table in tables:
        if not isinstance(table, dict):
            msg = "invalid recovery table entry"
            raise _recovery_error(msg)
        if set(table) != {"name", "rows"}:
            msg = "invalid recovery table payload shape"
            raise _recovery_error(msg)
        name = table["name"]
        if not isinstance(name, str) or name not in _REGISTRY_BY_TABLE:
            msg = "invalid recovery table name"
            raise _recovery_error(msg)
        if name in seen:
            msg = f"duplicate recovery table payload: {name}"
            raise _recovery_error(msg)
        order = _REGISTRY_BY_TABLE[name].dependency_order
        if order <= last_order:
            msg = "recovery table payload is not dependency ordered"
            raise _recovery_error(msg)
        seen.add(name)
        last_order = order
        _table_from_encoded_json(table)
    integrity = envelope["integrity"]
    if not isinstance(integrity, dict) or set(integrity) != _INTEGRITY_KEYS:
        msg = "invalid recovery bundle integrity metadata"
        raise _recovery_error(msg)
    if integrity["mac_alg"] != MAC_ALGORITHM:
        msg = "unsupported recovery bundle MAC algorithm"
        raise _recovery_error(msg)
    if not isinstance(integrity["content_sha256"], str) or not _HEX_SHA256_RE.fullmatch(
        integrity["content_sha256"]
    ):
        msg = "invalid recovery bundle content digest"
        raise _recovery_error(msg)
    if not isinstance(integrity["mac"], str) or not _HEX_SHA256_RE.fullmatch(
        integrity["mac"]
    ):
        msg = "invalid recovery bundle MAC"
        raise _recovery_error(msg)


def _validate_created_ts(created_ts: Any) -> None:
    if not isinstance(created_ts, str) or not created_ts:
        msg = "invalid recovery bundle creation timestamp"
        raise _recovery_error(msg)
    parseable = created_ts[:-1] + "+00:00" if created_ts.endswith("Z") else created_ts
    try:
        datetime.fromisoformat(parseable)
    except ValueError as exc:
        msg = "invalid recovery bundle creation timestamp"
        raise _recovery_error(msg) from exc


def _bundle_from_envelope(envelope: Mapping[str, Any]) -> RecoveryBundle:
    return RecoveryBundle(
        format_version=envelope["format_version"],
        proxy_id=envelope["proxy_id"],
        source_control_plane_id=envelope["source_control_plane_id"],
        created_ts=envelope["created_ts"],
        schema_version=envelope["schema_version"],
        tables=tuple(_table_from_encoded_json(table) for table in envelope["tables"]),
        integrity=IntegrityMetadata(
            content_sha256=envelope["integrity"]["content_sha256"],
            mac_alg=envelope["integrity"]["mac_alg"],
            mac=envelope["integrity"]["mac"],
        ),
    )


def _canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        msg = "recovery bundle is not canonical JSON serializable"
        raise _recovery_error(msg) from exc


def _json_loads_no_duplicates(raw: bytes) -> Any:
    try:
        text = raw.decode("utf-8")
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        msg = "malformed recovery bundle JSON"
        raise _recovery_error(msg) from exc


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            msg = f"duplicate JSON key in recovery bundle: {key}"
            raise _recovery_error(msg)
        obj[key] = value
    return obj


def _reject_json_constant(value: str) -> None:
    msg = f"unsupported JSON constant in recovery bundle: {value}"
    raise _recovery_error(msg)


def _ensure_private_dir(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    stat_result = path.lstat()
    if stat.S_ISLNK(stat_result.st_mode) or not stat.S_ISDIR(stat_result.st_mode):
        msg = "recovery path is not a private directory"
        raise _recovery_error(msg)
    Path(path).chmod(0o700)
    return path


def _atomic_write_private(path: Path, data: bytes, mode: int) -> None:
    root = _ensure_private_dir(path.parent)
    if path.exists() or path.is_symlink():
        _stat_regular_nosymlink(path)
    tmp_path = root / f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "wb", closefd=True) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        Path(tmp_path).chmod(mode)
        Path(tmp_path).replace(path)
        Path(path).chmod(mode)
        _fsync_dir(root)
    finally:
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass


def _read_private_regular_file(path: Path, *, max_bytes: int) -> bytes:
    stat_result = _stat_regular_nosymlink(path)
    if stat_result.st_size > max_bytes:
        msg = "recovery file exceeds maximum size"
        raise _recovery_error(msg)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        opened_stat = os.fstat(fd)
        if not stat.S_ISREG(opened_stat.st_mode):
            msg = "recovery file is not a regular file"
            raise _recovery_error(msg)
        if opened_stat.st_size > max_bytes:
            msg = "recovery file exceeds maximum size"
            raise _recovery_error(msg)
        with os.fdopen(fd, "rb", closefd=True) as handle:
            data = handle.read(max_bytes + 1)
    except OSError:
        os.close(fd)
        raise
    if len(data) > max_bytes:
        msg = "recovery file exceeds maximum size"
        raise _recovery_error(msg)
    return data


def _stat_regular_nosymlink(path: Path) -> os.stat_result:
    try:
        stat_result = path.lstat()
    except FileNotFoundError as exc:
        msg = "recovery file does not exist"
        raise _recovery_error(msg) from exc
    if stat.S_ISLNK(stat_result.st_mode):
        msg = "recovery file must not be a symlink"
        raise _recovery_error(msg)
    if not stat.S_ISREG(stat_result.st_mode):
        msg = "recovery file is not a regular file"
        raise _recovery_error(msg)
    return stat_result


def _fsync_dir(path: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    try:
        fd = os.open(path, flags)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        return
    finally:
        os.close(fd)


validate_recovery_registry()
