from __future__ import annotations

# ruff: noqa: EM101, EM102, TRY003
import hashlib
import time
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Final, Literal

from services import proxy_recovery
from services.db import connect
from services.proxy_recovery_db import recovery_export_query_plans
from services.proxy_write_guard import (
    ProxyLifecycleWriteError,
    proxy_lifecycle_lock_name,
    resolve_proxy_write_id,
)
from services.report_schedule_recipients import normalize_report_schedule_recipients
from services.schema_lifecycle import read_control_plane_identity


class ProxyRecoveryRestoreError(proxy_recovery.ProxyRecoveryError):
    """Raised when a recovery bundle is not safe to restore."""


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


@dataclass(frozen=True)
class RestoreTablePlan:
    table_name: str
    columns: tuple[str, ...]
    rows: tuple[tuple[Any, ...], ...]


@dataclass(frozen=True)
class RestorePlan:
    proxy_id: str
    source_control_plane_id: str
    bundle_content_sha256: str
    tables: tuple[RestoreTablePlan, ...]
    now_ts: int

    @property
    def row_count(self) -> int:
        return sum(len(table.rows) for table in self.tables)


@dataclass(frozen=True)
class RestoreResult:
    status: RestoreStatus
    proxy_id: str
    target_proxy_id: str
    source_control_plane_id: str
    target_control_plane_id: str
    bundle_content_sha256: str
    restored_tables: tuple[str, ...]
    restored_rows: int
    adopted_ts: int = 0
    reason: str = ""


_EXPECTED_TABLE_COLUMNS: Final = MappingProxyType(
    {plan.table_name: plan.columns for plan in recovery_export_query_plans()}
)
_EXPECTED_TABLE_ORDER: Final = tuple(_EXPECTED_TABLE_COLUMNS)

_INT_COLUMNS: Final = frozenset(
    {
        "enabled",
        "settings_version",
        "use_starttls",
        "verify_tls",
        "timeout_seconds",
        "require_https",
        "max_metadata_bytes",
        "source_profile_id",
        "proxy_port",
        "position",
        "direct_enabled",
        "expires_ts",
        "retention_days",
        "privacy",
        "window_seconds",
    }
)
_BYTES_COLUMNS: Final = frozenset({"archive_blob"})
_HEX_SHA_COLUMNS: Final = frozenset({"artifact_sha256", "bundle_sha256", "cert_sha256", "config_sha256"})
_PROXY_COLUMNS: Final = frozenset({"proxy_id"})

_MAX_ROWS_BY_TABLE: Final = MappingProxyType(
    {
        "adblock_lists": 100,
        "adblock_settings": 50,
        "adblock_artifact_revisions": 1,
        "certificate_bundle_revisions": 1,
        "admin_ui_https_settings": 1,
        "observability_settings": 1,
        "directory_auth_profiles": 10,
        "saml_auth_profiles": 10,
        "proxy_config_revisions": 1,
        "pac_profiles": 500,
        "pac_direct_domains": 10_000,
        "pac_direct_dst_nets": 10_000,
        "pac_backup_proxies": 500,
        "pac_proxy_chain_settings": 1,
        "policy_exceptions": 5_000,
        "sslfilter_domains": 10_000,
        "sslfilter_src_nets": 10_000,
        "sslfilter_settings": 100,
        "webfilter_settings": 2,
        "webfilter_whitelist": 10_000,
        "adblock_proxy_meta": 0,
        "observability_report_schedules": 200,
    }
)

_NATURAL_KEYS: Final = MappingProxyType(
    {
        "adblock_lists": ("key",),
        "adblock_settings": ("k",),
        "adblock_artifact_revisions": ("artifact_sha256",),
        "certificate_bundle_revisions": ("bundle_sha256",),
        "admin_ui_https_settings": (),
        "observability_settings": (),
        "directory_auth_profiles": ("provider",),
        "saml_auth_profiles": ("provider",),
        "proxy_config_revisions": ("proxy_id",),
        "pac_profiles": ("source_profile_id",),
        "pac_direct_domains": ("source_profile_id", "domain"),
        "pac_direct_dst_nets": ("source_profile_id", "cidr"),
        "pac_backup_proxies": ("proxy_id", "position"),
        "pac_proxy_chain_settings": ("proxy_id",),
        "policy_exceptions": (
            "proxy_id",
            "block_type",
            "client_ip",
            "domain",
            "category",
            "expires_ts",
        ),
        "sslfilter_domains": ("proxy_id", "policy", "domain"),
        "sslfilter_src_nets": ("proxy_id", "policy", "cidr"),
        "sslfilter_settings": ("proxy_id", "key"),
        "webfilter_settings": ("proxy_id", "k"),
        "webfilter_whitelist": ("proxy_id", "pattern"),
        "adblock_proxy_meta": ("proxy_id", "k"),
        "observability_report_schedules": (
            "proxy_id",
            "name",
            "cadence",
            "recipients",
            "pane",
            "report_format",
            "window_seconds",
        ),
    }
)

_PAC_CHILD_TABLES: Final = frozenset({"pac_direct_domains", "pac_direct_dst_nets"})
_ACTIVE_REVISION_TABLES: Final = frozenset(
    {
        "adblock_artifact_revisions",
        "certificate_bundle_revisions",
        "proxy_config_revisions",
    }
)
_EXACT_WEBFILTER_KEYS: Final = frozenset({"enabled", "blocked_categories"})
_OBSERVABILITY_REPORT_SCHEDULE_PANES: Final = frozenset(
    {
        "reports",
        "overview",
        "destinations",
        "clients",
        "cache",
        "ssl",
        "security",
        "performance",
    },
)

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

_ADOPTION_MARKER_TABLE: Final = "proxy_recovery_adoptions"
_ADOPTION_MARKER_PAIR_SELECT_SQL: Final = (
    "SELECT source_control_plane_id, target_control_plane_id, bundle_content_sha256, status, detail "
    "FROM proxy_recovery_adoptions "
    "WHERE proxy_id=%s AND target_control_plane_id=%s LIMIT 1"
)
_ADOPTION_MARKER_PROXY_SELECT_SQL: Final = (
    "SELECT target_control_plane_id "
    "FROM proxy_recovery_adoptions WHERE proxy_id=%s LIMIT 2"
)
_ADOPTION_MARKER_INSERT_SQL: Final = """
    INSERT INTO proxy_recovery_adoptions(
        proxy_id, target_control_plane_id, source_control_plane_id, bundle_content_sha256,
        status, adopted_ts, detail
    ) VALUES(%s,%s,%s,%s,'adopted',%s,'')
    """

_DELETE_DEFAULTS_SQL: Final = (
    "DELETE FROM adblock_lists",
    "DELETE FROM adblock_settings",
    "DELETE FROM adblock_artifact_revisions",
    "DELETE FROM certificate_bundle_revisions",
    "DELETE FROM admin_ui_https_settings WHERE id=1",
    "DELETE FROM observability_settings WHERE id=1",
    "DELETE FROM directory_auth_profiles",
    "DELETE FROM saml_auth_profiles",
)

_DELETE_PROXY_DEFAULTS_SQL: Final = (
    "DELETE FROM proxy_config_revisions WHERE proxy_id=%s AND is_active=1",
    "DELETE FROM pac_direct_domains WHERE profile_id IN (SELECT id FROM pac_profiles WHERE proxy_id=%s)",
    "DELETE FROM pac_direct_dst_nets WHERE profile_id IN (SELECT id FROM pac_profiles WHERE proxy_id=%s)",
    "DELETE FROM pac_profiles WHERE proxy_id=%s",
    "DELETE FROM pac_backup_proxies WHERE proxy_id=%s",
    "DELETE FROM pac_proxy_chain_settings WHERE proxy_id=%s",
    "DELETE FROM policy_exceptions WHERE proxy_id=%s",
    "DELETE FROM sslfilter_domains WHERE proxy_id=%s",
    "DELETE FROM sslfilter_src_nets WHERE proxy_id=%s",
    "DELETE FROM sslfilter_settings WHERE proxy_id=%s",
    "DELETE FROM webfilter_settings WHERE proxy_id=%s AND k IN ('enabled','blocked_categories')",
    "DELETE FROM webfilter_whitelist WHERE proxy_id=%s",
    "DELETE FROM adblock_proxy_meta WHERE proxy_id=%s",
    "DELETE FROM observability_report_schedules WHERE proxy_id=%s",
)


def build_restore_plan(
    bundle: proxy_recovery.RecoveryBundle,
    target_proxy_id: str,
    *,
    now_ts: int | None = None,
) -> RestorePlan:
    proxy_key = proxy_recovery.normalize_proxy_id(target_proxy_id)
    restore_ts = int(time.time() if now_ts is None else now_ts)
    bundle_proxy = proxy_recovery.normalize_proxy_id(bundle.proxy_id)
    if bundle_proxy != proxy_key:
        raise ProxyRecoveryRestoreError("recovery bundle proxy id does not match target proxy id")
    source_control_plane_id = _normalize_control_plane_id(bundle.source_control_plane_id)
    bundle_content_sha256 = _normalize_sha256_hex(bundle.integrity.content_sha256)

    payload_by_table: dict[str, proxy_recovery.RecoveryTablePayload] = {}
    for payload in bundle.tables:
        if payload.name in payload_by_table:
            raise ProxyRecoveryRestoreError(f"duplicate recovery table payload {payload.name!r}")
        payload_by_table[payload.name] = payload
    if tuple(payload_by_table) != _EXPECTED_TABLE_ORDER:
        raise ProxyRecoveryRestoreError("recovery bundle table coverage does not match restore contract")

    pac_profile_ids: set[int] = set()
    plans: list[RestoreTablePlan] = []
    for table_name in _EXPECTED_TABLE_ORDER:
        payload = payload_by_table[table_name]
        expected_columns = _EXPECTED_TABLE_COLUMNS[table_name]
        rows = _validate_rows(
            table_name,
            payload.rows,
            expected_columns,
            proxy_key,
            restore_ts,
        )
        if table_name == "pac_profiles":
            pac_profile_ids = {int(row[0]) for row in rows}
        if table_name in _PAC_CHILD_TABLES:
            _validate_pac_children(table_name, rows, pac_profile_ids)
        plans.append(RestoreTablePlan(table_name, expected_columns, rows))
    return RestorePlan(
        proxy_id=proxy_key,
        source_control_plane_id=source_control_plane_id,
        bundle_content_sha256=bundle_content_sha256,
        tables=tuple(plans),
        now_ts=restore_ts,
    )


def restore_recovery_bundle(
    conn: Any,
    bundle: proxy_recovery.RecoveryBundle,
    target_proxy_id: str,
    *,
    now_ts: int | None = None,
    lock_timeout_seconds: int = 10,
) -> RestoreResult:
    plan = build_restore_plan(bundle, target_proxy_id, now_ts=now_ts)
    target_identity = _read_target_identity(conn)
    skip = _skip_result_if_already_decided(conn, plan, target_identity)
    if skip is not None:
        return skip
    freshness_reason = _freshness_failure_reason(conn, plan.proxy_id)
    if freshness_reason:
        return _restore_result(
            _RESTORE_STATUS_NOT_ELIGIBLE,
            plan,
            target_identity,
            reason=freshness_reason,
        )
    first_decision = resolve_proxy_write_id(
        conn,
        plan.proxy_id,
        allow_alias=False,
        require_registered=True,
        use_cache=False,
    )
    if first_decision.proxy_id != plan.proxy_id:
        raise ProxyRecoveryRestoreError("target proxy id resolved unexpectedly during restore")

    lock_name = proxy_lifecycle_lock_name(plan.proxy_id)
    acquired = False
    in_transaction = False
    restored_identity = target_identity
    try:
        acquired = _acquire_lifecycle_lock(conn, lock_name, lock_timeout_seconds)
        second_decision = resolve_proxy_write_id(
            conn,
            plan.proxy_id,
            allow_alias=False,
            require_registered=True,
            use_cache=False,
        )
        if second_decision.proxy_id != plan.proxy_id:
            raise ProxyRecoveryRestoreError("target proxy id changed during restore lock acquisition")

        conn.execute("START TRANSACTION")
        in_transaction = True
        locked_identity = _read_target_identity(conn, for_update=True)
        skip = _skip_result_if_already_decided(
            conn,
            plan,
            locked_identity,
            for_update=True,
        )
        if skip is not None:
            conn.rollback()
            in_transaction = False
            return skip
        freshness_reason = _freshness_failure_reason(conn, plan.proxy_id)
        if freshness_reason:
            conn.rollback()
            in_transaction = False
            return _restore_result(
                _RESTORE_STATUS_NOT_ELIGIBLE,
                plan,
                locked_identity,
                reason=freshness_reason,
            )
        restored_identity = locked_identity
        _apply_restore_plan(conn, plan, locked_identity)
        conn.commit()
        in_transaction = False
    except Exception:
        if in_transaction:
            rollback = getattr(conn, "rollback", None)
            if callable(rollback):
                rollback()
        raise
    finally:
        if acquired:
            _release_lifecycle_lock(conn, lock_name)
    return _restore_result(
        _RESTORE_STATUS_ADOPTED,
        plan,
        restored_identity,
        adopted_ts=plan.now_ts,
    )


def read_validate_and_restore(
    target_proxy_id: str,
    *,
    connect_factory=connect,
    expected_source_control_plane_id: str | None = None,
    recovery_dir: str | None = None,
    now_ts: int | None = None,
    max_bundle_bytes: int = proxy_recovery.DEFAULT_MAX_BUNDLE_BYTES,
) -> RestoreResult:
    bundle = proxy_recovery.read_recovery_bundle(
        target_proxy_id,
        expected_source_control_plane_id=expected_source_control_plane_id,
        recovery_dir=recovery_dir,
        max_bundle_bytes=max_bundle_bytes,
    )
    with connect_factory() as conn:
        return restore_recovery_bundle(conn, bundle, target_proxy_id, now_ts=now_ts)


def validate_restore_contract() -> None:
    registry_tables = tuple(spec.table_name for spec in proxy_recovery.recovery_registry())
    if registry_tables != _EXPECTED_TABLE_ORDER:
        raise ProxyRecoveryRestoreError("restore contract does not match recovery registry")
    for plan in recovery_export_query_plans():
        if _EXPECTED_TABLE_COLUMNS[plan.table_name] != plan.columns:
            raise ProxyRecoveryRestoreError("restore columns do not match recovery export contract")


def _validate_rows(
    table_name: str,
    raw_rows: tuple[Any, ...],
    expected_columns: tuple[str, ...],
    proxy_key: str,
    now_ts: int,
) -> tuple[tuple[Any, ...], ...]:
    max_rows = _MAX_ROWS_BY_TABLE[table_name]
    if len(raw_rows) > max_rows:
        raise ProxyRecoveryRestoreError(f"recovery table {table_name} exceeds row limit")
    if table_name in _ACTIVE_REVISION_TABLES and len(raw_rows) > 1:
        raise ProxyRecoveryRestoreError(f"recovery table {table_name} has multiple active revisions")
    if table_name in {"admin_ui_https_settings", "observability_settings", "pac_proxy_chain_settings"} and len(raw_rows) > 1:
        raise ProxyRecoveryRestoreError(f"recovery table {table_name} has multiple singleton rows")

    rows: list[tuple[Any, ...]] = []
    seen_keys: set[tuple[Any, ...]] = set()
    natural_key = _NATURAL_KEYS[table_name]
    for raw in raw_rows:
        if not hasattr(raw, "keys"):
            raise ProxyRecoveryRestoreError(f"recovery row for {table_name} is not a mapping")
        raw_keys = tuple(raw.keys())
        if set(raw_keys) != set(expected_columns):
            raise ProxyRecoveryRestoreError(f"recovery row columns for {table_name} do not match restore contract")
        normalized = tuple(
            _normalize_column_value(table_name, column, raw[column], proxy_key, now_ts)
            for column in expected_columns
        )
        by_col = dict(zip(expected_columns, normalized, strict=True))
        if natural_key:
            key = tuple(by_col[column] for column in natural_key)
            if key in seen_keys:
                raise ProxyRecoveryRestoreError(f"duplicate natural key in recovery table {table_name}")
            seen_keys.add(key)
        rows.append(normalized)
    if table_name == "proxy_config_revisions":
        _validate_proxy_config_revision_digests(rows, expected_columns)
    if table_name == "webfilter_settings":
        keys = {dict(zip(expected_columns, row, strict=True))["k"] for row in rows}
        if not keys.issubset(_EXACT_WEBFILTER_KEYS):
            raise ProxyRecoveryRestoreError("webfilter restore contains unsupported setting key")
    if table_name == "observability_report_schedules":
        _validate_observability_report_schedule_rows(rows, expected_columns)
    return tuple(rows)


def _validate_observability_report_schedule_rows(
    rows: tuple[tuple[Any, ...], ...],
    columns: tuple[str, ...],
) -> None:
    for row in rows:
        by_col = dict(zip(columns, row, strict=True))
        cadence = str(by_col.get("cadence") or "").strip().lower()
        if cadence not in {"daily", "weekly"}:
            raise ProxyRecoveryRestoreError("observability_report_schedules cadence is invalid")
        report_format = str(by_col.get("report_format") or "").strip().lower()
        if report_format not in {"csv", "json", "jsonl"}:
            raise ProxyRecoveryRestoreError("observability_report_schedules report_format is invalid")
        pane = str(by_col.get("pane") or "").strip().lower()
        if pane not in _OBSERVABILITY_REPORT_SCHEDULE_PANES:
            raise ProxyRecoveryRestoreError("observability_report_schedules pane is invalid")
        window_seconds = int(by_col.get("window_seconds") or 0)
        if window_seconds < 300 or window_seconds > 7 * 24 * 3600:
            raise ProxyRecoveryRestoreError("observability_report_schedules window_seconds is invalid")


def _validate_proxy_config_revision_digests(
    rows: tuple[tuple[Any, ...], ...],
    columns: tuple[str, ...],
) -> None:
    if not rows:
        return
    sha_index = columns.index("config_sha256")
    text_index = columns.index("config_text")
    for row in rows:
        config_text = str(row[text_index] or "")
        expected_sha = hashlib.sha256(
            config_text.encode("utf-8", errors="replace"),
        ).hexdigest()
        if str(row[sha_index] or "") != expected_sha:
            raise ProxyRecoveryRestoreError(
                "proxy config revision digest does not match config text",
            )


def _normalize_column_value(
    table_name: str,
    column: str,
    value: Any,
    proxy_key: str,
    now_ts: int,
) -> Any:
    if column in _PROXY_COLUMNS:
        normalized = proxy_recovery.normalize_proxy_id(value)
        if normalized != proxy_key:
            raise ProxyRecoveryRestoreError(f"{table_name}.{column} does not match target proxy id")
        return normalized
    if column in _INT_COLUMNS:
        if isinstance(value, bool):
            value = int(value)
        elif not isinstance(value, int):
            raise ProxyRecoveryRestoreError(f"{table_name}.{column} must be an integer")
        if value < 0:
            raise ProxyRecoveryRestoreError(f"{table_name}.{column} must be non-negative")
        if table_name == "observability_report_schedules" and column in {"enabled", "privacy"} and value not in {0, 1}:
            raise ProxyRecoveryRestoreError(f"{table_name}.{column} must be 0 or 1")
        if column == "expires_ts" and value and value <= now_ts:
            raise ProxyRecoveryRestoreError("policy exception in recovery bundle is expired")
        return int(value)
    if column in _BYTES_COLUMNS:
        if not isinstance(value, bytes):
            raise ProxyRecoveryRestoreError(f"{table_name}.{column} must be bytes")
        return value
    if not isinstance(value, str):
        raise ProxyRecoveryRestoreError(f"{table_name}.{column} must be text")
    if "\x00" in value:
        raise ProxyRecoveryRestoreError(f"{table_name}.{column} contains a NUL byte")
    if len(value.encode("utf-8", errors="surrogatepass")) > 4 * 1024 * 1024:
        raise ProxyRecoveryRestoreError(f"{table_name}.{column} exceeds restore field size limit")
    if table_name == "observability_report_schedules":
        value = _normalize_observability_report_schedule_text(column, value)
    if column in _HEX_SHA_COLUMNS and (len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value)):
        raise ProxyRecoveryRestoreError(f"{table_name}.{column} must be lowercase sha256 hex")
    return value


def _normalize_observability_report_schedule_text(column: str, value: str) -> str:
    if column == "recipients":
        try:
            return normalize_report_schedule_recipients(value)
        except ValueError as exc:
            raise ProxyRecoveryRestoreError(
                "observability_report_schedules recipients are invalid",
            ) from exc
    if column in {"cadence", "pane", "report_format"}:
        return value.strip().lower()
    if column == "name":
        return value.strip()[:120]
    return value


def _validate_pac_children(
    table_name: str,
    rows: tuple[tuple[Any, ...], ...],
    pac_profile_ids: set[int],
) -> None:
    if not rows:
        return
    if not pac_profile_ids:
        raise ProxyRecoveryRestoreError(f"{table_name} has child rows without PAC profiles")
    for row in rows:
        source_profile_id = int(row[0])
        if source_profile_id not in pac_profile_ids:
            raise ProxyRecoveryRestoreError(f"{table_name} references an unknown PAC profile")


def _read_target_identity(conn: Any, *, for_update: bool = False) -> str:
    if not for_update:
        try:
            identity = read_control_plane_identity(conn)
        except Exception as exc:
            raise ProxyRecoveryRestoreError("target control plane identity is invalid") from exc
        if identity is None:
            raise ProxyRecoveryRestoreError("target control plane identity is missing")
        return _normalize_control_plane_id(identity)
    row = conn.execute(
        """
        SELECT control_plane_id
        FROM control_plane_identity
        WHERE id=1
        LIMIT 1
        FOR UPDATE
        """,
    ).fetchone()
    if row is None:
        raise ProxyRecoveryRestoreError("target control plane identity is missing")
    return _normalize_control_plane_id(_row_value(row, "control_plane_id", 0))


def _normalize_control_plane_id(value: Any) -> str:
    try:
        from services.schema_lifecycle import normalize_control_plane_identity

        return normalize_control_plane_identity(str(value or ""))
    except Exception as exc:
        raise ProxyRecoveryRestoreError("control plane identity is invalid") from exc


def _normalize_sha256_hex(value: Any) -> str:
    text = str(value or "")
    if len(text) != 64 or any(ch not in "0123456789abcdef" for ch in text):
        raise ProxyRecoveryRestoreError("bundle content digest is invalid")
    return text


def _restore_result(
    status: RestoreStatus,
    plan: RestorePlan,
    target_identity: str,
    *,
    adopted_ts: int = 0,
    reason: str = "",
) -> RestoreResult:
    restored_tables: tuple[str, ...] = ()
    restored_rows = 0
    if status == _RESTORE_STATUS_ADOPTED:
        restored_tables = tuple(table.table_name for table in plan.tables)
        restored_rows = plan.row_count
    return RestoreResult(
        status=status,
        proxy_id=plan.proxy_id,
        target_proxy_id=plan.proxy_id,
        source_control_plane_id=plan.source_control_plane_id,
        target_control_plane_id=target_identity,
        bundle_content_sha256=plan.bundle_content_sha256,
        restored_tables=restored_tables,
        restored_rows=restored_rows,
        adopted_ts=adopted_ts,
        reason=reason,
    )


def _skip_result_if_already_decided(
    conn: Any,
    plan: RestorePlan,
    target_identity: str,
    *,
    for_update: bool = False,
) -> RestoreResult | None:
    if plan.source_control_plane_id == target_identity:
        return _restore_result(
            _RESTORE_STATUS_SAME_CONTROL_PLANE,
            plan,
            target_identity,
            reason="bundle source is the current control plane",
        )
    marker_state = _adoption_marker_state(conn, plan, target_identity, for_update=for_update)
    if marker_state == "same_target":
        return _restore_result(
            _RESTORE_STATUS_ALREADY_ADOPTED,
            plan,
            target_identity,
            reason="target control plane already adopted this proxy bundle once",
        )
    if marker_state == "ambiguous":
        raise ProxyRecoveryRestoreError("target proxy has a conflicting recovery adoption marker")
    return None


def _adoption_marker_state(
    conn: Any,
    plan: RestorePlan,
    target_identity: str,
    *,
    for_update: bool = False,
) -> Literal["none", "same_target", "ambiguous"]:
    pair_sql = _ADOPTION_MARKER_PAIR_SELECT_SQL
    proxy_sql = _ADOPTION_MARKER_PROXY_SELECT_SQL
    if for_update:
        pair_sql += " FOR UPDATE"
        proxy_sql += " FOR UPDATE"
    pair_row = conn.execute(pair_sql, (plan.proxy_id, target_identity)).fetchone()
    if pair_row is not None:
        try:
            source_id = _normalize_control_plane_id(_row_value(pair_row, "source_control_plane_id", 0))
            marker_target = _normalize_control_plane_id(_row_value(pair_row, "target_control_plane_id", 1))
            bundle_sha = _normalize_sha256_hex(_row_value(pair_row, "bundle_content_sha256", 2))
        except ProxyRecoveryRestoreError:
            return "ambiguous"
        status = str(_row_value(pair_row, "status", 3) or "").strip().lower()
        detail = str(_row_value(pair_row, "detail", 4) or "")
        if (
            source_id == plan.source_control_plane_id
            and marker_target == target_identity
            and bundle_sha == plan.bundle_content_sha256
            and status == _RESTORE_STATUS_ADOPTED
            and detail == ""
        ):
            return "same_target"
        return "ambiguous"
    rows = conn.execute(proxy_sql, (plan.proxy_id,)).fetchall()
    if rows:
        return "ambiguous"
    return "none"


def _freshness_failure_reason(conn: Any, proxy_id: str) -> str:
    probes = (
        _fresh_adblock_lists,
        _fresh_adblock_settings,
        _fresh_no_adblock_artifacts,
        _fresh_no_certificate_bundles,
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
    actual = {
        (str(_row_value(row, "key", 0) or ""), str(_row_value(row, "url", 1) or ""), int(_row_value(row, "enabled", 2) or 0))
        for row in rows
    }
    allowed = {(key, url, 0) for key, url in _ADBLOCK_DEFAULT_LISTS.items()}
    if actual and actual != allowed:
        return "adblock lists are not canonical schema defaults"
    return ""


def _fresh_adblock_settings(conn: Any, _proxy_id: str) -> str:
    rows = _rows(conn, "SELECT k, v FROM adblock_settings ORDER BY k ASC")
    actual = {str(_row_value(row, "k", 0) or ""): str(_row_value(row, "v", 1) or "") for row in rows}
    if actual and actual != dict(_ADBLOCK_DEFAULT_SETTINGS):
        return "adblock settings are not canonical schema defaults"
    return ""


def _fresh_no_adblock_artifacts(conn: Any, _proxy_id: str) -> str:
    if _count(conn, "SELECT COUNT(*) AS count FROM adblock_artifact_revisions"):
        return "adblock artifact revision already exists"
    return ""


def _fresh_no_certificate_bundles(conn: Any, _proxy_id: str) -> str:
    if _count(conn, "SELECT COUNT(*) AS count FROM certificate_bundle_revisions"):
        return "certificate bundle revision already exists"
    return ""


def _fresh_admin_ui_https_settings(conn: Any, _proxy_id: str) -> str:
    rows = _rows(conn, "SELECT enabled, certfile, keyfile, san_tokens FROM admin_ui_https_settings WHERE id=1")
    if not rows:
        return ""
    if len(rows) == 1:
        row = rows[0]
        if (
            int(_row_value(row, "enabled", 0) or 0) == 0
            and str(_row_value(row, "certfile", 1) or "") == ""
            and str(_row_value(row, "keyfile", 2) or "") == ""
            and str(_row_value(row, "san_tokens", 3) or "") == ""
        ):
            return ""
    return "admin UI HTTPS settings are not canonical schema defaults"


def _fresh_observability_settings(conn: Any, _proxy_id: str) -> str:
    rows = _rows(conn, "SELECT retention_days FROM observability_settings WHERE id=1")
    if not rows:
        return ""
    if len(rows) == 1 and int(_row_value(rows[0], "retention_days", 0) or 0) == _OBSERVABILITY_DEFAULT_RETENTION_DAYS:
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
    columns = _EXPECTED_TABLE_COLUMNS["directory_auth_profiles"]
    actual = tuple(_project_row(row, columns) for row in rows)
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
    actual = tuple(_project_row(row, _EXPECTED_TABLE_COLUMNS["saml_auth_profiles"]) for row in rows)
    if actual == (dict(_SAML_DEFAULT_ROW),):
        return ""
    return "SAML auth profile is not the canonical schema default"


def _fresh_no_proxy_config_revision(conn: Any, proxy_id: str) -> str:
    if _count(conn, "SELECT COUNT(*) AS count FROM proxy_config_revisions WHERE proxy_id=%s", (proxy_id,)):
        return "proxy config revision already exists for target proxy"
    return ""


def _fresh_no_pac_profiles(conn: Any, proxy_id: str) -> str:
    if _count(conn, "SELECT COUNT(*) AS count FROM pac_profiles WHERE proxy_id=%s", (proxy_id,)):
        return "PAC profiles already exist for target proxy"
    return ""


def _fresh_no_pac_backup_proxies(conn: Any, proxy_id: str) -> str:
    if _count(conn, "SELECT COUNT(*) AS count FROM pac_backup_proxies WHERE proxy_id=%s", (proxy_id,)):
        return "PAC backup proxies already exist for target proxy"
    return ""


def _fresh_pac_proxy_chain_settings(conn: Any, proxy_id: str) -> str:
    rows = _rows(conn, "SELECT direct_enabled FROM pac_proxy_chain_settings WHERE proxy_id=%s", (proxy_id,))
    if not rows:
        return ""
    if len(rows) == 1 and int(_row_value(rows[0], "direct_enabled", 0) or 0) == 1:
        return ""
    return "PAC proxy chain settings are not canonical defaults"


def _fresh_no_policy_exceptions(conn: Any, proxy_id: str) -> str:
    if _count(conn, "SELECT COUNT(*) AS count FROM policy_exceptions WHERE proxy_id=%s", (proxy_id,)):
        return "policy exceptions already exist for target proxy"
    return ""


def _fresh_no_sslfilter_rows(conn: Any, proxy_id: str) -> str:
    if _count(conn, "SELECT COUNT(*) AS count FROM sslfilter_domains WHERE proxy_id=%s", (proxy_id,)):
        return "SSL filter rows already exist for target proxy"
    if _count(conn, "SELECT COUNT(*) AS count FROM sslfilter_src_nets WHERE proxy_id=%s", (proxy_id,)):
        return "SSL filter rows already exist for target proxy"
    if _count(conn, "SELECT COUNT(*) AS count FROM sslfilter_settings WHERE proxy_id=%s", (proxy_id,)):
        return "SSL filter rows already exist for target proxy"
    return ""


def _fresh_webfilter_settings(conn: Any, proxy_id: str) -> str:
    rows = _rows(conn, "SELECT k, v FROM webfilter_settings WHERE proxy_id=%s ORDER BY k ASC", (proxy_id,))
    if not rows:
        return ""
    actual = {str(_row_value(row, "k", 0) or ""): str(_row_value(row, "v", 1) or "") for row in rows}
    if actual == dict(_WEBFILTER_DEFAULT_SETTINGS):
        return ""
    return "webfilter settings are not canonical target defaults"


def _fresh_no_proxy_table_rows(conn: Any, proxy_id: str) -> str:
    if _count(conn, "SELECT COUNT(*) AS count FROM webfilter_whitelist WHERE proxy_id=%s", (proxy_id,)):
        return "target proxy declarative rows already exist"
    if _count(conn, "SELECT COUNT(*) AS count FROM adblock_proxy_meta WHERE proxy_id=%s", (proxy_id,)):
        return "target proxy declarative rows already exist"
    if _count(conn, "SELECT COUNT(*) AS count FROM observability_report_schedules WHERE proxy_id=%s", (proxy_id,)):
        return "target proxy declarative rows already exist"
    return ""


def _count(conn: Any, sql: str, params: tuple[Any, ...] = ()) -> int:
    row = conn.execute(sql, params).fetchone()
    try:
        return int(_row_value(row, "count", 0) or 0)
    except Exception as exc:
        raise ProxyRecoveryRestoreError("freshness probe returned an invalid count") from exc


def _rows(conn: Any, sql: str, params: tuple[Any, ...] = ()) -> tuple[Any, ...]:
    return tuple(conn.execute(sql, params).fetchall())


def _project_row(row: Any, columns: tuple[str, ...]) -> dict[str, Any]:
    projected: dict[str, Any] = {}
    for index, column in enumerate(columns):
        value = _row_value(row, column, index)
        if column in {
            "enabled",
            "use_starttls",
            "verify_tls",
            "require_https",
            "timeout_seconds",
            "max_metadata_bytes",
        }:
            value = int(value or 0)
        elif value is None:
            value = ""
        else:
            value = str(value)
        projected[column] = value
    return projected


def _acquire_lifecycle_lock(conn: Any, lock_name: str, timeout_seconds: int) -> bool:
    row = conn.execute(
        "SELECT GET_LOCK(%s, %s) AS acquired",
        (lock_name, int(timeout_seconds)),
    ).fetchone()
    try:
        acquired = int(_row_value(row, "acquired", 0) or 0) == 1
    except Exception:
        acquired = False
    if not acquired:
        raise ProxyLifecycleWriteError("timed out acquiring proxy lifecycle recovery lock")
    return True


def _release_lifecycle_lock(conn: Any, lock_name: str) -> None:
    conn.execute("DO RELEASE_LOCK(%s)", (lock_name,))


def _apply_restore_plan(conn: Any, plan: RestorePlan, target_identity: str) -> None:
    for sql in _DELETE_DEFAULTS_SQL:
        conn.execute(sql)
    for sql in _DELETE_PROXY_DEFAULTS_SQL:
        conn.execute(sql, (plan.proxy_id,))

    pac_profile_map: dict[int, int] = {}
    for table in plan.tables:
        if table.table_name == "adblock_lists":
            _insert_adblock_lists(conn, table.rows)
        elif table.table_name == "adblock_settings":
            _insert_adblock_settings(conn, table.rows)
        elif table.table_name == "adblock_artifact_revisions":
            _insert_adblock_artifact_revision(conn, table.rows, plan.now_ts)
        elif table.table_name == "certificate_bundle_revisions":
            _insert_certificate_bundle_revision(conn, table.rows, plan.now_ts)
        elif table.table_name == "admin_ui_https_settings":
            _insert_admin_ui_https_settings(conn, table.rows)
        elif table.table_name == "observability_settings":
            _insert_observability_settings(conn, table.rows, plan.now_ts)
        elif table.table_name == "directory_auth_profiles":
            _insert_directory_auth_profiles(conn, table.rows, plan.now_ts)
        elif table.table_name == "saml_auth_profiles":
            _insert_saml_auth_profiles(conn, table.rows, plan.now_ts)
        elif table.table_name == "proxy_config_revisions":
            _insert_proxy_config_revision(conn, table.rows, plan.now_ts)
        elif table.table_name == "pac_profiles":
            pac_profile_map = _insert_pac_profiles(conn, table.rows, plan.now_ts)
        elif table.table_name == "pac_direct_domains":
            _insert_pac_direct_domains(conn, table.rows, pac_profile_map)
        elif table.table_name == "pac_direct_dst_nets":
            _insert_pac_direct_dst_nets(conn, table.rows, pac_profile_map)
        elif table.table_name == "pac_backup_proxies":
            _insert_pac_backup_proxies(conn, table.rows, plan.now_ts)
        elif table.table_name == "pac_proxy_chain_settings":
            _insert_pac_proxy_chain_settings(conn, table.rows, plan.now_ts)
        elif table.table_name == "policy_exceptions":
            _insert_policy_exceptions(conn, table.rows, plan.now_ts)
        elif table.table_name == "sslfilter_domains":
            _insert_sslfilter_domains(conn, table.rows, plan.now_ts)
        elif table.table_name == "sslfilter_src_nets":
            _insert_sslfilter_src_nets(conn, table.rows, plan.now_ts)
        elif table.table_name == "sslfilter_settings":
            _insert_sslfilter_settings(conn, table.rows)
        elif table.table_name == "webfilter_settings":
            _insert_webfilter_settings(conn, table.rows)
        elif table.table_name == "webfilter_whitelist":
            _insert_webfilter_whitelist(conn, table.rows, plan.now_ts)
        elif table.table_name == "adblock_proxy_meta":
            if table.rows:
                raise ProxyRecoveryRestoreError("adblock_proxy_meta restore is intentionally empty")
        elif table.table_name == "observability_report_schedules":
            _insert_observability_report_schedules(conn, table.rows, plan.now_ts)
        else:
            raise ProxyRecoveryRestoreError(f"unsupported restore table {table.table_name}")
    _insert_adoption_marker(conn, plan, target_identity)


def _insert_many(conn: Any, sql: str, rows: tuple[tuple[Any, ...], ...]) -> None:
    if not rows:
        return
    executemany = getattr(conn, "executemany", None)
    if callable(executemany):
        executemany(sql, rows)
        return
    for row in rows:
        conn.execute(sql, row)


def _insert_adblock_lists(conn: Any, rows: tuple[tuple[Any, ...], ...]) -> None:
    _insert_many(conn, "INSERT INTO adblock_lists(`key`, url, enabled) VALUES(%s,%s,%s)", rows)


def _insert_adblock_settings(conn: Any, rows: tuple[tuple[Any, ...], ...]) -> None:
    _insert_many(conn, "INSERT INTO adblock_settings(k, v) VALUES(%s,%s)", rows)


def _insert_adblock_artifact_revision(conn: Any, rows: tuple[tuple[Any, ...], ...], now_ts: int) -> None:
    for artifact_sha256, archive_blob, report_json, settings_version, enabled_lists_json in rows:
        conn.execute(
            """
            INSERT INTO adblock_artifact_revisions(
                artifact_sha256, archive_blob, report_json, settings_version, source_kind,
                enabled_lists_json, created_by, created_ts, is_active
            ) VALUES(%s,%s,%s,%s,'recovery',%s,'proxy-recovery',%s,1)
            """,
            (artifact_sha256, archive_blob, report_json, settings_version, enabled_lists_json, now_ts),
        )


def _insert_certificate_bundle_revision(conn: Any, rows: tuple[tuple[Any, ...], ...], now_ts: int) -> None:
    for bundle_sha256, cert_sha256, cert_pem, key_pem, chain_pem in rows:
        conn.execute(
            """
            INSERT INTO certificate_bundle_revisions(
                bundle_sha256, cert_sha256, cert_pem, key_pem, chain_pem, source_kind,
                created_by, created_ts, is_active
            ) VALUES(%s,%s,%s,%s,%s,'recovery','proxy-recovery',%s,1)
            """,
            (bundle_sha256, cert_sha256, cert_pem, key_pem, chain_pem, now_ts),
        )


def _insert_admin_ui_https_settings(conn: Any, rows: tuple[tuple[Any, ...], ...]) -> None:
    for enabled, certfile, keyfile, san_tokens in rows:
        conn.execute(
            """
            INSERT INTO admin_ui_https_settings(id, enabled, certfile, keyfile, san_tokens, updated_by, updated_ts)
            VALUES(1,%s,%s,%s,%s,'proxy-recovery',0)
            """,
            (enabled, certfile, keyfile, san_tokens),
        )


def _insert_observability_settings(conn: Any, rows: tuple[tuple[Any, ...], ...], now_ts: int) -> None:
    for (retention_days,) in rows:
        conn.execute(
            "INSERT INTO observability_settings(id, retention_days, updated_ts) VALUES(1,%s,%s)",
            (retention_days, now_ts),
        )


def _insert_directory_auth_profiles(conn: Any, rows: tuple[tuple[Any, ...], ...], now_ts: int) -> None:
    for row in rows:
        conn.execute(
            """
            INSERT INTO directory_auth_profiles(
                provider, enabled, server_urls, use_starttls, verify_tls, ca_bundle,
                bind_dn, bind_password, base_dn, user_search_base, user_filter,
                user_attribute, group_search_base, group_filter, required_admin_group,
                timeout_seconds, last_test_ok, last_test_ts, last_test_detail, updated_ts
            ) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,0,0,'',%s)
            """,
            (*row, now_ts),
        )


def _insert_saml_auth_profiles(conn: Any, rows: tuple[tuple[Any, ...], ...], now_ts: int) -> None:
    for row in rows:
        conn.execute(
            """
            INSERT INTO saml_auth_profiles(
                provider, enabled, metadata_url, require_https, verify_tls, ca_bundle,
                timeout_seconds, max_metadata_bytes, raw_metadata_xml, parsed_metadata_json,
                entity_id, fetched_ts, cache_expires_ts, valid_until_ts, last_refresh_ok,
                last_refresh_ts, last_refresh_detail, public_base_url, username_attribute,
                groups_attribute, required_group, updated_ts
            ) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,'','',0,0,0,0,0,'',%s,%s,%s,%s,%s)
            """,
            (*row, now_ts),
        )


def _insert_proxy_config_revision(conn: Any, rows: tuple[tuple[Any, ...], ...], now_ts: int) -> None:
    for proxy_id, config_sha256, config_text in rows:
        conn.execute(
            """
            INSERT INTO proxy_config_revisions(
                proxy_id, config_sha256, config_text, source_kind, created_by, created_ts, is_active
            ) VALUES(%s,%s,%s,'recovery','proxy-recovery',%s,1)
            """,
            (proxy_id, config_sha256, config_text, now_ts),
        )


def _insert_pac_profiles(conn: Any, rows: tuple[tuple[Any, ...], ...], now_ts: int) -> dict[int, int]:
    mapping: dict[int, int] = {}
    for source_profile_id, proxy_id, name, client_cidr in rows:
        result = conn.execute(
            "INSERT INTO pac_profiles(proxy_id, name, client_cidr, created_ts) VALUES(%s,%s,%s,%s)",
            (proxy_id, name, client_cidr, now_ts),
        )
        target_id = int(getattr(result, "lastrowid", 0) or 0)
        if target_id <= 0:
            raise ProxyRecoveryRestoreError("PAC profile insert did not return a target id")
        if int(source_profile_id) in mapping:
            raise ProxyRecoveryRestoreError("duplicate PAC source profile mapping")
        mapping[int(source_profile_id)] = target_id
    return mapping


def _insert_pac_direct_domains(
    conn: Any,
    rows: tuple[tuple[Any, ...], ...],
    pac_profile_map: dict[int, int],
) -> None:
    _insert_many(
        conn,
        "INSERT INTO pac_direct_domains(profile_id, domain) VALUES(%s,%s)",
        tuple((_mapped_profile_id(pac_profile_map, source_profile_id), domain) for source_profile_id, domain in rows),
    )


def _insert_pac_direct_dst_nets(
    conn: Any,
    rows: tuple[tuple[Any, ...], ...],
    pac_profile_map: dict[int, int],
) -> None:
    _insert_many(
        conn,
        "INSERT INTO pac_direct_dst_nets(profile_id, cidr) VALUES(%s,%s)",
        tuple((_mapped_profile_id(pac_profile_map, source_profile_id), cidr) for source_profile_id, cidr in rows),
    )


def _mapped_profile_id(pac_profile_map: dict[int, int], source_profile_id: int) -> int:
    target_id = pac_profile_map.get(int(source_profile_id))
    if target_id is None:
        raise ProxyRecoveryRestoreError("PAC child row has no target profile mapping")
    return target_id


def _insert_pac_backup_proxies(conn: Any, rows: tuple[tuple[Any, ...], ...], now_ts: int) -> None:
    _insert_many(
        conn,
        "INSERT INTO pac_backup_proxies(proxy_id, proxy_host, proxy_port, position, created_ts) VALUES(%s,%s,%s,%s,%s)",
        tuple((*row, now_ts) for row in rows),
    )


def _insert_pac_proxy_chain_settings(conn: Any, rows: tuple[tuple[Any, ...], ...], now_ts: int) -> None:
    _insert_many(
        conn,
        "INSERT INTO pac_proxy_chain_settings(proxy_id, direct_enabled, updated_ts) VALUES(%s,%s,%s)",
        tuple((*row, now_ts) for row in rows),
    )


def _insert_policy_exceptions(conn: Any, rows: tuple[tuple[Any, ...], ...], now_ts: int) -> None:
    for proxy_id, block_type, client_ip, domain, category, admin_note, expires_ts in rows:
        conn.execute(
            """
            INSERT INTO policy_exceptions(
                proxy_id, status, block_type, client_ip, domain, category, created_ts,
                updated_ts, created_by, admin_note, expires_ts, revoked_ts, revoked_by, source_request_id
            ) VALUES(%s,'active',%s,%s,%s,%s,%s,%s,'proxy-recovery',%s,%s,0,'',NULL)
            """,
            (proxy_id, block_type, client_ip, domain, category, now_ts, now_ts, admin_note, expires_ts),
        )


def _insert_sslfilter_domains(conn: Any, rows: tuple[tuple[Any, ...], ...], now_ts: int) -> None:
    _insert_many(
        conn,
        "INSERT INTO sslfilter_domains(proxy_id, policy, domain, added_ts) VALUES(%s,%s,%s,%s)",
        tuple((*row, now_ts) for row in rows),
    )


def _insert_sslfilter_src_nets(conn: Any, rows: tuple[tuple[Any, ...], ...], now_ts: int) -> None:
    _insert_many(
        conn,
        "INSERT INTO sslfilter_src_nets(proxy_id, policy, cidr, added_ts) VALUES(%s,%s,%s,%s)",
        tuple((*row, now_ts) for row in rows),
    )


def _insert_sslfilter_settings(conn: Any, rows: tuple[tuple[Any, ...], ...]) -> None:
    _insert_many(conn, "INSERT INTO sslfilter_settings(proxy_id, `key`, value) VALUES(%s,%s,%s)", rows)


def _insert_webfilter_settings(conn: Any, rows: tuple[tuple[Any, ...], ...]) -> None:
    _insert_many(conn, "INSERT INTO webfilter_settings(proxy_id, k, v) VALUES(%s,%s,%s)", rows)


def _insert_webfilter_whitelist(conn: Any, rows: tuple[tuple[Any, ...], ...], now_ts: int) -> None:
    _insert_many(
        conn,
        "INSERT INTO webfilter_whitelist(proxy_id, pattern, added_ts) VALUES(%s,%s,%s)",
        tuple((*row, now_ts) for row in rows),
    )


def _insert_observability_report_schedules(conn: Any, rows: tuple[tuple[Any, ...], ...], now_ts: int) -> None:
    _insert_many(
        conn,
        """
        INSERT INTO observability_report_schedules(
            proxy_id, enabled, name, cadence, recipients, pane, report_format, privacy,
            window_seconds, created_ts, updated_ts, next_run_ts, last_run_ts, last_status
        ) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,0,0,'recovered')
        """,
        tuple((*row, now_ts, now_ts) for row in rows),
    )


def _insert_adoption_marker(conn: Any, plan: RestorePlan, target_identity: str) -> None:
    conn.execute(
        _ADOPTION_MARKER_INSERT_SQL,
        (
            plan.proxy_id,
            target_identity,
            plan.source_control_plane_id,
            plan.bundle_content_sha256,
            plan.now_ts,
        ),
    )


def _row_value(row: Any, key: str, index: int) -> Any:
    if row is None:
        return None
    try:
        return row[key]
    except Exception:
        try:
            return row[index]
        except Exception:
            return None


validate_restore_contract()
