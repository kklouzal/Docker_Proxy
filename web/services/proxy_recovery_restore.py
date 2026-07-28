from __future__ import annotations

# ruff: noqa: EM101, EM102, TRY003
import time
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Final

from services import proxy_recovery
from services.db import connect
from services.proxy_recovery_db import recovery_export_query_plans
from services.proxy_write_guard import (
    ProxyLifecycleWriteError,
    proxy_lifecycle_lock_name,
    resolve_proxy_write_id,
)
from services.schema_lifecycle import read_control_plane_identity


class ProxyRecoveryRestoreError(ValueError):
    """Raised when a recovery bundle is not safe to restore."""


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
    proxy_id: str
    source_control_plane_id: str
    target_control_plane_id: str
    restored_tables: tuple[str, ...]
    restored_rows: int


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

_ADOPTION_MARKER_TABLE: Final = "proxy_recovery_adoptions"
_ADOPTION_MARKER_SELECT_SQL: Final = (
    "SELECT source_control_plane_id, target_control_plane_id "
    "FROM proxy_recovery_adoptions WHERE proxy_id=%s LIMIT 1"
)
_ADOPTION_MARKER_INSERT_SQL: Final = """
    INSERT INTO proxy_recovery_adoptions(
        proxy_id, target_control_plane_id, source_control_plane_id, bundle_content_sha256,
        status, adopted_ts, detail
    ) VALUES(%s,%s,%s,%s,'restored',%s,'')
    """


# Fixed freshness probes.  They intentionally do not derive identifiers from a
# bundle.  Default rows inserted by schema init are allowed only when they match
# the explicit default predicate; restore deletes/replaces those rows in the same
# locked transaction.
_FRESHNESS_PROBES_NONE: Final = (
    (
        "adblock_lists",
        """
        SELECT COUNT(*) AS count
        FROM adblock_lists
        WHERE NOT (
            (`key`='easylist' AND url='https://easylist.to/easylist/easylist.txt' AND enabled=0)
            OR (`key`='easyprivacy' AND url='https://easylist.to/easylist/easyprivacy.txt' AND enabled=0)
            OR (`key`='cookiemonster' AND url='https://secure.fanboy.co.nz/fanboy-cookiemonster.txt' AND enabled=0)
        )
        """,
        (),
    ),
    (
        "adblock_settings",
        """
        SELECT COUNT(*) AS count
        FROM adblock_settings
        WHERE NOT (
            (k='enabled' AND v='1')
            OR (k='cache_ttl' AND v='3600')
            OR (k='cache_max' AND v='200000')
        )
        """,
        (),
    ),
    (
        "adblock_artifact_revisions",
        "SELECT COUNT(*) AS count FROM adblock_artifact_revisions WHERE is_active=1",
        (),
    ),
    (
        "certificate_bundle_revisions",
        "SELECT COUNT(*) AS count FROM certificate_bundle_revisions WHERE is_active=1",
        (),
    ),
    (
        "admin_ui_https_settings",
        """
        SELECT COUNT(*) AS count
        FROM admin_ui_https_settings
        WHERE NOT (id=1 AND enabled=0 AND certfile='' AND keyfile='' AND (san_tokens IS NULL OR san_tokens=''))
        """,
        (),
    ),
    (
        "observability_settings",
        "SELECT COUNT(*) AS count FROM observability_settings WHERE NOT (id=1 AND retention_days=30)",
        (),
    ),
    (
        "directory_auth_profiles",
        "SELECT COUNT(*) AS count FROM directory_auth_profiles",
        (),
    ),
    (
        "saml_auth_profiles",
        "SELECT COUNT(*) AS count FROM saml_auth_profiles",
        (),
    ),
)

_FRESHNESS_PROBES_PROXY: Final = (
    (
        "proxy_config_revisions",
        "SELECT COUNT(*) AS count FROM proxy_config_revisions WHERE proxy_id=%s AND is_active=1",
    ),
    ("pac_profiles", "SELECT COUNT(*) AS count FROM pac_profiles WHERE proxy_id=%s"),
    (
        "pac_direct_domains",
        """
        SELECT COUNT(*) AS count
        FROM pac_direct_domains d
        INNER JOIN pac_profiles p ON p.id=d.profile_id
        WHERE p.proxy_id=%s
        """,
    ),
    (
        "pac_direct_dst_nets",
        """
        SELECT COUNT(*) AS count
        FROM pac_direct_dst_nets n
        INNER JOIN pac_profiles p ON p.id=n.profile_id
        WHERE p.proxy_id=%s
        """,
    ),
    ("pac_backup_proxies", "SELECT COUNT(*) AS count FROM pac_backup_proxies WHERE proxy_id=%s"),
    (
        "pac_proxy_chain_settings",
        "SELECT COUNT(*) AS count FROM pac_proxy_chain_settings WHERE proxy_id=%s",
    ),
    ("policy_exceptions", "SELECT COUNT(*) AS count FROM policy_exceptions WHERE proxy_id=%s"),
    ("sslfilter_domains", "SELECT COUNT(*) AS count FROM sslfilter_domains WHERE proxy_id=%s"),
    ("sslfilter_src_nets", "SELECT COUNT(*) AS count FROM sslfilter_src_nets WHERE proxy_id=%s"),
    ("sslfilter_settings", "SELECT COUNT(*) AS count FROM sslfilter_settings WHERE proxy_id=%s"),
    (
        "webfilter_settings",
        """
        SELECT COUNT(*) AS count
        FROM webfilter_settings
        WHERE proxy_id=%s AND NOT ((k='enabled' AND v='0') OR (k='blocked_categories' AND v=''))
        """,
    ),
    ("webfilter_whitelist", "SELECT COUNT(*) AS count FROM webfilter_whitelist WHERE proxy_id=%s"),
    ("adblock_proxy_meta", "SELECT COUNT(*) AS count FROM adblock_proxy_meta WHERE proxy_id=%s"),
    (
        "observability_report_schedules",
        "SELECT COUNT(*) AS count FROM observability_report_schedules WHERE proxy_id=%s",
    ),
)


_DELETE_DEFAULTS_SQL: Final = (
    "DELETE FROM adblock_lists",
    "DELETE FROM adblock_settings",
    "DELETE FROM adblock_artifact_revisions WHERE is_active=1",
    "DELETE FROM certificate_bundle_revisions WHERE is_active=1",
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
    _validate_identity_eligibility(plan, target_identity)
    _assert_no_adoption_marker(conn, plan.proxy_id, target_identity)
    _assert_target_fresh(conn, plan.proxy_id)
    first_decision = resolve_proxy_write_id(
        conn,
        plan.proxy_id,
        allow_alias=False,
        require_registered=False,
        use_cache=False,
    )
    _assert_registry_lifecycle_allows_restore(conn, first_decision.proxy_id)
    if first_decision.proxy_id != plan.proxy_id:
        raise ProxyRecoveryRestoreError("target proxy id resolved unexpectedly during restore")

    lock_name = proxy_lifecycle_lock_name(plan.proxy_id)
    acquired = False
    in_transaction = False
    try:
        acquired = _acquire_lifecycle_lock(conn, lock_name, lock_timeout_seconds)
        second_decision = resolve_proxy_write_id(
            conn,
            plan.proxy_id,
            allow_alias=False,
            require_registered=False,
            use_cache=False,
        )
        _assert_registry_lifecycle_allows_restore(conn, second_decision.proxy_id)
        if second_decision.proxy_id != plan.proxy_id:
            raise ProxyRecoveryRestoreError("target proxy id changed during restore lock acquisition")

        conn.execute("START TRANSACTION")
        in_transaction = True
        locked_identity = _read_target_identity(conn, for_update=True)
        _validate_identity_eligibility(plan, locked_identity)
        _assert_no_adoption_marker(conn, plan.proxy_id, locked_identity, for_update=True)
        _assert_target_fresh(conn, plan.proxy_id)
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
    return RestoreResult(
        proxy_id=plan.proxy_id,
        source_control_plane_id=plan.source_control_plane_id,
        target_control_plane_id=target_identity,
        restored_tables=tuple(table.table_name for table in plan.tables),
        restored_rows=plan.row_count,
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
    if table_name == "webfilter_settings":
        keys = {dict(zip(expected_columns, row, strict=True))["k"] for row in rows}
        if not keys.issubset(_EXACT_WEBFILTER_KEYS):
            raise ProxyRecoveryRestoreError("webfilter restore contains unsupported setting key")
    return tuple(rows)


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
            return int(value)
        if not isinstance(value, int):
            raise ProxyRecoveryRestoreError(f"{table_name}.{column} must be an integer")
        if value < 0:
            raise ProxyRecoveryRestoreError(f"{table_name}.{column} must be non-negative")
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
    if column in _HEX_SHA_COLUMNS and (len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value)):
        raise ProxyRecoveryRestoreError(f"{table_name}.{column} must be lowercase sha256 hex")
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


def _validate_identity_eligibility(plan: RestorePlan, target_identity: str) -> None:
    if plan.source_control_plane_id == target_identity:
        raise ProxyRecoveryRestoreError("bundle source control plane matches target identity")


def _assert_no_adoption_marker(
    conn: Any,
    proxy_id: str,
    target_identity: str,
    *,
    for_update: bool = False,
) -> None:
    sql = _ADOPTION_MARKER_SELECT_SQL
    if for_update:
        sql += " FOR UPDATE"
    row = conn.execute(sql, (proxy_id,)).fetchone()
    if row is not None:
        marker_target = str(_row_value(row, "target_control_plane_id", 1) or "")
        if marker_target == target_identity:
            raise ProxyRecoveryRestoreError("target proxy already has a recovery adoption marker")
        raise ProxyRecoveryRestoreError("target proxy has an ambiguous recovery adoption marker")


def _assert_target_fresh(conn: Any, proxy_id: str) -> None:
    for table_name, sql, params in _FRESHNESS_PROBES_NONE:
        if _count(conn, sql, params) != 0:
            raise ProxyRecoveryRestoreError(f"target table {table_name} is not fresh")
    for table_name, sql in _FRESHNESS_PROBES_PROXY:
        if _count(conn, sql, (proxy_id,)) != 0:
            raise ProxyRecoveryRestoreError(f"target proxy table {table_name} is not fresh")


def _assert_registry_lifecycle_allows_restore(conn: Any, proxy_id: str) -> None:
    row = conn.execute(
        "SELECT status FROM proxy_instances WHERE proxy_id=%s LIMIT 1",
        (proxy_id,),
    ).fetchone()
    if row is None:
        return
    status = str(_row_value(row, "status", 0) or "unknown").strip().lower()
    if status in {"renaming", "rename_pending", "removing", "remove_pending", "removed", "deleting", "deleted", "replaced"}:
        raise ProxyRecoveryRestoreError(f"target proxy lifecycle status {status!r} rejects recovery restore")


def _count(conn: Any, sql: str, params: tuple[Any, ...]) -> int:
    row = conn.execute(sql, params).fetchone()
    try:
        return int(_row_value(row, "count", 0) or 0)
    except Exception as exc:
        raise ProxyRecoveryRestoreError("freshness probe returned an invalid count") from exc


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
