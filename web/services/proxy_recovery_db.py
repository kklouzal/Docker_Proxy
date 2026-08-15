from __future__ import annotations

import fcntl
import os
import stat
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Mapping, Sequence
    from pathlib import Path

from services import proxy_recovery
from services.db import connect
from services.schema_lifecycle import read_control_plane_identity


@dataclass(frozen=True)
class RecoveryExportQueryPlan:
    table_name: str
    columns: tuple[str, ...]
    sql: str
    param_mode: str


@dataclass(frozen=True)
class CapturedRecoveryState:
    proxy_id: str
    source_control_plane_id: str
    created_ts: str
    tables: tuple[proxy_recovery.RecoveryTablePayload, ...]


_PARAM_NONE: Final = "none"
_PARAM_PROXY: Final = "proxy"
_PARAM_PROXY_NOW: Final = "proxy_now"

WEBFILTER_SETTING_KEYS: Final = (
    "enabled",
    "blocked_categories",
)

EXPORT_QUERY_PLANS: Final = (
    RecoveryExportQueryPlan(
        "adblock_lists",
        ("key", "url", "enabled"),
        """
        SELECT `key`, url, enabled
        FROM adblock_lists
        ORDER BY `key` ASC
        """,
        _PARAM_NONE,
    ),
    RecoveryExportQueryPlan(
        "adblock_settings",
        ("k", "v"),
        """
        SELECT k, v
        FROM adblock_settings
        WHERE k<>'enabled'
        ORDER BY k ASC
        """,
        _PARAM_NONE,
    ),
    RecoveryExportQueryPlan(
        "adblock_artifact_revisions",
        (
            "artifact_sha256",
            "archive_blob",
            "report_json",
            "settings_version",
            "enabled_lists_json",
        ),
        """
        SELECT artifact_sha256, archive_blob, report_json, settings_version, enabled_lists_json
        FROM adblock_artifact_revisions
        WHERE is_active=1
        ORDER BY created_ts DESC, id DESC
        """,
        _PARAM_NONE,
    ),
    RecoveryExportQueryPlan(
        "certificate_bundle_revisions",
        ("bundle_sha256", "cert_sha256", "cert_pem", "key_pem", "chain_pem"),
        """
        SELECT bundle_sha256, cert_sha256, cert_pem, key_pem, chain_pem
        FROM certificate_bundle_revisions
        WHERE is_active=1
        ORDER BY created_ts DESC, id DESC
        """,
        _PARAM_NONE,
    ),
    RecoveryExportQueryPlan(
        "admin_ui_https_settings",
        ("enabled", "certfile", "keyfile", "san_tokens"),
        """
        SELECT enabled, certfile, keyfile, san_tokens
        FROM admin_ui_https_settings
        WHERE id=1
        ORDER BY id ASC
        """,
        _PARAM_NONE,
    ),
    RecoveryExportQueryPlan(
        "observability_settings",
        ("retention_days",),
        """
        SELECT retention_days
        FROM observability_settings
        WHERE id=1
        ORDER BY id ASC
        """,
        _PARAM_NONE,
    ),
    RecoveryExportQueryPlan(
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
        """
        SELECT provider, enabled, server_urls, use_starttls, verify_tls, ca_bundle,
               bind_dn, bind_password, base_dn, user_search_base, user_filter,
               user_attribute, group_search_base, group_filter, required_admin_group,
               timeout_seconds
        FROM directory_auth_profiles
        ORDER BY provider ASC
        """,
        _PARAM_NONE,
    ),
    RecoveryExportQueryPlan(
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
        """
        SELECT provider, enabled, metadata_url, require_https, verify_tls, ca_bundle,
               timeout_seconds, max_metadata_bytes, raw_metadata_xml, public_base_url,
               username_attribute, groups_attribute, required_group
        FROM saml_auth_profiles
        ORDER BY provider ASC
        """,
        _PARAM_NONE,
    ),
    RecoveryExportQueryPlan(
        "proxy_config_revisions",
        ("proxy_id", "config_sha256", "config_text"),
        """
        SELECT proxy_id, config_sha256, config_text
        FROM proxy_config_revisions
        WHERE proxy_id=%s AND is_active=1
        ORDER BY created_ts DESC, id DESC
        """,
        _PARAM_PROXY,
    ),
    RecoveryExportQueryPlan(
        "pac_profiles",
        ("source_profile_id", "proxy_id", "name", "client_cidr"),
        """
        SELECT id AS source_profile_id, proxy_id, name, client_cidr
        FROM pac_profiles
        WHERE proxy_id=%s
        ORDER BY id ASC
        """,
        _PARAM_PROXY,
    ),
    RecoveryExportQueryPlan(
        "pac_direct_domains",
        ("source_profile_id", "domain"),
        """
        SELECT p.id AS source_profile_id, d.domain
        FROM pac_direct_domains d
        INNER JOIN pac_profiles p ON p.id=d.profile_id
        WHERE p.proxy_id=%s
        ORDER BY p.id ASC, d.domain ASC
        """,
        _PARAM_PROXY,
    ),
    RecoveryExportQueryPlan(
        "pac_direct_dst_nets",
        ("source_profile_id", "cidr"),
        """
        SELECT p.id AS source_profile_id, n.cidr
        FROM pac_direct_dst_nets n
        INNER JOIN pac_profiles p ON p.id=n.profile_id
        WHERE p.proxy_id=%s
        ORDER BY p.id ASC, n.cidr ASC
        """,
        _PARAM_PROXY,
    ),
    RecoveryExportQueryPlan(
        "pac_backup_proxies",
        ("proxy_id", "proxy_host", "proxy_port", "position"),
        """
        SELECT proxy_id, proxy_host, proxy_port, position
        FROM pac_backup_proxies
        WHERE proxy_id=%s
        ORDER BY position ASC, id ASC
        """,
        _PARAM_PROXY,
    ),
    RecoveryExportQueryPlan(
        "pac_proxy_chain_settings",
        ("proxy_id", "direct_enabled"),
        """
        SELECT proxy_id, direct_enabled
        FROM pac_proxy_chain_settings
        WHERE proxy_id=%s
        ORDER BY proxy_id ASC
        """,
        _PARAM_PROXY,
    ),
    RecoveryExportQueryPlan(
        "policy_exceptions",
        (
            "proxy_id",
            "block_type",
            "client_ip",
            "domain",
            "category",
            "method",
            "admin_note",
            "expires_ts",
        ),
        """
        SELECT proxy_id, block_type, client_ip, domain, category, method, admin_note, expires_ts
        FROM policy_exceptions
        WHERE proxy_id=%s AND status='active' AND (expires_ts=0 OR expires_ts>%s)
        ORDER BY domain ASC, client_ip ASC, block_type ASC, category ASC, method ASC, expires_ts ASC, id ASC
        """,
        _PARAM_PROXY_NOW,
    ),
    RecoveryExportQueryPlan(
        "sslfilter_domains",
        ("proxy_id", "policy", "domain"),
        """
        SELECT proxy_id, policy, domain
        FROM sslfilter_domains
        WHERE proxy_id=%s
        ORDER BY policy ASC, domain ASC
        """,
        _PARAM_PROXY,
    ),
    RecoveryExportQueryPlan(
        "sslfilter_src_nets",
        ("proxy_id", "policy", "cidr"),
        """
        SELECT proxy_id, policy, cidr
        FROM sslfilter_src_nets
        WHERE proxy_id=%s
        ORDER BY policy ASC, cidr ASC
        """,
        _PARAM_PROXY,
    ),
    RecoveryExportQueryPlan(
        "sslfilter_settings",
        ("proxy_id", "key", "value"),
        """
        SELECT proxy_id, `key`, value
        FROM sslfilter_settings
        WHERE proxy_id=%s
        ORDER BY `key` ASC
        """,
        _PARAM_PROXY,
    ),
    RecoveryExportQueryPlan(
        "webfilter_settings",
        ("proxy_id", "k", "v"),
        """
        SELECT proxy_id, k, v
        FROM webfilter_settings
        WHERE proxy_id=%s AND k IN ('enabled','blocked_categories')
        ORDER BY k ASC
        """,
        _PARAM_PROXY,
    ),
    RecoveryExportQueryPlan(
        "webfilter_whitelist",
        ("proxy_id", "pattern"),
        """
        SELECT proxy_id, pattern
        FROM webfilter_whitelist
        WHERE proxy_id=%s
        ORDER BY pattern ASC
        """,
        _PARAM_PROXY,
    ),
    RecoveryExportQueryPlan(
        "adblock_proxy_meta",
        ("proxy_id", "k", "v"),
        """
        SELECT proxy_id, k, v
        FROM adblock_proxy_meta
        WHERE proxy_id=%s AND k='enabled'
        ORDER BY k ASC
        """,
        _PARAM_PROXY,
    ),
    RecoveryExportQueryPlan(
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
        """
        SELECT proxy_id, enabled, name, 'manual' AS cadence, '' AS recipients, pane, report_format,
               privacy, window_seconds
        FROM observability_report_schedules
        WHERE proxy_id=%s
        ORDER BY name ASC, pane ASC, id ASC
        """,
        _PARAM_PROXY,
    ),
)


def recovery_export_query_plans() -> tuple[RecoveryExportQueryPlan, ...]:
    return EXPORT_QUERY_PLANS


def validate_export_query_plan_coverage() -> None:
    registry_tables = tuple(
        spec.table_name for spec in proxy_recovery.recovery_registry()
    )
    plan_tables = tuple(plan.table_name for plan in EXPORT_QUERY_PLANS)
    if plan_tables != registry_tables:
        msg = "recovery DB export query plans do not match recovery registry order"
        raise proxy_recovery.ProxyRecoveryError(msg)
    for plan in EXPORT_QUERY_PLANS:
        lowered = " ".join(plan.sql.lower().split())
        if "select *" in lowered:
            msg = f"unsafe recovery export query for {plan.table_name}"
            raise proxy_recovery.ProxyRecoveryError(msg)
        if plan.table_name not in lowered:
            msg = f"recovery export query does not reference {plan.table_name}"
            raise proxy_recovery.ProxyRecoveryError(msg)
        if len(plan.columns) != len(set(plan.columns)):
            msg = f"duplicate recovery export columns for {plan.table_name}"
            raise proxy_recovery.ProxyRecoveryError(msg)


def capture_recovery_state(
    conn: Any,
    proxy_id: str,
    *,
    now_ts: int | None = None,
    max_bundle_bytes: int | None = None,
) -> CapturedRecoveryState:
    validate_export_query_plan_coverage()
    normalized_proxy_id = proxy_recovery.normalize_proxy_id(proxy_id)
    snapshot_ts = int(time.time() if now_ts is None else now_ts)
    created_ts = (
        datetime.fromtimestamp(snapshot_ts, UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    validated_limit = proxy_recovery.resolve_max_bundle_bytes(max_bundle_bytes)
    conn.execute("START TRANSACTION READ ONLY, WITH CONSISTENT SNAPSHOT")
    try:
        source_control_plane_id = read_control_plane_identity(conn)
        if source_control_plane_id is None:
            msg = "control plane identity is missing; run schema migration first"
            raise proxy_recovery.ProxyRecoveryError(msg)
        budget = _CaptureSizeBudget(
            normalized_proxy_id,
            source_control_plane_id,
            created_ts,
            validated_limit,
        )
        tables = []
        for plan in EXPORT_QUERY_PLANS:
            rows = tuple(
                _rows_for_plan(conn, plan, normalized_proxy_id, snapshot_ts, budget)
            )
            tables.append(proxy_recovery.RecoveryTablePayload(plan.table_name, rows))
        conn.commit()
    except Exception:
        rollback = getattr(conn, "rollback", None)
        if callable(rollback):
            rollback()
        raise
    return CapturedRecoveryState(
        proxy_id=normalized_proxy_id,
        source_control_plane_id=source_control_plane_id,
        created_ts=created_ts,
        tables=tuple(tables),
    )


@contextmanager
def _recovery_capture_lock(
    proxy_id: str,
    recovery_dir: Path | str | None,
) -> Iterator[None]:
    """Serialize snapshot-and-publish across all local proxy processes."""
    bundle_path = proxy_recovery.bundle_path_for_proxy(proxy_id, recovery_dir)
    root = proxy_recovery._ensure_private_dir(bundle_path.parent)
    lock_path = root / f".{bundle_path.name}.capture.lock"
    if lock_path.exists() or lock_path.is_symlink():
        proxy_recovery._stat_regular_nosymlink(lock_path)

    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd: int | None = None
    try:
        fd = os.open(lock_path, flags, 0o600)
        opened_stat = os.fstat(fd)
        if not stat.S_ISREG(opened_stat.st_mode):
            msg = "recovery capture lock is not a regular file"
            raise proxy_recovery.ProxyRecoveryError(msg)
        os.fchmod(fd, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
    except OSError as exc:
        if fd is not None:
            os.close(fd)
        msg = "unable to establish recovery capture lock"
        raise proxy_recovery.ProxyRecoveryError(msg) from exc
    except BaseException:
        if fd is not None:
            os.close(fd)
        raise

    try:
        yield
    finally:
        os.close(fd)


def capture_and_write_recovery_bundle(
    connect_factory: Callable[[], Any] = connect,
    proxy_id: str = "default",
    *,
    recovery_dir: Path | str | None = None,
    max_bundle_bytes: int | None = None,
) -> Path:
    normalized_proxy_id = proxy_recovery.normalize_proxy_id(proxy_id)
    validated_limit = proxy_recovery.resolve_max_bundle_bytes(max_bundle_bytes)
    with _recovery_capture_lock(normalized_proxy_id, recovery_dir):
        # The lock must precede the DB snapshot: locking only publication allows
        # a slow, older snapshot to replace a newer bundle.
        with connect_factory() as conn:
            captured = capture_recovery_state(
                conn, normalized_proxy_id, max_bundle_bytes=validated_limit
            )
        return proxy_recovery.write_recovery_bundle(
            captured.proxy_id,
            captured.tables,
            source_control_plane_id=captured.source_control_plane_id,
            created_ts=captured.created_ts,
            recovery_dir=recovery_dir,
            max_bundle_bytes=validated_limit,
        )


def _rows_for_plan(
    conn: Any,
    plan: RecoveryExportQueryPlan,
    proxy_id: str,
    now_ts: int,
    budget: _CaptureSizeBudget,
) -> Iterator[Mapping[str, Any]]:
    result = conn.execute(plan.sql, _params_for_plan(plan, proxy_id, now_ts))
    for row in result:
        normalized = _normalize_row(row, plan.columns)
        budget.add_row(plan.table_name, normalized)
        yield normalized


class _CaptureSizeBudget:
    """Exact final-envelope byte accounting without retaining encoded copies."""

    def __init__(
        self,
        proxy_id: str,
        source_control_plane_id: str,
        created_ts: str,
        limit: int,
    ) -> None:
        empty_tables = [
            {"name": plan.table_name, "rows": []} for plan in EXPORT_QUERY_PLANS
        ]
        envelope = {
            "format_version": proxy_recovery.FORMAT_VERSION,
            "proxy_id": proxy_id,
            "source_control_plane_id": source_control_plane_id,
            "created_ts": created_ts,
            "schema_version": proxy_recovery.DATA_SCHEMA_VERSION,
            "tables": empty_tables,
            "integrity": {
                "content_sha256": "0" * 64,
                "mac_alg": proxy_recovery.MAC_ALGORITHM,
                "mac": "0" * 64,
            },
        }
        self.size = len(proxy_recovery.serialize_envelope(envelope))
        self.limit = limit
        self.row_counts: dict[str, int] = {}
        self._check()

    def add_row(self, table_name: str, row: Mapping[str, Any]) -> None:
        encoded = proxy_recovery._encode_json_value(dict(row))
        self.size += len(proxy_recovery._canonical_json_bytes(encoded))
        if self.row_counts.get(table_name, 0):
            self.size += 1
        self.row_counts[table_name] = self.row_counts.get(table_name, 0) + 1
        self._check()

    def _check(self) -> None:
        if self.size > self.limit:
            msg = "recovery bundle exceeds maximum size during database capture"
            raise proxy_recovery.ProxyRecoveryError(msg)


def _params_for_plan(
    plan: RecoveryExportQueryPlan,
    proxy_id: str,
    now_ts: int,
) -> tuple[Any, ...]:
    if plan.param_mode == _PARAM_NONE:
        return ()
    if plan.param_mode == _PARAM_PROXY:
        return (proxy_id,)
    if plan.param_mode == _PARAM_PROXY_NOW:
        return (proxy_id, now_ts)
    msg = f"unknown recovery export parameter mode for {plan.table_name}"
    raise proxy_recovery.ProxyRecoveryError(msg)


def _normalize_row(row: Any, columns: Sequence[str]) -> Mapping[str, Any]:
    return {
        column: _normalize_value(_row_value(row, column, index))
        for index, column in enumerate(columns)
    }


def _row_value(row: Any, key: str, index: int) -> Any:
    try:
        return row[key]
    except Exception:
        return row[index]


def _normalize_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray | memoryview):
        return bytes(value)
    return value


validate_export_query_plan_coverage()
