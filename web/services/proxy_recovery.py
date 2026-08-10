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
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final

# Recovery bundles are private disaster-recovery material: they may contain
# declarative policy, certificates, directory/SAML settings, and future secret
# fields.  This module deliberately keeps all state local to the durable proxy
# volume, signs it with a per-proxy key that is independent of the Admin UI
# token, and avoids SQL/runtime integration so later slices can add DB export and
# import behind this small data-contract boundary.

FORMAT_VERSION: Final = 2
DATA_SCHEMA_VERSION: Final = 1
RECOVERY_MAX_BUNDLE_BYTES_ENV: Final = "PROXY_RECOVERY_MAX_BUNDLE_BYTES"
DEFAULT_MAX_BUNDLE_BYTES: Final = 128 * 1024 * 1024
MIN_MAX_BUNDLE_BYTES: Final = 1 * 1024 * 1024
HARD_MAX_BUNDLE_BYTES: Final = 512 * 1024 * 1024
# Recovery rows are JSON-shaped database values below a shallow fixed envelope.
# Sixty-four nested containers leaves generous room for legitimate future fields
# while keeping untrusted input safely below Python's recursive JSON operations.
_MAX_JSON_NESTING_DEPTH: Final = 64
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
class RecoveryBundleSizeConfig:
    max_bundle_bytes: int


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


def recovery_bundle_size_config_from_env() -> RecoveryBundleSizeConfig:
    return RecoveryBundleSizeConfig(
        max_bundle_bytes=validate_max_bundle_bytes(
            os.environ.get(RECOVERY_MAX_BUNDLE_BYTES_ENV),
        ),
    )


def resolve_max_bundle_bytes(max_bundle_bytes: int | None = None) -> int:
    if max_bundle_bytes is not None:
        return validate_max_bundle_bytes(max_bundle_bytes, allow_below_min=True)
    return recovery_bundle_size_config_from_env().max_bundle_bytes


def validate_max_bundle_bytes(
    value: object | None = None,
    *,
    allow_below_min: bool = False,
) -> int:
    if value is None:
        return DEFAULT_MAX_BUNDLE_BYTES
    if isinstance(value, bool):
        msg = "invalid recovery max bundle byte limit"
        raise _recovery_error(msg)
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            msg = "invalid recovery max bundle byte limit"
            raise _recovery_error(msg)
        if not stripped.isdecimal():
            msg = "invalid recovery max bundle byte limit"
            raise _recovery_error(msg)
        parsed = int(stripped)
    else:
        msg = "invalid recovery max bundle byte limit"
        raise _recovery_error(msg)
    if parsed < 1:
        msg = "invalid recovery max bundle byte limit"
        raise _recovery_error(msg)
    if not allow_below_min and parsed < MIN_MAX_BUNDLE_BYTES:
        msg = "recovery max bundle byte limit is below minimum"
        raise _recovery_error(msg)
    if parsed > HARD_MAX_BUNDLE_BYTES:
        msg = "recovery max bundle byte limit exceeds hard maximum"
        raise _recovery_error(msg)
    return parsed


def create_recovery_bundle(
    proxy_id: str,
    tables: Mapping[str, Iterable[Mapping[str, Any]]] | Iterable[RecoveryTablePayload],
    *,
    source_control_plane_id: str,
    schema_version: int = DATA_SCHEMA_VERSION,
    created_ts: str | None = None,
    recovery_dir: Path | str | None = None,
    max_bundle_bytes: int | None = None,
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
        max_bundle_bytes=resolve_max_bundle_bytes(max_bundle_bytes),
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
    max_bundle_bytes: int | None = None,
) -> Path:
    unsigned = _unsigned_payload(
        proxy_id,
        tables,
        source_control_plane_id=source_control_plane_id,
        schema_version=schema_version,
        created_ts=created_ts,
    )
    key = get_or_create_signing_key(unsigned["proxy_id"], recovery_dir)
    sealed = _seal_unsigned_payload(
        unsigned,
        key,
        max_bundle_bytes=resolve_max_bundle_bytes(max_bundle_bytes),
    )
    path = bundle_path_for_proxy(unsigned["proxy_id"], recovery_dir)
    _atomic_write_private(path, serialize_envelope(sealed), 0o600)
    return path


def read_recovery_bundle(
    proxy_id: str,
    *,
    expected_source_control_plane_id: str | None = None,
    recovery_dir: Path | str | None = None,
    max_bundle_bytes: int | None = None,
) -> RecoveryBundle:
    normalized = normalize_proxy_id(proxy_id)
    path = bundle_path_for_proxy(normalized, recovery_dir)
    validated_max_bundle_bytes = resolve_max_bundle_bytes(max_bundle_bytes)
    raw = _read_private_regular_file(path, max_bytes=validated_max_bundle_bytes)
    key = read_signing_key(normalized, recovery_dir)
    return parse_recovery_bundle(
        raw,
        expected_proxy_id=normalized,
        expected_source_control_plane_id=expected_source_control_plane_id,
        key=key,
        max_bundle_bytes=validated_max_bundle_bytes,
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
    max_bundle_bytes: int | None = None,
) -> RecoveryBundle:
    validated_max_bundle_bytes = resolve_max_bundle_bytes(max_bundle_bytes)
    if len(raw) > validated_max_bundle_bytes:
        msg = "recovery bundle exceeds maximum size"
        raise _recovery_error(msg)
    envelope = _json_loads_no_duplicates(raw)
    _validate_json_structure(envelope)
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
        rows = table["rows"]
        if not isinstance(rows, list):
            msg = "recovery table rows must be a list"
            raise _recovery_error(msg)
        if any(not isinstance(row, dict) for row in rows):
            msg = "recovery table row must decode to an object"
            raise _recovery_error(msg)
        seen.add(name)
        last_order = order
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
    _validate_json_structure(value)
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except RecursionError as exc:
        msg = "recovery bundle exceeds structural complexity limit"
        raise _recovery_error(msg) from exc
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
    except RecursionError as exc:
        msg = "recovery bundle exceeds structural complexity limit"
        raise _recovery_error(msg) from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        msg = "malformed recovery bundle JSON"
        raise _recovery_error(msg) from exc


def _validate_json_structure(value: Any) -> None:
    """Bound container nesting before recursive decode and canonicalization."""
    pending = [(iter((value,)), 0)]
    while pending:
        children, parent_depth = pending[-1]
        try:
            item = next(children)
        except StopIteration:
            pending.pop()
            continue
        if not isinstance(item, dict | list):
            continue
        depth = parent_depth + 1
        if depth > _MAX_JSON_NESTING_DEPTH:
            msg = "recovery bundle exceeds structural complexity limit"
            raise _recovery_error(msg)
        nested = item.values() if isinstance(item, dict) else item
        pending.append((iter(nested), depth))


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
