import contextlib
import csv
import hashlib
import inspect
import io
import json
import math
import os
import pathlib
import re
import secrets
import shutil
import subprocess
import sys
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from urllib.parse import unquote, urlparse, urlsplit

from flask import (
    Flask,
    Response,
    abort,
    g,
    has_request_context,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from markupsafe import Markup, escape
from services.adblock_artifacts import get_adblock_artifacts
from services.adblock_store import get_adblock_store as _default_get_adblock_store
from services.audit_store import get_audit_store as _default_get_audit_store
from services.auth_store import get_auth_store
from services.background_guard import acquire_background_lock
from services.cert_manager import (
    generate_self_signed_ca_bundle,
    parse_pfx_bundle,
)
from services.certificate_bundles import (
    get_certificate_bundles as _default_get_certificate_bundles,
)
from services.certificate_core import (
    materialize_admin_ui_server_certificate,
    normalize_admin_ui_certificate_sans,
    sanitize_admin_ui_certificate_san_token,
    validate_tls_material_paths,
)
from services.clamav_config_forms import (
    apply_clamav_options_to_config,
    extract_clamav_options,
    get_clamav_ui_field_map,
    get_clamav_ui_sections,
    read_clamav_options_from_form,
)
from services.config_revisions import ConfigApplication, ConfigRevisionMetadata
from services.config_revisions import (
    get_config_revisions as _default_get_config_revisions,
)
from services.diagnostic_store import (
    get_diagnostic_store as _default_get_diagnostic_store,
)
from services.directory_auth import get_directory_auth_store
from services.error_pages import (
    list_error_pages,
    read_template,
    render_preview,
    template_tokens,
)
from services.errors import public_error_message
from services.housekeeping import (
    run_housekeeping_once as _default_run_housekeeping_once,
)
from services.housekeeping import start_housekeeping
from services.http_optimizations import install_http_optimizations
from services.logutil import log_exception_throttled
from services.observability_maintenance import (
    ObservabilityMaintenanceAlreadyRunningError,
)
from services.observability_maintenance import (
    clear_observability_logs as _default_clear_observability_logs,
)
from services.observability_maintenance import (
    get_observability_maintenance_status as _default_get_observability_maintenance_status,
)
from services.observability_maintenance import (
    get_observability_retention_settings as _default_get_observability_retention_settings,
)
from services.observability_maintenance import (
    set_observability_retention_settings as _default_set_observability_retention_settings,
)
from services.observability_queries import (
    get_observability_queries as _default_get_observability_queries,
)
from services.observability_queries import (
    normalize_runtime_health_state_errors,
)
from services.operation_ledger import get_operation_ledger
from services.pac_profiles_store import (
    get_pac_profiles_store as _default_get_pac_profiles_store,
)
from services.pac_renderer import build_proxy_pac_state, resolve_proxy_pac_target
from services.policy_materializer import (
    ProxyPolicyState,
    build_proxy_policy_state_from_stores,
)
from services.policy_requests import (
    POLICY_EXCEPTION_DEFAULT_DURATION_SECONDS,
    POLICY_EXCEPTION_MAX_DURATION_SECONDS,
    POLICY_EXCEPTION_MIN_DURATION_SECONDS,
)
from services.policy_requests import (
    get_policy_request_store as _default_get_policy_request_store,
)
from services.privacy_labels import pseudonymize
from services.proxy_client import ProxyClientError
from services.proxy_client import get_proxy_client as _default_get_proxy_client
from services.proxy_context import (
    get_default_proxy_id,
    get_proxy_id,
    normalize_proxy_id,
    reset_proxy_id,
    set_proxy_id,
)
from services.proxy_health import (
    build_remote_clamav_view,
    build_unavailable_runtime_health,
    check_adblock_icap_health,
    check_av_icap_health,
    check_clamd_health,
)
from services.proxy_health import send_sample_av_icap as _shared_send_sample_av_icap
from services.proxy_health import test_eicar as _shared_test_eicar
from services.proxy_logs import proxy_log_status_code
from services.proxy_registry import get_proxy_registry as _default_get_proxy_registry
from services.proxy_sync import request_proxy_reconcile
from services.runtime_helpers import env_float as _env_float
from services.runtime_helpers import extract_domain as _extract_domain
from services.safe_browsing_v5 import SafeBrowsingStore
from services.saml_auth import (
    build_saml_auth,
    build_sp_info,
    build_sp_metadata,
    get_saml_auth_store,
    profile_metadata_cache_ready,
    profile_metadata_ready,
    resolve_saml_login,
)
from services.schema_lifecycle import ensure_startup_schema_if_configured
from services.squid_config_forms import (
    build_template_options,
    build_template_options_from_form,
    get_config_ui_field_map,
    get_config_ui_sections,
    normalize_safe_form_kind,
    parse_cache_override_form,
)
from services.squidctl import SquidController
from services.ssl_errors_store import (
    get_ssl_errors_store as _default_get_ssl_errors_store,
)
from services.sslfilter_store import get_sslfilter_store as _default_get_sslfilter_store
from services.sslfilter_store import normalize_src_net_rule, validate_domain_rule
from services.timeseries_store import (
    get_timeseries_store as _default_get_timeseries_store,
)
from services.ui_support import (
    bulk_lines as _bulk_lines,
)
from services.ui_support import (
    csv_safe as _csv_safe,
)
from services.ui_support import (
    present_observability_summary as _present_observability_summary,
)
from services.ui_support import (
    present_ssl_error_rows as _present_ssl_error_rows,
)
from services.ui_support import (
    window_label as _window_label,
)
from services.version_status import (
    build_component_version_status,
    current_component_metadata,
)
from services.webfilter_core import (
    _normalize_category_name as _normalize_webfilter_category_name,
)
from services.webfilter_core import (
    validate_source_url as _validate_webfilter_source_url,
)
from services.webfilter_store import get_webfilter_store as _default_get_webfilter_store
from services.winhttp_registry_builder import (
    WinHttpBuilderError,
    build_contract_output,
    decode_basic_winhttp_settings_hex,
    normalize_reg_binary_export,
)
from werkzeug.exceptions import HTTPException

ADMIN_UI_SSL_CERTFILE = "/etc/squid/ssl/certs/admin-ui.crt"
ADMIN_UI_SSL_KEYFILE = "/etc/squid/ssl/certs/admin-ui.key"
ADMIN_UI_CA_DIR = "/etc/squid/ssl/certs"

app = Flask(__name__)
install_http_optimizations(app)
_asset_version = str(int(time.time()))
OBSERVABILITY_DEFAULT_WINDOW = 24 * 60 * 60
_PROXY_HEALTH_CACHE: dict[tuple[Any, ...], tuple[float, dict[str, Any]]] = {}
_ADMIN_VERSION_STATUS_CACHE: tuple[float, dict[str, Any]] | None = None


_PROXY_HEALTH_TTL_SECONDS = _env_float(
    "PROXY_HEALTH_UI_CACHE_TTL_SECONDS",
    10.0,
    minimum=0.0,
    maximum=120.0,
)
_PROXY_OBSERVABILITY_TTL_SECONDS = _env_float(
    "PROXY_OBSERVABILITY_UI_CACHE_TTL_SECONDS",
    15.0,
    minimum=0.0,
    maximum=300.0,
)
_PROXY_HEALTH_STALE_IF_ERROR_SECONDS = _env_float(
    "PROXY_HEALTH_UI_STALE_IF_ERROR_SECONDS",
    60.0,
    minimum=0.0,
    maximum=600.0,
)


def _cached_health_payload_within(
    cached: tuple[float, dict[str, Any]] | None,
    *,
    now: float,
    max_age_seconds: float,
) -> dict[str, Any] | None:
    if cached is None:
        return None
    cached_at, payload = cached
    if now - cached_at <= max(0.0, float(max_age_seconds)):
        return dict(payload)
    return None


def _fresh_cached_health_payload(
    cached: tuple[float, dict[str, Any]] | None,
    *,
    now: float,
    ttl_seconds: float,
) -> dict[str, Any] | None:
    return _cached_health_payload_within(
        cached,
        now=now,
        max_age_seconds=ttl_seconds,
    )


def _stale_cached_health_payload(
    cached: tuple[float, dict[str, Any]] | None,
    *,
    now: float,
    ttl_seconds: float,
) -> dict[str, Any] | None:
    return _cached_health_payload_within(
        cached,
        now=now,
        max_age_seconds=max(
            float(ttl_seconds),
            float(_PROXY_HEALTH_STALE_IF_ERROR_SECONDS),
        ),
    )


_OBSERVABILITY_SUMMARY_CACHE: dict[tuple[Any, ...], tuple[float, dict[str, int]]] = {}
_OBSERVABILITY_RESULT_CACHE: dict[tuple[Any, ...], tuple[float, Any]] = {}
_OBSERVABILITY_RESULT_CACHE_LIMIT = 24
_OBSERVABILITY_RESULT_CACHE_TTL_SECONDS = 5.0


def _proxy_health_timeout_seconds() -> float:
    return _env_float("PROXY_HEALTH_UI_TIMEOUT_SECONDS", 1.5, minimum=0.5, maximum=30.0)


def _proxy_clamav_health_timeout_seconds() -> float:
    return _env_float(
        "PROXY_CLAMAV_HEALTH_UI_TIMEOUT_SECONDS",
        5.0,
        minimum=0.5,
        maximum=30.0,
    )


_OBSERVABILITY_PANES = (
    "overview",
    "destinations",
    "clients",
    "cache",
    "ssl",
    "security",
    "performance",
    "remediation",
    "reports",
    "settings",
)
_OBSERVABILITY_SORT_DEFAULTS = {
    "overview": "requests",
    "destinations": "requests",
    "clients": "requests",
    "cache": "requests",
    "ssl": "recent",
    "security": "recent",
    "performance": "recent",
    "remediation": "confidence",
    "reports": "bandwidth",
    "settings": "recent",
}
_OBSERVABILITY_SORT_OPTIONS = {
    "overview": ("requests",),
    "destinations": ("requests", "recent", "cache", "clients"),
    "clients": ("requests", "recent", "cache", "destinations"),
    "cache": ("requests", "recent", "domains", "clients"),
    "ssl": ("recent",),
    "security": ("recent",),
    "performance": ("recent",),
    "remediation": ("confidence", "count", "recent"),
    "reports": ("bandwidth",),
    "settings": ("recent",),
}
_OBSERVABILITY_OVERVIEW_EXPORT_METRICS = (
    "request_records",
    "cache_hits",
    "cache_misses",
    "cache_hit_pct",
    "clients",
    "destinations",
    "transactions",
    "icap_events",
    "av_icap_events",
    "adblock_icap_events",
)
_OBSERVABILITY_EMPTY_EXPORT_HEADERS = {
    "overview": ["metric", "value"],
    "destinations": [
        "domain",
        "requests",
        "percent_of_total",
        "clients",
        "transactions",
        "cache_hit_pct",
        "av_icap_events",
        "adblock_icap_events",
        "last_seen",
    ],
    "clients": [
        "client_ip",
        "hostname",
        "requests",
        "percent_of_total",
        "destinations",
        "transactions",
        "cache_hit_pct",
        "av_icap_events",
        "adblock_icap_events",
        "last_seen",
    ],
    "cache": [
        "reason",
        "requests",
        "percent_of_misses",
        "domains",
        "clients",
        "last_seen",
    ],
    "ssl": [
        "domain",
        "category",
        "category_label",
        "reason",
        "count",
        "first_seen",
        "last_seen",
    ],
    "security": ["source", "timestamp", "client", "target", "detail", "status"],
    "performance": ["type", "timestamp", "subject", "metric", "detail"],
    "remediation": [
        "severity",
        "component",
        "issue",
        "subject",
        "observations",
        "confidence",
        "last_seen",
        "recommended_action",
        "evidence",
    ],
    "reports": [
        "section",
        "subject",
        "requests_or_events",
        "clients",
        "destinations",
        "bytes",
        "cache_saved_bytes",
        "last_seen",
        "detail",
    ],
}


def _default_check_icap_adblock() -> dict[str, Any]:
    return check_adblock_icap_health(timeout=0.8, error_formatter=public_error_message)


def _default_check_icap_av() -> dict[str, Any]:
    return check_av_icap_health(timeout=0.8, error_formatter=public_error_message)


def _default_check_clamd() -> dict[str, Any]:
    return check_clamd_health(timeout=0.8, error_formatter=public_error_message)


def _default_send_sample_av_icap() -> dict[str, Any]:
    return _shared_send_sample_av_icap(error_formatter=public_error_message)


def _default_test_eicar() -> dict[str, Any]:
    return _shared_test_eicar(error_formatter=public_error_message)


@dataclass(frozen=True)
class AppRuntimeServices:
    controller: Any
    get_certificate_bundles: Any
    get_config_revisions: Any
    get_diagnostic_store: Any
    get_audit_store: Any
    get_timeseries_store: Any
    get_ssl_errors_store: Any
    get_adblock_store: Any
    get_webfilter_store: Any
    get_sslfilter_store: Any
    get_pac_profiles_store: Any
    get_proxy_client: Any
    get_proxy_registry: Any
    get_observability_queries: Any
    clear_observability_logs: Any
    run_observability_maintenance: Any
    get_observability_retention_settings: Any
    set_observability_retention_settings: Any
    check_icap_adblock: Any
    check_icap_av: Any
    check_clamd: Any
    send_sample_av_icap: Any
    test_eicar: Any
    get_policy_request_store: Any = _default_get_policy_request_store


_default_app_runtime_services = AppRuntimeServices(
    controller=SquidController(),
    get_certificate_bundles=_default_get_certificate_bundles,
    get_config_revisions=_default_get_config_revisions,
    get_diagnostic_store=_default_get_diagnostic_store,
    get_audit_store=_default_get_audit_store,
    get_timeseries_store=_default_get_timeseries_store,
    get_ssl_errors_store=_default_get_ssl_errors_store,
    get_adblock_store=_default_get_adblock_store,
    get_webfilter_store=_default_get_webfilter_store,
    get_policy_request_store=_default_get_policy_request_store,
    get_sslfilter_store=_default_get_sslfilter_store,
    get_pac_profiles_store=_default_get_pac_profiles_store,
    get_proxy_client=_default_get_proxy_client,
    get_proxy_registry=_default_get_proxy_registry,
    get_observability_queries=_default_get_observability_queries,
    clear_observability_logs=_default_clear_observability_logs,
    run_observability_maintenance=_default_run_housekeeping_once,
    get_observability_retention_settings=_default_get_observability_retention_settings,
    set_observability_retention_settings=_default_set_observability_retention_settings,
    check_icap_adblock=_default_check_icap_adblock,
    check_icap_av=_default_check_icap_av,
    check_clamd=_default_check_clamd,
    send_sample_av_icap=_default_send_sample_av_icap,
    test_eicar=_default_test_eicar,
)


# Admin-initiated proxy sync can legitimately take longer than the generic
# ProxyClient default: config, policy, adblock, cache, and certificate changes
# may perform controlled Squid/c-icap restarts. Keep the UI request bounded, but
# do not report a failed apply while the proxy is still safely restarting.
_ADMIN_PROXY_SYNC_TIMEOUT_SECONDS = 120.0


def _app_runtime_services() -> AppRuntimeServices:
    return _default_app_runtime_services


class _ControllerProxy:
    def __getattr__(self, name: str) -> Any:
        return getattr(_app_runtime_services().controller, name)


squid_controller = _ControllerProxy()


def get_certificate_bundles():
    return _app_runtime_services().get_certificate_bundles()


def get_config_revisions():
    return _app_runtime_services().get_config_revisions()


def get_diagnostic_store():
    return _app_runtime_services().get_diagnostic_store()


def get_audit_store():
    return _app_runtime_services().get_audit_store()


def get_timeseries_store():
    return _app_runtime_services().get_timeseries_store()


def get_ssl_errors_store():
    return _app_runtime_services().get_ssl_errors_store()


def get_adblock_store():
    return _app_runtime_services().get_adblock_store()


def get_webfilter_store():
    return _app_runtime_services().get_webfilter_store()


def get_policy_request_store():
    return _app_runtime_services().get_policy_request_store()


def get_sslfilter_store():
    return _app_runtime_services().get_sslfilter_store()


def get_pac_profiles_store():
    return _app_runtime_services().get_pac_profiles_store()


def get_proxy_client():
    return _app_runtime_services().get_proxy_client()


def get_proxy_registry():
    return _app_runtime_services().get_proxy_registry()


def get_observability_queries():
    return _app_runtime_services().get_observability_queries()


def clear_observability_logs():
    return _app_runtime_services().clear_observability_logs()


def run_observability_maintenance(
    *,
    analyze: bool = False,
    optimize: bool = False,
    run_type: str = "manual",
):
    runner = _app_runtime_services().run_observability_maintenance
    if "run_type" in inspect.signature(runner).parameters:
        return runner(analyze=analyze, optimize=optimize, run_type=run_type)
    return runner(analyze=analyze, optimize=optimize)


def get_observability_maintenance_status():
    try:
        return _default_get_observability_maintenance_status()
    except Exception:
        return {"latest": {}, "history": []}


def get_observability_retention_settings():
    return _app_runtime_services().get_observability_retention_settings()


def set_observability_retention_settings(*, retention_days: object):
    return _app_runtime_services().set_observability_retention_settings(
        retention_days=retention_days,
    )


def _cached_proxy_health(
    proxy_id: str,
    *,
    timeout_seconds: float,
    ttl_seconds: float = _PROXY_HEALTH_TTL_SECONDS,
    full: bool = False,
) -> dict[str, Any]:
    """Short-lived per-process health cache for navigation-time UI snapshots."""
    key = (str(proxy_id or ""), float(timeout_seconds), bool(full))
    now = time.monotonic()
    cached = _PROXY_HEALTH_CACHE.get(key)
    cached_payload = _fresh_cached_health_payload(
        cached,
        now=now,
        ttl_seconds=ttl_seconds,
    )
    if cached_payload is not None:
        return cached_payload
    try:
        payload = get_proxy_client().get_health(
            proxy_id,
            timeout_seconds=timeout_seconds,
            full=full,
        )
    except ProxyClientError as exc:
        cached_payload = _stale_cached_health_payload(
            cached,
            now=time.monotonic(),
            ttl_seconds=ttl_seconds,
        )
        if cached_payload is not None:
            stale_payload = dict(cached_payload)
            stale_payload["previous_ok"] = bool(stale_payload.get("ok"))
            stale_payload["previous_status"] = str(
                stale_payload.get("status") or "unknown",
            )
            stale_payload["ok"] = False
            stale_payload["status"] = "degraded"
            stale_payload["health_cache_detail"] = str(
                exc or "using recent cached health after refresh failure",
            )
            stale_payload.setdefault(
                "detail",
                "using recent cached health after refresh failure",
            )
            stale_payload["_stale"] = True
            return stale_payload
        proxy = get_proxy_registry().get_proxy(proxy_id)
        payload = build_unavailable_runtime_health(
            str(exc),
            proxy_status=proxy.status if proxy else "offline",
        )
        payload["_unavailable_cached"] = True
        _PROXY_HEALTH_CACHE[key] = (now, dict(payload))
        return payload
    _PROXY_HEALTH_CACHE[key] = (now, dict(payload))
    return payload


def _short_sha(value: object, *, length: int = 12) -> str:
    return str(value or "").strip()[: max(1, int(length))]


def _safe_revision_id(value: object) -> int:
    try:
        return int(value or 0)
    except Exception:
        return 0


def _latest_operation(
    proxy_id: str,
    *,
    target_kind: str = "",
    target_ref: object | None = None,
    operation_types: set[str] | None = None,
):
    try:
        operations = get_operation_ledger().list_operations(proxy_id, limit=100)
    except Exception:
        return None

    target_ref_text = str(target_ref or "")
    matching = []
    for op in operations:
        if target_kind and str(getattr(op, "target_kind", "") or "") != target_kind:
            continue
        if target_ref_text and str(getattr(op, "target_ref", "") or "") != target_ref_text:
            continue
        if operation_types and str(getattr(op, "operation_type", "") or "") not in operation_types:
            continue
        matching.append(op)
    if not matching:
        return None
    return max(
        matching,
        key=lambda op: (
            int(getattr(op, "updated_ts", 0) or 0),
            int(getattr(op, "operation_id", 0) or 0),
        ),
    )


def _operation_view(operation: Any | None) -> dict[str, Any]:
    if operation is None:
        return {
            "operation_id": 0,
            "operation_status": "",
            "operation_type": "",
            "operation_subject": "",
            "operation_summary": "",
            "operation_updated_ts": 0,
            "operation_detail": "",
        }
    return {
        "operation_id": _safe_revision_id(getattr(operation, "operation_id", 0)),
        "operation_status": str(getattr(operation, "status", "") or ""),
        "operation_type": str(getattr(operation, "operation_type", "") or ""),
        "operation_subject": str(getattr(operation, "subject", "") or ""),
        "operation_summary": str(getattr(operation, "summary", "") or ""),
        "operation_updated_ts": _safe_revision_id(getattr(operation, "updated_ts", 0)),
        "operation_detail": str(getattr(operation, "detail", "") or ""),
    }


def _certificate_revision_by_id(bundle_store: Any, revision_id: object) -> Any | None:
    try:
        get_revision = getattr(bundle_store, "get_revision", None)
        if callable(get_revision):
            return get_revision(revision_id)
    except Exception:
        return None
    return None


def _certificate_revision_sha(bundle_store: Any, revision_id: object) -> str:
    revision = _certificate_revision_by_id(bundle_store, revision_id)
    return str(getattr(revision, "bundle_sha256", "") or "").strip()


def _certificate_global_revert_context(
    operation: Any,
    bundle_store: Any,
) -> dict[str, Any]:
    if str(getattr(operation, "rollback_kind", "") or "") != "certificate_revision":
        return {"is_global_certificate_revert": False}
    current_revision = None
    try:
        current_revision = bundle_store.get_active_bundle()
    except Exception:
        current_revision = None
    rollback_sha = _certificate_revision_sha(
        bundle_store,
        getattr(operation, "rollback_ref", ""),
    )
    current_revision_id = _safe_revision_id(getattr(current_revision, "revision_id", 0))
    current_sha = str(getattr(current_revision, "bundle_sha256", "") or "").strip()
    target_ref = str(getattr(operation, "target_ref", "") or "").strip()
    request_hash = str(getattr(operation, "request_hash", "") or "").strip()
    target_matches_active = bool(
        current_revision_id
        and target_ref
        and str(current_revision_id) == target_ref
        and (not request_hash or not current_sha or request_hash == current_sha)
    )
    return {
        "is_global_certificate_revert": True,
        "global_revert_current_revision": current_revision_id,
        "global_revert_current_sha": current_sha,
        "global_revert_current_short_sha": _short_sha(current_sha),
        "global_revert_target_revision": target_ref,
        "global_revert_target_sha": request_hash,
        "global_revert_target_short_sha": _short_sha(request_hash),
        "global_revert_rollback_revision": str(
            getattr(operation, "rollback_ref", "") or "",
        ),
        "global_revert_rollback_sha": rollback_sha,
        "global_revert_rollback_short_sha": _short_sha(rollback_sha),
        "global_revert_target_matches_active": target_matches_active,
    }


def _operation_template_rows(operations: list[Any]) -> list[Any]:
    bundle_store = None
    rows = []
    for operation in operations:
        if callable(getattr(operation, "to_dict", None)):
            row = SimpleNamespace(**operation.to_dict())
        else:
            row = operation
        if str(getattr(row, "rollback_kind", "") or "") == "certificate_revision":
            if bundle_store is None:
                bundle_store = get_certificate_bundles()
            context = _certificate_global_revert_context(row, bundle_store)
            for key, value in context.items():
                try:
                    setattr(row, key, value)
                except Exception:
                    pass
        else:
            try:
                row.is_global_certificate_revert = False
            except Exception:
                pass
        rows.append(row)
    return rows


def _state_badge_class(state: str) -> str:
    if state == "reconciled":
        return "ok"
    if state in {"failed", "superseded", "drift", "unavailable"}:
        return "danger"
    if state in {"unknown", "untracked"}:
        return ""
    return "warn"


def _certificate_runtime_state(
    proxy_id: str,
    *,
    active_revision: Any | None = None,
    runtime_health: dict[str, Any] | None = None,
    latest_apply: Any | None = None,
) -> dict[str, Any]:
    bundle_store = get_certificate_bundles()
    if active_revision is None:
        try:
            active_revision = bundle_store.get_active_bundle()
        except Exception:
            active_revision = None
    if runtime_health is None:
        try:
            runtime_health = _cached_proxy_health(
                proxy_id,
                timeout_seconds=_proxy_health_timeout_seconds(),
                full=True,
            )
        except Exception:
            runtime_health = {}

    revision_id = _safe_revision_id(getattr(active_revision, "revision_id", 0))
    desired_sha = str(getattr(active_revision, "bundle_sha256", "") or "").strip()
    running_revision_id = _safe_revision_id(
        (runtime_health or {}).get("active_certificate_revision_id"),
    )
    running_desired_sha = str(
        (runtime_health or {}).get("active_certificate_sha") or "",
    ).strip()
    running_sha = str(
        (runtime_health or {}).get("current_certificate_sha") or "",
    ).strip()
    if latest_apply is None and revision_id:
        try:
            latest_apply = bundle_store.latest_apply(proxy_id, revision_id=revision_id)
        except Exception:
            latest_apply = None

    latest_operation = _latest_operation(
        proxy_id,
        target_kind="certificate_revision",
        target_ref=revision_id,
        operation_types={"certificate_apply", "certificate_revert"},
    )
    operation_status = str(getattr(latest_operation, "status", "") or "")
    operation_id = _safe_revision_id(getattr(latest_operation, "operation_id", 0))
    applied_sha = str(getattr(latest_apply, "bundle_sha256", "") or "").strip()
    applied_ts = _safe_revision_id(getattr(latest_apply, "applied_ts", 0))
    apply_ok = bool(getattr(latest_apply, "ok", False)) if latest_apply else False
    apply_detail = str(getattr(latest_apply, "detail", "") or "") if latest_apply else ""
    apply_matches = bool(
        revision_id
        and latest_apply is not None
        and _safe_revision_id(getattr(latest_apply, "revision_id", 0)) == revision_id
        and apply_ok
        and desired_sha
        and applied_sha
        and applied_sha == desired_sha
    )
    running_matches = bool(
        revision_id
        and desired_sha
        and running_sha
        and desired_sha == running_sha
        and (not running_revision_id or running_revision_id == revision_id)
    )

    if not revision_id:
        state = "untracked"
        label = "No active bundle"
        detail = "No active certificate bundle is saved."
    elif operation_status in {"pending", "applying"}:
        state = operation_status
        label = "Apply pending" if operation_status == "pending" else "Apply running"
        detail = (
            f"Certificate revision {revision_id} is {operation_status} as operation #{operation_id}; "
            "do not treat it as applied until runtime or apply evidence confirms it."
        )
    elif operation_status in {"failed", "superseded"}:
        state = operation_status
        label = "Apply failed" if operation_status == "failed" else "Apply superseded"
        detail = (
            f"Certificate revision {revision_id} ended {operation_status} in operation #{operation_id}; "
            "a recovery or later reconcile is required before trusting this proxy."
        )
    elif running_matches:
        state = "verified"
        label = "Runtime verified"
        detail = f"Desired certificate bundle {revision_id} matches the selected proxy runtime."
    elif apply_matches:
        state = "applied_unverified"
        label = "Apply recorded"
        detail = (
            f"Proxy recorded a successful apply for certificate revision {revision_id}, "
            "but current runtime bundle SHA evidence is unavailable."
        )
    elif latest_apply is not None and not apply_ok:
        state = "failed"
        label = "Apply failed"
        detail = apply_detail or f"Proxy recorded a failed apply for certificate revision {revision_id}."
    elif (
        latest_apply is not None
        and desired_sha
        and applied_sha
        and applied_sha != desired_sha
    ):
        state = "stale"
        label = "Stale apply evidence"
        detail = "Recorded certificate bundle hash does not match the active bundle."
    elif running_sha:
        state = "drift"
        label = "Desired/running mismatch"
        detail = (
            f"Desired certificate bundle {_short_sha(desired_sha) or 'unknown sha'} does not "
            f"match running bundle {_short_sha(running_sha) or 'unknown sha'}."
        )
    else:
        state = "unknown"
        label = "Pending evidence"
        detail = "No selected-proxy apply or runtime SHA evidence is available for the active bundle."

    can_force_reconcile = bool(
        revision_id
        and state
        in {
            "applied_unverified",
            "failed",
            "superseded",
            "stale",
            "drift",
            "unknown",
        }
    )
    action_help = ""
    if can_force_reconcile:
        action_help = (
            f"Queue a selected-proxy retry for desired certificate revision {revision_id} "
            f"({_short_sha(desired_sha) or 'unknown hash'})."
        )
    elif state in {"pending", "applying"}:
        action_help = (
            f"Operation #{operation_id} is already {operation_status}; wait for it to finish "
            "or use Operations if it later fails."
        )
    elif not revision_id:
        action_help = "Generate or upload a CA bundle before retrying proxy certificate apply."

    return {
        "proxy_id": proxy_id,
        "state": state,
        "label": label,
        "ok": True
        if state == "verified"
        else False
        if state in {"failed", "superseded", "drift", "stale"}
        else None,
        "detail": detail,
        "desired_revision_id": revision_id,
        "desired_bundle_sha256": desired_sha,
        "applied_bundle_sha256": applied_sha,
        "running_bundle_sha256": running_sha,
        "running_desired_bundle_sha256": running_desired_sha,
        "applied_ts": applied_ts,
        "can_force_reconcile": can_force_reconcile,
        "force_reconcile_help": action_help,
        **_operation_view(latest_operation),
    }


def _latest_config_revision_operation(proxy_id: str, revision_id: int):
    if revision_id <= 0:
        return None
    return _latest_operation(
        proxy_id,
        target_kind="config_revision",
        target_ref=revision_id,
    )


def _config_runtime_state(
    proxy_id: str,
    *,
    active_revision: ConfigRevisionMetadata | None = None,
    runtime_health: dict[str, Any] | None = None,
    latest_apply: ConfigApplication | None = None,
) -> dict[str, Any]:
    revisions = get_config_revisions()
    if active_revision is None:
        try:
            active_revision = revisions.get_active_revision_metadata(proxy_id)
        except Exception:
            active_revision = None
    if runtime_health is None:
        try:
            runtime_health = _cached_proxy_health(
                proxy_id,
                timeout_seconds=_proxy_health_timeout_seconds(),
                full=True,
            )
        except Exception:
            runtime_health = {}
    if latest_apply is None:
        try:
            latest_apply = revisions.latest_apply(proxy_id)
        except Exception:
            latest_apply = None

    revision_id = _safe_revision_id(getattr(active_revision, "revision_id", 0))
    revision_sha = str(getattr(active_revision, "config_sha256", "") or "")
    running_revision_id = _safe_revision_id(
        (runtime_health or {}).get("active_revision_id"),
    )
    runtime_active_sha = str((runtime_health or {}).get("active_revision_sha") or "")
    running_sha = str((runtime_health or {}).get("current_config_sha") or "")
    latest_apply_revision_id = _safe_revision_id(
        getattr(latest_apply, "revision_id", 0),
    )
    latest_operation = _latest_config_revision_operation(proxy_id, revision_id)
    operation_status = str(getattr(latest_operation, "status", "") or "")
    operation_id = _safe_revision_id(getattr(latest_operation, "operation_id", 0))

    comparison_sha = runtime_active_sha or revision_sha
    running_matches = bool(
        revision_id
        and comparison_sha
        and running_sha
        and comparison_sha == running_sha
        and (not running_revision_id or running_revision_id == revision_id)
    )
    apply_matches = bool(
        revision_id
        and latest_apply is not None
        and latest_apply_revision_id == revision_id
        and bool(getattr(latest_apply, "ok", False))
    )
    pending_statuses = {"pending", "applying"}
    failed_statuses = {"failed", "superseded"}

    if not revision_id:
        state = "untracked"
        label = "No saved revision"
        detail = "No active config revision is saved for this proxy yet."
    elif operation_status in pending_statuses:
        state = operation_status
        label = "Apply pending" if operation_status == "pending" else "Apply running"
        detail = (
            f"Saved revision {revision_id} is {operation_status} as operation #{operation_id}; "
            "the running proxy config may still be the previous revision."
        )
    elif operation_status in failed_statuses:
        state = operation_status
        label = "Apply failed" if operation_status == "failed" else "Apply superseded"
        detail = (
            f"Saved revision {revision_id} ended {operation_status} in operation #{operation_id}; "
            "do not treat it as running until a later apply succeeds."
        )
    elif running_matches:
        state = "reconciled"
        label = "Saved revision running"
        detail = f"Saved revision {revision_id} matches the selected proxy runtime."
    elif apply_matches:
        state = "applied_unverified"
        label = "Apply recorded"
        detail = (
            f"The proxy recorded a successful apply for saved revision {revision_id}, "
            "but current runtime SHA evidence is unavailable."
        )
    elif running_sha:
        state = "drift"
        label = "Saved/running mismatch"
        detail = (
            f"Saved revision {revision_id} ({_short_sha(revision_sha) or 'unknown sha'}) "
            f"does not match running config {_short_sha(running_sha) or 'unknown sha'}."
        )
    else:
        state = "unknown"
        label = "Runtime unknown"
        detail = "The selected proxy runtime did not report a running config SHA."

    return {
        "state": state,
        "label": label,
        "detail": detail,
        "proxy_id": proxy_id,
        "active_revision_id": revision_id,
        "active_revision_sha": revision_sha,
        "active_revision_short_sha": _short_sha(revision_sha),
        "running_revision_id": running_revision_id,
        "runtime_active_revision_sha": runtime_active_sha,
        "runtime_active_revision_short_sha": _short_sha(runtime_active_sha),
        "running_config_sha": running_sha,
        "running_config_short_sha": _short_sha(running_sha),
        "latest_apply_revision_id": latest_apply_revision_id,
        "latest_apply_ok": bool(getattr(latest_apply, "ok", False))
        if latest_apply is not None
        else None,
        "latest_apply_ts": _safe_revision_id(getattr(latest_apply, "applied_ts", 0)),
        "latest_apply_detail": str(getattr(latest_apply, "detail", "") or ""),
        "operation_id": operation_id,
        "operation_status": operation_status,
        "operation_updated_ts": _safe_revision_id(
            getattr(latest_operation, "updated_ts", 0),
        ),
        "operation_detail": str(getattr(latest_operation, "detail", "") or ""),
    }


def _selected_proxy_policy_state(proxy_id: str) -> ProxyPolicyState:
    return build_proxy_policy_state_from_stores(
        proxy_id,
        sslfilter_store=get_sslfilter_store(),
        webfilter_store=get_webfilter_store(),
    )


def _desired_policy_sha_for_proxy(proxy_id: str) -> tuple[str, str]:
    try:
        state = _selected_proxy_policy_state(proxy_id)
    except Exception as exc:
        return "", public_error_message(
            exc,
            default="Desired policy SHA could not be calculated.",
        )
    return str(state.policy_sha256 or ""), ""


def _latest_policy_operation(proxy_id: str, desired_policy_sha: str = ""):
    exact = None
    if desired_policy_sha:
        exact = _latest_operation(
            proxy_id,
            target_kind="policy_state",
            target_ref=desired_policy_sha,
            operation_types={"policy_sync"},
        )
    if exact is not None:
        return exact
    return _latest_operation(
        proxy_id,
        target_kind="policy_state",
        operation_types={"policy_sync"},
    )


def _operation_status_label(status: str) -> str:
    return {
        "pending": "pending",
        "applying": "running",
        "applied": "succeeded",
        "failed": "failed",
        "superseded": "superseded",
    }.get(status, status or "none")


def _policy_runtime_state(
    proxy_id: str,
    *,
    runtime_health: dict[str, Any] | None = None,
) -> dict[str, Any]:
    desired_policy_sha, desired_error = _desired_policy_sha_for_proxy(proxy_id)
    if runtime_health is None:
        try:
            runtime_health = _cached_proxy_health(
                proxy_id,
                timeout_seconds=_proxy_health_timeout_seconds(),
                full=True,
            )
        except Exception:
            runtime_health = {}
    runtime_desired_sha = str((runtime_health or {}).get("desired_policy_sha") or "")
    current_policy_sha = str((runtime_health or {}).get("current_policy_sha") or "")
    state_errors = normalize_runtime_health_state_errors(
        (runtime_health or {}).get("state_errors"),
    )
    latest_operation = _latest_policy_operation(proxy_id, desired_policy_sha)
    operation_status = str(getattr(latest_operation, "status", "") or "")
    operation_id = _safe_revision_id(getattr(latest_operation, "operation_id", 0))
    operation_target_ref = str(getattr(latest_operation, "target_ref", "") or "")
    operation_matches_desired = bool(
        latest_operation is not None
        and desired_policy_sha
        and operation_target_ref == desired_policy_sha
    )
    running_matches = bool(
        desired_policy_sha and current_policy_sha and desired_policy_sha == current_policy_sha
    )
    operation_matches_current_desired = bool(
        operation_matches_desired or (latest_operation is not None and not operation_target_ref)
    )

    if operation_status in {"pending", "applying"} and operation_matches_current_desired:
        state = operation_status
        label = "Policy apply pending" if operation_status == "pending" else "Policy apply running"
        detail = (
            f"Selected-proxy policy operation #{operation_id} is {operation_status}; "
            "desired policy settings are not proven running yet."
        )
    elif operation_status in {"failed", "superseded"} and operation_matches_current_desired:
        state = operation_status
        label = "Policy apply failed" if operation_status == "failed" else "Policy apply superseded"
        detail = (
            f"Selected-proxy policy operation #{operation_id} ended {operation_status}; "
            "do not treat the saved desired policy as running until a later reconcile succeeds."
        )
    elif running_matches:
        state = "reconciled"
        label = "Policy running"
        detail = "Desired policy SHA matches the selected proxy runtime policy SHA."
    elif operation_status == "applied" and operation_matches_current_desired:
        state = "applied_unverified"
        label = "Policy apply succeeded"
        detail = (
            f"Selected-proxy policy operation #{operation_id} succeeded, "
            "but current runtime policy SHA evidence is unavailable."
        )
    elif desired_policy_sha and current_policy_sha:
        state = "drift"
        label = "Desired/running mismatch"
        detail = (
            f"Desired policy {_short_sha(desired_policy_sha) or 'unknown sha'} does not "
            f"match running policy {_short_sha(current_policy_sha) or 'unknown sha'}."
        )
    elif desired_error:
        state = "unknown"
        label = "Policy evidence limited"
        detail = (
            "Desired policy state could not be fingerprinted for this Admin UI view. "
            f"{desired_error}"
        )
    else:
        state = "unknown"
        label = "Runtime policy unknown"
        detail = "The selected proxy runtime did not report enough policy SHA evidence."

    if latest_operation is not None and not operation_matches_current_desired:
        detail = (
            f"{detail} Latest selected-proxy policy operation #{operation_id} targets "
            "a different desired policy fingerprint, so it is shown as context only."
        )

    operation_payload = _operation_view(latest_operation)
    return {
        **operation_payload,
        "state": state,
        "label": label,
        "detail": detail,
        "badge_class": _state_badge_class(state),
        "proxy_id": proxy_id,
        "desired_policy_sha": desired_policy_sha,
        "desired_policy_short_sha": _short_sha(desired_policy_sha),
        "runtime_desired_policy_sha": runtime_desired_sha,
        "runtime_desired_policy_short_sha": _short_sha(runtime_desired_sha),
        "current_policy_sha": current_policy_sha,
        "current_policy_short_sha": _short_sha(current_policy_sha),
        "operation_status_label": _operation_status_label(operation_status),
        "operation_target_ref": operation_target_ref,
        "operation_target_short_ref": _short_sha(operation_target_ref),
        "operation_matches_desired": operation_matches_desired,
        "runtime_health_status": str((runtime_health or {}).get("status") or ""),
        "runtime_health_ts": _safe_revision_id((runtime_health or {}).get("timestamp")),
        "runtime_state_errors": state_errors,
    }


def _runtime_health_for_proxy(proxy_id: str) -> dict[str, Any]:
    try:
        return _cached_proxy_health(
            proxy_id,
            timeout_seconds=_proxy_health_timeout_seconds(),
            full=True,
        )
    except Exception:
        return {}


def _runtime_unavailable(runtime_health: dict[str, Any]) -> bool:
    status = str((runtime_health or {}).get("status") or "").lower()
    proxy_status = str((runtime_health or {}).get("proxy_status") or "").lower()
    return bool(
        (runtime_health or {}).get("_unavailable_cached")
        or status in {"offline", "unavailable"}
        or proxy_status in {"offline", "unavailable"}
    )


def _runtime_evidence_base(proxy_id: str, runtime_health: dict[str, Any]) -> dict[str, Any]:
    return {
        "proxy_id": proxy_id,
        "runtime_health_status": str((runtime_health or {}).get("status") or "unknown"),
        "runtime_proxy_status": str((runtime_health or {}).get("proxy_status") or ""),
        "runtime_health_ts": _safe_revision_id((runtime_health or {}).get("timestamp")),
        "runtime_state_errors": normalize_runtime_health_state_errors(
            (runtime_health or {}).get("state_errors"),
        ),
    }


def _latest_pac_operation(proxy_id: str, desired_pac_sha: str = ""):
    if desired_pac_sha:
        exact = _latest_operation(
            proxy_id,
            target_kind="pac_state",
            target_ref=desired_pac_sha,
            operation_types={"pac_refresh"},
        )
        if exact is not None:
            return exact
    return _latest_operation(
        proxy_id,
        target_kind="pac_state",
        operation_types={"pac_refresh"},
    )


def _pac_runtime_state(
    proxy_id: str,
    *,
    runtime_health: dict[str, Any] | None = None,
) -> dict[str, Any]:
    runtime_health = runtime_health if runtime_health is not None else _runtime_health_for_proxy(proxy_id)
    desired_pac_sha, desired_error = _desired_pac_state_sha_for_proxy(proxy_id)
    current_pac_sha = str((runtime_health or {}).get("current_pac_sha") or "")
    runtime_desired_pac_sha = str((runtime_health or {}).get("desired_pac_sha") or "")
    latest_operation = _latest_pac_operation(proxy_id, desired_pac_sha)
    operation_status = str(getattr(latest_operation, "status", "") or "")
    operation_id = _safe_revision_id(getattr(latest_operation, "operation_id", 0))
    operation_target_ref = str(getattr(latest_operation, "target_ref", "") or "")
    operation_matches_desired = bool(
        latest_operation is not None
        and desired_pac_sha
        and operation_target_ref == desired_pac_sha
    )
    operation_matches_current_desired = bool(
        operation_matches_desired or (latest_operation is not None and not operation_target_ref)
    )

    if not desired_pac_sha and not desired_error:
        state = "no_desired_state"
        label = "No desired PAC state"
        detail = "No saved PAC desired-state fingerprint is available for the selected proxy."
        recovery_action = "Save PAC routing settings to queue selected-proxy materialization."
    elif operation_status in {"pending", "applying"} and operation_matches_current_desired:
        state = operation_status
        label = "PAC materialization pending" if operation_status == "pending" else "PAC materialization running"
        detail = (
            f"Selected-proxy PAC operation #{operation_id} is {operation_status}; "
            "saved PAC profiles are not proven materialized yet."
        )
        recovery_action = "Wait for the selected proxy to reconcile, then refresh this page."
    elif operation_status in {"failed", "superseded"} and operation_matches_current_desired:
        state = operation_status
        label = "PAC materialization failed" if operation_status == "failed" else "PAC materialization superseded"
        detail = (
            f"Selected-proxy PAC operation #{operation_id} ended {operation_status}; "
            "do not treat saved PAC profiles as selected-proxy runtime until a later refresh succeeds."
        )
        recovery_action = "Save the PAC settings again to queue a fresh selected-proxy refresh."
    elif desired_pac_sha and current_pac_sha and desired_pac_sha == current_pac_sha:
        state = "reconciled"
        label = "PAC materialized"
        detail = "Saved PAC desired SHA matches the selected proxy runtime PAC SHA."
        recovery_action = "No action needed."
    elif desired_pac_sha and current_pac_sha:
        state = "drift"
        label = "Saved/runtime PAC mismatch"
        detail = (
            f"Saved PAC {_short_sha(desired_pac_sha) or 'unknown sha'} does not match "
            f"selected-proxy runtime PAC {_short_sha(current_pac_sha) or 'unknown sha'}."
        )
        recovery_action = "Save PAC routing settings to queue selected-proxy materialization."
    elif _runtime_unavailable(runtime_health):
        state = "unavailable"
        label = "PAC runtime unavailable"
        detail = "The selected proxy runtime is unavailable, so saved PAC profiles cannot be verified as materialized."
        recovery_action = "Restore selected-proxy health, then save PAC settings or run the existing proxy sync."
    elif desired_error:
        state = "unknown"
        label = "PAC evidence limited"
        detail = f"Desired PAC state could not be fingerprinted. {desired_error}"
        recovery_action = "Fix the PAC desired-state error, then save PAC settings again."
    else:
        state = "unknown"
        label = "PAC runtime unknown"
        detail = "The selected proxy did not report enough PAC SHA evidence to verify materialization."
        recovery_action = "Refresh selected-proxy health or use the existing PAC save controls to queue reconciliation."

    if latest_operation is not None and not operation_matches_current_desired:
        detail = (
            f"{detail} Latest selected-proxy PAC operation #{operation_id} targets a different "
            "PAC fingerprint, so stale success/failure is context only."
        )

    return {
        **_operation_view(latest_operation),
        **_runtime_evidence_base(proxy_id, runtime_health),
        "state": state,
        "label": label,
        "detail": detail,
        "recovery_action": recovery_action,
        "badge_class": _state_badge_class(state),
        "desired_pac_sha": desired_pac_sha,
        "desired_pac_short_sha": _short_sha(desired_pac_sha),
        "runtime_desired_pac_sha": runtime_desired_pac_sha,
        "runtime_desired_pac_short_sha": _short_sha(runtime_desired_pac_sha),
        "current_pac_sha": current_pac_sha,
        "current_pac_short_sha": _short_sha(current_pac_sha),
        "operation_status_label": _operation_status_label(operation_status),
        "operation_target_ref": operation_target_ref,
        "operation_target_short_ref": _short_sha(operation_target_ref),
        "operation_matches_desired": operation_matches_desired,
    }


def _latest_adblock_operation(proxy_id: str, revision_id: int = 0, artifact_sha: str = ""):
    if revision_id > 0:
        exact = _latest_operation(
            proxy_id,
            target_kind="adblock_artifact",
            target_ref=str(revision_id),
            operation_types={"adblock_refresh"},
        )
        if exact is not None:
            return exact
    return _latest_operation(
        proxy_id,
        target_kind="adblock_artifact",
        operation_types={"adblock_refresh"},
    )


def _latest_adblock_apply(proxy_id: str, revision_id: int):
    if revision_id <= 0:
        return None
    try:
        return get_adblock_artifacts().latest_apply(proxy_id, revision_id=revision_id)
    except Exception:
        return None


def _adblock_runtime_state(
    proxy_id: str,
    *,
    active_artifact: dict[str, Any],
    runtime_health: dict[str, Any] | None = None,
) -> dict[str, Any]:
    runtime_health = runtime_health if runtime_health is not None else _runtime_health_for_proxy(proxy_id)
    revision_id = _safe_int((active_artifact or {}).get("revision_id"))
    artifact_sha = str((active_artifact or {}).get("artifact_sha256") or "")
    current_sha = str((runtime_health or {}).get("current_adblock_sha") or "")
    runtime_active_sha = str((runtime_health or {}).get("active_adblock_sha") or "")
    latest_apply = _latest_adblock_apply(proxy_id, revision_id)
    latest_operation = _latest_adblock_operation(proxy_id, revision_id, artifact_sha)
    operation_status = str(getattr(latest_operation, "status", "") or "")
    operation_id = _safe_revision_id(getattr(latest_operation, "operation_id", 0))
    operation_target_ref = str(getattr(latest_operation, "target_ref", "") or "")
    operation_request_hash = str(getattr(latest_operation, "request_hash", "") or "")
    operation_matches_active = bool(
        latest_operation is not None
        and revision_id > 0
        and operation_target_ref == str(revision_id)
        and (not artifact_sha or not operation_request_hash or operation_request_hash == artifact_sha)
    )
    apply_ok = bool(getattr(latest_apply, "ok", False)) if latest_apply is not None else False
    apply_sha = str(getattr(latest_apply, "artifact_sha256", "") or "") if latest_apply is not None else ""
    apply_matches_active = bool(apply_ok and (not artifact_sha or apply_sha == artifact_sha))

    if not (active_artifact or {}).get("available"):
        state = "no_active_artifact"
        label = "No active adblock artifact"
        detail = "No shared compiled adblock artifact is active; there is no selected-proxy artifact to verify."
        recovery_action = "Use the existing Update now or Save lists controls to build an active artifact."
    elif operation_status in {"pending", "applying"} and operation_matches_active:
        state = operation_status
        label = "Adblock apply pending" if operation_status == "pending" else "Adblock apply running"
        detail = (
            f"Selected-proxy adblock operation #{operation_id} is {operation_status}; "
            "the shared artifact is not proven applied to runtime yet."
        )
        recovery_action = "Wait for selected-proxy reconciliation, then refresh this page."
    elif operation_status in {"failed", "superseded"} and operation_matches_active:
        state = operation_status
        label = "Adblock apply failed" if operation_status == "failed" else "Adblock apply superseded"
        detail = (
            f"Selected-proxy adblock operation #{operation_id} ended {operation_status}; "
            "do not treat the shared built artifact as applied runtime."
        )
        recovery_action = "Use the existing adblock refresh controls to queue a fresh selected-proxy apply."
    elif artifact_sha and current_sha and artifact_sha == current_sha and apply_matches_active:
        state = "reconciled"
        label = "Adblock artifact applied"
        detail = "Active shared artifact hash matches the selected proxy runtime hash and revision-scoped apply evidence."
        recovery_action = "No action needed."
    elif artifact_sha and current_sha and artifact_sha != current_sha:
        state = "drift"
        label = "Built/runtime adblock mismatch"
        detail = (
            f"Active artifact {_short_sha(artifact_sha) or 'unknown sha'} does not match "
            f"selected-proxy runtime {_short_sha(current_sha) or 'unknown sha'}."
        )
        recovery_action = "Use the existing adblock refresh controls to queue selected-proxy materialization."
    elif _runtime_unavailable(runtime_health):
        state = "unavailable"
        label = "Adblock runtime unavailable"
        detail = "The selected proxy runtime is unavailable, so the shared built artifact cannot be verified as applied."
        recovery_action = "Restore selected-proxy health, then use the existing adblock refresh controls or proxy sync."
    else:
        state = "built_unverified"
        label = "Built, not runtime-verified"
        detail = "A shared artifact exists, but selected-proxy runtime/apply evidence is missing for this revision."
        recovery_action = "Use the existing adblock refresh controls to queue selected-proxy materialization."

    if latest_operation is not None and not operation_matches_active:
        detail = (
            f"{detail} Latest selected-proxy adblock operation #{operation_id} targets a different "
            "artifact revision/hash, so stale success/failure is context only."
        )

    return {
        **_operation_view(latest_operation),
        **_runtime_evidence_base(proxy_id, runtime_health),
        "state": state,
        "label": label,
        "detail": detail,
        "recovery_action": recovery_action,
        "badge_class": _state_badge_class(state),
        "active_revision_id": revision_id,
        "active_adblock_sha": artifact_sha,
        "active_adblock_short_sha": _short_sha(artifact_sha),
        "runtime_active_adblock_sha": runtime_active_sha,
        "runtime_active_adblock_short_sha": _short_sha(runtime_active_sha),
        "current_adblock_sha": current_sha,
        "current_adblock_short_sha": _short_sha(current_sha),
        "latest_apply_id": _safe_revision_id(getattr(latest_apply, "application_id", 0)),
        "latest_apply_ok": bool(getattr(latest_apply, "ok", False)) if latest_apply is not None else None,
        "latest_apply_ts": _safe_revision_id(getattr(latest_apply, "applied_ts", 0)),
        "latest_apply_detail": str(getattr(latest_apply, "detail", "") or ""),
        "latest_apply_sha": apply_sha,
        "latest_apply_short_sha": _short_sha(apply_sha),
        "operation_status_label": _operation_status_label(operation_status),
        "operation_target_ref": operation_target_ref,
        "operation_target_short_ref": str(operation_target_ref or "")[:12],
        "operation_request_hash": operation_request_hash,
        "operation_request_short_hash": _short_sha(operation_request_hash),
        "operation_matches_active": operation_matches_active,
    }


def _cached_admin_version_status() -> dict[str, Any]:
    global _ADMIN_VERSION_STATUS_CACHE
    now = time.monotonic()
    ttl_seconds = _env_float(
        "VERSION_STATUS_CACHE_TTL_SECONDS",
        3600.0,
        minimum=60.0,
        maximum=86400.0,
    )
    if _ADMIN_VERSION_STATUS_CACHE is not None:
        cached_at, cached_payload = _ADMIN_VERSION_STATUS_CACHE
        if now - cached_at <= ttl_seconds:
            return dict(cached_payload)
    payload = build_component_version_status(current_component_metadata("admin-ui"))
    _ADMIN_VERSION_STATUS_CACHE = (now, dict(payload))
    return payload


def _proxy_version_status_from_health(health: dict[str, Any]) -> dict[str, Any]:
    metadata = health.get("version") if isinstance(health, dict) else None
    if not isinstance(metadata, dict):
        metadata = {"component": "proxy", "version": "unknown"}
    return build_component_version_status(metadata)


def _initial_version_header_status() -> dict[str, Any]:
    admin = current_component_metadata("admin-ui")
    return {
        "admin": {
            **admin,
            "state": "unknown",
            "detail": "Latest version check has not run yet.",
        },
        "proxy": {
            "component": "proxy",
            "version": "unknown",
            "revision": "",
            "revision_short": "unknown",
            "state": "unknown",
            "detail": "Selected proxy metadata has not loaded yet.",
        },
    }


def _prune_observability_result_cache() -> None:
    while len(_OBSERVABILITY_RESULT_CACHE) > _OBSERVABILITY_RESULT_CACHE_LIMIT:
        first_key = next(iter(_OBSERVABILITY_RESULT_CACHE), None)
        if first_key is None:
            break
        _OBSERVABILITY_RESULT_CACHE.pop(first_key, None)


def _observability_result_cache_key(
    *parts: Any,
    bucket_seconds: float = _OBSERVABILITY_RESULT_CACHE_TTL_SECONDS,
) -> tuple[Any, ...]:
    return tuple(parts)


def _runtime_health_remediation_cache_fingerprint(
    runtime_health: dict[str, Any] | None,
) -> str:
    if not isinstance(runtime_health, dict):
        return ""
    services = runtime_health.get("services")
    service_health = {}
    if isinstance(services, dict):
        service_health = {
            str(name): {
                "ok": payload.get("ok"),
                "detail": payload.get("detail"),
            }
            for name, payload in services.items()
            if isinstance(payload, dict)
        }
    stats = runtime_health.get("stats")
    memory = {}
    if isinstance(stats, dict) and isinstance(stats.get("memory"), dict):
        memory = dict(stats.get("memory") or {})
    payload = {
        "_stale": runtime_health.get("_stale"),
        "_unavailable_cached": runtime_health.get("_unavailable_cached"),
        "detail": runtime_health.get("detail"),
        "health_cache_detail": runtime_health.get("health_cache_detail"),
        "memory": memory,
        "proxy_id": runtime_health.get("proxy_id"),
        "proxy_status": runtime_health.get("proxy_status"),
        "services": service_health,
        "state_errors": normalize_runtime_health_state_errors(
            runtime_health.get("state_errors")
        ),
        "status": runtime_health.get("status"),
        "timestamp": runtime_health.get("timestamp"),
    }
    encoded = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8", errors="replace")).hexdigest()[:16]


def _cached_observability_result(
    cache_key: tuple[Any, ...],
    builder: Any,
    *,
    ttl_seconds: float = _OBSERVABILITY_RESULT_CACHE_TTL_SECONDS,
) -> Any:
    now = time.monotonic()
    cached = _OBSERVABILITY_RESULT_CACHE.get(cache_key)
    if cached is not None:
        cached_at, payload = cached
        if now - cached_at <= max(0.0, float(ttl_seconds)):
            return dict(payload) if isinstance(payload, dict) else payload
    payload = builder()
    stored = dict(payload) if isinstance(payload, dict) else payload
    _OBSERVABILITY_RESULT_CACHE[cache_key] = (now, stored)
    _prune_observability_result_cache()
    return dict(stored) if isinstance(stored, dict) else stored


def _max_workers() -> int:
    """Upper bound for Squid workers.

    Must match the backend Squid controller clamp to avoid the UI silently
    downscaling an existing config.
    """
    try:
        v = int((os.environ.get("MAX_WORKERS") or "4").strip())
    except Exception:
        v = 4
    # Hard-cap worker count to keep SMP sizing sane for this container profile.
    return min(4, max(1, v))


# Global request body limit (bytes). Keep reasonably above common form posts.
try:
    app.config.setdefault(
        "MAX_CONTENT_LENGTH",
        int((os.environ.get("MAX_CONTENT_LENGTH") or str(16 * 1024 * 1024)).strip()),
    )
except Exception:
    app.config.setdefault("MAX_CONTENT_LENGTH", 16 * 1024 * 1024)

# Session security: persist a secret key so login survives container restarts.
_auth_store = get_auth_store()


def _configured_app_secret():
    for name in ("FLASK_SECRET_KEY", "APP_SECRET_KEY", "SECRET_KEY"):
        value = (os.environ.get(name) or "").strip()
        if value:
            return value
    return ""


_env_secret = _configured_app_secret()


def _auth_secret_key():
    return _auth_store.get_or_create_secret_key()


def _directory_secret_key():
    if _env_secret:
        return _env_secret
    return _auth_secret_key()


_directory_auth_store = get_directory_auth_store(_directory_secret_key)
_saml_auth_store = get_saml_auth_store()
try:
    ensure_startup_schema_if_configured()
except Exception:
    app.logger.exception("Failed to apply MySQL schema migrations at Admin UI startup")
    raise
if _env_secret:
    app.secret_key = _env_secret
else:
    try:
        app.secret_key = _auth_store.get_or_create_secret_key()
    except Exception:
        # Fallback: sessions will reset on restart.
        app.secret_key = secrets.token_urlsafe(48)

# Cookie hardening. Defaults chosen to avoid breaking common HTTP deployments.
# Note: use explicit assignment (not setdefault) so the Set-Cookie attributes are
# reliably emitted across Flask/Werkzeug versions.
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
if (os.environ.get("SESSION_COOKIE_SECURE") or "").strip() in {
    "1",
    "true",
    "True",
    "yes",
    "on",
}:
    app.config["SESSION_COOKIE_SECURE"] = True

# Session timeout: auto-logout after 8 hours of inactivity (configurable via env).
try:
    _session_hours = int(os.environ.get("SESSION_TIMEOUT_HOURS", "8").strip())
except Exception:
    _session_hours = 8
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=max(1, _session_hours))

# Ensure there is at least one login.
with contextlib.suppress(Exception):
    _auth_store.ensure_default_admin()
try:
    _directory_auth_store.ensure_default_profiles()
except Exception:
    app.logger.exception("Failed to initialize directory auth provider profiles")
try:
    _saml_auth_store.ensure_default_profile()
except Exception:
    app.logger.exception("Failed to initialize SAML auth provider profile")


def _is_logged_in() -> bool:
    u = session.get("user")
    return bool(u and isinstance(u, str))


def _query_flag(value: bool) -> str | None:
    return "1" if value else None


_FLEET_MANAGEMENT_ENDPOINTS = frozenset(
    {"proxies", "remove_proxy", "reconcile_proxy_identity"},
)
_NON_PROXY_CONTEXT_ENDPOINTS = frozenset(
    {
        "static",
        "login",
        "logout",
        "health",
        "recover_admin_session",
        *_FLEET_MANAGEMENT_ENDPOINTS,
    },
)
_NON_PROXY_LINK_ENDPOINTS = frozenset(
    {
        "static",
        "login",
        "logout",
        "health",
        "recover_admin_session",
        "remove_proxy",
        "reconcile_proxy_identity",
    },
)


def _filter_none_params(params: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in params.items() if v is not None}


def _should_preserve_proxy(endpoint: str, params: dict[str, Any] | None = None) -> bool:
    if endpoint in _NON_PROXY_LINK_ENDPOINTS:
        return False
    return not (params and params.get("proxy_id") is not None)


def _link_proxy_id() -> str:
    if has_request_context():
        active_proxy = getattr(g, "_active_proxy", None)
        active_proxy_id = getattr(active_proxy, "proxy_id", None)
        if active_proxy_id:
            return normalize_proxy_id(active_proxy_id)
        if _is_logged_in():
            session_proxy_id = session.get("active_proxy_id")
            if session_proxy_id:
                return normalize_proxy_id(session_proxy_id)
    return get_proxy_id()


def _endpoint_url(endpoint: str, **params: Any) -> str:
    values = _filter_none_params(params)
    if _should_preserve_proxy(endpoint, values):
        values["proxy_id"] = _link_proxy_id()
    return url_for(endpoint, **values)


def _redirect_to(endpoint: str, **params):
    return redirect(_endpoint_url(endpoint, **params))


def _redirect_with_message(endpoint: str, *, ok: bool, msg: str, **params):
    return _redirect_to(endpoint, ok=("1" if ok else "0"), msg=msg, **params)


def _redirect_config(
    tab: str,
    *,
    ok: bool = False,
    error: bool = False,
    subtab: str | None = None,
    msg: str | None = None,
):
    return _redirect_to(
        "squid_config",
        tab=tab,
        subtab=subtab,
        ok=_query_flag(ok),
        error=_query_flag(error),
        apply_msg=(msg or "")[:1000] if msg else None,
    )


def _record_audit_event(
    kind: str,
    *,
    ok: bool,
    detail: str = "",
    config_text: str | None = None,
) -> None:
    payload: dict[str, Any] = {
        "kind": kind,
        "ok": ok,
        "remote_addr": request.remote_addr,
        "user_agent": request.headers.get("User-Agent"),
        "detail": str(detail or "")[:4000],
    }
    if config_text is not None:
        payload["config_text"] = config_text
    with contextlib.suppress(Exception):
        get_audit_store().record(**payload)


def _audit_safe_detail(value: Any, *, limit: int = 500) -> str:
    return " ".join(str(value or "").split())[:limit]


def _normalize_choice(
    value: str | None,
    allowed: tuple[str, ...] | list[str] | set[str],
    default: str,
) -> str:
    candidate = (value or "").strip().lower()
    return candidate if candidate in allowed else default


def _form_action(*, default: str = "", lower: bool = False) -> str:
    action = (request.form.get("action") or default).strip()
    return action.lower() if lower else action


def _bounded_int(
    value: object,
    *,
    default: int,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    try:
        parsed = int(str(value).strip())
    except Exception:
        parsed = int(default)
    if minimum is not None:
        parsed = max(minimum, parsed)
    if maximum is not None:
        parsed = min(maximum, parsed)
    return parsed


def _query_int_arg(
    name: str,
    *,
    default: int,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    return _bounded_int(
        request.args.get(name),
        default=default,
        minimum=minimum,
        maximum=maximum,
    )


def _csv_response(headers: Sequence[str], rows: Iterable[Sequence[object]]):
    buf = io.StringIO()
    writer = csv.writer(buf, delimiter=";", lineterminator="\n")
    writer.writerow(list(headers))
    for row in rows:
        writer.writerow([_csv_safe(value) for value in row])
    return app.response_class(buf.getvalue(), mimetype="text/csv; charset=utf-8")


def _json_response(payload: Any):
    return app.response_class(
        json.dumps(payload, sort_keys=True, separators=(",", ":")),
        mimetype="application/json; charset=utf-8",
    )


def _jsonl_response(rows: Iterable[dict[str, Any]]):
    body = "".join(
        json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows
    )
    return app.response_class(body, mimetype="application/x-ndjson; charset=utf-8")


def _observability_export_response(
    headers: Sequence[str],
    rows: Iterable[Sequence[object]],
    export_format: str,
):
    materialized = [list(row) for row in rows]
    if export_format == "json":
        return _json_response(
            [dict(zip(headers, row, strict=False)) for row in materialized],
        )
    if export_format == "jsonl":
        return _jsonl_response(
            dict(zip(headers, row, strict=False)) for row in materialized
        )
    return _csv_response(headers, materialized)


def _observability_privacy_label(
    value: object,
    *,
    namespace: str = "user",
) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if text.startswith(f"{namespace}-"):
        return text
    return pseudonymize(text, namespace=namespace)


def _observability_reports_privacy_payload(payload: Any) -> Any:
    """Remove or pseudonymize user/client identifiers from reports exports."""
    if isinstance(payload, list):
        return [_observability_reports_privacy_payload(item) for item in payload]
    if not isinstance(payload, dict):
        return payload

    sanitized: dict[str, Any] = {}
    for key, value in payload.items():
        if key in {"client_ip", "src_ip", "remote_addr", "client_label"}:
            sanitized[key] = _observability_privacy_label(value)
        elif key == "group":
            sanitized[key] = _observability_privacy_label(value, namespace="group")
        elif key in {
            "detail",
            "hostname",
            "hostname_source",
            "recipients",
            "user_agent",
        }:
            sanitized[key] = ""
        else:
            sanitized[key] = _observability_reports_privacy_payload(value)

    if "privacy" in sanitized and isinstance(sanitized["privacy"], dict):
        sanitized["privacy"] = {
            **sanitized["privacy"],
            "enabled": True,
            "mode": "pseudonymized",
        }
    return sanitized


def _observability_pane_from_request() -> str:
    return _normalize_choice(
        request.args.get("pane") or "overview",
        _OBSERVABILITY_PANES,
        "overview",
    )


def _observability_sort_from_request(pane: str) -> str:
    default = _OBSERVABILITY_SORT_DEFAULTS[pane]
    return _normalize_choice(
        request.args.get("sort") or default,
        _OBSERVABILITY_SORT_OPTIONS[pane],
        default,
    )


def _observability_resolve_hostnames_from_request() -> bool:
    resolve_values = request.args.getlist("resolve_hostnames")
    if not resolve_values:
        return True
    return any((value or "").strip() == "1" for value in resolve_values)


def _observability_privacy_from_request() -> bool:
    values = request.args.getlist("privacy")
    return any(
        (value or "").strip().lower() in {"1", "true", "yes", "on", "pseudonymized"}
        for value in values
    )


def _observability_search_from_request() -> str:
    return (request.args.get("q") or request.args.get("search") or "").strip().lower()


def _observability_export_format_from_request() -> str:
    return _normalize_choice(
        request.args.get("format") or "csv",
        ("csv", "json", "jsonl"),
        "csv",
    )


def _empty_observability_summary() -> dict[str, Any]:
    return {
        "request_records": 0,
        "cache_hits": 0,
        "cache_misses": 0,
        "cache_hit_pct": 0.0,
        "clients": 0,
        "destinations": 0,
        "transactions": 0,
        "icap_events": 0,
        "av_icap_events": 0,
        "adblock_icap_events": 0,
    }


def _database_remediation_payload(
    exc: BaseException, *, summary: dict[str, Any] | None = None
) -> dict[str, Any]:
    detail = public_error_message(
        exc, default="Observability data could not be loaded."
    )
    now = int(time.time())
    row = {
        "kind": "mysql_unreachable",
        "component": "MySQL / observability ingestion",
        "severity": "high",
        "title": "Observability database query failed",
        "subject": get_proxy_id(),
        "count": 1,
        "clients": 0,
        "last_seen": now,
        "confidence": "high",
        "recommended_action": "Check MySQL service health, credentials, connection pool limits, schema locks, and pending tailer flush queues before trusting current remediation coverage.",
        "evidence": detail[:240],
    }
    return {
        "summary": {
            "suggestions": 1,
            "high_confidence": 1,
            "observations": 1,
            "domains": 0,
            "latest": now,
            "http3_candidates": 0,
        },
        "rows": [row],
        "top_components": [
            {"label": row["component"], "full_label": row["component"], "count": 1}
        ],
        "top_kinds": [{"label": row["kind"], "full_label": row["kind"], "count": 1}],
        "quic_guidance": [
            "PAC files can steer HTTP/HTTPS proxy use, but they cannot force UDP/443 QUIC through an HTTP proxy.",
            "Restore database ingestion before treating the absence of HTTP/3 or remediation rows as evidence of clean traffic.",
        ],
        "summary_source": summary or _empty_observability_summary(),
    }


def _empty_observability_payload(
    pane: str,
    *,
    summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    base_summary = dict(summary or _empty_observability_summary())
    ssl_payload = {
        "summary": {
            "bucket_count": 0,
            "total_events": 0,
            "known_domains": 0,
            "unknown_target_buckets": 0,
        },
        "top_categories": [],
        "hints": [],
        "top_domains": [],
        "rows": [],
    }
    security_payload = {
        "summary": {
            "av_events": 0,
            "potential_findings": 0,
            "adblock_blocks": 0,
            "webfilter_blocks": 0,
            "webfilter_categories": 0,
            "combined_blocks": 0,
        },
        "notes": [],
        "av_rows": [],
        "av_top_targets": [],
        "adblock_rows": [],
        "adblock_top_domains": [],
        "webfilter_rows": [],
        "webfilter_top_categories": [],
    }
    performance_payload = {
        "summary": {
            "requests": 0,
            "transactions": 0,
            "icap_events": 0,
        },
        "av_icap_summary": {"events": 0},
        "adblock_icap_summary": {"events": 0},
        "slow_requests": [],
        "slow_icap_events": [],
        "top_user_agents": [],
        "top_bump_modes": [],
        "top_tls_server_versions": [],
        "top_policy_tags": [],
    }
    remediation_payload = {
        "summary": {
            "suggestions": 0,
            "high_confidence": 0,
            "observations": 0,
            "domains": 0,
            "latest": 0,
            "http3_candidates": 0,
        },
        "rows": [],
        "top_components": [],
        "top_kinds": [],
        "quic_guidance": [],
        "summary_source": base_summary,
    }

    if pane == "overview":
        return {
            "summary": base_summary,
            "destinations": [],
            "clients": [],
            "cache_reasons": [],
            "ssl": ssl_payload,
            "security": security_payload,
            "performance": performance_payload,
            "remediation": remediation_payload,
        }
    if pane in {"destinations", "clients", "cache"}:
        return {"rows": []}
    if pane == "ssl":
        return ssl_payload
    if pane == "security":
        return security_payload
    if pane == "performance":
        return performance_payload
    if pane == "remediation":
        return remediation_payload
    if pane == "reports":
        return {
            "summary": base_summary,
            "cache_savings": {"estimated_saved_bytes": 0, "byte_hit_pct": 0.0},
            "top_users": [],
            "top_blocked_categories": [],
            "top_malware_attempts": [],
            "top_ssl_bump_failures": [],
            "top_spliced_destinations": [],
            "per_group": [],
            "security": security_payload,
            "audit": {
                "summary": {"events": 0, "failed_events": 0, "last_seen": 0},
                "top_kinds": [],
                "recent": [],
            },
            "time_series": {"tables": [], "latest_ts": 0, "rollup_points": 0},
            "schedules": [],
            "export_contracts": [],
            "privacy": {"enabled": False, "mode": "raw"},
        }
    return {"rows": []}


def _merge_observability_payload_defaults(
    pane: str,
    payload: Any,
    *,
    summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    def merge(default: Any, value: Any) -> Any:
        if isinstance(default, dict):
            merged = dict(default)
            if isinstance(value, dict):
                for key, item in value.items():
                    merged[key] = merge(merged.get(key), item)
            return merged
        return value if value is not None else default

    defaults = _empty_observability_payload(pane, summary=summary)
    if not isinstance(payload, dict):
        return defaults
    return merge(defaults, payload)


def _empty_observability_export_response(pane: str, export_format: str = "csv"):
    headers = _OBSERVABILITY_EMPTY_EXPORT_HEADERS.get(
        pane,
        _OBSERVABILITY_EMPTY_EXPORT_HEADERS["destinations"],
    )
    if pane == "overview":
        rows = ([metric, 0] for metric in _OBSERVABILITY_OVERVIEW_EXPORT_METRICS)
        return _observability_export_response(headers, rows, export_format)
    return _observability_export_response(headers, [], export_format)


_POLICY_REFRESH_SUCCESS_PARAMS = {
    "ok",
    "wl_ok",
    "safe_browsing_saved",
    "inspection_saved",
    "private_saved",
    "compatibility_attempted",
    "compatibility_added",
}


def _policy_refresh_failure_detail(detail: str) -> str:
    prefix = "Policy changes were saved, but proxy reconciliation was not queued."
    clean_detail = (detail or "").strip()
    if not clean_detail:
        return prefix
    if clean_detail.startswith(prefix):
        return clean_detail
    return f"{prefix} {clean_detail}"


def _redirect_after_policy_refresh(
    endpoint: str,
    store: Any,
    *,
    force: bool = True,
    **params,
):
    ok, detail = _best_effort_refresh_managed_policy(store, force=force)
    if ok:
        params.setdefault("policy_queue", "1")
        if detail:
            params.setdefault("policy_msg", detail[:1000])
        return _redirect_to(endpoint, **params)

    for key in _POLICY_REFRESH_SUCCESS_PARAMS:
        params.pop(key, None)
    params["policy_error"] = "1"
    params["policy_msg"] = _policy_refresh_failure_detail(detail)[:1000]
    return _redirect_to(endpoint, **params)


def _redirect_after_pac_refresh(endpoint: str, **params):
    ok, detail = _queue_pac_runtime_refresh()
    if not ok:
        params.pop("ok", None)
        params["error"] = "1"
        params["msg"] = (
            detail
            or "PAC profile changes were saved, but proxy materialization was not queued."
        )
    return _redirect_to(endpoint, **params)


def _render_template_config_text(
    options: dict[str, Any],
    *,
    overrides: dict[str, bool] | None = None,
) -> str:
    current = _current_managed_config()
    effective_overrides = (
        overrides
        if overrides is not None
        else squid_controller.get_cache_override_options(current)
    )
    config_text = squid_controller.generate_config_from_template(options)
    return squid_controller.apply_cache_overrides(config_text, effective_overrides)


def _publish_template_config(
    options: dict[str, Any],
    *,
    source_kind: str,
    audit_kind: str,
    overrides: dict[str, bool] | None = None,
) -> tuple[bool, str]:
    config_text = _render_template_config_text(options, overrides=overrides)
    ok, detail = _publish_config_for_current_mode(config_text, source_kind=source_kind)
    _record_audit_event(audit_kind, ok=ok, detail=detail, config_text=config_text)
    return ok, str(detail or "")


def _active_proxy_management_url() -> str:
    proxy = get_proxy_registry().get_proxy(get_proxy_id())
    if proxy is None:
        return ""
    return str(proxy.management_url or "").strip()


def _uses_remote_proxy_runtime() -> bool:
    return bool(_active_proxy_management_url())


def _pac_profile_form_data(*, profile_id: int | None) -> dict[str, Any]:
    return {
        "profile_id": profile_id,
        "name": request.form.get("name") or "",
        "client_cidr": request.form.get("client_cidr") or "",
        "direct_domains_text": request.form.get("direct_domains") or "",
        "direct_dst_nets_text": request.form.get("direct_dst_nets") or "",
    }


def _selected_proxy_pac_context() -> tuple[Any, str, str]:
    target = resolve_proxy_pac_target(get_proxy_id())
    pac_url = target.pac_url
    warning = ""
    if not pac_url:
        warning = (
            "This proxy does not advertise an authoritative public PAC hostname yet. "
            "Set PROXY_PUBLIC_HOST or PROXY_PUBLIC_PAC_URL on the selected proxy container so the Admin UI can publish a direct PAC URL."
        )
    return target, pac_url, warning


def _safe_next_url(next_url: str) -> str:
    """Allow only local relative redirects to avoid open-redirect issues."""
    candidate = (next_url or "").strip()
    if not candidate:
        return ""
    # Disallow scheme-relative (//evil.com) and absolute URLs.
    if candidate.startswith("//"):
        return ""
    parsed = urlparse(candidate)
    if parsed.scheme or parsed.netloc:
        return ""
    # Backslashes are path separators for some clients/proxies and can turn a
    # path-looking redirect into an authority-looking URL after normalization.
    if "\\" in candidate:
        return ""
    decoded = candidate
    for _ in range(3):
        previous = decoded
        decoded = unquote(previous, errors="replace")
        if decoded == previous:
            break
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in decoded):
        return ""
    if "\\" in decoded or decoded.startswith("//"):
        return ""
    decoded_parsed = urlparse(decoded)
    if decoded_parsed.scheme or decoded_parsed.netloc:
        return ""
    if decoded.count("/") > candidate.count("/"):
        return ""
    # Only allow app-local paths.
    if not candidate.startswith("/"):
        return ""
    return candidate


def _clear_recoverable_session_state() -> None:
    session.pop("active_proxy_id", None)


@app.route("/recover", methods=["GET"])
def recover_admin_session():
    _clear_recoverable_session_state()
    return _redirect_to("index", recovered="1")


@app.errorhandler(Exception)
def _recover_from_unhandled_admin_error(exc: Exception):
    if isinstance(exc, HTTPException):
        return exc

    log_exception_throttled(
        app.logger,
        "web.app.unhandled",
        interval_seconds=10.0,
        message="Unhandled Admin UI request failed",
    )
    _clear_recoverable_session_state()
    message = escape(public_error_message(exc))
    recover_url = "/recover"
    with contextlib.suppress(Exception):
        recover_url = url_for("recover_admin_session")
    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Admin UI Recovery | Docker Proxy</title>
  <style>body{{font-family:system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:0;background:#f6f7f9;color:#151922}}main{{max-width:720px;margin:12vh auto;padding:32px;background:#fff;border:1px solid #d9dee8;border-radius:8px;box-shadow:0 12px 32px rgba(15,23,42,.08)}}h1{{font-size:1.35rem;margin:0 0 12px}}p{{line-height:1.5}}.btn{{display:inline-block;margin-top:14px;padding:10px 14px;border-radius:6px;background:#1f6feb;color:#fff;text-decoration:none;font-weight:600}}.small{{color:#5c667a;font-size:.92rem}}</style>
</head>
<body>
  <main>
    <h1>Admin UI recovered from a request error</h1>
    <p>The selected proxy/session context was reset so the next page load can start from the current registered proxy inventory.</p>
    <p class="small">{message}</p>
    <a class="btn" href="{escape(recover_url)}">Return to dashboard</a>
  </main>
</body>
</html>"""
    return Response(html, status=500, mimetype="text/html")


def _csrf_disabled() -> bool:
    return (os.environ.get("DISABLE_CSRF") or "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _ensure_csrf_token() -> str:
    tok = session.get("_csrf_token")
    if not tok or not isinstance(tok, str):
        tok = secrets.token_urlsafe(32)
        session["_csrf_token"] = tok
    return tok


@app.before_request
def _csrf_guard() -> None:
    if _csrf_disabled():
        return
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return
    if request.endpoint == "auth_saml_acs":
        return

    sent = (request.headers.get("X-CSRF-Token") or "").strip()
    if not sent:
        sent = (request.form.get("csrf_token") or "").strip()

    expected = _ensure_csrf_token()
    if not sent or not secrets.compare_digest(sent, expected):
        abort(403)
    return


@app.after_request
def _security_headers(resp):
    # Conservative baseline. Avoid breaking existing inline scripts/styles.
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    resp.headers.setdefault(
        "Permissions-Policy",
        "geolocation=(), microphone=(), camera=()",
    )
    try:
        if (resp.mimetype or "").lower().startswith("text/html"):
            resp.headers.setdefault(
                "Content-Security-Policy",
                "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
            )
    except Exception:
        pass
    return resp


@app.context_processor
def _inject_csrf():
    token = _ensure_csrf_token()

    def csrf_field() -> Markup:
        return Markup(
            f'<input type="hidden" name="csrf_token" value="{escape(token)}">'
        )

    return {
        "csrf_token": token,
        "csrf_field": csrf_field,
    }


@app.context_processor
def _inject_route_helpers():
    def scoped_url_for(endpoint: str, **values: Any) -> str:
        return _endpoint_url(endpoint, **values)

    return {
        "proxy_url": scoped_url_for,
        "url_for": scoped_url_for,
    }


@app.before_request
def _require_login_guard():
    # Allow liveness, scrape metrics, and static assets unauthenticated.
    if request.endpoint in {None, "static", "health", "performance_metrics"}:
        return None

    # Allow auth routes.
    if request.endpoint in {
        "login",
        "logout",
        "auth_saml_metadata",
        "auth_saml_login",
        "auth_saml_acs",
    }:
        return None

    if _is_logged_in():
        return None

    # Redirect everything else to login.
    return _redirect_to("login", next=request.full_path)


def _request_needs_proxy_context() -> bool:
    if request.endpoint in {None, *_NON_PROXY_CONTEXT_ENDPOINTS}:
        return False
    return _is_logged_in()


def _proxy_inventory_or_default(registry: Any) -> list[Any]:
    proxies = registry.list_proxies()
    if not proxies:
        proxies = [registry.ensure_default_proxy()]
    return proxies


def _resolve_proxy_from_inventory(
    registry: Any,
    proxies: list[Any],
    preferred: object | None,
) -> Any | None:
    preferred_key = normalize_proxy_id(preferred)
    active_proxy = next(
        (proxy for proxy in proxies if proxy.proxy_id == preferred_key),
        None,
    )
    if active_proxy is not None:
        return active_proxy

    resolved = registry.resolve_proxy_id(preferred_key)
    resolved_key = normalize_proxy_id(resolved)
    return next((proxy for proxy in proxies if proxy.proxy_id == resolved_key), None)


def _resolve_selected_proxy_context() -> tuple[str, Any, list[Any]]:
    requested_proxy = request.form.get("proxy_id") or request.args.get("proxy_id")
    if requested_proxy is not None:
        session["active_proxy_id"] = normalize_proxy_id(requested_proxy)

    preferred = normalize_proxy_id(
        session.get("active_proxy_id") or get_default_proxy_id()
    )
    registry = get_proxy_registry()
    proxies = _proxy_inventory_or_default(registry)
    active_proxy = _resolve_proxy_from_inventory(registry, proxies, preferred)
    if active_proxy is None:
        active_proxy = proxies[0]
    session["active_proxy_id"] = active_proxy.proxy_id
    return active_proxy.proxy_id, active_proxy, proxies


@app.before_request
def _bind_proxy_context() -> None:
    if not _request_needs_proxy_context():
        return
    active_proxy_id, active_proxy, proxies = _resolve_selected_proxy_context()
    g._active_proxy = active_proxy
    g._proxy_inventory = proxies
    token = set_proxy_id(active_proxy_id)
    g._proxy_context_token = token
    return


@app.teardown_request
def _reset_proxy_context(_exc) -> None:
    token = getattr(g, "_proxy_context_token", None)
    if token is not None:
        reset_proxy_id(token)


@app.context_processor
def _inject_proxy_context():
    if not _is_logged_in():
        return {
            "active_proxy_id": None,
            "active_proxy": None,
            "proxy_inventory": [],
        }
    get_proxy_id()
    active_proxy = getattr(g, "_active_proxy", None)
    proxies = getattr(g, "_proxy_inventory", None)
    if request.endpoint in _FLEET_MANAGEMENT_ENDPOINTS:
        requested_proxy = request.form.get("proxy_id") or request.args.get("proxy_id")
        if requested_proxy is not None:
            session["active_proxy_id"] = normalize_proxy_id(requested_proxy)
        registry = get_proxy_registry()
        proxies = _proxy_inventory_or_default(registry)
        preferred = normalize_proxy_id(
            session.get("active_proxy_id") or get_default_proxy_id(),
        )
        active_proxy = _resolve_proxy_from_inventory(registry, proxies, preferred)
        if active_proxy is None:
            active_proxy = proxies[0] if proxies else None
        if active_proxy is not None:
            session["active_proxy_id"] = active_proxy.proxy_id
        return {
            "active_proxy_id": active_proxy.proxy_id if active_proxy else None,
            "active_proxy": active_proxy,
            "proxy_inventory": proxies,
        }
    if active_proxy is None or proxies is None:
        _active_proxy_id, active_proxy, proxies = _resolve_selected_proxy_context()
    return {
        "active_proxy_id": active_proxy.proxy_id,
        "active_proxy": active_proxy,
        "proxy_inventory": proxies,
    }


@app.route("/login", methods=["GET", "POST"])
def login():
    saml_profile = _saml_auth_store.get_profile()
    saml_enabled = profile_metadata_ready(saml_profile)
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        next_url = _safe_next_url(request.form.get("next") or "")
        try:
            directory_result = _directory_auth_store.authenticate_admin(
                username, password
            )
        except Exception:
            app.logger.exception(
                "Directory authentication failed before local fallback"
            )
            directory_result = None
        directory_ok = bool(getattr(directory_result, "ok", False))
        directory_provider = (
            getattr(directory_result, "provider", "local")
            if directory_result
            else "local"
        )
        directory_attempted = directory_provider != "local"
        local_ok = (
            False if directory_ok else _auth_store.verify_user(username, password)
        )
        if directory_ok or local_ok:
            login_provider = directory_provider if directory_ok else "local"
            login_username = (
                getattr(directory_result, "username", username)
                if directory_ok
                else username
            )
            _establish_admin_session(login_username, login_provider)
            _record_audit_event(
                "login_success",
                ok=True,
                detail=f"user={login_username} provider={login_provider}",
            )
            return redirect(next_url or url_for("index"))
        # Log failed login attempt for security auditing
        failure_detail = f"user={username}"
        if directory_result is not None and directory_attempted:
            directory_detail = _audit_safe_detail(
                getattr(directory_result, "detail", "")
            )
            failure_detail += f" provider={directory_provider}"
            if directory_detail:
                failure_detail += f" directory_detail={directory_detail}"
        _record_audit_event("login_failed", ok=False, detail=failure_detail)
        return render_template(
            "login.html",
            error="Invalid username or password.",
            next=next_url,
            saml_enabled=saml_enabled,
        )

    if _is_logged_in():
        return _redirect_to("index")
    next_url = _safe_next_url(request.args.get("next") or "")
    return render_template(
        "login.html",
        error=None,
        next=next_url,
        saml_enabled=saml_enabled,
    )


def _establish_admin_session(username: str, provider: str) -> None:
    # Prevent session fixation by clearing any existing session data.
    prev_csrf = session.get("_csrf_token")
    session.clear()
    # Keep a CSRF token available immediately after login so that the
    # next POST (often triggered by UI actions) can succeed even if the
    # client does not perform an intermediate template-rendering GET.
    if prev_csrf and isinstance(prev_csrf, str):
        session["_csrf_token"] = prev_csrf
    else:
        session["_csrf_token"] = secrets.token_urlsafe(32)
    session["user"] = username
    session["auth_provider"] = provider
    session.permanent = True  # Apply PERMANENT_SESSION_LIFETIME


@app.route("/auth/saml/metadata", methods=["GET"])
def auth_saml_metadata():
    profile = _saml_auth_store.get_profile()
    try:
        metadata = build_sp_metadata(profile, request)
    except Exception as exc:
        _record_audit_event(
            "saml_metadata_failed",
            ok=False,
            detail=_audit_safe_detail(public_error_message(exc), limit=1000),
        )
        abort(503, description=public_error_message(exc))
    return Response(metadata, mimetype="application/samlmetadata+xml")


@app.route("/auth/saml/login", methods=["GET"])
def auth_saml_login():
    profile = _saml_auth_store.get_profile()
    next_url = _safe_next_url(request.args.get("next") or "")
    if not profile_metadata_ready(profile):
        _record_audit_event(
            "saml_login_failed",
            ok=False,
            detail="SAML provider is disabled or metadata cache is stale.",
        )
        return _redirect_to(
            "login",
            next=next_url,
            error="saml_unavailable",
        )
    try:
        auth = build_saml_auth(profile, request)
        redirect_url = auth.login(return_to=next_url or url_for("index"))
        request_id = getattr(auth, "get_last_request_id", lambda: "")()
        if request_id:
            session["saml_request_id"] = str(request_id)
        return redirect(redirect_url)
    except Exception as exc:
        app.logger.exception("SAML login initiation failed")
        _record_audit_event(
            "saml_login_failed",
            ok=False,
            detail=_audit_safe_detail(public_error_message(exc), limit=1000),
        )
        return _redirect_to("login", next=next_url)


@app.route("/auth/saml/acs", methods=["POST"])
def auth_saml_acs():
    profile = _saml_auth_store.get_profile()
    next_url = _safe_next_url(request.form.get("RelayState") or "")
    if not profile_metadata_ready(profile):
        _record_audit_event(
            "saml_login_failed",
            ok=False,
            detail="SAML ACS rejected because provider is disabled or metadata cache is stale.",
        )
        return _redirect_to("login", next=next_url)
    try:
        auth = build_saml_auth(profile, request)
        request_id = session.pop("saml_request_id", None)
        if request_id:
            auth.process_response(request_id=str(request_id))
        else:
            auth.process_response()
        result = resolve_saml_login(auth, profile)
    except Exception as exc:
        app.logger.exception("SAML ACS processing failed")
        result = type("_Result", (), {})()
        result.ok = False
        result.username = ""
        result.detail = public_error_message(exc)
    if not result.ok:
        _record_audit_event(
            "saml_login_failed",
            ok=False,
            detail=_audit_safe_detail(
                f"user={getattr(result, 'username', '')} detail={getattr(result, 'detail', '')}",
                limit=1000,
            ),
        )
        return _redirect_to("login", next=next_url)
    _establish_admin_session(result.username, "saml")
    _record_audit_event(
        "login_success",
        ok=True,
        detail=f"user={result.username} provider=saml",
    )
    return redirect(next_url or url_for("index"))


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return _redirect_to("login")


def _options_from_tunables(tunables: dict[str, Any]) -> dict[str, Any]:
    return build_template_options(tunables, max_workers=_max_workers())


_disable_background = (os.environ.get("DISABLE_BACKGROUND") or "").strip() == "1"

# In multi-worker servers, ensure only one process runs background workers.
if not _disable_background:
    try:
        if not acquire_background_lock():
            _disable_background = True
    except Exception:
        pass


def _safe_int(value: object, default: int = 0) -> int:
    try:
        return int(value or default)
    except Exception:
        return int(default)


def _present_adblock_artifact_summary(summary: object | None) -> dict[str, Any]:
    if summary is None:
        return {
            "available": False,
            "revision_id": 0,
            "artifact_sha256": "",
            "artifact_short_sha": "",
            "settings_version": 0,
            "source_kind": "",
            "created_by": "",
            "created_ts": 0,
            "enabled_lists": [],
            "counts": {},
            "breakdowns": {},
        }

    report = getattr(summary, "report", {}) or {}
    counts = report.get("counts") if isinstance(report, dict) else {}
    breakdowns = report.get("breakdowns") if isinstance(report, dict) else {}
    if not isinstance(counts, dict):
        counts = {}
    if not isinstance(breakdowns, dict):
        breakdowns = {}
    sha = str(getattr(summary, "artifact_sha256", "") or "")
    return {
        "available": True,
        "revision_id": _safe_int(getattr(summary, "revision_id", 0)),
        "artifact_sha256": sha,
        "artifact_short_sha": sha[:12],
        "settings_version": _safe_int(getattr(summary, "settings_version", 0)),
        "source_kind": str(getattr(summary, "source_kind", "") or ""),
        "created_by": str(getattr(summary, "created_by", "") or ""),
        "created_ts": _safe_int(getattr(summary, "created_ts", 0)),
        "enabled_lists": list(getattr(summary, "enabled_lists", []) or []),
        "counts": {str(key): _safe_int(value) for key, value in counts.items()},
        "breakdowns": breakdowns,
    }


def _present_adblock_build_state(
    store: Any,
    *,
    active_artifact: dict[str, Any],
    statuses: list[dict[str, Any]],
    settings: Any,
) -> dict[str, Any]:
    try:
        settings_version = _safe_int(store.get_settings_version())
    except Exception:
        settings_version = 0
    try:
        refresh_requested = _safe_int(store.get_refresh_requested())
    except Exception:
        refresh_requested = 0
    try:
        raw_status = store.get_artifact_build_status()
    except Exception:
        raw_status = {}
    if not isinstance(raw_status, dict):
        raw_status = {}

    try:
        settings_enabled = bool(
            settings.get("enabled", True)
            if isinstance(settings, dict)
            else getattr(settings, "enabled", True)
        )
    except Exception:
        settings_enabled = True
    configured_enabled_lists = sorted(
        str(row.get("key") or "").strip()
        for row in statuses
        if row.get("enabled") and str(row.get("key") or "").strip()
    )
    enabled_lists = configured_enabled_lists if settings_enabled else []
    active_lists = sorted(
        str(item).strip()
        for item in (active_artifact.get("enabled_lists") or [])
        if str(item).strip()
    )
    artifact_available = bool(active_artifact.get("available"))
    version_stale = bool(
        artifact_available
        and settings_version
        and _safe_int(active_artifact.get("settings_version")) != settings_version
    )
    lists_stale = bool(artifact_available and active_lists != enabled_lists)
    missing_enabled_artifact = bool(enabled_lists and not artifact_available)
    pending = bool(
        refresh_requested or version_stale or lists_stale or missing_enabled_artifact
    )

    ok_value = raw_status.get("ok")
    return {
        "pending": pending,
        "refresh_requested": refresh_requested,
        "settings_version": settings_version,
        "enabled_lists": enabled_lists,
        "configured_enabled_lists": configured_enabled_lists,
        "active_lists": active_lists,
        "artifact_empty_because_disabled": bool(
            not settings_enabled
            and artifact_available
            and not active_lists
            and configured_enabled_lists
        ),
        "version_stale": version_stale,
        "lists_stale": lists_stale,
        "missing_enabled_artifact": missing_enabled_artifact,
        "last_ok": ok_value is True,
        "last_failed": ok_value is False,
        "last_detail": str(raw_status.get("detail") or ""),
        "last_ts": _safe_int(raw_status.get("ts")),
        "last_revision_id": _safe_int(raw_status.get("revision_id")),
        "archive_bytes": _safe_int(raw_status.get("archive_bytes")),
        "download_pending": bool(raw_status.get("download_pending")),
    }


@app.template_filter("datetimeformat")
def _datetimeformat(ts: object) -> str:
    try:
        i = int(ts)  # type: ignore[arg-type]
        if i <= 0:
            return ""
        return datetime.fromtimestamp(i, UTC).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ""


if not _disable_background:
    # Build and activate adblock artifacts from MySQL-backed admin state.
    with contextlib.suppress(Exception):
        get_adblock_artifacts().start_background()

    # Start web filtering background updater (downloads/compiles categories daily at midnight).
    with contextlib.suppress(Exception):
        get_webfilter_store().start_background()

    # Scheduled housekeeping: daily prune at 02:00, weekly full maintenance Sunday 03:00.
    with contextlib.suppress(Exception):
        start_housekeeping(retention_days=30)


@app.context_processor
def inject_now():
    def fmt_ts(ts: int) -> str:
        try:
            return datetime.fromtimestamp(int(ts), UTC).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return ""

    return {
        # Use timezone-aware UTC to avoid deprecation warnings.
        "current_year": datetime.now(UTC).year,
        "asset_version": _asset_version,
        "fmt_ts": fmt_ts,
        "observability_default_window": OBSERVABILITY_DEFAULT_WINDOW,
        "version_header_status": _initial_version_header_status(),
    }


def _build_observability_snapshot(
    window_i: int = OBSERVABILITY_DEFAULT_WINDOW,
) -> tuple[dict[str, int], str]:
    since_ts = int(time.time()) - max(
        300,
        int(window_i or OBSERVABILITY_DEFAULT_WINDOW),
    )

    def _build_snapshot() -> dict[str, int]:
        diagnostic_summary: dict[str, Any] = {}
        ssl_summary: dict[str, Any] = {}
        try:
            diagnostic_summary = get_diagnostic_store().activity_summary(since=since_ts)
        except Exception:
            diagnostic_summary = {}
        try:
            ssl_rows = get_ssl_errors_store().list_recent(
                since=since_ts,
                search="",
                limit=100,
            )
            ssl_summary = _present_ssl_error_rows(ssl_rows).get("summary", {})
        except Exception:
            ssl_summary = {}
        return _present_observability_summary(
            diagnostic_summary=diagnostic_summary,
            ssl_summary=ssl_summary,
        )

    summary = _cached_observability_result(
        _observability_result_cache_key(
            "observability-snapshot",
            get_proxy_id(),
            since_ts,
        ),
        _build_snapshot,
    )
    return summary, _window_label(window_i)


def _cached_observability_summary(
    proxy_id: str,
    window_i: int = OBSERVABILITY_DEFAULT_WINDOW,
) -> dict[str, int]:
    window_i = max(300, int(window_i or OBSERVABILITY_DEFAULT_WINDOW))
    scoped_proxy_id = normalize_proxy_id(proxy_id)
    key = (scoped_proxy_id, window_i)
    now = time.monotonic()
    cached = _OBSERVABILITY_SUMMARY_CACHE.get(key)
    if cached is not None:
        cached_at, payload = cached
        if now - cached_at <= max(0.0, float(_PROXY_OBSERVABILITY_TTL_SECONDS)):
            return dict(payload)
    token = set_proxy_id(scoped_proxy_id)
    try:
        summary, _label = _build_observability_snapshot(window_i)
    finally:
        reset_proxy_id(token)
    _OBSERVABILITY_SUMMARY_CACHE[key] = (now, dict(summary))
    return dict(summary)


def _current_managed_config() -> str:
    """Return the effective config for the active proxy.

    Config revisions are the source of truth. The live Squid config is used only
    as a bootstrap fallback for a proxy that has not yet stored its first revision.
    """
    revisions = get_config_revisions()
    current = revisions.get_active_config_text(get_proxy_id())
    if current:
        return current
    fallback = squid_controller.get_current_config() or ""
    if fallback.strip():
        revisions.ensure_active_revision(
            get_proxy_id(),
            fallback,
            created_by="system",
            source_kind="bootstrap",
        )
    return fallback


def _validate_config_for_current_mode(config_text: str) -> tuple[bool, str]:
    """Validate with the selected proxy runtime when available.

    The admin UI image is intentionally standalone-capable and does not require
    a local Squid process. Real validation belongs on the selected proxy because
    that container owns the Squid binary, generated includes, ssl_db paths, and
    cache runtime layout.
    """
    proxy_id = get_proxy_id()
    if _active_proxy_management_url():
        try:
            result = get_proxy_client().validate_config(proxy_id, config_text)
            return bool(result.get("ok", False)), str(result.get("detail") or "")
        except ProxyClientError as exc:
            return False, f"Proxy validation failed: {exc}"

    if shutil.which("squid") is not None:
        return squid_controller.validate_config_text(config_text)

    return False, (
        f"Proxy '{proxy_id}' is not registered with a management URL, and this admin UI container "
        "does not include a local Squid runtime for validation. Start/select a proxy container before applying config changes."
    )


def _publish_config_for_current_mode(
    config_text: str,
    *,
    source_kind: str,
) -> tuple[bool, str]:
    config_text = squid_controller.normalize_config_text(config_text)
    proxy_id = get_proxy_id()
    created_by = str(session.get("user") or "")
    revisions = get_config_revisions()
    previous_revision = None
    try:
        previous_revision = revisions.get_active_revision(proxy_id)
    except Exception:
        previous_revision = None
    valid, validation_detail = _validate_config_for_current_mode(config_text)
    if not valid:
        detail = (validation_detail or "Squid config validation failed.").strip()
        return (
            False,
            f"Config validation failed; revision was not activated.\n{detail}".strip(),
        )
    revision = revisions.create_revision(
        proxy_id,
        config_text,
        created_by=created_by,
        source_kind=source_kind,
        activate=True,
    )
    restore_detail = ""

    def restore_previous_active_revision() -> None:
        nonlocal restore_detail
        try:
            restore_if_current = getattr(revisions, "restore_previous_if_current", None)
            if callable(restore_if_current):
                restored = restore_if_current(
                    proxy_id,
                    revision.revision_id,
                    getattr(previous_revision, "revision_id", None),
                )
            elif previous_revision is not None:
                revisions.activate_revision(proxy_id, previous_revision.revision_id)
                restored = True
            else:
                revisions.deactivate_revision(proxy_id, revision.revision_id)
                restored = True
            if restored and previous_revision is not None:
                restore_detail = "Previous active revision was restored."
            elif restored:
                restore_detail = "Unqueued revision was left inactive."
            else:
                restore_detail = (
                    "Active revision changed concurrently; newer active revision was preserved."
                )
        except Exception:
            log_exception_throttled(
                app.logger,
                "web.app.config_apply_restore_active_revision",
                interval_seconds=30.0,
                message="Failed to restore active config revision after reconcile queue failure",
            )
            restore_detail = (
                "Failed to restore the prior active revision after reconcile queue failure; "
                "check the operation ledger and config revision store before retrying."
            )

    try:
        operation = request_proxy_reconcile(
            proxy_id,
            operation_type="config_apply",
            subject="Squid config",
            summary=f"Revision {revision.revision_id} saved; applying asynchronously to proxy {proxy_id}.",
            target_kind="config_revision",
            target_ref=revision.revision_id,
            rollback_kind="config_revision" if previous_revision is not None else "",
            rollback_ref=getattr(previous_revision, "revision_id", "")
            if previous_revision is not None
            else "",
            request_hash=getattr(revision, "config_sha256", ""),
            detail=f"Revision {revision.revision_id} saved by admin-ui; waiting for proxy reconciliation.",
            created_by=created_by,
            # A user-initiated config apply is an explicit retry request for this
            # revision. If the active revision previously failed on the proxy,
            # the runtime quarantine guard should not turn the newly queued
            # operation into another no-op failure.
            force=True,
        )
    except Exception as exc:
        log_exception_throttled(
            app.logger,
            "web.app.config_apply_reconcile",
            interval_seconds=30.0,
            message="Failed to queue config apply reconciliation",
        )
        restore_previous_active_revision()
        return False, public_error_message(
            exc,
            default=(
                f"Revision {revision.revision_id} saved, but proxy reconcile was not queued. "
                f"{restore_detail}".strip()
            ),
        )
    if (
        not getattr(operation, "operation_id", 0)
        and getattr(operation, "status", "") == "failed"
    ):
        restore_previous_active_revision()
        detail = str(
            getattr(operation, "detail", "")
            or "Revision saved, but proxy reconcile was not queued."
        )
        if restore_detail:
            detail = f"{detail}\n{restore_detail}"
        return False, str(
            detail,
        )
    op_suffix = (
        f" operation #{operation.operation_id}"
        if getattr(operation, "operation_id", 0)
        else " operation"
    )
    return (
        True,
        f"Revision {revision.revision_id} saved; applying asynchronously as{op_suffix}.",
    )


def _trigger_proxy_sync(*, force: bool = False) -> tuple[bool, str]:
    """Queue reconciliation for the selected proxy through the operation ledger."""
    try:
        operation = request_proxy_reconcile(
            get_proxy_id(),
            operation_type="manual_sync",
            subject="Proxy reconciliation",
            summary="Manual proxy reconciliation queued.",
            detail="Admin requested proxy reconciliation.",
            created_by=str(session.get("user") or ""),
            force=force,
        )
    except Exception as exc:
        log_exception_throttled(
            app.logger,
            "web.app.proxy_sync",
            interval_seconds=30.0,
            message="Failed to queue proxy reconciliation",
        )
        return False, public_error_message(
            exc,
            default="Proxy reconciliation was not queued.",
        )
    if (
        not getattr(operation, "operation_id", 0)
        and getattr(operation, "status", "") == "failed"
    ):
        return False, str(
            getattr(operation, "detail", "") or "Proxy reconcile was not queued.",
        )
    op_suffix = (
        f" operation #{operation.operation_id}"
        if getattr(operation, "operation_id", 0)
        else ""
    )
    return True, f"Proxy reconciliation queued{op_suffix}."


def _trigger_policy_sync(*, force: bool = True) -> tuple[bool, str]:
    """Queue selected-proxy policy reconciliation with a desired-policy fingerprint."""
    proxy_id = get_proxy_id()
    desired_policy_sha, desired_error = _desired_policy_sha_for_proxy(proxy_id)
    summary = "Policy state reconciliation queued."
    detail = "Admin changed policy state; proxy should refresh materialized policy files."
    if desired_policy_sha:
        summary = f"Policy state {_short_sha(desired_policy_sha)} queued for reconciliation."
        detail = f"Desired policy SHA: {desired_policy_sha}"
    elif desired_error:
        detail = f"Desired policy SHA unavailable before queueing. {desired_error}"
    try:
        operation = request_proxy_reconcile(
            proxy_id,
            operation_type="policy_sync",
            subject="Policy reconciliation",
            summary=summary,
            target_kind="policy_state",
            target_ref=desired_policy_sha,
            detail=detail,
            created_by=str(session.get("user") or ""),
            force=force,
        )
    except Exception as exc:
        log_exception_throttled(
            app.logger,
            "web.app.policy_sync",
            interval_seconds=30.0,
            message="Failed to queue policy reconciliation",
        )
        return False, public_error_message(
            exc,
            default="Policy reconciliation was not queued.",
        )
    if (
        not getattr(operation, "operation_id", 0)
        and getattr(operation, "status", "") == "failed"
    ):
        return False, str(
            getattr(operation, "detail", "") or "Policy reconcile was not queued.",
        )
    op_suffix = (
        f" operation #{operation.operation_id}"
        if getattr(operation, "operation_id", 0)
        else ""
    )
    sha_suffix = f" for policy {_short_sha(desired_policy_sha)}" if desired_policy_sha else ""
    return True, f"Policy reconciliation queued{op_suffix}{sha_suffix}."


def _trigger_proxy_cache_clear() -> tuple[bool, str]:
    """Queue cache clearing for the selected proxy through the operation ledger."""
    try:
        operation = request_proxy_reconcile(
            get_proxy_id(),
            operation_type="cache_clear",
            subject="Proxy cache clear",
            summary="Proxy cache clear queued.",
            detail="Admin requested proxy disk cache clearing.",
            created_by=str(session.get("user") or ""),
            force=True,
        )
    except Exception as exc:
        log_exception_throttled(
            app.logger,
            "web.app.proxy_cache_clear",
            interval_seconds=30.0,
            message="Failed to queue proxy cache clear",
        )
        return False, public_error_message(
            exc,
            default="Proxy cache clear was not queued.",
        )
    if (
        not getattr(operation, "operation_id", 0)
        and getattr(operation, "status", "") == "failed"
    ):
        return False, str(
            getattr(operation, "detail", "") or "Proxy cache clear was not queued.",
        )
    op_suffix = (
        f" operation #{operation.operation_id}"
        if getattr(operation, "operation_id", 0)
        else ""
    )
    return True, f"Proxy cache clear queued{op_suffix}."


def _publish_certificate_bundle_remote(
    bundle,
    *,
    original_filename: str = "",
) -> tuple[bool, str]:
    bundle_store = get_certificate_bundles()
    previous_revision = None
    try:
        previous_revision = bundle_store.get_active_bundle()
    except Exception:
        previous_revision = None
    revision = bundle_store.create_revision(
        bundle,
        created_by=str(session.get("user") or ""),
        original_filename=(original_filename or "")[:255],
        activate=True,
    )
    leaf_detail = ""
    try:
        admin_https = bundle_store.get_admin_ui_https_settings()
        if bool(getattr(admin_https, "enabled", False)):
            material = _materialize_admin_ui_https_leaf(revision)
            leaf_detail = (
                " Admin UI HTTPS leaf certificate was regenerated "
                f"for {', '.join(material.sans)}."
            )
    except Exception as exc:
        leaf_detail = (
            " Admin UI HTTPS leaf certificate regeneration failed: "
            f"{public_error_message(exc)}"
        )

    restore_detail = ""

    def restore_previous_active_bundle() -> None:
        nonlocal restore_detail
        try:
            restore_if_current = getattr(bundle_store, "restore_previous_if_current", None)
            if callable(restore_if_current):
                restored = restore_if_current(
                    revision.revision_id,
                    getattr(previous_revision, "revision_id", None),
                )
            elif previous_revision is not None:
                bundle_store.activate_revision(previous_revision.revision_id)
                restored = True
            else:
                bundle_store.deactivate_revision(revision.revision_id)
                restored = True
            if restored and previous_revision is not None:
                restore_detail = "Previous active certificate bundle was restored."
            elif restored:
                restore_detail = (
                    "Unqueued certificate bundle revision was left inactive."
                )
            else:
                restore_detail = (
                    "Active certificate bundle changed concurrently; newer active bundle was preserved."
                )
        except Exception:
            log_exception_throttled(
                app.logger,
                "web.app.certificate_apply_restore_active_bundle",
                interval_seconds=30.0,
                message="Failed to restore active certificate bundle after reconcile queue failure",
            )
            restore_detail = (
                "Failed to restore the prior active certificate bundle after reconcile queue failure; "
                "check the certificate bundle store before retrying."
            )

    proxies = get_proxy_registry().list_proxies()
    attempted = len(proxies)
    queued_count = 0
    failure_details = []
    for proxy in proxies:
        try:
            operation = request_proxy_reconcile(
                proxy.proxy_id,
                operation_type="certificate_apply",
                subject="Certificate bundle",
                summary=f"Certificate revision {revision.revision_id} saved; applying asynchronously to proxy {proxy.proxy_id}.",
                target_kind="certificate_revision",
                target_ref=revision.revision_id,
                rollback_kind="certificate_revision"
                if previous_revision is not None
                and previous_revision.revision_id != revision.revision_id
                else "",
                rollback_ref=getattr(previous_revision, "revision_id", "")
                if previous_revision is not None
                and previous_revision.revision_id != revision.revision_id
                else "",
                request_hash=getattr(revision, "bundle_sha256", ""),
                detail=f"Certificate revision {revision.revision_id} saved by admin-ui; waiting for proxy reconciliation.",
                created_by=str(session.get("user") or ""),
                force=True,
            )
        except Exception as exc:
            failure_details.append(
                f"{proxy.proxy_id}: {public_error_message(exc)}",
            )
            continue
        if getattr(operation, "operation_id", 0) and operation.status == "pending":
            queued_count += 1
        elif (
            not getattr(operation, "operation_id", 0)
            and getattr(operation, "status", "") == "failed"
        ):
            operation_detail = (
                getattr(operation, "detail", "")
                or "Certificate bundle reconciliation was not queued."
            )
            failure_details.append(f"{proxy.proxy_id}: {operation_detail}")
    if attempted == 0:
        restore_previous_active_bundle()
        detail = (
            f"Certificate revision {revision.revision_id} saved, but no registered proxies were available; "
            "certificate bundle was not activated."
        )
        if restore_detail:
            detail = f"{detail}\n{restore_detail}"
        return False, detail + leaf_detail
    if queued_count == attempted:
        plural = "operation" if queued_count == 1 else "operations"
        detail = f"Certificate revision {revision.revision_id} saved. Queued {queued_count} async {plural}."
    elif queued_count == 0:
        restore_previous_active_bundle()
        detail = f"Certificate revision {revision.revision_id} saved, but no proxy reconciliation operations were queued."
        if failure_details:
            detail = f"{detail}\n{failure_details[0]}"
        if restore_detail:
            detail = f"{detail}\n{restore_detail}"
        return False, detail + leaf_detail
    else:
        detail = (
            f"Certificate revision {revision.revision_id} saved. "
            f"Queued {queued_count}/{attempted} async operations; not every proxy got a queued operation."
        )
        if failure_details:
            detail = f"{detail} First queue failure: {failure_details[0]}"
    return True, detail + leaf_detail


def _best_effort_init_store(store: Any, *, key: str, description: str) -> None:
    try:
        store.init_db()
    except Exception:
        log_exception_throttled(
            app.logger,
            f"web.app.{key}.init_db",
            interval_seconds=30.0,
            message=f"Failed to initialize {description} store",
        )


def _best_effort_refresh_managed_policy(
    store: Any,
    *,
    force: bool = True,
) -> tuple[bool, str]:
    try:
        return _trigger_policy_sync(force=force)
    except Exception as exc:
        log_exception_throttled(
            app.logger,
            "web.app.refresh_managed_policy",
            interval_seconds=30.0,
            message="Failed to refresh managed policy state",
        )
        return False, public_error_message(
            exc,
            default="Policy changes were saved, but proxy reconciliation was not queued.",
        )


def _desired_pac_state_sha_for_proxy(proxy_id: str) -> tuple[str, str]:
    try:
        state = build_proxy_pac_state(proxy_id)
    except Exception as exc:
        return "", public_error_message(
            exc,
            default="Desired PAC state SHA could not be calculated.",
        )
    return str(getattr(state, "state_sha256", "") or ""), ""


def _queue_pac_runtime_refresh() -> tuple[bool, str]:
    proxy_id = get_proxy_id()
    desired_pac_sha, desired_error = _desired_pac_state_sha_for_proxy(proxy_id)
    summary = "PAC profile changes queued for proxy materialization."
    detail = "Admin changed PAC profile state; proxy should refresh materialized PAC files."
    if desired_pac_sha:
        summary = f"PAC state {_short_sha(desired_pac_sha)} queued for materialization."
        detail = f"Desired PAC state SHA: {desired_pac_sha}"
    elif desired_error:
        detail = f"Desired PAC state SHA unavailable before queueing. {desired_error}"
    try:
        operation = request_proxy_reconcile(
            proxy_id,
            operation_type="pac_refresh",
            subject="PAC profile refresh",
            summary=summary,
            target_kind="pac_state",
            target_ref=desired_pac_sha,
            detail=detail,
            created_by=str(session.get("user") or ""),
            force=True,
        )
    except Exception as exc:
        log_exception_throttled(
            app.logger,
            "web.app.refresh_pac_runtime",
            interval_seconds=30.0,
            message="Failed to queue PAC runtime refresh",
        )
        return False, public_error_message(
            exc,
            default="PAC profile changes were saved, but proxy materialization was not queued.",
        )

    if (
        not getattr(operation, "operation_id", 0)
        and getattr(operation, "status", "") == "failed"
    ):
        return False, str(
            getattr(operation, "detail", "")
            or "PAC profile changes were saved, but proxy materialization was not queued."
        )

    op_suffix = (
        f" operation #{operation.operation_id}"
        if getattr(operation, "operation_id", 0)
        else ""
    )
    return True, f"PAC runtime refresh queued{op_suffix}."


def _best_effort_refresh_pac_runtime() -> None:
    _queue_pac_runtime_refresh()


def _adblock_runtime_refresh_target(*, store: Any | None = None) -> dict[str, str]:
    target: dict[str, str] = {
        "target_kind": "",
        "target_ref": "",
        "request_hash": "",
        "summary": "Adblock settings changed; proxy reconciliation queued.",
        "detail_suffix": "",
    }
    store = store or get_adblock_store()
    try:
        refresh_requested = bool(store.get_refresh_requested())
    except Exception:
        refresh_requested = False
    try:
        settings_version = _safe_int(store.get_settings_version())
    except Exception:
        settings_version = 0
    if refresh_requested:
        target.update(
            target_kind="adblock_artifact_build",
            target_ref=str(settings_version) if settings_version else "",
            summary=(
                f"Adblock artifact build for settings version {settings_version} queued."
                if settings_version
                else "Adblock artifact build queued."
            ),
            detail_suffix=(
                f"Desired adblock settings version: {settings_version}"
                if settings_version
                else "Desired adblock settings version was unavailable before queueing."
            ),
        )
        return target
    try:
        summary = get_adblock_artifacts().get_active_artifact_summary()
    except Exception:
        summary = None
    revision_id = _safe_int(getattr(summary, "revision_id", 0)) if summary else 0
    artifact_sha = str(getattr(summary, "artifact_sha256", "") or "").strip()
    if revision_id and artifact_sha:
        target.update(
            target_kind="adblock_artifact",
            target_ref=str(revision_id),
            request_hash=artifact_sha,
            summary=f"Adblock artifact revision {revision_id} ({_short_sha(artifact_sha)}) queued for runtime refresh.",
            detail_suffix=f"Desired adblock artifact revision: {revision_id}; SHA: {artifact_sha}",
        )
    else:
        target.update(
            target_kind="adblock_artifact",
            summary="Adblock runtime refresh queued without active artifact evidence.",
            detail_suffix="No active adblock artifact revision/SHA was available before queueing.",
        )
    return target


def _queue_adblock_runtime_refresh(*, action: str, store: Any | None = None) -> tuple[bool, str]:
    default = "Adblock changes were saved, but runtime refresh was not queued."
    target = _adblock_runtime_refresh_target(store=store)
    detail = f"Admin requested adblock runtime refresh after {action}."
    if target.get("detail_suffix"):
        detail = f"{detail}\n{target['detail_suffix']}"
    try:
        operation = request_proxy_reconcile(
            get_proxy_id(),
            operation_type="adblock_refresh",
            subject="Adblock runtime refresh",
            summary=target["summary"],
            target_kind=target["target_kind"],
            target_ref=target["target_ref"],
            request_hash=target["request_hash"],
            detail=detail,
            created_by=str(session.get("user") or ""),
            force=True,
        )
    except Exception as exc:
        log_exception_throttled(
            app.logger,
            "web.app.adblock_runtime_refresh",
            interval_seconds=30.0,
            message="Failed to queue adblock runtime refresh",
        )
        return False, public_error_message(exc, default=default)
    if (
        not getattr(operation, "operation_id", 0)
        and getattr(operation, "status", "") == "failed"
    ):
        return False, str(
            getattr(operation, "detail", "")
            or "Adblock runtime refresh was not queued."
        )
    op_suffix = (
        f" operation #{operation.operation_id}"
        if getattr(operation, "operation_id", 0)
        else ""
    )
    return True, f"Adblock runtime refresh queued{op_suffix}."


def _redirect_adblock_queue_failure(detail: str):
    return _redirect_to(
        "adblock",
        error="1",
        msg=detail or "Adblock changes were saved, but runtime refresh was not queued.",
    )


def _queue_adblock_or_error(*, action: str, store: Any | None = None):
    ok, detail = _queue_adblock_runtime_refresh(action=action, store=store)
    if not ok:
        return _redirect_adblock_queue_failure(detail)
    return None


def _handle_adblock_post(store: Any):
    action = _form_action()
    if action == "save_lists":
        enabled_map = {}
        for st in store.list_statuses():
            enabled_map[st.key] = request.form.get(f"enabled_{st.key}") == "on"
        store.set_enabled(enabled_map)
        store.request_refresh_now()
        if response := _queue_adblock_or_error(action="list save", store=store):
            return response
    elif action == "save_settings":
        enabled = request.form.get("adblock_enabled") == "on"
        cur = store.get_settings()
        cache_ttl = _bounded_int(
            request.form.get("cache_ttl"),
            default=int(cur.get("cache_ttl") or 0),
            minimum=0,
            maximum=7 * 24 * 3600,
        )
        cache_max = _bounded_int(
            request.form.get("cache_max"),
            default=int(cur.get("cache_max") or 0),
            minimum=0,
            maximum=1_000_000,
        )
        store.set_settings(enabled=enabled, cache_ttl=cache_ttl, cache_max=cache_max)
        store.request_refresh_now()
        if response := _queue_adblock_or_error(action="settings save", store=store):
            return response
    elif action == "refresh":
        any_enabled = False
        try:
            any_enabled = any(st.enabled for st in store.list_statuses())
        except Exception:
            any_enabled = False
        if not any_enabled:
            return _redirect_to("adblock", refresh_no_lists="1")
        store.request_refresh_now()
        if response := _queue_adblock_or_error(action="manual refresh", store=store):
            return response
        return _redirect_to("adblock", refresh_requested="1")
    elif action == "flush_cache":
        store.request_cache_flush()
        if response := _queue_adblock_or_error(action="cache flush", store=store):
            return response
        return _redirect_to("adblock", cache_flushed="1")
    return _redirect_to("adblock")


def _webfilter_setting(settings: Any, name: str, default: Any = None) -> Any:
    if isinstance(settings, dict):
        return settings.get(name, default)
    return getattr(settings, name, default)


def _webfilter_current_settings(store: Any) -> Any:
    try:
        return store.get_settings()
    except Exception:
        return {}


def _webfilter_setting_list(settings: Any, name: str) -> list[str]:
    value = _webfilter_setting(settings, name, [])
    items = value.split(",") if isinstance(value, str) else list(value or [])
    return [str(item).strip() for item in items if str(item or "").strip()]


def _webfilter_setting_bool(settings: Any, name: str, default: bool = False) -> bool:
    value = _webfilter_setting(settings, name, default)
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _truthy_env(value: object | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on", "enabled"}


def _admin_ui_https_path_status(path: str) -> dict[str, Any]:
    clean_path = (path or "").strip()
    path_obj = pathlib.Path(clean_path)
    readable = bool(
        clean_path and path_obj.is_file() and os.access(clean_path, os.R_OK)
    )
    size = 0
    non_empty = False
    if readable:
        with contextlib.suppress(OSError):
            size = path_obj.stat().st_size
            non_empty = size > 0
    return {
        "path": clean_path,
        "configured": bool(clean_path),
        "readable": readable,
        "non_empty": non_empty,
        "valid": bool(readable and non_empty),
        "size": size,
    }


def _admin_ui_https_default_material_status() -> dict[str, Any]:
    validation = validate_tls_material_paths(
        ADMIN_UI_SSL_CERTFILE, ADMIN_UI_SSL_KEYFILE
    )
    cert_status = validation.cert_status.__dict__
    key_status = validation.key_status.__dict__
    return {
        "certfile": ADMIN_UI_SSL_CERTFILE,
        "keyfile": ADMIN_UI_SSL_KEYFILE,
        "cert_status": cert_status,
        "key_status": key_status,
        "ready": validation.ready,
        "detail": validation.detail,
    }


def _admin_ui_https_request_san_tokens() -> tuple[str, ...]:
    tokens: list[str] = []
    if has_request_context():
        tokens.extend(
            [
                request.host,
                sanitize_admin_ui_certificate_san_token(request.host),
                request.headers.get("X-Forwarded-Host", ""),
            ],
        )
    public_host = os.environ.get("ADMIN_UI_PUBLIC_HOST") or os.environ.get(
        "PROXY_PUBLIC_HOST",
    )
    if public_host:
        tokens.append(public_host)
    return tuple(tokens)


def _admin_ui_https_configured_san_tokens(value: object) -> tuple[str, ...]:
    raw_tokens = [
        token.strip()
        for token in re.split(r"[\n,]+", str(value or ""))
        if token.strip()
    ]
    tokens: list[str] = []
    seen: set[str] = set()
    for token in raw_tokens:
        clean = sanitize_admin_ui_certificate_san_token(token)
        if not clean:
            msg = (
                "Admin UI HTTPS SAN entries must be DNS names or IP addresses "
                "without paths, credentials, or wildcards."
            )
            raise ValueError(msg)
        normalized = normalize_admin_ui_certificate_sans([clean])
        key = clean.lower()
        if key not in normalized:
            msg = (
                "Admin UI HTTPS SAN entries must be DNS names or IP addresses "
                "without paths, credentials, or wildcards."
            )
            raise ValueError(msg)
        if key not in seen:
            seen.add(key)
            tokens.append(clean)
    return tuple(tokens)


def _admin_ui_https_format_san_tokens(tokens: Iterable[object]) -> str:
    return "\n".join(str(token).strip() for token in tokens if str(token).strip())


def _admin_ui_https_saved_san_tokens(settings: Any | None) -> tuple[str, ...]:
    return _admin_ui_https_configured_san_tokens(getattr(settings, "san_tokens", ""))


def _admin_ui_https_leaf_san_tokens(settings: Any | None = None) -> tuple[str, ...]:
    saved_tokens = _admin_ui_https_saved_san_tokens(settings)
    return (*saved_tokens, *_admin_ui_https_request_san_tokens())


def _admin_ui_https_setting_uses_default_leaf(settings: Any | None) -> bool:
    if settings is None or not bool(getattr(settings, "enabled", False)):
        return True
    certfile = str(getattr(settings, "certfile", "") or "").strip()
    keyfile = str(getattr(settings, "keyfile", "") or "").strip()
    return certfile == ADMIN_UI_SSL_CERTFILE and keyfile == ADMIN_UI_SSL_KEYFILE


def _admin_ui_https_converge_leaf_settings(settings: Any | None) -> Any | None:
    if settings is None or _admin_ui_https_setting_uses_default_leaf(settings):
        return settings
    try:
        return get_certificate_bundles().set_admin_ui_https_settings(
            enabled=bool(getattr(settings, "enabled", False)),
            certfile=ADMIN_UI_SSL_CERTFILE if getattr(settings, "enabled", False) else "",
            keyfile=ADMIN_UI_SSL_KEYFILE if getattr(settings, "enabled", False) else "",
            san_tokens=getattr(settings, "san_tokens", ""),
            updated_by=getattr(settings, "updated_by", ""),
        )
    except Exception:
        app.logger.exception("Failed to converge Admin UI HTTPS leaf paths")
        return settings


def _materialize_admin_ui_https_leaf(bundle: Any, settings: Any | None = None):
    if settings is None:
        try:
            settings = get_certificate_bundles().get_admin_ui_https_settings()
        except Exception:
            settings = None
    return materialize_admin_ui_server_certificate(
        ADMIN_UI_CA_DIR,
        bundle,
        san_tokens=_admin_ui_https_leaf_san_tokens(settings),
    )


def _admin_ui_https_status(bundle: Any | None = None) -> dict[str, Any]:
    default_certfile = ADMIN_UI_SSL_CERTFILE
    default_keyfile = ADMIN_UI_SSL_KEYFILE
    runtime_enabled = _truthy_env(
        os.environ.get("ADMIN_UI_EFFECTIVE_HTTPS_ENABLED")
        if os.environ.get("ADMIN_UI_EFFECTIVE_HTTPS_ENABLED") is not None
        else os.environ.get("ADMIN_UI_HTTPS_ENABLED"),
    )
    runtime_certfile = (
        os.environ.get("ADMIN_UI_EFFECTIVE_SSL_CERTFILE")
        or os.environ.get(
            "ADMIN_UI_SSL_CERTFILE",
        )
        or (default_certfile if runtime_enabled else "")
    )
    runtime_keyfile = (
        os.environ.get("ADMIN_UI_EFFECTIVE_SSL_KEYFILE")
        or os.environ.get(
            "ADMIN_UI_SSL_KEYFILE",
        )
        or (default_keyfile if runtime_enabled else "")
    )
    runtime_source = os.environ.get("ADMIN_UI_EFFECTIVE_HTTPS_SOURCE") or (
        "env" if os.environ.get("ADMIN_UI_HTTPS_ENABLED") is not None else ""
    )
    try:
        desired = _admin_ui_https_converge_leaf_settings(
            get_certificate_bundles().get_admin_ui_https_settings()
        )
        desired_error = ""
    except Exception as exc:
        app.logger.exception("Failed to load Admin UI HTTPS settings")
        desired = None
        desired_error = public_error_message(
            exc,
            default="Failed to load saved Admin UI HTTPS settings.",
        )

    desired_enabled = bool(getattr(desired, "enabled", False))
    desired_certfile = default_certfile if desired_enabled else ""
    desired_keyfile = default_keyfile if desired_enabled else ""
    pending_restart = desired is not None and (
        desired_enabled != runtime_enabled
        or (desired_enabled and desired_certfile != runtime_certfile)
        or (desired_enabled and desired_keyfile != runtime_keyfile)
    )
    runtime_material = (
        validate_tls_material_paths(runtime_certfile, runtime_keyfile)
        if runtime_enabled
        else None
    )
    desired_material = (
        validate_tls_material_paths(desired_certfile, desired_keyfile)
        if desired_enabled
        else None
    )
    default_material = _admin_ui_https_default_material_status()
    saved_san_tokens = _admin_ui_https_saved_san_tokens(desired)
    admin_ui_sans = normalize_admin_ui_certificate_sans(
        _admin_ui_https_leaf_san_tokens(desired)
    )
    return {
        "runtime_enabled": runtime_enabled,
        "runtime_source": runtime_source,
        "runtime_certfile": runtime_certfile,
        "runtime_keyfile": runtime_keyfile,
        "runtime_cert_status": (
            runtime_material.cert_status.__dict__
            if runtime_material
            else _admin_ui_https_path_status(runtime_certfile)
        ),
        "runtime_key_status": (
            runtime_material.key_status.__dict__
            if runtime_material
            else _admin_ui_https_path_status(runtime_keyfile)
        ),
        "runtime_material_ready": runtime_material.ready if runtime_material else False,
        "runtime_material_detail": runtime_material.detail if runtime_material else "",
        "desired_enabled": desired_enabled,
        "desired_certfile": desired_certfile,
        "desired_keyfile": desired_keyfile,
        "desired_cert_status": (
            desired_material.cert_status.__dict__
            if desired_material
            else _admin_ui_https_path_status(desired_certfile)
        ),
        "desired_key_status": (
            desired_material.key_status.__dict__
            if desired_material
            else _admin_ui_https_path_status(desired_keyfile)
        ),
        "desired_material_ready": desired_material.ready if desired_material else False,
        "desired_material_detail": desired_material.detail if desired_material else "",
        "desired_updated_by": getattr(desired, "updated_by", "") if desired else "",
        "desired_updated_ts": getattr(desired, "updated_ts", 0) if desired else 0,
        "configured_san_tokens": _admin_ui_https_format_san_tokens(saved_san_tokens),
        "configured_sans": saved_san_tokens,
        "desired_error": desired_error,
        "pending_restart": pending_restart,
        "runtime_missing_material": bool(runtime_source == "db-missing-material"),
        "active_bundle_available": bundle is not None,
        "active_material_ready": default_material["ready"],
        "active_material_detail": default_material["detail"],
        "default_certfile": default_certfile,
        "default_keyfile": default_keyfile,
        "admin_ui_sans": admin_ui_sans,
    }


def _admin_ui_https_env_lines(
    *, enabled: bool, certfile: str, keyfile: str
) -> list[str]:
    return [f"ADMIN_UI_HTTPS_ENABLED={1 if enabled else 0}"]


def _admin_ui_https_redirect_host() -> str:
    candidates = [request.host if has_request_context() else ""]
    public_host = os.environ.get("ADMIN_UI_PUBLIC_HOST") or os.environ.get(
        "PROXY_PUBLIC_HOST",
    )
    if public_host:
        candidates.append(public_host)
    candidates.append("localhost")
    for candidate in candidates:
        value = str(candidate or "").split(",", 1)[0].strip()
        if not value or any(char in value for char in ("/", "\\", "@")):
            continue
        try:
            parsed = urlsplit(f"//{value}")
        except ValueError:
            continue
        hostname = (parsed.hostname or "").strip().strip("[]").rstrip(".")
        if not hostname:
            continue
        normalized = normalize_admin_ui_certificate_sans([hostname])
        hostname_key = hostname.lower()
        if hostname_key not in normalized:
            continue
        try:
            port = parsed.port
        except ValueError:
            port = None
        if port is None:
            return hostname_key
        if ":" in hostname_key:
            return f"[{hostname_key}]:{port}"
        return f"{hostname_key}:{port}"
    return "localhost"


def _admin_ui_https_next_url() -> str:
    return f"https://{_admin_ui_https_redirect_host()}{_endpoint_url('certs')}"


def _restart_admin_ui_web_process() -> tuple[bool, str]:
    supervisorctl = shutil.which("supervisorctl")
    if not supervisorctl:
        return False, "supervisorctl is not available in this runtime."
    try:
        subprocess.Popen(
            [
                sys.executable,
                "-c",
                (
                    "import subprocess, time; "
                    "time.sleep(0.2); "
                    f"subprocess.run([{supervisorctl!r}, '-c', '/etc/supervisord.conf', 'restart', 'web'])"
                ),
            ],
            close_fds=True,
            start_new_session=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception as exc:
        return False, public_error_message(
            exc,
            default="Failed to request Admin UI web restart.",
        )
    return True, "Admin UI web restart requested; reconnect using the selected scheme."


def _webfilter_category_refresh_required(
    current_settings: Any,
    *,
    enabled: bool,
) -> bool:
    return bool(enabled or _webfilter_setting_bool(current_settings, "enabled", False))


def _webfilter_set_settings(store: Any, **kwargs: Any) -> None:
    optional_names = {
        "source_provider",
        "safe_browsing_enabled",
        "safe_browsing_api_key",
        "safe_browsing_lists",
    }
    try:
        accepted_settings = set(inspect.signature(store.set_settings).parameters)
    except (TypeError, ValueError):
        accepted_settings = optional_names
    store.set_settings(
        **{
            key: value
            for key, value in kwargs.items()
            if key not in optional_names or key in accepted_settings
        },
    )


def _handle_webfilter_post(store: Any, tab: str):
    action = _form_action()
    if action == "save":
        current_settings = _webfilter_current_settings(store)
        enabled = request.form.get("enabled") == "on"
        source_url = (request.form.get("source_url") or "").strip()
        source_provider = (
            (request.form.get("source_provider") or "auto").strip().lower()
        )
        if source_provider not in {"auto", "ut1", "category-dir", "csv"}:
            source_provider = "auto"
        categories = [
            c.strip() for c in request.form.getlist("categories") if (c or "").strip()
        ]

        if enabled and categories and not source_url:
            return _redirect_to("webfilter", tab="categories", err_source="1")

        category_refresh_required = _webfilter_category_refresh_required(
            current_settings,
            enabled=enabled,
        )

        if source_url and category_refresh_required:
            try:
                source_url = _validate_webfilter_source_url(source_url)
            except ValueError:
                return _redirect_to("webfilter", tab="categories", err_source="1")

        try:
            _webfilter_set_settings(
                store,
                enabled=enabled,
                source_url=source_url,
                blocked_categories=categories,
                source_provider=source_provider,
                safe_browsing_enabled=bool(
                    _webfilter_setting(
                        current_settings,
                        "safe_browsing_enabled",
                        False,
                    ),
                ),
                safe_browsing_api_key=str(
                    _webfilter_setting(
                        current_settings,
                        "safe_browsing_api_key",
                        "",
                    )
                    or "",
                ),
                safe_browsing_lists=_webfilter_setting_list(
                    current_settings,
                    "safe_browsing_lists",
                ),
            )
        except ValueError:
            return _redirect_to("webfilter", tab="categories", err_source="1")
        if not category_refresh_required:
            return _redirect_to("webfilter", tab="categories")
        return _redirect_after_policy_refresh(
            "webfilter",
            store,
            force=True,
            tab="categories",
        )

    if action == "safe_browsing_save":
        current_settings = _webfilter_current_settings(store)
        safe_browsing_enabled = request.form.get("safe_browsing_enabled") == "on"
        safe_browsing_api_key = (
            request.form.get("safe_browsing_api_key") or ""
        ).strip()
        safe_browsing_clear_key = request.form.get("safe_browsing_clear_key") == "on"
        if safe_browsing_clear_key:
            safe_browsing_api_key = ""
        elif not safe_browsing_api_key:
            safe_browsing_api_key = str(
                _webfilter_setting(current_settings, "safe_browsing_api_key", "") or "",
            )
        safe_browsing_lists = [
            c.strip()
            for c in request.form.getlist("safe_browsing_lists")
            if (c or "").strip()
        ]
        safe_browsing_lists = list(
            SafeBrowsingStore.selected_lists(safe_browsing_lists)
        )

        if safe_browsing_enabled and not safe_browsing_lists:
            return _redirect_to(
                "webfilter", tab="categories", err_safe_browsing_lists="1"
            )

        if safe_browsing_enabled and not safe_browsing_api_key:
            return _redirect_to(
                "webfilter", tab="categories", err_safe_browsing_key="1"
            )

        try:
            _webfilter_set_settings(
                store,
                enabled=bool(_webfilter_setting(current_settings, "enabled", False)),
                source_url=str(
                    _webfilter_setting(current_settings, "source_url", "") or "",
                ),
                blocked_categories=_webfilter_setting_list(
                    current_settings,
                    "blocked_categories",
                ),
                source_provider=str(
                    _webfilter_setting(current_settings, "source_provider", "auto")
                    or "auto",
                ),
                safe_browsing_enabled=safe_browsing_enabled,
                safe_browsing_api_key=safe_browsing_api_key,
                safe_browsing_lists=safe_browsing_lists,
            )
        except ValueError:
            return _redirect_to("webfilter", tab="categories", err_source="1")
        return _redirect_after_policy_refresh(
            "webfilter",
            store,
            force=True,
            tab="categories",
            safe_browsing_saved="1",
        )

    if action == "whitelist_add":
        entry = (request.form.get("whitelist_domain") or "").strip()
        ok, err, _pat = store.add_whitelist(entry)
        if not ok:
            return _redirect_to(
                "webfilter",
                tab="whitelist",
                wl_err=(err or "1"),
            )
        return _redirect_after_policy_refresh(
            "webfilter",
            store,
            force=True,
            tab="whitelist",
            wl_ok="1",
        )

    if action == "whitelist_remove":
        pat = (request.form.get("pattern") or "").strip()
        with contextlib.suppress(Exception):
            store.remove_whitelist(pat)
        return _redirect_after_policy_refresh(
            "webfilter",
            store,
            force=True,
            tab="whitelist",
        )

    return _redirect_to("webfilter", tab=tab)


def _normalize_webfilter_categories(rows: Any) -> list[tuple[str, int]]:
    normalized: list[tuple[str, int]] = []
    for row in rows or []:
        if isinstance(row, (list, tuple)) and len(row) >= 2:
            key, count = row[0], row[1]
        else:
            key = getattr(row, "key", None) or getattr(row, "category", None)
            count = getattr(row, "domains", None) or getattr(row, "count", None) or 0
        key = str(key or "").strip()
        if not key:
            continue
        try:
            count_i = int(count or 0)
        except Exception:
            count_i = 0
        normalized.append((key, max(0, count_i)))
    return normalized


def _sslfilter_policy_from_form() -> str:
    return (request.form.get("policy") or "").strip().lower()


def _sslfilter_redirect(**params: Any):
    return _redirect_after_policy_refresh(
        "sslfilter",
        get_sslfilter_store(),
        force=True,
        **params,
    )


def _bool_result_param(ok: bool) -> str:
    return "1" if ok else "0"


def _add_sslfilter_domain(store: Any, policy: str, value: str) -> tuple[bool, str, str]:
    try:
        return store.add_domain(policy, value)
    except Exception as exc:
        return False, public_error_message(exc), ""


def _add_sslfilter_src(store: Any, policy: str, value: str) -> tuple[bool, str, str]:
    try:
        return store.add_src_net(policy, value)
    except Exception as exc:
        return False, public_error_message(exc), ""


def _handle_sslfilter_post(store: Any):
    action = _form_action(lower=True)
    policy = _sslfilter_policy_from_form()

    if action in {"apply_policy", "apply_verify"}:
        ok, detail = _trigger_policy_sync(force=True)
        detail = (
            detail or ("Policy sync requested." if ok else "Policy sync failed.")
        ).strip()
        _record_audit_event("sslfilter_apply_policy", ok=ok, detail=detail)
        return _redirect_to(
            "sslfilter",
            apply_ok=_bool_result_param(ok),
            apply_msg=detail[:1000],
        )

    if action == "toggle_inspection":
        store.set_inspection_enabled(request.form.get("inspection_enabled") == "on")
        return _sslfilter_redirect(inspection_saved="1")

    if action == "install_compatibility_preset":
        preset_id = (request.form.get("preset_id") or "").strip()
        added, attempted, err = store.install_compatibility_preset(preset_id)
        if err:
            return _redirect_to("sslfilter", err=err)
        return _sslfilter_redirect(
            compatibility_added=added,
            compatibility_attempted=attempted,
        )

    if action == "add":
        ok, err, canonical = _add_sslfilter_src(
            store,
            "nobump",
            request.form.get("cidr") or "",
        )
        if not ok:
            return _redirect_to("sslfilter", err=err or "Invalid CIDR.")
        return _sslfilter_redirect(ok="1", added="1", value=canonical, policy="nobump")

    if action == "remove":
        ok, err, canonical = normalize_src_net_rule(request.form.get("cidr") or "")
        if not ok:
            return _redirect_to("sslfilter", err=err or "Invalid CIDR.")
        store.remove_src_net("nobump", canonical)
        return _sslfilter_redirect(removed="1")

    if action in {"add_domain", "add_domain_bulk"}:
        if policy not in {"nobump", "nocache"}:
            return _redirect_to("sslfilter", err="Invalid domain policy.")
        field = "domains_bulk" if action == "add_domain_bulk" else "domain"
        values = (
            _bulk_lines(request.form.get(field))
            if action == "add_domain_bulk"
            else [request.form.get(field) or ""]
        )
        if not values:
            return _redirect_to(
                "sslfilter",
                err="At least one domain is required.",
                added=0,
            )
        added = 0
        errors: list[str] = []
        last_value = ""
        for value in values:
            ok, err, canonical = _add_sslfilter_domain(store, policy, value)
            if ok:
                added += 1
                last_value = canonical
            elif err:
                errors.append(f"{value}: {err}")
        if errors:
            if added:
                return _sslfilter_redirect(err=" | ".join(errors[:3]), added=added)
            return _redirect_to("sslfilter", err=" | ".join(errors[:3]), added=added)
        return _sslfilter_redirect(ok="1", added=added, value=last_value, policy=policy)

    if action == "remove_domain":
        if policy in {"nobump", "nocache"}:
            ok, err, canonical = validate_domain_rule(request.form.get("domain") or "")
            if not ok:
                return _redirect_to("sslfilter", err=err or "Invalid domain.")
            store.remove_domain(policy, canonical)
            return _sslfilter_redirect(removed="1")
        return _redirect_to("sslfilter", err="Invalid domain policy.")

    if action in {"add_src", "add_src_bulk"}:
        if policy not in {"nobump", "nocache"}:
            return _redirect_to("sslfilter", err="Invalid CIDR policy.")
        field = "src_bulk" if action == "add_src_bulk" else "cidr"
        values = (
            _bulk_lines(request.form.get(field))
            if action == "add_src_bulk"
            else [request.form.get(field) or ""]
        )
        if not values:
            return _redirect_to(
                "sslfilter",
                err="At least one CIDR/IP entry is required.",
                added=0,
            )
        added = 0
        errors: list[str] = []
        last_value = ""
        for value in values:
            ok, err, canonical = _add_sslfilter_src(store, policy, value)
            if ok:
                added += 1
                last_value = canonical
            elif err:
                errors.append(f"{value}: {err}")
        if errors:
            if added:
                return _sslfilter_redirect(err=" | ".join(errors[:3]), added=added)
            return _redirect_to("sslfilter", err=" | ".join(errors[:3]), added=added)
        return _sslfilter_redirect(ok="1", added=added, value=last_value, policy=policy)

    if action == "remove_src":
        if policy in {"nobump", "nocache"}:
            ok, err, canonical = normalize_src_net_rule(request.form.get("cidr") or "")
            if not ok:
                return _redirect_to("sslfilter", err=err or "Invalid CIDR.")
            store.remove_src_net(policy, canonical)
            return _sslfilter_redirect(removed="1")
        return _redirect_to("sslfilter", err="Invalid CIDR policy.")

    if action == "toggle_private":
        store.set_exclude_private_nets(request.form.get("exclude_private_nets") == "on")
        return _sslfilter_redirect(private_saved="1")

    return _redirect_to("sslfilter")


def _handle_pac_builder_post(store: Any):
    action = _form_action()
    try:
        if action == "add_backup_proxy":
            ok, err, _ = store.add_backup_proxy(
                proxy_host=request.form.get("backup_proxy_host") or "",
                proxy_port=request.form.get("backup_proxy_port") or "",
            )
            if not ok:
                return _redirect_to("pac_builder", error="1", msg=err)
            return _redirect_after_pac_refresh("pac_builder", ok="1")

        if action == "remove_backup_proxy":
            changed = store.delete_backup_proxy(
                _bounded_int(request.form.get("backup_proxy_id"), default=0)
            )
            if not changed:
                return _redirect_to(
                    "pac_builder", error="1", msg="Backup proxy not found."
                )
            return _redirect_after_pac_refresh("pac_builder", ok="1")

        if action == "move_backup_proxy":
            changed = store.move_backup_proxy(
                _bounded_int(request.form.get("backup_proxy_id"), default=0),
                request.form.get("direction") or "",
            )
            if not changed:
                return _redirect_to(
                    "pac_builder", error="1", msg="Backup proxy not found."
                )
            return _redirect_after_pac_refresh("pac_builder", ok="1")

        if action == "toggle_direct":
            store.set_direct_enabled(request.form.get("direct_enabled") == "on")
            return _redirect_after_pac_refresh("pac_builder", ok="1")

        if action == "create":
            ok, err, _ = store.upsert_profile(**_pac_profile_form_data(profile_id=None))
            if not ok:
                return _redirect_to("pac_builder", error="1", msg=err)
            return _redirect_after_pac_refresh("pac_builder", ok="1")

        if action == "update":
            pid = int(request.form.get("profile_id") or "0")
            ok, err, _ = store.upsert_profile(**_pac_profile_form_data(profile_id=pid))
            if not ok:
                return _redirect_to("pac_builder", error="1", msg=err)
            return _redirect_after_pac_refresh("pac_builder", ok="1")

        if action == "delete":
            pid = int(request.form.get("profile_id") or "0")
            changed = store.delete_profile(pid)
            if not changed:
                return _redirect_to("pac_builder", error="1", msg="Profile not found.")
            return _redirect_after_pac_refresh("pac_builder", ok="1")
    except Exception as e:
        return _redirect_to("pac_builder", error="1", msg=public_error_message(e))

    return _redirect_to("pac_builder")


def _handle_administration_post(store: Any, current_user: str):
    action = _form_action()
    if action in {
        "save_auth_provider",
        "test_auth_provider",
        "scan_auth_provider",
        "disable_auth_provider",
        "save_saml_provider",
        "refresh_saml_metadata",
        "disable_saml_provider",
    }:
        return _handle_auth_provider_post()
    try:
        if action == "add_user":
            username = (request.form.get("username") or "").strip()
            password = request.form.get("password") or ""
            store.add_user(username, password)
            return _redirect_with_message("administration", ok=True, msg="User added.")

        if action == "set_password":
            username = (request.form.get("username") or "").strip()
            new_password = request.form.get("new_password") or ""
            store.set_password(username, new_password)
            return _redirect_with_message(
                "administration",
                ok=True,
                msg="Password updated.",
            )

        if action == "delete_user":
            username = (request.form.get("username") or "").strip()
            if (
                username == current_user
                or username.casefold() == current_user.casefold()
            ):
                return _redirect_with_message(
                    "administration",
                    ok=False,
                    msg="Cannot remove the currently signed-in user.",
                )
            users = store.list_users()
            if len(users) <= 1:
                return _redirect_with_message(
                    "administration",
                    ok=False,
                    msg="Cannot remove the last user.",
                )
            store.delete_user(username)
            return _redirect_with_message(
                "administration",
                ok=True,
                msg="User removed.",
            )

        return _redirect_with_message("administration", ok=False, msg="Unknown action.")
    except ValueError as e:
        return _redirect_with_message(
            "administration",
            ok=False,
            msg=public_error_message(e),
        )
    except Exception as e:
        app.logger.exception("Administration action failed")
        return _redirect_with_message(
            "administration",
            ok=False,
            msg=public_error_message(e),
        )


def _handle_auth_provider_post():
    action = _form_action()
    provider = (request.form.get("provider") or "").strip()
    tab = provider if provider in {"ldap", "active_directory", "saml"} else "status"

    def _submitted_directory_payload() -> dict[str, Any]:
        payload = request.form.to_dict()
        ca_upload = request.files.get("ca_bundle_file")
        if ca_upload is not None and ca_upload.filename:
            payload["ca_bundle_upload"] = ca_upload.read()
        return payload

    try:
        if action == "save_saml_provider":
            _saml_auth_store.save_profile(request.form.to_dict())
            return _redirect_with_message(
                "administration",
                ok=True,
                msg="SAML provider saved.",
                tab="saml",
            )
        if action == "refresh_saml_metadata":
            result = _saml_auth_store.refresh_metadata()
            return _redirect_with_message(
                "administration",
                ok=result.ok,
                msg=result.detail,
                tab="saml",
            )
        if action == "disable_saml_provider":
            _saml_auth_store.disable_provider()
            return _redirect_with_message(
                "administration",
                ok=True,
                msg="SAML provider disabled.",
                tab="saml",
            )
        if action == "save_auth_provider":
            _directory_auth_store.save_profile(provider, _submitted_directory_payload())
            return _redirect_with_message(
                "administration",
                ok=True,
                msg="Authentication provider saved.",
                tab=tab,
            )
        if action == "test_auth_provider":
            payload = _submitted_directory_payload()
            was_enabled = _directory_auth_store.get_profile(provider).enabled
            payload["enabled"] = "0"
            _directory_auth_store.save_profile(provider, payload)
            result = _directory_auth_store.test_connection(provider)
            if was_enabled and result.ok:
                reenable_payload = dict(payload)
                reenable_payload["enabled"] = "1"
                reenable_payload["bind_password"] = ""
                _directory_auth_store.save_profile(provider, reenable_payload)
            return _redirect_with_message(
                "administration",
                ok=result.ok,
                msg=result.detail,
                tab=tab,
            )
        if action == "scan_auth_provider":
            payload = _submitted_directory_payload()
            was_enabled = _directory_auth_store.get_profile(provider).enabled
            payload["enabled"] = "0"
            saved_profile = _directory_auth_store.save_profile(provider, payload)
            result = _directory_auth_store.scan_directory(provider)
            if was_enabled and saved_profile.last_test_ok:
                reenable_payload = dict(payload)
                reenable_payload["enabled"] = "1"
                reenable_payload["bind_password"] = ""
                _directory_auth_store.save_profile(provider, reenable_payload)
            session[f"directory_scan_{provider}"] = {
                "base_dns": list(result.base_dns),
                "user_search_bases": list(result.user_search_bases),
                "group_search_bases": list(result.group_search_bases),
                "admin_groups": list(result.admin_groups),
            }
            return _redirect_with_message(
                "administration",
                ok=True,
                msg=result.detail,
                tab=tab,
            )
        if action == "disable_auth_provider":
            _directory_auth_store.disable_provider(provider)
            return _redirect_with_message(
                "administration",
                ok=True,
                msg="Authentication provider disabled.",
                tab=tab,
            )
    except ValueError as e:
        return _redirect_with_message(
            "administration",
            ok=False,
            msg=public_error_message(e),
            tab=tab,
        )
    except Exception as e:
        app.logger.exception("Authentication provider action failed")
        return _redirect_with_message(
            "administration",
            ok=False,
            msg=public_error_message(e),
            tab=tab,
        )
    return _redirect_with_message(
        "administration",
        ok=False,
        msg="Unknown authentication provider action.",
        tab=tab,
    )


def _saml_admin_status() -> dict[str, Any]:
    profile = _saml_auth_store.get_profile()
    try:
        sp_info = build_sp_info(profile, request)
    except Exception:
        sp_info = {"entity_id": "", "acs_url": "", "sls_url": ""}
    ready = profile_metadata_ready(profile)
    metadata = profile.parsed_metadata
    return {
        "profile": profile,
        "ready": ready,
        "metadata_ready": profile_metadata_cache_ready(profile),
        "sp": sp_info,
        "idp_entity_id": profile.entity_id,
        "signing_certs": metadata.get("signing_certs") or [],
    }


@app.route("/")
def index():
    proxy_id = get_proxy_id()
    observability = _cached_observability_summary(
        proxy_id,
        OBSERVABILITY_DEFAULT_WINDOW,
    )
    observability_window_label = _window_label(OBSERVABILITY_DEFAULT_WINDOW)
    try:
        health = _cached_proxy_health(
            proxy_id,
            timeout_seconds=_proxy_health_timeout_seconds(),
            full=True,
        )
    except ProxyClientError as exc:
        proxy = get_proxy_registry().get_proxy(proxy_id)
        health = {
            "ok": False,
            "status": proxy.status if proxy else "offline",
            "proxy_status": str(exc),
            "stats": {},
            "services": {
                "icap": {"ok": False, "detail": "unavailable"},
                "clamav": {"ok": False, "detail": "unavailable"},
            },
        }

    proxy_detail = str(health.get("proxy_status") or health.get("detail") or "")
    proxy_ok = bool(health.get("ok"))
    stats = health.get("stats") or {}
    try:
        trends = get_timeseries_store().summary()
    except Exception:
        trends = {}

    services = health.get("services") or {}
    icap_health = services.get("icap") or {"ok": False, "detail": "n/a"}
    clamav_health = services.get("clamav") or {"ok": False, "detail": "n/a"}
    forwarding_health = services.get("forwarding") or {"ok": False, "detail": "n/a"}

    last_config = None
    revisions = get_config_revisions()
    latest_apply = revisions.latest_apply(proxy_id)
    if latest_apply is not None:
        last_config = {
            "ts": latest_apply.applied_ts,
            "kind": "config_apply_remote",
            "ok": latest_apply.ok,
            "remote_addr": proxy_id,
            "user_agent": latest_apply.applied_by,
            "detail": latest_apply.detail,
        }
    else:
        try:
            row = get_audit_store().latest_config_apply()
            if row:
                last_config = {
                    "ts": int(row[0]),
                    "kind": row[1],
                    "ok": bool(row[2]),
                    "remote_addr": row[3],
                    "user_agent": row[4],
                    "detail": row[5],
                }
        except Exception:
            pass
    try:
        active_revision = revisions.get_active_revision_metadata(proxy_id)
    except Exception:
        active_revision = None
    config_runtime_state = _config_runtime_state(
        proxy_id,
        active_revision=active_revision,
        runtime_health=health,
        latest_apply=latest_apply,
    )

    return render_template(
        "index.html",
        proxy_status=proxy_detail,
        proxy_ok=proxy_ok,
        flask_status="OK",
        stats=stats,
        trends=trends,
        icap_health=icap_health,
        clamav_health=clamav_health,
        forwarding_health=forwarding_health,
        last_config=last_config,
        config_runtime_state=config_runtime_state,
        observability=observability,
        observability_window_label=observability_window_label,
    )


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True}), 200


@app.route("/api/version-status", methods=["GET"])
def api_version_status():
    admin_status = _cached_admin_version_status()
    proxy_status = _initial_version_header_status()["proxy"]
    proxy_id = normalize_proxy_id(
        request.args.get("proxy_id") or session.get("active_proxy_id") or ""
    )
    if proxy_id:
        try:
            health = _cached_proxy_health(
                proxy_id,
                timeout_seconds=_proxy_health_timeout_seconds(),
            )
            proxy_status = _proxy_version_status_from_health(health)
        except Exception as exc:
            proxy_status = {
                **proxy_status,
                "detail": public_error_message(
                    exc,
                    default="Selected proxy version metadata is unavailable.",
                ),
            }
    return jsonify({"ok": True, "admin": admin_status, "proxy": proxy_status})


@app.route("/api/squid-config", methods=["GET"])
def api_squid_config():
    cfg = _current_managed_config()
    return app.response_class(cfg, mimetype="text/plain; charset=utf-8")


@app.route("/api/squid-config/state", methods=["GET"])
def api_squid_config_state():
    proxy_id = get_proxy_id()
    return jsonify({"ok": True, **_config_runtime_state(proxy_id)}), 200


@app.route("/proxies/reconcile", methods=["POST"])
def reconcile_proxy_identity():
    old_proxy_id = (request.form.get("old_proxy_id") or "").strip()
    new_proxy_id = (request.form.get("new_proxy_id") or "").strip()
    display_name = (request.form.get("display_name") or "").strip()
    try:
        renamed = get_proxy_registry().rename_proxy(
            old_proxy_id,
            new_proxy_id,
            display_name=display_name or new_proxy_id,
        )
    except Exception as exc:
        return _redirect_to("proxies", error="1", msg=public_error_message(exc))
    if session.get("active_proxy_id") == normalize_proxy_id(old_proxy_id):
        session["active_proxy_id"] = renamed.proxy_id
    _PROXY_HEALTH_CACHE.clear()
    _OBSERVABILITY_SUMMARY_CACHE.clear()
    _OBSERVABILITY_RESULT_CACHE.clear()
    return _redirect_to("proxies", saved="1", proxy_id=renamed.proxy_id)


@app.route("/proxies/remove", methods=["POST"])
def remove_proxy():
    proxy_id = (request.form.get("proxy_id") or "").strip()
    confirmation = (request.form.get("confirm_proxy_id") or "").strip()
    normalized_proxy_id = normalize_proxy_id(proxy_id)
    if not proxy_id or proxy_id != normalized_proxy_id:
        return _redirect_to(
            "proxies",
            error="1",
            msg="Proxy removal requires an exact registered proxy ID.",
        )
    if confirmation != normalized_proxy_id:
        return _redirect_to(
            "proxies",
            error="1",
            msg="Type the proxy ID exactly to confirm removal.",
        )
    try:
        result = get_proxy_registry().remove_proxy(normalized_proxy_id)
    except Exception as exc:
        _record_audit_event(
            "proxy_remove",
            ok=False,
            detail=f"proxy_id={normalized_proxy_id} error={public_error_message(exc)}",
        )
        return _redirect_to("proxies", error="1", msg=public_error_message(exc))

    remaining = get_proxy_registry().list_proxies()
    if session.get("active_proxy_id") in {None, normalized_proxy_id}:
        if remaining:
            session["active_proxy_id"] = remaining[0].proxy_id
        else:
            session.pop("active_proxy_id", None)
    _PROXY_HEALTH_CACHE.clear()
    _OBSERVABILITY_SUMMARY_CACHE.clear()
    _OBSERVABILITY_RESULT_CACHE.clear()
    _record_audit_event(
        "proxy_remove",
        ok=True,
        detail=(
            f"proxy_id={result.proxy_id} deleted_rows={result.deleted_rows} "
            f"tables={','.join(result.table_counts)}"
        ),
    )
    return _redirect_to(
        "proxies",
        removed="1",
        msg=f"Removed {result.proxy_id} and deleted {result.deleted_rows} scoped MySQL rows.",
    )


@app.route("/proxies", methods=["GET"])
def proxies():
    registry = get_proxy_registry()
    requested_proxy = request.args.get("proxy_id")
    if requested_proxy is not None:
        session["active_proxy_id"] = normalize_proxy_id(requested_proxy)
    proxies = _proxy_inventory_or_default(registry)
    live_health = {
        proxy.proxy_id: {
            "ok": str(proxy.status or "").lower() == "healthy",
            "status": proxy.status,
            "proxy_status": proxy.detail,
            "detail": proxy.detail,
            "listener_details": [],
            "services": {},
        }
        for proxy in proxies
    }
    active_proxy_id = normalize_proxy_id(
        session.get("active_proxy_id") or get_default_proxy_id(),
    )
    active_proxy = _resolve_proxy_from_inventory(registry, proxies, active_proxy_id)
    if active_proxy is None:
        active_proxy = proxies[0] if proxies else None
    active_proxy_id = active_proxy.proxy_id if active_proxy else ""
    if active_proxy_id:
        session["active_proxy_id"] = active_proxy_id
    if active_proxy_id in live_health:
        try:
            live_health[active_proxy_id] = _cached_proxy_health(
                active_proxy_id,
                timeout_seconds=_proxy_health_timeout_seconds(),
            )
        except ProxyClientError as exc:
            active_proxy = next(
                (proxy for proxy in proxies if proxy.proxy_id == active_proxy_id),
                None,
            )
            live_health[active_proxy_id] = {
                "ok": False,
                "status": active_proxy.status if active_proxy else "unknown",
                "detail": str(exc),
                "listener_details": [],
                "services": {},
            }
    observability_by_proxy: dict[str, dict[str, Any]] = {}
    if active_proxy_id:
        try:
            observability_by_proxy[active_proxy_id] = _cached_observability_summary(
                active_proxy_id,
                OBSERVABILITY_DEFAULT_WINDOW,
            )
        except Exception:
            observability_by_proxy[active_proxy_id] = _present_observability_summary()
    return render_template(
        "fleet.html",
        proxies=proxies,
        live_health=live_health,
        observability_by_proxy=observability_by_proxy,
    )


@app.route("/operations", methods=["GET"])
def operations_status():
    proxy_id = get_proxy_id()
    ledger = get_operation_ledger()
    try:
        operations = ledger.list_operations(proxy_id, limit=100)
        operation_counts = ledger.counts_by_status(proxy_id)
    except Exception:
        operations = []
        operation_counts = {"pending": 0, "applying": 0, "applied": 0, "failed": 0}
    operations = _operation_template_rows(operations)
    return render_template(
        "operations.html",
        operations=operations,
        operation_counts=operation_counts,
    )


@app.route("/logs", methods=["GET"])
def logs_status():
    proxy_id = get_proxy_id()
    requested_log = request.args.get("log")
    payload, logs, _proxy_error = _get_selected_log_payload(proxy_id, requested_log)
    return render_template("logs.html", log_payload=payload, logs=logs)


def _get_selected_log_payload(
    proxy_id: str,
    requested_log: str | None,
) -> tuple[dict[str, Any], list[Any], bool]:
    selected_log = (requested_log or "access").strip() or "access"
    proxy_error = False
    try:
        payload = get_proxy_client().get_logs(proxy_id, log_key=selected_log)
    except ProxyClientError as exc:
        proxy_error = True
        payload = {
            "ok": False,
            "status": "unavailable",
            "detail": str(exc),
            "key": selected_log,
            "label": selected_log,
            "content": "",
            "size_bytes": 0,
            "truncated": False,
            "max_bytes": 256 * 1024,
            "logs": [],
        }
    logs = payload.get("logs") if isinstance(payload.get("logs"), list) else []
    if (
        requested_log is None
        and logs
        and not any(
            item.get("key") == payload.get("key")
            for item in logs
            if isinstance(item, dict)
        )
    ):
        first_log = next((item for item in logs if isinstance(item, dict)), None)
        if first_log is not None:
            try:
                payload = get_proxy_client().get_logs(
                    proxy_id,
                    log_key=first_log.get("key"),
                )
                logs = (
                    payload.get("logs")
                    if isinstance(payload.get("logs"), list)
                    else logs
                )
            except ProxyClientError:
                pass
    return payload, logs, proxy_error


@app.route("/api/logs", methods=["GET"])
def api_logs_status():
    proxy_id = get_proxy_id()
    requested_log = request.args.get("log")
    payload, _logs, proxy_error = _get_selected_log_payload(proxy_id, requested_log)
    if proxy_error:
        return jsonify(payload), 503
    return jsonify(payload), proxy_log_status_code(payload)


@app.route("/api/operations", methods=["GET"])
def api_operations():
    proxy_id = get_proxy_id()
    ledger = get_operation_ledger()
    try:
        after_ts = int(request.args.get("after_updated_ts") or 0)
        after_id = int(request.args.get("after_id") or 0)
    except Exception:
        after_ts = 0
        after_id = 0
    try:
        if after_ts or after_id:
            operations = ledger.list_recent_since(
                proxy_id,
                after_updated_ts=after_ts,
                after_id=after_id,
                limit=100,
            )
        else:
            operations = ledger.list_operations(proxy_id, limit=100)
        counts = ledger.counts_by_status(proxy_id)
        return jsonify(
            {
                "ok": True,
                "proxy_id": proxy_id,
                "operations": [op.to_dict() for op in operations],
                "counts": counts,
            },
        ), 200
    except Exception as exc:
        return jsonify(
            {
                "ok": False,
                "proxy_id": proxy_id,
                "operations": [],
                "counts": {},
                "error": public_error_message(exc),
            },
        ), 200


@app.route("/operations/<int:operation_id>/revert", methods=["POST"])
def revert_operation(operation_id: int):
    ledger = get_operation_ledger()
    try:
        op = ledger.get_operation(operation_id)
    except Exception:
        op = None
    if (
        op is None
        or op.proxy_id != get_proxy_id()
        or not op.can_revert
        or op.status != "failed"
    ):
        return _redirect_to("operations_status", error="not_revertible")
    if op.rollback_kind == "config_revision":
        revision = None
        try:
            revisions = get_config_revisions()
            active_revision = None
            try:
                active_revision = revisions.get_active_revision(op.proxy_id)
            except Exception:
                active_revision = None

            def restore_active_revision_after_failure() -> None:
                if revision is None:
                    return
                try:
                    restore_if_current = getattr(revisions, "restore_previous_if_current", None)
                    if callable(restore_if_current):
                        restore_if_current(
                            op.proxy_id,
                            revision.revision_id,
                            getattr(active_revision, "revision_id", None),
                        )
                    elif active_revision is not None:
                        revisions.activate_revision(
                            op.proxy_id,
                            active_revision.revision_id,
                        )
                    else:
                        revisions.deactivate_revision(op.proxy_id, revision.revision_id)
                except Exception:
                    log_exception_throttled(
                        app.logger,
                        "web.app.revert_operation_restore_active_revision",
                        interval_seconds=30.0,
                        message="Failed to restore active config revision after revert queue failure",
                    )

            previous = revisions.get_revision(op.rollback_ref, proxy_id=op.proxy_id)
            if previous is None:
                return _redirect_to("operations_status", error="rollback_missing")
            revision = revisions.create_revision(
                op.proxy_id,
                previous.config_text,
                created_by=str(session.get("user") or ""),
                source_kind=f"revert-{op.operation_type}",
                activate=True,
            )
            operation = request_proxy_reconcile(
                op.proxy_id,
                operation_type="revert",
                subject=f"Revert #{op.operation_id}",
                summary=f"Restored config revision {previous.revision_id}; applying asynchronously.",
                target_kind="config_revision",
                target_ref=revision.revision_id,
                rollback_kind="config_revision",
                rollback_ref=op.target_ref,
                request_hash=revision.config_sha256,
                detail=f"Revert queued from failed operation #{op.operation_id}.",
                created_by=str(session.get("user") or ""),
                force=False,
            )
            if (
                not getattr(operation, "operation_id", 0)
                and getattr(operation, "status", "") == "failed"
            ):
                restore_active_revision_after_failure()
                return _redirect_to("operations_status", error="revert_failed")
        except Exception:
            if revision is not None:
                restore_active_revision_after_failure()
            log_exception_throttled(
                app.logger,
                "web.app.revert_operation",
                interval_seconds=30.0,
                message="Failed to queue revert operation",
            )
            return _redirect_to("operations_status", error="revert_failed")
        return _redirect_to("operations_status", reverted="1")
    if op.rollback_kind == "certificate_revision":
        if request.form.get("confirm_global_certificate_revert") != "1":
            return _redirect_to(
                "operations_status",
                error="global_certificate_confirmation_required",
            )
        bundle_store = get_certificate_bundles()
        active_revision = None
        restored_revision = None
        try:
            try:
                active_revision = bundle_store.get_active_bundle()
            except Exception:
                active_revision = None
            rollback_revision = _certificate_revision_by_id(
                bundle_store,
                op.rollback_ref,
            )
            if rollback_revision is None:
                return _redirect_to("operations_status", error="rollback_missing")
            active_revision_id = _safe_revision_id(
                getattr(active_revision, "revision_id", 0),
            )
            active_sha = str(
                getattr(active_revision, "bundle_sha256", "") or "",
            ).strip()
            op_target_ref = str(getattr(op, "target_ref", "") or "").strip()
            op_target_sha = str(getattr(op, "request_hash", "") or "").strip()
            if (
                not active_revision_id
                or not op_target_ref
                or str(active_revision_id) != op_target_ref
                or (op_target_sha and active_sha and active_sha != op_target_sha)
            ):
                return _redirect_to("operations_status", error="rollback_stale")
            restored_revision = bundle_store.activate_revision(op.rollback_ref)

            rollback_ref = ""
            if (
                active_revision is not None
                and getattr(active_revision, "revision_id", None)
                != restored_revision.revision_id
            ):
                rollback_ref = str(active_revision.revision_id)

            proxies = get_proxy_registry().list_proxies()
            queued_count = 0
            failure_detail = ""
            for proxy in proxies:
                try:
                    operation = request_proxy_reconcile(
                        proxy.proxy_id,
                        operation_type="certificate_revert",
                        subject=f"Revert #{op.operation_id}",
                        summary=(
                            "Global certificate bundle revert queued: "
                            f"active CA revision {active_revision_id} "
                            f"({_short_sha(active_sha) or 'unknown hash'}) was replaced with "
                            f"revision {restored_revision.revision_id} "
                            f"({_short_sha(getattr(restored_revision, 'bundle_sha256', '')) or 'unknown hash'}); "
                            f"applying asynchronously to proxy {proxy.proxy_id}."
                        ),
                        target_kind="certificate_revision",
                        target_ref=restored_revision.revision_id,
                        rollback_kind="certificate_revision" if rollback_ref else "",
                        rollback_ref=rollback_ref,
                        request_hash=getattr(restored_revision, "bundle_sha256", ""),
                        detail=(
                            f"Global/shared active CA bundle revert queued from failed operation #{op.operation_id}. "
                            f"Current active revision before revert: {active_revision_id} "
                            f"sha={active_sha or 'unknown'}; rollback target revision: "
                            f"{restored_revision.revision_id} sha="
                            f"{getattr(restored_revision, 'bundle_sha256', '') or 'unknown'}. "
                            "This desired-state change affects every registered proxy, not only the selected proxy."
                        ),
                        created_by=str(session.get("user") or ""),
                        force=True,
                    )
                except Exception as exc:
                    if not failure_detail:
                        failure_detail = public_error_message(exc)
                    continue
                if (
                    getattr(operation, "operation_id", 0)
                    and operation.status == "pending"
                ):
                    queued_count += 1
                elif not failure_detail:
                    failure_detail = str(
                        getattr(operation, "detail", "")
                        or "Certificate bundle reconciliation was not queued.",
                    )

            if proxies and queued_count == 0:
                try:
                    restore_if_current = getattr(bundle_store, "restore_previous_if_current", None)
                    if callable(restore_if_current):
                        restore_if_current(
                            restored_revision.revision_id,
                            getattr(active_revision, "revision_id", None),
                        )
                    elif active_revision is not None:
                        bundle_store.activate_revision(active_revision.revision_id)
                    else:
                        bundle_store.deactivate_revision(restored_revision.revision_id)
                except Exception:
                    log_exception_throttled(
                        app.logger,
                        "web.app.revert_certificate_restore_active_bundle",
                        interval_seconds=30.0,
                        message="Failed to restore active certificate bundle after revert queue failure",
                    )
                if failure_detail:
                    app.logger.warning(
                        "Certificate bundle revert queue failed: %s",
                        failure_detail,
                    )
                return _redirect_to("operations_status", error="revert_failed")
        except Exception:
            if restored_revision is not None:
                try:
                    restore_if_current = getattr(bundle_store, "restore_previous_if_current", None)
                    if callable(restore_if_current):
                        restore_if_current(
                            restored_revision.revision_id,
                            getattr(active_revision, "revision_id", None),
                        )
                    elif active_revision is not None:
                        bundle_store.activate_revision(active_revision.revision_id)
                    else:
                        bundle_store.deactivate_revision(restored_revision.revision_id)
                except Exception:
                    log_exception_throttled(
                        app.logger,
                        "web.app.revert_certificate_restore_active_bundle",
                        interval_seconds=30.0,
                        message="Failed to restore active certificate bundle after revert failure",
                    )
            log_exception_throttled(
                app.logger,
                "web.app.revert_certificate_operation",
                interval_seconds=30.0,
                message="Failed to queue certificate bundle revert operation",
            )
            return _redirect_to("operations_status", error="revert_failed")
        return _redirect_to("operations_status", reverted="1")
    return _redirect_to("operations_status", error="unsupported_rollback")


@app.route("/observability", methods=["GET"])
def observability():
    queries = get_observability_queries()
    pane = _observability_pane_from_request()
    sort = _observability_sort_from_request(pane)
    limit = _query_int_arg("limit", default=50, minimum=10, maximum=200)
    window_i = _query_int_arg(
        "window",
        default=OBSERVABILITY_DEFAULT_WINDOW,
        minimum=300,
        maximum=7 * 24 * 3600,
    )
    since_ts = int(time.time()) - window_i
    search = _observability_search_from_request()
    resolve_hostnames = _observability_resolve_hostnames_from_request()
    privacy = _observability_privacy_from_request()

    try:
        summary = _cached_observability_result(
            _observability_result_cache_key(
                "observability",
                "summary",
                get_proxy_id(),
                window_i,
            ),
            lambda: queries.summary(since=since_ts),
        )
    except Exception:
        log_exception_throttled(
            app.logger,
            "web.app.observability.summary",
            interval_seconds=30.0,
            message="Failed to load observability summary; rendering empty state",
        )
        summary = _empty_observability_summary()
    summary = {
        **_empty_observability_summary(),
        **(summary if isinstance(summary, dict) else {}),
    }

    try:
        pane_payload: dict[str, Any]
        if pane == "overview":
            pane_payload = _cached_observability_result(
                _observability_result_cache_key(
                    "observability",
                    pane,
                    get_proxy_id(),
                    window_i,
                    search,
                    min(limit, 10),
                    int(resolve_hostnames),
                ),
                lambda: queries.overview_bundle(
                    since=since_ts,
                    search=search,
                    limit=min(limit, 10),
                    resolve_hostnames=resolve_hostnames,
                    summary=summary,
                ),
            )
        elif pane == "clients":
            pane_payload = _cached_observability_result(
                _observability_result_cache_key(
                    "observability",
                    pane,
                    get_proxy_id(),
                    window_i,
                    search,
                    limit,
                    sort,
                    int(resolve_hostnames),
                ),
                lambda: {
                    "rows": queries.top_clients(
                        since=since_ts,
                        search=search,
                        limit=limit,
                        sort=sort,
                        resolve_hostnames=resolve_hostnames,
                        total_requests=int(summary.get("request_records") or 0),
                    ),
                },
            )
        elif pane == "cache":
            pane_payload = _cached_observability_result(
                _observability_result_cache_key(
                    "observability",
                    pane,
                    get_proxy_id(),
                    window_i,
                    search,
                    limit,
                    sort,
                ),
                lambda: {
                    "rows": queries.top_cache_reasons(
                        since=since_ts,
                        search=search,
                        limit=limit,
                        sort=sort,
                    ),
                },
            )
        elif pane == "ssl":
            pane_payload = _cached_observability_result(
                _observability_result_cache_key(
                    "observability",
                    pane,
                    get_proxy_id(),
                    window_i,
                    search,
                    limit,
                ),
                lambda: queries.ssl_overview(
                    since=since_ts,
                    search=search,
                    limit=limit,
                ),
            )
        elif pane == "security":
            pane_payload = _cached_observability_result(
                _observability_result_cache_key(
                    "observability",
                    pane,
                    get_proxy_id(),
                    window_i,
                    search,
                    limit,
                ),
                lambda: queries.security_overview(
                    since=since_ts,
                    search=search,
                    limit=limit,
                ),
            )
        elif pane == "performance":
            performance_payload = _cached_observability_result(
                _observability_result_cache_key(
                    "observability",
                    pane,
                    get_proxy_id(),
                    window_i,
                    limit,
                ),
                lambda: queries.performance_overview(
                    since=since_ts,
                    limit=limit,
                    summary=summary,
                ),
            )
            pane_payload = _empty_observability_payload(pane, summary=summary)
            if isinstance(performance_payload, dict):
                pane_payload.update(performance_payload)
        elif pane == "remediation":
            runtime_health = _cached_proxy_health(
                get_proxy_id(),
                timeout_seconds=max(3.0, _proxy_health_timeout_seconds()),
                full=True,
            )
            pane_payload = _cached_observability_result(
                _observability_result_cache_key(
                    "observability",
                    pane,
                    get_proxy_id(),
                    window_i,
                    search,
                    limit,
                    sort,
                    _safe_int(runtime_health.get("timestamp")),
                    runtime_health.get("status") or "",
                    _runtime_health_remediation_cache_fingerprint(runtime_health),
                ),
                lambda: queries.remediation_overview(
                    since=since_ts,
                    search=search,
                    limit=limit,
                    sort=sort,
                    summary=summary,
                    runtime_health=runtime_health,
                ),
            )
        elif pane == "reports":
            pane_payload = _cached_observability_result(
                _observability_result_cache_key(
                    "observability",
                    pane,
                    get_proxy_id(),
                    window_i,
                    search,
                    limit,
                    int(resolve_hostnames),
                    int(privacy),
                ),
                lambda: queries.reporting_overview(
                    since=since_ts,
                    search=search,
                    limit=limit,
                    resolve_hostnames=resolve_hostnames,
                    privacy=privacy,
                    summary=summary,
                ),
            )
        elif pane == "settings":
            pane_payload = {
                "retention_settings": get_observability_retention_settings(),
                "maintenance_status": get_observability_maintenance_status(),
            }
        else:
            pane_payload = _cached_observability_result(
                _observability_result_cache_key(
                    "observability",
                    pane,
                    get_proxy_id(),
                    window_i,
                    search,
                    limit,
                    sort,
                ),
                lambda: {
                    "rows": queries.top_destinations(
                        since=since_ts,
                        search=search,
                        limit=limit,
                        sort=sort,
                        total_requests=int(summary.get("request_records") or 0),
                    ),
                },
            )
    except Exception as exc:
        log_exception_throttled(
            app.logger,
            f"web.app.observability.pane.{pane}",
            interval_seconds=30.0,
            message="Failed to load observability pane; rendering empty state",
        )
        if pane == "remediation":
            pane_payload = _database_remediation_payload(exc, summary=summary)
        else:
            pane_payload = _empty_observability_payload(pane, summary=summary)
    pane_payload = _merge_observability_payload_defaults(
        pane,
        pane_payload,
        summary=summary,
    )
    if pane == "remediation":
        _annotate_observability_remediation_actions(pane_payload)

    return render_template(
        "observability.html",
        pane=pane,
        sort=sort,
        limit=limit,
        window=window_i,
        window_label=_window_label(window_i),
        search=search,
        resolve_hostnames=resolve_hostnames,
        privacy=privacy,
        summary=summary,
        pane_payload=pane_payload,
    )


@app.route("/observability/clear-logs", methods=["POST"])
def observability_clear_logs():
    try:
        result = clear_observability_logs()
        cleared_tables = int(
            result.get("cleared_tables")
            or sum(
                1
                for table in result.get("tables") or []
                if table.get("status") == "cleared"
            ),
        )
        failed_tables = [
            str(table.get("table") or "")
            for table in result.get("tables") or []
            if table.get("status") == "failed"
        ]
        partial_tables = [
            str(table.get("table") or "")
            for table in result.get("tables") or []
            if table.get("status") == "partial"
        ]
        detail = f"cleared stored observability log history from {cleared_tables} tables across the fleet"
        if partial_tables:
            detail += f"; partially cleared tables: {', '.join(partial_tables[:5])}"
        if failed_tables:
            detail += f"; failed tables: {', '.join(failed_tables[:5])}"
        _record_audit_event(
            "observability_clear_logs",
            ok=not failed_tables and bool(result.get("ok", True)),
            detail=detail,
        )
        if failed_tables or partial_tables or not bool(result.get("ok", True)):
            return _redirect_to("observability", pane="overview", clear_error="1")
        return _redirect_to(
            "observability",
            pane="overview",
            logs_cleared="1",
            clear_tables=cleared_tables,
        )
    except Exception as exc:
        detail = public_error_message(exc)
        log_exception_throttled(
            app.logger,
            "web.app.observability.clear_logs",
            interval_seconds=30.0,
            message="Failed to clear stored observability logs",
        )
        _record_audit_event("observability_clear_logs", ok=False, detail=detail)
        return _redirect_to("observability", pane="overview", clear_error="1")


@app.route("/observability/maintenance", methods=["POST"])
def observability_maintenance():
    try:
        result = run_observability_maintenance(
            analyze=True,
            optimize=True,
            run_type="manual",
        )
        maintained_tables = int(
            (result.get("maintenance") or {}).get("maintained_tables")
            or sum(
                1
                for table in (result.get("maintenance") or {}).get("tables") or []
                if table.get("status") == "maintained"
            ),
        )
        days = int(result.get("retention_days") or 30)
        detail = (
            "ran observability MySQL prune, analyze, and optimize "
            f"with {days} day retention; maintained {maintained_tables} tables"
        )
        _record_audit_event(
            "observability_database_maintenance",
            ok=bool(result.get("ok", True)),
            detail=detail,
        )
        if not bool(result.get("ok", True)):
            return _redirect_to(
                "observability",
                pane="settings",
                maintenance_error="1",
            )
        return _redirect_to(
            "observability",
            pane="settings",
            maintenance_run="1",
            retention_days=days,
            maintained_tables=maintained_tables,
        )
    except ObservabilityMaintenanceAlreadyRunningError as exc:
        detail = public_error_message(exc)
        _record_audit_event(
            "observability_database_maintenance",
            ok=False,
            detail=detail,
        )
        return _redirect_to(
            "observability",
            pane="settings",
            maintenance_busy="1",
        )
    except Exception as exc:
        detail = public_error_message(exc)
        log_exception_throttled(
            app.logger,
            "web.app.observability.maintenance",
            interval_seconds=30.0,
            message="Failed to run observability database maintenance",
        )
        _record_audit_event(
            "observability_database_maintenance",
            ok=False,
            detail=detail,
        )
        return _redirect_to("observability", pane="settings", maintenance_error="1")


@app.route("/observability/settings", methods=["POST"])
def observability_settings():
    retention_days = _bounded_int(
        request.form.get("retention_days"),
        default=30,
        minimum=1,
        maximum=3650,
    )
    try:
        settings = set_observability_retention_settings(
            retention_days=retention_days,
        )
        days = int(settings.get("retention_days") or retention_days)
        _record_audit_event(
            "observability_retention_settings_save",
            ok=True,
            detail=f"set observability MySQL retention to {days} days",
        )
        return _redirect_to(
            "observability",
            pane="settings",
            settings_saved="1",
            retention_days=days,
        )
    except Exception as exc:
        detail = public_error_message(exc)
        _record_audit_event(
            "observability_retention_settings_save",
            ok=False,
            detail=detail,
        )
        return _redirect_to("observability", pane="settings", settings_error="1")


@app.route("/observability/report-schedules", methods=["POST"])
def observability_report_schedules():
    queries = get_observability_queries()
    pane = _normalize_choice(request.form.get("pane"), _OBSERVABILITY_PANES, "reports")
    cadence = _normalize_choice(
        request.form.get("cadence"),
        ("daily", "weekly"),
        "daily",
    )
    report_format = _normalize_choice(
        request.form.get("format"),
        ("csv", "json", "jsonl"),
        "csv",
    )
    privacy = str(request.form.get("privacy") or "1").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    enabled = str(request.form.get("enabled") or "1").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    window_i = _bounded_int(
        request.form.get("window"),
        default=OBSERVABILITY_DEFAULT_WINDOW,
        minimum=300,
        maximum=7 * 24 * 3600,
    )
    name = (request.form.get("name") or "").strip()
    recipients = (request.form.get("recipients") or "").strip()
    try:
        schedule = queries.save_report_schedule(
            name=name,
            cadence=cadence,
            recipients=recipients,
            pane=pane,
            report_format=report_format,
            privacy=privacy,
            window_seconds=window_i,
            enabled=enabled,
        )
        _OBSERVABILITY_RESULT_CACHE.clear()
        detail = (
            f"saved {cadence} {pane} observability report preset for {recipients[:160]}"
        )
        _record_audit_event(
            "observability_report_schedule_save",
            ok=True,
            detail=detail,
        )
        return _redirect_to(
            "observability",
            pane="reports",
            window=window_i,
            privacy=_query_flag(privacy),
            schedule_saved="1",
            schedule_id=schedule.get("id", ""),
        )
    except Exception as exc:
        detail = public_error_message(exc)
        _record_audit_event(
            "observability_report_schedule_save",
            ok=False,
            detail=detail,
        )
        return _redirect_to(
            "observability",
            pane="reports",
            window=window_i,
            privacy=_query_flag(privacy),
            schedule_error="1",
        )


@app.route("/observability/export", methods=["GET"])
def observability_export():
    queries = get_observability_queries()
    pane = _observability_pane_from_request()
    sort = _observability_sort_from_request(pane)
    limit = _query_int_arg("limit", default=200, minimum=10, maximum=1000)
    window_i = _query_int_arg(
        "window",
        default=OBSERVABILITY_DEFAULT_WINDOW,
        minimum=300,
        maximum=7 * 24 * 3600,
    )
    since_ts = int(time.time()) - window_i
    search = _observability_search_from_request()
    resolve_hostnames = _observability_resolve_hostnames_from_request()
    privacy = _observability_privacy_from_request()
    export_format = _observability_export_format_from_request()
    summary_data: dict[str, Any] | None = None
    total_requests = 0
    try:
        if pane in {"overview", "clients", "destinations", "performance", "reports"}:
            summary_data = _cached_observability_result(
                _observability_result_cache_key(
                    "observability",
                    "summary",
                    get_proxy_id(),
                    window_i,
                ),
                lambda: queries.summary(since=since_ts),
            )
            total_requests = int(summary_data.get("request_records") or 0)
        if pane == "overview":
            overview = queries.overview_bundle(
                since=since_ts,
                search=search,
                limit=min(limit, 10),
                resolve_hostnames=resolve_hostnames,
                summary=summary_data or {},
            )
            summary = overview["summary"]
            headers = ["metric", "value"]
            data_rows = (
                [metric, summary.get(metric, 0)]
                for metric in (
                    "request_records",
                    "cache_hits",
                    "cache_misses",
                    "cache_hit_pct",
                    "clients",
                    "destinations",
                    "transactions",
                    "icap_events",
                    "av_icap_events",
                    "adblock_icap_events",
                )
            )
            return _observability_export_response(headers, data_rows, export_format)

        if pane == "reports":
            payload = queries.reporting_overview(
                since=since_ts,
                search=search,
                limit=limit,
                resolve_hostnames=resolve_hostnames,
                privacy=privacy,
                summary=summary_data or {},
            )
            if privacy:
                payload = _observability_reports_privacy_payload(payload)
            if export_format == "json":
                return _json_response(payload)
            if export_format == "jsonl":
                rows = [
                    {"section": "top_users", **row}
                    for row in payload.get("top_users", [])
                ]
                rows.extend(
                    {"section": "top_blocked_categories", **row}
                    for row in payload.get("top_blocked_categories", [])
                )
                rows.extend(
                    {"section": "top_malware_attempts", **row}
                    for row in payload.get("top_malware_attempts", [])
                )
                rows.extend(
                    {"section": "top_ssl_bump_failures", **row}
                    for row in payload.get("top_ssl_bump_failures", [])
                )
                rows.extend(
                    {"section": "top_spliced_destinations", **row}
                    for row in payload.get("top_spliced_destinations", [])
                )
                rows.extend(
                    {"section": "per_group", **row}
                    for row in payload.get("per_group", [])
                )
                rows.extend(
                    {"section": "audit_recent", **row}
                    for row in (payload.get("audit") or {}).get("recent", [])
                )
                return _jsonl_response(rows)
            headers = _OBSERVABILITY_EMPTY_EXPORT_HEADERS["reports"]
            rows = []
            for row in payload.get("top_users", []):
                rows.append(
                    [
                        "top_users",
                        row.get("client_label") or row.get("client_ip", ""),
                        row.get("requests", 0),
                        "",
                        row.get("destinations", 0),
                        row.get("bytes", 0),
                        row.get("cache_hit_bytes", 0),
                        row.get("last_seen", 0),
                        row.get("hostname", ""),
                    ],
                )
            for row in payload.get("top_blocked_categories", []):
                rows.append(
                    [
                        "top_blocked_categories",
                        row.get("category", ""),
                        row.get("blocks", 0),
                        "",
                        "",
                        "",
                        "",
                        row.get("last_seen", 0),
                        "webfilter",
                    ],
                )
            for row in payload.get("top_malware_attempts", []):
                rows.append(
                    [
                        "top_malware_attempts",
                        row.get("domain", ""),
                        row.get("attempts", 0),
                        row.get("client_label", ""),
                        "",
                        "",
                        "",
                        row.get("last_seen", 0),
                        row.get("sample", ""),
                    ],
                )
            for row in payload.get("top_ssl_bump_failures", []):
                rows.append(
                    [
                        "top_ssl_bump_failures",
                        row.get("domain", ""),
                        row.get("count", 0),
                        "",
                        "",
                        "",
                        "",
                        row.get("last_seen", 0),
                        row.get("reason", ""),
                    ],
                )
            for row in payload.get("top_spliced_destinations", []):
                rows.append(
                    [
                        "top_spliced_destinations",
                        row.get("domain", ""),
                        row.get("requests", 0),
                        row.get("clients", 0),
                        "",
                        row.get("bytes", 0),
                        "",
                        row.get("last_seen", 0),
                        "splice",
                    ],
                )
            for row in payload.get("per_group", []):
                rows.append(
                    [
                        "per_group",
                        row.get("group", ""),
                        row.get("requests", 0),
                        row.get("clients", 0),
                        row.get("destinations", 0),
                        row.get("bytes", 0),
                        row.get("cache_hit_bytes", 0),
                        row.get("last_seen", 0),
                        row.get("group_source", ""),
                    ],
                )
            for row in (payload.get("audit") or {}).get("recent", []):
                rows.append(
                    [
                        "audit_recent",
                        row.get("kind", ""),
                        1,
                        "",
                        "",
                        "",
                        "",
                        row.get("ts", 0),
                        row.get("detail", ""),
                    ],
                )
            return _observability_export_response(headers, rows, export_format)

        if pane == "clients":
            rows = queries.top_clients(
                since=since_ts,
                search=search,
                limit=limit,
                sort=sort,
                resolve_hostnames=resolve_hostnames,
                total_requests=total_requests,
            )
            headers = [
                "client_ip",
                "hostname",
                "requests",
                "percent_of_total",
                "destinations",
                "transactions",
                "cache_hit_pct",
                "av_icap_events",
                "adblock_icap_events",
                "last_seen",
            ]
            data_rows = (
                [
                    pseudonymize(row.get("ip", ""), namespace="user")
                    if privacy
                    else row.get("ip", ""),
                    "" if privacy else row.get("hostname", ""),
                    row.get("requests", 0),
                    row.get("pct", 0.0),
                    row.get("destinations", 0),
                    row.get("transactions", 0),
                    row.get("cache_pct", 0.0),
                    row.get("av_icap_events", 0),
                    row.get("adblock_icap_events", 0),
                    row.get("last_seen", 0),
                ]
                for row in rows
            )
            return _observability_export_response(headers, data_rows, export_format)

        if pane == "cache":
            rows = queries.top_cache_reasons(
                since=since_ts,
                search=search,
                limit=limit,
                sort=sort,
            )
            headers = [
                "reason",
                "requests",
                "percent_of_misses",
                "domains",
                "clients",
                "last_seen",
            ]
            data_rows = (
                [
                    row.get("reason", ""),
                    row.get("requests", 0),
                    row.get("pct", 0.0),
                    row.get("domains", 0),
                    row.get("clients", 0),
                    row.get("last_seen", 0),
                ]
                for row in rows
            )
            return _observability_export_response(headers, data_rows, export_format)

        if pane == "ssl":
            payload = queries.ssl_overview(since=since_ts, search=search, limit=limit)
            rows = payload["rows"]
            headers = [
                "domain",
                "category",
                "category_label",
                "reason",
                "count",
                "first_seen",
                "last_seen",
            ]
            data_rows = (
                [
                    row.get("domain", ""),
                    row.get("category", ""),
                    row.get("category_label", ""),
                    row.get("reason", ""),
                    row.get("count", 0),
                    row.get("first_seen", 0),
                    row.get("last_seen", 0),
                ]
                for row in rows
            )
            return _observability_export_response(headers, data_rows, export_format)

        if pane == "security":
            payload = queries.security_overview(
                since=since_ts,
                search=search,
                limit=limit,
            )
            headers = ["source", "timestamp", "client", "target", "detail", "status"]
            rows = []
            for row in payload.get("av_rows", []):
                rows.append(
                    [
                        "av",
                        row.get("ts", 0),
                        pseudonymize(
                            row.get("client_ip", ""),
                            namespace="user",
                        )
                        if privacy
                        else row.get("client_ip", ""),
                        row.get("target_display", ""),
                        row.get("adapt_summary", ""),
                        row.get("av_status_label", ""),
                    ],
                )
            for row in payload.get("adblock_rows", []):
                rows.append(
                    [
                        "adblock",
                        row.get("ts", 0),
                        pseudonymize(
                            row.get("src_ip", ""),
                            namespace="user",
                        )
                        if privacy
                        else row.get("src_ip", ""),
                        row.get("url", ""),
                        f"HTTP {row.get('http_status', 0)}",
                        row.get("result", ""),
                    ],
                )
            for row in payload.get("webfilter_rows", []):
                rows.append(
                    [
                        "webfilter",
                        row.get("ts", 0),
                        pseudonymize(
                            row.get("src_ip", ""),
                            namespace="user",
                        )
                        if privacy
                        else row.get("src_ip", ""),
                        row.get("url", ""),
                        row.get("category", ""),
                        row.get("result", ""),
                    ],
                )
            return _observability_export_response(headers, rows, export_format)

        if pane == "remediation":
            try:
                runtime_health = _cached_proxy_health(
                    get_proxy_id(),
                    timeout_seconds=max(3.0, _proxy_health_timeout_seconds()),
                    full=True,
                )
            except Exception:
                runtime_health = {}
            payload = queries.remediation_overview(
                since=since_ts,
                search=search,
                limit=limit,
                sort=sort,
                summary=summary_data or {},
                runtime_health=runtime_health,
            )
            headers = _OBSERVABILITY_EMPTY_EXPORT_HEADERS["remediation"]
            rows = [
                [
                    row.get("severity", ""),
                    row.get("component", ""),
                    row.get("title", ""),
                    row.get("subject", ""),
                    row.get("count", 0),
                    row.get("confidence", ""),
                    row.get("last_seen", 0),
                    row.get("recommended_action", ""),
                    row.get("evidence", ""),
                ]
                for row in payload.get("rows", [])
            ]
            return _observability_export_response(headers, rows, export_format)

        if pane == "performance":
            payload = queries.performance_overview(
                since=since_ts,
                limit=limit,
                summary=summary_data or {},
            )
            headers = ["type", "timestamp", "subject", "metric", "detail"]
            rows = []
            for row in payload.get("slow_requests", []):
                rows.append(
                    [
                        "request",
                        row.get("ts", 0),
                        row.get("target_display", ""),
                        row.get("duration_ms", 0),
                        row.get("result_summary", ""),
                    ],
                )
            for row in payload.get("slow_icap_events", []):
                rows.append(
                    [
                        "icap",
                        row.get("ts", 0),
                        row.get("target_display", ""),
                        row.get("icap_time_ms", 0),
                        row.get("adapt_summary", ""),
                    ],
                )
            return _observability_export_response(headers, rows, export_format)

        rows = queries.top_destinations(
            since=since_ts,
            search=search,
            limit=limit,
            sort=sort,
            total_requests=total_requests,
        )
        headers = [
            "domain",
            "requests",
            "percent_of_total",
            "clients",
            "transactions",
            "cache_hit_pct",
            "av_icap_events",
            "adblock_icap_events",
            "last_seen",
        ]
        data_rows = (
            [
                row.get("domain", ""),
                row.get("requests", 0),
                row.get("pct", 0.0),
                row.get("clients", 0),
                row.get("transactions", 0),
                row.get("cache_pct", 0.0),
                row.get("av_icap_events", 0),
                row.get("adblock_icap_events", 0),
                row.get("last_seen", 0),
            ]
            for row in rows
        )
        return _observability_export_response(headers, data_rows, export_format)
    except Exception:
        log_exception_throttled(
            app.logger,
            f"web.app.observability.export.{pane}",
            interval_seconds=30.0,
            message="Failed to export observability pane; returning empty CSV",
        )
        return _empty_observability_export_response(pane, export_format)


def _observability_metrics_response():
    queries = get_observability_queries()
    window_i = _query_int_arg(
        "window",
        default=OBSERVABILITY_DEFAULT_WINDOW,
        minimum=300,
        maximum=7 * 24 * 3600,
    )
    since_ts = int(time.time()) - window_i
    proxy_id = get_proxy_id()
    lines = [
        "# HELP docker_proxy_observability_window_seconds Observability scrape query window.",
        "# TYPE docker_proxy_observability_window_seconds gauge",
        f'docker_proxy_observability_window_seconds{{proxy_id="{_prom_label(proxy_id)}"}} {window_i}',
    ]
    emitted_metric_meta: set[str] = {"docker_proxy_observability_window_seconds"}
    scrape_errors: list[str] = []

    def emit(
        name: str,
        help_text: str,
        value: object,
        labels: dict[str, object] | None = None,
    ) -> None:
        metric_labels = {"proxy_id": proxy_id, **(labels or {})}
        label_text = ",".join(
            f'{key}="{_prom_label(value)}"' for key, value in metric_labels.items()
        )
        if name not in emitted_metric_meta:
            lines.extend([f"# HELP {name} {help_text}", f"# TYPE {name} gauge"])
            emitted_metric_meta.add(name)
        lines.append(f"{name}{{{label_text}}} {_prom_value(value)}")

    def collect(name: str, callback: Callable[[], Any]) -> Any:
        try:
            return callback()
        except Exception:
            scrape_errors.append(name)
            log_exception_throttled(
                app.logger,
                f"web.app.observability.metrics.{name}",
                interval_seconds=30.0,
                message=f"Failed to collect observability metrics section: {name}",
            )
            return None

    summary = collect(
        "summary",
        lambda: _cached_observability_result(
            _observability_result_cache_key(
                "observability",
                "metrics",
                "summary",
                proxy_id,
                window_i,
            ),
            lambda: queries.summary(since=since_ts),
        ),
    )
    if isinstance(summary, dict):
        emit(
            "docker_proxy_observability_requests",
            "Requests observed in the selected window.",
            summary.get("request_records"),
        )
        emit(
            "docker_proxy_observability_clients",
            "Distinct clients observed in the selected window.",
            summary.get("clients"),
        )
        emit(
            "docker_proxy_observability_destinations",
            "Distinct destinations observed in the selected window.",
            summary.get("destinations"),
        )
        emit(
            "docker_proxy_observability_transactions",
            "Distinct transactions observed in the selected window.",
            summary.get("transactions"),
        )
        emit(
            "docker_proxy_observability_cache_hits",
            "Cache hit requests observed in the selected window.",
            summary.get("cache_hits"),
        )
        emit(
            "docker_proxy_observability_cache_misses",
            "Cache miss requests observed in the selected window.",
            summary.get("cache_misses"),
        )
        emit(
            "docker_proxy_observability_cache_hit_ratio",
            "Cache hit ratio in the selected window.",
            _ratio_from_percent(summary.get("cache_hit_pct")),
        )

    performance_summary_input = None
    if isinstance(summary, dict):
        performance_summary_input = {
            **summary,
            "requests": summary.get("requests", summary.get("request_records")),
            "domains": summary.get("domains", summary.get("destinations")),
        }

    cache = collect(
        "cache",
        lambda: _cached_observability_result(
            _observability_result_cache_key(
                "observability",
                "metrics",
                "cache",
                proxy_id,
                window_i,
            ),
            lambda: queries.cache_savings(since=since_ts),
        ),
    )
    if isinstance(cache, dict):
        emit(
            "docker_proxy_observability_cache_total_bytes",
            "Total response bytes observed in the selected window.",
            cache.get("total_bytes"),
        )
        emit(
            "docker_proxy_observability_cache_hit_bytes",
            "Cache hit response bytes observed in the selected window.",
            cache.get("hit_bytes"),
        )
        emit(
            "docker_proxy_observability_cache_miss_bytes",
            "Cache miss response bytes observed in the selected window.",
            cache.get("miss_bytes"),
        )
        emit(
            "docker_proxy_observability_cache_saved_bytes",
            "Estimated cache-served response bytes in the selected window.",
            cache.get("estimated_saved_bytes"),
        )

    performance = collect(
        "performance",
        lambda: _cached_observability_result(
            _observability_result_cache_key(
                "observability",
                "metrics",
                "performance",
                proxy_id,
                window_i,
            ),
            lambda: queries.performance_overview(
                since=since_ts,
                limit=8,
                summary=performance_summary_input,
            ),
        ),
    )
    if isinstance(performance, dict):
        performance_summary = performance.get("summary") or {}
        for key, metric_name, help_text in [
            (
                "requests",
                "docker_proxy_observability_performance_requests",
                "Requests included in the performance overview.",
            ),
            (
                "transactions",
                "docker_proxy_observability_performance_transactions",
                "Transactions included in the performance overview.",
            ),
            (
                "icap_events",
                "docker_proxy_observability_performance_icap_events",
                "ICAP events included in the performance overview.",
            ),
        ]:
            emit(metric_name, help_text, performance_summary.get(key))

        for service, payload in [
            ("av", performance.get("av_icap_summary") or {}),
            ("adblock", performance.get("adblock_icap_summary") or {}),
        ]:
            emit(
                "docker_proxy_observability_icap_events",
                "ICAP events observed by service in the selected window.",
                payload.get("events"),
                {"service": service},
            )
            emit(
                "docker_proxy_observability_icap_avg_time_ms",
                "Average ICAP adaptation time by service in the selected window.",
                payload.get("avg_icap_time_ms"),
                {"service": service},
            )
            emit(
                "docker_proxy_observability_icap_max_time_ms",
                "Maximum ICAP adaptation time by service in the selected window.",
                payload.get("max_icap_time_ms"),
                {"service": service},
            )

        slow_requests = performance.get("slow_requests") or []
        if slow_requests:
            emit(
                "docker_proxy_observability_slowest_http_request_duration_ms",
                "Slowest observed HTTP request duration in the selected window.",
                slow_requests[0].get("duration_ms"),
            )
        slow_icap_events = performance.get("slow_icap_events") or []
        if slow_icap_events:
            emit(
                "docker_proxy_observability_slowest_icap_time_ms",
                "Slowest observed ICAP adaptation time in the selected window.",
                slow_icap_events[0].get("icap_time_ms"),
                {"service": slow_icap_events[0].get("service_family") or "unknown"},
            )

        for dimension, rows in [
            ("user_agent", performance.get("top_user_agents") or []),
            ("bump_mode", performance.get("top_bump_modes") or []),
            ("tls_server_version", performance.get("top_tls_server_versions") or []),
            ("policy_tag", performance.get("top_policy_tags") or []),
        ]:
            for rank, row in enumerate(rows[:5], start=1):
                emit(
                    "docker_proxy_observability_top_dimension_count",
                    "Top bounded performance dimensions in the selected window.",
                    row.get("count"),
                    {
                        "dimension": dimension,
                        "rank": rank,
                        "value": row.get("label") or row.get("full_label") or "",
                    },
                )

    security = collect(
        "security",
        lambda: _cached_observability_result(
            _observability_result_cache_key(
                "observability",
                "metrics",
                "security",
                proxy_id,
                window_i,
            ),
            lambda: queries.security_overview(since=since_ts, limit=10),
        ),
    )
    if isinstance(security, dict):
        security_summary = security.get("summary") or {}
        emit(
            "docker_proxy_observability_security_blocks",
            "Enforcement block events in the selected window.",
            security_summary.get("combined_blocks"),
        )
        emit(
            "docker_proxy_observability_malware_attempts",
            "Potential AV findings in the selected window.",
            security_summary.get("potential_findings"),
        )

    lines.extend(
        [
            "# HELP docker_proxy_observability_scrape_error Observability metrics collector failures in the selected window.",
            "# TYPE docker_proxy_observability_scrape_error gauge",
        ],
    )
    if scrape_errors:
        lines.extend(
            f'docker_proxy_observability_scrape_error{{proxy_id="{_prom_label(proxy_id)}",section="{_prom_label(section)}"}} 1'
            for section in scrape_errors
        )
    else:
        lines.append(
            f'docker_proxy_observability_scrape_error{{proxy_id="{_prom_label(proxy_id)}",section="none"}} 0',
        )

    return app.response_class(
        "\n".join(lines) + "\n",
        mimetype="text/plain; version=0.0.4; charset=utf-8",
    )


@app.route("/observability/metrics", methods=["GET"])
def observability_metrics():
    return _observability_metrics_response()


@app.route("/performance", methods=["GET"])
def performance_metrics():
    return _observability_metrics_response()


def _prom_label(value: object) -> str:
    return (
        str(value or "")
        .replace("\\", "\\\\")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace('"', '\\"')
    )


def _prom_value(value: object) -> str:
    try:
        number = float(value or 0)
    except (TypeError, ValueError):
        number = 0.0
    if not math.isfinite(number) or number < 0:
        number = 0.0
    if number.is_integer():
        return str(int(number))
    return f"{number:.6g}"


def _ratio_from_percent(value: object) -> float:
    try:
        number = float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0
    if not math.isfinite(number) or number <= 0:
        return 0.0
    if number > 1:
        return min(number / 100.0, 1.0)
    return number


_OBSERVABILITY_NO_BUMP_DOMAIN_REMEDIATION_KINDS = {
    "aborted_media_segments",
    "cloudflare_challenge",
    "ssl_exclusion_candidate",
}


def _annotate_observability_remediation_actions(payload: dict[str, Any]) -> None:
    rows = payload.get("rows")
    if not isinstance(rows, list):
        return
    for row in rows:
        if not isinstance(row, dict):
            continue
        domain = _extract_domain(row.get("subject"))
        ok, _detail, canonical = validate_domain_rule(domain)
        row["no_bump_domain"] = canonical if ok else ""
        row["no_bump_domain_action"] = (
            bool(row.get("subject"))
            and (row.get("subject_type") or "domain") == "domain"
            and row.get("kind") in _OBSERVABILITY_NO_BUMP_DOMAIN_REMEDIATION_KINDS
            and ok
        )


@app.route("/requests", methods=["GET", "POST"])
def policy_requests():
    store = get_policy_request_store()
    _best_effort_init_store(store, key="policy_requests", description="policy request")
    proxy_id = get_proxy_id()
    if request.method == "POST":
        action = _form_action(lower=True)
        reviewer = str(session.get("user") or "")
        try:
            if action == "approve":
                duration = _bounded_int(
                    request.form.get("duration_seconds"),
                    default=POLICY_EXCEPTION_DEFAULT_DURATION_SECONDS,
                    minimum=POLICY_EXCEPTION_MIN_DURATION_SECONDS,
                    maximum=POLICY_EXCEPTION_MAX_DURATION_SECONDS,
                )
                indefinite = request.form.get("duration_mode") == "indefinite"
                store.approve_request(
                    int(request.form.get("request_id") or "0"),
                    reviewer=reviewer,
                    admin_note=request.form.get("admin_note") or "",
                    duration_seconds=duration,
                    indefinite=indefinite,
                    proxy_id=proxy_id,
                )
                refresh_ok, refresh_detail = _best_effort_refresh_managed_policy(
                    store,
                    force=True,
                )
                if not refresh_ok:
                    return _redirect_to(
                        "policy_requests",
                        error=_policy_refresh_failure_detail(refresh_detail),
                    )
                return _redirect_to(
                    "policy_requests",
                    ok=(
                        f"approved; {refresh_detail}" if refresh_detail else "approved"
                    ),
                )
            if action in {"reject", "close"}:
                store.close_request(
                    int(request.form.get("request_id") or "0"),
                    reviewer=reviewer,
                    admin_note=request.form.get("admin_note") or "",
                    status=("closed" if action == "close" else "rejected"),
                    proxy_id=proxy_id,
                )
                return _redirect_to("policy_requests", ok=action)
            if action == "revoke":
                store.revoke_exception(
                    int(request.form.get("exception_id") or "0"),
                    revoked_by=reviewer,
                    admin_note=request.form.get("admin_note") or "",
                    proxy_id=proxy_id,
                )
                refresh_ok, refresh_detail = _best_effort_refresh_managed_policy(
                    store,
                    force=True,
                )
                if not refresh_ok:
                    return _redirect_to(
                        "policy_requests",
                        error=_policy_refresh_failure_detail(refresh_detail),
                    )
                return _redirect_to(
                    "policy_requests",
                    ok=(f"revoked; {refresh_detail}" if refresh_detail else "revoked"),
                )
        except Exception as exc:
            return _redirect_to("policy_requests", error=public_error_message(exc))
        return _redirect_to("policy_requests")
    try:
        pending_requests = store.list_requests(
            statuses=["pending"],
            limit=200,
            proxy_id=proxy_id,
        )
        recent_requests = store.list_requests(limit=200, proxy_id=proxy_id)
        exceptions = store.list_exceptions(
            include_inactive=True,
            limit=200,
            proxy_id=proxy_id,
        )
    except Exception:
        log_exception_throttled(
            app.logger,
            "web.app.policy_requests.list",
            interval_seconds=30.0,
            message="Failed to load policy requests; rendering empty state",
        )
        pending_requests = []
        recent_requests = []
        exceptions = []
    return render_template(
        "requests.html",
        pending_requests=pending_requests,
        recent_requests=recent_requests,
        exceptions=exceptions,
        message=request.args.get("ok") or "",
        error=request.args.get("error") or "",
    )


@app.route("/ssl-errors", methods=["GET"])
def ssl_errors():
    return _redirect_to(
        "observability",
        pane="ssl",
        window=_query_int_arg(
            "window",
            default=OBSERVABILITY_DEFAULT_WINDOW,
            minimum=300,
            maximum=90 * 24 * 3600,
        ),
        limit=_query_int_arg("limit", default=50, minimum=10, maximum=200),
        q=((request.args.get("q") or "").strip().lower() or None),
    )


@app.route("/ssl-errors/exclude", methods=["POST"])
def ssl_errors_exclude():
    domain = _extract_domain(request.form.get("domain"))
    if not domain:
        return _redirect_to("observability", pane="ssl", q=domain)
    store = get_sslfilter_store()
    try:
        ok, detail, canonical = store.add_domain("nobump", domain)
    except Exception as exc:
        log_exception_throttled(
            app.logger,
            "web.app.ssl_errors_exclude",
            interval_seconds=30.0,
            message="Failed to add SSL error exclusion",
        )
        return _redirect_to(
            "observability",
            pane="ssl",
            q=domain,
            error="1",
            msg=public_error_message(exc, default="SSL exclusion was not saved."),
        )
    if ok:
        return _redirect_after_policy_refresh(
            "observability",
            store,
            force=True,
            pane="ssl",
            q=(canonical or domain),
        )
    return _redirect_to(
        "observability",
        pane="ssl",
        q=domain,
        error="1",
        msg=detail or "SSL exclusion was not saved.",
    )


@app.route("/observability/remediation/no-bump-domain", methods=["POST"])
def observability_remediation_no_bump_domain():
    domain = _extract_domain(request.form.get("domain"))
    redirect_params = {
        "pane": "remediation",
        "window": _bounded_int(
            request.form.get("window"),
            default=OBSERVABILITY_DEFAULT_WINDOW,
            minimum=300,
            maximum=7 * 24 * 3600,
        ),
        "limit": _bounded_int(
            request.form.get("limit"),
            default=50,
            minimum=10,
            maximum=200,
        ),
        "sort": _normalize_choice(
            request.form.get("sort"),
            _OBSERVABILITY_SORT_OPTIONS["remediation"],
            _OBSERVABILITY_SORT_DEFAULTS["remediation"],
        ),
        "q": ((request.form.get("q") or "").strip() or None),
    }
    if not domain:
        _record_audit_event(
            "observability_remediation_no_bump_domain",
            ok=False,
            detail="domain=",
        )
        return _redirect_to(
            "observability",
            **redirect_params,
            remediation_error="1",
            remediation_msg="A valid domain is required for no-bump remediation.",
        )

    store = get_sslfilter_store()
    try:
        ok, detail, canonical = store.add_domain("nobump", domain)
    except Exception as exc:
        detail = public_error_message(exc, default="No-bump domain was not saved.")
        _record_audit_event(
            "observability_remediation_no_bump_domain",
            ok=False,
            detail=_audit_safe_detail(f"domain={domain} detail={detail}"),
        )
        log_exception_throttled(
            app.logger,
            "web.app.observability_remediation_no_bump_domain",
            interval_seconds=30.0,
            message="Failed to add remediation no-bump domain",
        )
        return _redirect_to(
            "observability",
            **redirect_params,
            remediation_error="1",
            remediation_msg=detail,
        )

    saved_domain = canonical or domain
    if ok:
        refresh_ok, refresh_detail = _trigger_policy_sync(force=True)
        if not refresh_ok:
            partial_detail = (
                "No-bump domain was saved, but proxy reconciliation was not queued."
            )
            if refresh_detail:
                partial_detail = f"{partial_detail} {refresh_detail}"
            _record_audit_event(
                "observability_remediation_no_bump_domain",
                ok=False,
                detail=_audit_safe_detail(
                    f"domain={saved_domain} detail={partial_detail}",
                ),
            )
            return _redirect_to(
                "observability",
                **redirect_params,
                remediation_error="1",
                remediation_domain=saved_domain,
                remediation_msg=partial_detail,
            )
        _record_audit_event(
            "observability_remediation_no_bump_domain",
            ok=True,
            detail=_audit_safe_detail(
                f"domain={saved_domain} detail={detail or 'saved'}",
            ),
        )
        return _redirect_to(
            "observability",
            **redirect_params,
            remediation_ok="1",
            remediation_domain=saved_domain,
            remediation_msg=f"No-bump SSL exclusion saved for {saved_domain}.",
        )
    _record_audit_event(
        "observability_remediation_no_bump_domain",
        ok=False,
        detail=_audit_safe_detail(
            f"domain={saved_domain} detail={detail or 'not saved'}",
        ),
    )
    return _redirect_to(
        "observability",
        **redirect_params,
        remediation_error="1",
        remediation_msg=detail or "No-bump domain was not saved.",
    )


@app.route("/ssl-errors/export", methods=["GET"])
def ssl_errors_export():
    return _redirect_to(
        "observability_export",
        pane="ssl",
        window=_query_int_arg(
            "window",
            default=OBSERVABILITY_DEFAULT_WINDOW,
            minimum=300,
            maximum=90 * 24 * 3600,
        ),
        limit=_query_int_arg("limit", default=1000, minimum=10, maximum=1000),
        q=((request.args.get("q") or "").strip().lower() or None),
    )


@app.route("/adblock", methods=["GET", "POST"])
def adblock():
    store = get_adblock_store()
    _best_effort_init_store(store, key="adblock", description="adblock")

    if request.method == "POST":
        try:
            return _handle_adblock_post(store)
        except Exception as exc:
            log_exception_throttled(
                app.logger,
                "web.app.adblock.post",
                interval_seconds=30.0,
                message="Failed to process adblock admin action",
            )
            return _redirect_to("adblock", error="1", msg=public_error_message(exc))

    try:
        statuses = store.list_statuses()
    except Exception:
        log_exception_throttled(
            app.logger,
            "web.app.adblock.statuses",
            interval_seconds=30.0,
            message="Failed to load adblock list statuses; rendering empty state",
        )
        statuses = []
    try:
        settings = store.get_settings()
    except Exception:
        settings = {"enabled": True, "cache_ttl": 3600, "cache_max": 200000}
    try:
        stats = store.stats()
    except Exception:
        stats = {"total": 0, "last_24h": 0, "by_list": {}, "by_list_24h": {}}
    try:
        interval = store.get_update_interval_seconds()
    except Exception:
        interval = 6 * 60 * 60
    window_i = _query_int_arg(
        "window",
        default=3600,
        minimum=300,
        maximum=7 * 24 * 3600,
    )
    since_ts = int(time.time()) - window_i
    now_ts = int(time.time())
    status_rows = []
    for st in statuses:
        next_refresh = (
            now_ts
            if not st.enabled
            else (st.last_success + interval if st.last_success > 0 else now_ts)
        )
        last_failure_ts = st.last_attempt if st.last_error else 0
        status_rows.append(
            {
                "key": st.key,
                "url": st.url,
                "enabled": st.enabled,
                "rules": st.rules,
                "bytes": st.bytes,
                "last_success": st.last_success,
                "last_attempt": st.last_attempt,
                "last_error": st.last_error,
                "last_failure_ts": last_failure_ts,
                "next_refresh": next_refresh,
            },
        )

    try:
        adblock_icap_summary = get_diagnostic_store().icap_summary(
            since=since_ts,
            service="adblock",
        )
    except Exception:
        adblock_icap_summary = {
            "events": 0,
            "avg_icap_time_ms": 0,
            "max_icap_time_ms": 0,
        }

    try:
        active_artifact = _present_adblock_artifact_summary(
            get_adblock_artifacts().get_active_artifact_summary(),
        )
    except Exception:
        log_exception_throttled(
            app.logger,
            "web.app.adblock.artifact_summary",
            interval_seconds=30.0,
            message="Failed to load adblock artifact summary; rendering unavailable state",
        )
        active_artifact = _present_adblock_artifact_summary(None)
    artifact_build = _present_adblock_build_state(
        store,
        active_artifact=active_artifact,
        statuses=status_rows,
        settings=settings,
    )
    adblock_runtime_state = _adblock_runtime_state(
        get_proxy_id(),
        active_artifact=active_artifact,
    )

    return render_template(
        "adblock.html",
        statuses=status_rows,
        stats=stats,
        settings=settings,
        update_interval_seconds=interval,
        refresh_requested=(request.args.get("refresh_requested") == "1"),
        refresh_no_lists=(request.args.get("refresh_no_lists") == "1"),
        window=window_i,
        window_label=_window_label(window_i),
        adblock_icap_summary=adblock_icap_summary,
        active_artifact=active_artifact,
        artifact_build=artifact_build,
        adblock_runtime_state=adblock_runtime_state,
    )


@app.route("/webfilter", methods=["GET", "POST"])
def webfilter():
    store = get_webfilter_store()
    _best_effort_init_store(store, key="webfilter", description="web filter")

    tab = _normalize_choice(
        request.args.get("tab") or request.form.get("tab") or "categories",
        ("categories", "whitelist"),
        "categories",
    )

    if request.method == "POST":
        try:
            return _handle_webfilter_post(store, tab)
        except Exception as exc:
            log_exception_throttled(
                app.logger,
                "web.app.webfilter.post",
                interval_seconds=30.0,
                message="Failed to process webfilter admin action",
            )
            return _redirect_to(
                "webfilter",
                tab=tab,
                err=public_error_message(exc),
            )

    try:
        settings = store.get_settings()
    except Exception:
        log_exception_throttled(
            app.logger,
            "web.app.webfilter.settings",
            interval_seconds=30.0,
            message="Failed to load webfilter settings; rendering empty state",
        )
        settings = {"enabled": False, "source_url": "", "blocked_categories": []}
    try:
        safe_browsing_status = store.safe_browsing_status()
    except Exception:
        safe_browsing_status = None
    try:
        available = _normalize_webfilter_categories(store.list_available_categories())
    except Exception:
        available = []
    raw_selected = getattr(settings, "blocked_categories", None) or (
        settings.get("blocked_categories", []) if isinstance(settings, dict) else []
    )
    selected = {
        normalized
        for normalized in (
            _normalize_webfilter_category_name(category)
            for category in (raw_selected or [])
        )
        if normalized
    }
    try:
        whitelist_rows = store.list_whitelist()
    except Exception:
        whitelist_rows = []
    window_i = _query_int_arg(
        "window",
        default=3600,
        minimum=300,
        maximum=7 * 24 * 3600,
    )
    policy_runtime_state = _policy_runtime_state(get_proxy_id())
    return render_template(
        "webfilter.html",
        tab=tab,
        policy_runtime_state=policy_runtime_state,
        settings=settings,
        available_categories=available,
        selected=selected,
        whitelist_rows=whitelist_rows,
        safe_browsing_status=safe_browsing_status,
        window=window_i,
        window_label=_window_label(window_i),
        err_source=(request.args.get("err_source") == "1"),
        err_safe_browsing_lists=(request.args.get("err_safe_browsing_lists") == "1"),
        err_safe_browsing_key=(request.args.get("err_safe_browsing_key") == "1"),
        safe_browsing_saved=(request.args.get("safe_browsing_saved") == "1"),
        wl_ok=(request.args.get("wl_ok") == "1"),
        wl_err=(request.args.get("wl_err") or ""),
    )


@app.route("/webfilter/test", methods=["POST"])
def webfilter_test_domain():
    store = get_webfilter_store()
    _best_effort_init_store(store, key="webfilter_test", description="web filter")

    payload = request.get_json(silent=True) or {}
    domain = (payload.get("domain") or request.form.get("domain") or "").strip()
    try:
        res = store.test_domain(domain)
        return jsonify(res), 200
    except Exception as e:
        return jsonify(
            {"ok": False, "verdict": "error", "reason": public_error_message(e)},
        ), 200


@app.route("/sslfilter", methods=["GET", "POST"])
def sslfilter():
    store = get_sslfilter_store()
    _best_effort_init_store(store, key="sslfilter", description="SSL filter")

    if request.method == "POST":
        try:
            return _handle_sslfilter_post(store)
        except Exception as exc:
            log_exception_throttled(
                app.logger,
                "web.app.sslfilter.post",
                interval_seconds=30.0,
                message="Failed to process SSL filter admin action",
            )
            return _redirect_to("sslfilter", err=public_error_message(exc))

    rules = store.list_all()
    pac_target, pac_url, pac_warning = _selected_proxy_pac_context()
    policy_runtime_state = _policy_runtime_state(get_proxy_id())
    return render_template(
        "sslfilter.html",
        rules=rules,
        policy_runtime_state=policy_runtime_state,
        pac_target=pac_target,
        pac_url=pac_url,
        pac_warning=pac_warning,
        private_dst_nets=store.private_dst_nets,
        compatibility_presets=store.list_compatibility_presets(),
        ok=(request.args.get("ok") == "1"),
        err=(request.args.get("err") or ""),
    )


def _check_icap_adblock() -> dict[str, Any]:
    return _app_runtime_services().check_icap_adblock()


def _check_icap_av() -> dict[str, Any]:
    return _app_runtime_services().check_icap_av()


def _clamav_remote_health(proxy_id: str) -> dict[str, Any]:
    timeout_seconds = _proxy_clamav_health_timeout_seconds()
    key = (str(proxy_id or ""), "clamav", float(timeout_seconds))
    now = time.monotonic()
    cached = _PROXY_HEALTH_CACHE.get(key)
    cached_payload = _fresh_cached_health_payload(
        cached,
        now=now,
        ttl_seconds=_PROXY_HEALTH_TTL_SECONDS,
    )
    if cached_payload is not None:
        return cached_payload
    try:
        payload = get_proxy_client().get_clamav_health(
            proxy_id,
            timeout_seconds=timeout_seconds,
        )
    except AttributeError:
        return _cached_proxy_health(proxy_id, timeout_seconds=timeout_seconds)
    except ProxyClientError as exc:
        cached_payload = _fresh_cached_health_payload(
            cached,
            now=time.monotonic(),
            ttl_seconds=_PROXY_HEALTH_TTL_SECONDS,
        )
        if cached_payload is not None:
            stale_payload = dict(cached_payload)
            stale_payload["previous_ok"] = bool(stale_payload.get("ok"))
            stale_payload["previous_status"] = str(
                stale_payload.get("status") or "unknown",
            )
            stale_payload["ok"] = False
            stale_payload["status"] = "degraded"
            stale_payload["health_cache_detail"] = str(
                exc or "using recent cached ClamAV health after refresh failure",
            )
            stale_payload.setdefault(
                "detail",
                "using recent cached ClamAV health after refresh failure",
            )
            stale_payload["_stale"] = True
            return stale_payload
        proxy = get_proxy_registry().get_proxy(proxy_id)
        payload = build_unavailable_runtime_health(
            str(exc),
            proxy_status=proxy.status if proxy else "offline",
        )
        payload["_unavailable_cached"] = True
        _PROXY_HEALTH_CACHE[key] = (now, dict(payload))
        return payload
    _PROXY_HEALTH_CACHE[key] = (now, dict(payload))
    return payload


def _send_sample_av_icap() -> dict[str, Any]:
    return _app_runtime_services().send_sample_av_icap()


def _check_clamd() -> dict[str, Any]:
    return _app_runtime_services().check_clamd()


def _test_eicar() -> dict[str, Any]:
    return _app_runtime_services().test_eicar()


@app.route("/error-pages", methods=["GET"])
def error_pages():
    pages = list_error_pages()
    token_summary = {
        page.name: ", ".join(template_tokens(read_template(page.name)))
        for page in pages
    }
    return render_template(
        "error_pages.html",
        pages=pages,
        token_summary=token_summary,
    )


@app.route("/error-pages/preview/<name>", methods=["GET"])
def error_page_preview(name: str):
    try:
        html = render_preview(name)
    except KeyError:
        abort(404)
    response = Response(html, mimetype="text/html")
    response.headers["X-Robots-Tag"] = "noindex, nofollow"
    return response


@app.route("/clamav", methods=["GET"])
def clamav():
    cfg = _current_managed_config()
    clamav_enabled = _is_clamav_enabled(cfg)
    window_i = _query_int_arg(
        "window",
        default=3600,
        minimum=300,
        maximum=7 * 24 * 3600,
    )
    since_ts = int(time.time()) - window_i
    proxy_id = get_proxy_id()
    health_payload = _clamav_remote_health(proxy_id)
    clamav_view = build_remote_clamav_view(health_payload)
    health = clamav_view["health"]
    clamd_health = clamav_view["clamd_health"]
    av_icap_health = clamav_view["av_icap_health"]
    health_source = clamav_view["health_source"]

    try:
        clamav_icap_summary = get_diagnostic_store().icap_summary(
            since=since_ts,
            service="av",
        )
    except Exception:
        clamav_icap_summary = {
            "events": 0,
            "avg_icap_time_ms": 0,
            "max_icap_time_ms": 0,
        }

    clamav_options = extract_clamav_options(cfg)

    return render_template(
        "clamav.html",
        health=health,
        clamd_health=clamd_health,
        av_icap_health=av_icap_health,
        health_source=health_source,
        clamav_enabled=clamav_enabled,
        clamav_icap_summary=clamav_icap_summary,
        clamav_sections=get_clamav_ui_sections(),
        clamav_field_map=get_clamav_ui_field_map(),
        clamav_options=clamav_options,
        window=window_i,
        window_label=_window_label(window_i),
        eicar_result=request.args.get("eicar"),
        eicar_detail=request.args.get("eicar_detail"),
        icap_result=request.args.get("icap_sample"),
        icap_detail=request.args.get("icap_detail"),
        settings_ok=request.args.get("settings_ok"),
        settings_msg=request.args.get("settings_msg"),
    )


@app.route("/clamav/settings", methods=["POST"])
def clamav_settings():
    new_cfg = ""
    try:
        current = _current_managed_config()
        options = read_clamav_options_from_form(
            request.form,
            extract_clamav_options(current),
        )
        new_cfg = apply_clamav_options_to_config(current, options)
        ok, details = _publish_config_for_current_mode(
            new_cfg,
            source_kind="clamav-settings",
        )
    except Exception as exc:
        app.logger.exception("ClamAV settings apply failed")
        ok = False
        details = public_error_message(exc)
    _record_audit_event(
        "clamav_settings_apply",
        ok=ok,
        detail=(details or ""),
        config_text=new_cfg or None,
    )
    return _redirect_to(
        "clamav",
        settings_ok=_bool_result_param(ok),
        settings_msg=(details or "")[:1000],
    )


@app.route("/clamav/test-eicar", methods=["POST"])
def clamav_test_eicar():
    try:
        res = get_proxy_client().test_clamav_eicar(get_proxy_id())
    except ProxyClientError as exc:
        res = {"ok": False, "detail": str(exc)}
    return _redirect_to(
        "clamav",
        eicar="ok" if res.get("ok") else "fail",
        eicar_detail=(res.get("detail") or "")[:300],
    )


@app.route("/clamav/test-icap", methods=["POST"])
def clamav_test_icap():
    try:
        res = get_proxy_client().test_clamav_icap(get_proxy_id())
    except ProxyClientError as exc:
        res = {"ok": False, "detail": str(exc)}
    return _redirect_to(
        "clamav",
        icap_sample="ok" if res.get("ok") else "fail",
        icap_detail=(res.get("detail") or "")[:300],
    )


def _is_clamav_enabled(cfg_text: str) -> bool:
    options = extract_clamav_options(cfg_text or "")
    return bool(
        options.get("file_security_scan_downloads")
        or options.get("file_security_scan_uploads"),
    )


def _set_clamav_enabled(cfg_text: str, enabled: bool) -> str:
    options = extract_clamav_options(cfg_text or "")
    options["file_security_scan_downloads"] = bool(enabled)
    options["file_security_scan_uploads"] = bool(enabled)
    return apply_clamav_options_to_config(cfg_text or "", options)


@app.route("/clamav/toggle", methods=["POST"])
def clamav_toggle():
    action = _form_action(lower=True)
    new_cfg = ""
    try:
        cfg = _current_managed_config()
        currently_enabled = _is_clamav_enabled(cfg)

        if action == "enable":
            desired = True
        elif action == "disable":
            desired = False
        else:
            desired = not currently_enabled

        new_cfg = _set_clamav_enabled(cfg, desired)
        ok, details = _publish_config_for_current_mode(new_cfg, source_kind="clamav")
    except Exception as exc:
        log_exception_throttled(
            app.logger,
            "web.app.clamav_toggle",
            interval_seconds=30.0,
            message="Failed to toggle ClamAV runtime policy",
        )
        ok = False
        details = public_error_message(exc)
    _record_audit_event(
        "clamav_toggle",
        ok=ok,
        detail=(details or ""),
        config_text=new_cfg or None,
    )
    if ok:
        return _redirect_to("clamav")
    return _redirect_to("clamav", error="1")


@app.route("/squid/config", methods=["GET", "POST"])
def squid_config():
    config_sections = get_config_ui_sections()
    safe_tabs = tuple(section.key for section in config_sections)
    tab = _normalize_choice(
        request.args.get("tab") or request.form.get("tab") or "config",
        ("config", *safe_tabs),
        "config",
    )

    validation = None
    posted_config = None
    if request.method == "POST":
        action = _form_action(default="apply", lower=True)
        config_text = request.form.get("config_text", "")
        posted_config = config_text
        try:
            if action == "validate":
                ok, details = _validate_config_for_current_mode(config_text)
                validation = {"ok": ok, "detail": (details or "").strip()}
                _record_audit_event(
                    "config_validate_manual",
                    ok=ok,
                    detail=(details or ""),
                    config_text=config_text,
                )
            else:
                ok, details = _publish_config_for_current_mode(
                    config_text,
                    source_kind="manual",
                )
                _record_audit_event(
                    "config_apply_manual",
                    ok=ok,
                    detail=(details or ""),
                    config_text=config_text,
                )
                if ok:
                    return _redirect_config(tab, ok=True, msg=details)
                return _redirect_config(tab, error=True, msg=details)
        except Exception as exc:
            detail = public_error_message(exc)
            log_exception_throttled(
                app.logger,
                "web.app.squid_config.post",
                interval_seconds=30.0,
                message="Failed to process manual Squid config action",
            )
            _record_audit_event(
                "config_validate_manual"
                if action == "validate"
                else "config_apply_manual",
                ok=False,
                detail=detail,
                config_text=config_text,
            )
            if action == "validate":
                validation = {"ok": False, "detail": detail}
            else:
                return _redirect_config(tab, error=True, msg=detail)
    current_config = _current_managed_config()
    tunables = squid_controller.get_tunable_options(current_config)
    managed_options = build_template_options(tunables, max_workers=_max_workers())
    overrides = squid_controller.get_cache_override_options(current_config)
    caching_lines = squid_controller.get_caching_lines(current_config)
    timeout_lines = squid_controller.get_timeout_lines(current_config)
    logging_lines = squid_controller.get_logging_lines(current_config)
    network_lines = squid_controller.get_network_lines(current_config)
    dns_lines = squid_controller.get_dns_lines(current_config)
    ssl_lines = squid_controller.get_ssl_lines(current_config)
    icap_lines = squid_controller.get_icap_lines(current_config)
    privacy_lines = squid_controller.get_privacy_lines(current_config)
    limits_lines = squid_controller.get_limits_lines(current_config)
    performance_lines = squid_controller.get_performance_lines(current_config)
    http_lines = squid_controller.get_http_lines(current_config)
    line_map = {
        "caching": caching_lines,
        "timeouts": timeout_lines,
        "logging": logging_lines,
        "network": network_lines,
        "dns": dns_lines,
        "ssl": ssl_lines,
        "icap": icap_lines,
        "privacy": privacy_lines,
        "limits": limits_lines,
        "performance": performance_lines,
        "http": http_lines,
    }
    section_map = {section.key: section for section in config_sections}
    active_section = section_map.get(tab)
    sslfilter_rules = get_sslfilter_store().list_all()
    sslfilter_count = (
        len(getattr(sslfilter_rules, "no_bump_domains", []) or [])
        + len(getattr(sslfilter_rules, "no_cache_domains", []) or [])
        + len(getattr(sslfilter_rules, "no_bump_src_nets", []) or [])
        + len(getattr(sslfilter_rules, "no_cache_src_nets", []) or [])
        + (1 if bool(getattr(sslfilter_rules, "exclude_private_nets", False)) else 0)
    )
    summary = {
        "workers": tunables.get("workers") if tunables else None,
        "explicit_proxy_port": tunables.get("explicit_proxy_port")
        if tunables
        else None,
        "intercept_enabled": bool(tunables.get("intercept_enabled"))
        if tunables
        else False,
        "intercept_port": tunables.get("intercept_port") if tunables else None,
        "cache_dir_size_mb": tunables.get("cache_dir_size_mb") if tunables else None,
        "cache_mem_mb": tunables.get("cache_mem_mb") if tunables else None,
        "overrides": overrides or {},
        "overrides_on": any(overrides.values()) if overrides else False,
        "sslfilter_count": sslfilter_count,
    }
    config_runtime_state = _config_runtime_state(get_proxy_id())
    config_text = posted_config if posted_config is not None else current_config
    subtab = _normalize_choice(
        request.args.get("subtab") or "safe",
        ("safe", "overrides"),
        "safe",
    )
    return render_template(
        "squid_config.html",
        tab=tab,
        config_text=config_text,
        tunables=tunables,
        managed_options=managed_options,
        overrides=overrides,
        subtab=subtab,
        summary=summary,
        config_runtime_state=config_runtime_state,
        validation=validation,
        sslfilter_rules=sslfilter_rules,
        config_sections=config_sections,
        config_field_map=get_config_ui_field_map(),
        active_section=active_section,
        line_map=line_map,
        caching_lines=caching_lines,
        timeout_lines=timeout_lines,
        logging_lines=logging_lines,
        network_lines=network_lines,
        dns_lines=dns_lines,
        ssl_lines=ssl_lines,
        icap_lines=icap_lines,
        privacy_lines=privacy_lines,
        limits_lines=limits_lines,
        performance_lines=performance_lines,
        http_lines=http_lines,
    )


@app.route("/squid/config/apply-all", methods=["POST"])
def apply_all_saved_config():
    """Rebuild the selected proxy config from saved UI settings, validate, and apply it."""
    try:
        current = _current_managed_config()
        tunables = squid_controller.get_tunable_options(current)
        options = _options_from_tunables(tunables)
        overrides = squid_controller.get_cache_override_options(current)
        ok, detail = _publish_template_config(
            options,
            source_kind="template-reconcile",
            audit_kind="config_apply_all_saved",
            overrides=overrides,
        )
    except Exception as exc:
        detail = public_error_message(exc)
        _record_audit_event(
            "config_apply_all_saved",
            ok=False,
            detail=detail,
        )
        return _redirect_to(
            "squid_config",
            tab="config",
            apply_all_ok="0",
            apply_all_msg=detail[:1000],
        )

    return _redirect_to(
        "squid_config",
        tab="config",
        apply_all_ok=_bool_result_param(ok),
        apply_all_msg=(detail or "")[:1000],
    )


@app.route("/squid/config/apply-safe", methods=["POST"])
def apply_safe_caching():
    form_kind = normalize_safe_form_kind(request.form.get("form_kind"))
    try:
        current = _current_managed_config()
        tunables = squid_controller.get_tunable_options(current)
    except Exception:
        tunables = {}

    options = build_template_options_from_form(
        tunables,
        request.form,
        form_kind=form_kind,
        max_workers=_max_workers(),
    )

    try:
        ok, detail = _publish_template_config(
            options,
            source_kind="template",
            audit_kind="config_apply_template",
        )
    except Exception as exc:
        return _redirect_config(form_kind, error=True, msg=public_error_message(exc))

    return _redirect_config(form_kind, ok=ok, error=not ok, msg=detail)


@app.route("/squid/config/apply-overrides", methods=["POST"])
def apply_cache_overrides():
    # Apply cache override toggles on top of the current tunables and managed policy includes.
    try:
        current = _current_managed_config()
        tunables = squid_controller.get_tunable_options(current)

        options = _options_from_tunables(tunables)
        overrides = parse_cache_override_form(request.form)
        ok, detail = _publish_template_config(
            options,
            source_kind="overrides",
            audit_kind="config_apply_overrides",
            overrides=overrides,
        )
    except Exception as exc:
        return _redirect_config(
            "caching",
            subtab="overrides",
            error=True,
            msg=public_error_message(exc),
        )

    return _redirect_config(
        "caching",
        subtab="overrides",
        ok=ok,
        error=not ok,
        msg=detail,
    )


@app.route("/pac", methods=["GET", "POST"])
def pac_builder():
    store = get_pac_profiles_store()

    if request.method == "POST":
        return _handle_pac_builder_post(store)

    profiles = []
    try:
        profiles = store.list_profiles()
    except Exception:
        profiles = []

    pac_target, pac_url, pac_warning = _selected_proxy_pac_context()
    try:
        chain_settings = store.list_proxy_chain_settings()
    except Exception:
        chain_settings = None
    pac_runtime_state = _pac_runtime_state(get_proxy_id())
    return render_template(
        "pac.html",
        profiles=profiles,
        pac_url=pac_url,
        pac_warning=pac_warning,
        pac_target=pac_target,
        chain_settings=chain_settings,
        pac_runtime_state=pac_runtime_state,
    )


def _default_winhttp_registry_form() -> dict[str, Any]:
    return {
        "proxy_host": "",
        "proxy_port": "3128",
        "destination_schemes": ["http", "https"],
        "bypass_list": "",
        "include_local_bypass": True,
        "use_custom_proxy_map": False,
        "custom_proxy_map": "",
        "autoconfig_url": "",
        "autodetect": False,
        "advproxy_scope": "machine",
        "tracing_state": "disabled",
        "tracing_output": "",
        "trace_file_prefix": "",
        "tracing_level": "",
        "tracing_format": "",
        "max_trace_file_size": "",
        "reg_input": "",
    }


def _winhttp_form_from_request() -> dict[str, Any]:
    form = _default_winhttp_registry_form()
    form.update(
        {
            "proxy_host": request.form.get("proxy_host", ""),
            "proxy_port": request.form.get("proxy_port", "3128"),
            "destination_schemes": request.form.getlist("destination_schemes"),
            "bypass_list": request.form.get("bypass_list", ""),
            "include_local_bypass": request.form.get("include_local_bypass") == "on",
            "use_custom_proxy_map": request.form.get("use_custom_proxy_map") == "on",
            "custom_proxy_map": request.form.get("custom_proxy_map", ""),
            "autoconfig_url": request.form.get("autoconfig_url", ""),
            "autodetect": request.form.get("autodetect") == "on",
            "advproxy_scope": request.form.get("advproxy_scope", "machine"),
            "tracing_state": request.form.get("tracing_state", "disabled"),
            "tracing_output": request.form.get("tracing_output", ""),
            "trace_file_prefix": request.form.get("trace_file_prefix", ""),
            "tracing_level": request.form.get("tracing_level", ""),
            "tracing_format": request.form.get("tracing_format", ""),
            "max_trace_file_size": request.form.get("max_trace_file_size", ""),
            "reg_input": request.form.get("reg_input", ""),
        },
    )
    return form


@app.route("/tools/winhttp-registry", methods=["GET", "POST"])
def winhttp_registry_builder():
    form = _default_winhttp_registry_form()
    output = None
    normalized_reg_hex = ""
    decoded_reg = None
    error = ""
    action = ""

    if request.method == "POST":
        action = request.form.get("action", "generate")
        form = _winhttp_form_from_request()
        try:
            if action == "normalize_reg":
                normalized_reg_hex = normalize_reg_binary_export(
                    form.get("reg_input") or "",
                )
                try:
                    decoded_reg = decode_basic_winhttp_settings_hex(normalized_reg_hex)
                except WinHttpBuilderError:
                    decoded_reg = None
            else:
                output = build_contract_output(form)
        except WinHttpBuilderError as exc:
            error = str(exc)

    return render_template(
        "winhttp_registry.html",
        form=form,
        output=output,
        normalized_reg_hex=normalized_reg_hex,
        decoded_reg=decoded_reg,
        error=error,
        action=action,
    )


@app.route("/api/timeseries", methods=["GET"])
def api_timeseries():
    res = (request.args.get("resolution") or "1s").strip()
    window_i = _query_int_arg("window", default=60, minimum=10, maximum=365 * 24 * 3600)
    limit_i = _query_int_arg("limit", default=500)

    since = int(time.time()) - window_i
    points = get_timeseries_store().query(resolution=res, since=since, limit=limit_i)
    return jsonify({"resolution": res, "since": since, "points": points})


@app.route("/reload", methods=["POST"])
def reload_squid():
    ok, detail = _trigger_proxy_sync(force=True)
    _record_audit_event("proxy_sync", ok=ok, detail=detail)
    return redirect(_endpoint_url("index") + "#status")


@app.route("/cache/clear", methods=["POST"])
def clear_caches():
    ok, detail = _trigger_proxy_cache_clear()
    _record_audit_event("cache_clear", ok=ok, detail=detail)
    return redirect(_endpoint_url("index") + "#status")


@app.route("/certs", methods=["GET"])
def certs():
    return _render_certs_page(
        message=request.args.get("msg"),
        message_ok=request.args.get("ok") == "1",
    )


def _render_certs_page(
    *,
    message: str | None = None,
    message_ok: bool = False,
    admin_ui_https_next: str | None = None,
):
    bundle_store = get_certificate_bundles()
    bundle = bundle_store.get_active_bundle()
    certificate = "ca.crt" if bundle is not None else None
    admin_ui_https = _admin_ui_https_status(bundle)
    proxy_cert_statuses = []
    active_revision_id = (
        getattr(bundle, "revision_id", None) if bundle is not None else None
    )
    for proxy in get_proxy_registry().list_proxies():
        latest_apply = None
        if active_revision_id is not None:
            latest_apply = bundle_store.latest_apply(
                proxy.proxy_id,
                revision_id=active_revision_id,
            )
        state = _certificate_runtime_state(
            proxy.proxy_id,
            active_revision=bundle,
            latest_apply=latest_apply,
        )
        proxy_cert_statuses.append(
            {
                "proxy_id": proxy.proxy_id,
                "display_name": proxy.display_name or proxy.proxy_id,
                "revision_id": active_revision_id,
                **state,
            },
        )
    return render_template(
        "certs.html",
        certificate=certificate,
        bundle=bundle,
        proxy_cert_statuses=proxy_cert_statuses,
        admin_ui_https=admin_ui_https,
        admin_ui_https_env_lines=_admin_ui_https_env_lines(
            enabled=admin_ui_https["desired_enabled"],
            certfile=admin_ui_https["desired_certfile"],
            keyfile=admin_ui_https["desired_keyfile"],
        ),
        message=message,
        message_ok=message_ok,
        admin_ui_https_next=admin_ui_https_next,
    )


def _certificate_recovery_redirect(error: str = ""):
    params: dict[str, str] = {}
    if error:
        params["cert_recovery_error"] = error
    else:
        params["cert_recovery"] = "1"
    return _redirect_to("certs", **params)


def _selected_proxy_certificate_operation_conflicts(
    proxy_id: str,
    revision_id: int,
) -> tuple[bool, str]:
    operation = _latest_operation(
        proxy_id,
        target_kind="certificate_revision",
        target_ref=revision_id,
        operation_types={"certificate_apply", "certificate_revert"},
    )
    status = str(getattr(operation, "status", "") or "")
    if status in {"pending", "applying"}:
        return True, status
    return False, ""


@app.route("/certs/proxies/<path:proxy_id>/force-reconcile", methods=["POST"])
def force_reconcile_certificate_proxy(proxy_id: str):
    selected_proxy_id = get_proxy_id()
    proxy_key = normalize_proxy_id(proxy_id)
    if proxy_key != selected_proxy_id:
        return _certificate_recovery_redirect("proxy_scope")
    if get_proxy_registry().get_proxy(proxy_key) is None:
        return _certificate_recovery_redirect("proxy_scope")

    bundle_store = get_certificate_bundles()
    try:
        active_revision = bundle_store.get_active_bundle()
    except Exception:
        active_revision = None
    revision_id = _safe_revision_id(getattr(active_revision, "revision_id", 0))
    desired_sha = str(getattr(active_revision, "bundle_sha256", "") or "").strip()
    if not revision_id or not desired_sha:
        return _certificate_recovery_redirect("no_bundle")

    conflicted, _status = _selected_proxy_certificate_operation_conflicts(
        proxy_key,
        revision_id,
    )
    if conflicted:
        return _certificate_recovery_redirect("duplicate")

    operation = request_proxy_reconcile(
        proxy_key,
        operation_type="certificate_apply",
        subject="Certificate bundle retry",
        summary=f"Retry certificate revision {revision_id} for selected proxy {proxy_key}.",
        target_kind="certificate_revision",
        target_ref=revision_id,
        request_hash=desired_sha,
        detail=(
            f"Operator requested selected-proxy certificate retry for revision {revision_id} "
            f"with desired bundle {_short_sha(desired_sha)}. Runtime must report matching "
            "applied/running bundle SHA before this proxy is trusted."
        ),
        created_by=str(session.get("user") or ""),
        force=True,
    )
    if (
        not getattr(operation, "operation_id", 0)
        and getattr(operation, "status", "") == "failed"
    ):
        return _certificate_recovery_redirect("queue_failed")
    return _certificate_recovery_redirect()


@app.route("/certs/generate", methods=["POST"])
def generate_certificate():
    try:
        bundle = generate_self_signed_ca_bundle()
        ok, detail = _publish_certificate_bundle_remote(bundle)
        _record_audit_event("ca_ensure", ok=ok, detail=detail)
        return _redirect_with_message("certs", ok=ok, msg=detail)
    except Exception as e:
        app.logger.exception("CA generation failed")
        message = public_error_message(e)
        _record_audit_event("ca_ensure", ok=False, detail=message)
        return _redirect_with_message("certs", ok=False, msg=message)


@app.route("/certs/upload", methods=["POST"])
def upload_certificate_pfx():
    # Upload a PKCS#12 bundle containing cert + private key and install it as Squid's CA.
    pfx_file = request.files.get("pfx")
    password = request.form.get("pfx_password", "")

    if not pfx_file or not getattr(pfx_file, "filename", ""):
        return _redirect_with_message("certs", ok=False, msg="No PFX file selected.")

    filename = (pfx_file.filename or "").lower()
    _, ext = os.path.splitext(filename)
    if ext not in {".pfx", ".p12"}:
        return _redirect_with_message(
            "certs",
            ok=False,
            msg="Unsupported file type. Please upload a .pfx or .p12.",
        )

    # Basic guard against accidental huge uploads.
    if request.content_length is not None and request.content_length > (
        10 * 1024 * 1024
    ):
        return _redirect_with_message(
            "certs",
            ok=False,
            msg="Upload too large (max 10MB).",
        )

    # Read with a hard cap even if Content-Length is missing or incorrect.
    max_pfx_bytes = 10 * 1024 * 1024
    buf = bytearray()
    try:
        stream = getattr(pfx_file, "stream", None) or pfx_file
        while True:
            chunk = stream.read(512 * 1024)
            if not chunk:
                break
            buf.extend(chunk)
            if len(buf) > max_pfx_bytes:
                return _redirect_with_message(
                    "certs",
                    ok=False,
                    msg="Upload too large (max 10MB).",
                )
    except Exception:
        return _redirect_with_message("certs", ok=False, msg="Failed to read upload.")

    pfx_bytes = bytes(buf)
    try:
        parsed = parse_pfx_bundle(pfx_bytes, password=password)
        ok = bool(parsed.ok and parsed.bundle is not None)
        detail = parsed.message
        if ok and parsed.bundle is not None:
            ok, detail = _publish_certificate_bundle_remote(
                parsed.bundle,
                original_filename=(pfx_file.filename or "").strip(),
            )
    except Exception as exc:
        app.logger.exception("PFX upload failed")
        ok = False
        detail = public_error_message(
            exc,
            default="Failed to process uploaded PFX bundle.",
        )

    _record_audit_event("ca_upload_pfx", ok=ok, detail=detail)

    return _redirect_with_message("certs", ok=ok, msg=detail)


@app.route("/certs/admin-ui-https", methods=["POST"])
def update_admin_ui_https():
    enabled = "1" in request.form.getlist("enabled")
    try:
        configured_san_tokens = _admin_ui_https_configured_san_tokens(
            request.form.get("san_tokens", ""),
        )
    except ValueError as exc:
        return _redirect_with_message("certs", ok=False, msg=str(exc))
    bundle = get_certificate_bundles().get_active_bundle()
    if enabled and bundle is None:
        return _redirect_with_message(
            "certs",
            ok=False,
            msg="Generate or upload an SSL inspection CA bundle before enabling Admin UI HTTPS.",
        )
    material = None
    if enabled:
        try:
            material = _materialize_admin_ui_https_leaf(
                bundle,
                SimpleNamespace(san_tokens=_admin_ui_https_format_san_tokens(configured_san_tokens)),
            )
        except Exception as exc:
            return _redirect_with_message(
                "certs",
                ok=False,
                msg=(
                    "Admin UI HTTPS requires the active SSL inspection CA certificate "
                    "and key to generate a dedicated server certificate. "
                    f"{public_error_message(exc)}"
                ),
            )
    material_status = _admin_ui_https_default_material_status()
    if enabled and not material_status["ready"]:
        missing = []
        if not material_status["cert_status"]["valid"]:
            missing.append(material_status["certfile"])
        if not material_status["key_status"]["valid"]:
            missing.append(material_status["keyfile"])
        return _redirect_with_message(
            "certs",
            ok=False,
            msg=(
                "Admin UI HTTPS requires the generated Admin UI server certificate "
                f"and key to be mounted as valid PEM material in the admin-ui container: "
                f"{', '.join(missing)}. {material_status['detail']}"
            ),
        )
    certfile = material.certfile if enabled and material is not None else ""
    keyfile = material.keyfile if enabled and material is not None else ""

    try:
        get_certificate_bundles().set_admin_ui_https_settings(
            enabled=enabled,
            certfile=certfile,
            keyfile=keyfile,
            san_tokens=_admin_ui_https_format_san_tokens(configured_san_tokens),
            updated_by=str(session.get("user") or ""),
        )
        restart_ok, restart_detail = _restart_admin_ui_web_process()
        detail = "Saved Admin UI HTTPS preference. "
        detail += (
            restart_detail
            if restart_ok
            else f"{restart_detail} Restart the admin-ui web process or container for it to take effect."
        )
        _record_audit_event(
            "admin_ui_https_settings_save",
            ok=restart_ok,
            detail=detail,
        )
        if enabled and restart_ok:
            return _render_certs_page(
                message=detail,
                message_ok=True,
                admin_ui_https_next=_admin_ui_https_next_url(),
            )
        return _redirect_with_message("certs", ok=restart_ok, msg=detail)
    except Exception as exc:
        app.logger.exception("Failed to save Admin UI HTTPS settings")
        detail = public_error_message(
            exc,
            default="Failed to save Admin UI HTTPS settings.",
        )
        _record_audit_event("admin_ui_https_settings_save", ok=False, detail=detail)
        return _redirect_with_message("certs", ok=False, msg=detail)


@app.route("/certs/admin-ui-https/regenerate", methods=["POST"])
def regenerate_admin_ui_https_certificate():
    try:
        settings = _admin_ui_https_converge_leaf_settings(
            get_certificate_bundles().get_admin_ui_https_settings()
        )
        bundle = get_certificate_bundles().get_active_bundle()
        if bundle is None:
            return _redirect_with_message(
                "certs",
                ok=False,
                msg="Generate or upload an SSL inspection CA bundle before regenerating the Admin UI HTTPS certificate.",
            )
        material = _materialize_admin_ui_https_leaf(bundle, settings)
        get_certificate_bundles().set_admin_ui_https_settings(
            enabled=bool(getattr(settings, "enabled", False)),
            certfile=material.certfile,
            keyfile=material.keyfile,
            san_tokens=getattr(settings, "san_tokens", ""),
            updated_by=str(session.get("user") or ""),
        )
        detail = (
            "Regenerated Admin UI HTTPS certificate without changing the active CA. "
            f"SANs: {', '.join(material.sans)}"
        )
        _record_audit_event("admin_ui_https_certificate_regenerate", ok=True, detail=detail)
        return _redirect_with_message("certs", ok=True, msg=detail)
    except Exception as exc:
        app.logger.exception("Failed to regenerate Admin UI HTTPS certificate")
        detail = public_error_message(
            exc,
            default="Failed to regenerate Admin UI HTTPS certificate.",
        )
        _record_audit_event(
            "admin_ui_https_certificate_regenerate",
            ok=False,
            detail=detail,
        )
        return _redirect_with_message("certs", ok=False, msg=detail)


@app.route("/certs/download/<path:filename>", methods=["GET"])
def download_certificate(filename: str):
    # Only allow downloading the public CA cert
    if filename != "ca.crt":
        abort(404)
    bundle = get_certificate_bundles().get_active_bundle()
    if bundle is None:
        abort(404)
    response = app.response_class(
        bundle.fullchain_pem,
        mimetype="application/x-pem-file",
    )
    response.headers["Content-Disposition"] = "attachment; filename=squid-proxy-ca.crt"
    return response


@app.route("/administration", methods=["GET", "POST"])
def administration():
    store = _auth_store
    current_user = (session.get("user") or "").strip()

    if request.method == "POST":
        return _handle_administration_post(store, current_user)

    users = []
    try:
        users = store.list_users()
    except Exception:
        users = []

    auth_status_degraded = False
    try:
        auth_status = _directory_auth_store.get_status()
    except Exception:
        app.logger.exception("Failed to load directory authentication status")
        auth_status_degraded = True
        auth_status = {
            "active_provider": "local",
            "active_label": "Local accounts",
            "profiles": {},
            "providers": (),
            "provider_labels": {},
        }
    try:
        saml_status = _saml_admin_status()
    except Exception:
        app.logger.exception("Failed to load SAML authentication status")
        saml_status = {
            "profile": _saml_auth_store.default_profile(),
            "ready": False,
            "metadata_ready": False,
            "sp": {"entity_id": "", "acs_url": "", "sls_url": ""},
            "idp_entity_id": "",
            "signing_certs": [],
        }
    if saml_status["ready"]:
        auth_status = {
            **auth_status,
            "active_provider": "saml",
            "active_label": "SAML",
        }
    auth_tab = (request.args.get("tab") or "status").strip()
    if auth_status_degraded or auth_tab not in {
        "status",
        "ldap",
        "active_directory",
        "saml",
    }:
        auth_tab = "status"
    message = request.args.get("msg")
    message_ok = request.args.get("ok") == "1"
    auth_scan = (
        session.get(f"directory_scan_{auth_tab}")
        if auth_tab in {"ldap", "active_directory"}
        else None
    )
    return render_template(
        "administration.html",
        users=users,
        current_user=current_user,
        auth_status=auth_status,
        saml_status=saml_status,
        auth_tab=auth_tab,
        auth_scan=auth_scan or {},
        message=message,
        message_ok=message_ok,
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
