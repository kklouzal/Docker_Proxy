Total output lines: 4470

import contextlib
import csv
import hashlib
import inspect
import io
import json
import os
import secrets
import shutil
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlparse

from flask import (
    Flask,
    Response,
    abort,
    g,
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
from services.clamav_config_forms import (
    apply_clamav_options_to_config,
    extract_clamav_options,
    get_clamav_ui_field_map,
    get_clamav_ui_sections,
    read_clamav_options_from_form,
)
from services.config_revisions import (
    get_config_revisions as _default_get_config_revisions,
)
from services.diagnostic_store import (
    get_diagnostic_store as _default_get_diagnostic_store,
)
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
from services.operation_ledger import get_operation_ledger
from services.pac_profiles_store import (
    get_pac_profiles_store as _default_get_pac_profiles_store,
)
from services.pac_renderer import resolve_proxy_pac_target
from services.policy_requests import (
    get_policy_request_store as _default_get_policy_request_store,
)
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
from services.proxy_registry import get_proxy_registry as _default_get_proxy_registry
from services.proxy_sync import request_proxy_reconcile
from services.runtime_helpers import extract_domain as _extract_domain
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
from services.webfilter_store import get_webfilter_store as _default_get_webfilter_store
from services.webfilter_core import validate_source_url as _validate_webfilter_source_url
from services.winhttp_registry_builder import (
    WinHttpBuilderError,
    build_contract_output,
    decode_basic_winhttp_settings_hex,
    normalize_reg_binary_export,
)
from werkzeug.exceptions import HTTPException

app = Flask(__name__)
install_http_optimizations(app)
_asset_version = str(int(time.time()))
OBSERVABILITY_DEFAULT_WINDOW = 24 * 60 * 60
_PROXY_HEALTH_CACHE: dict[tuple[Any, ...], tuple[float, dict[str, Any]]] = {}


def _env_float(name: str, default: float, *, minimum: float, maximum: float) -> float:
    try:
        value = float((os.environ.get(name) or str(default)).strip() or default)
    except Exception:
        value = float(default)
    return max(float(minimum), min(float(maximum), value))


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
) -> dict[str, Any]:
    """Short-lived per-process health cache for navigation-time UI snapshots."""
    key = (str(proxy_id or ""), float(timeout_seconds))
    now = time.monotonic()
    cached = _PROXY_HEALTH_CACHE.get(key)
    if cached is not None:
        cached_at, payload = cached
        if now - cached_at <= max(0.0, float(ttl_seconds)):
            return dict(payload)
    try:
        payload = get_proxy_client().get_health(
            proxy_id,
            timeout_seconds=timeout_seconds,
        )
    except ProxyClientError as exc:
        if cached is not None:
            stale_payload = dict(cached[1])
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
_env_secret = (os.environ.get("FLASK_SECRET_KEY") or "").strip()
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


def _is_logged_in() -> bool:
    u = session.get("user")
    return bool(u and isinstance(u, str))


def _query_flag(value: bool) -> str | None:
    return "1" if value else None


_NON_PROXY_ENDPOINTS = frozenset(
    {"static", "login", "logout", "health", "recover_admin_session"},
)


def _filter_none_params(params: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in params.items() if v is not None}


def _should_preserve_proxy(endpoint: str, params: dict[str, Any] | None = None) -> bool:
    if endpoint in _NON_PROXY_ENDPOINTS:
        return False
    return not (params and params.get("proxy_id") is not None)


def _endpoint_url(endpoint: str, **params: Any) -> str:
    values = _filter_none_params(params)
    if _should_preserve_proxy(endpoint, values):
        values["proxy_id"] = get…27995 tokens truncated…file_security_scan_uploads"] = bool(enabled)
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
                    return _redirect_config(tab, ok=True)
                return _redirect_config(tab, error=True)
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
                return _redirect_config(tab, error=True)
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
        _record_audit_event(
            "config_apply_all_saved",
            ok=False,
            detail=public_error_message(exc),
        )
        return _redirect_to("squid_config", tab="config", apply_all_ok="0")

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
        ok, _details = _publish_template_config(
            options,
            source_kind="template",
            audit_kind="config_apply_template",
        )
    except Exception:
        return _redirect_config("caching", error=True)

    return _redirect_config(form_kind, ok=ok, error=not ok)


@app.route("/squid/config/apply-overrides", methods=["POST"])
def apply_cache_overrides():
    # Apply cache override toggles on top of the current tunables and managed policy includes.
    try:
        current = _current_managed_config()
        tunables = squid_controller.get_tunable_options(current)

        options = _options_from_tunables(tunables)
        overrides = parse_cache_override_form(request.form)
        ok, _details = _publish_template_config(
            options,
            source_kind="overrides",
            audit_kind="config_apply_overrides",
            overrides=overrides,
        )
    except Exception:
        return _redirect_config("caching", subtab="overrides", error=True)

    return _redirect_config("caching", subtab="overrides", ok=ok, error=not ok)


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
    return render_template(
        "pac.html",
        profiles=profiles,
        pac_url=pac_url,
        pac_warning=pac_warning,
        pac_target=pac_target,
        chain_settings=chain_settings,
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
    bundle_store = get_certificate_bundles()
    bundle = bundle_store.get_active_bundle()
    certificate = "ca.crt" if bundle is not None else None
    proxy_cert_statuses = []
    for proxy in get_proxy_registry().list_proxies():
        latest_apply = bundle_store.latest_apply(proxy.proxy_id)
        proxy_cert_statuses.append(
            {
                "proxy_id": proxy.proxy_id,
                "display_name": proxy.display_name or proxy.proxy_id,
                "ok": latest_apply.ok if latest_apply is not None else None,
                "detail": latest_apply.detail if latest_apply is not None else "",
                "applied_ts": latest_apply.applied_ts
                if latest_apply is not None
                else 0,
            },
        )
    message = request.args.get("msg")
    message_ok = request.args.get("ok") == "1"
    return render_template(
        "certs.html",
        certificate=certificate,
        bundle=bundle,
        proxy_cert_statuses=proxy_cert_statuses,
        message=message,
        message_ok=message_ok,
    )


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

    message = request.args.get("msg")
    message_ok = request.args.get("ok") == "1"
    return render_template(
        "administration.html",
        users=users,
        current_user=current_user,
        message=message,
        message_ok=message_ok,
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
