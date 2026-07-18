from __future__ import annotations

import hashlib
import json
import logging
import os
import pathlib
import shutil
import socket
import sqlite3
import subprocess
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from contextlib import contextmanager, suppress
from dataclasses import dataclass, replace
from typing import Any

from services.adblock_artifacts import (
    get_adblock_artifacts,
    materialize_archive_to_directory,
    read_materialized_artifact_sha,
)
from services.adblock_store import get_adblock_store
from services.certificate_bundles import get_certificate_bundles
from services.certificate_core import CertManager, materialize_certificate_bundle
from services.config_revisions import get_config_revisions
from services.db import DATABASE_ERRORS
from services.diagnostic_store import get_diagnostic_store
from services.errors import public_error_message
from services.health_checks import build_clamav_health
from services.live_stats import get_store
from services.logutil import log_exception_throttled, should_log
from services.materialized_files import write_managed_text_files
from services.operation_ledger import get_operation_ledger
from services.pac_renderer import (
    PAC_RENDER_DIR,
    build_proxy_pac_state,
    materialize_proxy_pac_state,
    read_materialized_pac_state_sha,
)
from services.policy_materializer import (
    MaterializedPolicyFile,
    build_proxy_policy_state,
    calculate_policy_sha,
)
from services.proxy_context import get_proxy_id
from services.proxy_health import check_adblock_icap_health as _check_icap_adblock
from services.proxy_health import check_av_icap_health as _check_icap_av
from services.proxy_health import check_clamd_health as _check_clamd
from services.proxy_health import send_sample_av_icap as _shared_send_sample_av_icap
from services.proxy_health import test_eicar as _shared_test_eicar
from services.proxy_registry import (
    get_proxy_registry,
    resolve_local_proxy_management_url,
    resolve_local_proxy_public_fields,
)
from services.runtime_helpers import decode_bytes as _decode_bytes
from services.squid_core import SquidController
from services.ssl_errors_store import get_ssl_errors_store
from services.stats import get_stats
from services.timeseries_store import get_timeseries_store
from services.version_status import current_component_metadata

logger = logging.getLogger(__name__)


_SUPERVISOR_CONTROL_LOCK = threading.RLock()
_SYNC_CONTROL_LOCK = threading.RLock()
_ADBLOCK_ICAP_SELF_HEAL_FAILURE_THRESHOLD = 3
_ADBLOCK_ICAP_SELF_HEAL_RESTART_COOLDOWN_SECONDS = 600.0


def _adblock_icap_self_heal_failure_threshold() -> int:
    try:
        value = int(
            (os.environ.get("ADBLOCK_ICAP_SELF_HEAL_FAILURE_THRESHOLD") or "").strip()
            or _ADBLOCK_ICAP_SELF_HEAL_FAILURE_THRESHOLD
        )
    except Exception:
        value = _ADBLOCK_ICAP_SELF_HEAL_FAILURE_THRESHOLD
    return max(1, min(value, 10))


def _adblock_icap_self_heal_restart_cooldown_seconds() -> float:
    try:
        value = float(
            (os.environ.get("ADBLOCK_ICAP_SELF_HEAL_RESTART_COOLDOWN_SECONDS") or "").strip()
            or _ADBLOCK_ICAP_SELF_HEAL_RESTART_COOLDOWN_SECONDS
        )
    except Exception:
        value = _ADBLOCK_ICAP_SELF_HEAL_RESTART_COOLDOWN_SECONDS
    return max(0.0, min(value, 3600.0))


def _clamp_icap_workers(value: object) -> int:
    try:
        workers = int(str(value).strip())
    except Exception:
        workers = 1
    return max(1, min(workers, 4))


def _bool_setting(value: object, *, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value).strip().lower()
    if not text:
        return default
    return text in {"1", "true", "yes", "on", "enabled"}


def _icap_supervisor_programs(base_name: str) -> tuple[str, ...]:
    name = str(base_name or "").strip()
    if name in {"cicap_adblock", "cicap_av"}:
        raw_workers = os.environ.get("SQUID_WORKERS") or os.environ.get("WORKERS")
        if raw_workers is None:
            return (name,)
        workers = _clamp_icap_workers(raw_workers)
        return tuple(f"{name}_{index}" for index in range(1, workers + 1))
    return (name,) if name else ()


def _int_or_none(value: object) -> int | None:
    try:
        parsed = int(value or 0)
    except Exception:
        return None
    return parsed if parsed > 0 else None


def _operation_requests_force(operation: Any) -> bool:
    value = getattr(operation, "force", None)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on", "force"}
    return bool(value)


def _operations_request_force(operations: list[Any] | None) -> bool:
    return any(_operation_requests_force(operation) for operation in operations or [])


_SUPPORTED_RUNTIME_OPERATION_TYPES = {
    "sync",
    "manual_sync",
    "runtime_nudge",
    "policy_sync",
    "config_sync",
    "config_apply",
    "revert",
    "certificate_apply",
    "certificate_revert",
    "pac_refresh",
    "adblock_refresh",
    "cache_clear",
}


def _operation_type(operation: Any) -> str:
    return str(getattr(operation, "operation_type", "") or "sync")


def _unsupported_operation_types(operations: list[Any] | None) -> list[str]:
    return sorted(
        {
            operation_type
            for operation_type in (_operation_type(operation) for operation in operations or [])
            if operation_type not in _SUPPORTED_RUNTIME_OPERATION_TYPES
        },
    )


def _supported_operation_types(operations: list[Any] | None) -> list[str]:
    return sorted(
        {
            operation_type
            for operation_type in (_operation_type(operation) for operation in operations or [])
            if operation_type in _SUPPORTED_RUNTIME_OPERATION_TYPES
        },
    )


def _operation_requests_config_force(operation: Any) -> bool:
    if not _operation_requests_force(operation):
        return False
    operation_type = _operation_type(operation)
    target_kind = str(getattr(operation, "target_kind", "") or "")
    return (
        operation_type in {"manual_sync", "config_sync", "config_apply"}
        or target_kind == "config_revision"
    )


def _operations_request_config_force(operations: list[Any] | None) -> bool:
    return any(
        _operation_requests_config_force(operation) for operation in operations or []
    )


def _operation_completion_status(
    operation: Any,
    *,
    default_status: str,
    detail: str,
    result: dict[str, Any],
) -> tuple[str, str]:
    operation_type = _operation_type(operation)
    if operation_type not in _SUPPORTED_RUNTIME_OPERATION_TYPES:
        op_detail = f"Unsupported proxy operation type '{operation_type}' was not executed."
        if detail:
            op_detail = f"{op_detail}\n{detail}"
        return "failed", op_detail[:4000]

    if default_status != "applied":
        return default_status, detail

    executed_operation_types = result.get("executed_operation_types")
    if executed_operation_types is not None:
        executed = {str(value) for value in executed_operation_types or []}
        if operation_type not in executed:
            op_detail = (
                f"Proxy operation '{operation_type}' completed reconciliation but did not "
                "report execution evidence for the requested operation."
            )
            if detail:
                op_detail = f"{op_detail}\n{detail}"
            return "failed", op_detail[:4000]

    if operation_type == "cache_clear" and not bool(result.get("cache_cleared")):
        op_detail = "Proxy cache clear did not report a completed cache clear side effect."
        if detail:
            op_detail = f"{op_detail}\n{detail}"
        return "failed", op_detail[:4000]

    target_kind = str(getattr(operation, "target_kind", "") or "")
    if target_kind == "policy_state":
        target_ref = str(getattr(operation, "target_ref", "") or "").strip()
        applied_ref = str(result.get("policy_sha256") or "").strip()
        current_ref = str(result.get("current_policy_sha") or "").strip()
        if target_ref and applied_ref and target_ref != applied_ref:
            op_detail = (
                f"Superseded by active policy state {applied_ref[:12]}; "
                f"queued policy state {target_ref[:12]} was not applied because a newer desired state was reconciled."
            )
            if detail:
                op_detail = f"{op_detail}\n{detail}"
            return "superseded", op_detail[:4000]
        if target_ref and current_ref and target_ref != current_ref:
            op_detail = (
                f"Policy sync did not converge selected-proxy runtime state; "
                f"queued policy {target_ref[:12]} differs from current policy {current_ref[:12]}."
            )
            if detail:
                op_detail = f"{op_detail}\n{detail}"
            return "failed", op_detail[:4000]
        return default_status, detail

    if target_kind == "certificate_revision":
        target_ref = _int_or_none(getattr(operation, "target_ref", None))
        applied_ref = _int_or_none(result.get("certificate_revision_id"))
        applied_hash = str(result.get("certificate_bundle_sha256") or "").strip()
        if target_ref is None:
            op_detail = (
                "Certificate operation completed reconciliation but did not include "
                "a valid queued certificate revision target."
            )
            if detail:
                op_detail = f"{op_detail}\n{detail}"
            return "failed", op_detail[:4000]
        if applied_ref is None:
            op_detail = (
                "Certificate operation completed reconciliation but did not report "
                "the active certificate revision evidence required to verify the queued target."
            )
            if detail:
                op_detail = f"{op_detail}\n{detail}"
            return "failed", op_detail[:4000]
        if target_ref == applied_ref:
            return default_status, detail

        hash_detail = f" ({applied_hash[:12]})" if applied_hash else ""
        op_detail = (
            f"Superseded by active certificate revision {applied_ref}{hash_detail}; "
            f"queued certificate revision {target_ref} was not applied because a newer "
            "desired certificate bundle was reconciled."
        )
        if detail:
            op_detail = f"{op_detail}\n{detail}"
        return "superseded", op_detail[:4000]

    if target_kind != "config_revision":
        return default_status, detail

    target_ref = _int_or_none(getattr(operation, "target_ref", None))
    applied_ref = _int_or_none(result.get("revision_id"))
    if target_ref is None:
        op_detail = (
            "Config operation completed reconciliation but did not include "
            "a valid queued config revision target."
        )
        if detail:
            op_detail = f"{op_detail}\n{detail}"
        return "failed", op_detail[:4000]
    if applied_ref is None:
        op_detail = (
            "Config operation completed reconciliation but did not report "
            "the active config revision evidence required to verify the queued target."
        )
        if detail:
            op_detail = f"{op_detail}\n{detail}"
        return "failed", op_detail[:4000]
    if target_ref == applied_ref:
        return default_status, detail

    op_detail = (
        f"Superseded by active config revision {applied_ref}; "
        f"queued config revision {target_ref} was not applied because a newer desired state was reconciled."
    )
    if detail:
        op_detail = f"{op_detail}\n{detail}"
    return "superseded", op_detail[:4000]


def _certificate_result_evidence(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "certificate_revision_id": _int_or_none(
            result.get("certificate_revision_id"),
        ),
        "certificate_bundle_sha256": str(
            result.get("certificate_bundle_sha256") or result.get("bundle_sha256") or "",
        ).strip(),
    }


@contextmanager
def _exclusive_runtime_lock(name: str, thread_lock: threading.RLock):
    """Serialize runtime mutations across proxy_api threads and proxy_agent."""
    with thread_lock:
        handle = None
        fcntl_mod = None
        try:
            lock_dir = (
                os.environ.get("PROXY_RUNTIME_LOCK_DIR") or "/tmp"
            ).strip() or "/tmp"
            pathlib.Path(lock_dir).mkdir(exist_ok=True, parents=True)
            handle = pathlib.Path(
                os.path.join(lock_dir, f"docker-proxy-{name}.lock"),
            ).open("a+", encoding="utf-8")
            try:
                import fcntl as fcntl_mod  # type: ignore

                fcntl_mod.flock(handle.fileno(), fcntl_mod.LOCK_EX)
            except Exception:
                fcntl_mod = None
            yield
        finally:
            if handle is not None:
                try:
                    if fcntl_mod is not None:
                        fcntl_mod.flock(handle.fileno(), fcntl_mod.LOCK_UN)
                except Exception:
                    pass
                with suppress(Exception):
                    handle.close()


@dataclass(frozen=True)
class ProxyRuntimeServices:
    controller: Any
    registry: Any
    revisions: Any
    certificate_bundles: Any
    adblock_artifacts: Any
    cert_manager: Any
    adblock_store: Any
    live_stats_store: Any
    diagnostic_store: Any
    timeseries_store: Any
    ssl_errors_store: Any
    stats_provider: Any
    runtime_services_builder: Any
    policy_state_builder: Any
    pac_state_builder: Any
    adblock_service_restarter: Any = None
    ssl_db_reinitializer: Any = None
    current_config_sha_reader: Any = None
    current_certificate_sha_reader: Any = None
    current_adblock_sha_reader: Any = None
    current_pac_sha_reader: Any = None
    current_policy_sha_reader: Any = None


def build_runtime_services(**overrides: Any) -> ProxyRuntimeServices:
    certs_dir = (
        os.environ.get("CERTS_DIR") or "/etc/squid/ssl/certs"
    ).strip() or "/etc/squid/ssl/certs"
    services = ProxyRuntimeServices(
        controller=SquidController(),
        registry=get_proxy_registry(),
        revisions=get_config_revisions(),
        certificate_bundles=get_certificate_bundles(),
        adblock_artifacts=get_adblock_artifacts(),
        cert_manager=CertManager(certs_dir),
        adblock_store=get_adblock_store(),
        live_stats_store=get_store(),
        diagnostic_store=get_diagnostic_store(),
        timeseries_store=get_timeseries_store(),
        ssl_errors_store=get_ssl_errors_store(),
        stats_provider=get_stats,
        runtime_services_builder=build_local_runtime_services,
        policy_state_builder=build_proxy_policy_state,
        pac_state_builder=build_proxy_pac_state,
    )
    return replace(services, **overrides) if overrides else services


def _call_health_check(func, /, **kwargs):
    try:
        return func(**kwargs)
    except TypeError:
        return func()


def _health_timeout_detail(name: str, timeout: float) -> str:
    service = {
        "icap": "adblock ICAP",
        "av_icap": "c-icap AV",
        "clamd": "clamd",
    }.get(name, name)
    return f"{service} health probe timed out after {timeout:.2f}s"


def _log_recoverable_db_or_unexpected(
    key: str,
    *,
    recoverable_message: str,
    unexpected_message: str,
    exc: BaseException,
    interval_seconds: float = 30.0,
) -> None:
    if isinstance(exc, DATABASE_ERRORS):
        if should_log(key, interval_seconds=interval_seconds):
            logger.warning(
                "%s: %s",
                recoverable_message,
                public_error_message(exc, default="Database is unavailable."),
            )
        return
    log_exception_throttled(
        logger,
        key,
        interval_seconds=interval_seconds,
        message=unexpected_message,
    )


def build_local_runtime_services(
    *,
    error_formatter=str,
    icap_timeout: float = 0.8,
    tcp_timeout: float = 0.75,
) -> dict[str, dict[str, Any]]:
    # Keep management health bounded by the slowest local probe instead of the
    # sum of every ICAP/ClamAV timeout. The Admin UI calls this endpoint with a
    # short timeout on page loads, so sequential checks can create false
    # proxy-management timeouts when one or more optional services are absent.
    checks = {
        "icap": (
            _check_icap_adblock,
            {"timeout": icap_timeout, "error_formatter": error_formatter},
        ),
        "av_icap": (
            _check_icap_av,
            {"timeout": icap_timeout, "error_formatter": error_formatter},
        ),
        "clamd": (
            _check_clamd,
            {"timeout": tcp_timeout, "error_formatter": error_formatter},
        ),
    }
    deadlines = {
        "icap": max(float(icap_timeout) + 0.5, 1.0),
        "av_icap": max(float(icap_timeout) + 0.5, 1.0),
        "clamd": max(float(tcp_timeout) + 0.5, 1.0),
    }
    results: dict[str, dict[str, Any]] = {}
    executor = ThreadPoolExecutor(
        max_workers=len(checks),
        thread_name_prefix="proxy-health",
    )
    try:
        futures = {
            name: executor.submit(_call_health_check, func, **kwargs)
            for name, (func, kwargs) in checks.items()
        }
        started_mono = time.monotonic()
        for name, future in futures.items():
            remaining = max(deadlines[name] - (time.monotonic() - started_mono), 0.0)
            try:
                results[name] = future.result(timeout=remaining)
            except FutureTimeoutError:
                future.cancel()
                results[name] = {
                    "ok": False,
                    "detail": _health_timeout_detail(name, deadlines[name]),
                }
            except Exception as exc:
                results[name] = {
                    "ok": False,
                    "detail": error_formatter(exc) if error_formatter else str(exc),
                }
    finally:
        executor.shutdown(wait=False, cancel_futures=True)

    clamd = results.get("clamd") or {"ok": False, "detail": "clamd health unavailable"}
    av_icap = results.get("av_icap") or {
        "ok": False,
        "detail": "c-icap av health unavailable",
    }
    return {
        "icap": results.get("icap")
        or {"ok": False, "detail": "adblock ICAP health unavailable"},
        "av_icap": av_icap,
        "clamd": clamd,
        "clamav": build_clamav_health(clamd, av_icap),
    }


def _listener_mode_summary(listeners: object) -> str:
    try:
        parts = []
        for item in listeners or []:
            port = int(
                getattr(item, "get", lambda _key, _default=None: _default)("port", 0)
                or 0,
            )
            mode = str(
                getattr(item, "get", lambda _key, _default=None: _default)(
                    "mode",
                    "explicit",
                )
                or "explicit",
            )
            if port:
                parts.append(f"{mode}:{port}")
        return ", ".join(parts)
    except Exception:
        return ""


def _short_sha(value: object) -> str:
    text = str(value or "").strip()
    return text[:12] if text else "missing"


def _state_drift_detail(label: str, desired_sha: object, current_sha: object) -> str:
    desired = str(desired_sha or "").strip()
    current = str(current_sha or "").strip()
    if not desired or desired == current:
        return ""
    return (
        f"{label}: desired {_short_sha(desired)} does not match "
        f"current {_short_sha(current)}."
    )


def _state_sync_failure_detail(
    label: str,
    base_detail: str,
    *,
    desired_sha: object,
    current_sha: object,
) -> str:
    detail = str(base_detail or "").strip()
    drift = _state_drift_detail(label, desired_sha, current_sha)
    if not drift:
        drift = (
            f"{label}: desired {_short_sha(desired_sha)}; "
            f"current {_short_sha(current_sha)}."
        )
    return "\n".join(part for part in (detail, drift) if part).strip()


def _decode_completed(proc: Any) -> str:
    stdout_text = _decode_bytes(getattr(proc, "stdout", b""))
    stderr_text = _decode_bytes(getattr(proc, "stderr", b""))
    if stdout_text and stderr_text:
        return (stdout_text + "\n" + stderr_text).strip()
    return (stdout_text or stderr_text).strip()


class ProxyRuntime:
    def __init__(self, *, services: ProxyRuntimeServices | None = None) -> None:
        self.services = services or build_runtime_services()
        self.controller = self.services.controller
        self.registry = self.services.registry
        self.revisions = self.services.revisions
        self.certificate_bundles = self.services.certificate_bundles
        self.adblock_artifacts = self.services.adblock_artifacts
        self.cert_manager = self.services.cert_manager
        self.adblock_store = self.services.adblock_store
        self.live_stats_store = self.services.live_stats_store
        self.diagnostic_store = self.services.diagnostic_store
        self.timeseries_store = self.services.timeseries_store
        self.ssl_errors_store = self.services.ssl_errors_store
        self.stats_provider = self.services.stats_provider
        self.runtime_services_builder = self.services.runtime_services_builder
        self.policy_state_builder = self.services.policy_state_builder
        self.pac_state_builder = self.services.pac_state_builder
        self.ssl_db_dir = (
            os.environ.get("SSL_DB_DIR") or "/var/lib/ssl_db/store"
        ).strip() or "/var/lib/ssl_db/store"
        self.adblock_compiled_dir = (
            os.environ.get("ADBLOCK_COMPILED_DIR")
            or self.adblock_artifacts.compiled_dir
        ).strip() or self.adblock_artifacts.compiled_dir
        self.pac_render_dir = (
            os.environ.get("PAC_RENDER_DIR") or PAC_RENDER_DIR
        ).strip() or PAC_RENDER_DIR
        try:
            self.health_cache_ttl_seconds = max(
                0.0,
                min(
                    120.0,
                    float(
                        (
                            os.environ.get("PROXY_HEALTH_CACHE_TTL_SECONDS") or "10.0"
                        ).strip()
                        or "10.0",
                    ),
                ),
            )
        except Exception:
            self.health_cache_ttl_seconds = 10.0
        self._health_cache_lock = threading.Lock()
        self._health_refresh_lock = threading.Lock()
        self._health_cache_ts = 0.0
        self._health_cache_value: dict[str, Any] | None = None
        self._navigation_health_cache_ts = 0.0
        self._navigation_health_cache_value: dict[str, Any] | None = None
        self._adblock_icap_health_failures = 0
        self._adblock_icap_last_restart_ts = 0.0

    @property
    def proxy_id(self) -> str:
        return get_proxy_id()

    def ensure_registered(self) -> None:
        self.registry.register_local_proxy()

    def _invalidate_health_cache(self) -> None:
        with self._health_cache_lock:
            self._health_cache_ts = 0.0
            self._health_cache_value = None
            self._navigation_health_cache_ts = 0.0
            self._navigation_health_cache_value = None

    def _current_config_sha(self) -> str:
        if self.services.current_config_sha_reader is not None:
            return str(self.services.current_config_sha_reader() or "")
        current = self.controller.get_current_config() or ""
        if not current:
            return ""
        normalizer = getattr(self.controller, "normalize_config_text", None)
        if callable(normalizer):
            current = normalizer(current)
        return hashlib.sha256(current.encode("utf-8", errors="replace")).hexdigest()

    def _current_adblock_enabled(self) -> bool:
        """Read persisted UI adblock routing state for generated Squid includes."""
        try:
            settings = self.adblock_store.get_settings()
        except Exception:
            logger.exception(
                "Failed to read adblock settings; defaulting Squid routing enabled"
            )
            return True
        if isinstance(settings, dict):
            value = settings.get("enabled", True)
        else:
            value = getattr(settings, "enabled", True)
        return _bool_setting(value, default=True)

    def _current_certificate_bundle_sha(self) -> str:
        if self.services.current_certificate_sha_reader is not None:
            return str(self.services.current_certificate_sha_reader() or "")
        bundle = self.cert_manager.load_bundle()
        return bundle.bundle_sha256 if bundle is not None else ""

    def _read_text_file(self, path: str) -> str:
        try:
            with pathlib.Path(path).open(encoding="utf-8") as fh:
                return fh.read()
        except FileNotFoundError:
            return ""
        except Exception:
            return ""

    def _atomic_write_text(self, path: str, content: str) -> None:
        directory = pathlib.Path(path).parent or "."
        pathlib.Path(directory).mkdir(exist_ok=True, parents=True)
        handle = None
        tmp_path = ""
        try:
            handle = tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                delete=False,
                dir=directory,
                prefix=".tmp-",
            )
            tmp_path = handle.name
            handle.write(content)
            handle.flush()
            handle.close()
            handle = None
            pathlib.Path(tmp_path).replace(path)
        finally:
            if handle is not None:
                with suppress(Exception):
                    handle.close()
            if tmp_path and pathlib.Path(tmp_path).exists():
                with suppress(Exception):
                    pathlib.Path(tmp_path).unlink()

    def _current_policy_sha(self) -> str:
        if self.services.current_policy_sha_reader is not None:
            return str(self.services.current_policy_sha_reader() or "")
        desired = self.policy_state_builder(self.proxy_id)
        current_files = tuple(
            MaterializedPolicyFile(
                path=item.path,
                content=self._read_text_file(item.path),
            )
            for item in desired.files
        )
        return calculate_policy_sha(current_files)

    def _policy_materialization_integrity(
        self,
        desired: Any,
        *,
        current_sha: str | None = None,
    ) -> tuple[bool, str]:
        current = (
            str(current_sha or "").strip()
            if current_sha is not None
            else self._current_policy_sha()
        )
        expected = str(getattr(desired, "policy_sha256", "") or "").strip()
        if current != expected:
            return False, "policy marker does not match the active policy state."

        for item in tuple(getattr(desired, "files", ()) or ()):
            path = pathlib.Path(str(getattr(item, "path", "") or ""))
            if not path.exists():
                return False, f"policy materialized file is missing: {path}"
            current_content = self._read_text_file(str(path))
            desired_content = str(getattr(item, "content", "") or "")
            if current_content != desired_content:
                return False, f"policy materialized file is stale: {path}"
        return True, ""

    def _current_adblock_artifact_sha(self) -> str:
        if self.services.current_adblock_sha_reader is not None:
            return str(self.services.current_adblock_sha_reader() or "")
        return read_materialized_artifact_sha(self.adblock_compiled_dir)

    def _active_adblock_lookup_rule_count(self) -> int | None:
        try:
            summary = self.adblock_artifacts.get_active_artifact_summary()
        except Exception:
            return None
        if summary is None:
            return None
        report: dict[str, Any]
        try:
            raw_report = getattr(summary, "report", None)
            if isinstance(raw_report, dict):
                report = raw_report
            else:
                report = json.loads(str(getattr(summary, "report_json", "") or "{}"))
        except Exception:
            return None
        try:
            lookup_counts = (report.get("breakdowns") or {}).get(
                "lookup_index_counts",
            ) or {}
            return max(0, int(lookup_counts.get("rules") or 0))
        except Exception:
            return None

    def _adblock_materialization_integrity(
        self,
        expected_sha: str,
        *,
        current_sha: str | None = None,
    ) -> tuple[bool, str]:
        current = (
            str(current_sha or "").strip()
            if current_sha is not None
            else self._current_adblock_artifact_sha()
        )
        expected = str(expected_sha or "").strip()
        if current != expected:
            return False, "adblock artifact marker does not match the active artifact."

        lookup_path = pathlib.Path(self.adblock_compiled_dir) / "request_lookup.sqlite"
        if not lookup_path.exists():
            return False, "adblock request lookup database is missing."

        try:
            conn = sqlite3.connect(str(lookup_path))
            try:
                row = conn.execute(
                    "SELECT value FROM metadata WHERE key='count_rules'",
                ).fetchone()
            finally:
                conn.close()
        except Exception as exc:
            detail = public_error_message(
                exc,
                default="adblock request lookup database could not be inspected.",
            )
            return False, detail

        expected_rules = self._active_adblock_lookup_rule_count()
        if expected_rules is None:
            return True, ""

        try:
            actual_rules = int(row[0]) if row else 0
        except Exception:
            actual_rules = 0
        if actual_rules != expected_rules:
            return (
                False,
                f"adblock request lookup rule count {actual_rules} does not match active artifact count {expected_rules}.",
            )
        return True, ""

    def _current_pac_state_sha(self) -> str:
        if self.services.current_pac_sha_reader is not None:
            return str(self.services.current_pac_sha_reader() or "")
        return read_materialized_pac_state_sha(self.pac_render_dir)

    def _pac_materialization_integrity(
        self,
        desired: Any,
        *,
        current_sha: str | None = None,
    ) -> tuple[bool, str]:
        current = (
            str(current_sha or "").strip()
            if current_sha is not None
            else self._current_pac_state_sha()
        )
        expected = str(getattr(desired, "state_sha256", "") or "").strip()
        if current != expected:
            return False, "PAC state marker does not match the active PAC state."

        root = pathlib.Path(getattr(self, "pac_render_dir", PAC_RENDER_DIR))
        for item in tuple(getattr(desired, "files", ()) or ()):
            raw_rel = str(getattr(item, "relative_path", "") or "").replace("\\", "/")
            rel = os.path.normpath(raw_rel).replace("\\", "/")
            if not rel or rel.startswith(("../", "/")) or rel in {".", ".."}:
                return False, f"PAC state contains unsafe materialized path: {raw_rel}"
            path = root / rel
            if not path.exists():
                return False, f"PAC materialized file is missing: {rel}"
            try:
                current_content = path.read_text(encoding="utf-8", errors="replace")
            except Exception as exc:
                detail = public_error_message(
                    exc,
                    default=f"PAC materialized file could not be inspected: {rel}",
                )
                return False, detail
            desired_content = str(getattr(item, "content", "") or "")
            if current_content != desired_content:
                return False, f"PAC materialized file is stale: {rel}"
        return True, ""

    @staticmethod
    def _logical_supervisor_program_prefix(program_name: str) -> str:
        if program_name == "cicap_adblock" or program_name.startswith("cicap_adblock_"):
            return "cicap_adblock_"
        if program_name == "cicap_av" or program_name.startswith("cicap_av_"):
            return "cicap_av_"
        return ""

    def _supervisor_status_lines(
        self,
        *,
        timeout_seconds: int = 10,
        programs: tuple[str, ...] = (),
    ) -> tuple[bool, str, dict[str, str]]:
        args = ["supervisorctl", "-c", "/etc/supervisord.conf", "status", *programs]
        try:
            status = subprocess.run(
                args,
                capture_output=True,
                timeout=timeout_seconds,
            )
        except Exception as exc:
            detail = public_error_message(
                exc, default="Failed to inspect supervisor status."
            )
            return False, detail, {}
        detail = _decode_completed(status).strip()
        lines: dict[str, str] = {}
        for line in detail.splitlines():
            parts = line.split(None, 2)
            if parts:
                lines[parts[0]] = line.strip()
        return status.returncode == 0, detail, lines

    def _resolve_supervisor_program_names(
        self,
        program_name: str,
        *,
        timeout_seconds: int = 10,
    ) -> tuple[list[str], str]:
        prefix = self._logical_supervisor_program_prefix(program_name)
        if not prefix:
            return [program_name], ""
        configured = list(_icap_supervisor_programs(program_name))
        _ok, detail, lines = self._supervisor_status_lines(
            timeout_seconds=timeout_seconds
        )
        matches = sorted(
            name for name in lines if name == program_name or name.startswith(prefix)
        )
        if matches:
            return matches, detail
        if configured != [program_name]:
            return configured, detail
        return [program_name], detail

    def _supervisor_program_status_exact(
        self,
        program_name: str,
        *,
        timeout_seconds: int = 10,
        accepted_states: tuple[str, ...] = ("RUNNING",),
    ) -> tuple[bool, str]:
        _ok, detail, lines = self._supervisor_status_lines(
            timeout_seconds=timeout_seconds,
            programs=(program_name,),
        )
        detail = detail or f"{program_name} status unavailable."
        for line in lines.values():
            parts = line.split(None, 2)
            if parts and parts[0] == program_name:
                return len(parts) > 1 and parts[1] in accepted_states, detail
        return False, detail

    def _supervisor_program_status(
        self,
        program_name: str,
        *,
        timeout_seconds: int = 10,
        accepted_states: tuple[str, ...] = ("RUNNING",),
    ) -> tuple[bool, str]:
        prefix = self._logical_supervisor_program_prefix(program_name)
        configured = list(_icap_supervisor_programs(program_name))
        if prefix:
            _ok, detail, lines = self._supervisor_status_lines(
                timeout_seconds=timeout_seconds
            )
            matching = [
                line
                for name, line in sorted(lines.items())
                if name in configured or name == program_name or name.startswith(prefix)
            ]
            if matching:
                ok = all(
                    len(parts := line.split(None, 2)) > 1
                    and parts[1] in accepted_states
                    for line in matching
                )
                return ok, "\n".join(matching)
            if configured != [program_name] and detail:
                return False, detail

        return self._supervisor_program_status_exact(
            program_name,
            timeout_seconds=timeout_seconds,
            accepted_states=accepted_states,
        )

    def _supervisor_programs_health(self) -> dict[str, Any]:
        programs = ("squid", "cicap_adblock", "cicap_av", "proxy_api", "proxy_agent")
        statuses: dict[str, dict[str, Any]] = {
            program: {"ok": False, "detail": f"{program} status unavailable."}
            for program in programs
        }
        ok_status, output, lines = self._supervisor_status_lines(timeout_seconds=2)
        if not ok_status and not lines:
            detail = output or "Failed to inspect supervisor status."
            return {
                "ok": False,
                "detail": detail,
                "programs": {
                    program: {"ok": False, "detail": detail} for program in programs
                },
            }

        for program in programs:
            prefix = self._logical_supervisor_program_prefix(program)
            matched = [
                line
                for name, line in sorted(lines.items())
                if name == program or (prefix and name.startswith(prefix))
            ]
            if not matched:
                continue
            statuses[program] = {
                "ok": all(
                    len(parts := line.split(None, 2)) > 1 and parts[1] == "RUNNING"
                    for line in matched
                ),
                "detail": "\n".join(matched),
            }

        detail_parts = [
            str(item.get("detail") or "")
            for item in statuses.values()
            if not item.get("ok")
        ]
        ok = not detail_parts
        return {
            "ok": ok,
            "detail": "; ".join(part for part in detail_parts if part)
            if detail_parts
            else "supervisor programs running",
            "programs": statuses,
        }

    def _operation_ledger_health(self) -> dict[str, Any]:
        try:
            counts = get_operation_ledger().counts_by_status(self.proxy_id)
        except Exception as exc:
            detail = public_error_message(
                exc,
                default="Proxy operation ledger is unavailable.",
            )
            return {
                "ok": False,
                "detail": detail,
                "counts": {},
            }

        normalized_counts = {
            status: max(0, int(counts.get(status) or 0))
            for status in ("pending", "applying", "applied", "superseded", "failed")
        }
        return {
            "ok": True,
            "detail": (
                "operation ledger reachable; "
                f"pending={normalized_counts['pending']} "
                f"applying={normalized_counts['applying']} "
                f"failed={normalized_counts['failed']}"
            ),
            "counts": normalized_counts,
        }

    def test_control_supervisor_program(
        self,
        program_name: str,
        *,
        action: str,
        timeout_seconds: int = 30,
    ) -> dict[str, Any]:
        """Test-mode-only supervisor control for live recovery tests.

        The management route that calls this method is gated by ENABLE_TEST_MODE
        and token auth. Keep a second allowlist here so the helper never becomes
        an arbitrary supervisorctl wrapper if a route is miswired.
        """
        self._invalidate_health_cache()
        allowed_programs = {"squid", "cicap_adblock", "cicap_av"}
        program = (program_name or "").strip()
        requested_action = (action or "").strip().lower()
        if program not in allowed_programs:
            return {
                "ok": False,
                "proxy_id": self.proxy_id,
                "program": program,
                "action": requested_action,
                "detail": "Program is not allowlisted for test supervisor control.",
            }
        if requested_action == "status":
            ok, detail = self._supervisor_program_status(
                program,
                timeout_seconds=timeout_seconds,
            )
            return {
                "ok": ok,
                "proxy_id": self.proxy_id,
                "program": program,
                "action": requested_action,
                "detail": detail,
            }
        if requested_action == "restart":
            if program == "squid":
                ok, detail = self.controller.restart_squid()
            else:
                ok, detail = self._restart_supervisor_program(
                    program,
                    timeout_seconds=timeout_seconds,
                    stop_on_failure=False,
                )
            return {
                "ok": ok,
                "proxy_id": self.proxy_id,
                "program": program,
                "action": requested_action,
                "detail": detail,
            }
        if requested_action not in {"stop", "start"}:
            return {
                "ok": False,
                "proxy_id": self.proxy_id,
                "program": program,
                "action": requested_action,
                "detail": "Unsupported test supervisor action.",
            }
        programs, resolve_detail = self._resolve_supervisor_program_names(
            program,
            timeout_seconds=timeout_seconds,
        )
        details = [str(resolve_detail or "").strip()] if len(programs) > 1 else []
        ok = True
        for supervisor_program in programs:
            try:
                proc = subprocess.run(
                    [
                        "supervisorctl",
                        "-c",
                        "/etc/supervisord.conf",
                        requested_action,
                        supervisor_program,
                    ],
                    capture_output=True,
                    timeout=timeout_seconds,
                )
            except Exception as exc:
                ok = False
                details.append(
                    public_error_message(
                        exc,
                        default=f"Failed to {requested_action} {supervisor_program}.",
                    )
                )
                continue
            details.append(
                _decode_completed(proc).strip()
                or f"{supervisor_program} {requested_action} requested."
            )
            ok = ok and proc.returncode == 0
        detail = (
            "\n".join(part for part in details if part)
            or f"{program} {requested_action} requested."
        )
        if requested_action == "start" and ok:
            status_ok, status_detail = self._supervisor_program_status(
                program,
                timeout_seconds=timeout_seconds,
            )
            ok = status_ok
            if status_detail:
                detail = f"{detail}\n{status_detail}"
        return {
            "ok": ok,
            "proxy_id": self.proxy_id,
            "program": program,
            "action": requested_action,
            "detail": detail,
        }

    def _restart_supervisor_program(
        self,
        program_name: str,
        *,
        timeout_seconds: int = 30,
        stop_on_failure: bool = False,
    ) -> tuple[bool, str]:
        with _exclusive_runtime_lock("supervisor", _SUPERVISOR_CONTROL_LOCK):
            ok, detail = self._restart_supervisor_program_unlocked(
                program_name,
                timeout_seconds=timeout_seconds,
                stop_on_failure=stop_on_failure,
            )
            if ok or self._logical_supervisor_program_prefix(program_name) == "":
                return ok, detail
            if "no such process" not in str(detail or "").lower():
                return ok, detail

            programs, resolve_detail = self._resolve_supervisor_program_names(
                program_name,
                timeout_seconds=timeout_seconds,
            )
            scaled_programs = [
                program for program in programs if program != program_name
            ]
            if not scaled_programs:
                return ok, detail
            results = [
                self._restart_supervisor_program_unlocked(
                    program,
                    timeout_seconds=timeout_seconds,
                    stop_on_failure=stop_on_failure,
                )
                for program in scaled_programs
            ]
            detail_parts = [
                str(part or "").strip() for part in (detail, resolve_detail)
            ]
            detail_parts.extend(
                str(result_detail or "").strip() for _ok, result_detail in results
            )
            return all(result_ok for result_ok, _detail in results), "\n".join(
                part for part in detail_parts if part
            )

    def _wait_for_supervisor_program_stopped(
        self,
        program_name: str,
        *,
        timeout_seconds: float = 30.0,
    ) -> tuple[bool, str]:
        deadline = time.time() + max(1.0, float(timeout_seconds))
        last_detail = ""
        while time.time() < deadline:
            try:
                proc = subprocess.run(
                    [
                        "supervisorctl",
                        "-c",
                        "/etc/supervisord.conf",
                        "status",
                        program_name,
                    ],
                    capture_output=True,
                    timeout=min(8.0, max(1.0, deadline - time.time())),
                )
                last_detail = _decode_completed(proc).strip()
                upper = last_detail.upper()
                if any(
                    state in upper
                    for state in ("STOPPED", "EXITED", "FATAL", "BACKOFF", "UNKNOWN")
                ):
                    return True, last_detail
                if (
                    proc.returncode != 0
                    and "RUNNING" not in upper
                    and "STARTING" not in upper
                    and "STOPPING" not in upper
                ):
                    return True, last_detail
            except Exception as exc:
                last_detail = public_error_message(
                    exc,
                    default=f"Failed to check {program_name} supervisor status.",
                )
            time.sleep(0.5)
        return False, last_detail or f"Timed out waiting for {program_name} to stop."

    def _restart_supervisor_program_unlocked(
        self,
        program_name: str,
        *,
        timeout_seconds: int = 30,
        stop_on_failure: bool = False,
    ) -> tuple[bool, str]:
        details: list[str] = []
        try:
            stop = subprocess.run(
                ["supervisorctl", "-c", "/etc/supervisord.conf", "stop", program_name],
                capture_output=True,
                timeout=timeout_seconds,
            )
        except Exception as exc:
            details.append(
                public_error_message(exc, default=f"Failed to stop {program_name}."),
            )
        else:
            stop_detail = (
                _decode_completed(stop).strip() or f"{program_name} stop requested."
            )
            details.append(stop_detail)

        stopped_ok, stopped_detail = self._wait_for_supervisor_program_stopped(
            program_name,
            timeout_seconds=timeout_seconds,
        )
        if stopped_detail and stopped_detail not in details:
            details.append(stopped_detail)
        if not stopped_ok:
            status_checker = (
                self._supervisor_program_status_exact
                if self._logical_supervisor_program_prefix(program_name)
                else self._supervisor_program_status
            )
            status_ok, status_detail = status_checker(
                program_name,
                timeout_seconds=timeout_seconds,
            )
            if status_detail and status_detail not in details:
                details.append(status_detail)
            if status_ok:
                details.append(f"{program_name} was already restarted by supervisor.")
                return True, "\n".join(
                    part for part in details if part
                ).strip() or f"{program_name} restarted."
            return False, "\n".join(
                part for part in details if part
            ).strip() or f"Failed to stop {program_name} before restart."

        for attempt in range(1, 6):
            if attempt > 1:
                time.sleep(1.0)
            try:
                start = subprocess.run(
                    [
                        "supervisorctl",
                        "-c",
                        "/etc/supervisord.conf",
                        "start",
                        program_name,
                    ],
                    capture_output=True,
                    timeout=timeout_seconds,
                )
            except Exception as exc:
                details.append(
                    public_error_message(
                        exc,
                        default=f"Failed to start {program_name}.",
                    ),
                )
                continue

            start_detail = (
                _decode_completed(start).strip() or f"{program_name} start requested."
            )
            details.append(start_detail)

            # A quick start can still crash immediately afterward. Require a
            # post-start supervisor status check to avoid accepting restart loops.
            time.sleep(1.0)
            status_ok, status_detail = self._supervisor_program_status_exact(
                program_name,
                timeout_seconds=timeout_seconds,
                accepted_states=("RUNNING", "STARTING"),
            )
            if status_detail:
                details.append(status_detail)
            if status_ok:
                return True, "\n".join(
                    part for part in details if part
                ).strip() or f"{program_name} restarted."

        if stop_on_failure:
            try:
                stop = subprocess.run(
                    [
                        "supervisorctl",
                        "-c",
                        "/etc/supervisord.conf",
                        "stop",
                        program_name,
                    ],
                    capture_output=True,
                    timeout=timeout_seconds,
                )
                stop_detail = _decode_completed(stop).strip()
                if stop_detail:
                    details.append(stop_detail)
            except Exception:
                pass
        return False, "\n".join(
            part for part in details if part
        ).strip() or f"Failed to restart {program_name}."

    def _restart_adblock_service(self) -> tuple[bool, str]:
        if self.services.adblock_service_restarter is not None:
            return self.services.adblock_service_restarter()
        ok, detail = self._restart_supervisor_program(
            "cicap_adblock",
            stop_on_failure=True,
        )
        if not ok:
            return ok, detail
        deadline = time.time() + 15.0
        last_health: dict[str, Any] = {}
        while time.time() < deadline:
            last_health = _check_icap_adblock(timeout=1.0, error_formatter=str)
            if bool(last_health.get("ok")):
                health_detail = str(
                    last_health.get("detail") or "adblock ICAP health check passed.",
                )
                return True, "\n".join(
                    part for part in (detail, health_detail) if str(part or "").strip()
                ).strip()
            time.sleep(0.5)
        health_detail = str(
            last_health.get("detail")
            or "adblock ICAP health check did not pass after restart.",
        )
        return False, "\n".join(
            part for part in (detail, health_detail) if str(part or "").strip()
        ).strip()

    def _snapshot_adblock_compiled_dir(self) -> str:
        snapshot_root = tempfile.mkdtemp(prefix="adblock-compiled-snapshot-")
        snapshot_dir = os.path.join(snapshot_root, "compiled")
        if pathlib.Path(self.adblock_compiled_dir).is_dir():
            shutil.copytree(self.adblock_compiled_dir, snapshot_dir, dirs_exist_ok=True)
        else:
            pathlib.Path(snapshot_dir).mkdir(exist_ok=True, parents=True)
        return snapshot_root

    def _restore_adblock_compiled_snapshot(self, snapshot_root: str) -> None:
        snapshot_dir = os.path.join(snapshot_root, "compiled")
        if pathlib.Path(self.adblock_compiled_dir).is_dir():
            shutil.rmtree(self.adblock_compiled_dir, ignore_errors=True)
        pathlib.Path(pathlib.Path(self.adblock_compiled_dir).parent or ".").mkdir(
            exist_ok=True,
            parents=True,
        )
        shutil.copytree(snapshot_dir, self.adblock_compiled_dir, dirs_exist_ok=True)

    def _ensure_policy_runtime_config(self) -> tuple[bool, str, bool]:
        controller = getattr(self, "controller", None)
        current_reader = getattr(controller, "get_current_config", None)
        normalizer = getattr(controller, "normalize_config_text", None)
        apply_config = getattr(controller, "apply_config_text", None)
        if not (
            callable(current_reader) and callable(normalizer) and callable(apply_config)
        ):
            return True, "", False
        try:
            current = current_reader() or ""
            normalized = normalizer(current)
        except Exception as exc:
            return (
                False,
                public_error_message(
                    exc,
                    default="Failed to inspect Squid config before policy reload.",
                ),
                False,
            )
        if normalized == current:
            return True, "", False
        ok, detail = apply_config(normalized)
        if ok:
            return (
                True,
                (
                    detail.strip()
                    or "Squid config normalized for generated policy includes."
                ),
                True,
            )
        return (
            False,
            (
                detail.strip()
                or "Failed to normalize Squid config for generated policy includes."
            ),
            False,
        )

    def _reload_for_policy_update(
        self,
        *,
        wait_for_adblock_icap: bool = True,
    ) -> tuple[bool, str]:
        # Policy materialization changes included ACL files, external ACL inputs,
        # and the local adblock ICAP service revision. A full Squid process restart is too
        # disruptive during live policy churn: Squid drains helper children slowly
        # under active proxied traffic, supervisor eventually SIGKILLs it, and the
        # proxy/admin test stack can hang behind half-closed sockets. Reconfigure is
        # the correct first-line operation for include/ACL changes because it reloads
        # the active config while keeping the listener stable.
        try:
            reconfigure_squid = getattr(self.controller, "reconfigure_squid", None)
            if callable(reconfigure_squid):
                ok, detail = reconfigure_squid(timeout=15, listener_timeout=10.0)
            else:
                proc = self.controller._run(
                    ["squid", "-k", "reconfigure"],
                    capture_output=True,
                    timeout=15,
                )
                detail = _decode_completed(proc).strip()
                ok = int(getattr(proc, "returncode", 1) or 0) == 0
        except Exception as exc:
            return False, public_error_message(
                exc,
                default="Squid reconfigure failed for policy update.",
            )
        detail = str(detail or "").strip()
        if ok and not callable(getattr(self.controller, "reconfigure_squid", None)):
            try:
                ok = bool(self.controller._wait_for_http_listener(timeout=10.0))
            except Exception:
                ok = True
        if ok and wait_for_adblock_icap:
            # Squid can accept TCP connections before ICAP OPTIONS/helper state has
            # fully converged after rapid policy/adblock churn. Wait for the local
            # adblock ICAP service too so the sync API does not hand traffic back to
            # callers while first requests can still bypass or hang on adaptation.
            deadline = time.time() + 15.0
            last_icap: dict[str, Any] = {}
            while time.time() < deadline:
                last_icap = _check_icap_adblock(timeout=1.0, error_formatter=str)
                if bool(last_icap.get("ok")):
                    break
                time.sleep(0.5)
            else:
                ok = False
                icap_detail = str(
                    last_icap.get("detail")
                    or "adblock ICAP health check did not pass after policy reload.",
                )
                detail = "\n".join(
                    part for part in (detail, icap_detail) if str(part or "").strip()
                ).strip()
        if ok:
            success_detail = "Squid reconfigured for policy update."
            if success_detail not in detail:
                detail = "\n".join(
                    part for part in (detail, success_detail) if str(part or "").strip()
                ).strip()
        return bool(ok), detail or (
            "Squid reconfigured for policy update."
            if ok
            else "Squid reconfigure failed for policy update."
        )

    def validate_config_text(self, config_text: str) -> dict[str, Any]:
        normalized = self.controller.normalize_config_text(config_text or "")
        ok, detail = self.controller.validate_config_text(normalized)
        return {
            "ok": bool(ok),
            "proxy_id": self.proxy_id,
            "detail": str(
                detail
                or (
                    "Squid config validation succeeded."
                    if ok
                    else "Squid config validation failed."
                ),
            ),
            "config_sha256": hashlib.sha256(
                normalized.encode("utf-8", errors="replace"),
            ).hexdigest()
            if normalized
            else "",
        }

    def rollback_last_known_good_config(self, *, reason: str = "") -> dict[str, Any]:
        self._invalidate_health_cache()
        ok, detail = self.controller.restore_last_known_good_config(
            reason=reason or "Rollback requested.",
        )
        current_sha = self._current_config_sha()
        with suppress(Exception):
            self.registry.mark_apply_result(
                self.proxy_id,
                ok=ok,
                detail=detail,
                current_config_sha=current_sha,
            )
        return {
            "ok": bool(ok),
            "proxy_id": self.proxy_id,
            "changed": bool(ok),
            "rolled_back": bool(ok),
            "current_config_sha": current_sha,
            "detail": detail,
        }

    def self_heal_config_if_needed(
        self,
        *,
        reason: str = "health check",
    ) -> dict[str, Any]:
        try:
            stdout, stderr = self.controller.get_status()
            status_detail = (
                _decode_bytes(stdout) + "\n" + _decode_bytes(stderr)
            ).strip()
            proxy_ok = not bool(stderr)
        except Exception as exc:
            status_detail = str(exc)
            proxy_ok = False

        listener_ok = True
        try:
            listener_ok = bool(self.controller._wait_for_http_listener(timeout=1.0))
        except Exception:
            listener_ok = proxy_ok

        if proxy_ok and listener_ok:
            return {
                "ok": True,
                "proxy_id": self.proxy_id,
                "changed": False,
                "rolled_back": False,
                "detail": status_detail or "Squid is healthy.",
            }

        detail_reason = f"Self-heal triggered by {reason}: {status_detail or 'Squid health check failed.'}"
        return self.rollback_last_known_good_config(reason=detail_reason)

    def self_heal_runtime_services_if_needed(
        self,
        *,
        reason: str = "health check",
    ) -> dict[str, Any]:
        status_ok, status_detail = self._supervisor_program_status(
            "cicap_adblock",
            timeout_seconds=5,
            accepted_states=("RUNNING", "STARTING"),
        )
        status_starting = any(
            len(parts := line.split(None, 2)) > 1
            and (parts[0] == "cicap_adblock" or parts[0].startswith("cicap_adblock_"))
            and parts[1] == "STARTING"
            for line in str(status_detail or "").splitlines()
        )
        if status_ok and status_starting:
            return {
                "ok": True,
                "proxy_id": self.proxy_id,
                "changed": False,
                "detail": status_detail
                or "adblock ICAP helper is warming up under supervisor.",
            }

        icap_health = _check_icap_adblock(timeout=0.8, error_formatter=str)
        if status_ok and bool(icap_health.get("ok")):
            self._adblock_icap_health_failures = 0
            return {
                "ok": True,
                "proxy_id": self.proxy_id,
                "changed": False,
                "detail": status_detail or "adblock ICAP helper is healthy.",
            }

        if status_ok:
            failures = int(getattr(self, "_adblock_icap_health_failures", 0) or 0) + 1
            self._adblock_icap_health_failures = failures
            threshold = _adblock_icap_self_heal_failure_threshold()
            now = time.monotonic()
            last_restart_ts = float(
                getattr(self, "_adblock_icap_last_restart_ts", 0.0) or 0.0
            )
            cooldown_seconds = _adblock_icap_self_heal_restart_cooldown_seconds()
            cooldown_remaining = max(
                0.0,
                cooldown_seconds - (now - last_restart_ts),
            )
            if failures < threshold or cooldown_remaining > 0:
                return {
                    "ok": True,
                    "proxy_id": self.proxy_id,
                    "changed": False,
                    "detail": "\n".join(
                        part
                        for part in (
                            (
                                f"Self-heal observed adblock ICAP probe failure "
                                f"{failures}/{threshold} triggered by {reason}; "
                                "supervisor still reports the helper running, so "
                                "restart is deferred to avoid churn."
                            ),
                            (
                                f"Restart cooldown active for "
                                f"{cooldown_remaining:.0f}s."
                                if cooldown_remaining > 0
                                else ""
                            ),
                            status_detail,
                            str(icap_health.get("detail") or ""),
                        )
                        if str(part or "").strip()
                    ),
                }

        else:
            self._adblock_icap_health_failures = 0

        ok_restart, restart_detail = self._restart_adblock_service()
        if status_ok:
            self._adblock_icap_last_restart_ts = time.monotonic()
            self._adblock_icap_health_failures = 0
        return {
            "ok": bool(ok_restart),
            "proxy_id": self.proxy_id,
            "changed": True,
            "detail": "\n".join(
                part
                for part in (
                    f"Self-heal triggered by {reason}: {status_detail}",
                    str(icap_health.get("detail") or ""),
                    restart_detail,
                )
                if str(part or "").strip()
            ),
        }

    def _clear_disk_cache_and_refresh_runtime(self) -> tuple[bool, str]:
        cache_ok, cache_detail = self.controller.clear_disk_cache()
        detail_parts = [
            str(cache_detail or "").strip(),
        ]
        if not cache_ok:
            return (
                False,
                "\n".join(part for part in detail_parts if part).strip()
                or "Proxy cache clear failed.",
            )

        return (
            True,
            "\n".join(part for part in detail_parts if part).strip()
            or "Proxy disk cache cleared.",
        )

    def _find_sslcrtd_binary(self) -> str:
        candidates = [
            shutil.which("ssl_crtd"),
            "/usr/lib/squid/ssl_crtd",
            "/usr/libexec/squid/ssl_crtd",
            "/usr/lib/squid/security_file_certgen",
            "/usr/libexec/squid/security_file_certgen",
        ]
        for candidate in candidates:
            if (
                candidate
                and pathlib.Path(candidate).exists()
                and os.access(candidate, os.X_OK)
            ):
                return candidate
        return ""

    def _reinitialize_ssl_db_and_restart(self) -> tuple[bool, str]:
        if self.services.ssl_db_reinitializer is not None:
            return self.services.ssl_db_reinitializer()
        ssl_db_dir = self.ssl_db_dir
        if not ssl_db_dir.startswith("/") or ssl_db_dir in {
            "/",
            "/etc",
            "/usr",
            "/var",
            "/var/lib",
        }:
            return (
                False,
                f"Refusing to reinitialize ssl_db at unsafe path: {ssl_db_dir}",
            )

        details: list[str] = []
        try:
            stopped = subprocess.run(
                ["supervisorctl", "-c", "/etc/supervisord.conf", "stop", "squid"],
                capture_output=True,
                timeout=20,
            )
            decoded = _decode_completed(stopped)
            if decoded:
                details.append(decoded)
        except Exception as exc:
            details.append(f"supervisorctl stop squid failed: {exc}")
            try:
                fallback = subprocess.run(
                    ["squid", "-k", "shutdown"],
                    capture_output=True,
                    timeout=10,
                )
                decoded = _decode_completed(fallback)
                if decoded:
                    details.append(decoded)
            except Exception as inner_exc:
                details.append(f"squid shutdown fallback failed: {inner_exc}")

        parent_dir = pathlib.Path(ssl_db_dir).parent or "/var/lib/ssl_db"
        try:
            shutil.rmtree(ssl_db_dir, ignore_errors=True)
            pathlib.Path(parent_dir).mkdir(exist_ok=True, parents=True)
        except Exception as exc:
            details.append(f"Failed to clear ssl_db directory: {exc}")
            return False, "\n".join([part for part in details if part]).strip()

        init_script = "/scripts/init_ssl_db.sh"
        if pathlib.Path(init_script).exists():
            try:
                env = os.environ.copy()
                env["SSL_DB_DIR"] = ssl_db_dir
                initialized = subprocess.run(
                    ["sh", init_script],
                    capture_output=True,
                    timeout=90,
                    env=env,
                )
            except Exception as exc:
                details.append(f"Failed to run {init_script}: {exc}")
                return False, "\n".join([part for part in details if part]).strip()

            init_detail = _decode_completed(initialized)
            if initialized.returncode != 0:
                details.append(init_detail or f"{init_script} failed")
                return False, "\n".join([part for part in details if part]).strip()

            if init_detail:
                details.append(init_detail)
        else:
            helper = self._find_sslcrtd_binary()
            if not helper:
                details.append("Could not find ssl_crtd/security_file_certgen helper.")
                return False, "\n".join([part for part in details if part]).strip()

            try:
                initialized = subprocess.run(
                    [helper, "-c", "-s", ssl_db_dir, "-M", "16MB"],
                    capture_output=True,
                    timeout=90,
                )
            except Exception as exc:
                details.append(f"Failed to initialize ssl_db: {exc}")
                return False, "\n".join([part for part in details if part]).strip()

            if initialized.returncode != 0:
                details.append(
                    _decode_completed(initialized) or "ssl_crtd initialization failed",
                )
                return False, "\n".join([part for part in details if part]).strip()

            details.append(
                _decode_completed(initialized)
                or f"Reinitialized ssl_db at {ssl_db_dir}.",
            )
            try:
                repair = subprocess.run(
                    [
                        "sh",
                        "-lc",
                        'chmod 700 "$1" 2>/dev/null || true; [ -d "$1/certs" ] && chmod 750 "$1/certs" 2>/dev/null || true; if getent passwd squid >/dev/null 2>&1; then chown -R squid:squid "$(dirname "$1")"; fi',
                        "sh",
                        ssl_db_dir,
                    ],
                    capture_output=True,
                    timeout=20,
                )
                if repair.returncode != 0:
                    details.append(
                        _decode_completed(repair)
                        or "Failed to repair ssl_db ownership and permissions.",
                    )
                    return False, "\n".join([part for part in details if part]).strip()
            except Exception as exc:
                details.append(
                    f"Failed to repair ssl_db ownership and permissions: {exc}",
                )
                return False, "\n".join([part for part in details if part]).strip()

        try:
            pathlib.Path(ssl_db_dir).chmod(0o700)
            certs_dir = os.path.join(ssl_db_dir, "certs")
            if pathlib.Path(certs_dir).is_dir():
                pathlib.Path(certs_dir).chmod(0o750)
        except Exception:
            pass

        ok_restart, restart_detail = self.controller.restart_squid()
        if restart_detail:
            details.append(restart_detail)
        if ok_restart:
            return True, "\n".join([part for part in details if part]).strip()

        # Squid is supervised in foreground mode.  After ``supervisorctl stop`` the
        # process may legitimately be STOPPED; in that state a direct
        # ``squid -k shutdown`` fallback cannot signal a PID file and Squid reports
        # "ERROR (not running)"/"ERROR (abnormal termination)".  That is not a
        # truthful final runtime state unless supervisor still cannot bring Squid
        # back and the listener remains unavailable.
        status_ok, status_detail = self._supervisor_program_status(
            "squid",
            timeout_seconds=5,
            accepted_states=("RUNNING",),
        )
        if status_detail:
            details.append(status_detail)
        if status_ok:
            try:
                if bool(self.controller._wait_for_http_listener(timeout=20.0)):
                    details.append(
                        "Squid recovered after ssl_db reinitialization and its HTTP listener is responding.",
                    )
                    return True, "\n".join(
                        [part for part in details if part],
                    ).strip()
            except Exception as exc:
                details.append(f"Squid listener recovery check failed: {exc}")

        try:
            start = subprocess.run(
                ["supervisorctl", "-c", "/etc/supervisord.conf", "start", "squid"],
                capture_output=True,
                timeout=25,
            )
            start_detail = _decode_completed(start)
            if start_detail:
                details.append(start_detail)
        except Exception as exc:
            details.append(f"supervisorctl start squid recovery failed: {exc}")

        status_ok, status_detail = self._supervisor_program_status(
            "squid",
            timeout_seconds=5,
            accepted_states=("RUNNING",),
        )
        if status_detail:
            details.append(status_detail)
        if status_ok:
            try:
                if bool(self.controller._wait_for_http_listener(timeout=20.0)):
                    details.append(
                        "Squid recovered after ssl_db reinitialization and its HTTP listener is responding.",
                    )
                    return True, "\n".join(
                        [part for part in details if part],
                    ).strip()
            except Exception as exc:
                details.append(f"Squid listener recovery check failed: {exc}")

        return False, "\n".join([part for part in details if part]).strip()

    def _publish_webcat_snapshot_for_policy_sync(self) -> tuple[bool, str]:
        try:
            from tools.webcat_acl import _Db as WebCatSnapshotDb  # type: ignore

            snapshot_db = WebCatSnapshotDb()
            expected_built_ts = snapshot_db._load_remote_built_ts()
            if expected_built_ts <= 0:
                return True, "No web category snapshot build is available yet."
            if snapshot_db._build_snapshot_from_db(expected_built_ts=expected_built_ts):
                return True, "Web category snapshot is current."
            return (
                False,
                "Failed to publish local web category snapshot; proxy will use the last usable snapshot if present.",
            )
        except Exception as exc:
            return False, public_error_message(
                exc,
                default="Failed to publish local web category snapshot.",
            )

    @staticmethod
    def _policy_requires_webcat_snapshot(desired: Any) -> bool:
        for item in getattr(desired, "files", ()) or ():
            path = str(getattr(item, "path", "") or "")
            if not path.endswith("30-webfilter.conf"):
                continue
            content = str(getattr(item, "content", "") or "")
            if "webcat_acl.py" in content:
                return True
        return False

    def sync_policy_state(self, *, force: bool = False) -> dict[str, Any]:
        desired = self.policy_state_builder(self.proxy_id)
        if self._policy_requires_webcat_snapshot(desired):
            snapshot_ok, snapshot_detail = (
                self._publish_webcat_snapshot_for_policy_sync()
            )
        else:
            snapshot_ok, snapshot_detail = (
                True,
                "Web category snapshot not required for current policy.",
            )
        current_sha = self._current_policy_sha()
        integrity_ok, integrity_detail = self._policy_materialization_integrity(
            desired,
            current_sha=current_sha,
        )
        if not force and integrity_ok:
            return {
                "ok": True,
                "proxy_id": self.proxy_id,
                "changed": False,
                "reload_required": False,
                "policy_sha256": desired.policy_sha256,
                "current_policy_sha": desired.policy_sha256,
                "detail": "Proxy is already using the active policy materialization."
                if snapshot_ok
                else snapshot_detail,
                "degraded": not snapshot_ok,
            }

        changed_files: list[tuple[str, str]] = []
        try:
            for item in desired.files:
                path = pathlib.Path(str(item.path or ""))
                current_content = self._read_text_file(item.path)
                if path.exists() and current_content == item.content:
                    continue
                changed_files.append((item.path, item.content))
            if changed_files:
                write_managed_text_files(*changed_files)
        except Exception as exc:
            return {
                "ok": False,
                "proxy_id": self.proxy_id,
                "changed": False,
                "reload_required": False,
                "policy_sha256": desired.policy_sha256,
                "current_policy_sha": current_sha,
                "detail": _state_sync_failure_detail(
                    "policy",
                    public_error_message(
                        exc,
                        default="Failed to materialize policy state.",
                    ),
                    desired_sha=desired.policy_sha256,
                    current_sha=current_sha,
                ),
            }

        if not changed_files:
            return {
                "ok": True,
                "proxy_id": self.proxy_id,
                "changed": False,
                "reload_required": False,
                "policy_sha256": desired.policy_sha256,
                "current_policy_sha": desired.policy_sha256,
                "detail": "Policy materialization is already current."
                if snapshot_ok
                else snapshot_detail,
                "degraded": not snapshot_ok,
            }

        return {
            "ok": True,
            "proxy_id": self.proxy_id,
            "changed": True,
            "reload_required": True,
            "policy_sha256": desired.policy_sha256,
            "current_policy_sha": desired.policy_sha256,
            "previous_policy_sha": current_sha,
            "detail": "\n".join(
                part
                for part in (
                    f"Updated {len(changed_files)} local policy file(s)."
                    if snapshot_ok
                    else f"Updated {len(changed_files)} local policy file(s); {snapshot_detail}",
                    (
                        "Reapplied policy state because local materialization was stale: "
                        f"{integrity_detail.strip()}"
                    )
                    if integrity_detail.strip()
                    else "",
                )
                if part
            ),
            "degraded": not snapshot_ok,
        }

    def sync_adblock_state(self, *, force: bool = False) -> dict[str, Any]:
        revision_meta = self.adblock_artifacts.get_active_artifact_metadata()
        store = self.adblock_store
        store.init_db()
        flush_requested = bool(store.get_cache_flush_requested())
        current_sha = self._current_adblock_artifact_sha()

        if revision_meta is None:
            if not flush_requested:
                return {
                    "ok": True,
                    "proxy_id": self.proxy_id,
                    "changed": False,
                    "artifact_changed": False,
                    "cache_flushed": False,
                    "revision_id": None,
                    "artifact_sha256": current_sha,
                    "detail": "No active adblock artifact is available.",
                }

            ok_restart, restart_detail = self._restart_adblock_service()
            if ok_restart:
                try:
                    store.mark_cache_flushed(size=0)
                except Exception as exc:
                    clear_detail = public_error_message(
                        exc,
                        default="Failed to clear adblock cache flush request.",
                    )
                    detail = "\n".join(
                        part
                        for part in (restart_detail.strip(), clear_detail)
                        if str(part or "").strip()
                    ).strip()
                    return {
                        "ok": False,
                        "proxy_id": self.proxy_id,
                        "changed": True,
                        "artifact_changed": False,
                        "cache_flushed": False,
                        "revision_id": None,
                        "artifact_sha256": current_sha,
                        "detail": detail,
                    }
            return {
                "ok": ok_restart,
                "proxy_id": self.proxy_id,
                "changed": True,
                "artifact_changed": False,
                "cache_flushed": bool(ok_restart),
                "revision_id": None,
                "artifact_sha256": current_sha,
                "detail": restart_detail.strip() or "Adblock runtime restarted.",
            }

        # Force sync should refresh policy/config/PAC state, but it must not churn the
        # adblock ICAP helper when the active artifact is already materialized. Live
        # policy workflows can issue many forced syncs in quick succession; restarting
        # cicap_adblock on every no-op sync can starve Squid/admin requests and leave
        # traffic probes hanging. Cache flush remains an explicit restart trigger.
        artifact_changed = bool(revision_meta.artifact_sha256 != current_sha)
        integrity_detail = ""
        if (
            not artifact_changed
            and not flush_requested
            and self.services.current_adblock_sha_reader is None
        ):
            integrity_ok, integrity_detail = self._adblock_materialization_integrity(
                revision_meta.artifact_sha256,
                current_sha=current_sha,
            )
            artifact_changed = not integrity_ok
        if not artifact_changed and not flush_requested:
            applied = None
            try:
                applied = self.adblock_artifacts.latest_apply(
                    self.proxy_id,
                    revision_id=revision_meta.revision_id,
                )
            except Exception:
                applied = None
            if applied is None:
                try:
                    applied = self.adblock_artifacts.record_apply_result(
                        self.proxy_id,
                        revision_meta.revision_id,
                        ok=True,
                        detail="Proxy is already using the active adblock artifact.",
                        applied_by="proxy",
                        artifact_sha256=revision_meta.artifact_sha256,
                    )
                except Exception as exc:
                    detail = public_error_message(
                        exc,
                        default="Failed to record adblock artifact application.",
                    )
                    return {
                        "ok": False,
                        "proxy_id": self.proxy_id,
                        "changed": False,
                        "adblock_changed": False,
                        "artifact_changed": False,
                        "cache_flushed": False,
                        "revision_id": revision_meta.revision_id,
                        "artifact_sha256": revision_meta.artifact_sha256,
                        "detail": detail,
                    }
            return {
                "ok": True,
                "proxy_id": self.proxy_id,
                "changed": False,
                "adblock_changed": False,
                "artifact_changed": False,
                "cache_flushed": False,
                "revision_id": revision_meta.revision_id,
                "application_id": getattr(applied, "application_id", None),
                "artifact_sha256": revision_meta.artifact_sha256,
                "detail": "Proxy is already using the active adblock artifact.",
            }

        if artifact_changed:
            revision = self.adblock_artifacts.get_active_artifact()
            if revision is None:
                return {
                    "ok": False,
                    "proxy_id": self.proxy_id,
                    "changed": False,
                    "artifact_changed": False,
                    "cache_flushed": False,
                    "revision_id": revision_meta.revision_id,
                    "artifact_sha256": revision_meta.artifact_sha256,
                    "detail": "Active adblock artifact metadata was present, but the full artifact could not be loaded.",
                }
            apply_revision_id = revision.revision_id
            apply_artifact_sha256 = revision.artifact_sha256
            snapshot_root = self._snapshot_adblock_compiled_dir()
            try:
                materialize_archive_to_directory(
                    self.adblock_compiled_dir,
                    archive_blob=revision.archive_blob,
                    artifact_sha256=revision.artifact_sha256,
                )
                integrity_ok, post_apply_detail = (
                    self._adblock_materialization_integrity(
                        revision.artifact_sha256,
                        current_sha=revision.artifact_sha256,
                    )
                )
                if not integrity_ok:
                    msg = (
                        "Materialized adblock artifact failed validation: "
                        f"{post_apply_detail}"
                    )
                    raise RuntimeError(msg)
            except Exception as exc:
                detail = public_error_message(
                    exc,
                    default="Failed to materialize adblock artifact.",
                )
                rollback_detail = ""
                try:
                    self._restore_adblock_compiled_snapshot(snapshot_root)
                    rollback_detail = "Restored previous adblock compiled artifact."
                except Exception as rollback_exc:
                    rollback_detail = public_error_message(
                        rollback_exc,
                        default="Failed to restore previous adblock artifact.",
                    )
                with suppress(Exception):
                    shutil.rmtree(snapshot_root, ignore_errors=True)
                if rollback_detail:
                    detail = f"{detail}\n{rollback_detail}"
                applied = self.adblock_artifacts.record_apply_result(
                    self.proxy_id,
                    revision.revision_id,
                    ok=False,
                    detail=detail,
                    applied_by="proxy",
                    artifact_sha256=revision.artifact_sha256,
                )
                return {
                    "ok": False,
                    "proxy_id": self.proxy_id,
                    "changed": False,
                    "artifact_changed": False,
                    "cache_flushed": False,
                    "revision_id": revision.revision_id,
                    "application_id": applied.application_id,
                    "artifact_sha256": revision.artifact_sha256,
                    "detail": detail,
                }
        else:
            apply_revision_id = revision_meta.revision_id
            apply_artifact_sha256 = revision_meta.artifact_sha256
            snapshot_root = ""

        ok_restart, restart_detail = self._restart_adblock_service()
        if not ok_restart and artifact_changed and snapshot_root:
            rollback_detail_parts = [
                restart_detail.strip()
                or "adblock ICAP helper failed after adblock artifact materialization.",
            ]
            try:
                self._restore_adblock_compiled_snapshot(snapshot_root)
                rollback_detail_parts.append(
                    "Restored previous adblock compiled artifact.",
                )
                rollback_ok, rollback_restart_detail = self._restart_adblock_service()
                if rollback_restart_detail.strip():
                    rollback_detail_parts.append(rollback_restart_detail.strip())
                if not rollback_ok:
                    rollback_detail_parts.append(
                        "Previous adblock artifact was restored, but the adblock ICAP helper still did not stay running.",
                    )
            except Exception as exc:
                rollback_detail_parts.append(
                    public_error_message(
                        exc,
                        default="Failed to restore previous adblock artifact.",
                    ),
                )
            finally:
                with suppress(Exception):
                    shutil.rmtree(snapshot_root, ignore_errors=True)
            detail = "\n".join(part for part in rollback_detail_parts if part).strip()
            applied = self.adblock_artifacts.record_apply_result(
                self.proxy_id,
                revision.revision_id,
                ok=False,
                detail=detail,
                applied_by="proxy",
                artifact_sha256=revision.artifact_sha256,
            )
            return {
                "ok": False,
                "proxy_id": self.proxy_id,
                "changed": False,
                "artifact_changed": False,
                "artifact_rolled_back": True,
                "cache_flushed": False,
                "revision_id": revision.revision_id,
                "application_id": applied.application_id,
                "artifact_sha256": revision.artifact_sha256,
                "detail": detail,
            }

        if artifact_changed and snapshot_root:
            with suppress(Exception):
                shutil.rmtree(snapshot_root, ignore_errors=True)
        cache_flush_detail = ""
        cache_flushed = False
        if ok_restart and flush_requested:
            try:
                store.mark_cache_flushed(size=0)
                cache_flushed = True
            except Exception as exc:
                cache_flush_detail = public_error_message(
                    exc,
                    default="Failed to clear adblock cache flush request.",
                )
        detail_parts = [restart_detail.strip() or "Adblock artifact applied."]
        if integrity_detail.strip():
            detail_parts.append(
                f"Reapplied artifact because local materialization was stale: {integrity_detail.strip()}",
            )
        if cache_flush_detail.strip():
            detail_parts.append(cache_flush_detail.strip())
        detail = "\n".join(part for part in detail_parts if part).strip()
        result_ok = bool(ok_restart and not cache_flush_detail)
        applied = self.adblock_artifacts.record_apply_result(
            self.proxy_id,
            apply_revision_id,
            ok=result_ok,
            detail=detail,
            applied_by="proxy",
            artifact_sha256=apply_artifact_sha256,
        )
        adblock_runtime_changed = bool(artifact_changed or flush_requested)
        return {
            "ok": result_ok,
            "proxy_id": self.proxy_id,
            "changed": adblock_runtime_changed,
            "adblock_changed": adblock_runtime_changed,
            "artifact_changed": artifact_changed,
            "cache_flushed": cache_flushed,
            "revision_id": apply_revision_id,
            "application_id": applied.application_id,
            "artifact_sha256": apply_artifact_sha256,
            "detail": detail,
        }

    def sync_pac_state(self, *, force: bool = False) -> dict[str, Any]:
        desired = self.pac_state_builder(self.proxy_id)
        current_sha = self._current_pac_state_sha()
        integrity_ok, integrity_detail = self._pac_materialization_integrity(
            desired,
            current_sha=current_sha,
        )
        if integrity_ok:
            return {
                "ok": True,
                "proxy_id": self.proxy_id,
                "changed": False,
                "state_sha256": desired.state_sha256,
                "current_state_sha256": current_sha,
                "detail": "Proxy is already using the active PAC materialization.",
            }

        try:
            materialize_proxy_pac_state(self.pac_render_dir, state=desired)
        except Exception as exc:
            return {
                "ok": False,
                "proxy_id": self.proxy_id,
                "changed": False,
                "state_sha256": desired.state_sha256,
                "current_state_sha256": current_sha,
                "detail": _state_sync_failure_detail(
                    "PAC",
                    public_error_message(
                        exc,
                        default="Failed to materialize PAC state.",
                    ),
                    desired_sha=desired.state_sha256,
                    current_sha=current_sha,
                ),
            }

        return {
            "ok": True,
            "proxy_id": self.proxy_id,
            "changed": True,
            "state_sha256": desired.state_sha256,
            "previous_state_sha256": current_sha,
            "detail": "\n".join(
                part
                for part in (
                    "PAC state materialized locally.",
                    (
                        "Reapplied PAC state because local materialization was stale: "
                        f"{integrity_detail.strip()}"
                    )
                    if integrity_detail.strip()
                    else "",
                )
                if part
            ),
        }

    def bootstrap_revision_if_missing(self) -> None:
        current = self.controller.get_current_config() or ""
        if current.strip():
            self.revisions.ensure_active_revision(
                self.proxy_id,
                current,
                created_by="system",
                source_kind="bootstrap",
            )

    def sync_certificate_bundle(self, *, force: bool = False) -> dict[str, Any]:
        revision_meta = self.certificate_bundles.get_active_bundle_metadata()
        if revision_meta is None:
            return {
                "ok": True,
                "proxy_id": self.proxy_id,
                "changed": False,
                "detail": "",
                "certificate_revision_id": None,
                "certificate_bundle_sha256": "",
            }

        current_sha = self._current_certificate_bundle_sha()
        if revision_meta.bundle_sha256 == current_sha:
            applied = None
            try:
                latest_apply = self.certificate_bundles.latest_apply(
                    self.proxy_id, revision_id=revision_meta.revision_id
                )
            except Exception:
                latest_apply = None
            if int(getattr(latest_apply, "revision_id", 0) or 0) != int(
                revision_meta.revision_id or 0,
            ):
                try:
                    applied = self.certificate_bundles.record_apply_result(
                        self.proxy_id,
                        revision_meta.revision_id,
                        ok=True,
                        detail="Proxy is already using the active certificate bundle.",
                        applied_by="proxy",
                        bundle_sha256=revision_meta.bundle_sha256,
                    )
                except Exception:
                    applied = None
            result = {
                "ok": True,
                "proxy_id": self.proxy_id,
                "certificate_revision_id": revision_meta.revision_id,
                "changed": False,
                "detail": "Proxy is already using the active certificate bundle.",
                "certificate_bundle_sha256": revision_meta.bundle_sha256,
            }
            if applied is not None:
                result["application_id"] = applied.application_id
            return result

        revision = self.certificate_bundles.get_active_bundle()
        if revision is None:
            return {
                "ok": False,
                "proxy_id": self.proxy_id,
                "certificate_revision_id": None,
                "changed": False,
                "detail": "Active certificate metadata was present, but the full bundle could not be loaded.",
                "certificate_bundle_sha256": "",
            }

        try:
            materialize_certificate_bundle(
                self.cert_manager.ca_dir,
                revision.to_bundle(),
                original_pfx_bytes=revision.original_pfx_blob,
            )
        except Exception as exc:
            detail = public_error_message(
                exc,
                default="Failed to materialize certificate bundle.",
            )
            applied = self.certificate_bundles.record_apply_result(
                self.proxy_id,
                revision.revision_id,
                ok=False,
                detail=detail,
                applied_by="proxy",
                bundle_sha256=revision.bundle_sha256,
            )
            return {
                "ok": False,
                "proxy_id": self.proxy_id,
                "certificate_revision_id": revision.revision_id,
                "application_id": applied.application_id,
                "changed": False,
                "detail": detail,
                "certificate_bundle_sha256": revision.bundle_sha256,
            }

        ok_restart, restart_detail = self._reinitialize_ssl_db_and_restart()
        detail = restart_detail.strip() or "Certificate bundle applied."
        applied = self.certificate_bundles.record_apply_result(
            self.proxy_id,
            revision.revision_id,
            ok=ok_restart,
            detail=detail,
            applied_by="proxy",
            bundle_sha256=revision.bundle_sha256,
        )
        return {
            "ok": ok_restart,
            "proxy_id": self.proxy_id,
            "certificate_revision_id": revision.revision_id,
            "application_id": applied.application_id,
            "changed": ok_restart,
            "detail": detail,
            "certificate_bundle_sha256": revision.bundle_sha256,
        }

    def start_background_tasks(self) -> None:
        if (os.environ.get("DISABLE_BACKGROUND") or "").strip() == "1":
            return
        for key, message, starter in (
            (
                "proxy_runtime.background.live_stats",
                "Failed to start proxy live stats background task",
                self.live_stats_store.start_background,
            ),
            (
                "proxy_runtime.background.diagnostic",
                "Failed to start proxy diagnostic background task",
                self.diagnostic_store.start_background,
            ),
            (
                "proxy_runtime.background.timeseries",
                "Failed to start proxy timeseries background task",
                lambda: self.timeseries_store.start_background(self.stats_provider),
            ),
            (
                "proxy_runtime.background.ssl_errors",
                "Failed to start proxy SSL errors background task",
                self.ssl_errors_store.start_background,
            ),
        ):
            try:
                starter()
            except Exception as exc:
                _log_recoverable_db_or_unexpected(
                    key,
                    recoverable_message=message,
                    unexpected_message=message,
                    exc=exc,
                    interval_seconds=30.0,
                )
        try:
            self.adblock_store.start_blocklog_background()
        except Exception as exc:
            _log_recoverable_db_or_unexpected(
                "proxy_runtime.background.adblock_blocklog",
                recoverable_message="Failed to start proxy adblock blocklog background task",
                unexpected_message="Failed to start proxy adblock blocklog background task",
                exc=exc,
                interval_seconds=30.0,
            )

    def collect_clamav_health(self) -> dict[str, Any]:
        started_mono = time.monotonic()
        try:
            probe_timeout = max(
                0.2,
                min(
                    10.0,
                    float(
                        (
                            os.environ.get("PROXY_CLAMAV_HEALTH_PROBE_TIMEOUT_SECONDS")
                            or "1.5"
                        ).strip()
                        or "1.5",
                    ),
                ),
            )
        except Exception:
            probe_timeout = 1.5
        services = self.runtime_services_builder(
            error_formatter=str,
            icap_timeout=probe_timeout,
            tcp_timeout=probe_timeout,
        )
        clamd = services.get("clamd") or {
            "ok": False,
            "detail": "clamd health unavailable",
        }
        av_icap = services.get("av_icap") or {
            "ok": False,
            "detail": "c-icap AV health unavailable",
        }
        clamav = services.get("clamav") or {
            "ok": bool(clamd.get("ok")) and bool(av_icap.get("ok")),
            "detail": "ClamAV health unavailable",
        }
        ok = bool(clamav.get("ok"))
        return {
            "ok": ok,
            "status": "healthy" if ok else "degraded",
            "proxy_id": self.proxy_id,
            "proxy_status": "ClamAV health checked via lightweight management endpoint.",
            "services": {
                "clamav": clamav,
                "av_icap": av_icap,
                "clamd": clamd,
            },
            "health_scope": "clamav",
            "health_elapsed_seconds": round(time.monotonic() - started_mono, 3),
            "timestamp": int(time.time()),
        }

    def collect_navigation_health(self, *, force: bool = False) -> dict[str, Any]:
        now_mono = time.monotonic()
        try:
            current_config_sha = self._current_config_sha()
        except Exception:
            current_config_sha = ""
        if not force and self.health_cache_ttl_seconds > 0:
            with self._health_cache_lock:
                cached = self._navigation_health_cache_value
                if (
                    cached is not None
                    and (now_mono - self._navigation_health_cache_ts)
                    < self.health_cache_ttl_seconds
                    and (
                        not current_config_sha
                        or str(cached.get("current_config_sha") or "")
                        == current_config_sha
                    )
                ):
                    return cached

        started_mono = time.monotonic()
        stdout, stderr = self.controller.get_status()
        proxy_status = (_decode_bytes(stdout) + "\n" + _decode_bytes(stderr)).strip()
        proxy_ok = not bool(stderr)
        try:
            listener_details = tuple(self.controller._http_listener_details())
            listener_ports = tuple(
                int(item.get("port") or 0)
                for item in listener_details
                if int(item.get("port") or 0)
            )
            listener_ok = bool(self.controller._wait_for_http_listener(timeout=0.5))
        except Exception:
            listener_details = ()
            listener_ports = ()
            listener_ok = proxy_ok
        services = {
            "supervisor": self._supervisor_programs_health(),
            "squid_listeners": {
                "ok": bool(listener_ok),
                "detail": _listener_mode_summary(listener_details)
                or "No Squid http_port listeners detected.",
                "listeners": [dict(item) for item in listener_details],
                "ports": list(listener_ports),
            },
        }
        ok = proxy_ok and all(bool(item.get("ok")) for item in services.values())
        result = {
            "ok": ok,
            "status": "healthy" if ok else "degraded",
            "proxy_id": self.proxy_id,
            "proxy_status": proxy_status,
            "listener_ports": list(listener_ports),
            "listener_details": [dict(item) for item in listener_details],
            "stats": {},
            "services": services,
            "version": current_component_metadata("proxy"),
            "current_config_sha": current_config_sha,
            "health_scope": "navigation",
            "health_elapsed_seconds": round(time.monotonic() - started_mono, 3),
            "timestamp": int(time.time()),
        }
        if not force and self.health_cache_ttl_seconds > 0:
            with self._health_cache_lock:
                self._navigation_health_cache_value = result
                self._navigation_health_cache_ts = time.monotonic()
        return result

    def collect_health(self, *, force: bool = False) -> dict[str, Any]:
        now_mono = time.monotonic()
        cached: dict[str, Any] | None = None
        current_config_sha_for_cache = ""
        try:
            current_config_sha_for_cache = self._current_config_sha()
        except Exception:
            current_config_sha_for_cache = ""

        def cache_matches_current_config(cached_value: dict[str, Any]) -> bool:
            return (
                not current_config_sha_for_cache
                or str(cached_value.get("current_config_sha") or "")
                == current_config_sha_for_cache
            )

        if not force and self.health_cache_ttl_seconds > 0:
            with self._health_cache_lock:
                cached = self._health_cache_value
                if (
                    cached is not None
                    and (now_mono - self._health_cache_ts)
                    < self.health_cache_ttl_seconds
                    and cache_matches_current_config(cached)
                ):
                    return cached

        cache_config_mismatched = bool(
            cached is not None
            and current_config_sha_for_cache
            and not cache_matches_current_config(cached)
        )
        refresh_acquired = self._health_refresh_lock.acquire(
            blocking=force or cached is None or cache_config_mismatched,
        )
        if not refresh_acquired:
            # Another request is already doing the expensive health probe. Return
            # the last known result rather than letting Gunicorn threads pile up
            # behind slow ICAP/supervisor/filesystem checks and causing Admin UI
            # management requests to time out.
            stale = dict(cached or {})
            stale["health_cache_stale"] = True
            stale["health_cache_detail"] = (
                "Returned stale health while a refresh was already in progress."
            )
            return stale

        try:
            if not force and self.health_cache_ttl_seconds > 0:
                now_mono = time.monotonic()
                with self._health_cache_lock:
                    cached = self._health_cache_value
                    if (
                        cached is not None
                        and (now_mono - self._health_cache_ts)
                        < self.health_cache_ttl_seconds
                        and cache_matches_current_config(cached)
                    ):
                        return cached

            started_mono = time.monotonic()
            stdout, stderr = self.controller.get_status()
            proxy_status = (
                _decode_bytes(stdout) + "\n" + _decode_bytes(stderr)
            ).strip()
            proxy_ok = not bool(stderr)
            stats = self.stats_provider()
            services = self.runtime_services_builder(
                error_formatter=str,
                icap_timeout=0.8,
                tcp_timeout=0.75,
            )
            services["supervisor"] = self._supervisor_programs_health()
            services["operation_ledger"] = self._operation_ledger_health()
            try:
                listener_details = tuple(self.controller._http_listener_details())
                listener_ports = tuple(
                    int(item.get("port") or 0)
                    for item in listener_details
                    if int(item.get("port") or 0)
                )
                listener_ok = bool(self.controller._wait_for_http_listener(timeout=1.0))
            except Exception:
                listener_details = ()
                listener_ports = ()
                listener_ok = proxy_ok
            services["squid_listeners"] = {
                "ok": bool(listener_ok),
                "detail": _listener_mode_summary(listener_details)
                or "No Squid http_port listeners detected.",
                "listeners": [dict(item) for item in listener_details],
                "ports": list(listener_ports),
            }
            active_revision = self.revisions.get_active_revision_metadata(self.proxy_id)
            active_certificate = self.certificate_bundles.get_active_bundle_metadata()
            active_adblock_artifact = (
                self.adblock_artifacts.get_active_artifact_metadata()
            )
            current_sha = current_config_sha_for_cache or self._current_config_sha()
            current_certificate_sha = self._current_certificate_bundle_sha()
            current_adblock_sha = self._current_adblock_artifact_sha()
            state_errors: list[str] = []
            desired_policy_sha = ""
            current_policy_sha = ""
            desired_pac = None
            desired_pac_sha = ""
            current_pac_sha = self._current_pac_state_sha()

            try:
                desired_policy = self.policy_state_builder(self.proxy_id)
                desired_policy_sha = desired_policy.policy_sha256
                current_policy_sha = self._current_policy_sha()
            except Exception as exc:
                state_errors.append(
                    f"policy: {public_error_message(exc, default='Failed to inspect desired proxy policy state.')}",
                )
                log_exception_throttled(
                    logger,
                    "proxy_runtime.collect_health.policy",
                    interval_seconds=30.0,
                    message="Failed to collect proxy policy health state",
                )

            try:
                desired_pac = self.pac_state_builder(self.proxy_id)
                desired_pac_sha = desired_pac.state_sha256
            except Exception as exc:
                state_errors.append(
                    f"pac: {public_error_message(exc, default='Failed to inspect desired PAC state.')}",
                )
                log_exception_throttled(
                    logger,
                    "proxy_runtime.collect_health.pac",
                    interval_seconds=30.0,
                    message="Failed to collect proxy PAC health state",
                )

            active_revision_sha = (
                active_revision.config_sha256 if active_revision else ""
            )
            if active_revision_sha and active_revision_sha != current_sha:
                try:
                    active_revision_full = self.revisions.get_active_revision(
                        self.proxy_id,
                    )
                    if active_revision_full is not None:
                        normalized_active_config = (
                            self.controller.normalize_config_text(
                                active_revision_full.config_text or "",
                            )
                        )
                        normalized_active_sha = hashlib.sha256(
                            normalized_active_config.encode(
                                "utf-8",
                                errors="replace",
                            ),
                        ).hexdigest()
                        if normalized_active_sha == current_sha:
                            active_revision_sha = normalized_active_sha
                except Exception:
                    log_exception_throttled(
                        logger,
                        "proxy_runtime.collect_health.config_revision_normalize",
                        interval_seconds=30.0,
                        message="Failed to normalize active config revision for health drift comparison",
                    )
            active_certificate_sha = (
                active_certificate.bundle_sha256 if active_certificate else ""
            )
            active_adblock_sha = (
                active_adblock_artifact.artifact_sha256
                if active_adblock_artifact
                else ""
            )
            state_errors.extend(
                drift_detail
                for drift_detail in (
                    _state_drift_detail("config", active_revision_sha, current_sha),
                    _state_drift_detail(
                        "certificate bundle",
                        active_certificate_sha,
                        current_certificate_sha,
                    ),
                    _state_drift_detail(
                        "adblock artifact",
                        active_adblock_sha,
                        current_adblock_sha,
                    ),
                    _state_drift_detail(
                        "policy", desired_policy_sha, current_policy_sha
                    ),
                    _state_drift_detail("PAC", desired_pac_sha, current_pac_sha),
                )
                if drift_detail
            )
            if active_adblock_sha and active_adblock_sha == current_adblock_sha:
                integrity_ok, integrity_detail = (
                    self._adblock_materialization_integrity(
                        active_adblock_sha,
                        current_sha=current_adblock_sha,
                    )
                )
                if not integrity_ok:
                    state_errors.append(f"adblock artifact: {integrity_detail}")
            if desired_pac is not None and desired_pac_sha == current_pac_sha:
                integrity_ok, integrity_detail = self._pac_materialization_integrity(
                    desired_pac,
                    current_sha=current_pac_sha,
                )
                if not integrity_ok:
                    state_errors.append(f"PAC: {integrity_detail}")

            ok = (
                proxy_ok
                and all(bool(item.get("ok")) for item in services.values())
                and not state_errors
            )
            result = {
                "ok": ok,
                "status": "healthy" if ok else "degraded",
                "proxy_id": self.proxy_id,
                "proxy_status": proxy_status,
                "listener_ports": list(listener_ports),
                "listener_details": [dict(item) for item in listener_details],
                "stats": stats,
                "services": services,
                "version": current_component_metadata("proxy"),
                "active_revision_id": active_revision.revision_id
                if active_revision
                else None,
                "active_revision_sha": active_revision_sha,
                "current_config_sha": current_sha,
                "active_certificate_revision_id": active_certificate.revision_id
                if active_certificate
                else None,
                "active_certificate_sha": active_certificate_sha,
                "current_certificate_sha": current_certificate_sha,
                "active_adblock_revision_id": active_adblock_artifact.revision_id
                if active_adblock_artifact
                else None,
                "active_adblock_sha": active_adblock_sha,
                "current_adblock_sha": current_adblock_sha,
                "desired_policy_sha": desired_policy_sha,
                "current_policy_sha": current_policy_sha,
                "desired_pac_sha": desired_pac_sha,
                "current_pac_sha": current_pac_sha,
                "state_errors": state_errors,
                "health_elapsed_seconds": round(time.monotonic() - started_mono, 3),
                "timestamp": int(time.time()),
            }
            if not force and self.health_cache_ttl_seconds > 0:
                with self._health_cache_lock:
                    self._health_cache_value = result
                    self._health_cache_ts = time.monotonic()
            return result
        finally:
            self._health_refresh_lock.release()

    def heartbeat(self) -> dict[str, Any]:
        try:
            self.self_heal_config_if_needed(reason="heartbeat")
        except Exception:
            log_exception_throttled(
                logger,
                "proxy_runtime.heartbeat.self_heal",
                interval_seconds=30.0,
                message="Proxy config self-heal check failed",
            )
        try:
            self.self_heal_runtime_services_if_needed(reason="heartbeat")
        except Exception:
            log_exception_throttled(
                logger,
                "proxy_runtime.heartbeat.service_self_heal",
                interval_seconds=30.0,
                message="Proxy runtime service self-heal check failed",
            )
        health = self.collect_health()
        public_fields = resolve_local_proxy_public_fields()
        self.registry.heartbeat(
            self.proxy_id,
            status=str(health.get("status") or "unknown"),
            hostname=(os.environ.get("PROXY_HOSTNAME") or socket.gethostname()).strip(),
            management_url=resolve_local_proxy_management_url(
                self.proxy_id,
                public_fields.get("public_host"),
            ),
            public_host=str(public_fields.get("public_host") or ""),
            public_pac_scheme=str(public_fields.get("public_pac_scheme") or "http"),
            public_pac_port=int(public_fields.get("public_pac_port") or 80),
            public_pac_path=str(public_fields.get("public_pac_path") or "/proxy.pac"),
            public_http_proxy_port=int(
                public_fields.get("public_http_proxy_port") or 3128,
            ),
            current_config_sha=str(health.get("current_config_sha") or ""),
            detail=str(health.get("proxy_status") or "")[:4000],
        )
        return health

    def sync_from_db(
        self,
        *,
        force: bool = False,
        operation_id: int | None = None,
    ) -> dict[str, Any]:
        with _exclusive_runtime_lock("sync", _SYNC_CONTROL_LOCK):
            claimed_operations = []
            ledger = None
            try:
                ledger = get_operation_ledger()
                ledger.requeue_stale_applying(self.proxy_id)
                claimed_operations = ledger.claim_pending(
                    self.proxy_id,
                    limit=100,
                    operation_id=operation_id,
                )
            except Exception as exc:
                _log_recoverable_db_or_unexpected(
                    "proxy_runtime.operation_ledger.claim",
                    recoverable_message="Proxy operation ledger unavailable during runtime reconciliation",
                    unexpected_message="Proxy operation ledger claim failed",
                    exc=exc,
                    interval_seconds=30.0,
                )
                claimed_operations = []
                ledger = None
            try:
                result = self._sync_from_db_unlocked(
                    force=bool(
                        force or _operations_request_config_force(claimed_operations),
                    ),
                    artifact_force=bool(
                        force or _operations_request_force(claimed_operations),
                    ),
                    operations=claimed_operations,
                )
            except Exception as exc:
                if ledger is not None and claimed_operations:
                    with suppress(Exception):
                        ledger.mark_many(
                            claimed_operations,
                            status="failed",
                            detail=str(exc)[:4000],
                        )
                raise
            if ledger is not None and claimed_operations:
                with suppress(Exception):
                    self._mark_claimed_operations(ledger, claimed_operations, result)
            return result

    def _mark_claimed_operations(
        self,
        ledger: Any,
        operations: list[Any],
        result: dict[str, Any],
    ) -> None:
        default_status = "applied" if bool(result.get("ok")) else "failed"
        detail = str(result.get("detail") or "Proxy reconciliation completed.")[:4000]
        current_policy_sha = str(result.get("current_policy_sha") or "").strip()
        if not current_policy_sha:
            with suppress(Exception):
                current_policy_sha = str(self._current_policy_sha() or "").strip()
        if current_policy_sha:
            result = {**result, "current_policy_sha": current_policy_sha}
        for operation in operations:
            status, operation_detail = _operation_completion_status(
                operation,
                default_status=default_status,
                detail=detail,
                result=result,
            )
            ledger.mark_status(
                getattr(operation, "operation_id", 0),
                status=status,
                detail=operation_detail,
            )

    def _sync_from_db_unlocked(
        self,
        *,
        force: bool = False,
        artifact_force: bool | None = None,
        operations: list[Any] | None = None,
    ) -> dict[str, Any]:
        self._invalidate_health_cache()
        self.ensure_registered()
        self.bootstrap_revision_if_missing()
        artifact_force_value = force if artifact_force is None else bool(
            artifact_force,
        )
        operation_types = set(_supported_operation_types(operations))
        unsupported_operation_types = _unsupported_operation_types(operations)
        operation_evidence = {
            "executed_operation_types": sorted(operation_types),
            "unsupported_operation_types": unsupported_operation_types,
        }
        unsupported_detail = ""
        if unsupported_operation_types:
            unsupported_detail = (
                "Unsupported proxy operation type(s) were not executed: "
                + ", ".join(unsupported_operation_types)
            )
        if unsupported_operation_types and not operation_types:
            return {
                "ok": False,
                "detail": unsupported_detail,
                "changed": False,
                "cache_cleared": False,
                "certificate_changed": False,
                "policy_changed": False,
                "adblock_changed": False,
                "pac_changed": False,
                "config_changed": False,
                "current_config_sha": self._current_config_sha(),
                **operation_evidence,
            }
        cert_result = self.sync_certificate_bundle(force=artifact_force_value)
        cert_evidence = _certificate_result_evidence(cert_result)
        cert_ok = bool(cert_result.get("ok", True))
        cert_changed = bool(cert_result.get("changed", False))
        detail_parts = (
            [str(cert_result.get("detail") or "").strip()]
            if str(cert_result.get("detail") or "").strip()
            else []
        )
        if unsupported_detail:
            detail_parts.append(unsupported_detail)
        if not cert_ok:
            detail = (
                "\n".join(detail_parts).strip() or "Certificate bundle sync failed."
            )
            self.registry.mark_apply_result(
                self.proxy_id,
                ok=False,
                detail=detail,
                current_config_sha=self._current_config_sha(),
            )
            cert_result["detail"] = detail
            cert_result.update(cert_evidence)
            cert_result.update(operation_evidence)
            return cert_result

        policy_result = self.sync_policy_state(force=artifact_force_value)
        policy_ok = bool(policy_result.get("ok", True))
        policy_changed = bool(policy_result.get("changed", False))
        policy_reload_required = bool(policy_result.get("reload_required", False))
        policy_evidence = {
            "policy_sha256": str(policy_result.get("policy_sha256") or ""),
            "current_policy_sha": str(policy_result.get("current_policy_sha") or ""),
        }
        if str(policy_result.get("detail") or "").strip():
            detail_parts.append(str(policy_result.get("detail") or "").strip())
        if not policy_ok:
            detail = "\n".join(detail_parts).strip() or "Policy materialization failed."
            self.registry.mark_apply_result(
                self.proxy_id,
                ok=False,
                detail=detail,
                current_config_sha=self._current_config_sha(),
            )
            policy_result.update(cert_evidence)
            policy_result.update(policy_evidence)
            policy_result.update(operation_evidence)
            policy_result["detail"] = detail
            return policy_result

        adblock_result = self.sync_adblock_state(force=artifact_force_value)
        adblock_ok = bool(adblock_result.get("ok", True))
        adblock_changed = bool(adblock_result.get("changed", False))
        if str(adblock_result.get("detail") or "").strip():
            detail_parts.append(str(adblock_result.get("detail") or "").strip())
        if not adblock_ok:
            detail = (
                "\n".join(detail_parts).strip()
                or "Adblock artifact materialization failed."
            )
            self.registry.mark_apply_result(
                self.proxy_id,
                ok=False,
                detail=detail,
                current_config_sha=self._current_config_sha(),
            )
            adblock_result.update(cert_evidence)
            adblock_result.update(policy_evidence)
            adblock_result.update(operation_evidence)
            adblock_result["detail"] = detail
            return adblock_result

        pac_result = self.sync_pac_state(force=artifact_force_value)
        pac_ok = bool(pac_result.get("ok", True))
        pac_changed = bool(pac_result.get("changed", False))
        if str(pac_result.get("detail") or "").strip():
            detail_parts.append(str(pac_result.get("detail") or "").strip())
        if not pac_ok:
            detail = "\n".join(detail_parts).strip() or "PAC materialization failed."
            self.registry.mark_apply_result(
                self.proxy_id,
                ok=False,
                detail=detail,
                current_config_sha=self._current_config_sha(),
            )
            pac_result.update(cert_evidence)
            pac_result.update(policy_evidence)
            pac_result.update(operation_evidence)
            pac_result["detail"] = detail
            return pac_result

        cache_cleared = False
        if "cache_clear" in operation_types:
            cache_ok, cache_detail = self._clear_disk_cache_and_refresh_runtime()
            cache_cleared = bool(cache_ok)
            if str(cache_detail or "").strip():
                detail_parts.append(str(cache_detail or "").strip())
            if not cache_ok:
                detail = "\n".join(detail_parts).strip() or "Proxy cache clear failed."
                self.registry.mark_apply_result(
                    self.proxy_id,
                    ok=False,
                    detail=detail,
                    current_config_sha=self._current_config_sha(),
                )
                return {
                    "ok": False,
                    "detail": detail,
                    "changed": bool(
                        cert_changed or policy_changed or adblock_changed or pac_changed
                    ),
                    "cache_cleared": False,
                    "certificate_changed": cert_changed,
                    "policy_changed": policy_changed,
                    "adblock_changed": adblock_changed,
                    "pac_changed": pac_changed,
                    "config_changed": False,
                    "current_config_sha": self._current_config_sha(),
                    **cert_evidence,
                    **policy_evidence,
                    **operation_evidence,
                }

        current_sha = self._current_config_sha()
        clamav_runtime_changed = False

        def changed_since_sync_start(*, policy_config_changed: bool = False) -> bool:
            return bool(
                cert_changed
                or policy_changed
                or adblock_changed
                or pac_changed
                or cache_cleared
                or clamav_runtime_changed
                or policy_config_changed
            )

        controller = getattr(self, "controller", None)
        set_adblock_icap_revision_token = getattr(
            controller,
            "set_adblock_icap_revision_token",
            None,
        )
        if callable(set_adblock_icap_revision_token):
            set_adblock_icap_revision_token(
                str(
                    adblock_result.get("artifact_sha256")
                    or self._current_adblock_artifact_sha()
                    or "",
                )[:16],
            )
        adblock_enabled = self._current_adblock_enabled()
        set_adblock_enabled = getattr(controller, "set_adblock_enabled", None)
        if callable(set_adblock_enabled):
            set_adblock_enabled(adblock_enabled)
        materialize_clamav_runtime_files = getattr(
            controller,
            "materialize_clamav_runtime_files",
            None,
        )
        if callable(materialize_clamav_runtime_files):
            current_config_reader = getattr(controller, "get_current_config", None)
            current_config_text = (
                current_config_reader() if callable(current_config_reader) else ""
            )
            ok_clamav_runtime, clamav_runtime_detail = materialize_clamav_runtime_files(
                current_config_text or "",
                adblock_enabled=adblock_enabled,
            )
            clamav_runtime_changed = bool(
                ok_clamav_runtime
                and "updated" in (clamav_runtime_detail or "").lower(),
            )
            if str(clamav_runtime_detail or "").strip() and clamav_runtime_changed:
                detail_parts.append(str(clamav_runtime_detail or "").strip())
            if not ok_clamav_runtime:
                detail = "\n".join(
                    [
                        *detail_parts,
                        str(
                            clamav_runtime_detail
                            or "ClamAV runtime file materialization failed.",
                        ),
                    ],
                ).strip()
                self.registry.mark_apply_result(
                    self.proxy_id,
                    ok=False,
                    detail=detail,
                    current_config_sha=current_sha,
                )
                return {
                    "ok": False,
                    "proxy_id": self.proxy_id,
                    "changed": changed_since_sync_start(),
                    "certificate_changed": cert_changed,
                    "policy_changed": policy_changed,
                    "adblock_changed": adblock_changed,
                    "pac_changed": pac_changed,
                    "cache_cleared": cache_cleared,
                    "config_changed": False,
                    "detail": detail,
                    **cert_evidence,
                    **policy_evidence,
                    **operation_evidence,
                }
        policy_config_ok, policy_config_detail, policy_config_changed = (
            self._ensure_policy_runtime_config()
        )
        if policy_config_detail.strip():
            detail_parts.append(policy_config_detail.strip())
        if not policy_config_ok:
            detail = (
                "\n".join(detail_parts).strip()
                or "Failed to normalize Squid config for policy reload."
            )
            self.registry.mark_apply_result(
                self.proxy_id,
                ok=False,
                detail=detail,
                current_config_sha=current_sha,
            )
            return {
                "ok": False,
                "proxy_id": self.proxy_id,
                "changed": changed_since_sync_start(
                    policy_config_changed=bool(policy_config_changed),
                ),
                "certificate_changed": cert_changed,
                "policy_changed": policy_changed,
                "adblock_changed": adblock_changed,
                "pac_changed": pac_changed,
                "cache_cleared": cache_cleared,
                "config_changed": bool(policy_config_changed),
                "detail": detail,
                **cert_evidence,
                **policy_evidence,
                **operation_evidence,
            }
        if policy_config_changed:
            current_sha = self._current_config_sha()
        revision_meta = self.revisions.get_active_revision_metadata(self.proxy_id)
        if revision_meta is None:
            reload_ok = True
            if policy_reload_required or adblock_changed or clamav_runtime_changed:
                reload_ok, reload_detail = self._reload_for_policy_update(
                    wait_for_adblock_icap=adblock_changed,
                )
                if reload_detail:
                    detail_parts.append(reload_detail)
            detail = (
                "\n".join(detail_parts).strip()
                or "No active config revision is available for this proxy."
            )
            result = {
                "ok": reload_ok,
                "proxy_id": self.proxy_id,
                "changed": changed_since_sync_start(
                    policy_config_changed=bool(policy_config_changed),
                ),
                "certificate_changed": cert_changed,
                "policy_changed": policy_changed,
                "adblock_changed": adblock_changed,
                "pac_changed": pac_changed,
                "cache_cleared": cache_cleared,
                "config_changed": bool(policy_config_changed),
                "detail": detail,
                **cert_evidence,
                **policy_evidence,
                **operation_evidence,
            }
            if (
                policy_reload_required or adblock_changed or clamav_runtime_changed
            ) and not reload_ok:
                self.registry.mark_apply_result(
                    self.proxy_id,
                    ok=False,
                    detail=detail,
                    current_config_sha=current_sha,
                )
            return result

        revision = None
        normalized_revision_text = ""
        normalized_revision_sha = ""
        normalized_config_current = False
        if (
            current_sha
            and revision_meta.config_sha256
            and revision_meta.config_sha256 != current_sha
        ):
            try:
                revision = self.revisions.get_active_revision(self.proxy_id)
                if revision is not None:
                    normalized_revision_text = self.controller.normalize_config_text(
                        revision.config_text,
                    )
                    normalized_revision_sha = hashlib.sha256(
                        normalized_revision_text.encode("utf-8", errors="replace"),
                    ).hexdigest()
                    normalized_config_current = normalized_revision_sha == current_sha
            except Exception:
                log_exception_throttled(
                    logger,
                    "proxy_runtime.sync_from_db.config_revision_normalize",
                    interval_seconds=30.0,
                    message="Failed to normalize active config revision for sync comparison",
                )

        if normalized_config_current:
            reload_ok = True
            if policy_reload_required or adblock_changed or clamav_runtime_changed:
                reload_ok, reload_detail = self._reload_for_policy_update(
                    wait_for_adblock_icap=adblock_changed,
                )
                if reload_detail:
                    detail_parts.append(reload_detail)
            detail = "Proxy is already using the active config revision."
            if detail_parts:
                detail_parts.append(detail)
                detail = "\n".join(detail_parts).strip()
            if (
                policy_reload_required or adblock_changed or clamav_runtime_changed
            ) and not reload_ok:
                self.registry.mark_apply_result(
                    self.proxy_id,
                    ok=False,
                    detail=detail,
                    current_config_sha=current_sha,
                )
            return {
                "ok": reload_ok,
                "proxy_id": self.proxy_id,
                "revision_id": revision_meta.revision_id,
                "changed": changed_since_sync_start(
                    policy_config_changed=bool(policy_config_changed),
                ),
                "certificate_changed": cert_changed,
                "policy_changed": policy_changed,
                "adblock_changed": adblock_changed,
                "pac_changed": pac_changed,
                "cache_cleared": cache_cleared,
                "config_changed": bool(policy_config_changed),
                "detail": detail,
                **cert_evidence,
                **policy_evidence,
                **operation_evidence,
            }

        latest_apply = None
        try:
            latest_apply = self.revisions.latest_apply(self.proxy_id)
        except Exception:
            latest_apply = None
        if (
            not force
            and latest_apply is not None
            and int(getattr(latest_apply, "revision_id", 0) or 0)
            == int(revision_meta.revision_id or 0)
            and not bool(getattr(latest_apply, "ok", False))
        ):
            detail = (
                f"Active config revision {revision_meta.revision_id} previously failed on this proxy; "
                "keeping the last-known-good running config until a new revision is activated or forced sync is requested."
            )
            self.registry.mark_apply_result(
                self.proxy_id,
                ok=False,
                detail=detail,
                current_config_sha=current_sha,
            )
            return {
                "ok": False,
                "proxy_id": self.proxy_id,
                "revision_id": revision_meta.revision_id,
                "changed": changed_since_sync_start(
                    policy_config_changed=bool(policy_config_changed),
                ),
                "certificate_changed": cert_changed,
                "policy_changed": policy_changed,
                "adblock_changed": adblock_changed,
                "pac_changed": pac_changed,
                "cache_cleared": cache_cleared,
                "config_changed": bool(policy_config_changed),
                "rollback_active": True,
                "detail": detail,
                **cert_evidence,
                **policy_evidence,
                **operation_evidence,
            }

        sync_changed = changed_since_sync_start(
            policy_config_changed=bool(policy_config_changed),
        )
        if revision_meta.config_sha256 == current_sha and (
            not force or not sync_changed
        ):
            reload_ok = True
            if policy_reload_required or adblock_changed or clamav_runtime_changed:
                reload_ok, reload_detail = self._reload_for_policy_update(
                    wait_for_adblock_icap=adblock_changed,
                )
                if reload_detail:
                    detail_parts.append(reload_detail)
            detail = "Proxy is already using the active config revision."
            if detail_parts:
                detail_parts.append(detail)
                detail = "\n".join(detail_parts).strip()
            if (
                policy_reload_required or adblock_changed or clamav_runtime_changed
            ) and not reload_ok:
                self.registry.mark_apply_result(
                    self.proxy_id,
                    ok=False,
                    detail=detail,
                    current_config_sha=current_sha,
                )
            return {
                "ok": reload_ok,
                "proxy_id": self.proxy_id,
                "revision_id": revision_meta.revision_id,
                "changed": sync_changed,
                "certificate_changed": cert_changed,
                "policy_changed": policy_changed,
                "adblock_changed": adblock_changed,
                "pac_changed": pac_changed,
                "cache_cleared": cache_cleared,
                "config_changed": bool(policy_config_changed),
                "detail": detail,
                **cert_evidence,
                **policy_evidence,
                **operation_evidence,
            }

        if revision is None:
            revision = self.revisions.get_active_revision(self.proxy_id)
        if revision is None:
            detail = "Active config revision metadata was present, but the full config text could not be loaded."
            self.registry.mark_apply_result(
                self.proxy_id,
                ok=False,
                detail=detail,
                current_config_sha=current_sha,
            )
            return {
                "ok": False,
                "proxy_id": self.proxy_id,
                "changed": changed_since_sync_start(
                    policy_config_changed=bool(policy_config_changed),
                ),
                "certificate_changed": cert_changed,
                "policy_changed": policy_changed,
                "adblock_changed": adblock_changed,
                "pac_changed": pac_changed,
                "cache_cleared": cache_cleared,
                "config_changed": bool(policy_config_changed),
                "detail": detail,
                **cert_evidence,
                **policy_evidence,
                **operation_evidence,
            }

        if not normalized_revision_text:
            normalized_revision_text = self.controller.normalize_config_text(
                revision.config_text,
            )
            normalized_revision_sha = hashlib.sha256(
                normalized_revision_text.encode("utf-8", errors="replace"),
            ).hexdigest()

        ok, config_detail = self.controller.apply_config_text(normalized_revision_text)
        self._invalidate_health_cache()
        if config_detail.strip():
            detail_parts.append(config_detail.strip())
        if ok and (policy_reload_required or adblock_changed or clamav_runtime_changed):
            policy_reload_ok, policy_reload_detail = self._reload_for_policy_update(
                wait_for_adblock_icap=adblock_changed,
            )
            ok = bool(policy_reload_ok)
            if policy_reload_detail.strip():
                detail_parts.append(policy_reload_detail.strip())
        detail = (
            "\n".join([part for part in detail_parts if part]).strip() or config_detail
        )
        applied = self.revisions.record_apply_result(
            self.proxy_id,
            revision.revision_id,
            ok=ok,
            detail=detail,
            applied_by="proxy",
        )
        new_sha = normalized_revision_sha if ok else current_sha
        self.registry.mark_apply_result(
            self.proxy_id,
            ok=ok,
            detail=detail,
            current_config_sha=new_sha,
        )
        return {
            "ok": ok,
            "proxy_id": self.proxy_id,
            "revision_id": revision.revision_id,
            "application_id": applied.application_id,
            "changed": True,
            "certificate_changed": cert_changed,
            "policy_changed": policy_changed,
            "adblock_changed": adblock_changed,
            "pac_changed": pac_changed,
            "cache_cleared": cache_cleared,
            "config_changed": True,
            "detail": detail,
            **cert_evidence,
            **policy_evidence,
            **operation_evidence,
        }

    def clear_cache(self) -> dict[str, Any]:
        self._invalidate_health_cache()
        ok, detail = self._clear_disk_cache_and_refresh_runtime()
        self.registry.mark_apply_result(
            self.proxy_id,
            ok=ok,
            detail=detail,
            current_config_sha=self._current_config_sha(),
        )
        return {
            "ok": ok,
            "proxy_id": self.proxy_id,
            "detail": detail,
        }

    def test_clamav_eicar(self) -> dict[str, Any]:
        result = _shared_test_eicar(error_formatter=str)
        return {
            "ok": bool(result.get("ok")),
            "proxy_id": self.proxy_id,
            "detail": str(result.get("detail") or ""),
        }

    def test_clamav_icap(self) -> dict[str, Any]:
        result = _shared_send_sample_av_icap(error_formatter=str)
        return {
            "ok": bool(result.get("ok")),
            "proxy_id": self.proxy_id,
            "detail": str(result.get("detail") or ""),
        }


_runtime: ProxyRuntime | None = None


def get_runtime() -> ProxyRuntime:
    global _runtime
    if _runtime is None:
        _runtime = ProxyRuntime()
    return _runtime
