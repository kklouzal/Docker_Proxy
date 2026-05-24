Total output lines: 2668

from __future__ import annotations

import hashlib
import logging
import os
import pathlib
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
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

logger = logging.getLogger(__name__)


_SUPERVISOR_CONTROL_LOCK = threading.RLock()
_SYNC_CONTROL_LOCK = threading.RLock()


def _int_or_none(value: object) -> int | None:
    try:
        parsed = int(value or 0)
    except Exception:
        return None
    return parsed if parsed > 0 else None


def _operation_completion_status(
    operation: Any,
    *,
    default_status: str,
    detail: str,
    result: dict[str, Any],
) -> tuple[str, str]:
    if default_status != "applied":
        return default_status, detail

    target_kind = str(getattr(operation, "target_kind", "") or "")
    if target_kind != "config_revision":
        return default_status, detail

    target_ref = _int_or_none(getattr(operation, "target_ref", None))
    applied_ref = _int_or_none(result.get("revision_id"))
    if target_ref is None or applied_ref is None or target_ref == applied_ref:
        return default_status, detail

    op_detail = (
        f"Superseded by active config revision {applied_ref}; "
        f"queued target revision {target_ref} was not applied because a newer desired state was reconciled."
    )
    if detail:
        op_detail = f"{op_detail}\n{detail}"
    return "superseded", op_detail[:4000]


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
            {"timeout": icap_timeout, "error_formatter": error_formatter},
        ),
    }
    results: dict[str, dict[str, Any]] = {}
    with ThreadPoolExecutor(
        max_workers=len(checks),
        thread_name_prefix="proxy-health",
    ) as executor:
        futures = {
            name: executor.submit(_call_health_check, func, **kwargs)
            for name, (func, kwargs) in checks.items()
        }
        for name, future in futures.items():
            try:
                results[name] = future.result(timeout=max(icap_timeout + 0.5, 1.0))
            except Exception as exc:
                results[name] = {
                    "ok": False,
                    "detail": error_formatter(exc) if error_formatter else str(exc),
                }

    clamd = results.get("clamd") or {"ok": False, "detail": "clamd health unavailable"}
    av_icap = results.get("av_icap") or {
        "ok": False,
        "detail": "c-icap av health unavailable",
    }
    return {
        "icap": results.get("icap")
        or {"ok": False, "detail": "c-icap adblock health unavailable"},
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


def _state_drift_detail(label: str, desired_sha: object, current_sha: object) -> str:
    desired = str(desired_sha or "").strip()
    current = str(current_sha or "").strip()
    if not desired or desired == current:
        return ""
    current_display = current[:12] if current else "missing"
    return f"{label}: desired {desired[:12]} does not match current {current_display}."


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
        return hashlib.sha256(current.encode("utf-8", errors="replace")).hexdigest()

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

    def _current_adblock_artifact_sha(self) -> str:
        if self.services.current_adblock_sha_reader is not None:
            return str(self.services.current_adblock_sha_reader() or "")
        return read_materialized_artifact_sha(self.adblock_compiled_dir)

    def _current_pac_state_sha(self) -> str:
        if self.services.current_pac_sha_reader is not None:
            return str(self.services.current_pac_sha_reader() or "")
        return read_materialized_pac_state_sha(self.pac_render_dir)

    def _supervisor_program_status(
        self,
        program_name: str,
        *,
        timeout_seconds: int = 10,
    ) -> tuple[bool, str]:
        try:
            status = subprocess.run(
                [
                    "supervisorctl",
                    "-c",
                    "/etc/supervisord.conf",
                    "status",
                    program_name,
                ],
                capture_output=True,
                timeout=timeout_seconds,
            )
        except Exception as exc:
            return False, public_error_message(
                exc,
                default=f"Failed to inspect {program_name} supervisor status.",
            )
        detail = (
            _decode_completed(status).strip() or f"{program_name} status unavailable."
        )
        for line in detail.splitlines():
            parts = line.split(None, 2)
            if parts and parts[0] == program_name:
                return len(parts) > 1 and parts[1] == "RUNNING", detail
        return False, detail

    def _supervisor_programs_health(self) -> dict[str, Any]:
        programs = ("squid", "cicap_adblock", "cicap_av", "proxy_api", "proxy_agent")
        statuses: dict[str, dict[str, Any]] = {
            program: {"ok": False, "detail": f"{program} status unavailable."}
            for program in programs
        }
        try:
            status = subprocess.run(
                ["supervisorctl", "-c", "/etc/supervisord.conf", "status", *programs],
                capture_output=True,
                timeout=2,
            )
            output = _decode_completed(status).strip()
        except Exception as exc:
            detail = public_error_message(
                exc,
                default="Failed to inspect supervisor status.",
            )
            return {
                "ok": False,
                "detail": detail,
                "programs": {
                    program: {"ok": False, "detail": detail} for program in programs
                },
            }

        for line in output.splitlines():
            parts = line.split(None, 2)
            if not parts:
                continue
            program = parts[0]
            if program not in statuses:
                continue
            statuses[program] = {
                "ok": len(parts) > 1 and parts[1] == "RUNNING",
                "detail": line.strip(),
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
    …16144 tokens truncated…   def sync_from_db(
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
            except Exception:
                claimed_operations = []
                ledger = None
            try:
                result = self._sync_from_db_unlocked(
                    force=force,
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
        operations: list[Any] | None = None,
    ) -> dict[str, Any]:
        self._invalidate_health_cache()
        self.ensure_registered()
        self.bootstrap_revision_if_missing()
        cert_result = self.sync_certificate_bundle(force=force)
        cert_ok = bool(cert_result.get("ok", True))
        cert_changed = bool(cert_result.get("changed", False))
        detail_parts = (
            [str(cert_result.get("detail") or "").strip()]
            if str(cert_result.get("detail") or "").strip()
            else []
        )
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
            return cert_result

        policy_result = self.sync_policy_state(force=force)
        policy_ok = bool(policy_result.get("ok", True))
        policy_changed = bool(policy_result.get("changed", False))
        policy_reload_required = bool(policy_result.get("reload_required", False))
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
            policy_result["detail"] = detail
            return policy_result

        adblock_result = self.sync_adblock_state(force=force)
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
            adblock_result["detail"] = detail
            return adblock_result

        pac_result = self.sync_pac_state(force=force)
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
            pac_result["detail"] = detail
            return pac_result

        operation_types = {
            str(getattr(operation, "operation_type", "") or "")
            for operation in (operations or [])
        }
        cache_cleared = False
        if "cache_clear" in operation_types:
            cache_ok, cache_detail = self.controller.clear_disk_cache()
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
                    "changed": bool(cert_changed or policy_changed or adblock_changed or pac_changed),
                    "cache_cleared": False,
                    "certificate_changed": cert_changed,
                    "policy_changed": policy_changed,
                    "adblock_changed": adblock_changed,
                    "pac_changed": pac_changed,
                    "config_changed": False,
                    "current_config_sha": self._current_config_sha(),
                }

        current_sha = self._current_config_sha()
        clamav_runtime_changed = False
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
                    "changed": cert_changed
                    or policy_changed
                    or adblock_changed
                    or pac_changed,
                    "certificate_changed": cert_changed,
                    "policy_changed": policy_changed,
                    "adblock_changed": adblock_changed,
                    "pac_changed": pac_changed,
                    "cache_cleared": cache_cleared,
                    "config_changed": False,
                    "detail": detail,
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
                "changed": cert_changed
                or policy_changed
                or adblock_changed
                or pac_changed,
                "certificate_changed": cert_changed,
                "policy_changed": policy_changed,
                "adblock_changed": adblock_changed,
                "pac_changed": pac_changed,
                "cache_cleared": cache_cleared,
                "config_changed": bool(policy_config_changed),
                "detail": detail,
            }
        if policy_config_changed:
            current_sha = self._current_config_sha()
        revision_meta = self.revisions.get_active_revision_metadata(self.proxy_id)
        if revision_meta is None:
            reload_ok = True
            if policy_reload_required or adblock_changed or clamav_runtime_changed:
                reload_ok, reload_detail = self._reload_for_policy_update()
                if reload_detail:
                    detail_parts.append(reload_detail)
            detail = (
                "\n".join(detail_parts).strip()
                or "No active config revision is available for this proxy."
            )
            result = {
                "ok": reload_ok,
                "proxy_id": self.proxy_id,
                "changed": cert_changed
                or policy_changed
                or adblock_changed
                or pac_changed
                or clamav_runtime_changed
                or policy_config_changed,
                "certificate_changed": cert_changed,
                "policy_changed": policy_changed,
                "adblock_changed": adblock_changed,
                "pac_changed": pac_changed,
                "cache_cleared": cache_cleared,
                "config_changed": bool(policy_config_changed),
                "detail": detail,
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
                "changed": cert_changed
                or policy_changed
                or adblock_changed
                or pac_changed
                or clamav_runtime_changed
                or policy_config_changed,
                "certificate_changed": cert_changed,
                "policy_changed": policy_changed,
                "adblock_changed": adblock_changed,
                "pac_changed": pac_changed,
                "cache_cleared": cache_cleared,
                "config_changed": bool(policy_config_changed),
                "rollback_active": True,
                "detail": detail,
            }

        if not force and revision_meta.config_sha256 == current_sha:
            reload_ok = True
            if policy_reload_required or adblock_changed or clamav_runtime_changed:
                reload_ok, reload_detail = self._reload_for_policy_update()
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
                "changed": cert_changed
                or policy_changed
                or adblock_changed
                or pac_changed
                or clamav_runtime_changed
                or policy_config_changed,
                "certificate_changed": cert_changed,
                "policy_changed": policy_changed,
                "adblock_changed": adblock_changed,
                "pac_changed": pac_changed,
                "cache_cleared": cache_cleared,
                "config_changed": bool(policy_config_changed),
                "detail": detail,
            }

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
                "changed": cert_changed
                or policy_changed
                or adblock_changed
                or pac_changed
                or clamav_runtime_changed
                or policy_config_changed,
                "certificate_changed": cert_changed,
                "policy_changed": policy_changed,
                "adblock_changed": adblock_changed,
                "pac_changed": pac_changed,
                "cache_cleared": cache_cleared,
                "config_changed": bool(policy_config_changed),
                "detail": detail,
            }

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
            policy_reload_ok, policy_reload_detail = self._reload_for_policy_update()
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
        }

    def clear_cache(self) -> dict[str, Any]:
        self._invalidate_health_cache()
        ok, detail = self.controller.clear_disk_cache()
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
