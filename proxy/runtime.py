from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import logging
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from typing import Any, Dict

from services.adblock_artifacts import get_adblock_artifacts, materialize_archive_to_directory, read_materialized_artifact_sha
from services.adblock_store import get_adblock_store
from services.certificate_bundles import get_certificate_bundles
from services.certificate_core import CertManager, materialize_certificate_bundle
from services.config_revisions import get_config_revisions
from services.diagnostic_store import get_diagnostic_store
from services.errors import public_error_message
from services.health_checks import build_clamav_health
from services.live_stats import get_store
from services.logutil import log_exception_throttled
from services.policy_materializer import MaterializedPolicyFile, build_proxy_policy_state, calculate_policy_sha
from services.proxy_health import check_adblock_icap_health as _check_icap_adblock, check_av_icap_health as _check_icap_av, check_clamd_health as _check_clamd, send_sample_av_icap as _shared_send_sample_av_icap, test_eicar as _shared_test_eicar
from services.proxy_context import get_proxy_id
from services.proxy_registry import get_proxy_registry, resolve_local_proxy_public_fields
from services.pac_renderer import PAC_RENDER_DIR, build_proxy_pac_state, materialize_proxy_pac_state, read_materialized_pac_state_sha
from services.runtime_helpers import decode_bytes as _decode_bytes
from services.squid_core import SquidController
from services.ssl_errors_store import get_ssl_errors_store
from services.stats import get_stats
from services.timeseries_store import get_timeseries_store


logger = logging.getLogger(__name__)


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
    certs_dir = (os.environ.get("CERTS_DIR") or "/etc/squid/ssl/certs").strip() or "/etc/squid/ssl/certs"
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


def build_local_runtime_services(*, error_formatter=str, icap_timeout: float = 0.8, tcp_timeout: float = 0.75) -> Dict[str, Dict[str, Any]]:
    icap = _call_health_check(_check_icap_adblock, timeout=icap_timeout, error_formatter=error_formatter)
    av_icap = _call_health_check(_check_icap_av, timeout=icap_timeout, error_formatter=error_formatter)
    clamd = _call_health_check(_check_clamd, timeout=icap_timeout, error_formatter=error_formatter)
    return {
        "icap": icap,
        "av_icap": av_icap,
        "clamd": clamd,
        "clamav": build_clamav_health(clamd, av_icap),
    }

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
        self.ssl_db_dir = (os.environ.get("SSL_DB_DIR") or "/var/lib/ssl_db/store").strip() or "/var/lib/ssl_db/store"
        self.adblock_compiled_dir = (os.environ.get("ADBLOCK_COMPILED_DIR") or self.adblock_artifacts.compiled_dir).strip() or self.adblock_artifacts.compiled_dir
        self.pac_render_dir = (os.environ.get("PAC_RENDER_DIR") or PAC_RENDER_DIR).strip() or PAC_RENDER_DIR
        try:
            self.health_cache_ttl_seconds = max(0.0, min(30.0, float((os.environ.get("PROXY_HEALTH_CACHE_TTL_SECONDS") or "3.0").strip() or "3.0")))
        except Exception:
            self.health_cache_ttl_seconds = 3.0
        self._health_cache_lock = threading.Lock()
        self._health_cache_ts = 0.0
        self._health_cache_value: Dict[str, Any] | None = None

    @property
    def proxy_id(self) -> str:
        return get_proxy_id()

    def ensure_registered(self) -> None:
        self.registry.register_local_proxy()

    def _invalidate_health_cache(self) -> None:
        with self._health_cache_lock:
            self._health_cache_ts = 0.0
            self._health_cache_value = None

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
            with open(path, "r", encoding="utf-8") as fh:
                return fh.read()
        except FileNotFoundError:
            return ""
        except Exception:
            return ""

    def _atomic_write_text(self, path: str, content: str) -> None:
        directory = os.path.dirname(path) or "."
        os.makedirs(directory, exist_ok=True)
        handle = None
        tmp_path = ""
        try:
            handle = tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False, dir=directory, prefix=".tmp-")
            tmp_path = handle.name
            handle.write(content)
            handle.flush()
            handle.close()
            handle = None
            os.replace(tmp_path, path)
        finally:
            if handle is not None:
                try:
                    handle.close()
                except Exception:
                    pass
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass

    def _current_policy_sha(self) -> str:
        if self.services.current_policy_sha_reader is not None:
            return str(self.services.current_policy_sha_reader() or "")
        desired = self.policy_state_builder(self.proxy_id)
        current_files = tuple(
            MaterializedPolicyFile(path=item.path, content=self._read_text_file(item.path))
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

    def _restart_supervisor_program(self, program_name: str, *, timeout_seconds: int = 30) -> tuple[bool, str]:
        try:
            proc = subprocess.run(
                ["supervisorctl", "-c", "/etc/supervisord.conf", "restart", program_name],
                capture_output=True,
                timeout=timeout_seconds,
            )
        except Exception as exc:
            return False, public_error_message(exc, default=f"Failed to restart {program_name}.")
        detail = _decode_completed(proc).strip() or f"{program_name} restarted."
        return proc.returncode == 0, detail

    def _restart_adblock_service(self) -> tuple[bool, str]:
        if self.services.adblock_service_restarter is not None:
            return self.services.adblock_service_restarter()
        return self._restart_supervisor_program("cicap_adblock")

    def _reload_for_policy_update(self) -> tuple[bool, str]:
        result = self.controller.reload_squid()
        if isinstance(result, tuple) and len(result) == 2:
            stdout, stderr = result
        else:
            stdout, stderr = b"", b""
        detail = (_decode_bytes(stdout) + "\n" + _decode_bytes(stderr)).strip()
        return (not bool(stderr)), detail or "Squid reloaded."

    def _find_sslcrtd_binary(self) -> str:
        candidates = [
            shutil.which("ssl_crtd"),
            "/usr/lib/squid/ssl_crtd",
            "/usr/libexec/squid/ssl_crtd",
            "/usr/lib/squid/security_file_certgen",
            "/usr/libexec/squid/security_file_certgen",
        ]
        for candidate in candidates:
            if candidate and os.path.exists(candidate) and os.access(candidate, os.X_OK):
                return candidate
        return ""

    def _reinitialize_ssl_db_and_restart(self) -> tuple[bool, str]:
        if self.services.ssl_db_reinitializer is not None:
            return self.services.ssl_db_reinitializer()
        ssl_db_dir = self.ssl_db_dir
        if not ssl_db_dir.startswith("/") or ssl_db_dir in ("/", "/etc", "/usr", "/var", "/var/lib"):
            return False, f"Refusing to reinitialize ssl_db at unsafe path: {ssl_db_dir}"

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
                fallback = subprocess.run(["squid", "-k", "shutdown"], capture_output=True, timeout=10)
                decoded = _decode_completed(fallback)
                if decoded:
                    details.append(decoded)
            except Exception as inner_exc:
                details.append(f"squid shutdown fallback failed: {inner_exc}")

        parent_dir = os.path.dirname(ssl_db_dir) or "/var/lib/ssl_db"
        try:
            shutil.rmtree(ssl_db_dir, ignore_errors=True)
            os.makedirs(parent_dir, exist_ok=True)
        except Exception as exc:
            details.append(f"Failed to clear ssl_db directory: {exc}")
            return False, "\n".join([part for part in details if part]).strip()

        init_script = "/scripts/init_ssl_db.sh"
        if os.path.exists(init_script):
            try:
                env = os.environ.copy()
                env["SSL_DB_DIR"] = ssl_db_dir
                initialized = subprocess.run(["sh", init_script], capture_output=True, timeout=90, env=env)
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
                initialized = subprocess.run([helper, "-c", "-s", ssl_db_dir, "-M", "16MB"], capture_output=True, timeout=90)
            except Exception as exc:
                details.append(f"Failed to initialize ssl_db: {exc}")
                return False, "\n".join([part for part in details if part]).strip()

            if initialized.returncode != 0:
                details.append(_decode_completed(initialized) or "ssl_crtd initialization failed")
                return False, "\n".join([part for part in details if part]).strip()

            details.append(_decode_completed(initialized) or f"Reinitialized ssl_db at {ssl_db_dir}.")
            try:
                repair = subprocess.run(
                    [
                        "sh",
                        "-lc",
                        'chmod 700 "$1" 2>/dev/null || true; [ -d "$1/certs" ] && chmod 750 "$1/certs" 2>/dev/null || true; if getent passwd squid >/dev/null 2>&1; then chown -R squid:squid "$(dirname \"$1\")"; fi',
                        "sh",
                        ssl_db_dir,
                    ],
                    capture_output=True,
                    timeout=20,
                )
                if repair.returncode != 0:
                    details.append(_decode_completed(repair) or "Failed to repair ssl_db ownership and permissions.")
                    return False, "\n".join([part for part in details if part]).strip()
            except Exception as exc:
                details.append(f"Failed to repair ssl_db ownership and permissions: {exc}")
                return False, "\n".join([part for part in details if part]).strip()

        try:
            os.chmod(ssl_db_dir, 0o700)
            certs_dir = os.path.join(ssl_db_dir, "certs")
            if os.path.isdir(certs_dir):
                os.chmod(certs_dir, 0o750)
        except Exception:
            pass

        ok_restart, restart_detail = self.controller.restart_squid()
        if restart_detail:
            details.append(restart_detail)
        return ok_restart, "\n".join([part for part in details if part]).strip()

    def sync_policy_state(self, *, force: bool = False) -> Dict[str, Any]:
        desired = self.policy_state_builder(self.proxy_id)
        current_sha = self._current_policy_sha()
        if not force and desired.policy_sha256 == current_sha:
            return {
                "ok": True,
                "proxy_id": self.proxy_id,
                "changed": False,
                "reload_required": False,
                "policy_sha256": desired.policy_sha256,
                "detail": "Proxy is already using the active policy materialization.",
            }

        changed_paths: list[str] = []
        try:
            for item in desired.files:
                current_content = self._read_text_file(item.path)
                if current_content == item.content:
                    continue
                self._atomic_write_text(item.path, item.content)
                changed_paths.append(item.path)
        except Exception as exc:
            return {
                "ok": False,
                "proxy_id": self.proxy_id,
                "changed": False,
                "reload_required": False,
                "policy_sha256": desired.policy_sha256,
                "detail": public_error_message(exc, default="Failed to materialize policy state."),
            }

        if not changed_paths:
            return {
                "ok": True,
                "proxy_id": self.proxy_id,
                "changed": False,
                "reload_required": False,
                "policy_sha256": desired.policy_sha256,
                "detail": "Policy materialization is already current.",
            }

        return {
            "ok": True,
            "proxy_id": self.proxy_id,
            "changed": True,
            "reload_required": True,
            "policy_sha256": desired.policy_sha256,
            "detail": f"Updated {len(changed_paths)} local policy file(s).",
        }

    def sync_adblock_state(self, *, force: bool = False) -> Dict[str, Any]:
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
                except Exception:
                    pass
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

        artifact_changed = bool(force or revision_meta.artifact_sha256 != current_sha)
        if not artifact_changed and not flush_requested:
            return {
                "ok": True,
                "proxy_id": self.proxy_id,
                "changed": False,
                "artifact_changed": False,
                "cache_flushed": False,
                "revision_id": revision_meta.revision_id,
                "artifact_sha256": revision_meta.artifact_sha256,
                "detail": "Proxy is already using the active adblock artifact.",
            }

        revision = self.adblock_artifacts.get_active_artifact()
        if revision is None:
            return {
                "ok": False,
                "proxy_id": self.proxy_id,
                "changed": False,
                "artifact_changed": False,
                "cache_flushed": False,
                "revision_id": None,
                "artifact_sha256": "",
                "detail": "Active adblock artifact metadata was present, but the full artifact could not be loaded.",
            }

        if artifact_changed:
            try:
                materialize_archive_to_directory(
                    self.adblock_compiled_dir,
                    archive_blob=revision.archive_blob,
                    artifact_sha256=revision.artifact_sha256,
                )
            except Exception as exc:
                detail = public_error_message(exc, default="Failed to materialize adblock artifact.")
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

        ok_restart, restart_detail = self._restart_adblock_service()
        if ok_restart and flush_requested:
            try:
                store.mark_cache_flushed(size=0)
            except Exception:
                pass
        detail = restart_detail.strip() or "Adblock artifact applied."
        applied = self.adblock_artifacts.record_apply_result(
            self.proxy_id,
            revision.revision_id,
            ok=ok_restart,
            detail=detail,
            applied_by="proxy",
            artifact_sha256=revision.artifact_sha256,
        )
        return {
            "ok": ok_restart,
            "proxy_id": self.proxy_id,
            "changed": bool(artifact_changed or flush_requested),
            "artifact_changed": artifact_changed,
            "cache_flushed": bool(ok_restart and flush_requested),
            "revision_id": revision.revision_id,
            "application_id": applied.application_id,
            "artifact_sha256": revision.artifact_sha256,
            "detail": detail,
        }

    def sync_pac_state(self, *, force: bool = False) -> Dict[str, Any]:
        desired = self.pac_state_builder(self.proxy_id)
        current_sha = self._current_pac_state_sha()
        if not force and desired.state_sha256 == current_sha:
            return {
                "ok": True,
                "proxy_id": self.proxy_id,
                "changed": False,
                "state_sha256": desired.state_sha256,
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
                "detail": public_error_message(exc, default="Failed to materialize PAC state."),
            }

        return {
            "ok": True,
            "proxy_id": self.proxy_id,
            "changed": True,
            "state_sha256": desired.state_sha256,
            "detail": "PAC state materialized locally.",
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

    def sync_certificate_bundle(self, *, force: bool = False) -> Dict[str, Any]:
        revision_meta = self.certificate_bundles.get_active_bundle_metadata()
        if revision_meta is None:
            return {
                "ok": True,
                "proxy_id": self.proxy_id,
                "changed": False,
                "detail": "",
                "revision_id": None,
            }

        current_sha = self._current_certificate_bundle_sha()
        if not force and revision_meta.bundle_sha256 == current_sha:
            return {
                "ok": True,
                "proxy_id": self.proxy_id,
                "revision_id": revision_meta.revision_id,
                "changed": False,
                "detail": "Proxy is already using the active certificate bundle.",
                "bundle_sha256": revision_meta.bundle_sha256,
            }

        revision = self.certificate_bundles.get_active_bundle()
        if revision is None:
            return {
                "ok": False,
                "proxy_id": self.proxy_id,
                "revision_id": None,
                "changed": False,
                "detail": "Active certificate metadata was present, but the full bundle could not be loaded.",
                "bundle_sha256": "",
            }

        try:
            materialize_certificate_bundle(
                self.cert_manager.ca_dir,
                revision.to_bundle(),
                original_pfx_bytes=revision.original_pfx_blob,
            )
        except Exception as exc:
            detail = public_error_message(exc, default="Failed to materialize certificate bundle.")
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
                "revision_id": revision.revision_id,
                "application_id": applied.application_id,
                "changed": False,
                "detail": detail,
                "bundle_sha256": revision.bundle_sha256,
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
            "revision_id": revision.revision_id,
            "application_id": applied.application_id,
            "changed": ok_restart,
            "detail": detail,
            "bundle_sha256": revision.bundle_sha256,
        }

    def start_background_tasks(self) -> None:
        if (os.environ.get("DISABLE_BACKGROUND") or "").strip() == "1":
            return
        self.live_stats_store.start_background()
        self.diagnostic_store.start_background()
        self.timeseries_store.start_background(self.stats_provider)
        self.ssl_errors_store.start_background()
        try:
            self.adblock_store.start_blocklog_background()
        except Exception:
            pass

    def collect_health(self, *, force: bool = False) -> Dict[str, Any]:
        if not force and self.health_cache_ttl_seconds > 0:
            now_mono = time.monotonic()
            with self._health_cache_lock:
                cached = self._health_cache_value
                if cached is not None and (now_mono - self._health_cache_ts) < self.health_cache_ttl_seconds:
                    return cached

        stdout, stderr = self.controller.get_status()
        proxy_status = (_decode_bytes(stdout) + "\n" + _decode_bytes(stderr)).strip()
        proxy_ok = not bool(stderr)
        stats = self.stats_provider()
        services = self.runtime_services_builder(error_formatter=str, icap_timeout=0.8, tcp_timeout=0.75)
        active_revision = self.revisions.get_active_revision_metadata(self.proxy_id)
        active_certificate = self.certificate_bundles.get_active_bundle_metadata()
        active_adblock_artifact = self.adblock_artifacts.get_active_artifact_metadata()
        current_sha = self._current_config_sha()
        current_certificate_sha = self._current_certificate_bundle_sha()
        current_adblock_sha = self._current_adblock_artifact_sha()
        state_errors: list[str] = []
        desired_policy_sha = ""
        current_policy_sha = ""
        desired_pac_sha = ""
        current_pac_sha = self._current_pac_state_sha()

        try:
            desired_policy = self.policy_state_builder(self.proxy_id)
            desired_policy_sha = desired_policy.policy_sha256
            current_policy_sha = calculate_policy_sha(
                tuple(
                    MaterializedPolicyFile(path=item.path, content=self._read_text_file(item.path))
                    for item in desired_policy.files
                )
            )
        except Exception as exc:
            state_errors.append(f"policy: {public_error_message(exc, default='Failed to inspect desired proxy policy state.')}")
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
            state_errors.append(f"pac: {public_error_message(exc, default='Failed to inspect desired PAC state.')}")
            log_exception_throttled(
                logger,
                "proxy_runtime.collect_health.pac",
                interval_seconds=30.0,
                message="Failed to collect proxy PAC health state",
            )

        ok = proxy_ok and all(bool(item.get("ok")) for item in services.values()) and not state_errors
        result = {
            "ok": ok,
            "status": "healthy" if ok else "degraded",
            "proxy_id": self.proxy_id,
            "proxy_status": proxy_status,
            "stats": stats,
            "services": services,
            "active_revision_id": active_revision.revision_id if active_revision else None,
            "active_revision_sha": active_revision.config_sha256 if active_revision else "",
            "current_config_sha": current_sha,
            "active_certificate_revision_id": active_certificate.revision_id if active_certificate else None,
            "active_certificate_sha": active_certificate.bundle_sha256 if active_certificate else "",
            "current_certificate_sha": current_certificate_sha,
            "active_adblock_revision_id": active_adblock_artifact.revision_id if active_adblock_artifact else None,
            "active_adblock_sha": active_adblock_artifact.artifact_sha256 if active_adblock_artifact else "",
            "current_adblock_sha": current_adblock_sha,
            "desired_policy_sha": desired_policy_sha,
            "current_policy_sha": current_policy_sha,
            "desired_pac_sha": desired_pac_sha,
            "current_pac_sha": current_pac_sha,
            "state_errors": state_errors,
            "timestamp": int(time.time()),
        }
        if self.health_cache_ttl_seconds > 0:
            with self._health_cache_lock:
                self._health_cache_value = result
                self._health_cache_ts = time.monotonic()
        return result

    def heartbeat(self) -> Dict[str, Any]:
        health = self.collect_health()
        public_fields = resolve_local_proxy_public_fields()
        self.registry.heartbeat(
            self.proxy_id,
            status=str(health.get("status") or "unknown"),
            hostname=(os.environ.get("PROXY_HOSTNAME") or socket.gethostname()).strip(),
            management_url=(os.environ.get("PROXY_MANAGEMENT_URL") or "").strip(),
            public_host=str(public_fields.get("public_host") or ""),
            public_pac_scheme=str(public_fields.get("public_pac_scheme") or "http"),
            public_pac_port=int(public_fields.get("public_pac_port") or 80),
            public_http_proxy_port=int(public_fields.get("public_http_proxy_port") or 3128),
            current_config_sha=str(health.get("current_config_sha") or ""),
            detail=str(health.get("proxy_status") or "")[:4000],
        )
        return health

    def sync_from_db(self, *, force: bool = False) -> Dict[str, Any]:
        self._invalidate_health_cache()
        self.ensure_registered()
        self.bootstrap_revision_if_missing()
        cert_result = self.sync_certificate_bundle(force=force)
        cert_ok = bool(cert_result.get("ok", True))
        cert_changed = bool(cert_result.get("changed", False))
        detail_parts = [str(cert_result.get("detail") or "").strip()] if str(cert_result.get("detail") or "").strip() else []
        if not cert_ok:
            detail = "\n".join(detail_parts).strip() or "Certificate bundle sync failed."
            self.registry.mark_apply_result(self.proxy_id, ok=False, detail=detail, current_config_sha=self._current_config_sha())
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
            self.registry.mark_apply_result(self.proxy_id, ok=False, detail=detail, current_config_sha=self._current_config_sha())
            policy_result["detail"] = detail
            return policy_result

        adblock_result = self.sync_adblock_state(force=force)
        adblock_ok = bool(adblock_result.get("ok", True))
        adblock_changed = bool(adblock_result.get("changed", False))
        if str(adblock_result.get("detail") or "").strip():
            detail_parts.append(str(adblock_result.get("detail") or "").strip())
        if not adblock_ok:
            detail = "\n".join(detail_parts).strip() or "Adblock artifact materialization failed."
            self.registry.mark_apply_result(self.proxy_id, ok=False, detail=detail, current_config_sha=self._current_config_sha())
            adblock_result["detail"] = detail
            return adblock_result

        pac_result = self.sync_pac_state(force=force)
        pac_ok = bool(pac_result.get("ok", True))
        pac_changed = bool(pac_result.get("changed", False))
        if str(pac_result.get("detail") or "").strip():
            detail_parts.append(str(pac_result.get("detail") or "").strip())
        if not pac_ok:
            detail = "\n".join(detail_parts).strip() or "PAC materialization failed."
            self.registry.mark_apply_result(self.proxy_id, ok=False, detail=detail, current_config_sha=self._current_config_sha())
            pac_result["detail"] = detail
            return pac_result

        current_sha = self._current_config_sha()
        revision_meta = self.revisions.get_active_revision_metadata(self.proxy_id)
        if revision_meta is None:
            reload_ok = True
            if policy_reload_required:
                reload_ok, reload_detail = self._reload_for_policy_update()
                if reload_detail:
                    detail_parts.append(reload_detail)
            detail = "\n".join(detail_parts).strip() or "No active config revision is available for this proxy."
            result = {
                "ok": reload_ok,
                "proxy_id": self.proxy_id,
                "changed": cert_changed or policy_changed or adblock_changed or pac_changed,
                "certificate_changed": cert_changed,
                "policy_changed": policy_changed,
                "adblock_changed": adblock_changed,
                "pac_changed": pac_changed,
                "config_changed": False,
                "detail": detail,
            }
            if policy_reload_required and not reload_ok:
                self.registry.mark_apply_result(self.proxy_id, ok=False, detail=detail, current_config_sha=current_sha)
            return result

        if not force and revision_meta.config_sha256 == current_sha:
            reload_ok = True
            if policy_reload_required:
                reload_ok, reload_detail = self._reload_for_policy_update()
                if reload_detail:
                    detail_parts.append(reload_detail)
            detail = "Proxy is already using the active config revision."
            if detail_parts:
                detail_parts.append(detail)
                detail = "\n".join(detail_parts).strip()
            if policy_reload_required and not reload_ok:
                self.registry.mark_apply_result(self.proxy_id, ok=False, detail=detail, current_config_sha=current_sha)
            return {
                "ok": reload_ok,
                "proxy_id": self.proxy_id,
                "revision_id": revision_meta.revision_id,
                "changed": cert_changed or policy_changed or adblock_changed or pac_changed,
                "certificate_changed": cert_changed,
                "policy_changed": policy_changed,
                "adblock_changed": adblock_changed,
                "pac_changed": pac_changed,
                "config_changed": False,
                "detail": detail,
            }

        revision = self.revisions.get_active_revision(self.proxy_id)
        if revision is None:
            detail = "Active config revision metadata was present, but the full config text could not be loaded."
            self.registry.mark_apply_result(self.proxy_id, ok=False, detail=detail, current_config_sha=current_sha)
            return {
                "ok": False,
                "proxy_id": self.proxy_id,
                "changed": cert_changed or policy_changed or adblock_changed or pac_changed,
                "certificate_changed": cert_changed,
                "policy_changed": policy_changed,
                "adblock_changed": adblock_changed,
                "pac_changed": pac_changed,
                "config_changed": False,
                "detail": detail,
            }

        normalized_revision_text = self.controller.normalize_config_text(revision.config_text)
        normalized_revision_sha = hashlib.sha256(normalized_revision_text.encode("utf-8", errors="replace")).hexdigest()

        ok, config_detail = self.controller.apply_config_text(normalized_revision_text)
        if config_detail.strip():
            detail_parts.append(config_detail.strip())
        detail = "\n".join([part for part in detail_parts if part]).strip() or config_detail
        applied = self.revisions.record_apply_result(
            self.proxy_id,
            revision.revision_id,
            ok=ok,
            detail=detail,
            applied_by="proxy",
        )
        new_sha = normalized_revision_sha if ok else current_sha
        self.registry.mark_apply_result(self.proxy_id, ok=ok, detail=detail, current_config_sha=new_sha)
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
            "config_changed": True,
            "detail": detail,
        }

    def clear_cache(self) -> Dict[str, Any]:
        self._invalidate_health_cache()
        ok, detail = self.controller.clear_disk_cache()
        self.registry.mark_apply_result(self.proxy_id, ok=ok, detail=detail, current_config_sha=self._current_config_sha())
        return {
            "ok": ok,
            "proxy_id": self.proxy_id,
            "detail": detail,
        }

    def test_clamav_eicar(self) -> Dict[str, Any]:
        result = _shared_test_eicar(error_formatter=str)
        return {
            "ok": bool(result.get("ok")),
            "proxy_id": self.proxy_id,
            "detail": str(result.get("detail") or ""),
        }

    def test_clamav_icap(self) -> Dict[str, Any]:
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
