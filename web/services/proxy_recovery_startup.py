from __future__ import annotations

import logging
import os
import socket
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from pathlib import Path

from services import proxy_recovery
from services.db import connect
from services.proxy_recovery_db import capture_and_write_recovery_bundle
from services.proxy_recovery_restore import (
    ProxyRecoveryRestoreError,
    RestoreResult,
    restore_recovery_bundle,
)
from services.proxy_registry import (
    resolve_local_proxy_management_url,
    resolve_local_proxy_public_fields,
)
from services.schema_lifecycle import ensure_startup_schema_if_configured

logger = logging.getLogger(__name__)

StartupRecoveryStatus = Literal[
    "missing_bundle",
    "adopted",
    "already_adopted",
    "same_control_plane",
]

_RECOVERY_OK_STATUSES = frozenset({"adopted", "already_adopted", "same_control_plane"})
_RECOVERY_CAPTURE_MIN_INTERVAL_SECONDS = 300.0


class ProxyRecoveryStartupError(proxy_recovery.ProxyRecoveryError):
    """Raised when startup must fail closed before normal DB mutation."""


class ProxyRecoveryCaptureError(proxy_recovery.ProxyRecoveryError):
    """Raised when a required recovery capture cannot be written."""


@dataclass(frozen=True)
class StartupRecoveryResult:
    status: StartupRecoveryStatus
    proxy_id: str
    bundle_present: bool = False
    capture_required: bool = False
    detail: str = ""
    restore_result: RestoreResult | None = None


@dataclass(frozen=True)
class RecoveryCaptureResult:
    ok: bool
    proxy_id: str
    path: str = ""
    reason: str = ""
    required: bool = False
    skipped: bool = False
    detail: str = ""


def run_startup_recovery(
    *,
    proxy_id: str,
    registry: Any,
    ensure_schema=ensure_startup_schema_if_configured,
    connect_factory=connect,
    recovery_dir: str | Path | None = None,
    max_bundle_bytes: int = proxy_recovery.DEFAULT_MAX_BUNDLE_BYTES,
) -> StartupRecoveryResult:
    """Adopt a proxy-local recovery bundle before normal startup mutation.

    The only DB write before restore is the minimal proxy registry row required by
    existing lifecycle write-guard semantics.  Normal registration reconciliation,
    config bootstrap, and refresh/apply are intentionally left to the caller after
    this function returns an explicit success/skip result.
    """
    normalized_proxy_id = proxy_recovery.normalize_proxy_id(proxy_id)
    state = _recovery_file_state(normalized_proxy_id, recovery_dir)
    bundle_exists = state["bundle_exists"]
    key_exists = state["key_exists"]

    if not bundle_exists:
        if key_exists:
            logger.info(
                "Proxy recovery startup skipped for proxy_id=%s status=missing_bundle detail=key_without_bundle",
                normalized_proxy_id,
            )
        else:
            logger.info(
                "Proxy recovery startup skipped for proxy_id=%s status=missing_bundle",
                normalized_proxy_id,
            )
        return StartupRecoveryResult(
            status="missing_bundle",
            proxy_id=normalized_proxy_id,
            bundle_present=False,
            capture_required=True,
            detail="no proxy-local recovery bundle is present",
        )
    if not key_exists:
        raise ProxyRecoveryStartupError(
            _manual_recovery_message(
                normalized_proxy_id,
                "recovery bundle is present but the signing key is missing",
            ),
        )

    try:
        ensure_schema()
    except Exception as exc:
        raise ProxyRecoveryStartupError(
            _manual_recovery_message(
                normalized_proxy_id,
                "schema migration/control-plane identity setup failed before recovery adoption",
            ),
        ) from exc

    _register_minimal_proxy_identity(registry, normalized_proxy_id)

    try:
        bundle = proxy_recovery.read_recovery_bundle(
            normalized_proxy_id,
            recovery_dir=recovery_dir,
            max_bundle_bytes=max_bundle_bytes,
        )
    except Exception as exc:
        raise ProxyRecoveryStartupError(
            _manual_recovery_message(
                normalized_proxy_id,
                "recovery bundle/key validation failed",
            ),
        ) from exc

    try:
        with connect_factory() as conn:
            result = restore_recovery_bundle(conn, bundle, normalized_proxy_id)
    except ProxyRecoveryRestoreError as exc:
        raise ProxyRecoveryStartupError(
            _manual_recovery_message(normalized_proxy_id, str(exc)),
        ) from exc
    except Exception as exc:
        raise ProxyRecoveryStartupError(
            _manual_recovery_message(
                normalized_proxy_id,
                "database restore failed before normal startup mutation",
            ),
        ) from exc

    if result.status == "not_eligible":
        reason = result.reason or "target database is not fresh enough for recovery adoption"
        raise ProxyRecoveryStartupError(_manual_recovery_message(normalized_proxy_id, reason))
    if result.status not in _RECOVERY_OK_STATUSES:
        raise ProxyRecoveryStartupError(
            _manual_recovery_message(
                normalized_proxy_id,
                f"unexpected recovery status {result.status!r}",
            ),
        )

    logger.info(
        "Proxy recovery startup completed for proxy_id=%s status=%s restored_rows=%s",
        normalized_proxy_id,
        result.status,
        result.restored_rows,
    )
    return StartupRecoveryResult(
        status=result.status,  # type: ignore[arg-type]
        proxy_id=normalized_proxy_id,
        bundle_present=True,
        capture_required=False,
        detail=result.reason,
        restore_result=result,
    )


def capture_recovery_bundle_after_authoritative_state(
    *,
    proxy_id: str,
    reason: str,
    required: bool = False,
    changed: bool = False,
    connect_factory=connect,
    recovery_dir: str | Path | None = None,
    max_bundle_bytes: int = proxy_recovery.DEFAULT_MAX_BUNDLE_BYTES,
    now_mono: float | None = None,
    last_capture_mono: float = 0.0,
    min_interval_seconds: float = _RECOVERY_CAPTURE_MIN_INTERVAL_SECONDS,
) -> RecoveryCaptureResult:
    normalized_proxy_id = proxy_recovery.normalize_proxy_id(proxy_id)
    reason_text = _safe_reason(reason)
    current_mono = time.monotonic() if now_mono is None else float(now_mono)
    if (
        not required
        and not changed
        and last_capture_mono > 0
        and current_mono - last_capture_mono < max(0.0, float(min_interval_seconds))
    ):
        return RecoveryCaptureResult(
            ok=True,
            proxy_id=normalized_proxy_id,
            reason=reason_text,
            skipped=True,
            detail="recovery capture skipped by interval gate",
        )
    try:
        path = capture_and_write_recovery_bundle(
            connect_factory,
            normalized_proxy_id,
            recovery_dir=recovery_dir,
            max_bundle_bytes=max_bundle_bytes,
        )
    except Exception as exc:
        detail = "required recovery capture failed" if required else "recovery capture failed"
        if required:
            raise ProxyRecoveryCaptureError(
                _manual_recovery_message(normalized_proxy_id, detail),
            ) from exc
        logger.warning(
            "Proxy recovery capture failed for proxy_id=%s reason=%s required=%s: %s",
            normalized_proxy_id,
            reason_text,
            required,
            exc.__class__.__name__,
        )
        return RecoveryCaptureResult(
            ok=False,
            proxy_id=normalized_proxy_id,
            reason=reason_text,
            required=required,
            detail=detail,
        )
    logger.info(
        "Proxy recovery capture completed for proxy_id=%s reason=%s required=%s",
        normalized_proxy_id,
        reason_text,
        required,
    )
    return RecoveryCaptureResult(
        ok=True,
        proxy_id=normalized_proxy_id,
        path=str(path),
        reason=reason_text,
        required=required,
    )


def _register_minimal_proxy_identity(registry: Any, proxy_id: str) -> Any:
    display_name = (os.environ.get("PROXY_DISPLAY_NAME") or proxy_id).strip() or proxy_id
    hostname = (os.environ.get("PROXY_HOSTNAME") or socket.gethostname()).strip()
    public_fields = resolve_local_proxy_public_fields()
    management_url = resolve_local_proxy_management_url(
        proxy_id,
        public_fields.get("public_host"),
    )
    return registry.ensure_proxy(
        proxy_id,
        display_name=display_name,
        hostname=hostname,
        management_url=management_url,
        public_host=str(public_fields.get("public_host") or ""),
        public_pac_scheme=str(public_fields.get("public_pac_scheme") or "http"),
        public_pac_port=int(public_fields.get("public_pac_port") or 80),
        public_pac_path=str(public_fields.get("public_pac_path") or "/proxy.pac"),
        public_http_proxy_port=int(public_fields.get("public_http_proxy_port") or 3128),
        status="starting",
        detail="proxy recovery startup identity guard",
    )


def _recovery_file_state(proxy_id: str, recovery_dir: str | Path | None) -> dict[str, bool]:
    bundle_path = proxy_recovery.bundle_path_for_proxy(proxy_id, recovery_dir)
    key_path = proxy_recovery.key_path_for_proxy(proxy_id, recovery_dir)
    return {
        "bundle_exists": _path_exists_no_follow(bundle_path),
        "key_exists": _path_exists_no_follow(key_path),
    }


def _path_exists_no_follow(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


def _safe_reason(reason: str) -> str:
    text = str(reason or "runtime").strip().lower().replace(" ", "_")
    safe = "".join(ch for ch in text if ch.isalnum() or ch in {"_", "-", "."})
    return safe[:64] or "runtime"


def _manual_recovery_message(proxy_id: str, reason: str) -> str:
    return (
        f"Proxy recovery adoption failed closed for proxy_id={proxy_id}: {reason}. "
        "Normal startup was stopped before declarative DB refresh. Preserve the recovery bundle/key "
        "and perform manual recovery or start against a fresh replacement control plane."
    )
