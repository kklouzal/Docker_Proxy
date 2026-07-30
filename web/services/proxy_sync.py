from __future__ import annotations

import logging

from services.errors import public_error_message, redact_sensitive_text
from services.operation_ledger import (
    ProxyOperation,
    get_operation_ledger,
    normalize_operation_request_hash,
)
from services.proxy_context import normalize_proxy_id
from services.proxy_registry import get_proxy_registry

logger = logging.getLogger(__name__)


def _ephemeral_operation(
    proxy_id: object | None,
    *,
    status: str,
    operation_type: str,
    subject: str,
    summary: str,
    target_kind: str = "",
    target_ref: object | None = None,
    rollback_kind: str = "",
    rollback_ref: object | None = None,
    request_hash: str = "",
    detail: str = "",
    created_by: str = "",
    force: bool = False,
) -> ProxyOperation:
    """Build an in-memory operation for paths that cannot create a DB ledger row."""
    import time

    now = int(time.time())
    try:
        normalized_request_hash = normalize_operation_request_hash(request_hash)
    except ValueError:
        normalized_request_hash = ""
    return ProxyOperation(
        operation_id=0,
        proxy_id=normalize_proxy_id(proxy_id),
        status=status,
        operation_type=(operation_type or "sync")[:64],
        subject=(subject or "")[:255],
        summary=(summary or "")[:512],
        target_kind=(target_kind or "")[:64],
        target_ref=str(target_ref or "")[:255],
        rollback_kind=(rollback_kind or "")[:64],
        rollback_ref=str(rollback_ref or "")[:255],
        request_hash=normalized_request_hash,
        detail=(detail or "")[:4000],
        created_by=(created_by or "")[:255],
        created_ts=now,
        started_ts=0,
        completed_ts=now if status in {"applied", "failed"} else 0,
        updated_ts=now,
        force=bool(force),
    )


def request_proxy_reconcile(
    proxy_id: object | None,
    *,
    operation_type: str,
    subject: str,
    summary: str,
    target_kind: str = "",
    target_ref: object | None = None,
    rollback_kind: str = "",
    rollback_ref: object | None = None,
    request_hash: str = "",
    detail: str = "",
    created_by: str = "",
    force: bool = False,
) -> ProxyOperation:
    """Queue proxy reconciliation through the durable operation ledger.

    Admin mutations must not fall back to direct proxy syncs: the ledger is the
    source of truth for queued work, ownership, status, and revert visibility.
    If the ledger cannot be written, return a failed ephemeral operation so the
    caller can surface that the reconcile was not queued.
    """
    try:
        ledger = get_operation_ledger()
        op = ledger.create_operation(
            proxy_id,
            operation_type=operation_type,
            subject=subject,
            summary=summary,
            target_kind=target_kind,
            target_ref=target_ref,
            rollback_kind=rollback_kind,
            rollback_ref=rollback_ref,
            request_hash=request_hash,
            detail=detail,
            created_by=created_by,
            force=force,
        )
    except Exception as exc:
        error_detail = public_error_message(
            exc,
            default="The operation ledger is unavailable.",
            max_len=500,
        )
        failure_detail = (
            "Proxy reconcile was not queued because the operation ledger is unavailable."
        )
        if error_detail:
            failure_detail = f"{failure_detail} {error_detail}"
        if detail:
            failure_detail = f"{redact_sensitive_text(detail)}\n{failure_detail}".strip()
        return _ephemeral_operation(
            proxy_id,
            status="failed",
            operation_type=operation_type,
            subject=subject,
            summary=summary,
            target_kind=target_kind,
            target_ref=target_ref,
            rollback_kind=rollback_kind,
            rollback_ref=rollback_ref,
            request_hash=request_hash,
            detail=failure_detail,
            created_by=created_by,
            force=force,
        )
    return op


def canonical_registered_proxy_id(proxy: object) -> str:
    proxy_id = getattr(proxy, "proxy_id", proxy)
    raw_proxy_id = "" if proxy_id is None else str(proxy_id).strip()
    canonical_proxy_id = normalize_proxy_id(proxy_id)
    if not raw_proxy_id or raw_proxy_id != canonical_proxy_id:
        return ""
    return canonical_proxy_id


def _canonical_registered_proxy_id(proxy: object) -> str:
    return canonical_registered_proxy_id(proxy)


def nudge_registered_proxies(*, force: bool = False) -> tuple[int, int]:
    """Queue reconciliation operations for all registered proxies."""
    proxies = list(get_proxy_registry().list_proxies())
    total = len(proxies)
    queued = 0
    seen_proxy_ids: set[str] = set()
    for proxy in proxies:
        proxy_id = canonical_registered_proxy_id(proxy)
        if not proxy_id:
            logger.warning(
                "Skipping registered proxy with invalid proxy_id during reconciliation nudge: %r",
                getattr(proxy, "proxy_id", proxy),
            )
            continue
        if proxy_id in seen_proxy_ids:
            logger.warning(
                "Skipping duplicate registered proxy identity during reconciliation nudge: %s",
                proxy_id,
            )
            continue
        seen_proxy_ids.add(proxy_id)
        op = request_proxy_reconcile(
            proxy_id,
            operation_type="runtime_nudge",
            subject="Proxy reconciliation",
            summary="Proxy reconciliation queued from a shared artifact update.",
            detail="Shared artifact changed; proxy should reconcile on its next operation poll.",
            force=force,
        )
        if getattr(op, "operation_id", 0) and op.status == "pending":
            queued += 1
        elif not getattr(op, "operation_id", 0) and op.status == "failed":
            logger.warning(
                "Proxy reconciliation nudge was not queued for %s: %s",
                proxy_id,
                getattr(op, "detail", "") or "operation ledger returned a failed operation",
            )
        else:
            logger.warning(
                "Proxy reconciliation nudge did not create a pending operation for %s: operation_id=%r status=%r",
                proxy_id,
                getattr(op, "operation_id", 0),
                getattr(op, "status", ""),
            )
    return total, queued
