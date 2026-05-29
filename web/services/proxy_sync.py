from __future__ import annotations

from services.operation_ledger import ProxyOperation, get_operation_ledger
from services.proxy_context import normalize_proxy_id
from services.proxy_registry import get_proxy_registry


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
        request_hash=(request_hash or "")[:64],
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
        failure_detail = f"Proxy reconcile was not queued because the operation ledger is unavailable: {exc}"
        if detail:
            failure_detail = f"{detail}\n{failure_detail}".strip()
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


def nudge_registered_proxies(*, force: bool = False) -> tuple[int, int]:
    """Queue reconciliation operations for all registered proxies."""
    proxies = list(get_proxy_registry().list_proxies())
    total = len(proxies)
    queued = 0
    for proxy in proxies:
        proxy_id = getattr(proxy, "proxy_id", proxy)
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
    return total, queued
