from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


def _add_web_to_path() -> None:
    web_dir = Path(__file__).resolve().parents[1]
    if str(web_dir) not in sys.path:
        sys.path.insert(0, str(web_dir))


@pytest.fixture
def proxy_sync_module():
    _add_web_to_path()
    from services import proxy_sync  # type: ignore

    return proxy_sync


class _Registry:
    def __init__(self, proxy_ids: list[object]) -> None:
        self._proxies = [SimpleNamespace(proxy_id=proxy_id) for proxy_id in proxy_ids]

    def list_proxies(self):
        return list(self._proxies)


class _Ledger:
    def __init__(self, failing: set[str] | None = None) -> None:
        self.failing = failing or set()
        self.operations: list[SimpleNamespace] = []

    def create_operation(self, proxy_id, **kwargs):
        if str(proxy_id) in self.failing:
            msg = "ledger unavailable"
            raise RuntimeError(msg)
        op = SimpleNamespace(
            operation_id=len(self.operations) + 1,
            proxy_id=str(proxy_id),
            status="pending",
            **kwargs,
        )
        self.operations.append(op)
        return op


def test_nudge_registered_proxies_returns_zero_when_registry_empty(
    monkeypatch, proxy_sync_module
) -> None:
    monkeypatch.setattr(proxy_sync_module, "get_proxy_registry", lambda: _Registry([]))

    assert proxy_sync_module.nudge_registered_proxies(force=True) == (0, 0)


def test_nudge_registered_proxies_queues_operations_for_registered_proxies(
    monkeypatch, proxy_sync_module
) -> None:
    ledger = _Ledger()
    monkeypatch.setattr(
        proxy_sync_module, "get_proxy_registry", lambda: _Registry(["live", "edge-2"])
    )
    monkeypatch.setattr(proxy_sync_module, "get_operation_ledger", lambda: ledger)

    assert proxy_sync_module.nudge_registered_proxies(force=False) == (2, 2)
    assert [
        (op.proxy_id, op.operation_type, op.status) for op in ledger.operations
    ] == [
        ("live", "runtime_nudge", "pending"),
        ("edge-2", "runtime_nudge", "pending"),
    ]


def test_nudge_registered_proxies_counts_only_queued_ledger_operations(
    monkeypatch, proxy_sync_module
) -> None:
    ledger = _Ledger(failing={"edge-error"})
    monkeypatch.setattr(
        proxy_sync_module,
        "get_proxy_registry",
        lambda: _Registry(["live", "edge-false", "edge-error"]),
    )
    monkeypatch.setattr(proxy_sync_module, "get_operation_ledger", lambda: ledger)

    assert proxy_sync_module.nudge_registered_proxies(force=True) == (3, 2)
    assert [op.proxy_id for op in ledger.operations] == ["live", "edge-false"]
    assert [op.force for op in ledger.operations] == [True, True]


def test_nudge_registered_proxies_skips_invalid_and_duplicate_registry_ids(
    monkeypatch, proxy_sync_module, caplog
) -> None:
    ledger = _Ledger()
    monkeypatch.setattr(
        proxy_sync_module,
        "get_proxy_registry",
        lambda: _Registry(["live", "bad id", "live", "../default", "edge-2"]),
    )
    monkeypatch.setattr(proxy_sync_module, "get_operation_ledger", lambda: ledger)

    assert proxy_sync_module.nudge_registered_proxies(force=False) == (5, 2)
    assert [op.proxy_id for op in ledger.operations] == ["live", "edge-2"]
    assert "invalid proxy_id" in caplog.text
    assert "duplicate registered proxy identity" in caplog.text


def test_nudge_registered_proxies_logs_non_pending_ledger_results(
    monkeypatch, proxy_sync_module, caplog
) -> None:
    class _MixedLedger(_Ledger):
        def create_operation(self, proxy_id, **kwargs):
            if str(proxy_id) == "edge-applying":
                return SimpleNamespace(
                    operation_id=7,
                    proxy_id=str(proxy_id),
                    status="applying",
                    **kwargs,
                )
            return super().create_operation(proxy_id, **kwargs)

    ledger = _MixedLedger(failing={"edge-error"})
    monkeypatch.setattr(
        proxy_sync_module,
        "get_proxy_registry",
        lambda: _Registry(["live", "edge-applying", "edge-error"]),
    )
    monkeypatch.setattr(proxy_sync_module, "get_operation_ledger", lambda: ledger)

    assert proxy_sync_module.nudge_registered_proxies(force=True) == (3, 1)
    assert [op.proxy_id for op in ledger.operations] == ["live"]
    assert "was not queued for edge-error" in caplog.text
    assert "did not create a pending operation for edge-applying" in caplog.text


def test_request_proxy_reconcile_does_not_fall_back_to_direct_sync_when_ledger_fails(
    monkeypatch, proxy_sync_module
) -> None:
    monkeypatch.setattr(
        proxy_sync_module,
        "get_operation_ledger",
        lambda: (_ for _ in ()).throw(RuntimeError("db down")),
    )

    operation = proxy_sync_module.request_proxy_reconcile(
        "live",
        operation_type="config_apply",
        subject="Squid config",
        summary="Apply config",
        detail="Revision saved.",
        force=True,
    )

    assert operation.operation_id == 0
    assert operation.status == "failed"
    assert operation.force is True
    assert "operation ledger is unavailable" in operation.detail


def test_request_proxy_reconcile_sanitizes_failed_ephemeral_operation_detail(
    monkeypatch,
    proxy_sync_module,
) -> None:
    monkeypatch.setattr(
        proxy_sync_module,
        "get_operation_ledger",
        lambda: (_ for _ in ()).throw(RuntimeError("password=hunter2")),
    )

    operation = proxy_sync_module.request_proxy_reconcile(
        "live",
        operation_type="config_apply",
        subject="Squid config",
        summary="Apply config",
        detail="Revision saved with token=abc123.",
    )

    assert operation.status == "failed"
    assert "token=[redacted]" in operation.detail
    assert "abc123" not in operation.detail
    assert "hunter2" not in operation.detail


@pytest.mark.parametrize(
    ("ledger_error", "failure_reason"),
    [
        (RuntimeError("password=ledger-secret"), "operation ledger is unavailable"),
        (
            ValueError("invalid identity token=ledger-secret"),
            "operation identity is invalid",
        ),
    ],
)
def test_request_proxy_reconcile_sanitizes_and_bounds_failed_operation_metadata(
    monkeypatch,
    proxy_sync_module,
    ledger_error,
    failure_reason,
) -> None:
    class _FailingLedger:
        def create_operation(self, _proxy_id, **_kwargs):
            raise ledger_error

    monkeypatch.setattr(
        proxy_sync_module,
        "get_operation_ledger",
        _FailingLedger,
    )

    operation = proxy_sync_module.request_proxy_reconcile(
        "live",
        operation_type="config_apply",
        subject="Squid config",
        summary=f"Apply config with token=summary-secret. {'s' * 600}",
        detail=f"Revision saved with password=detail-secret. {'d' * 5000}",
    )
    payload = operation.to_dict()

    assert payload["operation_id"] == 0
    assert payload["status"] == "failed"
    assert failure_reason in payload["detail"]
    assert "token=[redacted]" in payload["summary"]
    assert "password=[redacted]" in payload["detail"]
    assert "summary-secret" not in payload["summary"]
    assert "detail-secret" not in payload["detail"]
    assert "ledger-secret" not in f"{payload['summary']}\n{payload['detail']}"
    assert len(payload["summary"]) == 512
    assert len(payload["detail"]) == 4000
