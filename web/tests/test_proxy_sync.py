from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace


def _add_web_to_path() -> None:
    web_dir = Path(__file__).resolve().parents[1]
    if str(web_dir) not in sys.path:
        sys.path.insert(0, str(web_dir))


class _Registry:
    def __init__(self, proxy_ids: list[str]) -> None:
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


def test_nudge_registered_proxies_returns_zero_when_registry_empty(monkeypatch) -> None:
    _add_web_to_path()
    from services import proxy_sync  # type: ignore

    monkeypatch.setattr(proxy_sync, "get_proxy_registry", lambda: _Registry([]))

    assert proxy_sync.nudge_registered_proxies(force=True) == (0, 0)


def test_nudge_registered_proxies_queues_operations_for_registered_proxies(
    monkeypatch,
) -> None:
    _add_web_to_path()
    from services import proxy_sync  # type: ignore

    ledger = _Ledger()
    monkeypatch.setattr(
        proxy_sync, "get_proxy_registry", lambda: _Registry(["live", "edge-2"])
    )
    monkeypatch.setattr(proxy_sync, "get_operation_ledger", lambda: ledger)

    assert proxy_sync.nudge_registered_proxies(force=False) == (2, 2)
    assert [
        (op.proxy_id, op.operation_type, op.status) for op in ledger.operations
    ] == [
        ("live", "runtime_nudge", "pending"),
        ("edge-2", "runtime_nudge", "pending"),
    ]


def test_nudge_registered_proxies_counts_only_queued_ledger_operations(
    monkeypatch,
) -> None:
    _add_web_to_path()
    from services import proxy_sync  # type: ignore

    ledger = _Ledger(failing={"edge-error"})
    monkeypatch.setattr(
        proxy_sync,
        "get_proxy_registry",
        lambda: _Registry(["live", "edge-false", "edge-error"]),
    )
    monkeypatch.setattr(proxy_sync, "get_operation_ledger", lambda: ledger)

    assert proxy_sync.nudge_registered_proxies(force=True) == (3, 2)
    assert [op.proxy_id for op in ledger.operations] == ["live", "edge-false"]
    assert [op.force for op in ledger.operations] == [True, True]


def test_request_proxy_reconcile_does_not_fall_back_to_direct_sync_when_ledger_fails(
    monkeypatch,
) -> None:
    _add_web_to_path()
    from services import proxy_sync  # type: ignore

    monkeypatch.setattr(
        proxy_sync,
        "get_operation_ledger",
        lambda: (_ for _ in ()).throw(RuntimeError("db down")),
    )

    operation = proxy_sync.request_proxy_reconcile(
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
