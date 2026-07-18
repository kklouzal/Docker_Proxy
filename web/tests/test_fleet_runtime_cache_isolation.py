from __future__ import annotations

from typing import Any

from .admin_route_test_utils import (
    FakeAdblockArtifacts,
    FakeOperationLedger,
    FakeRegistry,
    load_admin_app,
)


class RecordingHealthClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, float | None, bool]] = []
        self.fail: set[str] = set()

    def get_health(
        self,
        proxy_id: object,
        *,
        timeout_seconds: float | None = None,
        full: bool = False,
    ) -> dict[str, Any]:
        key = str(proxy_id)
        self.calls.append((key, timeout_seconds, full))
        if key in self.fail:
            from services.proxy_client import ProxyClientError  # type: ignore

            detail = f"{key} unavailable"
            raise ProxyClientError(detail)
        return {
            "ok": True,
            "status": "healthy",
            "proxy_id": key,
            "proxy_status": "healthy",
            "timestamp": 100 if key == "edge-a" else 200,
            "current_policy_sha": f"policy-{key}",
            "current_pac_sha": f"pac-{key}",
            "current_adblock_sha": f"adblock-{key}",
            "state_errors": [],
        }


def test_runtime_health_ui_cache_is_per_proxy_and_returns_defensive_copies(
    monkeypatch,
    tmp_path,
) -> None:
    client = RecordingHealthClient()
    ctx = load_admin_app(
        monkeypatch,
        tmp_path,
        registry=FakeRegistry(["edge-a", "edge-b"]),
        proxy_client=client,
    )
    admin_app = ctx.module
    admin_app._PROXY_HEALTH_CACHE.clear()

    first = admin_app._cached_proxy_health(
        "edge-a",
        timeout_seconds=1.25,
        ttl_seconds=30,
        full=True,
    )
    first["proxy_id"] = "mutated"

    second = admin_app._cached_proxy_health(
        "edge-a",
        timeout_seconds=1.25,
        ttl_seconds=30,
        full=True,
    )
    assert second["proxy_id"] == "edge-a"
    assert client.calls == [("edge-a", 1.25, True)]

    third = admin_app._cached_proxy_health(
        "edge-b",
        timeout_seconds=1.25,
        ttl_seconds=30,
        full=True,
    )
    assert third["proxy_id"] == "edge-b"
    assert client.calls[-1] == ("edge-b", 1.25, True)

    cached_at, cached_payload = admin_app._PROXY_HEALTH_CACHE["edge-a", 1.25, True]
    admin_app._PROXY_HEALTH_CACHE["edge-a", 1.25, True] = (
        cached_at - 31,
        cached_payload,
    )
    client.fail.add("edge-a")
    stale = admin_app._cached_proxy_health(
        "edge-a",
        timeout_seconds=1.25,
        ttl_seconds=30,
        full=True,
    )
    assert stale["proxy_id"] == "edge-a"
    assert stale["_stale"] is True
    assert stale["ok"] is False
    assert stale["status"] == "degraded"
    assert stale["previous_ok"] is True
    assert stale["previous_status"] == "healthy"
    assert "edge-a unavailable" in stale["health_cache_detail"]

    client.fail.add("edge-c")
    unavailable = admin_app._cached_proxy_health(
        "edge-c",
        timeout_seconds=1.25,
        ttl_seconds=30,
        full=True,
    )
    assert unavailable["_unavailable_cached"] is True
    assert unavailable.get("_stale") is not True
    assert unavailable.get("proxy_id") != "edge-a"


def test_adblock_runtime_state_requires_selected_proxy_apply_revision_and_hash(
    monkeypatch,
    tmp_path,
) -> None:
    artifacts = FakeAdblockArtifacts()
    artifacts.record_apply_result(
        "edge-b",
        7,
        ok=True,
        artifact_sha256="sha-active",
    )
    artifacts.record_apply_result(
        "edge-a",
        6,
        ok=True,
        artifact_sha256="sha-active",
    )
    ledger = FakeOperationLedger()
    stale = ledger.create_operation(
        "edge-a",
        operation_type="adblock_refresh",
        target_kind="adblock_artifact",
        target_ref="6",
        request_hash="sha-active",
    )
    stale.status = "failed"
    ctx = load_admin_app(
        monkeypatch,
        tmp_path,
        registry=FakeRegistry(["edge-a", "edge-b"]),
        adblock_artifacts=artifacts,
        operation_ledger=ledger,
    )
    admin_app = ctx.module

    state = admin_app._adblock_runtime_state(
        "edge-a",
        active_artifact={
            "available": True,
            "revision_id": 7,
            "artifact_sha256": "sha-active",
        },
        runtime_health={
            "status": "healthy",
            "proxy_status": "healthy",
            "current_adblock_sha": "sha-active",
            "active_adblock_sha": "sha-active",
            "timestamp": 123,
        },
    )

    assert state["state"] == "built_unverified"
    assert state["latest_apply_ok"] is None
    assert state["operation_status"] == "failed"
    assert state["operation_matches_active"] is False
    assert "targets a different artifact revision/hash" in state["detail"]


def test_adblock_runtime_state_reconciles_only_with_selected_proxy_apply_hash(
    monkeypatch,
    tmp_path,
) -> None:
    artifacts = FakeAdblockArtifacts()
    artifacts.record_apply_result(
        "edge-a",
        7,
        ok=True,
        artifact_sha256="sha-active",
    )
    ledger = FakeOperationLedger()
    op = ledger.create_operation(
        "edge-a",
        operation_type="adblock_refresh",
        target_kind="adblock_artifact",
        target_ref="7",
        request_hash="sha-active",
    )
    op.status = "applied"
    ctx = load_admin_app(
        monkeypatch,
        tmp_path,
        registry=FakeRegistry(["edge-a"]),
        adblock_artifacts=artifacts,
        operation_ledger=ledger,
    )
    admin_app = ctx.module

    state = admin_app._adblock_runtime_state(
        "edge-a",
        active_artifact={
            "available": True,
            "revision_id": 7,
            "artifact_sha256": "sha-active",
        },
        runtime_health={
            "status": "healthy",
            "proxy_status": "healthy",
            "current_adblock_sha": "sha-active",
            "active_adblock_sha": "sha-active",
            "timestamp": 123,
        },
    )

    assert state["state"] == "reconciled"
    assert state["latest_apply_ok"] is True
    assert state["operation_matches_active"] is True


def test_pac_runtime_state_ignores_stale_operations_for_other_fingerprints(
    monkeypatch,
    tmp_path,
) -> None:
    ledger = FakeOperationLedger()
    cross_proxy = ledger.create_operation(
        "edge-b",
        operation_type="pac_refresh",
        target_kind="pac_state",
        target_ref="pac-edge-a",
    )
    cross_proxy.status = "failed"
    stale_same_proxy = ledger.create_operation(
        "edge-a",
        operation_type="pac_refresh",
        target_kind="pac_state",
        target_ref="old-pac-edge-a",
    )
    stale_same_proxy.status = "failed"
    ctx = load_admin_app(
        monkeypatch,
        tmp_path,
        registry=FakeRegistry(["edge-a", "edge-b"]),
        operation_ledger=ledger,
    )
    admin_app = ctx.module
    monkeypatch.setattr(
        admin_app,
        "_desired_pac_state_sha_for_proxy",
        lambda proxy_id: (f"pac-{proxy_id}", ""),
    )

    state = admin_app._pac_runtime_state(
        "edge-a",
        runtime_health={
            "status": "healthy",
            "proxy_status": "healthy",
            "current_pac_sha": "pac-edge-a",
            "desired_pac_sha": "pac-edge-a",
            "timestamp": 123,
        },
    )

    assert state["state"] == "reconciled"
    assert state["operation_id"] == stale_same_proxy.operation_id
    assert state["operation_matches_desired"] is False
    assert "targets a different PAC fingerprint" in state["detail"]
