from __future__ import annotations

import time

import pytest

from .live_test_helpers import LIVE_CONFIG, LiveStackClient, query_params

pytestmark = pytest.mark.live


def _operation_store():
    from services.operation_ledger import get_operation_ledger  # type: ignore

    return get_operation_ledger()


def _wait_for_operation_status(
    operation_id: int,
    expected_statuses: set[str],
    *,
    timeout_seconds: float = 120.0,
) -> object:
    deadline = time.monotonic() + timeout_seconds
    ledger = _operation_store()
    last_operation = None
    while time.monotonic() < deadline:
        last_operation = ledger.get_operation(operation_id)
        if getattr(last_operation, "status", "") in expected_statuses:
            return last_operation
        time.sleep(0.5)
    msg = (
        f"operation #{operation_id} did not reach {sorted(expected_statuses)}; "
        f"last status={getattr(last_operation, 'status', None)!r}"
    )
    raise AssertionError(msg)


def _cache_clear_operation_ids(proxy_id: str) -> list[int]:
    return [
        int(operation.operation_id)
        for operation in _operation_store().list_operations(proxy_id, limit=50)
        if operation.operation_type == "cache_clear"
    ]


def test_live_cache_clear_duplicate_while_applying_dedupes_side_effect(
    admin_client: LiveStackClient,
) -> None:
    before_ids = set(_cache_clear_operation_ids(LIVE_CONFIG.primary_proxy_id))

    first_response = admin_client.admin_post_form(
        "/cache/clear",
        {},
        csrf_path="/",
        follow_redirects=False,
    )
    duplicate_response = admin_client.admin_post_form(
        "/cache/clear",
        {},
        csrf_path="/",
        follow_redirects=False,
    )

    assert first_response.status == 302
    assert duplicate_response.status == 302
    after_ids = set(_cache_clear_operation_ids(LIVE_CONFIG.primary_proxy_id))
    new_ids = sorted(after_ids - before_ids)
    assert len(new_ids) == 1
    _wait_for_operation_status(new_ids[0], {"applied", "failed"})


def test_live_manual_config_duplicate_preserves_original_operation(
    admin_client: LiveStackClient,
) -> None:
    config_response = admin_client.admin_request("/api/squid-config")
    assert config_response.status == 200
    config_text = config_response.text
    before_ids = {
        int(operation.operation_id)
        for operation in _operation_store().list_operations(
            LIVE_CONFIG.primary_proxy_id,
            limit=100,
        )
        if operation.operation_type == "config_apply"
    }

    fields = {"tab": "config", "action": "apply", "config_text": config_text}
    first_response = admin_client.admin_post_form(
        "/squid/config?tab=config",
        fields,
        csrf_path="/squid/config?tab=config",
        timeout_seconds=120.0,
    )
    duplicate_response = admin_client.admin_post_form(
        "/squid/config?tab=config",
        fields,
        csrf_path="/squid/config?tab=config",
        timeout_seconds=120.0,
    )

    assert first_response.status == 200
    assert duplicate_response.status == 200
    assert query_params(first_response.url).get("ok") == ["1"]
    assert query_params(duplicate_response.url).get("ok") == ["1"]
    after_ops = [
        operation
        for operation in _operation_store().list_operations(
            LIVE_CONFIG.primary_proxy_id,
            limit=100,
        )
        if operation.operation_type == "config_apply"
        and int(operation.operation_id) not in before_ids
    ]
    assert len(after_ops) == 1
    assert after_ops[0].rollback_ref != after_ops[0].target_ref
    _wait_for_operation_status(after_ops[0].operation_id, {"applied", "superseded"})
