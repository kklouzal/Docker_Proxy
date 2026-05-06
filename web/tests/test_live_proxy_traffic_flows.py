from __future__ import annotations

import pytest

from .live_test_helpers import LiveStackClient, admin_client, unique_token, wait_for_proxy_fixture_response, wait_for_proxy_management_payload


pytestmark = pytest.mark.live


def test_live_proxy_supports_head_large_post_and_slow_requests(admin_client: LiveStackClient) -> None:
    token = unique_token("traffic_methods")

    head = wait_for_proxy_fixture_response(admin_client, f"/traffic/{token}", method="HEAD", timeout_seconds=120.0)
    assert head.status == 200
    assert head.body == b""

    body = (f"token={token}&".encode("utf-8") + b"x" * (1024 * 1024))
    post = wait_for_proxy_fixture_response(
        admin_client,
        f"/traffic/{token}",
        method="POST",
        data=body,
        headers={"Content-Type": "application/octet-stream"},
        timeout_seconds=120.0,
        needle=f'"content_length": {len(body)}',
    )
    assert post.status == 200
    assert post.json()["content_length"] == len(body)

    slow = wait_for_proxy_fixture_response(admin_client, f"/slow/{token}?delay_ms=1200", needle=token, timeout_seconds=120.0)
    assert slow.status == 200
    assert slow.json()["query"]["delay_ms"] == ["1200"]
    wait_for_proxy_management_payload()


def test_live_proxy_dns_failure_returns_squid_error_and_keeps_proxy_healthy(admin_client: LiveStackClient) -> None:
    missing_host = f"{unique_token('missing-dns')}.invalid"
    response = admin_client.proxy_fixture_request(
        f"http://{missing_host}/resource",
        timeout_seconds=30.0,
    )

    assert response.status in {502, 503, 504}
    body = response.text.lower()
    assert "dns" in body or "unable to forward" in body or "access denied" in body or "the requested url could not be retrieved" in body
    wait_for_proxy_management_payload()
