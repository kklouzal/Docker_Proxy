from __future__ import annotations

import pytest

from .live_test_helpers import LiveStackClient, admin_client, live_client_ip, unique_token, wait_for_admin_contains, wait_for_proxy_fixture_response


pytestmark = pytest.mark.live


def _generate_proxy_traffic(client: LiveStackClient) -> str:
    token = unique_token("live_observability")

    first = wait_for_proxy_fixture_response(client, f"/traffic/{token}")
    assert first.status == 200

    second = wait_for_proxy_fixture_response(client, f"/traffic/{token}")
    assert second.status == 200

    post_response = wait_for_proxy_fixture_response(
        client,
        f"/traffic/{token}",
        method="POST",
        data=f"token={token}".encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert post_response.status == 200

    slow_response = wait_for_proxy_fixture_response(client, f"/slow/{token}?delay_ms=900", needle=token, timeout_seconds=120.0)
    assert slow_response.status == 200
    assert token in slow_response.text

    return token


def test_live_observability_overview_destinations_and_clients_reflect_real_proxy_traffic(admin_client: LiveStackClient) -> None:
    _generate_proxy_traffic(admin_client)
    client_ip = live_client_ip()

    overview = wait_for_admin_contains(
        admin_client,
        "/observability?pane=overview&window=3600&q=traffic-fixture",
        "traffic-fixture",
    )
    assert "Largest signals" in overview.text
    assert "Security and enforcement overview" in overview.text

    destinations = wait_for_admin_contains(
        admin_client,
        "/observability?pane=destinations&window=3600&limit=25&q=traffic-fixture",
        "traffic-fixture",
    )
    assert "Requests by destination domain" in destinations.text

    clients = wait_for_admin_contains(
        admin_client,
        f"/observability?pane=clients&window=3600&limit=25&resolve_hostnames=0&q={client_ip}",
        client_ip,
    )
    assert "Requests by client IP" in clients.text


def test_live_observability_cache_performance_and_exports_use_real_proxy_logs(admin_client: LiveStackClient) -> None:
    token = _generate_proxy_traffic(admin_client)

    cache_page = wait_for_admin_contains(
        admin_client,
        "/observability?pane=cache&window=3600",
        "POST method (not cacheable by default)",
    )
    assert "Cache miss / bypass reasons" in cache_page.text

    performance_page = wait_for_admin_contains(
        admin_client,
        "/observability?pane=performance&window=3600&limit=25",
        token,
        timeout_seconds=120.0,
    )
    assert "Slowest requests" in performance_page.text
    assert "Traffic facets" in performance_page.text

    cache_export = admin_client.admin_request("/observability/export?pane=cache&window=3600")
    assert cache_export.status == 200
    assert "reason;requests;percent_of_misses;domains;clients;last_seen" in cache_export.text
    assert "POST method (not cacheable by default)" in cache_export.text

    destination_export = admin_client.admin_request("/observability/export?pane=destinations&window=3600&q=traffic-fixture")
    assert destination_export.status == 200
    assert "domain;requests;percent_of_total;clients;transactions;cache_hit_pct;av_icap_events;adblock_icap_events;last_seen" in destination_export.text
    assert "traffic-fixture" in destination_export.text