from __future__ import annotations

import concurrent.futures
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

import pytest

from .live_test_helpers import (
    LIVE_CONFIG,
    LiveStackClient,
    unique_token,
    wait_for_proxy_fixture_response,
    wait_for_proxy_management_payload,
)

pytestmark = pytest.mark.live


def test_live_proxy_supports_head_large_post_and_slow_requests(
    admin_client: LiveStackClient,
) -> None:
    token = unique_token("traffic_methods")

    head = wait_for_proxy_fixture_response(
        admin_client, f"/traffic/{token}", method="HEAD", timeout_seconds=120.0
    )
    assert head.status == 200
    assert head.body == b""

    body = f"token={token}&".encode() + b"x" * (1024 * 1024)
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

    slow = wait_for_proxy_fixture_response(
        admin_client,
        f"/slow/{token}?delay_ms=1200",
        needle=token,
        timeout_seconds=180.0,
        request_timeout_seconds=15.0,
    )
    assert slow.status == 200
    assert slow.json()["query"]["delay_ms"] == ["1200"]
    wait_for_proxy_management_payload()


def test_live_proxy_dns_failure_returns_squid_error_and_keeps_proxy_healthy(
    admin_client: LiveStackClient,
) -> None:
    missing_host = f"{unique_token('missing-dns')}.invalid"
    # This test follows live-stack cases that legitimately restart Squid while
    # applying runtime/cache transitions.  Wait for the product contract (Squid
    # returns an HTTP DNS/upstream error) instead of sampling the listener during
    # a short restart window.
    response = wait_for_proxy_fixture_response(
        admin_client,
        f"http://{missing_host}/resource",
        timeout_seconds=60.0,
        request_timeout_seconds=30.0,
        accept=lambda candidate: candidate.status in {502, 503, 504},
    )

    assert response.status in {502, 503, 504}
    body = response.text.lower()
    assert (
        "dns" in body
        or "unable to forward" in body
        or "access denied" in body
        or "the requested url could not be retrieved" in body
    )
    wait_for_proxy_management_payload()


def test_live_proxy_http_cache_miss_serial_and_parallel_bursts(
    admin_client: LiveStackClient,
) -> None:
    token = unique_token("http_cache_miss_burst")

    def fetch(index: int) -> tuple[int, str]:
        worker_client = LiveStackClient()
        response = worker_client.proxy_fixture_request(
            f"/traffic/{token}-{index}?cache_bust={token}-{index}",
            headers={"Cache-Control": "no-cache", "Pragma": "no-cache"},
            timeout_seconds=30.0,
        )
        return response.status, response.text

    serial = [fetch(index) for index in range(16)]
    assert all(status == 200 and token in body for status, body in serial)

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        parallel = list(executor.map(fetch, range(16, 76)))

    failures = [
        (status, body[:300])
        for status, body in parallel
        if status != 200 or token not in body or "ICAP_FAILURE" in body
    ]
    assert not failures
    wait_for_proxy_management_payload()


def _remote_http_proxy_url() -> str:
    parsed = urllib.parse.urlsplit(LIVE_CONFIG.remote_proxy_management_url)
    host = parsed.hostname or "proxy-edge-2"
    return f"http://{host}:3128"


def _proxied_request(proxy_url: str, url: str, *, timeout_seconds: float = 15.0):
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}),
        # Live proxy HTTPS traffic is intentionally ssl-bumped by Squid's test CA.
        urllib.request.HTTPSHandler(context=ssl._create_unverified_context()),  # noqa: S323
    )
    request = urllib.request.Request(
        url,
        headers={"Cache-Control": "no-cache", "Pragma": "no-cache"},
    )
    try:
        with opener.open(request, timeout=timeout_seconds) as response:
            return int(response.status), response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return int(exc.code), exc.read().decode("utf-8", errors="replace")


def test_live_remote_proxy_http_and_https_cold_misses_survive_unavailable_clamd(
    admin_client: LiveStackClient,
) -> None:
    token = unique_token("remote_cold_miss")
    proxy_url = _remote_http_proxy_url()
    http_url = f"{LIVE_CONFIG.traffic_fixture_url}/traffic/{token}?cache_bust={token}"
    https_url = f"https://example.com/?docker_proxy_cold_miss={token}"

    deadline = time.time() + 120
    last: tuple[int, str, int, str] | None = None
    while time.time() < deadline:
        http_status, http_body = _proxied_request(proxy_url, http_url)
        https_status, https_body = _proxied_request(proxy_url, https_url)
        last = (http_status, http_body[:500], https_status, https_body[:500])
        if (
            http_status == 200
            and token in http_body
            and "ICAP_FAILURE" not in http_body
            and https_status == 200
            and "Example Domain" in https_body
            and "ICAP_FAILURE" not in https_body
        ):
            wait_for_proxy_management_payload()
            return
        time.sleep(1)

    msg = f"remote proxy cold miss HTTP/HTTPS failed via {proxy_url}: {last!r}"
    raise AssertionError(msg)
