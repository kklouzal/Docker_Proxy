from __future__ import annotations

import pytest

from .live_test_helpers import LiveStackClient, admin_client, query_params, unique_domain


pytestmark = pytest.mark.live


def test_live_monitoring_pages_link_back_to_observability(admin_client: LiveStackClient) -> None:
    index_response = admin_client.admin_request("/")
    assert index_response.status == 200
    assert "Observability" in index_response.text
    assert "SSL incidents" in index_response.text
    assert "AV controls" in index_response.text

    clamav_response = admin_client.admin_request("/clamav?window=3600")
    assert clamav_response.status == 200
    assert "Observability hub" in clamav_response.text
    assert "Open security pane" in clamav_response.text
    assert "AV c-icap service" in clamav_response.text
    assert "Clamd backend" in clamav_response.text
    assert "Enable changes the Squid adaptation rule only" in clamav_response.text

    for path in ("/adblock?window=3600", "/webfilter", "/sslfilter", "/exclusions"):
        response = admin_client.admin_request(path)
        assert response.status == 200
        body = response.text
        assert "Observability" in body or "SSL incidents" in body


def test_live_monitoring_redirects_and_admin_actions_follow_real_routes(admin_client: LiveStackClient) -> None:
    ssl_redirect = admin_client.admin_request("/ssl-errors?window=3600&q=Example.COM")
    assert ssl_redirect.status == 200
    ssl_qs = query_params(ssl_redirect.url)
    assert ssl_qs.get("pane") == ["ssl"]
    assert ssl_qs.get("window") == ["3600"]
    assert ssl_qs.get("q") == ["example.com"]

    reload_response = admin_client.admin_post_form("/reload", {}, csrf_path="/", timeout_seconds=90.0)
    assert reload_response.status == 200
    assert "Status" in reload_response.text

    cache_clear_response = admin_client.admin_post_form("/cache/clear", {}, csrf_path="/", timeout_seconds=90.0)
    assert cache_clear_response.status == 200
    assert "Status" in cache_clear_response.text


def test_live_monitoring_quick_actions_persist_and_return_expected_destinations(admin_client: LiveStackClient) -> None:
    ssl_domain = unique_domain("ssl-exclude")
    ssl_exclude_response = admin_client.admin_post_form(
        "/ssl-errors/exclude",
        {"domain": ssl_domain},
        csrf_path="/observability?pane=ssl",
    )
    assert ssl_exclude_response.status == 200
    ssl_qs = query_params(ssl_exclude_response.url)
    assert ssl_qs.get("pane") == ["ssl"]
    assert ssl_qs.get("q") == [ssl_domain]
    assert ssl_domain in admin_client.admin_request("/exclusions").text

    bulk_domain_a = unique_domain("bulk-a")
    bulk_domain_b = unique_domain("bulk-b")
    bulk_response = admin_client.admin_post_form(
        "/exclusions",
        {
            "action": "add_domain_bulk",
            "domains_bulk": f"{bulk_domain_a}\n{bulk_domain_b}\n",
        },
        csrf_path="/exclusions",
    )
    assert bulk_response.status == 200
    bulk_qs = query_params(bulk_response.url)
    assert bulk_qs.get("bulk_added") == ["2"]
    exclusions_page = admin_client.admin_request("/exclusions")
    assert bulk_domain_a in exclusions_page.text
    assert bulk_domain_b in exclusions_page.text

    return_domain = unique_domain("return-to-observability")
    return_response = admin_client.admin_post_form(
        "/exclusions",
        {
            "action": "add_domain",
            "domain": return_domain,
            "return_to": "/observability?pane=destinations&window=3600",
        },
        csrf_path="/observability?pane=destinations",
    )
    assert return_response.status == 200
    return_qs = query_params(return_response.url)
    assert return_qs.get("pane") == ["destinations"]
    assert return_qs.get("window") == ["3600"]
    assert return_qs.get("exclude_added") == [return_domain]

    webfilter_test = admin_client.admin_post_json("/webfilter/test", {"domain": "example.com"})
    assert webfilter_test.status == 200
    payload = webfilter_test.json()
    assert payload["ok"] is True
    assert payload["domain"] == "example.com"