from __future__ import annotations

import pytest

from .live_test_helpers import (
    LIVE_CONFIG,
    LiveStackClient,
    active_certificate_bundle,
    admin_client,
    latest_certificate_apply,
    query_params,
    wait_for_certificate_apply,
    wait_for_proxy_inventory,
)


pytestmark = pytest.mark.live


def _apply_ts(application: object | None) -> int:
    return int(getattr(application, "applied_ts", 0) or 0)


@pytest.fixture
def multi_proxy_admin(admin_client: LiveStackClient) -> LiveStackClient:
    wait_for_proxy_inventory(
        admin_client,
        [LIVE_CONFIG.primary_proxy_id, LIVE_CONFIG.remote_proxy_id],
        timeout_seconds=120.0,
    )
    return admin_client


def test_live_generate_certificate_creates_shared_bundle_and_nudges_all_registered_proxies(
    multi_proxy_admin: LiveStackClient,
) -> None:
    primary_before = latest_certificate_apply(LIVE_CONFIG.primary_proxy_id)
    remote_before = latest_certificate_apply(LIVE_CONFIG.remote_proxy_id)

    response = multi_proxy_admin.admin_post_form(
        "/certs/generate",
        {},
        csrf_path="/certs",
        timeout_seconds=120.0,
    )
    assert response.status == 200
    assert query_params(response.url).get("ok") == ["1"]

    bundle = active_certificate_bundle()
    assert bundle is not None
    assert bundle.source_kind == "self_signed"

    primary_apply = wait_for_certificate_apply(
        LIVE_CONFIG.primary_proxy_id,
        revision_id=bundle.revision_id,
        after_ts=_apply_ts(primary_before) or None,
        timeout_seconds=120.0,
    )
    remote_apply = wait_for_certificate_apply(
        LIVE_CONFIG.remote_proxy_id,
        revision_id=bundle.revision_id,
        after_ts=_apply_ts(remote_before) or None,
        timeout_seconds=120.0,
    )
    assert primary_apply is not None
    assert remote_apply is not None

    certs_page = multi_proxy_admin.admin_request("/certs")
    assert certs_page.status == 200
    assert "Edge 2" in certs_page.text
    assert "Applied" in certs_page.text or "Pending" in certs_page.text

    download = multi_proxy_admin.admin_request("/certs/download/ca.crt")
    assert download.status == 200
    assert "attachment" in download.headers.get("Content-Disposition", "")
    assert "BEGIN CERTIFICATE" in download.text