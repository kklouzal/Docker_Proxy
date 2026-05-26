from __future__ import annotations

import json
import re
import time
import urllib.parse

import pytest

from .live_test_helpers import (
    LIVE_CONFIG,
    LiveStackClient,
    _live_poll_sleep,
    query_params,
    unique_domain,
    unique_token,
    wait_for_proxy_fixture_response,
    wait_for_proxy_management_payload,
)

pytestmark = pytest.mark.live


_PAC_PROFILE_RE = re.compile(
    r'<form [^>]*data-pac-profile-id="(\d+)" [^>]*data-pac-profile-name="([^"]*)"',
)


def _find_pac_profile_id(html: str, profile_name: str) -> int:
    for profile_id, name in _PAC_PROFILE_RE.findall(html):
        if name == profile_name:
            return int(profile_id)
    msg = f"Could not find PAC profile id for {profile_name!r}."
    raise AssertionError(msg)


def _adblock_store():
    from services.adblock_store import get_adblock_store  # type: ignore

    store = get_adblock_store()
    store.init_db()
    return store


def _adblock_artifacts_store():
    from services.adblock_artifacts import get_adblock_artifacts  # type: ignore

    return get_adblock_artifacts()


def _webfilter_store():
    from services.webfilter_store import get_webfilter_store  # type: ignore

    store = get_webfilter_store()
    store.init_db()
    return store


def _with_proxy_id(proxy_id: object, callback):
    from services.proxy_context import reset_proxy_id, set_proxy_id  # type: ignore

    token = set_proxy_id(proxy_id)
    try:
        return callback()
    finally:
        reset_proxy_id(token)


def _webfilter_settings(proxy_id: object):
    return _with_proxy_id(proxy_id, lambda: _webfilter_store().get_settings())


def _live_fixture_host() -> str:
    host = (
        urllib.parse.urlsplit(LIVE_CONFIG.traffic_fixture_url).hostname
        or "traffic-fixture"
    )
    return host.strip().lower().rstrip(".")


def _set_live_webcat_category(domain: str, category: str | None) -> None:
    from services.db import connect  # type: ignore
    from tools import webcat_build  # type: ignore

    normalized = (domain or "").strip().lower().rstrip(".")
    with connect() as conn:
        webcat_build._init_db(conn)  # type: ignore[attr-defined]
        if category:
            conn.execute(
                "INSERT INTO webcat_domains(domain,categories) VALUES(%s,%s) ON DUPLICATE KEY UPDATE categories=VALUES(categories)",
                (normalized, category),
            )
            conn.execute(
                "INSERT INTO webcat_categories(category,domains) VALUES(%s,1) ON DUPLICATE KEY UPDATE domains=GREATEST(domains,1)",
                (category,),
            )
        else:
            conn.execute("DELETE FROM webcat_domains WHERE domain=%s", (normalized,))
        row = conn.execute(
            "SELECT v FROM webcat_meta WHERE k=%s", ("built_ts",)
        ).fetchone()
        try:
            previous_built_ts = (
                int(str(row[0]).strip())
                if row and row[0] is not None and str(row[0]).strip()
                else 0
            )
        except (TypeError, ValueError):
            previous_built_ts = 0
        # Proxy helpers refresh their local webcat snapshot only when MySQL's
        # built_ts increases. Earlier live tests can leave a newer timestamp
        # than wall-clock+10, so make fixture mutations monotonic.
        built_ts = max(previous_built_ts + 1, int(time.time()) + 10)
        conn.execute(
            "INSERT INTO webcat_meta(k,v) VALUES('built_ts',%s) ON DUPLICATE KEY UPDATE v=VALUES(v)",
            (str(built_ts),),
        )


def _restore_webfilter_settings(proxy_id: object, settings) -> None:
    def _restore() -> None:
        store = _webfilter_store()
        store.set_settings(
            enabled=settings.enabled,
            source_url=settings.source_url,
            blocked_categories=list(settings.blocked_categories),
        )
        # Live tests must not leave a background web-category rebuild queued against
        # the production default internet feed. That external download can consume
        # the shared live-test stack long enough to starve later proxy/admin calls.
        store.clear_refresh_requested()

    _with_proxy_id(proxy_id, _restore)


def _sync_primary_proxy(client: LiveStackClient, *, force: bool = True) -> dict:
    response = client.proxy_management_post_json(
        "/api/manage/sync", {"force": force}, timeout_seconds=120.0
    )
    assert response.status == 200, response.text
    payload = response.json()
    assert payload.get("ok") is True, payload
    wait_for_proxy_management_payload()
    return payload


def _wait_for_proxy_status(
    client: LiveStackClient,
    path: str,
    expected_status: int,
    *,
    timeout_seconds: float = 120.0,
):
    deadline = time.time() + timeout_seconds
    last = None
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            last = client.proxy_fixture_request(path, timeout_seconds=10.0)
            last_error = None
            if last.status == expected_status:
                return last
        except Exception as exc:
            # Squid policy/adblock reloads can leave one in-flight proxied request
            # waiting on a closing ICAP/Squid worker. Treat that as transient stack
            # convergence and keep polling for the policy result instead of failing
            # the live gate on the first timed-out socket read.
            last_error = exc
        _live_poll_sleep()
    detail = (
        f"last={getattr(last, 'status', None)} body={getattr(last, 'text', '')[:500]}"
    )
    if last_error is not None:
        detail += f" last_error={last_error!r}"
    msg = f"Timed out waiting for proxied {path!r} to return HTTP {expected_status}; {detail}"
    raise AssertionError(msg)


def _write_live_adblock_artifact(
    directory,
    *,
    regex_block: str = "",
    regex_allow: str = "",
    domains_block: str = "",
    domains_allow: str = "",
    enabled: bool = True,
) -> int:
    settings_version = _adblock_store().get_settings_version()
    directory.mkdir(parents=True, exist_ok=True)
    for name, content in {
        "domains_allow.txt": domains_allow,
        "domains_block.txt": domains_block,
        "regex_allow.txt": regex_allow,
        "regex_block.txt": regex_block,
    }.items():
        (directory / name).write_text(content, encoding="utf-8")
    (directory / "settings.json").write_text(
        json.dumps(
            {
                "enabled": enabled,
                "cache_ttl": 120,
                "cache_max": 1000,
                "settings_version": settings_version,
                "enabled_lists": ["live-fixture"] if enabled else [],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    (directory / "report.json").write_text(
        json.dumps(
            {
                "enabled_lists": ["live-fixture"] if enabled else [],
                "counts": {
                    "domains_block": bool(domains_block.strip()),
                    "domains_allow": bool(domains_allow.strip()),
                    "regex_block": bool(regex_block.strip()),
                    "regex_allow": bool(regex_allow.strip()),
                },
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    return settings_version


def test_live_pac_profile_create_update_delete_updates_rendered_pac(
    admin_client: LiveStackClient,
) -> None:
    profile_name = unique_token("live_pac")
    direct_domain = unique_domain("direct")
    updated_name = unique_token("live_pac_updated")
    updated_domain = unique_domain("updated-direct")

    create_response = admin_client.admin_post_form(
        "/pac",
        {
            "action": "create",
            "name": profile_name,
            "client_cidr": "",
            "direct_domains": direct_domain,
            "direct_dst_nets": "",
        },
        csrf_path="/pac",
    )
    assert create_response.status == 200
    assert query_params(create_response.url).get("ok") == ["1"]
    assert profile_name in create_response.text
    _sync_primary_proxy(admin_client)

    pac_response = admin_client.pac_request(f"/proxy.pac?probe={profile_name}")
    assert pac_response.status == 200
    assert direct_domain in pac_response.text

    profiles_page = admin_client.admin_request("/pac")
    profile_id = _find_pac_profile_id(profiles_page.text, profile_name)

    update_response = admin_client.admin_post_form(
        "/pac",
        {
            "action": "update",
            "profile_id": str(profile_id),
            "name": updated_name,
            "client_cidr": "",
            "direct_domains": updated_domain,
            "direct_dst_nets": "10.77.0.0/16",
        },
        csrf_path="/pac",
    )
    assert update_response.status == 200
    assert query_params(update_response.url).get("ok") == ["1"]
    assert updated_name in update_response.text
    _sync_primary_proxy(admin_client)

    updated_pac = admin_client.pac_request(f"/proxy.pac?probe={updated_name}")
    assert updated_domain in updated_pac.text
    assert direct_domain not in updated_pac.text

    delete_response = admin_client.admin_post_form(
        "/pac",
        {
            "action": "delete",
            "profile_id": str(profile_id),
        },
        csrf_path="/pac",
    )
    assert delete_response.status == 200
    assert query_params(delete_response.url).get("ok") == ["1"]
    assert updated_name not in delete_response.text
    _sync_primary_proxy(admin_client)

    fallback_pac = admin_client.pac_request(f"/proxy.pac?probe=deleted-{updated_name}")
    assert updated_domain not in fallback_pac.text


def test_live_sslfilter_granular_policy_stays_proxy_side_only(
    admin_client: LiveStackClient,
) -> None:
    nobump_domain = unique_domain("nobump")
    nocache_domain = unique_domain("nocache")
    nobump_cidr = "10.55.77.0/24"
    nocache_cidr = "10.55.78.0/24"

    for payload in (
        {"action": "add_domain", "policy": "nobump", "domain": nobump_domain},
        {"action": "add_domain", "policy": "nocache", "domain": nocache_domain},
        {"action": "add_src", "policy": "nobump", "cidr": nobump_cidr},
        {"action": "add_src", "policy": "nocache", "cidr": nocache_cidr},
    ):
        response = admin_client.admin_post_form(
            "/sslfilter", payload, csrf_path="/sslfilter", timeout_seconds=90.0
        )
        assert response.status == 200

    toggle_private_response = admin_client.admin_post_form(
        "/sslfilter",
        {"action": "toggle_private", "exclude_private_nets": "on"},
        csrf_path="/sslfilter",
    )
    assert toggle_private_response.status == 200
    assert (
        "Private/local PAC bypass preference updated." in toggle_private_response.text
    )

    sslfilter_page = admin_client.admin_request("/sslfilter")
    assert nobump_domain in sslfilter_page.text
    assert nocache_domain in sslfilter_page.text
    assert nobump_cidr in sslfilter_page.text
    assert nocache_cidr in sslfilter_page.text
    assert 'name="exclude_private_nets" checked' in sslfilter_page.text

    pac_response = admin_client.pac_request(f"/proxy.pac?probe={nobump_domain}")
    assert pac_response.status == 200
    # SSL-filter/no-cache destination/source policies are proxy-side policy.
    # They must not become client-side PAC DIRECT rules.
    assert nobump_domain not in pac_response.text
    assert nocache_domain not in pac_response.text

    wait_for_proxy_management_payload()

    for payload in (
        {"action": "remove_domain", "policy": "nobump", "domain": nobump_domain},
        {"action": "remove_domain", "policy": "nocache", "domain": nocache_domain},
        {"action": "remove_src", "policy": "nobump", "cidr": nobump_cidr},
        {"action": "remove_src", "policy": "nocache", "cidr": nocache_cidr},
    ):
        response = admin_client.admin_post_form(
            "/sslfilter", payload, csrf_path="/sslfilter", timeout_seconds=90.0
        )
        assert response.status == 200

    final_page = admin_client.admin_request("/sslfilter")
    assert nobump_domain not in final_page.text
    assert nocache_domain not in final_page.text
    assert nobump_cidr not in final_page.text
    assert nocache_cidr not in final_page.text


def test_live_administration_add_change_and_delete_user(
    admin_client: LiveStackClient,
) -> None:
    username = unique_token("operator")
    initial_password = "InitialPass123!"
    rotated_password = "RotatedPass123!"

    add_user_response = admin_client.admin_post_form(
        "/administration",
        {
            "action": "add_user",
            "username": username,
            "password": initial_password,
        },
        csrf_path="/administration",
    )
    assert add_user_response.status == 200
    assert "User added." in add_user_response.text
    assert username in add_user_response.text

    delete_current_user_response = admin_client.admin_post_form(
        "/administration",
        {
            "action": "delete_user",
            "username": "admin",
        },
        csrf_path="/administration",
    )
    assert delete_current_user_response.status == 200
    assert (
        "Cannot remove the currently signed-in user."
        in delete_current_user_response.text
    )

    user_client = LiveStackClient()
    user_client.login(username=username, password=initial_password)
    change_password_response = user_client.admin_post_form(
        "/administration",
        {
            "action": "set_password",
            "username": username,
            "new_password": rotated_password,
        },
        csrf_path="/administration",
    )
    assert change_password_response.status == 200
    assert "Password updated." in change_password_response.text

    user_client.logout()
    relogin_client = LiveStackClient()
    relogin_client.login(username=username, password=rotated_password)

    cleanup_admin = LiveStackClient()
    cleanup_admin.login()
    delete_user_response = cleanup_admin.admin_post_form(
        "/administration",
        {
            "action": "delete_user",
            "username": username,
        },
        csrf_path="/administration",
    )
    assert delete_user_response.status == 200
    assert "User removed." in delete_user_response.text

    deleted_user_client = LiveStackClient()
    failed_login = deleted_user_client.login(
        username=username, password=rotated_password, expect_success=False
    )
    assert "Invalid username or password." in failed_login.text


def test_live_sslfilter_and_webfilter_whitelist_workflows(
    admin_client: LiveStackClient,
) -> None:
    cidr = "172.31.250.0/24"
    whitelist_domain = unique_domain("allow")

    add_cidr_response = admin_client.admin_post_form(
        "/sslfilter",
        {
            "action": "add",
            "cidr": cidr,
        },
        csrf_path="/sslfilter",
    )
    assert add_cidr_response.status == 200
    assert cidr in add_cidr_response.text

    remove_cidr_response = admin_client.admin_post_form(
        "/sslfilter",
        {
            "action": "remove",
            "cidr": cidr,
        },
        csrf_path="/sslfilter",
    )
    assert remove_cidr_response.status == 200
    assert cidr not in admin_client.admin_request("/sslfilter").text

    add_whitelist_response = admin_client.admin_post_form(
        "/webfilter?tab=whitelist",
        {
            "tab": "whitelist",
            "action": "whitelist_add",
            "whitelist_domain": whitelist_domain,
        },
        csrf_path="/webfilter?tab=whitelist",
    )
    assert add_whitelist_response.status == 200
    assert "Whitelist entry added." in add_whitelist_response.text
    assert whitelist_domain in add_whitelist_response.text

    remove_whitelist_response = admin_client.admin_post_form(
        "/webfilter?tab=whitelist",
        {
            "tab": "whitelist",
            "action": "whitelist_remove",
            "pattern": whitelist_domain,
        },
        csrf_path="/webfilter?tab=whitelist",
    )
    assert remove_whitelist_response.status == 200
    assert (
        whitelist_domain
        not in admin_client.admin_request("/webfilter?tab=whitelist").text
    )


def test_live_adblock_list_settings_refresh_and_flush_workflows(
    admin_client: LiveStackClient,
) -> None:
    store = _adblock_store()
    original_statuses = {status.key: status.enabled for status in store.list_statuses()}
    original_settings = store.get_settings()
    statuses = store.list_statuses()
    assert statuses, "expected live adblock store to seed default lists"
    target_key = statuses[0].key

    try:
        save_lists_response = admin_client.admin_post_form(
            "/adblock",
            {
                "action": "save_lists",
                f"enabled_{target_key}": "on",
            },
            csrf_path="/adblock",
        )
        assert save_lists_response.status == 200
        enabled_map = {status.key: status.enabled for status in store.list_statuses()}
        assert enabled_map[target_key] is True
        assert store.get_refresh_requested() > 0

        save_settings_response = admin_client.admin_post_form(
            "/adblock",
            {
                "action": "save_settings",
                "adblock_enabled": "on",
                "cache_ttl": "120",
                "cache_max": "999",
            },
            csrf_path="/adblock",
        )
        assert save_settings_response.status == 200
        settings = store.get_settings()
        assert settings["enabled"] is True
        assert settings["cache_ttl"] == 120
        assert settings["cache_max"] == 999

        refresh_response = admin_client.admin_post_form(
            "/adblock",
            {"action": "refresh"},
            csrf_path="/adblock",
            timeout_seconds=90.0,
        )
        assert refresh_response.status == 200
        assert query_params(refresh_response.url).get("refresh_requested") == ["1"]

        flush_response = admin_client.admin_post_form(
            "/adblock",
            {"action": "flush_cache"},
            csrf_path="/adblock",
            timeout_seconds=90.0,
        )
        assert flush_response.status == 200
        assert query_params(flush_response.url).get("cache_flushed") == ["1"]
        wait_for_proxy_management_payload()
        wait_for_proxy_fixture_response(admin_client, "/health", timeout_seconds=120.0)

        disable_all_response = admin_client.admin_post_form(
            "/adblock",
            {"action": "save_lists"},
            csrf_path="/adblock",
        )
        assert disable_all_response.status == 200
        refresh_no_lists_response = admin_client.admin_post_form(
            "/adblock",
            {"action": "refresh"},
            csrf_path="/adblock",
        )
        assert refresh_no_lists_response.status == 200
        assert query_params(refresh_no_lists_response.url).get("refresh_no_lists") == [
            "1"
        ]
    finally:
        store.set_enabled(original_statuses)
        store.set_settings(
            enabled=bool(original_settings.get("enabled")),
            cache_ttl=int(original_settings.get("cache_ttl") or 0),
            cache_max=int(original_settings.get("cache_max") or 0),
        )
        store.clear_refresh_requested()
        _with_proxy_id(
            LIVE_CONFIG.primary_proxy_id, lambda: store.mark_cache_flushed(size=0)
        )


def test_live_proxy_sync_materializes_adblock_artifact_revision(
    admin_client: LiveStackClient, tmp_path
) -> None:
    artifact_dir = tmp_path / "adblock-artifact"
    settings_version = _adblock_store().get_settings_version()
    artifact_dir.mkdir(parents=True, exist_ok=True)
    (artifact_dir / "domains_allow.txt").write_text(
        "allow-live-artifact.example\n", encoding="utf-8"
    )
    (artifact_dir / "domains_block.txt").write_text(
        "ads-live-artifact.example\n", encoding="utf-8"
    )
    (artifact_dir / "regex_allow.txt").write_text("", encoding="utf-8")
    (artifact_dir / "regex_block.txt").write_text(
        "/tracker-live-artifact[.]example/\n", encoding="utf-8"
    )
    (artifact_dir / "settings.json").write_text(
        json.dumps(
            {
                "enabled": False,
                "cache_ttl": 120,
                "cache_max": 1000,
                "settings_version": settings_version,
                "enabled_lists": ["live-fixture"],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (artifact_dir / "report.json").write_text(
        json.dumps(
            {
                "enabled_lists": ["live-fixture"],
                "counts": {
                    "domains_block": 1,
                    "domains_allow": 1,
                    "regex_block": 1,
                    "regex_allow": 0,
                },
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    revision = _adblock_artifacts_store().create_revision_from_directory(
        artifact_dir,
        settings_version=settings_version,
        enabled_lists=["live-fixture"],
        created_by="live-tests",
        source_kind="live-fixture",
    )
    store = _adblock_store()
    _with_proxy_id(LIVE_CONFIG.primary_proxy_id, store.request_cache_flush)

    sync_response = admin_client.proxy_management_post_json(
        "/api/manage/sync", {"force": False}, timeout_seconds=90.0
    )
    assert sync_response.status == 200
    sync_payload = sync_response.json()
    assert sync_payload.get("ok") is True
    sync_detail = str(sync_payload.get("detail") or "")
    assert sync_payload.get("adblock_changed") is True or (
        sync_payload.get("adblock_changed") is False
        and "already using the active adblock artifact" in sync_detail
    )

    deadline = time.time() + 60.0
    latest_apply = None
    while time.time() < deadline:
        latest_apply = _adblock_artifacts_store().latest_apply(
            LIVE_CONFIG.primary_proxy_id,
            revision_id=revision.revision_id,
        )
        if latest_apply is not None:
            break
        time.sleep(1.0)
    assert latest_apply is not None
    assert latest_apply.revision_id == revision.revision_id
    assert latest_apply.ok is True
    assert latest_apply.artifact_sha256 == revision.artifact_sha256
    assert (
        _with_proxy_id(LIVE_CONFIG.primary_proxy_id, store.get_cache_flush_requested)
        == 0
    )


def test_live_webfilter_category_validation_and_save_workflows(
    admin_client: LiveStackClient,
) -> None:
    original_settings = _webfilter_settings(LIVE_CONFIG.primary_proxy_id)
    source_url = f"https://example.com/{unique_token('webcat')}.tar.gz"

    try:
        missing_source_response = admin_client.admin_post_form(
            "/webfilter?tab=categories",
            {
                "action": "save",
                "tab": "categories",
                "enabled": "on",
                "source_url": "",
                "categories": ["adult"],
            },
            csrf_path="/webfilter?tab=categories",
        )
        assert missing_source_response.status == 200
        assert query_params(missing_source_response.url).get("err_source") == ["1"]

        invalid_source_response = admin_client.admin_post_form(
            "/webfilter?tab=categories",
            {
                "action": "save",
                "tab": "categories",
                "enabled": "on",
                "source_url": "ftp://example.invalid/webcat.tar.gz",
                "categories": ["adult"],
            },
            csrf_path="/webfilter?tab=categories",
        )
        assert invalid_source_response.status == 200
        assert query_params(invalid_source_response.url).get("err_source") == ["1"]

        save_response = admin_client.admin_post_form(
            "/webfilter?tab=categories",
            {
                "action": "save",
                "tab": "categories",
                "enabled": "on",
                "source_url": source_url,
                "categories": ["adult", "games"],
            },
            csrf_path="/webfilter?tab=categories",
            timeout_seconds=90.0,
        )
        assert save_response.status == 200
        assert query_params(save_response.url).get("tab") == ["categories"]
        assert query_params(save_response.url).get("err_source") is None
    finally:
        _restore_webfilter_settings(LIVE_CONFIG.primary_proxy_id, original_settings)


def test_live_policy_exception_request_public_submission_and_admin_lifecycle(
    admin_client: LiveStackClient,
) -> None:
    from services.policy_requests import get_policy_request_store  # type: ignore

    domain = unique_domain("policy-request")
    note = unique_token("policy_note")
    store = get_policy_request_store()
    store.init_db()
    before_ids = {r.id for r in store.list_requests(limit=1000)}
    submit_response = admin_client.proxy_public_request(
        "/policy-request",
        method="POST",
        data=(
            f"request_url=https%3A%2F%2F{domain}%2Fblocked&domain={domain}&block_type=webfilter&client_ip=1.2.3.4&user_note={note}"
        ).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout_seconds=30.0,
    )
    assert submit_response.status == 200
    assert "Request submitted" in submit_response.text
    pending = [
        r
        for r in store.list_requests(statuses=["pending"], limit=1000)
        if r.id not in before_ids and r.domain == domain
    ]
    assert len(pending) == 1
    request_row = pending[0]
    assert request_row.proxy_id == LIVE_CONFIG.primary_proxy_id
    assert request_row.block_type == "webfilter"
    assert request_row.client_ip != "1.2.3.4"
    assert note in request_row.user_note
    requests_page = admin_client.admin_request("/requests")
    assert requests_page.status == 200
    assert domain in requests_page.text
    assert note in requests_page.text
    approve_response = admin_client.admin_post_form(
        "/requests",
        {
            "action": "approve",
            "request_id": str(request_row.id),
            "duration_seconds": "3600",
            "admin_note": "live approval",
        },
        csrf_path="/requests",
        timeout_seconds=90.0,
    )
    assert approve_response.status == 200
    assert query_params(approve_response.url).get("ok") == ["approved"]
    active = [
        e
        for e in store.active_webfilter_exceptions(
            proxy_id=LIVE_CONFIG.primary_proxy_id
        )
        if e.source_request_id == request_row.id
    ]
    assert len(active) == 1
    assert active[0].domain == domain
    assert active[0].client_ip == request_row.client_ip
    revoke_response = admin_client.admin_post_form(
        "/requests",
        {
            "action": "revoke",
            "exception_id": str(active[0].id),
            "admin_note": "live cleanup",
        },
        csrf_path="/requests",
        timeout_seconds=90.0,
    )
    assert revoke_response.status == 200
    assert query_params(revoke_response.url).get("ok") == ["revoked"]
    assert all(
        e.id != active[0].id
        for e in store.active_webfilter_exceptions(
            proxy_id=LIVE_CONFIG.primary_proxy_id
        )
    )


def test_live_adblock_enforces_compiled_artifact_and_allow_exception(
    admin_client: LiveStackClient, tmp_path
) -> None:
    artifacts = _adblock_artifacts_store()
    blocked_token = unique_token("live_adblock_block")
    allowed_token = unique_token("live_adblock_allow")
    # Keep this on a neutral extension so the assertion isolates adblock
    # allow/block behavior instead of Squid file-security URL ACLs.
    blocked_path = f"/ads/{blocked_token}.json"
    allowed_path = f"/ads/{allowed_token}.json"

    artifact_dir = tmp_path / "adblock-artifact"
    settings_version = _write_live_adblock_artifact(
        artifact_dir,
        regex_block=f"/.*{blocked_token}[.]json.*/\n/.*{allowed_token}[.]json.*/\n",
        regex_allow=f"/.*{allowed_token}[.]json.*/\n",
    )
    revision = artifacts.create_revision_from_directory(
        artifact_dir,
        settings_version=settings_version,
        enabled_lists=["live-fixture"],
        created_by="live-tests",
        source_kind="live_enforcement",
        activate=True,
    )

    sync_payload = _sync_primary_proxy(admin_client)
    apply_row = artifacts.latest_apply(LIVE_CONFIG.primary_proxy_id)
    assert apply_row is not None
    assert apply_row.revision_id == revision.revision_id
    assert apply_row.ok is True

    sync_detail = sync_payload.get("detail", "")
    assert "Squid reconfigured for policy update." in sync_detail

    blocked = _wait_for_proxy_status(admin_client, blocked_path, 403)
    assert "ERR_ACCESS_DENIED" in blocked.text or "Access Denied" in blocked.text
    allowed = wait_for_proxy_fixture_response(
        admin_client, allowed_path, timeout_seconds=60.0
    )
    assert allowed.status == 200
    assert allowed.json().get("path") == allowed_path


def test_live_webfilter_blocks_category_and_policy_exception_allows_same_client(
    admin_client: LiveStackClient,
) -> None:
    from services.policy_requests import get_policy_request_store  # type: ignore

    proxy_id = LIVE_CONFIG.primary_proxy_id
    settings = _webfilter_settings(proxy_id)
    block_domain = _live_fixture_host()
    block_path = f"/category/{unique_token('webfilter')}"

    def _configure() -> None:
        store = _webfilter_store()
        store.set_settings(enabled=True, source_url="", blocked_categories=["adult"])
        store.clear_refresh_requested()

    try:
        _set_live_webcat_category(block_domain, "adult")
        _with_proxy_id(proxy_id, _configure)
        _sync_primary_proxy(admin_client)
        blocked = _wait_for_proxy_status(admin_client, block_path, 403)
        assert (
            "Docker Proxy policy" in blocked.text
            or "ERR_WEBFILTER_BLOCKED" in blocked.text
        )

        # Use the source address Squid sees for the live-test runner on the proxy listener.
        request_client_ip = __import__(
            "web.tests.live_test_helpers", fromlist=["live_client_ip"]
        ).live_client_ip()
        req = get_policy_request_store().create_request(
            proxy_id=proxy_id,
            client_ip=request_client_ip,
            request_url=f"{LIVE_CONFIG.traffic_fixture_url}{block_path}",
            domain=block_domain,
            category="adult",
            method="GET",
        )
        get_policy_request_store().approve_request(
            req.id, reviewer="live-tests", duration_seconds=300
        )
        _sync_primary_proxy(admin_client)
        allowed = wait_for_proxy_fixture_response(
            admin_client, block_path, timeout_seconds=60.0
        )
        assert allowed.status == 200
        assert (allowed.json().get("headers", {}).get("host") or "").split(":", 1)[
            0
        ] == block_domain
    finally:
        _restore_webfilter_settings(proxy_id, settings)
        _set_live_webcat_category(block_domain, None)
        _sync_primary_proxy(admin_client)
