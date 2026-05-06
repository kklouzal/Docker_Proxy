from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

from .admin_route_test_utils import (
    FakeAdblockStore,
    FakeExclusionsStore,
    FakePacProfilesStore,
    FakeSslfilterStore,
    FakeWebfilterStore,
    load_admin_app,
)


def _params(location: str) -> dict[str, list[str]]:
    return parse_qs(urlsplit(location).query)


def test_adblock_settings_accept_non_int_default_and_request_refresh(monkeypatch, tmp_path) -> None:
    store = FakeAdblockStore()
    loaded = load_admin_app(monkeypatch, tmp_path, adblock_store=store)
    with loaded.module.app.test_request_context(
        "/adblock",
        method="POST",
        data={"action": "save_settings", "adblock_enabled": "on", "cache_ttl": "not-int", "cache_max": "-10"},
    ):
        response = loaded.module._handle_adblock_post(store)
    assert response.status_code in {301, 302, 303}
    assert store.settings["enabled"] is True
    assert store.settings["cache_ttl"] == 3600
    assert store.settings["cache_max"] == -10
    assert store.refresh_requested == 1


def test_adblock_refresh_with_no_enabled_lists_redirects_with_warning(monkeypatch, tmp_path) -> None:
    store = FakeAdblockStore()
    for status in store.statuses:
        status.enabled = False
    loaded = load_admin_app(monkeypatch, tmp_path, adblock_store=store)
    with loaded.module.app.test_request_context("/adblock", method="POST", data={"action": "refresh"}):
        response = loaded.module._handle_adblock_post(store)
    assert _params(response.location)["refresh_no_lists"] == ["1"]
    assert store.refresh_requested == 0


def test_exclusions_bulk_domains_and_cidrs_report_counts_and_limit_error_detail(monkeypatch, tmp_path) -> None:
    store = FakeExclusionsStore()
    loaded = load_admin_app(monkeypatch, tmp_path, exclusions_store=store)
    domain_lines = "\n".join(["one.example", "bad domain/example", "two.example", "bad/2", "bad/3", "bad/4"])
    with loaded.module.app.test_request_context("/exclusions", method="POST", data={"action": "add_domain_bulk", "domains_bulk": domain_lines}):
        response = loaded.module._handle_exclusions_post(store)
    params = _params(response.location)
    assert params["bulk_added"] == ["2"]
    assert params["bulk_failed"] == ["4"]
    assert params["exclude_error"][0].count("Invalid domain") == 3

    cidr_lines = "\n".join(["10.0.0.0/8", "bad", "192.0.2.0/24", "bad-cidr"])
    with loaded.module.app.test_request_context("/exclusions", method="POST", data={"action": "add_src_bulk", "src_bulk": cidr_lines}):
        cidr_response = loaded.module._handle_exclusions_post(store)
    cidr_params = _params(cidr_response.location)
    assert cidr_params["bulk_cidrs_added"] == ["2"]
    assert cidr_params["bulk_cidrs_failed"] == ["2"]


def test_exclusions_return_to_accepts_only_local_paths(monkeypatch, tmp_path) -> None:
    store = FakeExclusionsStore()
    loaded = load_admin_app(monkeypatch, tmp_path, exclusions_store=store)
    with loaded.module.app.test_request_context(
        "/exclusions",
        method="POST",
        data={"action": "add_domain", "domain": "local.example", "return_to": "/observability?pane=ssl"},
    ):
        local_response = loaded.module._handle_exclusions_post(store)
    assert local_response.location.startswith("/observability")

    with loaded.module.app.test_request_context(
        "/exclusions",
        method="POST",
        data={"action": "add_domain", "domain": "fallback.example", "return_to": "https://evil.example/"},
    ):
        external_response = loaded.module._handle_exclusions_post(store)
    assert external_response.location.startswith("/exclusions")


def test_webfilter_save_validates_source_url_and_whitelist(monkeypatch, tmp_path) -> None:
    store = FakeWebfilterStore()
    loaded = load_admin_app(monkeypatch, tmp_path, webfilter_store=store)
    with loaded.module.app.test_request_context(
        "/webfilter",
        method="POST",
        data={"action": "save", "enabled": "on", "source_url": "", "categories": "adult"},
    ):
        missing = loaded.module._handle_webfilter_post(store, "categories")
    assert _params(missing.location)["err_source"] == ["1"]

    with loaded.module.app.test_request_context(
        "/webfilter",
        method="POST",
        data={"action": "save", "enabled": "on", "source_url": "ftp://example.invalid/list.tar.gz", "categories": "adult"},
    ):
        invalid = loaded.module._handle_webfilter_post(store, "categories")
    assert _params(invalid.location)["err_source"] == ["1"]

    with loaded.module.app.test_request_context(
        "/webfilter",
        method="POST",
        data={"action": "whitelist_add", "whitelist_domain": "bad value"},
    ):
        bad_whitelist = loaded.module._handle_webfilter_post(store, "whitelist")
    assert "wl_err" in _params(bad_whitelist.location)


def test_sslfilter_add_remove_and_unknown_actions(monkeypatch, tmp_path) -> None:
    store = FakeSslfilterStore()
    loaded = load_admin_app(monkeypatch, tmp_path, sslfilter_store=store)
    with loaded.module.app.test_request_context("/sslfilter", method="POST", data={"action": "add", "cidr": "bad"}):
        bad_add = loaded.module._handle_sslfilter_post(store)
    assert "err" in _params(bad_add.location)

    with loaded.module.app.test_request_context("/sslfilter", method="POST", data={"action": "add", "cidr": "10.1.2.0/24"}):
        ok_add = loaded.module._handle_sslfilter_post(store)
    assert _params(ok_add.location)["ok"] == ["1"]
    assert store.rows == [("10.1.2.0/24", 1)]

    with loaded.module.app.test_request_context("/sslfilter", method="POST", data={"action": "unknown"}):
        unknown = loaded.module._handle_sslfilter_post(store)
    assert urlsplit(unknown.location).path == "/sslfilter"


def test_pac_builder_bad_ids_and_xss_like_names_are_handled(monkeypatch, tmp_path) -> None:
    store = FakePacProfilesStore()
    loaded = load_admin_app(monkeypatch, tmp_path, pac_profiles_store=store)
    with loaded.module.app.test_request_context(
        "/pac",
        method="POST",
        data={"action": "create", "name": "<script>alert(1)</script>", "client_cidr": "", "direct_domains": "example.com"},
    ):
        created = loaded.module._handle_pac_builder_post(store)
    assert _params(created.location)["ok"] == ["1"]
    assert store.profiles[1].name == "<script>alert(1)</script>"

    with loaded.module.app.test_request_context("/pac", method="POST", data={"action": "update", "profile_id": "not-int"}):
        bad_id = loaded.module._handle_pac_builder_post(store)
    params = _params(bad_id.location)
    assert params["error"] == ["1"]
    assert params["msg"]
