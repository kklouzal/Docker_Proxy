from .flask_test_helpers import login, redirect_query_params


def test_pac_builder_create_profile(app_module):
    c = app_module.app.test_client()
    csrf = login(c)

    r = c.post(
        "/pac",
        headers={"X-CSRF-Token": csrf},
        data={
            "action": "create",
            "name": "test",
            "client_cidr": "",
            "direct_domains": "example.com\n",
            "direct_dst_nets": "",
        },
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)


def test_squid_config_network_tab_mentions_non_standard_ports(app_module):
    c = app_module.app.test_client()
    login(c)

    r = c.get("/squid/config?tab=network")
    assert r.status_code == 200
    body = r.data.decode("utf-8", errors="replace")
    assert "Web destination ports" in body
    assert "Non-standard HTTP and HTTPS destination ports are allowed by default" in body


def test_pac_builder_update_and_delete(app_module):
    c = app_module.app.test_client()
    csrf = login(c)

    store = getattr(app_module, "_test_pac_profiles_store")
    r_upd = c.post(
        "/pac",
        headers={"X-CSRF-Token": csrf},
        data={
            "action": "update",
            "profile_id": "5",
            "name": "updated",
            "client_cidr": "",
            "direct_domains": "example.com\n",
            "direct_dst_nets": "",
        },
        follow_redirects=False,
    )
    assert r_upd.status_code in (301, 302, 303, 307, 308)
    assert store.upserts and store.upserts[-1]["profile_id"] == 5

    r_del = c.post(
        "/pac",
        headers={"X-CSRF-Token": csrf},
        data={"action": "delete", "profile_id": "5"},
        follow_redirects=False,
    )
    assert r_del.status_code in (301, 302, 303, 307, 308)
    assert 5 in store.deletes


def test_squid_config_manual_apply_and_validate(app_module, monkeypatch):
    c = app_module.app.test_client()
    csrf = login(c)

    r_apply = c.post(
        "/squid/config",
        headers={"X-CSRF-Token": csrf},
        data={"action": "apply", "tab": "config", "config_text": "http_port 3128\n"},
        follow_redirects=False,
    )
    assert r_apply.status_code in (301, 302, 303, 307, 308)
    assert redirect_query_params(r_apply).get("ok") == ["1"]

    called = {"n": 0}

    def fake_validate(cfg_text: str):
        called["n"] += 1
        return True, "OK"

    controller = getattr(app_module, "_test_squid_controller")
    controller.validate_config_text = fake_validate  # type: ignore[method-assign]

    r_val = c.post(
        "/squid/config",
        headers={"X-CSRF-Token": csrf},
        data={"action": "validate", "tab": "config", "config_text": "http_port 3128\n"},
    )
    assert r_val.status_code == 200
    assert called["n"] == 1
