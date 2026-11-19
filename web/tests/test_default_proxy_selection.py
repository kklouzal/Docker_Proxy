from __future__ import annotations

import concurrent.futures
import threading
from urllib.parse import parse_qs, urlparse

import pytest

from .admin_route_test_utils import (
    FakeAuditStore,
    FakeRegistry,
    csrf_token,
    load_admin_app,
    login_client,
)
from .mysql_test_utils import configure_test_mysql_env


def _registry_module():
    from services import proxy_registry  # type: ignore

    return proxy_registry


def _query(response) -> dict[str, list[str]]:
    return parse_qs(urlparse(response.headers["Location"]).query)


# --- Registry (MySQL) -------------------------------------------------------


def test_env_bootstrap_applies_until_admin_selects_default(tmp_path, monkeypatch):
    monkeypatch.setenv("DEFAULT_PROXY_ID", "edge-env")
    configure_test_mysql_env(tmp_path / "default-selection-bootstrap")
    registry = _registry_module().ProxyRegistry()
    registry.ensure_proxy("edge-env")
    registry.ensure_proxy("edge-b")

    assert registry.default_proxy_selection() == ("edge-env", "environment")

    change = registry.set_default_proxy("edge-b")

    assert (change.previous_proxy_id, change.proxy_id, change.changed) == (
        "edge-env",
        "edge-b",
        True,
    )
    # The changing worker invalidates its cache immediately.
    assert registry.default_proxy_selection() == ("edge-b", "admin")
    assert registry.effective_default_proxy_id() == "edge-b"
    # A later DEFAULT_PROXY_ID change no longer overrides the stored choice.
    monkeypatch.setenv("DEFAULT_PROXY_ID", "edge-other")
    assert registry.default_proxy_selection(max_age_seconds=0) == ("edge-b", "admin")
    assert registry.set_default_proxy("edge-b").changed is False


def test_switching_default_unprotects_previous_and_protects_new(tmp_path, monkeypatch):
    # Production shape: the admin UI env still names a stale registration.
    monkeypatch.setenv("DEFAULT_PROXY_ID", "workstation-proxy")
    configure_test_mysql_env(tmp_path / "default-selection-switch")
    registry = _registry_module().ProxyRegistry()
    registry.ensure_proxy("workstation-proxy")
    registry.ensure_proxy("livingroom-proxy")
    registry.ensure_proxy("spare-proxy")

    with pytest.raises(ValueError, match="Default proxy"):
        registry.remove_proxy("workstation-proxy")

    registry.set_default_proxy("livingroom-proxy")

    with pytest.raises(ValueError, match="Default proxy"):
        registry.remove_proxy("livingroom-proxy")
    with pytest.raises(ValueError, match="Default proxy"):
        registry.rename_proxy("livingroom-proxy", "livingroom-2")
    with pytest.raises(ValueError, match="Default proxy"):
        registry.rename_proxy("spare-proxy", "livingroom-proxy")

    registry.rename_proxy("spare-proxy", "spare-2")
    result = registry.remove_proxy("workstation-proxy")

    assert result.complete is True
    assert [proxy.proxy_id for proxy in registry.list_proxies()] == [
        "livingroom-proxy",
        "spare-2",
    ]
    # The stale env default is neither re-created nor re-registrable.
    assert registry.ensure_default_proxy().proxy_id == "livingroom-proxy"
    with pytest.raises(ValueError, match="has been removed"):
        registry.ensure_proxy("workstation-proxy")
    assert registry.get_proxy("workstation-proxy") is None


def test_set_default_rejects_unregistered_and_lifecycle_blocked_proxies(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("DEFAULT_PROXY_ID", "edge-a")
    configure_test_mysql_env(tmp_path / "default-selection-reject")
    registry = _registry_module().ProxyRegistry()
    registry.ensure_proxy("edge-a")
    registry.ensure_proxy("edge-b")
    registry.ensure_proxy("edge-c")

    with pytest.raises(ValueError, match="not registered"):
        registry.set_default_proxy("edge-missing")

    with registry._connect() as conn:
        conn.execute(
            "UPDATE proxy_instances SET status='remove_pending' WHERE proxy_id='edge-b'",
        )
    with pytest.raises(ValueError, match="being removed"):
        registry.set_default_proxy("edge-b")

    with registry._connect() as conn:
        conn.execute(
            """
            INSERT INTO proxy_lifecycle_tombstones(proxy_id, action, target_proxy_id, detail, created_ts, updated_ts)
            VALUES('edge-c','renaming','edge-d','',1,1)
            """,
        )
    with pytest.raises(ValueError, match="edge-c"):
        registry.set_default_proxy("edge-c")

    assert registry.default_proxy_selection(max_age_seconds=0) == (
        "edge-a",
        "environment",
    )


def test_empty_inventory_bootstraps_effective_default_not_env(tmp_path, monkeypatch):
    monkeypatch.setenv("DEFAULT_PROXY_ID", "stale-env")
    monkeypatch.setenv("DEFAULT_PROXY_NAME", "Stale Env Name")
    configure_test_mysql_env(tmp_path / "default-selection-empty")
    registry = _registry_module().ProxyRegistry()
    registry.ensure_proxy("edge-b")
    registry.set_default_proxy("edge-b")
    with registry._connect() as conn:
        conn.execute("DELETE FROM proxy_instances")

    created = registry.ensure_default_proxy()

    assert created.proxy_id == "edge-b"
    assert created.display_name == "edge-b"
    assert [proxy.proxy_id for proxy in registry.list_proxies()] == ["edge-b"]


def test_other_workers_see_change_within_cache_ttl(tmp_path, monkeypatch):
    monkeypatch.setenv("DEFAULT_PROXY_ID", "edge-a")
    configure_test_mysql_env(tmp_path / "default-selection-cache")
    proxy_registry = _registry_module()
    worker_a = proxy_registry.ProxyRegistry()
    worker_b = proxy_registry.ProxyRegistry()
    worker_a.ensure_proxy("edge-a")
    worker_a.ensure_proxy("edge-b")
    assert worker_b.effective_default_proxy_id() == "edge-a"

    worker_a.set_default_proxy("edge-b")

    # Worker B may serve its cached value only until the bounded TTL expires.
    assert worker_b.effective_default_proxy_id() == "edge-a"
    clock = [0.0]
    monkeypatch.setattr(proxy_registry.time, "monotonic", lambda: clock[0])
    worker_b._invalidate_default_cache()
    assert worker_b.effective_default_proxy_id() == "edge-b"
    worker_a.set_default_proxy("edge-a")
    clock[0] = proxy_registry._DEFAULT_PROXY_CACHE_TTL_SECONDS
    assert worker_b.effective_default_proxy_id() == "edge-b"
    clock[0] += 0.001
    assert worker_b.effective_default_proxy_id() == "edge-a"


def test_database_outage_does_not_fall_back_to_env_default(tmp_path, monkeypatch):
    monkeypatch.setenv("DEFAULT_PROXY_ID", "edge-a")
    configure_test_mysql_env(tmp_path / "default-selection-outage")
    registry = _registry_module().ProxyRegistry()
    registry.ensure_proxy("edge-a")
    registry.ensure_proxy("edge-b")
    registry.set_default_proxy("edge-b")

    def unavailable():
        msg = "mysql unavailable"
        raise ConnectionError(msg)

    monkeypatch.setattr(registry, "_connect", unavailable)
    with pytest.raises(ConnectionError):
        registry.default_proxy_selection(max_age_seconds=0)


def test_proxy_process_identity_ignores_admin_selection(tmp_path, monkeypatch):
    monkeypatch.setenv("DEFAULT_PROXY_ID", "edge-a")
    configure_test_mysql_env(tmp_path / "default-selection-identity")
    registry = _registry_module().ProxyRegistry()
    registry.ensure_proxy("edge-a")
    registry.ensure_proxy("edge-b")
    registry.set_default_proxy("edge-b")

    from services.proxy_context import get_default_proxy_id, get_proxy_id

    assert get_default_proxy_id() == "edge-a"
    assert get_proxy_id() == "edge-a"


@pytest.mark.parametrize("attempt", range(3))
def test_concurrent_set_default_and_remove_never_strand_default(
    tmp_path, monkeypatch, attempt
):
    monkeypatch.setenv("DEFAULT_PROXY_ID", "edge-a")
    configure_test_mysql_env(tmp_path / f"default-selection-race-{attempt}")
    registry = _registry_module().ProxyRegistry()
    for proxy_id in ("edge-a", "edge-b", "edge-c"):
        registry.ensure_proxy(proxy_id)
    barrier = threading.Barrier(2)

    def run(operation):
        barrier.wait(timeout=10)
        try:
            return ("ok", operation())
        except ValueError as exc:
            return ("err", str(exc))

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        set_result, remove_result = executor.map(
            run,
            (
                lambda: registry.set_default_proxy("edge-b"),
                lambda: registry.remove_proxy("edge-b"),
            ),
        )

    default_id = registry.default_proxy_selection(max_age_seconds=0)[0]
    registered = {proxy.proxy_id for proxy in registry.list_proxies()}
    # Exactly one side wins, and the default always names a registered proxy.
    assert [set_result[0], remove_result[0]].count("ok") == 1
    assert default_id in registered
    if set_result[0] == "ok":
        assert default_id == "edge-b"
        assert "Default proxy" in remove_result[1]
    else:
        assert default_id == "edge-a"
        assert "edge-b" not in registered


# --- Admin routes -----------------------------------------------------------


def test_set_default_route_persists_audits_and_renders(monkeypatch, tmp_path):
    registry = FakeRegistry(proxy_ids=["default", "edge-2"])
    loaded = load_admin_app(monkeypatch, tmp_path, registry=registry)
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/proxies")

    response = client.post(
        "/proxies/default",
        data={"csrf_token": token, "proxy_id": "edge-2"},
        follow_redirects=False,
    )

    assert response.status_code in {301, 302, 303}
    assert _query(response)["default_set"] == ["1"]
    assert registry.default_changes == ["edge-2"]
    record = loaded.audit_store.records[-1]
    assert record["kind"] == "proxy_default_set"
    assert record["ok"] is True
    assert record["detail"] == "previous_proxy_id=default proxy_id=edge-2"

    with client.session_transaction() as sess:
        sess.pop("active_proxy_id", None)
    page = client.get("/proxies").get_data(as_text=True)
    assert '<span class="badge ok">Default</span>' in page
    assert "It was chosen on this page." in page
    # A new session lands on the stored default, and the default row offers
    # no remove/rename while the previous default can now be removed.
    with client.session_transaction() as sess:
        assert sess["active_proxy_id"] == "edge-2"
    assert page.count(">Make default</button>") == 1
    assert page.count('name="confirm_proxy_id"') == 1


def test_set_default_route_requires_csrf_and_login(monkeypatch, tmp_path):
    registry = FakeRegistry(proxy_ids=["default", "edge-2"])
    loaded = load_admin_app(monkeypatch, tmp_path, registry=registry)
    client = loaded.module.app.test_client()

    anonymous = client.post("/proxies/default", data={"proxy_id": "edge-2"})
    assert anonymous.status_code in {301, 302, 303, 403}

    login_client(client)
    missing_csrf = client.post("/proxies/default", data={"proxy_id": "edge-2"})

    assert missing_csrf.status_code == 403
    assert registry.default_changes == []


@pytest.mark.parametrize("proxy_id", ["", "edge 2", "missing-proxy"])
def test_set_default_route_rejects_non_registered_ids(monkeypatch, tmp_path, proxy_id):
    registry = FakeRegistry(proxy_ids=["default", "edge-2"])
    loaded = load_admin_app(monkeypatch, tmp_path, registry=registry)
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/proxies")

    response = client.post(
        "/proxies/default",
        data={"csrf_token": token, "proxy_id": proxy_id},
        follow_redirects=False,
    )

    assert _query(response)["error"] == ["1"]
    assert registry.default_changes == []


def test_set_default_route_reports_and_audits_registry_refusal(monkeypatch, tmp_path):
    registry = FakeRegistry(proxy_ids=["default", "edge-2"])
    registry.get_proxy("edge-2").status = "removing"
    audit_store = FakeAuditStore()
    loaded = load_admin_app(
        monkeypatch, tmp_path, registry=registry, audit_store=audit_store
    )
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/proxies")

    response = client.post(
        "/proxies/default",
        data={"csrf_token": token, "proxy_id": "edge-2"},
        follow_redirects=False,
    )

    assert _query(response)["error"] == ["1"]
    assert audit_store.records[-1]["kind"] == "proxy_default_set"
    assert audit_store.records[-1]["ok"] is False
    assert registry.default_proxy_id is None
