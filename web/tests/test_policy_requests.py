from __future__ import annotations

import importlib
import sys
from pathlib import Path

from .mysql_test_utils import configure_test_mysql_env, ensure_proxy_runtime_import_path, ensure_web_import_path


def test_policy_request_store_normalizes_approves_lists_and_revokes(tmp_path):
    configure_test_mysql_env(tmp_path / "policy-requests")
    ensure_web_import_path()
    from services.policy_requests import PolicyRequestStore

    store = PolicyRequestStore(); store.init_db()
    req = store.create_request(proxy_id="Edge A!!", client_ip="192.168.1.55", request_url="https://Bad.Example/path", domain="BAD.example:443", category="adult", method="get", user_note=" please\nallow ")
    assert req.proxy_id == "edge-a"
    assert req.domain == "bad.example"
    assert req.client_ip == "192.168.1.55"
    assert req.method == "GET"
    assert store.list_requests(statuses=["pending"])[0].id == req.id
    ex = store.approve_request(req.id, reviewer="admin", duration_seconds=3600, admin_note="ok")
    assert ex.status == "active" and ex.domain == "bad.example" and ex.expires_ts > 0
    assert store.active_webfilter_exceptions(proxy_id="edge-a")[0].id == ex.id
    store.revoke_exception(ex.id, revoked_by="admin", admin_note="done")
    assert store.active_webfilter_exceptions(proxy_id="edge-a") == []


def test_webfilter_materialization_renders_client_scoped_exceptions(monkeypatch, tmp_path):
    ensure_web_import_path()
    import services.webfilter_core as core
    core = importlib.reload(core)
    from services.policy_requests import PolicyException
    from services.proxy_context import reset_proxy_id, set_proxy_id

    class Store(core.WebFilterStoreBase):
        def get_settings(self):
            return core.WebFilterSettings(True, "", ["adult"], [], 0, 0, "", 0)
        def _resolve_category_aliases(self, categories):
            return categories

    class RequestStore:
        def active_webfilter_exceptions(self, *, proxy_id=None, at_ts=None, limit=5000):
            return [PolicyException(7, proxy_id or "edge-a", "active", "webfilter", "192.168.1.55", "bad.example", "adult", 1, 1, "admin", "", 0, 0, "", 1)]

    monkeypatch.setattr(core, "get_policy_request_store", lambda: RequestStore())
    token = set_proxy_id("edge-a")
    try:
        text = Store().render_materialized_state().include_text
    finally:
        reset_proxy_id(token)
    assert "acl webfilter_exception_src_7 src 192.168.1.55" in text
    assert "acl webfilter_exception_dst_7 dstdomain .bad.example" in text
    assert text.index("http_access allow webfilter_exception_src_7") < text.index("http_access deny webfilter_block_adult")


def test_error_page_only_webfilter_has_request_form():
    root = Path(__file__).resolve().parents[2]
    blocked = (root / "squid/error_pages/en/ERR_WEBFILTER_BLOCKED").read_text(encoding="utf-8")
    denied = (root / "squid/error_pages/en/ERR_ACCESS_DENIED").read_text(encoding="utf-8")
    assert 'action="http://%h/policy-request"' in blocked
    assert 'name="request_url" value="%U"' in blocked
    assert "/policy-request" not in denied


def test_proxy_public_policy_request_route_records(monkeypatch):
    ensure_proxy_runtime_import_path()
    monkeypatch.setenv("DISABLE_PROXY_AGENT", "1")
    import proxy.app as proxy_app
    proxy_app = importlib.reload(proxy_app)
    recorded = {}
    class Store:
        def create_request(self, **kwargs):
            recorded.update(kwargs)
            from services.policy_requests import PolicyRequest
            return PolicyRequest(123, kwargs.get("proxy_id") or "default", "pending", "webfilter", kwargs["client_ip"], kwargs["request_url"], kwargs["domain"], "", "", "", "", "", 1, 1, 0, "", None)
    monkeypatch.setattr(proxy_app, "get_policy_request_store", lambda: Store())
    res = proxy_app.app.test_client().post("/policy-request", base_url="http://localhost", data={"request_url":"https://bad.example/", "client_ip":"192.168.1.55", "domain":"bad.example", "user_note":"need"})
    assert res.status_code == 200
    assert recorded["domain"] == "bad.example"
    assert recorded["client_ip"] == "127.0.0.1"
    assert "Request submitted" in res.get_data(as_text=True)



def test_admin_policy_requests_route_and_link_smoke(monkeypatch, tmp_path):
    from .admin_route_test_utils import load_admin_app, login_client
    from services.policy_requests import PolicyException, PolicyRequest

    class Store:
        def __init__(self):
            self.approved = []
            self.revoked = []
        def init_db(self):
            pass
        def list_requests(self, *, statuses=None, limit=200):
            rows = [PolicyRequest(1, "edge-a", "pending", "webfilter", "192.168.1.55", "https://bad.example/", "bad.example", "adult", "GET", "ERR_ACCESS_DENIED", "needed", "", 1, 1, 0, "", None)]
            if statuses:
                rows = [r for r in rows if r.status in statuses]
            return rows
        def list_exceptions(self, *, include_inactive=True, limit=200):
            return [PolicyException(2, "edge-a", "active", "webfilter", "192.168.1.55", "ok.example", "", 1, 1, "admin", "ok", 0, 0, "", 1)]
        def approve_request(self, request_id, **kwargs):
            self.approved.append((request_id, kwargs))
            return self.list_exceptions()[0]
        def close_request(self, request_id, **kwargs):
            pass
        def revoke_exception(self, exception_id, **kwargs):
            self.revoked.append((exception_id, kwargs))

    store = Store()
    loaded = load_admin_app(monkeypatch, tmp_path, policy_request_store=store)
    monkeypatch.setattr(loaded.module, "_best_effort_refresh_managed_policy", lambda *a, **k: None)
    client = loaded.module.app.test_client()
    login_client(client)
    page = client.get("/requests")
    text = page.get_data(as_text=True)
    assert page.status_code == 200
    assert "Policy exception requests" in text
    assert "bad.example" in text
    assert "Requests</a>" in text
    token = text.split('name="csrf_token" value="', 1)[1].split('"', 1)[0]
    res = client.post("/requests", data={"csrf_token": token, "action": "approve", "request_id": "1", "duration_seconds": "3600"})
    assert res.status_code in {302, 303}
    assert store.approved and store.approved[0][0] == 1


def test_policy_request_store_rejects_invalid_scope_and_filters_active_exceptions(tmp_path):
    configure_test_mysql_env(tmp_path / "policy-request-filters")
    ensure_web_import_path()
    from services.policy_requests import PolicyRequestStore, normalize_block_type, normalize_client_ip, normalize_domain
    store = PolicyRequestStore(); store.init_db()
    assert normalize_client_ip("192.168.1.20, 10.0.0.9") == "192.168.1.20"
    assert normalize_client_ip("not an ip") == ""
    assert normalize_domain("https://Mixed.Example:443/path") == "mixed.example"
    assert normalize_domain("traffic-fixture") == "traffic-fixture"
    assert normalize_domain("", request_url="http://proxy:5000/path") == "proxy"
    assert normalize_domain("12345") == ""
    assert normalize_block_type("unknown<script>") == "webfilter"
    for kwargs in ({"client_ip":"192.168.1.44","domain":"not a host"},{"client_ip":"not an ip","domain":"blocked.example"}):
        try:
            store.create_request(proxy_id="edge-a", request_url="https://blocked.example/", **kwargs)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid request scope should be rejected")
    edge_req=store.create_request(proxy_id="edge-a",client_ip="192.168.1.55",request_url="https://blocked.example/path",domain="blocked.example",category="adult")
    remote_req=store.create_request(proxy_id="edge-b",client_ip="192.168.1.55",request_url="https://remote.example/path",domain="remote.example",category="adult")
    adblock_req=store.create_request(proxy_id="edge-a",block_type="adblock",client_ip="192.168.1.55",request_url="https://ads.example/path",domain="ads.example")
    active=store.approve_request(edge_req.id,reviewer="admin",indefinite=True)
    expired=store.approve_request(remote_req.id,reviewer="admin",duration_seconds=60)
    non_webfilter=store.approve_request(adblock_req.id,reviewer="admin",indefinite=True)
    assert active.expires_ts == 0
    assert non_webfilter.block_type == "adblock"
    assert [ex.id for ex in store.active_webfilter_exceptions(proxy_id="edge-a")] == [active.id]
    assert store.active_webfilter_exceptions(proxy_id="edge-b", at_ts=expired.expires_ts + 1) == []


def test_policy_request_store_state_transitions_are_one_way(tmp_path):
    configure_test_mysql_env(tmp_path / "policy-request-transitions")
    ensure_web_import_path()
    from services.policy_requests import PolicyRequestStore
    store=PolicyRequestStore(); store.init_db()
    rejected=store.create_request(proxy_id="edge-a",client_ip="192.168.1.55",request_url="https://reject.example/",domain="reject.example")
    store.close_request(rejected.id,reviewer="admin",status="rejected",admin_note="no")
    assert store.list_requests(statuses=["rejected"])[0].id == rejected.id
    try:
        store.approve_request(rejected.id,reviewer="admin",indefinite=True)
    except ValueError as exc:
        assert "Only pending" in str(exc)
    else:
        raise AssertionError("rejected request should not be approvable")
    approved=store.create_request(proxy_id="edge-a",client_ip="192.168.1.56",request_url="https://approve.example/",domain="approve.example")
    store.approve_request(approved.id,reviewer="admin",indefinite=True)
    store.close_request(approved.id,reviewer="admin",status="closed",admin_note="late close")
    assert store.list_requests(statuses=["approved"])[0].id == approved.id


def test_proxy_policy_request_route_is_public_listener_only_and_ignores_spoofed_client_ip(monkeypatch):
    ensure_proxy_runtime_import_path()
    monkeypatch.setenv("DISABLE_PROXY_AGENT","1")
    monkeypatch.setenv("PAC_HTTP_PORT","80")
    import proxy.app as proxy_app
    proxy_app=importlib.reload(proxy_app)
    recorded={}
    class Store:
        def create_request(self, **kwargs):
            recorded.update(kwargs)
            from services.policy_requests import PolicyRequest
            return PolicyRequest(456, kwargs.get("proxy_id") or "default", "pending", "webfilter", kwargs["client_ip"], kwargs["request_url"], kwargs["domain"], "", "", "", "", "", 1, 1, 0, "", None)
    monkeypatch.setattr(proxy_app,"get_policy_request_store",lambda:Store())
    client=proxy_app.app.test_client()
    management=client.post("/policy-request",base_url="http://localhost:5000",data={"request_url":"https://bad.example/","domain":"bad.example"})
    assert management.status_code == 404
    public=client.post("/policy-request",base_url="http://localhost:80",environ_base={"REMOTE_ADDR":"10.9.8.7"},data={"request_url":"https://bad.example/","client_ip":"1.2.3.4","domain":"bad.example"})
    assert public.status_code == 200
    assert recorded["client_ip"] == "10.9.8.7"
