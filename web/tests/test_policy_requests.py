from __future__ import annotations

import importlib
import re
import urllib.parse
from pathlib import Path

from .mysql_test_utils import (
    configure_test_mysql_env,
    ensure_proxy_runtime_import_path,
    ensure_web_import_path,
)


def test_policy_request_store_normalizes_approves_lists_and_revokes(tmp_path) -> None:
    configure_test_mysql_env(tmp_path / "policy-requests")
    ensure_web_import_path()
    from services.policy_requests import PolicyRequestStore

    store = PolicyRequestStore()
    store.init_db()
    req = store.create_request(
        proxy_id="Edge A!!",
        client_ip="192.168.1.55",
        request_url="https://Bad.Example/path",
        domain="BAD.example:443",
        category="adult",
        method="get",
        user_note=" please\nallow ",
    )
    assert req.proxy_id == "edge-a"
    assert req.domain == "bad.example"
    assert req.client_ip == "192.168.1.55"
    assert req.method == "GET"
    assert store.list_requests(statuses=["pending"])[0].id == req.id
    ex = store.approve_request(
        req.id, reviewer="admin", duration_seconds=3600, admin_note="ok"
    )
    assert ex.status == "active"
    assert ex.domain == "bad.example"
    assert ex.expires_ts > 0
    assert store.active_webfilter_exceptions(proxy_id="edge-a")[0].id == ex.id
    store.revoke_exception(ex.id, revoked_by="admin", admin_note="done")
    assert store.active_webfilter_exceptions(proxy_id="edge-a") == []


def test_policy_request_store_bounds_direct_approval_durations(tmp_path) -> None:
    configure_test_mysql_env(tmp_path / "policy-request-duration-bounds")
    ensure_web_import_path()
    from services.policy_requests import (
        POLICY_EXCEPTION_DEFAULT_DURATION_SECONDS,
        POLICY_EXCEPTION_MAX_DURATION_SECONDS,
        POLICY_EXCEPTION_MIN_DURATION_SECONDS,
        PolicyRequestStore,
    )

    store = PolicyRequestStore()
    store.init_db()

    def approve(domain: str, duration_seconds: object):
        req = store.create_request(
            proxy_id="edge-a",
            client_ip="192.168.1.55",
            request_url=f"https://{domain}/",
            domain=domain,
        )
        return store.approve_request(
            req.id,
            reviewer="admin",
            duration_seconds=duration_seconds,
        )

    minimum = approve("min.example", 0)
    default = approve("default.example", "not-int")
    maximum = approve("max.example", 999999999)
    indefinite = approve("indefinite.example", None)

    assert minimum.expires_ts - minimum.created_ts == (
        POLICY_EXCEPTION_MIN_DURATION_SECONDS
    )
    assert default.expires_ts - default.created_ts == (
        POLICY_EXCEPTION_DEFAULT_DURATION_SECONDS
    )
    assert maximum.expires_ts - maximum.created_ts == (
        POLICY_EXCEPTION_MAX_DURATION_SECONDS
    )
    assert indefinite.expires_ts == 0


def test_webfilter_materialization_renders_client_scoped_exceptions(
    monkeypatch, tmp_path
) -> None:
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
            return [
                PolicyException(
                    7,
                    proxy_id or "edge-a",
                    "active",
                    "webfilter",
                    "192.168.1.55",
                    "bad.example",
                    "adult",
                    1,
                    1,
                    "admin",
                    "",
                    0,
                    0,
                    "",
                    1,
                )
            ]

    monkeypatch.setattr(core, "get_policy_request_store", RequestStore)
    token = set_proxy_id("edge-a")
    try:
        text = Store().render_materialized_state().include_text
    finally:
        reset_proxy_id(token)
    assert "acl webfilter_exception_src_7 src 192.168.1.55" in text
    assert "acl webfilter_exception_dst_7 dstdomain bad.example .bad.example" in text
    assert text.index("http_access allow webfilter_exception_src_7") < text.index(
        "http_access deny webfilter_block_adult"
    )


def test_error_page_only_webfilter_has_request_form() -> None:
    root = Path(__file__).resolve().parents[2]
    blocked = (root / "squid/error_pages/en/ERR_WEBFILTER_BLOCKED").read_text(
        encoding="utf-8"
    )
    denied = (root / "squid/error_pages/en/ERR_ACCESS_DENIED").read_text(
        encoding="utf-8"
    )
    assert 'action="http://%h/policy-request"' in blocked
    assert 'name="request_url" value="%U"' in blocked
    assert "/policy-request" not in denied


def test_proxy_public_policy_request_route_records(monkeypatch) -> None:
    ensure_proxy_runtime_import_path()
    monkeypatch.setenv("DISABLE_PROXY_AGENT", "1")
    import proxy.app as proxy_app

    proxy_app = importlib.reload(proxy_app)
    recorded = {}

    class Store:
        def create_request(self, **kwargs):
            recorded.update(kwargs)
            from services.policy_requests import PolicyRequest

            return PolicyRequest(
                123,
                kwargs.get("proxy_id") or "default",
                "pending",
                "webfilter",
                kwargs["client_ip"],
                kwargs["request_url"],
                kwargs["domain"],
                "",
                "",
                "",
                "",
                "",
                1,
                1,
                0,
                "",
                None,
            )

    monkeypatch.setattr(proxy_app, "get_policy_request_store", Store)
    res = proxy_app.app.test_client().post(
        "/policy-request",
        base_url="http://localhost",
        data={
            "request_url": "https://bad.example/",
            "client_ip": "192.168.1.55",
            "domain": "bad.example",
            "user_note": "need",
        },
    )
    assert res.status_code == 200
    assert recorded["domain"] == "bad.example"
    assert recorded["client_ip"] == "127.0.0.1"
    assert "Request submitted" in res.get_data(as_text=True)


def test_admin_policy_requests_route_and_link_smoke(monkeypatch, tmp_path) -> None:
    from services.policy_requests import PolicyException, PolicyRequest

    from .admin_route_test_utils import load_admin_app, login_client

    class Store:
        def __init__(self) -> None:
            self.approved = []
            self.revoked = []

        def init_db(self) -> None:
            pass

        def list_requests(self, *, statuses=None, limit=200, proxy_id=None):
            rows = [
                PolicyRequest(
                    1,
                    "default",
                    "pending",
                    "webfilter",
                    "192.168.1.55",
                    "https://bad.example/",
                    "bad.example",
                    "adult",
                    "GET",
                    "ERR_ACCESS_DENIED",
                    "needed",
                    "",
                    1,
                    1,
                    0,
                    "",
                    None,
                )
            ]
            if statuses:
                rows = [r for r in rows if r.status in statuses]
            if proxy_id is not None:
                rows = [r for r in rows if r.proxy_id == proxy_id]
            return rows

        def list_exceptions(self, *, include_inactive=True, limit=200, proxy_id=None):
            rows = [
                PolicyException(
                    2,
                    "default",
                    "active",
                    "webfilter",
                    "192.168.1.55",
                    "ok.example",
                    "",
                    1,
                    1,
                    "admin",
                    "ok",
                    0,
                    0,
                    "",
                    1,
                )
            ]
            if proxy_id is not None:
                rows = [r for r in rows if r.proxy_id == proxy_id]
            return rows

        def approve_request(self, request_id, **kwargs):
            self.approved.append((request_id, kwargs))
            return self.list_exceptions()[0]

        def close_request(self, request_id, **kwargs) -> None:
            pass

        def revoke_exception(self, exception_id, **kwargs) -> None:
            self.revoked.append((exception_id, kwargs))

    store = Store()
    loaded = load_admin_app(monkeypatch, tmp_path, policy_request_store=store)
    monkeypatch.setattr(
        loaded.module, "_best_effort_refresh_managed_policy", lambda *a, **k: None
    )
    client = loaded.module.app.test_client()
    login_client(client)
    page = client.get("/requests")
    text = page.get_data(as_text=True)
    assert page.status_code == 200
    assert "Policy exception requests" in text
    assert "bad.example" in text
    assert "Requests</a>" in text
    token = text.split('name="csrf_token" value="', 1)[1].split('"', 1)[0]
    res = client.post(
        "/requests",
        data={
            "csrf_token": token,
            "action": "approve",
            "request_id": "1",
            "duration_seconds": "3600",
        },
    )
    assert res.status_code in {302, 303}
    assert store.approved
    assert store.approved[0][0] == 1


def test_admin_policy_requests_approval_and_revocation_disclose_queued_operation(
    monkeypatch,
    tmp_path,
) -> None:
    from services.policy_requests import PolicyException

    from .admin_route_test_utils import FakeRegistry, load_admin_app, login_client

    class Store:
        def __init__(self) -> None:
            self.approved: list[tuple[int, dict[str, object]]] = []
            self.revoked: list[tuple[int, dict[str, object]]] = []

        def init_db(self) -> None:
            pass

        def approve_request(self, request_id, **kwargs):
            self.approved.append((request_id, kwargs))
            return PolicyException(
                2,
                "edge-2",
                "active",
                "webfilter",
                "192.168.1.55",
                "ok.example",
                "adult",
                1,
                1,
                "admin",
                "approved",
                0,
                0,
                "",
                request_id,
            )

        def revoke_exception(self, exception_id, **kwargs) -> None:
            self.revoked.append((exception_id, kwargs))

    store = Store()
    monkeypatch.setenv("DISABLE_CSRF", "1")
    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        registry=FakeRegistry(["default", "edge-2"]),
        policy_request_store=store,
    )
    desired_policy_sha = "a" * 64
    monkeypatch.setattr(
        loaded.module,
        "_desired_policy_sha_for_proxy",
        lambda _proxy_id: (desired_policy_sha, ""),
    )
    client = loaded.module.app.test_client()
    login_client(client)

    approve_response = client.post(
        "/requests?proxy_id=edge-2",
        data={
            "action": "approve",
            "request_id": "7",
            "duration_seconds": "3600",
        },
        follow_redirects=False,
    )

    assert approve_response.status_code in {302, 303}
    approve_location = approve_response.headers.get("Location", "")
    approve_params = urllib.parse.parse_qs(
        urllib.parse.urlsplit(approve_location).query,
    )
    assert len(approve_params.get("ok", [])) == 1
    assert re.fullmatch(
        r"approved; Policy reconciliation queued operation #\d+ for policy a{12}\.",
        approve_params["ok"][0],
    )
    assert len(store.approved) == 1
    assert store.approved[0][0] == 7
    assert store.approved[0][1]["proxy_id"] == "edge-2"
    assert loaded.operation_ledger.operations[-1].proxy_id == "edge-2"
    assert loaded.operation_ledger.operations[-1].operation_type == "policy_sync"
    assert loaded.operation_ledger.operations[-1].target_ref == desired_policy_sha
    assert loaded.operation_ledger.operations[-1].status == "pending"

    approve_page = client.get(approve_location)
    approve_text = approve_page.get_data(as_text=True)
    assert (
        "Action completed: approved; Policy reconciliation queued operation #1 "
        "for policy aaaaaaaaaaaa."
        in approve_text
    )

    revoke_response = client.post(
        "/requests?proxy_id=edge-2",
        data={
            "action": "revoke",
            "exception_id": "2",
            "admin_note": "cleanup",
        },
        follow_redirects=False,
    )

    assert revoke_response.status_code in {302, 303}
    revoke_location = revoke_response.headers.get("Location", "")
    revoke_params = urllib.parse.parse_qs(
        urllib.parse.urlsplit(revoke_location).query,
    )
    assert len(revoke_params.get("ok", [])) == 1
    assert re.fullmatch(
        r"revoked; Policy reconciliation queued operation #\d+ for policy a{12}\.",
        revoke_params["ok"][0],
    )
    assert len(store.revoked) == 1
    assert store.revoked[0][0] == 2
    assert store.revoked[0][1]["proxy_id"] == "edge-2"
    assert loaded.operation_ledger.operations[-1].proxy_id == "edge-2"
    assert loaded.operation_ledger.operations[-1].operation_type == "policy_sync"
    assert loaded.operation_ledger.operations[-1].target_ref == desired_policy_sha
    assert loaded.operation_ledger.operations[-1].status == "pending"


def test_admin_policy_requests_queue_failure_reports_error_without_success(
    monkeypatch,
    tmp_path,
) -> None:
    from .admin_route_test_utils import load_admin_app, login_client

    class Store:
        def __init__(self) -> None:
            self.approved: list[tuple[int, dict[str, object]]] = []

        def init_db(self) -> None:
            pass

        def approve_request(self, request_id, **kwargs):
            self.approved.append((request_id, kwargs))

    store = Store()
    monkeypatch.setenv("DISABLE_CSRF", "1")
    loaded = load_admin_app(monkeypatch, tmp_path, policy_request_store=store)

    def fail_reconcile(*_args, **_kwargs):
        msg = "operation ledger unavailable"
        raise RuntimeError(msg)

    monkeypatch.setattr(loaded.module, "request_proxy_reconcile", fail_reconcile)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.post(
        "/requests",
        data={
            "action": "approve",
            "request_id": "7",
            "duration_seconds": "3600",
        },
        follow_redirects=False,
    )

    assert response.status_code in {302, 303}
    location = response.headers.get("Location", "")
    assert "error=" in location
    assert "ok=" not in location
    assert store.approved
    assert loaded.operation_ledger.operations == []

    page = client.get(location)
    text = page.get_data(as_text=True)
    assert "Policy changes were saved, but proxy reconciliation was not queued." in text
    assert "Action completed" not in text


def test_admin_policy_requests_approval_duration_is_bounded(
    monkeypatch,
    tmp_path,
) -> None:
    from .admin_route_test_utils import load_admin_app

    class Store:
        def __init__(self) -> None:
            self.approved: list[tuple[int, dict[str, object]]] = []

        def init_db(self) -> None:
            pass

        def approve_request(self, request_id, **kwargs):
            self.approved.append((request_id, kwargs))

    store = Store()
    loaded = load_admin_app(monkeypatch, tmp_path, policy_request_store=store)
    monkeypatch.setattr(
        loaded.module, "_best_effort_refresh_managed_policy", lambda *a, **k: None
    )

    def approve(
        duration_seconds: str, *, indefinite: bool = False
    ) -> dict[str, object]:
        data = {
            "action": "approve",
            "request_id": "1",
            "duration_seconds": duration_seconds,
        }
        if indefinite:
            data["duration_mode"] = "indefinite"
        with loaded.module.app.test_request_context(
            "/requests",
            method="POST",
            data=data,
        ):
            response = loaded.module.policy_requests()
        assert response.status_code in {302, 303}
        return store.approved[-1][1]

    assert approve("not-int")["duration_seconds"] == 24 * 60 * 60
    assert approve("0")["duration_seconds"] == 60
    assert approve("999999999")["duration_seconds"] == 30 * 24 * 60 * 60
    assert approve("0", indefinite=True)["indefinite"] is True


def test_admin_policy_requests_route_scopes_selected_proxy(
    monkeypatch,
    tmp_path,
) -> None:
    from services.policy_requests import PolicyException, PolicyRequest

    from .admin_route_test_utils import FakeRegistry, load_admin_app, login_client

    class Store:
        def __init__(self) -> None:
            self.approved: list[tuple[int, dict[str, object]]] = []
            self.revoked: list[tuple[int, dict[str, object]]] = []
            self.listed_requests: list[str | None] = []
            self.listed_exceptions: list[str | None] = []

        def init_db(self) -> None:
            pass

        def list_requests(self, *, statuses=None, limit=200, proxy_id=None):
            self.listed_requests.append(proxy_id)
            rows = [
                PolicyRequest(
                    10,
                    "edge-a",
                    "pending",
                    "webfilter",
                    "192.168.1.55",
                    "https://edge-a.example/",
                    "edge-a.example",
                    "adult",
                    "GET",
                    "ERR_ACCESS_DENIED",
                    "needed",
                    "",
                    1,
                    1,
                    0,
                    "",
                    None,
                ),
                PolicyRequest(
                    20,
                    "edge-b",
                    "pending",
                    "webfilter",
                    "192.168.1.56",
                    "https://edge-b.example/",
                    "edge-b.example",
                    "adult",
                    "GET",
                    "ERR_ACCESS_DENIED",
                    "needed",
                    "",
                    1,
                    1,
                    0,
                    "",
                    None,
                ),
            ]
            if statuses:
                rows = [row for row in rows if row.status in statuses]
            if proxy_id is not None:
                rows = [row for row in rows if row.proxy_id == proxy_id]
            return rows

        def list_exceptions(self, *, include_inactive=True, limit=200, proxy_id=None):
            self.listed_exceptions.append(proxy_id)
            rows = [
                PolicyException(
                    30,
                    "edge-a",
                    "active",
                    "webfilter",
                    "192.168.1.55",
                    "edge-a.example",
                    "adult",
                    1,
                    1,
                    "admin",
                    "ok",
                    0,
                    0,
                    "",
                    10,
                ),
                PolicyException(
                    40,
                    "edge-b",
                    "active",
                    "webfilter",
                    "192.168.1.56",
                    "edge-b.example",
                    "adult",
                    1,
                    1,
                    "admin",
                    "ok",
                    0,
                    0,
                    "",
                    20,
                ),
            ]
            if proxy_id is not None:
                rows = [row for row in rows if row.proxy_id == proxy_id]
            return rows

        def approve_request(self, request_id, **kwargs):
            self.approved.append((request_id, kwargs))
            return self.list_exceptions(proxy_id=kwargs.get("proxy_id"))[0]

        def close_request(self, request_id, **kwargs) -> None:
            pass

        def revoke_exception(self, exception_id, **kwargs) -> None:
            self.revoked.append((exception_id, kwargs))

    store = Store()
    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        registry=FakeRegistry(["edge-a", "edge-b"]),
        policy_request_store=store,
    )
    monkeypatch.setattr(
        loaded.module, "_best_effort_refresh_managed_policy", lambda *a, **k: None
    )
    client = loaded.module.app.test_client()
    login_client(client)

    page = client.get("/requests?proxy_id=edge-b")
    text = page.get_data(as_text=True)
    assert page.status_code == 200
    assert "edge-b.example" in text
    assert "edge-a.example" not in text
    assert store.listed_requests == ["edge-b", "edge-b"]
    assert store.listed_exceptions == ["edge-b"]

    token = text.split('name="csrf_token" value="', 1)[1].split('"', 1)[0]
    res = client.post(
        "/requests",
        data={
            "csrf_token": token,
            "proxy_id": "edge-b",
            "action": "approve",
            "request_id": "20",
            "duration_seconds": "3600",
        },
    )

    assert res.status_code in {302, 303}
    assert store.approved[0][0] == 20
    assert store.approved[0][1]["proxy_id"] == "edge-b"


def test_policy_request_store_rejects_invalid_scope_and_filters_active_exceptions(
    tmp_path,
) -> None:
    configure_test_mysql_env(tmp_path / "policy-request-filters")
    ensure_web_import_path()
    from services.policy_requests import (
        PolicyRequestStore,
        normalize_block_type,
        normalize_client_ip,
        normalize_domain,
    )

    store = PolicyRequestStore()
    store.init_db()
    assert normalize_client_ip("192.168.1.20, 10.0.0.9") == "192.168.1.20"
    assert normalize_client_ip("not an ip") == ""
    assert normalize_domain("https://Mixed.Example:443/path") == "mixed.example"
    assert normalize_domain("https://Bücher.Example:443/path") == (
        "xn--bcher-kva.example"
    )
    assert normalize_domain("", request_url="https://Bücher.Example/path") == (
        "xn--bcher-kva.example"
    )
    assert normalize_domain("traffic-fixture") == "traffic-fixture"
    assert normalize_domain("", request_url="http://proxy:5000/path") == "proxy"
    assert normalize_domain("12345") == ""
    assert normalize_domain("-bad.example") == ""
    assert normalize_domain("bad-.example") == ""
    assert normalize_domain("bad.-example") == ""
    assert normalize_domain("bad..example") == ""
    assert normalize_block_type("unknown<script>") == "webfilter"
    for kwargs in (
        {"client_ip": "192.168.1.44", "domain": "not a host"},
        {"client_ip": "not an ip", "domain": "blocked.example"},
    ):
        try:
            store.create_request(
                proxy_id="edge-a", request_url="https://blocked.example/", **kwargs
            )
        except ValueError:
            pass
        else:
            msg = "invalid request scope should be rejected"
            raise AssertionError(msg)
    edge_req = store.create_request(
        proxy_id="edge-a",
        client_ip="192.168.1.55",
        request_url="https://blocked.example/path",
        domain="blocked.example",
        category="adult",
    )
    remote_req = store.create_request(
        proxy_id="edge-b",
        client_ip="192.168.1.55",
        request_url="https://remote.example/path",
        domain="remote.example",
        category="adult",
    )
    adblock_req = store.create_request(
        proxy_id="edge-a",
        block_type="adblock",
        client_ip="192.168.1.55",
        request_url="https://ads.example/path",
        domain="ads.example",
    )
    active = store.approve_request(edge_req.id, reviewer="admin", indefinite=True)
    expired = store.approve_request(
        remote_req.id, reviewer="admin", duration_seconds=60
    )
    non_webfilter = store.approve_request(
        adblock_req.id, reviewer="admin", indefinite=True
    )
    assert active.expires_ts == 0
    assert non_webfilter.block_type == "adblock"
    assert [ex.id for ex in store.active_webfilter_exceptions(proxy_id="edge-a")] == [
        active.id
    ]
    assert (
        store.active_webfilter_exceptions(
            proxy_id="edge-b", at_ts=expired.expires_ts + 1
        )
        == []
    )


def test_policy_request_store_can_scope_admin_lists_and_mutations(tmp_path) -> None:
    configure_test_mysql_env(tmp_path / "policy-request-admin-scope")
    ensure_web_import_path()
    from services.policy_requests import PolicyRequestStore

    store = PolicyRequestStore()
    store.init_db()
    edge_req = store.create_request(
        proxy_id="edge-a",
        client_ip="192.168.1.55",
        request_url="https://edge.example/",
        domain="edge.example",
    )
    other_req = store.create_request(
        proxy_id="edge-b",
        client_ip="192.168.1.56",
        request_url="https://other.example/",
        domain="other.example",
    )

    assert [req.id for req in store.list_requests(proxy_id="edge-a")] == [edge_req.id]
    assert [req.id for req in store.list_requests(proxy_id="edge-b")] == [other_req.id]
    assert store.list_exceptions(proxy_id="edge-a") == []

    try:
        store.approve_request(other_req.id, reviewer="admin", proxy_id="edge-a")
    except ValueError as exc:
        assert "selected proxy" in str(exc)
    else:
        msg = "cross-proxy request approval should be rejected"
        raise AssertionError(msg)

    exception = store.approve_request(
        edge_req.id,
        reviewer="admin",
        indefinite=True,
        proxy_id="edge-a",
    )
    assert [ex.id for ex in store.list_exceptions(proxy_id="edge-a")] == [exception.id]
    assert store.list_exceptions(proxy_id="edge-b") == []

    try:
        store.revoke_exception(exception.id, revoked_by="admin", proxy_id="edge-b")
    except ValueError as exc:
        assert "selected proxy" in str(exc)
    else:
        msg = "cross-proxy exception revocation should be rejected"
        raise AssertionError(msg)
    assert store.active_webfilter_exceptions(proxy_id="edge-a") == [exception]
    store.revoke_exception(exception.id, revoked_by="admin", proxy_id="edge-a")
    assert store.active_webfilter_exceptions(proxy_id="edge-a") == []


def test_policy_request_store_state_transitions_are_one_way(tmp_path) -> None:
    configure_test_mysql_env(tmp_path / "policy-request-transitions")
    ensure_web_import_path()
    from services.policy_requests import PolicyRequestStore

    store = PolicyRequestStore()
    store.init_db()
    rejected = store.create_request(
        proxy_id="edge-a",
        client_ip="192.168.1.55",
        request_url="https://reject.example/",
        domain="reject.example",
    )
    store.close_request(
        rejected.id, reviewer="admin", status="rejected", admin_note="no"
    )
    assert store.list_requests(statuses=["rejected"])[0].id == rejected.id
    try:
        store.approve_request(rejected.id, reviewer="admin", indefinite=True)
    except ValueError as exc:
        assert "Only pending" in str(exc)
    else:
        msg = "rejected request should not be approvable"
        raise AssertionError(msg)
    approved = store.create_request(
        proxy_id="edge-a",
        client_ip="192.168.1.56",
        request_url="https://approve.example/",
        domain="approve.example",
    )
    store.approve_request(approved.id, reviewer="admin", indefinite=True)
    store.close_request(
        approved.id, reviewer="admin", status="closed", admin_note="late close"
    )
    assert store.list_requests(statuses=["approved"])[0].id == approved.id


def test_proxy_policy_request_route_is_public_listener_only_and_ignores_spoofed_client_ip(
    monkeypatch,
) -> None:
    ensure_proxy_runtime_import_path()
    monkeypatch.setenv("DISABLE_PROXY_AGENT", "1")
    monkeypatch.setenv("PAC_HTTP_PORT", "80")
    import proxy.app as proxy_app

    proxy_app = importlib.reload(proxy_app)
    recorded = {}

    class Store:
        def create_request(self, **kwargs):
            recorded.update(kwargs)
            from services.policy_requests import PolicyRequest

            return PolicyRequest(
                456,
                kwargs.get("proxy_id") or "default",
                "pending",
                "webfilter",
                kwargs["client_ip"],
                kwargs["request_url"],
                kwargs["domain"],
                "",
                "",
                "",
                "",
                "",
                1,
                1,
                0,
                "",
                None,
            )

    monkeypatch.setattr(proxy_app, "get_policy_request_store", Store)
    client = proxy_app.app.test_client()
    management = client.post(
        "/policy-request",
        base_url="http://localhost:5000",
        data={"request_url": "https://bad.example/", "domain": "bad.example"},
    )
    assert management.status_code == 404
    public = client.post(
        "/policy-request",
        base_url="http://localhost:80",
        environ_base={"REMOTE_ADDR": "10.9.8.7"},
        data={
            "request_url": "https://bad.example/",
            "client_ip": "1.2.3.4",
            "domain": "bad.example",
        },
    )
    assert public.status_code == 200
    assert recorded["client_ip"] == "10.9.8.7"


def test_proxy_policy_request_route_uses_trusted_forwarded_client_ip(
    monkeypatch,
) -> None:
    ensure_proxy_runtime_import_path()
    monkeypatch.setenv("DISABLE_PROXY_AGENT", "1")
    monkeypatch.setenv("PAC_HTTP_PORT", "80")
    monkeypatch.setenv("PAC_TRUSTED_PROXY_CIDRS", "192.0.2.0/24")
    import proxy.app as proxy_app

    proxy_app = importlib.reload(proxy_app)
    recorded = {}

    class Store:
        def create_request(self, **kwargs):
            recorded.update(kwargs)
            from services.policy_requests import PolicyRequest

            return PolicyRequest(
                789,
                kwargs.get("proxy_id") or "default",
                "pending",
                "webfilter",
                kwargs["client_ip"],
                kwargs["request_url"],
                kwargs["domain"],
                "",
                "",
                "",
                "",
                "",
                1,
                1,
                0,
                "",
                None,
            )

    monkeypatch.setattr(proxy_app, "get_policy_request_store", Store)
    res = proxy_app.app.test_client().post(
        "/policy-request",
        base_url="http://localhost:80",
        environ_base={"REMOTE_ADDR": "192.0.2.10"},
        headers={"X-Forwarded-For": "10.11.12.13, 192.0.2.10"},
        data={"request_url": "https://bad.example/", "domain": "bad.example"},
    )
    assert res.status_code == 200
    assert recorded["client_ip"] == "10.11.12.13"
