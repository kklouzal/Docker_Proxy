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


class _PolicyApproveResult:
    def __init__(self, row=None, *, lastrowid: int = 0, rowcount: int = 1):
        self._rows = row if isinstance(row, list) else ([] if row is None else [row])
        self.lastrowid = lastrowid
        self.rowcount = rowcount

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return list(self._rows)


class _PolicyApproveConn:
    def __init__(self, *, claim_rowcount: int = 1, block_type: str = "webfilter"):
        self.calls: list[tuple[str, tuple[object, ...]]] = []
        self.inserted_expires_ts: int | None = None
        self.claim_rowcount = claim_rowcount
        self.block_type = block_type

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def execute(self, sql, params=()):
        text = " ".join(str(sql).split())
        params_t = tuple(params or ())
        self.calls.append((text, params_t))
        if "FROM policy_requests WHERE id=%s" in text:
            return _PolicyApproveResult(
                {
                    "id": 7,
                    "proxy_id": "edge-a",
                    "status": "pending",
                    "block_type": self.block_type,
                    "client_ip": "192.168.1.55",
                    "request_url": "https://example.com/path",
                    "domain": "example.com",
                    "category": "adult",
                    "method": "GET",
                    "squid_error": "ERR_ACCESS_DENIED",
                    "user_note": "please allow",
                    "admin_note": "",
                    "created_ts": 900,
                    "updated_ts": 900,
                    "reviewed_ts": 0,
                    "reviewer": "",
                    "exception_id": None,
                },
            )
        if (
            "UPDATE policy_requests SET status='approved'" in text
            and "AND status='pending'" in text
        ):
            return _PolicyApproveResult(rowcount=self.claim_rowcount)
        if "INSERT INTO policy_exceptions" in text:
            self.inserted_expires_ts = int(params_t[10])
            return _PolicyApproveResult(lastrowid=11)
        if "FROM policy_exceptions WHERE id=%s" in text:
            return _PolicyApproveResult(
                {
                    "id": 11,
                    "proxy_id": "edge-a",
                    "status": "active",
                    "block_type": self.block_type,
                    "client_ip": "192.168.1.55",
                    "domain": "example.com",
                    "category": "adult",
                    "method": "GET",
                    "created_ts": 1000,
                    "updated_ts": 1000,
                    "created_by": "admin",
                    "admin_note": "ok",
                    "expires_ts": self.inserted_expires_ts,
                    "revoked_ts": 0,
                    "revoked_by": "",
                    "source_request_id": 7,
                },
            )
        return _PolicyApproveResult(rowcount=1)


def test_policy_exception_exposes_effective_expired_status(monkeypatch) -> None:
    ensure_web_import_path()
    from services import policy_requests

    module = importlib.reload(policy_requests)
    monkeypatch.setattr(module, "now_ts", lambda: 2000)

    expired = module.PolicyException(
        9,
        "default",
        "active",
        "webfilter",
        "192.168.1.55",
        "expired.example",
        "adult",
        1000,
        1000,
        "admin",
        "expired",
        1999,
        0,
        "",
        1,
    )
    active = module.PolicyException(
        10,
        "default",
        "active",
        "webfilter",
        "192.168.1.56",
        "active.example",
        "adult",
        1000,
        1000,
        "admin",
        "active",
        2001,
        0,
        "",
        2,
    )

    assert expired.status == "active"
    assert expired.effective_status == "expired"
    assert expired.can_revoke is False
    assert active.effective_status == "active"
    assert active.can_revoke is True


def test_policy_request_store_approval_omitted_duration_defaults_not_indefinite(
    monkeypatch,
) -> None:
    ensure_web_import_path()
    from services import policy_requests

    module = importlib.reload(policy_requests)
    conn = _PolicyApproveConn()
    store = module.PolicyRequestStore()
    monkeypatch.setattr(store, "init_db", lambda: None)
    monkeypatch.setattr(store, "_connect", lambda: conn)
    monkeypatch.setattr(module, "now_ts", lambda: 1000)

    exception = store.approve_request(7, reviewer="admin", admin_note="ok")

    assert exception.expires_ts == (
        1000 + module.POLICY_EXCEPTION_DEFAULT_DURATION_SECONDS
    )


def test_policy_request_store_approval_indefinite_flag_keeps_no_expiry(
    monkeypatch,
) -> None:
    ensure_web_import_path()
    from services import policy_requests

    module = importlib.reload(policy_requests)
    conn = _PolicyApproveConn()
    store = module.PolicyRequestStore()
    monkeypatch.setattr(store, "init_db", lambda: None)
    monkeypatch.setattr(store, "_connect", lambda: conn)
    monkeypatch.setattr(module, "now_ts", lambda: 1000)

    exception = store.approve_request(7, reviewer="admin", indefinite=True)

    assert exception.expires_ts == 0


def test_policy_request_store_approval_duplicate_lookup_and_insert_include_method(
    monkeypatch,
) -> None:
    ensure_web_import_path()
    from services import policy_requests

    module = importlib.reload(policy_requests)
    conn = _PolicyApproveConn()
    store = module.PolicyRequestStore()
    monkeypatch.setattr(store, "init_db", lambda: None)
    monkeypatch.setattr(store, "_connect", lambda: conn)
    monkeypatch.setattr(module, "now_ts", lambda: 1000)

    exception = store.approve_request(7, reviewer="admin", admin_note="ok")

    assert exception.method == "GET"
    duplicate_lookup = [
        (sql, params)
        for sql, params in conn.calls
        if "FROM policy_exceptions" in sql and "method=%s" in sql
    ]
    assert duplicate_lookup
    assert duplicate_lookup[0][1][5] == "GET"
    insert_calls = [
        (sql, params) for sql, params in conn.calls if "INSERT INTO policy_exceptions" in sql
    ]
    assert insert_calls
    assert "category,method,created_ts" in insert_calls[0][0]
    assert insert_calls[0][1][5] == "GET"


def test_policy_request_store_approval_stale_pending_claim_does_not_insert(
    monkeypatch,
) -> None:
    ensure_web_import_path()
    from services import policy_requests

    module = importlib.reload(policy_requests)
    conn = _PolicyApproveConn(claim_rowcount=0)
    store = module.PolicyRequestStore()
    monkeypatch.setattr(store, "init_db", lambda: None)
    monkeypatch.setattr(store, "_connect", lambda: conn)
    monkeypatch.setattr(module, "now_ts", lambda: 1000)

    try:
        store.approve_request(7, reviewer="admin", admin_note="late")
    except ValueError as exc:
        assert "Only pending" in str(exc)
    else:
        msg = "stale approval should fail before creating an exception"
        raise AssertionError(msg)

    executed_sql = [sql for sql, _params in conn.calls]
    assert any(
        "UPDATE policy_requests SET status='approved'" in sql
        and "AND status='pending'" in sql
        for sql in executed_sql
    )
    assert not any("INSERT INTO policy_exceptions" in sql for sql in executed_sql)
    assert not any("UPDATE policy_exceptions" in sql for sql in executed_sql)


def test_policy_request_store_rejects_unsupported_approval_before_exception_write(
    monkeypatch,
) -> None:
    ensure_web_import_path()
    from services import policy_requests

    module = importlib.reload(policy_requests)
    conn = _PolicyApproveConn(block_type="adblock")
    store = module.PolicyRequestStore()
    monkeypatch.setattr(store, "init_db", lambda: None)
    monkeypatch.setattr(store, "_connect", lambda: conn)
    monkeypatch.setattr(module, "now_ts", lambda: 1000)

    try:
        store.approve_request(7, reviewer="admin", admin_note="ok")
    except ValueError as exc:
        assert "Only webfilter requests can be approved" in str(exc)
    else:
        msg = "unsupported request types should not create policy exceptions"
        raise AssertionError(msg)

    executed_sql = [sql for sql, _params in conn.calls]
    assert any("FROM policy_requests WHERE id=%s" in sql for sql in executed_sql)
    assert not any(
        "UPDATE policy_requests SET status='approved'" in sql for sql in executed_sql
    )
    assert not any("INSERT INTO policy_exceptions" in sql for sql in executed_sql)
    assert not any("UPDATE policy_exceptions" in sql for sql in executed_sql)


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


def test_policy_request_store_reuses_unexpired_duplicate_approval_scope(
    monkeypatch, tmp_path
) -> None:
    configure_test_mysql_env(tmp_path / "policy-request-dedupe")
    ensure_web_import_path()
    from services import policy_requests

    module = importlib.reload(policy_requests)
    now = 1000
    monkeypatch.setattr(module, "now_ts", lambda: now)
    store = module.PolicyRequestStore()
    store.init_db()

    def create_duplicate_request():
        return store.create_request(
            proxy_id="edge-a",
            client_ip="192.168.1.55",
            request_url="https://duplicate.example/path",
            domain="duplicate.example",
            category="adult",
        )

    first_req = create_duplicate_request()
    first = store.approve_request(
        first_req.id,
        reviewer="admin",
        admin_note="first approval",
        duration_seconds=600,
    )

    now = 1100
    duplicate_req = create_duplicate_request()
    duplicate = store.approve_request(
        duplicate_req.id,
        reviewer="operator",
        admin_note="extend existing approval",
        duration_seconds=3600,
    )

    assert duplicate.id == first.id
    assert duplicate.source_request_id == duplicate_req.id
    assert duplicate.admin_note == "extend existing approval"
    assert duplicate.expires_ts == 4700
    assert [ex.id for ex in store.active_webfilter_exceptions(proxy_id="edge-a")] == [
        first.id
    ]
    approved_requests = store.list_requests(statuses=["approved"], proxy_id="edge-a")
    assert {req.id: req.exception_id for req in approved_requests} == {
        first_req.id: first.id,
        duplicate_req.id: first.id,
    }

    now = 5000
    expired_equivalent_req = create_duplicate_request()
    after_expiry = store.approve_request(
        expired_equivalent_req.id,
        reviewer="admin",
        indefinite=True,
    )
    assert after_expiry.id != first.id
    assert [ex.id for ex in store.active_webfilter_exceptions(proxy_id="edge-a")] == [
        after_expiry.id
    ]

    store.revoke_exception(after_expiry.id, revoked_by="admin")
    revoked_equivalent_req = create_duplicate_request()
    after_revoke = store.approve_request(
        revoked_equivalent_req.id,
        reviewer="admin",
        indefinite=True,
    )
    assert after_revoke.id not in {first.id, after_expiry.id}
    assert [ex.id for ex in store.active_webfilter_exceptions(proxy_id="edge-a")] == [
        after_revoke.id
    ]


def test_policy_request_store_keeps_method_scoped_approvals_distinct(
    monkeypatch, tmp_path
) -> None:
    configure_test_mysql_env(tmp_path / "policy-request-method-scope")
    ensure_web_import_path()
    from services import policy_requests

    module = importlib.reload(policy_requests)
    now = 1000
    monkeypatch.setattr(module, "now_ts", lambda: now)
    store = module.PolicyRequestStore()
    store.init_db()

    def create_request(method: str):
        return store.create_request(
            proxy_id="edge-a",
            client_ip="192.168.1.55",
            request_url="https://method.example/path",
            domain="method.example",
            category="adult",
            method=method,
        )

    get_req = create_request("get")
    get_exception = store.approve_request(
        get_req.id,
        reviewer="admin",
        duration_seconds=600,
    )
    assert get_exception.method == "GET"

    now = 1100
    post_req = create_request("post")
    post_exception = store.approve_request(
        post_req.id,
        reviewer="admin",
        duration_seconds=600,
    )
    assert post_exception.method == "POST"
    assert post_exception.id != get_exception.id

    now = 1200
    duplicate_get_req = create_request("GET")
    duplicate_get = store.approve_request(
        duplicate_get_req.id,
        reviewer="operator",
        duration_seconds=3600,
    )
    assert duplicate_get.id == get_exception.id

    active = store.active_webfilter_exceptions(proxy_id="edge-a")
    assert {(ex.domain, ex.client_ip, ex.category, ex.method) for ex in active} == {
        ("method.example", "192.168.1.55", "adult", "GET"),
        ("method.example", "192.168.1.55", "adult", "POST"),
    }
    approved_requests = store.list_requests(statuses=["approved"], proxy_id="edge-a")
    assert {req.id: req.exception_id for req in approved_requests} == {
        get_req.id: get_exception.id,
        post_req.id: post_exception.id,
        duplicate_get_req.id: get_exception.id,
    }


def test_policy_request_store_keeps_legacy_empty_method_exception_broad(
    tmp_path,
) -> None:
    configure_test_mysql_env(tmp_path / "policy-request-broad-method")
    ensure_web_import_path()
    from services.policy_requests import PolicyRequestStore

    store = PolicyRequestStore()
    store.init_db()
    broad_req = store.create_request(
        proxy_id="edge-a",
        client_ip="192.168.1.55",
        request_url="https://broad.example/path",
        domain="broad.example",
        category="adult",
        method="",
    )
    method_req = store.create_request(
        proxy_id="edge-a",
        client_ip="192.168.1.55",
        request_url="https://broad.example/path",
        domain="broad.example",
        category="adult",
        method="CONNECT",
    )

    broad_exception = store.approve_request(
        broad_req.id,
        reviewer="admin",
        indefinite=True,
    )
    method_exception = store.approve_request(
        method_req.id,
        reviewer="admin",
        indefinite=True,
    )

    assert broad_exception.method == ""
    assert method_exception.method == "CONNECT"
    assert method_exception.id != broad_exception.id
    assert [(ex.id, ex.method) for ex in store.active_webfilter_exceptions(proxy_id="edge-a")] == [
        (broad_exception.id, ""),
        (method_exception.id, "CONNECT"),
    ]


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
    omitted = approve("omitted.example", None)

    indefinite_req = store.create_request(
        proxy_id="edge-a",
        client_ip="192.168.1.55",
        request_url="https://indefinite.example/",
        domain="indefinite.example",
    )
    indefinite = store.approve_request(
        indefinite_req.id,
        reviewer="admin",
        duration_seconds=None,
        indefinite=True,
    )

    assert minimum.expires_ts - minimum.created_ts == (
        POLICY_EXCEPTION_MIN_DURATION_SECONDS
    )
    assert default.expires_ts - default.created_ts == (
        POLICY_EXCEPTION_DEFAULT_DURATION_SECONDS
    )
    assert maximum.expires_ts - maximum.created_ts == (
        POLICY_EXCEPTION_MAX_DURATION_SECONDS
    )
    assert omitted.expires_ts - omitted.created_ts == (
        POLICY_EXCEPTION_DEFAULT_DURATION_SECONDS
    )
    assert indefinite.expires_ts == 0


def test_webfilter_materialization_scopes_exceptions_to_enforced_categories(
    monkeypatch, tmp_path
) -> None:
    ensure_web_import_path()
    import services.webfilter_core as core

    core = importlib.reload(core)
    from services.policy_requests import PolicyException
    from services.proxy_context import reset_proxy_id, set_proxy_id

    class Store(core.WebFilterStoreBase):
        def get_settings(self):
            return core.WebFilterSettings(
                True,
                "",
                ["adult"],
                [],
                0,
                0,
                "",
                0,
                safe_browsing_enabled=True,
                safe_browsing_api_key="test-key",
            )

        def _resolve_category_aliases(self, categories):
            return categories

    class SafeBrowsingOnlyStore(Store):
        def get_settings(self):
            return core.WebFilterSettings(
                True,
                "",
                [],
                [],
                0,
                0,
                "",
                0,
                safe_browsing_enabled=True,
                safe_browsing_api_key="test-key",
            )

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
                    method="GET",
                ),
                PolicyException(
                    8,
                    proxy_id or "edge-a",
                    "active",
                    "webfilter",
                    "192.168.1.56",
                    "bad domain.example",
                    "adult",
                    1,
                    1,
                    "admin",
                    "",
                    0,
                    0,
                    "",
                    2,
                ),
                PolicyException(
                    9,
                    proxy_id or "edge-a",
                    "active",
                    "webfilter",
                    "192.168.1.57",
                    "stale.example",
                    "malware",
                    1,
                    1,
                    "admin",
                    "",
                    0,
                    0,
                    "",
                    3,
                    method="POST",
                ),
                PolicyException(
                    10,
                    proxy_id or "edge-a",
                    "active",
                    "webfilter",
                    "192.168.1.58",
                    "legacy.example",
                    "",
                    1,
                    1,
                    "admin",
                    "",
                    0,
                    0,
                    "",
                    4,
                ),
            ]

    monkeypatch.setattr(core, "get_policy_request_store", RequestStore)
    token = set_proxy_id("edge-a")
    try:
        text = Store().render_materialized_state().include_text
        safe_browsing_only_text = (
            SafeBrowsingOnlyStore().render_materialized_state().include_text
        )
    finally:
        reset_proxy_id(token)
    assert "acl webfilter_exception_src_7 src 192.168.1.55" in text
    assert "acl webfilter_exception_dst_7 dstdomain bad.example .bad.example" in text
    assert "acl webfilter_exception_method_7 method GET" in text
    assert "http_access allow webfilter_exception_src_7 webfilter_exception_dst_7 webfilter_exception_method_7" in text
    assert "webfilter_exception_src_8" not in text
    assert "bad domain.example" not in text
    assert "webfilter_exception_src_9" not in text
    assert "stale.example" not in text
    assert "webfilter_exception_src_10 src 192.168.1.58" in text
    assert "webfilter_exception_dst_10 dstdomain legacy.example .legacy.example" in text
    assert text.index("http_access allow webfilter_exception_src_7") < text.index(
        "http_access deny webfilter_block_adult"
    )
    assert "http_access deny webfilter_block_google_safe_browsing" in text

    assert "webfilter_exception_src_7" not in safe_browsing_only_text
    assert "webfilter_exception_src_9" not in safe_browsing_only_text
    assert "acl webfilter_exception_src_10 src 192.168.1.58" in safe_browsing_only_text
    assert safe_browsing_only_text.index(
        "http_access allow webfilter_exception_src_10"
    ) < safe_browsing_only_text.index(
        "http_access deny webfilter_block_google_safe_browsing"
    )


def test_error_page_only_webfilter_has_exception_request_guidance() -> None:
    root = Path(__file__).resolve().parents[2]
    blocked = (root / "squid/error_pages/en/ERR_WEBFILTER_BLOCKED").read_text(
        encoding="utf-8"
    )
    denied = (root / "squid/error_pages/en/ERR_ACCESS_DENIED").read_text(
        encoding="utf-8"
    )
    assert "Request an exception" in blocked
    assert "open the Docker Proxy admin UI and create a policy request" in blocked
    assert "policy-request" not in blocked
    assert "<form" not in blocked
    assert "<input" not in blocked
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


def test_proxy_public_policy_request_rejects_oversized_form_before_store(
    monkeypatch,
) -> None:
    ensure_proxy_runtime_import_path()
    monkeypatch.setenv("DISABLE_PROXY_AGENT", "1")
    monkeypatch.setenv("PAC_HTTP_PORT", "80")
    monkeypatch.setenv("POLICY_REQUEST_MAX_CONTENT_LENGTH", "128")
    import proxy.app as proxy_app

    proxy_app = importlib.reload(proxy_app)
    store_requested = False

    def get_store():
        nonlocal store_requested
        store_requested = True

        class Store:
            def create_request(self, **kwargs):
                return None

        return Store()

    monkeypatch.setattr(proxy_app, "get_policy_request_store", get_store)
    res = proxy_app.app.test_client().post(
        "/policy-request",
        base_url="http://localhost:80",
        data={
            "request_url": "https://bad.example/",
            "domain": "bad.example",
            "user_note": "x" * 300,
        },
    )

    assert res.status_code == 413
    assert "Policy request submissions are limited to 128 bytes" in res.get_data(
        as_text=True,
    )
    assert store_requested is False


def test_proxy_public_policy_request_rejects_parser_enforced_oversize(
    monkeypatch,
) -> None:
    ensure_proxy_runtime_import_path()
    monkeypatch.setenv("DISABLE_PROXY_AGENT", "1")
    monkeypatch.setenv("PAC_HTTP_PORT", "80")
    monkeypatch.setenv("POLICY_REQUEST_MAX_CONTENT_LENGTH", "128")
    from werkzeug.exceptions import RequestEntityTooLarge

    import proxy.app as proxy_app

    proxy_app = importlib.reload(proxy_app)
    store_requested = False

    def raise_too_large(_self):
        raise RequestEntityTooLarge

    def get_store():
        nonlocal store_requested
        store_requested = True

        class Store:
            def create_request(self, **kwargs):
                return None

        return Store()

    monkeypatch.setattr(proxy_app.app.request_class, "form", property(raise_too_large))
    monkeypatch.setattr(proxy_app, "get_policy_request_store", get_store)
    res = proxy_app.app.test_client().post(
        "/policy-request",
        base_url="http://localhost:80",
        data=b"request_url=https%3A%2F%2Fbad.example%2F&domain=bad.example",
        content_type="application/x-www-form-urlencoded",
        environ_overrides={"CONTENT_LENGTH": ""},
    )

    assert res.status_code == 413
    assert "Policy request submissions are limited to 128 bytes" in res.get_data(
        as_text=True,
    )
    assert store_requested is False


def test_proxy_public_policy_request_rejects_malformed_form_parse(
    monkeypatch,
) -> None:
    ensure_proxy_runtime_import_path()
    monkeypatch.setenv("DISABLE_PROXY_AGENT", "1")
    monkeypatch.setenv("PAC_HTTP_PORT", "80")
    from werkzeug.exceptions import BadRequest

    import proxy.app as proxy_app

    proxy_app = importlib.reload(proxy_app)
    store_requested = False

    def raise_bad_request(_self):
        raise BadRequest

    def get_store():
        nonlocal store_requested
        store_requested = True

        class Store:
            def create_request(self, **kwargs):
                return None

        return Store()

    monkeypatch.setattr(proxy_app.app.request_class, "form", property(raise_bad_request))
    monkeypatch.setattr(proxy_app, "get_policy_request_store", get_store)
    res = proxy_app.app.test_client().post(
        "/policy-request",
        base_url="http://localhost:80",
        data=b"request_url=%",
        content_type="application/x-www-form-urlencoded",
        environ_overrides={"CONTENT_LENGTH": ""},
    )

    assert res.status_code == 400
    body = res.get_data(as_text=True)
    assert "The policy request form could not be parsed" in body
    assert "Bad Request" not in body
    assert store_requested is False


def test_proxy_public_policy_request_invalid_size_limit_env_falls_back(
    monkeypatch,
) -> None:
    ensure_proxy_runtime_import_path()
    monkeypatch.setenv("DISABLE_PROXY_AGENT", "1")
    monkeypatch.setenv("PAC_HTTP_PORT", "80")
    monkeypatch.setenv("POLICY_REQUEST_MAX_CONTENT_LENGTH", "not-a-number")
    import proxy.app as proxy_app

    proxy_app = importlib.reload(proxy_app)
    recorded = {}

    class Store:
        def create_request(self, **kwargs):
            recorded.update(kwargs)
            from services.policy_requests import PolicyRequest

            return PolicyRequest(
                124,
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
        data={
            "request_url": "https://bad.example/",
            "domain": "bad.example",
            "user_note": "needed",
        },
    )

    assert res.status_code == 200
    assert recorded["domain"] == "bad.example"


def test_proxy_public_policy_request_get_does_not_fall_through_to_pac(
    monkeypatch,
) -> None:
    ensure_proxy_runtime_import_path()
    monkeypatch.setenv("DISABLE_PROXY_AGENT", "1")
    monkeypatch.setenv("PAC_HTTP_PORT", "80")
    import proxy.app as proxy_app

    proxy_app = importlib.reload(proxy_app)

    res = proxy_app.app.test_client().get(
        "/policy-request",
        base_url="http://localhost:80",
    )

    assert res.status_code == 405
    assert "FindProxyForURL" not in res.get_data(as_text=True)


def test_admin_policy_requests_route_and_link_smoke(monkeypatch, tmp_path) -> None:
    from services.policy_requests import PolicyException, PolicyRequest

    from .admin_route_test_utils import load_admin_app, login_client

    class Store:
        def __init__(self) -> None:
            self.approved = []
            self.revoked = []

        def init_db(self) -> None:
            pass

        def list_requests(
            self,
            *,
            statuses=None,
            limit=200,
            proxy_id=None,
            order_by="created",
        ):
            assert order_by in {"created", "updated"}
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
                ),
                PolicyException(
                    3,
                    "default",
                    "active",
                    "webfilter",
                    "192.168.1.56",
                    "expired.example",
                    "",
                    1,
                    1,
                    "admin",
                    "expired",
                    1,
                    0,
                    "",
                    2,
                ),
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
    assert "expired.example" in text
    assert "<td>expired</td>" in text
    assert 'aria-label="Revoke exception 2 for ok.example"' in text
    assert 'aria-label="Revoke exception 3 for expired.example"' not in text
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
        "for policy aaaaaaaaaaaa." in approve_text
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


def test_admin_policy_requests_unsupported_approval_reports_error_without_queue(
    monkeypatch,
    tmp_path,
) -> None:
    from services.policy_requests import PolicyRequest

    from .admin_route_test_utils import load_admin_app, login_client

    class Store:
        def __init__(self) -> None:
            self.approved: list[tuple[int, dict[str, object]]] = []
            self.closed: list[tuple[int, dict[str, object]]] = []

        def init_db(self) -> None:
            pass

        def list_requests(
            self,
            *,
            statuses=None,
            limit=200,
            proxy_id=None,
            order_by="created",
        ):
            assert order_by in {"created", "updated"}
            rows = [
                PolicyRequest(
                    7,
                    "default",
                    "pending",
                    "adblock",
                    "192.168.1.55",
                    "https://ads.example/",
                    "ads.example",
                    "",
                    "GET",
                    "ERR_ACCESS_DENIED",
                    "review me",
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
            return []

        def approve_request(self, request_id, **kwargs):
            self.approved.append((request_id, kwargs))
            msg = (
                "Only webfilter requests can be approved into enforced policy "
                "exceptions. Use reject or close for this request type."
            )
            raise ValueError(msg)

        def close_request(self, request_id, **kwargs) -> None:
            self.closed.append((request_id, kwargs))

    store = Store()
    monkeypatch.setenv("DISABLE_CSRF", "1")
    loaded = load_admin_app(monkeypatch, tmp_path, policy_request_store=store)
    queued = False

    def unexpected_refresh(*_args, **_kwargs):
        nonlocal queued
        queued = True
        return True, "queued"

    monkeypatch.setattr(
        loaded.module, "_best_effort_refresh_managed_policy", unexpected_refresh
    )
    client = loaded.module.app.test_client()
    login_client(client)

    page = client.get("/requests")
    text = page.get_data(as_text=True)
    assert page.status_code == 200
    assert "Only webfilter approvals create enforced" in text
    assert "Approval is unavailable for adblock requests" in text
    assert 'name="action" value="approve"' not in text
    assert 'name="action" value="reject"' in text

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
    params = urllib.parse.parse_qs(
        urllib.parse.urlsplit(response.headers.get("Location", "")).query,
    )
    assert params.get("error") == [
        "Only webfilter requests can be approved into enforced policy exceptions. Use reject or close for this request type."
    ]
    assert "ok" not in params
    assert len(store.approved) == 1
    assert queued is False
    assert loaded.operation_ledger.operations == []


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
            self.listed_requests: list[tuple[str | None, tuple[str, ...], str]] = []
            self.listed_exceptions: list[str | None] = []

        def init_db(self) -> None:
            pass

        def list_requests(
            self,
            *,
            statuses=None,
            limit=200,
            proxy_id=None,
            order_by="created",
        ):
            assert order_by in {"created", "updated"}
            self.listed_requests.append((proxy_id, tuple(statuses or ()), order_by))
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
    assert store.listed_requests == [
        ("edge-b", ("pending",), "created"),
        ("edge-b", (), "updated"),
    ]
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


def test_admin_policy_requests_invalid_mutation_ids_report_controlled_errors(
    monkeypatch,
    tmp_path,
) -> None:
    from .admin_route_test_utils import load_admin_app, login_client

    class Store:
        def __init__(self) -> None:
            self.approved: list[tuple[int, dict[str, object]]] = []
            self.closed: list[tuple[int, dict[str, object]]] = []
            self.revoked: list[tuple[int, dict[str, object]]] = []

        def init_db(self) -> None:
            pass

        def approve_request(self, request_id, **kwargs):
            self.approved.append((request_id, kwargs))

        def close_request(self, request_id, **kwargs) -> None:
            self.closed.append((request_id, kwargs))

        def revoke_exception(self, exception_id, **kwargs) -> None:
            self.revoked.append((exception_id, kwargs))

    store = Store()
    monkeypatch.setenv("DISABLE_CSRF", "1")
    loaded = load_admin_app(monkeypatch, tmp_path, policy_request_store=store)
    client = loaded.module.app.test_client()
    login_client(client)

    cases = (
        (
            {"action": "reject"},
            "Invalid policy request id.",
        ),
        (
            {
                "action": "approve",
                "request_id": "abc",
                "duration_seconds": "3600",
            },
            "Invalid policy request id.",
        ),
        (
            {"action": "close", "request_id": "0"},
            "Invalid policy request id.",
        ),
        (
            {"action": "revoke"},
            "Invalid policy exception id.",
        ),
        (
            {"action": "revoke", "exception_id": "abc"},
            "Invalid policy exception id.",
        ),
        (
            {"action": "revoke", "exception_id": "0"},
            "Invalid policy exception id.",
        ),
    )

    for data, expected_error in cases:
        response = client.post("/requests", data=data, follow_redirects=False)

        assert response.status_code in {302, 303}
        params = urllib.parse.parse_qs(
            urllib.parse.urlsplit(response.headers.get("Location", "")).query,
        )
        assert params.get("error") == [expected_error]
        assert "invalid literal for int" not in response.headers.get("Location", "")

    assert store.approved == []
    assert store.closed == []
    assert store.revoked == []


def test_policy_request_domain_normalization_rejects_raw_userinfo_or_email_like_hosts() -> (
    None
):
    ensure_web_import_path()
    from services.policy_requests import normalize_domain

    assert normalize_domain("user@example.com") == ""
    assert normalize_domain("operator:secret@example.com") == ""
    assert normalize_domain("example.com@evil.test") == ""
    assert normalize_domain("https://user:pass@Example.COM:443/path") == "example.com"


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
    try:
        store.approve_request(adblock_req.id, reviewer="admin", indefinite=True)
    except ValueError as exc:
        assert "Only webfilter requests can be approved" in str(exc)
    else:
        msg = "adblock request should remain review-only and not create an exception"
        raise AssertionError(msg)
    assert active.expires_ts == 0
    assert [
        req.id for req in store.list_requests(statuses=["pending"], proxy_id="edge-a")
    ] == [adblock_req.id]
    assert [ex.id for ex in store.active_webfilter_exceptions(proxy_id="edge-a")] == [
        active.id
    ]
    assert [ex.block_type for ex in store.list_exceptions(proxy_id="edge-a")] == [
        "webfilter"
    ]
    assert (
        store.active_webfilter_exceptions(
            proxy_id="edge-b", at_ts=expired.expires_ts + 1
        )
        == []
    )


def test_policy_request_store_can_order_recent_admin_list_by_updated_ts(
    monkeypatch, tmp_path
) -> None:
    configure_test_mysql_env(tmp_path / "policy-request-updated-order")
    ensure_web_import_path()
    from services import policy_requests

    module = importlib.reload(policy_requests)
    now = 1000
    monkeypatch.setattr(module, "now_ts", lambda: now)
    store = module.PolicyRequestStore()
    store.init_db()

    older = store.create_request(
        proxy_id="edge-a",
        client_ip="192.168.1.55",
        request_url="https://older.example/",
        domain="older.example",
    )
    now = 2000
    newer = store.create_request(
        proxy_id="edge-a",
        client_ip="192.168.1.56",
        request_url="https://newer.example/",
        domain="newer.example",
    )
    now = 3000
    store.close_request(
        older.id,
        reviewer="admin",
        status="rejected",
        admin_note="reviewed after newer request was created",
        proxy_id="edge-a",
    )

    assert [req.id for req in store.list_requests(limit=2, proxy_id="edge-a")] == [
        newer.id,
        older.id,
    ]
    assert [
        req.id
        for req in store.list_requests(
            limit=2,
            proxy_id="edge-a",
            order_by="updated",
        )
    ] == [older.id, newer.id]
    assert [
        req.id
        for req in store.list_requests(
            statuses=["pending"],
            limit=2,
            proxy_id="edge-a",
            order_by="updated",
        )
    ] == [newer.id]


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


def test_policy_request_store_unscoped_mutations_reject_missing_or_stale_rows(
    tmp_path,
) -> None:
    configure_test_mysql_env(tmp_path / "policy-request-unscoped-stale")
    ensure_web_import_path()
    from services.policy_requests import PolicyRequestStore

    store = PolicyRequestStore()
    store.init_db()

    def assert_value_error(callable_obj, expected: str) -> None:
        try:
            callable_obj()
        except ValueError as exc:
            assert expected in str(exc)
        else:
            msg = f"expected ValueError containing {expected!r}"
            raise AssertionError(msg)

    assert_value_error(
        lambda: store.close_request(9999, reviewer="admin"),
        "Pending request not found",
    )

    close_req = store.create_request(
        proxy_id="edge-a",
        client_ip="192.168.1.55",
        request_url="https://close.example/",
        domain="close.example",
    )
    store.close_request(close_req.id, reviewer="admin", status="rejected")
    assert store.list_requests(statuses=["rejected"])[0].id == close_req.id
    assert_value_error(
        lambda: store.close_request(close_req.id, reviewer="admin", status="closed"),
        "Pending request not found",
    )

    approve_req = store.create_request(
        proxy_id="edge-a",
        client_ip="192.168.1.56",
        request_url="https://approved.example/",
        domain="approved.example",
    )
    exception = store.approve_request(
        approve_req.id,
        reviewer="admin",
        indefinite=True,
    )
    assert_value_error(
        lambda: store.close_request(approve_req.id, reviewer="admin"),
        "Pending request not found",
    )

    assert_value_error(
        lambda: store.revoke_exception(9999, revoked_by="admin"),
        "Active exception not found",
    )
    store.revoke_exception(exception.id, revoked_by="admin", admin_note="cleanup")
    assert store.active_webfilter_exceptions(proxy_id="edge-a") == []
    assert_value_error(
        lambda: store.revoke_exception(exception.id, revoked_by="admin"),
        "Active exception not found",
    )


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
    try:
        store.close_request(
            approved.id,
            reviewer="admin",
            status="closed",
            admin_note="late close",
        )
    except ValueError as exc:
        assert "Pending request not found" in str(exc)
    else:
        msg = "approved request should not be closeable"
        raise AssertionError(msg)
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


def test_proxy_policy_request_route_uses_form_client_ip_from_trusted_proxy(
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
                790,
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
        data={
            "request_url": "https://bad.example/",
            "domain": "bad.example",
            "client_ip": "10.11.12.14",
        },
    )
    assert res.status_code == 200
    assert recorded["client_ip"] == "10.11.12.14"
