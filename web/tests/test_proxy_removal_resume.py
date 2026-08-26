from __future__ import annotations

from types import SimpleNamespace

from .admin_route_test_utils import (
    FakeRegistry,
    csrf_token,
    load_admin_app,
    login_client,
)


def test_proxy_remove_route_reports_durable_pending_pass_and_keeps_target_selected(
    monkeypatch,
    tmp_path,
) -> None:
    class PendingRemovalRegistry(FakeRegistry):
        def remove_proxy(self, proxy_id):
            proxy = self.get_proxy(proxy_id)
            assert proxy is not None
            proxy.status = "remove_pending"
            proxy.detail = "Proxy removal paused after bounded chunk limit."
            return SimpleNamespace(
                proxy_id=str(proxy_id),
                deleted_rows=50_000,
                table_counts={"ts_1h": 50_000},
                complete=False,
                truncated_tables=("ts_1h",),
                retry_detail=("paused after bounded chunk limit; retry to resume."),
            )

    registry = PendingRemovalRegistry(proxy_ids=["default", "edge-2"])
    loaded = load_admin_app(monkeypatch, tmp_path, registry=registry)
    client = loaded.module.app.test_client()
    login_client(client)
    with client.session_transaction() as sess:
        sess["active_proxy_id"] = "edge-2"
    token = csrf_token(client, "/proxies?proxy_id=edge-2")

    response = client.post(
        "/proxies/remove",
        data={
            "csrf_token": token,
            "proxy_id": "edge-2",
            "confirm_proxy_id": "edge-2",
        },
        follow_redirects=False,
    )

    assert response.status_code in {301, 302, 303}
    assert "pending=1" in response.headers["Location"]
    assert "removed=1" not in response.headers["Location"]
    assert "retry+to+resume" in response.headers["Location"]
    assert registry.get_proxy("edge-2") is not None
    with client.session_transaction() as sess:
        assert sess["active_proxy_id"] == "edge-2"
    assert any(
        record["kind"] == "proxy_remove"
        and record["ok"] is True
        and "status=pending" in record["detail"]
        and "deleted_rows=50000" in record["detail"]
        for record in loaded.audit_store.records
    )

    pending_page = client.get(response.headers["Location"])
    body = pending_page.get_data(as_text=True)
    assert pending_page.status_code == 200
    assert "Removal pending" in body
    assert "Pending table: ts_1h." in body
    assert "Continue removal" in body


def test_proxy_remove_retry_failure_audits_against_surviving_proxy(
    monkeypatch,
    tmp_path,
) -> None:
    class FailingRemovalRegistry(FakeRegistry):
        def remove_proxy(self, proxy_id):
            assert proxy_id == "edge-2"
            msg = "bounded removal retry failed"
            raise RuntimeError(msg)

    registry = FailingRemovalRegistry(proxy_ids=["default", "edge-2"])
    loaded = load_admin_app(monkeypatch, tmp_path, registry=registry)
    audited: list[tuple[str, str, bool, str]] = []
    monkeypatch.setattr(
        loaded.module,
        "_record_audit_event_for_proxy",
        lambda proxy_id, kind, *, ok, detail="", **_kwargs: audited.append(
            (proxy_id, kind, ok, detail)
        ),
    )
    client = loaded.module.app.test_client()
    login_client(client)
    with client.session_transaction() as sess:
        sess["active_proxy_id"] = "edge-2"
    token = csrf_token(client, "/proxies?proxy_id=edge-2")

    response = client.post(
        "/proxies/remove",
        data={
            "csrf_token": token,
            "proxy_id": "edge-2",
            "confirm_proxy_id": "edge-2",
        },
        follow_redirects=False,
    )

    assert response.status_code in {301, 302, 303}
    assert audited == [
        (
            "default",
            "proxy_remove",
            False,
            "proxy_id=edge-2 error=Operation failed. Check server logs for details.",
        )
    ]
    with client.session_transaction() as sess:
        assert sess["active_proxy_id"] == "edge-2"
