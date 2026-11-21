"""Shell/dashboard page states: action feedback, unreachable proxy, ledger failure."""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

from .admin_route_test_utils import (
    FakeOperationLedger,
    FakeProxyClient,
    load_admin_app,
    login_client,
)


def _client(monkeypatch, tmp_path, **overrides):
    monkeypatch.setenv("DISABLE_CSRF", "1")
    loaded = load_admin_app(monkeypatch, tmp_path, **overrides)
    client = loaded.module.app.test_client()
    login_client(client)
    return loaded, client


def test_reload_and_cache_clear_report_their_outcome_on_the_overview(
    monkeypatch, tmp_path
) -> None:
    _loaded, client = _client(monkeypatch, tmp_path)

    for path, expected in (
        ("/reload", "Proxy reconciliation queued"),
        ("/cache/clear", "Proxy cache clear queued"),
    ):
        response = client.post(path, follow_redirects=False)
        assert response.status_code in {302, 303}
        location = response.headers["Location"]
        assert location.endswith("#status")
        params = parse_qs(urlsplit(location).query)
        assert params["ok"] == ["1"]
        assert expected in params["msg"][0]

        page = client.get(location.split("#", 1)[0]).get_data(as_text=True)
        assert "Queued" in page
        assert expected in page


def test_reload_failure_is_reported_not_dropped(monkeypatch, tmp_path) -> None:
    loaded, client = _client(monkeypatch, tmp_path)

    def fail_reconcile(*_args, **_kwargs):
        msg = "operation ledger unavailable"
        raise RuntimeError(msg)

    monkeypatch.setattr(loaded.module, "request_proxy_reconcile", fail_reconcile)

    response = client.post("/reload", follow_redirects=False)
    params = parse_qs(urlsplit(response.headers["Location"]).query)
    assert params["ok"] == ["0"]
    page = client.get(response.headers["Location"].split("#", 1)[0])
    body = page.get_data(as_text=True)
    assert 'class="banner error"' in body
    assert "Failed" in body


def test_overview_shows_one_unreachable_notice_instead_of_per_service_errors(
    monkeypatch, tmp_path
) -> None:
    first = load_admin_app(monkeypatch, tmp_path)
    failing = FakeProxyClient(first.module, fail=True)
    _loaded, client = _client(monkeypatch, tmp_path, proxy_client=failing)

    body = client.get("/").get_data(as_text=True)

    assert "No health report from" in body
    assert "Proxy unreachable" in body
    # The client error is shown once, in the notice, not on every service row.
    assert body.count("proxy unavailable") == 1
    assert body.count("No report") == 3


def test_operations_page_reports_ledger_read_failure(monkeypatch, tmp_path) -> None:
    class BrokenLedger(FakeOperationLedger):
        def list_operations(self, *_args, **_kwargs):
            msg = "ledger down"
            raise RuntimeError(msg)

    _loaded, client = _client(monkeypatch, tmp_path, operation_ledger=BrokenLedger())

    body = client.get("/operations").get_data(as_text=True)

    assert "The operation ledger could not be read" in body
    assert "Operations could not be loaded." in body
    assert "No operations recorded for this proxy yet." not in body


def test_certs_page_hides_download_until_a_ca_exists(monkeypatch, tmp_path) -> None:
    _loaded, client = _client(monkeypatch, tmp_path)

    body = client.get("/certs").get_data(as_text=True)

    assert "/certs/download/" not in body
    assert "Generate CA" in body


def test_proxy_switcher_drops_one_shot_feedback_params(monkeypatch, tmp_path) -> None:
    _loaded, client = _client(monkeypatch, tmp_path)

    body = client.get("/?ok=1&msg=queued&pane=x").get_data(as_text=True)

    assert 'id="proxy-id"' in body
    assert '<input type="hidden" name="pane" value="x">' in body
    assert '<input type="hidden" name="msg"' not in body
    assert '<input type="hidden" name="ok"' not in body
