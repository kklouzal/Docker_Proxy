from .flask_test_helpers import login, redirect_query_params
from .ui_pages_test_support import app_module  # noqa: F401


def test_clamav_toggle_calls_apply_config(app_module):
    c = app_module.app.test_client()
    csrf = login(c)

    r = c.post("/clamav/toggle", headers={"X-CSRF-Token": csrf}, data={"action": "enable"}, follow_redirects=False)
    assert r.status_code in (301, 302, 303, 307, 308)

    calls = getattr(app_module, "_test_calls")
    assert calls["apply"] >= 1


def test_clamav_test_endpoints_redirect_with_result(app_module, monkeypatch):
    c = app_module.app.test_client()
    csrf = login(c)

    monkeypatch.setattr(app_module, "_test_eicar", lambda: {"ok": True, "detail": "Eicar FOUND"})
    r1 = c.post("/clamav/test-eicar", headers={"X-CSRF-Token": csrf}, data={}, follow_redirects=False)
    assert r1.status_code in (301, 302, 303, 307, 308)
    qs1 = redirect_query_params(r1)
    assert qs1.get("eicar") == ["ok"]
    assert qs1.get("eicar_detail") == ["Eicar FOUND"]

    monkeypatch.setattr(app_module, "_send_sample_av_icap", lambda: {"ok": False, "detail": "ICAP/1.0 500"})
    r2 = c.post("/clamav/test-icap", headers={"X-CSRF-Token": csrf}, data={}, follow_redirects=False)
    assert r2.status_code in (301, 302, 303, 307, 308)
    qs2 = redirect_query_params(r2)
    assert qs2.get("icap_sample") == ["fail"]
    assert qs2.get("icap_detail") == ["ICAP/1.0 500"]


def test_certs_generate_success_and_failure(app_module, monkeypatch):
    c = app_module.app.test_client()
    csrf = login(c)

    class FakeCM:
        def __init__(self):
            self.called = False

        def ca_exists(self):
            return False

        def ensure_ca(self):
            self.called = True

    fake = FakeCM()
    monkeypatch.setattr(app_module, "cert_manager", fake)

    r_ok = c.post("/certs/generate", headers={"X-CSRF-Token": csrf}, data={}, follow_redirects=False)
    assert r_ok.status_code in (301, 302, 303, 307, 308)
    assert fake.called is True
    assert redirect_query_params(r_ok).get("ok") == ["1"]

    def boom():
        raise RuntimeError("nope")

    fake2 = FakeCM()
    fake2.ensure_ca = boom  # type: ignore[method-assign]
    monkeypatch.setattr(app_module, "cert_manager", fake2)
    r_fail = c.post("/certs/generate", headers={"X-CSRF-Token": csrf}, data={}, follow_redirects=False)
    assert r_fail.status_code in (301, 302, 303, 307, 308)
    assert redirect_query_params(r_fail).get("ok") == ["0"]
