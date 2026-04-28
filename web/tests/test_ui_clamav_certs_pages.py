from .flask_test_helpers import login, redirect_query_params
from .ui_pages_test_support import app_module  # noqa: F401


def test_clamav_toggle_calls_apply_config(app_module):
    c = app_module.app.test_client()
    csrf = login(c)

    r = c.post("/clamav/toggle", headers={"X-CSRF-Token": csrf}, data={"action": "enable"}, follow_redirects=False)
    assert r.status_code in (301, 302, 303, 307, 308)

    calls = getattr(app_module, "_test_calls")
    assert calls["reload"] >= 1


def test_clamav_test_endpoints_redirect_with_result(app_module):
    c = app_module.app.test_client()
    csrf = login(c)

    r1 = c.post("/clamav/test-eicar", headers={"X-CSRF-Token": csrf}, data={}, follow_redirects=False)
    assert r1.status_code in (301, 302, 303, 307, 308)
    qs1 = redirect_query_params(r1)
    assert qs1.get("eicar") == ["ok"]
    assert qs1.get("eicar_detail") == ["eicar requested for default"]

    r2 = c.post("/clamav/test-icap", headers={"X-CSRF-Token": csrf}, data={}, follow_redirects=False)
    assert r2.status_code in (301, 302, 303, 307, 308)
    qs2 = redirect_query_params(r2)
    assert qs2.get("icap_sample") == ["ok"]
    assert qs2.get("icap_detail") == ["icap requested for default"]


def test_certs_generate_success_and_failure(app_module, monkeypatch):
    c = app_module.app.test_client()
    csrf = login(c)

    fake_bundle = object()
    monkeypatch.setattr(app_module, "generate_self_signed_ca_bundle", lambda: fake_bundle)
    monkeypatch.setattr(app_module, "_publish_certificate_bundle_remote", lambda bundle: (bundle is fake_bundle, "generated"))

    r_ok = c.post("/certs/generate", headers={"X-CSRF-Token": csrf}, data={}, follow_redirects=False)
    assert r_ok.status_code in (301, 302, 303, 307, 308)
    qs_ok = redirect_query_params(r_ok)
    assert qs_ok.get("ok") == ["1"]
    assert qs_ok.get("msg") == ["generated"]

    def boom():
        raise RuntimeError("nope")

    monkeypatch.setattr(app_module, "generate_self_signed_ca_bundle", boom)
    r_fail = c.post("/certs/generate", headers={"X-CSRF-Token": csrf}, data={}, follow_redirects=False)
    assert r_fail.status_code in (301, 302, 303, 307, 308)
    assert redirect_query_params(r_fail).get("ok") == ["0"]
