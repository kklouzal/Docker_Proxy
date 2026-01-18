import importlib
import os
import sys
from urllib.parse import parse_qs, urlsplit

import pytest


def _import_app_isolated(tmp_path):
    try:
        import flask  # noqa: F401
    except Exception as e:
        pytest.skip(f"Flask not available in this environment: {e}")

    web_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if web_dir not in sys.path:
        sys.path.insert(0, web_dir)

    os.environ["DISABLE_BACKGROUND"] = "1"
    os.environ["AUTH_DB"] = str(tmp_path / "auth.db")
    os.environ["FLASK_SECRET_PATH"] = str(tmp_path / "flask_secret.key")

    if "app" in sys.modules:
        del sys.modules["app"]

    import app as app_module  # type: ignore

    importlib.reload(app_module)
    app_module.app.testing = True
    return app_module


def _get_csrf_token(client) -> str:
    client.get("/login")
    with client.session_transaction() as sess:
        return sess.get("_csrf_token", "") or ""


def _login(client) -> str:
    csrf = _get_csrf_token(client)
    r = client.post(
        "/login",
        data={"username": "admin", "password": "admin", "next": "", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)
    return csrf


def _qs(resp) -> dict[str, list[str]]:
    loc = resp.headers.get("Location", "") or ""
    return parse_qs(urlsplit(loc).query)


def test_apply_safe_workers_are_clamped(tmp_path, monkeypatch):
    app_module = _import_app_isolated(tmp_path)

    captured = {"options": None}

    monkeypatch.setattr(app_module.squid_controller, "get_current_config", lambda: "")
    monkeypatch.setattr(
        app_module.squid_controller,
        "get_tunable_options",
        lambda _cfg=None: {"workers": 2, "negative_ttl_seconds": 123},
    )
    monkeypatch.setattr(app_module.squid_controller, "get_cache_override_options", lambda _cfg=None: {})

    def fake_generate(options, exclusions):
        captured["options"] = dict(options)
        return "CFG"

    monkeypatch.setattr(app_module.squid_controller, "generate_config_from_template_with_exclusions", fake_generate)
    monkeypatch.setattr(app_module.squid_controller, "apply_cache_overrides", lambda cfg, overrides: cfg)
    monkeypatch.setattr(app_module.squid_controller, "apply_config_text", lambda cfg: (True, "ok"))

    class FakeEx:
        domains = []
        src_nets = []
        exclude_private_nets = False

    monkeypatch.setattr(app_module, "get_exclusions_store", lambda: type("S", (), {"list_all": lambda self=None: FakeEx()})())

    c = app_module.app.test_client()
    csrf = _login(c)

    # too high -> clamped to MAX_WORKERS (default 32)
    r = c.post(
        "/squid/config/apply-safe",
        data={"form_kind": "caching", "workers": "999", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)
    assert captured["options"] is not None
    assert captured["options"]["workers"] == 32

    # too low -> clamped to 1
    captured["options"] = None
    r2 = c.post(
        "/squid/config/apply-safe",
        data={"form_kind": "caching", "workers": "0", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert r2.status_code in (301, 302, 303, 307, 308)
    assert captured["options"]["workers"] == 1


def test_apply_safe_optional_int_blank_does_not_override(tmp_path, monkeypatch):
    app_module = _import_app_isolated(tmp_path)

    captured = {"options": None}

    monkeypatch.setattr(app_module.squid_controller, "get_current_config", lambda: "")
    monkeypatch.setattr(
        app_module.squid_controller,
        "get_tunable_options",
        lambda _cfg=None: {"negative_ttl_seconds": 123, "workers": 2},
    )
    monkeypatch.setattr(app_module.squid_controller, "get_cache_override_options", lambda _cfg=None: {})

    def fake_generate(options, exclusions):
        captured["options"] = dict(options)
        return "CFG"

    monkeypatch.setattr(app_module.squid_controller, "generate_config_from_template_with_exclusions", fake_generate)
    monkeypatch.setattr(app_module.squid_controller, "apply_cache_overrides", lambda cfg, overrides: cfg)
    monkeypatch.setattr(app_module.squid_controller, "apply_config_text", lambda cfg: (True, "ok"))

    class FakeEx:
        domains = []
        src_nets = []
        exclude_private_nets = False

    monkeypatch.setattr(app_module, "get_exclusions_store", lambda: type("S", (), {"list_all": lambda self=None: FakeEx()})())

    c = app_module.app.test_client()
    csrf = _login(c)

    r = c.post(
        "/squid/config/apply-safe",
        data={
            "form_kind": "timeouts",
            "negative_ttl_seconds": "",  # optional int, blank should not override existing
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)
    assert captured["options"] is not None
    assert captured["options"]["negative_ttl_seconds"] == 123


def test_apply_safe_error_redirects(tmp_path, monkeypatch):
    app_module = _import_app_isolated(tmp_path)

    monkeypatch.setattr(app_module.squid_controller, "get_current_config", lambda: "")
    monkeypatch.setattr(app_module.squid_controller, "get_tunable_options", lambda _cfg=None: {})

    def boom(*_a, **_k):
        raise RuntimeError("boom")

    monkeypatch.setattr(app_module.squid_controller, "generate_config_from_template_with_exclusions", boom)

    class FakeEx:
        domains = []
        src_nets = []
        exclude_private_nets = False

    monkeypatch.setattr(app_module, "get_exclusions_store", lambda: type("S", (), {"list_all": lambda self=None: FakeEx()})())

    c = app_module.app.test_client()
    csrf = _login(c)

    r = c.post(
        "/squid/config/apply-safe",
        data={"form_kind": "caching", "workers": "2", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)
    loc = r.headers.get("Location", "") or ""
    assert "error=1" in loc


def test_apply_overrides_maps_form_to_dict(tmp_path, monkeypatch):
    app_module = _import_app_isolated(tmp_path)

    captured = {"overrides": None}

    monkeypatch.setattr(app_module.squid_controller, "get_current_config", lambda: "")
    monkeypatch.setattr(app_module.squid_controller, "get_tunable_options", lambda _cfg=None: {"workers": 2})

    class FakeEx:
        domains = []
        src_nets = []
        exclude_private_nets = False

    monkeypatch.setattr(app_module, "get_exclusions_store", lambda: type("S", (), {"list_all": lambda self=None: FakeEx()})())

    monkeypatch.setattr(app_module.squid_controller, "generate_config_from_template_with_exclusions", lambda options, exclusions: "CFG")

    def fake_apply_overrides(cfg_text: str, overrides: dict):
        captured["overrides"] = dict(overrides)
        return cfg_text

    monkeypatch.setattr(app_module.squid_controller, "apply_cache_overrides", fake_apply_overrides)
    monkeypatch.setattr(app_module.squid_controller, "apply_config_text", lambda cfg: (True, "ok"))

    c = app_module.app.test_client()
    csrf = _login(c)

    r = c.post(
        "/squid/config/apply-overrides",
        data={
            "override_client_no_cache": "on",
            "override_origin_private": "on",
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)
    assert captured["overrides"] is not None
    assert captured["overrides"]["client_no_cache"] is True
    assert captured["overrides"]["origin_private"] is True
    # unchecked boxes must be False
    assert captured["overrides"]["client_no_store"] is False
    assert captured["overrides"]["ignore_auth"] is False

    qs = _qs(r)
    assert qs.get("ok") == ["1"]
