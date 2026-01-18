import os
import sys
import tempfile

from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest


def _import_app_module():
    try:
        import flask  # noqa: F401
    except Exception as e:
        pytest.skip(f"Flask not available in this environment: {e}")

    web_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if web_dir not in sys.path:
        sys.path.insert(0, web_dir)

    os.environ.setdefault("DISABLE_BACKGROUND", "1")

    # Isolate auth state for deterministic tests.
    os.environ.setdefault("AUTH_DB", os.path.join(tempfile.mkdtemp(prefix="sfp_auth_"), "auth.db"))
    os.environ.setdefault(
        "FLASK_SECRET_PATH",
        os.path.join(tempfile.mkdtemp(prefix="sfp_secret_"), "flask_secret.key"),
    )

    import app as app_module  # type: ignore

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


@pytest.fixture()
def app_module(monkeypatch):
    app_module = _import_app_module()

    # Avoid real socket/subprocess health checks during unit tests.
    monkeypatch.setattr(app_module, "_check_icap_adblock", lambda: {"ok": True, "detail": "stub"})
    monkeypatch.setattr(app_module, "_check_clamd", lambda: {"ok": True, "detail": "stub"})
    monkeypatch.setattr(app_module, "_check_tcp", lambda host, port, timeout=0.6: {"ok": True, "detail": "stub"})
    monkeypatch.setattr(app_module, "_check_icap_service", lambda host, port, service: {"ok": True, "detail": "stub"})

    # Make status/config operations safe and observable.
    calls = {"reload": 0, "clear": 0, "apply": 0}

    def fake_get_status():
        return (b"OK\n", b"")

    def fake_get_current_config():
        # Minimal config text used across a few pages.
        return "http_port 3128\n"

    def fake_apply_config_text(cfg_text: str):
        calls["apply"] += 1
        return True, "ok"

    def fake_reload():
        calls["reload"] += 1

    def fake_clear():
        calls["clear"] += 1

    monkeypatch.setattr(app_module.squid_controller, "get_status", fake_get_status)
    monkeypatch.setattr(app_module.squid_controller, "get_current_config", fake_get_current_config)
    monkeypatch.setattr(app_module.squid_controller, "apply_config_text", fake_apply_config_text)
    monkeypatch.setattr(app_module.squid_controller, "reload_squid", fake_reload)
    monkeypatch.setattr(app_module.squid_controller, "clear_disk_cache", fake_clear)

    # Stub stats + trends.
    monkeypatch.setattr(
        app_module,
        "get_stats",
        lambda: {
            "cpu": {"util_percent": 1.0, "loadavg": {"1m": 0.1, "5m": 0.1, "15m": 0.1}},
            "memory": {"used_bytes": 1, "total_bytes": 2, "used_percent": 50.0},
            "storage": {
                "cache_path": "/var/spool/squid",
                "cache_dir_size_human": "1G",
                "cache_fs_used_human": "1G",
                "cache_fs_total_human": "2G",
                "cache_fs_free_human": "1G",
            },
            "squid": {"mgr_available": False, "hit_rate": None, "hit_rate_source": ""},
        },
    )

    class FakeTS:
        def summary(self):
            return {}

    monkeypatch.setattr(app_module, "get_timeseries_store", lambda: FakeTS())

    # Stores used by various pages.
    class FakeSSLErrors:
        def list_recent(self, *, since: int, search: str, limit: int):
            return []

        def top_domains(self, *, since: int, search: str, limit: int):
            return []

    monkeypatch.setattr(app_module, "get_ssl_errors_store", lambda: FakeSSLErrors())

    class FakeExclusions:
        def __init__(self):
            self.domains = []
            self.src_nets = []
            self.dst_nets = []
            self.exclude_private_nets = False

    class FakeExclusionsStore:
        def __init__(self):
            self._ex = FakeExclusions()
            self.added_domains = []

        def add_domain(self, domain: str):
            self.added_domains.append(domain.strip().lower().lstrip("."))

        def remove_domain(self, domain: str):
            if domain in self._ex.domains:
                self._ex.domains.remove(domain)

        def add_net(self, kind: str, cidr: str):
            return None

        def remove_net(self, kind: str, cidr: str):
            return None

        def set_exclude_private_nets(self, enabled: bool):
            self._ex.exclude_private_nets = bool(enabled)

        def list_all(self):
            return self._ex

    fake_ex_store = FakeExclusionsStore()
    monkeypatch.setattr(app_module, "get_exclusions_store", lambda: fake_ex_store)

    class FakeSocksStore:
        def summary(self, *, since: int):
            return {"total": 0, "clients": 0, "dests": 0}

        def top_clients(self, *, since: int, limit: int, search: str = ""):
            return []

        def top_destinations(self, *, since: int, limit: int, search: str = ""):
            return []

        def recent(self, *, limit: int, since: int, search: str = ""):
            return []

    monkeypatch.setattr(app_module, "get_socks_store", lambda: FakeSocksStore())

    class Status:
        def __init__(self, key: str, url: str, enabled: bool):
            self.key = key
            self.url = url
            self.enabled = enabled
            self.rules = 0
            self.bytes = 0
            self.last_success = 0
            self.last_attempt = 0
            self.last_error = ""

    class FakeAdblockStore:
        def __init__(self):
            self._enabled_map = {}
            self._settings = {}
            self._refresh = False
            self._flush = False
            self._statuses = [Status("list1", "https://example/list.txt", True)]

        def init_db(self):
            return None

        def list_statuses(self):
            return self._statuses

        def set_enabled(self, enabled_map):
            self._enabled_map = dict(enabled_map)

        def get_settings(self):
            return {"enabled": True, "cache_ttl": 60, "cache_max": 1000}

        def set_settings(self, *, enabled: bool, cache_ttl: int, cache_max: int):
            self._settings = {"enabled": enabled, "cache_ttl": cache_ttl, "cache_max": cache_max}

        def request_refresh_now(self):
            self._refresh = True

        def request_cache_flush(self):
            self._flush = True

        def stats(self):
            return {"total": 0, "last_24h": 0, "by_list": {}, "by_list_24h": {}}

        def cache_stats(self):
            return {"hits": 0, "misses": 0, "evictions": 0, "current_size": 0, "last_flush": 0, "last_flush_req": 0}

        def get_update_interval_seconds(self):
            return 3600

        def list_recent_block_events(self, *, limit: int):
            return []

    fake_adblock_store = FakeAdblockStore()
    monkeypatch.setattr(app_module, "get_adblock_store", lambda: fake_adblock_store)

    class FakeWebfilterStore:
        def __init__(self):
            self._settings = None
            self._apply_calls = 0
            self._removed_patterns = []

        def init_db(self):
            return None

        def set_settings(self, *, enabled: bool, source_url: str, blocked_categories: list[str]):
            self._settings = {"enabled": enabled, "source_url": source_url, "blocked_categories": blocked_categories}

        def apply_squid_include(self):
            self._apply_calls += 1
            return None

        def add_whitelist(self, entry: str):
            return True, "", entry.strip().lower() or "example.com"

        def remove_whitelist(self, pat: str):
            self._removed_patterns.append(pat)
            return None

        def get_settings(self):
            return SimpleNamespace(enabled=False, source_url="", blocked_categories=[])

        def list_available_categories(self):
            return [("adult", 123), ("games", 45)]

        def list_whitelist(self):
            return []

        def list_blocked_log(self, *, limit: int):
            return []

        def test_domain(self, domain: str):
            d = (domain or "").strip().lower()
            return {"ok": True, "domain": d, "verdict": "allow", "reason": "stub"}

    fake_webfilter_store = FakeWebfilterStore()
    monkeypatch.setattr(app_module, "get_webfilter_store", lambda: fake_webfilter_store)

    class FakeSSLFilterStore:
        def __init__(self):
            self._apply_calls = 0
            self._removed = []

        def init_db(self):
            return None

        def add_nobump(self, entry: str):
            return True, "", entry.strip() or "10.0.0.0/8"

        def remove_nobump(self, cidr: str):
            return None

        def apply_squid_include(self):
            self._apply_calls += 1
            return None

        def list_nobump(self):
            return []

    fake_sslfilter_store = FakeSSLFilterStore()
    monkeypatch.setattr(app_module, "get_sslfilter_store", lambda: fake_sslfilter_store)

    class FakePacProfiles:
        def __init__(self):
            self.upserts = []
            self.deletes = []

        def match_profile_for_client_ip(self, ip: str):
            return None

        def upsert_profile(self, **kwargs):
            self.upserts.append(dict(kwargs))
            return True, "", 1

        def delete_profile(self, pid: int):
            self.deletes.append(int(pid))
            return None

        def list_profiles(self):
            return []

    fake_pac_profiles = FakePacProfiles()
    monkeypatch.setattr(app_module, "get_pac_profiles_store", lambda: fake_pac_profiles)

    class FakeLive:
        def get_totals(self, *, since: int):
            return {"requests": 0, "cached": 0, "not_cached": 0}

        def list_global_not_cached_reasons(self, *, limit: int):
            return 0, []

        def list_clients(self, *, sort: str, order: str, limit: int, since: int, search: str):
            return []

        def list_client_domains(self, *, ip: str, sort: str):
            return []

        def list_client_not_cached(self, *, ip: str, limit: int):
            return []

        def list_domains(self, *, sort: str, order: str, limit: int, since: int, search: str):
            return []

        def list_domain_not_cached_reasons(self, *, domain: str, limit: int):
            return []

    monkeypatch.setattr(app_module, "get_store", lambda: FakeLive())

    class FakeAudit:
        def latest_config_apply(self):
            return None

    monkeypatch.setattr(app_module, "get_audit_store", lambda: FakeAudit())

    # Patch subprocess.run used by a few pages (imported dynamically inside handlers).
    import subprocess

    class P:
        returncode = 0
        stdout = ""
        stderr = ""

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: P())

    # Expose call counters for assertions.
    app_module._test_calls = calls  # type: ignore[attr-defined]
    app_module._test_fake_ex_store = fake_ex_store  # type: ignore[attr-defined]
    app_module._test_adblock_store = fake_adblock_store  # type: ignore[attr-defined]
    app_module._test_webfilter_store = fake_webfilter_store  # type: ignore[attr-defined]
    app_module._test_sslfilter_store = fake_sslfilter_store  # type: ignore[attr-defined]
    app_module._test_pac_profiles_store = fake_pac_profiles  # type: ignore[attr-defined]

    return app_module


@pytest.mark.parametrize(
    "path, expected",
    [
        ("/", "Status"),
        ("/live", "Live"),
        ("/ssl-errors", "SSL Errors"),
        ("/squid/config", "Squid"),
        ("/exclusions", "Exclusions"),
        ("/certs", "Certificates"),
        ("/adblock", "Ad"),
        ("/webfilter", "Web"),
        ("/clamav", "Clam"),
        ("/sslfilter", "SSL"),
        ("/socks", "SOCKS"),
        ("/pac", "PAC"),
        ("/administration", "Administration"),
    ],
)
def test_ui_pages_render_and_include_csrf_meta(app_module, path: str, expected: str):
    c = app_module.app.test_client()
    _login(c)

    r = c.get(path)
    assert r.status_code == 200
    body = r.data.decode("utf-8", errors="replace")
    assert "<meta name=\"csrf-token\"" in body
    assert expected.lower() in body.lower()


def test_index_post_actions_work(app_module):
    c = app_module.app.test_client()
    csrf = _login(c)

    r1 = c.post("/reload", headers={"X-CSRF-Token": csrf}, data={}, follow_redirects=False)
    assert r1.status_code in (301, 302, 303, 307, 308)

    r2 = c.post("/cache/clear", headers={"X-CSRF-Token": csrf}, data={}, follow_redirects=False)
    assert r2.status_code in (301, 302, 303, 307, 308)

    calls = getattr(app_module, "_test_calls")
    assert calls["reload"] == 1
    assert calls["clear"] == 1


def test_ssl_errors_exclude_posts_domain(app_module):
    c = app_module.app.test_client()
    csrf = _login(c)

    r = c.post(
        "/ssl-errors/exclude",
        headers={"X-CSRF-Token": csrf},
        data={"domain": "Example.COM"},
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)

    store = getattr(app_module, "_test_fake_ex_store")
    assert "example.com" in store.added_domains


def test_webfilter_test_domain_json(app_module):
    c = app_module.app.test_client()
    csrf = _login(c)

    r = c.post("/webfilter/test", headers={"X-CSRF-Token": csrf}, json={"domain": "example.com"})
    assert r.status_code == 200
    assert r.is_json
    data = r.get_json()
    assert data["ok"] is True
    assert data["domain"] == "example.com"


def test_clamav_toggle_calls_apply_config(app_module):
    c = app_module.app.test_client()
    csrf = _login(c)

    r = c.post("/clamav/toggle", headers={"X-CSRF-Token": csrf}, data={"action": "enable"}, follow_redirects=False)
    assert r.status_code in (301, 302, 303, 307, 308)

    calls = getattr(app_module, "_test_calls")
    assert calls["apply"] >= 1


def test_pac_builder_create_profile(app_module):
    c = app_module.app.test_client()
    csrf = _login(c)

    r = c.post(
        "/pac",
        headers={"X-CSRF-Token": csrf},
        data={
            "action": "create",
            "name": "test",
            "client_cidr": "",
            "socks_enabled": "",
            "socks_host": "",
            "socks_port": "1080",
            "direct_domains": "example.com\n",
            "direct_dst_nets": "",
        },
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)


def test_adblock_save_lists_updates_enabled_map(app_module):
    c = app_module.app.test_client()
    csrf = _login(c)

    store = getattr(app_module, "_test_adblock_store")
    assert store.list_statuses(), "expected at least one adblock list status"

    r = c.post(
        "/adblock",
        headers={"X-CSRF-Token": csrf},
        data={"action": "save_lists", "enabled_list1": "on"},
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)
    assert store._enabled_map == {"list1": True}


def test_adblock_save_settings_persists_values(app_module):
    c = app_module.app.test_client()
    csrf = _login(c)

    store = getattr(app_module, "_test_adblock_store")
    r = c.post(
        "/adblock",
        headers={"X-CSRF-Token": csrf},
        data={
            "action": "save_settings",
            "adblock_enabled": "on",
            "cache_ttl": "120",
            "cache_max": "999",
        },
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)
    assert store._settings == {"enabled": True, "cache_ttl": 120, "cache_max": 999}


def test_adblock_refresh_sets_flag_and_redirects(app_module):
    c = app_module.app.test_client()
    csrf = _login(c)

    store = getattr(app_module, "_test_adblock_store")
    store._statuses[0].enabled = True

    r = c.post(
        "/adblock",
        headers={"X-CSRF-Token": csrf},
        data={"action": "refresh"},
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)
    qs = _qs(r)
    assert qs.get("refresh_requested") == ["1"]
    assert store._refresh is True


def test_adblock_refresh_without_enabled_lists_redirects_notice(app_module):
    c = app_module.app.test_client()
    csrf = _login(c)

    store = getattr(app_module, "_test_adblock_store")
    store._statuses[0].enabled = False
    store._refresh = False

    r = c.post(
        "/adblock",
        headers={"X-CSRF-Token": csrf},
        data={"action": "refresh"},
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)
    qs = _qs(r)
    assert qs.get("refresh_no_lists") == ["1"]
    assert store._refresh is False


def test_adblock_flush_cache_sets_flag_and_redirects(app_module):
    c = app_module.app.test_client()
    csrf = _login(c)

    store = getattr(app_module, "_test_adblock_store")
    store._flush = False
    r = c.post(
        "/adblock",
        headers={"X-CSRF-Token": csrf},
        data={"action": "flush_cache"},
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)
    qs = _qs(r)
    assert qs.get("cache_flushed") == ["1"]
    assert store._flush is True


def test_webfilter_save_requires_source_url_when_enabling(app_module):
    c = app_module.app.test_client()
    csrf = _login(c)

    r = c.post(
        "/webfilter",
        headers={"X-CSRF-Token": csrf},
        data={
            "action": "save",
            "tab": "categories",
            "enabled": "on",
            "source_url": "",
            "categories": ["adult"],
        },
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)
    qs = _qs(r)
    assert qs.get("tab") == ["categories"]
    assert qs.get("err_source") == ["1"]


def test_webfilter_save_persists_settings_and_applies_include(app_module):
    c = app_module.app.test_client()
    csrf = _login(c)

    store = getattr(app_module, "_test_webfilter_store")
    r = c.post(
        "/webfilter",
        headers={"X-CSRF-Token": csrf},
        data={
            "action": "save",
            "tab": "categories",
            "enabled": "on",
            "source_url": "https://example/categories.zip",
            "categories": ["adult", "games"],
        },
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)
    assert store._settings == {
        "enabled": True,
        "source_url": "https://example/categories.zip",
        "blocked_categories": ["adult", "games"],
    }
    assert store._apply_calls >= 1


def test_webfilter_whitelist_add_ok_sets_flash_query(app_module):
    c = app_module.app.test_client()
    csrf = _login(c)

    r = c.post(
        "/webfilter",
        headers={"X-CSRF-Token": csrf},
        data={"action": "whitelist_add", "tab": "whitelist", "whitelist_domain": "Example.com"},
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)
    qs = _qs(r)
    assert qs.get("tab") == ["whitelist"]
    assert qs.get("wl_ok") == ["1"]


def test_webfilter_whitelist_add_error_sets_error_code(app_module):
    c = app_module.app.test_client()
    csrf = _login(c)

    store = getattr(app_module, "_test_webfilter_store")
    store.add_whitelist = lambda entry: (False, "bad_domain", "")  # type: ignore[method-assign]

    r = c.post(
        "/webfilter",
        headers={"X-CSRF-Token": csrf},
        data={"action": "whitelist_add", "tab": "whitelist", "whitelist_domain": "not a domain"},
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)
    qs = _qs(r)
    assert qs.get("tab") == ["whitelist"]
    assert qs.get("wl_err") == ["bad_domain"]


def test_webfilter_whitelist_remove_calls_store(app_module):
    c = app_module.app.test_client()
    csrf = _login(c)

    store = getattr(app_module, "_test_webfilter_store")
    store._removed_patterns = []
    r = c.post(
        "/webfilter",
        headers={"X-CSRF-Token": csrf},
        data={"action": "whitelist_remove", "tab": "whitelist", "pattern": "example.com"},
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)
    assert "example.com" in store._removed_patterns


def test_sslfilter_add_ok_and_error(app_module):
    c = app_module.app.test_client()
    csrf = _login(c)

    store = getattr(app_module, "_test_sslfilter_store")
    r_ok = c.post(
        "/sslfilter",
        headers={"X-CSRF-Token": csrf},
        data={"action": "add", "cidr": "10.0.0.0/8"},
        follow_redirects=False,
    )
    assert r_ok.status_code in (301, 302, 303, 307, 308)
    qs_ok = _qs(r_ok)
    assert qs_ok.get("ok") == ["1"]

    store.add_nobump = lambda entry: (False, "bad_cidr", "")  # type: ignore[method-assign]
    r_err = c.post(
        "/sslfilter",
        headers={"X-CSRF-Token": csrf},
        data={"action": "add", "cidr": "bad"},
        follow_redirects=False,
    )
    assert r_err.status_code in (301, 302, 303, 307, 308)
    qs_err = _qs(r_err)
    assert qs_err.get("err") == ["bad_cidr"]


def test_sslfilter_remove_calls_store(app_module):
    c = app_module.app.test_client()
    csrf = _login(c)

    store = getattr(app_module, "_test_sslfilter_store")
    removed = {"cidr": None}

    def fake_remove(cidr: str):
        removed["cidr"] = cidr
        return None

    store.remove_nobump = fake_remove  # type: ignore[method-assign]

    r = c.post(
        "/sslfilter",
        headers={"X-CSRF-Token": csrf},
        data={"action": "remove", "cidr": "10.0.0.0/8"},
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)
    assert removed["cidr"] == "10.0.0.0/8"


def test_exclusions_post_actions_and_apply(app_module, monkeypatch):
    c = app_module.app.test_client()
    csrf = _login(c)

    store = getattr(app_module, "_test_fake_ex_store")
    r_add = c.post(
        "/exclusions",
        headers={"X-CSRF-Token": csrf},
        data={"action": "add_domain", "domain": "Example.COM"},
        follow_redirects=False,
    )
    assert r_add.status_code in (301, 302, 303, 307, 308)
    assert "example.com" in store.added_domains

    r_toggle = c.post(
        "/exclusions",
        headers={"X-CSRF-Token": csrf},
        data={"action": "toggle_private", "exclude_private_nets": "on"},
        follow_redirects=False,
    )
    assert r_toggle.status_code in (301, 302, 303, 307, 308)
    assert store._ex.exclude_private_nets is True

    # Apply should regenerate a config from current tunables + exclusions and apply it.
    monkeypatch.setattr(app_module.squid_controller, "get_current_config", lambda: "")
    monkeypatch.setattr(app_module.squid_controller, "get_tunable_options", lambda _cfg=None: {})
    monkeypatch.setattr(app_module.squid_controller, "get_cache_override_options", lambda _cfg=None: {})
    monkeypatch.setattr(app_module.squid_controller, "generate_config_from_template_with_exclusions", lambda options, ex: "CFG")
    monkeypatch.setattr(app_module.squid_controller, "apply_cache_overrides", lambda cfg, overrides: cfg)
    monkeypatch.setattr(app_module.squid_controller, "apply_config_text", lambda cfg: (True, "ok"))

    r_apply = c.post(
        "/exclusions",
        headers={"X-CSRF-Token": csrf},
        data={"action": "apply"},
        follow_redirects=False,
    )
    assert r_apply.status_code in (301, 302, 303, 307, 308)
    assert _qs(r_apply).get("ok") == ["1"]


def test_clamav_test_endpoints_redirect_with_result(app_module, monkeypatch):
    c = app_module.app.test_client()
    csrf = _login(c)

    monkeypatch.setattr(app_module, "_test_eicar", lambda: {"ok": True, "detail": "Eicar FOUND"})
    r1 = c.post("/clamav/test-eicar", headers={"X-CSRF-Token": csrf}, data={}, follow_redirects=False)
    assert r1.status_code in (301, 302, 303, 307, 308)
    qs1 = _qs(r1)
    assert qs1.get("eicar") == ["ok"]
    assert qs1.get("eicar_detail") == ["Eicar FOUND"]

    monkeypatch.setattr(app_module, "_send_sample_av_icap", lambda: {"ok": False, "detail": "ICAP/1.0 500"})
    r2 = c.post("/clamav/test-icap", headers={"X-CSRF-Token": csrf}, data={}, follow_redirects=False)
    assert r2.status_code in (301, 302, 303, 307, 308)
    qs2 = _qs(r2)
    assert qs2.get("icap_sample") == ["fail"]
    assert qs2.get("icap_detail") == ["ICAP/1.0 500"]


def test_pac_builder_update_and_delete(app_module):
    c = app_module.app.test_client()
    csrf = _login(c)

    store = getattr(app_module, "_test_pac_profiles_store")
    r_upd = c.post(
        "/pac",
        headers={"X-CSRF-Token": csrf},
        data={
            "action": "update",
            "profile_id": "5",
            "name": "updated",
            "client_cidr": "",
            "socks_enabled": "",
            "socks_host": "",
            "socks_port": "1080",
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


def test_certs_generate_success_and_failure(app_module, monkeypatch):
    c = app_module.app.test_client()
    csrf = _login(c)

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
    assert _qs(r_ok).get("ok") == ["1"]

    def boom():
        raise RuntimeError("nope")

    fake2 = FakeCM()
    fake2.ensure_ca = boom  # type: ignore[method-assign]
    monkeypatch.setattr(app_module, "cert_manager", fake2)
    r_fail = c.post("/certs/generate", headers={"X-CSRF-Token": csrf}, data={}, follow_redirects=False)
    assert r_fail.status_code in (301, 302, 303, 307, 308)
    assert _qs(r_fail).get("ok") == ["0"]


def test_squid_config_manual_apply_and_validate(app_module, monkeypatch):
    c = app_module.app.test_client()
    csrf = _login(c)

    r_apply = c.post(
        "/squid/config",
        headers={"X-CSRF-Token": csrf},
        data={"action": "apply", "tab": "config", "config_text": "http_port 3128\n"},
        follow_redirects=False,
    )
    assert r_apply.status_code in (301, 302, 303, 307, 308)
    assert _qs(r_apply).get("ok") == ["1"]

    called = {"n": 0}

    def fake_validate(cfg_text: str):
        called["n"] += 1
        return True, "OK"

    monkeypatch.setattr(app_module.squid_controller, "validate_config_text", fake_validate)

    r_val = c.post(
        "/squid/config",
        headers={"X-CSRF-Token": csrf},
        data={"action": "validate", "tab": "config", "config_text": "http_port 3128\n"},
    )
    assert r_val.status_code == 200
    assert called["n"] == 1
