import os
import sys
import tempfile

from types import SimpleNamespace

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
        def init_db(self):
            return None

        def list_statuses(self):
            return [Status("list1", "https://example/list.txt", True)]

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

    monkeypatch.setattr(app_module, "get_adblock_store", lambda: FakeAdblockStore())

    class FakeWebfilterStore:
        def init_db(self):
            return None

        def set_settings(self, *, enabled: bool, source_url: str, blocked_categories: list[str]):
            self._settings = {"enabled": enabled, "source_url": source_url, "blocked_categories": blocked_categories}

        def apply_squid_include(self):
            return None

        def add_whitelist(self, entry: str):
            return True, "", entry.strip().lower() or "example.com"

        def remove_whitelist(self, pat: str):
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

    monkeypatch.setattr(app_module, "get_webfilter_store", lambda: FakeWebfilterStore())

    class FakeSSLFilterStore:
        def init_db(self):
            return None

        def add_nobump(self, entry: str):
            return True, "", entry.strip() or "10.0.0.0/8"

        def remove_nobump(self, cidr: str):
            return None

        def apply_squid_include(self):
            return None

        def list_nobump(self):
            return []

    monkeypatch.setattr(app_module, "get_sslfilter_store", lambda: FakeSSLFilterStore())

    class FakePacProfiles:
        def match_profile_for_client_ip(self, ip: str):
            return None

        def upsert_profile(self, **kwargs):
            return True, "", 1

        def delete_profile(self, pid: int):
            return None

        def list_profiles(self):
            return []

    monkeypatch.setattr(app_module, "get_pac_profiles_store", lambda: FakePacProfiles())

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
