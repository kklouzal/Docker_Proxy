from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any


class FakeTimeseriesStore:
    def summary(self):
        return {}


class FakeSSLErrorsStore:
    def list_recent(self, *, since: int, search: str, limit: int):
        return []

    def top_domains(self, *, since: int, search: str, limit: int):
        return []


class FakeSocksStore:
    def summary(self, *, since: int):
        return {"total": 0, "clients": 0, "dests": 0}

    def top_clients(self, *, since: int, limit: int, search: str = ""):
        return []

    def top_destinations(self, *, since: int, limit: int, search: str = ""):
        return []

    def recent(self, *, limit: int, since: int, search: str = ""):
        return []


@dataclass
class FakeAdblockStatus:
    key: str
    url: str
    enabled: bool
    rules: int = 0
    bytes: int = 0
    last_success: int = 0
    last_attempt: int = 0
    last_error: str = ""


class FakeAdblockStore:
    def __init__(self, *, statuses: list[FakeAdblockStatus] | None = None):
        self._enabled_map: dict[str, bool] = {}
        self._settings: dict[str, Any] = {}
        self._refresh = False
        self._flush = False
        self.flush_requested = False
        self._statuses = statuses or [FakeAdblockStatus("list1", "https://example/list.txt", True)]

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
        self.flush_requested = True

    def stats(self):
        return {"total": 0, "last_24h": 0, "by_list": {}, "by_list_24h": {}}

    def cache_stats(self):
        return {"hits": 0, "misses": 0, "evictions": 0, "current_size": 0, "last_flush": 0, "last_flush_req": 0}

    def get_update_interval_seconds(self):
        return 3600

    def list_recent_block_events(self, *, limit: int):
        return []


class FakeWebFilterStore:
    def __init__(self, *, local_apply_allowed: bool = True):
        self.saved: dict[str, Any] | None = None
        self._settings: dict[str, Any] | None = None
        self._apply_calls = 0
        self._removed_patterns: list[str] = []
        self.whitelist_result: tuple[bool, str, str] | None = None
        self.local_apply_allowed = local_apply_allowed

    def init_db(self):
        return None

    def set_settings(self, *, enabled: bool, source_url: str, blocked_categories: list[str]):
        self.saved = {
            "enabled": enabled,
            "source_url": source_url,
            "blocked_categories": blocked_categories,
        }
        self._settings = dict(self.saved)

    def apply_squid_include(self):
        if not self.local_apply_allowed:
            raise AssertionError("control-plane tests should not apply local webfilter includes")
        self._apply_calls += 1
        return None

    def add_whitelist(self, entry: str):
        if self.whitelist_result is not None:
            return self.whitelist_result
        normalized = entry.strip().lower() or "example.com"
        return True, "", normalized

    def remove_whitelist(self, pat: str):
        self._removed_patterns.append(pat)
        return None

    def get_settings(self):
        if self._settings is None:
            return SimpleNamespace(enabled=False, source_url="", blocked_categories=[])
        return SimpleNamespace(**self._settings)

    def list_available_categories(self):
        return [("adult", 123), ("games", 45)]

    def list_whitelist(self):
        return []

    def list_blocked_log(self, limit: int = 200):
        return []

    def test_domain(self, domain: str):
        d = (domain or "").strip().lower()
        return {"ok": True, "domain": d, "verdict": "allowed", "reason": "stub"}


class FakeSSLFilterStore:
    def __init__(self, *, local_apply_allowed: bool = True):
        self._apply_calls = 0
        self.local_apply_allowed = local_apply_allowed

    def init_db(self):
        return None

    def add_nobump(self, entry: str):
        normalized = entry.strip() or "10.0.0.0/8"
        return True, "", normalized

    def remove_nobump(self, cidr: str):
        return None

    def apply_squid_include(self):
        if not self.local_apply_allowed:
            raise AssertionError("control-plane tests should not apply local sslfilter includes")
        self._apply_calls += 1
        return None

    def list_nobump(self):
        return []


class FakePacProfilesStore:
    def __init__(self):
        self.upserts: list[dict[str, Any]] = []
        self.deletes: list[int] = []
        self.upsert_result: tuple[bool, str, int] = (True, "", 1)

    def match_profile_for_client_ip(self, ip: str):
        return None

    def upsert_profile(self, **kwargs):
        self.upserts.append(dict(kwargs))
        return self.upsert_result

    def delete_profile(self, pid: int):
        self.deletes.append(int(pid))
        return None

    def list_profiles(self):
        return []


class FakeExclusionsStore:
    def __init__(self):
        self.domains: list[str] = []
        self.added_domains: list[str] = []
        self.src_nets: list[str] = []
        self.dst_nets: list[str] = []
        self._ex = SimpleNamespace(
            domains=self.domains,
            src_nets=self.src_nets,
            dst_nets=self.dst_nets,
            exclude_private_nets=False,
        )

    def add_domain(self, domain: str):
        normalized = domain.strip().lower().lstrip(".")
        self.domains.append(normalized)
        self.added_domains.append(normalized)
        return True, ""

    def remove_domain(self, domain: str):
        normalized = domain.strip().lower().lstrip(".")
        if normalized in self.domains:
            self.domains.remove(normalized)

    def add_net(self, kind: str, cidr: str):
        if kind == "src_nets":
            self.src_nets.append(cidr)
        elif kind == "dst_nets":
            self.dst_nets.append(cidr)
        return True, ""

    def remove_net(self, kind: str, cidr: str):
        target = self.src_nets if kind == "src_nets" else self.dst_nets
        if cidr in target:
            target.remove(cidr)
        return None

    def set_exclude_private_nets(self, enabled: bool):
        self._ex.exclude_private_nets = bool(enabled)

    def list_all(self):
        return self._ex


class FakeDiagnosticStore:
    def activity_summary(self, *, since: int | None = None):
        return {
            "requests": 0,
            "clients": 0,
            "domains": 0,
            "transactions": 0,
            "icap_events": 0,
            "av_icap_events": 0,
            "adblock_icap_events": 0,
        }

    def list_recent_requests(self, *, since: int | None = None, search: str = "", client_ip: str = "", domain: str = "", master_xaction: str = "", limit: int = 50):
        return []

    def list_recent_transactions(self, *, since: int | None = None, search: str = "", client_ip: str = "", domain: str = "", master_xaction: str = "", service: str = "", limit: int = 50, icap_limit_per_transaction: int = 5):
        return []

    def find_request_by_master_xaction(self, master_xaction: str):
        return None

    def list_recent_icap(self, *, since: int | None = None, search: str = "", client_ip: str = "", domain: str = "", master_xaction: str = "", service: str = "", limit: int = 50):
        return []

    def list_icap_by_master_xaction(self, master_xaction: str, *, limit: int = 20):
        return []

    def list_request_candidates_for_domain_near_ts(self, *, domain: str, around_ts: int, window_seconds: int = 300, limit: int = 5, service: str = "", icap_limit_per_transaction: int = 5):
        return []

    def list_icap_candidates_for_domain_near_ts(self, *, domain: str, around_ts: int, window_seconds: int = 300, service: str = "", limit: int = 5):
        return []

    def list_request_candidates_for_policy_event(self, *, around_ts: int, url: str = "", client_ip: str = "", domain: str = "", window_seconds: int = 300, limit: int = 5, service: str = "", icap_limit_per_transaction: int = 5):
        return []

    def top_request_dimension(self, dimension: str, *, since: int | None = None, limit: int = 10):
        return []

    def top_policy_tags(self, *, since: int | None = None, limit: int = 10):
        return []

    def slowest_requests(self, *, since: int | None = None, limit: int = 10):
        return []

    def icap_summary(self, *, since: int | None = None, service: str = ""):
        return {"events": 0, "avg_icap_time_ms": 0, "max_icap_time_ms": 0}

    def slowest_icap_events(self, *, since: int | None = None, service: str = "", limit: int = 10):
        return []


class FakeAuditStore:
    def latest_config_apply(self):
        return None


class FakeCompletedProcess:
    returncode = 0
    stdout = ""
    stderr = ""


COMMON_STATS = {
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
}


def install_common_ui_test_doubles(monkeypatch, app_module):
    # Avoid real socket/subprocess health checks during unit tests.
    monkeypatch.setattr(app_module, "_check_icap_adblock", lambda: {"ok": True, "detail": "stub"})
    monkeypatch.setattr(app_module, "_check_clamd", lambda: {"ok": True, "detail": "stub"})
    monkeypatch.setattr(app_module, "_check_icap_av", lambda: {"ok": True, "detail": "stub", "target": "127.0.0.1:14001"})
    if hasattr(app_module, "_check_dante"):
        monkeypatch.setattr(app_module, "_check_dante", lambda: {"ok": True, "detail": "stub", "target": "127.0.0.1:1080"})
    if hasattr(app_module, "_check_tcp"):
        monkeypatch.setattr(app_module, "_check_tcp", lambda host, port, timeout=0.6: {"ok": True, "detail": "stub"})
    if hasattr(app_module, "_check_icap_service"):
        monkeypatch.setattr(app_module, "_check_icap_service", lambda host, port, service: {"ok": True, "detail": "stub"})

    calls = {"reload": 0, "clear": 0, "apply": 0}

    def fake_get_status():
        return (b"OK\n", b"")

    def fake_get_current_config():
        return "http_port 3128\n"

    def fake_apply_config_text(cfg_text: str):
        calls["apply"] += 1
        return True, "ok"

    def fake_reload():
        calls["reload"] += 1

    def fake_clear():
        calls["clear"] += 1

    class FakeProxyClient:
        def sync_proxy(self, proxy_id: str, force: bool = False):
            calls["reload"] += 1
            return {"ok": True, "detail": f"sync requested for {proxy_id}", "force": force}

        def clear_proxy_cache(self, proxy_id: str):
            calls["clear"] += 1
            return {"ok": True, "detail": f"cache clear requested for {proxy_id}"}

        def get_health(self, proxy_id: str, timeout_seconds: float = 1.5):
            return {
                "ok": True,
                "status": "healthy",
                "proxy_status": "OK",
                "stats": COMMON_STATS,
                "services": {
                    "icap": {"ok": True, "detail": "stub"},
                    "clamav": {"ok": True, "detail": "stub"},
                    "dante": {"ok": True, "detail": "stub"},
                    "clamd": {"ok": True, "detail": "stub"},
                    "av_icap": {"ok": True, "detail": "stub"},
                },
            }

        def test_clamav_eicar(self, proxy_id: str):
            return {"ok": True, "detail": f"eicar requested for {proxy_id}"}

        def test_clamav_icap(self, proxy_id: str):
            return {"ok": True, "detail": f"icap requested for {proxy_id}"}

    monkeypatch.setattr(app_module.squid_controller, "get_status", fake_get_status)
    monkeypatch.setattr(app_module.squid_controller, "get_current_config", fake_get_current_config)
    monkeypatch.setattr(app_module.squid_controller, "apply_config_text", fake_apply_config_text)
    monkeypatch.setattr(app_module.squid_controller, "reload_squid", fake_reload)
    monkeypatch.setattr(app_module.squid_controller, "clear_disk_cache", fake_clear)

    if hasattr(app_module, "get_stats"):
        monkeypatch.setattr(app_module, "get_stats", lambda: COMMON_STATS)
    monkeypatch.setattr(app_module, "get_timeseries_store", lambda: FakeTimeseriesStore())
    monkeypatch.setattr(app_module, "get_ssl_errors_store", lambda: FakeSSLErrorsStore())

    fake_ex_store = FakeExclusionsStore()
    fake_adblock_store = FakeAdblockStore()
    fake_webfilter_store = FakeWebFilterStore()
    fake_sslfilter_store = FakeSSLFilterStore()
    fake_pac_profiles = FakePacProfilesStore()

    monkeypatch.setattr(app_module, "get_exclusions_store", lambda: fake_ex_store)
    monkeypatch.setattr(app_module, "get_socks_store", lambda: FakeSocksStore())
    monkeypatch.setattr(app_module, "get_adblock_store", lambda: fake_adblock_store)
    monkeypatch.setattr(app_module, "get_webfilter_store", lambda: fake_webfilter_store)
    monkeypatch.setattr(app_module, "get_sslfilter_store", lambda: fake_sslfilter_store)
    monkeypatch.setattr(app_module, "get_pac_profiles_store", lambda: fake_pac_profiles)
    monkeypatch.setattr(app_module, "get_diagnostic_store", lambda: FakeDiagnosticStore())
    monkeypatch.setattr(app_module, "get_audit_store", lambda: FakeAuditStore())
    monkeypatch.setattr(app_module, "get_proxy_client", lambda: FakeProxyClient())

    import subprocess

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeCompletedProcess())

    app_module._test_calls = calls  # type: ignore[attr-defined]
    app_module._test_fake_ex_store = fake_ex_store  # type: ignore[attr-defined]
    app_module._test_adblock_store = fake_adblock_store  # type: ignore[attr-defined]
    app_module._test_webfilter_store = fake_webfilter_store  # type: ignore[attr-defined]
    app_module._test_sslfilter_store = fake_sslfilter_store  # type: ignore[attr-defined]
    app_module._test_pac_profiles_store = fake_pac_profiles  # type: ignore[attr-defined]
    return app_module
