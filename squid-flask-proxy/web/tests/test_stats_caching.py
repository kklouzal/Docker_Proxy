from __future__ import annotations

import time

import services.stats as stats


def _reset_cpu_cache() -> None:
    stats._CACHE_CPU_INFLIGHT = False
    stats._CACHE_CPU_TS = 0.0
    stats._CACHE_CPU_VALUE = None


def _reset_hit_rate_cache() -> None:
    stats._CACHE_HIT_RATE_INFLIGHT = False
    stats._CACHE_HIT_RATE_TS = 0.0
    stats._CACHE_HIT_RATE_VALUE = None
    stats._CACHE_HIT_RATE_SOURCE_VALUE = ""


def test_get_stats_caches_cpu(monkeypatch):
    # Make TTL long enough that a second call should reuse cached values.
    monkeypatch.setenv("STATS_CACHE_CPU_TTL_SECONDS", "60")
    _reset_cpu_cache()

    calls = {"cpu": 0, "load": 0}

    def fake_cpu(sample_seconds: float = 0.15):
        calls["cpu"] += 1
        return 12.34

    def fake_load():
        calls["load"] += 1
        return {"1m": 1.0, "5m": 0.5, "15m": 0.25}

    monkeypatch.setattr(stats, "get_cpu_utilization_percent", fake_cpu)
    monkeypatch.setattr(stats, "get_loadavg", fake_load)

    a = stats.get_stats()
    b = stats.get_stats()

    assert a["cpu"]["util_percent"] == 12.34
    assert b["cpu"]["util_percent"] == 12.34
    assert calls["cpu"] == 1
    assert calls["load"] == 1


def test_get_stats_cpu_cache_expires(monkeypatch):
    monkeypatch.setenv("STATS_CACHE_CPU_TTL_SECONDS", "1")
    _reset_cpu_cache()

    calls = {"cpu": 0}

    def fake_cpu(sample_seconds: float = 0.15):
        calls["cpu"] += 1
        return float(calls["cpu"])

    monkeypatch.setattr(stats, "get_cpu_utilization_percent", fake_cpu)
    monkeypatch.setattr(stats, "get_loadavg", lambda: None)

    first = stats.get_stats()["cpu"]["util_percent"]
    time.sleep(1.05)
    second = stats.get_stats()["cpu"]["util_percent"]

    assert first != second
    assert calls["cpu"] >= 2


def test_cachemgr_is_opt_in(monkeypatch):
    _reset_hit_rate_cache()

    # Even if squidclient exists, we should not call it unless STATS_USE_CACHEMGR is enabled.
    monkeypatch.delenv("STATS_USE_CACHEMGR", raising=False)

    monkeypatch.setattr(stats.shutil, "which", lambda name: "/usr/bin/squidclient")

    called = {"run": 0}

    def fake_run(*args, **kwargs):
        called["run"] += 1
        raise AssertionError("subprocess.run should not be called when STATS_USE_CACHEMGR is disabled")

    monkeypatch.setattr(stats.subprocess, "run", fake_run)
    assert stats.get_squid_mgr_text("info") is None
    assert called["run"] == 0


def test_cachemgr_sanitizes_proxy_env(monkeypatch):
    _reset_hit_rate_cache()
    monkeypatch.setenv("STATS_USE_CACHEMGR", "1")
    monkeypatch.setattr(stats.shutil, "which", lambda name: "/usr/bin/squidclient")

    # Simulate a proxied container environment.
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:3128")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:3128")
    monkeypatch.setenv("ALL_PROXY", "socks5://127.0.0.1:1080")
    monkeypatch.setenv("NO_PROXY", "example.com")

    captured = {"env": None}

    class P:
        returncode = 0
        stdout = "OK"

    def fake_run(cmd, capture_output, text, timeout, env=None):
        captured["env"] = env
        return P()

    monkeypatch.setattr(stats.subprocess, "run", fake_run)
    out = stats.get_squid_mgr_text("info")
    assert out == "OK"

    env = captured["env"]
    assert env is not None
    assert "HTTP_PROXY" not in env
    assert "HTTPS_PROXY" not in env
    assert "ALL_PROXY" not in env
    assert "127.0.0.1" in env.get("NO_PROXY", "")
    assert "localhost" in env.get("NO_PROXY", "")
