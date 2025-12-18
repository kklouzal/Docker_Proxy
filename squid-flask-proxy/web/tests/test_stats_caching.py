from __future__ import annotations

import time

import services.stats as stats


def _reset_cpu_cache() -> None:
    stats._CACHE_CPU_INFLIGHT = False
    stats._CACHE_CPU_TS = 0.0
    stats._CACHE_CPU_VALUE = None


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
