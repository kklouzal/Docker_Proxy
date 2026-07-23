from __future__ import annotations

import time
from typing import NoReturn

import pytest
from services import stats


def _reset_cpu_cache() -> None:
    stats._CACHE_CPU_INFLIGHT = False
    stats._CACHE_CPU_TS = 0.0
    stats._CACHE_CPU_VALUE = None


def _reset_hit_rate_cache() -> None:
    stats._CACHE_HIT_RATE_INFLIGHT = False
    stats._CACHE_HIT_RATE_TS = 0.0
    stats._CACHE_HIT_RATE_VALUE = None
    stats._CACHE_HIT_RATE_SOURCE_VALUE = ""


def _reset_stats_caches() -> None:
    stats._CACHE_DIR_SIZE_INFLIGHT = False
    stats._CACHE_DIR_SIZE_TS = 0.0
    stats._CACHE_DIR_SIZE_VALUE = None
    stats._CACHE_DISK_USAGE_INFLIGHT = False
    stats._CACHE_DISK_USAGE_TS = 0.0
    stats._CACHE_DISK_USAGE_VALUE = None
    _reset_hit_rate_cache()
    _reset_cpu_cache()


def test_get_stats_caches_cpu(monkeypatch) -> None:
    # Make TTL long enough that a second call should reuse cached values.
    monkeypatch.setenv("STATS_CACHE_CPU_TTL_SECONDS", "60")
    _reset_cpu_cache()

    calls = {"cpu": 0, "load": 0}

    def fake_cpu(sample_seconds: float = 0.15) -> float:
        calls["cpu"] += 1
        return 12.34

    def fake_load():
        calls["load"] += 1
        return {"1m": 1.0, "5m": 0.5, "15m": 0.25}

    monkeypatch.setattr(stats, "get_cpu_utilization_percent", fake_cpu)
    monkeypatch.setattr(stats, "get_loadavg", fake_load)

    a = stats.get_stats()
    b = stats.get_stats()

    assert a["cpu"]["util_percent"] == pytest.approx(12.34)
    assert b["cpu"]["util_percent"] == pytest.approx(12.34)
    assert calls["cpu"] == 1
    assert calls["load"] == 1


def test_get_stats_cpu_cache_expires(monkeypatch) -> None:
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


def test_get_stats_invalid_ttl_env_falls_back_without_crashing(monkeypatch) -> None:
    _reset_stats_caches()
    monkeypatch.setenv("STATS_CACHE_DIR_SIZE_TTL_SECONDS", "abc")
    monkeypatch.setenv("STATS_CACHE_DISK_USAGE_TTL_SECONDS", "bad")
    monkeypatch.setenv("STATS_CACHE_HIT_RATE_TTL_SECONDS", "nope")
    monkeypatch.setenv("STATS_CACHE_CPU_TTL_SECONDS", "not-an-int")

    calls = {"dir": 0, "disk": 0, "hit": 0, "cpu": 0, "load": 0}

    def fake_dir_size(path: str) -> int:
        calls["dir"] += 1
        return 1024

    def fake_disk_usage(path: str) -> stats.DiskUsage:
        calls["disk"] += 1
        return stats.DiskUsage(total_bytes=100, used_bytes=40, free_bytes=60)

    def fake_hit_rate() -> dict[str, float | None]:
        calls["hit"] += 1
        return {"request_hit_ratio": 10.0, "byte_hit_ratio": 20.0}

    def fake_cpu(sample_seconds: float = 0.15) -> float:
        calls["cpu"] += 1
        return 12.34

    def fake_load():
        calls["load"] += 1
        return {"1m": 1.0, "5m": 0.5, "15m": 0.25}

    monkeypatch.setattr(stats, "get_meminfo", lambda: {"total": 10, "available": 4})
    monkeypatch.setattr(stats, "get_directory_size_bytes", fake_dir_size)
    monkeypatch.setattr(stats, "get_disk_usage", fake_disk_usage)
    monkeypatch.setattr(stats, "parse_access_log_hit_rate", fake_hit_rate)
    monkeypatch.setattr(stats, "get_squid_mgr_text", lambda section: None)
    monkeypatch.setattr(stats, "get_cpu_utilization_percent", fake_cpu)
    monkeypatch.setattr(stats, "get_loadavg", fake_load)

    first = stats.get_stats()
    second = stats.get_stats()

    assert first["cpu"]["util_percent"] == pytest.approx(12.34)
    assert second["storage"]["cache_dir_size_bytes"] == 1024
    assert calls == {"dir": 1, "disk": 1, "hit": 1, "cpu": 1, "load": 1}


def test_get_stats_ttl_env_values_are_clamped_to_existing_minimums(monkeypatch) -> None:
    _reset_stats_caches()
    monkeypatch.setenv("STATS_CACHE_DIR_SIZE_TTL_SECONDS", "0")
    monkeypatch.setenv("STATS_CACHE_DISK_USAGE_TTL_SECONDS", "0")
    monkeypatch.setenv("STATS_CACHE_HIT_RATE_TTL_SECONDS", "0")
    monkeypatch.setenv("STATS_CACHE_CPU_TTL_SECONDS", "0")

    calls = {"dir": 0, "disk": 0, "hit": 0, "cpu": 0, "load": 0}

    monkeypatch.setattr(stats, "get_meminfo", lambda: {"total": 10, "available": 4})
    monkeypatch.setattr(
        stats,
        "get_directory_size_bytes",
        lambda path: calls.__setitem__("dir", calls["dir"] + 1) or 1024,
    )
    monkeypatch.setattr(
        stats,
        "get_disk_usage",
        lambda path: calls.__setitem__("disk", calls["disk"] + 1)
        or stats.DiskUsage(total_bytes=100, used_bytes=40, free_bytes=60),
    )
    monkeypatch.setattr(
        stats,
        "parse_access_log_hit_rate",
        lambda: calls.__setitem__("hit", calls["hit"] + 1)
        or {"request_hit_ratio": 10.0, "byte_hit_ratio": 20.0},
    )
    monkeypatch.setattr(stats, "get_squid_mgr_text", lambda section: None)
    monkeypatch.setattr(
        stats,
        "get_cpu_utilization_percent",
        lambda sample_seconds=0.15: calls.__setitem__("cpu", calls["cpu"] + 1)
        or 12.34,
    )
    monkeypatch.setattr(
        stats,
        "get_loadavg",
        lambda: calls.__setitem__("load", calls["load"] + 1)
        or {"1m": 1.0, "5m": 0.5, "15m": 0.25},
    )

    stats.get_stats()
    stats.get_stats()

    assert calls == {"dir": 1, "disk": 1, "hit": 1, "cpu": 1, "load": 1}


def test_cachemgr_is_opt_in(monkeypatch) -> None:
    _reset_hit_rate_cache()

    # Even if squidclient exists, we should not call it unless STATS_USE_CACHEMGR is enabled.
    monkeypatch.delenv("STATS_USE_CACHEMGR", raising=False)

    monkeypatch.setattr(stats.shutil, "which", lambda name: "/usr/bin/squidclient")

    called = {"run": 0}

    def fake_run(*args, **kwargs) -> NoReturn:
        called["run"] += 1
        msg = "subprocess.run should not be called when STATS_USE_CACHEMGR is disabled"
        raise AssertionError(msg)

    monkeypatch.setattr(stats.subprocess, "run", fake_run)
    assert stats.get_squid_mgr_text("info") is None
    assert called["run"] == 0


def test_cachemgr_sanitizes_proxy_env(monkeypatch) -> None:
    _reset_hit_rate_cache()
    monkeypatch.setenv("STATS_USE_CACHEMGR", "1")
    monkeypatch.setattr(stats.shutil, "which", lambda name: "/usr/bin/squidclient")

    # Simulate a proxied container environment.
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:3128")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:3128")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:3128")
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
