from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from services.short_lived_cache import KeyedSingleFlight


def test_same_key_miss_runs_builder_once_and_returns_copies() -> None:
    coordinator = KeyedSingleFlight()
    cache = {}
    entered = threading.Event()
    release = threading.Event()
    calls = 0

    def builder():
        nonlocal calls
        calls += 1
        entered.set()
        assert release.wait(2)
        return {"calls": calls}

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(
            coordinator.get_or_build,
            cache,
            "same",
            now=lambda: 10.0,
            ttl_seconds=5.0,
            builder=builder,
            copy_value=dict,
        )
        assert entered.wait(2)
        second = pool.submit(
            coordinator.get_or_build,
            cache,
            "same",
            now=lambda: 10.0,
            ttl_seconds=5.0,
            builder=builder,
            copy_value=dict,
        )
        release.set()
        first_value = first.result(timeout=2)
        second_value = second.result(timeout=2)

    assert calls == 1
    assert first_value == second_value == {"calls": 1}
    assert first_value is not second_value
    assert first_value is not cache["same"][1]


def test_different_keys_refresh_independently() -> None:
    coordinator = KeyedSingleFlight()
    cache = {}
    both_entered = threading.Barrier(3)
    release = threading.Event()

    def build(value: str):
        both_entered.wait(timeout=2)
        assert release.wait(2)
        return value

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(
                coordinator.get_or_build,
                cache,
                key,
                now=lambda: 10.0,
                ttl_seconds=5.0,
                builder=lambda key=key: build(key),
                copy_value=lambda value: value,
            )
            for key in ("a", "b")
        ]
        both_entered.wait(timeout=2)
        release.set()
        assert [future.result(timeout=2) for future in futures] == ["a", "b"]


def test_clear_during_refresh_prevents_stale_repopulation() -> None:
    coordinator = KeyedSingleFlight()
    cache = {"old": (1.0, "old")}
    entered = threading.Event()
    release = threading.Event()

    def builder():
        entered.set()
        assert release.wait(2)
        return "stale-refresh"

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(
            coordinator.get_or_build,
            cache,
            "key",
            now=lambda: 10.0,
            ttl_seconds=0.0,
            builder=builder,
            copy_value=lambda value: value,
        )
        assert entered.wait(2)
        coordinator.clear(cache)
        release.set()
        assert future.result(timeout=2) == "stale-refresh"

    assert cache == {}


def test_builder_failure_keeps_existing_stale_value() -> None:
    coordinator = KeyedSingleFlight()
    cache = {"key": (1.0, {"old": True})}

    def fail():
        detail = "no refresh"
        raise RuntimeError(detail)

    with pytest.raises(RuntimeError, match="no refresh"):
        coordinator.get_or_build(
            cache,
            "key",
            now=lambda: 10.0,
            ttl_seconds=1.0,
            builder=fail,
            copy_value=dict,
        )

    assert cache == {"key": (1.0, {"old": True})}
