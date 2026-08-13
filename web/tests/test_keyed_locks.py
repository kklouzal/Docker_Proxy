from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from services.keyed_locks import KeyedLockRegistry


def test_keyed_lock_registry_retains_entry_for_owner_and_waiter() -> None:
    registry = KeyedLockRegistry[str]()
    owner_entered = threading.Event()
    release_owner = threading.Event()
    waiter_entered = threading.Event()
    release_waiter = threading.Event()

    def owner() -> None:
        with registry.locked(["target"]):
            owner_entered.set()
            assert release_owner.wait(5)

    def waiter() -> None:
        assert owner_entered.wait(5)
        with registry.locked(["target"]):
            waiter_entered.set()
            assert release_waiter.wait(5)

    with ThreadPoolExecutor(max_workers=2) as executor:
        owner_future = executor.submit(owner)
        waiter_future = executor.submit(waiter)
        assert owner_entered.wait(5)
        assert len(registry) == 1
        assert not waiter_entered.wait(0.1)
        release_owner.set()
        assert waiter_entered.wait(5)
        owner_future.result(timeout=5)
        assert len(registry) == 1
        release_waiter.set()
        waiter_future.result(timeout=5)

    assert len(registry) == 0


def test_keyed_lock_registry_releases_high_cardinality_churn() -> None:
    registry = KeyedLockRegistry[str]()

    for index in range(256):
        with registry.locked([f"target-{index}"]):
            assert len(registry) == 1

    assert len(registry) == 0


def test_keyed_lock_registry_orders_multi_key_acquisition() -> None:
    registry = KeyedLockRegistry[str]()
    first_entered = threading.Event()
    release_first = threading.Event()
    second_entered = threading.Event()

    def first() -> None:
        with registry.locked(["b", "a"]):
            first_entered.set()
            assert release_first.wait(5)

    def second() -> None:
        assert first_entered.wait(5)
        with registry.locked(["a", "b"]):
            second_entered.set()

    with ThreadPoolExecutor(max_workers=2) as executor:
        first_future = executor.submit(first)
        second_future = executor.submit(second)
        assert first_entered.wait(5)
        assert not second_entered.wait(0.1)
        release_first.set()
        first_future.result(timeout=5)
        second_future.result(timeout=5)

    assert second_entered.is_set()
    assert len(registry) == 0
