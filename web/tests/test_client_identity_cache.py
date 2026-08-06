from __future__ import annotations

import socket
import sys
import threading
import time
from pathlib import Path


def _add_web_to_path() -> None:
    web_dir = Path(__file__).resolve().parents[1]
    if str(web_dir) not in sys.path:
        sys.path.insert(0, str(web_dir))


_add_web_to_path()
from services.client_identity_cache import (  # type: ignore  # noqa: E402
    _REVERSE_DNS_LOOKUP_THREAD_LIMIT,
    ClientIdentityCache,
)


def test_client_identity_cache_invalid_ip_returns_invalid_without_lookup(
    monkeypatch,
) -> None:
    cache = ClientIdentityCache()
    monkeypatch.setattr(
        cache,
        "_lookup_hostname",
        lambda _ip: (_ for _ in ()).throw(AssertionError("lookup called")),
    )

    assert cache.resolve("not an ip") == {
        "hostname": "",
        "hostname_source": "",
        "hostname_status": "invalid",
    }


def test_client_identity_cache_resolve_uses_lookup_once_then_cache(monkeypatch) -> None:
    cache = ClientIdentityCache(success_ttl_seconds=30.0)
    calls: list[str] = []

    def fake_lookup(ip: str) -> tuple[str, str, str]:
        calls.append(ip)
        return "host.example", "rdns", "resolved"

    monkeypatch.setattr(cache, "_lookup_hostname", fake_lookup)

    assert cache.resolve("192.0.2.10")["hostname"] == "host.example"
    assert cache.resolve("192.0.2.10")["hostname"] == "host.example"
    assert calls == ["192.0.2.10"]


def test_client_identity_cache_coalesces_concurrent_normalized_misses(
    monkeypatch,
) -> None:
    cache = ClientIdentityCache(
        success_ttl_seconds=30.0,
        lookup_timeout_seconds=0.5,
    )
    first_lookup_started = threading.Event()
    duplicate_started = threading.Event()
    first_resolve_finished = threading.Event()
    calls_lock = threading.Lock()
    calls: list[str] = []
    results: dict[str, dict[str, str]] = {}

    def fake_lookup(ip: str) -> tuple[str, str, str]:
        with calls_lock:
            calls.append(ip)
            call_number = len(calls)
        if call_number == 1:
            first_lookup_started.set()
            duplicate_started.wait(timeout=0.2)
            return "host.example", "rdns", "resolved"
        duplicate_started.set()
        first_resolve_finished.wait(timeout=0.5)
        return "", "", "unresolved"

    def resolve_first() -> None:
        results["first"] = cache.resolve("2001:0db8::1")
        first_resolve_finished.set()

    def resolve_second() -> None:
        results["second"] = cache.resolve("2001:db8::1")

    monkeypatch.setattr(cache, "_lookup_hostname", fake_lookup)
    threads = [
        threading.Thread(target=resolve_first),
        threading.Thread(target=resolve_second),
    ]
    threads[0].start()
    assert first_lookup_started.wait(timeout=0.5)
    threads[1].start()
    for thread in threads:
        thread.join(timeout=1.0)

    assert all(not thread.is_alive() for thread in threads)
    assert cache.resolve("2001:db8::1")["hostname"] == "host.example"
    assert calls == ["2001:db8::1"]
    assert results == {
        "first": {
            "hostname": "host.example",
            "hostname_source": "rdns",
            "hostname_status": "resolved",
        },
        "second": {
            "hostname": "host.example",
            "hostname_source": "rdns",
            "hostname_status": "resolved",
        },
    }


def test_client_identity_cache_inflight_wait_is_bounded_without_cache_poisoning(
    monkeypatch,
) -> None:
    cache = ClientIdentityCache(
        success_ttl_seconds=30.0,
        lookup_timeout_seconds=0.05,
    )
    lookup_started = threading.Event()
    release_lookup = threading.Event()
    owner_result: list[dict[str, str]] = []
    calls: list[str] = []

    def slow_lookup(ip: str) -> tuple[str, str, str]:
        calls.append(ip)
        lookup_started.set()
        release_lookup.wait(timeout=1.0)
        return "host.example", "rdns", "resolved"

    monkeypatch.setattr(cache, "_lookup_hostname", slow_lookup)
    owner = threading.Thread(
        target=lambda: owner_result.append(cache.resolve("192.0.2.10"))
    )
    owner.start()
    assert lookup_started.wait(timeout=0.5)

    started_at = time.monotonic()
    waiting_result = cache.resolve("192.0.2.10")
    elapsed = time.monotonic() - started_at

    assert waiting_result == {
        "hostname": "",
        "hostname_source": "",
        "hostname_status": "unresolved",
    }
    assert 0.04 <= elapsed < 0.25
    assert "192.0.2.10" not in cache._cache

    release_lookup.set()
    owner.join(timeout=0.5)
    assert not owner.is_alive()
    assert calls == ["192.0.2.10"]
    assert owner_result[0]["hostname"] == "host.example"
    assert cache.resolve("192.0.2.10")["hostname"] == "host.example"


def test_client_identity_cache_owner_failure_releases_waiter_and_allows_retry(
    monkeypatch,
) -> None:
    cache = ClientIdentityCache(
        success_ttl_seconds=30.0,
        lookup_timeout_seconds=0.5,
    )
    lookup_started = threading.Event()
    release_lookup = threading.Event()
    waiter_started = threading.Event()
    calls: list[str] = []
    owner_errors: list[Exception] = []
    waiter_results: list[dict[str, str]] = []

    def flaky_lookup(ip: str) -> tuple[str, str, str]:
        calls.append(ip)
        if len(calls) == 1:
            lookup_started.set()
            release_lookup.wait(timeout=1.0)
            msg = "unexpected resolver failure"
            raise RuntimeError(msg)
        return "recovered.example", "rdns", "resolved"

    def resolve_owner() -> None:
        try:
            cache.resolve("192.0.2.10")
        except Exception as exc:
            owner_errors.append(exc)

    monkeypatch.setattr(cache, "_lookup_hostname", flaky_lookup)
    owner = threading.Thread(target=resolve_owner)
    owner.start()
    assert lookup_started.wait(timeout=0.5)

    inflight = cache._inflight["192.0.2.10"]
    original_wait = inflight.wait

    def observed_wait(timeout: float | None = None) -> bool:
        waiter_started.set()
        return original_wait(timeout=timeout)

    monkeypatch.setattr(inflight, "wait", observed_wait)
    waiter = threading.Thread(
        target=lambda: waiter_results.append(cache.resolve("192.0.2.10"))
    )
    waiter.start()
    assert waiter_started.wait(timeout=0.5)
    release_lookup.set()

    owner.join(timeout=0.5)
    waiter.join(timeout=0.5)
    assert not owner.is_alive()
    assert not waiter.is_alive()
    assert len(owner_errors) == 1
    assert isinstance(owner_errors[0], RuntimeError)
    assert waiter_results == [
        {
            "hostname": "",
            "hostname_source": "",
            "hostname_status": "unresolved",
        }
    ]
    assert "192.0.2.10" not in cache._cache
    assert "192.0.2.10" not in cache._inflight

    assert cache.resolve("192.0.2.10")["hostname"] == "recovered.example"
    assert calls == ["192.0.2.10", "192.0.2.10"]


def test_client_identity_cache_distinct_misses_resolve_in_parallel(monkeypatch) -> None:
    cache = ClientIdentityCache(
        success_ttl_seconds=30.0,
        lookup_timeout_seconds=0.5,
    )
    calls_lock = threading.Lock()
    both_started = threading.Event()
    release_lookups = threading.Event()
    calls: list[str] = []
    results: list[dict[str, str]] = []

    def parallel_lookup(ip: str) -> tuple[str, str, str]:
        with calls_lock:
            calls.append(ip)
            if len(calls) == 2:
                both_started.set()
        release_lookups.wait(timeout=0.5)
        return f"host-{ip}.example", "rdns", "resolved"

    monkeypatch.setattr(cache, "_lookup_hostname", parallel_lookup)
    threads = [
        threading.Thread(target=lambda: results.append(cache.resolve("192.0.2.10"))),
        threading.Thread(target=lambda: results.append(cache.resolve("192.0.2.11"))),
    ]
    for thread in threads:
        thread.start()

    assert both_started.wait(timeout=0.5)
    release_lookups.set()
    for thread in threads:
        thread.join(timeout=0.5)

    assert all(not thread.is_alive() for thread in threads)
    assert set(calls) == {"192.0.2.10", "192.0.2.11"}
    assert {result["hostname"] for result in results} == {
        "host-192.0.2.10.example",
        "host-192.0.2.11.example",
    }


def test_client_identity_cache_distinct_misses_respect_global_lookup_limit(
    monkeypatch,
) -> None:
    cache = ClientIdentityCache(
        success_ttl_seconds=30.0,
        lookup_timeout_seconds=0.5,
    )
    calls_lock = threading.Lock()
    lookup_slots_full = threading.Event()
    release_lookups = threading.Event()
    calls: list[str] = []
    results: dict[str, dict[str, str]] = {}

    def blocked_lookup(ip: str) -> tuple[str, list[str], list[str]]:
        with calls_lock:
            calls.append(ip)
            if len(calls) == _REVERSE_DNS_LOOKUP_THREAD_LIMIT:
                lookup_slots_full.set()
        release_lookups.wait(timeout=1.0)
        return f"host-{ip}.example", [], []

    monkeypatch.setattr(
        "services.client_identity_cache.socket.gethostbyaddr",
        blocked_lookup,
    )
    active_ips = [
        f"192.0.2.{index}" for index in range(1, _REVERSE_DNS_LOOKUP_THREAD_LIMIT + 1)
    ]
    overflow_ips = ["192.0.2.101", "192.0.2.102"]
    active_threads = [
        threading.Thread(
            target=lambda ip=ip: results.__setitem__(ip, cache.resolve(ip))
        )
        for ip in active_ips
    ]
    overflow_threads = [
        threading.Thread(
            target=lambda ip=ip: results.__setitem__(ip, cache.resolve(ip))
        )
        for ip in overflow_ips
    ]

    try:
        for thread in active_threads:
            thread.start()
        assert lookup_slots_full.wait(timeout=0.5)

        for thread in overflow_threads:
            thread.start()
        for thread in overflow_threads:
            thread.join(timeout=0.5)

        assert all(not thread.is_alive() for thread in overflow_threads)
        assert len(calls) == _REVERSE_DNS_LOOKUP_THREAD_LIMIT
        assert all(
            results[ip]["hostname_status"] == "unresolved" for ip in overflow_ips
        )
    finally:
        release_lookups.set()
        for thread in active_threads + overflow_threads:
            thread.join(timeout=0.5)

    assert all(not thread.is_alive() for thread in active_threads)
    assert set(calls) == set(active_ips)
    assert all(results[ip]["hostname_status"] == "resolved" for ip in active_ips)

    retried = cache.resolve(overflow_ips[0])
    assert retried == {
        "hostname": f"host-{overflow_ips[0]}.example",
        "hostname_source": "rdns",
        "hostname_status": "resolved",
    }
    assert calls.count(overflow_ips[0]) == 1


def test_client_identity_cache_normalizes_valid_rdns_hostname(monkeypatch) -> None:
    cache = ClientIdentityCache(success_ttl_seconds=30.0)

    monkeypatch.setattr(
        "services.client_identity_cache.socket.gethostbyaddr",
        lambda _ip: ("WorkStation.Example.", [], []),
    )

    assert cache.resolve("192.0.2.10") == {
        "hostname": "workstation.example",
        "hostname_source": "rdns",
        "hostname_status": "resolved",
    }


def test_client_identity_cache_canonicalizes_idn_rdns_hostname(monkeypatch) -> None:
    cache = ClientIdentityCache(success_ttl_seconds=30.0)

    monkeypatch.setattr(
        "services.client_identity_cache.socket.gethostbyaddr",
        lambda _ip: ("M\u00fcnchen.Example.", [], []),
    )

    assert cache.resolve("192.0.2.10") == {
        "hostname": "xn--mnchen-3ya.example",
        "hostname_source": "rdns",
        "hostname_status": "resolved",
    }


def test_client_identity_cache_canonicalizes_idna_dot_rdns_hostname(
    monkeypatch,
) -> None:
    cache = ClientIdentityCache(success_ttl_seconds=30.0)

    monkeypatch.setattr(
        "services.client_identity_cache.socket.gethostbyaddr",
        lambda _ip: ("B\u00fccher\uff0eExample\uff61", [], []),
    )

    assert cache.resolve("192.0.2.10") == {
        "hostname": "xn--bcher-kva.example",
        "hostname_source": "rdns",
        "hostname_status": "resolved",
    }


def test_client_identity_cache_rejects_malformed_rdns_hostnames(monkeypatch) -> None:
    cache = ClientIdentityCache(failure_ttl_seconds=10.0)
    responses = iter(
        [
            ("bad\nname.example", [], []),
            ("bad name.example", [], []),
            ("-bad.example", [], []),
            ("bad..example", [], []),
            (f"{'a' * 64}.example", [], []),
            ("192.0.2.44", [], []),
            ("::1", [], []),
            ("localhost.localdomain", [], []),
            ("\uff11\uff12\uff17\uff0e\uff10\uff0e\uff10\uff0e\uff11", [], []),
        ]
    )

    monkeypatch.setattr(
        "services.client_identity_cache.socket.gethostbyaddr",
        lambda _ip: next(responses),
    )

    for ip in [
        "192.0.2.10",
        "192.0.2.11",
        "192.0.2.12",
        "192.0.2.13",
        "192.0.2.14",
        "192.0.2.15",
        "192.0.2.16",
        "192.0.2.17",
        "192.0.2.18",
    ]:
        assert cache.resolve(ip) == {
            "hostname": "",
            "hostname_source": "",
            "hostname_status": "unresolved",
        }


def test_client_identity_cache_rejects_ambiguous_numeric_rdns_hostnames(
    monkeypatch,
) -> None:
    cache = ClientIdentityCache(failure_ttl_seconds=10.0)
    responses = iter(
        [
            ("0x7f.1", [], []),
            ("0177.0.0.1", [], []),
            ("127.1", [], []),
            ("1.2.3.999", [], []),
            ("0x7f.999", [], []),
        ]
    )

    monkeypatch.setattr(
        "services.client_identity_cache.socket.gethostbyaddr",
        lambda _ip: next(responses),
    )

    for ip in [
        "192.0.2.20",
        "192.0.2.21",
        "192.0.2.22",
        "192.0.2.23",
        "192.0.2.24",
    ]:
        assert cache.resolve(ip) == {
            "hostname": "",
            "hostname_source": "",
            "hostname_status": "unresolved",
        }


def test_client_identity_cache_accepts_valid_dns_rdns_hostnames_with_digits(
    monkeypatch,
) -> None:
    cache = ClientIdentityCache(success_ttl_seconds=30.0)
    responses = iter(
        [
            ("proxy-0177.example.", [], []),
            ("edge-0x7f.example", [], []),
        ]
    )

    monkeypatch.setattr(
        "services.client_identity_cache.socket.gethostbyaddr",
        lambda _ip: next(responses),
    )

    assert cache.resolve("192.0.2.30") == {
        "hostname": "proxy-0177.example",
        "hostname_source": "rdns",
        "hostname_status": "resolved",
    }
    assert cache.resolve("192.0.2.31") == {
        "hostname": "edge-0x7f.example",
        "hostname_source": "rdns",
        "hostname_status": "resolved",
    }


def test_client_identity_cache_treats_dns_lookup_errors_as_unresolved(
    monkeypatch,
) -> None:
    cache = ClientIdentityCache(failure_ttl_seconds=10.0)

    def fail_lookup(_ip: str) -> tuple[str, list[str], list[str]]:
        msg = "no PTR"
        raise socket.herror(msg)

    monkeypatch.setattr(
        "services.client_identity_cache.socket.gethostbyaddr",
        fail_lookup,
    )

    assert cache.resolve("192.0.2.10") == {
        "hostname": "",
        "hostname_source": "",
        "hostname_status": "unresolved",
    }


def test_client_identity_cache_reverse_dns_timeout_returns_unresolved(
    monkeypatch,
) -> None:
    cache = ClientIdentityCache(failure_ttl_seconds=10.0, lookup_timeout_seconds=0.05)
    started = threading.Event()
    release = threading.Event()
    finished = threading.Event()

    def slow_lookup(_ip: str) -> tuple[str, list[str], list[str]]:
        try:
            started.set()
            release.wait(timeout=1.0)
            return "late.example", [], []
        finally:
            finished.set()

    monkeypatch.setattr(
        "services.client_identity_cache.socket.gethostbyaddr",
        slow_lookup,
    )

    try:
        assert cache.resolve("192.0.2.10") == {
            "hostname": "",
            "hostname_source": "",
            "hostname_status": "unresolved",
        }
        assert started.wait(timeout=0.5)
    finally:
        release.set()
        assert finished.wait(timeout=0.5)


def test_client_identity_cache_resolve_does_not_mutate_global_socket_timeout(
    monkeypatch,
) -> None:
    cache = ClientIdentityCache(success_ttl_seconds=30.0)

    def fail_setdefaulttimeout(_timeout: object) -> None:
        msg = "socket.setdefaulttimeout must not be called"
        raise AssertionError(msg)

    monkeypatch.setattr(
        "services.client_identity_cache.socket.setdefaulttimeout",
        fail_setdefaulttimeout,
    )
    monkeypatch.setattr(
        "services.client_identity_cache.socket.gethostbyaddr",
        lambda _ip: ("WorkStation.Example.", [], []),
    )

    assert cache.resolve("192.0.2.10") == {
        "hostname": "workstation.example",
        "hostname_source": "rdns",
        "hostname_status": "resolved",
    }


def test_client_identity_cache_resolve_many_does_not_mutate_global_socket_timeout(
    monkeypatch,
) -> None:
    cache = ClientIdentityCache(success_ttl_seconds=30.0)

    def fail_setdefaulttimeout(_timeout: object) -> None:
        msg = "socket.setdefaulttimeout must not be called"
        raise AssertionError(msg)

    monkeypatch.setattr(
        "services.client_identity_cache.socket.setdefaulttimeout",
        fail_setdefaulttimeout,
    )
    responses = {
        "192.0.2.10": "host-a.example",
        "2001:db8::1": "host-b.example",
    }
    monkeypatch.setattr(
        "services.client_identity_cache.socket.gethostbyaddr",
        lambda ip: (responses[ip], [], []),
    )

    resolved = cache.resolve_many(["192.0.2.10", "2001:db8::1"])

    assert resolved["192.0.2.10"] == {
        "hostname": "host-a.example",
        "hostname_source": "rdns",
        "hostname_status": "resolved",
    }
    assert resolved["2001:db8::1"] == {
        "hostname": "host-b.example",
        "hostname_source": "rdns",
        "hostname_status": "resolved",
    }


def test_client_identity_cache_resolve_many_deduplicates_and_records_failures(
    monkeypatch,
) -> None:
    cache = ClientIdentityCache(failure_ttl_seconds=10.0)
    calls: list[str] = []

    def fake_lookup(ip: str) -> tuple[str, str, str]:
        calls.append(ip)
        return "", "", "unresolved"

    monkeypatch.setattr(cache, "_lookup_hostname", fake_lookup)

    resolved = cache.resolve_many(["192.0.2.10", "bad", "192.0.2.10", "2001:db8::1"])
    assert set(resolved) == {"192.0.2.10", "2001:db8::1"}
    assert resolved["192.0.2.10"]["hostname_status"] == "unresolved"
    assert resolved["2001:db8::1"]["hostname_status"] == "unresolved"
    assert calls == ["192.0.2.10", "2001:db8::1"]


def test_client_identity_cache_evicts_oldest_entry_when_full(monkeypatch) -> None:
    cache = ClientIdentityCache(max_entries=1)
    # max_entries is clamped to at least 64; shrink after construction to exercise eviction deterministically.
    cache.max_entries = 1
    now = {"value": 1000.0}
    monkeypatch.setattr(
        "services.client_identity_cache.time.time", lambda: now["value"]
    )
    monkeypatch.setattr(
        cache, "_lookup_hostname", lambda ip: (f"host-{ip}", "rdns", "resolved")
    )

    assert cache.resolve("192.0.2.1")["hostname"] == "host-192.0.2.1"
    now["value"] += 1.0
    assert cache.resolve("192.0.2.2")["hostname"] == "host-192.0.2.2"
    assert "192.0.2.1" not in cache._cache
    assert "192.0.2.2" in cache._cache


def test_client_identity_cache_replaces_expired_entry(monkeypatch) -> None:
    cache = ClientIdentityCache(success_ttl_seconds=30.0)
    now = {"value": 1000.0}
    responses = iter(
        [
            ("first.example", "rdns", "resolved"),
            ("second.example", "rdns", "resolved"),
        ]
    )
    calls: list[str] = []

    monkeypatch.setattr(
        "services.client_identity_cache.time.time", lambda: now["value"]
    )

    def fake_lookup(ip: str) -> tuple[str, str, str]:
        calls.append(ip)
        return next(responses)

    monkeypatch.setattr(cache, "_lookup_hostname", fake_lookup)

    assert cache.resolve("192.0.2.10")["hostname"] == "first.example"
    now["value"] += 30.0
    assert cache.resolve("192.0.2.10")["hostname"] == "second.example"
    assert calls == ["192.0.2.10", "192.0.2.10"]
