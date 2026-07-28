from __future__ import annotations

import socket
import sys
import threading
from pathlib import Path


def _add_web_to_path() -> None:
    web_dir = Path(__file__).resolve().parents[1]
    if str(web_dir) not in sys.path:
        sys.path.insert(0, str(web_dir))


_add_web_to_path()
from services.client_identity_cache import (  # type: ignore  # noqa: E402
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
