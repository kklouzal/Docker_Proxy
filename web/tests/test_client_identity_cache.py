from __future__ import annotations

import socket
import sys
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
    ]:
        assert cache.resolve(ip) == {
            "hostname": "",
            "hostname_source": "",
            "hostname_status": "unresolved",
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
