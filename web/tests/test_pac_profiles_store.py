from __future__ import annotations

import sys
from pathlib import Path


def _add_web_path() -> None:
    web_root = Path(__file__).resolve().parents[1]
    if str(web_root) not in sys.path:
        sys.path.insert(0, str(web_root))


class _FakeResult:
    def __init__(self, rows: list[dict[str, object]]) -> None:
        self._rows = rows

    def fetchall(self):
        return self._rows

    def fetchone(self):
        return self._rows[0] if self._rows else None


class _FakeConn:
    def __init__(
        self,
        *,
        direct_domain_rows: list[dict[str, object]] | None = None,
    ) -> None:
        self.calls: list[tuple[str, tuple[object, ...]]] = []
        self.direct_domain_rows = direct_domain_rows

    def execute(self, sql: str, params: tuple[object, ...] = ()):
        self.calls.append((sql, params))
        if sql.startswith("SELECT id, name, client_cidr, created_ts FROM pac_profiles"):
            return _FakeResult(
                [
                    {
                        "id": 11,
                        "name": "alpha",
                        "client_cidr": "10.0.0.0/24",
                        "created_ts": 1,
                    },
                    {"id": 12, "name": "beta", "client_cidr": "", "created_ts": 2},
                ],
            )
        if sql.startswith("SELECT profile_id, domain FROM pac_direct_domains"):
            return _FakeResult(
                self.direct_domain_rows
                if self.direct_domain_rows is not None
                else
                [
                    {"profile_id": 11, "domain": "a.example"},
                    {"profile_id": 11, "domain": "b.example"},
                    {"profile_id": 12, "domain": "catch.example"},
                ],
            )
        if sql.startswith("SELECT profile_id, cidr FROM pac_direct_dst_nets"):
            return _FakeResult(
                [
                    {"profile_id": 11, "cidr": "10.0.0.0/8"},
                    {"profile_id": 12, "cidr": "192.168.1.0/24"},
                ],
            )
        if "FROM pac_backup_proxies" in sql and sql.lstrip().startswith("SELECT id"):
            return _FakeResult(
                [
                    {
                        "id": 21,
                        "proxy_host": "backup-a.example",
                        "proxy_port": 3128,
                        "position": 1,
                        "created_ts": 1,
                    },
                    {
                        "id": 22,
                        "proxy_host": "backup-b.example",
                        "proxy_port": 8080,
                        "position": 2,
                        "created_ts": 2,
                    },
                ],
            )
        if sql.startswith("SELECT direct_enabled FROM pac_proxy_chain_settings"):
            return _FakeResult([{"direct_enabled": 0}])
        return _FakeResult([])


class _FakeStore:
    def __init__(self, conn: _FakeConn) -> None:
        self.conn = conn

    def __enter__(self):
        return self.conn

    def __exit__(self, exc_type, exc, tb):
        return False


def test_list_profiles_batches_child_queries(monkeypatch) -> None:
    _add_web_path()
    import services.pac_profiles_store as mod

    conn = _FakeConn()
    store = mod.PacProfilesStore()

    monkeypatch.setattr(mod, "connect", lambda: _FakeStore(conn))
    monkeypatch.setattr(mod, "get_proxy_id", lambda: "default")
    monkeypatch.setattr(mod.PacProfilesStore, "init_db", lambda self: None)

    profiles = store.list_profiles()

    assert [p.id for p in profiles] == [11, 12]
    assert profiles[0].direct_domains == ["a.example", "b.example"]
    assert profiles[0].direct_dst_nets == ["10.0.0.0/8"]
    assert profiles[1].direct_domains == ["catch.example"]
    assert profiles[1].direct_dst_nets == ["192.168.1.0/24"]
    assert len(conn.calls) == 3
    assert conn.calls[0][0].startswith(
        "SELECT id, name, client_cidr, created_ts FROM pac_profiles"
    )
    assert "profile_id IN" in conn.calls[1][0]
    assert "profile_id IN" in conn.calls[2][0]


def test_list_profiles_normalizes_stale_direct_domain_rows(monkeypatch) -> None:
    _add_web_path()
    import services.pac_profiles_store as mod

    conn = _FakeConn(
        direct_domain_rows=[
            {"profile_id": 11, "domain": "Example.COM"},
            {"profile_id": 11, "domain": ".example.com"},
            {"profile_id": 11, "domain": "https://Bücher.Example:443/path"},
            {"profile_id": 11, "domain": "bad domain.example"},
            {"profile_id": 12, "domain": "*.Media.Example"},
        ],
    )
    store = mod.PacProfilesStore()

    monkeypatch.setattr(mod, "connect", lambda: _FakeStore(conn))
    monkeypatch.setattr(mod, "get_proxy_id", lambda: "default")
    monkeypatch.setattr(mod.PacProfilesStore, "init_db", lambda self: None)

    profiles = store.list_profiles()

    assert profiles[0].direct_domains == [
        "example.com",
        "xn--bcher-kva.example",
    ]
    assert profiles[1].direct_domains == ["*.media.example"]


def test_list_proxy_chain_settings_returns_backups_and_direct_toggle(
    monkeypatch,
) -> None:
    _add_web_path()
    import services.pac_profiles_store as mod

    conn = _FakeConn()
    store = mod.PacProfilesStore()

    monkeypatch.setattr(mod, "connect", lambda: _FakeStore(conn))
    monkeypatch.setattr(mod, "get_proxy_id", lambda: "default")
    monkeypatch.setattr(mod.PacProfilesStore, "init_db", lambda self: None)

    settings = store.list_proxy_chain_settings()

    assert [item.proxy_host for item in settings.backup_proxies] == [
        "backup-a.example",
        "backup-b.example",
    ]
    assert [item.proxy_port for item in settings.backup_proxies] == [3128, 8080]
    assert settings.direct_enabled is False


def test_direct_domain_normalization_accepts_urls_idn_and_wildcards() -> None:
    _add_web_path()
    import services.pac_profiles_store as mod

    assert mod._normalize_domain("https://Bücher.Example:443/path") == (
        "xn--bcher-kva.example",
        "",
    )
    assert mod._normalize_domain("*.Bücher.Example") == (
        "*.xn--bcher-kva.example",
        "",
    )
    assert mod._normalize_domain(".Example.COM") == ("example.com", "")
    assert mod._normalize_domain("-bad.example")[0] is None
    assert mod._normalize_domain("bad domain.example")[0] is None


def test_backup_proxy_host_port_normalization_accepts_url_and_default_port() -> None:
    _add_web_path()
    import services.pac_profiles_store as mod

    assert mod._normalize_proxy_host_port(
        "http://Backup.Example:8080/proxy.pac", ""
    ) == ("backup.example", 8080, "")
    assert mod._normalize_proxy_host_port("[2001:db8::10]:3129", None) == (
        "2001:db8::10",
        3129,
        "",
    )
    assert mod._normalize_proxy_host_port("backup.example", "") == (
        "backup.example",
        3128,
        "",
    )
