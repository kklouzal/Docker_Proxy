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
        direct_dst_net_rows: list[dict[str, object]] | None = None,
        profile_ids: set[int] | None = None,
        backup_proxy_rows: list[dict[str, object]] | None = None,
        backup_proxy_ids: list[int] | None = None,
    ) -> None:
        self.calls: list[tuple[str, tuple[object, ...]]] = []
        self.direct_domain_rows = direct_domain_rows
        self.direct_dst_net_rows = direct_dst_net_rows
        self.profile_ids = profile_ids if profile_ids is not None else {11, 12}
        self.backup_proxy_rows = backup_proxy_rows
        self.backup_proxy_ids = (
            backup_proxy_ids if backup_proxy_ids is not None else [21, 22]
        )

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
                else [
                    {"profile_id": 11, "domain": "a.example"},
                    {"profile_id": 11, "domain": "b.example"},
                    {"profile_id": 12, "domain": "catch.example"},
                ],
            )
        if sql.startswith("SELECT profile_id, cidr FROM pac_direct_dst_nets"):
            return _FakeResult(
                self.direct_dst_net_rows
                if self.direct_dst_net_rows is not None
                else [
                    {"profile_id": 11, "cidr": "10.0.0.0/8"},
                    {"profile_id": 12, "cidr": "192.168.1.0/24"},
                ],
            )
        if "FROM pac_backup_proxies" in sql and sql.lstrip().startswith("SELECT id"):
            return _FakeResult(
                self.backup_proxy_rows
                if self.backup_proxy_rows is not None
                else [
                    {
                        "id": self.backup_proxy_ids[0],
                        "proxy_host": "backup-a.example",
                        "proxy_port": 3128,
                        "position": 1,
                        "created_ts": 1,
                    },
                    {
                        "id": self.backup_proxy_ids[1],
                        "proxy_host": "backup-b.example",
                        "proxy_port": 8080,
                        "position": 2,
                        "created_ts": 2,
                    },
                ][: len(self.backup_proxy_ids)],
            )
        if sql.startswith("SELECT 1 FROM pac_backup_proxies"):
            return _FakeResult(
                [{"1": 1}] if int(params[0]) in self.backup_proxy_ids else []
            )
        if sql.startswith("SELECT 1 FROM pac_profiles"):
            return _FakeResult([{"1": 1}] if int(params[0]) in self.profile_ids else [])
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


def _patched_store(monkeypatch, conn: _FakeConn | None = None):
    _add_web_path()
    import services.pac_profiles_store as mod

    conn = conn or _FakeConn()
    store = mod.PacProfilesStore()

    monkeypatch.setattr(mod, "connect", lambda: _FakeStore(conn))
    monkeypatch.setattr(mod, "get_proxy_id", lambda: "default")
    monkeypatch.setattr(mod.PacProfilesStore, "init_db", lambda self: None)

    return mod, conn, store


def test_init_db_lazy_bootstrap_uses_valid_pac_dst_net_ddl(monkeypatch) -> None:
    _add_web_path()
    import services.pac_profiles_store as mod
    from services import schema_lifecycle

    conn = _FakeConn()
    store = mod.PacProfilesStore()

    monkeypatch.setattr(mod, "connect", lambda: _FakeStore(conn))
    monkeypatch.setattr(
        schema_lifecycle,
        "runtime_schema_ready_for_lazy_store",
        lambda _conn: False,
    )

    store.init_db()

    pac_dst_net_ddls = [
        " ".join(sql.split())
        for sql, _params in conn.calls
        if sql.lstrip().startswith(
            "CREATE TABLE IF NOT EXISTS pac_direct_dst_nets",
        )
    ]
    assert pac_dst_net_ddls == [(
        "CREATE TABLE IF NOT EXISTS pac_direct_dst_nets ( "
        "profile_id BIGINT NOT NULL, cidr VARCHAR(64) NOT NULL, "
        "PRIMARY KEY(profile_id, cidr) )"
    )]
    assert pac_dst_net_ddls[0].count("PRIMARY KEY") == 1
    assert store._schema_ready is True


def test_list_profiles_batches_child_queries(monkeypatch) -> None:
    _, conn, store = _patched_store(monkeypatch)

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
    _, _, store = _patched_store(
        monkeypatch,
        _FakeConn(
            direct_domain_rows=[
                {"profile_id": 11, "domain": "Example.COM"},
                {"profile_id": 11, "domain": ".example.com"},
                {"profile_id": 11, "domain": "https://Bücher.Example:443/path"},
                {"profile_id": 11, "domain": "bad domain.example"},
                {"profile_id": 12, "domain": "*.Media.Example"},
            ],
        ),
    )

    profiles = store.list_profiles()

    assert profiles[0].direct_domains == [
        "example.com",
        "xn--bcher-kva.example",
    ]
    assert profiles[1].direct_domains == ["*.media.example"]


def test_list_profiles_normalizes_stale_direct_dst_net_rows(monkeypatch) -> None:
    _, _, store = _patched_store(
        monkeypatch,
        _FakeConn(
            direct_dst_net_rows=[
                {"profile_id": 11, "cidr": "10.77.0.1/24"},
                {"profile_id": 11, "cidr": "10.77.0.128/24"},
                {"profile_id": 11, "cidr": "2001:db8::/32"},
                {"profile_id": 11, "cidr": "not-a-cidr"},
                {"profile_id": 12, "cidr": "192.168.1.7/24"},
            ],
        ),
    )

    profiles = store.list_profiles()

    assert profiles[0].direct_dst_nets == ["10.77.0.0/24"]
    assert profiles[1].direct_dst_nets == ["192.168.1.0/24"]


def test_list_proxy_chain_settings_returns_backups_and_direct_toggle(
    monkeypatch,
) -> None:
    _, _, store = _patched_store(monkeypatch)

    settings = store.list_proxy_chain_settings()

    assert [item.proxy_host for item in settings.backup_proxies] == [
        "backup-a.example",
        "backup-b.example",
    ]
    assert [item.proxy_port for item in settings.backup_proxies] == [3128, 8080]
    assert settings.direct_enabled is False


def test_list_proxy_chain_settings_filters_stale_invalid_backup_rows(
    monkeypatch,
) -> None:
    _, _, store = _patched_store(
        monkeypatch,
        _FakeConn(
            backup_proxy_rows=[
                {
                    "id": 21,
                    "proxy_host": "backup-zero.example",
                    "proxy_port": 0,
                    "position": 1,
                    "created_ts": 1,
                },
                {
                    "id": 22,
                    "proxy_host": "backup-hostile.example;DIRECT",
                    "proxy_port": 3128,
                    "position": 2,
                    "created_ts": 2,
                },
                {
                    "id": 23,
                    "proxy_host": "backup-good.example",
                    "proxy_port": 8080,
                    "position": 3,
                    "created_ts": 3,
                },
                {
                    "id": 24,
                    "proxy_host": "fe80::1%eth0",
                    "proxy_port": 3128,
                    "position": 4,
                    "created_ts": 4,
                },
                {
                    "id": 25,
                    "proxy_host": "[fe80::2%eth0]:3129",
                    "proxy_port": 3129,
                    "position": 5,
                    "created_ts": 5,
                },
                {
                    "id": 26,
                    "proxy_host": "2001:db8::10",
                    "proxy_port": 3130,
                    "position": 6,
                    "created_ts": 6,
                },
            ],
            backup_proxy_ids=[21, 22, 23, 24, 25, 26],
        ),
    )

    settings = store.list_proxy_chain_settings()

    assert [(item.proxy_host, item.proxy_port) for item in settings.backup_proxies] == [
        ("backup-good.example", 8080),
        ("2001:db8::10", 3130),
    ]


def test_backup_proxy_mutations_report_changed_status(monkeypatch) -> None:
    _, _, store = _patched_store(monkeypatch)

    assert store.move_backup_proxy(22, "up") is True
    assert store.move_backup_proxy(22, "down") is False
    assert store.move_backup_proxy(999, "up") is False
    assert store.delete_backup_proxy(21) is True
    assert store.delete_backup_proxy(999) is False


def test_delete_profile_reports_changed_status(monkeypatch) -> None:
    _, _, store = _patched_store(monkeypatch)

    assert store.delete_profile(11) is True
    assert store.delete_profile(999) is False


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
    assert mod._normalize_domain("bad..example")[0] is None
    assert mod._normalize_domain("bad domain.example")[0] is None


def test_backup_proxy_host_port_normalization_accepts_url_and_default_port() -> None:
    _add_web_path()
    import services.pac_profiles_store as mod

    assert mod._normalize_proxy_host_port("Backup.Proxy.Example.", None) == (
        "backup.proxy.example",
        3128,
        "",
    )
    assert mod._normalize_proxy_host_port(
        "http://Backup.Proxy.Example.:8080", ""
    ) == ("backup.proxy.example", 8080, "")
    assert mod._normalize_proxy_host_port(
        "http://Backup.Example:8080", ""
    ) == ("backup.example", 8080, "")
    assert mod._normalize_proxy_host_port(
        "https://Backup.Example", "9090"
    ) == ("backup.example", 9090, "")
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
    assert mod._normalize_proxy_host_port("backup.example", "9090") == (
        "backup.example",
        9090,
        "",
    )
    assert mod._normalize_proxy_host_port("Backup-01.Example", None) == (
        "backup-01.example",
        3128,
        "",
    )
    assert mod._normalize_proxy_host_port("192.0.2.10", None) == (
        "192.0.2.10",
        3128,
        "",
    )
    assert mod._normalize_proxy_host_port("http://192.0.2.10:8080", "") == (
        "192.0.2.10",
        8080,
        "",
    )
    assert mod._normalize_proxy_host_port("2001:db8::10", None) == (
        "2001:db8::10",
        3128,
        "",
    )


def test_backup_proxy_host_port_normalization_accepts_scheme_url_without_port() -> None:
    _add_web_path()
    import services.pac_profiles_store as mod

    assert mod._normalize_proxy_host_port("http://backup.example", None) == (
        "backup.example",
        3128,
        "",
    )
    assert mod._normalize_proxy_host_port("https://backup.example", "9090") == (
        "backup.example",
        9090,
        "",
    )


def test_backup_proxy_host_port_normalization_rejects_scheme_url_empty_port() -> None:
    _add_web_path()
    import services.pac_profiles_store as mod

    for host in ("http://backup.example:", "https://backup.example:"):
        assert mod._normalize_proxy_host_port(host, None) == (
            None,
            None,
            "Invalid proxy port.",
        )


def test_backup_proxy_host_port_normalization_rejects_scoped_ipv6() -> None:
    _add_web_path()
    import services.pac_profiles_store as mod

    for host in (
        "fe80::1%eth0",
        "[fe80::1%eth0]:3128",
        "http://[fe80::1%25eth0]:3128",
    ):
        assert mod._normalize_proxy_host_port(host, None) == (
            None,
            None,
            "Invalid proxy host.",
        )


def test_backup_proxy_host_port_normalization_rejects_unsupported_url_schemes() -> None:
    _add_web_path()
    import services.pac_profiles_store as mod

    for host in (
        "ftp://backup.example:21/proxy.pac",
        "gopher://backup.example:3128/",
    ):
        assert mod._normalize_proxy_host_port(host, "") == (
            None,
            None,
            "Invalid proxy host.",
        )


def test_backup_proxy_host_port_normalization_rejects_url_paths_queries_fragments() -> None:
    _add_web_path()
    import services.pac_profiles_store as mod

    for host in (
        "https://backup.example/proxy.pac",
        "https://backup.example:8443/proxy.pac",
        "https://backup.example?x=1",
        "https://backup.example#frag",
    ):
        assert mod._normalize_proxy_host_port(host, "9090") == (
            None,
            None,
            "Invalid proxy host.",
        )


def test_backup_proxy_host_port_normalization_rejects_unsafe_hosts() -> None:
    _add_web_path()
    import services.pac_profiles_store as mod

    for host in (
        "backup.example;DIRECT",
        "backup.example,DIRECT",
        '"backup.example"',
        "bad_host.example",
        "-backup.example",
        "backup-.example",
        "backup..example",
    ):
        assert mod._normalize_proxy_host_port(host, None) == (
            None,
            None,
            "Invalid proxy host.",
        )


def test_backup_proxy_host_port_normalization_rejects_ambiguous_ipv4_hosts() -> None:
    _add_web_path()
    import services.pac_profiles_store as mod

    for host in (
        "010.000.000.001",
        "192.168.1",
        "999.999.999.999",
        "0x7f.0x0.0x0.0x1",
        "http://010.000.000.001:8080",
        "http://192.168.1:8080",
        "http://999.999.999.999:8080",
    ):
        assert mod._normalize_proxy_host_port(host, None) == (
            None,
            None,
            "Invalid proxy host.",
        )


def test_backup_proxy_host_port_normalization_rejects_embedded_credentials() -> None:
    _add_web_path()
    import services.pac_profiles_store as mod

    for host in (
        "http://user:pass@backup.example:8080/proxy.pac",
        "http://user@backup.example:8080/proxy.pac",
        "http://:pass@backup.example:8080/proxy.pac",
    ):
        assert mod._normalize_proxy_host_port(host, "") == (
            None,
            None,
            "Proxy host must not include embedded credentials.",
        )


def test_backup_proxy_host_port_normalization_rejects_malformed_inline_ports() -> None:
    _add_web_path()
    import services.pac_profiles_store as mod

    assert mod._normalize_proxy_host_port("backup.example", 0) == (
        None,
        None,
        "Proxy port must be between 1 and 65535.",
    )
    assert mod._normalize_proxy_host_port("backup.example:abc", None) == (
        None,
        None,
        "Invalid proxy port.",
    )
    assert mod._normalize_proxy_host_port("[2001:db8::10]:abc", "") == (
        None,
        None,
        "Invalid proxy port.",
    )
    assert mod._normalize_proxy_host_port("[2001:db8::10]:abc", "8080") == (
        None,
        None,
        "Invalid proxy port.",
    )
    assert mod._normalize_proxy_host_port("[2001:db8::10]junk", "8080") == (
        None,
        None,
        "Invalid proxy port.",
    )
    assert mod._normalize_proxy_host_port("[2001:db8::10]:8443", "3128") == (
        None,
        None,
        "Conflicting proxy ports.",
    )
    assert mod._normalize_proxy_host_port("http://backup.example:8443", "3128") == (
        None,
        None,
        "Conflicting proxy ports.",
    )
    assert mod._normalize_proxy_host_port(
        "http://backup.example:abc/proxy.pac", ""
    ) == (
        None,
        None,
        "Invalid proxy port.",
    )
    assert mod._normalize_proxy_host_port(
        "http://backup.example:65536/proxy.pac", ""
    ) == (
        None,
        None,
        "Invalid proxy port.",
    )
    assert mod._normalize_proxy_host_port(
        "http://backup.example:0/proxy.pac", ""
    ) == (
        None,
        None,
        "Proxy port must be between 1 and 65535.",
    )
    assert mod._normalize_proxy_host_port(
        "http://backup.example:abc/proxy.pac", "9090"
    ) == (
        None,
        None,
        "Invalid proxy port.",
    )
    assert mod._normalize_proxy_host_port(
        "http://backup.example:65536/proxy.pac", "9090"
    ) == (
        None,
        None,
        "Invalid proxy port.",
    )
    assert mod._normalize_proxy_host_port(
        "http://backup.example:0/proxy.pac", "9090"
    ) == (
        None,
        None,
        "Proxy port must be between 1 and 65535.",
    )
