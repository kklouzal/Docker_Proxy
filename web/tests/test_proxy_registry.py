from __future__ import annotations

import concurrent.futures
import importlib
import threading
from typing import TYPE_CHECKING, ClassVar

import pytest

from .mysql_test_utils import configure_test_mysql_env

# Escaped IDNA/fullwidth regression inputs avoid Ruff's ambiguous-unicode lint.
IDNA_MANAGEMENT_HOST = "B\u00dcCHER.example"
FULLWIDTH_LOOPBACK_IPV4_IDNA_DOTS = (
    "\uff11\uff12\uff17\u3002\uff10\u3002\uff10\u3002\uff11"
)

if TYPE_CHECKING:
    from types import ModuleType


def _proxy_registry() -> ModuleType:
    from services import proxy_registry  # type: ignore

    return proxy_registry


def _concurrent_results(*operations):
    barrier = threading.Barrier(len(operations))

    def run(operation):
        barrier.wait(timeout=10)
        try:
            return ("ok", operation())
        except Exception as exc:
            return ("err", type(exc).__name__, str(exc))

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(operations)) as executor:
        return list(executor.map(run, operations))


def test_lifecycle_lock_name_matches_write_guard_for_long_proxy_ids() -> None:
    proxy_registry = _proxy_registry()
    from services.proxy_write_guard import proxy_lifecycle_lock_name  # type: ignore

    proxy_id = "edge-" + "a" * 58
    registry = proxy_registry.ProxyRegistry()

    assert len(proxy_id) == 63
    assert registry._lifecycle_lock_name(proxy_id) == proxy_lifecycle_lock_name(
        proxy_id
    )
    assert (
        registry._lifecycle_lock_name(proxy_id)
        != f"docker_proxy:proxy_lifecycle:{proxy_id}"[:64]
    )


def test_parse_public_pac_url_handles_scheme_host_ports_and_invalid_values() -> None:
    proxy_registry = _proxy_registry()

    assert proxy_registry._parse_public_pac_url("proxy.example") == (
        "proxy.example",
        "http",
        80,
        "/proxy.pac",
    )
    assert proxy_registry._parse_public_pac_url("BadHost.Example.") == (
        "badhost.example",
        "http",
        80,
        "/proxy.pac",
    )
    assert proxy_registry._parse_public_pac_url("2130706433/proxy.pac") == (
        "",
        "http",
        80,
        "/proxy.pac",
    )
    assert proxy_registry._parse_public_pac_url("017700000001/proxy.pac") == (
        "",
        "http",
        80,
        "/proxy.pac",
    )
    assert proxy_registry._parse_public_pac_url("https://proxy.example/proxy.pac") == (
        "proxy.example",
        "https",
        443,
        "/proxy.pac",
    )
    assert proxy_registry._parse_public_pac_url(
        "proxy.example:8080/custom.pac?site=lab"
    ) == ("proxy.example", "http", 8080, "/custom.pac?site=lab")
    assert proxy_registry._parse_public_pac_url("") == ("", "http", 80, "/proxy.pac")
    assert proxy_registry._parse_public_pac_url(
        "ftp://proxy.example:9000/proxy.pac"
    ) == ("", "http", 80, "/proxy.pac")
    assert proxy_registry._parse_public_pac_url("https:///proxy.pac") == (
        "",
        "http",
        80,
        "/proxy.pac",
    )
    assert proxy_registry._parse_public_pac_url(
        "https://bad host.example/proxy.pac"
    ) == (
        "",
        "http",
        80,
        "/proxy.pac",
    )
    assert proxy_registry._parse_public_pac_url(
        "http://bad_host.example/proxy.pac"
    ) == (
        "",
        "http",
        80,
        "/proxy.pac",
    )
    assert proxy_registry._parse_public_pac_url("http://localhost/proxy.pac") == (
        "",
        "http",
        80,
        "/proxy.pac",
    )
    assert proxy_registry._parse_public_pac_url("proxy.internal/proxy.pac") == (
        "",
        "http",
        80,
        "/proxy.pac",
    )


@pytest.mark.parametrize(
    "value",
    [
        "https://proxy.example:/proxy.pac",
        "proxy.example:/proxy.pac",
        "https://[2001:4860:4860::8888]:/proxy.pac",
        "[2001:4860:4860::8888]:/proxy.pac",
        "https://user:secret@proxy.example:/proxy.pac",
    ],
)
def test_parse_public_pac_url_rejects_empty_explicit_authority_ports(
    value: str,
) -> None:
    proxy_registry = _proxy_registry()

    assert proxy_registry._parse_public_pac_url(value) == (
        "",
        "http",
        80,
        "/proxy.pac",
    )


@pytest.mark.parametrize(
    "value",
    [
        "https://proxy.example:not-a-port/proxy.pac",
        "proxy.example:not-a-port/proxy.pac",
    ],
)
def test_parse_public_pac_url_rejects_invalid_explicit_authority_ports(
    value: str,
) -> None:
    proxy_registry = _proxy_registry()

    assert proxy_registry._parse_public_pac_url(value) == (
        "",
        "http",
        80,
        "/proxy.pac",
    )


def test_public_pac_path_normalization_rejects_unsafe_route_shapes() -> None:
    proxy_registry = _proxy_registry()

    assert (
        proxy_registry.normalize_public_pac_path("download/wpad.dat?site=lab")
        == "/download/wpad.dat?site=lab"
    )
    assert (
        proxy_registry.normalize_public_pac_path(
            "https://proxy.example/custom/proxy.pac?site=lab"
        )
        == "/custom/proxy.pac?site=lab"
    )
    assert proxy_registry.normalize_public_pac_path("https:/custom/proxy.pac") == (
        "/proxy.pac"
    )
    assert proxy_registry.normalize_public_pac_path("https:///custom/proxy.pac") == (
        "/proxy.pac"
    )
    assert (
        proxy_registry.normalize_public_pac_path(
            "https://user:secret@proxy.example/custom/proxy.pac?site=lab"
        )
        == "/proxy.pac"
    )
    assert (
        proxy_registry.normalize_public_pac_path("/download/wpad.dat#not-sent")
        == "/proxy.pac"
    )
    assert (
        proxy_registry.normalize_public_pac_path(
            "https://proxy.example/custom/proxy.pac?site=lab#not-sent"
        )
        == "/proxy.pac"
    )
    assert proxy_registry.normalize_public_pac_path("//evil.example/wpad.dat") == (
        "/proxy.pac"
    )
    assert proxy_registry.normalize_public_pac_path("/../secret.pac") == "/proxy.pac"
    assert (
        proxy_registry.normalize_public_pac_path("/download/%2e%2e/secret.pac")
        == "/proxy.pac"
    )
    assert proxy_registry.normalize_public_pac_path("/download%2fwpad.dat") == (
        "/proxy.pac"
    )
    assert proxy_registry.normalize_public_pac_path("/download%5cwpad.dat") == (
        "/proxy.pac"
    )
    assert proxy_registry.normalize_public_pac_path("/download/%77pad.dat") == (
        "/download/%77pad.dat"
    )
    assert (
        proxy_registry.normalize_public_pac_path("/download/wpad.dat?site=lab%20one")
        == "/download/wpad.dat?site=lab%20one"
    )
    assert (
        proxy_registry.normalize_public_pac_path("/download/wpad.dat?site=lab\\evil")
        == "/proxy.pac"
    )
    assert (
        proxy_registry.normalize_public_pac_path("/download/wpad.dat?site=lab%5Cevil")
        == "/proxy.pac"
    )
    assert (
        proxy_registry.normalize_public_pac_path("/download/wpad.dat?site=lab%255Cevil")
        == "/proxy.pac"
    )
    assert (
        proxy_registry.normalize_public_pac_path("/download/wpad.dat?site=%0alab")
        == "/proxy.pac"
    )
    assert (
        proxy_registry.normalize_public_pac_path("/download/wpad.dat\nInjected: yes")
        == "/proxy.pac"
    )
    assert (
        proxy_registry.normalize_public_pac_path(
            "javascript:alert(1)",
            default="",
        )
        == ""
    )


@pytest.mark.parametrize(
    "value",
    [
        "/download/root%ZZ.pac",
        "/download/root%",
        "/download/root%A.pac",
        "/download/%E0%A4%A.pac",
        "/download/%25ZZ.pac",
        "/download/%25.pac",
        "/download/%2525ZZ.pac",
        "https://proxy.example/download/root%ZZ.pac",
        "https://proxy.example/download/%E0%A4%A.pac",
        "https://proxy.example/download/%25ZZ.pac",
        "/download/wpad.dat?site=lab%ZZ",
        "/download/wpad.dat?site=lab%",
        "/download/wpad.dat?site=lab%A",
        "/download/wpad.dat?site=%E0%A4%A",
        "/download/wpad.dat?site=%25ZZ",
        "https://proxy.example/download/wpad.dat?site=lab%ZZ",
        "https://proxy.example/download/wpad.dat?site=%E0%A4%A",
        "https://proxy.example/download/wpad.dat?site=%25ZZ",
    ],
)
def test_public_pac_path_normalization_rejects_malformed_percent_encoding(
    value: str,
) -> None:
    proxy_registry = _proxy_registry()

    assert proxy_registry.normalize_public_pac_path(value) == "/proxy.pac"


@pytest.mark.parametrize(
    "value",
    [
        "/download/%252e%252e/secret.pac",
        "/download/%252fwpad.dat",
        "/download/%255cwpad.dat",
        "https://proxy.example/%252e%252e/secret.pac",
        "https://proxy.example/download/%252fwpad.dat",
        "https://proxy.example/download/%255cwpad.dat",
    ],
)
def test_public_pac_path_normalization_rejects_double_encoded_route_shapes(
    value: str,
) -> None:
    proxy_registry = _proxy_registry()

    assert proxy_registry.normalize_public_pac_path(value) == "/proxy.pac"


def test_parse_public_pac_url_rejects_fragment_public_pac_url() -> None:
    proxy_registry = _proxy_registry()

    assert proxy_registry._parse_public_pac_url(
        "https://pac.example:8443/custom/proxy.pac?site=lab#not-sent"
    ) == (
        "",
        "http",
        80,
        "/proxy.pac",
    )


@pytest.mark.parametrize(
    "value",
    [
        "https://pa\tc.example/proxy.pac",
        "https://pac.example/custom/proxy.pac\nInjected: yes",
        "https://pac.example/custom/proxy.pac\x7f",
        "proxy.example/custom\rproxy.pac",
    ],
)
def test_parse_public_pac_url_rejects_control_character_public_pac_urls(
    value: str,
) -> None:
    proxy_registry = _proxy_registry()

    assert proxy_registry._parse_public_pac_url(value) == (
        "",
        "http",
        80,
        "/proxy.pac",
    )


def test_parse_public_pac_url_rejects_zero_explicit_authority_port() -> None:
    proxy_registry = _proxy_registry()

    assert proxy_registry._parse_public_pac_url(
        "https://pac.example:0/custom/proxy.pac?site=lab"
    ) == (
        "",
        "http",
        80,
        "/proxy.pac",
    )


@pytest.mark.parametrize(
    "value",
    [
        "https://pac.example/download/%25ZZ.pac",
        "https://pac.example/download/wpad.dat?site=%25ZZ",
    ],
)
def test_parse_public_pac_url_falls_back_from_reencoded_malformed_percent_path(
    value: str,
) -> None:
    proxy_registry = _proxy_registry()

    assert proxy_registry._parse_public_pac_url(value) == (
        "pac.example",
        "https",
        443,
        "/proxy.pac",
    )


def test_resolve_local_proxy_public_fields_prefers_explicit_env_over_public_pac_url(
    monkeypatch,
) -> None:
    proxy_registry = _proxy_registry()

    monkeypatch.setenv(
        "PROXY_PUBLIC_PAC_URL", "https://from-url.example:8443/proxy.pac"
    )
    monkeypatch.setenv("PROXY_PUBLIC_HOST", "Explicit.Example.")
    monkeypatch.setenv("PROXY_PUBLIC_PAC_SCHEME", "http")
    monkeypatch.setenv("PROXY_PUBLIC_PAC_PORT", "8080")
    monkeypatch.setenv("PROXY_PUBLIC_HTTP_PROXY_PORT", "3129")

    assert proxy_registry.resolve_local_proxy_public_fields() == {
        "public_host": "explicit.example",
        "public_pac_scheme": "http",
        "public_pac_port": 8080,
        "public_pac_path": "/proxy.pac",
        "public_http_proxy_port": 3129,
    }


def test_resolve_local_proxy_public_fields_rejects_invalid_explicit_public_host(
    monkeypatch,
) -> None:
    proxy_registry = _proxy_registry()

    monkeypatch.setenv("PROXY_PUBLIC_PAC_URL", "https://pac.example/wpad.dat?site=lab")
    monkeypatch.setenv("PROXY_PUBLIC_HOST", "bad host.example")
    monkeypatch.delenv("PROXY_PUBLIC_PAC_SCHEME", raising=False)
    monkeypatch.delenv("PROXY_PUBLIC_PAC_PORT", raising=False)
    monkeypatch.delenv("PROXY_PUBLIC_HTTP_PROXY_PORT", raising=False)

    assert proxy_registry.resolve_local_proxy_public_fields() == {
        "public_host": "pac.example",
        "public_pac_scheme": "https",
        "public_pac_port": 443,
        "public_pac_path": "/wpad.dat?site=lab",
        "public_http_proxy_port": 3128,
    }


def test_resolve_local_proxy_public_fields_falls_back_to_public_pac_url_and_port_defaults(
    monkeypatch,
) -> None:
    proxy_registry = _proxy_registry()

    monkeypatch.setenv("PROXY_PUBLIC_PAC_URL", "https://pac.example/wpad.dat?site=lab")
    monkeypatch.delenv("PROXY_PUBLIC_HOST", raising=False)
    monkeypatch.delenv("PROXY_PUBLIC_PAC_SCHEME", raising=False)
    monkeypatch.setenv("PROXY_PUBLIC_PAC_PORT", "not-a-port")
    monkeypatch.setenv("PROXY_PUBLIC_HTTP_PROXY_PORT", "99999")

    assert proxy_registry.resolve_local_proxy_public_fields() == {
        "public_host": "pac.example",
        "public_pac_scheme": "https",
        "public_pac_port": 443,
        "public_pac_path": "/wpad.dat?site=lab",
        "public_http_proxy_port": 3128,
    }


def test_resolve_local_proxy_public_fields_preserves_compose_dns_public_pac_url(
    monkeypatch,
) -> None:
    proxy_registry = _proxy_registry()

    monkeypatch.setenv("PROXY_PUBLIC_HOST", "proxy-edge-2")
    monkeypatch.setenv("PROXY_PUBLIC_PAC_URL", "http://proxy-edge-2/proxy.pac")
    monkeypatch.setenv("PROXY_PUBLIC_PAC_SCHEME", "http")
    monkeypatch.setenv("PROXY_PUBLIC_PAC_PORT", "80")
    monkeypatch.setenv("PROXY_PUBLIC_HTTP_PROXY_PORT", "3128")

    assert proxy_registry.resolve_local_proxy_public_fields() == {
        "public_host": "proxy-edge-2",
        "public_pac_scheme": "http",
        "public_pac_port": 80,
        "public_pac_path": "/proxy.pac",
        "public_http_proxy_port": 3128,
    }


def test_parse_public_pac_url_preserves_compose_dns_public_host() -> None:
    proxy_registry = _proxy_registry()

    assert proxy_registry._parse_public_pac_url("http://proxy-edge-2/proxy.pac") == (
        "proxy-edge-2",
        "http",
        80,
        "/proxy.pac",
    )


def test_resolve_local_proxy_public_fields_rejects_userinfo_public_pac_url(
    monkeypatch,
) -> None:
    proxy_registry = _proxy_registry()

    monkeypatch.setenv(
        "PROXY_PUBLIC_PAC_URL", "https://user:secret@pac.example/wpad.dat?site=lab"
    )
    monkeypatch.delenv("PROXY_PUBLIC_HOST", raising=False)
    monkeypatch.delenv("PROXY_PUBLIC_PAC_SCHEME", raising=False)
    monkeypatch.delenv("PROXY_PUBLIC_PAC_PORT", raising=False)

    assert proxy_registry.resolve_local_proxy_public_fields() == {
        "public_host": "",
        "public_pac_scheme": "http",
        "public_pac_port": 80,
        "public_pac_path": "/proxy.pac",
        "public_http_proxy_port": 3128,
    }


def test_resolve_local_proxy_management_url_prefers_explicit_url(monkeypatch) -> None:
    proxy_registry = _proxy_registry()

    monkeypatch.setenv("PROXY_MANAGEMENT_URL", "http://custom-proxy:9443/root/")
    monkeypatch.setenv("PROXY_MANAGEMENT_HOST", "ignored-host")

    assert (
        proxy_registry.resolve_local_proxy_management_url("Proxy-IT")
        == "http://custom-proxy:9443/root"
    )


def test_management_url_normalization_canonicalizes_listener_base() -> None:
    proxy_registry = _proxy_registry()

    assert (
        proxy_registry.normalize_management_url("proxy-mgmt:5000")
        == "http://proxy-mgmt:5000"
    )
    assert (
        proxy_registry.normalize_management_url("http://Example.COM.:5000/root/")
        == "http://example.com:5000/root"
    )
    assert (
        proxy_registry.normalize_management_url(
            f"http://{IDNA_MANAGEMENT_HOST}:5000/root"
        )
        == "http://xn--bcher-kva.example:5000/root"
    )
    assert (
        proxy_registry.normalize_management_url("http://proxy-mgmt:5000/root/")
        == "http://proxy-mgmt:5000/root"
    )
    assert (
        proxy_registry.normalize_management_url(
            "http://proxy-mgmt:5000/root/api/manage/health",
        )
        == "http://proxy-mgmt:5000/root"
    )
    assert (
        proxy_registry.normalize_management_url("http://proxy-mgmt:5000/root/%68ome")
        == "http://proxy-mgmt:5000/root/%68ome"
    )
    assert (
        proxy_registry.normalize_management_url("http://proxy-mgmt:5000/api/manage")
        == "http://proxy-mgmt:5000"
    )
    assert (
        proxy_registry.normalize_management_url("http://proxy-mgmt:5000/management")
        == "http://proxy-mgmt:5000/management"
    )


def test_management_url_normalization_rejects_unsafe_shapes() -> None:
    proxy_registry = _proxy_registry()

    assert proxy_registry.normalize_management_url("ftp://proxy-mgmt:5000") == ""
    assert proxy_registry.normalize_management_url("http://user:pass@proxy:5000") == ""
    assert proxy_registry.normalize_management_url("http://proxy:bad/api/manage") == ""
    assert proxy_registry.normalize_management_url("http://proxy:0/api/manage") == ""
    assert proxy_registry.normalize_management_url("proxy:0") == ""
    assert proxy_registry.normalize_management_url("http://proxy:") == ""
    assert proxy_registry.normalize_management_url("http://proxy:/api/manage") == ""
    assert proxy_registry.normalize_management_url("proxy:") == ""
    assert (
        proxy_registry.normalize_management_url(
            "http://[2001:4860:4860::8888]:",
        )
        == ""
    )
    assert (
        proxy_registry.normalize_management_url(
            "http://[2001:4860:4860::8888]:/api/manage",
        )
        == ""
    )
    assert proxy_registry.normalize_management_url("http://proxy:5000/../admin") == ""
    assert (
        proxy_registry.normalize_management_url("http://proxy:5000/api%2fmanage/health")
        == ""
    )
    assert (
        proxy_registry.normalize_management_url(
            "http://proxy:5000/root%2fapi/manage/health"
        )
        == ""
    )
    assert (
        proxy_registry.normalize_management_url("http://proxy:5000/root%5cadmin") == ""
    )
    assert (
        proxy_registry.normalize_management_url("http://proxy:5000/root?debug=1") == ""
    )
    assert (
        proxy_registry.normalize_management_url("http://proxy:5000/root#status") == ""
    )
    assert proxy_registry.normalize_management_url("http://proxy:5000/root\nx") == ""


@pytest.mark.parametrize(
    "value",
    [
        "http://proxy:5000/root%ZZ",
        "http://proxy:5000/root%",
        "http://proxy:5000/root%A",
        "http://proxy:5000/%E0%A4%A",
        "http://proxy:5000/root%25ZZ",
        "http://proxy:5000/root%25",
        "http://proxy:5000/root?debug=%ZZ",
        "http://proxy:5000/root?debug=%E0%A4%A",
        "http://proxy:5000/root?debug=%25ZZ",
    ],
)
def test_management_url_normalization_rejects_malformed_percent_encoding(
    value: str,
) -> None:
    proxy_registry = _proxy_registry()

    assert proxy_registry.normalize_management_url(value) == ""


@pytest.mark.parametrize(
    "value",
    [
        "http://proxy.example/%252e%252e/admin",
        "http://proxy.example/root/%252e%252e/admin",
        "http://proxy.example/%252fapi/manage",
        "http://proxy.example/root/%255cadmin",
    ],
)
def test_management_url_normalization_rejects_double_encoded_route_shapes(
    value: str,
) -> None:
    proxy_registry = _proxy_registry()

    assert proxy_registry.normalize_management_url(value) == ""


def test_management_url_normalization_rejects_ambiguous_ipv4_hosts() -> None:
    proxy_registry = _proxy_registry()

    assert proxy_registry.normalize_management_url("http://2130706433:5000") == ""
    assert proxy_registry.normalize_management_url("017700000001:5000") == ""
    assert proxy_registry.normalize_management_url("127.1:5000") == ""
    assert (
        proxy_registry.normalize_management_url(
            f"http://{FULLWIDTH_LOOPBACK_IPV4_IDNA_DOTS}:5000"
        )
        == ""
    )


@pytest.mark.parametrize(
    "value",
    [
        "http://bad_host:5000",
        "http://proxy;evil:5000",
        "http://proxy%2eexample:5000",
        "http://[2001:4860:4860::8888%25eth0]:5000/api/manage",
    ],
)
def test_management_url_normalization_rejects_malformed_authority_hosts(
    value: str,
) -> None:
    proxy_registry = _proxy_registry()

    assert proxy_registry.normalize_management_url(value) == ""


def test_resolve_local_proxy_management_url_derives_from_proxy_id(monkeypatch) -> None:
    proxy_registry = _proxy_registry()

    monkeypatch.delenv("PROXY_MANAGEMENT_URL", raising=False)
    monkeypatch.delenv("PROXY_MANAGEMENT_HOST", raising=False)
    monkeypatch.delenv("PROXY_PUBLIC_HOST", raising=False)
    monkeypatch.delenv("PROXY_MANAGEMENT_SCHEME", raising=False)
    monkeypatch.delenv("PROXY_MANAGEMENT_PORT", raising=False)

    assert (
        proxy_registry.resolve_local_proxy_management_url("Proxy-IT")
        == "http://proxy-it:5000"
    )
    assert (
        proxy_registry.resolve_local_proxy_management_url("default")
        == "http://proxy:5000"
    )


def test_resolve_local_proxy_management_url_supports_host_scheme_and_port(
    monkeypatch,
) -> None:
    proxy_registry = _proxy_registry()

    monkeypatch.delenv("PROXY_MANAGEMENT_URL", raising=False)
    monkeypatch.setenv("PROXY_MANAGEMENT_HOST", "edge-mgmt")
    monkeypatch.setenv("PROXY_MANAGEMENT_SCHEME", "https")
    monkeypatch.setenv("PROXY_MANAGEMENT_PORT", "5443")

    assert (
        proxy_registry.resolve_local_proxy_management_url("Proxy-IT")
        == "https://edge-mgmt:5443"
    )


def test_resolve_local_proxy_management_url_uses_public_host_before_proxy_id(
    monkeypatch,
) -> None:
    proxy_registry = _proxy_registry()

    monkeypatch.delenv("PROXY_MANAGEMENT_URL", raising=False)
    monkeypatch.delenv("PROXY_MANAGEMENT_HOST", raising=False)

    assert (
        proxy_registry.resolve_local_proxy_management_url("live", "proxy")
        == "http://proxy:5000"
    )


def test_row_to_instance_normalizes_ports_booleans_and_display_name() -> None:
    proxy_registry = _proxy_registry()

    row = {
        "proxy_id": "edge-2",
        "display_name": "",
        "hostname": "edge-host",
        "management_url": "http://edge:5000",
        "public_host": "Bad_Edge.Example",
        "public_pac_scheme": "ftp",
        "public_pac_port": 0,
        "public_pac_path": "/../secret.pac",
        "public_http_proxy_port": "3129",
        "status": "healthy",
        "last_heartbeat": 123,
        "last_apply_ts": 456,
        "last_apply_ok": "1",
        "current_config_sha": "abc",
        "detail": "ok",
        "created_ts": 100,
        "updated_ts": 200,
    }

    instance = proxy_registry.ProxyRegistry()._row_to_instance(row)
    assert instance is not None
    assert instance.display_name == "edge-2"
    assert instance.public_host == ""
    assert instance.public_pac_scheme == "http"
    assert instance.public_pac_port == 80
    assert instance.public_pac_path == "/proxy.pac"
    assert instance.public_http_proxy_port == 3129
    assert instance.last_apply_ok is True


def test_init_db_tolerates_concurrent_column_add_race() -> None:
    proxy_registry = _proxy_registry()
    import pymysql  # type: ignore

    class Result:
        def fetchall(self):
            return []

        def fetchone(self):
            return {"acquired": 1}

    class Conn:
        def __init__(self) -> None:
            self.statements: list[str] = []

        def execute(self, sql, params=None):
            statement = str(sql)
            self.statements.append(statement)
            if "ADD COLUMN public_host" in statement:
                raise pymysql.OperationalError(1060, "Duplicate column name")
            return Result()

    class Context:
        def __init__(self, conn: Conn) -> None:
            self.conn = conn

        def __enter__(self) -> Conn:
            return self.conn

        def __exit__(self, exc_type, exc, tb) -> bool:
            return False

    conn = Conn()
    registry = proxy_registry.ProxyRegistry()
    registry._connect = lambda: Context(conn)  # type: ignore[method-assign]

    registry.init_db()

    assert registry._schema_ready is True
    assert any("ADD COLUMN public_host" in statement for statement in conn.statements)


def test_register_local_proxy_reconciles_stale_identity_by_management_url(
    monkeypatch, tmp_path
):
    configure_test_mysql_env(tmp_path / "proxy-identity-reconcile")
    proxy_registry = _proxy_registry()

    registry = proxy_registry.ProxyRegistry()
    registry.ensure_proxy(
        "Proxy-P",
        display_name="Proxy-P",
        hostname="proxy-pr",
        management_url="http://proxy-pr:5000",
        public_host="proxy-pr",
    )
    registry.ensure_proxy("Proxy-IT", management_url="http://proxy-it:5000")

    monkeypatch.setenv("PROXY_INSTANCE_ID", "Proxy-PR")
    monkeypatch.setenv("PROXY_DISPLAY_NAME", "Proxy-PR")
    monkeypatch.setenv("PROXY_MANAGEMENT_URL", "http://proxy-pr:5000")
    monkeypatch.setenv("PROXY_PUBLIC_HOST", "proxy-pr")

    registered = registry.register_local_proxy()

    assert registered.proxy_id == "Proxy-PR"
    assert registered.display_name == "Proxy-PR"
    assert registry.get_proxy("Proxy-P") is None
    assert registry.get_proxy("Proxy-PR") is not None


def test_rename_proxy_rewrites_other_proxy_id_tables(tmp_path):
    configure_test_mysql_env(tmp_path / "proxy-identity-rename")
    proxy_registry = _proxy_registry()

    registry = proxy_registry.ProxyRegistry()
    registry.init_db()
    registry.ensure_proxy("Proxy-P", display_name="Proxy-P")
    with registry._connect() as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS proxy_identity_test_rows (proxy_id VARCHAR(64) NOT NULL, value VARCHAR(32) NOT NULL)"
        )
        conn.execute(
            "INSERT INTO proxy_identity_test_rows(proxy_id, value) VALUES(%s,%s)",
            ("Proxy-P", "kept"),
        )

    renamed = registry.rename_proxy("Proxy-P", "Proxy-PR", display_name="Proxy-PR")

    assert renamed.proxy_id == "Proxy-PR"
    assert registry.get_proxy("Proxy-P") is None
    with registry._connect() as conn:
        row = conn.execute(
            "SELECT proxy_id FROM proxy_identity_test_rows WHERE value=%s",
            ("kept",),
        ).fetchone()
    assert row["proxy_id"] == "Proxy-PR"


def test_resolve_proxy_id_honors_rename_alias(tmp_path):
    configure_test_mysql_env(tmp_path / "proxy-identity-alias")
    proxy_registry = _proxy_registry()

    registry = proxy_registry.ProxyRegistry()
    registry.ensure_proxy("Proxy-P", display_name="Proxy-P")
    with registry._connect() as conn:
        conn.execute(
            "INSERT INTO proxy_id_aliases(alias_proxy_id, proxy_id, created_ts, updated_ts) VALUES(%s,%s,%s,%s)",
            ("Proxy-Legacy", "Proxy-P", 1, 1),
        )

    registry.rename_proxy("Proxy-P", "Proxy-PR", display_name="Proxy-PR")

    assert registry.resolve_proxy_id("Proxy-P") == "Proxy-PR"
    assert registry.resolve_proxy_id("Proxy-Legacy") == "Proxy-PR"
    assert registry.resolve_proxy_id("Proxy-PR") == "Proxy-PR"


def test_remove_proxy_deletes_registry_aliases_and_proxy_scoped_rows(tmp_path):
    configure_test_mysql_env(tmp_path / "proxy-remove")
    proxy_registry = _proxy_registry()

    registry = proxy_registry.ProxyRegistry()
    registry.ensure_proxy("edge-2", display_name="Edge")
    registry.ensure_proxy("edge-keep", display_name="Keep")
    registry.rename_proxy("edge-2", "edge-live", display_name="Edge")
    with registry._connect() as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS proxy_removal_test_rows (proxy_id VARCHAR(64) NOT NULL, value VARCHAR(32) NOT NULL)"
        )
        conn.execute(
            "INSERT INTO proxy_id_aliases(alias_proxy_id, proxy_id, created_ts, updated_ts) VALUES(%s,%s,%s,%s)",
            ("edge-live", "other-proxy", 1, 1),
        )
        conn.execute(
            "INSERT INTO proxy_removal_test_rows(proxy_id, value) VALUES(%s,%s),(%s,%s)",
            ("edge-live", "removed", "other-proxy", "kept"),
        )

    removed = registry.remove_proxy("edge-live")

    assert removed.proxy_id == "edge-live"
    assert removed.table_counts["proxy_instances"] == 1
    assert removed.table_counts["proxy_removal_test_rows"] == 1
    assert removed.table_counts["proxy_id_aliases"] == 1
    assert removed.table_counts["proxy_id_aliases.alias_proxy_id"] == 1
    assert registry.get_proxy("edge-live") is None
    with registry._connect() as conn:
        removed_row = conn.execute(
            "SELECT proxy_id FROM proxy_removal_test_rows WHERE value=%s",
            ("removed",),
        ).fetchone()
        kept_row = conn.execute(
            "SELECT proxy_id FROM proxy_removal_test_rows WHERE value=%s",
            ("kept",),
        ).fetchone()
        alias_row = conn.execute(
            "SELECT proxy_id FROM proxy_id_aliases WHERE alias_proxy_id=%s OR proxy_id=%s",
            ("edge-2", "edge-live"),
        ).fetchone()
    assert removed_row is None
    assert kept_row["proxy_id"] == "other-proxy"
    assert alias_row is None


def test_remove_proxy_rejects_unknown_proxy(tmp_path):
    configure_test_mysql_env(tmp_path / "proxy-remove-missing")
    proxy_registry = _proxy_registry()

    registry = proxy_registry.ProxyRegistry()
    registry.ensure_proxy("default")

    try:
        registry.remove_proxy("missing")
    except ValueError as exc:
        assert "not registered" in str(exc)
    else:
        msg = "remove_proxy should reject unknown proxies"
        raise AssertionError(msg)


def test_init_db_preserves_retired_socks_storage() -> None:
    proxy_registry = _proxy_registry()

    required_columns = {
        "proxy_id",
        "display_name",
        "hostname",
        "management_url",
        "public_host",
        "public_pac_scheme",
        "public_pac_port",
        "public_pac_path",
        "public_http_proxy_port",
        "status",
        "last_heartbeat",
        "last_apply_ts",
        "last_apply_ok",
        "current_config_sha",
        "detail",
        "created_ts",
        "updated_ts",
        "public_socks_enabled",
        "public_socks_proxy_port",
    }

    class Result:
        def __init__(self, rows=None):
            self._rows = rows or []

        def fetchall(self):
            return list(self._rows)

        def fetchone(self):
            return {"acquired": 1}

    class Conn:
        def __init__(self) -> None:
            self.statements: list[str] = []

        def execute(self, sql, params=None):
            statement = str(sql)
            self.statements.append(statement)
            if "information_schema.columns" in statement:
                return Result(
                    [{"column_name": column} for column in sorted(required_columns)]
                )
            return Result()

    class Context:
        def __init__(self, conn: Conn) -> None:
            self.conn = conn

        def __enter__(self) -> Conn:
            return self.conn

        def __exit__(self, exc_type, exc, tb) -> bool:
            return False

    conn = Conn()
    registry = proxy_registry.ProxyRegistry()
    registry._connect = lambda: Context(conn)  # type: ignore[method-assign]

    registry.init_db()

    destructive_statements = [
        statement
        for statement in conn.statements
        if "DROP COLUMN public_socks" in statement
        or "DROP TABLE IF EXISTS socks_events" in statement
    ]
    assert destructive_statements == []


class _FaultResult:
    def __init__(self, row=None, rows=None, *, rowcount: int = 0) -> None:
        self._row = row
        self._rows = list(rows or ([] if row is None else [row]))
        self.rowcount = rowcount

    def fetchone(self):
        return self._row

    def fetchall(self):
        return list(self._rows)


class _RollbackTrackingContext:
    def __init__(self, conn) -> None:
        self.conn = conn

    def __enter__(self):
        return self.conn

    def __exit__(self, exc_type, exc, tb) -> bool:
        if exc_type is None:
            self.conn.commit()
        else:
            self.conn.rollback()
        return False


class _RegistryFaultConn:
    select_row: ClassVar[dict[str, object]] = {
        "proxy_id": "edge-old",
        "display_name": "Edge Old",
        "hostname": "edge-old",
        "management_url": "http://edge-old:5000",
        "public_host": "edge-old",
        "public_pac_scheme": "http",
        "public_pac_port": 80,
        "public_pac_path": "/proxy.pac",
        "public_http_proxy_port": 3128,
        "status": "unknown",
        "last_heartbeat": 0,
        "last_apply_ts": 0,
        "last_apply_ok": 0,
        "current_config_sha": "",
        "detail": "",
        "created_ts": 1,
        "updated_ts": 1,
    }

    def __init__(self, registry_module, *, fail_lifecycle_once: bool = True) -> None:
        import pymysql  # type: ignore

        self.registry_module = registry_module
        self.deadlock_error = pymysql.OperationalError(1213, "deadlock victim")
        self.fail_lifecycle_once = fail_lifecycle_once
        self.attempts = 0
        self.commits = 0
        self.rollbacks = 0
        self.statements: list[str] = []
        self.proxy_rows: dict[str, dict[str, object]] = {
            "edge-old": dict(self.select_row)
        }
        self.aliases: dict[str, str] = {}
        self.tombstones: dict[str, tuple[str, str]] = {}
        self.scoped_rows: list[str] = ["edge-old", "edge-old"]
        self.snapshot_initial()

    def snapshot_initial(self) -> None:
        self._initial_proxy_rows = {
            proxy_id: dict(row) for proxy_id, row in self.proxy_rows.items()
        }
        self._initial_aliases = dict(self.aliases)
        self._initial_tombstones = dict(self.tombstones)
        self._initial_scoped_rows = list(self.scoped_rows)

    def context(self):
        self.attempts += 1
        return _RollbackTrackingContext(self)

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1
        self.proxy_rows = {
            proxy_id: dict(row) for proxy_id, row in self._initial_proxy_rows.items()
        }
        self.aliases = dict(self._initial_aliases)
        self.tombstones = dict(self._initial_tombstones)
        self.scoped_rows = list(self._initial_scoped_rows)

    def execute(self, sql, params=()):
        text = " ".join(str(sql).split())
        self.statements.append(text)
        params = tuple(params or ())
        if text.startswith("SELECT GET_LOCK"):
            return _FaultResult({"acquired": 1})
        if text.startswith("DO RELEASE_LOCK"):
            return _FaultResult()
        if text.startswith("CREATE TABLE IF NOT EXISTS proxy_lifecycle_tombstones"):
            return _FaultResult()
        if "FROM proxy_instances WHERE proxy_id=%s" in text and "FOR UPDATE" in text:
            row = self.proxy_rows.get(str(params[0]))
            return _FaultResult(row)
        if text == "SELECT proxy_id FROM proxy_instances ORDER BY proxy_id FOR UPDATE":
            rows = [{"proxy_id": key} for key in sorted(self.proxy_rows)]
            return _FaultResult(rows=rows)
        if "FROM proxy_id_aliases WHERE alias_proxy_id=%s LIMIT 1" in text:
            target = self.aliases.get(str(params[0]))
            return _FaultResult({"proxy_id": target} if target is not None else None)
        if "FROM proxy_lifecycle_tombstones WHERE proxy_id=%s LIMIT 1" in text:
            tombstone = self.tombstones.get(str(params[0]))
            if tombstone is None:
                return _FaultResult()
            action, target = tombstone
            return _FaultResult({"action": action, "target_proxy_id": target})
        if "FROM proxy_id_aliases WHERE alias_proxy_id IN" in text:
            rows = [
                {"alias_proxy_id": alias, "proxy_id": target}
                for alias, target in sorted(self.aliases.items())
                if alias in {str(params[0]), str(params[1])}
            ]
            return _FaultResult(rows=rows)
        if text.startswith("UPDATE proxy_instances SET status='renaming'"):
            self.proxy_rows[str(params[2])]["status"] = "renaming"
            return _FaultResult(rowcount=1)
        if text.startswith("UPDATE proxy_instances SET status='rename_pending'"):
            self.proxy_rows[str(params[2])]["status"] = "rename_pending"
            return _FaultResult(rowcount=1)
        if text.startswith("INSERT INTO proxy_lifecycle_tombstones"):
            proxy_id = str(params[0])
            if "'renaming'" in text:
                self.tombstones[proxy_id] = ("renaming", str(params[1]))
            elif "'renamed'" in text:
                self.tombstones[proxy_id] = ("renamed", str(params[1]))
            elif "'removing'" in text:
                self.tombstones[proxy_id] = ("removing", "")
            return _FaultResult(rowcount=1)
        if text.startswith("UPDATE proxy_instances SET status='removing'"):
            self.proxy_rows[str(params[2])]["status"] = "removing"
            return _FaultResult(rowcount=1)
        if text.startswith("UPDATE proxy_instances SET status='remove_pending'"):
            self.proxy_rows[str(params[2])]["status"] = "remove_pending"
            return _FaultResult(rowcount=1)
        if text.startswith("UPDATE proxy_instances SET proxy_id=%s"):
            new_key = str(params[0])
            old_key = str(params[-1])
            row = self.proxy_rows.pop(old_key)
            row["proxy_id"] = new_key
            row["display_name"] = str(params[1])
            self.proxy_rows[new_key] = row
            return _FaultResult(rowcount=1)
        if text.startswith("UPDATE proxy_id_aliases SET proxy_id=%s"):
            old_target = str(params[2])
            for alias, target in list(self.aliases.items()):
                if target == old_target:
                    self.aliases[alias] = str(params[0])
            return _FaultResult(rowcount=0)
        if text.startswith("INSERT INTO proxy_id_aliases"):
            self.aliases[str(params[0])] = str(params[1])
            return _FaultResult(rowcount=1)
        if text.startswith("DELETE FROM proxy_lifecycle_tombstones"):
            self.tombstones.pop(str(params[0]), None)
            return _FaultResult(rowcount=1)
        if text.startswith("DELETE FROM proxy_id_aliases WHERE proxy_id=%s"):
            target = str(params[0])
            count = sum(1 for value in self.aliases.values() if value == target)
            self.aliases = {k: v for k, v in self.aliases.items() if v != target}
            return _FaultResult(rowcount=count)
        if text.startswith("DELETE FROM proxy_id_aliases WHERE alias_proxy_id=%s"):
            return _FaultResult(
                rowcount=1 if self.aliases.pop(str(params[0]), None) is not None else 0
            )
        if text.startswith("DELETE FROM proxy_instances WHERE proxy_id=%s"):
            return _FaultResult(
                rowcount=1
                if self.proxy_rows.pop(str(params[0]), None) is not None
                else 0
            )
        if text.startswith("UPDATE proxy_lifecycle_tombstones SET action='removed'"):
            self.tombstones[str(params[2])] = ("removed", "")
            return _FaultResult(rowcount=1)
        msg = f"Unexpected SQL: {text}"
        raise AssertionError(msg)

    def rename_scoped_rows(
        self,
        _conn,
        *,
        old_proxy_id: str,
        new_proxy_id: str,
        **_kwargs,
    ):
        self.scoped_rows = [
            new_proxy_id if row == old_proxy_id else row for row in self.scoped_rows
        ]
        if self.fail_lifecycle_once:
            self.fail_lifecycle_once = False
            raise self.deadlock_error
        return self.registry_module.ProxyLifecycleRunResult(
            action="rename",
            proxy_id=old_proxy_id,
            target_proxy_id=new_proxy_id,
            table_counts={"proxy_fault_rows": len(self.scoped_rows)},
        )

    def remove_scoped_rows(self, _conn, *, proxy_id: str, **_kwargs):
        removed = sum(1 for row in self.scoped_rows if row == proxy_id)
        self.scoped_rows = [row for row in self.scoped_rows if row != proxy_id]
        if self.fail_lifecycle_once:
            self.fail_lifecycle_once = False
            raise self.deadlock_error
        return self.registry_module.ProxyLifecycleRunResult(
            action="remove",
            proxy_id=proxy_id,
            table_counts={"proxy_fault_rows": removed},
        )


def test_rename_proxy_retries_deadlock_as_whole_transaction_without_partial_metadata(
    monkeypatch,
):
    proxy_registry = _proxy_registry()
    conn = _RegistryFaultConn(proxy_registry)
    registry = proxy_registry.ProxyRegistry()
    registry.init_db = lambda: None  # type: ignore[method-assign]
    registry._connect = conn.context  # type: ignore[method-assign]
    monkeypatch.setattr(
        proxy_registry, "prepare_proxy_lifecycle", lambda *_a, **_k: None
    )
    monkeypatch.setattr(
        proxy_registry, "rename_proxy_scoped_rows", conn.rename_scoped_rows
    )
    monkeypatch.setattr(
        proxy_registry, "time", type("Clock", (), {"time": staticmethod(lambda: 10)})
    )
    monkeypatch.setenv("MYSQL_CONNECT_RETRIES", "2")
    monkeypatch.setenv("MYSQL_CONNECT_RETRY_DELAY_SECONDS", "0")
    monkeypatch.setenv("MYSQL_RETRY_JITTER_SECONDS", "0")
    registry.get_proxy = lambda proxy_id: proxy_registry.ProxyInstance(  # type: ignore[method-assign]
        proxy_id=str(proxy_id),
        display_name="Edge New",
        hostname="edge-new",
        management_url="http://edge-new:5000",
        public_host="edge-new",
        public_pac_scheme="http",
        public_pac_port=80,
        public_pac_path="/proxy.pac",
        public_http_proxy_port=3128,
        status="unknown",
        last_heartbeat=0,
        last_apply_ts=0,
        last_apply_ok=False,
        current_config_sha="",
        detail="",
        created_ts=1,
        updated_ts=10,
    )

    renamed = registry.rename_proxy("edge-old", "edge-new", display_name="Edge New")

    assert renamed.proxy_id == "edge-new"
    assert conn.attempts == 2
    assert conn.rollbacks == 1
    assert conn.proxy_rows.keys() == {"edge-new"}
    assert conn.aliases == {"edge-old": "edge-new"}
    assert conn.tombstones == {"edge-old": ("renamed", "edge-new")}
    assert conn.scoped_rows == ["edge-new", "edge-new"]


def test_remove_proxy_retries_deadlock_as_whole_transaction_without_partial_metadata(
    monkeypatch,
):
    proxy_registry = _proxy_registry()
    conn = _RegistryFaultConn(proxy_registry)
    conn.proxy_rows["edge-keep"] = {**conn.select_row, "proxy_id": "edge-keep"}
    conn.snapshot_initial()
    registry = proxy_registry.ProxyRegistry()
    registry.init_db = lambda: None  # type: ignore[method-assign]
    registry._connect = conn.context  # type: ignore[method-assign]
    monkeypatch.setattr(
        proxy_registry, "prepare_proxy_lifecycle", lambda *_a, **_k: None
    )
    monkeypatch.setattr(
        proxy_registry, "remove_proxy_scoped_rows", conn.remove_scoped_rows
    )
    monkeypatch.setattr(
        proxy_registry, "time", type("Clock", (), {"time": staticmethod(lambda: 10)})
    )
    monkeypatch.setenv("MYSQL_CONNECT_RETRIES", "2")
    monkeypatch.setenv("MYSQL_CONNECT_RETRY_DELAY_SECONDS", "0")
    monkeypatch.setenv("MYSQL_RETRY_JITTER_SECONDS", "0")

    removed = registry.remove_proxy("edge-old")

    assert removed.complete is True
    assert conn.attempts == 2
    assert conn.rollbacks == 1
    assert conn.proxy_rows.keys() == {"edge-keep"}
    assert conn.aliases == {}
    assert conn.tombstones == {"edge-old": ("removed", "")}
    assert conn.scoped_rows == []


def test_concurrent_rename_and_remove_same_source_serializes_without_hijack(tmp_path):
    configure_test_mysql_env(tmp_path / "proxy-rename-remove-concurrent")
    proxy_registry = _proxy_registry()

    registry = proxy_registry.ProxyRegistry()
    registry.ensure_proxy("edge-old", display_name="Old")
    registry.ensure_proxy("edge-keep", display_name="Keep")
    with registry._connect() as conn:
        conn.execute(
            "CREATE TABLE proxy_concurrent_lifecycle_rows (id BIGINT PRIMARY KEY AUTO_INCREMENT, proxy_id VARCHAR(64) NOT NULL, value VARCHAR(32) NOT NULL)",
        )
        conn.execute(
            "INSERT INTO proxy_concurrent_lifecycle_rows(proxy_id, value) VALUES(%s,%s)",
            ("edge-old", "owned"),
        )

    def rename_old():
        return ("rename", registry.rename_proxy("edge-old", "edge-new").proxy_id)

    def remove_old():
        return ("remove", registry.remove_proxy("edge-old").proxy_id)

    results = _concurrent_results(rename_old, remove_old)
    successes = [payload for status, payload, *_rest in results if status == "ok"]
    failures = [payload for status, *payload in results if status == "err"]

    assert len(successes) == 1
    assert len(failures) == 1
    assert registry.get_proxy("edge-old") is None
    assert registry.get_proxy("edge-keep") is not None

    with registry._connect() as conn:
        rows = conn.execute(
            "SELECT proxy_id, COUNT(*) AS c FROM proxy_concurrent_lifecycle_rows GROUP BY proxy_id ORDER BY proxy_id",
        ).fetchall()
    grouped_rows = [(row["proxy_id"], int(row["c"] or 0)) for row in rows]

    if successes[0][0] == "rename":
        assert successes[0] == ("rename", "edge-new")
        assert registry.get_proxy("edge-new") is not None
        assert registry.resolve_proxy_id("edge-old") == "edge-new"
        assert grouped_rows == [("edge-new", 1)]
    else:
        assert successes[0] == ("remove", "edge-old")
        assert registry.get_proxy("edge-new") is None
        assert grouped_rows == []


def test_concurrent_rename_same_source_to_different_targets_serializes_without_hijack(
    tmp_path,
):
    configure_test_mysql_env(tmp_path / "proxy-rename-rename-concurrent")
    proxy_registry = _proxy_registry()

    registry = proxy_registry.ProxyRegistry()
    registry.ensure_proxy("edge-old", display_name="Old")
    with registry._connect() as conn:
        conn.execute(
            "CREATE TABLE proxy_concurrent_rename_rows (id BIGINT PRIMARY KEY AUTO_INCREMENT, proxy_id VARCHAR(64) NOT NULL, value VARCHAR(32) NOT NULL)",
        )
        conn.execute(
            "INSERT INTO proxy_concurrent_rename_rows(proxy_id, value) VALUES(%s,%s),(%s,%s)",
            ("edge-old", "a", "edge-old", "b"),
        )

    def rename_a():
        return registry.rename_proxy("edge-old", "edge-new-a").proxy_id

    def rename_b():
        return registry.rename_proxy("edge-old", "edge-new-b").proxy_id

    results = _concurrent_results(rename_a, rename_b)
    successes = [payload for status, payload, *_rest in results if status == "ok"]
    failures = [payload for status, *payload in results if status == "err"]

    assert len(successes) == 1
    assert len(failures) == 1
    winner = successes[0]
    loser = "edge-new-b" if winner == "edge-new-a" else "edge-new-a"
    assert registry.get_proxy("edge-old") is None
    assert registry.get_proxy(winner) is not None
    assert registry.get_proxy(loser) is None
    assert registry.resolve_proxy_id("edge-old") == winner
    with registry._connect() as conn:
        rows = conn.execute(
            "SELECT proxy_id, COUNT(*) AS c FROM proxy_concurrent_rename_rows GROUP BY proxy_id ORDER BY proxy_id",
        ).fetchall()
    assert [(row["proxy_id"], int(row["c"] or 0)) for row in rows] == [(winner, 2)]


def test_lifecycle_incomplete_error_identity_survives_lifecycle_reload() -> None:
    proxy_registry = _proxy_registry()
    from services import proxy_lifecycle  # type: ignore
    from services.proxy_lifecycle import ProxyLifecycleIncompleteError  # type: ignore

    reloaded_lifecycle = importlib.reload(proxy_lifecycle)

    assert (
        reloaded_lifecycle.ProxyLifecycleIncompleteError
        is ProxyLifecycleIncompleteError
    )
    assert proxy_registry.ProxyLifecycleIncompleteError is ProxyLifecycleIncompleteError


def test_rename_proxy_incomplete_lifecycle_rolls_back_without_success_metadata(
    monkeypatch,
):
    proxy_registry = _proxy_registry()
    from services.proxy_lifecycle import ProxyLifecycleIncompleteError  # type: ignore

    conn = _RegistryFaultConn(proxy_registry, fail_lifecycle_once=False)
    registry = proxy_registry.ProxyRegistry()
    registry.init_db = lambda: None  # type: ignore[method-assign]
    registry._connect = conn.context  # type: ignore[method-assign]
    monkeypatch.setattr(
        proxy_registry, "prepare_proxy_lifecycle", lambda *_a, **_k: None
    )

    def incomplete(_conn, *, old_proxy_id: str, new_proxy_id: str, **_kwargs):
        conn.scoped_rows = [
            new_proxy_id if row == old_proxy_id else row for row in conn.scoped_rows
        ]
        return proxy_registry.ProxyLifecycleRunResult(
            action="rename",
            proxy_id=old_proxy_id,
            target_proxy_id=new_proxy_id,
            complete=False,
            table_counts={"proxy_fault_rows": 1},
            truncated_tables=("proxy_fault_rows",),
        )

    monkeypatch.setattr(proxy_registry, "rename_proxy_scoped_rows", incomplete)
    monkeypatch.setattr(
        proxy_registry, "time", type("Clock", (), {"time": staticmethod(lambda: 10)})
    )

    with pytest.raises(ProxyLifecycleIncompleteError, match="paused"):
        registry.rename_proxy("edge-old", "edge-new", display_name="Edge New")

    assert conn.attempts == 1
    assert conn.rollbacks == 1
    assert conn.proxy_rows.keys() == {"edge-old"}
    assert conn.proxy_rows["edge-old"]["status"] == "unknown"
    assert conn.aliases == {}
    assert conn.tombstones == {}
    assert conn.scoped_rows == ["edge-old", "edge-old"]


def test_remove_proxy_incomplete_lifecycle_rolls_back_without_success_metadata(
    monkeypatch,
):
    proxy_registry = _proxy_registry()
    from services.proxy_lifecycle import ProxyLifecycleIncompleteError  # type: ignore

    conn = _RegistryFaultConn(proxy_registry, fail_lifecycle_once=False)
    conn.proxy_rows["edge-keep"] = {**conn.select_row, "proxy_id": "edge-keep"}
    conn.snapshot_initial()
    registry = proxy_registry.ProxyRegistry()
    registry.init_db = lambda: None  # type: ignore[method-assign]
    registry._connect = conn.context  # type: ignore[method-assign]
    monkeypatch.setattr(
        proxy_registry, "prepare_proxy_lifecycle", lambda *_a, **_k: None
    )

    def incomplete(_conn, *, proxy_id: str, **_kwargs):
        conn.scoped_rows = [row for row in conn.scoped_rows if row != proxy_id]
        return proxy_registry.ProxyLifecycleRunResult(
            action="remove",
            proxy_id=proxy_id,
            complete=False,
            table_counts={"proxy_fault_rows": 1},
            truncated_tables=("proxy_fault_rows",),
        )

    monkeypatch.setattr(proxy_registry, "remove_proxy_scoped_rows", incomplete)
    monkeypatch.setattr(
        proxy_registry, "time", type("Clock", (), {"time": staticmethod(lambda: 10)})
    )

    with pytest.raises(ProxyLifecycleIncompleteError, match="paused"):
        registry.remove_proxy("edge-old")

    assert conn.attempts == 1
    assert conn.rollbacks == 1
    assert conn.proxy_rows.keys() == {"edge-keep", "edge-old"}
    assert conn.proxy_rows["edge-old"]["status"] == "unknown"
    assert conn.aliases == {}
    assert conn.tombstones == {}
    assert conn.scoped_rows == ["edge-old", "edge-old"]


def test_rename_proxy_is_idempotent_and_tombstones_old_identity(tmp_path):
    configure_test_mysql_env(tmp_path / "proxy-rename-idempotent")
    proxy_registry = _proxy_registry()

    registry = proxy_registry.ProxyRegistry()
    registry.ensure_proxy("edge-old", display_name="Edge")
    first = registry.rename_proxy("edge-old", "edge-new", display_name="Edge New")
    second = registry.rename_proxy("edge-old", "edge-new", display_name="Edge New")

    assert first.proxy_id == "edge-new"
    assert second.proxy_id == "edge-new"
    assert registry.resolve_proxy_id("edge-old") == "edge-new"
    try:
        registry.ensure_proxy("edge-old")
    except ValueError as exc:
        assert "renamed to" in str(exc)
    else:
        msg = "renamed proxy id must not be recreated by stale writers"
        raise AssertionError(msg)


@pytest.mark.parametrize(
    ("old_proxy_id", "new_proxy_id"),
    [("edge-default", "edge-renamed"), ("edge-old", "edge-default")],
)
def test_rename_proxy_rejects_default_identity(
    tmp_path,
    monkeypatch,
    old_proxy_id,
    new_proxy_id,
):
    monkeypatch.setenv("DEFAULT_PROXY_ID", "edge-default")
    configure_test_mysql_env(
        tmp_path / f"proxy-rename-default-{old_proxy_id}-{new_proxy_id}",
    )
    proxy_registry = _proxy_registry()

    registry = proxy_registry.ProxyRegistry()
    registry.ensure_proxy("edge-default", display_name="Default")
    registry.ensure_proxy("edge-old", display_name="Old")

    with pytest.raises(ValueError, match="Default proxy"):
        registry.rename_proxy(old_proxy_id, new_proxy_id)

    assert registry.get_proxy("edge-default") is not None
    assert registry.get_proxy("edge-old") is not None


def test_rename_proxy_rejects_target_alias_collision(tmp_path):
    configure_test_mysql_env(tmp_path / "proxy-rename-alias-collision")
    proxy_registry = _proxy_registry()

    registry = proxy_registry.ProxyRegistry()
    registry.ensure_proxy("edge-old", display_name="Old")
    registry.ensure_proxy("edge-live", display_name="Live")
    registry.rename_proxy("edge-live", "edge-new", display_name="New")

    with pytest.raises(ValueError, match="already registered as an alias"):
        registry.rename_proxy("edge-old", "edge-live")

    assert registry.get_proxy("edge-old") is not None
    assert registry.get_proxy("edge-new") is not None


def test_rename_proxy_rejects_incomplete_idempotent_retry_with_leftover_rows(
    tmp_path,
):
    configure_test_mysql_env(tmp_path / "proxy-rename-leftover-idempotency")
    proxy_registry = _proxy_registry()
    from services.proxy_lifecycle import ProxyLifecycleIncompleteError  # type: ignore

    registry = proxy_registry.ProxyRegistry()
    registry.ensure_proxy("edge-new", display_name="New")
    with registry._connect() as conn:
        conn.execute(
            """
            INSERT INTO proxy_id_aliases(alias_proxy_id, proxy_id, created_ts, updated_ts)
            VALUES(%s,%s,%s,%s)
            """,
            ("edge-old", "edge-new", 1, 1),
        )
        conn.execute(
            """
            INSERT INTO proxy_lifecycle_tombstones(proxy_id, action, target_proxy_id, detail, created_ts, updated_ts)
            VALUES(%s,'renaming',%s,'incomplete',1,1)
            """,
            ("edge-old", "edge-new"),
        )
        conn.execute(
            "CREATE TABLE proxy_leftover_rows (id BIGINT PRIMARY KEY AUTO_INCREMENT, proxy_id VARCHAR(64) NOT NULL)",
        )
        conn.execute(
            "INSERT INTO proxy_leftover_rows(proxy_id) VALUES(%s)",
            ("edge-old",),
        )

    with pytest.raises(ProxyLifecycleIncompleteError, match="leftover scoped rows"):
        registry.rename_proxy("edge-old", "edge-new")


def test_rename_proxy_repairs_completed_rename_metadata_without_old_row(tmp_path):
    configure_test_mysql_env(tmp_path / "proxy-rename-repair-metadata")
    proxy_registry = _proxy_registry()

    registry = proxy_registry.ProxyRegistry()
    registry.ensure_proxy("edge-new", display_name="New")
    with registry._connect() as conn:
        conn.execute(
            """
            INSERT INTO proxy_lifecycle_tombstones(proxy_id, action, target_proxy_id, detail, created_ts, updated_ts)
            VALUES(%s,'renaming',%s,'needs metadata repair',1,1)
            """,
            ("edge-old", "edge-new"),
        )

    repaired = registry.rename_proxy("edge-old", "edge-new")

    assert repaired.proxy_id == "edge-new"
    assert registry.resolve_proxy_id("edge-old") == "edge-new"
    with registry._connect() as conn:
        tombstone = conn.execute(
            "SELECT action FROM proxy_lifecycle_tombstones WHERE proxy_id=%s",
            ("edge-old",),
        ).fetchone()
    assert tombstone["action"] == "renamed"


def test_rename_proxy_rejects_conflicting_in_progress_target_without_mysql(monkeypatch):
    proxy_registry = _proxy_registry()

    class Result:
        def __init__(self, row=None):
            self._row = row

        def fetchone(self):
            return self._row

    class Conn:
        def execute(self, sql, params=None):
            statement = str(sql)
            if "FROM proxy_instances" in statement and "FOR UPDATE" in statement:
                return Result({"proxy_id": "edge-old", "display_name": "Edge"})
            if "FROM proxy_lifecycle_tombstones" in statement:
                return Result(
                    {
                        "action": "renaming",
                        "target_proxy_id": "edge-new-a",
                    },
                )
            return Result()

        def commit(self) -> None:
            return None

    class Context:
        def __enter__(self):
            return Conn()

        def __exit__(self, exc_type, exc, tb):
            return False

    class Lock:
        def __enter__(self):
            return None

        def __exit__(self, exc_type, exc, tb):
            return False

    registry = proxy_registry.ProxyRegistry()
    registry.init_db = lambda: None  # type: ignore[method-assign]
    registry._connect = Context  # type: ignore[method-assign]
    monkeypatch.setattr(proxy_registry, "mysql_advisory_lock", lambda *args: Lock())
    monkeypatch.setattr(
        proxy_registry, "prepare_proxy_lifecycle", lambda *_a, **_k: None
    )

    try:
        registry.rename_proxy("edge-old", "edge-new-b", display_name="Edge B")
    except ValueError as exc:
        assert "rename in progress to 'edge-new-a'" in str(exc)
    else:
        msg = "paused rename must not resume toward a different target"
        raise AssertionError(msg)


def test_rename_proxy_incomplete_bounded_result_rolls_back_before_retry(
    monkeypatch,
    tmp_path,
):
    configure_test_mysql_env(tmp_path / "proxy-rename-conflicting-retry")
    proxy_registry = _proxy_registry()
    from services.proxy_lifecycle import ProxyLifecycleIncompleteError  # type: ignore

    registry = proxy_registry.ProxyRegistry()
    registry.ensure_proxy("edge-old", display_name="Edge")
    with registry._connect() as conn:
        conn.execute(
            "CREATE TABLE proxy_rename_conflict_rows (id BIGINT PRIMARY KEY AUTO_INCREMENT, proxy_id VARCHAR(64) NOT NULL, value VARCHAR(32) NOT NULL)",
        )
        for i in range(5):
            conn.execute(
                "INSERT INTO proxy_rename_conflict_rows(proxy_id, value) VALUES(%s,%s)",
                ("edge-old", f"row-{i}"),
            )

    monkeypatch.setenv("MYSQL_PROXY_LIFECYCLE_CHUNK_SIZE", "2")
    monkeypatch.setenv("MYSQL_PROXY_LIFECYCLE_MAX_ROWS_PER_TABLE", "2")
    try:
        registry.rename_proxy("edge-old", "edge-new-a", display_name="Edge A")
    except ProxyLifecycleIncompleteError as exc:
        assert exc.result.truncated_tables == ("proxy_rename_conflict_rows",)
        assert exc.result.table_counts["proxy_rename_conflict_rows"] == 2
    else:
        msg = "rename should pause at bounded table limit"
        raise AssertionError(msg)

    with registry._connect() as conn:
        rows = conn.execute(
            "SELECT proxy_id, COUNT(*) AS c FROM proxy_rename_conflict_rows GROUP BY proxy_id ORDER BY proxy_id",
        ).fetchall()
        status = conn.execute(
            "SELECT status FROM proxy_instances WHERE proxy_id=%s",
            ("edge-old",),
        ).fetchone()
        tombstone = conn.execute(
            "SELECT 1 FROM proxy_lifecycle_tombstones WHERE proxy_id=%s",
            ("edge-old",),
        ).fetchone()
    assert [(row["proxy_id"], int(row["c"] or 0)) for row in rows] == [
        ("edge-old", 5),
    ]
    assert status["status"] != "rename_pending"
    assert tombstone is None

    monkeypatch.setenv("MYSQL_PROXY_LIFECYCLE_MAX_ROWS_PER_TABLE", "100")
    resumed = registry.rename_proxy("edge-old", "edge-new-b", display_name="Edge B")

    assert resumed.proxy_id == "edge-new-b"
    with registry._connect() as conn:
        rows = conn.execute(
            "SELECT proxy_id, COUNT(*) AS c FROM proxy_rename_conflict_rows GROUP BY proxy_id ORDER BY proxy_id",
        ).fetchall()
    assert [(row["proxy_id"], int(row["c"] or 0)) for row in rows] == [
        ("edge-new-b", 5),
    ]


def test_remove_proxy_cleans_pac_profile_children_and_tombstones_identity(tmp_path):
    configure_test_mysql_env(tmp_path / "proxy-remove-pac-children")
    proxy_registry = _proxy_registry()

    registry = proxy_registry.ProxyRegistry()
    registry.ensure_proxy("edge-remove", display_name="Edge")
    registry.ensure_proxy("edge-keep", display_name="Keep")
    with registry._connect() as conn:
        conn.execute(
            """
            CREATE TABLE pac_profiles (
                id BIGINT PRIMARY KEY AUTO_INCREMENT,
                proxy_id VARCHAR(64) NOT NULL DEFAULT 'default',
                name VARCHAR(255) NOT NULL,
                client_cidr VARCHAR(64) NOT NULL DEFAULT '',
                created_ts BIGINT NOT NULL,
                KEY idx_pac_profiles_proxy (proxy_id, id)
            )
            """,
        )
        conn.execute(
            "CREATE TABLE pac_direct_domains (profile_id BIGINT NOT NULL, domain VARCHAR(255) NOT NULL, PRIMARY KEY(profile_id, domain))",
        )
        conn.execute(
            "CREATE TABLE pac_direct_dst_nets (profile_id BIGINT NOT NULL, cidr VARCHAR(64) NOT NULL, PRIMARY KEY(profile_id, cidr))",
        )
        result = conn.execute(
            "INSERT INTO pac_profiles(proxy_id, name, client_cidr, created_ts) VALUES(%s,'p','',1)",
            ("edge-remove",),
        )
        profile_id = int(result.lastrowid)
        conn.execute(
            "INSERT INTO pac_direct_domains(profile_id, domain) VALUES(%s,'example.com')",
            (profile_id,),
        )
        conn.execute(
            "INSERT INTO pac_direct_dst_nets(profile_id, cidr) VALUES(%s,'10.0.0.0/8')",
            (profile_id,),
        )

    removed = registry.remove_proxy("edge-remove")

    assert removed.complete is True
    assert removed.table_counts["pac_profiles"] == 1
    assert removed.table_counts["pac_direct_domains"] == 1
    assert removed.table_counts["pac_direct_dst_nets"] == 1
    assert registry.get_proxy("edge-remove") is None
    try:
        registry.ensure_proxy("edge-remove")
    except ValueError as exc:
        assert "removed" in str(exc)
    else:
        msg = "removed proxy id must not be recreated"
        raise AssertionError(msg)
    with registry._connect() as conn:
        assert (
            conn.execute("SELECT 1 FROM pac_direct_domains LIMIT 1").fetchone() is None
        )
        assert (
            conn.execute("SELECT 1 FROM pac_direct_dst_nets LIMIT 1").fetchone() is None
        )


def test_remove_proxy_rejects_default_identity(tmp_path, monkeypatch):
    monkeypatch.setenv("DEFAULT_PROXY_ID", "edge-default")
    configure_test_mysql_env(tmp_path / "proxy-remove-default")
    proxy_registry = _proxy_registry()

    registry = proxy_registry.ProxyRegistry()
    registry.ensure_proxy("edge-default", display_name="Default")
    registry.ensure_proxy("edge-other", display_name="Other")

    with pytest.raises(ValueError, match="Default proxy"):
        registry.remove_proxy("edge-default")

    assert registry.get_proxy("edge-default") is not None


def test_remove_proxy_rejects_last_proxy(tmp_path):
    configure_test_mysql_env(tmp_path / "proxy-remove-last")
    proxy_registry = _proxy_registry()

    registry = proxy_registry.ProxyRegistry()
    registry.ensure_proxy("edge-only", display_name="Only")

    with pytest.raises(ValueError, match="last registered proxy"):
        registry.remove_proxy("edge-only")

    assert registry.get_proxy("edge-only") is not None


def test_remove_proxy_incomplete_bounded_result_rolls_back_before_retry(
    monkeypatch,
    tmp_path,
):
    configure_test_mysql_env(tmp_path / "proxy-remove-resume")
    proxy_registry = _proxy_registry()
    from services.proxy_lifecycle import ProxyLifecycleIncompleteError  # type: ignore

    registry = proxy_registry.ProxyRegistry()
    registry.ensure_proxy("edge-big", display_name="Edge")
    registry.ensure_proxy("edge-keep", display_name="Keep")
    with registry._connect() as conn:
        conn.execute(
            "CREATE TABLE proxy_large_backlog (id BIGINT PRIMARY KEY AUTO_INCREMENT, proxy_id VARCHAR(64) NOT NULL, value VARCHAR(32) NOT NULL)",
        )
        for i in range(5):
            conn.execute(
                "INSERT INTO proxy_large_backlog(proxy_id, value) VALUES(%s,%s)",
                ("edge-big", f"row-{i}"),
            )

    monkeypatch.setenv("MYSQL_PROXY_LIFECYCLE_CHUNK_SIZE", "2")
    monkeypatch.setenv("MYSQL_PROXY_LIFECYCLE_MAX_ROWS_PER_TABLE", "2")
    try:
        registry.remove_proxy("edge-big")
    except ProxyLifecycleIncompleteError as exc:
        assert exc.result.truncated_tables == ("proxy_large_backlog",)
        assert exc.result.table_counts["proxy_large_backlog"] == 2
    else:
        msg = "removal should pause at bounded table limit"
        raise AssertionError(msg)

    with registry._connect() as conn:
        remaining = conn.execute(
            "SELECT COUNT(*) AS c FROM proxy_large_backlog WHERE proxy_id=%s",
            ("edge-big",),
        ).fetchone()
        status = conn.execute(
            "SELECT status FROM proxy_instances WHERE proxy_id=%s",
            ("edge-big",),
        ).fetchone()
        tombstone = conn.execute(
            "SELECT 1 FROM proxy_lifecycle_tombstones WHERE proxy_id=%s",
            ("edge-big",),
        ).fetchone()
    assert int(remaining["c"] or 0) == 5
    assert status["status"] != "remove_pending"
    assert tombstone is None

    monkeypatch.setenv("MYSQL_PROXY_LIFECYCLE_MAX_ROWS_PER_TABLE", "100")
    removed = registry.remove_proxy("edge-big")

    assert removed.complete is True
    assert removed.table_counts["proxy_large_backlog"] == 5
    assert "proxy_large_backlog" in removed.discovered_tables
    assert registry.remove_proxy("edge-big").deleted_rows == 0


def test_rename_proxy_missing_prepared_index_rolls_back_without_ddl_leak(
    monkeypatch,
    tmp_path,
):
    configure_test_mysql_env(tmp_path / "proxy-rename-missing-prepared-index")
    proxy_registry = _proxy_registry()
    from services.proxy_lifecycle import ProxyLifecycleIncompleteError  # type: ignore

    registry = proxy_registry.ProxyRegistry()
    registry.ensure_proxy("edge-old", display_name="Edge")
    with registry._connect() as conn:
        conn.execute(
            "CREATE TABLE proxy_missing_rename_index (id BIGINT PRIMARY KEY AUTO_INCREMENT, proxy_id VARCHAR(64) NOT NULL, value VARCHAR(32) NOT NULL)",
        )
        for i in range(3):
            conn.execute(
                "INSERT INTO proxy_missing_rename_index(proxy_id, value) VALUES(%s,%s)",
                ("edge-old", f"row-{i}"),
            )

    original_prepare = proxy_registry.prepare_proxy_lifecycle
    monkeypatch.setattr(
        proxy_registry,
        "prepare_proxy_lifecycle",
        lambda *_args, **_kwargs: (),
    )
    with pytest.raises(ProxyLifecycleIncompleteError) as exc_info:
        registry.rename_proxy("edge-old", "edge-new", display_name="Edge")

    assert exc_info.value.result.truncated_tables == ("proxy_missing_rename_index",)
    with registry._connect() as conn:
        rows = conn.execute(
            "SELECT proxy_id, COUNT(*) AS c FROM proxy_missing_rename_index GROUP BY proxy_id ORDER BY proxy_id",
        ).fetchall()
        old_status = conn.execute(
            "SELECT status FROM proxy_instances WHERE proxy_id=%s",
            ("edge-old",),
        ).fetchone()
        new_row = conn.execute(
            "SELECT 1 FROM proxy_instances WHERE proxy_id=%s LIMIT 1",
            ("edge-new",),
        ).fetchone()
        tombstone = conn.execute(
            "SELECT 1 FROM proxy_lifecycle_tombstones WHERE proxy_id=%s LIMIT 1",
            ("edge-old",),
        ).fetchone()
        index_row = conn.execute(
            """
            SELECT 1
            FROM information_schema.statistics
            WHERE table_schema = DATABASE()
              AND table_name = 'proxy_missing_rename_index'
              AND column_name = 'proxy_id'
              AND seq_in_index = 1
            LIMIT 1
            """,
        ).fetchone()
    assert [(row["proxy_id"], int(row["c"] or 0)) for row in rows] == [
        ("edge-old", 3),
    ]
    assert old_status["status"] == "unknown"
    assert new_row is None
    assert tombstone is None
    assert index_row is None

    monkeypatch.setattr(proxy_registry, "prepare_proxy_lifecycle", original_prepare)
    renamed = registry.rename_proxy("edge-old", "edge-new", display_name="Edge")

    assert renamed.proxy_id == "edge-new"
    with registry._connect() as conn:
        rows = conn.execute(
            "SELECT proxy_id, COUNT(*) AS c FROM proxy_missing_rename_index GROUP BY proxy_id ORDER BY proxy_id",
        ).fetchall()
    assert [(row["proxy_id"], int(row["c"] or 0)) for row in rows] == [
        ("edge-new", 3),
    ]


def test_remove_proxy_missing_prepared_index_rolls_back_without_ddl_leak(
    monkeypatch,
    tmp_path,
):
    configure_test_mysql_env(tmp_path / "proxy-remove-missing-prepared-index")
    proxy_registry = _proxy_registry()
    from services.proxy_lifecycle import ProxyLifecycleIncompleteError  # type: ignore

    registry = proxy_registry.ProxyRegistry()
    registry.ensure_proxy("edge-remove", display_name="Edge")
    registry.ensure_proxy("edge-keep", display_name="Keep")
    with registry._connect() as conn:
        conn.execute(
            "CREATE TABLE proxy_missing_remove_index (id BIGINT PRIMARY KEY AUTO_INCREMENT, proxy_id VARCHAR(64) NOT NULL, value VARCHAR(32) NOT NULL)",
        )
        for i in range(3):
            conn.execute(
                "INSERT INTO proxy_missing_remove_index(proxy_id, value) VALUES(%s,%s)",
                ("edge-remove", f"row-{i}"),
            )

    original_prepare = proxy_registry.prepare_proxy_lifecycle
    monkeypatch.setattr(
        proxy_registry,
        "prepare_proxy_lifecycle",
        lambda *_args, **_kwargs: (),
    )
    with pytest.raises(ProxyLifecycleIncompleteError) as exc_info:
        registry.remove_proxy("edge-remove")

    assert exc_info.value.result.truncated_tables == ("proxy_missing_remove_index",)
    with registry._connect() as conn:
        remaining = conn.execute(
            "SELECT COUNT(*) AS c FROM proxy_missing_remove_index WHERE proxy_id=%s",
            ("edge-remove",),
        ).fetchone()
        status = conn.execute(
            "SELECT status FROM proxy_instances WHERE proxy_id=%s",
            ("edge-remove",),
        ).fetchone()
        tombstone = conn.execute(
            "SELECT 1 FROM proxy_lifecycle_tombstones WHERE proxy_id=%s LIMIT 1",
            ("edge-remove",),
        ).fetchone()
        index_row = conn.execute(
            """
            SELECT 1
            FROM information_schema.statistics
            WHERE table_schema = DATABASE()
              AND table_name = 'proxy_missing_remove_index'
              AND column_name = 'proxy_id'
              AND seq_in_index = 1
            LIMIT 1
            """,
        ).fetchone()
    assert int(remaining["c"] or 0) == 3
    assert status["status"] == "unknown"
    assert tombstone is None
    assert index_row is None

    monkeypatch.setattr(proxy_registry, "prepare_proxy_lifecycle", original_prepare)
    removed = registry.remove_proxy("edge-remove")

    assert removed.complete is True
    assert registry.get_proxy("edge-remove") is None
    with registry._connect() as conn:
        remaining = conn.execute(
            "SELECT COUNT(*) AS c FROM proxy_missing_remove_index WHERE proxy_id=%s",
            ("edge-remove",),
        ).fetchone()
    assert int(remaining["c"] or 0) == 0


def test_rename_proxy_adds_lifecycle_index_for_discovered_tables(tmp_path):
    configure_test_mysql_env(tmp_path / "proxy-rename-index-contract")
    proxy_registry = _proxy_registry()

    registry = proxy_registry.ProxyRegistry()
    registry.ensure_proxy("edge-source", display_name="Edge")
    with registry._connect() as conn:
        conn.execute(
            "CREATE TABLE proxy_unindexed_rows (id BIGINT PRIMARY KEY AUTO_INCREMENT, proxy_id VARCHAR(64) NOT NULL, value VARCHAR(32) NOT NULL)",
        )
        conn.execute(
            "INSERT INTO proxy_unindexed_rows(proxy_id, value) VALUES(%s,'x')",
            ("edge-source",),
        )

    registry.rename_proxy("edge-source", "edge-target", display_name="Edge")

    with registry._connect() as conn:
        row = conn.execute(
            "SELECT proxy_id FROM proxy_unindexed_rows WHERE value='x'",
        ).fetchone()
        index_row = conn.execute(
            """
            SELECT 1
            FROM information_schema.statistics
            WHERE table_schema = DATABASE()
              AND table_name = 'proxy_unindexed_rows'
              AND column_name = 'proxy_id'
              AND seq_in_index = 1
            LIMIT 1
            """,
        ).fetchone()
    assert row["proxy_id"] == "edge-target"
    assert index_row is not None
