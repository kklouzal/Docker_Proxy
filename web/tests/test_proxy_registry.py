from __future__ import annotations

import sys
from pathlib import Path

from .mysql_test_utils import configure_test_mysql_env


def _add_web_to_path() -> None:
    web_dir = Path(__file__).resolve().parents[1]
    if str(web_dir) not in sys.path:
        sys.path.insert(0, str(web_dir))


def test_parse_public_pac_url_handles_scheme_host_ports_and_invalid_values() -> None:
    _add_web_to_path()
    from services import proxy_registry  # type: ignore

    assert proxy_registry._parse_public_pac_url("proxy.example") == (
        "proxy.example",
        "http",
        80,
    )
    assert proxy_registry._parse_public_pac_url("https://proxy.example/proxy.pac") == (
        "proxy.example",
        "https",
        443,
    )
    assert proxy_registry._parse_public_pac_url(
        "http://proxy.example:8080/proxy.pac"
    ) == ("proxy.example", "http", 8080)
    assert proxy_registry._parse_public_pac_url("") == ("", "http", 80)
    assert proxy_registry._parse_public_pac_url(
        "ftp://proxy.example:9000/proxy.pac"
    ) == ("proxy.example", "http", 9000)
    assert proxy_registry._parse_public_pac_url(
        "https://proxy.example:not-a-port/proxy.pac"
    ) == ("proxy.example", "https", 443)


def test_resolve_local_proxy_public_fields_prefers_explicit_env_over_public_pac_url(
    monkeypatch,
) -> None:
    _add_web_to_path()
    from services import proxy_registry  # type: ignore

    monkeypatch.setenv(
        "PROXY_PUBLIC_PAC_URL", "https://from-url.example:8443/proxy.pac"
    )
    monkeypatch.setenv("PROXY_PUBLIC_HOST", "explicit.example")
    monkeypatch.setenv("PROXY_PUBLIC_PAC_SCHEME", "http")
    monkeypatch.setenv("PROXY_PUBLIC_PAC_PORT", "8080")
    monkeypatch.setenv("PROXY_PUBLIC_HTTP_PROXY_PORT", "3129")

    assert proxy_registry.resolve_local_proxy_public_fields() == {
        "public_host": "explicit.example",
        "public_pac_scheme": "http",
        "public_pac_port": 8080,
        "public_http_proxy_port": 3129,
    }


def test_resolve_local_proxy_public_fields_falls_back_to_public_pac_url_and_port_defaults(
    monkeypatch,
) -> None:
    _add_web_to_path()
    from services import proxy_registry  # type: ignore

    monkeypatch.setenv("PROXY_PUBLIC_PAC_URL", "https://pac.example/proxy.pac")
    monkeypatch.delenv("PROXY_PUBLIC_HOST", raising=False)
    monkeypatch.delenv("PROXY_PUBLIC_PAC_SCHEME", raising=False)
    monkeypatch.setenv("PROXY_PUBLIC_PAC_PORT", "not-a-port")
    monkeypatch.setenv("PROXY_PUBLIC_HTTP_PROXY_PORT", "99999")

    assert proxy_registry.resolve_local_proxy_public_fields() == {
        "public_host": "pac.example",
        "public_pac_scheme": "https",
        "public_pac_port": 443,
        "public_http_proxy_port": 3128,
    }


def test_resolve_local_proxy_management_url_prefers_explicit_url(monkeypatch) -> None:
    _add_web_to_path()
    from services import proxy_registry  # type: ignore

    monkeypatch.setenv("PROXY_MANAGEMENT_URL", "http://custom-proxy:9443/root/")
    monkeypatch.setenv("PROXY_MANAGEMENT_HOST", "ignored-host")

    assert (
        proxy_registry.resolve_local_proxy_management_url("Proxy-IT")
        == "http://custom-proxy:9443/root"
    )


def test_resolve_local_proxy_management_url_derives_from_proxy_id(monkeypatch) -> None:
    _add_web_to_path()
    from services import proxy_registry  # type: ignore

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
    _add_web_to_path()
    from services import proxy_registry  # type: ignore

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
    _add_web_to_path()
    from services import proxy_registry  # type: ignore

    monkeypatch.delenv("PROXY_MANAGEMENT_URL", raising=False)
    monkeypatch.delenv("PROXY_MANAGEMENT_HOST", raising=False)

    assert (
        proxy_registry.resolve_local_proxy_management_url("live", "proxy")
        == "http://proxy:5000"
    )


def test_row_to_instance_normalizes_ports_booleans_and_display_name() -> None:
    _add_web_to_path()
    from services import proxy_registry  # type: ignore

    row = {
        "proxy_id": "edge-2",
        "display_name": "",
        "hostname": "edge-host",
        "management_url": "http://edge:5000",
        "public_host": "edge.example",
        "public_pac_scheme": "ftp",
        "public_pac_port": 0,
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
    assert instance.public_pac_scheme == "http"
    assert instance.public_pac_port == 80
    assert instance.public_http_proxy_port == 3129
    assert instance.last_apply_ok is True


def test_init_db_tolerates_concurrent_column_add_race() -> None:
    _add_web_to_path()
    import pymysql  # type: ignore
    from services import proxy_registry  # type: ignore

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
    _add_web_to_path()
    from services import proxy_registry  # type: ignore

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
    _add_web_to_path()
    from services import proxy_registry  # type: ignore

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
    _add_web_to_path()
    from services import proxy_registry  # type: ignore

    registry = proxy_registry.ProxyRegistry()
    registry.ensure_proxy("Proxy-P", display_name="Proxy-P")

    registry.rename_proxy("Proxy-P", "Proxy-PR", display_name="Proxy-PR")

    assert registry.resolve_proxy_id("Proxy-P") == "Proxy-PR"
    assert registry.resolve_proxy_id("Proxy-PR") == "Proxy-PR"


def test_init_db_preserves_retired_socks_storage() -> None:
    _add_web_to_path()
    from services import proxy_registry  # type: ignore

    required_columns = {
        "proxy_id",
        "display_name",
        "hostname",
        "management_url",
        "public_host",
        "public_pac_scheme",
        "public_pac_port",
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
