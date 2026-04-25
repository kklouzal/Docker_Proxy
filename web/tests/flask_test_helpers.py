from __future__ import annotations

import importlib
import sys
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .mysql_test_utils import apply_test_environment, configure_test_mysql_env, ensure_web_import_path, make_temp_secret_path


def _require_flask() -> None:
    try:
        import flask  # noqa: F401
    except Exception as exc:  # pragma: no cover - environment dependent
        raise unittest.SkipTest(f"Flask not available in this environment: {exc}") from exc


def import_local_app_module(
    *,
    secret_prefix: str = "sfp_secret_",
    mysql_prefix: str = "sfp_mysql_",
):
    _require_flask()
    ensure_web_import_path()
    apply_test_environment(
        {
            "DISABLE_BACKGROUND": "1",
            "PROXY_MANAGEMENT_TOKEN": "test-token",
            "DEFAULT_PROXY_ID": "default",
        }
    )
    secret_path = make_temp_secret_path(secret_prefix)
    configure_test_mysql_env(str(make_temp_secret_path(mysql_prefix, filename="mysql-marker")), secret_path=secret_path)

    import app as app_module  # type: ignore

    app_module.app.testing = True
    return app_module


def import_local_flask_app(
    *,
    secret_prefix: str = "sfp_secret_",
    mysql_prefix: str = "sfp_mysql_",
):
    return import_local_app_module(secret_prefix=secret_prefix, mysql_prefix=mysql_prefix).app


def import_isolated_app_module(tmp_path: Path):
    _require_flask()
    ensure_web_import_path()
    apply_test_environment(
        {
            "DISABLE_BACKGROUND": "1",
            "PROXY_MANAGEMENT_TOKEN": "test-token",
            "DEFAULT_PROXY_ID": "default",
        }
    )
    configure_test_mysql_env(tmp_path, secret_path=tmp_path / "flask_secret.key")

    if "app" in sys.modules:
        del sys.modules["app"]

    import app as app_module  # type: ignore

    importlib.reload(app_module)
    app_module.app.testing = True
    return app_module


def get_csrf_token(client) -> str:
    client.get("/login")
    with client.session_transaction() as sess:
        return sess.get("_csrf_token", "") or ""


def login(client, username: str = "admin", password: str = "admin", next_url: str = "") -> str:
    csrf = get_csrf_token(client)
    response = client.post(
        "/login",
        data={"username": username, "password": password, "next": next_url, "csrf_token": csrf},
        follow_redirects=False,
    )
    assert response.status_code in (301, 302, 303, 307, 308)
    return csrf


def redirect_query_params(response) -> dict[str, list[str]]:
    location = response.headers.get("Location", "") or ""
    return parse_qs(urlsplit(location).query)