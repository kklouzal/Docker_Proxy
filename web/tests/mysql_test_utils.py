from __future__ import annotations

import atexit
import hashlib
import os
import sys
import tempfile
from pathlib import Path
from typing import Any
from unittest import SkipTest
from urllib.parse import urlparse, urlunparse

import pymysql


REPO_ROOT = Path(__file__).resolve().parents[2]
WEB_ROOT = REPO_ROOT / "web"
_LOADED_ENV = False
_REGISTERED_DATABASES: set[str] = set()
_CLEANUP_REGISTERED = False
_TEST_ENV_MAP = {
    "MYSQL_TEST_DATABASE_URL": "DATABASE_URL",
    "MYSQL_TEST_HOST": "MYSQL_HOST",
    "MYSQL_TEST_PORT": "MYSQL_PORT",
    "MYSQL_TEST_USER": "MYSQL_USER",
    "MYSQL_TEST_PASSWORD": "MYSQL_PASSWORD",
    "MYSQL_TEST_DATABASE": "MYSQL_DATABASE",
    "MYSQL_TEST_CHARSET": "MYSQL_CHARSET",
    "MYSQL_TEST_CONNECT_TIMEOUT": "MYSQL_CONNECT_TIMEOUT",
}
_MODULES_TO_PURGE_EXACT = {"app", "proxy"}
_MODULES_TO_PURGE_PREFIXES = ("services.", "proxy.")


def ensure_python_import_paths(*paths: str | Path) -> None:
    for path in paths:
        path_text = str(path)
        if path_text not in sys.path:
            sys.path.insert(0, path_text)


def ensure_web_import_path() -> None:
    ensure_python_import_paths(WEB_ROOT)


def ensure_proxy_runtime_import_path() -> None:
    ensure_python_import_paths(REPO_ROOT, WEB_ROOT)


def make_temp_dir(prefix: str) -> Path:
    return Path(tempfile.mkdtemp(prefix=prefix))


def make_temp_secret_path(prefix: str, *, filename: str = "flask_secret.key") -> Path:
    return make_temp_dir(prefix) / filename


def apply_test_environment(overrides: dict[str, object] | None = None) -> None:
    for key, value in (overrides or {}).items():
        os.environ[str(key)] = str(value)


def _parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values

    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            value = value[1:-1]
        values[key] = value
    return values


def _load_mysql_env_if_needed() -> None:
    global _LOADED_ENV
    if _LOADED_ENV:
        return
    _LOADED_ENV = True

    if os.environ.get("DATABASE_URL") or os.environ.get("MYSQL_HOST"):
        return

    explicit_test_env = False
    for source_key, target_key in _TEST_ENV_MAP.items():
        value = (os.environ.get(source_key) or "").strip()
        if value:
            os.environ[target_key] = value
            explicit_test_env = True
    if explicit_test_env:
        return

    allow_env_files = (os.environ.get("MYSQL_TEST_ALLOW_ENV_FILES") or "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    if not allow_env_files:
        return

    for env_path in (REPO_ROOT / ".env", REPO_ROOT / "config" / "app.env"):
        values = _parse_env_file(env_path)
        for key in (
            "DATABASE_URL",
            "MYSQL_HOST",
            "MYSQL_PORT",
            "MYSQL_USER",
            "MYSQL_PASSWORD",
            "MYSQL_DATABASE",
            "MYSQL_CHARSET",
            "MYSQL_CONNECT_TIMEOUT",
            "MYSQL_CREATE_DATABASE",
        ):
            if key in values and not os.environ.get(key):
                os.environ[key] = values[key]
        if os.environ.get("DATABASE_URL") or os.environ.get("MYSQL_HOST"):
            return


def _base_connection_params() -> dict[str, Any]:
    _load_mysql_env_if_needed()

    url = (os.environ.get("DATABASE_URL") or "").strip()
    if url:
        parsed = urlparse(url)
        scheme = (parsed.scheme or "").lower()
        if not scheme.startswith("mysql"):
            raise SkipTest(f"Unsupported DATABASE_URL for MySQL tests: {scheme}")
        return {
            "host": parsed.hostname or "127.0.0.1",
            "port": int(parsed.port or 3306),
            "user": parsed.username or os.environ.get("MYSQL_USER") or "root",
            "password": parsed.password or os.environ.get("MYSQL_PASSWORD") or "",
            "charset": os.environ.get("MYSQL_CHARSET") or "utf8mb4",
            "connect_timeout": int(os.environ.get("MYSQL_CONNECT_TIMEOUT") or "10"),
        }

    host = (os.environ.get("MYSQL_HOST") or "").strip()
    user = (os.environ.get("MYSQL_USER") or "").strip()
    if not host and not user:
        raise SkipTest(
            "MySQL test configuration is not available. Set DATABASE_URL, MYSQL_* variables, or MYSQL_TEST_* variables. "
            "To opt into loading local env files for tests, set MYSQL_TEST_ALLOW_ENV_FILES=1."
        )

    return {
        "host": host or "127.0.0.1",
        "port": int((os.environ.get("MYSQL_PORT") or "3306").strip() or "3306"),
        "user": user or "root",
        "password": os.environ.get("MYSQL_PASSWORD") or "",
        "charset": os.environ.get("MYSQL_CHARSET") or "utf8mb4",
        "connect_timeout": int((os.environ.get("MYSQL_CONNECT_TIMEOUT") or "10").strip() or "10"),
    }


def _drop_database(database_name: str) -> None:
    params = _base_connection_params()
    conn = pymysql.connect(autocommit=True, **params)
    try:
        with conn.cursor() as cur:
            cur.execute(f"DROP DATABASE IF EXISTS `{database_name}`")
    finally:
        conn.close()


def _register_cleanup() -> None:
    global _CLEANUP_REGISTERED
    if _CLEANUP_REGISTERED:
        return
    _CLEANUP_REGISTERED = True

    def _cleanup() -> None:
        for database_name in sorted(_REGISTERED_DATABASES):
            try:
                _drop_database(database_name)
            except Exception:
                pass

    atexit.register(_cleanup)


def _reset_db_module_cache() -> None:
    ensure_web_import_path()
    try:
        from services.db import reset_mysql_ready_for_tests
    except Exception:
        return
    reset_mysql_ready_for_tests()


def _set_database_name(database_name: str) -> None:
    url = (os.environ.get("DATABASE_URL") or "").strip()
    if url:
        parsed = urlparse(url)
        new_url = urlunparse(parsed._replace(path=f"/{database_name}"))
        os.environ["DATABASE_URL"] = new_url
    os.environ["MYSQL_DATABASE"] = database_name


def _purge_runtime_modules() -> None:
    for module_name in list(sys.modules):
        if module_name in _MODULES_TO_PURGE_EXACT or module_name.startswith(_MODULES_TO_PURGE_PREFIXES):
            sys.modules.pop(module_name, None)


def configure_test_mysql_env(seed: object, *, secret_path: str | Path | None = None) -> str:
    digest = hashlib.sha1(str(seed).encode("utf-8", errors="replace")).hexdigest()[:16]
    database_name = f"sfp_test_{digest}"

    _load_mysql_env_if_needed()
    _set_database_name(database_name)
    os.environ["MYSQL_CREATE_DATABASE"] = "1"
    os.environ["DISABLE_BACKGROUND"] = "1"
    if secret_path is not None:
        os.environ["FLASK_SECRET_PATH"] = str(secret_path)

    _drop_database(database_name)
    _REGISTERED_DATABASES.add(database_name)
    _register_cleanup()
    _reset_db_module_cache()
    _purge_runtime_modules()
    return database_name
