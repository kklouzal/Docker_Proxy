from __future__ import annotations

import atexit
import contextlib
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
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
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

    allow_env_files = (
        os.environ.get("MYSQL_TEST_ALLOW_ENV_FILES") or ""
    ).strip().lower() in {
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
            msg = f"Unsupported DATABASE_URL for MySQL tests: {scheme}"
            raise SkipTest(msg)
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
        msg = (
            "MySQL test configuration is not available. Set DATABASE_URL, MYSQL_* variables, or MYSQL_TEST_* variables. "
            "To opt into loading local env files for tests, set MYSQL_TEST_ALLOW_ENV_FILES=1."
        )
        raise SkipTest(
            msg,
        )

    return {
        "host": host or "127.0.0.1",
        "port": int((os.environ.get("MYSQL_PORT") or "3306").strip() or "3306"),
        "user": user or "root",
        "password": os.environ.get("MYSQL_PASSWORD") or "",
        "charset": os.environ.get("MYSQL_CHARSET") or "utf8mb4",
        "connect_timeout": int(
            (os.environ.get("MYSQL_CONNECT_TIMEOUT") or "10").strip() or "10"
        ),
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
            with contextlib.suppress(Exception):
                _drop_database(database_name)

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


# Runtime modules (and their parent-package attributes) as they were before the
# first purge in the current test. ``configure_test_mysql_env`` purges them so the
# test re-imports services against its private database; the snapshot lets the
# suite-wide fixture restore the original module objects afterwards. Without the
# restore, test modules that imported ``services.*`` at collection time keep the
# old module objects while ``monkeypatch.setattr("services.x.attr", ...)`` and
# fresh imports in later tests resolve to the purged-and-reimported copies, which
# makes results depend on test order.
_MODULE_SNAPSHOT: dict[str, Any] | None = None
_MISSING = object()


def _is_runtime_module(module_name: str) -> bool:
    return module_name in _MODULES_TO_PURGE_EXACT or module_name.startswith(
        _MODULES_TO_PURGE_PREFIXES
    )


def _snapshot_runtime_modules() -> None:
    global _MODULE_SNAPSHOT
    if _MODULE_SNAPSHOT is not None:
        return
    _MODULE_SNAPSHOT = {
        name: module for name, module in sys.modules.items() if _is_runtime_module(name)
    }


def restore_runtime_modules() -> bool:
    """Undo every runtime-module purge made since the last restore.

    Called after each test by the suite-wide autouse fixture in the repository
    ``conftest.py``. Returns False (and does nothing) unless the test called
    ``configure_test_mysql_env``; the fixture then also restores the process
    environment, so the MySQL settings mapped from ``MYSQL_TEST_*`` are mapped
    again by the next MySQL test instead of leaking into later tests.
    """
    global _LOADED_ENV, _MODULE_SNAPSHOT
    snapshot = _MODULE_SNAPSHOT
    if snapshot is None:
        return False
    _MODULE_SNAPSHOT = None
    _LOADED_ENV = False
    _close_discarded_db_module(snapshot.get("services.db"))
    for module_name in [name for name in sys.modules if _is_runtime_module(name)]:
        if module_name not in snapshot:
            _detach_from_package(module_name)
            sys.modules.pop(module_name, None)
    for module_name, module in snapshot.items():
        sys.modules[module_name] = module
    for module_name, module in snapshot.items():
        if "." not in module_name:
            continue
        package_name, attr_name = module_name.rsplit(".", 1)
        package = sys.modules.get(package_name)
        if package is not None:
            setattr(package, attr_name, module)
    return True


def _close_discarded_db_module(original: Any) -> None:
    # The re-imported services.db owns its own connection pool and connect
    # circuit (probe thread). Release them before the module is dropped, or
    # every MySQL test strands idle connections until the server runs out
    # (1040 Too many connections).
    fresh = sys.modules.get("services.db")
    if fresh is None or fresh is original:
        return
    reset = getattr(fresh, "reset_mysql_ready_for_tests", None)
    if callable(reset):
        reset()


def _detach_from_package(module_name: str) -> None:
    if "." not in module_name:
        return
    package_name, attr_name = module_name.rsplit(".", 1)
    package = sys.modules.get(package_name)
    if package is not None and getattr(package, attr_name, _MISSING) is sys.modules.get(
        module_name
    ):
        delattr(package, attr_name)


def _purge_runtime_modules() -> None:
    _snapshot_runtime_modules()
    purged: list[str] = []
    for module_name in list(sys.modules):
        if _is_runtime_module(module_name):
            sys.modules.pop(module_name, None)
            purged.append(module_name)
    for module_name in purged:
        if "." not in module_name:
            continue
        package_name, attr_name = module_name.rsplit(".", 1)
        package = sys.modules.get(package_name)
        if package is not None and getattr(package, attr_name, None) is not None:
            delattr(package, attr_name)


def configure_test_mysql_env(
    seed: object, *, secret_path: str | Path | None = None
) -> str:
    digest = hashlib.sha1(str(seed).encode("utf-8", errors="replace")).hexdigest()[:16]
    database_name = f"sfp_test_{digest}"

    _load_mysql_env_if_needed()
    _base_connection_params()
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


def register_test_proxies(*proxy_ids: str) -> None:
    """Register proxies the way Admin UI/proxy startup does before proxy writes.

    Proxy-scoped stores write through ``guarded_proxy_write``, which fails closed
    unless the proxy registry metadata exists and the target proxy is registered.
    Call after ``configure_test_mysql_env`` so the registry uses the test database.
    """
    from services.proxy_registry import get_proxy_registry  # type: ignore

    registry = get_proxy_registry()
    registry.init_db()
    for proxy_id in proxy_ids or ("default",):
        registry.ensure_proxy(proxy_id)
