from __future__ import annotations

import importlib
import os


def test_mysql_test_env_vars_take_priority_over_local_env_files(monkeypatch):
    mysql_test_utils = importlib.import_module("web.tests.mysql_test_utils")
    tracked_keys = [
        "DATABASE_URL",
        "MYSQL_HOST",
        "MYSQL_PORT",
        "MYSQL_USER",
        "MYSQL_PASSWORD",
        "MYSQL_DATABASE",
        "MYSQL_CHARSET",
        "MYSQL_CONNECT_TIMEOUT",
    ]
    original = {key: os.environ.get(key) for key in tracked_keys}

    monkeypatch.setattr(mysql_test_utils, "_LOADED_ENV", False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("MYSQL_HOST", raising=False)
    monkeypatch.delenv("MYSQL_USER", raising=False)
    monkeypatch.delenv("MYSQL_PASSWORD", raising=False)
    monkeypatch.delenv("MYSQL_PORT", raising=False)
    monkeypatch.delenv("MYSQL_TEST_ALLOW_ENV_FILES", raising=False)
    monkeypatch.setenv("MYSQL_TEST_HOST", "127.0.0.1")
    monkeypatch.setenv("MYSQL_TEST_PORT", "3307")
    monkeypatch.setenv("MYSQL_TEST_USER", "root")
    monkeypatch.setenv("MYSQL_TEST_PASSWORD", "secret")

    try:
        mysql_test_utils._load_mysql_env_if_needed()

        assert mysql_test_utils.os.environ["MYSQL_HOST"] == "127.0.0.1"
        assert mysql_test_utils.os.environ["MYSQL_PORT"] == "3307"
        assert mysql_test_utils.os.environ["MYSQL_USER"] == "root"
        assert mysql_test_utils.os.environ["MYSQL_PASSWORD"] == "secret"
    finally:
        for key, value in original.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
