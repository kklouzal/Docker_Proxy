from __future__ import annotations

import sys
from pathlib import Path

import pytest

from .mysql_test_utils import configure_test_mysql_env


def _add_web_to_path() -> None:
    web_dir = Path(__file__).resolve().parents[1]
    if str(web_dir) not in sys.path:
        sys.path.insert(0, str(web_dir))


def test_auth_store_connect_uses_shared_db_connector(tmp_path, monkeypatch) -> None:
    _add_web_to_path()
    from services import auth_store  # type: ignore

    sentinel = object()
    captured: dict[str, object] = {"args": (), "kwargs": {}}

    def fake_connect(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return sentinel

    monkeypatch.setattr(auth_store, "connect", fake_connect)

    store = auth_store.AuthStore(secret_path=str(tmp_path / "secret.key"))
    assert store._connect() is sentinel
    assert captured["args"] == ()
    assert captured["kwargs"] == {}


def test_auth_store_username_and_password_validation(tmp_path) -> None:
    _add_web_to_path()
    configure_test_mysql_env(tmp_path, secret_path=tmp_path / "secret.key")

    from services.auth_store import AuthStore  # type: ignore

    store = AuthStore(secret_path=str(tmp_path / "secret.key"))

    for username in ("", "has space", "bad@name", "x" * 65):
        with pytest.raises(ValueError):
            store.add_user(username, "pass")

    for password in ("", "123"):
        with pytest.raises(ValueError):
            store.add_user("ok", password)

    store.add_user("user_1", "1234")
    assert store.verify_user("user_1", "1234") is True
    assert store.verify_user("user_1", "nope") is False

    with pytest.raises(ValueError, match="already exists"):
        store.add_user("user_1", "abcd")

    with pytest.raises(ValueError, match="not found"):
        store.set_password("missing", "abcd")

    with pytest.raises(ValueError, match="not found"):
        store.delete_user("missing")

    store.set_password("user_1", "abcd")
    assert store.verify_user("user_1", "abcd") is True
    store.delete_user("user_1")
    assert store.verify_user("user_1", "abcd") is False