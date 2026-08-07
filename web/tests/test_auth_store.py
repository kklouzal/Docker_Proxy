from __future__ import annotations

import multiprocessing
import stat
import sys
import threading
import time
from pathlib import Path

import pytest

from .mysql_test_utils import configure_test_mysql_env


def _add_web_to_path() -> None:
    web_dir = Path(__file__).resolve().parents[1]
    if str(web_dir) not in sys.path:
        sys.path.insert(0, str(web_dir))


def _auth_store_module():
    _add_web_to_path()
    from services import auth_store  # type: ignore

    return auth_store


def test_auth_store_connect_uses_shared_db_connector(tmp_path, monkeypatch) -> None:
    auth_store = _auth_store_module()

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


def test_auth_store_repairs_existing_secret_permissions(tmp_path) -> None:
    auth_store = _auth_store_module()
    secret_path = tmp_path / "secret.key"
    secret_path.write_text("existing-secret\n", encoding="utf-8")
    secret_path.chmod(0o644)

    store = auth_store.AuthStore(secret_path=str(secret_path))

    assert store.get_or_create_secret_key() == "existing-secret"
    assert stat.S_IMODE(secret_path.stat().st_mode) == 0o600


def test_auth_store_refuses_existing_secret_symlink_without_following(
    tmp_path,
    monkeypatch,
) -> None:
    auth_store = _auth_store_module()
    target_path = tmp_path / "outside.key"
    target_path.write_text("outside-secret\n", encoding="utf-8")
    target_path.chmod(0o644)
    secret_path = tmp_path / "secret.key"
    secret_path.symlink_to(target_path)
    path_calls = {"open": 0, "chmod": 0}
    original_open = Path.open
    original_chmod = Path.chmod

    def tracked_open(path, *args, **kwargs):
        if path == secret_path:
            path_calls["open"] += 1
        return original_open(path, *args, **kwargs)

    def tracked_chmod(path, *args, **kwargs):
        if path == secret_path:
            path_calls["chmod"] += 1
        return original_chmod(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", tracked_open)
    monkeypatch.setattr(Path, "chmod", tracked_chmod)
    store = auth_store.AuthStore(secret_path=str(secret_path))

    with pytest.raises(RuntimeError, match="must not be a symlink"):
        store.get_or_create_secret_key()

    assert path_calls == {"open": 0, "chmod": 0}
    assert target_path.read_text(encoding="utf-8") == "outside-secret\n"
    assert stat.S_IMODE(target_path.stat().st_mode) == 0o644


def test_auth_store_refuses_existing_non_regular_secret_path(tmp_path) -> None:
    auth_store = _auth_store_module()
    secret_path = tmp_path / "secret.key"
    secret_path.mkdir()
    store = auth_store.AuthStore(secret_path=str(secret_path))

    with pytest.raises(RuntimeError, match="must be a regular file"):
        store.get_or_create_secret_key()


def test_auth_store_creates_secret_with_owner_only_permissions(
    tmp_path,
    monkeypatch,
) -> None:
    auth_store = _auth_store_module()
    monkeypatch.setattr(auth_store.secrets, "token_urlsafe", lambda size: "new-secret")
    secret_path = tmp_path / "nested" / "secret.key"

    store = auth_store.AuthStore(secret_path=str(secret_path))

    assert store.get_or_create_secret_key() == "new-secret"
    assert secret_path.read_text(encoding="utf-8") == "new-secret\n"
    assert stat.S_IMODE(secret_path.stat().st_mode) == 0o600


def test_auth_store_replaces_existing_empty_secret_file(tmp_path, monkeypatch) -> None:
    auth_store = _auth_store_module()
    monkeypatch.setattr(auth_store.secrets, "token_urlsafe", lambda size: "new-secret")
    secret_path = tmp_path / "secret.key"
    secret_path.touch(mode=0o644)

    store = auth_store.AuthStore(secret_path=str(secret_path))

    assert store.get_or_create_secret_key() == "new-secret"
    assert secret_path.read_text(encoding="utf-8") == "new-secret\n"
    assert stat.S_IMODE(secret_path.stat().st_mode) == 0o600


def test_auth_store_does_not_use_predictable_shared_tmp_path(
    tmp_path,
    monkeypatch,
) -> None:
    auth_store = _auth_store_module()
    monkeypatch.setattr(auth_store.secrets, "token_urlsafe", lambda size: "new-secret")
    secret_path = tmp_path / "secret.key"
    predictable_tmp_path = tmp_path / "secret.key.tmp"
    predictable_tmp_path.write_text("do-not-clobber\n", encoding="utf-8")

    store = auth_store.AuthStore(secret_path=str(secret_path))

    assert store.get_or_create_secret_key() == "new-secret"
    assert secret_path.read_text(encoding="utf-8") == "new-secret\n"
    assert predictable_tmp_path.read_text(encoding="utf-8") == "do-not-clobber\n"
    assert list(tmp_path.glob(".secret.key.*.tmp")) == []


def test_auth_store_fsyncs_parent_after_failed_secret_publish_cleanup(
    tmp_path,
    monkeypatch,
) -> None:
    auth_store = _auth_store_module()
    monkeypatch.setattr(auth_store.secrets, "token_urlsafe", lambda size: "new-secret")
    publish_error = OSError("secret publication failed")

    def fail_secret_publish(*_args, **_kwargs) -> None:
        raise publish_error

    monkeypatch.setattr(auth_store.os, "link", fail_secret_publish)
    parent_fsyncs: list[Path] = []
    monkeypatch.setattr(
        auth_store,
        "_fsync_parent_dir",
        lambda path: parent_fsyncs.append(Path(path).parent),
    )
    secret_path = tmp_path / "secret.key"

    with pytest.raises(OSError, match="secret publication failed") as raised:
        auth_store.AuthStore(secret_path=str(secret_path)).get_or_create_secret_key()

    assert raised.value is publish_error
    assert parent_fsyncs == [tmp_path]
    assert not secret_path.exists()
    assert list(tmp_path.glob(".secret.key.*.tmp")) == []


def test_auth_store_secret_creation_is_serialized_for_concurrent_callers(
    tmp_path,
    monkeypatch,
) -> None:
    auth_store = _auth_store_module()
    calls = 0
    calls_lock = threading.Lock()

    def fake_token_urlsafe(_size: int) -> str:
        nonlocal calls
        with calls_lock:
            calls += 1
            value = f"new-secret-{calls}"
        time.sleep(0.02)
        return value

    monkeypatch.setattr(auth_store.secrets, "token_urlsafe", fake_token_urlsafe)
    secret_path = tmp_path / "secret.key"
    store = auth_store.AuthStore(secret_path=str(secret_path))
    ready = threading.Barrier(8)
    results: list[str] = []

    def load_secret() -> None:
        ready.wait(timeout=2)
        results.append(store.get_or_create_secret_key())

    threads = [threading.Thread(target=load_secret) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=2)

    assert all(not thread.is_alive() for thread in threads)
    assert results == ["new-secret-1"] * 8
    assert secret_path.read_text(encoding="utf-8") == "new-secret-1\n"
    assert calls == 1


def _load_secret_in_process(secret_path, ready, result_queue, worker_id: int) -> None:
    auth_store = _auth_store_module()
    original_read = auth_store.AuthStore._read_existing_secret_file

    def synchronized_initial_read(path: Path) -> str | None:
        value = original_read(path)
        if value is None:
            ready.wait(timeout=5)
        return value

    auth_store.AuthStore._read_existing_secret_file = staticmethod(
        synchronized_initial_read,
    )
    auth_store.secrets.token_urlsafe = lambda _size: f"process-secret-{worker_id}"
    try:
        result = auth_store.AuthStore(secret_path=secret_path).get_or_create_secret_key()
        result_queue.put(("ok", result))
    except BaseException as exc:
        result_queue.put(("error", repr(exc)))


def test_auth_store_secret_creation_is_atomic_across_processes(tmp_path) -> None:
    context = multiprocessing.get_context("fork")
    secret_path = tmp_path / "secret.key"
    ready = context.Barrier(4)
    result_queue = context.Queue()
    processes = [
        context.Process(
            target=_load_secret_in_process,
            args=(str(secret_path), ready, result_queue, worker_id),
        )
        for worker_id in range(4)
    ]

    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=10)

    stuck_processes = [process for process in processes if process.is_alive()]
    for process in stuck_processes:
        process.terminate()
        process.join(timeout=2)
    assert not stuck_processes
    assert all(process.exitcode == 0 for process in processes)
    results = [result_queue.get(timeout=2) for _ in processes]
    result_queue.close()
    result_queue.join_thread()
    assert all(status == "ok" for status, _result in results)
    returned_secrets = [result for _status, result in results]
    assert returned_secrets == [returned_secrets[0]] * len(returned_secrets)
    assert secret_path.read_text(encoding="utf-8") == f"{returned_secrets[0]}\n"
    assert list(tmp_path.glob(".secret.key.*.tmp")) == []


def test_auth_store_username_and_password_validation(tmp_path) -> None:
    configure_test_mysql_env(tmp_path, secret_path=tmp_path / "secret.key")
    auth_store_cls = _auth_store_module().AuthStore

    store = auth_store_cls(secret_path=str(tmp_path / "secret.key"))

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
