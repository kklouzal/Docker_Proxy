from __future__ import annotations

import builtins
import sys
from pathlib import Path
from types import SimpleNamespace


def _add_web_to_path() -> None:
    web_dir = Path(__file__).resolve().parents[1]
    if str(web_dir) not in sys.path:
        sys.path.insert(0, str(web_dir))


def test_acquire_background_lock_force_skips_filesystem(monkeypatch) -> None:
    _add_web_to_path()
    import services.background_guard as background_guard  # type: ignore

    monkeypatch.setenv("BACKGROUND_FORCE", "1")
    monkeypatch.setattr(background_guard.os, "open", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("open called")))

    assert background_guard.acquire_background_lock() is True


def test_acquire_background_lock_allows_when_lock_directory_cannot_be_created(monkeypatch) -> None:
    _add_web_to_path()
    import services.background_guard as background_guard  # type: ignore

    monkeypatch.delenv("BACKGROUND_FORCE", raising=False)
    monkeypatch.setenv("BACKGROUND_LOCK_PATH", "/unwritable/background.lock")
    monkeypatch.setattr(background_guard.os, "makedirs", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("nope")))

    assert background_guard.acquire_background_lock() is True


def test_acquire_background_lock_non_posix_allows_and_closes_fd(monkeypatch) -> None:
    _add_web_to_path()
    import services.background_guard as background_guard  # type: ignore

    closed: list[int] = []
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "fcntl":
            raise ImportError("no fcntl")
        return real_import(name, *args, **kwargs)

    monkeypatch.delenv("BACKGROUND_FORCE", raising=False)
    monkeypatch.setenv("BACKGROUND_LOCK_PATH", "background.lock")
    monkeypatch.setattr(background_guard.os, "open", lambda *_args, **_kwargs: 42)
    monkeypatch.setattr(background_guard.os, "close", lambda fd: closed.append(fd))
    monkeypatch.setattr(builtins, "__import__", fake_import)

    assert background_guard.acquire_background_lock() is True
    assert closed == [42]


def test_should_log_throttles_by_key_and_interval(monkeypatch) -> None:
    _add_web_to_path()
    import services.logutil as logutil  # type: ignore

    logutil._last_log.clear()
    current = {"value": 100.0}
    monkeypatch.setattr(logutil.time, "monotonic", lambda: current["value"])

    assert logutil.should_log("same", interval_seconds=10.0) is True
    assert logutil.should_log("same", interval_seconds=10.0) is False
    assert logutil.should_log("other", interval_seconds=10.0) is True
    current["value"] = 111.0
    assert logutil.should_log("same", interval_seconds=10.0) is True


def test_log_exception_throttled_never_raises_and_respects_interval(monkeypatch) -> None:
    _add_web_to_path()
    import services.logutil as logutil  # type: ignore

    logutil._last_log.clear()
    current = {"value": 200.0}
    calls: list[str] = []
    logger = SimpleNamespace(exception=lambda message, *args: calls.append(message % args if args else message))
    monkeypatch.setattr(logutil.time, "monotonic", lambda: current["value"])

    logutil.log_exception_throttled(logger, "key", "one", interval_seconds=10.0, message="failure %s")
    logutil.log_exception_throttled(logger, "key", "two", interval_seconds=10.0, message="failure %s")
    current["value"] = 211.0
    logutil.log_exception_throttled(logger, "key", "three", interval_seconds=10.0, message="failure %s")

    assert calls == ["failure one", "failure three"]

    bad_logger = SimpleNamespace(exception=lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("logger failed")))
    logutil.log_exception_throttled(bad_logger, "bad", interval_seconds=0.0, message="ignored")
