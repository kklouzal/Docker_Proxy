from __future__ import annotations

import builtins
import sys
from pathlib import Path
from types import SimpleNamespace


def _add_web_to_path() -> None:
    web_dir = Path(__file__).resolve().parents[1]
    if str(web_dir) not in sys.path:
        sys.path.insert(0, str(web_dir))


_add_web_to_path()

from services import background_guard, logutil  # type: ignore  # noqa: E402


def _reset_logutil_state() -> None:
    logutil._last_log.clear()
    logutil._last_log_interval.clear()
    logutil._last_prune = 0.0


def _reset_background_guard(monkeypatch) -> None:
    monkeypatch.delenv("BACKGROUND_FORCE", raising=False)
    monkeypatch.setattr(background_guard, "_LOCK_FD", None)
    monkeypatch.setattr(background_guard, "_LOCK_PID", None)
    _reset_logutil_state()


def test_acquire_background_lock_force_skips_filesystem(monkeypatch) -> None:
    monkeypatch.setenv("BACKGROUND_FORCE", "1")
    monkeypatch.setattr(
        background_guard.os,
        "open",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("open called")),
    )

    assert background_guard.acquire_background_lock() is True


def test_acquire_background_lock_denies_unexpected_guard_failure(monkeypatch) -> None:
    logged: list[str] = []
    _reset_background_guard(monkeypatch)
    monkeypatch.setattr(
        background_guard.os,
        "getpid",
        lambda: (_ for _ in ()).throw(RuntimeError("token=unexpected-secret")),
    )
    monkeypatch.setattr(
        background_guard.logger,
        "error",
        lambda message, *args: logged.append(message % args if args else message),
    )

    assert background_guard.acquire_background_lock() is False
    assert logged == [
        "Unexpected background lock guard failure; background tasks disabled"
    ]
    assert "unexpected-secret" not in logged[0]


def test_acquire_background_lock_denies_when_lock_directory_cannot_be_created(
    monkeypatch,
) -> None:
    logged: list[str] = []
    _reset_background_guard(monkeypatch)
    monkeypatch.setenv(
        "BACKGROUND_LOCK_PATH", "/password=directory-secret/background.lock"
    )
    monkeypatch.setattr(
        background_guard.pathlib.Path,
        "mkdir",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            OSError("password=exception-secret")
        ),
    )
    monkeypatch.setattr(
        background_guard.logger,
        "error",
        lambda message, *args: logged.append(message % args if args else message),
    )

    assert background_guard.acquire_background_lock() is False
    assert background_guard.acquire_background_lock() is False
    assert logged == [
        "Failed to create background lock directory; background tasks disabled"
    ]
    assert "secret" not in logged[0]


def test_acquire_background_lock_denies_when_lock_file_cannot_be_opened(
    monkeypatch, tmp_path
) -> None:
    logged: list[str] = []
    _reset_background_guard(monkeypatch)
    monkeypatch.setenv("BACKGROUND_LOCK_PATH", str(tmp_path / "background.lock"))
    monkeypatch.setattr(
        background_guard.os,
        "open",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("token=open-secret")),
    )
    monkeypatch.setattr(
        background_guard.logger,
        "error",
        lambda message, *args: logged.append(message % args if args else message),
    )

    assert background_guard.acquire_background_lock() is False
    assert logged == ["Failed to open background lock file; background tasks disabled"]
    assert "open-secret" not in logged[0]


def test_acquire_background_lock_denies_when_locking_import_fails_and_closes_fd(
    monkeypatch,
) -> None:
    closed: list[int] = []
    logged: list[str] = []
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "fcntl":
            msg = "token=import-secret"
            raise ImportError(msg)
        return real_import(name, *args, **kwargs)

    _reset_background_guard(monkeypatch)
    monkeypatch.setenv("BACKGROUND_LOCK_PATH", "background.lock")
    monkeypatch.setattr(background_guard.os, "open", lambda *_args, **_kwargs: 42)
    monkeypatch.setattr(background_guard.os, "close", closed.append)
    monkeypatch.setattr(builtins, "__import__", fake_import)
    monkeypatch.setattr(
        background_guard.logger,
        "error",
        lambda message, *args: logged.append(message % args if args else message),
    )

    assert background_guard.acquire_background_lock() is False
    assert closed == [42]
    assert logged == [
        "Background file locking is unavailable; background tasks disabled"
    ]
    assert "import-secret" not in logged[0]


def test_acquire_background_lock_denies_when_flock_fails_and_closes_fd(
    monkeypatch,
) -> None:
    import fcntl

    closed: list[int] = []
    logged: list[str] = []
    _reset_background_guard(monkeypatch)
    monkeypatch.setenv("BACKGROUND_LOCK_PATH", "background.lock")
    monkeypatch.setattr(background_guard.os, "open", lambda *_args, **_kwargs: 43)
    monkeypatch.setattr(background_guard.os, "close", closed.append)
    monkeypatch.setattr(
        fcntl,
        "flock",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            OSError("password=flock-secret")
        ),
    )
    monkeypatch.setattr(
        background_guard.logger,
        "error",
        lambda message, *args: logged.append(message % args if args else message),
    )

    assert background_guard.acquire_background_lock() is False
    assert closed == [43]
    assert logged == ["Failed to acquire background lock; background tasks disabled"]
    assert "flock-secret" not in logged[0]


def test_acquire_background_lock_contention_denies_and_closes_fd(monkeypatch) -> None:
    import fcntl

    closed: list[int] = []
    logged: list[str] = []
    _reset_background_guard(monkeypatch)
    monkeypatch.setenv("BACKGROUND_LOCK_PATH", "background.lock")
    monkeypatch.setattr(background_guard.os, "open", lambda *_args, **_kwargs: 44)
    monkeypatch.setattr(background_guard.os, "close", closed.append)
    monkeypatch.setattr(
        fcntl,
        "flock",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(BlockingIOError),
    )
    monkeypatch.setattr(
        background_guard.logger,
        "error",
        lambda message, *args: logged.append(message % args if args else message),
    )

    assert background_guard.acquire_background_lock() is False
    assert closed == [44]
    assert logged == []


def test_acquire_background_lock_is_idempotent_for_current_process(monkeypatch, tmp_path) -> None:
    import fcntl

    opened: list[str] = []
    flocked: list[int] = []
    fds = iter([101, 102])
    lock_path = tmp_path / "background.lock"

    _reset_background_guard(monkeypatch)
    monkeypatch.setenv("BACKGROUND_LOCK_PATH", str(lock_path))

    def fake_open(path, *_args, **_kwargs):
        opened.append(path)
        return next(fds)

    def fake_flock(fd, flags):
        flocked.append(fd)

    monkeypatch.setattr(background_guard.os, "open", fake_open)
    monkeypatch.setattr(fcntl, "flock", fake_flock)

    assert background_guard.acquire_background_lock() is True
    assert background_guard.acquire_background_lock() is True

    assert opened == [str(lock_path)]
    assert flocked == [101]
    assert background_guard._LOCK_FD == 101
    assert background_guard.os.getpid() == background_guard._LOCK_PID


def test_should_log_throttles_by_key_and_interval(monkeypatch) -> None:
    _reset_logutil_state()
    current = {"value": 100.0}
    monkeypatch.setattr(logutil.time, "monotonic", lambda: current["value"])

    assert logutil.should_log("same", interval_seconds=10.0) is True
    assert logutil.should_log("same", interval_seconds=10.0) is False
    assert logutil.should_log("other", interval_seconds=10.0) is True
    current["value"] = 111.0
    assert logutil.should_log("same", interval_seconds=10.0) is True


def test_log_exception_throttled_never_raises_and_respects_interval(
    monkeypatch,
) -> None:
    _reset_logutil_state()
    current = {"value": 200.0}
    calls: list[str] = []
    logger = SimpleNamespace(
        exception=lambda message, *args: calls.append(
            message % args if args else message
        )
    )
    monkeypatch.setattr(logutil.time, "monotonic", lambda: current["value"])

    logutil.log_exception_throttled(
        logger, "key", "one", interval_seconds=10.0, message="failure %s"
    )
    logutil.log_exception_throttled(
        logger, "key", "two", interval_seconds=10.0, message="failure %s"
    )
    current["value"] = 211.0
    logutil.log_exception_throttled(
        logger, "key", "three", interval_seconds=10.0, message="failure %s"
    )

    assert calls == ["failure one", "failure three"]

    bad_logger = SimpleNamespace(
        exception=lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("logger failed")
        )
    )
    logutil.log_exception_throttled(
        bad_logger, "bad", interval_seconds=0.0, message="ignored"
    )


def test_should_log_prunes_stale_dynamic_keys_after_safe_window(monkeypatch) -> None:
    _reset_logutil_state()
    current = {"value": 1000.0}
    monkeypatch.setattr(logutil.time, "monotonic", lambda: current["value"])

    assert logutil.should_log("dynamic.old", interval_seconds=10.0) is True
    current["value"] += logutil._THROTTLE_KEY_PRUNE_INTERVAL_SECONDS
    assert logutil.should_log("dynamic.recent", interval_seconds=10.0) is True

    current["value"] = 4899.0
    assert logutil.should_log("trigger.after", interval_seconds=10.0) is True

    assert "dynamic.old" not in logutil._last_log
    assert "dynamic.old" not in logutil._last_log_interval
    assert "dynamic.recent" in logutil._last_log


def test_should_log_keeps_keys_within_throttle_interval_when_pruning(monkeypatch) -> None:
    _reset_logutil_state()
    current = {"value": 10000.0}
    monkeypatch.setattr(logutil.time, "monotonic", lambda: current["value"])

    assert logutil.should_log("long.active", interval_seconds=7200.0) is True
    current["value"] += logutil._THROTTLE_KEY_MIN_RETENTION_SECONDS + 1.0
    assert logutil.should_log("trigger", interval_seconds=10.0) is True

    assert "long.active" in logutil._last_log
    assert logutil.should_log("long.active", interval_seconds=7200.0) is False


def test_should_log_malformed_intervals_do_not_break_logging_loop(monkeypatch) -> None:
    _reset_logutil_state()
    current = {"value": 1000.0}
    monkeypatch.setattr(logutil.time, "monotonic", lambda: current["value"])

    assert logutil.should_log(  # type: ignore[arg-type]
        "bad.none", interval_seconds=None
    ) is True
    assert logutil.should_log(  # type: ignore[arg-type]
        "bad.text", interval_seconds="oops"
    ) is True
    assert logutil.should_log("bad.negative", interval_seconds=-10.0) is True

    current["value"] += 1.0
    assert logutil.should_log(  # type: ignore[arg-type]
        "bad.none", interval_seconds=None
    ) is True
