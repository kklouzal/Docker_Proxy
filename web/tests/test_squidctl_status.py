from __future__ import annotations

from types import SimpleNamespace

import pytest


def test_get_status_ignores_stderr_when_squid_check_succeeds() -> None:
    from services import squidctl  # type: ignore

    controller = squidctl.SquidController(
        cmd_run=lambda *args, **kwargs: SimpleNamespace(
            returncode=0, stdout=b"", stderr=b"WARNING: harmless\n"
        ),
    )

    stdout, stderr = controller.get_status()

    assert stdout == b"Squid check ok."
    assert stderr == b""


def test_restart_squid_stops_waits_for_listener_release_then_starts(
    monkeypatch,
) -> None:
    from services import squidctl  # type: ignore

    calls: list[list[str]] = []

    def fake_run(args, **_kwargs):
        calls.append(list(args))
        if "stop" in args:
            return SimpleNamespace(returncode=0, stdout=b"squid: stopped\n", stderr=b"")
        if args[-2:] == ["status", "squid"]:
            return SimpleNamespace(returncode=0, stdout=b"squid STOPPED\n", stderr=b"")
        if "start" in args:
            return SimpleNamespace(returncode=0, stdout=b"squid: started\n", stderr=b"")
        msg = f"unexpected command: {args!r}"
        raise AssertionError(msg)

    controller = squidctl.SquidController(cmd_run=fake_run)
    absent_checks: list[float] = []
    ready_checks: list[float] = []
    monkeypatch.setattr(
        controller,
        "_wait_for_http_listener_absent",
        lambda *, timeout: absent_checks.append(timeout) or True,
    )
    monkeypatch.setattr(
        controller,
        "_wait_for_http_listener",
        lambda *, timeout: ready_checks.append(timeout) or True,
    )

    ok, detail = controller.restart_squid()

    assert ok is True
    assert calls == [
        ["supervisorctl", "-c", "/etc/supervisord.conf", "stop", "squid"],
        ["supervisorctl", "-c", "/etc/supervisord.conf", "status", "squid"],
        ["supervisorctl", "-c", "/etc/supervisord.conf", "start", "squid"],
    ]
    assert absent_checks == [30.0]
    assert ready_checks == [45.0]
    assert "Squid HTTP listener is accepting connections" in detail


def test_clear_disk_cache_uses_bounded_restart_wait(
    monkeypatch,
    tmp_path,
) -> None:
    from services import squidctl  # type: ignore

    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    (cache_dir / "swap.state").write_text("cached\n", encoding="utf-8")
    ready_timeouts: list[float] = []
    prepare_timeouts: list[float] = []
    calls: list[list[str]] = []
    absent_checks: list[float] = []

    def fake_run(args, **kwargs):
        calls.append(list(args))
        if args[-2:] == ["stop", "squid"]:
            return SimpleNamespace(returncode=0, stdout=b"squid: stopped\n", stderr=b"")
        if args[:3] == ["squid", "-N", "-z"]:
            prepare_timeouts.append(float(kwargs["timeout"]))
            return SimpleNamespace(returncode=0, stdout=b"squid -z OK\n", stderr=b"")
        msg = f"unexpected command: {args!r}"
        raise AssertionError(msg)

    controller = squidctl.SquidController(cmd_run=fake_run)
    monkeypatch.setattr(
        controller,
        "get_current_config",
        lambda: f"cache_dir aufs {cache_dir} 100 16 256\n",
    )
    monkeypatch.setattr(
        controller,
        "_wait_for_http_listener_absent",
        lambda *, timeout: absent_checks.append(float(timeout)) or True,
    )
    monkeypatch.setattr(
        controller,
        "_wait_for_squid_pidfile_stale_or_absent",
        lambda *, timeout: True,
    )
    monkeypatch.setattr(controller, "_remove_stale_squid_pidfile", lambda **_kwargs: "")
    monkeypatch.setattr(
        controller,
        "restart_squid",
        lambda *, ready_timeout=45.0: (
            ready_timeouts.append(float(ready_timeout)) or (True, "restarted")
        ),
    )

    ok, detail = controller.clear_disk_cache()

    assert ok is True
    assert calls == [
        ["supervisorctl", "-c", "/etc/supervisord.conf", "stop", "squid"],
        ["squid", "-N", "-z", "-f", controller.squid_conf_path],
    ]
    assert ready_timeouts == [20.0]
    assert prepare_timeouts == [90.0]
    assert absent_checks == [8.0, 1.0, 1.0]
    assert not (cache_dir / "swap.state").exists()
    assert "restarted" in detail


def test_clear_disk_cache_clears_all_configured_cache_dirs(
    monkeypatch,
    tmp_path,
) -> None:
    from services import squidctl  # type: ignore

    cache_a = tmp_path / "cache-a"
    cache_b = tmp_path / "cache-b"
    cache_a.mkdir()
    cache_b.mkdir()
    (cache_a / "swap.state").write_text("cached-a\n", encoding="utf-8")
    (cache_b / "swap.state").write_text("cached-b\n", encoding="utf-8")
    calls: list[list[str]] = []

    def fake_run(args, **_kwargs):
        calls.append(list(args))
        if args[-2:] == ["stop", "squid"]:
            return SimpleNamespace(returncode=0, stdout=b"squid: stopped\n", stderr=b"")
        if args[:3] == ["squid", "-N", "-z"]:
            return SimpleNamespace(returncode=0, stdout=b"squid -z OK\n", stderr=b"")
        msg = f"unexpected command: {args!r}"
        raise AssertionError(msg)

    controller = squidctl.SquidController(cmd_run=fake_run)
    monkeypatch.setattr(
        controller,
        "get_current_config",
        lambda: (
            f"cache_dir rock {cache_a} 100 slot-size=32768\n"
            f"cache_dir ufs {cache_b} 100 16 256\n"
        ),
    )
    monkeypatch.setattr(
        controller,
        "_wait_for_http_listener_absent",
        lambda *, timeout: True,
    )
    monkeypatch.setattr(
        controller,
        "_wait_for_squid_pidfile_stale_or_absent",
        lambda *, timeout: True,
    )
    monkeypatch.setattr(controller, "_remove_stale_squid_pidfile", lambda **_kwargs: "")
    monkeypatch.setattr(
        controller,
        "restart_squid",
        lambda *, ready_timeout=45.0: (True, "restarted"),
    )

    ok, detail = controller.clear_disk_cache()

    assert ok is True
    assert calls == [
        ["supervisorctl", "-c", "/etc/supervisord.conf", "stop", "squid"],
        ["squid", "-N", "-z", "-f", controller.squid_conf_path],
    ]
    assert not (cache_a / "swap.state").exists()
    assert not (cache_b / "swap.state").exists()
    assert f"cleared: {cache_a}" in detail
    assert f"cleared: {cache_b}" in detail
    assert "restarted" in detail


def test_clear_disk_cache_cleans_live_pid_before_prepare(
    monkeypatch,
    tmp_path,
) -> None:
    from services import squidctl  # type: ignore

    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    calls: list[list[str]] = []
    stale_checks: list[float] = []
    absent_checks: list[float] = []
    ready_timeouts: list[float] = []
    removed: list[str] = []

    def fake_run(args, **_kwargs):
        calls.append(list(args))
        if args[-2:] == ["stop", "squid"]:
            return SimpleNamespace(returncode=0, stdout=b"squid: stopped\n", stderr=b"")
        if args[:3] == ["squid", "-N", "-z"]:
            return SimpleNamespace(returncode=0, stdout=b"squid -z OK\n", stderr=b"")
        if args == ["squid", "-k", "shutdown"]:
            return SimpleNamespace(
                returncode=0,
                stdout=b"squid shutdown requested\n",
                stderr=b"",
            )
        msg = f"unexpected command: {args!r}"
        raise AssertionError(msg)

    controller = squidctl.SquidController(cmd_run=fake_run)
    monkeypatch.setattr(
        controller,
        "get_current_config",
        lambda: f"cache_dir aufs {cache_dir} 100 16 256\n",
    )
    monkeypatch.setattr(
        controller,
        "_wait_for_http_listener_absent",
        lambda *, timeout: absent_checks.append(float(timeout)) or True,
    )

    def wait_for_stale(*, timeout):
        stale_checks.append(float(timeout))
        return len(stale_checks) > 1

    monkeypatch.setattr(
        controller,
        "_wait_for_squid_pidfile_stale_or_absent",
        wait_for_stale,
    )
    monkeypatch.setattr(
        controller,
        "_remove_stale_squid_pidfile",
        lambda **_kwargs: removed.append("pidfile")
        or "Removed stale Squid PID file /var/run/squid.pid.",
    )
    monkeypatch.setattr(
        controller,
        "restart_squid",
        lambda *, ready_timeout=45.0: (
            ready_timeouts.append(float(ready_timeout)) or (True, "restarted")
        ),
    )

    ok, detail = controller.clear_disk_cache()

    assert ok is True
    assert calls == [
        ["supervisorctl", "-c", "/etc/supervisord.conf", "stop", "squid"],
        ["squid", "-k", "shutdown"],
        ["squid", "-N", "-z", "-f", controller.squid_conf_path],
    ]
    assert stale_checks == [10.0, 10.0, 1.0, 10.0]
    assert absent_checks == [8.0, 1.0, 20.0, 1.0]
    assert removed == ["pidfile", "pidfile", "pidfile"]
    assert ready_timeouts == [20.0]
    assert "before cache preparation" in detail
    assert "restarted" in detail


def test_clear_disk_cache_fails_before_prepare_when_live_pid_persists(
    monkeypatch,
    tmp_path,
) -> None:
    from services import squidctl  # type: ignore

    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    (cache_dir / "swap.state").write_text("cached\n", encoding="utf-8")
    calls: list[list[str]] = []
    stale_checks: list[float] = []
    restart_calls: list[float] = []

    def fake_run(args, **_kwargs):
        calls.append(list(args))
        if args[-2:] == ["stop", "squid"]:
            return SimpleNamespace(returncode=0, stdout=b"squid: stopped\n", stderr=b"")
        if args == ["squid", "-k", "shutdown"]:
            return SimpleNamespace(
                returncode=0,
                stdout=b"squid shutdown requested\n",
                stderr=b"",
            )
        msg = f"unexpected command: {args!r}"
        raise AssertionError(msg)

    controller = squidctl.SquidController(cmd_run=fake_run)
    monkeypatch.setattr(
        controller,
        "get_current_config",
        lambda: f"cache_dir aufs {cache_dir} 100 16 256\n",
    )
    monkeypatch.setattr(
        controller,
        "_wait_for_http_listener_absent",
        lambda *, timeout: True,
    )
    monkeypatch.setattr(
        controller,
        "_wait_for_squid_pidfile_stale_or_absent",
        lambda *, timeout: stale_checks.append(float(timeout)) or False,
    )
    monkeypatch.setattr(controller, "_remove_stale_squid_pidfile", lambda **_kwargs: "")
    monkeypatch.setattr(
        controller,
        "restart_squid",
        lambda *, ready_timeout=45.0: (
            restart_calls.append(float(ready_timeout)) or (True, "unexpected restart")
        ),
    )

    ok, detail = controller.clear_disk_cache()

    assert ok is False
    assert calls == [
        ["supervisorctl", "-c", "/etc/supervisord.conf", "stop", "squid"],
        ["squid", "-k", "shutdown"],
    ]
    assert stale_checks == [10.0, 10.0, 1.0]
    assert restart_calls == []
    assert (cache_dir / "swap.state").exists()
    assert "before cache preparation" in detail
    assert "still points to a live process" in detail
    assert "unexpected restart" not in detail


def test_clear_disk_cache_fails_when_prepare_listener_stays_bound(
    monkeypatch,
    tmp_path,
) -> None:
    from services import squidctl  # type: ignore

    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    calls: list[list[str]] = []
    absent_checks: list[float] = []
    restart_calls: list[float] = []

    def fake_run(args, **_kwargs):
        calls.append(list(args))
        if args[-2:] == ["stop", "squid"]:
            return SimpleNamespace(returncode=0, stdout=b"squid: stopped\n", stderr=b"")
        if args[:3] == ["squid", "-N", "-z"]:
            return SimpleNamespace(returncode=0, stdout=b"squid -z OK\n", stderr=b"")
        if args == ["squid", "-k", "shutdown"]:
            return SimpleNamespace(
                returncode=0,
                stdout=b"squid shutdown requested\n",
                stderr=b"",
            )
        msg = f"unexpected command: {args!r}"
        raise AssertionError(msg)

    controller = squidctl.SquidController(cmd_run=fake_run)
    monkeypatch.setattr(
        controller,
        "get_current_config",
        lambda: f"cache_dir aufs {cache_dir} 100 16 256\n",
    )

    def listener_absent(*, timeout):
        absent_checks.append(float(timeout))
        return len(absent_checks) == 1

    monkeypatch.setattr(
        controller,
        "_wait_for_http_listener_absent",
        listener_absent,
    )
    monkeypatch.setattr(
        controller,
        "_wait_for_squid_pidfile_stale_or_absent",
        lambda *, timeout: True,
    )
    monkeypatch.setattr(controller, "_remove_stale_squid_pidfile", lambda **_kwargs: "")
    monkeypatch.setattr(
        controller,
        "restart_squid",
        lambda *, ready_timeout=45.0: (
            restart_calls.append(float(ready_timeout)) or (True, "unexpected restart")
        ),
    )

    ok, detail = controller.clear_disk_cache()

    assert ok is False
    assert calls == [
        ["supervisorctl", "-c", "/etc/supervisord.conf", "stop", "squid"],
        ["squid", "-k", "shutdown"],
        ["supervisorctl", "-c", "/etc/supervisord.conf", "stop", "squid"],
    ]
    assert absent_checks == [8.0, 1.0, 20.0, 8.0, 20.0]
    assert restart_calls == []
    assert "before cache preparation" in detail
    assert "listener stayed bound" in detail


def test_clear_disk_cache_retries_supervisor_stop_before_prepare(
    monkeypatch,
    tmp_path,
) -> None:
    from services import squidctl  # type: ignore

    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    (cache_dir / "swap.state").write_text("cached\n", encoding="utf-8")
    calls: list[list[str]] = []
    absent_checks: list[float] = []
    ready_timeouts: list[float] = []

    def fake_run(args, **_kwargs):
        calls.append(list(args))
        if args[-2:] == ["stop", "squid"]:
            return SimpleNamespace(returncode=0, stdout=b"squid: stopped\n", stderr=b"")
        if args[:3] == ["squid", "-N", "-z"]:
            return SimpleNamespace(returncode=0, stdout=b"squid -z OK\n", stderr=b"")
        if args == ["squid", "-k", "shutdown"]:
            return SimpleNamespace(
                returncode=0,
                stdout=b"squid shutdown requested\n",
                stderr=b"",
            )
        msg = f"unexpected command: {args!r}"
        raise AssertionError(msg)

    controller = squidctl.SquidController(cmd_run=fake_run)
    monkeypatch.setattr(
        controller,
        "get_current_config",
        lambda: f"cache_dir aufs {cache_dir} 100 16 256\n",
    )

    def listener_absent(*, timeout):
        absent_checks.append(float(timeout))
        return len(absent_checks) in {3, 7, 8}

    monkeypatch.setattr(
        controller,
        "_wait_for_http_listener_absent",
        listener_absent,
    )
    monkeypatch.setattr(
        controller,
        "_wait_for_squid_pidfile_stale_or_absent",
        lambda *, timeout: True,
    )
    monkeypatch.setattr(controller, "_remove_stale_squid_pidfile", lambda **_kwargs: "")
    monkeypatch.setattr(
        controller,
        "_terminate_orphaned_http_listener_processes",
        lambda *, timeout: "No orphaned Squid listener processes were found.",
    )
    monkeypatch.setattr(
        controller,
        "restart_squid",
        lambda *, ready_timeout=45.0: (
            ready_timeouts.append(float(ready_timeout)) or (True, "restarted")
        ),
    )

    ok, detail = controller.clear_disk_cache()

    assert ok is True
    assert calls == [
        ["supervisorctl", "-c", "/etc/supervisord.conf", "stop", "squid"],
        ["squid", "-k", "shutdown"],
        ["squid", "-k", "shutdown"],
        ["supervisorctl", "-c", "/etc/supervisord.conf", "stop", "squid"],
        ["squid", "-N", "-z", "-f", controller.squid_conf_path],
    ]
    assert absent_checks == [8.0, 8.0, 8.0, 1.0, 20.0, 8.0, 20.0, 1.0]
    assert ready_timeouts == [20.0]
    assert not (cache_dir / "swap.state").exists()
    assert "No orphaned Squid listener processes were found." in detail
    assert "restarted" in detail


def test_clear_disk_cache_retries_supervisor_stop_after_prepare(
    monkeypatch,
    tmp_path,
) -> None:
    from services import squidctl  # type: ignore

    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    (cache_dir / "swap.state").write_text("cached\n", encoding="utf-8")
    calls: list[list[str]] = []
    absent_checks: list[float] = []
    ready_timeouts: list[float] = []

    def fake_run(args, **_kwargs):
        calls.append(list(args))
        if args[-2:] == ["stop", "squid"]:
            return SimpleNamespace(returncode=0, stdout=b"squid: stopped\n", stderr=b"")
        if args[:3] == ["squid", "-N", "-z"]:
            return SimpleNamespace(returncode=0, stdout=b"squid -z OK\n", stderr=b"")
        if args == ["squid", "-k", "shutdown"]:
            return SimpleNamespace(
                returncode=0,
                stdout=b"squid shutdown requested\n",
                stderr=b"",
            )
        msg = f"unexpected command: {args!r}"
        raise AssertionError(msg)

    controller = squidctl.SquidController(cmd_run=fake_run)
    monkeypatch.setattr(
        controller,
        "get_current_config",
        lambda: f"cache_dir aufs {cache_dir} 100 16 256\n",
    )

    def listener_absent(*, timeout):
        absent_checks.append(float(timeout))
        return len(absent_checks) in {1, 2, 6, 7}

    monkeypatch.setattr(
        controller,
        "_wait_for_http_listener_absent",
        listener_absent,
    )
    monkeypatch.setattr(
        controller,
        "_wait_for_squid_pidfile_stale_or_absent",
        lambda *, timeout: True,
    )
    monkeypatch.setattr(controller, "_remove_stale_squid_pidfile", lambda **_kwargs: "")
    monkeypatch.setattr(
        controller,
        "_terminate_orphaned_http_listener_processes",
        lambda *, timeout: "No orphaned Squid listener processes were found.",
    )
    monkeypatch.setattr(
        controller,
        "restart_squid",
        lambda *, ready_timeout=45.0: (
            ready_timeouts.append(float(ready_timeout)) or (True, "restarted")
        ),
    )

    ok, detail = controller.clear_disk_cache()

    assert ok is True
    assert calls == [
        ["supervisorctl", "-c", "/etc/supervisord.conf", "stop", "squid"],
        ["squid", "-N", "-z", "-f", controller.squid_conf_path],
        ["squid", "-k", "shutdown"],
        ["supervisorctl", "-c", "/etc/supervisord.conf", "stop", "squid"],
    ]
    assert absent_checks == [8.0, 1.0, 1.0, 20.0, 8.0, 20.0]
    assert ready_timeouts == [20.0]
    assert not (cache_dir / "swap.state").exists()
    assert "cache preparation left" in detail
    assert "No orphaned Squid listener processes were found." in detail
    assert "restarted" in detail


@pytest.mark.parametrize(
    "cache_path",
    [
        "/",
        "/var",
        "/var/lib",
        "/var/log",
        "/var/spool",
        "/tmp",
        "relative/cache",
    ],
)
def test_clear_disk_cache_refuses_broad_or_relative_cache_dirs(
    monkeypatch,
    cache_path,
) -> None:
    from services import squidctl  # type: ignore

    calls: list[list[str]] = []

    def fake_run(args, **_kwargs):
        calls.append(list(args))
        return SimpleNamespace(returncode=0, stdout=b"unexpected\n", stderr=b"")

    controller = squidctl.SquidController(cmd_run=fake_run)
    monkeypatch.setattr(
        controller,
        "get_current_config",
        lambda: f"cache_dir aufs {cache_path} 100 16 256\n",
    )

    ok, detail = controller.clear_disk_cache()

    assert ok is False
    assert calls == []
    assert f"Refusing to clear cache_dir at unsafe path: {cache_path}" == detail


def test_clear_disk_cache_fails_when_squid_z_returns_nonzero(
    monkeypatch,
    tmp_path,
) -> None:
    from services import squidctl  # type: ignore

    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    (cache_dir / "swap.state").write_text("cached\n", encoding="utf-8")
    restart_calls: list[float] = []

    def fake_run(args, **_kwargs):
        if args[-2:] == ["stop", "squid"]:
            return SimpleNamespace(returncode=0, stdout=b"squid: stopped\n", stderr=b"")
        if args[:3] == ["squid", "-N", "-z"]:
            return SimpleNamespace(
                returncode=1,
                stdout=b"",
                stderr=b"cache_dir init failed\n",
            )
        msg = f"unexpected command: {args!r}"
        raise AssertionError(msg)

    controller = squidctl.SquidController(cmd_run=fake_run)
    monkeypatch.setattr(
        controller,
        "get_current_config",
        lambda: f"cache_dir aufs {cache_dir} 100 16 256\n",
    )
    monkeypatch.setattr(
        controller,
        "_wait_for_http_listener_absent",
        lambda *, timeout: True,
    )
    monkeypatch.setattr(
        controller,
        "_wait_for_squid_pidfile_stale_or_absent",
        lambda *, timeout: True,
    )
    monkeypatch.setattr(controller, "_remove_stale_squid_pidfile", lambda **_kwargs: "")
    monkeypatch.setattr(
        controller,
        "restart_squid",
        lambda *, ready_timeout=45.0: (
            restart_calls.append(float(ready_timeout)) or (True, "unexpected restart")
        ),
    )

    ok, detail = controller.clear_disk_cache()

    assert ok is False
    assert restart_calls == []
    assert not (cache_dir / "swap.state").exists()
    assert "cache_dir init failed" in detail
    assert "unexpected restart" not in detail


def test_clear_disk_cache_fails_when_squid_z_raises(
    monkeypatch,
    tmp_path,
) -> None:
    from services import squidctl  # type: ignore

    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    (cache_dir / "swap.state").write_text("cached\n", encoding="utf-8")
    restart_calls: list[float] = []

    def fake_run(args, **_kwargs):
        if args[-2:] == ["stop", "squid"]:
            return SimpleNamespace(returncode=0, stdout=b"squid: stopped\n", stderr=b"")
        if args[:3] == ["squid", "-N", "-z"]:
            msg = "spawn failed"
            raise RuntimeError(msg)
        msg = f"unexpected command: {args!r}"
        raise AssertionError(msg)

    controller = squidctl.SquidController(cmd_run=fake_run)
    monkeypatch.setattr(
        controller,
        "get_current_config",
        lambda: f"cache_dir aufs {cache_dir} 100 16 256\n",
    )
    monkeypatch.setattr(
        controller,
        "_wait_for_http_listener_absent",
        lambda *, timeout: True,
    )
    monkeypatch.setattr(
        controller,
        "_wait_for_squid_pidfile_stale_or_absent",
        lambda *, timeout: True,
    )
    monkeypatch.setattr(controller, "_remove_stale_squid_pidfile", lambda **_kwargs: "")
    monkeypatch.setattr(
        controller,
        "restart_squid",
        lambda *, ready_timeout=45.0: (
            restart_calls.append(float(ready_timeout)) or (True, "unexpected restart")
        ),
    )

    ok, detail = controller.clear_disk_cache()

    assert ok is False
    assert restart_calls == []
    assert not (cache_dir / "swap.state").exists()
    assert "squid -z error: spawn failed" in detail
    assert "unexpected restart" not in detail


def test_clear_disk_cache_fails_fast_when_listener_never_releases(
    monkeypatch,
    tmp_path,
) -> None:
    from services import squidctl  # type: ignore

    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    (cache_dir / "swap.state").write_text("cached\n", encoding="utf-8")
    calls: list[list[str]] = []
    absent_checks: list[float] = []
    orphan_timeouts: list[float] = []

    def fake_run(args, **_kwargs):
        calls.append(list(args))
        return SimpleNamespace(returncode=0, stdout=b"ok\n", stderr=b"")

    controller = squidctl.SquidController(cmd_run=fake_run)
    monkeypatch.setattr(
        controller,
        "get_current_config",
        lambda: f"cache_dir aufs {cache_dir} 100 16 256\n",
    )
    monkeypatch.setattr(
        controller,
        "_wait_for_http_listener_absent",
        lambda *, timeout: absent_checks.append(float(timeout)) or False,
    )
    monkeypatch.setattr(
        controller,
        "_terminate_orphaned_http_listener_processes",
        lambda *, timeout: orphan_timeouts.append(float(timeout)) or "no orphans",
    )
    monkeypatch.setattr(
        controller,
        "restart_squid",
        lambda *, ready_timeout=45.0: (True, "unexpected restart"),
    )

    ok, detail = controller.clear_disk_cache()

    assert ok is False
    assert calls == [
        ["supervisorctl", "-c", "/etc/supervisord.conf", "stop", "squid"],
        ["squid", "-k", "shutdown"],
    ]
    assert absent_checks == [8.0, 8.0, 8.0]
    assert orphan_timeouts == [6.0]
    assert (cache_dir / "swap.state").exists()
    assert "did not release before cache clear" in detail


def test_cleanup_after_cache_prepare_removes_live_pid_without_listener(
    monkeypatch,
) -> None:
    from services import squidctl  # type: ignore

    calls: list[list[str]] = []
    stale_checks: list[float] = []
    remove_kwargs: list[dict[str, bool]] = []

    def fake_run(args, **_kwargs):
        calls.append(list(args))
        if args == ["squid", "-k", "shutdown"]:
            return SimpleNamespace(
                returncode=0,
                stdout=b"squid shutdown requested\n",
                stderr=b"",
            )
        msg = f"unexpected command: {args!r}"
        raise AssertionError(msg)

    def wait_for_stale(*, timeout):
        stale_checks.append(float(timeout))
        return len(stale_checks) > 2

    def remove_stale(**kwargs):
        remove_kwargs.append(dict(kwargs))
        return "Removed stale Squid PID file /var/run/squid.pid."

    controller = squidctl.SquidController(cmd_run=fake_run)
    monkeypatch.setattr(
        controller,
        "_wait_for_squid_pidfile_stale_or_absent",
        wait_for_stale,
    )
    monkeypatch.setattr(
        controller,
        "_wait_for_http_listener_absent",
        lambda *, timeout: True,
    )
    monkeypatch.setattr(controller, "_remove_stale_squid_pidfile", remove_stale)

    details: list[str] = []
    ok = controller._cleanup_after_cache_prepare(details)

    assert ok is True
    assert calls == [["squid", "-k", "shutdown"]]
    assert stale_checks == [10.0, 10.0, 1.0]
    assert remove_kwargs == [{"allow_live_without_listener": True}]
    assert any("Removed stale Squid PID file" in detail for detail in details)


def test_restart_squid_removes_live_pidfile_when_listener_is_absent(
    monkeypatch,
) -> None:
    from services import squidctl  # type: ignore

    calls: list[list[str]] = []
    remove_kwargs: list[dict[str, bool]] = []

    def fake_run(args, **_kwargs):
        calls.append(list(args))
        if args[-2:] == ["stop", "squid"]:
            return SimpleNamespace(returncode=0, stdout=b"squid: stopped\n", stderr=b"")
        if args[-2:] == ["status", "squid"]:
            return SimpleNamespace(returncode=0, stdout=b"squid STOPPED\n", stderr=b"")
        if args[-2:] == ["start", "squid"]:
            return SimpleNamespace(returncode=0, stdout=b"squid: started\n", stderr=b"")
        msg = f"unexpected command: {args!r}"
        raise AssertionError(msg)

    def remove_stale(**kwargs):
        remove_kwargs.append(dict(kwargs))
        return "Removed stale Squid PID file /var/run/squid.pid."

    controller = squidctl.SquidController(cmd_run=fake_run)
    monkeypatch.setattr(
        controller,
        "_wait_for_http_listener_absent",
        lambda *, timeout: True,
    )
    monkeypatch.setattr(
        controller,
        "_wait_for_http_listener",
        lambda *, timeout: True,
    )
    monkeypatch.setattr(
        controller,
        "_wait_for_squid_pidfile_stale_or_absent",
        lambda *, timeout: True,
    )
    monkeypatch.setattr(controller, "_remove_stale_squid_pidfile", remove_stale)

    ok, detail = controller.restart_squid()

    assert ok is True
    assert remove_kwargs == [{"allow_live_without_listener": True}]
    assert calls == [
        ["supervisorctl", "-c", "/etc/supervisord.conf", "stop", "squid"],
        ["supervisorctl", "-c", "/etc/supervisord.conf", "status", "squid"],
        ["supervisorctl", "-c", "/etc/supervisord.conf", "start", "squid"],
    ]
    assert "Removed stale Squid PID file" in detail
    assert "Squid HTTP listener is accepting connections" in detail


def test_restart_squid_accepts_supervisor_auto_restart_race(monkeypatch) -> None:
    from services import squidctl  # type: ignore

    calls: list[list[str]] = []

    def fake_run(args, **_kwargs):
        calls.append(list(args))
        if args[-2:] == ["stop", "squid"]:
            return SimpleNamespace(returncode=0, stdout=b"squid: stopped\n", stderr=b"")
        if args[-2:] == ["status", "squid"]:
            return SimpleNamespace(
                returncode=0, stdout=b"squid RUNNING pid 123\n", stderr=b""
            )
        msg = f"unexpected command: {args!r}"
        raise AssertionError(msg)

    controller = squidctl.SquidController(cmd_run=fake_run)
    monkeypatch.setattr(
        controller, "_wait_for_http_listener_absent", lambda *, timeout: True
    )
    monkeypatch.setattr(controller, "_wait_for_http_listener", lambda *, timeout: True)
    monkeypatch.setattr(
        controller, "_wait_for_squid_pidfile_stale_or_absent", lambda *, timeout: False
    )
    monkeypatch.setattr(controller, "_remove_stale_squid_pidfile", lambda **_kwargs: "")

    ok, detail = controller.restart_squid()

    assert ok is True
    assert calls == [
        ["supervisorctl", "-c", "/etc/supervisord.conf", "stop", "squid"],
        ["supervisorctl", "-c", "/etc/supervisord.conf", "status", "squid"],
    ]
    assert "already restarted by supervisor" in detail


def test_restart_squid_fails_when_listener_never_releases(monkeypatch) -> None:
    from services import squidctl  # type: ignore

    calls: list[list[str]] = []

    def fake_run(args, **_kwargs):
        calls.append(list(args))
        return SimpleNamespace(returncode=0, stdout=b"ok\n", stderr=b"")

    controller = squidctl.SquidController(cmd_run=fake_run)
    monkeypatch.setattr(
        controller, "_wait_for_http_listener_absent", lambda *, timeout: False
    )

    ok, detail = controller.restart_squid()

    assert ok is False
    assert calls == [
        ["supervisorctl", "-c", "/etc/supervisord.conf", "stop", "squid"],
        ["squid", "-k", "shutdown"],
    ]
    assert "did not release" in detail
