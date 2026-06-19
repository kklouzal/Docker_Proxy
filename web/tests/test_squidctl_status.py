from __future__ import annotations

from types import SimpleNamespace


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

    def fake_run(args, **kwargs):
        if args[-2:] == ["stop", "squid"]:
            return SimpleNamespace(returncode=0, stdout=b"squid: stopped\n", stderr=b"")
        if args[:2] == ["squid", "-z"]:
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
        lambda *, timeout: True,
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
    assert ready_timeouts == [20.0]
    assert prepare_timeouts == [90.0]
    assert not (cache_dir / "swap.state").exists()
    assert "restarted" in detail


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
        if args[:2] == ["squid", "-z"]:
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
        if args[:2] == ["squid", "-z"]:
            raise RuntimeError("spawn failed")
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
    monkeypatch.setattr(controller, "_remove_stale_squid_pidfile", lambda: "")

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
