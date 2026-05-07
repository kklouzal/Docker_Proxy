from __future__ import annotations

from types import SimpleNamespace


def test_get_status_ignores_stderr_when_squid_check_succeeds():
    import services.squidctl as squidctl  # type: ignore

    controller = squidctl.SquidController(
        cmd_run=lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=b"", stderr=b"WARNING: harmless\n")
    )

    stdout, stderr = controller.get_status()

    assert stdout == b"Squid check ok."
    assert stderr == b""


def test_restart_squid_stops_waits_for_listener_release_then_starts(monkeypatch):
    import services.squidctl as squidctl  # type: ignore

    calls: list[list[str]] = []

    def fake_run(args, **_kwargs):
        calls.append(list(args))
        if "stop" in args:
            return SimpleNamespace(returncode=0, stdout=b"squid: stopped\n", stderr=b"")
        if args[-2:] == ["status", "squid"]:
            return SimpleNamespace(returncode=0, stdout=b"squid STOPPED\n", stderr=b"")
        if "start" in args:
            return SimpleNamespace(returncode=0, stdout=b"squid: started\n", stderr=b"")
        raise AssertionError(f"unexpected command: {args!r}")

    controller = squidctl.SquidController(cmd_run=fake_run)
    absent_checks: list[float] = []
    ready_checks: list[float] = []
    monkeypatch.setattr(controller, "_wait_for_http_listener_absent", lambda *, timeout: absent_checks.append(timeout) or True)
    monkeypatch.setattr(controller, "_wait_for_http_listener", lambda *, timeout: ready_checks.append(timeout) or True)

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


def test_restart_squid_accepts_supervisor_auto_restart_race(monkeypatch):
    import services.squidctl as squidctl  # type: ignore

    calls: list[list[str]] = []

    def fake_run(args, **_kwargs):
        calls.append(list(args))
        if args[-2:] == ["stop", "squid"]:
            return SimpleNamespace(returncode=0, stdout=b"squid: stopped\n", stderr=b"")
        if args[-2:] == ["status", "squid"]:
            return SimpleNamespace(returncode=0, stdout=b"squid RUNNING pid 123\n", stderr=b"")
        raise AssertionError(f"unexpected command: {args!r}")

    controller = squidctl.SquidController(cmd_run=fake_run)
    monkeypatch.setattr(controller, "_wait_for_http_listener_absent", lambda *, timeout: True)
    monkeypatch.setattr(controller, "_wait_for_http_listener", lambda *, timeout: True)
    monkeypatch.setattr(controller, "_wait_for_squid_pidfile_stale_or_absent", lambda *, timeout: False)
    monkeypatch.setattr(controller, "_remove_stale_squid_pidfile", lambda: "")

    ok, detail = controller.restart_squid()

    assert ok is True
    assert calls == [
        ["supervisorctl", "-c", "/etc/supervisord.conf", "stop", "squid"],
        ["supervisorctl", "-c", "/etc/supervisord.conf", "status", "squid"],
    ]
    assert "already restarted by supervisor" in detail


def test_restart_squid_fails_when_listener_never_releases(monkeypatch):
    import services.squidctl as squidctl  # type: ignore

    calls: list[list[str]] = []

    def fake_run(args, **_kwargs):
        calls.append(list(args))
        return SimpleNamespace(returncode=0, stdout=b"ok\n", stderr=b"")

    controller = squidctl.SquidController(cmd_run=fake_run)
    monkeypatch.setattr(controller, "_wait_for_http_listener_absent", lambda *, timeout: False)

    ok, detail = controller.restart_squid()

    assert ok is False
    assert calls == [
        ["supervisorctl", "-c", "/etc/supervisord.conf", "stop", "squid"],
        ["squid", "-k", "shutdown"],
    ]
    assert "did not release" in detail
