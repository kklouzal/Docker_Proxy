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


def test_get_status_falls_back_to_supervisor_when_pidfile_is_missing():
    import services.squidctl as squidctl  # type: ignore

    calls = {"count": 0}

    def fake_run(args, **kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            return SimpleNamespace(
                returncode=1,
                stdout=b"",
                stderr=b"FATAL: failed to open /var/run/squid.pid: (2) No such file or directory\n",
            )
        return SimpleNamespace(returncode=0, stdout=b"squid RUNNING pid 123, uptime 0:01:00\n", stderr=b"")

    controller = squidctl.SquidController(cmd_run=fake_run)

    stdout, stderr = controller.get_status()

    assert b"RUNNING" in stdout
    assert stderr == b""


def test_reload_squid_restarts_under_supervisor_when_pidfile_is_missing():
    import services.squidctl as squidctl  # type: ignore

    calls = {"commands": []}

    def fake_run(args, **kwargs):
        calls["commands"].append(tuple(args))
        if tuple(args[:3]) == ("squid", "-k", "reconfigure"):
            return SimpleNamespace(
                returncode=1,
                stdout=b"",
                stderr=b"FATAL: failed to open /var/run/squid.pid: (2) No such file or directory\n",
            )
        if tuple(args[:4]) == ("supervisorctl", "-c", "/etc/supervisord.conf", "restart"):
            return SimpleNamespace(returncode=0, stdout=b"squid: started\n", stderr=b"")
        raise AssertionError(f"Unexpected command: {args}")

    controller = squidctl.SquidController(cmd_run=fake_run)

    stdout, stderr = controller.reload_squid()

    assert b"started" in stdout
    assert stderr == b""