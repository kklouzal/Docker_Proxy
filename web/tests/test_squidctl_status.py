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