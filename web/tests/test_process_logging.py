from __future__ import annotations

import subprocess
import sys

from .mysql_test_utils import REPO_ROOT


def _run(code: str, **env: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", code],
        check=True,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        env={
            "PATH": "/usr/bin:/bin",
            "PYTHONPATH": f"{REPO_ROOT}:{REPO_ROOT / 'web'}",
            **env,
        },
    )


def test_process_logging_emits_info_lifecycle_lines_to_stderr() -> None:
    result = _run(
        "import logging; from services.logutil import configure_process_logging; "
        "configure_process_logging(); "
        "logging.getLogger('proxy.agent').info('control-plane startup completed'); "
        "logging.getLogger('x').debug('hidden')",
    )

    assert "INFO proxy.agent: control-plane startup completed" in result.stderr
    assert "hidden" not in result.stderr


def test_process_logging_honors_level_override_and_existing_configuration() -> None:
    quiet = _run(
        "import logging; from services.logutil import configure_process_logging; "
        "configure_process_logging(); logging.getLogger('a').info('info line')",
        PROXY_LOG_LEVEL="warning",
    )
    preconfigured = _run(
        "import logging, sys; logging.basicConfig(stream=sys.stdout, level=logging.ERROR); "
        "from services.logutil import configure_process_logging; "
        "configure_process_logging(); logging.getLogger('a').warning('warn line')",
    )

    assert "info line" not in quiet.stderr
    assert "warn line" not in preconfigured.stdout + preconfigured.stderr


def test_unchanged_periodic_recovery_capture_logs_below_info(
    monkeypatch, caplog
) -> None:
    import logging

    from services import proxy_recovery_startup  # type: ignore

    monkeypatch.setattr(
        proxy_recovery_startup,
        "capture_and_write_recovery_bundle",
        lambda *_args, **_kwargs: "/tmp/bundle.json",
    )
    with caplog.at_level(logging.DEBUG, logger=proxy_recovery_startup.logger.name):
        for changed in (False, True):
            proxy_recovery_startup.capture_recovery_bundle_after_authoritative_state(
                proxy_id="edge",
                reason="runtime_sync",
                changed=changed,
            )

    levels = [record.levelno for record in caplog.records]
    assert levels == [logging.DEBUG, logging.INFO]
