from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import subprocess

from .subprocess_test_utils import run_test_process

SCRIPT_PATH = Path(__file__).resolve().parents[2] / "docker" / "squid_logrotate.sh"


def run_logrotate_once(
    tmp_path: Path,
    conf_text: str = "logfile_rotate 3\n",
    *,
    log_name: str = "access-observe.log",
    command_shim: tuple[str, str] | None = None,
    check: bool = True,
) -> tuple[Path, subprocess.CompletedProcess[str]]:
    log_path = tmp_path / log_name
    conf_path = tmp_path / "squid.conf"
    conf_path.write_text(conf_text, encoding="utf-8")

    env = os.environ.copy()
    env.update(
        {
            "SQUID_LOG_ROTATE_RUN_ONCE": "1",
            "SQUID_LOG_ROTATE_INITIAL_DELAY_SECONDS": "0",
            "SQUID_CONF_PATH": str(conf_path),
            "SQUID_LOG_ROTATE_LOGFILES": str(log_path),
        }
    )
    if command_shim is not None:
        command, script = command_shim
        shim_dir = tmp_path / "bin"
        shim_dir.mkdir(exist_ok=True)
        shim_path = shim_dir / command
        shim_path.write_text(f"#!/bin/sh\n{script}\n", encoding="utf-8")
        shim_path.chmod(0o755)
        env["PATH"] = f"{shim_dir}:{env['PATH']}"

    result = run_test_process(
        ["/bin/sh", str(SCRIPT_PATH)],
        check=check,
        env=env,
        text=True,
        capture_output=True,
    )
    return log_path, result


def test_squid_logrotate_copytruncates_observability_logs_without_runtime_rotate() -> (
    None
):
    script = SCRIPT_PATH.read_text(encoding="utf-8")

    assert "if ! squid -k rotate" not in script
    assert "squid -k rotate" in script  # comment only: documents why it is avoided.
    assert "/var/log/squid/access-observe.log" in script
    assert "/var/log/squid/icap.log" in script
    assert "/var/log/cicap-access.log" in script
    assert 'cp "$logfile" "${logfile}.1"' in script
    assert 'truncate -s 0 "$logfile"' in script


def test_squid_logrotate_advances_numbered_history_instead_of_overwriting_dot_1(
    tmp_path: Path,
) -> None:
    log_path = tmp_path / "access-observe.log"

    for content in ("first\n", "second\n", "third\n"):
        log_path.write_text(content, encoding="utf-8")
        run_logrotate_once(tmp_path)

    assert log_path.read_text(encoding="utf-8") == ""
    assert (tmp_path / "access-observe.log.1").read_text(encoding="utf-8") == "third\n"
    assert (tmp_path / "access-observe.log.2").read_text(encoding="utf-8") == "second\n"
    assert (tmp_path / "access-observe.log.3").read_text(encoding="utf-8") == "first\n"

    log_path.write_text("fourth\n", encoding="utf-8")
    run_logrotate_once(tmp_path)

    assert log_path.read_text(encoding="utf-8") == ""
    assert (tmp_path / "access-observe.log.1").read_text(encoding="utf-8") == "fourth\n"
    assert (tmp_path / "access-observe.log.2").read_text(encoding="utf-8") == "third\n"
    assert (tmp_path / "access-observe.log.3").read_text(encoding="utf-8") == "second\n"
    assert not (tmp_path / "access-observe.log.4").exists()


def test_squid_logrotate_uses_env_rotation_count_override(tmp_path: Path) -> None:
    log_path = tmp_path / "icap.log"
    conf_path = tmp_path / "squid.conf"
    conf_path.write_text("logfile_rotate 10\n", encoding="utf-8")

    env = os.environ.copy()
    env.update(
        {
            "SQUID_LOG_ROTATE_RUN_ONCE": "1",
            "SQUID_LOG_ROTATE_INITIAL_DELAY_SECONDS": "0",
            "SQUID_CONF_PATH": str(conf_path),
            "SQUID_LOG_ROTATE_LOGFILES": str(log_path),
            "SQUID_LOGFILE_ROTATE_COUNT": "2",
        }
    )

    for content in ("one\n", "two\n", "three\n"):
        log_path.write_text(content, encoding="utf-8")
        run_test_process(["/bin/sh", str(SCRIPT_PATH)], check=True, env=env)

    assert log_path.read_text(encoding="utf-8") == ""
    assert (tmp_path / "icap.log.1").read_text(encoding="utf-8") == "three\n"
    assert (tmp_path / "icap.log.2").read_text(encoding="utf-8") == "two\n"
    assert not (tmp_path / "icap.log.3").exists()


def test_squid_logrotate_zero_retention_still_truncates_active_log(
    tmp_path: Path,
) -> None:
    log_path = tmp_path / "cicap-access.log"
    log_path.write_text("active\n", encoding="utf-8")

    run_logrotate_once(tmp_path, "logfile_rotate 0\n", log_name="cicap-access.log")

    assert log_path.read_text(encoding="utf-8") == ""
    assert not (tmp_path / "cicap-access.log.1").exists()


def test_squid_logrotate_archive_copy_failure_preserves_active_log_and_fails(
    tmp_path: Path,
) -> None:
    log_path = tmp_path / "access-observe.log"
    log_path.write_text("irreplaceable evidence\n", encoding="utf-8")

    _, result = run_logrotate_once(
        tmp_path,
        command_shim=("cp", "exit 73"),
        check=False,
    )

    assert result.returncode != 0
    assert log_path.read_text(encoding="utf-8") == "irreplaceable evidence\n"
    assert "failed to archive" in result.stderr
    assert f"truncated {log_path}" not in result.stdout


def test_squid_logrotate_history_failure_preserves_active_log_and_fails(
    tmp_path: Path,
) -> None:
    log_path = tmp_path / "access-observe.log"
    log_path.write_text("current evidence\n", encoding="utf-8")
    (tmp_path / "access-observe.log.1").write_text("prior evidence\n", encoding="utf-8")

    _, result = run_logrotate_once(
        tmp_path,
        command_shim=("mv", "exit 74"),
        check=False,
    )

    assert result.returncode != 0
    assert log_path.read_text(encoding="utf-8") == "current evidence\n"
    assert (tmp_path / "access-observe.log.1").read_text(
        encoding="utf-8"
    ) == "prior evidence\n"
    assert "failed to advance archive" in result.stderr
    assert f"truncated {log_path}" not in result.stdout


def test_squid_logrotate_truncation_failure_is_reported_without_success(
    tmp_path: Path,
) -> None:
    log_path = tmp_path / "access-observe.log"
    log_path.write_text("active evidence\n", encoding="utf-8")

    _, result = run_logrotate_once(
        tmp_path,
        command_shim=("truncate", "exit 75"),
        check=False,
    )

    assert result.returncode != 0
    assert log_path.read_text(encoding="utf-8") == "active evidence\n"
    assert (tmp_path / "access-observe.log.1").read_text(
        encoding="utf-8"
    ) == "active evidence\n"
    assert "failed to truncate" in result.stderr
    assert f"truncated {log_path}" not in result.stdout
